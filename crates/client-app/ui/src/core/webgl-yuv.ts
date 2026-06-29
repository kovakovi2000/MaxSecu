// WebGL YUV(I420) -> RGB render core for the sandboxed video player.
//
// This module is pure UI (outside the TCB). It receives ALREADY-decoded,
// already-validated I420 planes (Y full-res, U/V half-res) from the backend
// video worker and draws them to a <canvas> via WebGL. The player (Task 5.2)
// base64-decodes the frame DTO and feeds the planes into draw().
//
// We deliberately keep this dependency-free: raw WebGL1 (with a WebGL2 fallback
// for context creation only), single-channel LUMINANCE textures, and a
// fullscreen-triangle blit with a BT.709 limited-range conversion in the shader.

// Thrown when the WebView has no usable WebGL context. The player maps this to
// PlayerPhase::CodecUnavailable so the user gets an honest "can't render" state
// instead of a silent black frame.
export class WebglUnavailable extends Error {
  constructor(message = "WebGL is not available in this WebView") {
    super(message);
    this.name = "WebglUnavailable";
  }
}

// Thrown when a shader fails to compile or the program fails to link. The player
// maps this to PlayerPhase::Error. Carries the GL info log for diagnostics.
export class WebglProgramError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WebglProgramError";
  }
}

// Luma plane is full resolution (w*h); both chroma planes are half resolution,
// rounded UP, matching I420 / YUV 4:2:0 subsampling.
export function planeSizes(w: number, h: number): { y: number; u: number; v: number } {
  const cw = Math.ceil(w / 2);
  const ch = Math.ceil(h / 2);
  const chroma = cw * ch;
  return { y: w * h, u: chroma, v: chroma };
}

// A single I420 frame's planes plus its luma dimensions. The chroma planes are
// implicitly ceil(width/2) x ceil(height/2).
export interface YuvFrame {
  width: number;
  height: number;
  y: Uint8Array;
  u: Uint8Array;
  v: Uint8Array;
}

export interface YuvRenderer {
  // Uploads the frame's planes and blits one RGB frame to the canvas.
  draw(frame: YuvFrame): void;
  // Resizes the canvas backing store + GL viewport.
  resize(w: number, h: number): void;
  // Releases all GL objects (textures/program/shaders/buffer).
  dispose(): void;
}

// GLSL sources for the blit. Kept in a pure function so it is unit-testable
// (the planar math + shader assembly) without a real GL context.
export function buildProgramSources(): { vertex: string; fragment: string } {
  // Fullscreen triangle: three clip-space verts that cover [-1,1]^2 with one
  // primitive (no index buffer, no quad seam). Texture coords are derived from
  // the clip position; the Y axis is flipped so frame row 0 lands at the top.
  const vertex = `
attribute vec2 aPos;
varying vec2 vTexCoord;
void main() {
  vTexCoord = vec2(aPos.x * 0.5 + 0.5, 1.0 - (aPos.y * 0.5 + 0.5));
  gl_Position = vec4(aPos, 0.0, 1.0);
}
`.trim();

  // BT.709 LIMITED-RANGE (a.k.a. "TV"/studio range) YUV 4:2:0 -> RGB.
  //
  // Planes arrive as LUMINANCE / UNSIGNED_BYTE, so each sampled channel is in
  // [0,1] as value/255. Limited range packs luma Y into [16,235] and chroma
  // U/V into [16,240], with chroma centered on 128. Normalizing over /255:
  //   Y' = Y - 16/255  = Y - 0.0627
  //   U' = U - 128/255 = U - 0.50196
  //   V' = V - 128/255 = V - 0.50196
  //
  // BT.709 limited-range conversion matrix (blue-from-U is the exact
  // 255/224 * 2 * (1 - 0.0722) = 2.112):
  //   R = 1.164 * Y' + 0.000 * U' + 1.793 * V'
  //   G = 1.164 * Y' - 0.213 * U' - 0.533 * V'
  //   B = 1.164 * Y' + 2.112 * U' + 0.000 * V'
  const fragment = `
precision mediump float;
varying vec2 vTexCoord;
uniform sampler2D yTex;
uniform sampler2D uTex;
uniform sampler2D vTex;
void main() {
  // BT.709 limited-range: de-offset luma and center chroma (offsets /255).
  float y = texture2D(yTex, vTexCoord).r - 0.0627;
  float u = texture2D(uTex, vTexCoord).r - 0.50196;
  float v = texture2D(vTex, vTexCoord).r - 0.50196;
  // BT.709 limited-range YUV -> RGB.
  float r = 1.164 * y + 1.793 * v;
  float g = 1.164 * y - 0.213 * u - 0.533 * v;
  float b = 1.164 * y + 2.112 * u;
  gl_FragColor = vec4(clamp(r, 0.0, 1.0), clamp(g, 0.0, 1.0), clamp(b, 0.0, 1.0), 1.0);
}
`.trim();

  return { vertex, fragment };
}

// Fullscreen triangle in clip space; texcoords are derived in the vertex shader.
const TRIANGLE = new Float32Array([
  -1, -1,
  3, -1,
  -1, 3,
]);

function compileShader(gl: WebGLRenderingContext, type: number, source: string): WebGLShader {
  const shader = gl.createShader(type);
  if (!shader) throw new WebglProgramError("gl.createShader returned null");
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    const log = gl.getShaderInfoLog(shader) ?? "(no info log)";
    gl.deleteShader(shader);
    const kind = type === gl.VERTEX_SHADER ? "vertex" : "fragment";
    throw new WebglProgramError(`${kind} shader failed to compile: ${log}`);
  }
  return shader;
}

function makePlaneTexture(gl: WebGLRenderingContext): WebGLTexture {
  const tex = gl.createTexture();
  if (!tex) throw new WebglProgramError("gl.createTexture returned null");
  gl.bindTexture(gl.TEXTURE_2D, tex);
  // No mips; clamp at edges; linear filtering for a smooth upscale.
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
  return tex;
}

// Creates a renderer bound to `canvas`. Throws WebglUnavailable if no WebGL
// context can be obtained, and WebglProgramError on compile/link failure.
export function createYuvRenderer(canvas: HTMLCanvasElement): YuvRenderer {
  // Prefer WebGL2 if present (still used in WebGL1-compatible mode here), but
  // WebGL1 + LUMINANCE/UNSIGNED_BYTE is the most portable path for WebView2.
  const opts: WebGLContextAttributes = { antialias: false, depth: false, alpha: false };
  const ctx = (canvas.getContext("webgl", opts) ??
    canvas.getContext("webgl2", opts)) as WebGLRenderingContext | null;
  if (!ctx) throw new WebglUnavailable();
  const gl: WebGLRenderingContext = ctx;

  const { vertex, fragment } = buildProgramSources();
  const vs = compileShader(gl, gl.VERTEX_SHADER, vertex);
  const fs = compileShader(gl, gl.FRAGMENT_SHADER, fragment);

  const program = gl.createProgram();
  if (!program) throw new WebglProgramError("gl.createProgram returned null");
  gl.attachShader(program, vs);
  gl.attachShader(program, fs);
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    const log = gl.getProgramInfoLog(program) ?? "(no info log)";
    gl.deleteProgram(program);
    gl.deleteShader(vs);
    gl.deleteShader(fs);
    throw new WebglProgramError(`program failed to link: ${log}`);
  }
  gl.useProgram(program);

  // Single-byte planes: relax row alignment so non-multiple-of-4 widths upload
  // correctly.
  gl.pixelStorei(gl.UNPACK_ALIGNMENT, 1);

  // Fullscreen-triangle vertex buffer.
  const buffer = gl.createBuffer();
  if (!buffer) throw new WebglProgramError("gl.createBuffer returned null");
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  gl.bufferData(gl.ARRAY_BUFFER, TRIANGLE, gl.STATIC_DRAW);
  const aPos = gl.getAttribLocation(program, "aPos");
  gl.enableVertexAttribArray(aPos);
  gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 0, 0);

  // Bind the three samplers to fixed texture units 0/1/2.
  const yTex = makePlaneTexture(gl);
  const uTex = makePlaneTexture(gl);
  const vTex = makePlaneTexture(gl);
  gl.uniform1i(gl.getUniformLocation(program, "yTex"), 0);
  gl.uniform1i(gl.getUniformLocation(program, "uTex"), 1);
  gl.uniform1i(gl.getUniformLocation(program, "vTex"), 2);

  function uploadPlane(unit: number, tex: WebGLTexture, w: number, h: number, data: Uint8Array): void {
    gl.activeTexture(gl.TEXTURE0 + unit);
    gl.bindTexture(gl.TEXTURE_2D, tex);
    gl.texImage2D(
      gl.TEXTURE_2D,
      0,
      gl.LUMINANCE,
      w,
      h,
      0,
      gl.LUMINANCE,
      gl.UNSIGNED_BYTE,
      data,
    );
  }

  let disposed = false;

  return {
    draw(frame: YuvFrame): void {
      if (disposed) return;
      const cw = Math.ceil(frame.width / 2);
      const ch = Math.ceil(frame.height / 2);
      gl.useProgram(program);
      uploadPlane(0, yTex, frame.width, frame.height, frame.y);
      uploadPlane(1, uTex, cw, ch, frame.u);
      uploadPlane(2, vTex, cw, ch, frame.v);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    },

    resize(w: number, h: number): void {
      if (disposed) return;
      canvas.width = w;
      canvas.height = h;
      gl.viewport(0, 0, w, h);
    },

    dispose(): void {
      if (disposed) return;
      disposed = true;
      gl.deleteTexture(yTex);
      gl.deleteTexture(uTex);
      gl.deleteTexture(vTex);
      gl.deleteBuffer(buffer);
      gl.deleteShader(vs);
      gl.deleteShader(fs);
      gl.deleteProgram(program);
    },
  };
}
