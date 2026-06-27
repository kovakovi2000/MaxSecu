# MaxSecu — Media Pipeline & Decode Sandbox

**Status:** Spec (prove out **early** — the sandbox is the Phase-4b gate and the system's #1 risk; stack.md §1.7/§4 item 6).
**Scope:** how the client transcodes at upload and decodes shared media at view **without** letting a decoder 0-day reach keys, plaintext, or the network (`DESIGN.md` §8.1, D30, threat-model row "Malicious author's media → viewer's decoder"). Includes the **canonical-format choice** (a security decision, flagged for ratification).
**Companion to:** `DESIGN.md` §8.1/§13/§15.3, `docs/stack.md` §1.7.

> **The risk, stated plainly.** Viewing shared media runs complex C codecs on **attacker-authored bytes**. A crafted file can trigger memory-corruption **RCE in the viewer's process** — which, in the key-holding main process, would expose that user's private key and plaintext. *Authenticated authorship does not make the bytes safe* (authenticated ≠ benign, D24). We **contain**, not eliminate: decode in a secret-less, network-less, OS-isolated worker, behind hard pre-decode bounds, using the smallest/most-hardened decoder set possible.

---

## 1. Process model — thin key-holder, isolated decoder

```
┌─ Main process (TCB: keys, plaintext, directory) ─┐        ┌─ Decode worker (NO secrets) ─────────┐
│  - unwrap DEK, AEAD-decrypt streams to RAM       │  IPC   │  - AppContainer + restricted token    │
│  - hand RAW MEDIA BYTES (no keys) to worker  ────┼───────▶│  - Job Object caps (mem/CPU/no-child) │
│  - receive DECODED FRAMES/PCM back  ◀────────────┼────────│  - NO network, NO key/dir handles     │
│  - validate decoded dims/format, then render     │        │  - ffmpeg/dav1d/image decoders here    │
└──────────────────────────────────────────────────┘        └───────────────────────────────────────┘
```

- The **main process never links ffmpeg or any media codec.** All decode/transcode happens in the worker (`stack.md` §1.7). The worker receives only the **already-decrypted media stream** for one file and returns only decoded frames/clips/PCM over IPC.
- A decoder compromise is thus contained to a process that **holds no secrets and cannot exfiltrate** (no network, no key/directory handles).
- **Worker output is untrusted too:** the main process validates returned dimensions/format/length against the manifest-declared, pre-bounded values before handing anything to the renderer.

---

## 2. OS isolation (Windows v1)

Mandatory worker confinement (deny-by-default):

- **AppContainer** with **no capabilities** — in particular **no `internetClient`/`internetClientServer`/`privateNetwork`** (no network is reachable, by capability, not just firewall).
- **Restricted/lowbox token**, distinct low integrity level; no access to the user's files, the `local_key_blob`, the directory cache, or the main process's handles.
- **Job Object** limits: max committed memory, max CPU time, **`JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 1`** and **kill-on-job-close**, **`LIMIT_BREAKAWAY_OK` denied** — the worker **cannot spawn children** (no shelling out).
- **Process mitigations:** CFG; **ACG** (dynamic-code-prohibition — no JIT/codegen in the decoder); **no-child-process**; **no-remote-images / binary-signature** policy; bottom-up + high-entropy ASLR; DEP. Disable **WER/crash dumps** for the worker (a crash must not write a memory image, §8.1).
- **Separate window station/desktop** (no shatter/clipboard surface).
- **One worker per decode job**, killed and re-spawned per file (no state carried between two authors' inputs).

> Linux ceremony/build hosts are not in this path; the viewer is Windows-only in v1 (stack.md §1). The same shape ports later via seccomp-bpf + namespaces + no-net.

---

## 3. Pre-decode bounds (reject before you allocate)

Checked in the main process (cheap, no decoder) **and** re-checked in the worker, before any decoder touches the bytes:

- **Declared vs. actual size:** the stream's `total_bytes`/`chunk_count` come from the **signed manifest** (can't be forged, only chosen) — reject anything over the configured ceilings.
- **Dimension/duration caps before allocation:** parse only the container/header enough to read width×height×frames / duration, and **reject** beyond caps (e.g. max W×H, max pixels, max duration, max frame count) **before** allocating frame buffers — the classic decompression-bomb guard.
- **Single declared codec/format only:** the canonical format (§4) is the *only* accepted input at view time; anything else is rejected pre-decode (no codec auto-probing of the demuxer zoo).
- **Hard wall-clock + memory budget** on the job (Job Object), so a pathological input is killed, not hung.

---

## 4. Canonical format — a security choice (▶ ratify)

The uploader **transcodes every file to ONE canonical format before upload** (D30), so a *viewer* only ever decodes that one format and can ship a **single, hardened, minimal decoder** instead of ffmpeg's whole demuxer set. **Pick the canonical format for decoder safety first, compression second.** My recommendation:

| Class | Canonical (recommended) | Why (safety-first) |
|---|---|---|
| **Video** | **AV1 in fMP4/CMAF**, decoded with **`dav1d`** | `dav1d` is purpose-built for security, **continuously fuzzed**, widely deployed, with a far cleaner memory-safety record than legacy H.264/H.265 C decoders; AV1 is royalty-free and well-supported. Container normalized to fragmented MP4. |
| **Image** | **PNG**, decoded with a **memory-safe Rust decoder** (`png`/`zune-png`); **lossy fallback** transcoded to AVIF (still `dav1d`) or a constrained JPEG via a memory-safe decoder (`zune-jpeg`) | Prefer **pure-Rust, memory-safe** image decoders so the largest image surface isn't C at all. Keep the *viewer's* image path Rust where possible. |
| **Audio** (in video) | **Opus** in the same MP4/CMAF | modern, single well-reviewed decoder |
| **Blog/text** | not media — rendered as **escaped/sanitized** markup, never raw HTML (D24/§8.1) | no decoder; injection-sanitized |

Rationale and tradeoffs:
- **`dav1d` (AV1)** gives the best *decoder-safety-per-format* for video and lets the **view path** be a single audited decoder. The heavier **full transcoder** (libav, many input codecs) is needed **only at upload**, on the author's *own* input — also sandboxed, but the author's input is less adversarial than arbitrary shared media.
- **Fragmented/progressive output is mandatory (enables decrypt-while-play).** The canonical container is written **fragmented (CMAF/fMP4, faststart)** so a viewer can begin playback after the first chunks rather than downloading the whole file — the streaming path of `DESIGN.md` §8.1/§12.10. A non-fragmented output (whole `moov` at the end) would force a full download before play and is rejected by the transcode step.
- **Avoid hardware/OS-kernel decoders** on the view path: GPU/driver/Media-Foundation decoders move attacker bytes into kernel/driver space *outside* the AppContainer's containment. Prefer the userspace, sandboxable `dav1d`/Rust decoders even at a CPU cost.
- **Prefer memory-safe decoders wherever they exist** (images especially): a Rust decoder removes the memory-corruption class for that format outright; reserve C decoders (`dav1d`) for where no mature memory-safe equivalent exists, and keep them patched + fuzzed.
- **"Quality-preserving" caveat:** prefer **remux / stream-copy** when the source is *already* canonical (no re-encode, no loss, smaller plaintext-handling window); otherwise a visually-lossless encode (`stack.md` §1.7).

> **▶ Ratify with the external cryptographer/security reviewer.** Format choice interacts with quality expectations, encode cost, and decoder audit status; AV1/`dav1d` + Rust-image is the safety-first default, but it's a real decision (e.g. if H.264 hardware ubiquity is required for performance, that trades containment for speed — not recommended for the view path). The `alg`/format identifier is threaded through the manifest, so a later change is a registry addition, not a wire-format break.

---

## 5. Upload vs. view paths

| | Input | Decoder set | Isolation |
|---|---|---|---|
| **Upload (author's own bytes)** | arbitrary source media | **full transcoder** (libav) → canonical (§4) + thumbnail + preview | sandbox (§2) — less adversarial input, but still untrusted |
| **View (others' shared bytes)** | **only** the canonical format | **single hardened decoder** (`dav1d` / Rust image) | sandbox (§2) — maximally adversarial; the hot risk |

**Preview-before-upload (D30):** after conversion the author's client renders the converted result in the **same in-app player** and the user **confirms** it looks correct before encryption/upload — a WYSIWYG check that the canonical re-encode succeeded. (Confirm-UX runs against the sandbox-decoded output, like any view.)

---

## 6. Verification & exit gate (Phase 4b, stack.md §1.7)
- **Continuous fuzzing** of the decode worker (canonical-format corpus + mutated/crafted inputs); a finding is triaged like a security bug. The corpus is committed.
- **Containment tests (exit gate):** a decoder fuzz/exploit corpus **cannot read keys, the directory, or any user file, and cannot reach the network**, from inside the worker (verified by attempting each and asserting denial). A crash writes **no** memory image (WER disabled).
- **Bounds tests:** decompression-bomb / oversize-dimension / over-duration inputs are rejected **before** allocation (§3).
- **No-plaintext tests (shared with §8.1):** the server, cache, and Dropbox never hold a decoded byte/thumbnail/preview (all artifacts are client-made and encrypted, §13).

---

## 7. Residual (honest)
The sandbox **contains**, it does not eliminate. The genuine residuals (§15.3):
- a **0-day in the sandboxed decoder** combined with a **sandbox/AppContainer escape** would still reach the host — keep decoders patched, prefer memory-safe ones, keep the worker secret-less so a *non-escaping* compromise yields nothing;
- the **upload transcoder** is a larger surface (full libav) but runs on the author's *own* input and is equally sandboxed;
- worker **output** is validated but a logic bug in validation is its own surface — keep the decoded-frame validation minimal and typed.

This is the system's top RCE surface and the reason native clients + this isolation exist (D1/D30); treat any change to the worker's privilege or the canonical format as a security-reviewed change.

---

## Cross-references
`DESIGN.md` §8.1 (in-memory/sandbox handling), §13 (streams/thumbnails as plaintext-derived, client-only), §15.3 (decoder residual), D30 (media locus + decoder safety), D33 (per-file streams). `docs/stack.md` §1.7 (crate/tool choices). `docs/parameters.md` §1.6 (RAM budget). `docs/api.md` §9 (encrypted stream transport).
