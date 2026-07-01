/// Pure helper: build the custom-protocol URL for a video's file id.
///
/// Tauri v2 serves a registered custom URI-scheme protocol at
/// `http://<scheme>.localhost/<path>` on **Windows** (WebView2) — NOT `<scheme>://…`,
/// which WebView2 treats as an unknown scheme and refuses to load. This app targets
/// Windows, so we emit the `http://stream.localhost/media/<id>` form the native
/// `<video>` element can actually fetch (allowed by the `media-src http://stream.localhost`
/// CSP). The Rust `stream_media` handler parses the file id from the last path segment.
/// Kept in a side-effect-free module (no media-chrome / Tauri imports) so it is
/// unit-testable under node:test.
export function streamSrc(fileId: string): string {
  return `http://stream.localhost/media/${fileId}`;
}
