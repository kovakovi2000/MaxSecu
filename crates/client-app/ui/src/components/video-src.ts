/// Pure helper: build the stream:// Range-protocol URL for a video's file id.
/// Kept in a side-effect-free module (no media-chrome / Tauri imports) so it is
/// unit-testable under node:test.
export function streamSrc(fileId: string): string {
  return `stream://media/${fileId}`;
}
