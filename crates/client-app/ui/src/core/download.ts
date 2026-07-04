import { call } from "./rpc.ts";
import { serial } from "./serial.ts";
import { toast } from "./toast.ts";
import { downloadName } from "./download-name.ts";

// Shared per-post Download flow (Task 5.2), used by <media-viewer> and the generic
// <media-card>. Opens the native "save as" dialog pre-filled with a type-appropriate
// name, then verify+decrypt+writes the plaintext via `download_content`. Real backend
// calls only — no file bytes or keys cross the seam here (the decrypt-and-write happens
// inside the TCB in `download_content`; the dialog returns only a path string). A
// cancelled dialog is a silent no-op; success/failure surface as a toast.
export async function downloadPost(
  fileId: string,
  fileType: string,
  title: string,
): Promise<void> {
  let savePath: string | null;
  try {
    savePath = await call<string | null>("save_file", {
      defaultName: downloadName(fileType, title),
    });
  } catch (x) {
    toast("error", downloadErr(x));
    return;
  }
  if (savePath === null) return; // user cancelled the save dialog

  try {
    // download_content re-auths (holds the single ConnectLock), so route it through
    // the shared serial queue — it must not race in-flight card/viewer decrypts.
    const written = await serial(() =>
      call<string>("download_content", { req: { file_id: fileId, save_path: savePath } }),
    );
    // Rendered via the toast host's textContent (never innerHTML), so the path is safe.
    toast("success", `Saved to ${written}`);
  } catch (x) {
    toast("error", downloadErr(x));
  }
}

// Best-effort extraction of a backend UiError message; neutral fallback otherwise.
export function downloadErr(x: unknown): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return "Could not download this item.";
}
