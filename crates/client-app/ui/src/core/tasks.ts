import { on } from "./rpc.ts";
import type { UploadMsg, FetchMsg } from "./types.ts";

// Tracks in-flight long-running tasks for the status strip's active-tasks count
// (spec §4/§6). Counts uploads (between first event and done/failed) + viewer
// fetches (between fetching and ready/failed), keyed by id so duplicates don't
// double-count. No backend change — it binds the existing event channels.
type Listener = (n: number) => void;

class ActiveTasks {
  private uploads = new Set<string>();
  private fetches = new Set<string>();
  private listeners = new Set<Listener>();
  private wired = false;

  private ensureWired() {
    if (this.wired) return;
    this.wired = true;
    void on<UploadMsg>("maxsecu://upload-state", (m) => {
      if (m.phase === "done" || m.phase === "failed") this.uploads.delete(m.job_id);
      else this.uploads.add(m.job_id);
      this.notify();
    });
    void on<FetchMsg>("maxsecu://fetch-state", (m) => {
      if (m.phase === "ready" || m.phase === "failed") this.fetches.delete(m.file_id);
      else this.fetches.add(m.file_id);
      this.notify();
    });
  }
  private count(): number {
    return this.uploads.size + this.fetches.size;
  }
  private notify() {
    for (const l of [...this.listeners]) l(this.count());
  }
  subscribe(l: Listener): () => void {
    this.ensureWired();
    this.listeners.add(l);
    l(this.count());
    return () => this.listeners.delete(l);
  }
}

export const activeTasks = new ActiveTasks();
