import type { Settings } from "./types.ts";

export type SettingsListener = (s: Settings) => void;

// A small reactive store: single source of truth for the current Settings. Pure
// (no Tauri import) so it is unit-testable. `patchLocal` does a one-level-deep
// merge of section objects and notifies subscribers; persistence lives in the
// Tauri-aware wrapper in settings.ts.
export class SettingsStore {
  private state: Settings;
  private listeners = new Set<SettingsListener>();
  constructor(initial: Settings) {
    this.state = initial;
  }
  get(): Settings {
    return this.state;
  }
  set(next: Settings): void {
    this.state = next;
    this.notify();
  }
  // Deep-merge one or more section patches (e.g. { appearance: { theme } }).
  patchLocal(patch: Partial<Settings>): void {
    const cur = this.state as unknown as Record<string, Record<string, unknown>>;
    const merged: Record<string, Record<string, unknown>> = { ...cur };
    for (const [section, vals] of Object.entries(patch)) {
      merged[section] = { ...(cur[section] ?? {}), ...(vals as Record<string, unknown>) };
    }
    this.state = merged as unknown as Settings;
    this.notify();
  }
  subscribe(l: SettingsListener): () => void {
    this.listeners.add(l);
    l(this.state);
    return () => this.listeners.delete(l);
  }
  private notify(): void {
    for (const l of [...this.listeners]) l(this.state);
  }
}
