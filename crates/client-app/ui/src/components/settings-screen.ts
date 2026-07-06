import { call } from "../core/rpc.ts";
import { settingsStore, updateSettings, loadAndApplySettings, getThemePreset, setThemePreset } from "../core/settings.ts";
import type { Settings, RamLimits } from "../core/types.ts";

// Settings (spec §5/§7): appearance / accessibility / performance / behavior /
// connection / account / privacy. Preference controls write through the SHARED
// settings store (so the header RAM gauge + the shell theme stay in sync and apply
// live); the RAM control is bounded to the live `ram_limits`. Account actions
// are explicit submits. Accessible: focused landmark on mount, labelled controls
// in fieldsets, role=status live regions.
const DEFAULTS: Settings = {
  a11y: { reduced_motion: false, high_contrast: false, text_size: "normal" },
  behavior: { confirm_destructive: false },
  performance: { media_cache_cap_mb: 1024, thumb_cache_cap_mb: 256, feed_concurrency: 4, transcode_threads: 4, decode_threads: 4, cache_location: "Memory" },
  connection: { route_mode: "prefer-server" },
  appearance: { theme: "dark" },
};

export class SettingsScreen extends HTMLElement {
  private limits: RamLimits = { default_mb: 256, min_mb: 64, max_mb: 4096 };
  private unsub: (() => void) | null = null;

  connectedCallback() {
    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="set-h">
        <h1 id="set-h">Settings</h1>
        <p id="set-status" role="status" aria-live="polite"></p>

        <div id="set-form">
          <div class="settings-column settings-column-left">
            <fieldset class="settings-card appearance-card">
              <legend>Appearance</legend>
              <label>Theme
                <select name="theme">
                  <option value="tech">Tech (default)</option>
                  <option value="cheese">Cheese</option>
                  <option value="pottery">Pottery</option>
                </select></label>
              <p class="hint">Theme presets are placeholders for upcoming visual passes.</p>
            </fieldset>

            <fieldset class="settings-card a11y-card">
              <legend>Accessibility</legend>
              <label><input type="checkbox" name="reduced_motion" /> Reduce motion</label>
              <label><input type="checkbox" name="high_contrast" /> High contrast</label>
              <label>Text size
                <select name="text_size">
                  <option value="normal">Normal</option>
                  <option value="large">Large</option>
                  <option value="larger">Larger</option>
                </select></label>
            </fieldset>

            <fieldset class="settings-card performance-card">
              <legend>Performance</legend>
              <label>Media cache (MB)
                <input type="range" name="media_range" step="1" />
                <input type="number" name="media_cache_cap_mb" step="1" /></label>
              <label>Thumbnails cache (MB)
                <input type="number" name="thumb_cache_cap_mb" step="1" /></label>
              <p id="ram-hint" class="hint"></p>
              <div class="settings-cache-panel" aria-label="Live cache usage">
                <div>
                  <strong>Live cache usage</strong>
                  <p class="hint">Media and thumbnail cache meters use the same clearable gauge language as the header.</p>
                </div>
                <ram-gauge></ram-gauge>
              </div>
              <label>Feed concurrency (cards decoded in parallel)
                <input type="number" name="feed_concurrency" min="1" max="8" step="1" /></label>
              <label>Transcode threads
                <input type="number" name="transcode_threads" min="1" step="1" /></label>
              <label>Decode threads
                <input type="number" name="decode_threads" min="1" step="1" /></label>
              <p id="cores-hint" class="hint"></p>
              <label>Cache location
                <select name="cache_location">
                  <option value="Memory">Memory (RAM only)</option>
                  <option value="Disk">Disk</option>
                </select></label>
              <p class="hint">Memory keeps cached ciphertext in RAM only, bounded by the caps above. Disk spills ciphertext to a temp dir (no cap) and is wiped on start and exit.</p>
            </fieldset>
          </div>

          <div class="settings-column settings-column-right">
            <fieldset class="settings-card connection-card">
              <legend>Connection</legend>
              <label>Download route
                <select name="route_mode">
                  <option value="prefer-server">Prefer server (default)</option>
                  <option value="prefer-dropbox">Prefer Dropbox offload</option>
                  <option value="tor-only">Tor only</option>
                </select></label>
              <p class="hint">Prefer server proxies all media through the server. Prefer Dropbox downloads offloaded media directly from cloud storage when available (still verified locally). Tor only routes everything over Tor and fails closed.</p>
            </fieldset>

            <fieldset class="settings-card behavior-card">
              <legend>Behavior</legend>
              <label><input type="checkbox" name="confirm_destructive" /> Confirm destructive actions</label>
            </fieldset>

            <fieldset class="settings-card account-card">
              <legend>Account</legend>
              <p id="acct-status" role="status" aria-live="polite"></p>
              <form id="pw-form">
                <label>Current password
                  <input type="password" name="oldpw" autocomplete="current-password" /></label>
                <label>New password
                  <input type="password" name="newpw" autocomplete="new-password" /></label>
                <button type="submit">Change password</button>
              </form>
              <form id="exp-form">
                <p id="exp-warn" role="note">Back up the keystore file securely — it is only as safe as your password.</p>
                <label>Export keystore to path
                  <input type="text" name="dest" autocomplete="off" /></label>
                <button type="submit">Export keystore</button>
              </form>
            </fieldset>

            <fieldset class="settings-card privacy">
              <legend>Privacy</legend>
              <p>Your content is encrypted on this device with keys only you hold before
                it ever leaves — the server stores and serves only ciphertext and can
                never read your posts. Cached ciphertext is wiped and your keys are
                zeroized from memory when the app closes. Settings stay on this device;
                no analytics or telemetry are collected. You can optionally route all
                traffic over Tor from the Connection settings above.</p>
            </fieldset>
          </div>
        </div>
      </main>`;
    (this.querySelector("#main") as HTMLElement).focus();

    const prefForm = this.querySelector("#set-form") as HTMLElement;
    prefForm.addEventListener("change", (e) => this.onPrefChange(e));

    (this.querySelector("#pw-form") as HTMLFormElement)
      .addEventListener("submit", (e) => { e.preventDefault(); this.onChangePassword(); });
    (this.querySelector("#exp-form") as HTMLFormElement)
      .addEventListener("submit", (e) => { e.preventDefault(); this.onExportKeystore(); });

    // Keep the form mirrored to the shared store (so any other store edit shows
    // up here live, and vice-versa).
    this.unsub = settingsStore.subscribe((s) => this.writeControls(s));

    this.init();
  }
  disconnectedCallback() {
    this.unsub?.();
  }

  private async init() {
    try { this.limits = await call<RamLimits>("ram_limits"); } catch { /* keep defaults */ }
    // Both cap inputs (and the media slider) share the same ram_limits bounds.
    const range = this.input("media_range");
    const media = this.input("media_cache_cap_mb");
    const thumb = this.input("thumb_cache_cap_mb");
    for (const el of [range, media, thumb]) {
      el.min = String(this.limits.min_mb);
      el.max = String(this.limits.max_mb);
    }
    (this.querySelector("#ram-hint") as HTMLElement).textContent =
      `Each cache: ${this.limits.min_mb}–${this.limits.max_mb} MB (cap = total RAM − 6 GB).`;
    // Bound the thread budgets to the machine's logical-CPU count. The backend
    // re-clamps 1..=cores on save, so this is a convenience bound, not the SoT.
    let cores = 4;
    try { cores = await call<number>("system_cores"); } catch { /* keep fallback */ }
    this.input("transcode_threads").max = String(cores);
    this.input("decode_threads").max = String(cores);
    (this.querySelector("#cores-hint") as HTMLElement).textContent =
      `Thread budgets: 1–${cores} (max = logical CPUs). Decode threads are reserved for a confined decode path.`;
    const loaded = await loadAndApplySettings();
    this.writeControls(loaded ?? DEFAULTS);
  }

  private input(name: string): HTMLInputElement {
    return this.querySelector(`#set-form [name="${name}"]`) as HTMLInputElement;
  }
  private sel(name: string): HTMLSelectElement {
    return this.querySelector(`#set-form [name="${name}"]`) as HTMLSelectElement;
  }

  private async onPrefChange(e: Event) {
    const status = this.querySelector("#set-status")!;
    const target = e.target as HTMLElement;
    // Keep the media slider and its number input mirrored.
    if (target?.getAttribute("name") === "media_range") {
      this.input("media_cache_cap_mb").value = this.input("media_range").value;
    } else if (target?.getAttribute("name") === "media_cache_cap_mb") {
      this.input("media_range").value = this.input("media_cache_cap_mb").value;
    }
    const text = this.sel("text_size").value;
    const cur = settingsStore.get().performance;
    const numOr = (name: string, fallback: number) => {
      const v = Number(this.input(name).value);
      return Number.isFinite(v) ? v : fallback;
    };
    setThemePreset(this.sel("theme").value);
    const patch: Partial<Settings> = {
      // Backend settings keep the existing dark appearance contract; the new visual
      // theme presets are frontend-only placeholders applied via data-theme.
      appearance: { theme: "dark" },
      a11y: {
        reduced_motion: this.input("reduced_motion").checked,
        high_contrast: this.input("high_contrast").checked,
        text_size: text === "large" || text === "larger" ? text : "normal",
      },
      performance: {
        // The two caps + three knobs round-trip through their inputs (the backend
        // clamps caps to ram_limits, feed 1..=8, threads 1..=cores). Fall back to
        // the current stored value, then the default, if empty/non-numeric.
        media_cache_cap_mb: numOr("media_cache_cap_mb", cur.media_cache_cap_mb ?? DEFAULTS.performance.media_cache_cap_mb),
        thumb_cache_cap_mb: numOr("thumb_cache_cap_mb", cur.thumb_cache_cap_mb ?? DEFAULTS.performance.thumb_cache_cap_mb),
        feed_concurrency: numOr("feed_concurrency", cur.feed_concurrency ?? DEFAULTS.performance.feed_concurrency),
        transcode_threads: numOr("transcode_threads", cur.transcode_threads ?? DEFAULTS.performance.transcode_threads),
        decode_threads: numOr("decode_threads", cur.decode_threads ?? DEFAULTS.performance.decode_threads),
        cache_location: this.sel("cache_location").value === "Disk" ? "Disk" : "Memory",
      },
      behavior: { confirm_destructive: this.input("confirm_destructive").checked },
      connection: { route_mode: this.sel("route_mode").value as Settings["connection"]["route_mode"] },
    };
    try {
      await updateSettings(patch);
      status.textContent = "Saved.";
    } catch (x) {
      status.textContent = errMsg(x, "Could not save settings.");
    }
  }

  private writeControls(s: Settings): void {
    void s;
    this.sel("theme").value = getThemePreset();
    this.input("reduced_motion").checked = s.a11y.reduced_motion;
    this.input("high_contrast").checked = s.a11y.high_contrast;
    this.sel("text_size").value = s.a11y.text_size;
    this.input("media_cache_cap_mb").value = String(s.performance.media_cache_cap_mb);
    this.input("media_range").value = String(s.performance.media_cache_cap_mb);
    this.input("thumb_cache_cap_mb").value = String(s.performance.thumb_cache_cap_mb);
    this.input("feed_concurrency").value = String(s.performance.feed_concurrency);
    this.input("transcode_threads").value = String(s.performance.transcode_threads);
    this.input("decode_threads").value = String(s.performance.decode_threads);
    this.sel("cache_location").value = s.performance.cache_location ?? "Memory";
    this.input("confirm_destructive").checked = s.behavior.confirm_destructive;
    this.sel("route_mode").value = s.connection.route_mode;
  }

  private async onChangePassword() {
    const status = this.querySelector("#acct-status")!;
    const oldp = (this.querySelector('input[name="oldpw"]') as HTMLInputElement).value;
    const newp = (this.querySelector('input[name="newpw"]') as HTMLInputElement).value;
    try {
      await call<void>("change_password", { req: { old_password: oldp, new_password: newp } });
      status.textContent = "Password changed.";
      (this.querySelector('input[name="oldpw"]') as HTMLInputElement).value = "";
      (this.querySelector('input[name="newpw"]') as HTMLInputElement).value = "";
    } catch (x) {
      status.textContent = errMsg(x, "Could not change the password.");
    }
  }
  private async onExportKeystore() {
    const status = this.querySelector("#acct-status")!;
    const dest = (this.querySelector('input[name="dest"]') as HTMLInputElement).value;
    try {
      await call<void>("export_keystore", { req: { dest_path: dest } });
      status.textContent = "Keystore exported.";
    } catch (x) {
      status.textContent = errMsg(x, "Could not export the keystore.");
    }
  }
}

function errMsg(x: unknown, fallback: string): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return fallback;
}

customElements.define("settings-screen", SettingsScreen);
