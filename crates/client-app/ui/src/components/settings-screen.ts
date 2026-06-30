import { call } from "../core/rpc.ts";
import { settingsStore, updateSettings, loadAndApplySettings } from "../core/settings.ts";
import type { Settings, RamLimits } from "../core/types.ts";

// Settings (spec §5/§7): appearance / accessibility / performance / behavior /
// connection / account / privacy. Preference controls write through the SHARED
// settings store (so quick-settings + the shell theme stay in sync and apply
// live); the RAM control is bounded to the live `ram_limits`. Account actions
// are explicit submits. Accessible: focused landmark on mount, labelled controls
// in fieldsets, role=status live regions.
const DEFAULTS: Settings = {
  a11y: { reduced_motion: false, high_contrast: false, text_size: "normal" },
  behavior: { confirm_destructive: false },
  performance: { ram_cache_cap_mb: 256 },
  connection: { use_tor: false },
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

        <form id="set-form">
          <fieldset>
            <legend>Appearance</legend>
            <label>Theme
              <select name="theme">
                <option value="dark">Dark</option>
                <option value="light">Light</option>
              </select></label>
          </fieldset>

          <fieldset>
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

          <fieldset>
            <legend>Performance</legend>
            <label>RAM cache cap (MB)
              <input type="range" name="ram_range" step="1" />
              <input type="number" name="ram_cache_cap_mb" step="1" /></label>
            <p id="ram-hint" class="hint"></p>
          </fieldset>

          <fieldset>
            <legend>Behavior</legend>
            <label><input type="checkbox" name="confirm_destructive" /> Confirm destructive actions</label>
          </fieldset>

          <fieldset>
            <legend>Connection</legend>
            <label><input type="checkbox" name="use_tor" disabled /> Route over Tor
              <span> (arrives in a later phase)</span></label>
          </fieldset>
        </form>

        <fieldset>
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

        <fieldset>
          <legend>Privacy</legend>
          <p>MaxSecu stores and encrypts your content locally before it ever leaves this
            device. Settings are kept on this device only; no analytics or telemetry are
            collected.</p>
        </fieldset>
      </main>`;
    (this.querySelector("#main") as HTMLElement).focus();

    const prefForm = this.querySelector("#set-form") as HTMLFormElement;
    prefForm.addEventListener("change", (e) => this.onPrefChange(e));

    (this.querySelector("#pw-form") as HTMLFormElement)
      .addEventListener("submit", (e) => { e.preventDefault(); this.onChangePassword(); });
    (this.querySelector("#exp-form") as HTMLFormElement)
      .addEventListener("submit", (e) => { e.preventDefault(); this.onExportKeystore(); });

    // Keep the form mirrored to the shared store (so a quick-settings edit shows
    // up here live, and vice-versa).
    this.unsub = settingsStore.subscribe((s) => this.writeControls(s));

    this.init();
  }
  disconnectedCallback() {
    this.unsub?.();
  }

  private async init() {
    try { this.limits = await call<RamLimits>("ram_limits"); } catch { /* keep defaults */ }
    const range = this.input("ram_range");
    const num = this.input("ram_cache_cap_mb");
    range.min = String(this.limits.min_mb); range.max = String(this.limits.max_mb);
    num.min = String(this.limits.min_mb); num.max = String(this.limits.max_mb);
    (this.querySelector("#ram-hint") as HTMLElement).textContent =
      `Allowed ${this.limits.min_mb}–${this.limits.max_mb} MB (cap = total RAM − 6 GB).`;
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
    if (target?.getAttribute("name") === "ram_range") {
      this.input("ram_cache_cap_mb").value = this.input("ram_range").value;
    } else if (target?.getAttribute("name") === "ram_cache_cap_mb") {
      this.input("ram_range").value = this.input("ram_cache_cap_mb").value;
    }
    const ram = Number(this.input("ram_cache_cap_mb").value);
    const text = this.sel("text_size").value;
    const patch: Partial<Settings> = {
      appearance: { theme: this.sel("theme").value === "light" ? "light" : "dark" },
      a11y: {
        reduced_motion: this.input("reduced_motion").checked,
        high_contrast: this.input("high_contrast").checked,
        text_size: text === "large" || text === "larger" ? text : "normal",
      },
      performance: { ram_cache_cap_mb: Number.isFinite(ram) ? ram : DEFAULTS.performance.ram_cache_cap_mb },
      behavior: { confirm_destructive: this.input("confirm_destructive").checked },
    };
    try {
      await updateSettings(patch);
      status.textContent = "Saved.";
    } catch (x) {
      status.textContent = errMsg(x, "Could not save settings.");
    }
  }

  private writeControls(s: Settings): void {
    this.sel("theme").value = s.appearance.theme;
    this.input("reduced_motion").checked = s.a11y.reduced_motion;
    this.input("high_contrast").checked = s.a11y.high_contrast;
    this.sel("text_size").value = s.a11y.text_size;
    this.input("ram_cache_cap_mb").value = String(s.performance.ram_cache_cap_mb);
    this.input("ram_range").value = String(s.performance.ram_cache_cap_mb);
    this.input("confirm_destructive").checked = s.behavior.confirm_destructive;
    this.input("use_tor").checked = s.connection.use_tor;
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
