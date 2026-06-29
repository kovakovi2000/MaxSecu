import { call } from "../core/rpc.ts";
import { applySettings, loadAndApplySettings } from "../core/settings.ts";
import type { Settings } from "../core/types.ts";

// Settings (spec §5): accessibility / performance / behavior / connection / account
// / privacy sections. Preference controls (a11y/performance/behavior) round-trip on
// change through set_settings → applySettings, reflecting any backend clamping back
// into the form. Account actions (change password / export keystore) are explicit
// button clicks. Accessible: landmark focused on mount, labelled controls grouped in
// fieldsets, role=status live regions for save + account feedback.
const DEFAULTS: Settings = {
  a11y: { reduced_motion: false, high_contrast: false, text_size: "normal" },
  behavior: { confirm_destructive: false },
  performance: { ram_cache_cap_mb: 256 },
  connection: { use_tor: false },
};

export class SettingsScreen extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="set-h">
        <h1 id="set-h">Settings</h1>
        <p id="set-status" role="status" aria-live="polite"></p>

        <form id="set-form">
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
              <input type="number" name="ram_cache_cap_mb" min="16" max="4096" step="1" /></label>
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
    prefForm.addEventListener("change", () => this.saveFromControls());

    const pwForm = this.querySelector("#pw-form") as HTMLFormElement;
    pwForm.addEventListener("submit", (e) => { e.preventDefault(); this.onChangePassword(); });

    const expForm = this.querySelector("#exp-form") as HTMLFormElement;
    expForm.addEventListener("submit", (e) => { e.preventDefault(); this.onExportKeystore(); });

    this.init();
  }

  private async init() {
    const loaded = await loadAndApplySettings();
    this.writeControls(loaded ?? DEFAULTS);
  }

  private input(name: string): HTMLInputElement {
    return this.querySelector(`#set-form [name="${name}"]`) as HTMLInputElement;
  }

  private readControls(): Settings {
    const textSel = this.querySelector('#set-form [name="text_size"]') as HTMLSelectElement;
    const text = textSel.value;
    const text_size: Settings["a11y"]["text_size"] =
      text === "large" || text === "larger" ? text : "normal";
    const ram = Number(this.input("ram_cache_cap_mb").value);
    return {
      a11y: {
        reduced_motion: this.input("reduced_motion").checked,
        high_contrast: this.input("high_contrast").checked,
        text_size,
      },
      behavior: { confirm_destructive: this.input("confirm_destructive").checked },
      performance: { ram_cache_cap_mb: Number.isFinite(ram) ? ram : DEFAULTS.performance.ram_cache_cap_mb },
      connection: { use_tor: this.input("use_tor").checked },
    };
  }

  private writeControls(s: Settings): void {
    this.input("reduced_motion").checked = s.a11y.reduced_motion;
    this.input("high_contrast").checked = s.a11y.high_contrast;
    (this.querySelector('#set-form [name="text_size"]') as HTMLSelectElement).value = s.a11y.text_size;
    this.input("ram_cache_cap_mb").value = String(s.performance.ram_cache_cap_mb);
    this.input("confirm_destructive").checked = s.behavior.confirm_destructive;
    this.input("use_tor").checked = s.connection.use_tor;
  }

  private async saveFromControls() {
    const status = this.querySelector("#set-status")!;
    const next: Settings = this.readControls();
    try {
      const norm = await call<Settings>("set_settings", { settings: next });
      applySettings(norm);
      this.writeControls(norm); // reflect clamping back into the form
      status.textContent = "Saved.";
    } catch (x) {
      status.textContent = errMsg(x, "Could not save settings.");
    }
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
