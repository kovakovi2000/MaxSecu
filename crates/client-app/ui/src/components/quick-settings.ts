import { call } from "../core/rpc.ts";
import { applySettings } from "../core/settings.ts";
import type { Settings } from "../core/types.ts";

// ⚡ Quick-settings popover (spec §5): the most-used a11y/behavior toggles with
// instant apply. Accessible: the trigger has aria-expanded/aria-controls; the
// popover is keyboard-dismissible (Esc) and focus-managed; all toggles labelled.
export class QuickSettings extends HTMLElement {
  private open = false;
  private current: Settings | null = null;

  connectedCallback() {
    this.innerHTML = `
      <div class="qs">
        <button id="qs-btn" aria-expanded="false" aria-controls="qs-pop" aria-haspopup="true" title="Quick settings">⚡</button>
        <div id="qs-pop" role="group" aria-label="Quick settings" hidden></div>
      </div>`;
    const btn = this.querySelector("#qs-btn") as HTMLButtonElement;
    btn.addEventListener("click", () => this.toggle());
    // Esc closes the popover and returns focus to the trigger.
    this.addEventListener("keydown", (e) => {
      if ((e as KeyboardEvent).key === "Escape" && this.open) {
        this.close();
        btn.focus();
      }
    });
  }

  private async toggle() {
    if (this.open) { this.close(); return; }
    // Load current settings when opening so the toggles reflect reality.
    try { this.current = await call<Settings>("get_settings"); } catch { this.current = null; }
    this.renderPopover();
    this.open = true;
    const pop = this.querySelector("#qs-pop") as HTMLElement;
    const btn = this.querySelector("#qs-btn") as HTMLButtonElement;
    pop.hidden = false;
    btn.setAttribute("aria-expanded", "true");
    // Move focus to the first control for keyboard users.
    (pop.querySelector("input,select,button") as HTMLElement | null)?.focus();
  }

  private close() {
    this.open = false;
    const pop = this.querySelector("#qs-pop") as HTMLElement;
    const btn = this.querySelector("#qs-btn") as HTMLButtonElement;
    pop.hidden = true;
    btn.setAttribute("aria-expanded", "false");
  }

  private renderPopover() {
    const s = this.current ?? defaults();
    const pop = this.querySelector("#qs-pop") as HTMLElement;
    pop.replaceChildren();

    pop.appendChild(this.checkbox(s, "Reduced motion", s.a11y.reduced_motion, (v) => { s.a11y.reduced_motion = v; }));
    pop.appendChild(this.checkbox(s, "High contrast", s.a11y.high_contrast, (v) => { s.a11y.high_contrast = v; }));

    // Text size select.
    const tl = document.createElement("label");
    tl.textContent = "Text size ";
    const sel = document.createElement("select");
    for (const opt of ["normal", "large", "larger"] as const) {
      const o = document.createElement("option");
      o.value = opt; o.textContent = opt;
      if (s.a11y.text_size === opt) o.selected = true;
      sel.appendChild(o);
    }
    sel.addEventListener("change", () => {
      const v = sel.value;
      s.a11y.text_size = (v === "large" || v === "larger") ? v : "normal";
      void this.save(s);
    });
    tl.appendChild(sel);
    pop.appendChild(tl);

    pop.appendChild(this.checkbox(s, "Confirm destructive actions", s.behavior.confirm_destructive, (v) => { s.behavior.confirm_destructive = v; }));

    // Tor (disabled placeholder).
    const torLabel = document.createElement("label");
    const tor = document.createElement("input");
    tor.type = "checkbox"; tor.disabled = true; tor.checked = s.connection.use_tor;
    torLabel.append(tor, document.createTextNode(" Route over Tor (later)"));
    pop.appendChild(torLabel);

    pop.appendChild(this.status());
  }

  private checkbox(s: Settings, labelText: string, checked: boolean, set: (v: boolean) => void): HTMLLabelElement {
    const label = document.createElement("label");
    const box = document.createElement("input");
    box.type = "checkbox"; box.checked = checked;
    box.addEventListener("change", () => { set(box.checked); void this.save(s); });
    label.append(box, document.createTextNode(` ${labelText}`));
    return label;
  }

  private status(): HTMLParagraphElement {
    const p = document.createElement("p");
    p.id = "qs-status"; p.setAttribute("role", "status"); p.setAttribute("aria-live", "polite");
    return p;
  }

  private async save(s: Settings) {
    const status = this.querySelector("#qs-status");
    try {
      const norm = await call<Settings>("set_settings", { settings: s });
      this.current = norm;
      applySettings(norm);
      if (status) status.textContent = "Saved.";
    } catch (x) {
      if (status) status.textContent = errMsg(x, "Could not save.");
    }
  }
}

function defaults(): Settings {
  return { a11y: { reduced_motion: false, high_contrast: false, text_size: "normal" }, behavior: { confirm_destructive: false }, performance: { ram_cache_cap_mb: 256 }, connection: { use_tor: false } };
}
function errMsg(x: unknown, fallback: string): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return fallback;
}

customElements.define("quick-settings", QuickSettings);
