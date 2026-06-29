import { Router } from "../core/router.ts";
import { on } from "../core/rpc.ts";
import { getUsername } from "../core/session.ts";
import "./status-pill.ts";
import "./connect-screen.ts";
import "./bootstrap-screen.ts";
import "./pending-screen.ts";
import "./admin-screen.ts";
import "./feed-screen.ts";
import "./media-viewer.ts";
import "./upload-screen.ts";
import "./upload-tray.ts";
import "./settings-screen.ts";
import { loadAndApplySettings } from "../core/settings.ts";
import type { StatusPill } from "./status-pill.ts";
import type { ConnState } from "../core/types.ts";

export class AppShell extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `
      <header role="banner">
        <nav role="navigation" aria-label="Primary">
          <a href="#/feed">Feed</a> &middot; <span>My Content</span> &middot; <a href="#/upload">Upload</a> &middot; <a href="#/admin">Admin</a> &middot; <a href="#/settings">Settings</a>
        </nav>
        <status-pill id="pill"></status-pill>
        <upload-tray></upload-tray>
      </header>
      <div id="outlet"></div>`;
    // Apply persisted a11y prefs at startup, regardless of the current route.
    void loadAndApplySettings();
    const outlet = this.querySelector("#outlet")!;
    const pill = this.querySelector("#pill") as StatusPill;
    new Router((r) => {
      if (r === "pending") {
        // Build via the DOM (not innerHTML) so the username goes into an
        // attribute, never parsed as markup.
        const el = document.createElement("pending-screen");
        el.setAttribute("username", getUsername());
        outlet.replaceChildren(el);
      } else {
        outlet.innerHTML = r === "feed"
          ? "<feed-screen></feed-screen>"
          : r === "viewer"
          ? "<media-viewer></media-viewer>"
          : r === "upload"
          ? "<upload-screen></upload-screen>"
          : r === "settings"
          ? "<settings-screen></settings-screen>"
          : r === "admin"
          ? "<admin-screen></admin-screen>"
          : r === "bootstrap"
          ? "<bootstrap-screen></bootstrap-screen>"
          : "<connect-screen></connect-screen>";
      }
      // WCAG 2.4.3: the old content (incl. the focused control) was just
      // removed; move focus to the new screen's main landmark so focus order
      // is preserved and screen readers land on the new view.
      const main = outlet.querySelector<HTMLElement>("#main");
      main?.focus();
    });
    on<ConnState>("maxsecu://connection-state", (s) => { pill.state = s.state; });
  }
}
customElements.define("app-shell", AppShell);
