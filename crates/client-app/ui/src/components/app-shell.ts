import { Router } from "../core/router.ts";
import { on } from "../core/rpc.ts";
import "./status-pill.ts";
import "./connect-screen.ts";
import "./feed-empty.ts";
import type { StatusPill } from "./status-pill.ts";
import type { ConnState } from "../core/types.ts";

export class AppShell extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `
      <header role="banner">
        <nav role="navigation" aria-label="Primary">
          <a href="#/feed">Feed</a> &middot; <span>My Content</span> &middot; <span>Upload</span> &middot; <span>Admin</span> &middot; <span>Settings</span>
        </nav>
        <status-pill id="pill"></status-pill>
      </header>
      <div id="outlet"></div>`;
    const outlet = this.querySelector("#outlet")!;
    const pill = this.querySelector("#pill") as StatusPill;
    new Router((r) => {
      outlet.innerHTML = r === "feed"
        ? "<feed-empty></feed-empty>"
        : "<connect-screen></connect-screen>";
    });
    on<ConnState>("maxsecu://connection-state", (s) => { pill.state = s.state; });
  }
}
customElements.define("app-shell", AppShell);
