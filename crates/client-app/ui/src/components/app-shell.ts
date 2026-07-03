import { Router, type Route } from "../core/router.ts";
import { call, on } from "../core/rpc.ts";
import { getUsername } from "../core/session.ts";
import "./status-pill.ts";
import "./connect-screen.ts";
import "./recovery-login-screen.ts";
import "./register-screen.ts";
import "./bootstrap-screen.ts";
import "./pending-screen.ts";
import "./admin-screen.ts";
import "./feed-screen.ts";
import "./media-viewer.ts";
import "./upload-screen.ts";
import "./upload-tray.ts";
import "./share-tray.ts";
import "./settings-screen.ts";
import "./ram-gauge.ts";
import "./toast-host.ts";
import "./trust-alarm.ts";
import "./skeleton-card.ts";
import { loadAndApplySettings, bindDocumentToSettings } from "../core/settings.ts";
import { activeTasks } from "../core/tasks.ts";
import { subscribeBusy, isBusy } from "../core/busy.ts";
import type { StatusPill } from "./status-pill.ts";
import type { ConnState } from "../core/types.ts";

const NAV: Array<{ route: Route; label: string }> = [
  { route: "feed", label: "Feed" },
  { route: "mine", label: "My Content" },
  { route: "upload", label: "Upload" },
  { route: "admin", label: "Admin" },
  { route: "settings", label: "Settings" },
];

export class AppShell extends HTMLElement {
  connectedCallback() {
    const links = NAV.map(
      (n) => `<a href="#/${n.route}" data-route="${n.route}">${n.label}</a>`,
    ).join("");
    this.innerHTML = `
      <header role="banner" class="app-header">
        <div class="app-brand" aria-label="MaxSecu">
          <span class="app-brand-mark" aria-hidden="true">◆</span>
          <span>MaxSecu <small>secure media</small></span>
        </div>
        <nav role="navigation" aria-label="Primary" class="nav-rail">${links}</nav>
        <div class="header-actions">
          <ram-gauge id="ram"></ram-gauge>
        </div>
        <div class="status-strip" role="region" aria-label="Status">
          <status-pill id="pill"></status-pill>
          <span id="sync-ind" class="sync-ind" role="status" aria-live="polite">Zero-knowledge session</span>
          <span id="tasks-ind" class="tasks-ind" role="status" aria-live="polite">No active tasks</span>
        </div>
        <div class="tray-stack">
          <upload-tray></upload-tray>
          <share-tray></share-tray>
        </div>
      </header>
      <toast-host></toast-host>
      <trust-alarm></trust-alarm>
      <div id="outlet"></div>`;

    void loadAndApplySettings();
    bindDocumentToSettings();

    const outlet = this.querySelector("#outlet")!;
    const pill = this.querySelector("#pill") as StatusPill;
    const nav = this.querySelector(".nav-rail") as HTMLElement;

    // Navigation guard: while a transcode/upload is in flight the nav rail is
    // disabled (visually + functionally) and closing the tab/window warns. The
    // router (see router.ts) independently refuses hash changes; blocking the
    // click here also stops keyboard Enter on a focused link. Focus is NOT
    // trapped — links stay focusable, only their activation is suppressed.
    nav.addEventListener("click", (e) => {
      if (isBusy()) e.preventDefault();
    });
    subscribeBusy((busy) => {
      nav.querySelectorAll<HTMLAnchorElement>("a").forEach((a) => {
        a.toggleAttribute("aria-disabled", busy);
        a.classList.toggle("nav-disabled", busy);
      });
      window.onbeforeunload = busy
        ? (e: BeforeUnloadEvent) => {
          e.preventDefault();
          e.returnValue = "";
          return "";
        }
        : null;
    });

    new Router((incomingRoute) => {
      let r = incomingRoute;
      const hasSession = getUsername().trim().length > 0;
      const publicRoute = r === "connect" || r === "bootstrap" || r === "recovery"
        || r === "register";
      if (!hasSession && !publicRoute) {
        r = "connect";
        if (location.hash !== "#/connect") history.replaceState(null, "", "#/connect");
      }

      const showAppChrome = hasSession && r !== "connect" && r !== "bootstrap"
        && r !== "pending" && r !== "recovery" && r !== "register";
      this.toggleAttribute("data-app-chrome", showAppChrome);
      this.querySelectorAll<HTMLAnchorElement>(".nav-rail a").forEach((a) => {
        const isActive = showAppChrome && (a.getAttribute("data-route") === r
          || (r === "mine" && a.getAttribute("data-route") === "mine"));
        a.toggleAttribute("aria-current", isActive);
        a.classList.toggle("active", isActive);
      });

      if (r === "pending") {
        const el = document.createElement("pending-screen");
        el.setAttribute("username", getUsername());
        outlet.replaceChildren(el);
      } else if (r === "mine") {
        const el = document.createElement("feed-screen");
        el.setAttribute("mine", "");
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
          : r === "recovery"
          ? "<recovery-login-screen></recovery-login-screen>"
          : r === "register"
          ? "<register-screen></register-screen>"
          : "<connect-screen></connect-screen>";
      }
      const main = outlet.querySelector<HTMLElement>("#main");
      main?.focus();
    });

    // Startup precedence (spec §0-D7): on a fresh launch route to the recovery
    // panel if a cold recovery keyblob sits beside the exe, else the register panel
    // if a single-use registration key is present, else leave the normal connect
    // landing. Only the INITIAL screen follows this order — the user can navigate
    // elsewhere afterwards, and an explicit deep-link/reload to a non-landing hash
    // is respected. Fire-and-forget: any failure falls safe to the connect landing.
    void this.applyStartupMode();

    on<ConnState>("maxsecu://connection-state", (s) => { pill.state = s.state; });

    const tasksInd = this.querySelector("#tasks-ind") as HTMLElement;
    activeTasks.subscribe((n) => {
      tasksInd.textContent = n === 0 ? "No active tasks" : `${n} active task${n === 1 ? "" : "s"}`;
    });
  }

  // Route the initial screen by startup precedence (recovery → register → normal).
  // Only overrides the default connect landing; an explicit route (reload/deep-link)
  // is left untouched so the gate never hijacks in-app navigation.
  private async applyStartupMode() {
    const isLanding = () =>
      location.hash === "" || location.hash === "#/" || location.hash === "#/connect";
    if (!isLanding()) return;
    try {
      const mode = await call<string>("startup_mode");
      // The command is async; the user may have navigated away (or a deep-link may
      // have set the hash) while it was in flight. Re-check BEFORE overriding so a
      // stale startup mode never hijacks an intentional in-app navigation.
      if (!isLanding()) return;
      if (mode === "recovery") location.hash = "#/recovery";
      else if (mode === "register") location.hash = "#/register";
      // "normal" → keep the default connect landing.
    } catch {
      // Fail safe: stay on the normal connect landing on any error.
    }
  }
}
customElements.define("app-shell", AppShell);
