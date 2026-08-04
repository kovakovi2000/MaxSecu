import { Router, type Route } from "../core/router.ts";
import { call, on } from "../core/rpc.ts";
import { clearPrincipal, getPrincipalKind, hasPrincipal } from "../core/session.ts";
// The recovery route gate lives in core/ so it is unit-testable — this module
// imports Tauri (via core/rpc.ts) and cannot be loaded in plain Node. `admin` is
// deliberately NOT gated: a recovery session really can mint a registration key.
// See core/recovery-routes.ts for the end-to-end citation chain.
import { isRouteHiddenFor } from "../core/recovery-routes.ts";
import "./status-pill.ts";
import "./connect-screen.ts";
import "./recovery-login-screen.ts";
import "./register-screen.ts";
import "./admin-screen.ts";
import "./feed-screen.ts";
import "./media-viewer.ts";
import "./bundle-screen.ts";
import "./upload-screen.ts";
import "./upload-tray.ts";
import "./share-tray.ts";
import "./settings-screen.ts";
import "./ram-gauge.ts";
import "./toast-host.ts";
import "./trust-alarm.ts";
import "./skeleton-card.ts";
import { loadAndApplySettings, bindDocumentToSettings } from "../core/settings.ts";
import { refreshFrontendDeco } from "../core/frontends.ts";
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
      <div data-deco-slot="app-bg" aria-hidden="true"></div>
      <header role="banner" class="app-header">
        <div class="app-brand" aria-label="MaxSecu">
          <span class="app-brand-mark" aria-hidden="true">◆</span>
          <span>MaxSecu <small>secure media</small></span>
        </div>
        <nav role="navigation" aria-label="Primary" class="nav-rail">${links}</nav>
        <div class="header-actions">
          <span data-deco-slot="header" aria-hidden="true"></span>
          <ram-gauge id="ram"></ram-gauge>
        </div>
      </header>
      <div id="recovery-banner" class="recovery-banner" role="status" aria-live="polite" hidden>
        <strong class="rb-label">RECOVERY SESSION</strong>
        <span class="rb-copy">Signed in with the cold recovery key — you can see, open and download everyone's content, and you can invite a new user from Admin. You cannot post or delete, and sharing is not available from a recovery session.</span>
        <button id="rb-end" type="button" class="danger">End recovery session</button>
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
      <div id="busy-overlay" class="busy-overlay" role="status" aria-live="polite" hidden>
        <span class="busy-kicker">Active task</span>
        <strong id="busy-title">Working…</strong>
        <small>Keep this window open until it finishes.</small>
      </div>
      <toast-host></toast-host>
      <trust-alarm></trust-alarm>
      <div id="outlet"></div>`;

    void loadAndApplySettings();
    bindDocumentToSettings();

    const outlet = this.querySelector("#outlet")!;
    const pill = this.querySelector("#pill") as StatusPill;
    const nav = this.querySelector(".nav-rail") as HTMLElement;
    const header = this.querySelector(".app-header") as HTMLElement;
    const busyOverlay = this.querySelector("#busy-overlay") as HTMLElement;
    const busyTitle = this.querySelector("#busy-title") as HTMLElement;
    const busyKicker = this.querySelector(".busy-kicker") as HTMLElement;
    const recoveryBanner = this.querySelector("#recovery-banner") as HTMLElement;
    const recoveryEnd = this.querySelector("#rb-end") as HTMLButtonElement;
    const syncInd = this.querySelector("#sync-ind") as HTMLElement;

    const syncHeaderHeight = () => {
      this.style.setProperty("--mx-header-height", `${Math.ceil(header.getBoundingClientRect().height)}px`);
    };
    syncHeaderHeight();
    if (typeof ResizeObserver !== "undefined") {
      const ro = new ResizeObserver(syncHeaderHeight);
      ro.observe(header);
    }
    window.addEventListener("resize", syncHeaderHeight);

    // Navigation guard: while a transcode/upload is in flight the nav rail is
    // disabled (visually + functionally) and closing the tab/window warns. The
    // router (see router.ts) independently refuses hash changes; blocking the
    // click here also stops keyboard Enter on a focused link. Focus is NOT
    // trapped — links stay focusable, only their activation is suppressed.
    nav.addEventListener("click", (e) => {
      if (isBusy()) e.preventDefault();
    });
    subscribeBusy((busy, reason) => {
      nav.querySelectorAll<HTMLAnchorElement>("a").forEach((a) => {
        a.toggleAttribute("aria-disabled", busy);
        a.classList.toggle("nav-disabled", busy);
      });
      busyOverlay.hidden = !busy;
      if (busy) {
        const label = reason.toLowerCase().includes("upload") ? "Active upload" : "Active task";
        busyKicker.textContent = label;
        busyTitle.textContent = reason || "Working…";
      }
      window.onbeforeunload = busy
        ? (e: BeforeUnloadEvent) => {
          e.preventDefault();
          e.returnValue = "";
          return "";
        }
        : null;
    });

    const applyRoute = (incomingRoute: Route) => {
      let r = incomingRoute;
      const hasSession = hasPrincipal();
      const kind = getPrincipalKind();
      const isRecovery = kind === "recovery";
      const publicRoute = r === "connect" || r === "recovery" || r === "register";
      if (!hasSession && !publicRoute) {
        r = "connect";
        if (location.hash !== "#/connect") history.replaceState(null, "", "#/connect");
      }
      // Same shape as the not-signed-in redirect above: hiding the nav links does
      // not stop a manual hash, a stale deep-link or the back button, so a
      // recovery principal is bounced off its dead-end routes onto the feed.
      if (isRouteHiddenFor(kind, r)) {
        r = "feed";
        if (location.hash !== "#/feed") history.replaceState(null, "", "#/feed");
      }

      const showAppChrome = hasSession && r !== "connect"
        && r !== "recovery" && r !== "register";
      this.toggleAttribute("data-app-chrome", showAppChrome);
      // A recovery session must never be mistaken for an ordinary one: a
      // persistent banner (not a toast) plus a reworded resting status line, and
      // an attribute the skins can hook. The banner stays visible on EVERY route
      // while the principal is recovery, so "End recovery session" is always
      // one click away.
      this.toggleAttribute("data-principal-recovery", isRecovery);
      recoveryBanner.hidden = !isRecovery;
      // Assign only on a real change: #sync-ind is an aria-live region, and
      // rewriting its text node on every route change can make a screen reader
      // re-announce identical text. At HEAD it was written once, at first render.
      const syncText = isRecovery
        ? "Recovery session — view + invite"
        : "Zero-knowledge session";
      if (syncInd.textContent !== syncText) syncInd.textContent = syncText;
      this.querySelectorAll<HTMLAnchorElement>(".nav-rail a").forEach((a) => {
        const route = a.getAttribute("data-route") as Route;
        a.hidden = isRouteHiddenFor(kind, route);
        const isActive = showAppChrome && (route === r
          || (r === "mine" && route === "mine"));
        a.toggleAttribute("aria-current", isActive);
        a.classList.toggle("active", isActive);
      });

      if (r === "mine") {
        const el = document.createElement("feed-screen");
        el.setAttribute("mine", "");
        outlet.replaceChildren(el);
      } else {
        outlet.innerHTML = r === "feed"
          ? "<feed-screen></feed-screen>"
          : r === "viewer"
          ? "<media-viewer></media-viewer>"
          : r === "bundle"
          ? "<bundle-screen></bundle-screen>"
          : r === "upload"
          ? "<upload-screen></upload-screen>"
          : r === "settings"
          ? "<settings-screen></settings-screen>"
          : r === "admin"
          ? "<admin-screen></admin-screen>"
          : r === "recovery"
          ? "<recovery-login-screen></recovery-login-screen>"
          : r === "register"
          ? "<register-screen></register-screen>"
          : "<connect-screen></connect-screen>";
      }
      const main = outlet.querySelector<HTMLElement>("#main");
      main?.focus();
      refreshFrontendDeco();
    };
    new Router(applyRoute);

    // "End recovery session": tell the backend to tear the session down —
    // `end_recovery_session` (NOT the plain `logout`) is what also drops the
    // parked authenticated channel and zeroizes the cold recovery Identity — then
    // forget the UI-side principal and return to the recovery gate. The local
    // teardown runs even if the backend call rejects, so the UI can never be left
    // claiming a session the user asked to end.
    recoveryEnd.addEventListener("click", async () => {
      recoveryEnd.disabled = true;
      try {
        await call("end_recovery_session");
      } catch {
        // Best-effort: the Rust side tears down locally regardless.
      }
      clearPrincipal();
      // Setting an unchanged hash fires no hashchange, so re-render directly when
      // we are already on the recovery gate.
      if (location.hash === "#/recovery") applyRoute("recovery");
      else location.hash = "#/recovery";
      recoveryEnd.disabled = false;
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
