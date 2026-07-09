/* Apply the persisted frontend before first paint (no flash). Runs as a same-origin
   classic script — the app CSP (default-src 'self', no script-src) blocks INLINE JS,
   so this must stay an external file. The skin id is injected by the Rust host via an
   initialization script (window.__MAXSECU_BOOT__.frontend, sourced from settings.json).
   A legacy localStorage value is the one-version migration fallback.
   Mirrors STYLESHEETS in src/core/frontends.ts. */
(function () {
  try {
    var boot = window.__MAXSECU_BOOT__ || {};
    var f = boot.frontend;
    if (!f) {
      try { f = localStorage.getItem("maxsecu.frontend"); } catch (e) { /* unavailable */ }
    }
    var map = { "default": "styles.css", "pizza": "styles.pizza.css", "slot3": "styles.slot3.css" };
    if (f && map[f]) {
      document.documentElement.setAttribute("data-frontend", f);
      var l = document.getElementById("frontend-css");
      if (l) l.setAttribute("href", map[f]);
    }
  } catch (e) { /* keep default */ }
})();
