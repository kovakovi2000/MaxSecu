/* Apply the persisted frontend before first paint (no flash). Runs as a same-origin
   classic script — the app CSP (default-src 'self', no script-src) blocks INLINE JS,
   so this must stay an external file. Mirrors STYLESHEETS in src/core/frontends.ts. */
(function () {
  try {
    var f = localStorage.getItem("maxsecu.frontend");
    var map = { "default": "styles.css", "pizza": "styles.pizza.css", "slot3": "styles.slot3.css" };
    if (f && map[f]) {
      document.documentElement.setAttribute("data-frontend", f);
      var l = document.getElementById("frontend-css");
      if (l) l.setAttribute("href", map[f]);
    }
  } catch (e) { /* storage unavailable — keep default */ }
})();
