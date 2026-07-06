// Post-bundle copy step: place index.html, the pre-paint bootstrap, every frontend
// stylesheet, and the pizza asset into dist/ (which the Tauri exe embeds at compile
// time). boot.js is a separate same-origin file because the app CSP blocks inline JS.
import { copyFileSync, mkdirSync } from "node:fs";

mkdirSync("dist/assets", { recursive: true });

for (const f of ["index.html", "boot.js", "styles.css", "styles.pizza.css", "styles.slot3.css"]) {
  copyFileSync(f, `dist/${f}`);
}
copyFileSync("assets/pizza.png", "dist/assets/pizza.png");

console.log("copied: index.html + boot.js + 3 stylesheets + assets/pizza.png -> dist/");
