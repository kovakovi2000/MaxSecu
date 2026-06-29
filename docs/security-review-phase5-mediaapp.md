# Phase 5 (Media App) — Security Review & Sign-off (Settings + Accessibility)

**Scope:** the Phase-5 change set on branch `media-app` — commit range `c7109ea..HEAD` (`c7109ea` = the Phase-4 baseline). Phase 5 adds the Settings screen + ⚡ Quick-settings popover (Account / Connection / Performance / Behavior / Accessibility / Privacy), persisted to `<dir>/config/settings.json`; applies the accessibility options live; provides the ceremony-free account actions (change password, export the portable keystore); and adds an automated accessibility check to CI.

**Method:** TDD, subagent-driven on Opus, per-task two-stage review (the security-sensitive `change_password` got a dedicated security review), all findings fixed before acceptance, plus a final holistic review. Verification artifacts: the config + keystore unit tests; the UI a11y structural lint (`crates/client-app/ui/src/a11y.test.ts`, 22 checks); and the green gate suite (client-app clippy `-D warnings`, `cargo deny`, `cargo audit`, `MAXSECU_PG_OPTIONAL=1 cargo test --workspace`, UI typecheck + build + `npm test` + `npm run test:a11y`).

**Verdict:** **PASS** — no Critical, High, or Medium findings. Phase 5 has **no server interaction, no new server endpoints, and no `client-core` change**; settings are non-secret local preferences and the only sensitive action (`change_password`) is fail-closed, atomic, identity-confined, and zeroized. Documented residuals (§4) are security-neutral.

---

## 1. What Phase 5 added (and did not)

- **No server change, no client-core change.** Settings are local `client-app` config + UI; the account actions reuse the existing `client-core::keyblob` (`reseal`/`unlock`/`seal`). No new route, no new crypto.
- **`client-app`:** `SettingsConfig` (`config.rs`, JSON at `<dir>/config/settings.json`, with a `normalized()` clamp); `keystore::{change_password, export_keystore}`; commands `get_settings`/`set_settings`/`change_password`/`export_keystore`.
- **UI:** `core/settings.ts` (apply data-attrs + load-on-boot), `styles.css` (a11y rules), `<settings-screen>`, `<quick-settings>`, and the a11y structural lint.

## 2. Per-area findings & dispositions

| # | Area | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | **Settings hold no secret** | **Sound (✓).** `settings.json` carries only non-secret preferences (`a11y{reduced_motion,high_contrast,text_size}`, `behavior{confirm_destructive}`, `performance{ram_cache_cap_mb}`, `connection{use_tor}`) — no password, key, token, or KDF parameter. Safe to persist in cleartext. `normalized()` clamps untrusted (hand-edited) values (RAM cap to 16–4096; `text_size` to a whitelist) on both load and save, so a tampered file cannot inject an out-of-range value. | Info | Accepted (correct). |
| 2 | **`change_password`** | **Sound (✓).** Re-seals the at-rest blob via `keyblob::reseal`, which internally `unlock(old)?` (so a wrong old password fails closed → mapped to `unauthorized`) then `seal(new)`. The new-password strength is checked **first** (`weak_password`) before the blob is read or written. The new blob is written to a sibling temp file and `rename`d over the original — an atomic replace, so any failure (wrong old, weak new, write error) leaves the **original blob intact** (proven by the test that the original password still unlocks after a rejected change). The `Identity` is created and dropped entirely inside `reseal`; it never crosses the command boundary. Both passwords are `zeroize::Zeroizing` at the command and never logged/returned (the command returns `()`). | Info | Accepted (correct). |
| 3 | **`export_keystore`** | **Sound (✓).** Copies the **already-Argon2id-sealed** `local_key_blob` (ciphertext) to a user-chosen path — the portable backup / recovery path. It never calls `unlock`/decrypt; only raw bytes are read and written. The UI shows an explicit "back this up securely — only as safe as your password" warning. | Info | Accepted (correct). |
| 4 | **Settings round-trip + clamping** | **Sound (✓).** `set_settings` persists the `normalized()` value and returns it; the UI applies it and writes the (possibly clamped) value back into the controls, so the displayed state never diverges from what was stored. `applySettings` sets `data-reduced-motion`/`data-high-contrast`/`data-text-size` on `<html>`; `styles.css` keys on those attributes only (no untrusted data influences styles). | Info | Accepted (correct). |
| 5 | **UI / TCB boundary** | **Sound (✓).** Only non-secret DTOs cross the seam. Passwords flow UI → command (`Zeroizing`) → `keystore` and are cleared from the inputs on success; no password is logged or written to the DOM. Dynamic content is rendered via `textContent`/`createElement`; the single innerHTML interpolation in `bootstrap-screen` (the one-time glass-break creds dialog, Phase 2) is HTML-escaped via `esc(...)` and is asserted-safe by the a11y lint's XSS guard (which permits `${esc(` and flags any unescaped interpolation). | Info | Accepted (correct). |
| 6 | **Accessibility (WCAG 2.1 AA)** | **Sound (✓).** Reduced-motion (explicit setting **and** the OS `prefers-reduced-motion`), high-contrast, and scalable text-size are applied live; `:focus-visible` gives always-visible keyboard focus; `loadAndApplySettings()` runs on app-shell boot so prefs apply at startup regardless of route. Every routed screen has a focusable `main` landmark, on-mount focus, labelled controls, and a `role="status"`/`aria-live` feedback region — guarded against regression by the `a11y.test.ts` structural lint (22 checks, dependency-free `node:test`). The Quick-settings popover has `aria-expanded`/`aria-controls`, Esc-to-close with focus return, and labelled toggles. | Info | Accepted (correct). |
| 7 | **Sanitized errors** | **Sound (✓).** Every command returns a stable sanitized `UiError` code (`settings_failed`/`unauthorized`/`weak_password`/`no_keystore`/`export_failed`); no path/crypto/password detail leaks. | Info | Accepted (correct). |

## 3. Threat-model coverage (Phase-5-relevant)

- **Secret leak via settings persistence:** closed — settings hold no secret.
- **Keystore corruption on a failed password change:** closed — atomic temp-then-rename; original intact on any failure (tested).
- **Wrong-old-password oracle / silent acceptance:** closed — `reseal`→`unlock(old)` fails closed to `unauthorized`; a weak new password is rejected before any write.
- **Key/identity leak across the UI seam:** closed — the identity is confined to `reseal`; `export_keystore` copies ciphertext only; passwords are zeroized and never returned.
- **Tampered settings file:** mitigated — `normalized()` clamps out-of-range/invalid values on load.
- **XSS via settings or other UI:** closed — `textContent` rendering; the only escaped-innerHTML path is HTML-escaped and lint-guarded; a11y CSS keys on data-attrs only.

## 4. Residuals / deferrals (intentional, security-neutral)

- **Real Tor transport** — the toggle is a disabled placeholder (Phase-1 deferral).
- **Shamir K-of-N recovery UI** (`admin-core::recovery`) — an ops ceremony; `export_keystore` is the Phase-5 portable-backup path.
- **Full axe-core-in-jsdom a11y check** — the components import the Tauri API, so a full DOM render needs a Tauri-API mock + jsdom harness; the dependency-free structural lint is the Phase-5 CI guard.
- **RAM-cache cap enforcement** — Phase 5 persists the preference; wiring it to an actual bounded in-memory cache is a later perf slice (no client-side blob cache exists yet to bound).
- **Cosmetic:** `change_password` maps a (rare) corrupt-blob `reseal` error to `unauthorized` rather than a distinct corruption code; a leftover `local_key_blob.tmp` is not cleaned up on a `rename` failure (keystore ops are non-concurrent). Neither affects security.
- **Optional fold-in:** the Phase-4 UI-polish follow-ups (wire `upload_jobs`/`cancel_upload` into the tray; drop the dead `Encrypting` variant; cap staged jobs) remain tracked.

## 5. Conclusion

**PASS.** Phase 5 keeps the zero-knowledge model intact: it adds no server interaction and no crypto; settings are non-secret local preferences; the password change re-seals the at-rest identity entirely within the client TCB, fail-closed and atomic with the identity never crossing the boundary; the keystore export copies ciphertext only; and the accessibility layer meets WCAG 2.1 AA with an automated CI guard. No Critical/High/Medium issues; the residuals are documented and security-neutral.
