# Universal Video Ingest — Holistic Security Review & Sign-off

**Scope:** the full **Universal Video Ingest** feature on branch `feat/universal-video-ingest` — commit range `e4ccf0f..HEAD` (24 commits: design + Phase-0 ratification, D-1..D-7 implementation, per-task review fixes, and the capstone e2e). The feature lets the media app **ingest essentially any common video file** (H.264/H.265/VP9/AV1/MPEG-4/… in mp4/mov/mkv/webm/avi/…, with audio) and transcode it to the single canonical **AV1 + AAC-LC / chunk-aligned CMAF** format the viewer already decodes — so a real clip uploads and plays back **with sound**. It closes the Phase-7 media-app R1 (audio) / R2 (real ffmpeg ingest) residuals.

**Companion to / builds on:** `docs/superpowers/specs/2026-06-30-universal-video-ingest-design.md` (§9 security, §11 testing, §12 residuals), `docs/superpowers/ratification/2026-06-30-universal-video-ingest-ratification.md` (the HARD-GATE Phase-0 spike: ffmpeg pin, argv, Fork X, caps), `docs/security-review-phase7-mediaapp.md` (the sandboxed-video decode model this extends), and `docs/media-sandbox.md` (the decode-isolation model).

**Method:** this is an **independent verification** that (a) the design's threat-model claims hold in the committed code, and (b) every fix flagged by the per-task security reviews actually landed. Cross-cutting invariants were re-checked with commands run in-turn on the project's Windows 11 / MSVC host; the actual outputs are quoted. Codec-internal facts are inherited from the security-reviewed-before-adoption Phase-7 codec ratification (the view path is unchanged: `rav1d`/`symphonia`).

**Verdict:** **PASS — no Critical, High, or Medium finding open against the committed path.** Running a large C decoder (ffmpeg) on attacker-authored bytes is the system's **#1 RCE surface**; this feature keeps it — and the viewer's `rav1d`/`symphonia` decode — **structurally out of the key-holding process**: ffmpeg runs only inside the proven capability-free AppContainer + Job Object (no network, no keys, no children, memory-capped, kill-on-close), reachable only via a **scoped, RAII-revoked per-path ACL grant**; the re-mux worker is **pure-Rust, zero-`unsafe`, bounds-safe** on ffmpeg's attacker-derived output; the embedded ffmpeg is **SHA-256-pinned and verified every run**, materialized via an **atomic replace**; the key-holding `client-app` and TCB `client-core` link **none** of the codecs; supply-chain (`cargo deny` / `cargo audit`) is clean; and **every** failure collapses to a sanitized `video_failed` / `video_unavailable` with no decode oracle. The residuals (Phase-B LGPL-from-source ffmpeg, loudness normalization, >64 MiB large-source streaming, VFR / extreme-anamorphic edges, the #[ignore] capstone) are honestly recorded and are **not** security gaps in the committed path. **The sandbox contains; it does not eliminate** (a decoder 0-day *plus* an AppContainer escape would still reach the host) — which is exactly why the decoder is kept secret-less, network-less, child-less, and pinned.

---

## 1. Scope + threat model

- **The RCE surface.** ffmpeg (a large C demux/decode stack) parses **arbitrary, attacker-authored** source media. A codec 0-day there is the highest-value target in the system. The feature's non-negotiable requirement is that this decode **never** runs in the process that holds the user's identity key / plaintext / network sockets.
- **The mitigation.** ffmpeg runs as a **confined external `.exe`** inside the identical Windows confinement the Phase-7 decode worker already uses (capability-free AppContainer SID ⇒ no network *by capability*, low-IL token that cannot read the user's key blob; Job Object with `ActiveProcessLimit=1` ⇒ no child processes, a hard `ProcessMemoryLimit`, `KILL_ON_JOB_CLOSE`, bounded-wait-then-force-kill). Its filesystem reach is scoped to exactly one per-job directory via a merged, RAII-revoked DACL ACE. Its media output goes to a **file** (never stdio); stdin/stdout are `NUL`; stderr is a bounded (64 KiB) diagnostic capture.
- **The second boundary.** ffmpeg's *output* mp4 is itself attacker-derived (it is a transform of attacker input). It is re-muxed into the canonical fragment layout by a **separate** pure-Rust, `unsafe`-denied worker whose ISO-BMFF parsing is bounds-safe and fail-closed. The viewer then decodes the canonical fragments with the unchanged, confined `rav1d`/`symphonia` decode worker.
- **Trust seam.** Only `TranscodeOptions` / progress / preview DTOs cross the Tauri seam; keys, wraps, and plaintext never do. The decoder is structurally outside the key holder in **two** places (the confined `ffmpeg.exe`; the confined `media-worker`).

**Sandbox posture (inherited, standing):** the sandbox **contains, it does not eliminate**. A sandboxed-decoder 0-day *combined with* an AppContainer escape would still reach the host — which is why both confined processes are kept **secret-less** (a non-escaping compromise yields nothing to read or exfiltrate) and the ffmpeg binary is integrity-pinned.

---

## 2. Per-decision security analysis (D-1 .. D-7) — with the review fixes verified present

### D-1 — Embedded, integrity-pinned ffmpeg (`73f9e75` + fix `fe0bc2d`)
`crates/client-app/src/ffmpeg_bin.rs`. A prebuilt static `ffmpeg.exe` is baked in via `include_bytes!` behind the default-on `embed-ffmpeg` feature, pinned to `FFMPEG_SHA256` (`6ed7e5c9…2e0e`, matching the ratification). `ensure_ffmpeg` materializes it to `<appdir>/bin/ffmpeg-<sha8>.exe` and **hash-verifies the on-disk copy every run**, re-extracting on any mismatch (tamper / truncation). The in-binary bytes are defensively re-verified against the pin before any extraction (fail-closed if a corrupt embed ever disagreed). This removes the "attacker swaps ffmpeg.exe on PATH" vector — tampering now requires breaking the signed client binary's own integrity.

**Review fix confirmed present (atomic-replace + exclusive temp):** the extract path writes to a same-directory temp file opened with `OpenOptions::new().write(true).create_new(true)` (exclusive create — refuses to follow/truncate a planted name at the temp path), `write_all` + **`sync_all`** (flush before publish), then **`std::fs::rename(&tmp, &target)`** — on Windows this is `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`, a single-syscall atomic replace with **no remove-first absence window** and no concurrent-remove race; the tamper-recovery (re-extract) case rides the same atomic replace. A crash mid-write can only ever leave the temp file, never a half-written final exe (`ffmpeg_bin.rs:121-145`). Tests cover materialize-verified, re-extract-after-tamper, and idempotent no-rewrite.

### D-2 — Confined ffmpeg spawn + scoped path-ACL (`396035e`, `e9c7bb5`, + hardening `5914b9c`)
`crates/media-launcher/src/win32.rs`.
- **`grant_path_to_appcontainer` / `PathGrant`:** captures the path's **current** DACL + label, **merges one** allow ACE for the capability-free container SID (`SetEntriesInAclW` copies the existing ACEs — never clobbers), and for a writable workspace also applies a **Low integrity label** so the Low-IL AppContainer can write-up. The returned `PathGrant` is an RAII guard that restores the prior DACL (and prior label, if it set one) on `revoke()` **or `Drop`** — so a panicking job driver cannot leave a lingering grant on the user's filesystem. On every early-error path the SID is freed and any partial change rolled back.
- **`spawn_confined_exe` / `setup_confined_exe_child`:** the **same** capability-free AppContainer SID + `SECURITY_CAPABILITIES` and the **same** Job Object as the proven decode worker (`ActiveProcessLimit=1`, `JOB_OBJECT_LIMIT_PROCESS_MEMORY`, `KILL_ON_JOB_CLOSE`), with `stdin=NUL`, `stdout=NUL`, and stderr a bounded (`FFMPEG_STDERR_CAP_BYTES = 64 KiB`, head-kept, drained-past-cap so ffmpeg can't block) capture pipe. Media never crosses stdio (it goes to the granted file).

**Review hardening confirmed present (handle-list allow-list + configurable timeout):**
- **`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`** (`win32.rs:1204,1239-1255`): `CreateProcessW` is called with `bInheritHandles=TRUE`, so without an explicit allow-list the confined child would inherit **every** inheritable handle open in the key-holding parent — an ambient-inheritance gap across the RCE boundary. The proc-thread attribute list carries a **two-attribute** set (security capabilities + handle list) restricting inheritance to **precisely three** handles: NUL stdin, NUL stdout, and the stderr-write end. The array outlives `CreateProcessW`.
- **Configurable per-job timeout** (`finish_confined_with_timeout(guard, timeout_ms)`, `win32.rs:910-934,1432`): the ffmpeg path passes a per-job forced-kill bound (a legitimate large/long transcode can exceed the worker's fixed 2-minute wait) — generous but **always FINITE**; on `WAIT_TIMEOUT` the child is actively `TerminateProcess`'d then briefly waited on. A worker that closes output and spins within the memory cap cannot hang the trusted launcher.

**Confinement differentials (Windows, `cfg(windows)`):**
- `crates/media-launcher/tests/ffmpeg_confine_windows.rs`: `confined_transcode_succeeds_within_granted_dir` (confined ffmpeg transcodes within its grant) vs. `confined_denies_input_outside_granted_dir_while_unconfined_allows` (a non-granted-file read is **DENIED confined**, **ALLOWED unconfined** — proving the test exercises real confinement, not a universally-broken capability).
- `crates/media-launcher/tests/file_acl_windows.rs`: `read_execute_file_grant_then_revoke`, `read_write_dir_grant_label_then_revoke_via_drop` (the ACE + Low label appear on grant and are gone after revoke/Drop — the grant is scoped and self-healing).

### D-3 / D-6 — Re-mux worker on ffmpeg's attacker-derived output (`086a1ec` + fix `6439c5b`)
`crates/media-transcode-worker/` (`remux.rs`). symphonia demuxes ffmpeg's output mp4; the worker hand-re-muxes the AV1 samples into the canonical multi-sample-GOP video `trak` and copies ffmpeg's `mp4a`/`esds` audio SampleEntry **verbatim** (avoids hand-authoring the AudioSpecificConfig — the riskiest part, proven readable in the spike). ffmpeg's output is **attacker-derived**, so all parsing is bounds-safe and fail-closed; `VideoBounds` caps are enforced pre-alloc. The crate is **`unsafe`-denied crate-wide** (`Cargo.toml`: `unsafe_code = "deny"`).

**Review fix confirmed present (`box_at` hostile-`largesize` overflow):** `box_at` (`remux.rs:91-126`) computes `remaining = data.len().checked_sub(off)?`, requires `remaining >= 8` (and `>= 16` for a 64-bit `largesize`), maps an unrepresentable `largesize` to `usize::MAX`, and rejects via `if total < hdr || total > remaining` — a comparison against **remaining bytes, never an addition** (`off + total`), so a hostile `largesize` up to `u64::MAX` with `off > 0` can neither overflow/wrap nor produce a reversed range that then slice-panics. `child_boxes` advances by a strictly-increasing `next` (loop terminates); `find_child` short-circuits (never materializes ~8M entries from a 64 MiB source of 8-byte boxes). Regression tests: `child_boxes_is_bounds_safe_on_truncation`, `child_boxes_is_bounds_safe_on_hostile_largesize` (the exact reversed-range repro: a valid `free` box then a `size==1` box with `largesize == u64::MAX` → returns without panic).

### R1 — Confined AAC decode → validated PCM (`5dff528` + hardening `1aa3afe`)
`crates/media-worker/src/session.rs`. The **confined** decode worker now AAC-decodes the audio track to PCM — a new attacker-byte decode surface (symphonia's pure-Rust `aac`; no `unsafe` added). Fail-closed: symphonia errors map to a `WorkerMsg::Error`, never a panic/OOB.

**Review hardening confirmed present (both caps):**
- **Decode-expansion ceiling** `MAX_FRAGMENT_AUDIO_SECONDS = 120` (`session.rs:80,245-247`): the per-fragment emitted-sample budget is `max_sample_rate × max_audio_channels × 120` (saturating, so a pathological bounds set can't wrap) — a hard ceiling so a small hostile fragment within `max_fragment_bytes` cannot expand into unbounded PCM (`validate_pcm` deliberately does not magnitude-cap, so this session-layer bound is the magnitude defense).
- **Demux-iteration cap** `MAX_AUDIO_PACKETS = 1 << 20` (`session.rs:89,258-262`): a byte cap is enforced upstream in `on_fragment`, but a pathological table of a great many tiny/empty packets could spin the drain loop; this caps it. A fresh `AacDecoder` is built per fragment (each canonical fragment is independently decodable).

### A/V timing (`105d058`)
Real per-frame video `stts`, real video pts, window-relative offset, audio-master player clock. Attacker-derived pts/duration arithmetic is saturating / overflow-safe (e.g. the audio ceiling uses `saturating_mul`), with no panic on degenerate pts.

### D-7 — Player robustness on extreme sources (`0036de0` + SAR fix `77b3563`)
`crates/client-app/src/commands/video.rs` + player.
- **Bounded in-flight decoded-frame delivery** `MAX_FRAME_BUF_BYTES = 64 MiB` (`video.rs:97,430-451`): an extreme (4K+ / high-frame-count) GOP whose decoded frames would exceed the ceiling **drops its oldest buffered frames** (`push_bounded`) rather than OOMing the key-holding process / WebView, surfaced as a **benign count-only `Gap{skipped}`** (no oracle). Test `decode_and_emit` D-7 case: 60 frames, budget 48 → drops 12, emits 48 with correct window-relative pts.
- **ffmpeg-output self-OOM guard** (`f6536a1`, `upload.rs:181-186`): ffmpeg's `out.mp4` / `thumb.png` are size-checked against the re-mux worker's `MAX_FRAME_BYTES` accept ceiling **before** they are read into memory — a large source fails closed at the 64 MiB re-mux ceiling instead of allocating an arbitrarily large buffer only for the framed codec to reject it.
- **SAR-aware even-dimension scale fix confirmed present** (`ffmpeg_args.rs:160-171`): `Original` → `scale='trunc(iw*sar/2)*2':'trunc(ih/2)*2',setsar=1`; `Height(h)` → `scale='trunc({h}*dar/2)*2':{h},setsar=1`; `Custom` → `scale={w}:{h},setsar=1`. AV1 4:2:0 requires even W/H; a genuinely anamorphic (SAR≠1) source is resampled to **square pixels at the true display aspect** and stamped `setsar=1`. For a square-pixel source `sar==1`, so every branch is byte-identical to the prior even-only coercion (existing round-trips unaffected).

---

## 3. Containment / bounds / hostile-input evidence

| Surface | Evidence | Result |
|---|---|---|
| Confined ffmpeg differential | `media-launcher/tests/ffmpeg_confine_windows.rs` | confined transcode succeeds; non-granted read DENIED confined vs ALLOWED unconfined |
| Scoped ACL grant + revoke | `media-launcher/tests/file_acl_windows.rs` | ACE + Low label present on grant, gone after revoke/Drop |
| Re-mux bounds-safety | `media-transcode-worker/src/remux.rs` tests (4) | truncation + hostile `u64::MAX` largesize → no panic, well-formed prefix only |
| Audio decode-bomb | `MAX_FRAGMENT_AUDIO_SECONDS` / `MAX_AUDIO_PACKETS` (session.rs) | PCM expansion + iteration bounded, fail-closed |
| Frame-buffer DoS | `MAX_FRAME_BUF_BYTES` bounded delivery (video.rs) | oldest dropped, benign `Gap{skipped}`, no OOM/oracle |
| ffmpeg-output size | `upload.rs` `over_cap` pre-read check | > `MAX_FRAME_BYTES` fails closed before alloc |

The confinement is inherited **byte-identical** from the Phase-7 decode worker (same `appcontainer_sid`, same Job flags via the shared `win32.rs`); ffmpeg's memory cap (a decompression bomb is Job-killed, not hung), no-children limit, kill-on-close, and the bounded-wait-then-force-kill safety net all apply to the ffmpeg spawn.

---

## 4. The muxing-of-decoder-adjacent-bytes review

ffmpeg's output mp4 is a transform of attacker input and is treated as **untrusted**. The re-mux worker never *decodes* it — it demuxes with symphonia and re-tables the samples — but it does **parse ISO-BMFF box structure** on those bytes, which is itself an attack surface. The review confirms:
- **No addition-based length math.** `box_at` compares declared box length against `remaining = data.len() - off` (computed with `checked_sub`), so a 32-bit size, a 64-bit `largesize` (up to `u64::MAX`), or the size-0 to-end form can never overflow, wrap, or yield a reversed slice range (the `6439c5b` fix; the reversed-range panic is regression-tested).
- **Termination + non-amplification.** `child_boxes` advances by a strictly-increasing offset; `find_child` short-circuits without materializing a giant child list.
- **Pre-alloc caps.** `VideoBounds` (8K-class, finite) bound dimensions/pixels/fragment/total bytes before any allocation; over-cap → fail closed.
- **Verbatim descriptor reuse.** The `mp4a`/`esds` AudioSampleEntry is copied byte-for-byte from ffmpeg's `stsd` (validated symphonia-readable in the spike), avoiding hand-authored AudioSpecificConfig.
- **Zero `unsafe`.** The whole crate is `unsafe_code = "deny"`; symphonia (`isomp4`) is pure-Rust with `asm` off.

---

## 5. Cross-cutting invariants — verified

**5.1 Codec-free key-holding process (`cargo tree -i`, run in-turn).** The inverse dependency query erroring *"did not match any packages"* means the crate is absent from that package's entire subgraph:
```
$ cargo tree -p maxsecu-client-app -i symphonia  → did not match any packages
$ cargo tree -p maxsecu-client-app -i rav1d      → did not match any packages
$ cargo tree -p maxsecu-client-app -i rav1e      → did not match any packages
$ cargo tree -p maxsecu-client-app -i ac-ffmpeg  → did not match any packages
$ cargo tree -p maxsecu-media-launcher -i symphonia / -i rav1d → did not match any packages
```
The key-holding `client-app` and the codec-free `media-launcher` it links contain **none** of the codecs; the decoders live only in the confined `media-worker` (view) and the pure-Rust `media-transcode-worker` (demux-only). ffmpeg is a **confined external `.exe`**, not a Rust dependency at all.

**5.2 No new `unsafe` outside the audited win32 launcher.** `media-transcode-worker` is `unsafe_code = "deny"` crate-wide; `client-app/src/ffmpeg_bin.rs` and `media-launcher/src/lib.rs` contain **zero** `unsafe` (grep = 0). All FFI `unsafe` remains confined to the one audited module, `media-launcher/src/win32.rs`.

**5.3 No new external crate; GPL-ffmpeg is aggregated, not linked.** The feature adds **no new crate dependency** — the transcode worker's only runtime dep is `symphonia` (`isomp4`), already in the graph. The static ffmpeg is a **prebuilt binary embedded via `include_bytes!`** and executed as a separate confined process; it is an **aggregated** GPL work (bytes riding inside the client exe, invoked over a process boundary), **not linked** into any Rust crate. No GPL symbol enters the MaxSecu link. (Provenance/license note: a full prebuilt ffmpeg is GPL — acceptable for a local/personal build; a minimal LGPL-from-source build is the Phase-B residual.)

**5.4 Supply-chain clean.**
```
$ cargo deny check → advisories ok, bans ok, licenses ok, sources ok
$ cargo audit      → exit clean (18 allowed warnings)
```
The only `cargo deny` note is a dormant `advisory-not-detected` **warning** for `RUSTSEC-2024-0429` (glib, the pre-existing GTK-stack entry — not this feature's code, not a codec); `cargo audit` reports the same glib item as an allowed/known warning. `ring` / `openssl` stay banned and absent.

**5.5 Fail-closed everywhere.** Every ingest failure — unsupported/corrupt input, ffmpeg nonzero exit, over-cap geometry, re-mux failure, over-ceiling output size, worker abort — collapses to the sanitized `UiError { code: "video_failed" | "video_unavailable" }`. No path/IO detail, ffmpeg stderr, or internal state crosses the Tauri seam; there is no decode oracle. The confined `ffmpeg_bin` module surfaces exactly one sanitized error, and the launcher's `SpawnError` (which carries only a step name + Win32 code) never reaches the UI (`.map_err(|_| video_prep_err())`).

---

## 6. Residuals / deferred (NOT security gaps in the committed path)

| Ref | Residual | Severity | Disposition / closure |
|---|---|---|---|
| **Phase-B ffmpeg from source** | The embedded ffmpeg is a **prebuilt GPL** static build (aggregated exe, not linked). | Deferred (licensing/hardening) | Compile a **minimal static ffmpeg from source** (LGPL, only the needed demuxers/decoders + AV1/AAC encoders) for size + reproducibility. No change to the confinement or trust model. |
| **Loudness normalization** | No loudness/EBU-R128 normalization or advanced audio filtering. | Deferred (functional) | Phase-B; audio is passed through at a fixed bitrate. |
| **>64 MiB large-source streaming** | `client-app` size-checks ffmpeg's output against the **64 MiB re-mux accept ceiling** (`MAX_FRAME_BYTES`) and **fails closed** on larger — full chunked/temp-file large-source delivery to the re-mux worker is not yet wired. | Deferred (functional) | Add chunked/streamed source delivery; **not a security gap** — bounds + confinement still apply, and over-ceiling fails closed with no alloc. |
| **VFR / extreme anamorphic edges** | The pinned argv assumes CFR-ish sources; the SAR-aware scale (`77b3563`) handles standard anamorphic, but exotic VFR / mixed-SAR streams beyond it are out of scope. | Deferred (functional) | Broader format/edge sweep in Phase-B; degenerate cases still fail closed, never crash. |
| **Ratification argv is even-only** | The Phase-0 ratification doc records the **historical** even-only `scale=trunc(iw/2)*2:trunc(ih/2)*2` argv; the shipped code uses the **SAR-aware** filter (a documented review follow-up, `77b3563`). | Info (doc drift) | Documented here; the code is the source of truth and is square-pixel-correct. |
| **Capstone e2e is `#[ignore]`** | `crates/client-app/tests/universal_video_e2e.rs::universal_video_ingest_capstone_over_real_tls` (real transcode → upload → view with audio + A/V sync + extreme high-res + resolution-change over real TLS) is `#[ignore]` (~15-20 min). | Info (test runtime) | Run explicitly: `cargo test -p maxsecu-client-app --test universal_video_e2e -- --ignored --test-threads=1`. |

**Inherited standing residuals.** The Phase-7 view-side decoder residuals stand unchanged (F1 `rav1d` panic and F2 `symphonia` `stsz` OOM are **contained** DoS — worker-abort → per-fragment respawn, and the Job memory cap, respectively; both ASan-clean, both with upstream issues drafted). The sandbox **contains, it does not eliminate**. Treat any change to a confined process's privilege, the canonical format, the ffmpeg pin/argv, or the C carve-out as a **security-reviewed** change.

---

## 7. Conclusion

**PASS — no Critical/High/Medium open against the committed path.** Verified end-to-end:
- the **#1 RCE surface (ffmpeg) runs only inside the proven capability-free AppContainer + Job Object**, reachable via a scoped, RAII-revoked per-path ACL grant, with NUL stdio, bounded stderr, an **explicit handle-inheritance allow-list**, and a finite forced-kill timeout — confinement byte-identical to the Phase-7 decode worker, with a denied-confined / allowed-unconfined differential;
- the **embedded ffmpeg is SHA-256-pinned and verified every run**, materialized via an **atomic replace** over an exclusive-create + `sync_all` temp (no half-written exe, no absence window);
- the **re-mux worker is pure-Rust, zero-`unsafe`, and bounds-safe** on ffmpeg's attacker-derived output (the hostile-`largesize` reversed-range panic fixed and regression-tested);
- the **new audio decode surface is decode-bomb- and iteration-capped**, and the **player is DoS-bounded** (64 MiB in-flight ceiling, benign count-only skip) with SAR-correct scaling;
- the **key-holding `client-app` / TCB `client-core` / `media-launcher` link none of the codecs**; **no new crate** is added; GPL ffmpeg is an **aggregated exe, not linked**;
- **`cargo deny` / `cargo audit` are clean**, and **every** failure is a sanitized `video_failed` / `video_unavailable` with no oracle.

All four per-task review fixes flagged for confirmation are present in the code: the D-1 atomic-replace + exclusive temp, the D-2 handle-list allow-list + configurable timeout, the D-3/D-6 `box_at` bounds fix, and the R1 audio caps. The residuals are deferred honestly with their closure paths and are not security gaps in the committed path. **Universal Video Ingest hardens the system's #1 RCE surface as far as the committed path allows and is signed off PASS.**
