# RAM Cache Model Rework — Independent Security Review & Sign-off

**Date:** 2026-07-06
**Branch:** `feat/ram-cache-model`
**Commit range reviewed:** `bd5ff32..HEAD` (15 commits, `da0747d`…`2761262`)
**Scope:** `crates/client-app` only — the two app-global ciphertext caches (Media + Thumbnails), the per-process ephemeral seal, the dual-mode gauges/clear commands, the settings split, and the Exit-hook zeroize/disk-wipe.
**Spec:** `docs/superpowers/specs/2026-07-06-ram-cache-model-design.md` (authoritative intent; §"Security review" enumerates the required checks).

**Method:** a **fresh, independent re-verification** against the committed source — not a restatement of the per-task reviews. Every property below was traced to its implementing lines; the underlying AEAD/RNG primitives were followed into `crates/crypto`. Where the spec claims a structural property (e.g. "no per-session cache summed into the gauge"), I confirmed the type/ownership change that makes it true.

---

## Verdict

**PASS — no Critical, High, or Medium finding.**

The rework holds every security property the spec requires. The two caches store **ciphertext only** in both backends; full-content and card-meta blobs are sealed under a per-process ephemeral AES-256-GCM key drawn from the OS CSPRNG, never persisted, and explicitly zeroized on exit; video fragments are already content-DEK ciphertext and are not double-sealed; cross-item isolation is enforced by a validated hex-only `(Ns, id_hex, sub)` key over the *requested* file id; persistence across `cancel_video` does not retain any key material (only ciphertext); and the Disk backend is path-traversal-proof and wiped on both start and exit. The change is client-app-local: no server, wire-format, or `client-core` change. The gauge-over-100% defect is structurally eliminated. The residuals (a swap copy of the ephemeral key written *before* the wipe; the transient decoded frame on-screen in the WebView) are pre-existing, out of scope, and honestly recorded below.

---

## Threat model recap

- **In scope:** an OS page-out / hibernation / crash-dump spilling cache memory to disk; a stale on-disk cache surviving a session; cross-video / cross-item read-through under one shared cache; a forged/substituted author or content id; a hostile cache key attempting path traversal; key material lingering in RAM after the app closes.
- **Out of scope (unchanged by this rework):** a privileged local attacker with live process-memory (RAM) inspection; the transient decoded frame the native `<video>`/`<img>` element must hold in the WebView to render; a copy of the ephemeral key paged to swap *before* the exit-time wipe (the key is not `mlock`'d).
- **Inviolable rule (re-verified):** the cache layer never receives or writes plaintext content; only ciphertext (either content-DEK ciphertext, or ephemeral-sealed ciphertext) is ever at rest in RAM or on disk.

---

## Property 1 — Cross-video / cross-item isolation under the shared cache — PASS

Both caches share one `BlobCache` engine keyed by the composite `type Key = (Ns, String, u32)` (`blob_cache.rs:65`), i.e. `(namespace, id_hex, sub)`. Every public entry point runs `id_hex` through `validated_key` (`blob_cache.rs:392-404`), which rejects any non-hex, empty, or over-long id and returns the **lowercased** canonical form — so `/`, `\`, `.`, `:`, and case-variant collisions are impossible, and a malformed id is a miss, not a cross-read.

- The id is the **requested** file id, not a server-supplied one: `open_video_inner` derives `file_id_hex` from `hex16(file_id_str)` on the caller's request (`video.rs:334-335`) and threads that exact `job.file_id_hex` through every `serve_range` cache get/put (`video.rs:665, 725, 762`). The verify ladder binds the served record to that requested id (`open_video_job_core`, `video.rs:101-128`), so video A's fragments (`Ns::Frag, A, seq`) are unreachable under video B's key.
- **Namespace separation** is total: `Ns::Frag`, `Ns::Content`, `Ns::Card` are distinct key components and map to distinct on-disk filename tags (`blob_cache.rs:54-62`). The `namespaces_do_not_collide` test (`blob_cache.rs:737-752`) pins that `(Frag, aa, 0)` and `(Content, aa, 0)` are independent entries. This matters because `MediaCache` co-mingles raw `Frag` and sealed `Content` under one budget.
- A present-but-wrong-length or corrupt fragment is **not** a hit: `cached_fragment_valid` (`video.rs:138-149`) deframes the blob and requires exactly `chunk_len` chunks via the bounds-safe `deframe_count` (`video.rs:154-173`), mirroring the feeder's own hit condition, so a poisoned/short entry forces a re-fetch rather than serving bad bytes.

## Property 2 — Persistence posture (D1/D8) — PASS

- The ciphertext cache is **external** to the `VideoJob`. `MediaCache` is a single `Arc<Mutex<BlobCache>>` (`media_cache.rs:24`) managed once at startup (`main.rs:49-51,77`); `serve_range` borrows it as a parameter (`video.rs:641-647`). Dropping a job touches no cached bytes.
- `cancel_video` only removes the job from `VideoJobs` (`video.rs:519-535`), which drops the `ContentDecryptor` and **zeroizes the content subkey** — but the shared `MediaCache` is never referenced there. The `cancel_drops_job_but_shared_cache_persists` test (`video.rs:1201-1234`) asserts the exact ciphertext survives the job drop.
- The decryptor **never crosses the Tauri seam**: it lives in the `VideoJobs` registry and is only borrowed synchronously inside `serve_range`/`probe_total_len` for in-TCB decrypt (`video.rs:717-726, 245-247`); only sliced plaintext byte ranges (already exposed by the `stream://` protocol) leave the process.
- The **only** cache removals are: cap-driven LRU (`BlobCache::put`/`set_cap`, `blob_cache.rs:199,292-295`), manual Clear (`clear_media_cache`/`clear_thumb_cache`, `video.rs:585-596`), app-close (Property 5), and explicit content deletion (`invalidate_file`, `media_cache.rs:72-77` / `thumb_cache.rs:144-149`). Leaving a post or the viewer invokes none of these — persistence holds.

## Property 3 — Ephemeral-seal construction — PASS

`SessionSeal` (`session_seal.rs`):

- **Key origin:** `random_array::<32>()` (`session_seal.rs:27`), which routes to `getrandom` / the OS CSPRNG (`crates/crypto/src/rng.rs:9-18`, `BCryptGenRandom` on Windows) — never a userspace PRNG.
- **RAM-only, never persisted/serialized:** the key is a `std::sync::Mutex<Zeroizing<[u8; 32]>>` field (`session_seal.rs:20`) with no `Serialize`/`Deserialize`, no disk write, and no accessor returning it.
- **AEAD:** `seal` is `random 12-byte nonce ‖ AES-256-GCM(key, nonce, aad=[], pt)` (`session_seal.rs:37-45`) via the audited `maxsecu_crypto::{seal,open}` single-shot `Aes256Gcm` primitives (`crates/crypto/src/aead.rs:251-278`). No new crypto dependency.
- **Unique random 96-bit nonce per seal:** drawn fresh each call (`session_seal.rs:38`); the birthday bound and its ≪2^32-seals validity for the bounded caches are documented at `session_seal.rs:34-36`, with an explicit warning against high-volume reuse. `distinct_nonces_per_seal` (`session_seal.rs:87-90`) pins that identical plaintext seals to different bytes.
- **Fail-closed `open`:** too-short input, tamper, and wrong-key all return `None` (`session_seal.rs:50-58`); tests `tampered_blob_fails`, `wrong_key_fails`, `truncated_blob_is_none`, `exactly_nonce_len_blob_is_none` cover the boundaries.
- **Sealed vs unsealed by design:** `ThumbCache` seals every `Card` entry (`thumb_cache.rs:104-106`) and `MediaCache::put_content` seals every `Content` payload (`media_cache.rs:47-52`) before rest; video `Frag` entries are **not** re-sealed (`media_cache.rs:17-23`) because they are already ciphertext under the content DEK — no double-encryption, and still ciphertext-at-rest. Round-trip tests confirm the stored blob never contains the plaintext title/body (`thumb_cache.rs:287-294`, `media_cache.rs:206-217`).

## Property 4 — Disk backend is ciphertext-only (D5), traversal-proof — PASS

- `BlobCache::put` writes **exactly** the opaque bytes it is handed (`blob_cache.rs:202-206`) — no transform, encrypt, or inspect. The CIPHERTEXT-ONLY invariant is documented at `blob_cache.rs:12-22`. The `on_disk_bytes_are_exactly_the_ciphertext_never_plaintext` test scans for a deliberately-never-passed plaintext marker across **both** `Frag` and `Content` namespaces (`blob_cache.rs:529-553`).
- What reaches the Disk backend is always ciphertext: `Frag` = content-DEK ciphertext; `Content`/`Card` = ephemeral-sealed ciphertext. Sealed-under-ephemeral-key content on disk is undecryptable once the key is zeroized and is wiped at the next start regardless.
- **Path traversal is impossible:** the filename is `<ns>_<id_hex>_<sub>.blob` (`blob_cache.rs:409-411`) where `ns` is a fixed path-safe tag, `sub` is decimal `u32`, and `id_hex` is hex-validated — proven by `path_traversal_keys_are_rejected` (`blob_cache.rs:556-569`, covering `../evil`, `a/b`, `a\b`, `..`, empty, non-hex). The crate is compiled `unsafe_code = "forbid"` (`Cargo.toml:116`), so the not-content-indexed attribute is set via an **absolute** `%SystemRoot%\System32\attrib.exe` invocation with no PATH-hijack surface (`blob_cache.rs:420-433`).
- The on-disk dir is marked `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` best-effort so at-rest ciphertext is not search-indexed (`blob_cache.rs:169, 420-433`).

## Property 5 — Exit-hook zeroize + disk-wipe (D6/D5a) — PASS

- `RunEvent::Exit` (`main.rs:179-195`) calls `media.clear_and_zeroize_sync()`, `thumb.clear_and_zeroize_sync()`, then `seal.zeroize()`, using the managed state while it is still alive (a managed-state drop is not guaranteed at shutdown).
- **Memory mode** wipes the `Zeroizing<Vec<u8>>` blobs (`blob_cache.rs:88,209,340-346,365-377`); **Disk mode** deletes the `cache/media/*` and `cache/thumb/*` backing files (`blob_cache.rs:368-370`). Both zero the byte accounting.
- **Single shared key wiped:** `seal.zeroize()` overwrites the one interior-mutable `Mutex<Zeroizing<[u8;32]>>` (`session_seal.rs:69-72`) that both the managed `Arc<SessionSeal>` and `ThumbCache`'s clone observe (both derive from the one `seal` in `main.rs:48,56,76`). After the wipe, any earlier-paged sealed blob no longer opens — `zeroize_wipes_key_so_prior_blobs_no_longer_open` (`session_seal.rs:122-131`) pins this.
- **Start-time wipe too:** every Disk open removes prior subdir contents (`open_disk`, `blob_cache.rs:161-177`), so a Disk cache never crosses a session boundary even after a crash that skipped the exit hook.
- **Never panics/blocks:** the `*_sync` variants use `try_lock`, not `blocking_lock` (`media_cache.rs:131-135`, `thumb_cache.rs:218-222`), so the synchronous Exit callback cannot panic on the missing runtime context nor block shutdown. A contended miss (essentially never at Exit) leaves, at worst, ciphertext-only files that the next start wipes and the zeroized key makes undecryptable.

## Property 6 — Residual (stated honestly)

- **Ephemeral key already in swap.** The 32-byte key's live RAM copy is wiped on close, but a copy the OS paged to swap **before** the wipe is outside our control — the key is not `mlock`'d. This is documented in-code (`session_seal.rs:60-68`) and accepted (spec §Non-goals, §"Security review").
- **Transient on-screen frame.** The single decoded frame the native `<video>`/`<img>` currently displays is plaintext by necessity in the WebView. Pre-existing, unavoidable for native rendering, out of scope (spec §Non-goals).
- **What sealing buys.** A pagefile/hibernation spill of the sealed caches contains **only ciphertext**, which becomes permanently undecryptable the moment the ephemeral key is zeroized on close. That is the entire point of sealing content and card meta rather than caching them in the clear.
- Not defended: a privileged local attacker with live process-memory access (spec §Non-goals) — the sealed caches, the decryptor subkey, and the ephemeral key are all live-readable in RAM by such an attacker, as with any in-process secret.

---

## Cross-check of spec non-goals & decisions

- **Client-app-only.** The entire change set is under `crates/client-app` (Property scope; commit range confirms). No server, wire-format, or `client-core` type/behavior change — the viewer/streamer still call the unchanged `verify_and_open`/`verify_and_open_headers`/`open_content_decryptor` TCB entry points (`viewer.rs:130-133`, `video.rs:42-45`).
- **Gauge >100% is structurally fixed.** There is now exactly one shared cache per budget, not N per-session `FragmentCache`s summed to the cap. `cache_stats` reads each single cache once and, in Memory mode, `gauge_fill` reconciles it to the live cap via `set_cap` before reporting `memory_bytes` (`video.rs:560-581`, `media_cache.rs:85-93`), so the numerator can never exceed the denominator. `cache_stats_memory_never_over_cap` (`video.rs:1314-1329`) pins this. Disk mode is explicitly informational (numerator = on-disk size; denominator = startup free-space estimate, `disk_free.rs:14-23`), and may legitimately approach/exceed 100% on a long session — accepted per D5a.
- **Default location = Memory.** `FragmentCacheLocation::default()` is `Memory` (`config.rs:249-254`); the legacy `ram_cache_cap_mb` migrates into `media_cache_cap_mb` without re-serializing the dead key (`config.rs:262-300`, tests `config.rs:664-696`).
- **`version as u32` narrowing** (`thumb_cache.rs:78-83`, `media_cache.rs:52,66`): not security-relevant. File versions are small monotonic counters; the truncation is documented as collision-free in the practical range. Even a hypothetical wrap would only cause a benign cache miss/mismatch under a key still scoped to the correct `file_id` and namespace — no cross-item disclosure. Noted, not a finding.

---

## Test surface & holistic pre-merge gate (run green)

The rework ships dense unit coverage co-located with each module: `blob_cache.rs` (roundtrip, case-normalization, LRU, oversize-skip, path-traversal rejection, corrupt-file miss, ciphertext-only on both namespaces, uncapped-disk, `is_disk`, clear-both-backends), `session_seal.rs` (roundtrip, distinct nonces, tamper/wrong-key/truncation fail-closed, zeroize-invalidates), `media_cache.rs` and `thumb_cache.rs` (seal roundtrip + stored-blob-is-ciphertext, invalidate/invalidate_file, gauge reconcile, location toggle rebuild, clear), and `commands/video.rs` (D5-gated open, forged-author fail-closed, cancel-persists-cache, gauge-never-over-cap, independent per-cache clear). The evidence for each security property above is the source itself; the tests corroborate.

The holistic pre-merge gate was executed and is **green** (2026-07-06):

- `cargo test -p maxsecu-client-app` — **281 passed, 0 failed**.
- `cargo test -p maxsecu-client-e2e range_streaming_reassembles_plaintext_over_real_tls` (native `stream://` range path over real loopback TLS, shared `MediaCache`) — **1 passed**.
- `cd ui && npm run typecheck` — clean; `npm test` — **155 passed, 0 failed**; `npm run build` — esbuild bundle regenerated (`dist/main.js`).
- `cargo build --bin maxsecu-client-app` — compiles.

**Remaining before ship:** the manual GUI smoke (windowed, human-verified) — play a bundle's videos simultaneously and confirm the Media gauge stays ≤100% and never sums past the cap; leave + re-open a video is an instant cache hit; lowering a cap evicts down; toggling to Disk switches the gauge to on-disk/free-space; the two Clear buttons drop their bar to 0; app close clears/zeroizes. Per the build gotcha, rebuild the esbuild bundle + the client binary before the smoke, and do **not** restart the demo server.

---

## Sign-off

I independently verified each security property required by the spec against the committed code on `feat/ram-cache-model`. I found **no Critical, High, or Medium security defect**. The two residuals (pre-wipe swap copy of the ephemeral key; the transient on-screen decoded frame) are pre-existing, out of scope, and honestly recorded.

**Verdict: PASS.**
