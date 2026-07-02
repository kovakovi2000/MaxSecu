# Plan — Write-back cold-tier offload engine

**Created:** 2026-07-02
**Branch:** local `main` (no push).
**Origin:** user-specified target behavior for how the server should tier storage to Dropbox. This is a **write-back / lazy-offload** model, distinct from the pre-existing (never-wired) write-through `TieredBlobStore`.

## Target behavior (from the user)
- New uploads land on the **server's local disk only**.
- A file (stream/chunk) is **offloaded to the cold tier (Dropbox) and deleted locally** when EITHER:
  - (a) it hasn't been requested for **> 1 month** (idle), or
  - (b) local storage is **at its configured capacity** and space is needed — which happens on **both upload and download** (both need free local space).
- **Request handling:**
  - *Default:* server frees space, downloads from Dropbox, relays to the client (server-proxied).
  - *Dropbox setting on:* server brokers a short-lived Dropbox URL; client downloads directly.
  - *Tor on:* direct-URL disabled (leak risk); server fetches from Dropbox and relays.
  - *Never offloaded (still local):* only the server serves it, from local disk.

## Resolved decisions (AskUserQuestion timed out — proceeded on best judgment; RE-CONFIRM)
1. **Durability = write-back / lazy** (as the user described). Caveat documented: a *never-yet-offloaded* file has no second copy until its first offload — disk loss before that loses it. Write path kept a single policy point so switching to write-through is small later.
2. **local-XOR-cold invariant:** every chunk lives in exactly one tier. `put`→local; `offload`→move to cold (upload + delete local); `rehydrate` on read-miss→move back (cold.get + local.put + cold.delete). ⇒ `chunk_count = local.count + cold.count` is exact and restart-safe.
3. **Scope = server-side engine only.** Client direct-link/Tor request branches depend on unbuilt client-app work (T4/T5 spec track). `broker_direct_link` yields a cold link only for offloaded chunks; a local chunk → `None` → server proxies.
4. **Config-gated cold tier:** default NONE (plain `FsBlobStore` = today's behavior); `fs` (FsColdTier, testable, no creds); `dropbox` (DropboxTier, env token). Capacity + idle-days configurable. Clock injected for tests.

## Tasks (sequential; single cohesive feature, controller-implemented + self-review)

### 1 — `WriteBackTier` store (`crates/server/src/writeback_tier.rs`, new)
- `struct WriteBackTier { local: Arc<dyn BlobStore>, cold: Arc<dyn ColdTier>, index: Mutex<LocalIndex>, capacity_bytes: u64, idle: Duration, clock: Clock, fetching: Mutex<HashSet<(String,u64)>> }`.
- `LocalIndex` — `HashMap<ChunkKey, Entry{ size, last_access: SystemTime }>` + `total_bytes`. Methods: `record_put(key,size,now) -> Vec<victims>` (LRU by `last_access`, evict while `total_bytes > capacity` and `len > 1`, never the just-inserted); `record_access(key,now)`; `remove(key)`; `remove_stream(blob_ref)`; `idle_victims(now, idle) -> Vec<ChunkKey>`; `contains`.
- `Clock` — small injectable now-source (`System` | test `Fixed(Arc<Mutex<SystemTime>>)` with `advance`).
- `impl BlobStore for WriteBackTier`:
  - `put_chunk`: `local.put_chunk`; under lock `record_put` → victims; drop lock; `offload(v)` each (best-effort).
  - `get_chunk`: local hit → `record_access`, return; miss → mark fetching, `cold.get_chunk`; Some → rehydrate (`local.put_chunk` + `cold.delete_chunk`) + `record_put`(→ offload victims) + unmark, return Some; None → unmark, return None.
  - `chunk_count` = `local.chunk_count + cold.chunk_count` (XOR invariant → no overlap).
  - `delete_stream`/`delete_chunk`: both tiers + index.
  - `chunk_status`: index→Cache; fetching→ColdFetching; `cold.has_chunk`→ColdReady; else None.
  - `broker_direct_link`: local (index) → `Ok(None)`; else `cold.broker_direct_link`.
- `offload(key)` (private): read `local.get_chunk`; if present `cold.put_chunk` then `local.delete_chunk` + `index.remove`. Cold failure → keep local (no data loss), stop the batch.
- `run_idle_sweep(&self)` (pub): compute `idle_victims(now, idle)` under lock, offload each. Never holds the lock across `.await`.
- **Never hold the index `Mutex` across an `.await`** (mirrors `TieredBlobStore::cache_and_evict`).
- Unit tests (`-- --test-threads=1` not needed; pure tokio): write-back leaves cold empty; capacity eviction moves LRU to cold + deletes local; access bumps recency; rehydrate-on-miss moves back (cold emptied, local repopulated); `chunk_count` across mixed residency; idle sweep offloads only idle chunks (Fixed clock advance); best-effort offload keeps the chunk on cold failure; delete clears both tiers + index; direct-link None for local / Some for offloaded; status transitions.

### 2 — Config (`crates/portable-server/src/config.rs`)
- `enum ColdTierCfg { None, Fs(PathBuf), Dropbox{ token: String, root: String } }`.
- `LauncherConfig` gains `cold_tier: ColdTierCfg`, `cache_capacity_bytes: u64`, `offload_idle_days: u64`.
- Env: `MAXSECU_COLD_TIER` = `off`(default)|`fs`|`dropbox`; `MAXSECU_COLD_FS_DIR`; `MAXSECU_DROPBOX_TOKEN` + `MAXSECU_DROPBOX_ROOT`; `MAXSECU_CACHE_CAPACITY_BYTES` (default 250 GB = 250_000_000_000); `MAXSECU_OFFLOAD_IDLE_DAYS` (default 30). Keep `from_parts(env-closure)` pure + tested. Dropbox token NEVER logged.

### 3 — Wiring (`crates/portable-server/src/run.rs`)
- Build `local = FsBlobStore`. If `cold_tier != None`: build the cold tier, wrap in `Arc<WriteBackTier>`, use as `blobs`, and **spawn the idle sweeper** (`tokio::spawn` an interval loop calling `run_idle_sweep`) — only when tiering is on (smoke test stays task-free). Else `blobs = local` (unchanged).
- `prepare` stays reusable; sweeper spawned inside `prepare` guarded on config so `run` and the smoke test share one path.
- Print the tier mode in `run`'s banner (never the token).

## Acceptance
- `cargo build --workspace --tests` 0 warnings; `cargo test -p maxsecu-server --lib` (incl. new writeback tests) + `-p maxsecu-portable-server` green; existing `tier.rs` write-through tests untouched/green; `MAXSECU_PG_OPTIONAL=1 cargo test --workspace --lib` green; `boot_smoke` still passes. `cargo deny check bans licenses sources` ok (no new deps expected). Self-review: no index lock across `.await`; offload/rehydrate preserve local-XOR-cold; cold failure never loses data; no token logged.

## Deferred / open (surface to user)
- Durability caveat of write-back (re-confirm vs write-through).
- Client-side direct-link download + Tor-forces-proxy (T4/T5 spec track).
- Real Dropbox live-verify needs the user's `DROPBOX_TEST_TOKEN`.
- Index is in-memory (like the existing store); after restart capacity/idle bookkeeping re-seeds lazily (a chunk gets indexed on next access/put). Optional later: startup scan of the local store to seed the index.
