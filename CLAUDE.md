# MaxSecu — working agreements

## Backward compatibility (non-negotiable)

> **Every upgrade must keep existing users' access intact — account/login, keys, and already-uploaded data. No change may force a re-enroll, re-key, re-upload, re-share, or reset.**

MaxSecu runs on a real VPS with real, non-technical users, and there is **no admin escape hatch by design**. A change that makes a user's keyblob, DEK wrap or directory binding unreadable destroys their data permanently — nobody can recover it. This has already happened once (`2a626d6`: every already-enrolled recipient had to re-enroll).

**Run the compat gate before every push:**

```powershell
powershell -File scripts/compat-gate.ps1
```

It runs both workspaces (offline, seconds):

```
cargo test -p maxsecu-compat --locked
cargo test --manifest-path crates/client-app/Cargo.toml --locked --no-default-features --features unpinned-dev --test compat
```

Install the pre-push hook once — after that it runs automatically and blocks a push that breaks the rule:

```powershell
powershell -File scripts/install-hooks.ps1
```

Before committing a change to a format, run `/compat-check` (reviews the working diff against the rule).

**When the gate fails, editing the fixture is never the fix.** The corpus is add-only: fixtures may be added, never edited, never deleted. An intentional format change needs a read path that still opens the old bytes, a NEW fixture for the new ones, and an entry in `docs/compat/LEDGER.md`.

- `docs/compat/CHECKLIST.md` — the eleven frozen surfaces, their blast radius, and how to evolve a format safely (add optional fields; never repurpose or hard-require; **prefer widening over tightening** — a stricter check that rejects data the previous version wrote is a break even when it is more secure).
- `docs/compat/LEDGER.md` — the append-only record of intentional format changes.

`SKIP_COMPAT_GATE=1` bypasses the local hook only. **CI cannot be bypassed.**
