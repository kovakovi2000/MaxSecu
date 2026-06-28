#!/usr/bin/env bash
# Reproducible-build verification (DESIGN §8 control 2 / D1; stack.md §1.5).
#
# Builds a release binary TWICE, in two isolated target directories with
# deterministic flags, and fails (exit 1) unless the two artifacts are
# byte-identical (same SHA-256). This is the runnable half of the Phase-6
# "reproducible-build verification documented" exit gate; docs/reproducible-builds.md
# is the recipe a third party follows to reproduce a published hash.
#
# Determinism levers (all must match between any two builds to reproduce a hash):
#   - pinned toolchain            (rust-toolchain.toml: channel 1.96.0)
#   - locked dependency graph     (--locked, Cargo.lock with the exact versions)
#   - fixed build epoch           (SOURCE_DATE_EPOCH)
#   - remapped source/dep/target paths (--remap-path-prefix → constant logical roots)
#   - no incremental compilation  (CARGO_INCREMENTAL=0)
#
# Usage:  scripts/reproducible-build.sh [crate] [bin]
#   defaults: crate=maxsecu-media-worker  bin=media-worker
# Run from the repo root (on Linux/WSL). The host target is used for the
# determinism demonstration; the musl static release artifact-of-record recipe
# is in docs/reproducible-builds.md (it needs `rustup target add` + a musl
# toolchain and is documented, not exercised here).
set -euo pipefail

CRATE="${1:-maxsecu-media-worker}"
BIN="${2:-media-worker}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# A fixed, arbitrary epoch (2023-11-14T22:13:20Z) — the value is irrelevant as
# long as every reproducing build uses the SAME one.
export SOURCE_DATE_EPOCH=1700000000
export CARGO_INCREMENTAL=0

COMMON_REMAP="--remap-path-prefix=${HOME}/.cargo=/cargo --remap-path-prefix=${REPO_ROOT}=/src"

build_into() {
    local out_dir="$1"
    rm -rf "$out_dir"
    # Map this build's isolated target dir to the SAME logical /target as the
    # other build's, so the target path can never leak a difference into the bytes.
    CARGO_TARGET_DIR="$out_dir" \
    RUSTFLAGS="${COMMON_REMAP} --remap-path-prefix=${out_dir}=/target" \
        cargo build --release --locked -p "$CRATE" --bin "$BIN" >&2
    echo "${out_dir}/release/${BIN}"
}

echo "Reproducible-build check: ${CRATE} :: ${BIN}" >&2
A_BIN="$(build_into "${REPO_ROOT}/target-repro-a")"
B_BIN="$(build_into "${REPO_ROOT}/target-repro-b")"

A_SHA="$(sha256sum "$A_BIN" | cut -d' ' -f1)"
B_SHA="$(sha256sum "$B_BIN" | cut -d' ' -f1)"

echo "build A: ${A_SHA}  (${A_BIN})" >&2
echo "build B: ${B_SHA}  (${B_BIN})" >&2

if [ "$A_SHA" = "$B_SHA" ]; then
    echo "REPRODUCIBLE: identical SHA-256 (${A_SHA})"
    exit 0
else
    echo "NOT REPRODUCIBLE: hashes differ — investigate non-determinism (see docs/reproducible-builds.md)" >&2
    exit 1
fi
