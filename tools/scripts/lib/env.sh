# shellcheck shell=bash
# tools/scripts/lib/env.sh — shared environment bootstrap for Ipê tooling.
# SOURCE this (never execute it): `source "$(dirname "$0")/lib/env.sh"`.
#
# The compiler is `ipe` (a Rust cargo workspace); the binary is built by cargo
# and lives in the (possibly global) cargo target dir. This file defines
# REPO + IPE_BIN and does NOT cd (callers `cd "$REPO"` themselves so the failure
# path stays theirs).
#
# It is idempotent: safe to source even when the caller has already cd'd into the
# repo or pre-set CARGO_TARGET_DIR / RUSTC_WRAPPER / IPE_BIN (all `${VAR:-…}`).

# ── PATH: prepend the canonical dev dirs, PRESERVE the inherited PATH ────────
# cargo resolves from its canonical local dir first. The trailing `$PATH` is
# LOAD-BEARING on CI: GitHub's setup-node puts `node` / `curl` on the runner PATH
# at non-canonical locations — clobbering it would abort the sweep at its
# `curl` preflight (the RUN check + the mirror's network fallback need it).
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin:$PATH"

# ── Shared cargo target + sccache + CARGO_INCREMENTAL=0 ─────────────────────
# A shared CARGO_TARGET_DIR compiles the heavy deps (axum/tokio/serde/sqlx/…)
# ONCE and persists across each example's `rm -rf out`. This repo's global
# ~/.cargo/config.toml already pins `target-dir = ~/.cache/ipe-lang-target`, so
# this default AGREES with where a bare `cargo build` of the workspace lands
# ipe — the same dir the sweep's per-example `cargo build` reuses. Override
# CARGO_TARGET_DIR to relocate; we honour a pre-existing value.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/ipe/ipe-target}"
mkdir -p "$CARGO_TARGET_DIR" || {
  echo "env.sh: could not create CARGO_TARGET_DIR='$CARGO_TARGET_DIR' (perms/ENOSPC?)" >&2
  return 1 2>/dev/null || exit 1
}

# sccache (RUSTC_WRAPPER) caches each rustc by content hash — the big LOCAL win,
# coupled to CARGO_INCREMENTAL=0 (sccache caches NOTHING with incremental=true).
# IPE_NO_SCCACHE=1 force-disables this wrapper. CI runners carry no sccache, so
# CI jobs never take this branch: they cache compiled dependencies with
# `Swatinem/rust-cache` and `verify-manifest.py` refuses any job that wraps
# rustc. The static/cross-compile build jobs (.github/workflows/static.yml)
# also set IPE_NO_SCCACHE=1 — they persist CARGO_TARGET_DIR + ~/.cargo via
# actions/cache, leaving CARGO_INCREMENTAL at cargo's default so the persisted
# target dir does incremental rebuilds.
if [ -z "${IPE_NO_SCCACHE:-}" ] && command -v sccache >/dev/null 2>&1; then
    export RUSTC_WRAPPER="${RUSTC_WRAPPER:-sccache}"
    export CARGO_INCREMENTAL=0
fi

# ── Repo-root detection → REPO ───────────────────────────────────────────────
# Honour an explicit IPE_REPO; else detect via this file's location (works from
# any subdir of any clone). Don't cd — that's the caller's. Only IPE_REPO seeds
# the root; REPO is a common var other tooling exports, so trusting an inherited
# value would poison every "$REPO/…" path.
REPO="${IPE_REPO:-}"
[ -z "$REPO" ] && [ -f "$PWD/tools/scripts/lib/examples.sh" ] && REPO="$PWD"
if [ -z "$REPO" ]; then
  _env_sh_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
  if [ -n "$_env_sh_dir" ]; then
    REPO="$(git -C "$_env_sh_dir" rev-parse --show-toplevel 2>/dev/null)"
  fi
  unset _env_sh_dir
fi
if [ -z "$REPO" ]; then
  echo "env.sh: could not locate repo root (set IPE_REPO to override)" >&2
  return 1 2>/dev/null || exit 1
fi
export REPO

# ── IPE_BIN detection ───────────────────────────────────────────────────────
# The compiler binary is produced by `cargo build [--release] -p ipe`. Because
# this repo's ~/.cargo/config.toml pins a GLOBAL target-dir, the binary lands in
# $CARGO_TARGET_DIR/{release,debug}/ipe — NOT $REPO/target — so probe the shared
# target FIRST, then the in-repo target/ (the layout on a checkout WITHOUT a
# global target-dir), then PATH. Release is preferred over debug (faster sweep).
# IPE_BIN honoured verbatim if the caller pre-set it.
# On Windows the cargo artifact is `ipe.exe`; elsewhere it is `ipe`. `_exe` is
# the suffix to probe for so the same loop resolves either.
_exe=""
case "$(uname -s 2>/dev/null)" in MINGW*|MSYS*|CYGWIN*|Windows_NT) _exe=".exe" ;; esac
if [ -z "${IPE_BIN:-}" ]; then
  for _cand in \
    "$CARGO_TARGET_DIR/release/ipe$_exe" \
    "$CARGO_TARGET_DIR/debug/ipe$_exe" \
    "$REPO/target/release/ipe$_exe" \
    "$REPO/target/debug/ipe$_exe"; do
    if [ -x "$_cand" ]; then IPE_BIN="$_cand"; break; fi
  done
  # Last resort: a ipe on PATH.
  [ -z "${IPE_BIN:-}" ] && command -v ipe >/dev/null 2>&1 && IPE_BIN="$(command -v ipe)"
  unset _cand
fi
export IPE_BIN="${IPE_BIN:-$CARGO_TARGET_DIR/release/ipe$_exe}"
unset _exe

# ── Vendored runtime dir (ipe --runtime) ────────────────────────────────────
# ipe's build vendors the runtime module tree into each emitted crate. Left
# UNSET it auto-resolves by walking up to `$REPO/src/runtime/rust/src`
# (resolve_runtime() in src/ipe-cli/src/lib.rs). We export the explicit path so
# the sweep is independent of the invocation CWD; callers may override. The tree
# is the `ipe-runtime-rust` crate's source root — the `.rs` module files sit
# directly under it (no nested `ipe_runtime`/`ipe_runtime` subdir); a wrong path
# here makes `ipe dev build` mis-vendor the runtime and the emitted crate cargo-fails.
export IPE_RUNTIME_DIR="${IPE_RUNTIME_DIR:-$REPO/src/runtime/rust/src}"
