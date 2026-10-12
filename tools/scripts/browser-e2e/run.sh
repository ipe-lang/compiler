#!/usr/bin/env bash
# Run the browser E2E Playwright specs against locally built binaries.
#
# Usage:
#   bash tools/scripts/browser-e2e/run.sh [GEO_PORT] [LAYOUT_PORT] [FOCUS_PORT]
#
# GEO_PORT defaults to 18080, LAYOUT_PORT to 18081 and FOCUS_PORT to 18082.
# The script:
#   1. Builds the ipe compiler (cargo build -p ipe --release).
#   2. Compiles each example (geo-clipboard, layout-fill, focus-across-patch)
#      via `ipe dev build`.
#   3. Cargo-builds each emitted Rust project.
#   4. Spawns each binary on its port.
#   5. Runs the Playwright specs.
#   6. Kills the binaries on exit.
#
# Prerequisites: node, npx, Rust toolchain, IPE_RUNTIME_DIR set (or run
# from the repo root where scripts/ipe-index wakeup auto-discovers it).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SPEC_DIR="$(cd "$(dirname "$0")" && pwd)"
GEO_PORT="${1:-18080}"
LAYOUT_PORT="${2:-18081}"
FOCUS_PORT="${3:-18082}"

export IPE_GEO_CLIPBOARD_PORT="$GEO_PORT"
export IPE_LAYOUT_FILL_PORT="$LAYOUT_PORT"
export IPE_FOCUS_ACROSS_PATCH_PORT="$FOCUS_PORT"
export IPE_RUNTIME_DIR="${IPE_RUNTIME_DIR:-$REPO_ROOT/src/runtime/rust/src}"

echo "==> Building ipe compiler..."
cargo build --release -p ipe --manifest-path "$REPO_ROOT/Cargo.toml"
IPE="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release/ipe"

SERVER_PIDS=()
trap 'for pid in "${SERVER_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done' EXIT

# serve NAME PORT — compile, cargo-build and spawn examples/shapes/web/NAME,
# then block until it answers on PORT (fail closed on a dead port).
serve() {
  local name="$1" port="$2"
  local out="${TMPDIR:-/tmp}/$name-browser-e2e"

  echo "==> Compiling $name example..."
  rm -rf "$out"
  "$IPE" dev build "$REPO_ROOT/examples/shapes/web/$name/package.ipe" --out "$out"

  echo "==> Cargo-building emitted $name project..."
  cargo build --release --manifest-path "$out/rust/Cargo.toml"
  # The binary is the emitted `[package] name`, under CARGO_TARGET_DIR when set.
  local pkg binary
  pkg="$(sed -n 's/^name = "\(.*\)"$/\1/p;T;q' "$out/rust/Cargo.toml")"
  binary="${CARGO_TARGET_DIR:-$out/rust/target}/release/$pkg"
  if [ -z "$pkg" ] || [ ! -x "$binary" ]; then
    echo "   $name binary not found at '$binary'" >&2
    exit 1
  fi

  echo "==> Spawning $name server on port $port..."
  IPE_WEB_PORT="$port" IPE_CSRF=off IPE_CONSOLE_EMBED=off "$binary" &
  SERVER_PIDS+=("$!")

  echo "==> Waiting for $name server readiness..."
  local ready="" i
  for i in $(seq 1 40); do
    if curl -sf --max-time 2 "http://127.0.0.1:$port/" >/dev/null 2>&1; then
      echo "   server ready (attempt $i)"
      ready=1
      break
    fi
    sleep 0.5
  done
  # Fail closed: an unready server means Playwright runs against a dead port.
  if [ -z "$ready" ]; then
    echo "   $name server never became ready on port $port" >&2
    exit 1
  fi
}

serve geo-clipboard "$GEO_PORT"
serve layout-fill "$LAYOUT_PORT"
serve focus-across-patch "$FOCUS_PORT"

echo "==> Installing Playwright + Chromium (if not cached)..."
cd "$SPEC_DIR"
npm install --save-dev @playwright/test 2>/dev/null || true
npx playwright install chromium 2>/dev/null || true

echo "==> Running Playwright specs..."
npx playwright test --config playwright.config.mjs

echo "==> Done. Screenshots in $SPEC_DIR/artifacts/"
