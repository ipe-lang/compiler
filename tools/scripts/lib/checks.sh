# shellcheck shell=bash
# tools/scripts/lib/checks.sh — SINGLE SOURCE OF TRUTH for the per-shape "exercise an
# already-built binary" logic. SOURCE this (never execute it):
#   source "$(dirname "$0")/lib/checks.sh"
#
# The exercise_* contract is backend-agnostic: it drives a built binary and asks
# "did it work?" per shape (cli/server/live/tui/webview/wasm). night_guard is
# OPT-IN (IPE_SWEEP_NIGHT_GATE=1) so it NEVER blocks GitHub CI. resolve_bin looks
# under out/rust/target and the shared CARGO_TARGET_DIR for the emitted binary,
# using the name from the project's emitted Cargo.toml (default: ipe-app).
#
# Depends on lib/env.sh being sourced first (CARGO_TARGET_DIR, PATH, REPO). It is
# idempotent and side-effect-light at source time (a few exports).

# ── Shared exercise env ─────────────────────────────────────────────────────
# Server/live examples that use Ipe.Auth refuse to boot without a >=32-byte
# secret (CORRECT production behaviour). Provide a test secret so those apps boot;
# honoured only if the caller hasn't set their own.
export IPE_AUTH_TOKEN_SECRET="${IPE_AUTH_TOKEN_SECRET:-ipe-run-sweep-test-secret-0123456789-abcdef}"

# ── Panic detection (shared) ────────────────────────────────────────────────
# A Rust panic / abort string in a binary's output = a soundness failure (the
# whole reason the Rust backend exists). Go panics surface the same way, so the
# pattern catches both backends' aborts.
PANIC_RE="panicked|CompilerBug|RUST_BACKTRACE|index out of bounds|unwrap\(\) on|called .Result::unwrap|goroutine [0-9]+ \[|runtime error:"

# ── Host OS detection (shared) ───────────────────────────────────────────────
case "${OSTYPE:-}" in
  linux*)            IPE_HOST_OS=linux   ;;
  darwin*)           IPE_HOST_OS=macos   ;;
  msys*|cygwin*|win*) IPE_HOST_OS=windows ;;
  *)
    case "$(uname -s 2>/dev/null)" in
      Linux)                       IPE_HOST_OS=linux   ;;
      Darwin)                      IPE_HOST_OS=macos   ;;
      MINGW*|MSYS*|CYGWIN*|Windows_NT) IPE_HOST_OS=windows ;;
      *)                           IPE_HOST_OS=linux   ;;
    esac
    ;;
esac
export IPE_HOST_OS

# ── EXERCISE_SKIP_RC: the rc an exercise_* returns when this HOST can't run the
# shape at all (no pty / no display) — distinct from 0 (pass) and 1 (fail).
EXERCISE_SKIP_RC=125

# ── night_guard <sweep-name>: OPT-IN local deferral window ───────────────────
# PORT NOTE: upstream night-gated this heavy sweep to 22:00–08:00 America/Sao_Paulo
# on a slim shared box AND that gate blocked nothing on CI (CI set IPE_SWEEP_FORCE).
# Here it is OFF BY DEFAULT so it can NEVER block GitHub CI. Set
# IPE_SWEEP_NIGHT_GATE=1 to re-enable the local low-load window; IPE_SWEEP_FORCE=1
# still overrides it. When enabled + outside the window + not forced → exit 2.
night_guard() {
  local sweep="${1:-sweep}" hour
  [ "${IPE_SWEEP_NIGHT_GATE:-0}" = 1 ] || return 0   # gate disabled → no-op (default)
  [ -n "${IPE_SWEEP_FORCE:-}" ] && return 0
  hour="$(TZ=America/Sao_Paulo date +%H 2>/dev/null)"
  hour="$((10#${hour:-12}))"
  if [ "$hour" -ge 22 ] || [ "$hour" -lt 8 ]; then return 0; fi
  echo "deferred: $sweep runs 22:00–08:00 America/Sao_Paulo (IPE_SWEEP_NIGHT_GATE=1); set IPE_SWEEP_FORCE=1 to override" >&2
  exit 2
}

# ── http_responds <code>: any real HTTP status (100-599) = serving ──────────
http_responds() { case "$1" in [1-5][0-9][0-9]) return 0;; *) return 1;; esac; }

# ── free_port: an ephemeral free TCP port. FAIL-CLOSED (no fixed fallback) ───
free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()' 2>/dev/null; }

# ── reap [bin-name]: kill stray app / driver / Xvfb processes between examples ─
# Optional first arg: the manifest-derived binary name for this example (kills it
# by exact name in addition to the ipe-app default and the out/-path pattern).
reap() {
  command -v pkill >/dev/null 2>&1 || return 0
  local names=("ipe-app" "app")
  [ -n "${1:-}" ] && names+=("$1")
  for p in "${names[@]}"; do pkill -x "$p" 2>/dev/null; done
  pkill -f "examples/.*/out/" 2>/dev/null; pkill -f wasm-verify.mjs 2>/dev/null
  pkill -x Xvfb 2>/dev/null
}

# ── Node PATH for the wasm RUN check (wasm-verify.mjs) ───────────────────────
NODE_BIN="$(for _nb in "$HOME"/.nvm/versions/node/*/bin; do [ -d "$_nb" ] && printf '%s\n' "$_nb"; done | sort -V | tail -1)"
export PATH="${NODE_BIN:+$NODE_BIN:}$PATH"

# ── scenario_for <example-name>: the wasm browser scenario key for an example ─
# The wasm RUN check (wasm-verify.mjs) takes a scenario key. There is no
# per-example interaction scenario file, so every example degrades to `smoke`
# (boot + non-empty body only). Kept as a function so the key derivation lives
# in one place if named scenarios are wired later.
scenario_for() {
  local ex="$1"
  echo "$ex" | sed -E 's/^[0-9]+-//' >/dev/null
  echo smoke
}

# ── resolve_bin <example-dir>: the freshest Rust binary ipe just built ──────
# The binary name matches the `[package] name` in the emitted out/rust/Cargo.toml
# (which the compiler sanitizes from ipe.toml's `name`). Projects with no `name`
# emit the default `ipe-app`. Probe the shared CARGO_TARGET_DIR first (fastest),
# then the per-example target, then fall back to the newest executable found.
resolve_bin() {
  local d="$1" bin_name b exe=""
  # On Windows the emitted binary carries the .exe suffix; elsewhere it does not.
  [ "${IPE_HOST_OS:-}" = windows ] && exe=".exe"
  bin_name="$(sed -n 's/^name = "\(.*\)"/\1/p' "$d/out/rust/Cargo.toml" 2>/dev/null | head -1)"
  bin_name="${bin_name:-ipe-app}"
  # Static sweep (IPE_SWEEP_STATIC=1): the artifact lives under the target
  # triple's subdir. NEVER fall through to the dynamic probes — a stale
  # dynamic artifact would silently substitute for the static one.
  if [ "${IPE_SWEEP_STATIC:-0}" = 1 ]; then
    local triple="${IPE_STATIC_TRIPLE:-x86_64-unknown-linux-musl}"
    for b in \
      "$CARGO_TARGET_DIR/$triple/debug/$bin_name$exe" \
      "$d/out/rust/target/$triple/debug/$bin_name$exe"; do
      [ -x "$b" ] && [ ! -d "$b" ] && { echo "$b"; return 0; }
    done
    return 1
  fi
  for b in \
    "$CARGO_TARGET_DIR/debug/$bin_name$exe" \
    "$CARGO_TARGET_DIR/release/$bin_name$exe" \
    "$d/out/rust/target/debug/$bin_name$exe"; do
    [ -n "$b" ] && [ -x "$b" ] && [ ! -d "$b" ] && { echo "$b"; return 0; }
  done
  b="$(find "$CARGO_TARGET_DIR/debug" "$d/out/rust/target/debug" -maxdepth 1 -type f -executable 2>/dev/null \
        | xargs -r ls -t 2>/dev/null | head -1)"
  [ -n "$b" ] && { echo "$b"; return 0; }
  return 1
}

# ── assert_static_bin <bin>: ldd says the binary is genuinely static ─────────
# ldd exits non-zero for a static binary on some platforms; the MESSAGE is the
# contract ("statically linked" / "not a dynamic executable").
assert_static_bin() {
  local out; out="$(ldd "$1" 2>&1)"
  case "$out" in
    *"statically linked"*|*"not a dynamic executable"*) return 0 ;;
    *) return 1 ;;
  esac
}

# _abs_bin <path> -> absolute path (passthrough if already absolute).
_abs_bin() { case "$1" in /*) printf '%s\n' "$1";; *) printf '%s/%s\n' "$(cd "$(dirname "$1")" 2>/dev/null && pwd)" "$(basename "$1")";; esac; }

# ════════════════════════════════════════════════════════════════════════════
# exercise_* — drive an already-built binary per shape. 0=pass / 1=fail /
# EXERCISE_SKIP_RC=skip. Each writes the binary's stdout+stderr to <logfile> and
# runs from a fresh TMPDIR scratch cwd (so cwd-relative state never leaks into
# the repo root).
# ════════════════════════════════════════════════════════════════════════════

# exercise_cli <bin> <logfile> [timeout]
exercise_cli() {
  local bin="$1" log="$2" tmo="${3:-25}" rc tries=0 abin run_dir
  abin="$bin"; case "$bin" in /*) ;; *) abin="$(cd "$(dirname "$bin")" 2>/dev/null && pwd)/$(basename "$bin")";; esac
  run_dir="$(mktemp -d "${TMPDIR:-/tmp}/ipe-cli.XXXXXX")"
  while :; do
    ( cd "$run_dir" && exec timeout "$tmo" "$abin" ) >"$log" 2>&1 </dev/null; rc=$?
    { [ "$rc" = 126 ] || grep -qiE 'text file busy|texto ocupada|ETXTBSY' "$log" 2>/dev/null; } || break
    tries=$((tries+1)); [ "$tries" -ge 10 ] && break; sync; sleep 0.4
  done
  rm -rf "$run_dir" 2>/dev/null
  if   [ "$rc" = 124 ]; then return 1            # timeout / hang
  elif grep -qiE "$PANIC_RE" "$log"; then return 1   # panic (caller greps to label)
  elif [ "$rc" != 0 ]; then return 3             # non-zero exit = a real failure
  fi
  return 0
}

# exercise_server <bin> <port> <logfile>
exercise_server() {
  local bin="$1" port="$2" log="$3" pid i code lp code2 ok="" run_dir abin
  abin="$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")"
  run_dir="$(mktemp -d "${TMPDIR:-/tmp}/ipe-serve.XXXXXX")"
  ( cd "$run_dir" && exec env IPE_WEB_PORT="$port" PORT="$port" "$abin" ) >"$log" 2>&1 </dev/null &
  pid=$!
  for i in $(seq 1 30); do
    kill -0 "$pid" 2>/dev/null || break
    code="$(curl -s -o /dev/null -m 1 -w '%{http_code}' "http://127.0.0.1:$port/" 2>/dev/null || true)"
    http_responds "$code" && { ok=1; break; }
    lp="$(grep -iE "listening on" "$log" | grep -oE ":[0-9]+" | tail -1 | tr -d ':')"
    if [ -n "$lp" ] && [ "$lp" != "$port" ]; then
      code2="$(curl -s -o /dev/null -m 1 -w '%{http_code}' "http://127.0.0.1:$lp/" 2>/dev/null || true)"
      http_responds "$code2" && { ok=1; break; }
    fi
    sleep 0.5
  done
  kill -TERM "$pid" 2>/dev/null; sleep 0.5; kill -KILL "$pid" 2>/dev/null
  rm -rf "$run_dir" 2>/dev/null
  if grep -qiE "$PANIC_RE" "$log"; then return 1; fi
  [ -n "$ok" ] && return 0
  if [ "${IPE_HOST_OS:-}" = macos ] && grep -qiE "listening on" "$log"; then
    return "$EXERCISE_SKIP_RC"
  fi
  return 1
}

# exercise_tui <bin> <logfile>  (pty smoke, OS-aware)
exercise_tui() {
  local bin="$1" log="$2" abin run_dir
  abin="$(_abs_bin "$bin")"
  run_dir="$(mktemp -d "${TMPDIR:-/tmp}/ipe-tui.XXXXXX")"
  case "$IPE_HOST_OS" in
    macos)
      if command -v script >/dev/null 2>&1; then
        ( cd "$run_dir" && script -q /dev/null timeout 8 "$abin" ) >"$log" 2>&1 </dev/null
      else
        printf 'SKIP (macos: no `script` for pty)\n' >"$log"; rm -rf "$run_dir" 2>/dev/null; return "$EXERCISE_SKIP_RC"
      fi
      ;;
    windows)
      printf 'SKIP (windows: headless pty needs ConPTY/node-pty — not yet wired)\n' >"$log"
      rm -rf "$run_dir" 2>/dev/null
      return "$EXERCISE_SKIP_RC"
      ;;
    *)
      local q_bin
      printf -v q_bin '%q' "$abin"
      ( cd "$run_dir" && script -qec "timeout 8 $q_bin" /dev/null ) >"$log" 2>&1 </dev/null
      ;;
  esac
  rm -rf "$run_dir" 2>/dev/null
  if   grep -qiE "$PANIC_RE" "$log"; then return 1
  elif grep -qiE "not a tty|inappropriate ioctl|TERM environment" "$log"; then return 1
  fi
  return 0
}

# exercise_webview <bin> <logfile>  (OS-aware headless smoke; under xvfb-run,
# the verdict is the program's own recorded exit status, never xvfb-run's own
# wrapper status, and a run whose status was never recorded is refused)
exercise_webview() {
  local bin="$1" log="$2" abin run_dir
  abin="$(_abs_bin "$bin")"
  run_dir="$(mktemp -d "${TMPDIR:-/tmp}/ipe-webview.XXXXXX")"
  case "$IPE_HOST_OS" in
    macos)
      ( cd "$run_dir" && timeout 8 "$abin" ) >"$log" 2>&1 </dev/null
      ;;
    windows)
      ( cd "$run_dir" && timeout -k 5 8 "$abin" ) >"$log" 2>&1 </dev/null
      ;;
    *)
      if ! command -v xvfb-run >/dev/null 2>&1; then
        printf 'SKIP (linux: xvfb-run not installed)\n' >"$log"; rm -rf "$run_dir" 2>/dev/null; return "$EXERCISE_SKIP_RC"
      fi
      local status_file="$run_dir/xvfb-exit-status"
      ( cd "$run_dir" && xvfb-run -a sh -c 'timeout "$1" "$2"; printf %s "$?" >"$3"' sh 8 "$abin" "$status_file" ) >"$log" 2>&1 </dev/null
      if ! grep -qE '^[0-9]+$' "$status_file" 2>/dev/null; then
        printf '\nthe program'"'"'s exit status was never recorded under xvfb-run\n' >>"$log"
        rm -rf "$run_dir" 2>/dev/null
        return 1
      fi
      ;;
  esac
  rm -rf "$run_dir" 2>/dev/null
  grep -qiE "$PANIC_RE" "$log" && return 1
  return 0
}
