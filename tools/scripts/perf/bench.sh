#!/usr/bin/env bash
# Ipê dev-loop performance harness — WALL-CLOCK (not CPU) benchmarks.
#
# Drives the reference served `Ipe.Tea.Web` app in `fixture/` with the SAME
# commands a user runs (`ipe dev build`, `ipe dev run`, `ipe dev watch`) and reports the
# numbers surfaced in README.md:
#
#   * Cold build          — a clean, from-scratch `ipe dev build` (full `rustc`).
#   * Warm build          — the incremental rebuild `ipe dev watch` falls back to only
#     (= App recompilation)  for a TYPE change (a `Model` field, a signature). Every
#                            other edit — text, `init`, `update`, subscriptions,
#                            styles — hot-swaps instead (below), so a recompile is
#                            the rare case.
#   * Dev watch hot reload — a non-type Ui edit (a style value) pushed by
#                            `ipe dev watch` with no `cargo` at all; measured
#                            end-to-end (edit → served HTML reflects it), in ms.
#   * Release binary size — the running app binary's size on disk.
#   * Peak RAM            — RSS high-water of the running served app.
#
# Both `ipe dev run` and `ipe dev watch` default to port 8000; the harness pins each to
# a free port instead (`IPE_WEB_PORT` for run, `--port` for watch) so a stray
# server can never collide. Nothing is built in-tree: the fixture is copied to a
# scratch dir.
# Usage:  IPE=/path/to/ipe [IPE_RUNTIME_DIR=…] tools/scripts/perf/bench.sh [--json]
set -uo pipefail

IPE="${IPE:-ipe}"
JSON=0; [ "${1:-}" = "--json" ] && JSON=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRATCH_ROOT="${IPE_PERF_SCRATCH:-/mnt/ipe-scratch/perf}"
mkdir -p "$SCRATCH_ROOT" 2>/dev/null || SCRATCH_ROOT="${TMPDIR:-/tmp}"
WORK="$(mktemp -d "$SCRATCH_ROOT/ipe-perf.XXXXXX")"
MAIN="$WORK/src/Main.ipe"

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; pkill -f "$WORK" 2>/dev/null || true; rm -rf "$WORK" 2>/dev/null || true; }
trap cleanup EXIT

now_s() { date +%s.%N; }
now_ms() { date +%s%3N; }
secs() { awk "BEGIN{printf \"%.2f\", $2 - $1}"; }
note() { [ "$JSON" = 0 ] && printf '%s\n' "perf: $*" >&2 || true; }
build() { ( cd "$WORK" && $IPE dev build -q ) >"$1" 2>&1; }
# A free TCP port on loopback (python3, else a fixed high port).
free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()' 2>/dev/null || echo 8731; }
# Poll (≤ N*0.1s) until GET / on $1 answers; 0 on success.
wait_http() { local port="$1" n="${2:-600}"; for _ in $(seq 1 "$n"); do curl -fsS "http://127.0.0.1:$port/" >/dev/null 2>&1 && return 0; sleep 0.1; done; return 1; }
# Wait (≤ N*0.1s) until nothing LISTENs on $1.
wait_port_free() { local port="$1" n="${2:-100}"; for _ in $(seq 1 "$n"); do ss -ltnH "sport = :$port" 2>/dev/null | rg -q . || return 0; sleep 0.1; done; return 1; }

cp -r "$HERE/fixture/." "$WORK/"
note "fixture → $WORK (ipe: $($IPE version 2>/dev/null | tr -d '\n' || echo "$IPE"))"
COLD=n/a WARM=n/a HOT=n/a BIN=n/a RAM=n/a

# 1. Cold build.
note "[1/4] cold build …"; ( cd "$WORK" && $IPE clean >/dev/null 2>&1 || true )
t0=$(now_s); if build /tmp/ipe-perf-cold.log; then t1=$(now_s); COLD=$(secs "$t0" "$t1")
else note "  cold build FAILED:"; tail -6 /tmp/ipe-perf-cold.log >&2; fi
note "  cold build = ${COLD}s"

# 2. Warm build = App recompilation — a TYPE change forces the rebuild.
if [ "$COLD" != n/a ]; then
  note "[2/4] warm build (type change → recompile) …"
  sed -i 's/{ count : Int }/{ count : Int, seen : Bool }/;s/{ count = 0 }/{ count = 0, seen = False }/' "$MAIN"
  t0=$(now_s); build /tmp/ipe-perf-warm.log && { t1=$(now_s); WARM=$(secs "$t0" "$t1"); }
  sed -i 's/{ count : Int, seen : Bool }/{ count : Int }/;s/{ count = 0, seen = False }/{ count = 0 }/' "$MAIN"
  note "  warm build = ${WARM}s"
fi

# 3+4. Peak RAM + binary size — off the running server (real `ipe dev run`).
if [ "$COLD" != n/a ]; then
  note "[3/4] peak RAM + binary size (ipe dev run) …"
  RPORT=$(free_port)
  ( cd "$WORK" && IPE_WEB_PORT="$RPORT" $IPE dev run -q >/tmp/ipe-perf-run.log 2>&1 ) & PIDS+=($!)
  if wait_http "$RPORT" 900; then
    SRV=$(ss -ltnHp "sport = :$RPORT" 2>/dev/null | rg -o 'pid=[0-9]+' | rg -o '[0-9]+' | head -1)
    if [ -n "${SRV:-}" ]; then
      RK=$(awk '/VmHWM/{print $2}' "/proc/$SRV/status" 2>/dev/null); [ -n "${RK:-}" ] && RAM=$(awk "BEGIN{printf \"%.1f\", $RK/1024}")
      EXE=$(readlink -f "/proc/$SRV/exe" 2>/dev/null); [ -n "${EXE:-}" ] && [ -f "$EXE" ] && BIN=$(awk "BEGIN{printf \"%.1f\", $(stat -c%s "$EXE")/1048576}")
    fi
  else note "  ipe dev run never served on :$RPORT:"; tail -6 /tmp/ipe-perf-run.log >&2; fi
  pkill -f "$WORK" 2>/dev/null || true; wait_port_free "$RPORT" || true
  note "  peak RAM = ${RAM} MB · binary = ${BIN} MB"
fi

# Y. Dev watch hot reload — appearance edit, end-to-end, no cargo.
note "[4/4] dev watch hot reload …"
WPORT=$(free_port)
( cd "$WORK" && $IPE dev watch -q --port "$WPORT" >/tmp/ipe-perf-watch.log 2>&1 ) & PIDS+=($!)
if wait_http "$WPORT" 1500; then
  up=0; for _ in $(seq 1 300); do curl -fsS "http://127.0.0.1:$WPORT/" 2>/dev/null | rg -q '#ffffff' && { up=1; break; }; sleep 0.2; done
  if [ "$up" = 1 ]; then
    t0=$(now_ms); sed -i 's/#ffffff/#eeeeee/' "$MAIN"; applied=0
    for _ in $(seq 1 500); do curl -fsS "http://127.0.0.1:$WPORT/" 2>/dev/null | rg -q '#eeeeee' && { applied=1; break; }; sleep 0.02; done
    t1=$(now_ms); [ "$applied" = 1 ] && HOT=$((t1 - t0)); sed -i 's/#eeeeee/#ffffff/' "$MAIN"
  else note "  watch served but initial value not found"; fi
else note "  watch never served on :$WPORT:"; tail -6 /tmp/ipe-perf-watch.log >&2; fi
pkill -f "$WORK" 2>/dev/null || true
note "  dev watch hot reload = ${HOT} ms"

if [ "$JSON" = 1 ]; then
  printf '{"cold_build_s":"%s","warm_build_s":"%s","hot_reload_ms":"%s","binary_mb":"%s","peak_ram_mb":"%s"}\n' "$COLD" "$WARM" "$HOT" "$BIN" "$RAM"
else
  echo; echo "── Ipê dev-loop perf (wall-clock) ─────────────────────────────"
  printf '  Cold build (from clean)   : %s s\n'  "$COLD"
  printf '  Warm build / recompilation: %s s\n'  "$WARM"
  printf '  Dev watch hot reload      : %s ms\n' "$HOT"
  printf '  App binary size           : %s MB\n' "$BIN"
  printf '  Peak RAM (served app)     : %s MB\n' "$RAM"
  echo   "───────────────────────────────────────────────────────────────"
fi
