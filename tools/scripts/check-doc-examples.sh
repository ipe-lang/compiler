#!/usr/bin/env bash
# Doc-test gate for Ipê doc-string examples (component F).
#
# Judges every code block the standard library's doc pages serve, from
# `{-| … -}` and `-- |` doc comments alike, via `ipe doc --check-examples`.
#
# FENCE MARKERS
# ─────────────
# Blocks are read by the same fence scan the doc renderer uses. A block with
# `-->` annotations on expression lines is also used for result-assertion in
# the E2E tier (when IPE_E2E=1).
#
# EXIT
#   0 — every block agrees with src/ipe-cli/src/doc_examples_rot.txt
#   1 — a block disagrees with the ledger
#   2 — setup error (missing ipe binary)
#
set -euo pipefail

source "$(dirname "$0")/lib/env.sh"

if [ ! -x "$IPE_BIN" ]; then
    echo "ERROR: ipe binary not found at '$IPE_BIN'" >&2
    echo "       build with: cargo build --release -p ipe" >&2
    exit 2
fi

echo "=== Ipê doc-string example gate ==="
echo "    ipe binary: $IPE_BIN"
echo

"$IPE_BIN" doc --check-examples
