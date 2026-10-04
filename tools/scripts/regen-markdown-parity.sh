#!/usr/bin/env bash
# Regenerate the Markdown semantic-parity snapshot.
#
# `Ipe.Markdown` is the Markdown parse authority. This runs the parity
# serializer (examples/shapes/script/markdown-parity) through `ipe dev run` and
# writes its stdout to the committed snapshot the doc-side Rust port is checked
# against. The snapshot is therefore produced by an actual `ipe` run — never
# hand-authored — so `Ipe.Markdown` stays the single source of truth and any
# drift reddens CI (see the `markdown-parity` job: regenerate then
# `tools/scripts/generated-unchanged.sh`).
#
# Usage:
#   tools/scripts/regen-markdown-parity.sh [path-to-ipe-binary]
#
# With no argument, builds the `ipe` binary with cargo and uses it.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
serializer_dir="$repo_root/examples/shapes/script/markdown-parity"
snapshot="$repo_root/src/ipe-docs/src/markdown/parity/snapshot.txt"

if [[ $# -ge 1 ]]; then
  ipe_bin="$1"
else
  echo "regen-markdown-parity: building the ipe binary…" >&2
  cargo build -p ipe --bin ipe >&2
  ipe_bin="$(cargo metadata --format-version 1 --no-deps \
    | grep -o '"target_directory":"[^"]*"' | head -1 | cut -d'"' -f4)/debug/ipe"
fi

# Build output goes to a private scratch dir, so the regen leaves the source
# tree untouched. The snapshot is renamed into place only once the run
# succeeds, so a failed run never leaves it truncated.
scratch="$(mktemp -d)"
staged="$(mktemp "$snapshot.XXXXXX")"
trap 'rm -rf "$scratch" "$staged"' EXIT

echo "regen-markdown-parity: running the serializer via $ipe_bin…" >&2
# `ipe dev run` emits + builds + runs the serializer; its stdout is the snapshot.
( cd "$serializer_dir" && "$ipe_bin" dev run --out "$scratch/out" ) > "$staged"
mv "$staged" "$snapshot"

echo "regen-markdown-parity: wrote $snapshot" >&2
