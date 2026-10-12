#!/usr/bin/env bash
# Regenerate every checked-in golden emit artifact from its source using the
# freshly-built `ipe` compiler. A golden dir that ships a `main.rs` is a
# byte-diff golden; rebuild it and copy the emitted artifacts over the stored
# ones:
#
#   * `src/main.rs`              -> `<golden>/main.rs`   (always)
#   * `src/ipe_mods/<mod>.rs`    -> `<golden>/ipe_mods/` (multi-module goldens)
#   * `Cargo.toml`               -> `<golden>/Cargo.toml` (goldens that check one
#                                     in) — the machine-specific dependency-model
#                                     runtime `path` is normalized to a stable
#                                     placeholder so the blessed manifest stays
#                                     portable across machines
#
# A golden dir is built from `Main.ipe` (single-file) or `ipe.toml` (project),
# whichever it ships. Dirs with only a `Main.ipe` and no `main.rs`
# (SEAL/run/exit-0 goldens) are left untouched — there is nothing to byte-diff.
#
# The default native emit is the dependency model, so the emitted `Cargo.toml`
# names the runtime as an absolute path dependency; the placeholder rewrite
# below mirrors the normalize-on-compare the golden tests apply.
#
# Usage:
#   source tools/scripts/lib/env.sh        # exports IPE_BIN + IPE_RUNTIME_DIR
#   tools/scripts/regen-goldens.sh [--check]
#
# --check regenerates into a scratch dir and DIFFS instead of overwriting,
# exiting non-zero on any drift (a dry-run gate).

set -euo pipefail

REPO="$(git rev-parse --show-toplevel)"
GOLDEN_ROOT="$REPO/tests/golden"
CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

: "${IPE_BIN:?source tools/scripts/lib/env.sh first (IPE_BIN unset)}"
: "${IPE_RUNTIME_DIR:?source tools/scripts/lib/env.sh first (IPE_RUNTIME_DIR unset)}"

# The token a blessed golden `Cargo.toml` stores in place of the machine-specific
# dependency-model runtime path (kept in sync with the golden tests' own
# `RUNTIME_PATH_PLACEHOLDER`).
PLACEHOLDER='__IPE_RUNTIME_PATH__'

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

regenerated=0
drift=0
skipped=0

# Rewrite the dependency-model runtime `path = "<abs>"` on the `ipe-runtime-rust`
# dependency line to the stable placeholder, leaving every other byte untouched.
normalize_manifest() {
    sed -E '/package = "ipe-runtime-rust"/ s#(path = ")[^"]*(")#\1'"$PLACEHOLDER"'\2#' "$1"
}

# Re-bless (or --check-diff) one emitted file against its golden counterpart.
# $1 = emitted path, $2 = golden path, $3 = "manifest" to normalize first.
bless_file() {
    local emitted="$1" golden="$2" kind="${3:-plain}"
    local rendered="$emitted"
    if [[ "$kind" == "manifest" ]]; then
        rendered="$scratch/normalized.$(basename "$golden")"
        normalize_manifest "$emitted" > "$rendered"
    fi
    if [[ "$CHECK" == "1" ]]; then
        if ! diff -q "$golden" "$rendered" > /dev/null 2>&1; then
            echo "DRIFT $(basename "$(dirname "$golden")")/$(basename "$golden")"
            drift=$((drift + 1))
        fi
    else
        cp -f "$rendered" "$golden"
        regenerated=$((regenerated + 1))
    fi
}

for dir in "$GOLDEN_ROOT"/*/; do
    name="$(basename "$dir")"
    golden_main_rs="$dir/main.rs"
    # Only regenerate dirs that already ship a byte-diff `main.rs`.
    [[ -f "$golden_main_rs" ]] || { skipped=$((skipped + 1)); continue; }

    out="$scratch/$name"
    rm -rf "$out"

    # Build from `Main.ipe` (single-file) or `ipe.toml` (project), whichever the
    # golden ships. Both land the emitted crate at "$out/rust/src/main.rs".
    built=0
    if [[ -f "$dir/Main.ipe" ]]; then
        if ( cd "$dir" && timeout 120 "$IPE_BIN" dev build "Main.ipe" --out "$out" ) \
                > "$scratch/$name.log" 2>&1; then
            built=1
        fi
    elif [[ -f "$dir/ipe.toml" ]]; then
        if ( cd "$dir" && timeout 120 "$IPE_BIN" dev build --out "$out" ) \
                > "$scratch/$name.log" 2>&1; then
            built=1
        fi
    fi
    if [[ "$built" != 1 ]]; then
        echo "SKIP $name: ipe dev build failed or no buildable source (not a plain-emit golden?)" >&2
        skipped=$((skipped + 1))
        continue
    fi

    emitted="$out/rust/src/main.rs"
    [[ -f "$emitted" ]] || { echo "SKIP $name: no emitted src/main.rs" >&2; skipped=$((skipped + 1)); continue; }

    bless_file "$emitted" "$golden_main_rs" plain

    # Multi-module split files: re-bless every emitted `src/ipe_mods/<mod>.rs`
    # over the checked-in golden of the same name. Only touch modules the golden
    # already tracks — a golden that carries no `ipe_mods/` gets none.
    if [[ -d "$dir/ipe_mods" ]]; then
        for gm in "$dir/ipe_mods"/*.rs; do
            [[ -f "$gm" ]] || continue
            em="$out/src/ipe_mods/$(basename "$gm")"
            [[ -f "$em" ]] || { echo "SKIP $name: emitted lacks ipe_mods/$(basename "$gm")" >&2; continue; }
            bless_file "$em" "$gm" plain
        done
    fi

    # Manifest golden: re-bless the emitted `Cargo.toml` with the runtime path
    # normalized to the placeholder, when the golden checks one in.
    if [[ -f "$dir/Cargo.toml" && -f "$out/Cargo.toml" ]]; then
        bless_file "$out/Cargo.toml" "$dir/Cargo.toml" manifest
    fi
done

if [[ "$CHECK" == "1" ]]; then
    echo "checked goldens; drift=$drift skipped=$skipped"
    [[ "$drift" == "0" ]]
else
    echo "regenerated $regenerated golden files; skipped=$skipped"
fi
