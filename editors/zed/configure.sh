#!/bin/sh
# editors/zed/configure.sh — prepares the Ipê extension for Zed.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/ipe-lang/compiler/main/editors/zed/configure.sh | sh
#   (or from a checkout: sh editors/zed/configure.sh)
#
# What it does:
#   1. Preflight: ipe, zed (or zeditor), rustup + cargo (Zed compiles the
#      extension's Rust part itself), git.
#   2. Assembles the extension (editors/zed-ipe + the grammar's highlight
#      queries) into ${XDG_DATA_HOME:-~/.local/share}/ipe/zed-ipe, pinning
#      Zed's grammar checkout to the commit the queries came from.
#   3. Prints the one step Zed only offers in its UI: install that directory
#      as a dev extension. The extension provides highlighting and starts
#      `ipe lsp` itself — settings.json is never edited.
#
# Environment: IPE_EDITORS_REF (git ref a curl run fetches, default main),
# XDG_DATA_HOME, XDG_CONFIG_HOME.

set -eu

# --- bootstrap the shared helpers (local checkout, else the same ref) -------
IPE_EDITORS_REF="${IPE_EDITORS_REF:-main}"
IPE_SRC_ROOT=""
case "$0" in
    */configure.sh)
        _d="$(cd "$(dirname "$0")/../.." 2>/dev/null && pwd)" || _d=""
        if [ -n "$_d" ] && [ -f "$_d/editors/lib/ipe-editors.sh" ]; then IPE_SRC_ROOT="$_d"; fi ;;
esac
if [ -n "$IPE_SRC_ROOT" ]; then
    # shellcheck source=../lib/ipe-editors.sh
    . "$IPE_SRC_ROOT/editors/lib/ipe-editors.sh"
else
    _lib="$(mktemp)" || exit 1
    curl -fsSL "https://raw.githubusercontent.com/ipe-lang/compiler/$IPE_EDITORS_REF/editors/lib/ipe-editors.sh" -o "$_lib" \
        || { rm -f "$_lib"; printf 'error: cannot download editors/lib/ipe-editors.sh\n' >&2; exit 1; }
    # shellcheck source=/dev/null
    . "$_lib"
    rm -f "$_lib"
fi
IPE_TAG="Zed"

# --- preflight ---------------------------------------------------------------
need ipe "install the Ipê toolchain first: https://github.com/ipe-lang/compiler"
if ! ipe_have zed && ! ipe_have zeditor; then
    die "Zed not found ('zed' or 'zeditor' on PATH) — install Zed first: https://zed.dev"
fi
need rustup "Zed builds the extension's Rust part with rustup — install it: https://rustup.rs"
need cargo "install a Rust toolchain with rustup: https://rustup.rs"
need git "Zed fetches the grammar with git"
# Zed compiles the extension for wasm32-wasip2 and adds the target itself when
# missing, but only via rustup — silently, inside its UI, on the first install
# attempt. Adding it here up front turns a missing target into a clear message
# now instead of Zed's opaque "compiling Rust extension" failure later.
rustup target add wasm32-wasip2 > /dev/null 2>&1 \
    || warn "could not add the wasm32-wasip2 rustup target automatically — Zed builds this extension for it; run \`rustup target add wasm32-wasip2\` by hand"

EXT_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/ipe/zed-ipe"

# --- the one revision everything comes from ------------------------------------------
# Zed clones the grammar from extension.toml's `repository` at `rev`; the
# highlight query is assembled below. Both come from one commit, fixed here: a
# checkout's HEAD (served to Zed from the checkout itself, so an unpushed or
# squash-merged commit works) or the commit IPE_EDITORS_REF names on GitHub.
GRAMMAR_PATHS="$IPE_GRAMMAR_DIR/src $IPE_GRAMMAR_DIR/queries/highlights.scm"
if [ -n "$IPE_SRC_ROOT" ]; then
    SRC_REAL="$(cd "$IPE_SRC_ROOT" && pwd -P)" || die "cannot resolve $IPE_SRC_ROOT"
    SRC_TOP="$(git -C "$SRC_REAL" rev-parse --show-toplevel 2> /dev/null)" || SRC_TOP=""
    [ "$SRC_TOP" = "$SRC_REAL" ] \
        || die "$SRC_REAL is not a git checkout — Zed fetches the grammar with git; use the curl install instead"
    # shellcheck disable=SC2086
    dirty="$(git -C "$SRC_REAL" status --porcelain --untracked-files=all -- $GRAMMAR_PATHS)" \
        || die "cannot read the git status of $SRC_REAL"
    [ -z "$dirty" ] \
        || die "uncommitted grammar or highlight-query changes in $SRC_REAL — Zed builds the committed grammar, so commit or stash them first"
    GRAMMAR_REV="$(git -C "$SRC_REAL" rev-parse --verify 'HEAD^{commit}')" \
        || die "$SRC_REAL has no commit to pin the grammar to"
    # Zed compares this URL byte for byte and it lands in a TOML string.
    case "$SRC_REAL" in
        *[\"\\%]*) die "the checkout path $SRC_REAL contains \", \\ or %, which Zed's grammar URL cannot carry — move the checkout" ;;
    esac
    [ -z "$(printf '%s' "$SRC_REAL" | LC_ALL=C tr -d '\040-\176\200-\377')" ] \
        || die "the checkout path $SRC_REAL contains a control character — move the checkout"
    # Zed trims the clone's origin URL before comparing it, so a URL ending in
    # whitespace (Unicode White_Space) never matches on a rebuild.
    for _ws in ' ' "$(printf '\302\205')" "$(printf '\302\240')" "$(printf '\341\232\200')" \
        "$(printf '\342\200\200')" "$(printf '\342\200\201')" "$(printf '\342\200\202')" \
        "$(printf '\342\200\203')" "$(printf '\342\200\204')" "$(printf '\342\200\205')" \
        "$(printf '\342\200\206')" "$(printf '\342\200\207')" "$(printf '\342\200\210')" \
        "$(printf '\342\200\211')" "$(printf '\342\200\212')" "$(printf '\342\200\250')" \
        "$(printf '\342\200\251')" "$(printf '\342\200\257')" "$(printf '\342\201\237')" \
        "$(printf '\343\200\200')"; do
        case "$SRC_REAL" in
            *"$_ws") die "the checkout path $SRC_REAL ends in whitespace, which Zed's grammar URL cannot carry — move the checkout" ;;
        esac
    done
    GRAMMAR_REPOSITORY="file://$SRC_REAL"
else
    GRAMMAR_REV="$(ipe_resolve_ref "$IPE_EDITORS_REF")"
    GRAMMAR_REPOSITORY="https://github.com/$IPE_REPO_SLUG"
    IPE_RAW_BASE="https://raw.githubusercontent.com/$IPE_REPO_SLUG/$GRAMMAR_REV"
fi

# --- assemble the extension -------------------------------------------------------
# The highlight queries come straight from the grammar (their single source);
# the rest is editors/zed-ipe.
ipe_workdir
X="$IPE_WORK/zed-ipe"
for f in extension.toml Cargo.toml Cargo.lock .cargo/config.toml src/lib.rs languages/ipe/config.toml; do
    ipe_fetch "editors/zed-ipe/$f" "$X/$f"
done
# Zed reads only highlights.scm from these; it rejects a capture-less
# injections query, so none is shipped.
# From a checkout the query is read from the pinned commit itself, never the
# working tree, so it is the grammar commit's query by construction.
if [ -n "$IPE_SRC_ROOT" ]; then
    mkdir -p "$X/languages/ipe"
    git -C "$SRC_REAL" cat-file blob "$GRAMMAR_REV:$IPE_GRAMMAR_DIR/queries/highlights.scm" \
        > "$X/languages/ipe/highlights.scm" \
        || die "$GRAMMAR_REV has no $IPE_GRAMMAR_DIR/queries/highlights.scm"
else
    ipe_fetch "$IPE_GRAMMAR_DIR/queries/highlights.scm" "$X/languages/ipe/highlights.scm"
fi
GRAMMAR_REPOSITORY="$GRAMMAR_REPOSITORY" GRAMMAR_REV="$GRAMMAR_REV" awk '
    $0 == "repository = \"@IPE_GRAMMAR_REPOSITORY@\"" { print "repository = \"" ENVIRON["GRAMMAR_REPOSITORY"] "\""; r++; next }
    $0 == "rev = \"@IPE_GRAMMAR_REV@\"" { print "rev = \"" ENVIRON["GRAMMAR_REV"] "\""; v++; next }
    { print }
    END { if (r != 1 || v != 1) exit 1 }
' "$X/extension.toml" > "$X/extension.toml.pinned" \
    || die "extension.toml must hold exactly one grammar repository and one rev placeholder"
mv -f "$X/extension.toml.pinned" "$X/extension.toml"
grep -Eq '^rev = "[0-9a-f]{40}"$' "$X/extension.toml" \
    || die "extension.toml does not pin the grammar to a commit"

# Zed reuses an existing grammar directory only when
# `git remote get-url origin`, run with GIT_CONFIG_GLOBAL=/dev/null, prints this
# exact URL; anything else (an install from the other source, a moved checkout,
# a directory that is not a clone) it refuses. The directory is Zed's own
# rebuildable cache, so it goes and Zed clones afresh — never through a
# symlinked grammars directory, which would delete outside Zed's cache.
GRAMMARS="$EXT_DIR/grammars"
GRAMMAR_CLONE="$GRAMMARS/ipe"
if [ -e "$GRAMMAR_CLONE" ] || [ -L "$GRAMMAR_CLONE" ]; then
    _origin="$(GIT_CONFIG_GLOBAL=/dev/null git --git-dir "$GRAMMAR_CLONE/.git" remote get-url origin 2> /dev/null)" \
        || _origin=""
    if [ "$_origin" != "$GRAMMAR_REPOSITORY" ]; then
        [ ! -L "$GRAMMARS" ] \
            || die "$GRAMMARS is a symlink; remove the stale grammar clone $GRAMMAR_CLONE by hand, then re-run"
        rm -rf "$GRAMMAR_CLONE" "$GRAMMARS/ipe.wasm" || die "cannot remove $GRAMMAR_CLONE"
        say "removed Zed's grammar directory that is not a clone of $GRAMMAR_REPOSITORY ($GRAMMAR_CLONE); Zed clones it afresh on the next build"
    fi
fi

for f in extension.toml Cargo.toml Cargo.lock .cargo/config.toml src/lib.rs \
    languages/ipe/config.toml languages/ipe/highlights.scm; do
    ipe_install_file "$X/$f" "$EXT_DIR/$f"
done
# Query files an earlier run installed that Zed must no longer load.
for q in injections locals; do
    stale="$EXT_DIR/languages/ipe/$q.scm"
    if [ -f "$stale" ]; then
        b="$(ipe_backup "$stale")"
        rm -f "$stale"
        say "retired $stale (kept as $b)"
    fi
done

# --- settings.json: read-only check ---------------------------------------------------
# Older versions of this script merged keys into settings.json; the extension
# makes them unnecessary and some were never valid Zed settings. Point them out,
# never edit the file.
SETTINGS="${XDG_CONFIG_HOME:-$HOME/.config}/zed/settings.json"
if [ -f "$SETTINGS" ] && grep -Eq '"ipe-lsp"|"Ipê"|"auto_formatter"' "$SETTINGS"; then
    warn "$SETTINGS has Ipê keys from an older setup (\"Ipê\", \"ipe-lsp\", \"auto_formatter\")"
    warn "they are no longer needed — remove them by hand; this script does not edit settings.json"
fi

say "extension assembled at $EXT_DIR"
cat << EOF

  One step left — Zed installs local extensions only from its UI:
    1. Open Zed; run the command palette action  zed: install dev extension
    2. Choose the directory:  $EXT_DIR
  Zed compiles the grammar and the extension (about a minute, first time only),
  then highlights .ipe files and starts 'ipe lsp' for them. Trust the project
  folder when Zed asks, or language servers stay off. Re-run this script and
  "Rebuild" the extension in Zed's Extensions page to update.

EOF
