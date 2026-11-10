#!/usr/bin/env bash
# Tests for editors/*/configure.sh and editors/lib/ipe-editors.sh.
#
# Runs every script against a throwaway HOME with stub editors on PATH, so it
# never touches the real configuration. Covers the refusals (too-old editors,
# Doom without a private config, a config Helix rejects) as well as the
# happy-path guarantees (backups, managed-block idempotency, untouched user
# content), plus two drift checks: the Zed grammar pin and ipe-mode's keywords.
#
# Usage: bash editors/tests/configure-test.sh   (from anywhere; needs cc, git)
#
# The Zed wasm32-wasip2 build check additionally needs rustup + cargo with the
# wasm32-wasip2 target installed; it skips with a message when that target is
# absent, except under CI (CI=true), where it is mandatory.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ipe-editors-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# A fresh sandbox: HOME + XDG dirs + a stub bin dir first on PATH.
sandbox() {
    SB="$WORK/$1"
    rm -rf "$SB"
    mkdir -p "$SB/home" "$SB/bin"
    export HOME="$SB/home" XDG_CONFIG_HOME="$SB/home/.config" XDG_DATA_HOME="$SB/home/.local/share"
    unset EMACSDIR DOOMDIR
    PATH="$SB/bin:$ORIG_PATH"
    stub ipe 'exit 0'
}
stub() { printf '#!/bin/sh\n%s\n' "$2" > "$SB/bin/$1"; chmod +x "$SB/bin/$1"; }
ORIG_PATH="$PATH"
ORIG_HOME="$HOME"

# The grammar Zed builds and the highlight query assembled beside it.
GRAMMAR_REL="editors/tree-sitter-ipe"
GRAMMAR_PATHS="$GRAMMAR_REL/src $GRAMMAR_REL/queries/highlights.scm"
# zed_pin_truthful EXT_DIR SRC_ROOT — replay Zed's grammar checkout from the
# assembled extension.toml exactly as Zed runs it (git init; remote add origin
# <repository>; fetch --depth 1 origin <rev>; checkout <rev>), then require the
# checked-out grammar to be SRC_ROOT's and its highlight query the assembled one.
zed_pin_truthful() {
    local toml="$1/extension.toml" clone="$WORK/zed-grammar-clone" repo rev path
    repo="$(sed -n '/^\[grammars\.ipe\]$/,/^\[/s/^repository = "\(.*\)"$/\1/p' "$toml")"
    rev="$(sed -n '/^\[grammars\.ipe\]$/,/^\[/s/^rev = "\([0-9a-f]\{40\}\)"$/\1/p' "$toml")"
    path="$(sed -n '/^\[grammars\.ipe\]$/,/^\[/s/^path = "\(.*\)"$/\1/p' "$toml")"
    [ -n "$repo" ] && [ -n "$rev" ] && [ "$path" = "$GRAMMAR_REL" ] || return 1
    rm -rf "$clone" && mkdir -p "$clone" || return 1
    git -C "$clone" init -q \
        && git --git-dir "$clone/.git" remote add origin "$repo" \
        && git --git-dir "$clone/.git" fetch -q --depth 1 origin "$rev" 2> /dev/null \
        && (cd "$clone" && git --git-dir "$clone/.git" checkout -q "$rev" 2> /dev/null) \
        && cmp -s "$clone/$path/queries/highlights.scm" "$1/languages/ipe/highlights.scm" \
        && diff -r -q "$clone/$path/src" "$2/$GRAMMAR_REL/src" > /dev/null
}

# --- lib: backups and managed blocks -----------------------------------------------
sandbox lib
(
    set -e
    IPE_SRC_ROOT="$ROOT"
    # shellcheck source=../lib/ipe-editors.sh
    . "$ROOT/editors/lib/ipe-editors.sh"
    f="$HOME/conf"
    printf 'user line 1\nuser line 2\n' > "$f"
    printf 'managed A\n' > "$WORK/a"
    printf 'managed B\n' > "$WORK/b"
    ipe_write_block "$f" "#" "$WORK/a" > /dev/null
    ipe_write_block "$f" "#" "$WORK/a" > /dev/null
    ipe_write_block "$f" "#" "$WORK/b" > /dev/null
    b1="$(ipe_backup "$f")"
    b2="$(ipe_backup "$f")"
    printf '%s\n%s\n' "$b1" "$b2" > "$WORK/backups"
) || bad "lib helpers ran"
f="$HOME/conf"
check "managed block written once, user lines kept" \
    '[ "$(grep -c "^managed " "$f")" = 1 ] && grep -q "^user line 1$" "$f" && grep -q "^user line 2$" "$f"'
check "managed block replaced in place" 'grep -q "^managed B$" "$f" && ! grep -q "^managed A$" "$f"'
check "exactly one begin and one end marker" \
    '[ "$(grep -c ">>> ipe (managed by" "$f")" = 1 ] && [ "$(grep -c "<<< ipe <<<" "$f")" = 1 ]'
check "unchanged rewrite makes no backup (2 changes -> 2 backups + 2 explicit)" \
    '[ "$(ls "$HOME" | grep -c "conf.ipe-backup-")" = 4 ]'
check "same-second backups get distinct names" \
    '[ "$(sed -n 1p "$WORK/backups")" != "$(sed -n 2p "$WORK/backups")" ]'

# --- Helix ----------------------------------------------------------------------------
sandbox helix-old
stub hx 'echo "helix 23.10 (abc)"'
if sh "$ROOT/editors/helix/configure.sh" > "$SB/out" 2>&1; then bad "Helix: refuses 23.10"; else ok "Helix: refuses 23.10"; fi
check "Helix: refusal writes nothing" '[ ! -e "$XDG_CONFIG_HOME/helix" ]'

sandbox helix-health-fails
stub hx 'case "$1" in --version) echo "helix 24.7 (abc)";; --health) echo "Error parsing user language config";; esac'
mkdir -p "$XDG_CONFIG_HOME/helix"
printf '[[language]]\nname = "rust"\n' > "$XDG_CONFIG_HOME/helix/languages.toml"
cp "$XDG_CONFIG_HOME/helix/languages.toml" "$SB/orig"
if sh "$ROOT/editors/helix/configure.sh" > "$SB/out" 2>&1; then
    bad "Helix: failed health check exits non-zero"
else
    ok "Helix: failed health check exits non-zero"
fi
check "Helix: failed health check restores languages.toml" 'cmp -s "$SB/orig" "$XDG_CONFIG_HOME/helix/languages.toml"'
check "Helix: failure never prints the success line" '! grep -q "setup complete" "$SB/out"'

sandbox helix-ok
stub hx 'case "$1" in --version) echo "helix 24.7 (abc)";; --health) printf "Configured language servers:\nHighlight queries: ✓\n";; esac'
mkdir -p "$XDG_CONFIG_HOME/helix"
printf '# mine\n[[language]]\nname = "rust"\n' > "$XDG_CONFIG_HOME/helix/languages.toml"
sh "$ROOT/editors/helix/configure.sh" > "$SB/out" 2>&1 && ok "Helix: happy path" || bad "Helix: happy path"
sh "$ROOT/editors/helix/configure.sh" > "$SB/out2" 2>&1 || true
L="$XDG_CONFIG_HOME/helix/languages.toml"
check "Helix: grammar + queries installed" \
    '[ -s "$XDG_CONFIG_HOME/helix/runtime/grammars/ipe.so" ] && [ -s "$XDG_CONFIG_HOME/helix/runtime/queries/ipe/highlights.scm" ]'
check "Helix: user content kept, one ipe-lsp table" \
    'grep -q "^# mine$" "$L" && [ "$(grep -c "^\[language-server.ipe-lsp\]" "$L")" = 1 ]'
check "Helix: re-run is a no-op" 'grep -q "already up to date" "$SB/out2" && [ "$(ls "$XDG_CONFIG_HOME/helix" | grep -c ipe-backup)" = 1 ]'

sandbox helix-handwritten
stub hx 'case "$1" in --version) echo "helix 24.7 (abc)";; --health) printf "Highlight queries: ✓\n";; esac'
mkdir -p "$XDG_CONFIG_HOME/helix"
printf '[language-server.ipe-lsp]\ncommand = "ipe"\n' > "$XDG_CONFIG_HOME/helix/languages.toml"
cp "$XDG_CONFIG_HOME/helix/languages.toml" "$SB/orig"
sh "$ROOT/editors/helix/configure.sh" > "$SB/out" 2>&1 || true
check "Helix: hand-written Ipê definition left untouched" 'cmp -s "$SB/orig" "$XDG_CONFIG_HOME/helix/languages.toml"'

# --- Neovim ---------------------------------------------------------------------------
sandbox nvim-old
stub nvim 'echo "NVIM v0.10.4"'
if sh "$ROOT/editors/neovim/configure.sh" > "$SB/out" 2>&1; then bad "Neovim: refuses 0.10"; else ok "Neovim: refuses 0.10"; fi
check "Neovim: refusal writes nothing" '[ ! -e "$XDG_DATA_HOME/nvim" ]'

sandbox nvim-check-fails
stub nvim 'case "$1" in --version) echo "NVIM v0.11.4";; *) echo "parser not loadable" >&2; exit 1;; esac'
if sh "$ROOT/editors/neovim/configure.sh" > "$SB/out" 2>&1; then
    bad "Neovim: failed headless check exits non-zero"
else
    ok "Neovim: failed headless check exits non-zero"
fi
check "Neovim: failure never prints the success line" '! grep -q "setup complete" "$SB/out"'

# --- Emacs ----------------------------------------------------------------------------
sandbox emacs-old
stub emacs 'echo 28'
if sh "$ROOT/editors/emacs/configure.sh" > "$SB/out" 2>&1; then bad "Emacs: refuses 28"; else ok "Emacs: refuses 28"; fi

sandbox emacs-doom-unconfigured
stub emacs 'echo 30'
mkdir -p "$XDG_CONFIG_HOME/emacs/lisp"
: > "$XDG_CONFIG_HOME/emacs/.doom"
if sh "$ROOT/editors/emacs/configure.sh" > "$SB/out" 2>&1; then
    bad "Emacs: Doom without private config refused"
else
    ok "Emacs: Doom without private config refused"
fi
check "Emacs: Doom refusal writes nothing" '[ ! -e "$XDG_DATA_HOME/ipe" ] && [ ! -e "$XDG_CONFIG_HOME/emacs/init.el" ]'

if command -v emacs > /dev/null 2>&1 && [ "$(emacs -Q --batch --eval '(princ emacs-major-version)' 2>/dev/null || echo 0)" -ge 29 ]; then
    REAL_EMACS="$(command -v emacs)"
    sandbox emacs-doom
    ln -s "$REAL_EMACS" "$SB/bin/emacs"
    mkdir -p "$XDG_CONFIG_HOME/emacs/lisp" "$XDG_CONFIG_HOME/doom"
    : > "$XDG_CONFIG_HOME/emacs/.doom"
    printf ';; my doom config\n' > "$XDG_CONFIG_HOME/doom/config.el"
    sh "$ROOT/editors/emacs/configure.sh" > "$SB/out" 2>&1 && ok "Emacs: Doom happy path" || { bad "Emacs: Doom happy path"; cat "$SB/out"; }
    check "Emacs: Doom config.el gets the block, keeps user lines" \
        'grep -q "^;; my doom config$" "$XDG_CONFIG_HOME/doom/config.el" && grep -qF "(require '"'"'ipe-mode)" "$XDG_CONFIG_HOME/doom/config.el"'
else
    printf 'skip Emacs 29+ not available for the Doom happy path\n'
fi

# --- Zed ------------------------------------------------------------------------------
sandbox zed
stub zed 'exit 0'
stub rustup 'exit 0'
stub cargo 'exit 0'
mkdir -p "$XDG_CONFIG_HOME/zed"
printf '// my settings\n{ "languages": { "Ipê": {} }, }\n' > "$XDG_CONFIG_HOME/zed/settings.json"
cp "$XDG_CONFIG_HOME/zed/settings.json" "$SB/orig"
sh "$ROOT/editors/zed/configure.sh" > "$SB/out" 2>&1 && ok "Zed: happy path" || bad "Zed: happy path"
check "Zed: settings.json never edited" 'cmp -s "$SB/orig" "$XDG_CONFIG_HOME/zed/settings.json"'
check "Zed: legacy settings keys reported" 'grep -q "older setup" "$SB/out"'
check "Zed: extension assembled" \
    '[ -s "$XDG_DATA_HOME/ipe/zed-ipe/extension.toml" ] && [ -s "$XDG_DATA_HOME/ipe/zed-ipe/languages/ipe/highlights.scm" ] && [ -s "$XDG_DATA_HOME/ipe/zed-ipe/src/lib.rs" ]'

# The stubbed rustup/cargo above prove only that configure.sh assembles the
# right files. Zed itself then runs `cargo build --release --target
# wasm32-wasip2` inside that assembled directory with RUSTC_WRAPPER cleared
# (WASI builds hang under sccache) — the step nothing here proved before,
# letting a Cargo.lock/Cargo.toml/target-rustflags regression ship unbuilt.
# Mandatory in CI (GitHub Actions sets CI=true, and the workflow installs the
# target); skips with a message when wasm32-wasip2 is not installed locally.
ZED_ASSEMBLED="$XDG_DATA_HOME/ipe/zed-ipe"
PATH="$ORIG_PATH"
# The sandboxed HOME hides the real toolchain; point rustup and cargo back at it.
export RUSTUP_HOME="${RUSTUP_HOME:-$ORIG_HOME/.rustup}" CARGO_HOME="${CARGO_HOME:-$ORIG_HOME/.cargo}"
if command -v rustup > /dev/null 2>&1 && command -v cargo > /dev/null 2>&1 \
    && (cd "$ZED_ASSEMBLED" && rustup target list --installed 2> /dev/null | grep -qx wasm32-wasip2); then
    WASM_TARGET_DIR="$WORK/zed-wasm-build"
    if (cd "$ZED_ASSEMBLED" && RUSTC_WRAPPER= cargo build --release --target wasm32-wasip2 \
        --target-dir "$WASM_TARGET_DIR") > "$WORK/zed-wasm-build.log" 2>&1
    then
        ok "Zed: extension compiles for wasm32-wasip2"
    else
        bad "Zed: extension compiles for wasm32-wasip2"
        cat "$WORK/zed-wasm-build.log"
    fi
    check "Zed: wasm artifact produced" '[ -s "$WASM_TARGET_DIR/wasm32-wasip2/release/zed_ipe.wasm" ]'
elif [ "${CI:-}" = "true" ]; then
    bad "Zed: wasm32-wasip2 target missing — the CI workflow must install it"
else
    printf 'skip Zed wasm32-wasip2 build (target not installed; run: rustup target add wasm32-wasip2)\n'
fi

sandbox zed-missing
if sh "$ROOT/editors/zed/configure.sh" > "$SB/out" 2>&1; then bad "Zed: refuses without zed"; else ok "Zed: refuses without zed"; fi

# --- Zed grammar pin, on a throwaway checkout ------------------------------------------
# A one-commit copy of this checkout's editors/ working tree (with a space in
# its path) that the refusals below may dirty and re-commit without touching
# this checkout.
PATH="$ORIG_PATH"
copy_editors() { # DEST — the working tree's tracked and unignored editors/ files
    mkdir -p "$1"
    git -C "$ROOT" ls-files -z --cached --others --exclude-standard -- editors \
        | (cd "$ROOT" && tar --null -T - -cf -) | tar -x -C "$1"
}
FAKE="$WORK/fake checkout"
copy_editors "$FAKE"
fake_git() { git -C "$FAKE" -c user.name=t -c user.email=t@t -c commit.gpgsign=false "$@"; }
fake_git init -q && fake_git add -A && fake_git commit -q -m fixture
sandbox zed-pin
stub zed 'exit 0'
stub rustup 'exit 0'
stub cargo 'exit 0'
ZED_EXT="$XDG_DATA_HOME/ipe/zed-ipe"
# Zed's grammar clone from another source, left by an earlier install.
mkdir -p "$ZED_EXT/grammars/ipe"
git -C "$ZED_EXT/grammars/ipe" init -q
git --git-dir "$ZED_EXT/grammars/ipe/.git" remote add origin "https://github.com/ipe-lang/compiler"
: > "$ZED_EXT/grammars/ipe.wasm"
sh "$FAKE/editors/zed/configure.sh" > "$SB/out" 2>&1 && ok "Zed pin: happy path from a checkout" || { bad "Zed pin: happy path from a checkout"; cat "$SB/out"; }
check "Zed pin: pinned to the checkout's HEAD, served from the checkout" \
    'grep -qxF "repository = \"file://$(cd "$FAKE" && pwd -P)\"" "$ZED_EXT/extension.toml" && grep -qx "rev = \"$(fake_git rev-parse HEAD)\"" "$ZED_EXT/extension.toml"'
check "Zed pin: the replay checks out the checkout's grammar and query" 'zed_pin_truthful "$ZED_EXT" "$FAKE"'
check "Zed pin: a grammar clone of another source is removed" \
    '[ ! -e "$ZED_EXT/grammars/ipe" ] && [ ! -e "$ZED_EXT/grammars/ipe.wasm" ]'
# A clone of the same source is Zed's to update and stays.
mkdir -p "$ZED_EXT/grammars/ipe"
git -C "$ZED_EXT/grammars/ipe" init -q
git --git-dir "$ZED_EXT/grammars/ipe/.git" remote add origin "file://$(cd "$FAKE" && pwd -P)"
sh "$FAKE/editors/zed/configure.sh" > "$SB/out" 2>&1 && ok "Zed pin: re-run" || bad "Zed pin: re-run"
check "Zed pin: a grammar clone of the same source is kept" '[ -d "$ZED_EXT/grammars/ipe/.git" ]'
# A grammar change committed after the install: the re-run pins the new commit.
printf '; changed\n' >> "$FAKE/$GRAMMAR_REL/queries/highlights.scm"
fake_git commit -q -am "grammar change"
sh "$FAKE/editors/zed/configure.sh" > "$SB/out" 2>&1 && ok "Zed pin: re-run after a grammar commit" || bad "Zed pin: re-run after a grammar commit"
check "Zed pin: a grammar commit moves the pin with it" \
    'grep -qx "rev = \"$(fake_git rev-parse HEAD)\"" "$ZED_EXT/extension.toml" && zed_pin_truthful "$ZED_EXT" "$FAKE"'
# Refusal: uncommitted grammar or query changes (Zed would build the commit,
# the query would be the working tree's) leave the installed extension alone.
cp "$ZED_EXT/extension.toml" "$SB/toml.before"
printf '; uncommitted\n' >> "$FAKE/$GRAMMAR_REL/queries/highlights.scm"
if sh "$FAKE/editors/zed/configure.sh" > "$SB/out" 2>&1; then bad "Zed pin: refuses an uncommitted query change"; else ok "Zed pin: refuses an uncommitted query change"; fi
check "Zed pin: the refusal names the uncommitted change" 'grep -q "uncommitted grammar or highlight-query changes" "$SB/out"'
fake_git checkout -q -- "$GRAMMAR_REL/queries/highlights.scm"
: > "$FAKE/$GRAMMAR_REL/src/untracked.h"
if sh "$FAKE/editors/zed/configure.sh" > "$SB/out" 2>&1; then bad "Zed pin: refuses an untracked grammar file"; else ok "Zed pin: refuses an untracked grammar file"; fi
rm -f "$FAKE/$GRAMMAR_REL/src/untracked.h"
check "Zed pin: refusals left the installed extension.toml unchanged" 'cmp -s "$SB/toml.before" "$ZED_EXT/extension.toml"'
# Refusal: a template carrying a stored commit instead of the placeholder.
sed -i.bak 's/^rev = "@IPE_GRAMMAR_REV@"$/rev = "e7ff85a969e481cc46563733dbb501f97a75bff7"/' "$FAKE/editors/zed-ipe/extension.toml"
rm -f "$FAKE/editors/zed-ipe/extension.toml.bak"
if sh "$FAKE/editors/zed/configure.sh" > "$SB/out" 2>&1; then bad "Zed pin: refuses a stored grammar commit"; else ok "Zed pin: refuses a stored grammar commit"; fi
fake_git checkout -q -- editors/zed-ipe/extension.toml
# Refusal: a copy of editors/ outside any git checkout.
NOGIT="$WORK/nogit"
copy_editors "$NOGIT"
if GIT_CEILING_DIRECTORIES="$WORK" sh "$NOGIT/editors/zed/configure.sh" > "$SB/out" 2>&1; then
    bad "Zed pin: refuses a copy outside a git checkout"
else
    ok "Zed pin: refuses a copy outside a git checkout"
fi
# The query comes from the pinned commit even when the working tree hides a
# change from `git status` (skip-worktree): Zed builds the commit's grammar.
fake_git update-index --skip-worktree "$GRAMMAR_REL/queries/highlights.scm"
printf '; hidden from git status\n' >> "$FAKE/$GRAMMAR_REL/queries/highlights.scm"
sh "$FAKE/editors/zed/configure.sh" > "$SB/out" 2>&1 && ok "Zed pin: re-run with a skip-worktree query" || bad "Zed pin: re-run with a skip-worktree query"
check "Zed pin: the assembled query is the pinned commit's, not the working tree's" \
    'fake_git cat-file blob "HEAD:$GRAMMAR_REL/queries/highlights.scm" | cmp -s - "$ZED_EXT/languages/ipe/highlights.scm" && zed_pin_truthful "$ZED_EXT" "$FAKE"'
fake_git update-index --no-skip-worktree "$GRAMMAR_REL/queries/highlights.scm"
fake_git checkout -q -- "$GRAMMAR_REL/queries/highlights.scm"
# Zed keeps a grammar directory only when `git remote get-url origin` without
# the global git config prints the pinned URL; every other directory goes.
FAKE_URL="file://$(cd "$FAKE" && pwd -P)"
rm -rf "$ZED_EXT/grammars/ipe"
mkdir -p "$ZED_EXT/grammars/ipe"
git -C "$ZED_EXT/grammars/ipe" init -q
git --git-dir "$ZED_EXT/grammars/ipe/.git" remote add origin "https://example.invalid/ipe-grammar"
printf '[url "%s"]\n\tinsteadOf = https://example.invalid/ipe-grammar\n' "$FAKE_URL" > "$HOME/.gitconfig"
sh "$FAKE/editors/zed/configure.sh" > "$SB/out" 2>&1 && ok "Zed pin: re-run with a global insteadOf" || bad "Zed pin: re-run with a global insteadOf"
rm -f "$HOME/.gitconfig"
check "Zed pin: a clone matching only through the global git config is removed" '[ ! -e "$ZED_EXT/grammars/ipe" ]'
mkdir -p "$ZED_EXT/grammars/ipe"
: > "$ZED_EXT/grammars/ipe/leftover"
sh "$FAKE/editors/zed/configure.sh" > "$SB/out" 2>&1 && ok "Zed pin: re-run over a non-clone grammar directory" || bad "Zed pin: re-run over a non-clone grammar directory"
check "Zed pin: a grammar directory that is not a clone is removed" '[ ! -e "$ZED_EXT/grammars/ipe" ]'
# Refusal: a symlinked grammars directory is never deleted through.
OUTSIDE="$WORK/outside-zed-cache"
mkdir -p "$OUTSIDE/ipe"
git -C "$OUTSIDE/ipe" init -q
git --git-dir "$OUTSIDE/ipe/.git" remote add origin "https://example.invalid/elsewhere"
rm -rf "$ZED_EXT/grammars"
ln -s "$OUTSIDE" "$ZED_EXT/grammars"
if sh "$FAKE/editors/zed/configure.sh" > "$SB/out" 2>&1; then bad "Zed pin: refuses to delete through a symlinked grammars directory"; else ok "Zed pin: refuses to delete through a symlinked grammars directory"; fi
check "Zed pin: the symlink target survives" '[ -d "$OUTSIDE/ipe/.git" ]'
rm -f "$ZED_EXT/grammars"
# Refusal: a checkout path ending in whitespace, which Zed trims off the
# clone's origin URL and so never matches on a rebuild.
for trail in ' ' "$(printf '\302\240')"; do
    TRAIL="$WORK/trail$trail"
    copy_editors "$TRAIL"
    git -C "$TRAIL" -c user.name=t -c user.email=t@t -c commit.gpgsign=false init -q
    git -C "$TRAIL" add -A
    git -C "$TRAIL" -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -q -m fixture
    if sh "$TRAIL/editors/zed/configure.sh" > "$SB/out" 2>&1; then
        bad "Zed pin: refuses a checkout path ending in whitespace ($(printf '%s' "$trail" | od -An -tx1 | tr -d ' '))"
    else
        check "Zed pin: refuses a checkout path ending in whitespace ($(printf '%s' "$trail" | od -An -tx1 | tr -d ' '))" \
            'grep -q "ends in whitespace" "$SB/out"'
    fi
done

# --- lib: IPE_EDITORS_REF resolution (curl installs) -------------------------------------
sandbox resolve
# A real repository behind the GitHub URL (git's insteadOf), so ls-remote's
# own output is parsed: an annotated tag, a tag of a tag, a lightweight tag,
# and a name that is both a branch and a tag.
REMOTE="$WORK/remote"
rgit() { git -C "$REMOTE" -c user.name=t -c user.email=t@t -c commit.gpgsign=false -c tag.gpgsign=false "$@"; }
git init -q "$REMOTE"
rgit commit -q --allow-empty -m one
C1="$(rgit rev-parse HEAD)"
rgit tag -a v1 -m v1
rgit -c advice.nestedTag=false tag -a v2 -m v2 v1
rgit tag v0
rgit commit -q --allow-empty -m two
C2="$(rgit rev-parse HEAD)"
rgit branch -M main
rgit branch both
rgit tag both
resolve() {
    (IPE_SRC_ROOT="$ROOT"; . "$ROOT/editors/lib/ipe-editors.sh"
        GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="url.file://$REMOTE.insteadOf" \
            GIT_CONFIG_VALUE_0="https://github.com/$IPE_REPO_SLUG" ipe_resolve_ref "$1") 2> /dev/null
}
check "lib: a branch resolves to its commit" '[ "$(resolve main)" = "$C2" ]'
check "lib: an annotated tag resolves to its peeled commit" '[ "$(resolve v1)" = "$C1" ]'
check "lib: a tag of a tag resolves to its peeled commit" '[ "$(resolve v2)" = "$C1" ]'
check "lib: a lightweight tag resolves to its commit" '[ "$(resolve v0)" = "$C1" ]'
check "lib: a full commit id resolves to itself" '[ "$(resolve 0123456789abcdef0123456789abcdef01234567)" = 0123456789abcdef0123456789abcdef01234567 ]'
check "lib: refuses a name that is both a branch and a tag" '! resolve both > /dev/null'
check "lib: refuses an unknown ref" '! resolve nope > /dev/null'
check "lib: refuses a ref outside the ref-name alphabet" '! resolve "main;rm" > /dev/null && ! resolve "-x" > /dev/null && ! resolve "" > /dev/null'
stub git 'exit 128'
hash -r
check "lib: refuses when the refs cannot be listed" '! resolve main > /dev/null'

# --- drift checks ---------------------------------------------------------------------------
PATH="$ORIG_PATH"
check "Zed: extension.toml stores no grammar commit (configure.sh derives it)" \
    '! grep -Eq "^rev = \"[0-9a-f]{40}\"" "$ROOT/editors/zed-ipe/extension.toml" && grep -qx "rev = \"@IPE_GRAMMAR_REV@\"" "$ROOT/editors/zed-ipe/extension.toml"'
if [ -n "$(git -C "$ROOT" status --porcelain --untracked-files=all -- $GRAMMAR_PATHS)" ]; then
    printf 'skip Zed pin replay on this checkout (uncommitted grammar changes; configure.sh refuses them)\n'
else
    check "Zed: the assembled pin checks out this checkout's grammar and query" \
        'zed_pin_truthful "$ZED_ASSEMBLED" "$ROOT"'
    # Refusal: the same assembled extension pinned to the parent of the last
    # grammar change (a stale pin) must fail the replay.
    last_grammar="$(git -C "$ROOT" log -1 --format=%H -- $GRAMMAR_PATHS)"
    stale="$(git -C "$ROOT" rev-parse --verify -q "$last_grammar^" || true)"
    if [ -z "$stale" ] || git -C "$ROOT" diff --quiet "$stale" HEAD -- $GRAMMAR_PATHS; then
        bad "Zed: a stale-pin fixture exists (a commit before the last grammar change)"
    else
        STALE_EXT="$WORK/zed-stale-ext"
        rm -rf "$STALE_EXT" && cp -R "$ZED_ASSEMBLED" "$STALE_EXT"
        sed -i.bak "s/^rev = \"[0-9a-f]\{40\}\"\$/rev = \"$stale\"/" "$STALE_EXT/extension.toml"
        if grep -qx "rev = \"$stale\"" "$STALE_EXT/extension.toml" && ! zed_pin_truthful "$STALE_EXT" "$ROOT"; then
            ok "Zed: the replay refuses a pin to a commit with another grammar"
        else
            bad "Zed: the replay refuses a pin to a commit with another grammar"
        fi
    fi
fi

hl_keywords="$(awk '/^\[/{k=1; buf=""; next} k && /^\] @keyword/{print buf; k=0; next} k{buf=buf" "$0}' \
    "$ROOT/editors/tree-sitter-ipe/queries/highlights.scm" | tr -s ' "' '\n' | grep -E '^[a-z]+$' | sort -u)"
el_keywords="$(sed -n '/(defconst ipe-keywords/,/)$/p' "$ROOT/editors/emacs/ipe-mode.el" \
    | grep -o '"[a-z]*"' | tr -d '"' | sort -u)"
check "ipe-mode keywords match the grammar's keyword captures" '[ -n "$hl_keywords" ] && [ "$hl_keywords" = "$el_keywords" ]'

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
