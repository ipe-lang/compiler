# editors/lib/ipe-editors.sh — shared helpers for editors/*/configure.sh.
#
# Sourced (never executed) by each configure.sh after it bootstraps this file
# from the local checkout or from the same git ref on GitHub. POSIX sh.
#
# Contract every configure.sh relies on:
#   * fail closed — any failed step exits non-zero before a success message;
#   * never destroy user content — every file is backed up to a unique
#     `<file>.ipe-backup-<timestamp>` name before it is changed, and an
#     unchanged file is never rewritten;
#   * one source for the grammar, queries and editor files — the local
#     checkout this script lives in, or the `IPE_EDITORS_REF` ref on GitHub.

IPE_REPO_SLUG="ipe-lang/compiler"
IPE_EDITORS_REF="${IPE_EDITORS_REF:-main}"
IPE_RAW_BASE="https://raw.githubusercontent.com/$IPE_REPO_SLUG/$IPE_EDITORS_REF"

# Grammar sources a C compiler needs, relative to the repository root.
IPE_GRAMMAR_DIR="editors/tree-sitter-ipe"
IPE_GRAMMAR_FILES="src/parser.c src/scanner.c src/tree_sitter/parser.h src/tree_sitter/alloc.h src/tree_sitter/array.h"
IPE_QUERY_NAMES="highlights injections locals tags textobjects indents"

IPE_TAG="${IPE_TAG:-ipe}"

die() { printf '%s: error: %s\n' "$IPE_TAG" "$*" >&2; exit 1; }
warn() { printf '%s: warning: %s\n' "$IPE_TAG" "$*" >&2; }
say() { printf '%s: %s\n' "$IPE_TAG" "$*"; }

# ipe_have CMD — CMD resolves to an executable (dash's `command -v` also
# reports a non-executable file on PATH).
ipe_have() {
    _p="$(command -v "$1" 2>/dev/null)" || return 1
    case "$_p" in
        /*) [ -x "$_p" ] ;;
        *) return 0 ;;
    esac
}

need() {
    ipe_have "$1" || die "'$1' not found — $2"
}

# ipe_workdir — a private scratch directory removed on exit.
ipe_workdir() {
    if [ -z "${IPE_WORK:-}" ]; then
        IPE_WORK="$(mktemp -d "${TMPDIR:-/tmp}/ipe-editors.XXXXXX")" || die "cannot create a temporary directory"
        # shellcheck disable=SC2064
        trap "rm -rf '$IPE_WORK'" EXIT
        trap 'exit 130' INT TERM
    fi
}

# ipe_fetch REL DEST — copy REL (a repository-relative path) to DEST, from the
# local checkout when this script runs from one, else from IPE_EDITORS_REF.
ipe_fetch() {
    mkdir -p "$(dirname "$2")"
    if [ -n "${IPE_SRC_ROOT:-}" ]; then
        [ -f "$IPE_SRC_ROOT/$1" ] || die "missing $IPE_SRC_ROOT/$1 in the local checkout"
        cp "$IPE_SRC_ROOT/$1" "$2"
    else
        curl -fsSL "$IPE_RAW_BASE/$1" -o "$2" || die "download failed: $IPE_RAW_BASE/$1"
    fi
}

# ipe_resolve_ref REF — print the commit REF names on GitHub: a 40-hex REF as
# is, else the one branch or tag called REF (a tag peeled to its commit).
# Refuses a REF outside the ref-name alphabet, an unknown REF, and a REF that
# names both a branch and a tag.
ipe_resolve_ref() {
    case "$1" in
        "" | -* | *[!A-Za-z0-9._/-]*) die "IPE_EDITORS_REF '$1' is not a branch, tag or commit name" ;;
    esac
    case "$1" in
        *[!0-9a-f]*) ;;
        *) if [ "${#1}" -eq 40 ]; then printf '%s\n' "$1"; return 0; fi ;;
    esac
    _refs="$(git ls-remote "https://github.com/$IPE_REPO_SLUG" "refs/heads/$1" "refs/tags/$1")" \
        || die "cannot list the refs of https://github.com/$IPE_REPO_SLUG"
    _sha="$(printf '%s\n' "$_refs" | awk -v r="$1" '
        $2 == "refs/heads/" r { head = $1; n++ }
        $2 == "refs/tags/" r { tag = $1; n++ }
        $2 == "refs/tags/" r "^{}" { peeled = $1 }
        END {
            if (n != 1) exit 1
            if (head != "") print head
            else if (peeled != "") print peeled
            else print tag
        }')" || die "IPE_EDITORS_REF '$1' names no single branch or tag of https://github.com/$IPE_REPO_SLUG"
    case "$_sha" in
        "" | *[!0-9a-f]*) die "git ls-remote returned no commit for '$1'" ;;
    esac
    [ "${#_sha}" -eq 40 ] || die "git ls-remote returned no commit for '$1'"
    printf '%s\n' "$_sha"
}

# ipe_backup FILE — copy FILE to a fresh, never-reused backup name; prints it.
ipe_backup() {
    stamp="$(date +%Y%m%d-%H%M%S)"
    dest="$1.ipe-backup-$stamp"
    n=1
    while [ -e "$dest" ]; do
        dest="$1.ipe-backup-$stamp-$n"
        n=$((n + 1))
    done
    cp -p "$1" "$dest" || die "cannot back up $1"
    printf '%s\n' "$dest"
}

# ipe_install_file SRC DEST — install SRC at DEST. An identical DEST is left
# alone; a different one is backed up first. The write is atomic (same-dir
# temp file + rename).
ipe_install_file() {
    if [ -f "$2" ] && cmp -s "$1" "$2"; then
        return 0
    fi
    mkdir -p "$(dirname "$2")"
    if [ -e "$2" ]; then
        b="$(ipe_backup "$2")"
        say "backed up $2 -> $b"
    fi
    cp "$1" "$2.ipe-tmp.$$" && mv -f "$2.ipe-tmp.$$" "$2" || die "cannot write $2"
    say "installed $2"
}

# ipe_fetch_grammar DIR — fetch the grammar sources + queries into DIR.
ipe_fetch_grammar() {
    for f in $IPE_GRAMMAR_FILES; do
        ipe_fetch "$IPE_GRAMMAR_DIR/$f" "$1/$f"
    done
    for q in $IPE_QUERY_NAMES; do
        ipe_fetch "$IPE_GRAMMAR_DIR/queries/$q.scm" "$1/queries/$q.scm"
    done
}

# ipe_build_grammar SRCDIR OUT — compile the tree-sitter parser into the shared
# library OUT (a C11 compiler is the only requirement).
ipe_build_grammar() {
    cc="${CC:-cc}"
    command -v "$cc" >/dev/null 2>&1 || die "no C compiler ('$cc') — install one (e.g. gcc or clang) to build the grammar"
    mkdir -p "$(dirname "$2")"
    case "$(uname -s)" in
        Darwin) shared="-dynamiclib" ;;
        *) shared="-shared" ;;
    esac
    # shellcheck disable=SC2086
    "$cc" $shared -fPIC -O2 -std=c11 -I "$1/src" "$1/src/parser.c" "$1/src/scanner.c" -o "$2" \
        || die "compiling the tree-sitter grammar failed"
}

# ipe_dylib_ext — the platform shared-library extension (so / dylib).
ipe_dylib_ext() {
    case "$(uname -s)" in
        Darwin) printf 'dylib' ;;
        *) printf 'so' ;;
    esac
}

# ipe_has_block FILE — true when FILE holds the managed Ipê block.
ipe_has_block() {
    [ -f "$1" ] && grep -qF ">>> ipe (managed by" "$1"
}

# ipe_write_block FILE COMMENT BODYFILE — make FILE hold exactly one managed
# block whose body is BODYFILE, delimited by COMMENT-prefixed marker lines.
# Content outside the markers is preserved byte for byte. No-op when the block
# is already current; otherwise FILE is backed up before the atomic rewrite and
# IPE_LAST_BACKUP names the backup ("" when FILE did not exist).
ipe_write_block() {
    file="$1"
    begin="$2 >>> ipe (managed by editors configure.sh; edits inside are overwritten) >>>"
    end="$2 <<< ipe <<<"
    ipe_workdir
    new="$IPE_WORK/block.new"
    {
        if [ -f "$file" ]; then
            awk '
                index($0, ">>> ipe (managed by") { skip = 1; next }
                skip && index($0, "<<< ipe <<<") { skip = 0; next }
                !skip { print }
            ' "$file"
        fi
        printf '%s\n' "$begin"
        cat "$3"
        printf '%s\n' "$end"
    } > "$new" || die "cannot compose $file"
    if [ -f "$file" ] && cmp -s "$new" "$file"; then
        IPE_LAST_BACKUP=""
        say "$file already up to date"
        return 0
    fi
    # A file that previously lacked the block gets a blank separator line.
    if [ -f "$file" ] && [ -s "$file" ] && ! ipe_has_block "$file"; then
        { cat "$file"; printf '\n%s\n' "$begin"; cat "$3"; printf '%s\n' "$end"; } > "$new" \
            || die "cannot compose $file"
    fi
    mkdir -p "$(dirname "$file")"
    IPE_LAST_BACKUP=""
    if [ -e "$file" ]; then
        IPE_LAST_BACKUP="$(ipe_backup "$file")"
        say "backed up $file -> $IPE_LAST_BACKUP"
    fi
    cp "$new" "$file.ipe-tmp.$$" && mv -f "$file.ipe-tmp.$$" "$file" || die "cannot write $file"
    say "updated $file"
}

# ipe_restore FILE BACKUP — put BACKUP back over FILE (used when verification
# of a just-written config fails).
ipe_restore() {
    cp -p "$2" "$1" || die "cannot restore $1 from $2 — restore it by hand"
    warn "restored $1 from $2"
}

# ipe_strip_ansi — drop terminal colour escapes from stdin.
ipe_strip_ansi() {
    sed "s/$(printf '\033')\[[0-9;]*m//g"
}

# ipe_version_ge HAVE WANT — dotted-numeric comparison (HAVE >= WANT).
ipe_version_ge() {
    [ "$(printf '%s\n%s\n' "$2" "$1" | sort -t. -k1,1n -k2,2n -k3,3n | head -n1)" = "$2" ]
}
