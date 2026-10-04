# shellcheck shell=bash
# tools/scripts/lib/examples.sh — SINGLE SOURCE OF TRUTH for the example set.
# SOURCE this (never execute it).
#
# DERIVED, NOT HARDCODED. Every set is computed at call time from the example
# dirs on disk + their Ipê source. The ONLY thing that excludes an example is
# Go-FFI, because the Rust backend does not bind Go packages. A greenfield
# example that has never built on Rust SURFACES as a real failure rather than
# being silently filtered out.
#
# THE GO-FFI SIGNAL IS THE IMPORT, NOT `[go.dependencies]`. The real Go-FFI tell
# is a Ipê `import` of a Go-PACKAGE module — one that resolves to neither a Ipê
# stdlib module nor a local project `.ipe` file (`Github.Com.…`, `Net.Http`,
# `Fyne.…`).
#
# Provides (all FUNCTIONS — call them, don't read arrays):
#   all_examples            → every candidate example dir, one per line (no trailing /).
#   all_examples_into <arr> → the same set, loaded into array <arr>.
#   is_out_of_scope <dir>   → exit 0 IFF Go-FFI (imports an unresolvable Go-pkg module).
#   is_web_example  <dir>   → exit 0 IFF Ipe.Web / Ipe.Http.Server (browser-drivable).
#   example_shape   <dir>   → wasm|tui|webview|fyne|web|program
#   build_set               → all_examples − Go-FFI (the BUILD sweep set).
#   run_set / perf_set      → == build_set.

# The shape/scope classifiers below decide with rg. Require it up front so a
# missing rg fails loud here rather than silently misclassifying an example
# (rg absent -> every `rg -q` reads as "no match" -> an example is dropped
# from or kept in a set on a false signal instead of a hard error).
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/require-tool.sh"
require_tool rg find sort perl

# ── all_examples: every candidate dir on disk, trailing slash stripped ───────
# The first-party dirs: numbered legacy examples, wasm, rust, ffi, and the
# per-shape demos under examples/shapes/*/*.
#
# The `examples/wasm/*` glob is load-bearing: those dirs are non-numbered, so
# without it they fall out of every sweep set and a stale shape rename rots them
# silently.
all_examples_into() {
  _require_out_name all_examples_into "${1:-}" array
  local -n __ae_out="$1"
  __ae_out=()
  local __ae_d __ae_globs=(examples/[0-9]*/ examples/wasm/*/ examples/rust/*/ examples/ffi/*/ examples/shapes/*/*/)
  for __ae_d in "${__ae_globs[@]}"; do
    [ -d "$__ae_d" ] || continue
    __ae_d="${__ae_d%/}"
    [ -f "$__ae_d/src/Main.ipe" ] || continue
    __ae_out+=("$__ae_d")
  done
}
all_examples() {
  local -a dirs=()
  all_examples_into dirs
  [ "${#dirs[@]}" -eq 0 ] || printf '%s\n' "${dirs[@]}"
}

# ── _build_stdlib_index: ONE-TIME in-memory index of stdlib module paths ──────
# ADAPTED: this repo's stdlib source lives under src/stdlib (and, once it
# lands, a top-level ipe-stdlib/). IPE_STDLIB_DIRS is a space-separated list of
# roots to index; both are scanned so a bare/partial stdlib import (`import
# System` → Ipe.System) resolves regardless of which tree owns it. Every
# `/`-delimited suffix of each module path (minus `.ipe`) is recorded as an O(1)
# key. The BUILT flag is the idempotency guard across re-sources.
IPE_STDLIB_DIRS="${IPE_STDLIB_DIRS:-src/stdlib ipe-stdlib}"
declare -gA _IPE_STDLIB_INDEX
_build_stdlib_index() {
  [ -n "${_IPE_STDLIB_INDEX_BUILT:-}" ] && return 0
  local f rest root
  local -a stdlib_files
  for root in $IPE_STDLIB_DIRS; do
    [ -d "$root" ] || continue
    stdlib_files=()
    enumerate_files stdlib_files '*.ipe' "$root"
    for f in "${stdlib_files[@]}"; do
      # index keys are relative to the stdlib ROOT (so Ipê/Core/String.ipe →
      # Ipê/Core/String, Core/String, String), mirroring the source layout.
      rest="${f#"$root"/}"; rest="${rest%.ipe}"
      while :; do
        _IPE_STDLIB_INDEX["$rest"]=1
        case "$rest" in
          */*) rest="${rest#*/}" ;;
          *)   break ;;
        esac
      done
    done
  done
  # No indexed stdlib means every bare stdlib import would misread as Go-FFI
  # and silently drop its example from every set.
  if [ "${#_IPE_STDLIB_INDEX[@]}" -eq 0 ]; then
    echo "examples.sh: no stdlib module indexed under IPE_STDLIB_DIRS='$IPE_STDLIB_DIRS'" >&2
    exit 2
  fi
  _IPE_STDLIB_INDEX_BUILT=1
}

# ── is_out_of_scope <dir>: the ONLY exclusion is Go-FFI (IMPORT signal) ──────
# Return 0 (exclude) IFF the example imports a Go-PACKAGE module: a Ipê `import`
# whose module name resolves to NEITHER a Ipê stdlib module NOR a local project
# `.ipe` file. The recursive `.ipe` walk is load-bearing: some examples hide
# their `Github.Com.…`/`Net.Http`/`Fyne.…` imports inside Lib.* submodules.
#   • prefix Ipê. / Ipe.  → Ipê stdlib          → IN scope
#   • prefix Rust.        → Rust-FFI wrapper crate → IN scope
#   • dotted name suffix-matches the stdlib index → IN scope
#   • dotted name resolves to a `.ipe` under the project → IN (local mod)
#   • otherwise (`Github.Com.…`, `Net.Http`, `Fyne.…`) → Go-FFI → OUT
is_out_of_scope() {
  local dir="$1" m rel localpaths localdone=""
  # Explicit out-of-scope: skyshop-rs is the heavyweight real-world FFI proof
  # (firestore + async-stripe via wrapper crates). Verified separately, not in
  # the per-commit gate.
  case "$dir" in */skyshop-rs) return 0 ;; esac
  _build_stdlib_index
  # Enumerate the source set (checked, non-empty) first, then run rg directly
  # over it, so neither a producer failure nor an rg error reads as "no
  # imports found" → "in scope".
  local -a ipe_files=()
  enumerate_files ipe_files '*.ipe' "$dir/src"
  local imports=""
  match_capture imports "is_out_of_scope: import scan ($dir)" -- \
    rg --no-filename -No '^[[:space:]]*import[[:space:]]+([A-Za-z0-9_.]+)' -r '$1' "${ipe_files[@]}" || true
  while read -r m; do
    [ -z "$m" ] && continue
    case "$m" in Ipê.*|Ipe.*|Rust.*) continue ;; esac # Ipê stdlib / Rust-FFI wrapper → in scope
    rel="${m//.//}"
    [ -n "${_IPE_STDLIB_INDEX[$rel]:-}" ] && continue
    if [ -z "$localdone" ]; then
      local -a project_files=()
      enumerate_files project_files '*.ipe' "$dir"
      localpaths=$'\n'"$(printf '%s\n' "${project_files[@]}")"$'\n'
      localdone=1
    fi
    case "$localpaths" in *"/${rel}.ipe"$'\n'*) continue ;; esac
    return 0                                          # unresolvable → Go-package → OUT
  done <<< "$imports"
  return 1                                            # every import resolved → in scope
}

# ── is_live_network_cli <name>: a cli whose RUN makes a LIVE EXTERNAL call ───
# A cli that issues a real HTTP request to a third-party host has a
# non-deterministic, network-dependent RUN that can HANG on a CI runner with
# flaky egress. That is a host/network artifact, NOT a Rust defect, so its
# RUN-hang degrades to SKIP. EXPLICIT, documented set — never a heuristic.
is_live_network_cli() {
  case "$1" in
    02-go-stdlib) return 0 ;;
  esac
  return 1
}

# ── expected_red_reason <name>: a KNOWN, tracked red the gate reports but does
# not fail on ──────────────────────────────────────────────────────────────────
# An example whose BUILD is EXPECTED to fail for a tracked reason, so the sweep
# surfaces it as a visible reminder without failing the whole gate — while any
# NEW/unexpected red in any other example still fails. Prints the reason and
# returns 0 for a registered name; returns 1 (no output) otherwise. EXPLICIT,
# documented set — never a heuristic.
expected_red_reason() {
  case "$1" in
  esac
  return 1
}

# ── is_web_example <dir>: Ipe.Web OR Ipe.Http.Server (browser-drivable) ─────
is_web_example() {
  _shape_match "$1/src" 'Ipe\.Tea\.Web|Web\.tea|Server\.listen|Ipe\.Http\.Server'
}

# ── example_manifest <dir>: the project manifest path, or empty ──────────────
# `package.ipe` is the project manifest the compiler builds. This detector also
# falls back to a legacy `ipe.toml` so it can still read the shape of any
# example that has not yet been converted.
example_manifest() {
  if   [ -f "$1/package.ipe" ]; then echo "$1/package.ipe"
  elif [ -f "$1/ipe.toml" ];    then echo "$1/ipe.toml"
  fi
}

# ── is_wasm_example <dir>: declares wasm in its project manifest ─────────────
# The wasm shape is the only one detected from the project manifest rather than
# from source imports, because `Web.tea` also appears in wasm examples (the
# same function emits `wasm_app` under --target wasm). The manifest's wasm
# declaration (`Package.wasm` in package.ipe, or a `[wasm]` section in the legacy
# ipe.toml) is the authoritative build-time signal.
is_wasm_example() {
  local m; m="$(example_manifest "$1")"
  [ -n "$m" ] || return 1
  match_or_fail "is_wasm_example: $m" -- rg -q '^\[wasm\]|Package\.wasm' "$m"
}

# ── needs_ffi_install <dir>: a rust-dependencies example without bindings ─────
# An example that declares Rust FFI crates in its manifest (`Package.rustDependencies`
# in package.ipe, or a `[rust.dependencies]` section in the legacy ipe.toml) binds
# real Rust SDK crates shim-free; those bindings are generated by a SANDBOXED `ipe
# install --allow-build-scripts` into a gitignored `.ipe/cache/ffi/rust` cache. The
# per-commit sweep does not run that install (it compiles third-party SDKs with
# build scripts — heavy, network, RCE-sandbox territory), so without a
# pre-populated cache the `import Rust.<Crate>` modules are absent and `ipe
# dev build` fails IPE-N0020. That is an install prerequisite, not a compiler defect:
# such an example is SKIPPED (not RED) unless its bindings cache already exists.
needs_ffi_install() {
  local d="$1" m; m="$(example_manifest "$d")"
  [ -n "$m" ] || return 1
  match_or_fail "needs_ffi_install: $m" -- rg -q '^\[rust\.dependencies\]|Package\.rustDependencies' "$m" || return 1
  # Bindings already generated (cache present) → buildable, do not skip.
  [ -d "$d/.ipe/cache/ffi/rust" ] && return 1
  return 0
}

# ── example_shape <dir>: wasm|tui|webview|fyne|server|live|cli ───────────────
# `_shape_match` strips Ipê comments — both `{- … -}` block/doc comments (which
# can span lines) AND `--…` line comments — from the whole source before matching,
# so prose that names a backend (e.g. a `{-| … like Ipe.Web … -}` doc comment on
# a CLI example) can't misclassify the example by its shape.
_shape_match() { # $1=src dir  $2=regex
  # Each stage runs alone with its own exit status checked — enumerate, strip
  # with perl into a variable, then match on a herestring. No live pipe: a
  # pipe would let an early stage's failure hide behind the matcher's "no
  # match", and `rg -q` quitting early would SIGPIPE the writer into a false
  # error.
  local -a src_files=()
  enumerate_files src_files '*.ipe' "$1"
  # perl opens each file itself and dies on an open or read failure: its
  # implicit `<>` loop only warns on an unreadable file and still exits 0,
  # which would hand the matcher a partial text.
  local text rc=0
  # shellcheck disable=SC2016  # perl source, expanded by perl, not the shell
  text="$(perl -e '
    for my $f (@ARGV) {
      open my $fh, "<", $f or die "_shape_match: cannot open $f: $!\n";
      local $/;
      my $src = <$fh>;
      defined $src or die "_shape_match: cannot read $f: $!\n";
      close $fh or die "_shape_match: cannot close $f: $!\n";
      $src =~ s/\{-.*?-\}//gs;
      $src =~ s/--[^\n]*//g;
      print $src;
    }' -- "${src_files[@]}")" || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "_shape_match: perl comment strip over $1 exited $rc" >&2
    exit 2
  fi
  match_or_fail "_shape_match: $1 ($2)" -- rg -q -e "$2" <<<"$text"
}
example_shape() {
  local d="$1" s="$1/src"
  # wasm: detected from the manifest's wasm declaration, not from source imports,
  # because Web.tea also appears in wasm sources (it emits wasm_app under
  # --target wasm). Check this BEFORE the web/program shape match.
  if   is_wasm_example "$d";                                then echo wasm
  elif _shape_match "$s" 'Ipe\.Tea\.Tui|Tui\.tea';          then echo tui
  elif _shape_match "$s" 'Ipe\.WebView|WebView\.app';        then echo webview
  elif _shape_match "$s" 'Fyne';                             then echo fyne
  elif _shape_match "$s" 'Ipe\.Tea\.Web|Web\.tea';          then echo web
  elif _shape_match "$s" 'Server\.listen|Ipe\.Http\.Server'; then echo program
  else echo program; fi
}

# ── build_set: all_examples minus Go-FFI (unresolvable-import examples) ──────
build_set() {
  if [ -n "${_IPE_BUILD_SET+x}" ]; then printf '%s' "$_IPE_BUILD_SET"; return 0; fi
  # The set is built into an array in this shell, never read from a process
  # substitution whose writer's death would read as a clean end of the set.
  local d out="" dirs=()
  all_examples_into dirs
  for d in "${dirs[@]}"; do
    is_out_of_scope "$d" && continue
    out+="$d"$'\n'
  done
  _IPE_BUILD_SET="$out"
  printf '%s' "$out"
}

run_set()  { build_set; }
perf_set() { build_set; }

# ── first_party_check_set: the `ipe type-check`-only FLOOR over shipped examples ─
# The first-party examples the project SHIPS and expects to type-check: every
# flat `examples/shapes/*/*` and `examples/wasm/*` dir with a `src/Main.ipe`
# entry. Emitted one per line.
#
# SCOPE — this is a floor, not the parity sweep:
#   • INCLUDE examples/shapes/** and examples/wasm/** — authored, expected to
#     `ipe type-check` clean; a non-compiling one is a shipped regression.
#   • EXCLUDE an FFI-gated example — one that declares Rust FFI crates
#     with no generated bindings cache (needs_ffi_install). Its `import Rust.<Crate>`
#     modules are absent until `ipe install --allow-build-scripts` runs its
#     sandboxed bindings generation, which the per-commit gate does not do
#     (build-scripts / network / RCE-sandbox — the Rust-FFI subsystem). That is
#     an install prerequisite, not a shipped-broken example.
#
# A dir without a flat `src/Main.ipe` (a nested multi-project like
# examples/wasm/language-playground, whose sub-projects each carry their own
# manifest) has no single check entry and is not part of this flat floor.
first_party_check_set() {
  local d globs=(examples/shapes/*/*/ examples/wasm/*/)
  for d in "${globs[@]}"; do
    d="${d%/}"
    [ -f "$d/src/Main.ipe" ] || continue
    needs_ffi_install "$d" && continue
    printf '%s\n' "$d"
  done
  # Explicit: without this, the function's exit status is whatever the LAST
  # loop iteration's last command happened to return (e.g. a false `[ -f … ]`
  # on the final glob entry) — an accident of enumeration order, not a signal
  # of success/failure. A caller that checks this function's `$?` to detect a
  # real producer failure needs 0 to mean "enumeration completed" reliably,
  # even when it enumerated zero entries.
  return 0
}
