#!/usr/bin/env bash
# Self-test for tools/scripts/lib/require-tool.sh — proves the fail-closed
# refusals a missing-tool gate must take, so the mechanism can't silently
# regress to "if rg …; then" reading exit 127 as "no match".
#
# Exit 0 when every case behaves; prints the failing case(s) and exits 1
# otherwise.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lib="$repo_root/tools/scripts/lib/require-tool.sh"

fail=0
check() {
    local desc="$1" got="$2" want="$3"
    if [ "$got" != "$want" ]; then
        echo "FAIL: $desc — got '$got', want '$want'" >&2
        fail=1
    else
        echo "ok: $desc"
    fi
}
# cause_of <output> <substring>: "named" when the output carries the expected
# cause, else the output itself — so a refusal is proven to fire for the reason
# under test, not an unrelated earlier exit 2.
cause_of() {
    case "$1" in *"$2"*) echo named ;; *) printf '%s' "$1" ;; esac
}

# ── an rg-free PATH: every ordinary coreutils/bash/dirname/etc. tool stays
# reachable so the harness itself keeps working, but `rg` specifically is
# absent — isolating "rg is missing" from "PATH is empty". ─────────────────
rg_free_path="$(mktemp -d)"
for d in /usr/local/bin /usr/bin /bin; do
    [ -d "$d" ] || continue
    for f in "$d"/*; do
        [ -e "$f" ] || continue
        b="$(basename "$f")"
        [ "$b" = rg ] && continue
        [ -e "$rg_free_path/$b" ] && continue
        ln -s "$f" "$rg_free_path/$b" 2>/dev/null
    done
done

fixture_dir="$(mktemp -d)"
trap 'chmod -R u+rwX "$fixture_dir" 2>/dev/null; rm -rf "$rg_free_path" "$fixture_dir"' EXIT

# The helpers run only allowlisted executables (matchers rg/grep, producers
# git/find/sort), so each stub is an executable file under an allowlisted name
# with a chosen exit code, named by path.
stub() { # stub <dir> <name> <body>
    mkdir -p "$fixture_dir/$1"
    printf '#!/usr/bin/env bash\n%s\n' "$3" > "$fixture_dir/$1/$2"
    chmod +x "$fixture_dir/$1/$2"
}
stub m0 rg 'exit 0'
stub m1 rg 'exit 1'
stub m2 rg 'exit 2'
stub mprint rg 'printf "$@"'
stub p128 git 'printf "a\\0"; exit 128'
stub pprint git 'while [ "$#" -gt 0 ] && [ "$1" != ls-files ]; do shift; done; shift; printf "$@"'
m0="$fixture_dir/m0/rg"
m1="$fixture_dir/m1/rg"
m2="$fixture_dir/m2/rg"
mprint="$fixture_dir/mprint/rg"
p128="$fixture_dir/p128/git"
pprint="$fixture_dir/pprint/git"

# ── require_tool: a missing tool exits 2, a present one exits 0 ─────────────
rc=0
PATH="$rg_free_path" bash -c "source '$lib'; require_tool rg" >/dev/null 2>&1 || rc=$?
check "require_tool exits 2 when the tool is missing" "$rc" 2

rc=0
bash -c "source '$lib'; require_tool bash" >/dev/null 2>&1 || rc=$?
check "require_tool exits 0 when the tool is present" "$rc" 0

# ── rg_status: exit 1 is no-match, exit 2 (or any non-0/1) is error ─────────
got="$(bash -c "source '$lib'; rg_status 0")"
check "rg_status 0 -> match" "$got" match
got="$(bash -c "source '$lib'; rg_status 1")"
check "rg_status 1 -> no-match" "$got" no-match
got="$(bash -c "source '$lib'; rg_status 2")"
check "rg_status 2 -> error" "$got" error
got="$(bash -c "source '$lib'; rg_status 127")"
check "rg_status 127 (command not found) -> error" "$got" error

# ── match_or_fail: mirrors rg_status through a real command's exit code ─────
rc=0
bash -c "source '$lib'; match_or_fail t -- '$m1'" >/dev/null 2>&1
rc=$?
check "match_or_fail: exit 1 (no match) returns 1, doesn't hard-fail" "$rc" 1

rc=0
bash -c "source '$lib'; match_or_fail t -- '$m0'" >/dev/null 2>&1
rc=$?
check "match_or_fail: exit 0 (match) returns 0" "$rc" 0

rc=0
bash -c "source '$lib'; match_or_fail t -- '$m2'" >/dev/null 2>&1
rc=$?
check "match_or_fail: exit 2 (rg error) hard-exits 2" "$rc" 2

rc=0
PATH="$rg_free_path" bash -c "source '$lib'; match_or_fail t -- rg foo bar" >/dev/null 2>&1
rc=$?
check "match_or_fail: command-not-found (127) hard-exits, never reads as no-match" "$rc" 2

# ── the actual gate: fails on a fixture with a known tone violation ─────────
goldens_fixture="$fixture_dir/render_goldens"
explain_fixture="$fixture_dir/explain"
mkdir -p "$goldens_fixture" "$explain_fixture"
# The gate scans explain_fixture too (jargon + jargon_cased), so
# require_scan_root needs a matching *.md file in it from the start — an
# emptied scan root must fail closed (exit 2), so every gate invocation below
# needs a real file present in BOTH scanned dirs, not just the one under test.
printf '# IPE-T0001\n\nno jargon here either\n' > "$explain_fixture/IPE-T0001.md"
printf 'IPE-T0001: type mismatch\n\nsee salsa for details\n' > "$goldens_fixture/violation.txt"

rc=0
GOLDENS_DIR="$goldens_fixture" EXPLAIN_DIR="$explain_fixture" \
    bash "$repo_root/tools/scripts/lint-diagnostic-tone.sh" >/dev/null 2>&1 || rc=$?
check "diagnostic-tone gate fails on a fixture jargon violation" "$rc" 1

rm -f "$goldens_fixture/violation.txt"
printf 'IPE-T0001: type mismatch\n\nno jargon here\n' > "$goldens_fixture/clean.txt"
rc=0
GOLDENS_DIR="$goldens_fixture" EXPLAIN_DIR="$explain_fixture" \
    bash "$repo_root/tools/scripts/lint-diagnostic-tone.sh" >/dev/null 2>&1 || rc=$?
check "diagnostic-tone gate passes on a clean fixture" "$rc" 0

# ── the actual gate: hard-fails (never vacuously passes) when rg is absent ──
rc=0
printf 'IPE-T0001: type mismatch\n\nsee salsa for details\n' > "$goldens_fixture/violation.txt"
GOLDENS_DIR="$goldens_fixture" EXPLAIN_DIR="$explain_fixture" PATH="$rg_free_path" \
    bash "$repo_root/tools/scripts/lint-diagnostic-tone.sh" >/dev/null 2>&1 || rc=$?
check "diagnostic-tone gate exits 2 (not 0) when rg is missing from PATH" "$rc" 2
rm -f "$goldens_fixture/violation.txt"

# ── require_scan_root: a missing or emptied scan root must fail closed (exit
# 2), never read as "clean" because rg then simply finds nothing ───────────
nonexistent_dir="$fixture_dir/does-not-exist"
rc=0
GOLDENS_DIR="$nonexistent_dir" EXPLAIN_DIR="$explain_fixture" \
    bash "$repo_root/tools/scripts/lint-diagnostic-tone.sh" >/dev/null 2>&1 || rc=$?
check "diagnostic-tone gate exits 2 when GOLDENS_DIR does not exist" "$rc" 2

empty_goldens="$fixture_dir/empty-goldens"
mkdir -p "$empty_goldens"
rc=0
GOLDENS_DIR="$empty_goldens" EXPLAIN_DIR="$explain_fixture" \
    bash "$repo_root/tools/scripts/lint-diagnostic-tone.sh" >/dev/null 2>&1 || rc=$?
check "diagnostic-tone gate exits 2 when GOLDENS_DIR has no matching file" "$rc" 2
rmdir "$empty_goldens"

rc=0
bash -c "source '$lib'; require_scan_root '$nonexistent_dir' '*.txt'" >/dev/null 2>&1 || rc=$?
check "require_scan_root exits 2 when the dir is missing" "$rc" 2

mkdir -p "$fixture_dir/empty-root"
rc=0
bash -c "source '$lib'; require_scan_root '$fixture_dir/empty-root' '*.txt'" >/dev/null 2>&1 || rc=$?
check "require_scan_root exits 2 when the dir has no matching file" "$rc" 2
rmdir "$fixture_dir/empty-root"

rc=0
bash -c "source '$lib'; require_scan_root '$goldens_fixture' '*.txt'" >/dev/null 2>&1 || rc=$?
check "require_scan_root exits 0 when the dir has a matching file" "$rc" 0

# ── match_capture: mirrors match_or_fail, plus captures the matched text ───
got="$(bash -c "source '$lib'; match_capture v t -- '$mprint' 'a\nb\n'; printf '%s' \"\$v\"")"
check "match_capture: match captures the command's stdout" "$got" "$(printf 'a\nb')"

rc=0
bash -c "source '$lib'; match_capture v t -- '$m1'" >/dev/null 2>&1
rc=$?
check "match_capture: exit 1 (no match) returns 1, doesn't hard-fail" "$rc" 1

rc=0
bash -c "source '$lib'; match_capture v t -- '$m0'" >/dev/null 2>&1
rc=$?
check "match_capture: exit 0 (match) returns 0" "$rc" 0

rc=0
bash -c "source '$lib'; match_capture v t -- '$m2'" >/dev/null 2>&1
rc=$?
check "match_capture: exit 2 hard-exits 2" "$rc" 2

# ── capture_nul / enumerate_files: producer failure or empty set exits 2 ────
rc=0
bash -c "source '$lib'; capture_nul v t -- '$p128' ls-files" >/dev/null 2>&1 || rc=$?
check "capture_nul: a producer exiting 128 after partial output hard-exits 2" "$rc" 2

got="$(bash -c "source '$lib'; capture_nul v t -- '$pprint' ls-files 'a b\\0c\\0'; printf '%s|' \"\${v[@]}\"")"
check "capture_nul: loads NUL-delimited records intact" "$got" "a b|c|"

mkdir -p "$fixture_dir/enum/sub" "$fixture_dir/enum-empty"
printf 'x\n' > "$fixture_dir/enum/sub/b.ipe"
printf 'x\n' > "$fixture_dir/enum/a.ipe"
got="$(bash -c "source '$lib'; enumerate_files v '*.ipe' '$fixture_dir/enum'; printf '%s|' \"\${v[@]#$fixture_dir/enum/}\"")"
check "enumerate_files: sorted set of every matching file" "$got" "a.ipe|sub/b.ipe|"

rc=0
bash -c "source '$lib'; enumerate_files v '*.ipe' '$fixture_dir/enum-empty'" >/dev/null 2>&1 || rc=$?
check "enumerate_files: an empty set exits 2" "$rc" 2

rc=0
bash -c "source '$lib'; enumerate_files v '*.ipe' '$fixture_dir/enum' '$fixture_dir/nope'" >/dev/null 2>&1 || rc=$?
check "enumerate_files: any missing root exits 2" "$rc" 2

# ── output-name collisions: a caller name equal to a former helper local
# still receives the value (every helper local is `__`-prefixed) ────────────
for name in rc d desc var tmp out; do
    got="$(bash -c "source '$lib'; capture_nul $name d -- '$pprint' ls-files 'a\\0'; printf '%s' \"\${#${name}[@]}\"" 2>&1)"
    check "capture_nul: output named '$name' receives the set" "$got" 1
    got="$(bash -c "source '$lib'; match_capture $name d -- '$mprint' hit; printf '%s' \"\$$name\"" 2>&1)"
    check "match_capture: output named '$name' receives the text" "$got" hit
done
for name in glob root found sorted tmp out var r; do
    got="$(bash -c "source '$lib'; enumerate_files $name '*.ipe' '$fixture_dir/enum'; printf '%s' \"\${#${name}[@]}\"" 2>&1)"
    check "enumerate_files: output named '$name' receives the set" "$got" 2
done

# ── output-name refusals: the reserved `__` prefix and a non-identifier are
# refused (exit 2) by every helper that writes a caller variable ───────────
reserved_names="__cn_var __cn_desc __cn_tmp __cn_rc __mc_var __mc_desc __mc_out __mc_rc
    __ef_var __ef_glob __ef_root __ef_found __ef_tmp __ef_sorted __ef_out __rsr_files
    __dc_kind __mf_desc __mf_rc __x"
for name in $reserved_names; do
    for call in "capture_nul $name t -- '$pprint' ls-files 'a\\0'" \
                "match_capture $name t -- '$mprint' hit" \
                "enumerate_files $name '*.ipe' '$fixture_dir/enum'"; do
        rc=0
        out="$(bash -c "source '$lib'; $call" 2>&1)" || rc=$?
        check "${call%% *}: reserved output '$name' exits 2" "$rc" 2
        check "${call%% *}: reserved output '$name' is the reported cause" \
            "$(cause_of "$out" "output variable '$name' is not a lowercase identifier")" named
    done
done
for name in "''" 1x a-b 'a[0]' "'x y'"; do
    for helper in "capture_nul $name t -- '$pprint' ls-files 'a\\0'" \
                  "match_capture $name t -- '$mprint' hit" \
                  "enumerate_files $name '*.ipe' '$fixture_dir/enum'"; do
        rc=0
        out="$(bash -c "source '$lib'; $helper" 2>&1)" || rc=$?
        check "${helper%% *}: invalid output $name exits 2" "$rc" 2
        check "${helper%% *}: invalid output $name is the reported cause" \
            "$(cause_of "$out" "is not a lowercase identifier")" named
    done
done

# ── direct-command refusals: builtins (eval, source, ., command, builtin,
# exec, false), keywords, aliases, shells, and launchers can each run a
# masked pipeline, so every helper refuses them (exit 2) ──────────────────
for helper in "match_or_fail t" "match_capture v t" "capture_nul v t"; do
    for cmd in "eval 'false | rg foo'" "source /dev/null" ". /dev/null" \
               "command rg foo" "builtin echo" "exec rg foo" "false"; do
        rc=0
        out="$(bash -c "source '$lib'; $helper -- $cmd" 2>&1)" || rc=$?
        check "${helper%% *}: refuses builtin '${cmd%% *}' (exit 2)" "$rc" 2
        check "${helper%% *}: builtin '${cmd%% *}' is the reported cause" \
            "$(cause_of "$out" "'${cmd%% *}' is builtin")" named
    done
    rc=0
    out="$(bash -c "source '$lib'; $helper -- time rg foo" 2>&1)" || rc=$?
    check "${helper%% *}: refuses a keyword (exit 2)" "$rc" 2
    check "${helper%% *}: the keyword is the reported cause" \
        "$(cause_of "$out" "'time' is keyword")" named
    rc=0
    out="$(bash -c "source '$lib'; shopt -s expand_aliases; alias al='false | true'
$helper -- al" 2>&1)" || rc=$?
    check "${helper%% *}: refuses an alias (exit 2)" "$rc" 2
    check "${helper%% *}: the alias is the reported cause" \
        "$(cause_of "$out" "'al' is alias")" named
    rc=0
    out="$(bash -c "source '$lib'; wrapped() { false | true; }; $helper -- wrapped" 2>&1)" || rc=$?
    check "${helper%% *}: refuses a shell function (exit 2)" "$rc" 2
    check "${helper%% *}: the function is the reported cause" \
        "$(cause_of "$out" "'wrapped' is function")" named
    for cmd in "bash -c 'false | rg foo'" "sh -c 'false | rg foo'" \
               "$(type -P bash) -c 'false | rg foo'" "env rg foo" "xargs rg"; do
        rc=0
        out="$(bash -c "source '$lib'; $helper -- $cmd" 2>&1)" || rc=$?
        check "${helper%% *}: refuses launcher '${cmd%% *}' (exit 2)" "$rc" 2
        check "${helper%% *}: launcher '${cmd%% *}' is the reported cause" \
            "$(cause_of "$out" "is not a known-contract")" named
    done
done

# ── known-contract allowlist: an executable whose exit code is not a known
# matcher/producer contract is refused (exit 2), however it is disguised ────
opaque="$fixture_dir/opaque"
mkdir -p "$opaque"
ln -s "$(type -P bash)" "$opaque/myshell"
ln -s "$(type -P bash)" "$opaque/rg"
ln -s "$(type -P bash)" "$opaque/git"
real_rg="$(type -P rg)"
for helper in "match_or_fail t" "match_capture v t" "capture_nul v t"; do
    for cmd in "'$opaque/myshell' -c 'false | rg -q x'" \
               "'$opaque/rg' -c 'false | rg -q x'" "'$opaque/git' -c 'false | rg -q x'" \
               "perl -e 'exit(system(\"false|rg -q x\")>>8)'" \
               "awk 'BEGIN{exit system(\"false|rg -q x\")}'" \
               "python3 -c 'import subprocess,sys; sys.exit(subprocess.call(\"false|rg -q x\", shell=True))'" \
               "/usr/bin/time bash -c 'false | rg -q x'" "ionice bash -c 'false | rg -q x'" \
               "flock /dev/null bash -c 'false | rg -q x'"; do
        word="${cmd%% *}"; word="${word//\'/}"
        rc=0
        out="$(bash -c "source '$lib'; $helper -- $cmd" 2>&1)" || rc=$?
        check "${helper%% *}: refuses opaque runner '${word##*/}' (exit 2)" "$rc" 2
        if [ -n "$(type -P "$word")" ]; then
            check "${helper%% *}: '${word##*/}' is refused as an unknown contract" \
                "$(cause_of "$out" "is not a known-contract")" named
        else
            check "${helper%% *}: absent '${word##*/}' is refused as not a command" \
                "$(cause_of "$out" "is not a command")" named
        fi
    done
    rc=0
    out="$(bash -c "source '$lib'; hash -p '$(type -P bash)' rg; hash -p '$(type -P bash)' git
$helper -- $( [ "${helper%% *}" = capture_nul ] && echo git || echo rg ) -c 'false | rg -q x'" 2>&1)" || rc=$?
    check "${helper%% *}: refuses a 'hash -p' entry disguising a shell (exit 2)" "$rc" 2
    check "${helper%% *}: the hashed shell is the reported cause" \
        "$(cause_of "$out" "resolves to $(readlink -f "$(type -P bash)")")" named
done
for helper in "match_or_fail t" "match_capture v t"; do
    for cmd in "find /nonexistent -exec rg x {} +" "sort /dev/null" "git ls-files"; do
        rc=0
        out="$(bash -c "source '$lib'; $helper -- $cmd" 2>&1)" || rc=$?
        check "${helper%% *}: refuses non-matcher '${cmd%% *}' (exit 2)" "$rc" 2
        check "${helper%% *}: non-matcher '${cmd%% *}' is the reported cause" \
            "$(cause_of "$out" "is not a known-contract matcher")" named
    done
    rc=0
    out="$(bash -c "source '$lib'; $helper -- rg --pre /bin/false x /dev/null" 2>&1)" || rc=$?
    check "${helper%% *}: refuses 'rg --pre' (exit 2)" "$rc" 2
    check "${helper%% *}: 'rg --pre' is the reported cause" \
        "$(cause_of "$out" "'rg --pre' is outside the known exit contract")" named
    mkdir -p "$opaque/linked"
    ln -sf "$real_rg" "$opaque/linked/rg"
    rc=0
    bash -c "source '$lib'; $helper -- '$opaque/linked/rg' -q zzz_no_such_text /dev/null" >/dev/null 2>&1 || rc=$?
    check "${helper%% *}: a symlink named rg to the real rg keeps the no-match verdict (1)" "$rc" 1
    rc=0
    bash -c "source '$lib'; $helper -- grep -q zzz_no_such_text /dev/null" >/dev/null 2>&1 || rc=$?
    check "${helper%% *}: grep no-match returns 1" "$rc" 1
    rc=0
    bash -c "source '$lib'; $helper -- grep -q x /nonexistent" >/dev/null 2>&1 || rc=$?
    check "${helper%% *}: grep error (exit 2) hard-exits 2" "$rc" 2
    rc=0
    RIPGREP_CONFIG_PATH="$fixture_dir/rgrc" bash -c "printf -- '--invert-match\n' > '$fixture_dir/rgrc'; source '$lib'; $helper -- rg -q zzz_no_such_text '$lib'" >/dev/null 2>&1 || rc=$?
    check "${helper%% *}: an inherited RIPGREP_CONFIG_PATH cannot flip the verdict" "$rc" 1
done
for cmd in "find /nonexistent -exec rg x {} +" "find . -execdir true {} ;" \
           "find . -ok true {} ;" "find . -okdir true {} ;" \
           "sort --compress-program=bash /dev/null" "sort --co=bash /dev/null" \
           "git -c alias.x=!false x" "git status" "git" \
           "git rev-parse --git-dir" "git rev-parse --show-toplevel HEAD" "git rev-parse"; do
    rc=0
    out="$(bash -c "source '$lib'; capture_nul v t -- $cmd" 2>&1)" || rc=$?
    check "capture_nul: refuses '$cmd' (exit 2)" "$rc" 2
    check "capture_nul: '$cmd' is refused as outside the contract" \
        "$(cause_of "$out" "is outside the known exit contract")" named
done
for cmd in "rg -l x ." "grep -rl x ." "cat /dev/null"; do
    rc=0
    out="$(bash -c "source '$lib'; capture_nul v t -- $cmd" 2>&1)" || rc=$?
    check "capture_nul: refuses non-producer '${cmd%% *}' (exit 2)" "$rc" 2
    check "capture_nul: non-producer '${cmd%% *}' is the reported cause" \
        "$(cause_of "$out" "is not a known-contract producer")" named
done

# ── output-target refusals: `_`, bash specials, and readonly/attributed
# targets are refused (exit 2) by every writer, before any write ───────────
for pre_name in "_" "BASH_VERSINFO" "GROUPS" "FUNCNAME" "RANDOM" "PATH" "Upper" \
                "readonly v=1;v" "readonly -a v=();v" "declare -i v;v" "declare -l v;v" \
                "declare -A v;v" "x=1; declare -n v=x;v" "declare -r v;v"; do
    pre=""; name="$pre_name"
    case "$pre_name" in *";"*) pre="${pre_name%;*};"; name="${pre_name##*;}" ;; esac
    for helper in "capture_nul $name t -- '$pprint' ls-files 'a\\0'" \
                  "match_capture $name t -- '$mprint' hit" \
                  "enumerate_files $name '*.ipe' '$fixture_dir/enum'"; do
        rc=0
        out="$(bash -c "source '$lib'; $pre $helper" 2>&1)" || rc=$?
        check "${helper%% *}: target '$pre_name' exits 2" "$rc" 2
        if [ -n "$pre" ]; then want="output variable '$name' carries attributes"
        else want="output variable '$name' is not a lowercase identifier"; fi
        check "${helper%% *}: target '$pre_name' is the reported cause" \
            "$(cause_of "$out" "$want")" named
    done
done
for pre_name in "declare -a v;v" "local_v"; do
    name="${pre_name##*;}"; pre=""
    case "$pre_name" in *";"*) pre="${pre_name%;*};" ;; esac
    got="$(bash -c "source '$lib'; $pre capture_nul $name t -- '$pprint' ls-files 'a\\0b\\0'; printf '%s' \"\${#${name}[@]}\"" 2>&1)"
    check "capture_nul: plain target '$pre_name' receives the set" "$got" 2
done

# ── output-target shape: each writer accepts exactly the shape it writes ───
got="$(bash -c "source '$lib'; v=''; match_capture v t -- '$mprint' hit; printf '%s' \"\$v\"" 2>&1)"
check "match_capture: pre-declared plain scalar receives the text" "$got" hit
got="$(bash -c "source '$lib'; f() { local v=''; match_capture v t -- '$mprint' hit; printf '%s' \"\$v\"; }; f" 2>&1)"
check "match_capture: caller-local plain scalar receives the text" "$got" hit
rc=0
out="$(bash -c "source '$lib'; v=(a b c); match_capture v t -- '$mprint' hit" 2>&1)" || rc=$?
check "match_capture: array target exits 2 (a scalar write keeps stale elements)" "$rc" 2
check "match_capture: array target is the reported cause" \
    "$(cause_of "$out" "is an array, but this helper writes a scalar")" named
for helper in "capture_nul v t -- '$pprint' ls-files 'a\\0'" \
              "enumerate_files v '*.ipe' '$fixture_dir/enum'"; do
    rc=0
    out="$(bash -c "source '$lib'; v=x; $helper" 2>&1)" || rc=$?
    check "${helper%% *}: plain scalar target exits 2" "$rc" 2
    check "${helper%% *}: plain scalar target is the reported cause" \
        "$(cause_of "$out" "is a scalar, but this helper writes an array")" named
done

# ── env scrub: a matcher never runs under a config variable it cannot drop,
# and the refusal names exactly the variable that survived ─────────────────
stub g0 grep 'exit 0'
g0="$fixture_dir/g0/grep"
for pair in "RIPGREP_CONFIG_PATH:$m0:$mprint:GREP_OPTIONS" "GREP_OPTIONS:$g0:$g0:RIPGREP_CONFIG_PATH"; do
    IFS=: read -r var mcmd ccmd other <<<"$pair"
    for helper in "match_or_fail t -- '$mcmd'" "match_capture v t -- '$ccmd' hit"; do
        rc=0
        out="$(bash -c "source '$lib'; readonly $var=cfg; export $var; $helper" 2>&1)" || rc=$?
        check "${helper%% *} (${mcmd##*/}): readonly $var exits 2" "$rc" 2
        check "${helper%% *} (${mcmd##*/}): readonly $var is the reported cause" \
            "$(cause_of "$out" "could not scrub $var —")" named
        check "${helper%% *} (${mcmd##*/}): the refusal names only the surviving variable" \
            "$(case "$out" in *"$other"*|*readonly?*) echo "$out" ;; *) echo only ;; esac)" only
        # A nameref alias is scrubbed too; a readonly nameref binding (which
        # unset -n cannot remove) is refused.
        rc=0
        out="$(bash -c "source '$lib'; export $var=zz; declare -rn $var=zz; $helper" 2>&1)" || rc=$?
        check "${helper%% *} (${mcmd##*/}): readonly nameref $var exits 2" "$rc" 2
        check "${helper%% *} (${mcmd##*/}): readonly nameref $var is the reported cause" \
            "$(cause_of "$out" "could not scrub $var —")" named
    done
done

# ── env scrub: a caller's exported local shadowing an exported global is
# dropped in every scope, never falsely refused nor left in effect ─────────
printf -- '--invert-match\n' > "$fixture_dir/rgrc-shadow"
rc=0
out="$(RIPGREP_CONFIG_PATH="$fixture_dir/rgrc-shadow" bash -c "source '$lib'; f() { local -x RIPGREP_CONFIG_PATH='$fixture_dir/rgrc-shadow'; match_or_fail t -- rg -q zzz_no_such_text '$lib'; }; f" 2>&1)" || rc=$?
check "match_or_fail: a local -x RIPGREP_CONFIG_PATH over an exported global is scrubbed (no-match, 1)" "$rc:$out" "1:"
rc=0
out="$(bash -c "source '$lib'; f() { local -x RIPGREP_CONFIG_PATH=x; g; }; g() { local -x RIPGREP_CONFIG_PATH=y; match_or_fail t -- '$m0'; }; export RIPGREP_CONFIG_PATH=z; f" 2>&1)" || rc=$?
check "match_or_fail: three stacked RIPGREP_CONFIG_PATH bindings are all dropped (match, 0)" "$rc:$out" "0:"

# ── env scrub: sort runs under LC_ALL=C or not at all ──────────────────────
rc=0
out="$(bash -c "source '$lib'; readonly LC_ALL=en_US.UTF-8; enumerate_files v '*.ipe' '$fixture_dir/enum'" 2>&1)" || rc=$?
check "enumerate_files: a readonly non-C LC_ALL exits 2" "$rc" 2
check "enumerate_files: the unpinnable LC_ALL is the reported cause" \
    "$(cause_of "$out" "could not scrub LC_ALL —")" named

# ── enumerate_files: a failing sort leaves no staged temp file behind ───────
sort_tmpdir="$(mktemp -d)"
sort_stub="$fixture_dir/sort-fail-bin"
mkdir -p "$sort_stub"
printf '#!/bin/sh\nexit 3\n' > "$sort_stub/sort"
chmod +x "$sort_stub/sort"
rc=0
TMPDIR="$sort_tmpdir" PATH="$sort_stub:$PATH" \
    bash -c "source '$lib'; enumerate_files v '*.ipe' '$fixture_dir/enum'" >/dev/null 2>&1 || rc=$?
check "enumerate_files: failing sort exits 2" "$rc" 2
check "enumerate_files: failing sort leaves no temp file" "$(ls -A "$sort_tmpdir")" ""
rm -rf "$sort_tmpdir"

# ── enumerate_files: a sort result that is not exactly a permutation of the
# found set is refused whatever sort's exit code — a dropped record, a record
# truncated mid-way, a substituted or duplicated record, and a writer killed
# while emitting the final record ──────────────────────────────────────────
real_sort="$(type -P sort)"
sort_case() { # sort_case <name> <sh body using $S for the real sort> <cause> <what>
    local d="$fixture_dir/sort-$1-bin"
    mkdir -p "$d"
    printf '#!/bin/sh\nS=%s\n%s\n' "$real_sort" "$2" > "$d/sort"
    chmod +x "$d/sort"
    local rc=0 out
    out="$(PATH="$d:$PATH" bash -c "source '$lib'; enumerate_files v '*.ipe' '$fixture_dir/enum'" 2>&1)" || rc=$?
    check "enumerate_files: $4 exits 2" "$rc" 2
    check "enumerate_files: $4 is the reported cause" "$(cause_of "$out" "$3")" named
}
# shellcheck disable=SC2016  # $S / $$ expand inside the stub
sort_case drop '"$S" "$@" | head -z -n 1' "refusing a possibly truncated set" \
    "a dropped record (rc 0)"
# shellcheck disable=SC2016
sort_case midrec '"$S" "$@" | head -c -3' "not one of the found" \
    "a final record truncated mid-way (rc 0)"
# shellcheck disable=SC2016
sort_case forged '"$S" "$@" | tail -z -n +2; printf "/etc/passwd\0"' "not one of the found" \
    "a substituted record (rc 0)"
# shellcheck disable=SC2016
sort_case dup 'f="$("$S" "$@" | head -z -n 1 | tr -d "\0")"; printf "%s\0%s\0" "$f" "$f"' \
    "not one of the found" "a duplicated record standing in for another (rc 0)"
# shellcheck disable=SC2016
sort_case killed '"$S" "$@" | head -c -3; kill -9 $$' "producer exited 137" \
    "a writer killed during the final record"

# ── live caller smoke: examples.sh's scalar capture runs on a clean tree ────
rc=0
out="$(bash -c "source '$repo_root/tools/scripts/lib/examples.sh'; is_out_of_scope '$repo_root/examples/shapes/script/log-severities'" 2>&1)" || rc=$?
check "examples.sh: is_out_of_scope classifies an in-scope example (rc 1, no hard exit)" "$rc:$out" "1:"

# ── stub producers: a PATH dir whose tool exits with a chosen error code ─────
real_git="$(command -v git)"
stub_bin="$fixture_dir/stub-bin"
mkdir -p "$stub_bin"
# git that fails `ls-files` (the tracked-set producer) and passes through the rest.
cat > "$stub_bin/git" <<EOF
#!/usr/bin/env bash
for a in "\$@"; do [ "\$a" = ls-files ] && exit 128; done
exec "$real_git" "\$@"
EOF
chmod +x "$stub_bin/git"
rg_stub_home="$fixture_dir/stub-home"
mkdir -p "$rg_stub_home/.cargo/bin"
printf '#!/usr/bin/env bash\nexit 2\n' > "$rg_stub_home/.cargo/bin/rg"
chmod +x "$rg_stub_home/.cargo/bin/rg"

new_repo() {
    local r="$1"
    mkdir -p "$r"
    "$real_git" -C "$r" init -q
    printf 'ok\n' > "$r/README"
    "$real_git" -C "$r" add README
}

# ── enumerate_files: a root spelled like a find option stays a path ─────────
mkdir -p "$fixture_dir/optroot/-delete"
printf 'x\n' > "$fixture_dir/optroot/-delete/keep.txt"
got="$(cd "$fixture_dir/optroot" && bash -c "source '$lib'; enumerate_files v '*.txt' -delete; printf '%s|' \"\${v[@]}\"" 2>&1)"
check "enumerate_files: a '-delete' root is scanned as a directory" "$got" "./-delete/keep.txt|"
check "enumerate_files: a '-delete' root never deletes" \
    "$([ -e "$fixture_dir/optroot/-delete/keep.txt" ] && echo kept || echo deleted)" kept
mkdir -p "$fixture_dir/bangroot/!" "$fixture_dir/bangroot/decoy.txt"
printf 'x\n' > "$fixture_dir/bangroot/!/a.txt"
got="$(cd "$fixture_dir/bangroot" && bash -c "source '$lib'; enumerate_files v '*.txt' '!'; printf '%s|' \"\${v[@]}\"" 2>&1)"
check "enumerate_files: a '!' root is scanned as a directory, never negates" "$got" "./!/a.txt|"

# ── artifact-guard: producer failure, forbidden artifact, clean tree ─────────
guard="$repo_root/.github/ci/artifact-guard.sh"
new_repo "$fixture_dir/repo-clean"
rc=0
(cd "$fixture_dir/repo-clean" && bash "$guard") >/dev/null 2>&1 || rc=$?
check "artifact-guard: a clean tracked set passes" "$rc" 0

rc=0
out="$(cd "$fixture_dir/repo-clean" && PATH="$stub_bin:$PATH" bash "$guard" 2>&1)" || rc=$?
check "artifact-guard: git ls-files exiting 128 fails closed (exit 2), never clean" "$rc" 2
check "artifact-guard: the git failure is the reported cause" \
    "$(cause_of "$out" "producer exited 128")" named

new_repo "$fixture_dir/repo-target"
mkdir -p "$fixture_dir/repo-target/x/target"
printf 'blob\n' > "$fixture_dir/repo-target/x/target/y"
"$real_git" -C "$fixture_dir/repo-target" add x/target/y
rc=0
(cd "$fixture_dir/repo-target" && bash "$guard") >/dev/null 2>&1 || rc=$?
check "artifact-guard: a tracked x/target/y fails (exit 1)" "$rc" 1

new_repo "$fixture_dir/repo-decoy"
rc=0
(cd "$fixture_dir/repo-target" && GIT_DIR="$fixture_dir/repo-decoy/.git" \
    GIT_WORK_TREE="$fixture_dir/repo-decoy" bash "$guard") >/dev/null 2>&1 || rc=$?
check "artifact-guard: GIT_DIR/GIT_WORK_TREE at a clean decoy still checks the real tree (exit 1)" "$rc" 1

new_repo "$fixture_dir/repo-ext"
printf 'blob\n' > "$fixture_dir/repo-ext/lib.rlib"
"$real_git" -C "$fixture_dir/repo-ext" add lib.rlib
rc=0
(cd "$fixture_dir/repo-ext" && bash "$guard") >/dev/null 2>&1 || rc=$?
check "artifact-guard: a tracked .rlib fails (exit 1)" "$rc" 1

# ── git contract env: config injection and a swapped index are neutralised,
# an unscrubbable GIT_* is refused ─────────────────────────────────────────
new_repo "$fixture_dir/repo-env"
printf '#!/bin/sh\ntouch "%s"\n' "$fixture_dir/fsmonitor-ran" > "$fixture_dir/fsmonitor-hook"
chmod +x "$fixture_dir/fsmonitor-hook"
tracked_list() { # run capture_nul git ls-files in repo-env under extra shell setup $1
    (cd "$fixture_dir/repo-env" && bash -c "source '$lib'; $1 capture_nul t d -- git ls-files -z; printf '%s|' \"\${t[@]}\"" 2>&1)
}
rm -f "$fixture_dir/fsmonitor-ran"
got="$(tracked_list "export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0='$fixture_dir/fsmonitor-hook';")"
check "capture_nul git: GIT_CONFIG_COUNT core.fsmonitor still yields the real tracked set" "$got" "README|"
check "capture_nul git: GIT_CONFIG_COUNT core.fsmonitor never runs the hook" \
    "$([ -e "$fixture_dir/fsmonitor-ran" ] && echo ran || echo not-run)" not-run
rm -f "$fixture_dir/fsmonitor-ran"
got="$(tracked_list "export GIT_CONFIG_PARAMETERS=\"'core.fsmonitor'='$fixture_dir/fsmonitor-hook'\";")"
check "capture_nul git: GIT_CONFIG_PARAMETERS core.fsmonitor never runs the hook" \
    "$([ -e "$fixture_dir/fsmonitor-ran" ] && echo ran || echo not-run):$got" "not-run:README|"
rm -f "$fixture_dir/fsmonitor-ran"
printf '[core]\n\tfsmonitor = %s\n' "$fixture_dir/fsmonitor-hook" > "$fixture_dir/global-gitconfig"
got="$(tracked_list "export HOME='$fixture_dir' XDG_CONFIG_HOME='$fixture_dir'; cp '$fixture_dir/global-gitconfig' '$fixture_dir/.gitconfig';")"
"$real_git" -C "$fixture_dir/repo-env" config core.fsmonitor "$fixture_dir/fsmonitor-hook"
got2="$(tracked_list "")"
"$real_git" -C "$fixture_dir/repo-env" config --unset core.fsmonitor
rm -f "$fixture_dir/.gitconfig"
check "capture_nul git: a global or repo-local core.fsmonitor never runs the hook" \
    "$([ -e "$fixture_dir/fsmonitor-ran" ] && echo ran || echo not-run):$got:$got2" "not-run:README|:README|"
printf 'forged\n' > "$fixture_dir/repo-env/forged"
GIT_INDEX_FILE="$fixture_dir/forged-index" "$real_git" -C "$fixture_dir/repo-env" add forged
rm -f "$fixture_dir/repo-env/forged"
got="$(tracked_list "export GIT_INDEX_FILE='$fixture_dir/forged-index';")"
check "capture_nul git: an exported GIT_INDEX_FILE cannot swap in a forged tracked set" "$got" "README|"
got="$(tracked_list "f() { local -x GIT_INDEX_FILE='$fixture_dir/forged-index'; capture_nul t d -- git ls-files -z; printf '%s|' \"\${t[@]}\"; exit; }; f;")"
check "capture_nul git: a local -x GIT_INDEX_FILE cannot swap in a forged tracked set" "$got" "README|"
for pre in "readonly GIT_INDEX_FILE='$fixture_dir/forged-index'; export GIT_INDEX_FILE" \
           "readonly GIT_CONFIG_GLOBAL='$fixture_dir/global-gitconfig'; export GIT_CONFIG_GLOBAL"; do
    var="${pre#readonly }"; var="${var%%=*}"
    rc=0
    out="$(cd "$fixture_dir/repo-env" && bash -c "source '$lib'; $pre; capture_nul t d -- git ls-files -z" 2>&1)" || rc=$?
    check "capture_nul git: readonly $var exits 2" "$rc" 2
    check "capture_nul git: readonly $var is the reported cause" \
        "$(cause_of "$out" "could not scrub $var —")" named
done

# ── examples.sh: an rg error while classifying is a hard failure ─────────────
ex_lib="$repo_root/tools/scripts/lib/examples.sh"
ffi_ex="$fixture_dir/ffi-example"
mkdir -p "$ffi_ex/src"
printf -- '-- classifier stub\n' > "$ffi_ex/src/Main.ipe"
printf 'Package.rustDependencies []\n' > "$ffi_ex/package.ipe"
rc=0
bash -c "source '$ex_lib'; needs_ffi_install '$ffi_ex'" >/dev/null 2>&1 || rc=$?
check "needs_ffi_install: detects a rust-dependencies manifest (exit 0)" "$rc" 0
rc=0
out="$(PATH="$rg_stub_home/.cargo/bin:$PATH" bash -c "source '$ex_lib'; needs_ffi_install '$ffi_ex'" 2>&1)" || rc=$?
check "needs_ffi_install: rg exiting 2 hard-exits 2, never reads as no-FFI" "$rc" 2
check "needs_ffi_install: the rg error is the reported cause" \
    "$(cause_of "$out" "command exited 2")" named

# ── examples.sh: an unreadable source file fails the shape scan closed ─────
shape_ex="$fixture_dir/shape-example"
mkdir -p "$shape_ex/src"
printf 'import Ipe.Tea.Tui\n' > "$shape_ex/src/Main.ipe"
got="$(bash -c "source '$ex_lib'; example_shape '$shape_ex'" 2>&1)"
check "example_shape: a readable Tui source classifies as tui" "$got" tui
printf -- '-- classifier stub\n' > "$shape_ex/src/Hidden.ipe"
chmod 000 "$shape_ex/src/Hidden.ipe"
rc=0
out="$(bash -c "source '$ex_lib'; example_shape '$shape_ex'" 2>&1)" || rc=$?
check "example_shape: an unreadable source file exits 2, never a partial scan" "$rc" 2
check "example_shape: the unreadable file is the reported cause" \
    "$(cause_of "$out" "cannot open $shape_ex/src/Hidden.ipe")" named
chmod 644 "$shape_ex/src/Hidden.ipe"

# ── first-party floor: producer error and empty set both exit 2 ──────────────
floor="$repo_root/tools/scripts/first-party-check-floor.sh"
floor_repo="$fixture_dir/floor-repo"
mkdir -p "$floor_repo/tools/scripts"
: > "$floor_repo/tools/scripts/first-party-check-floor.sh"
run_floor() { # $1 = HOME for the run (its .cargo/bin leads env.sh's PATH)
    IPE_REPO="$floor_repo" IPE_BIN="$(type -P true)" HOME="$1" \
        CARGO_TARGET_DIR="$fixture_dir/floor-target" IPE_NO_SCCACHE=1 \
        bash "$floor" 2>&1
}
out="$(run_floor "$fixture_dir/plain-home")"; rc=$?
check "first-party floor: an empty example set exits 2" "$rc" 2
check "first-party floor: the empty set is the reported cause" \
    "$(cause_of "$out" "enumerated zero examples")" named

mkdir -p "$floor_repo/examples/shapes/cli/demo/src"
printf -- '-- classifier stub\n' > "$floor_repo/examples/shapes/cli/demo/src/Main.ipe"
printf 'Package.name "demo"\n' > "$floor_repo/examples/shapes/cli/demo/package.ipe"
out="$(run_floor "$fixture_dir/plain-home")"; rc=$?
check "first-party floor: a one-example set whose check passes exits 0" "$rc" 0
out="$(run_floor "$rg_stub_home")"; rc=$?
check "first-party floor: the set producer failing (rg exit 2) exits 2" "$rc" 2
check "first-party floor: the producer failure is the reported cause" \
    "$(cause_of "$out" "failed to enumerate")" named

# ── tree-sitter parity: a missing or empty scan root exits 2 before any parse ─
parity="$repo_root/editors/tree-sitter-ipe/scripts/parity-check.sh"
out="$(PARITY_SCAN_ROOTS="$fixture_dir/enum:$fixture_dir/nope" bash "$parity" 2>&1)"; rc=$?
check "parity-check: a missing scan root exits 2" "$rc" 2
check "parity-check: the missing root is the reported cause" \
    "$(cause_of "$out" "missing scan root")" named
out="$(PARITY_SCAN_ROOTS="$fixture_dir/enum:$fixture_dir/enum-empty" bash "$parity" 2>&1)"; rc=$?
check "parity-check: an empty scan root exits 2" "$rc" 2
check "parity-check: the empty root is the reported cause" \
    "$(cause_of "$out" "nothing to scan")" named

# ── structural: every fail-closed helper call site in the tree names a
# command on its contract's allowlist, judged by the lib's own allowlist
# predicates (the runtime refusal's static twin) ───────────────────────────
sh_files=()
(cd "$repo_root" && git ls-files -z -- '*.sh' > "$fixture_dir/sh-files") \
    || { echo "FAIL: git ls-files over *.sh failed" >&2; fail=1; }
mapfile -d '' -t sh_files < "$fixture_dir/sh-files"
# shellcheck disable=SC2016  # perl source, expanded by perl, not the shell
scan_pl='
    for my $f (@ARGV) {
        next if $f eq "tools/scripts/tests/test-require-tool.sh";
        open my $fh, "<", $f or die "open $f: $!";
        local $/; my $src = <$fh>; close $fh;
        $src =~ s/\\\n/ /g;
        for my $line (split /\n/, $src) {
            next if $line =~ /^\s*#/;
            while ($line =~ /\b(match_or_fail|match_capture|capture_nul)\b[^#]*?\s--\s+([^\s;|&)]+)/g) {
                print "$f\t$1\t$2\n";
            }
        }
    }
'
# scan_sites <file...>: print every call site whose command word is off the
# allowlist of its helper's contract ("scan errored" when the scan fails).
scan_sites() {
    local sites
    sites="$(perl -e "$scan_pl" "$@")" || { echo "scan errored"; return; }
    # shellcheck disable=SC2016  # expanded by the inner bash
    bash -c '
        source "$1"
        while IFS=$'"'\t'"' read -r f h cmd; do
            [ -n "$f" ] || continue
            case "$h" in capture_nul) pred=_require_producer_name ;; *) pred=_require_matcher_name ;; esac
            "$pred" "${cmd##*/}" || echo "$f: $h -- $cmd"
        done <<<"$2"
    ' _ "$lib" "$sites"
}
offenders="$(cd "$repo_root" && scan_sites "${sh_files[@]}")"
check "every match_or_fail/match_capture/capture_nul call site names an allowlisted command" "$offenders" ""
# The scan must fire on the shape it exists to forbid.
bad_sh="$fixture_dir/bad-gate.sh"
cat > "$bad_sh" <<'EOF'
_git_scan() { git ls-files | rg -e "$1"; }
match_capture hits "target scan" -- \
  _git_scan '(^|/)target/'
EOF
got="$(scan_sites "$bad_sh")"
check "structural scan flags a function-wrapped pipeline call site" \
    "$(cause_of "$got" "match_capture -- _git_scan")" named
for shape in "eval 'false | rg foo'" "bash -c 'false | rg foo'" "sh -c 'false | rg foo'" \
             "/bin/bash -ec 'false | rg foo'" "source ./gate.sh" ". ./gate.sh" \
             "command rg foo" "builtin echo" "exec rg foo" "perl -e 1" "awk 1" \
             "find . -name x" "env rg foo"; do
    printf 'match_or_fail "t" -- %s\n' "$shape" > "$bad_sh"
    got="$(scan_sites "$bad_sh")"
    check "structural scan flags a '${shape%% *}' call site" \
        "$(cause_of "$got" "match_or_fail -- ${shape%% *}")" named
done
printf 'capture_nul v "t" -- rg -l foo\n' > "$bad_sh"
got="$(scan_sites "$bad_sh")"
check "structural scan flags a matcher passed to capture_nul" \
    "$(cause_of "$got" "capture_nul -- rg")" named
printf 'match_or_fail "t" -- rg -q foo bar\nmatch_capture v "t" -- grep x y\ncapture_nul v "t" -- git ls-files -z\n' > "$bad_sh"
got="$(scan_sites "$bad_sh")"
check "structural scan passes direct allowlisted call sites" "$got" ""

if [ "$fail" -ne 0 ]; then
    echo "test-require-tool: FAILED" >&2
    exit 1
fi
echo "test-require-tool: all cases pass"
