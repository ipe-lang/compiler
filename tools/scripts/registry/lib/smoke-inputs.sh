# shellcheck shell=bash
# Typed inputs for the live-registry publish smoke (`publish-smoke.sh`).
#
# Every operator value the smoke pastes into interpreted text (an Ipê string
# literal, a git askpass helper, an API or clone URL) is parsed here ONCE, at the
# script boundary, into a shape that carries no quote, `$`, backtick, `&`, `\`,
# `@`, whitespace, or control byte. A parser prints the accepted value on stdout;
# a refusal prints `[smoke][input] <INPUT>: …` on stderr, prints nothing on
# stdout, and exits 2. Character classes are spelled out in full so the verdict
# never depends on the locale's collation of a range.
#
# Sourced, never executed. Defines no state beyond the reserved defaults below.

# The reserved disposable package names the smoke publishes when the operator
# names none. `ipe package publish` re-parses either through `PackageName::parse`.
# shellcheck disable=SC2034  # read by the sourcing script and its tests
PROBE_DEFAULT_NAME="ipe-registry-smoke-probe"
# shellcheck disable=SC2034
PROBE_DEFAULT_BAD_NAME="ipe-registry-smoke-probe-bad"

_SMOKE_LOWER='abcdefghijklmnopqrstuvwxyz'
_SMOKE_UPPER='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
_SMOKE_DIGIT='0123456789'

# Refuse input $1 (its name) holding value $2, for reason $3; exits 2.
smoke_refuse() {
  printf '[smoke][input] %s: refused %q — %s\n' "$1" "$2" "$3" >&2
  exit 2
}

# Package name: a lowercase letter, then lowercase alphanumerics or single `-`,
# ending alphanumeric, 2..64 bytes. Usage: parse_package_name <INPUT> <value>.
parse_package_name() {
  local re="^[${_SMOKE_LOWER}][${_SMOKE_LOWER}${_SMOKE_DIGIT}-]{0,62}[${_SMOKE_LOWER}${_SMOKE_DIGIT}]\$"
  if ! [[ $2 =~ $re ]] || [[ $2 == *--* ]]; then
    smoke_refuse "$1" "$2" "expected a package name [a-z][a-z0-9-]{0,62}[a-z0-9] with no doubled '-'"
  fi
  printf '%s\n' "$2"
}

# A probe version: `0.0.0-smoke.<stamp>.<run>.<attempt>` (or `-smokebad.`), where
# <stamp> is a 14-digit UTC `%Y%m%d%H%M%S`, <run>.<attempt> the run tag. The run
# tag keeps two runs started in the same second apart, and semver orders the
# stamp first, so every new version still exceeds every earlier one.
# Usage: parse_probe_version <INPUT> <value>.
parse_probe_version() {
  local d="${_SMOKE_DIGIT}"
  local re="^0\\.0\\.0-smoke(bad)?\\.[123456789][${d}]{13}\\.[123456789][${d}]{0,18}\\.(0|[123456789][${d}]{0,4})\$"
  [[ $2 =~ $re ]] \
    || smoke_refuse "$1" "$2" "expected 0.0.0-smoke[bad].<14-digit UTC stamp>.<run>.<attempt>"
  printf '%s\n' "$2"
}

# The run tag `<run>.<attempt>`: a run id (decimal, no leading zero, 1..19
# digits) and an attempt (decimal 0..99999, no leading zero).
# Usage: parse_run_tag <run-id> <attempt>.
parse_run_tag() {
  local d="${_SMOKE_DIGIT}"
  local run_re="^[123456789][${d}]{0,18}\$"
  local attempt_re="^(0|[123456789][${d}]{0,4})\$"
  [[ $1 =~ $run_re ]] \
    || smoke_refuse GITHUB_RUN_ID "$1" "expected a decimal run id with no leading zero"
  [[ $2 =~ $attempt_re ]] \
    || smoke_refuse GITHUB_RUN_ATTEMPT "$2" "expected a decimal attempt with no leading zero"
  printf '%s.%s\n' "$1" "$2"
}

# Assemble and parse one probe version. Usage:
# probe_version <smoke|smokebad> <14-digit stamp> <run tag>.
probe_version() {
  case "$1" in
    smoke | smokebad) ;;
    *) smoke_refuse "probe kind" "$1" "expected smoke or smokebad" ;;
  esac
  parse_probe_version "probe version" "0.0.0-$1.$2.$3"
}

# GitHub owner (user or org): alphanumerics and single inner `-`, 1..39 bytes.
# Usage: parse_gh_owner <INPUT> <value>.
parse_gh_owner() {
  local an="${_SMOKE_LOWER}${_SMOKE_UPPER}${_SMOKE_DIGIT}"
  local re="^[${an}]([${an}-]{0,37}[${an}])?\$"
  [[ $2 =~ $re ]] \
    || smoke_refuse "$1" "$2" "expected a GitHub owner [A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
  printf '%s\n' "$2"
}

# `<owner>/<repo>` slug; the repo is [A-Za-z0-9._-]{1,100}, never `.` or `..`.
# Usage: parse_repo_slug <INPUT> <value>.
parse_repo_slug() {
  local owner="${2%%/*}" repo="${2#*/}"
  local re="^[${_SMOKE_LOWER}${_SMOKE_UPPER}${_SMOKE_DIGIT}._-]{1,100}\$"
  [[ $2 == */* ]] \
    || smoke_refuse "$1" "$2" "expected <owner>/<repo>"
  (parse_gh_owner "$1" "$owner" >/dev/null) \
    || smoke_refuse "$1" "$2" "the owner part is not a GitHub owner"
  if ! [[ $repo =~ $re ]] || [[ $repo == . ]] || [[ $repo == .. ]]; then
    smoke_refuse "$1" "$2" "expected a repo name [A-Za-z0-9._-]{1,100}, never . or .."
  fi
  printf '%s\n' "$2"
}

# An https URL of host and plain path segments; the trailing `/` is dropped so
# `<url>/<path>` joins never double it. Usage: parse_https_url <INPUT> <value>.
parse_https_url() {
  local an="${_SMOKE_LOWER}${_SMOKE_UPPER}${_SMOKE_DIGIT}"
  local re="^https://[${an}.-]+(/[${an}._~-]+)*/?\$"
  [[ $2 =~ $re ]] \
    || smoke_refuse "$1" "$2" "expected https://<host>[/<path>] of [A-Za-z0-9._~-] segments"
  printf '%s\n' "${2%/}"
}

# Poll budget in seconds: decimal 1..86400. `0` is refused, never a default.
# Usage: parse_poll_secs <INPUT> <value>.
parse_poll_secs() {
  local re="^[123456789][${_SMOKE_DIGIT}]{0,4}\$"
  if ! [[ $2 =~ $re ]] || (( 10#$2 > 86400 )); then
    smoke_refuse "$1" "$2" "expected whole seconds in 1..86400"
  fi
  printf '%s\n' "$2"
}

# Render a probe manifest template to stdout. The template must carry `@name@`
# and `@version@` exactly once each; both values are parsed first, and no `@` may
# survive substitution. A refusal prints nothing on stdout and exits 2.
# Usage: render_probe_manifest <template> <name> <version>.
render_probe_manifest() {
  local tmpl="$1" name version text token stripped count
  name="$(parse_package_name "probe name" "$2")" || exit 2
  version="$(parse_probe_version "probe version" "$3")" || exit 2
  if ! [ -f "$tmpl" ] || ! [ -r "$tmpl" ]; then
    smoke_refuse "probe template" "$tmpl" "not a readable file"
  fi
  text="$(<"$tmpl")"
  for token in @name@ @version@; do
    stripped="${text//"$token"/}"
    count=$(( (${#text} - ${#stripped}) / ${#token} ))
    [ "$count" -eq 1 ] \
      || smoke_refuse "probe template" "$tmpl" "token $token appears $count times, expected exactly 1"
  done
  text="${text//@name@/"$name"}"
  text="${text//@version@/"$version"}"
  [[ $text != *@* ]] \
    || smoke_refuse "probe template" "$tmpl" "an unknown @token@ is left after substitution"
  printf '%s\n' "$text"
}

# Write the git askpass helper to path $1 (mode 0700). Its text is fixed: the
# user name and the token are read from the helper's own environment
# (IPE_SMOKE_ASKPASS_USER, IPE_SMOKE_TOKEN) when git runs it, so no value is ever
# spliced into the generated code.
write_askpass() {
  cat >"$1" <<'ASKPASS'
#!/usr/bin/env bash
case "${1:-}" in
  *Username*) printf '%s' "${IPE_SMOKE_ASKPASS_USER:-}" ;;
  *Password*) printf '%s' "${IPE_SMOKE_TOKEN:-}" ;;
esac
ASKPASS
  chmod 700 "$1"
}
