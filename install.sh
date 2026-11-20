#!/bin/sh
# Ipê installer — detects your platform, downloads the matching release binary,
# and installs `ipe` (+ `ipe-ffi-inspector`) to a bin dir on your PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/ipe-lang/compiler/main/install.sh -o ipe-install.sh && sh ipe-install.sh
#
# Overrides:  IPE_VERSION=v0.1.0  IPE_INSTALL_DIR=$HOME/.local/bin  sh install.sh
set -eu

# The whole installer is one group with stdout on /dev/null: it talks only
# through the message helpers below, on stderr, so no command's own output
# reaches the terminal. The shell reads the group in full before running any
# of it, so a truncated download runs nothing.
{

REPO="ipe-lang/compiler"
# Set only by `ipe upgrade`'s own wrapper — see die_no_prebuilt below.
WRAPPED="${IPE_UPGRADE_WRAPPED:-0}"
TAG_FILE="${IPE_UPGRADE_TAG_FILE:-}"

# >>> message helpers
# Every installer write to the terminal goes through this block. A message is a
# single-quoted format plus values: the helpers fill each `%s` with the value
# escaped by safe_text, so an environment- or network-derived value can never
# drive or spoof the terminal. Style tokens (`@B@` bold, `@Y@` yellow, `@L@`
# light yellow, `@D@` dim, `@G@` green, `@R@` red, `@0@` reset) are expanded in
# the format only, never in a value. The install-script tests scan the rest of
# the script and refuse any other shape: a `$` in a format, a non-literal
# format, a value count that differs from the `%s` count, or a terminal write
# outside this block.

# ── Palette ──────────────────────────────────────────────────────────────────
# Mirror the CLI (style.rs): a soft Ipê-amarelo (256-colour 222) for the banner,
# a light (bright) yellow (ANSI 93) for a running stage, a soft green (114) for
# success, a plain red (31) for failure, a mid grey (244) for dim hints. Colour
# only when stderr is a terminal and NO_COLOR is unset (per https://no-color.org).
if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
  C_YELLOW="$(printf '\033[38;5;222m')"
  C_LYELLOW="$(printf '\033[93m')"
  C_DIM="$(printf '\033[38;5;244m')"
  C_GREEN="$(printf '\033[38;5;114m')"
  C_RED="$(printf '\033[31m')"
  C_BOLD="$(printf '\033[1m')"
  C_RESET="$(printf '\033[0m')"
  IS_TTY=1
else
  C_YELLOW=''; C_LYELLOW=''; C_DIM=''; C_GREEN=''; C_RED=''; C_BOLD=''; C_RESET=''
  IS_TTY=0
fi

# MSG_UTF8 is 1 when the locale (the first non-empty of LC_ALL, LC_CTYPE, LANG)
# names UTF-8, so the terminal decodes it; only then does safe_text keep a
# well-formed UTF-8 sequence raw. Otherwise every byte >= 0x80 is escaped: on a
# terminal that does not decode UTF-8, a continuation byte 0x80-0x9F is a C1
# control.
MSG_UTF8=0
for _mu_locale in "${LC_ALL:-}" "${LC_CTYPE:-}" "${LANG:-}"; do
  [ -n "$_mu_locale" ] || continue
  case "$_mu_locale" in
    *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*) MSG_UTF8=1 ;;
  esac
  break
done

# safe_text TEXT — TEXT with every character that can drive or spoof a terminal
# written as `\ooo` octal escapes of its bytes: C0 controls and DEL, the C1 set
# (U+0080-U+009F), the format characters (Cf: bidi overrides and isolates,
# zero-width characters, U+FEFF, ...) and the line/paragraph separators
# (U+2028, U+2029). A backslash prints as `\\`, so the escape is injective. A
# well-formed UTF-8 sequence for any other character prints raw when MSG_UTF8
# is 1; every other byte >= 0x80 (a malformed, overlong, surrogate or
# out-of-range sequence, or any non-ASCII byte when MSG_UTF8 is 0) is escaped
# one byte at a time, resyncing at the next byte.
#
# awk sees TEXT only as `od` byte numbers and prints only ASCII: a byte kept raw
# leaves awk as a `\0ooo` escape that `printf %b` turns back into that byte. So
# the verdict never depends on how an awk splits characters (some awks decode
# UTF-8 whatever the locale) or on what its `%c` prints for a byte >= 0x80.
safe_text() {
  printf '%b' "$(printf '%s' "$1" | od -An -v -tu1 | LC_ALL=C awk -v utf8="$MSG_UTF8" '
    function hex(s,   v, k) {
      v = 0
      for (k = 1; k <= length(s); k++) v = v * 16 + index("0123456789ABCDEF", substr(s, k, 1)) - 1
      return v
    }
    function hidden(cp,   k) {
      for (k = 1; k <= nr; k++) if (cp >= lo[k] && cp <= hi[k]) return 1
      return 0
    }
    function cont(x) { return x >= 128 && x <= 191 }
    function shown(x) { return sprintf("\\\\%03o", x) }
    BEGIN {
      # The escaped code points >= 0x80: C1 (Cc), Cf, Zl and Zp (Unicode 15.1;
      # U+2065 is the unassigned slot inside the 2060-206F format run).
      nr = split("80-9F AD 600-605 61C 6DD 70F 890-891 8E2 180E 200B-200F 2028-202E 2060-206F FEFF FFF9-FFFB 110BD 110CD 13430-1343F 1BCA0-1BCA3 1D173-1D17A E0001 E0020-E007F", r, " ")
      for (k = 1; k <= nr; k++) {
        d = index(r[k], "-")
        if (d) { lo[k] = hex(substr(r[k], 1, d - 1)); hi[k] = hex(substr(r[k], d + 1)) }
        else { lo[k] = hex(r[k]); hi[k] = lo[k] }
      }
      n = 0
    }
    { for (f = 1; f <= NF; f++) b[++n] = $f + 0 }
    END {
      out = ""; i = 1
      while (i <= n) {
        o = b[i]
        if (o < 128) {
          if (o < 32 || o == 127) out = out shown(o)
          else if (o == 92) out = out "\\\\\\\\"
          else out = out sprintf("%c", o)
          i++
          continue
        }
        len = 0; cp = 0
        if (utf8 == 1) {
          b2 = (i + 1 <= n) ? b[i + 1] : 0
          b3 = (i + 2 <= n) ? b[i + 2] : 0
          b4 = (i + 3 <= n) ? b[i + 3] : 0
          if (o >= 194 && o <= 223) {
            if (cont(b2)) { len = 2; cp = (o - 192) * 64 + b2 - 128 }
          } else if (o >= 224 && o <= 239) {
            lo2 = (o == 224) ? 160 : 128; hi2 = (o == 237) ? 159 : 191
            if (b2 >= lo2 && b2 <= hi2 && cont(b3)) {
              len = 3; cp = (o - 224) * 4096 + (b2 - 128) * 64 + b3 - 128
            }
          } else if (o >= 240 && o <= 244) {
            lo2 = (o == 240) ? 144 : 128; hi2 = (o == 244) ? 143 : 191
            if (b2 >= lo2 && b2 <= hi2 && cont(b3) && cont(b4)) {
              len = 4; cp = (o - 240) * 262144 + (b2 - 128) * 4096 + (b3 - 128) * 64 + b4 - 128
            }
          }
        }
        if (len == 0) { out = out shown(o); i++; continue }
        h = hidden(cp)
        for (k = 0; k < len; k++) {
          if (h) out = out shown(b[i + k])
          else out = out sprintf("\\0%03o", b[i + k])
        }
        i += len
      }
      printf "%s", out
    }')"
}

# msg_style FMT — set MSG_STYLED to FMT with each style token replaced by its
# palette code. Only a format passes through here, never a value.
msg_style() {
  _ms_in="$1"; MSG_STYLED=''
  while :; do
    case "$_ms_in" in
      *@?@*) ;;
      *) break ;;
    esac
    _ms_pre="${_ms_in%%@?@*}"
    _ms_rest="${_ms_in#"$_ms_pre"}"
    _ms_tail="${_ms_rest#???}"
    case "${_ms_rest%"$_ms_tail"}" in
      @B@) _ms_code="$C_BOLD" ;;
      @Y@) _ms_code="$C_YELLOW" ;;
      @L@) _ms_code="$C_LYELLOW" ;;
      @D@) _ms_code="$C_DIM" ;;
      @G@) _ms_code="$C_GREEN" ;;
      @R@) _ms_code="$C_RED" ;;
      @0@) _ms_code="$C_RESET" ;;
      *) _ms_code='@'; _ms_tail="${_ms_rest#@}" ;;
    esac
    MSG_STYLED="$MSG_STYLED$_ms_pre$_ms_code"
    _ms_in="$_ms_tail"
  done
  MSG_STYLED="$MSG_STYLED$_ms_in"
}

# render FMT [VALUE...] — print FMT (style tokens expanded) with each `%s`
# filled by the matching VALUE escaped through safe_text.
render() {
  msg_style "$1"; shift
  _rn=$#
  while [ "$_rn" -gt 0 ]; do
    set -- "$@" "$(safe_text "$1")"
    shift
    _rn=$((_rn - 1))
  done
  # shellcheck disable=SC2059  # FMT is a single-quoted literal (install_messages scan)
  printf "$MSG_STYLED" "$@"
}

# msg_text FMT [VALUE...] — set MSG_TEXT to the rendered message, trailing
# newlines included.
msg_text() {
  MSG_TEXT="$(render "$@"; printf x)"
  MSG_TEXT="${MSG_TEXT%x}"
}

# say FMT [VALUE...] — one rendered line on stderr.
say() {
  msg_text "$@"
  printf '%s\n' "$MSG_TEXT" >&2
}

# prompt FMT [VALUE...] — a rendered question on stderr, with no newline.
prompt() {
  msg_text "$@"
  printf '%s' "$MSG_TEXT" >&2
}

# ── Stage progress ───────────────────────────────────────────────────────────
# The streamlined per-stage shape shared with the CLI (src/ipe-cli/src/progress.rs):
# while a stage runs it is one line — a light-yellow spinner + label; on success
# the SAME line is rewritten (carriage return) to a light-green ✓ + message; on
# failure to a light-red ✗ + message. Off a terminal (pipe / CI / NO_COLOR) each
# stage is one plain flush-left line with no spinner, no rewrite, and no ANSI, so
# CI logs stay clean. All chatter goes to stderr so stdout stays clean.
#
# The rendered (already escaped) label of the stage currently in flight, so an
# outcome can clear a line at least as wide as it and leave no tail behind.
STAGE_LABEL=''

# stage_start FMT [VALUE...] — paint the running line (spinner frame 0 + label
# in light yellow) with no trailing newline on a terminal, so the outcome
# overwrites it.
stage_start() {
  msg_text "$@"
  STAGE_LABEL="$MSG_TEXT"
  if [ "$IS_TTY" = 1 ]; then
    printf '\r  %s⠋%s %s%s%s\033[0K' \
      "$C_LYELLOW" "$C_RESET" "$C_LYELLOW" "$STAGE_LABEL" "$C_RESET" >&2
  else
    printf '  %s\n' "$STAGE_LABEL" >&2
  fi
}

# stage_settle_ok TEXT — rewrite the running line to a light-green ✓ and the
# rendered TEXT (terminal), or emit one plain line (non-terminal).
stage_settle_ok() {
  if [ "$IS_TTY" = 1 ]; then
    printf '\r  %s✓%s %s%s%s\033[0K\n' \
      "$C_GREEN" "$C_RESET" "$C_GREEN" "$1" "$C_RESET" >&2
  else
    printf '  ✓ %s\n' "$1" >&2
  fi
  STAGE_LABEL=''
}

# stage_settle_fail TEXT — rewrite the running line to a light-red ✗ and the
# rendered TEXT (terminal), or emit one plain line (non-terminal).
stage_settle_fail() {
  if [ "$IS_TTY" = 1 ]; then
    printf '\r  %s✗%s %s%s%s\033[0K\n' \
      "$C_RED" "$C_RESET" "$C_RED" "$1" "$C_RESET" >&2
  else
    printf '  ✗ %s\n' "$1" >&2
  fi
  STAGE_LABEL=''
}

# stage_ok FMT [VALUE...] — settle the running stage as success.
stage_ok() {
  msg_text "$@"
  stage_settle_ok "$MSG_TEXT"
}

# stage_fail FMT [VALUE...] — settle the running stage as failure. Whether the
# caller then stops or continues is its own decision; this only renders.
stage_fail() {
  msg_text "$@"
  stage_settle_fail "$MSG_TEXT"
}

# stage_skip — settle a running stage as a neutral soft-skip (dim bullet, TTY
# only), with no message of its own. Use this when the caller will state the
# actual fact separately (or not at all) — it exists so a stage can be closed
# cleanly without forcing a restatement that the next line would duplicate.
stage_skip() {
  if [ -n "$STAGE_LABEL" ] && [ "$IS_TTY" = 1 ]; then
    printf '\r  %s•%s %s%s%s\033[0K\n' \
      "$C_DIM" "$C_RESET" "$C_DIM" "$STAGE_LABEL" "$C_RESET" >&2
    STAGE_LABEL=''
  fi
}

# info FMT [VALUE...] — a dimmed, deeper-indented sub-note beneath a stage (a
# soft skip, a secondary fact). Never a stage outcome itself. Settles any
# running stage first (see stage_skip) so the note lands on its own line rather
# than overwriting the spinner.
info() {
  msg_text "$@"
  stage_skip
  printf '    %s%s%s\n' "$C_DIM" "$MSG_TEXT" "$C_RESET" >&2
}

# die_settle FMT [VALUE...] — the failure line die and die_prerequisite share:
# settle any running stage as a failure carrying the message, or print it on a
# ✗ line of its own.
die_settle() {
  msg_text "$@"
  if [ -n "$STAGE_LABEL" ]; then
    stage_settle_fail "$MSG_TEXT"
  else
    printf '\n  %s✗%s %s%s%s\n' "$C_RED" "$C_RESET" "$C_RED" "$MSG_TEXT" "$C_RESET" >&2
  fi
}

# die FMT [VALUE...] — settle any running stage as a failure, then exit 1.
# Mirrors the CLI's failure shape: the actionable message rides the ✗ line.
die() {
  die_settle "$@"
  exit 1
}

# die_prerequisite FMT [VALUE...] — die for a host tool the installer needs and
# did not find, with exit 3: distinct from a failed install (1) and from no
# prebuilt binary (2, die_no_prebuilt).
die_prerequisite() {
  die_settle "$@"
  exit 3
}

# banner FMT [VALUE...] — the opening "Ipê language - <version>" line.
banner() {
  msg_text "$@"
  printf '\n  %s%sIpê language%s %s- %s%s\n\n' \
    "$C_BOLD" "$C_YELLOW" "$C_RESET" "$C_DIM" "$MSG_TEXT" "$C_RESET" >&2
}

# progress_begin — hide the cursor while the download line animates.
progress_begin() {
  printf '\033[?25l' >&2
}

# progress_end — show the cursor again and clear the progress line.
progress_end() {
  printf '\033[?25h\r\033[K' >&2
}

# spin_glyph IDX → the IDXth braille spinner frame (0-9). Selected by `case`
# rather than `cut -c`, which counts BYTES in a C locale and would slice a
# multi-byte UTF-8 frame into garbage.
spin_glyph() {
  case "$1" in
    0) printf '⠋' ;; 1) printf '⠙' ;; 2) printf '⠹' ;; 3) printf '⠸' ;;
    4) printf '⠼' ;; 5) printf '⠴' ;; 6) printf '⠦' ;; 7) printf '⠧' ;;
    8) printf '⠇' ;; *) printf '⠏' ;;
  esac
}

# render_progress IDX GOT TOTAL START — one animated line to stderr: spinner
# frame IDX, then percent, bar, sizes and ETA (or bytes and elapsed time when
# TOTAL is unknown). Every argument is a number the installer computed.
render_progress() {
  glyph="$(spin_glyph "$1")"; rp_got="$2"; rp_total="$3"; rp_start="$4"

  now="$(date +%s 2>/dev/null || echo "$rp_start")"
  elapsed=$(( now - rp_start ))
  [ "$elapsed" -lt 0 ] && elapsed=0

  bar_w=24
  if [ "$rp_total" -gt 0 ] 2>/dev/null; then
    pct=$(( rp_got * 100 / rp_total ))
    [ "$pct" -gt 100 ] && pct=100
    filled=$(( rp_got * bar_w / rp_total ))
    [ "$filled" -gt "$bar_w" ] && filled="$bar_w"
    bar=''
    i=0
    while [ "$i" -lt "$bar_w" ]; do
      if [ "$i" -lt "$filled" ]; then bar="$bar#"; else bar="$bar-"; fi
      i=$(( i + 1 ))
    done
    # ETA from the running average rate.
    eta='--:--'
    if [ "$rp_got" -gt 0 ] && [ "$elapsed" -gt 0 ]; then
      rate=$(( rp_got / elapsed ))
      if [ "$rate" -gt 0 ]; then
        remain=$(( (rp_total - rp_got) / rate ))
        [ "$remain" -lt 0 ] && remain=0
        eta="$(fmt_eta "$remain")"
      fi
    fi
    printf '\r  %s%s%s  %s%3d%%%s [%s%s%s]  %s / %s  %sETA %s%s\033[K' \
      "$C_YELLOW" "$glyph" "$C_RESET" \
      "$C_BOLD" "$pct" "$C_RESET" \
      "$C_YELLOW" "$bar" "$C_RESET" \
      "$(human "$rp_got")" "$(human "$rp_total")" \
      "$C_DIM" "$eta" "$C_RESET" >&2
  else
    # Unknown total: spinner + downloaded bytes + elapsed.
    printf '\r  %s%s%s  %s downloaded  %s%ds elapsed%s\033[K' \
      "$C_YELLOW" "$glyph" "$C_RESET" \
      "$(human "$rp_got")" \
      "$C_DIM" "$elapsed" "$C_RESET" >&2
  fi
}

# human BYTES → e.g. "1.4 MB". Integer math only (POSIX sh has no floats).
human() {
  h_b="${1:-0}"
  if [ "$h_b" -lt 1024 ] 2>/dev/null; then
    printf '%d B' "$h_b"
  elif [ "$h_b" -lt 1048576 ]; then
    printf '%d.%d KB' "$(( h_b / 1024 ))" "$(( (h_b % 1024) * 10 / 1024 ))"
  else
    printf '%d.%d MB' "$(( h_b / 1048576 ))" "$(( (h_b % 1048576) * 10 / 1048576 ))"
  fi
}

# fmt_eta SECONDS → "M:SS" (or "H:MM:SS" past an hour).
fmt_eta() {
  e_s="${1:-0}"
  if [ "$e_s" -ge 3600 ]; then
    printf '%d:%02d:%02d' "$(( e_s / 3600 ))" "$(( (e_s % 3600) / 60 ))" "$(( e_s % 60 ))"
  else
    printf '%d:%02d' "$(( e_s / 60 ))" "$(( e_s % 60 ))"
  fi
}
# <<< message helpers

# >>> input parsers
# release_tag_ok TAG — TAG is a release tag: `v` or `ipe-v`, then a digit, then
# only `[A-Za-z0-9.+-]`, at most 128 bytes (the ceiling `ipe upgrade` reads the
# tag file back with). The shell mirror of the CLI's `parse_installer_tag`
# grammar class, so a tag reaches the download URL, the messages and the tag
# file only as a plain version string.
release_tag_ok() {
  [ "${#1}" -le 128 ] || return 1
  case "$1" in
    v[0-9]*|ipe-v[0-9]*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.+-]*) return 1 ;;
  esac
  return 0
}

# require_release_tag TAG — refuse TAG unless release_tag_ok accepts it.
require_release_tag() {
  release_tag_ok "$1" || die 'The release tag %s is not a version tag (vX.Y.Z).' "$1"
}

# home_flaw DIR — set HOME_FLAW to the class of the first byte in DIR that a
# shell reads as code, or as a line break, inside the double-quoted
# `. "DIR/.ipe/env"` line the installer adds to a startup file, or to '' when
# DIR holds none: a double quote, a dollar sign, a backtick, a backslash, a
# newline, or any other C0 control byte or DEL. Spaces and non-ASCII characters stay legal
# (`/c/Users/John Doe`, an accented user name). DIR is judged as `od` byte
# numbers, so the verdict never depends on a tool's character model; a trailing
# `/` sentinel byte proves `od` read DIR to its end, so an `od` that is missing,
# fails, or prints anything but byte numbers refuses DIR rather than admitting
# it unread.
home_flaw() {
  HOME_FLAW=''
  _hf_last=''
  for _hf_byte in $(printf '%s/' "$1" | od -An -v -tu1); do
    case "$_hf_byte" in
      34) HOME_FLAW='a double quote' ;;
      36) HOME_FLAW='a dollar sign' ;;
      96) HOME_FLAW='a backtick' ;;
      92) HOME_FLAW='a backslash' ;;
      10) HOME_FLAW='a newline' ;;
      [0-9]|1[0-9]|2[0-9]|3[01]|127) HOME_FLAW='a control character' ;;
      *[!0123456789]*) HOME_FLAW='a byte the installer could not read' ;;
    esac
    [ -z "$HOME_FLAW" ] || return 0
    _hf_last="$_hf_byte"
  done
  [ "$_hf_last" = 47 ] || HOME_FLAW='a byte the installer could not read'
}

# parse_home DIR — set USER_HOME to DIR, the home directory every later path
# and every line the installer writes for a shell derives from; die when DIR is
# empty, relative, or home_flaw finds a flaw in it. A relative DIR would make
# the line added to a startup file source a file relative to whatever directory
# a shell starts in.
parse_home() {
  [ -n "$1" ] || die 'HOME is not set. Set it to your home directory and try again.'
  case "$1" in
    /*) ;;
    *) die 'Refusing HOME %s: it is not an absolute path, so the line the installer adds to your startup file would source a file relative to whatever directory a shell starts in. Set HOME to the absolute path of your home directory and try again.' "$1" ;;
  esac
  home_flaw "$1"
  [ -z "$HOME_FLAW" ] \
    || die 'Refusing HOME %s: it contains %s, which a shell would run as code from the line the installer adds to your startup file. Set HOME to a plain directory path and try again.' "$1" "$HOME_FLAW"
  USER_HOME="$1"
}

# fish_literal TEXT — set FISH_LITERAL to TEXT as one fish single-quoted
# literal. Inside fish single quotes a backslash escapes a backslash or a
# single quote, so each of those is written backslash-escaped; every other
# character is literal.
fish_literal() {
  _fl_in="$1"; _fl_out=''
  while [ -n "$_fl_in" ]; do
    _fl_tail="${_fl_in#?}"
    _fl_char="${_fl_in%"$_fl_tail"}"
    case "$_fl_char" in
      \\|\') _fl_out="$_fl_out\\$_fl_char" ;;
      *) _fl_out="$_fl_out$_fl_char" ;;
    esac
    _fl_in="$_fl_tail"
  done
  FISH_LITERAL="'$_fl_out'"
}
# <<< input parsers

# >>> private-scratch helpers
# A scratch path handed to another writer (`curl -o`, the tag file `ipe upgrade`
# reads back) is safe only while no other user can replace any component of it.
# So scratch lives only in a directory made by `mktemp -d` under a verified base
# and re-checked after creation: a real directory (not a symlink), owned by us,
# no group/other bits. Windows shells (MSYS/Cygwin) only emulate POSIX owners
# and modes, so there only the type checks apply.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) SCRATCH_POSIX_MODES=0 ;;
  *) SCRATCH_POSIX_MODES=1 ;;
esac

# scratch_private_verdict MODE OWNER ME PATTERN — an entry with `ls -l` mode
# string MODE and owner uid OWNER is private to uid ME when OWNER is ME and MODE
# matches PATTERN.
scratch_private_verdict() {
  [ -n "$1" ] && [ -n "$3" ] && [ "$2" = "$3" ] || return 1
  # shellcheck disable=SC2254  # PATTERN is a deliberate case pattern
  case "$1" in $4) return 0 ;; esac
  return 1
}

# scratch_entry_private PATH PATTERN — PATH is owned by the effective uid and
# its `ls -l` mode string matches PATTERN.
scratch_entry_private() {
  _sp_ls="$(ls -ldn -- "$1" 2>/dev/null)" || return 1
  read -r _sp_mode _sp_links _sp_uid _sp_rest <<SCRATCH_LS
$_sp_ls
SCRATCH_LS
  scratch_private_verdict "$_sp_mode" "$_sp_uid" "$(id -u)" "$2"
}

# scratch_base_reason MODE OWNER GROUP ME MYGID — the rule an entry with `ls -l`
# mode string MODE, owner uid OWNER and group gid GROUP breaks as a trusted base
# component for uid ME (primary gid MYGID), as one token; `ok` when it is
# trusted. Callers accept only `ok`, so empty or unexpected output (a failed
# subshell included) refuses. Trusted: a directory owned by ME or root,
# writable by no one else unless sticky. Group-writable is allowed only for
# ME's own directory in group MYGID with no ACL, the user-private-group layout.
scratch_base_reason() {
  [ -n "$4" ] || { echo unknown-identity; return 0; }
  case "$1" in
    '') echo empty-mode; return 0 ;;
    l*) echo symlink; return 0 ;;
    d*) ;;
    *) echo not-a-dir; return 0 ;;
  esac
  [ "$2" = "$4" ] || [ "$2" = 0 ] || { echo foreign-owner; return 0; }
  case "$1" in d????????[tT]*) echo ok; return 0 ;; esac
  case "$1" in d???????w*) echo world-writable-not-sticky; return 0 ;; esac
  case "$1" in
    # An ACL (`+`) can grant a named user write through the group mask.
    d????w*+) echo acl ;;
    d????w*)
      if [ "$2" = "$4" ] && [ -n "$5" ] && [ "$3" = "$5" ]; then echo ok
      else echo group-writable
      fi
      ;;
    *) echo ok ;;
  esac
  return 0
}

# scratch_base_verdict MODE OWNER GROUP ME MYGID — scratch_base_reason prints
# exactly `ok`.
scratch_base_verdict() {
  [ "$(scratch_base_reason "$@")" = ok ]
}


# scratch_base_entry_reason DIR ME MYGID — set TMP_REFUSED_REASON to the
# scratch_base_reason token for DIR (`ok` when trusted, `unreadable` when `ls`
# cannot describe it), and TMP_REFUSED_OWNER / TMP_REFUSED_MODE to the facts it
# was judged on.
scratch_base_entry_reason() {
  TMP_REFUSED_OWNER=''; TMP_REFUSED_MODE=''; TMP_REFUSED_REASON=unreadable
  _be_ls="$(ls -ldn -- "$1" 2>/dev/null)" || return 0
  read -r _be_mode _be_links _be_uid _be_gid _be_rest <<SCRATCH_LS
$_be_ls
SCRATCH_LS
  TMP_REFUSED_OWNER="$_be_uid"; TMP_REFUSED_MODE="$_be_mode"
  TMP_REFUSED_REASON="$(scratch_base_reason "$_be_mode" "$_be_uid" "$_be_gid" "$2" "$3")"
}

# trusted_tmp_base BASE — print BASE's physical (symlink-free) path and set
# TMP_TRUSTED_BASE to it when it and every ancestor pass scratch_base_reason;
# fail otherwise, recording the refused component in TMP_REFUSED_PATH,
# TMP_REFUSED_OWNER, TMP_REFUSED_MODE and TMP_REFUSED_REASON. Call it in the
# current shell (not `$(...)`) to read those variables back.
trusted_tmp_base() {
  TMP_TRUSTED_BASE=''; TMP_REFUSED_PATH="$1"; TMP_REFUSED_OWNER=''
  TMP_REFUSED_MODE=''; TMP_REFUSED_REASON=unresolvable
  _tb_dir="$(cd -P -- "$1" 2>/dev/null && pwd -P)" || return 1
  [ -n "$_tb_dir" ] || return 1
  if [ "$SCRATCH_POSIX_MODES" = 1 ]; then
    _tb_me="$(id -u)"; _tb_grp="$(id -g)"; _tb_walk="$_tb_dir"; _tb_left=256
    while :; do
      TMP_REFUSED_PATH="$_tb_walk"
      scratch_base_entry_reason "$_tb_walk" "$_tb_me" "$_tb_grp"
      [ "$TMP_REFUSED_REASON" = ok ] || return 1
      case "$_tb_walk" in /|//) break ;; esac
      _tb_left=$((_tb_left - 1))
      [ "$_tb_left" -gt 0 ] || {
        TMP_REFUSED_OWNER=''; TMP_REFUSED_MODE=''; TMP_REFUSED_REASON=too-deep
        return 1
      }
      _tb_walk="$(dirname -- "$_tb_walk")"
    done
  fi
  TMP_REFUSED_PATH=''; TMP_REFUSED_OWNER=''; TMP_REFUSED_MODE=''
  TMP_REFUSED_REASON=''; TMP_TRUSTED_BASE="$_tb_dir"
  printf '%s\n' "$_tb_dir"
}

# die_tmp_base_refused — refuse the last trusted_tmp_base verdict: the refused
# path, its owner and mode, the broken rule, and the remedy.
die_tmp_base_refused() {
  _tr_token="$TMP_REFUSED_REASON"
  case "$TMP_REFUSED_REASON" in
    unknown-identity) _tr_rule='your user id could not be determined' ;;
    empty-mode) _tr_rule='its permissions could not be read' ;;
    unreadable) _tr_rule='it could not be listed' ;;
    unresolvable) _tr_rule='it does not exist or cannot be entered' ;;
    too-deep) _tr_rule='it is nested too deep to verify' ;;
    symlink) _tr_rule='it is a symbolic link' ;;
    not-a-dir) _tr_rule='it is not a directory' ;;
    foreign-owner) _tr_rule='it is owned by another user (neither you nor root)' ;;
    world-writable-not-sticky) _tr_rule='anyone can write to it and it lacks the sticky bit' ;;
    acl) _tr_rule='it is group-writable and carries an ACL that can grant other users write' ;;
    group-writable) _tr_rule='it is writable by a group other than your own private group' ;;
    *) _tr_rule='it failed the private-scratch check'; _tr_token=unknown ;;
  esac
  _tr_note=''
  case "$TMP_REFUSED_OWNER" in
    65534|nobody)
      _tr_note=' Owner uid 65534 (nobody) usually means a uid unmapped in this container or user namespace.'
      ;;
  esac
  die 'Refusing the temp directory %s: %s (owner uid %s, mode %s): %s [%s].%s Set TMPDIR to a directory you own with mode 700.' \
    "${TMPDIR:-/tmp}" "$TMP_REFUSED_PATH" "${TMP_REFUSED_OWNER:-unknown}" \
    "${TMP_REFUSED_MODE:-unknown}" "$_tr_rule" "$_tr_token" "$_tr_note"
}


# private_dir_ok DIR — DIR is a real directory owned by us with mode 0700 bits.
private_dir_ok() {
  [ -d "$1" ] && [ ! -L "$1" ] || return 1
  [ "$SCRATCH_POSIX_MODES" = 1 ] || return 0
  scratch_entry_private "$1" 'd???------*'
}

# tag_file_ok FILE — FILE is a regular file (not a symlink) we own with no
# group/other bits, inside a private directory whose ancestors are trusted.
tag_file_ok() {
  [ -f "$1" ] && [ ! -L "$1" ] || return 1
  _tf_dir="$(dirname -- "$1")"
  private_dir_ok "$_tf_dir" || return 1
  trusted_tmp_base "$(dirname -- "$_tf_dir")" >/dev/null || return 1
  [ "$SCRATCH_POSIX_MODES" = 1 ] || return 0
  scratch_entry_private "$1" '-???------*'
}
# <<< private-scratch helpers

# >>> prerequisite commands
# The command that installs each host prerequisite, per OS family: one
# `KIND:FAMILY)` row per pair. The CLI's own prerequisite table is checked
# against these rows.
PREREQ_FAMILIES='debian fedora arch alpine suse macos freebsd'

# prereq_command KIND FAMILY — set PREREQ_CMD to the command that installs KIND
# (`c-toolchain` or `curl`) on FAMILY, or '' when there is no row.
prereq_command() {
  case "$1:$2" in
    c-toolchain:debian) PREREQ_CMD='sudo apt install build-essential' ;;
    c-toolchain:fedora) PREREQ_CMD='sudo dnf install gcc' ;;
    c-toolchain:arch) PREREQ_CMD='sudo pacman -S --needed base-devel' ;;
    c-toolchain:alpine) PREREQ_CMD='sudo apk add build-base' ;;
    c-toolchain:suse) PREREQ_CMD='sudo zypper install gcc' ;;
    c-toolchain:macos) PREREQ_CMD='xcode-select --install' ;;
    c-toolchain:freebsd) PREREQ_CMD='cc ships in the FreeBSD base system' ;;
    curl:debian) PREREQ_CMD='sudo apt install curl' ;;
    curl:fedora) PREREQ_CMD='sudo dnf install curl' ;;
    curl:arch) PREREQ_CMD='sudo pacman -S --needed curl' ;;
    curl:alpine) PREREQ_CMD='sudo apk add curl' ;;
    curl:suse) PREREQ_CMD='sudo zypper install curl' ;;
    curl:macos) PREREQ_CMD='brew install curl' ;;
    curl:freebsd) PREREQ_CMD='sudo pkg install curl' ;;
    *) PREREQ_CMD='' ;;
  esac
}

# os_family FILE — set OS_FAMILY from the os-release FILE: the family of the
# first word of `ID`, then of `ID_LIKE`, that names one, else `unknown`. At most
# 64 lines are read.
os_family() {
  OS_FAMILY=unknown; _of_id=''; _of_like=''; _of_n=0; _of_line=''
  [ -f "$1" ] && [ -r "$1" ] || return 0
  while IFS= read -r _of_line || [ -n "$_of_line" ]; do
    _of_n=$((_of_n + 1))
    [ "$_of_n" -le 64 ] || break
    case "$_of_line" in
      ID=*) _of_id="${_of_line#ID=}" ;;
      ID_LIKE=*) _of_like="${_of_line#ID_LIKE=}" ;;
    esac
    _of_line=''
  done <"$1"
  # Every byte but a lowercase letter, a digit and `._-` becomes a blank, so the
  # unquoted split below sees plain words and no glob character.
  _of_words="$(printf '%s %s' "$_of_id" "$_of_like" \
    | LC_ALL=C sed 's/[^abcdefghijklmnopqrstuvwxyz0123456789._-]/ /g')" || _of_words=''
  for _of_word in $_of_words; do
    case "$_of_word" in
      debian|ubuntu|linuxmint|pop|raspbian|elementary|zorin|kali|neon) OS_FAMILY=debian ;;
      fedora|rhel|centos|rocky|almalinux|ol|amzn) OS_FAMILY=fedora ;;
      arch|manjaro|endeavouros|artix|garuda) OS_FAMILY=arch ;;
      alpine|postmarketos) OS_FAMILY=alpine ;;
      suse|opensuse|opensuse-leap|opensuse-tumbleweed|sles|sled) OS_FAMILY=suse ;;
      *) ;;
    esac
    [ "$OS_FAMILY" = unknown ] || return 0
  done
}

# prereq_remedy KIND — print the command that installs KIND on OS_FAMILY, or
# every family's row when the family is unknown.
prereq_remedy() {
  if [ "$OS_FAMILY" != unknown ]; then
    prereq_command "$1" "$OS_FAMILY"
    say '        @D@%s@0@' "$PREREQ_CMD"
    return 0
  fi
  for _pr_family in $PREREQ_FAMILIES; do
    prereq_command "$1" "$_pr_family"
    say '        %s: @D@%s@0@' "$_pr_family" "$PREREQ_CMD"
  done
}
# <<< prerequisite commands

# >>> fetch helpers
# Every network request the installer makes goes through fetch_to or fetch_ok,
# and every fetcher they run gives the same guarantees: HTTPS only, redirects
# included; TLS 1.2 or later; certificate verification that no user config or
# environment can turn off; failure on an HTTP error; a time ceiling; and a
# size ceiling checked before the body is used. curl comes first, then GNU
# Wget, then FreeBSD fetch; any other wget is refused.
FETCHER=''
RUSTUP_CMD=''
FETCH_AUTH=0
FETCH_TOTAL=0
WGET_CODE=''
WGET_LOCATION=''
# The bytes a fetched URL may hold, spelled out so no locale widens a range.
FETCH_URL_CHARS='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~:/?#@!*+,;=%&-'
# The most redirects a GNU Wget fetch follows.
FETCH_MAX_HOPS=5
# The size ceiling of the release archive, in bytes (256 MiB).
ARCHIVE_MAX_BYTES=268435456

# fetch_url_ok URL — URL starts `https://`, is at most 2048 bytes, and holds
# only FETCH_URL_CHARS.
fetch_url_ok() {
  [ "${#1}" -le 2048 ] || return 1
  case "$1" in
    https://?*) ;;
    *) return 1 ;;
  esac
  # shellcheck disable=SC2254  # FETCH_URL_CHARS is a deliberate bracket set
  case "$1" in
    *[!$FETCH_URL_CHARS]*) return 1 ;;
  esac
}

# fetch_resolve — set FETCHER to the first fetcher on this host that gives
# every guarantee, and write GNU Wget's private config; refuse the host when no
# fetcher does.
fetch_resolve() {
  FETCHER=''; _fr_other_wget=0
  if command -v curl >/dev/null 2>&1; then
    FETCHER=curl
  elif command -v wget >/dev/null 2>&1; then
    _fr_version="$(wget --version 2>/dev/null | head -n 1)" || _fr_version=''
    case "$_fr_version" in
      'GNU Wget '*) FETCHER=wget ;;
      *) _fr_other_wget=1 ;;
    esac
  fi
  if [ -z "$FETCHER" ] && [ "$plat" = freebsd ] && command -v fetch >/dev/null 2>&1; then
    FETCHER=fetch
  fi
  if [ -z "$FETCHER" ]; then
    if [ "$_fr_other_wget" = 1 ]; then
      die_other_wget
    fi
    die_no_fetcher
  fi
  # The rustup bootstrap, spelled for this fetcher, for the user to run.
  case "$FETCHER" in
    curl) RUSTUP_CMD="curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" ;;
    wget) RUSTUP_CMD='wget --https-only --secure-protocol=TLSv1_2 -qO- https://sh.rustup.rs | sh' ;;
    *) RUSTUP_CMD='fetch -qo - https://sh.rustup.rs | sh' ;;
  esac
  if [ "$FETCHER" = wget ]; then
    # Replaces every system and user wgetrc for each GNU Wget run.
    printf 'check_certificate = on\nnetrc = off\n' >"$tmp/wgetrc" \
      || die 'Could not write %s.' "$tmp/wgetrc"
  fi
}

# die_no_fetcher — refuse a host with no fetcher, naming the install command.
die_no_fetcher() {
  say '\n    The installer downloads over HTTPS with curl or GNU Wget and found neither.'
  say '    Install curl, then run the installer again:'
  prereq_remedy curl
  die_prerequisite 'Missing prerequisite: curl or wget [prerequisite fetcher].'
}

# die_other_wget — refuse a wget that is not GNU Wget (such as BusyBox wget):
# the installer runs only fetchers whose certificate verification it can hold on.
die_other_wget() {
  say '\n    The installer downloads with curl or GNU Wget, each run with certificate verification held on.'
  say '    The wget on this host is another implementation (such as BusyBox wget). Install curl, then run the installer again:'
  prereq_remedy curl
  case "$OS_FAMILY" in
    alpine|unknown) ;;
    *) say '        alpine: @D@%s@0@' "apk add curl" ;;
  esac
  die_prerequisite 'Missing prerequisite: curl or GNU Wget [prerequisite fetcher].'
}

# fetch_auth_setup — when GITHUB_TOKEN or GH_TOKEN holds a token, write it to a
# private file the fetcher reads it from, never its arguments, and set
# FETCH_AUTH to 1. FreeBSD fetch sends no custom header, so it resolves the
# release anonymously; so does a value with a byte no GitHub token holds.
fetch_auth_setup() {
  FETCH_AUTH=0
  _fa_token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
  [ -n "$_fa_token" ] || return 0
  [ "$FETCHER" != fetch ] || return 0
  case "$_fa_token" in
    *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-]*)
      info 'The GitHub token in the environment is not a token; resolving the release anonymously.'
      return 0
      ;;
  esac
  if [ "${#_fa_token}" -gt 1024 ]; then
    info 'The GitHub token in the environment is not a token; resolving the release anonymously.'
    return 0
  fi
  if [ "$FETCHER" = curl ]; then
    ( umask 077 && printf 'Authorization: Bearer %s\n' "$_fa_token" >"$tmp/auth.header" ) \
      || die 'Could not write %s.' "$tmp/auth.header"
  else
    ( umask 077 \
      && printf 'check_certificate = on\nnetrc = off\nheader = Authorization: Bearer %s\n' \
        "$_fa_token" >"$tmp/auth.wgetrc" ) \
      || die 'Could not write %s.' "$tmp/auth.wgetrc"
  fi
  FETCH_AUTH=1
}

# fetch_to FILE URL MAX_BYTES MAX_SECS [auth] — write URL's body to FILE. Fails
# when URL is refused by fetch_url_ok, the fetch fails, or the body exceeds
# MAX_BYTES. `auth` sends the token fetch_auth_setup prepared, if any. MAX_SECS
# bounds a curl transfer; GNU Wget and fetch stop on a stalled read.
fetch_to() {
  _ft_file="$1"; _ft_url="$2"; _ft_max="$3"; _ft_secs="$4"; _ft_auth="${5:-}"
  [ "$FETCH_AUTH" = 1 ] || _ft_auth=''
  fetch_url_ok "$_ft_url" || return 1
  case "$FETCHER" in
    curl)
      if [ "$_ft_auth" = auth ]; then
        curl -q --proto =https --proto-redir =https --tlsv1.2 -fsSL \
          --connect-timeout 15 --max-time "$_ft_secs" --max-filesize "$_ft_max" \
          -H @"$tmp/auth.header" -o "$_ft_file" "$_ft_url" 2>/dev/null || return 1
      else
        curl -q --proto =https --proto-redir =https --tlsv1.2 -fsSL \
          --connect-timeout 15 --max-time "$_ft_secs" --max-filesize "$_ft_max" \
          -o "$_ft_file" "$_ft_url" 2>/dev/null || return 1
      fi
      ;;
    wget) wget_walk "$_ft_file" "$_ft_url" "$_ft_auth" || return 1 ;;
    fetch)
      ( unset SSL_NO_VERIFY_PEER SSL_NO_VERIFY_HOSTNAME SSL_CA_CERT_FILE SSL_CA_CERT_PATH
        fetch -q -T 30 -o "$_ft_file" "$_ft_url" 2>/dev/null ) || return 1
      ;;
    *) return 1 ;;
  esac
  fetch_size_ok "$_ft_file" "$_ft_max"
}

# fetch_size_ok FILE MAX_BYTES — FILE exists and holds at most MAX_BYTES bytes;
# an oversized FILE is removed.
fetch_size_ok() {
  [ -f "$1" ] || return 1
  _fs_got="$(wc -c <"$1" | tr -d ' ')" || return 1
  case "$_fs_got" in
    ''|*[!0123456789]*) return 1 ;;
  esac
  if [ "$_fs_got" -gt "$2" ]; then
    rm -f "$1"
    info 'The server sent %s bytes, over the %s-byte ceiling for that file.' "$_fs_got" "$2"
    return 1
  fi
}

# fetch_ok URL — URL answers with a success status.
fetch_ok() {
  fetch_url_ok "$1" || return 1
  case "$FETCHER" in
    curl)
      curl -q --proto =https --proto-redir =https --tlsv1.2 -fsSL \
        --connect-timeout 15 --max-time 15 -I -o /dev/null "$1" 2>/dev/null
      ;;
    wget) wget_walk '' "$1" '' ;;
    fetch)
      ( unset SSL_NO_VERIFY_PEER SSL_NO_VERIFY_HOSTNAME SSL_CA_CERT_FILE SSL_CA_CERT_PATH
        fetch -q -T 30 -s "$1" >/dev/null 2>&1 )
      ;;
    *) return 1 ;;
  esac
}

# fetch_total URL — set FETCH_TOTAL to URL's size from a one-byte range
# request, or 0 when unknown. curl only: the progress bar runs under curl.
fetch_total() {
  FETCH_TOTAL=0
  [ "$FETCHER" = curl ] || return 0
  fetch_url_ok "$1" || return 0
  _fl_head="$(curl -q --proto =https --proto-redir =https --tlsv1.2 -fsSL \
    --connect-timeout 15 --max-time 30 -r 0-0 -D - -o /dev/null "$1" 2>/dev/null)" \
    || _fl_head=''
  [ -n "$_fl_head" ] || return 0
  FETCH_TOTAL="$(printf '%s\n' "$_fl_head" \
    | tr -d '\r' \
    | sed -n 's#^[Cc]ontent-[Rr]ange: *bytes [0-9]*-[0-9]*/\([0-9][0-9]*\).*#\1#p' \
    | tail -n 1)" || FETCH_TOTAL=0
  case "$FETCH_TOTAL" in
    ''|*[!0123456789]*) FETCH_TOTAL=0 ;;
  esac
  [ "${#FETCH_TOTAL}" -le 12 ] || FETCH_TOTAL=0
}

# wget_walk FILE URL [auth] — fetch URL with GNU Wget into FILE, or probe it
# when FILE is empty, following at most FETCH_MAX_HOPS redirects by hand: each
# hop's Location must pass fetch_url_ok, so a redirect never leaves HTTPS.
wget_walk() {
  _ww_file="$1"; _ww_url="$2"; _ww_hops=0
  _ww_config="$tmp/wgetrc"
  if [ "${3:-}" = auth ]; then
    _ww_config="$tmp/auth.wgetrc"
  fi
  while :; do
    fetch_url_ok "$_ww_url" || return 1
    _ww_status=0
    if [ -n "$_ww_file" ]; then
      wget --config="$_ww_config" --https-only --secure-protocol=TLSv1_2 --timeout=15 \
        --tries=1 --max-redirect=0 --server-response -q -O "$_ww_file" "$_ww_url" \
        2>"$tmp/wget.log" || _ww_status=$?
    else
      wget --config="$_ww_config" --https-only --secure-protocol=TLSv1_2 --timeout=15 \
        --tries=1 --max-redirect=0 --server-response -q --spider "$_ww_url" \
        2>"$tmp/wget.log" || _ww_status=$?
    fi
    [ "$_ww_status" != 0 ] || return 0
    # GNU Wget exits 8 on any server error response, a redirect it may not
    # follow included.
    [ "$_ww_status" = 8 ] || return 1
    wget_redirect "$tmp/wget.log" || return 1
    _ww_hops=$((_ww_hops + 1))
    [ "$_ww_hops" -le "$FETCH_MAX_HOPS" ] || return 1
    _ww_url="$WGET_LOCATION"
  done
}

# wget_redirect LOG — set WGET_LOCATION to the target of the last response in
# GNU Wget's --server-response LOG; fail unless that response is a redirect
# (301, 302, 303, 307 or 308) whose Location starts `https://`.
wget_redirect() {
  WGET_CODE=''; WGET_LOCATION=''; _wr_n=0; _wr_line=''
  while IFS= read -r _wr_line || [ -n "$_wr_line" ]; do
    _wr_n=$((_wr_n + 1))
    [ "$_wr_n" -le 256 ] || return 1
    case "$_wr_line" in
      '  HTTP/'*)
        _wr_rest="${_wr_line#*HTTP/}"
        _wr_rest="${_wr_rest#*[ ]}"
        WGET_CODE="${_wr_rest%%[ ]*}"
        WGET_LOCATION=''
        ;;
      '  '[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:*)
        # One blank follows the colon; any other spacing leaves the target
        # empty, which is refused below.
        _wr_rest="${_wr_line#*:}"
        _wr_rest="${_wr_rest# }"
        WGET_LOCATION="${_wr_rest%%[ ]*}"
        ;;
    esac
    _wr_line=''
  done <"$1"
  case "$WGET_CODE" in
    301|302|303|307|308) ;;
    *) return 1 ;;
  esac
  case "$WGET_LOCATION" in
    https://?*) ;;
    *) return 1 ;;
  esac
}
# <<< fetch helpers

# ── Checksum helpers ─────────────────────────────────────────────────────────
SHA256_TOOL=''
SHA256_GOT=''
SUMS_WANT=''
SUMS_FAULT=''

# sha256_resolve — set SHA256_TOOL to the first SHA-256 tool on this host;
# refuse the host when it has none, since every download is verified.
sha256_resolve() {
  SHA256_TOOL=''
  for _sr_tool in sha256sum shasum sha256 openssl; do
    if command -v "$_sr_tool" >/dev/null 2>&1; then
      SHA256_TOOL="$_sr_tool"
      return 0
    fi
  done
  die_no_sha256
}

# die_no_sha256 — refuse a host with no SHA-256 tool, naming the tools.
die_no_sha256() {
  say '\n    The installer verifies every download against the release SHA256SUMS and found no SHA-256 tool.'
  say '    Install one of sha256sum (coreutils), shasum, sha256 or openssl, then run the installer again.'
  die_prerequisite 'Missing prerequisite: a SHA-256 tool [prerequisite sha256].'
}

# hex_digest_ok TEXT — TEXT is exactly 64 lowercase hex digits.
hex_digest_ok() {
  [ "${#1}" -eq 64 ] || return 1
  case "$1" in
    *[!0123456789abcdef]*) return 1 ;;
  esac
}

# sha256_of FILE — set SHA256_GOT to FILE's SHA-256 digest, computed by
# SHA256_TOOL; fail unless the tool printed one well-formed digest.
sha256_of() {
  SHA256_GOT=''
  case "$SHA256_TOOL" in
    sha256sum) _so_out="$(sha256sum "$1" 2>/dev/null)" || return 1 ;;
    shasum) _so_out="$(shasum -a 256 "$1" 2>/dev/null)" || return 1 ;;
    sha256) _so_out="$(sha256 -q "$1" 2>/dev/null)" || return 1 ;;
    openssl) _so_out="$(openssl dgst -sha256 -r "$1" 2>/dev/null)" || return 1 ;;
    *) return 1 ;;
  esac
  _so_out="${_so_out%%[ ]*}"
  hex_digest_ok "$_so_out" || return 1
  SHA256_GOT="$_so_out"
}

# sums_entry FILE NAME — set SUMS_WANT to the digest the SHA256SUMS FILE lists
# for exactly NAME, a `<digest>  NAME` or `<digest> *NAME` line. SUMS_FAULT is
# '' on one well-formed entry, `missing` on none, and `malformed` on a bad
# digest, a second entry, or a list over 4096 lines.
sums_entry() {
  SUMS_WANT=''; SUMS_FAULT=missing; _se_n=0; _se_line=''
  [ -f "$1" ] || return 0
  while IFS= read -r _se_line || [ -n "$_se_line" ]; do
    _se_n=$((_se_n + 1))
    if [ "$_se_n" -gt 4096 ]; then
      SUMS_FAULT=malformed
      return 0
    fi
    _se_hex="${_se_line%%[ ]*}"
    _se_rest="${_se_line#"$_se_hex"}"
    _se_line=''
    case "$_se_rest" in
      "  $2"|" *$2") ;;
      *) continue ;;
    esac
    if [ -n "$SUMS_WANT" ] || ! hex_digest_ok "$_se_hex"; then
      SUMS_FAULT=malformed
      return 0
    fi
    SUMS_WANT="$_se_hex"
    SUMS_FAULT=''
  done <"$1"
}

# ── The closing "Before your first build" block ──────────────────────────────
# before_first_build — name each build prerequisite this host lacks, with the
# command that installs it, and the curl the other `ipe` commands download
# with when the installer ran without it. Advisory: ipe is already installed.
before_first_build() {
  if [ "$cargo_ok" = 1 ] && [ "$cc_ok" = 1 ] && [ "$FETCHER" = curl ]; then
    return 0
  fi
  say '\n  @B@Before your first build@0@'
  if [ "$cargo_ok" != 1 ]; then
    if [ "$plat" = windows ]; then
      say '    Install Rust %s or later with the installer from @D@%s@0@' "$MIN_CARGO_VERSION" "$rustup_url"
    elif [ "$cargo_old" = 1 ]; then
      say '    Update Rust to %s or later:' "$MIN_CARGO_VERSION"
      say '        @D@%s@0@' "rustup update"
    else
      say '    Install Rust %s or later with rustup:' "$MIN_CARGO_VERSION"
      say '        @D@%s@0@' "$RUSTUP_CMD"
    fi
  fi
  if [ "$cc_ok" != 1 ]; then
    say '    Install a C toolchain, which Rust links through:'
    prereq_remedy c-toolchain
  fi
  if [ "$FETCHER" != curl ]; then
    say '    ipe upgrade, ipe login and ipe publish download with curl. Install it:'
    prereq_remedy curl
  fi
}

# die_no_prebuilt TAG PLAT CPU — exits 2, a distinct code the `ipe upgrade`
# wrapper uses to show the "still being generated" message instead of generic
# failure text. Exit 2 (not 1) signals "no prebuilt binary" specifically.
#
# IPE_UPGRADE_WRAPPED=1 marks a run launched BY `ipe upgrade` (never set by a
# direct run of the installer): that wrapper renders its own single failure message
# using the real resolved tag, so this function skips its own stderr banner
# and instead writes the tag into the private file the wrapper named in
# IPE_UPGRADE_TAG_FILE — only when tag_file_ok verifies it is a private file in
# a private directory. Without such a file (or when the write fails) the banner
# below is shown as for a direct run.
die_no_prebuilt() {
  _tag="$1"; _plat="$2"; _cpu="$3"
  if [ "$WRAPPED" = 1 ] && [ -n "$TAG_FILE" ] && tag_file_ok "$TAG_FILE" \
    && printf '%s\n' "$_tag" 2>/dev/null >"$TAG_FILE"; then
    exit 2
  fi
  say '\n  @B@@R@@0@ No prebuilt binary for %s on %s-%s.' "$_tag" "$_plat" "$_cpu"
  say '      Possibly the binaries for that version are still being generated.'
  say '      If you prefer, build from source:'
  say '          cargo install --git https://github.com/%s ipe' "$REPO"
  exit 2
}

# ── Gate every local input once, at the boundary ─────────────────────────────
# Each environment input is parsed here, before the first network request, so
# every later use (URLs, env files, the tag file, messages) sees a checked value.
#
# HOME is read here and nowhere else: every later path and every line written
# for a shell to source derives from USER_HOME, the value parse_home accepted.
parse_home "${HOME:-}"
INSTALL_DIR="${IPE_INSTALL_DIR:-$USER_HOME/.local/bin}"
#
# INSTALL_DIR ends up written verbatim into the ~/.ipe env files, which the
# user's shell later sources (executes). Parse, don't validate: reject any path
# carrying shell metacharacters here, ONCE, so every downstream sink can treat
# it as a safe literal. Only ordinary path characters are allowed; a quote,
# backtick, `$`, or whitespace could inject shell code into a sourced file, so we
# refuse rather than try to quote it perfectly at each use. Backslash and the
# drive-letter colon ARE allowed — Windows paths (`D:\...`) need them, and both
# are inert inside the single-quoted `export PATH='…'` the env file emits (the
# fish file escapes each backslash, see fish_literal). The class is spelled out
# byte by byte, so no locale's collation can widen a range. The directory must
# also be absolute (`/…` or a drive letter): a relative PATH entry would make
# every later shell look commands up relative to its working directory.
case "$INSTALL_DIR" in
  '') die 'The install directory is empty.' ;;
  *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/+@:\\-]*)
    die 'The install directory %s holds a character the installer will not write into a shell startup file: only letters, digits, backslash and . _ / + @ : - are allowed. Set IPE_INSTALL_DIR to a directory path made of those and try again.' "$INSTALL_DIR" ;;
  /*|[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz]:[\\/]*) ;;
  *) die 'The install directory %s is not an absolute path. Set IPE_INSTALL_DIR to an absolute directory path and try again.' "$INSTALL_DIR" ;;
esac
fish_literal "$INSTALL_DIR"
INSTALL_DIR_FISH="$FISH_LITERAL"
# A requested release tag becomes a download URL path segment and the tag file
# `ipe upgrade` reads back, so it must be a plain version tag.
if [ -n "${IPE_VERSION:-}" ]; then
  require_release_tag "$IPE_VERSION"
fi
# The scratch base: TMPDIR and every ancestor must be trusted (see the
# private-scratch helpers); the scratch directory itself is re-checked after
# `mktemp -d` creates it.
trusted_tmp_base "${TMPDIR:-/tmp}" >/dev/null || die_tmp_base_refused
scratch_base="$TMP_TRUSTED_BASE"

# ── Detect platform → the release artifact name ──────────────────────────────
os="$(uname -s)"; arch="$(uname -m)"
case "$os" in
  Linux)   plat=linux ;;
  Darwin)  plat=darwin ;;
  FreeBSD) plat=freebsd ;;
  MINGW*|MSYS*|CYGWIN*) plat=windows ;;
  *) die 'Unsupported OS: %s' "$os" ;;
esac
case "$arch" in
  x86_64|amd64) cpu=x64 ;;
  arm64|aarch64) cpu=arm64 ;;
  *) die 'Unsupported architecture: %s' "$arch" ;;
esac

# Published matrix (see .github/workflows/release.yml). Reject combos we don't ship.
case "$plat-$cpu" in
  linux-x64|linux-arm64|darwin-x64|darwin-arm64|freebsd-x64|windows-x64) : ;;
  *) die 'No prebuilt binary for %s-%s — build from source: https://github.com/%s' "$plat" "$cpu" "$REPO" ;;
esac
artifact="ipe-$plat-$cpu"
[ "$plat" = windows ] && ext=zip || ext=tar.gz

# ── The OS family, for the commands that install a missing prerequisite ──────
case "$plat" in
  darwin) OS_FAMILY=macos ;;
  freebsd) OS_FAMILY=freebsd ;;
  linux) os_family /etc/os-release ;;
  *) OS_FAMILY=unknown ;;
esac

# ── The private scratch directory, before any download ───────────────────────
tmp="$(mktemp -d "$scratch_base/ipe-install.XXXXXX")" \
  || die 'Could not create a private temp directory under %s.' "$scratch_base"
trap 'rm -rf "$tmp"' EXIT
private_dir_ok "$tmp" || die 'The temp directory %s is not private to you.' "$tmp"
pkg="$tmp/pkg.$ext"

if [ -n "${IPE_VERSION:-}" ]; then
  banner '%s' "$IPE_VERSION"
else
  banner 'latest'
fi

# ── Host prerequisites the install itself needs ──────────────────────────────
fetch_resolve
sha256_resolve
# A GitHub token in the environment authenticates the release lookup, so a
# shared CI runner is not held to the anonymous API's per-IP rate limit.
fetch_auth_setup

# gh_latest_release — set tag to the latest release's tag; fail when the API
# cannot be reached or its answer names no tag.
gh_latest_release() {
  fetch_to "$tmp/latest.json" "https://api.github.com/repos/$REPO/releases/latest" \
    1048576 30 auth || return 1
  tag="$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$tmp/latest.json" | head -n 1)" \
    || return 1
  [ -n "$tag" ]
}

# ── Resolve version (default: latest release tag) ────────────────────────────
if [ -n "${IPE_VERSION:-}" ]; then
  tag="$IPE_VERSION"
else
  stage_start 'Resolving the latest release…'
  gh_latest_release \
    || die 'Could not resolve the latest release from GitHub (set IPE_VERSION=vX.Y.Z).'
  require_release_tag "$tag"
  stage_ok 'Found %s.' "$tag"
fi

# Display version: the release tag may carry an `ipe-` prefix (e.g. ipe-v0.1.2).
# Strip it for the human-facing "vX.Y.Z" while keeping $tag for URLs.
ver="${tag#ipe-}"

base="https://github.com/$REPO/releases/download/$tag"
url="$base/$artifact.$ext"

# ── Check prebuilt binary availability ──────────────────────────────
stage_start 'Checking for prebuilt binaries…'
have_bin=0
if fetch_ok "$url"; then
  have_bin=1
  stage_ok 'Prebuilt binary available for %s-%s.' "$plat" "$cpu"
else
  # Settle the stage without restating the fact here — the fact is stated
  # exactly once, either by the retry prompt just below or by die_no_prebuilt
  # at the final gate.
  stage_skip
  if [ -n "${IPE_VERSION:-}" ] && [ "$IS_TTY" = 1 ] && [ -r /dev/tty ]; then
    say '\n    @B@No prebuilt ipe %s binary for %s-%s.@0@' "$ver" "$plat" "$cpu"
    prompt '    Install the @B@latest@0@ release instead? [Y/n] '
    ans=''
    if IFS= read -r ans < /dev/tty 2>/dev/null; then
      case "$ans" in
        ''|[Yy]|[Yy][Ee][Ss])
          stage_start 'Resolving the latest release…'
          gh_latest_release || die 'Could not resolve the latest release from GitHub.'
          require_release_tag "$tag"
          ver="${tag#ipe-}"
          base="https://github.com/$REPO/releases/download/$tag"
          url="$base/$artifact.$ext"
          if fetch_ok "$url"; then
            have_bin=1
            stage_ok 'Prebuilt binary available for %s-%s.' "$plat" "$cpu"
          else
            info 'Latest release also has no binary for %s-%s.' "$plat" "$cpu"
          fi
          ;;
      esac
    fi
  fi
fi

# ── Minimum Rust version (for building from source) ─────────────────
# Kept in sync with the workspace Cargo.toml: edition = "2024" requires
# Rust >= 1.85 (stable since 2025-02-20).
MIN_CARGO_VERSION="1.85.0"

# version_gte MAJ MIN PATCH MAJ MIN PATCH — true when A >= B.
version_gte() {
  a1="$1"; a2="$2"; a3="$3"
  b1="$4"; b2="$5"; b3="$6"
  [ "$a1" -gt "$b1" ] && return 0
  [ "$a1" -lt "$b1" ] && return 1
  [ "$a2" -gt "$b2" ] && return 0
  [ "$a2" -lt "$b2" ] && return 1
  [ "$a3" -ge "$b3" ]
}

# ── Check Rust toolchain ────────────────────────────────────────────
# Rust is a build prerequisite, not an install one: it is installed only on
# the user's consent at a terminal, and otherwise named in the closing
# "Before your first build" block.
stage_start 'Checking Rust toolchain…'
cargo_ok=0
cargo_old=0
rustup_url="https://win.rustup.rs/x86_64"
if command -v cargo >/dev/null 2>&1; then
  cargo_ver_raw="$(cargo version 2>/dev/null | cut -d' ' -f2)"
  cargo_ver="${cargo_ver_raw%%-*}"
  cargo_major="$(printf '%s\n' "$cargo_ver" | cut -d. -f1)"
  cargo_minor="$(printf '%s\n' "$cargo_ver" | cut -d. -f2)"
  cargo_patch="$(printf '%s\n' "$cargo_ver" | cut -d. -f3)"
  cargo_patch="${cargo_patch:-0}"
  min_major="$(printf '%s\n' "$MIN_CARGO_VERSION" | cut -d. -f1)"
  min_minor="$(printf '%s\n' "$MIN_CARGO_VERSION" | cut -d. -f2)"
  min_patch="$(printf '%s\n' "$MIN_CARGO_VERSION" | cut -d. -f3)"
  if version_gte "$cargo_major" "$cargo_minor" "$cargo_patch" \
                  "$min_major" "$min_minor" "$min_patch"; then
    cargo_ok=1
    stage_ok 'Found cargo %s (>= %s).' "$cargo_ver_raw" "$MIN_CARGO_VERSION"
  else
    cargo_old=1
    info 'Found cargo %s (< required %s).' "$cargo_ver_raw" "$MIN_CARGO_VERSION"
  fi
else
  info 'Rust is not installed.'
  if [ -f "$USER_HOME/.cargo/env" ] && [ "$IS_TTY" = 1 ] && [ -r /dev/tty ]; then
    say '\n    @B@Rust seems installed but not on your @0@PATH@B@.@0@'
    prompt '    Source @B@~/.cargo/env@0@ now? [Y/n] '
    ans=''
    if IFS= read -r ans < /dev/tty 2>/dev/null; then
      case "$ans" in
        ''|[Yy]|[Yy][Ee][Ss])
          # shellcheck source=/dev/null
          . "$USER_HOME/.cargo/env"
          if command -v cargo >/dev/null 2>&1; then
            cargo_ok=1
            stage_ok 'Rust now available (%s).' "$(cargo version | cut -d' ' -f2)"
          fi
          ;;
      esac
    fi
  fi
  if [ "$cargo_ok" != 1 ] && [ "$IS_TTY" = 1 ] && [ -r /dev/tty ]; then
    say '\n    @B@Rust is not installed.@0@'
    case "$plat" in
      linux|darwin|freebsd)
        prompt '    Install Rust via @B@rustup@0@? [Y/n] '
        ;;
      windows)
        say '    Download the Rust installer from:\n      @D@%s@0@' "$rustup_url"
        prompt '    Open the link and run the installer? [Y/n] '
        ;;
    esac
    ans=''
    if IFS= read -r ans < /dev/tty 2>/dev/null; then
      case "$ans" in
        ''|[Yy]|[Yy][Ee][Ss])
          case "$plat" in
            linux|darwin|freebsd)
              stage_start 'Installing Rust via rustup…'
              # rustup-init is fetched whole before it runs, so a failed fetch
              # is a failed install; `-y` answers rustup-init's own prompt.
              if fetch_to "$tmp/rustup-init.sh" https://sh.rustup.rs 1048576 60 \
                && sh "$tmp/rustup-init.sh" -y 2>/dev/null; then
                if [ -f "$USER_HOME/.cargo/env" ]; then
                  # shellcheck source=/dev/null
                  . "$USER_HOME/.cargo/env"
                fi
                if command -v cargo >/dev/null 2>&1; then
                  cargo_ok=1
                  info 'Rust installed (%s).' "$(cargo version | cut -d' ' -f2)"
                fi
              else
                info 'rustup exited non-zero — check https://rustup.rs for manual install.'
              fi
              ;;
            windows)
              info 'Download the installer from: %s' "$rustup_url"
              ;;
          esac
          ;;
      esac
    fi
  fi
fi

# ── Check the C toolchain Rust links through (advisory) ──────────────────────
# macOS always has the /usr/bin/cc shim, so the Command Line Tools are asked
# for directly. Windows links through the MSVC tools, which `ipe` itself checks.
cc_ok=1
case "$plat" in
  darwin) xcode-select -p >/dev/null 2>&1 || cc_ok=0 ;;
  windows) ;;
  *) command -v cc >/dev/null 2>&1 || cc_ok=0 ;;
esac

# ── Bail out when no binary is available ────────────────────────────
if [ "$have_bin" != 1 ]; then
  die_no_prebuilt "$tag" "$plat" "$cpu"
fi

# ── Download the binary with a friendly progress display ─────────────────────
stage_start 'Downloading ipe %s for %s-%s…' "$ver" "$plat" "$cpu"

# download_with_progress URL DEST
# Under curl on a TTY, download in the background writing to DEST, and animate
# a spinner + percent + bar + size + ETA by polling DEST's on-disk size against
# the known total. Otherwise download quietly and print one plain line — no
# ANSI, no animation.
download_with_progress() {
  dl_url="$1"; dl_dest="$2"

  if [ "$IS_TTY" != 1 ] || [ "$FETCHER" != curl ]; then
    fetch_to "$dl_dest" "$dl_url" "$ARCHIVE_MAX_BYTES" 900 \
      || die 'Download failed: %s' "$dl_url"
    got="$(wc -c < "$dl_dest" 2>/dev/null || echo 0)"
    stage_ok 'Downloaded %s.' "$(human "$got")"
    return 0
  fi

  # Total size (best-effort; 0 ⇒ unknown, bar degrades to a byte counter).
  fetch_total "$dl_url"
  total="$FETCH_TOTAL"

  # The download runs in its own subshell so `set -e` can't trip on the
  # spinner loop; poll DEST size for the animation. Pre-create DEST so the
  # poller's `< DEST` never hits a not-yet-opened file mid-race.
  : > "$dl_dest"
  ( dl_rc=0; fetch_to "$dl_dest" "$dl_url" "$ARCHIVE_MAX_BYTES" 900 || dl_rc=$?; echo "$dl_rc" > "$tmp/curl.rc" ) &
  dl_pid=$!

  si=0
  start="$(date +%s 2>/dev/null || echo 0)"
  progress_begin

  while kill -0 "$dl_pid" 2>/dev/null; do
    got="$(wc -c < "$dl_dest" 2>/dev/null || echo 0)"
    render_progress "$si" "$got" "$total" "$start"
    si=$(( (si + 1) % 10 ))
    sleep 0.1 2>/dev/null || sleep 1
  done
  wait "$dl_pid" 2>/dev/null || true

  progress_end

  rc="$(cat "$tmp/curl.rc" 2>/dev/null || echo 1)"
  [ "$rc" = 0 ] || die 'Download failed: %s' "$dl_url"

  got="$(wc -c < "$dl_dest" 2>/dev/null || echo 0)"
  stage_ok 'Downloaded %s.' "$(human "$got")"
}

download_with_progress "$url" "$pkg"

# ── Verify the checksum ──────────────────────────────────────────────────────
# Every install is verified against the release's SHA256SUMS: a list that
# cannot be fetched, holds no entry for the artifact, or holds a malformed one
# stops the install before anything is extracted.
stage_start 'Verifying the download…'
fetch_to "$tmp/SHA256SUMS" "$base/SHA256SUMS" 65536 60 \
  || die 'Could not fetch %s, so the download cannot be verified [checksum-unavailable].' "$base/SHA256SUMS"
sums_entry "$tmp/SHA256SUMS" "$artifact.$ext"
case "$SUMS_FAULT" in
  '') ;;
  missing) die 'The release SHA256SUMS lists no checksum for %s, so the download cannot be verified [checksum-entry-missing].' "$artifact.$ext" ;;
  *) die 'The release SHA256SUMS entry for %s is not one 64-digit SHA-256 checksum [checksum-entry-malformed].' "$artifact.$ext" ;;
esac
sha256_of "$pkg" || die 'Could not compute the SHA-256 checksum of the download.'
if [ "$SHA256_GOT" = "$SUMS_WANT" ]; then
  stage_ok 'Checksum verified.'
else
  die 'Checksum mismatch for %s — refusing to install (expected %s, got %s).' "$artifact.$ext" "$SUMS_WANT" "$SHA256_GOT"
fi

# ── Extract + install ────────────────────────────────────────────────────────
stage_start 'Installing to %s…' "$INSTALL_DIR"
if [ "$ext" = zip ]; then
  # `unzip` isn't guaranteed (e.g. Git Bash on Windows); bsdtar (`tar`) reads
  # zips on Windows and macOS, so fall back to it.
  if command -v unzip >/dev/null 2>&1; then
    unzip -q "$pkg" -d "$tmp" || die 'Could not unzip the download.'
  else
    tar -xf "$pkg" -C "$tmp" || die 'Could not extract the download.'
  fi
else
  tar xzf "$pkg" -C "$tmp" || die 'Could not extract the download.'
fi
mkdir -p "$INSTALL_DIR"
installed=0
for b in ipe ipe-ffi-inspector; do
  [ "$plat" = windows ] && b="$b.exe"
  if [ -f "$tmp/$b" ]; then
    install -m 0755 "$tmp/$b" "$INSTALL_DIR/$b" 2>/dev/null \
      || { cp "$tmp/$b" "$INSTALL_DIR/$b"; chmod +x "$INSTALL_DIR/$b"; }
    installed=$(( installed + 1 ))
  fi
done
[ "$installed" -gt 0 ] || die 'The archive contained no ipe binaries.'
stage_ok 'Installed ipe %s to %s/ipe' "$ver" "$INSTALL_DIR"

# ── PATH setup ────────────────────────────────────────────────────────────────
# ipe is installed, but a bin dir is only useful once it is on PATH. We make
# that painless without ever silently editing a shell file. Following rustup, we
# own a managed env file under ~/.ipe (env for POSIX shells, env.fish for fish)
# that exports INSTALL_DIR onto PATH, and we add ONE attributable line to the
# login shell's rc that sources it. The user sees the exact file and line, and
# consents on the real terminal (/dev/tty — never the piped installer on stdin)
# before we touch a dotfile. Because the PATH mechanics live in our own file, a
# future update or uninstall rewrites or removes it cleanly, and the rc keeps a
# single stable `. "$HOME/.ipe/env"` line.

IPE_HOME="$USER_HOME/.ipe"
ENV_POSIX="$IPE_HOME/env"
ENV_FISH="$IPE_HOME/env.fish"

# on_path — succeed when INSTALL_DIR is already a PATH entry.
on_path() {
  case ":${PATH:-}:" in
    *":$INSTALL_DIR:"*) return 0 ;;
    *) return 1 ;;
  esac
}

# canonical_home — USER_HOME with any symlinks and `..` resolved to a physical path,
# computed once. The prefix test below compares physical paths, so a link whose
# textual target begins with "$USER_HOME/" but resolves elsewhere cannot slip past.
canonical_home="$(cd -P "$USER_HOME" 2>/dev/null && pwd -P)" || canonical_home="$USER_HOME"

# refuse_symlink_escape PATH — die if PATH is a symlink whose target resolves
# outside USER_HOME. A managed env file or dotfile must stay within the user's home;
# we never follow a link that would let us write elsewhere. The whole symlink
# chain and every `..` are resolved (readlink -f where available, else a
# physical-cd fallback) before the comparison, so a relative `../` target or a
# multi-hop chain cannot escape.
refuse_symlink_escape() {
  rse_path="$1"
  [ -L "$rse_path" ] || return 0

  # Resolve the link fully. readlink -f follows the chain and normalizes `..`;
  # the fallback resolves the parent physically and appends the basename, which
  # collapses a `..` that would otherwise escape.
  rse_real="$(readlink -f "$rse_path" 2>/dev/null || true)"
  if [ -z "$rse_real" ]; then
    rse_dir="$(dirname "$rse_path")"
    rse_base="$(basename "$rse_path")"
    rse_pdir="$(cd -P "$rse_dir" 2>/dev/null && pwd -P)" || rse_pdir="$rse_dir"
    rse_real="$rse_pdir/$rse_base"
  fi

  case "$rse_real/" in
    "$canonical_home"/*) return 0 ;;
    *) die '%s is a symlink pointing outside your home directory — refusing to edit it.' "$rse_path" ;;
  esac
}

# resolve_shell_rc — set SH_NAME and RC_FILE (the login shell's startup file),
# RC_SOURCE_LINE (the one line we append to rc to source our env file), and
# PATH_NOW / SOURCE_NOW (the two commands the user can run in the current shell
# to activate PATH immediately — put ipe on PATH directly, or source the edited
# rc's env file).
resolve_shell_rc() {
  SH_NAME="$(basename "${SHELL:-sh}")"
  case "$SH_NAME" in
    zsh)  RC_FILE="${ZDOTDIR:-$USER_HOME}/.zshrc" ;;
    bash)
      # Prefer an existing file; else .bash_profile on macOS (login shells),
      # .bashrc elsewhere.
      if   [ -f "$USER_HOME/.bashrc" ];       then RC_FILE="$USER_HOME/.bashrc"
      elif [ -f "$USER_HOME/.bash_profile" ]; then RC_FILE="$USER_HOME/.bash_profile"
      elif [ "$plat" = darwin ];         then RC_FILE="$USER_HOME/.bash_profile"
      else RC_FILE="$USER_HOME/.bashrc"; fi
      ;;
    fish) RC_FILE="${XDG_CONFIG_HOME:-$USER_HOME/.config}/fish/config.fish" ;;
    ksh)  RC_FILE="$USER_HOME/.kshrc" ;;
    *)    RC_FILE="$USER_HOME/.profile" ;;
  esac
  if [ "$SH_NAME" = fish ]; then
    RC_SOURCE_LINE="source \"$ENV_FISH\""
    PATH_NOW="fish_add_path $INSTALL_DIR_FISH"
    SOURCE_NOW="source \"$ENV_FISH\""
  else
    RC_SOURCE_LINE=". \"$ENV_POSIX\""
    # shellcheck disable=SC2016  # $PATH must stay literal so it expands per-shell
    PATH_NOW="export PATH='$INSTALL_DIR':\"\$PATH\""
    SOURCE_NOW=". \"$ENV_POSIX\""
  fi
}

# write_env_files — (re)write our managed env files with the current PATH line.
# These are entirely ours, so overwriting them on every run keeps them correct
# after a move or version change. POSIX and fish both get one, so a user who
# switches shells still has the right file to source.
# write_managed FILE CONTENT — write CONTENT to FILE by rendering to a fresh
# exclusively-created (`mktemp`) temp file inside the validated $IPE_HOME and `mv`-ing it into place. `mv`
# replaces a symlink at FILE rather than following it, so a final-component
# symlink swapped in after our check cannot redirect the write outside USER_HOME
# (closing the check-then-write TOCTOU that a plain `>` redirect leaves open).
write_managed() {
  wm_dest="$1"; wm_body="$2"
  wm_tmp="$(mktemp "$IPE_HOME/.env.XXXXXX")" || die 'Could not write %s.' "$wm_dest"
  printf '%s' "$wm_body" > "$wm_tmp" || die 'Could not write %s.' "$wm_dest"
  mv -f "$wm_tmp" "$wm_dest" || { rm -f "$wm_tmp"; die 'Could not write %s.' "$wm_dest"; }
}

write_env_files() {
  refuse_symlink_escape "$IPE_HOME"
  mkdir -p "$IPE_HOME" 2>/dev/null || die 'Could not create %s.' "$IPE_HOME"
  refuse_symlink_escape "$ENV_POSIX"
  refuse_symlink_escape "$ENV_FISH"
  # INSTALL_DIR is gated to path characters at the boundary, so single-quoting
  # it here yields an inert literal even though the file is later sourced; the
  # fish file takes INSTALL_DIR_FISH, whose backslashes fish_literal escaped.
  # shellcheck disable=SC2016  # $PATH must stay literal for per-shell expansion
  write_env_files_posix="# Managed by the Ipê installer — puts ipe on your PATH.
case \":\${PATH}:\" in *':$INSTALL_DIR:'*) ;; *) export PATH='$INSTALL_DIR':\"\$PATH\" ;; esac
"
  write_env_files_fish="# Managed by the Ipê installer — puts ipe on your PATH.
if not contains $INSTALL_DIR_FISH \$PATH
    fish_add_path $INSTALL_DIR_FISH
end
"
  write_managed "$ENV_POSIX" "$write_env_files_posix"
  write_managed "$ENV_FISH" "$write_env_files_fish"
}

# activation_hint — the two commands to activate PATH in the CURRENT shell: run
# ipe onto PATH directly, or source the env file the edited rc now loads.
activation_hint() {
  say '    To use @B@ipe@0@ right now, run:'
  say '        @D@%s@0@' "$PATH_NOW"
  say '    or reload the updated startup file with:'
  say '        @D@%s@0@\n' "$SOURCE_NOW"
}

# manual_path_hint — the do-it-yourself fallback when we did not edit the rc:
# source our env file (already written) from the shell's startup file yourself.
manual_path_hint() {
  say '    Add ipe to your PATH by putting this line in @Y@%s@0@:' "$RC_FILE"
  say '        @D@%s@0@\n' "$RC_SOURCE_LINE"
}

# persist_path — put INSTALL_DIR on PATH for good: write our managed env files,
# then append one attributable line to the login shell's rc that sources the
# right one, after showing the exact file + line and getting a yes on the real
# terminal. Idempotent (never double-adds), consented (never silent), and
# attributable (under a fixed marker). A non-interactive run prints the manual
# hint instead of editing anything.
persist_path() {
  resolve_shell_rc
  write_env_files

  # Already sourcing our env file from the rc — nothing to add.
  if [ -f "$RC_FILE" ] && grep -Fq "$RC_SOURCE_LINE" "$RC_FILE" 2>/dev/null; then
    stage_ok 'ipe is on your PATH (via %s).' "$RC_FILE"
    return 0
  fi

  # No terminal to ask on (piped into a non-interactive shell, CI): never edit a
  # file unasked — print the manual hint and stop.
  if [ "$IS_TTY" != 1 ] || [ ! -r /dev/tty ]; then
    manual_path_hint
    return 0
  fi

  say '\n  @B@%s is not on your PATH yet.@0@' "$INSTALL_DIR"
  say '    Add it to @Y@%s@0@ so every shell finds @B@ipe@0@?' "$RC_FILE"
  say '        @D@%s@0@' "$RC_SOURCE_LINE"
  prompt '    Update it now? [Y/n] '

  # A successful read of an empty line (bare ENTER) means yes; a failed read
  # (closed tty / EOF) is NOT consent — default to leaving the file untouched.
  ans=''
  if ! IFS= read -r ans < /dev/tty; then
    ans=n
  fi
  case "$ans" in
    ''|[Yy]|[Yy][Ee][Ss])
      mkdir -p "$(dirname "$RC_FILE")" 2>/dev/null || true
      refuse_symlink_escape "$RC_FILE"
      { printf '\n# Added by the Ipê installer\n'
        printf '%s\n' "$RC_SOURCE_LINE"
      } >> "$RC_FILE" || die 'Could not write to %s.' "$RC_FILE"
      stage_ok 'Added ipe to your PATH (via %s).' "$RC_FILE"
      activation_hint
      ;;
    *)
      info 'Left %s untouched.' "$RC_FILE"
      manual_path_hint
      ;;
  esac
}

# ── Done + next steps ────────────────────────────────────────────────────────
if ! on_path; then
  # Put INSTALL_DIR on PATH for this run (live immediately when the installer is
  # sourced), then persist it for future shells.
  export PATH="$INSTALL_DIR:$PATH"
  persist_path
fi

# Success banner: the green word carries the good news; the footer mirrors the
# CLI's "report bugs" line (kept in sync with the style SSOT by a drift test).
say '\n  Ipê %s was @G@successfully@0@ installed!' "$ver"
before_first_build
say '\n  If you find any bugs, please report them at https://github.com/%s/issues.\n' "$REPO"
} >/dev/null
