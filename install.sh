#!/bin/sh
# Ipê installer — detects your platform, downloads the matching release binary,
# and installs `ipe` (+ `ipe-ffi-inspector`) to a bin dir on your PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/ipe-lang/compiler/main/install.sh | sh
#
# Overrides:  IPE_VERSION=v0.1.0  IPE_INSTALL_DIR=$HOME/.local/bin  sh install.sh
set -eu

# The whole installer is one group with stdout on /dev/null: it talks only
# through the message helpers below, on stderr, so no command's own output
# reaches the terminal. The shell reads the group in full before running any
# of it, so a truncated download runs nothing.
{

REPO="ipe-lang/compiler"
INSTALL_DIR="${IPE_INSTALL_DIR:-$HOME/.local/bin}"
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
# `curl … | sh` logs stay clean. All chatter goes to stderr so stdout stays clean.
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

# die FMT [VALUE...] — settle any running stage as a failure, then exit
# non-zero. Mirrors the CLI's failure shape: the actionable message rides the ✗
# line.
die() {
  msg_text "$@"
  if [ -n "$STAGE_LABEL" ]; then
    stage_settle_fail "$MSG_TEXT"
  else
    printf '\n  %s✗%s %s%s%s\n' "$C_RED" "$C_RESET" "$C_RED" "$MSG_TEXT" "$C_RESET" >&2
  fi
  exit 1
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

# die_no_prebuilt TAG PLAT CPU — exits 2, a distinct code the `ipe upgrade`
# wrapper uses to show the "still being generated" message instead of generic
# failure text. Exit 2 (not 1) signals "no prebuilt binary" specifically.
#
# IPE_UPGRADE_WRAPPED=1 marks a run launched BY `ipe upgrade` (never set by a
# direct `curl | sh`): that wrapper renders its own single failure message
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
# INSTALL_DIR ends up written verbatim into the ~/.ipe env files, which the
# user's shell later sources (executes). Parse, don't validate: reject any path
# carrying shell metacharacters here, ONCE, so every downstream sink can treat
# it as a safe literal. Only ordinary path characters are allowed; a quote,
# backtick, `$`, or whitespace could inject shell code into a sourced file, so we
# refuse rather than try to quote it perfectly at each use. Backslash and the
# drive-letter colon ARE allowed — Windows paths (`D:\...`) need them, and both
# are inert inside the single-quoted `export PATH='…'` the env file emits.
case "$INSTALL_DIR" in
  *[!A-Za-z0-9._/+@:\\-]*)
    die 'The install directory contains unsupported characters: %s' "$INSTALL_DIR" ;;
  '') die 'The install directory is empty.' ;;
esac
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

# Fetch the GitHub "latest release" JSON. When a token is present in the
# environment (GITHUB_TOKEN / GH_TOKEN) the request is authenticated, so shared
# CI runners are not rate-limited — the anonymous API allows only 60 req/hr/IP
# and a busy runner IP hits 403. A real user without a token uses the generous
# per-IP anonymous limit unchanged.
gh_latest_release() {
  _tok="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
  if [ -n "$_tok" ]; then
    curl -fsSL -H "Authorization: Bearer $_tok" "https://api.github.com/repos/$REPO/releases/latest"
  else
    curl -fsSL "https://api.github.com/repos/$REPO/releases/latest"
  fi
}

# ── Resolve version (default: latest release tag) ────────────────────────────
# Fetch the whole API response into a variable FIRST, then parse it. Piping curl
# straight into `grep -m1`/`head` makes the reader close the pipe early, curl
# hits EPIPE mid-write, and you get `curl: (23) Failed writing body`. Capturing
# the body in full sidesteps SIGPIPE entirely.
if [ -n "${IPE_VERSION:-}" ]; then
  tag="$IPE_VERSION"
  banner '%s' "$tag"
else
  banner 'latest'
  stage_start 'Resolving the latest release…'
  resp="$(gh_latest_release)" \
    || die 'Could not reach GitHub to resolve the latest release (set IPE_VERSION=vX.Y.Z).'
  # Grep over the captured string — no pipe from curl, so no early-close.
  tag="$(printf '%s\n' "$resp" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)"
  [ -n "$tag" ] || die 'Could not parse the latest release tag (set IPE_VERSION=vX.Y.Z).'
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
if curl -fsSL -o /dev/null -I --max-time 10 "$url" 2>/dev/null; then
  have_bin=1
  stage_ok 'Prebuilt binary available for %s-%s.' "$plat" "$cpu"
else
  # Settle the stage without restating the fact here — the fact is stated
  # exactly once, either by the retry prompt just below or by die_no_prebuilt
  # at the final gate; saying it here too was a literal duplicate.
  stage_skip
  if [ -n "${IPE_VERSION:-}" ] && [ "$IS_TTY" = 1 ] && [ -r /dev/tty ]; then
    say '\n    @B@No prebuilt ipe %s binary for %s-%s.@0@' "$ver" "$plat" "$cpu"
    prompt '    Install the @B@latest@0@ release instead? [Y/n] '
    ans=''
    if IFS= read -r ans < /dev/tty 2>/dev/null; then
      case "$ans" in
        ''|[Yy]|[Yy][Ee][Ss])
          stage_start 'Resolving the latest release…'
          resp="$(gh_latest_release)" \
            || die 'Could not reach GitHub.'
          tag="$(printf '%s\n' "$resp" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)"
          [ -n "$tag" ] || die 'Could not parse latest release tag.'
          require_release_tag "$tag"
          ver="${tag#ipe-}"
          base="https://github.com/$REPO/releases/download/$tag"
          url="$base/$artifact.$ext"
          if curl -fsSL -o /dev/null -I --max-time 10 "$url" 2>/dev/null; then
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
stage_start 'Checking Rust toolchain…'
cargo_ok=0
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
    info 'Found cargo %s (< required %s).' "$cargo_ver_raw" "$MIN_CARGO_VERSION"
  fi
else
  info 'Rust is not installed.'
  if [ -f "$HOME/.cargo/env" ] && [ "$IS_TTY" = 1 ] && [ -r /dev/tty ]; then
    say '\n    @B@Rust seems installed but not on your @0@PATH@B@.@0@'
    prompt '    Source @B@~/.cargo/env@0@ now? [Y/n] '
    ans=''
    if IFS= read -r ans < /dev/tty 2>/dev/null; then
      case "$ans" in
        ''|[Yy]|[Yy][Ee][Ss])
          # shellcheck source=/dev/null
          . "$HOME/.cargo/env"
          if command -v cargo >/dev/null 2>&1; then
            cargo_ok=1
            stage_ok 'Rust now available (%s).' "$(cargo version | cut -d' ' -f2)"
          fi
          ;;
      esac
    fi
  fi
  if [ "$cargo_ok" != 1 ]; then
    rustup_url="https://win.rustup.rs/x86_64"
    if [ "$IS_TTY" = 1 ] && [ -r /dev/tty ]; then
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
                # `sh -s -- -y` hands `-y` to rustup-init (unattended install).
                if curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs 2>/dev/null \
                  | sh -s -- -y 2>/dev/null; then
                  if [ -f "$HOME/.cargo/env" ]; then
                    # shellcheck source=/dev/null
                    . "$HOME/.cargo/env"
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
    if [ "$cargo_ok" != 1 ]; then
      info 'Install Rust later: https://rustup.rs'
    fi
  fi
fi

# ── Bail out when no binary is available ────────────────────────────
if [ "$have_bin" != 1 ]; then
  die_no_prebuilt "$tag" "$plat" "$cpu"
fi

# ── Download the binary with a friendly progress display ─────────────────────
tmp="$(mktemp -d "$scratch_base/ipe-install.XXXXXX")" \
  || die 'Could not create a private temp directory under %s.' "$scratch_base"
trap 'rm -rf "$tmp"' EXIT
private_dir_ok "$tmp" || die 'The temp directory %s is not private to you.' "$tmp"
pkg="$tmp/pkg.$ext"

stage_start 'Downloading ipe %s for %s-%s…' "$ver" "$plat" "$cpu"

# download_with_progress URL DEST
# On a TTY, run curl in the background writing to DEST, and animate a spinner +
# percent + bar + size + ETA by polling DEST's on-disk size against the known
# total. Off a TTY (pipe/CI), fall back to a couple of plain lines — no ANSI,
# no animation, no SIGPIPE.
download_with_progress() {
  dl_url="$1"; dl_dest="$2"

  # Total size (best-effort; 0 ⇒ unknown, bar degrades to a byte counter).
  # A one-byte range GET is more reliable than HEAD across GitHub's signed CDN
  # redirect: it always lands on a 206 carrying `Content-Range: bytes 0-0/TOTAL`.
  # Parse from a captured string, never a live pipe (no SIGPIPE).
  total=0
  range_resp="$(curl -fsSL -r 0-0 -D - -o /dev/null "$dl_url" 2>/dev/null || true)"
  if [ -n "$range_resp" ]; then
    total="$(printf '%s\n' "$range_resp" \
      | tr -d '\r' \
      | sed -n 's#^[Cc]ontent-[Rr]ange: *bytes [0-9]*-[0-9]*/\([0-9][0-9]*\).*#\1#p' \
      | tail -n1)"
    [ -n "$total" ] || total=0
  fi

  if [ "$IS_TTY" != 1 ]; then
    # Non-terminal: quiet download, single plain status line, no animation.
    curl -fsSL "$dl_url" -o "$dl_dest" \
      || die 'Download failed: %s' "$dl_url"
    got="$(wc -c < "$dl_dest" 2>/dev/null || echo 0)"
    stage_ok 'Downloaded %s.' "$(human "$got")"
    return 0
  fi

  # Terminal: curl in background (its own subshell so `set -e` can't trip on the
  # spinner loop); poll DEST size for the animation. Pre-create DEST so the
  # poller's `< DEST` never hits a not-yet-opened file mid-race.
  : > "$dl_dest"
  ( curl -fsSL "$dl_url" -o "$dl_dest"; echo $? > "$tmp/curl.rc" ) &
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

# ── Verify checksum (when the release ships SHA256SUMS) ───────────────────────
# Opportunistic: if the release publishes SHA256SUMS and we have a sha256 tool,
# verify the artifact. A present-but-mismatched sum is fatal; a missing sums
# file or missing tool is a soft skip (older releases, minimal environments).
stage_start 'Verifying the download…'
sums="$(curl -fsSL "$base/SHA256SUMS" 2>/dev/null || true)"
if [ -n "$sums" ]; then
  want="$(printf '%s\n' "$sums" \
    | sed -n "s/^\\([0-9a-fA-F][0-9a-fA-F]*\\) [ *]*$artifact\\.$ext\$/\\1/p" \
    | head -n1)"
  if [ -n "$want" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      got_sum="$(sha256sum "$pkg" | cut -d' ' -f1)"
    elif command -v shasum >/dev/null 2>&1; then
      got_sum="$(shasum -a 256 "$pkg" | cut -d' ' -f1)"
    else
      got_sum=''
    fi
    if [ -z "$got_sum" ]; then
      info 'No sha256 tool found — skipping checksum verification.'
    elif [ "$got_sum" = "$want" ]; then
      stage_ok 'Checksum verified.'
    else
      die 'Checksum mismatch for %s — refusing to install (expected %s, got %s).' "$artifact.$ext" "$want" "$got_sum"
    fi
  else
    info 'No checksum listed for %s — skipping verification.' "$artifact.$ext"
  fi
else
  info 'This release ships no SHA256SUMS — skipping checksum verification.'
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

IPE_HOME="$HOME/.ipe"
ENV_POSIX="$IPE_HOME/env"
ENV_FISH="$IPE_HOME/env.fish"

# on_path — succeed when INSTALL_DIR is already a PATH entry.
on_path() {
  case ":${PATH:-}:" in
    *":$INSTALL_DIR:"*) return 0 ;;
    *) return 1 ;;
  esac
}

# canonical_home — $HOME with any symlinks and `..` resolved to a physical path,
# computed once. The prefix test below compares physical paths, so a link whose
# textual target begins with "$HOME/" but resolves elsewhere cannot slip past.
canonical_home="$(cd -P "$HOME" 2>/dev/null && pwd -P)" || canonical_home="$HOME"

# refuse_symlink_escape PATH — die if PATH is a symlink whose target resolves
# outside $HOME. A managed env file or dotfile must stay within the user's home;
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
    zsh)  RC_FILE="${ZDOTDIR:-$HOME}/.zshrc" ;;
    bash)
      # Prefer an existing file; else .bash_profile on macOS (login shells),
      # .bashrc elsewhere.
      if   [ -f "$HOME/.bashrc" ];       then RC_FILE="$HOME/.bashrc"
      elif [ -f "$HOME/.bash_profile" ]; then RC_FILE="$HOME/.bash_profile"
      elif [ "$plat" = darwin ];         then RC_FILE="$HOME/.bash_profile"
      else RC_FILE="$HOME/.bashrc"; fi
      ;;
    fish) RC_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/fish/config.fish" ;;
    ksh)  RC_FILE="$HOME/.kshrc" ;;
    *)    RC_FILE="$HOME/.profile" ;;
  esac
  if [ "$SH_NAME" = fish ]; then
    RC_SOURCE_LINE="source \"$ENV_FISH\""
    PATH_NOW="fish_add_path $INSTALL_DIR"
    SOURCE_NOW="source \"$ENV_FISH\""
  else
    RC_SOURCE_LINE=". \"$ENV_POSIX\""
    # shellcheck disable=SC2016  # $PATH must stay literal so it expands per-shell
    PATH_NOW="export PATH=\"$INSTALL_DIR:\$PATH\""
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
# symlink swapped in after our check cannot redirect the write outside $HOME
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
  # it here yields an inert literal even though the file is later sourced.
  # shellcheck disable=SC2016  # $PATH must stay literal for per-shell expansion
  write_env_files_posix="# Managed by the Ipê installer — puts ipe on your PATH.
case \":\${PATH}:\" in *\":$INSTALL_DIR:\"*) ;; *) export PATH='$INSTALL_DIR':\"\$PATH\" ;; esac
"
  write_env_files_fish="# Managed by the Ipê installer — puts ipe on your PATH.
if not contains '$INSTALL_DIR' \$PATH
    fish_add_path '$INSTALL_DIR'
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
say '\n  If you find any bugs, please report them at https://github.com/%s/issues.\n' "$REPO"
} >/dev/null
