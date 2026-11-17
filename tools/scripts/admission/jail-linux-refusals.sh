#!/bin/sh
# Refusal proof for jail-linux.sh: each input the wrapper must turn away is
# refused, before any jail is built, for the reason the wrapper names. A run
# that succeeds, or fails for another reason, is a red.
#
# Runs unprivileged: every refusal precedes the jail.

set -u

JAIL="${JAIL:-tools/scripts/admission/jail-linux.sh}"
FIXTURE="tests/fixtures/admission/untrusted-build.sh"
FAILED=0

# expect_refusal <reason substring> <command...>
expect_refusal() {
    want="$1"
    shift
    if out="$("$@" 2>&1)"; then
        echo "NOT REFUSED: $*"
        FAILED=1
        return
    fi
    case "$out" in
        *"$want"*) echo "refused ($want): $*" ;;
        *)
            echo "REFUSED FOR ANOTHER REASON: $*"
            echo "$out"
            FAILED=1
            ;;
    esac
}

# A dropped ESCAPE_PATH never falls back to a default path.
expect_refusal "ESCAPE_PATH is unset" \
    env -u ESCAPE_PATH sh "$JAIL" "$FIXTURE"
expect_refusal "ESCAPE_PATH is unset" \
    env ESCAPE_PATH= sh "$JAIL" "$FIXTURE"
# The input must be a readable regular file the launcher opens itself.
expect_refusal "is not a readable regular file" \
    env ESCAPE_PATH=/usr/jail-escape-probe sh "$JAIL" tests/fixtures/admission
expect_refusal "is not a readable regular file" \
    env ESCAPE_PATH=/usr/jail-escape-probe sh "$JAIL" tests/fixtures/admission/absent.sh

exit "$FAILED"
