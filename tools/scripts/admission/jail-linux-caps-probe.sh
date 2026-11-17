#!/bin/sh
# Input for jail-linux.sh: the process the jail runs holds no capability and
# inherits no descriptor beyond stdio. Run through the wrapper, never alone:
#
#   sudo env ESCAPE_PATH=... tools/scripts/admission/jail-linux.sh \
#       tools/scripts/admission/jail-linux-caps-probe.sh
#
# Capabilities are read from a child (`sed`), so the check covers what an
# untrusted build started by the jailed shell receives after `execve`. An absent
# field is a red, never a pass. The bounding set is not judged: with every held
# set empty and NoNewPrivs on, no `execve` (setuid or file capabilities) can
# raise a set, so the bounding set limits nothing further.

set -u
FAILED=0

for field in CapInh CapPrm CapEff CapAmb; do
    value="$(sed -n "s/^$field:[[:space:]]*//p" /proc/self/status)"
    if [ "$value" = "0000000000000000" ]; then
        echo "$field: none -- OK"
    else
        echo "$field: '$value' -- FAIL (the jailed process holds capabilities)"
        FAILED=1
    fi
done

nnp="$(sed -n 's/^NoNewPrivs:[[:space:]]*//p' /proc/self/status)"
if [ "$nnp" = "1" ]; then
    echo "NoNewPrivs: 1 -- OK"
else
    echo "NoNewPrivs: '$nnp' -- FAIL"
    FAILED=1
fi

# Descriptors 3..9 are never the shell's own (it keeps its script at >= 10), so
# any open one was inherited from the launcher.
for fd in 3 4 5 6 7 8 9; do
    if (: <&"$fd") 2>/dev/null; then
        echo "fd $fd: inherited -- FAIL"
        FAILED=1
    fi
done

exit "$FAILED"
