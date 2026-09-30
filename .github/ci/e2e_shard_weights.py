#!/usr/bin/env python3
"""Rewrite `e2e_shard_weights.json` from the timings in `e2e` job logs.

Refresh when shard wall-clocks drift apart (the weights steer balance only;
coverage never depends on them):

    gh run view <run-id> --json jobs --jq '.jobs[] | select(.name | startswith("e2e (")) | .databaseId' |
      while read -r id; do gh api "repos/ipe-lang/compiler/actions/jobs/$id/logs" > "/tmp/e2e-$id.log"; done
    python3 .github/ci/e2e_shard_weights.py /tmp/e2e-*.log

Several runs may be passed at once; a test's weight is its mean over every log
line that timed it. Each nextest result line (`PASS [ 12.345s] (1/99) <binary-id>
<test-name>`) is classed HEAVY or LIGHT by its binary name and summed into the
bucket `e2e_shard.bucket` gives its name. Logs that time no test are refused, so
a wrong download never zeroes the table.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import e2e_shard as es  # noqa: E402

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_RESULT = re.compile(r"\b(?:PASS|FAIL|TIMEOUT|SIGKILL)\s+\[\s*(\d+(?:\.\d+)?)s\]\s+\(\s*\d+/\s*\d+\)\s+(\S+)\s+(\S.*?)\s*$")


def timings(text: str) -> dict[tuple[str, str], list[float]]:
    """Return (binary-id, test-name) -> seconds for every nextest result line in `text`."""
    out: dict[tuple[str, str], list[float]] = defaultdict(list)
    for line in _ANSI.sub("", text).splitlines():
        m = _RESULT.search(line)
        if m:
            out[(m[2], m[3])].append(float(m[1]))
    return out


def is_heavy(binary_id: str) -> bool:
    """Return whether a nextest binary id (`crate::binary` or `crate`) is in the HEAVY class."""
    return binary_id.rsplit("::", 1)[-1] in es.HEAVY_BINARIES


def weights(samples: dict[tuple[str, str], list[float]]) -> dict[str, list[int]]:
    """Return the per-class, per-bucket seconds of the mean timing of every test."""
    if not samples:
        raise es.ShardError("the logs time no test")
    acc = {cls: [0.0] * es.MODULUS for cls in es.CLASSES}
    for (binary_id, name), secs in samples.items():
        acc["heavy" if is_heavy(binary_id) else "light"][es.bucket(name)] += sum(secs) / len(secs)
    return es.parse_weights({cls: [round(s) for s in row] for cls, row in acc.items()})


def main(argv: list[str]) -> int:
    if not argv or any(a.startswith("-") for a in argv):
        print("usage: e2e_shard_weights.py LOG...", file=sys.stderr)
        return 2
    samples: dict[tuple[str, str], list[float]] = defaultdict(list)
    try:
        for path in argv:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for key, secs in timings(fh.read()).items():
                    samples[key] += secs
        table = weights(samples)
        es.plan(table)
        with open(es.WEIGHTS_FILE, "w", encoding="utf-8") as fh:
            json.dump(table, fh, sort_keys=True)
            fh.write("\n")
    except (OSError, es.ShardError) as exc:
        print(f"e2e_shard_weights: {exc}", file=sys.stderr)
        return 1
    print(f"e2e_shard_weights: {len(samples)} tests weighed into {es.WEIGHTS_FILE}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
