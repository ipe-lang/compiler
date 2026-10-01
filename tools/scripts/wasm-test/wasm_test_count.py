#!/usr/bin/env python3
"""Prove a non-host test runner executed exactly the expected number of tests.

Usage: `cargo test … | python3 tools/scripts/wasm-test/wasm_test_count.py N`,
where `N` is the `expect_tests` of the cell of `.github/ci/test-claims.yml`
the piped cargo command runs; `verify-manifest` check 20 proves every claim
step passes its cell's number. The runner's output is echoed unchanged. The
step fails unless that output holds exactly one `test result: … P passed; F
failed` line with `P` equal to `N` and `F` zero; a missing line, a second
line, a short or long count, and any failure are each refused. Stdlib only:
it runs after the build, with no CI dependency installed.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable
from typing import TextIO

_SUMMARY = re.compile(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed;")
_COUNT = re.compile(r"[1-9][0-9]{0,5}\Z")
# A runner line longer than this is echoed but never read as a summary.
MAX_LINE = 64 * 1024


def count(lines: Iterable[str], expect: int, out: TextIO) -> str | None:
    """Echo `lines` to `out`; None when they hold exactly one summary of
    `expect` passed and none failed, else why not."""
    summaries: list[tuple[int, int]] = []
    for line in lines:
        out.write(line)
        if len(line) > MAX_LINE:
            continue
        m = _SUMMARY.search(line)
        if m:
            summaries.append((int(m.group(1)), int(m.group(2))))
    out.flush()
    if not summaries:
        return "the runner printed no `test result:` line"
    if len(summaries) > 1:
        return f"the runner printed {len(summaries)} `test result:` lines; a cell is one test binary"
    passed, failed = summaries[0]
    if failed:
        return f"{failed} test(s) failed"
    if passed != expect:
        return f"{passed} test(s) passed, but the cell claims {expect}"
    return None


def main(argv: list[str], stdin: TextIO, stdout: TextIO, stderr: TextIO) -> int:
    if len(argv) != 1 or not _COUNT.match(argv[0]):
        stderr.write("usage: wasm_test_count.py N  (N a positive decimal count)\n")
        return 2
    expect = int(argv[0])
    why = count(stdin, expect, stdout)
    if why is not None:
        stderr.write(f"wasm_test_count: {why}\n")
        return 1
    stderr.write(f"wasm_test_count: {expect} passed, as claimed\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:], sys.stdin, sys.stdout, sys.stderr))
