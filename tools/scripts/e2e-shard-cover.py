#!/usr/bin/env python3
"""Prove the e2e shard plan partitions the run's own nextest archive exactly.

`seal-slice` runs this with $E2E_PLAN, the `changes` job's `e2e_plan` output:
the same plan every `e2e` shard read its selection from. It lists the archive
in full and once per plan entry, and exits 0 only when every archived test is
selected by exactly one shard, every shard selects a test, and no shard
selects a test outside the archive, so "the e2e shards run every archived test" is checked on every run, never
assumed. The plan's shape and its tie to the `e2e` matrix are pinned by
`.github/ci/e2e_shard.py --lint`.

Every failure exits non-zero; a malformed plan, a malformed listing, or an
empty archive is a failure, never a pass.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter

ARCHIVE_ARGS = ("--archive-file", "nextest.tar.zst", "--workspace-remap", ".", "--profile", "ci")
MAX_SHARDS = 256
MAX_PLAN_CHARS = 64 * 1024
LIST_TIMEOUT_S = 300


class CoverError(Exception):
    """A plan or listing that proves nothing."""


def parse_plan(text: str) -> dict[int, str]:
    """Parse `{"1": {"filter"}, ..., "N": ...}` into shard -> filter."""
    if len(text) > MAX_PLAN_CHARS:
        raise CoverError(f"E2E_PLAN exceeds {MAX_PLAN_CHARS} characters")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CoverError(f"E2E_PLAN is not JSON: {exc}") from exc
    if not isinstance(doc, dict) or not doc:
        raise CoverError("E2E_PLAN is not a non-empty object")
    if len(doc) > MAX_SHARDS:
        raise CoverError(f"E2E_PLAN has more than {MAX_SHARDS} shards")
    expected = [str(k) for k in range(1, len(doc) + 1)]
    if sorted(doc, key=lambda k: (len(k), k)) != expected:
        raise CoverError(f"E2E_PLAN keys are {sorted(doc)!r}, expected \"1\"..\"{len(doc)}\"")
    plan: dict[int, str] = {}
    for key, entry in doc.items():
        if not isinstance(entry, dict) or set(entry) != {"filter"}:
            raise CoverError(f"E2E_PLAN shard {key} must be exactly {{filter}}")
        filt = entry["filter"]
        if not isinstance(filt, str) or not filt.strip():
            raise CoverError(f"E2E_PLAN shard {key} has an empty or non-string selection")
        plan[int(key)] = filt
    return plan


def matched_tests(listing: str) -> list[str]:
    """Return the `binary-id test-name` of every test a nextest JSON listing selects."""
    try:
        doc = json.loads(listing)
    except json.JSONDecodeError as exc:
        raise CoverError(f"nextest listing is not JSON: {exc}") from exc
    suites = doc.get("rust-suites") if isinstance(doc, dict) else None
    if not isinstance(suites, dict):
        raise CoverError("nextest listing has no `rust-suites` object")
    out: list[str] = []
    for binary_id, suite in suites.items():
        cases = suite.get("testcases") if isinstance(suite, dict) else None
        if not isinstance(cases, dict):
            raise CoverError(f"suite {binary_id!r} has no `testcases` object")
        for name, case in cases.items():
            match = case.get("filter-match") if isinstance(case, dict) else None
            status = match.get("status") if isinstance(match, dict) else None
            if status not in ("matches", "mismatch"):
                raise CoverError(f"test {binary_id} {name} has no known filter-match status")
            if status == "matches":
                out.append(f"{binary_id} {name}")
    return out


def partition_errors(full: list[str], shards: dict[int, list[str]], count: int) -> list[str]:
    """Return why the `count` shard selections fail to partition `full`, or [] when they do."""
    errors: list[str] = []
    if not full:
        errors.append("the archive lists no tests: an empty set proves no coverage")
    if count < 1 or sorted(shards) != list(range(1, count + 1)):
        errors.append(f"shards listed {sorted(shards)}, expected 1..{count}")
    full_set = set(full)
    if len(full_set) != len(full):
        errors.append("the archive listing repeats a test id")
    owners: Counter[str] = Counter()
    for shard in sorted(shards):
        if not shards[shard]:
            errors.append(f"shard {shard} selects no test")
        for test in shards[shard]:
            owners[test] += 1
            if test not in full_set:
                errors.append(f"shard {shard} selects {test}, which the archive does not list")
    for test in sorted(full_set):
        seen = owners.get(test, 0)
        if seen == 0:
            errors.append(f"no shard runs {test}")
        elif seen > 1:
            errors.append(f"{test} runs in {seen} shards")
    return errors


def _list(extra: list[str]) -> list[str]:
    cmd = ["cargo", "nextest", "list", *ARCHIVE_ARGS, "--message-format", "json", *extra]
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=LIST_TIMEOUT_S)
    if proc.returncode != 0:
        raise CoverError(f"`{' '.join(cmd)}` exited {proc.returncode}:\n{proc.stderr}")
    return matched_tests(proc.stdout)


def cover(plan_text: str) -> int:
    """Fail unless the plan's selections partition the archive's test set exactly."""
    plan = parse_plan(plan_text)
    full = _list([])
    shards = {k: _list(["-E", filt]) for k, filt in plan.items()}
    errors = partition_errors(full, shards, len(plan))
    for err in errors:
        print(f"e2e shard cover: {err}", file=sys.stderr)
    if errors:
        return 1
    print(f"e2e shard cover: {len(plan)} shards partition all {len(full)} archived tests exactly once.")
    return 0


def main(argv: list[str]) -> int:
    if argv:
        print("usage: E2E_PLAN=<json> e2e-shard-cover.py", file=sys.stderr)
        return 2
    try:
        return cover(os.environ.get("E2E_PLAN", ""))
    except (CoverError, OSError, subprocess.SubprocessError) as exc:
        print(f"e2e shard cover: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
