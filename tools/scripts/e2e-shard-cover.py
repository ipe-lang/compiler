#!/usr/bin/env python3
"""Prove the e2e shard plan partitions the run's own nextest archive exactly.

`seal-slice-cover` runs this with $E2E_PLAN, the `changes` job's `e2e_plan`
output: the same plan every `e2e` shard reads its selection from. It lists the archive
in full and once per plan entry, and exits 0 only when every archived test is
selected by exactly one shard and no shard selects a test outside the archive,
so "the e2e shards run every archived test" is checked on every run, never
assumed. The plan's shape and its tie to the `e2e` matrix are pinned by
`.github/ci/e2e_shard.py --lint`.

It also lists the archive once per distinct `.config/nextest.toml` override
filter (every profile) and refuses one that selects no test, except the
filters `PLATFORM_ONLY` names, whose tests the Linux archive cannot hold; a
`PLATFORM_ONLY` entry no override still carries is refused too. Every shard
group of the plan must select at least one test. So a group, a timeout or a
test-group override keyed by a binary or module that moved is caught on the
run that moves it. The full sorted test-id list is written to `test-ids.txt`
for the job to upload, so two runs' test sets can be compared id by id.

Every failure exits non-zero; a malformed plan, a malformed listing, a
malformed override table, or an empty archive is a failure, never a pass.
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
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NEXTEST_CONFIG = os.path.join(REPO, ".config", "nextest.toml")
TEST_IDS_FILE = "test-ids.txt"
# Override filters whose tests are `cfg`-gated off Linux, so the archive this
# job lists holds none of them.
PLATFORM_ONLY = frozenset({"package(ipe) & kind(lib) & test(/junction/)"})


class CoverError(Exception):
    """A plan or listing that proves nothing."""


def parse_plan(text: str) -> dict[int, tuple[str, str]]:
    """Parse `{"1": {"filter", "partition"}, ..., "N": ...}` into shard -> (filter, partition)."""
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
    plan: dict[int, tuple[str, str]] = {}
    for key, entry in doc.items():
        if not isinstance(entry, dict) or set(entry) != {"filter", "partition"}:
            raise CoverError(f"E2E_PLAN shard {key} must be exactly {{filter, partition}}")
        filt, part = entry["filter"], entry["partition"]
        if not isinstance(filt, str) or not filt.strip() or not isinstance(part, str) or not part.strip():
            raise CoverError(f"E2E_PLAN shard {key} has an empty or non-string selection")
        plan[int(key)] = (filt, part)
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


def override_filters(text: str) -> list[str]:
    """Return every `[[profile.<name>.overrides]]` filter of a nextest config, in order.

    Each override table must carry exactly one `filter = '...'` (or `"..."`
    without escapes) on one line; any other shape is refused, so a filter
    this reader cannot see is never silently left unchecked.
    """
    filters: list[str] = []
    in_override = False
    seen = 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("["):
            if in_override and seen != 1:
                raise CoverError(f"nextest.toml override before line {number} has {seen} filters, expected 1")
            in_override = line.startswith("[[profile.") and line.endswith(".overrides]]")
            seen = 0
            continue
        if not in_override or not line.startswith("filter"):
            continue
        key, sep, value = line.partition("=")
        value = value.strip()
        quote = value[:1]
        if key.strip() != "filter" or not sep or quote not in ("'", '"') or not value.endswith(quote) or len(value) < 3:
            raise CoverError(f"nextest.toml line {number}: unreadable filter {raw!r}")
        body = value[1:-1]
        if quote in body or (quote == '"' and "\\" in body):
            raise CoverError(f"nextest.toml line {number}: unreadable filter {raw!r}")
        filters.append(body)
        seen += 1
    if in_override and seen != 1:
        raise CoverError(f"the last nextest.toml override has {seen} filters, expected 1")
    if not filters:
        raise CoverError("nextest.toml declares no override filter: the reader no longer matches the file")
    return filters


def filter_errors(counts: dict[str, int]) -> list[str]:
    """Return why the override filters' match `counts` fail, or [] when every one is live."""
    errors: list[str] = []
    for filt in sorted(counts):
        if filt in PLATFORM_ONLY:
            if counts[filt] > 0:
                errors.append(f"PLATFORM_ONLY filter {filt!r} selects {counts[filt]} archived tests: drop it from PLATFORM_ONLY")
        elif counts[filt] == 0:
            errors.append(f"nextest.toml override {filt!r} selects no archived test: it names a binary, module or test that no longer exists")
    for filt in sorted(PLATFORM_ONLY - set(counts)):
        errors.append(f"PLATFORM_ONLY filter {filt!r} is no override in nextest.toml: drop the stale entry")
    return errors


def group_errors(plan: dict[int, tuple[str, str]], shards: dict[int, list[str]]) -> list[str]:
    """Return every plan filter (one shard group) whose shards together select no test."""
    totals: dict[str, int] = {}
    for shard, (filt, _) in plan.items():
        totals[filt] = totals.get(filt, 0) + len(shards.get(shard, []))
    return [f"the shard group {filt!r} selects no archived test" for filt, total in totals.items() if total == 0]


def _list(extra: list[str]) -> list[str]:
    cmd = ["cargo", "nextest", "list", *ARCHIVE_ARGS, "--message-format", "json", *extra]
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=LIST_TIMEOUT_S)
    if proc.returncode != 0:
        raise CoverError(f"`{' '.join(cmd)}` exited {proc.returncode}:\n{proc.stderr}")
    return matched_tests(proc.stdout)


def cover(plan_text: str) -> int:
    """Fail unless the plan's selections partition the archive's test set exactly."""
    plan = parse_plan(plan_text)
    with open(NEXTEST_CONFIG, encoding="utf-8") as handle:
        filters = list(dict.fromkeys(override_filters(handle.read())))
    full = _list([])
    with open(TEST_IDS_FILE, "w", encoding="utf-8") as handle:
        handle.writelines(f"{test}\n" for test in sorted(full))
    shards = {k: _list(["-E", filt, "--partition", part]) for k, (filt, part) in plan.items()}
    counts = {filt: len(_list(["-E", filt])) for filt in filters}
    errors = partition_errors(full, shards, len(plan)) + group_errors(plan, shards) + filter_errors(counts)
    for err in errors:
        print(f"e2e shard cover: {err}", file=sys.stderr)
    if errors:
        return 1
    print(f"e2e shard cover: {len(plan)} shards partition all {len(full)} archived tests exactly once.")
    print(f"e2e shard cover: all {len(filters)} nextest.toml override filters select archived tests.")
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
