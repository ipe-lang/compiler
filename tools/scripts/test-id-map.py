#!/usr/bin/env python3
"""Prove a test-binary consolidation moved every test and lost none.

Two acceptance checks for a change that moves top-level test files into a
harness as modules:

    test-id-map.py --static <base> <head>
        Every test source file the diff touches keeps its count of
        `#[...test]` attributes: a renamed file against its old self, a
        modified file against its base. A deleted test file is refused, since
        a move must show as a rename.

    test-id-map.py --ids <before.txt> <after.txt>
        Two `test-ids.txt` listings (one `<binary-id> <test-name>` per line,
        as `seal-slice-cover` uploads them) are a bijection: each id of the
        base run is either still present, or reappears as
        `<crate>::<harness> <old_binary>::<test>` for exactly one harness. No
        id is unmapped on either side, none repeats, and the totals agree.

Every failure exits 1 with each reason on stderr; usage errors exit 2.
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections import Counter

TEST_ATTR = re.compile(r"^[ \t]*#\[(?:[A-Za-z_][A-Za-z0-9_]*::)*test(?:\([^\n]*\))?\]", re.MULTILINE)


def is_test_source(path: str) -> bool:
    """A Rust file under some `tests/` directory."""
    return path.endswith(".rs") and ("/tests/" in path or path.startswith("tests/"))


def test_count(text: str) -> int:
    """The number of `#[test]`-like attributes (`#[test]`, `#[tokio::test(...)]`) in `text`."""
    return len(TEST_ATTR.findall(text))


def parse_name_status(text: str) -> list[tuple[str, list[str]]]:
    """Parse `git diff --name-status -M` output into `(status letter, paths)`."""
    out: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        status, *paths = line.split("\t")
        if not status or not paths:
            raise ValueError(f"unreadable diff line {line!r}")
        out.append((status[0], paths))
    return out


def static_errors(entries, read_base, read_head) -> tuple[list[str], list[str]]:
    """Return `(errors, report)` for the diff `entries`; `read_*` give a file's text at each side."""
    errors: list[str] = []
    report: list[str] = []
    for status, paths in entries:
        old, new = paths[0], paths[-1]
        if not (is_test_source(old) or is_test_source(new)):
            continue
        if status == "D":
            errors.append(f"{old} is deleted, not moved: a consolidation shows every member as a rename")
            continue
        if status == "A":
            report.append(f"added {new} ({test_count(read_head(new))} tests)")
            continue
        if status not in ("R", "M", "C"):
            errors.append(f"{new}: unexpected diff status {status!r}")
            continue
        before, after = test_count(read_base(old)), test_count(read_head(new))
        if before != after:
            errors.append(f"{old} -> {new}: {before} tests before, {after} after")
        else:
            report.append(f"{old} -> {new}: {after} tests" if old != new else f"{new}: {after} tests")
    return errors, report


def read_ids(text: str, label: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Parse a `test-ids.txt` listing into `(binary_id, test)` pairs and the reasons it is malformed."""
    ids: list[tuple[str, str]] = []
    errors: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        binary, sep, test = line.partition(" ")
        if not sep or not binary or not test or " " in binary:
            errors.append(f"{label}:{number}: {line!r} is not `<binary-id> <test-name>`")
            continue
        ids.append((binary, test))
    for item, seen in Counter(ids).items():
        if seen > 1:
            errors.append(f"{label}: `{item[0]} {item[1]}` is listed {seen} times")
    if not ids:
        errors.append(f"{label} lists no test: an empty set proves nothing")
    return ids, errors


def map_ids(before: list[tuple[str, str]], after: list[tuple[str, str]]) -> tuple[list[str], Counter[str]]:
    """Return `(errors, moves)`: why `before` -> `after` is no bijection, and the count per move."""
    errors: list[str] = []
    moves: Counter[str] = Counter()
    after_set = set(after)
    claimed: set[tuple[str, str]] = set()
    by_name: dict[str, list[tuple[str, str]]] = {}
    for binary, test in after:
        by_name.setdefault(test, []).append((binary, test))
    for binary, test in before:
        if (binary, test) in after_set:
            claimed.add((binary, test))
            moves["unchanged"] += 1
            continue
        crate, sep, old = binary.partition("::")
        candidates = by_name.get(f"{old}::{test}", []) if sep else []
        hits = [h for h in candidates if h[0].startswith(f"{crate}::")]
        if len(hits) != 1:
            why = "is in no harness" if not hits else f"is in {len(hits)} harnesses"
            errors.append(f"`{binary} {test}` {why} of the new run")
            continue
        if hits[0] in claimed:
            errors.append(f"`{hits[0][0]} {hits[0][1]}` of the new run is claimed by two tests of the base run")
        claimed.update(hits)
        moves[f"{binary} -> {hits[0][0]}"] += 1
    for item in after:
        if item not in claimed:
            errors.append(f"`{item[0]} {item[1]}` of the new run maps to no test of the base run")
    if len(before) != len(after):
        errors.append(f"the base run lists {len(before)} tests, the new run {len(after)}")
    return errors, moves


def _git_show(rev: str, path: str) -> str:
    return subprocess.run(["git", "show", f"{rev}:{path}"], check=True, capture_output=True, text=True).stdout


def run_static(base: str, head: str) -> int:
    diff = subprocess.run(
        ["git", "diff", "--name-status", "-M", base, head], check=True, capture_output=True, text=True
    ).stdout
    errors, report = static_errors(parse_name_status(diff), lambda p: _git_show(base, p), lambda p: _git_show(head, p))
    for line in report:
        print(f"test-id-map: {line}")
    for err in errors:
        print(f"test-id-map: {err}", file=sys.stderr)
    return 1 if errors else 0


def run_ids(before_path: str, after_path: str) -> int:
    with open(before_path, encoding="utf-8") as handle:
        before, errors = read_ids(handle.read(), before_path)
    with open(after_path, encoding="utf-8") as handle:
        after, after_errors = read_ids(handle.read(), after_path)
    errors += after_errors
    map_errors, moves = map_ids(before, after)
    errors += map_errors
    for move, count in sorted(moves.items()):
        print(f"test-id-map: {move}: {count}")
    for err in errors:
        print(f"test-id-map: {err}", file=sys.stderr)
    if not errors:
        print(f"test-id-map: {len(before)} tests before, {len(after)} after, every one mapped exactly once.")
    return 1 if errors else 0


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "--static":
        return run_static(argv[1], argv[2])
    if len(argv) == 3 and argv[0] == "--ids":
        return run_ids(argv[1], argv[2])
    print("usage: test-id-map.py --static <base> <head> | --ids <before.txt> <after.txt>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"test-id-map: {exc}", file=sys.stderr)
        sys.exit(1)
