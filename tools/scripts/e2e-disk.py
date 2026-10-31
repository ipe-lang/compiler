#!/usr/bin/env python3
"""Bound the e2e shard's disk: a floor before the shard and a census after it.

`--disk-floor` exits non-zero unless the workspace and temp mounts each hold
`DISK_FLOOR_BYTES`, the sum of the named terms below, so a runner that cannot
hold the shard is a named refusal before any test runs.

`--census <root>...` lists every cargo target directory (cargo writes
`CACHEDIR.TAG` at each target root) left under the roots, apart from the
declared shared target and the unpacked archive, prints the largest, and exits
non-zero on any leftover or on any part of a root it could not read. It reads
names only and never deletes.

`.github/ci/e2e_shard.py --lint` pins where the `e2e` job runs this and that
`TEST_THREADS` and `EXTRACT_DIR` here equal the shard's own.
"""

from __future__ import annotations

import contextlib
import os
import sys

# Equal to `.github/ci/e2e_shard.py` `TEST_THREADS` and `EXTRACT_DIR` (its
# `--lint` refuses a drift).
TEST_THREADS = 2
EXTRACT_DIR = "$RUNNER_TEMP/nextest-x"
# A shard's disk peak is bounded by terms that do not grow with its test count:
# the unpacked archive (already on disk when the floor is checked), the shared
# dependency tree (fixed by the emitted runtime's Cargo.lock), one app crate per
# test thread in the shared target, and one isolated cold tree at a time (the
# `e2e_support::target` lock). The floor is the sum of the terms still to be
# written when the shard starts, so a runner that cannot hold the shard is a
# named refusal before any test runs, not a runner death in the middle.
GIB = 1024**3
MIB = 1024**2
SHARED_DEP_TREE_BYTES = 6 * GIB  # a cold shared target: the runtime's full dependency tree
APP_CRATE_BYTES = 768 * MIB  # one emitted app crate's leaf artifacts in the shared target
ISOLATED_TREE_BYTES = 6 * GIB  # one isolated cold tree, at most one per runner
RESULTS_SLACK_BYTES = 1 * GIB  # JUnit, logs, scratch emitted sources
DISK_FLOOR_TERMS = (
    ("shared dependency tree", SHARED_DEP_TREE_BYTES),
    (f"{TEST_THREADS} test threads x one app crate", TEST_THREADS * APP_CRATE_BYTES),
    ("one isolated cold tree", ISOLATED_TREE_BYTES),
    ("results slack", RESULTS_SLACK_BYTES),
)
DISK_FLOOR_BYTES = sum(b for _, b in DISK_FLOOR_TERMS)
SHARED_TARGET_VAR = "IPE_ORACLE_SHARED_TARGET"
CENSUS_MAX_DEPTH = 16
CENSUS_MAX_ENTRIES = 2_000_000
CENSUS_TOP = 10
CACHEDIR_TAG = "CACHEDIR.TAG"


def free_bytes(path: str) -> int:
    """Return the bytes an unprivileged process may still write on `path`'s mount."""
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def disk_floor(paths: list[str], reader=free_bytes) -> int:
    """Exit 1 unless every path's mount has `DISK_FLOOR_BYTES` free."""
    terms = ", ".join(f"{name} {b}" for name, b in DISK_FLOOR_TERMS)
    failed = False
    for path in paths:
        try:
            free = reader(path)
        except OSError as exc:
            print(f"e2e disk floor: cannot read free space on {path}: {exc}", file=sys.stderr)
            failed = True
            continue
        if free < DISK_FLOOR_BYTES:
            print(
                f"e2e disk floor: {path} has {free} bytes free, below DISK_FLOOR_BYTES={DISK_FLOOR_BYTES} ({terms})",
                file=sys.stderr,
            )
            failed = True
        else:
            print(f"e2e disk floor: {path} has {free} bytes free (floor {DISK_FLOOR_BYTES}).")
    return 1 if failed else 0


def _excluded(path: str, excluded: set[str]) -> bool:
    real = os.path.realpath(path)
    return any(real == ex or real.startswith(ex + os.sep) for ex in excluded)


def census_walk(roots: list[str], excluded: list[str]) -> tuple[list[str], list[str]]:
    """Return every cargo target root (a directory holding `CACHEDIR.TAG`) under
    `roots` outside `excluded`, and every reason the walk is unproven.

    The walk never follows a symlink, reads names only, stops at
    `CENSUS_MAX_DEPTH` and `CENSUS_MAX_ENTRIES`, and reports a directory it
    cannot read or descend as unproven, never as clean.
    """
    ex = {os.path.realpath(e) for e in excluded if e}
    found: list[str] = []
    unproven: list[str] = []
    seen = 0
    stack = [(r, 0) for r in roots if os.path.isdir(r) and not os.path.islink(r)]
    while stack:
        path, depth = stack.pop()
        if _excluded(path, ex):
            continue
        try:
            entries = list(os.scandir(path))
        except OSError as exc:
            unproven.append(f"{path}: unreadable ({exc.strerror})")
            continue
        seen += len(entries)
        if seen > CENSUS_MAX_ENTRIES:
            unproven.append(f"the walk passed {CENSUS_MAX_ENTRIES} entries")
            break
        if any(e.name == CACHEDIR_TAG for e in entries):
            found.append(path)
            continue
        for e in entries:
            if e.is_dir(follow_symlinks=False):
                if depth + 1 > CENSUS_MAX_DEPTH:
                    unproven.append(f"{e.path}: deeper than {CENSUS_MAX_DEPTH}")
                else:
                    stack.append((e.path, depth + 1))
    return sorted(found), unproven


def _tree_bytes(path: str) -> int:
    total = 0
    for dirpath, _, files in os.walk(path, followlinks=False):
        for name in files:
            with contextlib.suppress(OSError):
                total += os.lstat(os.path.join(dirpath, name)).st_size
    return total


def census(roots: list[str], env: dict[str, str]) -> int:
    """Exit 1 when a cargo target directory other than the shared target and the
    unpacked archive survives the shard, or the walk cannot prove there is none."""
    excluded = [env.get(SHARED_TARGET_VAR, "")]
    runner_temp = env.get("RUNNER_TEMP", "")
    if runner_temp:
        excluded.append(EXTRACT_DIR.replace("$RUNNER_TEMP", runner_temp))
    for root in roots:
        with contextlib.suppress(OSError):
            usage = os.statvfs(root)
            print(f"e2e census: {root}: {usage.f_bavail * usage.f_frsize} bytes free")
    found, unproven = census_walk(roots, excluded)
    sized = sorted(((_tree_bytes(p), p) for p in found), reverse=True)
    for size, path in sized[:CENSUS_TOP]:
        print(f"e2e census: leftover target {path} ({size} bytes)", file=sys.stderr)
    for why in unproven:
        print(f"e2e census: unproven: {why}", file=sys.stderr)
    if found or unproven:
        print(
            f"e2e census: {len(found)} cargo target(s) outlived their test; every test-spawned build "
            "takes its target from `e2e_support::target`, which removes it on drop",
            file=sys.stderr,
        )
        return 1
    print("e2e census: no test-spawned cargo target outlived its test.")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--disk-floor"]:
        return disk_floor([os.environ.get("GITHUB_WORKSPACE") or os.getcwd(), os.environ.get("TMPDIR") or "/tmp"])
    if len(argv) >= 2 and argv[0] == "--census":
        return census(argv[1:], dict(os.environ))
    print("usage: e2e-disk.py --disk-floor | --census <root>...", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
