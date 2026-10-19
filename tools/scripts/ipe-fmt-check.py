#!/usr/bin/env python3
"""Verdict: every in-repo Ipê project is `ipe fmt --check` clean.

A project is a directory holding a git-tracked `package.ipe`; the set is
discovered from `git ls-files`, never hand-kept, so a new project is held to
the formatter the moment it is tracked. A project beneath a `tests` directory
is a test input — its exact bytes, deliberately unparseable ones included, are
what its test pins — so the formatter does not judge it.

Each project is checked with `$IPE_BIN fmt --check --plain <dir>`, and the
verdict is that command's exit status alone: any non-zero exit (drift, a parse
error, a missing path, a signal, a timeout) fails the project.

Exit: 0 = every project is formatted · 1 = one or more are not ·
      2 = setup (no `ipe` binary, git failed, or no project discovered).
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable, Iterable, Sequence

MANIFEST = "package.ipe"
TEST_INPUT_COMPONENT = "tests"
TIMEOUT_SECS = 120

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

Runner = Callable[[Sequence[str], str], int]


def projects(tracked: Iterable[str]) -> list[str]:
    """The project directories among `tracked` (repo-relative, `/`-separated) paths, sorted."""
    found = set()
    for path in tracked:
        parts = path.split("/")
        if parts[-1] != MANIFEST or TEST_INPUT_COMPONENT in parts[:-1]:
            continue
        found.add("/".join(parts[:-1]) or ".")
    return sorted(found)


def tracked_files(root: str) -> list[str]:
    raw = subprocess.run(
        ["git", "-C", root, "ls-files", "-z"], check=True, capture_output=True
    ).stdout
    return [p.decode("utf-8") for p in raw.split(b"\0") if p]


def run_ipe(argv: Sequence[str], cwd: str) -> int:
    try:
        return subprocess.run(argv, cwd=cwd, timeout=TIMEOUT_SECS, check=False).returncode
    except subprocess.TimeoutExpired:
        print(f"ipe fmt check: timed out after {TIMEOUT_SECS}s: {' '.join(argv)}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"ipe fmt check: could not run {argv[0]!r}: {e}", file=sys.stderr)
        return 1


def unformatted(ipe_bin: str, root: str, dirs: Sequence[str], run: Runner = run_ipe) -> list[str]:
    """The projects in `dirs` whose `ipe fmt --check --plain` exits non-zero."""
    return [d for d in dirs if run([ipe_bin, "fmt", "--check", "--plain", d], root) != 0]


def main(argv: list[str], env: dict[str, str], root: str = ROOT, run: Runner = run_ipe) -> int:
    if argv:
        print(__doc__, file=sys.stderr)
        return 2
    ipe_bin = env.get("IPE_BIN", "")
    if not ipe_bin or not os.path.isfile(ipe_bin) or not os.access(ipe_bin, os.X_OK):
        print(f"ipe fmt check: IPE_BIN {ipe_bin!r} is not an executable file", file=sys.stderr)
        return 2
    try:
        dirs = projects(tracked_files(root))
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError) as e:
        print(f"ipe fmt check: could not list the tracked files: {e}", file=sys.stderr)
        return 2
    if not dirs:
        print(
            f"ipe fmt check: no tracked {MANIFEST} discovered under {root}; refusing to pass an empty set",
            file=sys.stderr,
        )
        return 2
    bad = unformatted(ipe_bin, root, dirs, run)
    if bad:
        print(f"ipe fmt check: {len(bad)} of {len(dirs)} project(s) are not `ipe fmt` clean:", file=sys.stderr)
        for d in bad:
            print(f"  {d}  (fix: ipe fmt {d})", file=sys.stderr)
        return 1
    print(f"ipe fmt check: all {len(dirs)} project(s) are `ipe fmt` clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:], dict(os.environ)))
