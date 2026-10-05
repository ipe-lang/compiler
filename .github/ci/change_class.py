#!/usr/bin/env python3
"""Fail-closed change classifier: decides which path-scoped CI tiers a PR may skip.

A scope's output is `false` (its tiers may skip) only on positive proof that
EVERY changed path is irrelevant to it; anything else — an unknown path, an
empty or unreadable diff, a non-PR event, a crash — yields `true` (run).

Irrelevance is proven one of two ways, and never by absence from an allowlist:
  * the path is PROSE: an explicitly enumerated file or directory that
    `guard()` (run as the verdict tool `prose_guard.py`) proves no build, test,
    script, or CI step reads;
  * the scope is not `code`, the path lies inside a SCOPED_ROOT (a source tree
    whose per-scope relevance is enumerated below), and it matches none of the
    scope's relevant patterns.
Every path outside PROSE and SCOPED_ROOTS (tools/, tests/, examples/, dotfile
configs, root files, a new top-level directory) runs every scope.

Usage: `change_class.py --SCOPE...` writes `SCOPE=true|false` per scope to
"$GITHUB_OUTPUT" (a flag names its scope with `-` for `_`: `--panic-scan`). It
is an advisory tool: a usage error or a crash leaves every output unset, which
each consumer reads as run.

Inputs (env, classify): EVENT_NAME; PR_HEAD_SHA (pull_request — the tested
commit must be the base + PR-head merge commit); MERGE_GROUP_BASE_SHA
(merge_group — the queue's base commit, which the checkout must contain).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drift_assertion  # noqa: E402  # the one drift-assertion parser, shared with verify-manifest

# ── The PROSE set: the only paths `code` may skip on ─────────────────────────
# Each entry is guarded (guard()): no crate, include!, drift check, script,
# workflow, or source literal may reach it. Directory entries end in "/".
PROSE_FILES = frozenset(
    {
        "CONTRIBUTING.md",
        "LICENSE",
        "NOTICE",
        "docs/divergences-from-elm.md",
    }
)
PROSE_DIRS = ("docs/adr/", "docs/assets/", "misc/")
# A tracked file under PROSE_DIRS must be inert by type as well as by location.
PROSE_SUFFIXES = (".md", ".png", ".svg", ".jpg", ".jpeg", ".gif", ".webp")

# ── Scoped roots: source trees whose per-scope relevance is enumerated ──────
SCOPED_ROOTS = ("src/", "editors/")

# Relevant patterns per narrow scope, evaluated only inside SCOPED_ROOTS.
# `code` has none: it skips on PROSE alone. A scope must cover every tracked
# file the packages its jobs select compile or read (verify-manifest check 16).

# Crates the runtime compiles or tests against (its path-dependency closure).
_RUNTIME = (
    "src/runtime/**",
    "src/compiler/diagnostics/**",
    "src/compiler/env/**",
    "src/compiler/intern/**",
    "src/compiler/parse/**",
    "src/compiler/path-core/**",
    "src/compiler/syntax/**",
)
_EMIT = (
    "src/compiler/backend/**",
    "src/compiler/lower/**",
    "src/compiler/ir/**",
    "src/compiler/kernels/**",
    "src/stdlib/**",
) + _RUNTIME
SCOPES: dict[str, tuple[str, ...]] = {
    "code": (),
    "emit": _EMIT,
    # The asan/tsan crates' closure beyond `emit`.
    "sanitize": _EMIT
    + (
        "src/compiler/canon/**",
        "src/compiler/ffi/**",
        "src/compiler/fs_open/**",
        "src/compiler/sandbox/**",
        "src/compiler/types/**",
        "src/ffi-bindgen-macro/**",
    ),
    "wasm": _RUNTIME
    + (
        "src/compiler/backend/**",
        "src/compiler/kernels/**",
        "src/stdlib/**",
        "src/wasm/**",
        "**/*wasm*",
    ),
    "editors": ("editors/**",),
    # `ipe-wasm` compiles the whole front end and backend, and the jail
    # runner's tests drive the `ipe` binary: every `src/` crate reaches them.
    "playground": ("src/**",),
    # tools/panic-scan/panic-scan --walk src reads every `.rs` and `Cargo.toml` under src/.
    "panic_scan": ("src/**/*.rs", "src/**/Cargo.toml"),
    # editors/tree-sitter-ipe/scripts/parity-check.sh parses src/stdlib/Ipe/ (and examples/).
    "grammar": ("editors/tree-sitter-ipe/**", "src/stdlib/Ipe/**"),
}

# Paths CI consumes that must never be PROSE (the guard asserts it).
CI_CONSUMED = (
    ".cargo/",
    ".config/",
    ".github/",
    "examples/",
    "tools/",
    "AGENTS.md",
    "Cargo.lock",
    "Cargo.toml",
    "PRINCIPLES.md",
    "README.md",
    "clippy.toml",
    "deny.toml",
    "install.sh",
    "rust-toolchain.toml",
    "rustfmt.toml",
)

# Source files whose text the literal scan reads.
CODE_SUFFIXES = (
    ".rs", ".py", ".sh", ".yml", ".yaml", ".toml", ".json", ".js", ".mjs",
    ".ts", ".in", ".ipe", ".txt", ".cfg",
)
# This classifier and its tests name every PROSE entry by construction.
SELF_FILES = frozenset({".github/ci/change_class.py", ".github/ci/test_change_class.py"})

_INCLUDE = re.compile(
    r"\binclude(?:_str|_bytes|_dir)?!\s*\(\s*(?:concat!\s*\(\s*env!\s*\(\s*\"CARGO_MANIFEST_DIR\"\s*\)\s*,\s*)?\"([^\"]+)\""
)
# A second relevance filter would reopen the allowlist class this module closes.
_FOREIGN_FILTER = re.compile(r"\buses:\s*['\"]?dorny/paths-filter")


@dataclass(frozen=True)
class Changed:
    paths: tuple[str, ...]


@dataclass(frozen=True)
class Unknown:
    reason: str


Diff = Changed | Unknown


def glob_regex(pattern: str) -> re.Pattern[str]:
    """Compile a `**`/`*` path glob (`*` stays within one segment)."""
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def is_prose(path: str) -> bool:
    return path in PROSE_FILES or path.startswith(PROSE_DIRS)


def forces(scope: str, path: str) -> bool:
    """True when `path` changing obliges `scope`'s tiers to run."""
    if is_prose(path):
        return False
    if scope == "code" or not path.startswith(SCOPED_ROOTS):
        return True
    return any(glob_regex(p).match(path) for p in SCOPES[scope])


def scope_runs(scope: str, diff: Diff) -> bool:
    """Fail closed: only a readable, non-empty, fully-irrelevant diff skips."""
    if isinstance(diff, Unknown) or not diff.paths:
        return True
    return any(forces(scope, p) for p in diff.paths)


def git(root: str, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", root, *args], check=True, capture_output=True
    ).stdout


def diff_paths(root: str, base: str, head: str) -> tuple[str, ...]:
    raw = git(root, "diff", "--no-renames", "-z", "--name-only", base, head)
    return tuple(p.decode("utf-8") for p in raw.split(b"\0") if p)


def read_diff(root: str, env: dict[str, str]) -> Diff:
    event = env.get("EVENT_NAME", "")
    if event == "pull_request":
        parents = git(root, "rev-list", "--parents", "-n1", "HEAD").decode().split()[1:]
        pr_head = env.get("PR_HEAD_SHA", "")
        if len(parents) != 2 or not pr_head or parents[1] != pr_head:
            return Unknown("tested commit is not the base + PR-head merge commit")
        return Changed(diff_paths(root, "HEAD^1", "HEAD"))
    if event == "merge_group":
        base = env.get("MERGE_GROUP_BASE_SHA", "")
        if not base:
            return Unknown("merge_group without a base sha")
        return Changed(diff_paths(root, base, "HEAD"))
    return Unknown(f"event {event!r} runs every scope")


def classify(root: str, env: dict[str, str], scopes: Sequence[str]) -> dict[str, bool]:
    unknown = [s for s in scopes if s not in SCOPES]
    if unknown:
        raise ValueError(f"unknown scope(s): {', '.join(unknown)}")
    try:
        diff = read_diff(root, env)
    except Exception as err:  # noqa: BLE001 — any failure must run every scope.
        diff = Unknown(f"classifier error: {err}")
    if isinstance(diff, Unknown):
        print(f"change_class: {diff.reason} — every scope runs", file=sys.stderr)
    return {s: scope_runs(s, diff) for s in scopes}


# ── Guard: the PROSE set is provably unread ──────────────────────────────────


def _covers(entry: str, path: str) -> bool:
    """`entry` (a PROSE file or dir) and `path` overlap either way."""
    if entry.endswith("/"):
        return path.startswith(entry) or entry.startswith(path.rstrip("/") + "/")
    return path == entry or entry.startswith(path.rstrip("/") + "/")


def prose_entries() -> tuple[str, ...]:
    return tuple(sorted(PROSE_FILES)) + PROSE_DIRS


def _overlaps_prose(path: str) -> str | None:
    return next((e for e in prose_entries() if _covers(e, path)), None)


def _norm(path: str) -> str | None:
    """Normalize a repo-relative path; None when it escapes the repository."""
    parts: list[str] = []
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(seg)
    return "/".join(parts)


def _crate_dir(path: str, crate_dirs: frozenset[str]) -> str:
    d = os.path.dirname(path)
    while d and d not in crate_dirs:
        d = os.path.dirname(d)
    return d


def _is_comment(line: str) -> bool:
    s = line.lstrip()
    return s.startswith(("//", "#", "*", "--", "/*", "<!--"))


def _prose_tokens() -> tuple[str, ...]:
    return tuple(sorted(PROSE_FILES)) + tuple(d.rstrip("/") for d in PROSE_DIRS)


def guard(root: str, tracked: Iterable[str]) -> list[str]:
    """Every reason the PROSE set is not provably unread (empty when sound)."""
    files = sorted(set(tracked))
    errors: list[str] = []

    for path in CI_CONSUMED:
        if (e := _overlaps_prose(path)) is not None:
            errors.append(f"CI-consumed path {path!r} overlaps PROSE entry {e!r}")

    crate_dirs = frozenset(
        os.path.dirname(f) for f in files if os.path.basename(f) == "Cargo.toml"
    )
    for d in sorted(crate_dirs):
        if d and (e := _overlaps_prose(d + "/")) is not None:
            errors.append(f"crate {d!r} overlaps PROSE entry {e!r}")

    for f in files:
        if is_prose(f) and f not in PROSE_FILES and not f.endswith(PROSE_SUFFIXES):
            errors.append(f"{f!r} under PROSE is not a prose file type {PROSE_SUFFIXES}")

    for pattern_scope, patterns in SCOPES.items():
        for p in patterns:
            if not p.startswith(SCOPED_ROOTS + ("**/",)):
                errors.append(f"scope {pattern_scope!r} pattern {p!r} lies outside SCOPED_ROOTS")
            elif not any(glob_regex(p).match(f) for f in files):
                errors.append(f"scope {pattern_scope!r} pattern {p!r} matches no tracked file")

    tokens = _prose_tokens()
    token_res = [(t, re.compile(r"(?<![\w.-])" + re.escape(t) + r"(?![\w-])")) for t in tokens]
    for f in files:
        if f in SELF_FILES or is_prose(f) or not f.endswith(CODE_SUFFIXES):
            continue
        try:
            with open(os.path.join(root, f), encoding="utf-8") as fh:
                text = fh.read()
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        base_dir = os.path.dirname(f)
        crate = _crate_dir(f, crate_dirs)
        for lineno, line in enumerate(text.splitlines(), 1):
            if _is_comment(line):
                continue
            for m in _INCLUDE.finditer(line):
                arg = m.group(1)
                if arg.startswith("$CARGO_MANIFEST_DIR"):
                    target = _norm(os.path.join(crate, arg[len("$CARGO_MANIFEST_DIR"):].lstrip("/")))
                elif "CARGO_MANIFEST_DIR" in m.group(0):
                    target = _norm(os.path.join(crate, arg.lstrip("/")))
                else:
                    target = _norm(os.path.join(base_dir, arg))
                if target is not None and (e := _overlaps_prose(target)) is not None:
                    errors.append(f"{f}:{lineno}: includes {target!r}, which overlaps PROSE entry {e!r}")
            if f.startswith(".github/") and _FOREIGN_FILTER.search(line):
                errors.append(f"{f}:{lineno}: path filter outside change_class.py — classify through it")
            for assertion in drift_assertion.in_shell(line):
                for arg in assertion.paths:
                    target = _norm(arg)
                    if target is not None and (e := _overlaps_prose(target + "/" if arg.endswith("/") else target)) is not None:
                        errors.append(f"{f}:{lineno}: drift check reads {arg!r}, which overlaps PROSE entry {e!r}")
            for token, token_re in token_res:
                if token_re.search(line):
                    errors.append(f"{f}:{lineno}: names PROSE entry {token!r} — a reader makes it non-prose")
    return errors


def tracked_files(root: str) -> list[str]:
    raw = git(root, "ls-files", "-z")
    return [p.decode("utf-8") for p in raw.split(b"\0") if p]


def scope_flags(argv: Sequence[str]) -> tuple[str, ...] | None:
    """The scopes `argv` names as `--SCOPE` flags, or None unless every word is
    the flag of a distinct known scope and there is at least one."""
    by_flag = {"--" + s.replace("_", "-"): s for s in SCOPES}
    scopes = tuple(by_flag.get(a, "") for a in argv)
    if not scopes or "" in scopes or len(set(scopes)) != len(scopes):
        return None
    return scopes


def main(argv: Sequence[str]) -> int:
    scopes = scope_flags(argv)
    if scopes is None:
        print(__doc__, file=sys.stderr)
        return 2
    root = git(".", "rev-parse", "--show-toplevel").decode().strip()
    result = classify(root, dict(os.environ), scopes)
    lines = [f"{s}={'true' if runs else 'false'}" for s, runs in result.items()]
    print("\n".join(lines))
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as fh:
            fh.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
