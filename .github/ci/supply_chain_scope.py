#!/usr/bin/env python3
"""Prove the dependency scan judges every registry crate the release build links.

`deny.toml [graph]` names the graph `cargo deny` judges; the release build
(`release_build`) names the graph that ships. This script derives the
release's registry crates `R` from `cargo tree` with exactly the release
features and packages, writes a temporary config that is `deny.toml`
verbatim except for a `[bans]` table banning each crate of `R` by exact
version, runs `cargo deny check bans` on it, and refuses unless every crate of
`R` is reported banned — a crate the judged graph omits is never reported, so
an omission is a refusal, never a silent pass.

Exit 0: covered. Exit 1: a scope gap (a release crate the scan never judges,
or no crate judged at all). Exit 2: a tool or input failure (the release
graph empty or missing its sentinel, a child over its time or output ceiling,
an unexpected exit, an unparseable line). Every outcome other than covered is
a refusal; no failure mode passes.
"""

from __future__ import annotations

import enum
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11 (a local run); CI's runner has tomllib
    import tomli as tomllib  # type: ignore[no-redef]

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import release_build  # noqa: E402  # the release feature set and packages

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The release-only crate whose absence from `R` means the release graph lost
# its release feature (the embedded wasm engine `wasi_run` pulls in).
SENTINEL_CRATE = "wasmtime"

# Each child's ceilings: the wall-clock seconds it may run and the bytes it
# may write to each of stdout and stderr before it is killed.
CHILD_TIMEOUT_S = 900
CHILD_OUTPUT_CEILING = 64 * 1024 * 1024

# `cargo deny`'s exit code is a bitmask of the failed checks; bans is 2.
DENY_EXIT_BANS_FAILED = 2

# A `cargo tree --prefix none --format '{p}'` line: `name vVERSION`, then an
# optional ` (<source or path>)`, ` (proc-macro)` and the ` (*)` repeat mark.
_TREE_LINE_RE = re.compile(
    r"(?P<name>[A-Za-z0-9_-]+) v(?P<version>[0-9][0-9A-Za-z.+-]*)"
    r"(?P<path> \([^()]*\))?(?: \(proc-macro\))?(?: \(\*\))?"
)
# A path or git source in that parenthetical: not a registry crate.
_NON_REGISTRY_SOURCE_RE = re.compile(r" \((?:/|[A-Za-z]:\\|git\+|https?://)")
# The banned diagnostic's message: `crate 'name = version' is explicitly banned`.
_BANNED_MESSAGE_RE = re.compile(r"crate '(?P<name>[A-Za-z0-9_-]+) = (?P<version>[^']+)' is explicitly banned")


class ScopeErrorKind(enum.Enum):
    """Why the scope proof refused; `exit_code` separates gaps from failures."""

    NOT_COVERED = "a release crate is not in the judged graph"
    NO_BANNED = "cargo deny judged no release crate at all"
    EMPTY_RELEASE = "the release graph has no registry crate"
    NO_SENTINEL = "the release graph lacks its sentinel crate"
    TREE_LINE = "an unparseable cargo tree line"
    CONFIG = "the temporary config does not keep deny.toml's graph or ban R"
    TIMEOUT = "a child crossed its time ceiling"
    OUTPUT_CEILING = "a child crossed its output ceiling"
    TOOL_EXIT = "a child exited with an unexpected code"
    NOT_JSON = "a cargo deny output line is not a JSON object"
    NO_CODE = "a cargo deny diagnostic has no code"
    BAD_LABEL = "a banned diagnostic does not name a crate and version"

    @property
    def exit_code(self) -> int:
        """1 for a scope gap, 2 for a tool or input failure."""
        return 1 if self in (ScopeErrorKind.NOT_COVERED, ScopeErrorKind.NO_BANNED) else 2


class ScopeError(Exception):
    """A typed refusal: its kind and the detail naming what was refused."""

    def __init__(self, kind: ScopeErrorKind, detail: str) -> None:
        super().__init__(f"{kind.value}: {detail}")
        self.kind = kind
        self.detail = detail


@dataclass(frozen=True)
class RunResult:
    """One child's outcome; `returncode` is None when it was killed."""

    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    overflowed: bool = False


Runner = Callable[[Sequence[str], str], RunResult]
Crate = tuple[str, str]


def bounded_run(argv: Sequence[str], cwd: str) -> RunResult:
    """Run `argv` in `cwd` in its own process group, held to the child ceilings.

    A reader thread per stream stops at `CHILD_OUTPUT_CEILING`; crossing it,
    or `CHILD_TIMEOUT_S`, kills the whole group (cargo's own children too).
    """
    proc = subprocess.Popen(  # noqa: S603  # argv is built here, never a shell string
        list(argv),
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    overflow = threading.Event()

    def kill_group() -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def pump(stream, buf: bytearray) -> None:  # noqa: ANN001  # a binary pipe
        while chunk := stream.read1(1 << 16):
            if len(buf) + len(chunk) > CHILD_OUTPUT_CEILING:
                overflow.set()
                kill_group()
                break
            buf.extend(chunk)
        stream.close()

    out, err = bytearray(), bytearray()
    readers = [
        threading.Thread(target=pump, args=(proc.stdout, out), daemon=True),
        threading.Thread(target=pump, args=(proc.stderr, err), daemon=True),
    ]
    for t in readers:
        t.start()
    timed_out = False
    try:
        rc: int | None = proc.wait(timeout=CHILD_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill_group()
        proc.wait()
        rc = None
    for t in readers:
        t.join(timeout=30)
    if overflow.is_set():
        rc = None
    return RunResult(rc, bytes(out), bytes(err), timed_out=timed_out, overflowed=overflow.is_set())


def _checked(result: RunResult, what: str, ok_codes: tuple[int, ...]) -> RunResult:
    """`result`, or the typed refusal its ceiling or exit code names."""
    if result.timed_out:
        raise ScopeError(ScopeErrorKind.TIMEOUT, f"{what} ran past {CHILD_TIMEOUT_S}s")
    if result.overflowed:
        raise ScopeError(ScopeErrorKind.OUTPUT_CEILING, f"{what} wrote over {CHILD_OUTPUT_CEILING} bytes")
    if result.returncode not in ok_codes:
        tail = result.stderr.decode("utf-8", "replace")[-2000:]
        raise ScopeError(
            ScopeErrorKind.TOOL_EXIT,
            f"{what} exited {result.returncode}, expected one of {list(ok_codes)}:\n{tail}",
        )
    return result


def tree_argv() -> list[str]:
    """The `cargo tree` listing the release build's normal and build dependencies.

    The features and packages are read from `release_build` at call time, so
    the listing is the release command's graph, never a restated copy. Colour
    is off on the command line, so an ambient `CARGO_TERM_COLOR` cannot put
    escape codes into the lines `parse_tree` reads.
    """
    argv = ["cargo", "tree", "--color", "never", "--locked", "-e", "normal,build"]
    argv += ["--target", "all"]
    argv += ["--prefix", "none", "--format", "{p}", "--features", release_build.RELEASE_FEATURE]
    for pkg in release_build.RELEASE_PACKAGES:
        argv += ["-p", pkg]
    return argv


def fetch_argv() -> list[str]:
    """The locked download of the workspace graph's sources.

    `cargo deny` runs `--offline`, so it reads crate manifests from the local
    cache alone; this fetch fills that cache first, on every runner.
    """
    return ["cargo", "fetch", "--color", "never", "--locked"]


def deny_argv(manifest: str, config: str) -> list[str]:
    """The `cargo deny` bans check of `manifest` under `config` (cargo-deny 0.20 layout)."""
    return [
        "cargo",
        "deny",
        "--color",
        "never",
        "--manifest-path",
        manifest,
        "--config",
        config,
        "--locked",
        "--offline",
        "--format",
        "json",
        "check",
        "bans",
        "--hide-inclusion-graph",
    ]


def parse_tree(text: str) -> set[Crate]:
    """The registry crates of a `cargo tree` listing; path and git crates are dropped."""
    crates: set[Crate] = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        m = _TREE_LINE_RE.fullmatch(line)
        if m is None:
            raise ScopeError(ScopeErrorKind.TREE_LINE, repr(line))
        if m.group("path") and _NON_REGISTRY_SOURCE_RE.match(m.group("path")):
            continue
        crates.add((m.group("name"), m.group("version")))
    return crates


def release_crates(runner: Runner, root: str) -> set[Crate]:
    """`R`: the release build's registry crates, refused when empty or sentinel-less."""
    result = _checked(runner(tree_argv(), root), "cargo tree", (0,))
    crates = parse_tree(result.stdout.decode("utf-8", "replace"))
    if not crates:
        raise ScopeError(ScopeErrorKind.EMPTY_RELEASE, "cargo tree listed no registry crate")
    if not any(name == SENTINEL_CRATE for name, _ in crates):
        raise ScopeError(
            ScopeErrorKind.NO_SENTINEL,
            f"`{SENTINEL_CRATE}` is not in the release graph of `--features "
            f"{release_build.RELEASE_FEATURE}`; the release feature no longer reaches it",
        )
    return crates


def _table_spans(lines: list[str]) -> list[tuple[str, int, int]]:
    """Each table or array-of-tables header's name and its `[start, end)` line span."""
    heads = [
        (i, line.strip().lstrip("[").split("]", 1)[0].strip())
        for i, line in enumerate(lines)
        if line.lstrip().startswith("[")
    ]
    spans = []
    for k, (start, name) in enumerate(heads):
        end = heads[k + 1][0] if k + 1 < len(heads) else len(lines)
        spans.append((name, start, end))
    return spans


def scope_config(deny_text: str, crates: set[Crate]) -> str:
    """`deny_text` with its `[bans]` tables replaced by one banning each of `crates`.

    Every other table, `[graph]` included, is kept byte for byte: that graph
    is what the proof judges. The result is re-parsed and refused unless its
    graph equals the input's and its bans are exactly `crates`.
    """
    try:
        original = tomllib.loads(deny_text)
    except tomllib.TOMLDecodeError as e:
        raise ScopeError(ScopeErrorKind.CONFIG, f"deny.toml does not parse: {e}") from e
    lines = deny_text.splitlines(keepends=True)
    drop = {
        i
        for name, start, end in _table_spans(lines)
        if name == "bans" or name.startswith("bans.")
        for i in range(start, end)
    }
    kept = "".join(line for i, line in enumerate(lines) if i not in drop)
    if not kept.endswith("\n"):
        kept += "\n"
    bans = ['\n[bans]\n', 'multiple-versions = "allow"\n', 'wildcards = "allow"\n', "deny = [\n"]
    bans += [f'    {{ crate = "{name}@{version}" }},\n' for name, version in sorted(crates)]
    bans.append("]\n")
    text = kept + "".join(bans)
    try:
        derived = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ScopeError(ScopeErrorKind.CONFIG, f"the derived config does not parse: {e}") from e
    if derived.get("graph") != original.get("graph"):
        raise ScopeError(ScopeErrorKind.CONFIG, "the derived config's [graph] differs from deny.toml's")
    denied = {tuple(e["crate"].split("@", 1)) for e in derived["bans"]["deny"]}
    if denied != crates or set(derived["bans"]) != {"multiple-versions", "wildcards", "deny"}:
        raise ScopeError(ScopeErrorKind.CONFIG, "the derived [bans] is not exactly the release ban list")
    return text


def banned_crates(stderr: bytes) -> set[Crate]:
    """The crates `cargo deny --format json` reported banned, every line parsed strictly."""
    banned: set[Crate] = set()
    for raw in stderr.decode("utf-8", "replace").splitlines():
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ScopeError(ScopeErrorKind.NOT_JSON, repr(raw[:200])) from e
        if not isinstance(obj, dict):
            raise ScopeError(ScopeErrorKind.NOT_JSON, repr(raw[:200]))
        if obj.get("type") != "diagnostic":
            continue
        fields = obj.get("fields")
        code = fields.get("code") if isinstance(fields, dict) else None
        if not isinstance(code, str):
            raise ScopeError(ScopeErrorKind.NO_CODE, repr(raw[:200]))
        if code != "banned":
            continue
        message = fields.get("message")
        m = _BANNED_MESSAGE_RE.fullmatch(message) if isinstance(message, str) else None
        if m is None:
            raise ScopeError(ScopeErrorKind.BAD_LABEL, repr(message))
        banned.add((m.group("name"), m.group("version")))
    return banned


def prove_scope(runner: Runner, root: str = REPO_ROOT) -> set[Crate]:
    """`R` when every crate of it is judged by `root`'s `deny.toml` graph; else a `ScopeError`."""
    crates = release_crates(runner, root)
    with open(os.path.join(root, "deny.toml"), encoding="utf-8") as f:
        config = scope_config(f.read(), crates)
    with tempfile.TemporaryDirectory(prefix="supply-chain-scope-") as tmp:
        config_path = os.path.join(tmp, "deny.toml")
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(config)
        _checked(runner(fetch_argv(), root), "cargo fetch", (0,))
        argv = deny_argv(os.path.join(root, "Cargo.toml"), config_path)
        result = _checked(runner(argv, tmp), "cargo deny check bans", (DENY_EXIT_BANS_FAILED,))
    banned = banned_crates(result.stderr)
    if not banned:
        raise ScopeError(ScopeErrorKind.NO_BANNED, "cargo deny reported no banned crate")
    missing = sorted(crates - banned)
    if missing:
        named = ", ".join(f"{n}@{v}" for n, v in missing[:20])
        more = f" (+{len(missing) - 20} more)" if len(missing) > 20 else ""
        raise ScopeError(
            ScopeErrorKind.NOT_COVERED,
            f"{len(missing)} release crate(s) the scan never judges: {named}{more}",
        )
    return crates


def main() -> int:
    try:
        crates = prove_scope(bounded_run)
    except ScopeError as e:
        print(f"supply-chain-scope: REFUSED — {e}", file=sys.stderr)
        return e.kind.exit_code
    print(
        f"supply-chain-scope: OK — all {len(crates)} registry crates of the release build "
        f"(`--features {release_build.RELEASE_FEATURE}`) are in the judged graph"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
