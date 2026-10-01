#!/usr/bin/env python3
"""The one reader of a cargo invocation in CI shell text.

`parse` reads the words after `cargo` into a `CargoInvocation`: its
`+toolchain`, its global options (`-C` included), its subcommand (aliases
resolved, `nextest run` as one), and the package and target selection of a
compiling subcommand. It refuses, never skips, an option it does not know, an
unknown subcommand (an alias from a cargo config could compile anything), and
an operand a subcommand does not take.

`in_shell` finds every cargo invocation in shell text and the directory it
runs in. It follows `cd`/`pushd` (a `cd` inside a subshell stays there), the
wrappers `env`, `timeout`, `nice`, `nohup`, `time`, `command`, `exec` and
`stdbuf`, a `sh -c`/`bash -c` body and an `eval` argument; a `cargo` word
under any other command is refused. A directory it cannot know statically (a
computed `cd "$dir"`, an absolute path outside the checkout, `cd -`, `popd`)
is `None`.

`select` resolves an invocation, its directory, and the workspace `Layout`
into the `Selection` cargo builds: named packages, the package a member
directory defaults to, the whole root workspace (a bare invocation at the
virtual root, or `--workspace`), or bins picked by `--bin`.

A compiling invocation also carries its `--target` triple, its feature set
(`-F`/`--features`, comma- or space-separated, repeats unioned; an empty list
is refused), `--all-features`, `--no-default-features`, and its
`TargetSelection`: `DefaultTargets` when no target-kind option is given, else
`ExplicitTargets` naming the lib, the `--test` names, and whether every test
target (`--tests`, `--all-targets`) or any other kind is picked.

Callers: `verify-manifest` check 15 (only one job builds `ipe`), check 16
(a path-scoped job's scope covers what it compiles) and check 20 (every
non-host test cell is run by the job that claims it).
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass

import shell_lex

# The expression GitHub substitutes before the shell runs: the checkout root.
_WORKSPACE_EXPR = re.compile(r"\$\{\{\s*github\.workspace\s*\}\}")
_ANY_EXPR = re.compile(r"\$\{\{.*?\}\}", re.S)
_WORKSPACE_VARS = ("$GITHUB_WORKSPACE", "${GITHUB_WORKSPACE}")
# How deep `sh -c` / `eval` bodies nest before the text is refused.
NESTING_LIMIT = 8

# cargo's global options.
_GLOBAL_FLAGS = frozenset(
    {"-q", "--quiet", "-v", "-vv", "--verbose", "--locked", "--offline", "--frozen", "-V", "--version", "--list", "-h", "--help"}
)
_GLOBAL_VALUED = frozenset({"--config", "-Z", "-C", "--color", "--explain"})

_ALIASES = {"b": "build", "c": "check", "t": "test", "r": "run", "d": "doc"}
# Subcommands that read the package selection and compile it.
COMPILING = frozenset(
    {"build", "check", "clippy", "test", "run", "rustc", "doc", "bench", "install", "package", "publish",
     "nextest run", "nextest archive", "nextest list"}
)
# Subcommands that compile nothing; their arguments are not read.
_INERT = frozenset(
    {"fmt", "fetch", "update", "deny", "audit", "tree", "metadata", "generate-lockfile", "locate-project",
     "pkgid", "search", "version", "help", "clean", "vendor", "verify-project", "owner", "yank", "login",
     "logout", "init", "new", "add", "remove", "info", "report", "config"}
)

# Options every compiling subcommand takes.
_SELECT_VALUED = frozenset({"-p", "--package", "--exclude", "--manifest-path", "--bin", "--example", "--test", "--bench"})
_COMMON_VALUED = _SELECT_VALUED | frozenset(
    {"-F", "--features", "--target", "--target-dir", "--profile", "-j", "--jobs", "--message-format",
     "--color", "--config", "-Z", "--lockfile-path", "--artifact-dir"}
)
_COMMON_FLAGS = frozenset(
    {"--workspace", "--all", "--bins", "--lib", "--examples", "--tests", "--benches", "--all-targets", "--doc",
     "--release", "-r", "--locked", "--offline", "--frozen", "-q", "--quiet", "-v", "-vv", "--verbose",
     "--no-default-features", "--all-features", "--keep-going", "--future-incompat-report",
     "--ignore-rust-version", "--timings", "-h", "--help"}
)
_NEXTEST_VALUED = frozenset(
    {"--archive-file", "--workspace-remap", "--partition", "-P", "--test-threads", "--no-tests", "-E",
     "--filterset", "--filter-expr", "--retries", "--cargo-profile", "--run-ignored", "--failure-output",
     "--success-output", "--status-level", "--final-status-level", "--tool-config-file", "--build-jobs",
     "--max-fail", "--show-progress", "--archive-format", "--zstd-level", "--binaries-metadata",
     "--cargo-metadata", "--target-dir-remap", "--extract-to", "--cargo-message-format", "--user-config-file"}
)
_NEXTEST_FLAGS = frozenset(
    {"--no-fail-fast", "--fail-fast", "--no-capture", "--nocapture", "--hide-progress-bar", "--cargo-quiet",
     "--cargo-verbose", "--ignore-default-filter", "--no-output-indent", "--extract-overwrite",
     "--persist-extract-tempdir"}
)
# Per subcommand: extra valued options, extra flags, and what an operand is
# ("filter": a test-name filter; "args": the program's arguments start;
# "crate": a crate to install; None: refused). After `--` nothing is read.
_SUBCOMMANDS: dict[str, tuple[frozenset[str], frozenset[str], str | None]] = {
    "build": (frozenset(), frozenset(), None),
    "check": (frozenset(), frozenset(), None),
    "clippy": (frozenset(), frozenset({"--fix", "--allow-dirty", "--allow-staged", "--no-deps"}), None),
    "test": (frozenset(), frozenset({"--no-run", "--no-fail-fast"}), "filter"),
    "bench": (frozenset(), frozenset({"--no-run", "--no-fail-fast"}), "filter"),
    "run": (frozenset(), frozenset(), "args"),
    "rustc": (frozenset({"--crate-type", "--print"}), frozenset(), None),
    "doc": (frozenset(), frozenset({"--open", "--no-deps", "--document-private-items"}), None),
    "install": (
        frozenset({"--path", "--git", "--branch", "--tag", "--rev", "--version", "--vers", "--root", "--registry", "--index"}),
        frozenset({"--force", "-f", "--list", "--no-track", "--debug"}),
        "crate",
    ),
    "package": (frozenset({"--registry", "--index"}), frozenset({"--no-verify", "--allow-dirty", "--list", "-l"}), None),
    "publish": (frozenset({"--registry", "--index", "--token"}), frozenset({"--no-verify", "--allow-dirty", "--dry-run"}), None),
    "nextest run": (_NEXTEST_VALUED, _NEXTEST_FLAGS, "filter"),
    "nextest archive": (_NEXTEST_VALUED, _NEXTEST_FLAGS, None),
    "nextest list": (_NEXTEST_VALUED, _NEXTEST_FLAGS, "filter"),
}


@dataclass(frozen=True)
class DefaultTargets:
    """No target-kind option: cargo picks its default targets (for `test`,
    the lib, every test target, bins and examples)."""

    def selects(self, target: str) -> bool:
        """Whether `target` (`lib`, or `test:<name>`) is among these."""
        return target == "lib" or (target.startswith("test:") and len(target) > len("test:"))


@dataclass(frozen=True)
class ExplicitTargets:
    """The target kinds named on the command line."""

    lib: bool = False
    tests: frozenset[str] = frozenset()
    all_tests: bool = False
    other: bool = False

    def selects(self, target: str) -> bool:
        """Whether `target` (`lib`, or `test:<name>`) is among these."""
        if target == "lib":
            return self.lib
        name = target.removeprefix("test:")
        return name != target and (self.all_tests or name in self.tests)


TargetSelection = DefaultTargets | ExplicitTargets

# Target-kind options: each flips `ExplicitTargets` on.
_KIND_FLAGS = frozenset({"--lib", "--tests", "--all-targets", "--bins", "--examples", "--benches", "--doc"})
_KIND_VALUED = frozenset({"--test", "--bin", "--example", "--bench"})
_FEATURE_SPLIT = re.compile(r"[,\s]+")


@dataclass(frozen=True)
class CargoInvocation:
    """One `cargo` command. `subcommand` is its canonical name (`""` for a
    bare `cargo --version`); the selection fields are empty unless it is
    `COMPILING`."""

    command: str
    toolchain: str | None
    directory: str | None
    subcommand: str
    packages: tuple[str, ...] = ()
    workspace: bool = False
    bins: tuple[str, ...] = ()
    manifest_path: str | None = None
    install_crates: tuple[str, ...] = ()
    install_path: str | None = None
    target: str | None = None
    features: frozenset[str] = frozenset()
    all_features: bool = False
    no_default_features: bool = False
    selection: TargetSelection = DefaultTargets()
    filtered: bool = False
    no_run: bool = False


def _option(word: str, valued: frozenset[str], flags: frozenset[str]) -> tuple[str, str | None, bool] | None:
    """`word` as (option, joined value, takes the next word), or None when it
    is no known option."""
    if word.startswith("--") and "=" in word:
        name, value = word.split("=", 1)
        if name in valued or name in flags:
            return name, value, False
        return None
    if word in valued:
        return word, None, True
    if word in flags:
        return word, None, False
    if not word.startswith("--") and len(word) > 2 and word[:2] in valued:
        return word[:2], word[2:].removeprefix("="), False
    return None


def parse(words: Sequence[str]) -> CargoInvocation | str:
    """The invocation `words` (starting after `cargo`) spell, or why it is
    refused."""
    command = " ".join(["cargo", *words])
    i, n = 0, len(words)
    toolchain = directory = None
    if i < n and words[i].startswith("+"):
        toolchain, i = words[i][1:], i + 1
    while i < n and words[i].startswith("-"):
        got = _option(words[i], _GLOBAL_VALUED, _GLOBAL_FLAGS)
        if got is None:
            return f"`{command}`: global option {words[i]!r} is not one this check reads"
        name, value, takes = got
        if takes:
            if i + 1 >= n:
                return f"`{command}`: {name} lacks its value"
            value, i = words[i + 1], i + 2
        else:
            i += 1
        if name == "-C":
            directory = value
    if i >= n:
        return CargoInvocation(command, toolchain, directory, "")
    sub = _ALIASES.get(words[i], words[i])
    i += 1
    if sub == "nextest":
        if i < n and words[i] in ("run", "archive", "list", "r"):
            sub, i = "nextest " + ("run" if words[i] == "r" else words[i]), i + 1
        elif i < n and words[i] in ("--version", "-V", "--help", "-h", "help", "self", "show-config"):
            return CargoInvocation(command, toolchain, directory, "nextest")
        else:
            return f"`{command}`: a nextest subcommand this check does not read"
    if sub in _INERT:
        return CargoInvocation(command, toolchain, directory, sub)
    spec = _SUBCOMMANDS.get(sub)
    if spec is None:
        return f"`{command}`: subcommand {sub!r} is not one this check reads (a cargo alias could compile anything)"
    extra_valued, extra_flags, operand = spec
    valued, flags = _COMMON_VALUED | extra_valued, _COMMON_FLAGS | extra_flags
    packages: list[str] = []
    bins: list[str] = []
    crates: list[str] = []
    workspace = False
    manifest = install_path = target = None
    filtered = all_features = no_default_features = no_run = explicit = False
    features: set[str] = set()
    lib = all_tests = other = False
    tests: set[str] = set()
    while i < n:
        w = words[i]
        if w == "--":
            break
        if not w.startswith("-") or w == "-":
            if operand == "args":
                break
            if operand == "crate":
                crates.append(w)
            elif operand == "filter" and not filtered:
                filtered = True
            else:
                return f"`{command}`: operand {w!r} is not one `cargo {sub}` takes"
            i += 1
            continue
        got = _option(w, valued, flags)
        if got is None:
            return f"`{command}`: option {w!r} is not one this check reads for `cargo {sub}`"
        name, value, takes = got
        if takes:
            if i + 1 >= n:
                return f"`{command}`: {name} lacks its value"
            value, i = words[i + 1], i + 2
        else:
            i += 1
        if name in ("-p", "--package"):
            packages.append(value or "")
        elif name in ("--workspace", "--all"):
            workspace = True
        elif name == "--bin":
            bins.append(value or "")
        elif name == "--manifest-path":
            manifest = value
        elif name == "--path":
            install_path = value
        elif name == "--target":
            if not value:
                return f"`{command}`: --target lacks its value"
            if target is not None and target != value:
                return f"`{command}`: more than one --target, which this check does not read"
            target = value
        elif name in ("-F", "--features"):
            named = {f for f in _FEATURE_SPLIT.split(value or "") if f}
            if not named:
                return f"`{command}`: {name} names no feature"
            features |= named
        elif name == "--all-features":
            all_features = True
        elif name == "--no-default-features":
            no_default_features = True
        elif name == "--no-run":
            no_run = True
        if name in _KIND_FLAGS or name in _KIND_VALUED:
            explicit = True
            if name == "--lib":
                lib = True
            elif name == "--test":
                if not value:
                    return f"`{command}`: --test lacks its value"
                tests.add(value)
            elif name == "--tests":
                all_tests = True
            elif name == "--all-targets":
                lib = all_tests = other = True
            else:
                other = True
    selection: TargetSelection = (
        ExplicitTargets(lib, frozenset(tests), all_tests, other) if explicit else DefaultTargets()
    )
    return CargoInvocation(
        command, toolchain, directory, sub, tuple(packages), workspace, tuple(bins), manifest, tuple(crates),
        install_path, target, frozenset(features), all_features, no_default_features, selection, filtered, no_run,
    )


def resolve(cwd: str | None, path: str) -> str | None:
    """`path` taken from repo-relative `cwd` as a normalized repo-relative
    path (`""` the root), or None when it is not statically inside the
    checkout."""
    for var in _WORKSPACE_VARS:
        if path == var or path.startswith(var + "/"):
            cwd, path = "", path[len(var) :].lstrip("/") or "."
            break
    if cwd is None or not path or path.startswith(("/", "~")) or any(c in path for c in "$`*?["):
        return None
    joined = posixpath.normpath(posixpath.join(cwd or ".", path))
    if joined == ".." or joined.startswith("../"):
        return None
    return "" if joined == "." else joined


@dataclass(frozen=True)
class Found:
    """One cargo invocation (or the refusal of one) and the directory it runs
    in."""

    line: str
    invocation: CargoInvocation | str
    cwd: str | None


# Leading words that are shell syntax, not the command.
_RESERVED = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "time"})
# Commands whose arguments are data, never a command they run.
_DATA = frozenset({"echo", "printf", ":", "true", "false", "test", "[", "[[", "which", "type", "hash"})
_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh"})
# Wrappers that run their operand as a command: each maps to its valued options.
_WRAPPERS: dict[str, frozenset[str]] = {
    "env": frozenset({"-u", "--unset"}),
    "timeout": frozenset({"-s", "--signal", "-k", "--kill-after"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "nohup": frozenset(),
    "command": frozenset(),
    "exec": frozenset({"-a"}),
    "stdbuf": frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}),
}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _head(words: list[str]) -> list[str]:
    i = 0
    while i < len(words) and (words[i] in _RESERVED or _ASSIGNMENT.match(words[i])):
        i += 1
    return words[i:]


def _unwrap(words: list[str]) -> tuple[str, list[str]] | str:
    """The command `words` run once wrappers are peeled, as (kind, words):
    `cargo` (the words after it), `shell` (a body to read as shell), `cd`,
    `opaque-cd`, `data`, `none`; or a refusal."""
    words = _head(words)
    while words:
        head, rest = posixpath.basename(words[0]), words[1:]
        if head == "cargo":
            return "cargo", rest
        if head in ("cd", "pushd"):
            args = [w for w in rest if w not in ("-L", "-P", "-e", "-@", "--")]
            return ("cd", args[:1]) if args and args[0] != "-" else ("opaque-cd", [])
        if head == "popd":
            return "opaque-cd", []
        if head in _DATA or (head == "command" and rest[:1] in (["-v"], ["-V"])):
            return "data", []
        if head == "eval":
            return "shell", [" ".join(rest)]
        if head in _SHELLS:
            j = 0
            has_c = False
            while j < len(rest) and rest[j].startswith(("-", "+")) and rest[j] != "--":
                if rest[j] in ("-o", "+o", "-O", "+O"):
                    j += 1
                elif not rest[j].startswith("--") and "c" in rest[j][1:]:
                    has_c = True
                j += 1
            if has_c:
                return ("shell", rest[j : j + 1]) if j < len(rest) else f"`{' '.join(words)}` lacks its -c body"
            return "none", rest
        if head in _WRAPPERS:
            if head == "env" and any(w in ("-C", "--chdir", "-S", "--split-string") or w.startswith(("--chdir=", "--split-string=")) for w in rest):
                return f"`{' '.join(words)}` changes the directory or splits a string, which this check does not read"
            valued = _WRAPPERS[head]
            j = 0
            while j < len(rest) and rest[j].startswith("-") and rest[j] != "-":
                j += 2 if rest[j] in valued else 1
            if head == "timeout":
                j += 1
            words = _head(rest[j:])
            continue
        return "none", rest
    return "none", []


def in_shell(text: str, cwd: str | None = "", depth: int = 0) -> Iterator[Found]:
    """Every cargo invocation in shell `text` run from `cwd`, with its own
    directory. GitHub expressions are substituted as the runner does before
    the shell sees the text."""
    text = _WORKSPACE_EXPR.sub("$GITHUB_WORKSPACE", text)
    text = _ANY_EXPR.sub("$GITHUB_EXPRESSION", text)
    dirs: dict[tuple[int, ...], str | None] = {(): cwd}
    for cmd in shell_lex.split_commands(text):
        scope = cmd.subshell
        here = next(dirs[scope[:k]] for k in range(len(scope), -1, -1) if scope[:k] in dirs)
        line = " ".join(cmd.words)
        got = _unwrap(cmd.words)
        if isinstance(got, str):
            yield Found(line, got, here)
            continue
        kind, rest = got
        if kind == "cargo":
            yield Found(line, parse(rest), here)
        elif kind == "cd":
            dirs[scope] = resolve(here, rest[0])
        elif kind == "opaque-cd":
            dirs[scope] = None
        elif kind == "shell":
            if depth >= NESTING_LIMIT:
                yield Found(line, f"`{line}` nests shell bodies past {NESTING_LIMIT} levels", here)
            elif rest:
                yield from in_shell(rest[0], here, depth + 1)
        elif kind == "none" and any(posixpath.basename(w) == "cargo" for w in rest):
            yield Found(line, f"`{line}` runs `cargo` through a command this check cannot read", here)


@dataclass(frozen=True)
class Layout:
    """The root workspace: its member directories, every directory holding a
    tracked `Cargo.toml`, whether the root manifest is virtual with no
    `default-members` (so a bare invocation there builds every member), every
    directory holding a tracked file, and `output_dir`, which says whether
    the checkout's ignore rules reserve a directory's `Cargo.toml` for build
    output."""

    members: frozenset[str]
    manifests: frozenset[str]
    root_selects_all: bool
    held: frozenset[str] = frozenset()
    output_dir: Callable[[str], bool] = lambda _d: False


def layout(
    root_manifest: dict, tracked: Sequence[str], output_dir: Callable[[str], bool] = lambda _d: False
) -> Layout:
    """The `Layout` of a parsed root `Cargo.toml` and the tracked paths."""
    ws = root_manifest.get("workspace")
    members = ws.get("members") if isinstance(ws, dict) else None
    literal = frozenset(m for m in members or [] if isinstance(m, str))
    manifests = frozenset(
        posixpath.dirname(p) for p in tracked if posixpath.basename(p) == "Cargo.toml"
    )
    selects_all = isinstance(ws, dict) and "package" not in root_manifest and "default-members" not in ws
    held: set[str] = {""}
    for p in tracked:
        d = posixpath.dirname(p)
        while d and d not in held:
            held.add(d)
            d = posixpath.dirname(d)
    return Layout(literal, manifests, selects_all, frozenset(held), output_dir)


@dataclass(frozen=True)
class Selection:
    """What one invocation compiles in the root workspace: the `-p` specs it
    names, the member directories it defaults to, every member
    (`whole_workspace`), or the members owning `bins`. `in_workspace` is
    False when its manifest is not statically one of the root workspace's;
    `known` is False when where its manifest lies is not known at all (a
    run-time directory or `--manifest-path`)."""

    packages: tuple[str, ...]
    dirs: tuple[str, ...]
    whole_workspace: bool
    bins: tuple[str, ...]
    in_workspace: bool
    known: bool = True


def _manifest_dir(layout: Layout, start: str | None) -> str | None:
    """The directory of the manifest cargo finds from `start` upward, when it
    is the root's or a member's; else None. A directory the checkout does not
    hold and whose `Cargo.toml` is reserved for build output (an emitted
    crate) holds a manifest generated at run time, not one of the root's."""
    d = start
    while d is not None:
        if d in layout.manifests:
            return d if d == "" or d in layout.members else None
        if d == "":
            return None
        if d not in layout.held and layout.output_dir(d):
            return None
        d = posixpath.dirname(d)
    return None


def select(inv: CargoInvocation, cwd: str | None, layout: Layout) -> Selection | str:
    """The `Selection` `inv` compiles when run in `cwd`, or why it is refused."""
    here = cwd if inv.directory is None else resolve(cwd, inv.directory)
    if inv.manifest_path is not None:
        path = resolve(here, inv.manifest_path)
        if path is not None and posixpath.basename(path) != "Cargo.toml":
            return f"`{inv.command}`: --manifest-path {inv.manifest_path!r} names no Cargo.toml"
        mdir = None
        if path is not None:
            d = posixpath.dirname(path)
            mdir = d if d in layout.manifests and (d == "" or d in layout.members) else None
        known = path is not None
    else:
        mdir = _manifest_dir(layout, here)
        known = here is not None
    packages, bins = inv.packages, inv.bins
    if mdir is None:
        return Selection(packages, (), False, bins, False, known)
    if packages:
        return Selection(packages, (), False, bins, True)
    if inv.workspace or (mdir == "" and not bins):
        if not layout.root_selects_all and not inv.workspace:
            return f"`{inv.command}`: the root manifest has a package or `default-members`, so what a bare invocation builds is not read"
        return Selection((), (), True, bins, True)
    if mdir == "":
        return Selection((), (), False, bins, True)
    return Selection((), (mdir,), False, bins, True)
