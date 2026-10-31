#!/usr/bin/env python3
"""Typed `local:` dispositions of `check-manifest.yml`: the local gate's SSOT.

Every `gate` entry of the manifest declares exactly one local disposition:

  local: {tier: quick|affected|full, run: [<command>, ...], complete: true}
      The gate is reproduced locally by these commands. Tiers nest:
      `affected` runs every `quick` command too, `full` runs all three.
      The optional `complete: true` also holds the converse: every command
      line CI runs for the gate has a token-equal local twin.
  local: {covered-by: <gate context>}
      Another gate's local commands already exercise this one (a matrix slice
      of a wider suite). The target must itself declare `run`.
  local: {ci-only: <reason>}
      No local reproduction exists; the reason is one of `CI_ONLY_REASONS`.

A `<command>` is a string, or a mapping with `cmd` (required), `env`, `cwd`,
`differs`, `tier` and `package`. Its text may use the closed set of
`PLACEHOLDERS`. Unless the command carries `differs: <reason>`, it must equal,
token for token (after the placeholders take their CI values and
`CI_ONLY_FLAGS` are dropped), one command line of a `run:` step in the
producing job (or a job it `aggregates`), with the same `working-directory`;
every declared `env` entry must equal the CI value visible to that step. A
`differs` command is exempt from the token match only; its `env` and `cwd` are
still verified. So the local gate cannot run a command CI does not run, and CI
cannot change a mirrored command without the manifest guard going red.

A command's own `tier` overrides the gate's declared `tier` for that one
command (a command cheap enough to run earlier than the rest of its job's
mirror, e.g. a crate's own tests promoted to `quick` inside an otherwise
`affected` gate). A command's `package` skips it unless that crate owns a
changed file, reusing the same `Selection` the `{packages}` placeholder
expands from — never a second, hand-rolled path matcher — so a change outside
that crate (or outside every crate, which conservatively selects all of them)
decides whether the command runs at all, not just which crates it is `-p`'d
over.

LIMIT: without `complete: true` the match is one-directional. A new CI step
with no `local:` twin is not detected; the `local:` block of that gate must be
extended by hand. A gate whose CI job runs only commands the gate mirrors
declares `complete: true`, so CI and the local gate are one set.

`tools/scripts/gate` executes the plan built here and refuses to run when the
manifest fails `check_local_dispositions`; `verify-manifest.py` runs the same
check in CI. Pure stdlib plus the shared strict YAML loader.
"""

from __future__ import annotations

import enum
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field, replace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import strict_yaml  # noqa: E402  # the shared strict loader

GITHUB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(GITHUB_DIR)
MANIFEST = os.path.join(GITHUB_DIR, "ci", "check-manifest.yml")


class Tier(enum.IntEnum):
    """A local gate tier; a higher tier runs every lower tier's commands."""

    QUICK = 1
    AFFECTED = 2
    FULL = 3


TIER_NAMES = {"quick": Tier.QUICK, "affected": Tier.AFFECTED, "full": Tier.FULL}

# Why a gate has no local twin. A closed set: a new kind of CI-only check needs
# a deliberate addition here, not a free-text excuse.
CI_ONLY_REASONS = {
    "platform": "needs a runner OS or architecture other than the local host",
    "privileged": "needs root, a system sandbox, or kernel settings on the runner",
    "classifier": "a CI path classifier; it has no meaning outside a workflow run",
    "run-history": "a verdict over other workflow runs on the default branch; only GitHub holds them",
    "pull-request-state": "a verdict over a pull request's reviews and commits; only GitHub holds them",
    "inline-script": (
        "an inline workflow script bound to the runner layout; local parity "
        "needs it extracted into a tools/scripts entry point"
    ),
}

# Placeholder -> the text it stands for in CI. `{packages}` and
# `{lib_packages}` must be whole tokens; they expand to a package selection.
PACKAGE_PLACEHOLDERS = ("{packages}", "{lib_packages}")
PLACEHOLDERS = {
    "{packages}": "--workspace",
    "{lib_packages}": "--workspace",
    "{repo_root}": "${{ github.workspace }}",
    "{target_dir}": "${{ github.workspace }}/target",
    # The warm target every IPE_E2E emitted build links from; locally, the
    # lane's own target dir.
    "{oracle_target}": "${{ github.workspace }}/.cache/oracle-shared-target",
    # The release `ipe` build-tools compiles once and ships to its consumers;
    # locally, the one `cargo build --release -p ipe` in the target dir.
    "{ipe_bin}": "${{ runner.temp }}/ipe-release/ipe",
}
PLACEHOLDER_RE = re.compile(r"\{[a-z_]+\}")
EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
OBJECT_ID_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def canon_expr(text: str) -> str:
    """Workflow expressions with their inner spaces removed.

    GitHub substitutes `${{ ... }}` before the shell splits a line, so an
    unquoted expression is one word; without its spaces it splits as one.
    """
    return EXPR_RE.sub(lambda m: "${{" + re.sub(r"\s+", "", m.group(1)) + "}}", text)


# Flags CI adds only because of its runner environment (it pre-fetches crates).
CI_ONLY_FLAGS = frozenset({"--offline"})

# Target kinds whose crate carries doctests (`cargo test --doc -p` refuses a
# package without one).
DOCTEST_KINDS = frozenset({"lib", "rlib", "dylib", "proc-macro"})

# Characters a shell gives meaning to outside quotes. The gate runs a command
# as an argv with no shell, so any of these would run literally here while the
# token-equal CI line means something else there (a `$FILTER` that expands in
# CI is a filter matching nothing locally, and a test run matching nothing
# exits 0).
SHELL_OPERATORS = frozenset("|&;<>()")
SHELL_GLOBS = frozenset("*?[")
SHELL_WORD_START = frozenset("~#!")

LOCAL_KEYS_RUN = frozenset({"tier", "run"})
LOCAL_KEYS_RUN_OPTIONAL = frozenset({"complete"})
COMMAND_KEYS = frozenset({"cmd", "env", "cwd", "differs", "tier", "package"})
ENV_NAME_RE = re.compile(r"[A-Z_][A-Z0-9_]*\Z")
PACKAGE_NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]*\Z")


@dataclass(frozen=True)
class Command:
    """One local command, as declared (placeholders unexpanded)."""

    argv: tuple[str, ...]
    env: tuple[tuple[str, str], ...]
    cwd: str
    differs: str | None
    # The tier this one command runs at (defaults to its gate's declared
    # tier) and the crate, if any, that must own a changed file for it to
    # run at all — independent of which crates a `{packages}` word selects.
    tier: Tier
    package: str | None = None


@dataclass(frozen=True)
class RunLocal:
    """The gate is reproduced locally by `commands`, each at its own `tier`
    (defaulting to this one) and conditioned on its own `package`."""

    tier: Tier
    commands: tuple[Command, ...]
    complete: bool = False


@dataclass(frozen=True)
class CoveredBy:
    """Another gate's local commands already exercise this gate."""

    context: str


@dataclass(frozen=True)
class CiOnly:
    """The gate has no local reproduction, for a reason in `CI_ONLY_REASONS`."""

    reason: str


LocalDisposition = RunLocal | CoveredBy | CiOnly


def shell_hazard(text: str) -> str | None:
    """Why `text` would not mean the same to a shell as to `shlex.split`.

    The quote-aware scan refuses what a shell would expand, glob, redirect,
    chain or comment: `$` and backquote outside single quotes; operators,
    globs, braces other than a whole placeholder, a backslash, a word-leading
    `~`, `#` or `!` outside any quotes; a newline anywhere; and a leading
    `NAME=value` assignment (declare it under `env:`). None when inert.
    """
    if "\n" in text or "\r" in text:
        return "a newline separates shell commands"
    quote: str | None = None
    word_start = True
    i = 0
    while i < len(text):
        ch = text[i]
        if quote == "'":
            if ch == "'":
                quote = None
        elif ch == "\\":
            return "a backslash outside single quotes escapes differently in a shell"
        elif quote == '"':
            if ch == '"':
                quote = None
            elif ch in "$`":
                return f"{ch!r} expands inside double quotes"
        elif ch in "'\"":
            quote = ch
        elif ch in "$`":
            return f"{ch!r} expands in a shell"
        elif ch in SHELL_OPERATORS:
            return f"{ch!r} is a shell operator"
        elif ch in SHELL_GLOBS:
            return f"{ch!r} is a shell glob"
        elif ch == "{":
            m = PLACEHOLDER_RE.match(text, i)
            if m is None:
                return "'{' outside a placeholder is a shell brace expansion"
            i = m.end()
            word_start = False
            continue
        elif ch == "}":
            return "'}' outside a placeholder is a shell brace expansion"
        elif word_start and ch in SHELL_WORD_START:
            return f"a word-leading {ch!r} is shell syntax (home expansion, comment or negation)"
        word_start = quote is None and ch in " \t"
        i += 1
    first = text.split(None, 1)[0] if text.split() else ""
    if "=" in first and ENV_NAME_RE.match(first.split("=", 1)[0]):
        return "a leading NAME=value is a shell assignment; declare it under `env:`"
    return None


def _parse_command(raw: object, loc: str, errors: list[str], default_tier: Tier) -> Command | None:
    """Parse one `run:` item, refusing every malformed shape."""
    if isinstance(raw, str):
        raw = {"cmd": raw}
    if not isinstance(raw, dict):
        errors.append(f"{loc}: a command is a string or a mapping, got {type(raw).__name__}")
        return None
    unknown = set(raw) - COMMAND_KEYS
    if unknown:
        errors.append(f"{loc}: unknown command key(s) {sorted(unknown)} (allowed: {sorted(COMMAND_KEYS)})")
        return None
    text = raw.get("cmd")
    if not isinstance(text, str) or not text.strip():
        errors.append(f"{loc}: `cmd` must be a non-empty string")
        return None
    ok = True
    if "${{" in text:
        errors.append(f"{loc}: {text!r} holds a workflow expression; use a placeholder")
        ok = False
    hazard = shell_hazard(text)
    if hazard is not None:
        errors.append(f"{loc}: {text!r} is not inert without a shell: {hazard}")
        return None
    try:
        argv = tuple(shlex.split(text))
    except ValueError as e:
        errors.append(f"{loc}: {text!r} is not a shell-word list: {e}")
        return None
    for tok in argv:
        for ph in PLACEHOLDER_RE.findall(tok):
            if ph not in PLACEHOLDERS:
                errors.append(f"{loc}: unknown placeholder {ph} (allowed: {sorted(PLACEHOLDERS)})")
                ok = False
            elif ph in PACKAGE_PLACEHOLDERS and tok != ph:
                errors.append(f"{loc}: {ph} must be a whole word, got {tok!r}")
                ok = False
    env_raw = raw.get("env", {})
    env: list[tuple[str, str]] = []
    if not isinstance(env_raw, dict):
        errors.append(f"{loc}: `env` must be a mapping")
        ok = False
    else:
        for k, v in env_raw.items():
            if not isinstance(k, str) or not ENV_NAME_RE.match(k):
                errors.append(f"{loc}: env name {k!r} is not an UPPER_SNAKE identifier")
                ok = False
            elif not isinstance(v, str):
                errors.append(f"{loc}: env {k} must be a string, got {type(v).__name__}")
                ok = False
            elif "${{" in v or any(
                ph not in PLACEHOLDERS or ph in PACKAGE_PLACEHOLDERS for ph in PLACEHOLDER_RE.findall(v)
            ):
                errors.append(f"{loc}: env {k}={v!r} uses a workflow expression or a disallowed placeholder")
                ok = False
            else:
                env.append((k, v))
    cwd = raw.get("cwd", ".")
    if not isinstance(cwd, str) or os.path.isabs(cwd) or ".." in cwd.split("/") or not cwd:
        errors.append(f"{loc}: `cwd` must be a relative path inside the repo, got {cwd!r}")
        ok = False
    differs = raw.get("differs")
    if "differs" in raw and (not isinstance(differs, str) or not differs.strip()):
        errors.append(f"{loc}: `differs` must state why the command differs from CI")
        ok = False
    cmd_tier = default_tier
    if "tier" in raw:
        cmd_tier = TIER_NAMES.get(raw["tier"]) if isinstance(raw["tier"], str) else None
        if cmd_tier is None:
            errors.append(f"{loc}: tier {raw['tier']!r} is not one of {sorted(TIER_NAMES)}")
            ok = False
    package = raw.get("package")
    if "package" in raw and (not isinstance(package, str) or not PACKAGE_NAME_RE.match(package)):
        errors.append(f"{loc}: `package` must be a crate name, got {package!r}")
        ok = False
    elif package is not None:
        # The condition names the crate the command itself runs over, so a
        # misspelt condition cannot leave the command silently never planned.
        targets = [argv[i + 1] for i, w in enumerate(argv[:-1]) if w == "-p"]
        if targets != [package]:
            errors.append(f"{loc}: `package` {package!r} must be the command's one `-p` crate, got {targets}")
            ok = False
    if not ok:
        return None
    return Command(
        argv, tuple(env), os.path.normpath(cwd) if cwd != "." else ".", differs, cmd_tier, package
    )


def parse_local(ctx: str, raw: object, errors: list[str]) -> LocalDisposition | None:
    """Parse one gate entry's `local:` value into its typed disposition."""
    loc = f"{ctx!r} local"
    if not isinstance(raw, dict) or not raw:
        errors.append(f"{loc}: must be a mapping with `tier`+`run`, `covered-by`, or `ci-only`")
        return None
    keys = set(raw)
    if keys == {"covered-by"}:
        target = raw["covered-by"]
        if not isinstance(target, str) or not target:
            errors.append(f"{loc}: `covered-by` must name a gate context")
            return None
        return CoveredBy(target)
    if keys == {"ci-only"}:
        reason = raw["ci-only"]
        if not isinstance(reason, str) or reason not in CI_ONLY_REASONS:
            errors.append(f"{loc}: ci-only reason {reason!r} is not one of {sorted(CI_ONLY_REASONS)}")
            return None
        return CiOnly(reason)
    if not LOCAL_KEYS_RUN <= keys or keys - LOCAL_KEYS_RUN - LOCAL_KEYS_RUN_OPTIONAL:
        errors.append(
            f"{loc}: keys {sorted(keys)} are not exactly one disposition "
            "(`tier`+`run`[+`complete`] | `covered-by` | `ci-only`)"
        )
        return None
    complete = raw.get("complete", False)
    if complete is not True and "complete" in raw:
        errors.append(f"{loc}: `complete` is `true` or absent, got {complete!r}")
        return None
    tier = TIER_NAMES.get(raw["tier"]) if isinstance(raw["tier"], str) else None
    if tier is None:
        errors.append(f"{loc}: tier {raw['tier']!r} is not one of {sorted(TIER_NAMES)}")
        return None
    run = raw["run"]
    if not isinstance(run, list) or not run:
        errors.append(f"{loc}: `run` must be a non-empty list of commands")
        return None
    commands = [_parse_command(item, f"{loc} run[{i}]", errors, tier) for i, item in enumerate(run)]
    if any(c is None for c in commands):
        return None
    cmds = tuple(c for c in commands if c is not None)
    if complete and any(c.differs is not None for c in cmds):
        errors.append(f"{loc}: a `complete` gate mirrors CI token for token; it has no `differs` command")
        return None
    return RunLocal(tier, cmds, complete)


def parse_manifest_locals(entries: list[dict], errors: list[str]) -> dict[str, LocalDisposition]:
    """Parse every entry's `local:`; a gate needs one, any other entry none."""
    parsed: dict[str, LocalDisposition] = {}
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            errors.append(f"checks[{i}]: an entry is a mapping, got {type(e).__name__}")
            continue
        ctx = e.get("context")
        if not isinstance(ctx, str):
            continue
        if e.get("disposition") != "gate":
            if "local" in e:
                errors.append(f"{ctx!r}: only a `gate` entry declares `local:` (this is {e.get('disposition')!r})")
            continue
        if "local" not in e:
            errors.append(f"{ctx!r}: gate has no `local:` disposition (tier+run | covered-by | ci-only)")
            continue
        disp = parse_local(ctx, e["local"], errors)
        if disp is not None:
            parsed[ctx] = disp
    for ctx, disp in parsed.items():
        if isinstance(disp, CoveredBy):
            target = parsed.get(disp.context)
            if disp.context == ctx or not isinstance(target, RunLocal):
                errors.append(
                    f"{ctx!r} local: covered-by {disp.context!r} must name another gate whose local is `tier`+`run`"
                )
    return parsed


# ---- drift: a local command must be a command CI runs --------------------


@dataclass(frozen=True)
class CiLine:
    """One command line of a CI `run:` step, with the step's env and cwd."""

    argv: tuple[str, ...]
    env: dict[str, str]
    cwd: str


def _logical_lines(script: str) -> list[str]:
    """Split a `run:` script into command lines, joining `\\` continuations."""
    lines: list[str] = []
    buf = ""
    for line in script.splitlines():
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        lines.append(buf + line)
        buf = ""
    if buf:
        lines.append(buf)
    return lines


def _mapping(value: object) -> dict[str, str]:
    return {str(k): canon_expr(str(v)) for k, v in value.items()} if isinstance(value, dict) else {}


def _job_matches(job_id: str, job: dict, names: set[str]) -> bool:
    name = str(job.get("name", job_id))
    return job_id in names or name in names or any(name.startswith(n + " (") for n in names)


def _default_working_directory(doc: dict) -> str | None:
    """`defaults.run.working-directory` of a job or workflow, if declared.

    GitHub resolves each `defaults.run` key on its own (job over workflow), so
    a job's `defaults` without a working directory keeps the workflow's.
    """
    defaults = doc.get("defaults")
    run = defaults.get("run") if isinstance(defaults, dict) else None
    wd = run.get("working-directory") if isinstance(run, dict) else None
    return str(wd) if wd is not None else None


def ci_lines(workflow_doc: dict, ctx: str, aggregates: list[str]) -> list[CiLine]:
    """Every command line of the jobs producing `ctx` (and those it aggregates)."""
    names = {ctx, *aggregates}
    wf_env = _mapping(workflow_doc.get("env"))
    out: list[CiLine] = []
    for job_id, job in (workflow_doc.get("jobs") or {}).items():
        if not isinstance(job, dict) or not _job_matches(str(job_id), job, names):
            continue
        job_env = {**wf_env, **_mapping(job.get("env"))}
        default_wd = _default_working_directory(job) or _default_working_directory(workflow_doc) or "."
        for step in job.get("steps") or []:
            if not isinstance(step, dict) or not isinstance(step.get("run"), str):
                continue
            env = {**job_env, **_mapping(step.get("env"))}
            cwd = os.path.normpath(str(step.get("working-directory", default_wd)))
            for line in _logical_lines(step["run"]):
                try:
                    argv = tuple(shlex.split(canon_expr(line), comments=True))
                except ValueError:
                    continue
                if argv:
                    out.append(CiLine(argv, env, cwd))
    return out


def ci_argv(cmd: Command) -> tuple[str, ...]:
    """The command's words with every placeholder at its CI value."""
    words: list[str] = []
    for tok in cmd.argv:
        for ph, ci in PLACEHOLDERS.items():
            tok = tok.replace(ph, canon_expr(ci))
        words.append(tok)
    return tuple(words)


def ci_env_value(value: str) -> str:
    for ph, ci in PLACEHOLDERS.items():
        value = value.replace(ph, canon_expr(ci))
    return value


def check_drift(ctx: str, run: RunLocal, lines: list[CiLine], errors: list[str]) -> None:
    """Refuse a local command that is not a command of the producing CI job."""
    if not lines:
        errors.append(f"{ctx!r} local: no `run:` step found in its producing job(s)")
        return
    for i, cmd in enumerate(run.commands):
        loc = f"{ctx!r} local run[{i}]"
        want = ci_argv(cmd)
        candidates = [ln for ln in lines if ln.cwd == cmd.cwd]
        if cmd.differs is not None and not candidates:
            errors.append(f"{loc}: cwd {cmd.cwd!r} is not the working directory of any step CI runs for this gate")
            continue
        if cmd.differs is None:
            candidates = [ln for ln in candidates if tuple(t for t in ln.argv if t not in CI_ONLY_FLAGS) == want]
            if not candidates:
                errors.append(
                    f"{loc}: {shlex.join(cmd.argv)!r} (cwd {cmd.cwd!r}) matches no command CI runs for "
                    "this gate — mirror the CI command exactly, or mark it `differs: <reason>`"
                )
                continue
        for key, value in cmd.env:
            expected = ci_env_value(value)
            if not any(ln.env.get(key) == expected for ln in candidates):
                errors.append(f"{loc}: env {key}={value!r} is not the CI value of {key} for this gate")
    if run.complete:
        mirrored = {(ci_argv(cmd), cmd.cwd) for cmd in run.commands}
        for ln in lines:
            argv = tuple(t for t in ln.argv if t not in CI_ONLY_FLAGS)
            if (argv, ln.cwd) not in mirrored:
                errors.append(
                    f"{ctx!r} local: CI runs {shlex.join(ln.argv)!r} (cwd {ln.cwd!r}) for this gate with no "
                    "local twin — a `complete` gate mirrors every CI command"
                )


def load_workflow(producer: str, github_dir: str) -> dict | None:
    path = os.path.join(github_dir, "workflows", producer)
    if not os.path.isfile(path):
        return None
    try:
        with open(path) as f:
            doc = strict_yaml.safe_load(f)
    except (OSError, strict_yaml.yaml.YAMLError):
        return None
    return doc if isinstance(doc, dict) else None


def check_local_dispositions(
    entries: list[dict], errors: list[str], github_dir: str = GITHUB_DIR
) -> dict[str, LocalDisposition]:
    """Parse every `local:` and refuse any that drifts from its CI producer."""
    parsed = parse_manifest_locals(entries, errors)
    by_ctx = {e.get("context"): e for e in entries if isinstance(e, dict)}
    for ctx, disp in parsed.items():
        if not isinstance(disp, RunLocal):
            continue
        entry = by_ctx[ctx]
        producer = entry.get("producer")
        doc = load_workflow(str(producer), github_dir) if producer else None
        if doc is None:
            errors.append(f"{ctx!r} local: producer workflow {producer!r} not found or not a loadable mapping")
            continue
        check_drift(ctx, disp, ci_lines(doc, ctx, list(entry.get("aggregates") or [])), errors)
    return parsed


def load_manifest_entries(path: str = MANIFEST) -> list[dict]:
    """The manifest's `checks` list; ValueError when the document has none."""
    try:
        with open(path) as f:
            doc = strict_yaml.safe_load(f)
    except strict_yaml.yaml.YAMLError as e:
        raise ValueError(f"{path}: {e}") from e
    checks = doc.get("checks") if isinstance(doc, dict) else None
    if not isinstance(checks, list):
        raise ValueError(f"{path}: no top-level `checks:` list")
    return checks


# ---- planning: which commands a tier runs, over which packages -----------


@dataclass(frozen=True)
class Workspace:
    """The cargo workspace members: directories, doctest-ability, path edges."""

    root: str
    target_dir: str
    member_dirs: dict[str, str]
    doctest: frozenset[str]
    path_deps: dict[str, frozenset[str]]
    # owner -> members whose sources read a path inside it without a cargo
    # edge (see `source_readers`). Empty until `with_source_readers`.
    readers: dict[str, frozenset[str]] = field(default_factory=dict)

    @staticmethod
    def from_metadata(meta: dict) -> Workspace:
        root = meta["workspace_root"]
        members = set(meta["workspace_members"])
        by_dir: dict[str, str] = {}
        doctest: set[str] = set()
        pkgs = [p for p in meta["packages"] if p["id"] in members]
        for p in pkgs:
            rel = os.path.relpath(os.path.dirname(p["manifest_path"]), root)
            by_dir[p["name"]] = "" if rel == "." else rel
            if any(k in DOCTEST_KINDS for t in p["targets"] for k in t["kind"]):
                doctest.add(p["name"])
        dir_to_name = {os.path.join(root, d) if d else root: n for n, d in by_dir.items()}
        deps: dict[str, frozenset[str]] = {}
        for p in pkgs:
            names = {dir_to_name.get(os.path.normpath(d["path"])) for d in p["dependencies"] if d.get("path")}
            deps[p["name"]] = frozenset(n for n in names if n and n != p["name"])
        return Workspace(root, meta["target_directory"], by_dir, frozenset(doctest), deps)

    def owner(self, path: str) -> str | None:
        """The member owning a repo-relative file (deepest dir), else None."""
        best: tuple[int, str] | None = None
        for name, d in self.member_dirs.items():
            if d and (path == d or path.startswith(d + "/")) and (best is None or len(d) > best[0]):
                best = (len(d), name)
        return best[1] if best else None

    def owners_within(self, path: str) -> set[str]:
        """Members owning `path` or any file under it (a directory path)."""
        found = {n for n, d in self.member_dirs.items() if d and d.startswith(path + "/")}
        owner = self.owner(path)
        return found | {owner} if owner else found

    def with_source_readers(self) -> Workspace:
        return replace(self, readers=source_readers(self))

    def reverse_closure(self, seeds: set[str]) -> set[str]:
        """`seeds` plus every member that depends on or reads one, transitively."""
        rdeps: dict[str, set[str]] = {n: set() for n in self.member_dirs}
        for n, ds in self.path_deps.items():
            for d in ds:
                rdeps.setdefault(d, set()).add(n)
        for owner, rs in self.readers.items():
            rdeps.setdefault(owner, set()).update(rs)
        out = set(seeds)
        pending = list(seeds)
        while pending:
            for r in rdeps.get(pending.pop(), ()):
                if r not in out:
                    out.add(r)
                    pending.append(r)
        return out


# A Rust string literal's body (escapes kept; raw strings are read as plain).
RUST_STR_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
SCAN_PRUNE = frozenset({"target", ".git", "node_modules"})


def _path_literal(lit: str) -> str | None:
    """A literal that names a relative path, leading `/` stripped (as after
    `concat!(env!("CARGO_MANIFEST_DIR"), "/...")`).

    None for a literal no file reference is spelled as, only path-traversal
    test strings are: a bare `..` chain, or a `..` after a named component.
    """
    if "/" not in lit:
        return None
    parts = [p for p in lit.split("/") if p not in ("", ".")]
    named = [p for p in parts if p != ".."]
    if not named or parts.index(named[0]) < max((i for i, p in enumerate(parts) if p == ".."), default=-1):
        return None
    return lit.lstrip("/")


def source_readers(ws: Workspace) -> dict[str, frozenset[str]]:
    """owner -> the members whose Rust sources name an existing path inside it.

    A crate that `include_str!`s, `include!`s or reads another crate's file
    (a stdlib `.ipe`, a runtime source, a template directory) is affected by a
    change there even with no cargo edge between them. Each `.rs` file of a
    member is scanned for path literals, resolved against the file's
    directory, the crate directory and the repository root; any that exists
    inside a different member (or is a directory holding members) adds an edge.
    An extra edge only widens `affected`.

    LIMIT: a path assembled from single-component pieces at run time
    (`dir.join("stdlib").join("Ipe")`) is invisible to a literal scan.
    """
    member_abs = {os.path.join(ws.root, d) for d in ws.member_dirs.values() if d}
    edges: dict[str, set[str]] = {}
    for name, rel_dir in ws.member_dirs.items():
        if not rel_dir:
            continue
        crate = os.path.join(ws.root, rel_dir)
        for dirpath, dirnames, filenames in os.walk(crate):
            dirnames[:] = [
                d for d in dirnames if d not in SCAN_PRUNE and os.path.join(dirpath, d) not in member_abs
            ]
            for fn in filenames:
                if not fn.endswith(".rs"):
                    continue
                with open(os.path.join(dirpath, fn), encoding="utf-8", errors="replace") as f:
                    text = f.read()
                for lit in RUST_STR_RE.findall(text):
                    rel = _path_literal(lit)
                    if rel is None:
                        continue
                    for base in (dirpath, crate, ws.root):
                        target = os.path.normpath(os.path.join(base, rel))
                        rel_target = os.path.relpath(target, ws.root)
                        if rel_target == "." or rel_target.split(os.sep)[0] == ".." or not os.path.exists(target):
                            continue
                        for owner in ws.owners_within(rel_target):
                            if owner != name:
                                edges.setdefault(owner, set()).add(name)
    return {o: frozenset(rs) for o, rs in edges.items()}


def load_workspace(repo_root: str) -> Workspace:
    """The workspace from `cargo metadata`, with its source-read edges."""
    return Workspace.from_metadata(cargo_metadata(repo_root)).with_source_readers()


@dataclass(frozen=True)
class Selection:
    """The packages a tier checks: none, the whole workspace, or a named set."""

    packages: frozenset[str] | None

    def words(self, ws: Workspace, doctest_only: bool) -> list[str] | None:
        """Cargo package words, or None when the selection is empty."""
        if self.packages is None:
            return ["--workspace"]
        names = sorted(n for n in self.packages if not doctest_only or n in ws.doctest)
        return [w for n in names for w in ("-p", n)] or None


def select_packages(tier: Tier, changed: list[str], ws: Workspace) -> Selection:
    """Map changed files to the packages a tier covers.

    A file no member owns (workspace manifests, lockfile, config, shared
    fixtures) may affect every crate, so it selects the whole workspace.
    `affected` widens the owners by cargo path edges and by the source-read
    edges of `Workspace.readers`; see `source_readers` for the one LIMIT.
    """
    if tier is Tier.FULL:
        return Selection(None)
    owners = set()
    for path in changed:
        owner = ws.owner(path)
        if owner is None:
            return Selection(None)
        owners.add(owner)
    if tier is Tier.AFFECTED:
        owners = ws.reverse_closure(owners)
    return Selection(frozenset(owners))


@dataclass(frozen=True)
class Step:
    """One planned local command, fully expanded for this machine."""

    context: str
    argv: tuple[str, ...]
    env: tuple[tuple[str, str], ...]
    cwd: str


def expand(cmd: Command, ctx: str, sel: Selection, ws: Workspace) -> Step | None:
    """Expand placeholders to local values; None when the selection is empty
    or, for a `package`-conditioned command, when that crate owns no changed
    file (an unowned change still conservatively selects every command, same
    as an unprefixed `{packages}` word would)."""
    if cmd.package is not None and sel.packages is not None and cmd.package not in sel.packages:
        return None
    local = {
        "{repo_root}": ws.root,
        "{target_dir}": ws.target_dir,
        "{oracle_target}": ws.target_dir,
        "{ipe_bin}": os.path.join(ws.target_dir, "release", "ipe"),
    }
    argv: list[str] = []
    for tok in cmd.argv:
        if tok in PACKAGE_PLACEHOLDERS:
            words = sel.words(ws, doctest_only=tok == "{lib_packages}")
            if words is None:
                return None
            argv.extend(words)
            continue
        for ph, val in local.items():
            tok = tok.replace(ph, val)
        argv.append(tok)
    env = []
    for k, v in cmd.env:
        for ph, val in local.items():
            v = v.replace(ph, val)
        env.append((k, v))
    return Step(ctx, tuple(argv), tuple(env), os.path.join(ws.root, cmd.cwd) if cmd.cwd != "." else ws.root)


def plan(
    tier: Tier, entries: list[dict], parsed: dict[str, LocalDisposition], changed: list[str], ws: Workspace
) -> list[Step]:
    """The ordered commands `tier` runs, in manifest order, lowest tier first.

    A command identical to an earlier one (same words, env and cwd, such as a
    shared `cargo build --release -p ipe`) runs once, at its first position.
    """
    sel = select_packages(tier, changed, ws)
    runs = [
        (e["context"], parsed[e["context"]])
        for e in entries
        if isinstance(parsed.get(e.get("context")), RunLocal)
    ]
    steps: list[Step] = []
    seen: set[tuple[tuple[str, ...], tuple[tuple[str, str], ...], str]] = set()
    for t in Tier:
        if t > tier:
            break
        for ctx, disp in runs:
            if not isinstance(disp, RunLocal):
                continue
            for c in disp.commands:
                if c.tier is t:
                    s = expand(c, ctx, sel, ws)
                    if s is not None and (s.argv, s.env, s.cwd) not in seen:
                        seen.add((s.argv, s.env, s.cwd))
                        steps.append(s)
    return steps


def cargo_metadata(repo_root: str) -> dict:
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(out.stdout)


def changed_files(repo_root: str, base: str) -> list[str]:
    """Files differing from the merge-base with `base`, plus untracked files."""

    def git(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=repo_root, check=True, capture_output=True, text=True).stdout

    # `--end-of-options`: a `--base` spelled like an option stays a revision.
    merge_base = git("merge-base", "--end-of-options", "HEAD", base).strip()
    if not OBJECT_ID_RE.fullmatch(merge_base):
        raise subprocess.CalledProcessError(1, ["git", "merge-base"], stderr=f"no merge-base with {base!r}")
    # `--no-renames`: a moved file names its old path too, whose crate lost it.
    # `-z`: paths arrive verbatim, never C-quoted.
    tracked = git("diff", "--name-only", "--no-renames", "-z", merge_base, "--").split("\0")
    untracked = git("ls-files", "-z", "--others", "--exclude-standard").split("\0")
    return sorted({p for p in tracked + untracked if p})
