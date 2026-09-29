#!/usr/bin/env python3
"""Typed `local:` dispositions of `check-manifest.yml`: the local gate's SSOT.

Every `gate` entry of the manifest declares exactly one local disposition:

  local: {tier: quick|affected|full, run: [<command>, ...]}
      The gate is reproduced locally by these commands. Tiers nest:
      `affected` runs every `quick` command too, `full` runs all three.
  local: {covered-by: <gate context>}
      Another gate's local commands already exercise this one (a matrix slice
      of a wider suite). The target must itself declare `run`.
  local: {ci-only: <reason>}
      No local reproduction exists; the reason is one of `CI_ONLY_REASONS`.

A `<command>` is a string, or a mapping with `cmd` (required), `env`, `cwd` and
`differs`. Its text may use the closed set of `PLACEHOLDERS`. Unless the
command carries `differs: <reason>`, it must equal, token for token (after
the placeholders take their CI values and `CI_ONLY_FLAGS` are dropped), one
command line of a `run:` step in the producing job (or a job it `aggregates`),
with the same `working-directory`; every declared `env` entry must equal the
CI value visible to that step. A `differs` command is exempt from the token
match only; its `env` and `cwd` are still verified. So the local gate cannot
run a command CI does not run, and CI cannot change a mirrored command without
the manifest guard going red.

LIMIT: the match is one-directional. A new CI step with no `local:` twin is
not detected; the `local:` block of that gate must be extended by hand.

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
from dataclasses import dataclass

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
}
PLACEHOLDER_RE = re.compile(r"\{[a-z_]+\}")
EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")


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

LOCAL_KEYS_RUN = frozenset({"tier", "run"})
COMMAND_KEYS = frozenset({"cmd", "env", "cwd", "differs"})
ENV_NAME_RE = re.compile(r"[A-Z_][A-Z0-9_]*\Z")


@dataclass(frozen=True)
class Command:
    """One local command, as declared (placeholders unexpanded)."""

    argv: tuple[str, ...]
    env: tuple[tuple[str, str], ...]
    cwd: str
    differs: str | None


@dataclass(frozen=True)
class RunLocal:
    """The gate is reproduced locally by `commands` at `tier`."""

    tier: Tier
    commands: tuple[Command, ...]


@dataclass(frozen=True)
class CoveredBy:
    """Another gate's local commands already exercise this gate."""

    context: str


@dataclass(frozen=True)
class CiOnly:
    """The gate has no local reproduction, for a reason in `CI_ONLY_REASONS`."""

    reason: str


LocalDisposition = RunLocal | CoveredBy | CiOnly


def _parse_command(raw: object, loc: str, errors: list[str]) -> Command | None:
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
    if not ok:
        return None
    return Command(argv, tuple(env), os.path.normpath(cwd) if cwd != "." else ".", differs)


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
        if reason not in CI_ONLY_REASONS:
            errors.append(f"{loc}: ci-only reason {reason!r} is not one of {sorted(CI_ONLY_REASONS)}")
            return None
        return CiOnly(reason)
    if keys != LOCAL_KEYS_RUN:
        errors.append(
            f"{loc}: keys {sorted(keys)} are not exactly one disposition "
            "(`tier`+`run` | `covered-by` | `ci-only`)"
        )
        return None
    tier = TIER_NAMES.get(raw["tier"]) if isinstance(raw["tier"], str) else None
    if tier is None:
        errors.append(f"{loc}: tier {raw['tier']!r} is not one of {sorted(TIER_NAMES)}")
        return None
    run = raw["run"]
    if not isinstance(run, list) or not run:
        errors.append(f"{loc}: `run` must be a non-empty list of commands")
        return None
    commands = [_parse_command(item, f"{loc} run[{i}]", errors) for i, item in enumerate(run)]
    if any(c is None for c in commands):
        return None
    return RunLocal(tier, tuple(c for c in commands if c is not None))


def parse_manifest_locals(entries: list[dict], errors: list[str]) -> dict[str, LocalDisposition]:
    """Parse every entry's `local:`; a gate needs one, any other entry none."""
    parsed: dict[str, LocalDisposition] = {}
    for e in entries:
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


def ci_lines(workflow_doc: dict, ctx: str, aggregates: list[str]) -> list[CiLine]:
    """Every command line of the jobs producing `ctx` (and those it aggregates)."""
    names = {ctx, *aggregates}
    wf_env = _mapping(workflow_doc.get("env"))
    out: list[CiLine] = []
    for job_id, job in (workflow_doc.get("jobs") or {}).items():
        if not isinstance(job, dict) or not _job_matches(str(job_id), job, names):
            continue
        job_env = {**wf_env, **_mapping(job.get("env"))}
        defaults = job.get("defaults") or workflow_doc.get("defaults") or {}
        default_wd = (defaults.get("run") or {}).get("working-directory", ".") if isinstance(defaults, dict) else "."
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


def load_workflow(producer: str, github_dir: str) -> dict | None:
    path = os.path.join(github_dir, "workflows", producer)
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        doc = strict_yaml.safe_load(f)
    return doc if isinstance(doc, dict) else None


def check_local_dispositions(
    entries: list[dict], errors: list[str], github_dir: str = GITHUB_DIR
) -> dict[str, LocalDisposition]:
    """Parse every `local:` and refuse any that drifts from its CI producer."""
    parsed = parse_manifest_locals(entries, errors)
    by_ctx = {e.get("context"): e for e in entries}
    for ctx, disp in parsed.items():
        if not isinstance(disp, RunLocal):
            continue
        entry = by_ctx[ctx]
        producer = entry.get("producer")
        doc = load_workflow(str(producer), github_dir) if producer else None
        if doc is None:
            errors.append(f"{ctx!r} local: producer workflow {producer!r} not found")
            continue
        check_drift(ctx, disp, ci_lines(doc, ctx, list(entry.get("aggregates") or [])), errors)
    return parsed


def load_manifest_entries(path: str = MANIFEST) -> list[dict]:
    with open(path) as f:
        doc = strict_yaml.safe_load(f)
    return list(doc["checks"])


# ---- planning: which commands a tier runs, over which packages -----------


@dataclass(frozen=True)
class Workspace:
    """The cargo workspace members: directories, doctest-ability, path edges."""

    root: str
    target_dir: str
    member_dirs: dict[str, str]
    doctest: frozenset[str]
    path_deps: dict[str, frozenset[str]]

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

    def reverse_closure(self, seeds: set[str]) -> set[str]:
        """`seeds` plus every member that depends on one, transitively."""
        rdeps: dict[str, set[str]] = {n: set() for n in self.member_dirs}
        for n, ds in self.path_deps.items():
            for d in ds:
                rdeps.setdefault(d, set()).add(n)
        out = set(seeds)
        pending = list(seeds)
        while pending:
            for r in rdeps.get(pending.pop(), ()):
                if r not in out:
                    out.add(r)
                    pending.append(r)
        return out


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
    """Map changed files to the packages a tier covers, failing closed.

    A file no member owns (workspace manifests, lockfile, config, shared
    fixtures) may affect every crate, so it selects the whole workspace.
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
    """Expand placeholders to local values; None when the selection is empty."""
    local = {"{repo_root}": ws.root, "{target_dir}": ws.target_dir}
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
            if isinstance(disp, RunLocal) and disp.tier is t:
                for c in disp.commands:
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

    merge_base = git("merge-base", "HEAD", base).strip()
    tracked = git("diff", "--name-only", merge_base).splitlines()
    untracked = git("ls-files", "--others", "--exclude-standard").splitlines()
    return sorted({p for p in tracked + untracked if p})
