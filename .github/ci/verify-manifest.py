#!/usr/bin/env python3
"""Drift gate for the CI check-disposition SSOT (ci/check-manifest.yml).

Fails (exit 1) when the manifest and reality disagree, so no check can exist
without a declared disposition and no `gate` can silently lose its producer.

Checks performed
  1. Every status context produced by .github/workflows/*.yml or *.yaml
     (matrix legs expanded) is present in the manifest.  An unclassified
     check is the exact "silent advisory red" this SSOT exists to forbid.
  2. Manifest self-consistency:
       - a known disposition (gate | nightly-gate | informational | delete);
       - `informational` entries name an `owner`;
       - an entry that `guards` a Security/Soundness/SEAL invariant is NOT
         `informational` (§0/§1/§3: a guarantee may not sit in an un-gated bucket);
       - a `gate`/`nightly-gate` entry has a producer workflow that exists;
       - a `delete` entry has no producer (an orphan), else it is a live check.
  3. Fail-closed dependency surfacing: GitHub reports a job whose `needs`
     failed as SKIPPED, and a skipped required check counts as passing.  So
     every job a gate transitively `needs` must itself surface in a gate (its
     own context is a gate, or a gate `aggregates` it); likewise a
     nightly-gate's ancestors must surface in a gate or nightly-gate.  A
     status context produced by two jobs is refused outright — a required
     context must resolve to exactly one producer.
  4. Required-set reconciliation (best-effort, non-fatal by default): every
     manifest `gate` context should be in the branch-protection required set and
     vice-versa.  Run with `--ruleset FILE` (a JSON dump of the ruleset's
     required contexts) to make mismatches fatal; without it the manifest is the
     SSOT and the check is skipped with a note.
  5. `ci/deterministic-checks.json` — the SSOT of (job, check step) pairs
     consumed by ci.yml's `cancel-on-cheap-red` watcher and
     rerun-failed-once.yml — is well-formed (exact keys, non-empty strings with
     no surrounding whitespace, no duplicate job), its job set equals the
     watcher's `needs:`, and each pair's step is a `name:` of that job's steps
     in ci.yml.
  6. sccache wiring: the ONLY sanctioned way a job gets sccache is
     `uses: ./.github/actions/sccache`, a composite action that installs
     `mozilla-actions/sccache-action` and writes RUSTC_WRAPPER/
     SCCACHE_GHA_ENABLED to `$GITHUB_ENV` itself, so the wrapper can never
     exist in a job without the binary that backs it. Every local `./` `uses:`
     (step or composite step) is resolved on disk (action.yml, then
     action.yaml) under a normalized, byte-exact id; an unresolved, ambiguous,
     case-variant, non-composite, cyclic, or over-deep local action is
     refused, as is a job-level `uses:` (reusable workflow). Outside the
     composite this refuses: a raw `mozilla-actions/sccache-action` reference;
     an `env:` key naming a rustc wrapper, a rustc replacement, or SCCACHE_*
     at any scope; and any `env:` value, `run:`, `shell:`,
     `defaults.run.shell`, or `with:` text naming one (or cargo's
     `rustc-wrapper` config spelling), or assembling its target through a
     GitHub Actions expression function (`format(`, `join(`, `toJSON(`, or
     `fromJSON(` over a literal; any letter case) instead of naming it
     literally. Every workflow, manifest, and local
     action is loaded through `strict_yaml` (see that module), so a
     duplicate mapping key, a `<<` merge key, an anchor/alias, or an
     explicit tag — each
     legal to a plain YAML loader but resolved differently, or not at all,
     from what GitHub Actions runs — is refused rather than silently
     resolved. A job that reaches the composite,
     directly or through local actions, may not own a step named in
     `ci/deterministic-checks.json` (sccache's cache backend does network I/O
     a deterministic check must never risk). The composite itself must equal
     one canonical structure exactly. Malformed shapes are refused, never
     skipped. Limits are listed on `check_sccache_wiring`.

Pure stdlib + PyYAML (already a CI dependency).  No network.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import posixpath
import re
import sys
from dataclasses import dataclass

try:
    import yaml
except ImportError:  # pragma: no cover - CI always has PyYAML
    print("verify-manifest: PyYAML is required (pip install pyyaml)", file=sys.stderr)
    sys.exit(2)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import strict_yaml  # noqa: E402  # the shared strict loader, SSOT for every YAML load below

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Both extensions: a workflow (or, for check 6, a local composite action) is a
# workflow whichever suffix its YAML uses — a `*.yml`-only glob silently drops
# a `*.yaml` file from every check below it feeds.
WORKFLOW_GLOBS = (
    os.path.join(REPO_ROOT, "workflows", "*.yml"),
    os.path.join(REPO_ROOT, "workflows", "*.yaml"),
)
MANIFEST = os.path.join(REPO_ROOT, "ci", "check-manifest.yml")
DETERMINISTIC_CHECKS_FILE = os.path.join(REPO_ROOT, "ci", "deterministic-checks.json")
CANCEL_WATCHER_WORKFLOW = "ci.yml"
CANCEL_WATCHER_JOB_ID = "cancel-on-cheap-red"

SCCACHE_ACTION_PREFIX = "mozilla-actions/sccache-action@"
SCCACHE_COMPOSITE_USES = "./.github/actions/sccache"
# Identity of a local action: its repo-root-relative path, normalized
# (`./x/`, `./x`, `./a/../x` are one path) and byte-exact. Two paths that are
# case-fold-equal but not byte-equal are refused outright (macOS and Windows
# runners resolve them to one directory), so identity never needs folding.
SCCACHE_COMPOSITE_ID = posixpath.normpath(SCCACHE_COMPOSITE_USES[2:])
SCCACHE_WRAPPER_VAR = "RUSTC_WRAPPER"
SCCACHE_GHA_VAR = "SCCACHE_GHA_ENABLED"
# SSOT: every env-var name that hands rustc a wrapper.
SCCACHE_WRAPPER_KEY_NAMES = (
    SCCACHE_WRAPPER_VAR,
    "CARGO_BUILD_RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
)
# SSOT: every env-var name that replaces rustc itself.
RUSTC_REPLACING_KEY_NAMES = ("RUSTC", "CARGO_BUILD_RUSTC")
SCCACHE_ENV_KEYS = {k.casefold() for k in SCCACHE_WRAPPER_KEY_NAMES + RUSTC_REPLACING_KEY_NAMES} | {
    SCCACHE_GHA_VAR.casefold()
}
# Any wrapper-shaped key above, OR a generic SCCACHE_* key.
SCCACHE_KEY_RE = re.compile(
    "(?:" + "|".join(re.escape(k) for k in SCCACHE_WRAPPER_KEY_NAMES) + r"|SCCACHE_[A-Z0-9_]*)",
    re.IGNORECASE,
)
# Loose refusal predicate over free text (`run:`, `shell:`, `defaults.run.
# shell`, `with:` and `env:` values): any wrapper/sccache-shaped key; cargo's
# own `rustc-wrapper`/`rustc-workspace-wrapper` config spelling (`cargo
# --config build.rustc-wrapper=...`, a written `.cargo/config.toml`); a
# rustc-replacing key (`CARGO_BUILD_RUSTC` in any case, `RUSTC` as an
# upper-case word, `rustc` in any case and after any character — a printf
# `\n` escape included — directly followed by `=` or `:`). No `$GITHUB_ENV`
# is required — an inline `KEY=v cmd`, an `export`, a `shell: env KEY=v bash
# {0}`, or an `env:` value a `run:` later expands into a write wires rustc
# just as well. Over-strict by design: a refused false positive is cheap, a
# missed wiring is not.
SCCACHE_WIRING_TEXT_RE = re.compile(
    SCCACHE_KEY_RE.pattern
    + r"|rustc[-_](?:workspace[-_])?wrapper"
    + r"|CARGO_BUILD_RUSTC"
    + r"|(?-i:(?<![A-Za-z0-9_])RUSTC(?![A-Za-z0-9_]))"
    + r"|rustc\s*[=:]",
    re.IGNORECASE,
)
# The sanctioned composite is exactly ONE canonical structure: an install
# step `{uses: mozilla-actions/sccache-action@<ref>}`, then `SCCACHE_WIRE_STEP`
# byte-exact. Its wiring is proven by equality, never by pattern.
SCCACHE_INSTALL_USES_RE = re.compile(re.escape(SCCACHE_ACTION_PREFIX) + r"[A-Za-z0-9._-]+\Z")
SCCACHE_WIRE_RUN = (
    "set -euo pipefail\n"
    f'echo "{SCCACHE_WRAPPER_VAR}=sccache" >> "$GITHUB_ENV"\n'
    f'echo "{SCCACHE_GHA_VAR}=true" >> "$GITHUB_ENV"\n'
)
SCCACHE_WIRE_STEP = {"name": "Wire rustc through sccache", "shell": "bash", "run": SCCACHE_WIRE_RUN}
SCCACHE_COMPOSITE_DOC_KEYS = frozenset({"name", "description", "runs"})
# Bound on local-action nesting; a chain deeper than this is refused, never
# assumed not to reach the sccache composite.
LOCAL_ACTION_DEPTH_LIMIT = 20


VALID_DISPOSITIONS = {"gate", "gate-external", "nightly-gate", "informational", "delete"}
# Workflows whose jobs are release/automation plumbing, never PR/promotion
# status gates — excluded from the "produced context" set so the drift gate does
# not demand a disposition for a release upload job.
PLUMBING_WORKFLOWS = {
    "release.yml",
    "release-please.yml",
    "rerun-failed-once.yml",
    "nightly-full-gate.yml",
    "manifest-guard.yml",
    "ci-health.yml",
}


def expand_matrix_names(name: str, strategy: dict) -> list[str]:
    """Expand a job `name:` containing ${{ matrix.KEY }} over its matrix values.

    Only the simple `matrix: {KEY: [a, b, ...]}` form is expanded (that covers
    every matrix in this repo).  A name with no matrix ref returns [name]; an
    unexpandable ref falls back to a regex-friendly wildcard match later.
    """
    refs = re.findall(r"\$\{\{\s*matrix\.([a-zA-Z0-9_]+)\s*\}\}", name)
    if not refs:
        return [name]
    matrix = (strategy or {}).get("matrix") or {}
    result = [name]
    for key in refs:
        values = matrix.get(key)
        if not isinstance(values, list):
            return [name]  # cannot expand; keep the templated form
        expanded = []
        for base in result:
            for v in values:
                expanded.append(base.replace("${{ matrix.%s }}" % key, str(v)))
                expanded.append(
                    base.replace("${{ matrix.%s }}" % key.strip(), str(v))
                )
        # de-dup while preserving order
        seen = set()
        result = [x for x in expanded if not (x in seen or seen.add(x))]
    return result


class Job:
    """One workflow job: its status contexts and direct `needs`."""

    def __init__(self, workflow: str, job_id: str, contexts: list[str], needs: list[str]):
        self.workflow = workflow
        self.job_id = job_id
        self.contexts = contexts
        self.needs = needs


def workflow_jobs() -> list[Job]:
    """Every job of every non-plumbing workflow, matrix legs expanded."""
    jobs: list[Job] = []
    paths = sorted(p for g in WORKFLOW_GLOBS for p in glob.glob(g))
    for path in paths:
        fname = os.path.basename(path)
        if fname in PLUMBING_WORKFLOWS:
            continue
        try:
            doc = strict_yaml.safe_load(open(path))
        except yaml.YAMLError as e:
            print(f"verify-manifest: {fname} is not valid YAML: {e}", file=sys.stderr)
            sys.exit(2)
        if not isinstance(doc, dict):
            continue
        for job_id, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            name = job.get("name", job_id)
            needs = job.get("needs") or []
            if isinstance(needs, str):
                needs = [needs]
            contexts = expand_matrix_names(str(name), job.get("strategy") or {})
            jobs.append(Job(fname, str(job_id), contexts, [str(n) for n in needs]))
    return jobs


def produced_contexts(jobs: list[Job]) -> dict[str, list[str]]:
    """Map produced status-context string -> producing workflow filenames."""
    contexts: dict[str, list[str]] = {}
    for job in jobs:
        for ctx in job.contexts:
            contexts.setdefault(ctx, []).append(job.workflow)
    return contexts


def load_deterministic_checks(
    errors: list[str], root: str = REPO_ROOT
) -> list[tuple[str, str]] | None:
    """Parse `ci/deterministic-checks.json` into (context, step) pairs, or
    record why it is malformed.  Strict: the shell consumers match these
    strings byte-exactly, so anything a consumer could misread is rejected.
    """
    where = os.path.join(root, "ci", "deterministic-checks.json")
    try:
        with open(where) as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        errors.append(f"cannot read {where}: {e}")
        return None
    if not isinstance(doc, dict) or set(doc) != {"about", "checks"}:
        errors.append(f"{where}: top level must be an object with exactly the keys 'about' and 'checks'")
        return None
    checks = doc["checks"]
    if not isinstance(checks, list) or not checks:
        errors.append(f"{where}: 'checks' must be a non-empty list")
        return None
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for i, entry in enumerate(checks):
        if not isinstance(entry, dict) or set(entry) != {"context", "step"}:
            errors.append(f"{where}: checks[{i}] must be an object with exactly the keys 'context' and 'step'")
            continue
        ctx, step = entry["context"], entry["step"]
        bad = False
        for key, val in (("context", ctx), ("step", step)):
            if not isinstance(val, str) or not val or val != val.strip() or "\n" in val:
                errors.append(
                    f"{where}: checks[{i}].{key} = {val!r} must be a non-empty "
                    "single-line string with no leading/trailing whitespace"
                )
                bad = True
        if bad:
            continue
        if ctx in seen:
            errors.append(f"{where}: context {ctx!r} is listed more than once")
            continue
        seen.add(ctx)
        pairs.append((ctx, step))
    return pairs


def check_deterministic_set(jobs: list[Job], errors: list[str]) -> None:
    """`ci/deterministic-checks.json` is the one SSOT behind ci.yml's
    `cancel-on-cheap-red` watcher and rerun-failed-once.yml's retry skip.
    Its job set must equal the watcher's `needs:`, and each pair's step must
    be a literal `name:` of that job's steps — a renamed or unnamed check step
    would otherwise never match and silently disable both consumers.
    """
    pairs = load_deterministic_checks(errors)
    if pairs is None:
        return

    by_job_id = {
        j.job_id: j for j in jobs if j.workflow == CANCEL_WATCHER_WORKFLOW
    }
    watcher = by_job_id.get(CANCEL_WATCHER_JOB_ID)
    if watcher is None:
        errors.append(
            f"{CANCEL_WATCHER_WORKFLOW} has no {CANCEL_WATCHER_JOB_ID!r} job — "
            f"{DETERMINISTIC_CHECKS_FILE} has no watcher to check against"
        )
        return

    raw_jobs = strict_yaml.safe_load(
        open(os.path.join(REPO_ROOT, "workflows", CANCEL_WATCHER_WORKFLOW))
    ).get("jobs") or {}

    # context -> job id, over single-context (non-matrix) jobs of ci.yml only:
    # a matrix leg's context cannot be tied to one check step unambiguously.
    ctx_to_job: dict[str, str] = {}
    for j in by_job_id.values():
        if len(j.contexts) == 1:
            ctx_to_job[j.contexts[0]] = j.job_id

    listed_ids: set[str] = set()
    for ctx, step in pairs:
        job_id = ctx_to_job.get(ctx)
        if job_id is None:
            errors.append(
                f"{DETERMINISTIC_CHECKS_FILE}: context {ctx!r} is not the "
                f"context of a single-context job in {CANCEL_WATCHER_WORKFLOW}"
            )
            continue
        listed_ids.add(job_id)
        raw_job = raw_jobs.get(job_id) or {}
        if "strategy" in raw_job:
            errors.append(
                f"{DETERMINISTIC_CHECKS_FILE}: job {job_id!r} has a `strategy:`; "
                "a deterministic check must be a single unexpanded job"
            )
        if "${{" in ctx or "${{" in step:
            errors.append(
                f"{DETERMINISTIC_CHECKS_FILE}: {ctx!r}/{step!r} contains an "
                "expression; consumers match literal names only"
            )
        steps = raw_job.get("steps") or []
        named = [st for st in steps if isinstance(st, dict) and st.get("name") == step]
        if len(named) != 1:
            errors.append(
                f"{DETERMINISTIC_CHECKS_FILE}: job {job_id!r} must have exactly "
                f"one step named {step!r} (found {len(named)})"
            )
            continue
        if "if" in named[0] or "continue-on-error" in named[0]:
            errors.append(
                f"{DETERMINISTIC_CHECKS_FILE}: step {step!r} of job {job_id!r} "
                "must run unconditionally: no `if:` and no `continue-on-error:`"
            )

    needed = set(watcher.needs)
    unknown = needed - set(by_job_id)
    if unknown:
        errors.append(
            f"{CANCEL_WATCHER_WORKFLOW}: {CANCEL_WATCHER_JOB_ID!r} needs "
            f"unknown job(s) {sorted(unknown)}"
        )
    missing = listed_ids - needed
    extra = needed - listed_ids - unknown
    if missing:
        errors.append(
            f"{DETERMINISTIC_CHECKS_FILE} lists job(s) {sorted(missing)} but "
            f"{CANCEL_WATCHER_JOB_ID!r} does not `needs:` them"
        )
    if extra:
        errors.append(
            f"{CANCEL_WATCHER_JOB_ID!r} needs {sorted(extra)} but they are "
            f"missing from {DETERMINISTIC_CHECKS_FILE}"
        )


def _refuse_shape(loc: str, what: str, expected: str, got: object, errors: list[str]) -> None:
    errors.append(
        f"{loc}: {what} is not {expected} (got {type(got).__name__}: {got!r}) — "
        "cannot verify it carries no sccache wiring; refused fail-closed"
    )


@dataclass(frozen=True)
class Step:
    """One workflow (or composite action) step, typed just enough for the
    sccache-wiring checks: `uses:`/`name:`/`run:`/`shell:` are read nowhere
    else in this module via raw `.get()`.
    """

    raw: dict

    def _str(self, key: str) -> str | None:
        v = self.raw.get(key)
        return v if isinstance(v, str) else None

    @property
    def name(self) -> str | None:
        return self._str("name")

    @property
    def uses(self) -> str | None:
        return self._str("uses")

    @property
    def uses_folded(self) -> str:
        return (self.uses or "").casefold()

    @property
    def run(self) -> str | None:
        return self._str("run")

    @property
    def shell(self) -> str | None:
        return self._str("shell")

    @property
    def label(self) -> str:
        return self.name or self.uses or "<unnamed>"


def _typed_steps(container: dict, loc: str, errors: list[str]) -> list[Step]:
    """`steps:` of a job or composite `runs:` as typed steps. Absent is empty;
    present but not a list, or an entry that is not a mapping, is refused —
    an unreadable step cannot be proven free of sccache wiring."""
    if "steps" not in container:
        return []
    raw = container["steps"]
    if not isinstance(raw, list):
        _refuse_shape(loc, "steps:", "a list", raw, errors)
        return []
    out: list[Step] = []
    for i, st in enumerate(raw):
        if isinstance(st, dict):
            out.append(Step(st))
        else:
            _refuse_shape(loc, f"steps[{i}]", "a mapping", st, errors)
    return out


@dataclass(frozen=True)
class WorkflowJob:
    job_id: str
    raw: dict


@dataclass(frozen=True)
class SccacheWorkflow:
    fname: str
    doc: dict
    jobs: list[WorkflowJob]


def _load_sccache_workflows(root: str, errors: list[str]) -> list[SccacheWorkflow]:
    """Every workflow (`*.yml` and `*.yaml`), typed. A document that is not a
    mapping, a `jobs:` that is not a non-empty mapping, or a job that is not a
    mapping is refused, never skipped."""
    out: list[SccacheWorkflow] = []
    paths = sorted(
        p
        for pattern in ("*.yml", "*.yaml")
        for p in glob.glob(os.path.join(root, "workflows", pattern))
    )
    for path in paths:
        fname = os.path.basename(path)
        try:
            with open(path) as f:
                doc = strict_yaml.safe_load(f)
        except yaml.YAMLError as e:
            errors.append(f"{fname} is not valid YAML: {e}")
            continue
        if not isinstance(doc, dict):
            _refuse_shape(fname, "the workflow document", "a mapping", doc, errors)
            continue
        raw_jobs = doc.get("jobs")
        if not isinstance(raw_jobs, dict) or not raw_jobs:
            _refuse_shape(fname, "jobs:", "a non-empty mapping", raw_jobs, errors)
            continue
        jobs: list[WorkflowJob] = []
        for jid, j in raw_jobs.items():
            if isinstance(j, dict):
                jobs.append(WorkflowJob(str(jid), j))
            else:
                _refuse_shape(f"{fname}: job {str(jid)!r}", "the job", "a mapping", j, errors)
        out.append(SccacheWorkflow(fname, doc, jobs))
    return out


def _env_keys_folded(env: dict) -> set[str]:
    return {str(k).casefold() for k in env}


def _scoped_env(container: dict, loc: str, errors: list[str]) -> dict:
    """Extract an `env:` mapping at one scope (workflow/job/step/container/
    service), failing CLOSED when `env:` is present but not a plain mapping
    (e.g. `env: ${{ fromJSON(vars.E) }}`) — such a value's keys cannot be
    determined statically, so "it does not set an sccache-wiring key" cannot
    be proven and must never be assumed (PRINCIPLES §1: fail closed absent
    proof of safety). A missing `env:` is simply empty, not an error.
    """
    if not isinstance(container, dict) or "env" not in container:
        return {}
    e = container["env"]
    if isinstance(e, dict):
        return e
    errors.append(
        f"{loc}: env: is not a plain mapping (got {type(e).__name__}: {e!r}) — "
        "cannot verify it does not set an sccache-wiring key; refused fail-closed"
    )
    return {}


def _refuse_env_keys(env: dict, loc: str, errors: list[str]) -> None:
    """Rule (b) over the keys, and rule (c) over every `KEY: value` pair — a
    value can carry a key name a later `run:` expands into a write."""
    for key in sorted(_env_keys_folded(env) & SCCACHE_ENV_KEYS):
        errors.append(
            f"{loc} env sets {key!r} — sccache wiring must come only from "
            f"{SCCACHE_COMPOSITE_USES}, never a hand-set env:"
        )
    for k, v in env.items():
        _refuse_wiring_text(f"{k}: {v}", loc, f"env.{k}", errors)


def _refuse_wiring_text(text: str | None, loc: str, what: str, errors: list[str]) -> None:
    """Rule (c): free text outside the sanctioned composite that names any
    wrapper/sccache-shaped key or cargo's `rustc-wrapper` spelling — or that
    assembles its target from a GitHub Actions expression function instead of
    naming it literally, which would otherwise dodge the scan above."""
    if text is None:
        return
    m = SCCACHE_WIRING_TEXT_RE.search(text)
    if m:
        errors.append(
            f"{loc} {what} writes {SCCACHE_WRAPPER_VAR}/rustc-wrapper/SCCACHE_*-shaped "
            f"wiring ({m.group(0)!r}: inline env, export, $GITHUB_ENV, `cargo "
            f"--config`, or a cargo config file) outside {SCCACHE_COMPOSITE_USES} — "
            "the composite is the one sanctioned setter"
        )
    expr_error = strict_yaml.refuse_expression_assembly(text, f"{loc} {what}")
    if expr_error:
        errors.append(expr_error)


def _audit_defaults(container: dict, loc: str, errors: list[str]) -> None:
    """`defaults.run.shell` at workflow or job scope wraps every `run:` step,
    so a wrapper hidden there wires rustc for the whole scope."""
    if "defaults" not in container:
        return
    d = container["defaults"]
    if not isinstance(d, dict):
        _refuse_shape(loc, "defaults:", "a mapping", d, errors)
        return
    if "run" not in d:
        return
    r = d["run"]
    if not isinstance(r, dict):
        _refuse_shape(loc, "defaults.run:", "a mapping", r, errors)
        return
    if "shell" in r:
        if isinstance(r["shell"], str):
            _refuse_wiring_text(r["shell"], loc, "defaults.run.shell", errors)
        else:
            _refuse_shape(loc, "defaults.run.shell", "a string", r["shell"], errors)


def _audit_step(st: Step, loc: str, errors: list[str]) -> None:
    """Rules (a)/(b)/(c) for one step outside the sanctioned composite."""
    if st.uses is not None and st.uses_folded.startswith(SCCACHE_ACTION_PREFIX.casefold()):
        errors.append(
            f"{loc} runs the raw {SCCACHE_ACTION_PREFIX}... action directly — use "
            f"{SCCACHE_COMPOSITE_USES} instead, the one place it may run"
        )
    _refuse_env_keys(_scoped_env(st.raw, f"{loc} env", errors), loc, errors)
    for key in ("run", "shell"):
        if key in st.raw and not isinstance(st.raw[key], str):
            _refuse_shape(loc, f"{key}:", "a string", st.raw[key], errors)
    _refuse_wiring_text(st.run, loc, "run:", errors)
    _refuse_wiring_text(st.shell, loc, "shell:", errors)
    if "with" in st.raw:
        w = st.raw["with"]
        if not isinstance(w, dict):
            _refuse_shape(loc, "with:", "a mapping", w, errors)
        else:
            for k, v in w.items():
                _refuse_wiring_text(f"{k}: {v}", loc, f"with.{k}", errors)


@dataclass(frozen=True)
class LocalAction:
    """A resolved local composite action: `id` is its identity (see
    `SCCACHE_COMPOSITE_ID`), `display` the path as written for messages,
    `doc` the parsed action document."""

    id: str
    display: str
    steps: list[Step]
    doc: dict


def _local_action_path(uses: str | None) -> str | None:
    """The normalized repo-root-relative path of a local `uses: ./...`
    reference, or None when `uses` is not local (a pinned third-party
    action, `docker://...`). GitHub resolves a local `uses:` against the
    repository root regardless of which file contains it."""
    if uses is None or not uses.startswith("./"):
        return None
    return posixpath.normpath(uses[2:])


class LocalActions:
    """Every local action reachable from a `uses: ./...`, resolved on disk
    the way GitHub does (repo root, then `action.yml`, then `action.yaml`).
    Resolution is the graph: nothing is discovered by glob, so no reference
    can point at an action this pass never read. Anything it cannot read as
    a composite is refused, never taken to not reach sccache."""

    def __init__(self, root: str, errors: list[str]):
        self.root = root
        self.errors = errors
        self._by_id: dict[str, LocalAction | None] = {}
        self._folded: dict[str, str] = {}
        self._reach: dict[str, bool] = {}

    def disk_dir(self, rel: str) -> str:
        # `root` is the `.github` directory; the repository root is its parent.
        return os.path.join(os.path.dirname(self.root), rel)

    def _exact_on_disk(self, rel: str, shown: str, loc: str) -> bool:
        """Every component of `rel` present on disk is present byte-exactly,
        with no case-fold-equal sibling. A missing tail is left to `_load`."""
        parent = os.path.dirname(self.root)
        for part in rel.split("/"):
            try:
                entries = os.listdir(parent)
            except OSError:
                return True
            twins = sorted(e for e in entries if e.casefold() == part.casefold())
            if len(twins) > 1:
                self.errors.append(
                    f"{loc}: local action {shown!r} passes through {parent!r}, which holds "
                    f"case-fold-equal entries {twins} — ambiguous on a case-insensitive "
                    "runner; refused"
                )
                return False
            if twins and twins[0] != part:
                self.errors.append(
                    f"{loc}: local action {shown!r} names {part!r} but the directory holds "
                    f"{twins[0]!r} — identity is byte-exact; refused"
                )
                return False
            parent = os.path.join(parent, part)
        return True

    def audit_case_collisions(self, top: str, loc: str) -> None:
        """Refuse any directory under `top` holding two case-fold-equal
        entries, referenced or not: a case-insensitive checkout merges them."""
        for d, dirs, files in os.walk(top):
            dirs.sort()
            seen: dict[str, str] = {}
            for e in sorted(dirs + files):
                first = seen.setdefault(e.casefold(), e)
                if first != e:
                    self.errors.append(
                        f"{loc}: {d!r} holds case-fold-equal entries {first!r} and {e!r} — "
                        "a case-insensitive runner resolves both to one path; refused"
                    )

    def resolve(self, uses: str | None, loc: str) -> LocalAction | None:
        """The composite behind a local `uses:`, or None (not local, or
        refused — the refusal is recorded)."""
        rel = _local_action_path(uses)
        if rel is None:
            return None
        if rel in self._by_id:
            return self._by_id[rel]
        self._by_id[rel] = None
        other = self._folded.setdefault(rel.casefold(), rel)
        if other != rel:
            self.errors.append(
                f"{loc}: local action {uses!r} is case-fold-equal to {other!r} but not "
                "byte-equal — a case-insensitive runner resolves both to one directory; refused"
            )
            return None
        if rel in (".", "..") or rel.startswith("../") or os.path.isabs(rel):
            self.errors.append(f"{loc}: local action {uses!r} escapes the repository root; refused")
            return None
        if not self._exact_on_disk(rel, uses or rel, loc):
            return None
        action = self._load(rel, uses or rel, loc)
        self._by_id[rel] = action
        if action is not None and rel != SCCACHE_COMPOSITE_ID:
            for st in action.steps:
                _audit_step(st, f"{action.display}/action.yml: step {st.label!r}", self.errors)
        return action

    def _load(self, rel: str, shown: str, loc: str) -> LocalAction | None:
        d = self.disk_dir(rel)
        found = [
            os.path.join(d, n) for n in ("action.yml", "action.yaml") if os.path.isfile(os.path.join(d, n))
        ]
        if not found:
            self.errors.append(
                f"{loc}: local action {shown!r} does not exist (no action.yml/action.yaml "
                f"at {d}) — an unresolved action cannot be proven sccache-free; refused"
            )
            return None
        if len(found) > 1:
            self.errors.append(
                f"{loc}: local action {shown!r} has both action.yml and action.yaml — "
                "ambiguous; refused"
            )
            return None
        path = found[0]
        try:
            with open(path) as f:
                doc = strict_yaml.safe_load(f)
        except yaml.YAMLError as e:
            self.errors.append(f"{path} is not valid YAML: {e}")
            return None
        if not isinstance(doc, dict):
            _refuse_shape(path, "the action document", "a mapping", doc, self.errors)
            return None
        runs = doc.get("runs")
        if not isinstance(runs, dict):
            _refuse_shape(path, "runs:", "a mapping", runs, self.errors)
            return None
        if runs.get("using") != "composite":
            self.errors.append(
                f"{path}: `runs.using` must be 'composite' (got {runs.get('using')!r}) — a "
                "node/docker local action is opaque to this check; refused"
            )
            return None
        display = "./" + rel
        return LocalAction(rel, display, _typed_steps(runs, path, self.errors), doc)

    def reaches_sccache(self, action: LocalAction, loc: str) -> bool:
        """Whether `action` is, or transitively `uses:`, the sanctioned
        composite. A cycle or a chain past `LOCAL_ACTION_DEPTH_LIMIT` is
        recorded as a refusal and answered True (fail closed)."""
        return self._walk(action, loc, 0, frozenset())

    def _walk(self, action: LocalAction, loc: str, depth: int, stack: frozenset[str]) -> bool:
        if action.id == SCCACHE_COMPOSITE_ID:
            return True
        if action.id in self._reach:
            return self._reach[action.id]
        if action.id in stack:
            self.errors.append(f"{loc}: local action cycle through {action.display}; refused")
            return True
        if depth >= LOCAL_ACTION_DEPTH_LIMIT:
            self.errors.append(
                f"{loc}: local action nesting exceeds {LOCAL_ACTION_DEPTH_LIMIT} levels at "
                f"{action.display} — reach of {SCCACHE_COMPOSITE_USES} cannot be decided; refused"
            )
            return True
        hit = False
        for st in action.steps:
            child = self.resolve(st.uses, f"{action.display}/action.yml: step {st.label!r}")
            if child is not None and self._walk(child, loc, depth + 1, stack | {action.id}):
                hit = True
        self._reach[action.id] = hit
        return hit


def _check_sccache_composite(actions: LocalActions, errors: list[str]) -> None:
    """The composite action is the one sanctioned place `sccache-action` may
    run and `$GITHUB_ENV` may be written, so a job trusting `uses:
    ./.github/actions/sccache` must get a real wrapper. Proof is equality:
    the document holds only `SCCACHE_COMPOSITE_DOC_KEYS`, `runs:` is exactly
    `{using: composite, steps: [install, wire]}`, the install step is exactly
    `{uses: mozilla-actions/sccache-action@<ref>}`, and the wiring step equals
    `SCCACHE_WIRE_STEP`. Any other shape — a condition, an extra or reordered
    step, a nested local `uses:`, an extra key — is refused.
    """
    action = actions.resolve(SCCACHE_COMPOSITE_USES, "sccache composite self-check")
    if action is None:
        return
    where = f"{action.display}/action.yml"
    extra = sorted(str(k) for k in action.doc if k not in SCCACHE_COMPOSITE_DOC_KEYS)
    if extra:
        errors.append(f"{where}: keys {extra} are outside the canonical composite; refused")
    runs = action.doc["runs"]
    if set(runs) != {"using", "steps"}:
        errors.append(
            f"{where}: `runs:` keys must be exactly ['steps', 'using'] (got "
            f"{sorted(str(k) for k in runs)}); refused"
        )
    steps = runs.get("steps")
    if not isinstance(steps, list) or len(steps) != 2:
        errors.append(
            f"{where}: the canonical composite has exactly two steps (install, then "
            f"wire), got {steps!r}; refused"
        )
        return
    install, wire = steps
    if not (
        isinstance(install, dict)
        and set(install) == {"uses"}
        and isinstance(install["uses"], str)
        and SCCACHE_INSTALL_USES_RE.match(install["uses"])
    ):
        errors.append(
            f"{where}: step 1 must be exactly {{'uses': '{SCCACHE_ACTION_PREFIX}<ref>'}} "
            f"(got {install!r}); refused"
        )
    if wire != SCCACHE_WIRE_STEP:
        errors.append(
            f"{where}: step 2 is not the canonical wiring step {SCCACHE_WIRE_STEP!r} "
            f"(got {wire!r}) — any other shape can leave rustc unwired; refused"
        )


def _job_sub_env_scopes(job_raw: dict, loc: str, errors: list[str]) -> list[tuple[str, dict]]:
    """(scope-name, raw-container) pairs for a job's `container:` and each
    `services.<id>:` sub-scope — each may carry its own `env:` a
    sccache-wiring key could hide in, same as the job's own `env:`. A
    string `container:` (image only) has no env; any other non-mapping
    shape is refused."""
    scopes: list[tuple[str, dict]] = []
    if "container" in job_raw:
        container = job_raw["container"]
        if isinstance(container, dict):
            scopes.append(("container", container))
        elif not isinstance(container, str):
            _refuse_shape(loc, "container:", "a mapping or image string", container, errors)
    if "services" in job_raw:
        services = job_raw["services"]
        if not isinstance(services, dict):
            _refuse_shape(loc, "services:", "a mapping", services, errors)
        else:
            for sid, svc in services.items():
                if isinstance(svc, dict):
                    scopes.append((f"service {sid!r}", svc))
                else:
                    _refuse_shape(loc, f"service {sid!r}", "a mapping", svc, errors)
    return scopes


def check_sccache_wiring(errors: list[str], root: str = REPO_ROOT) -> None:
    """The only sanctioned way a job gets sccache is `uses:
    ./.github/actions/sccache` (see `_check_sccache_composite`), so a wrapper
    never exists in a job without the binary that backs it. Refused:
      (a) a raw `mozilla-actions/sccache-action` reference (case-folded) in a
          workflow or any other reachable local action;
      (b) an `env:` key naming a wrapper var, a rustc-replacing var
          (`RUSTC`, `CARGO_BUILD_RUSTC`), or SCCACHE_GHA_ENABLED (case-folded)
          at workflow, job, container, service, or step scope, in a workflow
          or any other reachable local action; an `env:` that is present but
          not a plain mapping is refused outright;
      (c) free text naming a wrapper var, a rustc-replacing var, an SCCACHE_*
          key, or cargo's `rustc-wrapper` spelling in any `env:` value (every
          scope of (b)), `run:`, step `shell:`, workflow/job
          `defaults.run.shell`, or `with:` value — any syntax, `$GITHUB_ENV`
          or not (YAML comments are not values and are never read);
      (d) a job that reaches the sccache composite — directly or through any
          chain of local actions — while owning a step named in
          `ci/deterministic-checks.json` (sccache's GitHub Actions cache
          backend does network I/O); an unreadable deterministic-checks file
          is itself refused, since the step set cannot be established.
    Every local `uses: ./...` is resolved on disk from the repo root
    (`action.yml`, then `action.yaml`); an unresolvable, ambiguous, non-
    composite (node/docker), cyclic, or over-deep (> LOCAL_ACTION_DEPTH_LIMIT)
    reference is refused. Identity is the normalized, byte-exact path: a
    reference, or any entry under `.github/actions/` referenced or not, that
    is case-fold-equal to another path but not byte-equal is refused, so the
    composite's exemption from (a)-(c) holds only for its exact path. A
    job-level `uses:` (reusable workflow, local or remote) is refused. A
    malformed shape (`jobs:`, `steps:`, a job, a step, `env:`, `defaults:`,
    `container:`, `services:`) is refused, never skipped.

    LIMIT — static YAML cannot see, and this check does NOT prove absent:
      - a third-party action that itself exports a wrapper into the job;
      - a repo script invoked from `run:` (`run: tools/ci/wire.sh`) that
        writes a wrapper or `$GITHUB_ENV`;
      - key indirection assembled at run time (`K=WRAPPER; echo
        "RUSTC_$K=..." >> "$GITHUB_ENV"`), or an `env:`/`with:` value whose
        key name arrives only through `${{ }}` (`vars`, `secrets`, outputs);
      - a rustc replacement outside the named keys (a `PATH` entry shadowing
        `rustc`, a `rustup` toolchain override, a linker/runner setting).
    Those are review-gated, not machine-gated.
    """
    start = len(errors)
    actions = LocalActions(root, errors)
    _check_sccache_composite(actions, errors)

    det_errors: list[str] = []
    pairs = load_deterministic_checks(det_errors, root)
    if pairs is None:
        errors.append(
            "check 6 cannot establish the deterministic check steps "
            f"({det_errors[0] if det_errors else 'unreadable'}) — refused fail-closed"
        )
        deterministic_steps: set[str] = set()
    else:
        deterministic_steps = {step for _, step in pairs}

    # Defence in depth: every action on disk under `.github/actions/` is
    # audited even when nothing references it yet. Reachability never relies
    # on this list — it comes from resolving each `uses:`.
    actions.audit_case_collisions(os.path.join(root, "actions"), "local action audit")
    for pattern in ("action.yml", "action.yaml"):
        for path in sorted(glob.glob(os.path.join(root, "actions", "**", pattern), recursive=True)):
            rel = os.path.relpath(os.path.dirname(path), root).replace(os.sep, "/")
            actions.resolve(f"./.github/{rel}", "local action audit")

    for wf in _load_sccache_workflows(root, errors):
        wloc = f"{wf.fname}: workflow-level"
        _refuse_env_keys(_scoped_env(wf.doc, f"{wloc} env", errors), wloc, errors)
        _audit_defaults(wf.doc, wf.fname, errors)
        for job in wf.jobs:
            jloc = f"{wf.fname}: job {job.job_id!r}"
            _refuse_env_keys(_scoped_env(job.raw, f"{jloc} env", errors), jloc, errors)
            _audit_defaults(job.raw, jloc, errors)
            for scope_name, scope_raw in _job_sub_env_scopes(job.raw, jloc, errors):
                sloc = f"{jloc} {scope_name}"
                _refuse_env_keys(_scoped_env(scope_raw, f"{sloc} env", errors), sloc, errors)
            if "uses" in job.raw:
                errors.append(
                    f"{jloc}: calls a reusable workflow ({job.raw['uses']!r}) — its jobs "
                    "are outside this check; refused"
                )
            steps = _typed_steps(job.raw, jloc, errors)
            via: str | None = None
            reaches = False
            for st in steps:
                stloc = f"{jloc} step {st.label!r}"
                _audit_step(st, stloc, errors)
                action = actions.resolve(st.uses, stloc)
                if action is not None and actions.reaches_sccache(action, stloc):
                    reaches = True
                    if via is None and action.id != SCCACHE_COMPOSITE_ID:
                        via = action.display
            if reaches:
                hit = sorted({st.name for st in steps if st.name is not None} & deterministic_steps)
                if hit:
                    via_note = f" (via {via})" if via else ""
                    errors.append(
                        f"{jloc} uses {SCCACHE_COMPOSITE_USES}{via_note} but also owns "
                        f"deterministic check step(s) {hit} — sccache's GitHub Actions "
                        "cache backend does network I/O inside a step that must be "
                        "network-free (ci/deterministic-checks.json)"
                    )

    # One defect reached from several sites is reported once.
    own = list(dict.fromkeys(errors[start:]))
    del errors[start:]
    errors.extend(own)


def load_manifest() -> dict:
    doc = strict_yaml.safe_load(open(MANIFEST))
    if not isinstance(doc, dict) or "checks" not in doc:
        print("verify-manifest: manifest missing top-level `checks:`", file=sys.stderr)
        sys.exit(2)
    return doc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--ruleset",
        help="JSON file: a list of required status-check context strings. "
        "When given, gate<->required mismatches are fatal.",
    )
    args = ap.parse_args()

    manifest = load_manifest()
    entries = manifest["checks"]
    by_context: dict[str, dict] = {}
    errors: list[str] = []

    # ---- 2. manifest self-consistency ----
    for e in entries:
        ctx = e.get("context")
        disp = e.get("disposition")
        if not ctx:
            errors.append(f"manifest entry without a context: {e!r}")
            continue
        if ctx in by_context:
            errors.append(f"duplicate manifest context: {ctx!r}")
        by_context[ctx] = e
        if disp not in VALID_DISPOSITIONS:
            errors.append(f"{ctx!r}: invalid disposition {disp!r} (want one of {sorted(VALID_DISPOSITIONS)})")
            continue
        if disp == "informational" and not e.get("owner"):
            errors.append(f"{ctx!r}: informational check must name an `owner`")
        if disp == "informational" and e.get("guards"):
            errors.append(
                f"{ctx!r}: guards {e['guards']!r} but is informational — a "
                "Security/Soundness/SEAL guarantee may not be un-gated"
            )
        if disp in ("gate", "nightly-gate") and not e.get("producer"):
            errors.append(f"{ctx!r}: {disp} entry has no producer workflow")
        if disp == "gate-external" and e.get("producer"):
            errors.append(
                f"{ctx!r}: disposition=gate-external must have no producer — the "
                "status is posted out-of-band, not by a CI workflow"
            )
        if disp == "delete" and e.get("producer"):
            errors.append(
                f"{ctx!r}: disposition=delete but a producer is set — a live "
                "check may not be marked delete"
            )

    # ---- 1. every produced context is classified ----
    jobs = workflow_jobs()
    produced = produced_contexts(jobs)
    manifest_ctxs = set(by_context)

    # A context named in some entry's `aggregates:` list is an internal matrix
    # leg / prep job whose result rolls up into that single promotable context;
    # it inherits the aggregator's disposition and is considered classified.
    # `aggregates:` names the job id or the leg-name PREFIX (matrix legs expand
    # to "<name> (i/n)"), so match by exact id or by prefix.
    aggregated_prefixes: list[str] = []
    aggregated_exact: set[str] = set()
    for e in by_context.values():
        for agg in e.get("aggregates") or []:
            aggregated_exact.add(agg)
            aggregated_prefixes.append(agg)

    def is_aggregated(ctx: str) -> bool:
        if ctx in aggregated_exact:
            return True
        # matrix leg "asan (1/6)" is aggregated by "asan"
        return any(ctx.startswith(p + " (") or ctx == p for p in aggregated_prefixes)

    for ctx, wfs in sorted(produced.items()):
        if len(wfs) > 1:
            errors.append(
                f"context {ctx!r} is produced by {len(wfs)} jobs ({', '.join(wfs)}) — "
                "a required context must resolve to exactly one producer; give "
                "each job a unique `name:`"
            )
        if ctx in manifest_ctxs or is_aggregated(ctx):
            continue
        errors.append(
            f"produced context {ctx!r} (from {wfs[0]}) has NO disposition in "
            "ci/check-manifest.yml — every check must be classified"
        )

    # ---- 5. ci/deterministic-checks.json vs the watcher + ci.yml steps ----
    check_deterministic_set(jobs, errors)

    # ---- 6. sccache wiring: action <-> RUSTC_WRAPPER/SCCACHE_GHA_ENABLED ----
    check_sccache_wiring(errors)

    # ---- 3. fail-closed dependency surfacing ----
    def surfaced_dispositions(job: Job) -> set[str]:
        """Dispositions of the manifest entries this job's outcome reaches."""
        disps: set[str] = set()
        for ctx in job.contexts:
            entry = by_context.get(ctx)
            if entry:
                disps.add(entry["disposition"])
        for entry in by_context.values():
            for agg in entry.get("aggregates") or []:
                if agg == job.job_id or any(
                    c == agg or c.startswith(agg + " (") for c in job.contexts
                ):
                    disps.add(entry["disposition"])
        return disps

    surfacing = {"gate": {"gate"}, "nightly-gate": {"gate", "nightly-gate"}}
    for job in jobs:
        direct = {by_context[c]["disposition"] for c in job.contexts if c in by_context}
        siblings = {j.job_id: j for j in jobs if j.workflow == job.workflow}
        for disp, allowed in surfacing.items():
            if disp not in direct:
                continue
            seen: set[str] = set()
            pending = list(job.needs)
            while pending:
                dep_id = pending.pop()
                if dep_id in seen:
                    continue
                seen.add(dep_id)
                dep = siblings.get(dep_id)
                if dep is None:
                    errors.append(f"{job.workflow}: job {job.job_id!r} needs unknown job {dep_id!r}")
                    continue
                if surfaced_dispositions(dep).isdisjoint(allowed):
                    errors.append(
                        f"{job.workflow}: {disp} {job.contexts[0]!r} needs {dep_id!r}, "
                        f"which surfaces in no {'/'.join(sorted(allowed))} context — its "
                        "failure would skip the gate, and a skipped required check "
                        "passes (fail-open)"
                    )
                pending.extend(dep.needs)

    # A manifest gate/nightly-gate that claims a live producer but is not
    # actually produced (an orphan the other way).  gate-external is excluded:
    # its whole purpose is to be required without a CI producer.
    for ctx, e in by_context.items():
        if e.get("internal"):
            continue
        if e["disposition"] in ("gate", "nightly-gate") and ctx not in produced:
            errors.append(
                f"{ctx!r}: disposition={e['disposition']} with producer "
                f"{e.get('producer')!r} but NO workflow produces this context "
                "(orphaned required context — wire it or set disposition:delete)"
            )

    # ---- 4. required-set reconciliation ----
    # gate-external contexts are required by the ruleset even though no CI
    # workflow produces them; include them alongside plain gate entries.
    gate_ctxs = {c for c, e in by_context.items() if e["disposition"] in ("gate", "gate-external")}
    if args.ruleset:
        required = set(json.load(open(args.ruleset)))
        missing_from_ruleset = gate_ctxs - required
        extra_in_ruleset = required - gate_ctxs
        for c in sorted(missing_from_ruleset):
            errors.append(f"gate {c!r} is NOT in the required set (add it to the ruleset)")
        for c in sorted(extra_in_ruleset):
            errors.append(
                f"required context {c!r} is not a manifest `gate` "
                "(remove from the ruleset or re-classify)"
            )
    else:
        print(
            "verify-manifest: no --ruleset given; skipping live required-set "
            "reconciliation. The manifest is the SSOT; see ci/RECONCILIATION.md "
            "for the intended required set."
        )

    if errors:
        print("\nverify-manifest: FAIL\n", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(file=sys.stderr)
        return 1

    n_gate = sum(1 for e in entries if e["disposition"] == "gate")
    n_gate_ext = sum(1 for e in entries if e["disposition"] == "gate-external")
    n_nightly = sum(1 for e in entries if e["disposition"] == "nightly-gate")
    n_info = sum(1 for e in entries if e["disposition"] == "informational")
    n_del = sum(1 for e in entries if e["disposition"] == "delete")
    print(
        f"verify-manifest: OK — {len(entries)} checks classified "
        f"({n_gate} gate, {n_gate_ext} gate-external, {n_nightly} nightly-gate, "
        f"{n_info} informational, {n_del} delete); "
        f"{len(produced)} produced contexts, all covered."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
