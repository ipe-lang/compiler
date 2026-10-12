#!/usr/bin/env python3
"""SSOT for the e2e SEAL shard partition: its selection, its plan, its wiring.

A shard's test selection is defined here once. `--plan` publishes every
shard's selection as the `changes` job output `e2e_plan`; each `e2e` matrix
shard runs `cargo nextest run` on its own entry of that plan, and `seal-slice`
proves (`tools/scripts/e2e-shard-cover.py`, from the run's own nextest archive)
that the same plan partitions the archive exactly: every test is selected by
exactly one shard and no shard selects a test outside the archive. `--lint`
proves ci.yml wires exactly that: the `e2e` matrix enumerates shards
1..SHARDS, its one nextest run reads its selection only from the plan, and
`seal-slice` proves the cover of that same plan; artifact-guard runs it.

Modes:
  --plan    write `plan=<JSON {"K": {"filter", "partition"}}>` to $GITHUB_OUTPUT.
  --lint    fail unless ci.yml wires the plan, the shards and the cover exactly.

Every failure exits non-zero; an unwritable output or an unexpected shape is a
failure, never a pass.
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
CI_WORKFLOW = os.path.join(REPO, ".github", "workflows", "ci.yml")
E2E_JOB = "e2e"
CHANGES_JOB = "changes"
SEAL_SLICE_JOB = "seal-slice"
PLAN_INVOCATION = "python3 .github/ci/e2e_shard.py --plan"
PLAN_STEP_ID = "e2e-plan"
PLAN_OUTPUT = "e2e_plan"
PLAN_OUTPUT_VALUE = "${{ steps.e2e-plan.outputs.plan }}"
COVER_INVOCATION = "python3 tools/scripts/e2e-shard-cover.py"
COVER_ENV = {"E2E_PLAN": "${{ needs.changes.outputs.e2e_plan }}"}
_SHARD_ENTRY = "fromJSON(needs.changes.outputs.e2e_plan)[matrix.shard]"
SHARD_ENV = {
    "SHARD_FILTER": "${{ " + _SHARD_ENTRY + ".filter }}",
    "SHARD_PARTITION": "${{ " + _SHARD_ENTRY + ".partition }}",
}

# The goldens whose emitted project drives a real multi-minute cold `cargo
# build` (webview/wry, server/axum, the live-HTTP set, the watch daemons). The
# `ci` nextest profile serializes this set into `heavy-server-e2e`
# (max-threads=1), so the HEAVY shards spread it across parallel runners and
# the LIGHT shards run the heavy-free complement at full width.
HEAVY = (
    "binary(watch_sigterm) | binary(watch_integration) | binary(watch_hot_appearance)"
    " | binary(watch_bluegreen) | binary(watch_cancellation) | binary(server_e2e)"
    " | binary(live_e2e) | binary(http_e2e) | binary(g_http_live) | binary(webview_e2e)"
    " | binary(secured_store_e2e) | binary(test_command) | binary(verify) | binary(stdlib_coverage_dynamic)"
)
HEAVY_SHARDS = 5
LIGHT_SHARDS = 9
SHARDS = HEAVY_SHARDS + LIGHT_SHARDS

ARCHIVE_ARGS = ("--archive-file", "nextest.tar.zst", "--workspace-remap", ".", "--profile", "ci")
# `--test-threads=2`: each E2E test drives a memory-heavy emitted-project
# `cargo build` that itself uses every core; two in flight fit the runner.
# `--no-tests=fail`: a shard whose selection matches nothing is red, never a
# vacuous green.
RUN_ONLY_ARGS = ("--no-fail-fast", "--test-threads=2", "--no-tests=fail")
RUN_COMMAND = " ".join(
    ("cargo", "nextest", "run", *ARCHIVE_ARGS, *RUN_ONLY_ARGS, '-E "$SHARD_FILTER"', '--partition "$SHARD_PARTITION"')
)


class ShardError(Exception):
    """A shard index, listing, or workflow shape that proves nothing."""


def selection(shard: int) -> list[str]:
    """Return the nextest filter + partition arguments of one shard."""
    if isinstance(shard, bool) or not isinstance(shard, int) or not 1 <= shard <= SHARDS:
        raise ShardError(f"shard must be an integer in 1..{SHARDS}, got {shard!r}")
    if shard <= HEAVY_SHARDS:
        return ["-E", HEAVY, "--partition", f"count:{shard}/{HEAVY_SHARDS}"]
    return ["-E", f"not ({HEAVY})", "--partition", f"count:{shard - HEAVY_SHARDS}/{LIGHT_SHARDS}"]


def plan() -> dict[str, dict[str, str]]:
    """Return every shard's selection, keyed by its decimal index."""
    out: dict[str, dict[str, str]] = {}
    for k in range(1, SHARDS + 1):
        _, filt, _, part = selection(k)
        out[str(k)] = {"filter": filt, "partition": part}
    return out


def write_plan(path: str) -> int:
    """Append the plan to the step-output file; no file or a failed write is exit 1."""
    if not path:
        print("e2e_shard: GITHUB_OUTPUT is unset", file=sys.stderr)
        return 1
    line = "plan=" + json.dumps(plan(), separators=(",", ":"), sort_keys=True)
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        print(f"e2e_shard: GITHUB_OUTPUT is unwritable: {exc}", file=sys.stderr)
        return 1
    print(f"e2e_shard: planned {SHARDS} shards ({HEAVY_SHARDS} heavy, {LIGHT_SHARDS} light).")
    return 0


def _steps(job: object) -> list[dict]:
    steps = job.get("steps") if isinstance(job, dict) else None
    return [s for s in steps if isinstance(s, dict)] if isinstance(steps, list) else []


def _needs(job: dict) -> list[object]:
    needs = job.get("needs")
    return [needs] if isinstance(needs, str) else needs if isinstance(needs, list) else []


def _runs(step: dict, text: str) -> bool:
    run = step.get("run")
    return isinstance(run, str) and text in run


def _exact_step(steps: list[dict], text: str, what: str) -> tuple[dict | None, list[str]]:
    """Return the one step whose run names `text`, refusing none, many, or a masked one."""
    found = [s for s in steps if _runs(s, text)]
    if len(found) != 1:
        return None, [f"{what}: exactly one step must run `{text}`, found {len(found)}"]
    step = found[0]
    errors: list[str] = []
    if step.get("run", "").strip() != text:
        errors.append(f"{what}: the step must run only `{text}`, got {step.get('run')!r}")
    if "continue-on-error" in step:
        errors.append(f"{what}: the step must not set `continue-on-error`")
    return step, errors


def wiring_errors(workflow: dict) -> list[str]:
    """Return why ci.yml could run a shard, or prove a cover, off the SSOT plan, or []."""
    jobs = workflow.get("jobs") if isinstance(workflow, dict) else None
    if not isinstance(jobs, dict):
        return ["ci.yml has no jobs"]
    errors: list[str] = []
    changes = jobs.get(CHANGES_JOB)
    if not isinstance(changes, dict):
        errors.append(f"ci.yml has no `{CHANGES_JOB}` job")
    else:
        step, errs = _exact_step(_steps(changes), PLAN_INVOCATION, f"`{CHANGES_JOB}`")
        errors += errs
        if step is not None:
            if step.get("id") != PLAN_STEP_ID:
                errors.append(f"`{CHANGES_JOB}`: the plan step must have `id: {PLAN_STEP_ID}`")
            if "if" in step or "env" in step:
                errors.append(f"`{CHANGES_JOB}`: the plan step must set no `if:` or `env:`")
        outputs = changes.get("outputs")
        if not isinstance(outputs, dict) or outputs.get(PLAN_OUTPUT) != PLAN_OUTPUT_VALUE:
            errors.append(f"`{CHANGES_JOB}` output `{PLAN_OUTPUT}` must be exactly `{PLAN_OUTPUT_VALUE}`")
    job = jobs.get(E2E_JOB)
    if not isinstance(job, dict):
        return [*errors, f"ci.yml has no `{E2E_JOB}` job"]
    strategy = job.get("strategy")
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    if not isinstance(matrix, dict) or set(matrix) != {"shard"}:
        errors.append(f"`{E2E_JOB}` matrix must have exactly one key, `shard`")
    elif matrix["shard"] != list(range(1, SHARDS + 1)):
        errors.append(f"`{E2E_JOB}` matrix shard is {matrix['shard']!r}, expected 1..{SHARDS}")
    if CHANGES_JOB not in _needs(job):
        errors.append(f"`{E2E_JOB}` must need `{CHANGES_JOB}`, the job that publishes the plan")
    steps = _steps(job)
    step, errs = _exact_step(steps, RUN_COMMAND, f"`{E2E_JOB}`")
    errors += errs
    if step is not None:
        env = step.get("env")
        if not isinstance(env, dict) or {k: env.get(k) for k in SHARD_ENV} != SHARD_ENV:
            errors.append(f"`{E2E_JOB}`: the shard step's selection env must be exactly {SHARD_ENV}")
    if sum(_runs(s, "nextest run") for s in steps) != 1:
        errors.append(f"`{E2E_JOB}` must run nextest in exactly one step, the planned shard run")
    for job_id, other in jobs.items():
        if job_id != E2E_JOB and any(_runs(s, "SHARD_FILTER") for s in _steps(other)):
            errors.append(f"job {job_id!r} reads a shard selection outside `{E2E_JOB}`")
    seal = jobs.get(SEAL_SLICE_JOB)
    if not isinstance(seal, dict):
        errors.append(f"ci.yml has no `{SEAL_SLICE_JOB}` job")
    else:
        if CHANGES_JOB not in _needs(seal):
            errors.append(f"`{SEAL_SLICE_JOB}` must need `{CHANGES_JOB}`, the job that publishes the plan")
        step, errs = _exact_step(_steps(seal), COVER_INVOCATION, f"`{SEAL_SLICE_JOB}`")
        errors += errs
        if step is not None and step.get("env") != COVER_ENV:
            errors.append(f"`{SEAL_SLICE_JOB}`: the cover step's env must be exactly {COVER_ENV}")
    return errors


def lint(path: str = CI_WORKFLOW) -> int:
    """Fail unless ci.yml wires the plan, the shards and the cover exactly."""
    sys.path.insert(0, HERE)
    import strict_yaml  # noqa: PLC0415  # PyYAML-backed; only `--lint` needs it

    try:
        with open(path, encoding="utf-8") as fh:
            workflow = strict_yaml.safe_load(fh)
    except Exception as exc:  # noqa: BLE001  # any read or parse failure is a refusal
        print(f"e2e shard lint: ci.yml is unreadable: {exc}", file=sys.stderr)
        return 1
    errors = wiring_errors(workflow)
    for err in errors:
        print(f"e2e shard lint: {err}", file=sys.stderr)
    if errors:
        return 1
    print(f"e2e shard lint: ci.yml runs shards 1..{SHARDS} from the plan and proves its cover.")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--plan"]:
        return write_plan(os.environ.get("GITHUB_OUTPUT", ""))
    if argv == ["--lint"]:
        return lint()
    print("usage: e2e_shard.py --plan | --lint", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
