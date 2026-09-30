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
`seal-slice` proves the cover of that same plan; manifest-guard runs it.

Balance. The HEAVY class runs on shards 1..HEAVY_SHARDS, the LIGHT class on
the rest. Within a class a test's bucket is `len(test name) mod MODULUS`,
selected by a `test()` regex: every name has exactly one length, so each
class's buckets are total and disjoint by construction, and naming no binary
or test the selection never rots into a filterset error. Buckets are assigned
to the class's shards by longest-processing-time greedy over the measured
seconds per bucket in `e2e_shard_weights.json`, so every shard lands near the
class mean. The weights only steer the assignment: a stale or all-zero table
costs balance, never coverage. Refresh them from recent `e2e` job logs with
`.github/ci/e2e_shard_weights.py`.

Modes:
  --plan    write `plan=<JSON {"K": {"filter"}}>` to $GITHUB_OUTPUT.
  --lint    fail unless the plan builds and ci.yml wires the plan, the shards
            and the cover exactly.

Every failure exits non-zero; an unwritable output or an unexpected shape is a
failure, never a pass.
"""

from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
CI_WORKFLOW = os.path.join(REPO, ".github", "workflows", "ci.yml")
NEXTEST_TOML = os.path.join(REPO, ".config", "nextest.toml")
WEIGHTS_FILE = os.path.join(HERE, "e2e_shard_weights.json")
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
SHARD_ENV = {"SHARD_FILTER": "${{ " + _SHARD_ENTRY + ".filter }}"}

# The goldens whose emitted project drives a real multi-minute cold `cargo
# build` (webview/wry, server/axum, the live-HTTP set, the watch daemons). The
# `ci` nextest profile serializes this set into `heavy-server-e2e`
# (max-threads=1), so the HEAVY shards spread it across parallel runners and
# the LIGHT shards run the heavy-free complement at full width.
HEAVY_BINARIES = (
    "watch_sigterm", "watch_integration", "watch_hot_appearance", "watch_bluegreen",
    "watch_cancellation", "server_e2e", "live_e2e", "http_e2e", "g_http_live",
    "webview_e2e", "test_command", "verify", "stdlib_coverage_dynamic",
)
HEAVY = " | ".join(f"binary({b})" for b in HEAVY_BINARIES)
# The nextest test-group `.config/nextest.toml` uses to serialize HEAVY_BINARIES
# (see that file's `heavy-server-e2e` comment). `--lint` proves its `ci` and
# `default` profile overrides select exactly this SSOT's binaries, so the two
# copies of the heavy set cannot drift apart unnoticed.
HEAVY_TEST_GROUP = "heavy-server-e2e"
HEAVY_SHARDS = 5
LIGHT_SHARDS = 9
SHARDS = HEAVY_SHARDS + LIGHT_SHARDS
# Class name -> (class filter, first shard, shard count); the classes tile 1..SHARDS.
CLASSES = {
    "heavy": (HEAVY, 1, HEAVY_SHARDS),
    "light": (f"not ({HEAVY})", HEAVY_SHARDS + 1, LIGHT_SHARDS),
}
# Name-length buckets per class; at least the widest class's shard count, so
# every shard owns a bucket.
MODULUS = 64

ARCHIVE_ARGS = ("--archive-file", "nextest.tar.zst", "--workspace-remap", ".", "--profile", "ci")
# `--test-threads=2`: each E2E test drives a memory-heavy emitted-project
# `cargo build` that itself uses every core; two in flight fit the runner.
# `--no-tests=fail`: a shard whose selection matches nothing is red, never a
# vacuous green.
RUN_ONLY_ARGS = ("--no-fail-fast", "--test-threads=2", "--no-tests=fail")
RUN_COMMAND = " ".join(("cargo", "nextest", "run", *ARCHIVE_ARGS, *RUN_ONLY_ARGS, '-E "$SHARD_FILTER"'))


class ShardError(Exception):
    """A shard index, weight table, listing, or workflow shape that proves nothing."""


def bucket(name: str) -> int:
    """Return the name-length bucket of one test name."""
    return len(name) % MODULUS


def bucket_regex(buckets: list[int]) -> str:
    """Return the regex matching exactly the test names whose bucket is in `buckets`."""
    if not buckets or any(isinstance(b, bool) or not isinstance(b, int) or not 0 <= b < MODULUS for b in buckets):
        raise ShardError(f"buckets must be a non-empty list of integers in 0..{MODULUS - 1}, got {buckets!r}")
    alts = "|".join(f".{{{b}}}" for b in sorted(set(buckets)))
    return f"^(?:.{{{MODULUS}}})*(?:{alts})$"


def parse_weights(doc: object) -> dict[str, list[int]]:
    """Parse `{class: [seconds per bucket]}`, one entry per class and per bucket."""
    if not isinstance(doc, dict) or set(doc) != set(CLASSES):
        raise ShardError(f"weights must be an object with exactly the keys {sorted(CLASSES)}")
    out: dict[str, list[int]] = {}
    for cls, row in doc.items():
        if not isinstance(row, list) or len(row) != MODULUS:
            raise ShardError(f"weights[{cls!r}] must list exactly {MODULUS} buckets")
        if any(isinstance(w, bool) or not isinstance(w, int) or w < 0 for w in row):
            raise ShardError(f"weights[{cls!r}] must hold non-negative integer seconds")
        out[cls] = row
    return out


def load_weights(path: str | None = None) -> dict[str, list[int]]:
    """Read and parse the weight table (default: the checked-in one); an unreadable table is a ShardError."""
    path = WEIGHTS_FILE if path is None else path
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ShardError(f"weights {path} are unreadable: {exc}") from exc
    return parse_weights(doc)


def assign(weights: list[int], bins: int) -> list[list[int]]:
    """Spread buckets over `bins` shards, heaviest first onto the lightest shard.

    Ties go to the shard holding fewer buckets, then the lower index, so the
    result is deterministic and, with at least `bins` buckets, no shard is empty.
    """
    if not 1 <= bins <= len(weights):
        raise ShardError(f"cannot spread {len(weights)} buckets over {bins} shards")
    load = [0] * bins
    owned: list[list[int]] = [[] for _ in range(bins)]
    for b in sorted(range(len(weights)), key=lambda b: (-weights[b], b)):
        j = min(range(bins), key=lambda j: (load[j], len(owned[j]), j))
        load[j] += weights[b]
        owned[j].append(b)
    return [sorted(o) for o in owned]


def plan(weights: dict[str, list[int]] | None = None) -> dict[str, dict[str, str]]:
    """Return every shard's selection, keyed by its decimal index."""
    table = load_weights() if weights is None else parse_weights(weights)
    out: dict[str, dict[str, str]] = {}
    for cls, (filt, first, count) in CLASSES.items():
        for i, buckets in enumerate(assign(table[cls], count)):
            out[str(first + i)] = {"filter": f"({filt}) & test(/{bucket_regex(buckets)}/)"}
    if sorted(out, key=int) != [str(k) for k in range(1, SHARDS + 1)]:
        raise ShardError(f"the classes do not tile shards 1..{SHARDS}")
    return out


def selection(shard: int, weights: dict[str, list[int]] | None = None) -> list[str]:
    """Return the nextest filter arguments of one shard."""
    if isinstance(shard, bool) or not isinstance(shard, int) or not 1 <= shard <= SHARDS:
        raise ShardError(f"shard must be an integer in 1..{SHARDS}, got {shard!r}")
    return ["-E", plan(weights)[str(shard)]["filter"]]


def write_plan(path: str) -> int:
    """Append the plan to the step-output file; no file or a failed write is exit 1."""
    if not path:
        print("e2e_shard: GITHUB_OUTPUT is unset", file=sys.stderr)
        return 1
    try:
        line = "plan=" + json.dumps(plan(), separators=(",", ":"), sort_keys=True)
    except ShardError as exc:
        print(f"e2e_shard: {exc}", file=sys.stderr)
        return 1
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


def _heavy_group_binaries(overrides: object, what: str) -> frozenset[str]:
    """Return the binary set of the one `HEAVY_TEST_GROUP` override in `overrides`, or raise."""
    if not isinstance(overrides, list):
        raise ShardError(f"{what}: `overrides` must be a list")
    matches = [o for o in overrides if isinstance(o, dict) and o.get("test-group") == HEAVY_TEST_GROUP]
    if len(matches) != 1:
        raise ShardError(f"{what}: exactly one override must set test-group = {HEAVY_TEST_GROUP!r}, found {len(matches)}")
    filt = matches[0].get("filter")
    if not isinstance(filt, str) or not filt:
        raise ShardError(f"{what}: the {HEAVY_TEST_GROUP!r} override must set a non-empty string filter")
    terms = filt.split(" | ")
    names: list[str] = []
    for term in terms:
        m = re.fullmatch(r"binary\((\w+)\)", term)
        if m is None:
            raise ShardError(f"{what}: filter must be `binary(NAME)` terms joined by ` | `, got {term!r}")
        names.append(m[1])
    if len(names) != len(set(names)):
        raise ShardError(f"{what}: filter names a binary more than once: {filt!r}")
    return frozenset(names)


def nextest_lint_errors(doc: object) -> list[str]:
    """Return why nextest.toml's `HEAVY_TEST_GROUP` overrides disagree with `HEAVY_BINARIES`, or []."""
    expected = frozenset(HEAVY_BINARIES)
    errors: list[str] = []
    for prof in ("ci", "default"):
        what = f"nextest.toml profile.{prof}.overrides"
        try:
            profiles = doc.get("profile") if isinstance(doc, dict) else None
            overrides = profiles.get(prof, {}).get("overrides") if isinstance(profiles, dict) else None
            found = _heavy_group_binaries(overrides, what)
        except ShardError as exc:
            errors.append(str(exc))
            continue
        if found != expected:
            missing = sorted(expected - found)
            extra = sorted(found - expected)
            errors.append(f"{what}: {HEAVY_TEST_GROUP!r} filter disagrees with HEAVY_BINARIES (missing {missing}, extra {extra})")
    return errors


def lint(path: str = CI_WORKFLOW, nextest_path: str = NEXTEST_TOML) -> int:
    """Fail unless ci.yml wires the plan, the shards and the cover exactly, and nextest.toml agrees with HEAVY_BINARIES."""
    sys.path.insert(0, HERE)
    import strict_yaml  # noqa: PLC0415  # PyYAML-backed; only `--lint` needs it

    try:
        import tomllib  # noqa: PLC0415  # Python 3.11+; only `--lint` needs it
    except ImportError:  # pragma: no cover - CI runs 3.11+
        import tomli as tomllib  # type: ignore[no-redef]  # noqa: PLC0415

    try:
        with open(path, encoding="utf-8") as fh:
            workflow = strict_yaml.safe_load(fh)
    except Exception as exc:  # noqa: BLE001  # any read or parse failure is a refusal
        print(f"e2e shard lint: ci.yml is unreadable: {exc}", file=sys.stderr)
        return 1
    errors = wiring_errors(workflow)
    try:
        plan()
    except ShardError as exc:
        errors.append(str(exc))
    try:
        with open(nextest_path, "rb") as fh:
            nextest_doc = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"nextest.toml is unreadable: {exc}")
    else:
        errors += nextest_lint_errors(nextest_doc)
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
