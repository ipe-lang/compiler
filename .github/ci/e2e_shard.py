#!/usr/bin/env python3
"""SSOT for the e2e SEAL shard partition: its selection, its plan, its wiring.

A shard's test selection is defined here once, as an ordered table of shard
groups whose last group takes the complement, sized from the measured time
table `e2e-shard-times.txt`. `--plan` publishes every shard's
selection as the `changes` job output `e2e_plan`; each `e2e` matrix shard runs
`cargo nextest run` on its own entry of that plan, and `seal-slice-cover`
proves (`tools/scripts/e2e-shard-cover.py`, from the run's own nextest archive,
in parallel with the shards) that the same plan partitions the archive exactly:
every test is selected by exactly one shard and no shard selects a test outside
the archive. `seal-slice` is the phase verdict over the shards and that proof.
`--lint` proves the group table is well formed and ci.yml wires exactly that:
the `e2e` matrix enumerates shards 1..SHARDS, its one nextest run reads its
selection only from the plan, the cover of that same plan runs once, only in
`seal-slice-cover`, unconditionally, and `seal-slice` needs it; artifact-guard
runs it.

Modes:
  --plan    write `plan=<JSON {"K": {"filter", "partition"}}>` to $GITHUB_OUTPUT.
  --lint    fail unless the groups are well formed and ci.yml wires the plan,
            the shards and the cover exactly, every `IPE_E2E` step names a
            workspace shared target, the `e2e` job frees disk, unpacks and
            deletes the archive and checks the floor before its shard, and
            every nextest install pins `NEXTEST_VERSION`.

Every failure exits non-zero; an unwritable output or an unexpected shape is a
failure, never a pass.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
CI_WORKFLOW = os.path.join(REPO, ".github", "workflows", "ci.yml")
E2E_JOB = "e2e"
CHANGES_JOB = "changes"
SEAL_SLICE_JOB = "seal-slice"
SEAL_COVER_JOB = "seal-slice-cover"
TEST_PREP_JOB = "test-prep"
PLAN_INVOCATION = "python3 .github/ci/e2e_shard.py --plan"
PLAN_STEP_ID = "e2e-plan"
PLAN_OUTPUT = "e2e_plan"
PLAN_OUTPUT_VALUE = "${{ steps.e2e-plan.outputs.plan }}"
COVER_SCRIPT = "tools/scripts/e2e-shard-cover.py"
COVER_INVOCATION = f"python3 {COVER_SCRIPT}"
COVER_ENV = {"E2E_PLAN": "${{ needs.changes.outputs.e2e_plan }}"}
_SHARD_ENTRY = "fromJSON(needs.changes.outputs.e2e_plan)[matrix.shard]"
SHARD_ENV = {
    "SHARD_FILTER": "${{ " + _SHARD_ENTRY + ".filter }}",
    "SHARD_PARTITION": "${{ " + _SHARD_ENTRY + ".partition }}",
}

# The goldens whose emitted project drives a real multi-minute cold `cargo
# build` (webview/wry, server/axum, the live-HTTP set, the watch daemons). The
# `ci` nextest profile serializes this set into `heavy-server-e2e`
# (max-threads=1), so its tests are spread across parallel runners rather than
# queued behind each other on one.
HEAVY_BINARIES = (
    "watch_sigterm",
    "watch_integration",
    "watch_hot_appearance",
    "watch_bluegreen",
    "watch_cancellation",
    "server_e2e",
    "live_e2e",
    "http_e2e",
    "g_http_live",
    "webview_e2e",
    "secured_store_e2e",
    "server_shutdown_e2e",
    "test_command",
    "verify",
    "stdlib_coverage_dynamic",
)
HEAVY = " | ".join(f"binary({b})" for b in HEAVY_BINARIES)
COMPLEMENT = "all()"
# Every e2e shard runs nextest with `--test-threads=TEST_THREADS`.
TEST_THREADS = 2
# The `e2e` matrix width: the shard groups share exactly this many shards.
TOTAL_SHARDS = 14


@dataclass(frozen=True)
class OneTest:
    """A group of one test, on one shard of its own."""

    name: str
    binary: str
    test: str


@dataclass(frozen=True)
class Binaries:
    """A group of whole test binaries, `in_flight` of its tests at a time."""

    name: str
    binaries: tuple[str, ...]
    in_flight: int


@dataclass(frozen=True)
class Rest:
    """The complement: every test no earlier group selects."""

    name: str
    in_flight: int


GroupSpec = OneTest | Binaries | Rest

# The shard groups, in order. Group i selects its own filter minus every
# earlier group's (`effective_filters`), and the last group is the complement,
# so every test is in exactly one group whatever the filters match; each
# group's tests are split by `--partition count:k/shards`. A `OneTest` group
# takes one shard; the `Binaries` and `Rest` groups share the rest of the
# `TOTAL_SHARDS` in proportion to their measured time (`allocate`, from
# `TIMES_FILE`). The sizes are advisory only: a test no named group matches
# still runs in the complement, and `e2e-shard-cover.py` proves the partition
# on every run's archive.
# - each multi-minute `stdlib_coverage_dynamic` column test gets a shard alone,
#   since the heavy group runs serially and either one would set a shard's
#   length;
# - the rest of the serialized heavy set, one test at a time;
# - the two longest light binaries, kept apart from the rest so their tests
#   spread evenly instead of landing in one complement shard;
# - the complement.
SPECS: tuple[GroupSpec, ...] = (
    OneTest("coverage-build-run", "stdlib_coverage_dynamic", "build_run_column_over_a_representative_slice"),
    OneTest("coverage-dynamic-columns", "stdlib_coverage_dynamic", "dynamic_columns_pass_over_the_whole_surface"),
    Binaries("heavy", HEAVY_BINARIES, 1),
    Binaries("db-issues", ("g_db", "g_issues"), TEST_THREADS),
    Rest("light", TEST_THREADS),
)

TIMES_FILE = os.path.join(HERE, "e2e-shard-times.txt")
# The weight of a binary a group names but `TIMES_FILE` lacks: the `ci`
# profile's per-test ceiling (300 s), so an unmeasured binary is sized as at
# least one test at the longest a test may run, never as free.
DEFAULT_WEIGHT_S = 300
MAX_WEIGHT_S = 7 * 24 * 3600
MAX_TIMES_BYTES = 1024 * 1024
MAX_TIMES_ROWS = 20_000
_BINARY_ID = re.compile(r"[A-Za-z0-9_-]+(::(bin/)?[A-Za-z0-9_-]+)?\Z")
_TEST_NAME = re.compile(r"[A-Za-z0-9_:]+\Z")


class ShardError(Exception):
    """A shard index, group table, listing, or workflow shape that proves nothing."""


def group_errors(groups: object) -> list[str]:
    """Return why `groups` is not an ordered group table whose last filter takes the complement, or []."""
    if not isinstance(groups, tuple) or not groups:
        return ["the shard groups must be a non-empty tuple"]
    errors: list[str] = []
    names: set[str] = set()
    for i, group in enumerate(groups, start=1):
        if not isinstance(group, tuple) or len(group) != 3:
            errors.append(f"group {i} must be a (name, filter, shards) tuple")
            continue
        name, filt, shards = group
        if not isinstance(name, str) or not name.strip() or not name.isascii():
            errors.append(f"group {i} has an empty or non-ASCII name")
        elif name in names:
            errors.append(f"group {i} repeats the name {name!r}")
        else:
            names.add(name)
        if not isinstance(filt, str) or not filt.strip() or not filt.isascii():
            errors.append(f"group {i} ({name!r}) has an empty or non-ASCII filter")
        if isinstance(shards, bool) or not isinstance(shards, int) or shards < 1:
            errors.append(f"group {i} ({name!r}) must run on at least one shard, got {shards!r}")
    last = groups[-1]
    if not isinstance(last, tuple) or len(last) != 3 or last[1] != COMPLEMENT:
        errors.append(f"the last group's filter must be `{COMPLEMENT}`, so a test no named group matches still runs")
    return errors


def shard_total(groups: tuple[tuple[str, str, int], ...]) -> int:
    """Return how many shards `groups` spreads over, refusing a malformed table."""
    errors = group_errors(groups)
    if errors:
        raise ShardError("; ".join(errors))
    return sum(shards for _, _, shards in groups)


def effective_filters(groups: tuple[tuple[str, str, int], ...]) -> list[str]:
    """Return each group's selection: its own filter minus every earlier group's."""
    shard_total(groups)
    out: list[str] = []
    for i, (_, filt, _) in enumerate(groups):
        earlier = " | ".join(f"({f})" for _, f, _ in groups[:i])
        out.append(f"({filt}) & not ({earlier})" if earlier else f"({filt})")
    return out


@dataclass(frozen=True)
class Times:
    """`TIMES_FILE`: seconds per nextest binary id, and per isolated test."""

    binaries: dict[str, int]
    tests: dict[tuple[str, str], int]


def parse_times(text: str) -> Times:
    """Parse the time table; any malformed, duplicate, or oversized row refuses it all."""
    if len(text.encode()) > MAX_TIMES_BYTES:
        raise ShardError(f"the time table is over {MAX_TIMES_BYTES} bytes")
    binaries: dict[str, int] = {}
    tests: dict[tuple[str, str], int] = {}
    rows = 0
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        rows += 1
        if rows > MAX_TIMES_ROWS:
            raise ShardError(f"the time table has over {MAX_TIMES_ROWS} rows")
        words = line.split(" ")
        if len(words) not in (2, 3) or not words[-1].isascii() or not words[-1].isdigit():
            raise ShardError(f"time table line {n} is not `<binary-id> [<test>] <seconds>`: {line!r}")
        seconds = int(words[-1])
        if seconds > MAX_WEIGHT_S:
            raise ShardError(f"time table line {n}: {seconds} s is over {MAX_WEIGHT_S}")
        if not _BINARY_ID.match(words[0]):
            raise ShardError(f"time table line {n}: {words[0]!r} is not a nextest binary id")
        if len(words) == 2:
            if words[0] in binaries:
                raise ShardError(f"time table line {n}: {words[0]!r} is listed twice")
            binaries[words[0]] = seconds
            continue
        key = (words[0], words[1])
        if not _TEST_NAME.match(words[1]):
            raise ShardError(f"time table line {n}: {words[1]!r} is not a test name")
        if words[0] not in binaries:
            raise ShardError(f"time table line {n}: test of {words[0]!r} precedes that binary's own line")
        if key in tests:
            raise ShardError(f"time table line {n}: test {words[1]!r} is listed twice")
        if seconds > binaries[words[0]]:
            raise ShardError(f"time table line {n}: a test outweighs its whole binary")
        tests[key] = seconds
    if not binaries:
        raise ShardError("the time table lists no binary")
    return Times(binaries, tests)


def load_times(path: str = TIMES_FILE) -> Times:
    """Read and parse the time table; an unreadable one is refused."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read(MAX_TIMES_BYTES + 1)
    except (OSError, UnicodeDecodeError) as exc:
        raise ShardError(f"the time table is unreadable: {exc}") from None
    return parse_times(text)


def binary_name(binary_id: str) -> str | None:
    """The name `binary(...)` matches for an integration-test binary id
    (`crate::name`), or None for a library or `bin/` target, which no named
    group selects."""
    _, sep, name = binary_id.partition("::")
    return name if sep and not name.startswith("bin/") else None


def spec_filter(spec: GroupSpec) -> str:
    """The nextest filter of one group, before earlier groups are excluded."""
    if isinstance(spec, OneTest):
        return f"binary({spec.binary}) & test(={spec.test})"
    if isinstance(spec, Binaries):
        return " | ".join(f"binary({b})" for b in spec.binaries)
    return COMPLEMENT


def spec_errors(specs: object) -> list[str]:
    """Why `specs` is not a group spec table a time table can size, or []."""
    if not isinstance(specs, tuple) or not specs:
        return ["the group specs must be a non-empty tuple"]
    errors: list[str] = []
    for i, spec in enumerate(specs, start=1):
        if not isinstance(spec, (OneTest, Binaries, Rest)):
            errors.append(f"group spec {i} is not a OneTest, Binaries, or Rest")
        elif isinstance(spec, Rest) != (i == len(specs)):
            errors.append(f"group spec {i} ({spec.name!r}): the complement must be the last group, and only it")
        elif isinstance(spec, Binaries) and not spec.binaries:
            errors.append(f"group spec {i} ({spec.name!r}) names no binary")
        elif not isinstance(spec, OneTest) and (
            isinstance(spec.in_flight, bool) or not isinstance(spec.in_flight, int) or spec.in_flight < 1
        ):
            errors.append(f"group spec {i} ({spec.name!r}) must run at least one test at a time")
    return errors


def group_weights(specs: tuple[GroupSpec, ...], times: Times) -> list[int]:
    """Each group's measured seconds, over the tests it selects once earlier
    groups are excluded; a named binary the table lacks weighs
    `DEFAULT_WEIGHT_S`. A `OneTest` group's weight is not used (it takes one
    shard) and is reported as its test's own time."""
    claimed_tests: set[tuple[str, str]] = set()
    claimed_names: set[str] = set()
    out: list[int] = []
    for spec in specs:
        if isinstance(spec, OneTest):
            keys = {k for k in times.tests if binary_name(k[0]) == spec.binary and k[1] == spec.test}
            keys -= claimed_tests
            out.append(sum(times.tests[k] for k in keys))
            claimed_tests |= keys
            continue
        if isinstance(spec, Binaries):
            names = [b for b in spec.binaries if b not in claimed_names]
            ids = [i for i in times.binaries if binary_name(i) in names]
            missing = [b for b in names if not any(binary_name(i) == b for i in ids)]
            claimed_names |= set(names)
        else:
            ids = [i for i in times.binaries if binary_name(i) not in claimed_names]
            missing = []
        weight = DEFAULT_WEIGHT_S * len(missing)
        for i in ids:
            isolated = sum(t for k, t in times.tests.items() if k[0] == i and k in claimed_tests)
            weight += max(times.binaries[i] - isolated, 0)
        out.append(weight)
    return out


def allocate(specs: tuple[GroupSpec, ...], times: Times, total: int = TOTAL_SHARDS) -> tuple[tuple[str, str, int], ...]:
    """The `(name, filter, shards)` table: one shard per `OneTest` group, and
    the rest of `total` over the other groups, each at least one, every next
    shard to the group whose per-shard time (weight / in-flight / shards) is
    longest (the earliest on a tie)."""
    errors = spec_errors(specs)
    if errors:
        raise ShardError("; ".join(errors))
    weights = group_weights(specs, times)
    shards = [1] * len(specs)
    sized = [(i, s.in_flight) for i, s in enumerate(specs) if not isinstance(s, OneTest)]
    spare = total - len(specs)
    if spare < 0:
        raise ShardError(f"{len(specs)} groups do not fit in {total} shards")
    for _ in range(spare):
        longest, _ = max(sized, key=lambda g: weights[g[0]] / g[1] / shards[g[0]])
        shards[longest] += 1
    return tuple((s.name, spec_filter(s), n) for s, n in zip(specs, shards, strict=True))


GROUPS = allocate(SPECS, load_times())
SHARDS = shard_total(GROUPS)

ARCHIVE_FILE = "nextest.tar.zst"
# Where the `e2e` job unpacks the archive before it deletes it. The archive is
# about 2.1 GB and its unpacked binaries several times that; holding both for
# the whole shard is the fixed disk cost the shards died of, so the job unpacks
# once, removes the archive, and runs from the unpacked copy.
EXTRACT_DIR = "$RUNNER_TEMP/nextest-x"
EXTRACT_COMMAND = " ".join(
    (
        "cargo nextest list --archive-file",
        ARCHIVE_FILE,
        "--workspace-remap . --extract-to",
        f'"{EXTRACT_DIR}"',
        "--extract-overwrite -E 'none()'",
    )
)
EXTRACT_RUN = f"{EXTRACT_COMMAND}\nrm -- {ARCHIVE_FILE}"
ARCHIVE_ARGS = (
    "--binaries-metadata",
    f'"{EXTRACT_DIR}/target/nextest/binaries-metadata.json"',
    "--cargo-metadata",
    f'"{EXTRACT_DIR}/target/nextest/cargo-metadata.json"',
    "--target-dir-remap",
    f'"{EXTRACT_DIR}/target"',
    "--workspace-remap",
    ".",
    "--profile",
    "ci",
)
# `--test-threads=2`: each E2E test drives a memory-heavy emitted-project
# `cargo build` that itself uses every core; two in flight fit the runner.
# `--no-tests=fail`: a shard whose selection matches nothing is red, never a
# vacuous green.
RUN_ONLY_ARGS = ("--no-fail-fast", f"--test-threads={TEST_THREADS}", "--no-tests=fail")
RUN_COMMAND = " ".join(
    ("cargo", "nextest", "run", *ARCHIVE_ARGS, *RUN_ONLY_ARGS, '-E "$SHARD_FILTER"', '--partition "$SHARD_PARTITION"')
)


def selection(shard: int, groups: tuple[tuple[str, str, int], ...] = GROUPS) -> list[str]:
    """Return the nextest filter + partition arguments of one shard."""
    total = shard_total(groups)
    if isinstance(shard, bool) or not isinstance(shard, int) or not 1 <= shard <= total:
        raise ShardError(f"shard must be an integer in 1..{total}, got {shard!r}")
    first = 1
    for (_, _, shards), filt in zip(groups, effective_filters(groups), strict=True):
        if shard < first + shards:
            return ["-E", filt, "--partition", f"count:{shard - first + 1}/{shards}"]
        first += shards
    raise ShardError(f"shard {shard} falls in no group")


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
    sizes = ", ".join(f"{name} {shards}" for name, _, shards in GROUPS)
    print(f"e2e_shard: planned {SHARDS} shards ({sizes}).")
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


def wiring_errors(workflow: dict, groups: tuple[tuple[str, str, int], ...] = GROUPS) -> list[str]:
    """Return why ci.yml could run a shard, or prove a cover, off the SSOT plan, or []."""
    errors = group_errors(groups)
    if errors:
        return errors
    total = shard_total(groups)
    jobs = workflow.get("jobs") if isinstance(workflow, dict) else None
    if not isinstance(jobs, dict):
        return ["ci.yml has no jobs"]
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
    elif matrix["shard"] != list(range(1, total + 1)):
        errors.append(f"`{E2E_JOB}` matrix shard is {matrix['shard']!r}, expected 1..{total}")
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
    elif SEAL_COVER_JOB not in _needs(seal):
        errors.append(f"`{SEAL_SLICE_JOB}` must need `{SEAL_COVER_JOB}`, so its verdict cannot omit the cover")
    for job_id, other in jobs.items():
        if job_id != SEAL_COVER_JOB and any(_runs(s, COVER_SCRIPT) for s in _steps(other)):
            errors.append(f"job {job_id!r} runs the cover outside `{SEAL_COVER_JOB}`")
    cover_job = jobs.get(SEAL_COVER_JOB)
    if not isinstance(cover_job, dict):
        errors.append(f"ci.yml has no `{SEAL_COVER_JOB}` job")
        return errors
    for need in (CHANGES_JOB, TEST_PREP_JOB):
        if need not in _needs(cover_job):
            errors.append(f"`{SEAL_COVER_JOB}` must need `{need}`, the job that publishes the plan and the archive")
    cover_steps = _steps(cover_job)
    if sum(_runs(s, COVER_SCRIPT) for s in cover_steps) != 1:
        errors.append(f"`{SEAL_COVER_JOB}` must run the cover in exactly one step")
    step, errs = _exact_step(cover_steps, COVER_INVOCATION, f"`{SEAL_COVER_JOB}`")
    errors += errs
    if step is not None:
        if "if" in step:
            errors.append(f"`{SEAL_COVER_JOB}`: the cover step must carry no `if:`; a skipped step leaves the job green")
        if step.get("env") != COVER_ENV:
            errors.append(f"`{SEAL_COVER_JOB}`: the cover step's env must be exactly {COVER_ENV}")
    return errors


# The e2e job's disk floor and census live in `tools/scripts/e2e-disk.py` (a
# `.github/ci/` tool may not run inside a test job); `--lint` pins its argv,
# its place in the job, and that its test-thread term equals `TEST_THREADS`.
DISK_SCRIPT = "tools/scripts/e2e-disk.py"
DISK_FLOOR_INVOCATION = f"python3 {DISK_SCRIPT} --disk-floor"
FREE_DISK_MARKER = "sudo rm -rf /usr/local/lib/android /usr/share/dotnet /opt/ghc /opt/hostedtoolcache/CodeQL"
DOWNLOAD_ACTION = "actions/download-artifact@"
# The nextest every workflow installs. `taiki-e/install-action` installs the
# latest release unless `tool:` names a version, so an unpinned install changes
# the flags the shard's unpack-then-run relies on under an unchanged workflow.
NEXTEST_VERSION = "0.9.146"
NEXTEST_TOOL = f"nextest@{NEXTEST_VERSION}"
INSTALL_ACTION = "taiki-e/install-action@"
NEXTEST_INSTALL_REF = "taiki-e/install-action@23d41aa71228a2692ee31bb433f070fd4bdc6661"
SHARED_TARGET_VAR = "IPE_ORACLE_SHARED_TARGET"
SHARED_TARGET_PREFIX = "${{ github.workspace }}/"


def _env_of(*scopes: object) -> dict[str, object]:
    merged: dict[str, object] = {}
    for scope in scopes:
        env = scope.get("env") if isinstance(scope, dict) else None
        if isinstance(env, dict):
            merged.update(env)
    return merged


def _e2e_armed(value: object) -> bool:
    """Any `IPE_E2E` other than absent, empty or `0` arms the full tier (fail closed)."""
    return value is not None and str(value).strip() not in ("", "0")


def shared_target_errors(workflow: dict) -> list[str]:
    """Return every step that arms `IPE_E2E` without a workspace-rooted shared target."""
    jobs = workflow.get("jobs") if isinstance(workflow, dict) else None
    if not isinstance(jobs, dict):
        return ["ci.yml has no jobs"]
    errors: list[str] = []
    for job_id, job in jobs.items():
        for i, step in enumerate(_steps(job)):
            env = _env_of(workflow, job, step)
            if not _e2e_armed(env.get("IPE_E2E")):
                continue
            shared = env.get(SHARED_TARGET_VAR)
            where = f"job {job_id!r} step {step.get('name', i)!r}"
            if not isinstance(shared, str) or not shared.startswith(SHARED_TARGET_PREFIX):
                errors.append(
                    f"{where}: arms IPE_E2E without {SHARED_TARGET_VAR} under `{SHARED_TARGET_PREFIX}` "
                    f"(got {shared!r}); its emitted builds would fall back to private targets"
                )
            elif ".." in shared[len(SHARED_TARGET_PREFIX) :].split("/"):
                errors.append(f"{where}: {SHARED_TARGET_VAR} must stay under the workspace, got {shared!r}")
    return errors


def _index(steps: list[dict], pred) -> list[int]:
    return [i for i, s in enumerate(steps) if pred(s)]


def disk_order_errors(workflow: dict) -> list[str]:
    """Return why the `e2e` job could hold the archive during its run, skip the
    floor, or run off the declared order free-disk -> download -> unpack -> floor -> shard."""
    jobs = workflow.get("jobs") if isinstance(workflow, dict) else None
    job = jobs.get(E2E_JOB) if isinstance(jobs, dict) else None
    if not isinstance(job, dict):
        return [f"ci.yml has no `{E2E_JOB}` job"]
    steps = _steps(job)
    order = (
        ("the free-disk step", _index(steps, lambda s: _runs(s, FREE_DISK_MARKER))),
        ("the archive download", _index(steps, lambda s: str(s.get("uses", "")).startswith(DOWNLOAD_ACTION))),
        ("the unpack-then-delete step", _index(steps, lambda s: s.get("run", "").strip() == EXTRACT_RUN)),
        ("the disk floor", _index(steps, lambda s: s.get("run", "").strip() == DISK_FLOOR_INVOCATION)),
        ("the shard run", _index(steps, lambda s: _runs(s, RUN_COMMAND))),
    )
    errors: list[str] = []
    last = -1
    for what, idx in order:
        if len(idx) != 1:
            errors.append(f"`{E2E_JOB}`: exactly one step must be {what}, found {len(idx)}")
            continue
        step = steps[idx[0]]
        if "if" in step or "continue-on-error" in step:
            errors.append(f"`{E2E_JOB}`: {what} must carry no `if:` or `continue-on-error`")
        if idx[0] < last:
            errors.append(f"`{E2E_JOB}`: {what} runs out of order (free-disk -> download -> unpack -> floor -> shard)")
        last = max(last, idx[0])
    extract = order[2][1]
    shard = order[4][1]
    if len(extract) == 1 and len(shard) == 1:
        for step in steps[extract[0] + 1 : shard[0] + 1]:
            if ARCHIVE_FILE in json.dumps(step):
                errors.append(f"`{E2E_JOB}`: a step after the unpack still names `{ARCHIVE_FILE}`; the archive must be gone before the shard runs")
    return errors


def nextest_pin_errors(workflows: dict[str, dict]) -> list[str]:
    """Return every nextest install that does not pin `NEXTEST_VERSION`."""
    errors: list[str] = []
    for name, wf in workflows.items():
        jobs = wf.get("jobs") if isinstance(wf, dict) else None
        if not isinstance(jobs, dict):
            continue
        for job_id, job in jobs.items():
            for step in _steps(job):
                uses = str(step.get("uses", ""))
                if not uses.startswith(INSTALL_ACTION):
                    continue
                with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
                tool = str(with_.get("tool", "nextest" if uses == NEXTEST_INSTALL_REF else ""))
                tools = [t for t in re.split(r"[\s,]+", tool) if t]
                for t in tools:
                    if t.split("@", 1)[0] in ("nextest", "cargo-nextest") and t != NEXTEST_TOOL:
                        errors.append(f"{name} job {job_id!r}: nextest install must be `tool: {NEXTEST_TOOL}`, got {t!r}")
    return errors


def load_disk_script():
    """Load `tools/scripts/e2e-disk.py` as a module."""
    import importlib.util  # noqa: PLC0415

    spec = importlib.util.spec_from_file_location("e2e_disk", os.path.join(REPO, DISK_SCRIPT))
    if spec is None or spec.loader is None:
        raise ShardError(f"{DISK_SCRIPT} is unloadable")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def disk_script_errors(load=load_disk_script) -> list[str]:
    """Return why the disk floor could budget a thread count other than the shard's."""
    try:
        disk = load()
    except Exception as exc:  # noqa: BLE001  # any load failure is a refusal
        return [f"{DISK_SCRIPT} is unloadable: {exc}"]
    if getattr(disk, "TEST_THREADS", None) != TEST_THREADS:
        return [f"{DISK_SCRIPT} budgets TEST_THREADS={getattr(disk, 'TEST_THREADS', None)!r}, the shard runs {TEST_THREADS}"]
    if getattr(disk, "EXTRACT_DIR", None) != EXTRACT_DIR:
        return [f"{DISK_SCRIPT} excludes EXTRACT_DIR={getattr(disk, 'EXTRACT_DIR', None)!r}, the job unpacks to {EXTRACT_DIR}"]
    return []


def _load_workflows() -> dict[str, dict]:
    sys.path.insert(0, HERE)
    import strict_yaml  # noqa: PLC0415  # PyYAML-backed; only `--lint` needs it

    out: dict[str, dict] = {}
    wf_dir = os.path.dirname(CI_WORKFLOW)
    for name in sorted(os.listdir(wf_dir)):
        if name.endswith((".yml", ".yaml")):
            with open(os.path.join(wf_dir, name), encoding="utf-8") as fh:
                out[name] = strict_yaml.safe_load(fh)
    return out


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
    errors = [*group_errors(GROUPS), *wiring_errors(workflow)]
    errors += shared_target_errors(workflow) + disk_order_errors(workflow) + disk_script_errors()
    try:
        errors += nextest_pin_errors(_load_workflows())
    except Exception as exc:  # noqa: BLE001  # any read or parse failure is a refusal
        errors.append(f"a workflow is unreadable: {exc}")
    for err in errors:
        print(f"e2e shard lint: {err}", file=sys.stderr)
    if errors:
        return 1
    print(f"e2e shard lint: ci.yml runs shards 1..{SHARDS} from the plan and proves its cover in `{SEAL_COVER_JOB}`.")
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
