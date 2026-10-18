#!/usr/bin/env python3
"""SSOT for the automatic-rerun policy: a failed run is retried only on infra.

`rerun-failed-once.yml` re-runs a failed "Build & test" run's failed jobs once,
and only when this module proves every failed job died of infrastructure: its
log or annotations match an infrastructure signature below AND carry no test
failure marker. Anything else — a test failure, a lint, an unknown red, an
unreadable log, a listing error — is `false`: no rerun. A retry that turns a
flaky test green would hide nondeterminism the language forbids (PRINCIPLES.md
principle 2), so the default is the red, never the retry.

The same rule holds inside a run: no nextest profile, workflow, or composite
action may set a test retry, so a flaky test fails its shard instead of
reporting FLAKY and passing. `--lint` proves both halves (the signature table's
shape and the absence of any retry setting) and the workflow's wiring.

Modes:
  --decide  write `rerun=true` to $GITHUB_OUTPUT iff every failed job of
            $RUN_ID (attempt 1) in $REPO is infra-only, `rerun=false`
            otherwise, and exit 0; the workflow reruns only on the exact word
            `true`. An unwritable $GITHUB_OUTPUT exits 1 with no output set.
  --proven-test-red
            write `cancel=true` to $GITHUB_OUTPUT iff some failed leg of the
            job $PRODUCER names, in attempt $RUN_ATTEMPT of run $RUN_ID, is a
            proven test red (`proven_test_red`), `cancel=false` otherwise,
            and exit 0. ci.yml's merge-group fail-fast watchers cancel the
            run only on the exact word `true`, so an unknown, infra-only, or
            unreadable red never cancels. An unwritable $GITHUB_OUTPUT exits
            1 with no output set.
  --lint    fail unless the signature table, the retry ban, and
            rerun-failed-once.yml's wiring all hold. artifact-guard runs it.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Iterable
from typing import IO
from dataclasses import dataclass

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
RERUN_WORKFLOW = os.path.join(REPO_ROOT, ".github", "workflows", "rerun-failed-once.yml")
NEXTEST_CONFIG = os.path.join(REPO_ROOT, ".config", "nextest.toml")
RETRY_SCAN_DIRS = (os.path.join(".github", "workflows"), os.path.join(".github", "actions"))

# (id, pattern). Each pattern names one infrastructure failure by its literal
# text; each carries a literal prefix and at most one wildcard, so a search over
# a capped line stays linear on attacker-controlled log text.
SIGNATURES: tuple[tuple[str, str], ...] = (
    ("lost-runner", r"The runner has received a shutdown signal"),
    ("lost-runner", r"lost communication with the server"),
    ("enospc", r"No space left on device"),
    ("enospc", r"\bENOSPC\b"),
    ("cache-5xx", r"Cache service responded with 5\d\d\b"),
    ("download-5xx", r"Unexpected HTTP response: 5\d\d\b"),
    ("download-5xx", r"The requested URL returned error: 5\d\d\b"),
    ("download-5xx", r"failed to get successful HTTP response from .*, got 5\d\d\b"),
    ("download-network", r"curl: \((?:6|7|28|35|52|56)\)"),
    ("download-network", r"Could not resolve host"),
    ("download-network", r"could not download file from '"),
)

# A test that failed, timed out, or crashed. Its presence vetoes the rerun even
# when an infra signature also matched: a test failure is never retried.
TEST_FAILURE_MARKERS: tuple[str, ...] = (
    r"\b(?:FAIL|TIMEOUT|SIGSEGV|SIGABRT|SIGKILL|ABORT|LEAK-FAIL) \[ *\d+(?:\.\d+)?s\]",
    r"error: test run failed",
    r"test result: FAILED",
    r"\bFLAKY \d+/\d+ \[",
)

# A test that ran and failed: nextest's `FAIL` status line or libtest's
# summary, each with a sample line it must match. The merge-group fail-fast
# watchers cancel a run only on one of these. A timeout, a signal, or a leak
# is a crash: it vetoes a rerun (TEST_FAILURE_MARKERS) but proves no test
# red, since a starved or killed runner produces it too. Every sample also
# matches a veto marker, so a red the watcher cancels on is one the rerun
# policy would never retry.
PROVEN_TEST_RED_MARKERS: tuple[tuple[str, str], ...] = (
    (r"(?<![\w-])FAIL \[ *\d+(?:\.\d+)?s\]", "        FAIL [  12.881s] ipe::emit broken_case"),
    (r"test result: FAILED\.", "test result: FAILED. 3 passed; 1 failed; 0 ignored"),
)

MAX_LINE_CHARS = 4096
MAX_LOG_LINES = 2_000_000
MAX_LOG_CHARS = 256 * 1024 * 1024
MAX_FAILED_JOBS = 256
GH_TIMEOUT_S = 180

_SIGNATURE_RES = tuple((sid, re.compile(p)) for sid, p in SIGNATURES)
_MARKER_RES = tuple(re.compile(p) for p in TEST_FAILURE_MARKERS)
_PROVEN_RES = tuple(re.compile(p) for p, _ in PROVEN_TEST_RED_MARKERS)

# Terminal control sequences (ci.yml sets `CARGO_TERM_COLOR: always`, so nextest
# and cargo wrap `FAIL` / `error` in SGR codes). They are removed before any
# match, so a coloured test failure still vetoes. Every alternative is
# anchored on ESC or C1 and consumes a bounded class, so the scan stays linear.
_CONTROL_SEQ = re.compile(r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]|(?:\x1b\]|\x9d)[^\x07\x1b\x9c]*(?:\x07|\x1b\\|\x9c)|\x1b[ -/]*[0-~]?")

# A line reporting a retried operation (cargo's "spurious network error (2
# tries remaining)", a download "Retrying ...") shows an infra hiccup the job
# recovered from, not the cause of its failure. It is never infra evidence; the
# final unrecovered error line, which carries no retry wording, still is.
_RECOVERED_RETRY = re.compile(r"(?i)\bspurious\b|\bretry(?:ing)?\b|\btries remaining\b|\bretries remaining\b")


class PolicyError(Exception):
    """A listing, log, or workflow shape that proves nothing."""


@dataclass(frozen=True)
class Evidence:
    """What one failed job's log and annotations prove about its failure."""

    infra: frozenset[str]
    test_failure: bool
    # A `PROVEN_TEST_RED_MARKERS` line was seen (implies `test_failure`).
    test_red: bool = False

    @property
    def infra_only(self) -> bool:
        return bool(self.infra) and not self.test_failure


def scan(lines: Iterable[str]) -> Evidence:
    """Classify a job's log/annotation lines. Too many lines is a refusal."""
    infra: set[str] = set()
    test_failure = False
    test_red = False
    for count, raw in enumerate(lines, start=1):
        if count > MAX_LOG_LINES:
            raise PolicyError(f"log exceeds {MAX_LOG_LINES} lines")
        line = _CONTROL_SEQ.sub("", raw[:MAX_LINE_CHARS])
        if not _RECOVERED_RETRY.search(line):
            for sid, rx in _SIGNATURE_RES:
                if sid not in infra and rx.search(line):
                    infra.add(sid)
        if not test_failure and any(rx.search(line) for rx in _MARKER_RES):
            test_failure = True
        if not test_red and any(rx.search(line) for rx in _PROVEN_RES):
            test_red = True
    return Evidence(frozenset(infra), test_failure or test_red, test_red)


def decide(evidence: list[Evidence | None]) -> bool:
    """Rerun iff at least one job failed and every failed job is infra-only.

    `None` is a job whose evidence could not be read: it proves nothing, so it
    blocks the rerun.
    """
    if not evidence or len(evidence) > MAX_FAILED_JOBS:
        return False
    return all(e is not None and e.infra_only for e in evidence)


def proven_test_red(log: Evidence | None, notes: Evidence | None) -> bool:
    """A failed job is a proven test red iff its log AND its annotations were
    read, its log shows a test that ran and failed (`test_red`), and neither
    source carries an infrastructure signature.

    `None` is a source that could not be read: it proves nothing, so the
    answer is no. A crash, an empty or garbled log, or a test failure beside
    an infra signature is no proof either.
    """
    if log is None or notes is None:
        return False
    return log.test_red and not log.infra and not notes.infra


# A job concluding one of these needs no proof; EVERY other conclusion — a
# failure, a timeout, a cancellation, one GitHub adds later — must be proven
# infra-only, since `gh run rerun --failed` re-runs it too and a timed-out job
# is a hang, never a retry candidate.
PASSED_CONCLUSIONS = frozenset({"success", "skipped", "neutral"})
JOBS_JQ = '.jobs[] | "\\(.id)\\t\\(.conclusion)"'


def failed_job_ids(text: str) -> list[int]:
    """Parse one `<id> TAB <conclusion>` line per job; return the ids that did not pass."""
    ids: list[str] = []
    failed: set[str] = set()
    for line in text.splitlines():
        job_id, sep, conclusion = line.partition("\t")
        if not sep or not re.fullmatch(r"[a-z_]+", conclusion):
            raise PolicyError(f"job listing has a malformed line {line!r}")
        ids.append(job_id)
        if conclusion not in PASSED_CONCLUSIONS:
            failed.add(job_id)
    parsed = parse_job_ids("\n".join(ids))
    if len(parsed) != len(ids):
        raise PolicyError("job listing has an empty job id")
    return [i for i, raw in zip(parsed, ids) if raw in failed]


JOB_ROWS_JQ = '.jobs[] | "\\(.id)\\t\\(.conclusion)\\t\\(.name)"'


def failed_jobs_named(text: str) -> list[tuple[int, str]]:
    """Parse one `<id> TAB <conclusion> TAB <name>` line per job; return
    (id, name) of every job that did not pass. Same refusals as
    `failed_job_ids`, plus an empty name."""
    rows: list[tuple[str, str]] = []
    failed: set[str] = set()
    for line in text.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3 or not re.fullmatch(r"[a-z_]+", parts[1]) or not parts[2]:
            raise PolicyError(f"job listing has a malformed line {line!r}")
        job_id, conclusion, name = parts
        rows.append((job_id, name))
        if conclusion not in PASSED_CONCLUSIONS:
            failed.add(job_id)
    parsed = parse_job_ids("\n".join(i for i, _ in rows))
    if len(parsed) != len(rows):
        raise PolicyError("job listing has an empty job id")
    return [(i, name) for i, (raw, name) in zip(parsed, rows) if raw in failed]


def is_leg_of(name: str, producer: str) -> bool:
    """Whether the job named `name` in a run listing is `producer` or one of
    its matrix legs (`producer (<values>)`). ci/verify-manifest.py proves
    this rule picks exactly a watched producer's contexts out of ci.yml."""
    return name == producer or (name.startswith(producer + " (") and name.endswith(")"))


def parse_job_ids(text: str) -> list[int]:
    """Parse one canonical decimal job id per line; anything else is refused."""
    ids: list[int] = []
    for line in text.splitlines():
        if not line.isascii() or not line.isdigit() or line != str(int(line)) or int(line) == 0:
            raise PolicyError(f"job id listing has a non-id line {line!r}")
        ids.append(int(line))
    if len(ids) != len(set(ids)):
        raise PolicyError("job id listing repeats an id")
    return ids


def bounded_lines(stream: IO[str]) -> Iterable[str]:
    """Yield `stream` as lines of at most MAX_LINE_CHARS characters.

    A longer line is yielded in MAX_LINE_CHARS pieces (every piece is scanned,
    none is dropped), so no single read grows past the cap; more than
    MAX_LOG_CHARS characters in all is a refusal.
    """
    total = 0
    while True:
        piece = stream.readline(MAX_LINE_CHARS)
        if not piece:
            return
        total += len(piece)
        if total > MAX_LOG_CHARS:
            raise PolicyError(f"log exceeds {MAX_LOG_CHARS} characters")
        yield piece


def _gh_lines(args: list[str]) -> Iterable[str]:
    """Stream `gh api` stdout in bounded lines; a non-zero exit is a refusal."""
    with subprocess.Popen(
        ["gh", "api", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        errors="replace",
    ) as proc:
        if proc.stdout is None:
            raise PolicyError(f"`gh api {args[0]}` has no stdout pipe")
        yield from bounded_lines(proc.stdout)
        try:
            code = proc.wait(timeout=GH_TIMEOUT_S)
        except subprocess.TimeoutExpired as exc:
            proc.kill()
            raise PolicyError(f"`gh api {args[0]}` timed out") from exc
    if code != 0:
        raise PolicyError(f"`gh api {args[0]}` exited {code}")


def _gh_text(args: list[str]) -> str:
    proc = subprocess.run(
        ["gh", "api", *args], check=False, capture_output=True, text=True, timeout=GH_TIMEOUT_S
    )
    if proc.returncode != 0:
        raise PolicyError(f"`gh api {args[0]}` exited {proc.returncode}")
    return proc.stdout


def _job_evidence(repo: str, job_id: int) -> Evidence | None:
    log, notes = _job_sources(repo, job_id)
    if log is None and notes is None:
        return None
    parts = [e for e in (log, notes) if e is not None]
    # A lost runner often leaves no readable log; its annotation alone is the
    # evidence. A test marker in either source still vetoes.
    return Evidence(
        frozenset().union(*(e.infra for e in parts)),
        any(e.test_failure for e in parts),
    )


def run_decide(repo: str, run_id: str) -> bool:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise PolicyError(f"REPO {repo!r} is not owner/name")
    if not run_id.isascii() or not run_id.isdigit():
        raise PolicyError(f"RUN_ID {run_id!r} is not a decimal id")
    listing = _gh_text(
        [
            f"repos/{repo}/actions/runs/{run_id}/attempts/1/jobs",
            "--paginate",
            "--jq",
            JOBS_JQ,
        ]
    )
    ids = failed_job_ids(listing)
    if not ids or len(ids) > MAX_FAILED_JOBS:
        return False
    return decide([_job_evidence(repo, j) for j in ids])


def _job_sources(repo: str, job_id: int) -> tuple[Evidence | None, Evidence | None]:
    """The scanned log and annotations of one job, each None when unreadable."""
    try:
        log = scan(_gh_lines([f"repos/{repo}/actions/jobs/{job_id}/logs"]))
    except (PolicyError, OSError, subprocess.SubprocessError):
        log = None
    try:
        notes = scan(
            _gh_lines([f"repos/{repo}/check-runs/{job_id}/annotations", "--paginate", "--jq", ".[].message"])
        )
    except (PolicyError, OSError, subprocess.SubprocessError):
        notes = None
    return log, notes


def decide_cancel(
    failed: list[tuple[int, str]],
    producer: str,
    sources: Callable[[int], tuple[Evidence | None, Evidence | None]],
) -> bool:
    """Cancel iff some failed leg of `producer` is a proven test red.

    `failed` is (id, name) of every failed job in the run; `sources(id)`
    returns that job's (log, annotations) evidence. More failed legs than
    MAX_FAILED_JOBS proves nothing.
    """
    legs = [j for j, name in failed if is_leg_of(name, producer)]
    if not legs or len(legs) > MAX_FAILED_JOBS:
        return False
    return any(proven_test_red(*sources(j)) for j in legs)


def run_cancel_decision(repo: str, run_id: str, attempt: str, producer: str) -> bool:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise PolicyError(f"REPO {repo!r} is not owner/name")
    for what, value in (("RUN_ID", run_id), ("RUN_ATTEMPT", attempt)):
        if not value.isascii() or not value.isdigit():
            raise PolicyError(f"{what} {value!r} is not a decimal id")
    if not producer or producer != producer.strip() or "${{" in producer or not producer.isprintable():
        raise PolicyError(f"PRODUCER {producer!r} is not a job name")
    # Every page of the attempt's listing, unfiltered: a job a server-side
    # filter dropped could never be proven, so nothing is filtered there.
    listing = _gh_text(
        [f"repos/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs", "--paginate", "--jq", JOB_ROWS_JQ]
    )
    return decide_cancel(failed_jobs_named(listing), producer, lambda j: _job_sources(repo, j))


def signature_errors(signatures: tuple[tuple[str, str], ...], markers: tuple[str, ...]) -> list[str]:
    """Return why the signature/marker tables could fail open, or []."""
    errors: list[str] = []
    probes = ("", " ", "error", "FAIL", "test failed", "error: could not compile `ipe`")
    for where, table in (("signature", [p for _, p in signatures]), ("marker", list(markers))):
        if not table:
            errors.append(f"the {where} table is empty")
        if len(table) != len(set(table)):
            errors.append(f"the {where} table repeats a pattern")
        for pat in table:
            if not isinstance(pat, str) or not pat or pat != pat.strip():
                errors.append(f"{where} pattern {pat!r} is empty or padded")
                continue
            try:
                rx = re.compile(pat)
            except re.error as exc:
                errors.append(f"{where} pattern {pat!r} does not compile: {exc}")
                continue
            if pat.count(".*") > 1:
                errors.append(f"{where} pattern {pat!r} has more than one wildcard")
            if where == "signature" and any(rx.search(p) for p in probes):
                errors.append(f"signature {pat!r} matches generic failure text")
    for sid, _ in signatures:
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", sid or ""):
            errors.append(f"signature id {sid!r} is not kebab-case")
    return errors


def proven_marker_errors(
    proven: tuple[tuple[str, str], ...], markers: tuple[str, ...]
) -> list[str]:
    """Return why the proven-test-red table could cancel on a red the rerun
    policy would retry, or on generic failure text, or []."""
    errors: list[str] = []
    if not proven:
        errors.append("the proven-test-red table is empty")
    patterns = [p for p, _ in proven]
    if len(patterns) != len(set(patterns)):
        errors.append("the proven-test-red table repeats a pattern")
    probes = ("", " ", "error", "FAIL", "test failed", "error: test run failed",
              "     TIMEOUT [ 900.001s] x", "     SIGSEGV [   0.4s] x", "  LEAK-FAIL [   1.0s] x")
    vetoes = [re.compile(m) for m in markers]
    for pat, sample in proven:
        try:
            rx = re.compile(pat)
        except re.error as exc:
            errors.append(f"proven-test-red pattern {pat!r} does not compile: {exc}")
            continue
        if ".*" in pat:
            errors.append(f"proven-test-red pattern {pat!r} has a wildcard")
        if not rx.search(sample):
            errors.append(f"proven-test-red pattern {pat!r} does not match its sample {sample!r}")
        if not any(v.search(sample) for v in vetoes):
            errors.append(f"proven-test-red sample {sample!r} matches no veto marker; the rerun policy would retry it")
        for probe in probes:
            if rx.search(probe):
                errors.append(f"proven-test-red pattern {pat!r} matches crash or generic text {probe!r}")
    return errors


# A bare, quoted, dotted, or inline-table `retries` key. Only a whole-line
# comment is skipped: a `#` inside a string must not hide a key after it.
_RETRY_TOML = re.compile(r"""(?:^|[\s{,.])["']?retries["']?\s*=""")
_RETRY_WORKFLOW = re.compile(r"--retries\b|NEXTEST_RETRIES|--flaky-result\b|NEXTEST_FLAKY_RESULT")


def retry_errors(root: str = REPO_ROOT) -> list[str]:
    """Return every place a test retry is configured, or []."""
    errors: list[str] = []
    try:
        with open(os.path.join(root, ".config", "nextest.toml"), encoding="utf-8") as fh:
            for n, line in enumerate(fh, start=1):
                if not line.lstrip().startswith("#") and _RETRY_TOML.search(line):
                    errors.append(f".config/nextest.toml:{n}: sets `retries`; a flaky test must fail, not retry")
    except OSError as exc:
        errors.append(f".config/nextest.toml is unreadable: {exc}")
    for rel in RETRY_SCAN_DIRS:
        base = os.path.join(root, rel)
        if not os.path.isdir(base):
            errors.append(f"{rel} is missing")
            continue
        for dirpath, _, files in os.walk(base):
            for name in sorted(files):
                if not name.endswith((".yml", ".yaml")):
                    continue
                path = os.path.join(dirpath, name)
                with open(path, encoding="utf-8") as fh:
                    for n, line in enumerate(fh, start=1):
                        if _RETRY_WORKFLOW.search(line):
                            errors.append(f"{os.path.relpath(path, root)}:{n}: sets a nextest retry")
    return errors


RERUN_IF = "steps.gate.outputs.rerun == 'true'"
DECIDE_INVOCATION = "python3 .github/ci/rerun_policy.py --decide"
DECIDE_ENV = {
    "GH_TOKEN": "${{ secrets.PROMOTE_TOKEN || secrets.GITHUB_TOKEN }}",
    "REPO": "${{ github.repository }}",
    "RUN_ID": "${{ github.event.workflow_run.id }}",
}


def _strip_expr(text: str) -> str:
    text = text.strip()
    if text.startswith("${{") and text.endswith("}}"):
        return text[3:-2].strip()
    return text


def wiring_errors(workflow: dict) -> list[str]:
    """Return why rerun-failed-once.yml could rerun without a `true` verdict, or []."""
    jobs = workflow.get("jobs") if isinstance(workflow, dict) else None
    if not isinstance(jobs, dict) or not jobs:
        return ["rerun-failed-once.yml has no jobs"]
    errors: list[str] = []
    decide_steps: list[dict] = []
    rerun_steps: list[tuple[str, dict]] = []
    for job_id, job in jobs.items():
        steps = job.get("steps") if isinstance(job, dict) else None
        if not isinstance(steps, list):
            errors.append(f"job {job_id!r} has no steps list")
            continue
        for step in steps:
            run = step.get("run") if isinstance(step, dict) else None
            if not isinstance(run, str):
                continue
            if DECIDE_INVOCATION in run:
                decide_steps.append(step)
            if "gh run rerun" in run:
                rerun_steps.append((job_id, step))
    if len(decide_steps) != 1:
        errors.append(f"exactly one step must run `{DECIDE_INVOCATION}`, found {len(decide_steps)}")
    elif decide_steps[0].get("id") != "gate":
        errors.append("the decide step must have `id: gate`")
    else:
        gate = decide_steps[0]
        if gate.get("run", "").strip() != DECIDE_INVOCATION:
            errors.append(f"the decide step must run only `{DECIDE_INVOCATION}`, got {gate.get('run')!r}")
        if gate.get("env") != DECIDE_ENV:
            errors.append(f"the decide step's env must be exactly {DECIDE_ENV}")
        for key in ("if", "continue-on-error"):
            if key in gate:
                errors.append(f"the decide step must not set `{key}`")
    if len(rerun_steps) != 1:
        errors.append(f"exactly one step may run `gh run rerun`, found {len(rerun_steps)}")
    else:
        _, step = rerun_steps[0]
        cond = step.get("if")
        if not isinstance(cond, str) or _strip_expr(cond) != RERUN_IF:
            errors.append(f"the rerun step's `if:` must be exactly `{RERUN_IF}`, got {cond!r}")
        if "continue-on-error" in step:
            errors.append("the rerun step must not set `continue-on-error`")
    return errors


def lint(root: str = REPO_ROOT) -> int:
    sys.path.insert(0, HERE)
    import strict_yaml  # noqa: PLC0415  # PyYAML-backed; only `lint` needs it

    errors = (
        signature_errors(SIGNATURES, TEST_FAILURE_MARKERS)
        + proven_marker_errors(PROVEN_TEST_RED_MARKERS, TEST_FAILURE_MARKERS)
        + retry_errors(root)
    )
    path = os.path.join(root, ".github", "workflows", "rerun-failed-once.yml")
    try:
        with open(path, encoding="utf-8") as fh:
            errors += wiring_errors(strict_yaml.safe_load(fh))
    except Exception as exc:  # noqa: BLE001  # any read or parse failure is a refusal
        errors.append(f"rerun-failed-once.yml is unreadable: {exc}")
    for err in errors:
        print(f"rerun policy: {err}", file=sys.stderr)
    if errors:
        return 1
    print(f"rerun policy: {len(SIGNATURES)} infra signatures, no test retries, rerun gated on `true`.")
    return 0


def write_output(path: str, line: str) -> int:
    """Append `line` to the step-output file; no file or a failed write is exit 1."""
    if not path:
        print("rerun policy: GITHUB_OUTPUT is unset — no verdict, so no action", file=sys.stderr)
        return 1
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        print(f"rerun policy: GITHUB_OUTPUT is unwritable: {exc} — no verdict, so no action", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--decide"]:
        run_id = os.environ.get("RUN_ID", "")
        try:
            verdict = run_decide(os.environ.get("REPO", ""), run_id)
        except (PolicyError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            print(f"rerun policy: {exc} — no rerun", file=sys.stderr)
            verdict = False
        word = "true" if verdict else "false"
        print(f"rerun policy: run {run_id!r} infra-only verdict: {word}")
        return write_output(os.environ.get("GITHUB_OUTPUT", ""), f"rerun={word}")
    if argv == ["--proven-test-red"]:
        run_id = os.environ.get("RUN_ID", "")
        producer = os.environ.get("PRODUCER", "")
        try:
            verdict = run_cancel_decision(
                os.environ.get("REPO", ""), run_id, os.environ.get("RUN_ATTEMPT", ""), producer
            )
        except (PolicyError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            print(f"rerun policy: {exc} — no cancel", file=sys.stderr)
            verdict = False
        word = "true" if verdict else "false"
        print(f"rerun policy: run {run_id!r} job {producer!r} proven test red: {word}")
        return write_output(os.environ.get("GITHUB_OUTPUT", ""), f"cancel={word}")
    if argv == ["--lint"]:
        return lint()
    print("usage: rerun_policy.py --decide | --proven-test-red | --lint", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
