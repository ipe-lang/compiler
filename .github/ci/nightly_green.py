#!/usr/bin/env python3
"""SSOT for the `nightly-green` gate: a red nightly blocks the next merge.

The nightly is every run of a workflow that produces a `nightly-gate` context
in `check-manifest.yml` — its *producers*, `PRODUCERS` below: "Build & test"
(ci.yml) dispatched on main by nightly-full-gate.yml, and the scheduled runs of
the others. `nightly-green` is a required context that passes only when EVERY
producer is proven green, each in one of two ways:

  1. the change's own commit passed a dispatched run of that producer (the
     recovery path: a PR that fixes a red nightly dispatches the producer on
     its branch, proves itself, and can merge), or
  2. the producer's latest concluded nightly run on main (a re-run in flight
     counts, its verdict not yet known) is at most MAX_AGE_H hours old (a
     stopped nightly is not a green one), ran on a commit of main's own history
     in this repository (a tag or branch merely named `main` proves nothing),
     and its jobs are green.

A run's jobs are green when every `nightly-gate` context of the producer is a
job that concluded `success`, and every other job concluded `success` or
`skipped` — except a job whose context the manifest declares non-blocking
(`NON_BLOCKING_DISPOSITIONS`). A job the manifest does not name blocks: an
unknown job is never assumed harmless.

Absence is not a pass: no run, a missing gate job, an unreadable listing, an
unexpected shape, a cancelled or stale nightly — each is a red.

Modes:
  --verdict  exit 0 iff the proof above holds for $EVENT_NAME / $HEAD_SHA in
             $REPO (a merge-group change is read from the runner's own
             $GITHUB_REF, the queue ref); exit 1 otherwise, naming why.
  --lint     fail unless nightly-green.yml runs `--verdict` unconditionally,
             the manifest declares `nightly-green` a gate, and `PRODUCERS`
             equals what the manifest and each producer's triggers derive.
             artifact-guard runs it.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
CONTEXT = "nightly-green"
WORKFLOW_FILE = "nightly-green.yml"
WORKFLOWS_DIR = ".github/workflows"
MAIN = "main"
MAX_AGE_H = 48
# Runs fetched per listing; the newest matching run across all listings is judged.
LISTING_PAGE = 20
# Jobs fetched per page of a run's job listing, and the most pages read; a run
# with more jobs than the bound covers is refused, never judged on a prefix.
JOBS_PAGE = 100
MAX_JOB_PAGES = 10
# Fields a run is judged on; two equally fresh copies of one run must agree on them.
_JUDGED_FIELDS = ("event", "path", "status", "conclusion", "head_branch", "head_sha", "created_at")
GH_TIMEOUT_S = 60
VERDICT_INVOCATION = "python3 .github/ci/nightly_green.py --verdict"
EXPECTED_ENV = {
    "EVENT_NAME": "${{ github.event_name }}",
    "HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
    "REPO": "${{ github.repository }}",
    "GH_TOKEN": "${{ github.token }}",
}
NIGHTLY_DISPOSITION = "nightly-gate"
# Dispositions whose job never decides the nightly verdict (`candidate` is
# surfaced with a promotion criterion instead, never judged here).
NON_BLOCKING_DISPOSITIONS = frozenset({"informational", "delete", "candidate"})
# Triggers whose runs on main are a producer's nightly; only a dispatch can
# target a branch, so it alone is the change-commit recovery event.
NIGHTLY_TRIGGERS = ("schedule", "workflow_dispatch")
RECOVERY_TRIGGER = "workflow_dispatch"

_SHA = re.compile(r"[0-9a-f]{40}")
_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
_QUEUE_REF = re.compile(r"refs/heads/gh-readonly-queue/main/pr-([1-9][0-9]{0,9})-[0-9a-f]{40}")


class NightlyError(Exception):
    """A listing, run, or event shape that proves nothing."""


@dataclass(frozen=True)
class Producer:
    """One workflow producing `nightly-gate` contexts, as the manifest and its triggers derive it."""

    workflow: str
    events: tuple[str, ...]
    recovery: str | None
    gates: frozenset[str]
    non_blocking: frozenset[str]

    @property
    def path(self) -> str:
        return f"{WORKFLOWS_DIR}/{self.workflow}"


# Asserted equal to the manifest + trigger derivation by `--lint` (artifact-guard);
# held here because the verdict runs from a sparse checkout of this file alone.
PRODUCERS: tuple[Producer, ...] = (
    Producer(
        workflow="admission-sandbox.yml",
        events=("schedule", "workflow_dispatch"),
        recovery="workflow_dispatch",
        gates=frozenset(
            {
                "windows-x64 (Docker Windows container, process isolation)",
                "freebsd-x64 (jail(8) inside vmactions VM)",
            }
        ),
        non_blocking=frozenset(),
    ),
    Producer(
        workflow="ci.yml",
        events=("workflow_dispatch",),
        recovery="workflow_dispatch",
        gates=frozenset(
            {
                "asan-all",
                "tsan",
                "ruleset-drift",
                "linux-arm64-tier2 (fifth platform — fail-closed refuse-to-certify proof)",
            }
        ),
        non_blocking=frozenset({"cancel-on-cheap-red"}),
    ),
    Producer(
        workflow="ruleset-admin-read.yml",
        events=("schedule",),
        recovery=None,
        gates=frozenset({"ruleset-admin-read"}),
        non_blocking=frozenset(),
    ),
    Producer(
        workflow="static.yml",
        events=("schedule", "workflow_dispatch"),
        recovery="workflow_dispatch",
        gates=frozenset({"linux-cfree-gate (refusal is fail-closed)"}),
        non_blocking=frozenset(
            {
                "linux-static-x64 (dlmalloc)",
                "linux-static-x64 (mimalloc)",
                "linux-static-arm64 (dlmalloc)",
                "windows-static (dlmalloc, MSVC +crt-static)",
                "freebsd-cross (x86_64-unknown-freebsd, build-only)",
            }
        ),
    ),
)


def _parse_time(text: object) -> datetime:
    if not isinstance(text, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", text):
        raise NightlyError(f"run timestamp {text!r} is not an ISO-8601 UTC instant")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _positive_int(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def _run_id(run: dict) -> int:
    rid = _positive_int(run.get("id"))
    if rid is None:
        raise NightlyError(f"run listing entry id {run.get('id')!r} is not a positive integer")
    return rid


def _attempt(run: dict) -> int:
    attempt = _positive_int(run.get("run_attempt", 1))
    if attempt is None:
        raise NightlyError(f"run {run.get('id')} attempt {run.get('run_attempt')!r} is not a positive integer")
    return attempt


def _judged(run: dict) -> tuple[object, ...]:
    head_repo = run.get("head_repository")
    return (
        *(run.get(key) for key in _JUDGED_FIELDS),
        head_repo.get("full_name") if isinstance(head_repo, dict) else head_repo,
    )


def _fresher(a: dict, b: dict) -> dict:
    """Return the copy of one run that reflects its later state; copies equally fresh must agree."""
    rank_a = (_attempt(a), _parse_time(a.get("updated_at", a.get("created_at"))))
    rank_b = (_attempt(b), _parse_time(b.get("updated_at", b.get("created_at"))))
    if rank_a != rank_b:
        return a if rank_a > rank_b else b
    if _judged(a) != _judged(b):
        raise NightlyError(f"run listings disagree on run {a.get('id')} at the same attempt and update time")
    return a


def newest_run(
    listings: list[object], producer: Producer, events: tuple[str, ...], *, branch: str | None, sha: str | None
) -> dict | None:
    """Return the newest completed `producer` run of `events` on `branch` / at `sha` across `listings`, or None.

    No single listing is trusted to be complete, ordered, or filtered as asked:
    a server-side filter can serve a stale index or drop recent runs. Every
    listing is read, runs are unioned by id (the freshest copy of each wins),
    and selection happens here: event, workflow path, branch or commit, and
    completion are matched client-side, and the newest by `created_at` is
    chosen. A run re-running (attempt above 1, not completed) already
    concluded once, so it is a candidate: it shadows every older run and is
    judged unfinished, never skipped for an older green. A listing only ever
    omits runs, so the union is at least as fresh as any one listing. Any
    malformed listing or entry refuses.
    """
    union: dict[int, dict] = {}
    for listing in listings:
        runs = listing.get("workflow_runs") if isinstance(listing, dict) else None
        if not isinstance(runs, list):
            raise NightlyError("run listing has no `workflow_runs` list")
        for run in runs:
            if not isinstance(run, dict):
                raise NightlyError("run listing entry is not an object")
            rid = _run_id(run)
            _attempt(run)
            _parse_time(run.get("created_at"))
            seen = union.get(rid)
            union[rid] = run if seen is None else _fresher(seen, run)
    newest: tuple[datetime, dict] | None = None
    for run in union.values():
        if (
            (run.get("status") != "completed" and _attempt(run) == 1)
            or run.get("event") not in events
            or run.get("path") != producer.path
            or (branch is not None and run.get("head_branch") != branch)
            or (sha is not None and run.get("head_sha") != sha)
        ):
            continue
        created = _parse_time(run.get("created_at"))
        if newest is None or created > newest[0]:
            newest = (created, run)
    return None if newest is None else newest[1]


def run_errors(
    run: dict | None,
    producer: Producer,
    events: tuple[str, ...],
    *,
    branch: str | None,
    sha: str | None,
    now: datetime | None,
) -> list[str]:
    """Return why `run` is not a concluded `producer` run fit to be judged by its jobs, or [] when it is.

    `branch`/`sha` pin where it must have run; `now` (when given) bounds its
    age. A run may conclude `failure` only when the producer has a
    non-blocking job that could have failed it; its jobs then decide.
    """
    if run is None:
        return [f"no completed {'/'.join(events)} run of {producer.workflow} exists"]
    errors: list[str] = []
    if run.get("event") not in events:
        errors.append(f"run event is {run.get('event')!r}, not one of {list(events)}")
    if run.get("path") != producer.path:
        errors.append(f"run workflow is {run.get('path')!r}, not {producer.path!r}")
    if run.get("status") != "completed":
        errors.append(f"run status is {run.get('status')!r}, not 'completed'")
    concluded = ("success", "failure") if producer.non_blocking else ("success",)
    if run.get("conclusion") not in concluded:
        errors.append(f"run {run.get('html_url', run.get('id'))} concluded {run.get('conclusion')!r}")
    if branch is not None and run.get("head_branch") != branch:
        errors.append(f"run branch is {run.get('head_branch')!r}, not {branch!r}")
    if sha is not None and run.get("head_sha") != sha:
        errors.append(f"run commit is {run.get('head_sha')!r}, not {sha!r}")
    if now is not None:
        try:
            created = _parse_time(run.get("created_at"))
        except NightlyError as exc:
            errors.append(str(exc))
        else:
            if created > now + timedelta(minutes=5):
                errors.append(f"run was created in the future ({created.isoformat()})")
            elif now - created > timedelta(hours=MAX_AGE_H):
                errors.append(
                    f"latest nightly is older than {MAX_AGE_H}h (run {run.get('id')}, created {created.isoformat()})"
                )
    return errors


def jobs_of(pages: list[object], rid: int) -> list[dict]:
    """Return the jobs `pages` (a run's job listing, page by page) hold for run `rid`.

    The pages must cover the listing's `total_count` exactly with distinct
    jobs (a page that shifts under the read repeats one job in place of
    another), and every job must name `rid` and carry a positive id and a
    string name; anything else refuses.
    """
    jobs: list[dict] = []
    ids: set[int] = set()
    total: int | None = None
    for page in pages:
        if not isinstance(page, dict) or not isinstance(page.get("jobs"), list):
            raise NightlyError(f"run {rid} job listing page has no `jobs` list")
        count = page.get("total_count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise NightlyError(f"run {rid} job listing total_count {count!r} is not a count")
        if total is not None and count != total:
            raise NightlyError(f"run {rid} job listing pages disagree on total_count")
        total = count
        for job in page["jobs"]:
            if not isinstance(job, dict) or not isinstance(job.get("name"), str):
                raise NightlyError(f"run {rid} job listing entry is not a named job")
            if job.get("run_id") != rid:
                raise NightlyError(f"run {rid} job listing holds a job of run {job.get('run_id')!r}")
            jid = _positive_int(job.get("id"))
            if jid is None:
                raise NightlyError(f"run {rid} job {job['name']!r} id {job.get('id')!r} is not a positive integer")
            if jid in ids:
                raise NightlyError(f"run {rid} job listing holds job {jid} twice")
            ids.add(jid)
            jobs.append(job)
    if total is None or len(jobs) != total:
        raise NightlyError(f"run {rid} job listing holds {len(jobs)} jobs, not its total_count {total!r}")
    return jobs


def job_errors(jobs: list[dict], producer: Producer) -> list[str]:
    """Return why `jobs` (one run's latest job results) do not prove `producer` green, or []."""
    errors: list[str] = []
    seen: set[str] = set()
    for job in jobs:
        name = job["name"]
        seen.add(name)
        if name in producer.non_blocking and name not in producer.gates:
            continue
        status, conclusion = job.get("status"), job.get("conclusion")
        allowed = ("success",) if name in producer.gates else ("success", "skipped")
        if status != "completed" or conclusion not in allowed:
            errors.append(f"job {name!r} is {status!r}/{conclusion!r}, not {'/'.join(allowed)}")
    errors += [f"nightly-gate job {name!r} did not run" for name in sorted(producer.gates - seen)]
    return errors


def ancestry_errors(sha: object, compare: object, repo: str, run_repo: object) -> list[str]:
    """Return why a `compare/<sha>...main` result does not put `sha` on main, or []."""
    errors: list[str] = []
    if run_repo != repo:
        errors.append(f"run head repository is {run_repo!r}, not {repo!r}")
    status = compare.get("status") if isinstance(compare, dict) else None
    if status not in ("identical", "ahead"):
        errors.append(f"run commit {str(sha)[:12]} is not on {MAIN} (compare status {status!r})")
    return errors


def on_main_errors(repo: str, run: dict) -> list[str]:
    sha = run.get("head_sha")
    if not isinstance(sha, str) or not _SHA.fullmatch(sha):
        return [f"run commit {sha!r} is not a 40-hex commit"]
    head_repo = run.get("head_repository")
    run_repo = head_repo.get("full_name") if isinstance(head_repo, dict) else None
    return ancestry_errors(sha, _gh_json(f"repos/{repo}/compare/{sha}...{MAIN}"), repo, run_repo)


def change_sha_source(event: str, head_sha: str, head_ref: str) -> tuple[str, str] | None:
    """Return how to find the change's own commit: ("sha", s) or ("pr", n).

    None means the event carries no change commit (a push or a dispatch on
    main), so only the main nightly can prove it. An event this gate does not
    know, or a malformed payload value, is refused.
    """
    if event == "pull_request":
        if not _SHA.fullmatch(head_sha):
            raise NightlyError(f"pull_request head sha {head_sha!r} is not a 40-hex commit")
        return ("sha", head_sha)
    if event == "merge_group":
        m = _QUEUE_REF.fullmatch(head_ref)
        if not m:
            raise NightlyError(f"merge_group head ref {head_ref!r} is not a main queue ref")
        return ("pr", m.group(1))
    if event in ("push", "workflow_dispatch"):
        return None
    raise NightlyError(f"event {event!r} is not one nightly-green judges")


def _gh_json(path: str) -> object:
    proc = subprocess.run(
        ["gh", "api", path], check=False, capture_output=True, text=True, timeout=GH_TIMEOUT_S
    )
    if proc.returncode != 0:
        raise NightlyError(f"`gh api {path}` exited {proc.returncode}: {proc.stderr.strip()}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise NightlyError(f"`gh api {path}` returned non-JSON: {exc}") from exc


def _listing_paths(repo: str, producer: Producer, event: str, scope: str) -> tuple[str, ...]:
    """Independent `.../runs` listings that each may hold `producer`'s `event` runs in `scope`.

    The workflow listing filtered by event and scope, the workflow listing
    filtered by event only, and the repository listing filtered by event and
    scope are separate server-side indexes; none is trusted alone.
    """
    page = f"event={event}&per_page={LISTING_PAGE}"
    return (
        f"repos/{repo}/actions/workflows/{producer.workflow}/runs?{page}&{scope}",
        f"repos/{repo}/actions/workflows/{producer.workflow}/runs?{page}",
        f"repos/{repo}/actions/runs?{page}&{scope}",
    )


def _jobs_path(repo: str, rid: int, page: int) -> str:
    return f"repos/{repo}/actions/runs/{rid}/jobs?filter=latest&per_page={JOBS_PAGE}&page={page}"


def _reread(repo: str, run: dict) -> dict:
    """Return the freshest of `run`'s listed copy and its own `actions/runs/<id>` document.

    Every listing can carry a stale copy of the chosen run (an earlier attempt's
    verdict); the run's own document is read and the later state judged.
    """
    rid = _run_id(run)
    fresh = _gh_json(f"repos/{repo}/actions/runs/{rid}")
    if not isinstance(fresh, dict) or _run_id(fresh) != rid:
        raise NightlyError(f"run {rid} document is not that run")
    _parse_time(fresh.get("created_at"))
    return _fresher(run, fresh)


def _jobs(repo: str, rid: int) -> list[dict]:
    """Read run `rid`'s latest job results, page by page, at most `MAX_JOB_PAGES` pages."""
    pages: list[object] = []
    collected = 0
    for number in range(1, MAX_JOB_PAGES + 1):
        page = _gh_json(_jobs_path(repo, rid, number))
        pages.append(page)
        jobs = page.get("jobs") if isinstance(page, dict) else None
        count = page.get("total_count") if isinstance(page, dict) else None
        if not isinstance(jobs, list) or not jobs or not isinstance(count, int):
            break
        collected += len(jobs)
        if collected >= count:
            break
    return jobs_of(pages, rid)


def _newest(
    repo: str, producer: Producer, events: tuple[str, ...], scope: str, *, branch: str | None, sha: str | None
) -> dict | None:
    listings = [_gh_json(path) for event in events for path in _listing_paths(repo, producer, event, scope)]
    chosen = newest_run(listings, producer, events, branch=branch, sha=sha)
    return None if chosen is None else _reread(repo, chosen)


def _proof_errors(
    repo: str,
    producer: Producer,
    events: tuple[str, ...],
    scope: str,
    *,
    branch: str | None,
    sha: str | None,
    now: datetime | None,
) -> list[str]:
    run = _newest(repo, producer, events, scope, branch=branch, sha=sha)
    errors = run_errors(run, producer, events, branch=branch, sha=sha, now=now)
    if errors or run is None:
        return errors
    if branch == MAIN:
        # `head_branch` is only a name: a tag or a fork branch called `main`
        # carries it too. The run proves main only if its commit is on main.
        errors = on_main_errors(repo, run)
        if errors:
            return errors
    return job_errors(_jobs(repo, _run_id(run)), producer)


def producer_errors(repo: str, producer: Producer, change_sha: str | None, now: datetime) -> list[str]:
    """Return why `producer` is not proven green for a change at `change_sha` (None: main only), or []."""
    reasons: list[str] = []
    if change_sha is not None and producer.recovery is not None:
        own = _proof_errors(
            repo, producer, (producer.recovery,), f"head_sha={change_sha}", branch=None, sha=change_sha, now=None
        )
        if not own:
            return []
        reasons += [f"{producer.workflow} at change commit {change_sha[:12]}: {e}" for e in own]
    main = _proof_errors(repo, producer, producer.events, f"branch={MAIN}", branch=MAIN, sha=None, now=now)
    if not main:
        return []
    hint = (
        f" (prove a fix with `gh workflow run {producer.workflow} --ref <branch>`)"
        if producer.recovery is not None
        else " (it runs on main only: `gh run rerun` its run, or follow the break-glass in .github/ci/RECONCILIATION.md)"
    )
    return reasons + [f"{producer.workflow} main nightly: {e}{hint}" for e in main]


def verdict(env: dict[str, str], now: datetime) -> list[str]:
    """Return [] when the gate passes, else every reason it does not."""
    repo = env.get("REPO", "")
    if not _REPO.fullmatch(repo):
        raise NightlyError(f"REPO {repo!r} is not owner/name")
    source = change_sha_source(env.get("EVENT_NAME", ""), env.get("HEAD_SHA", ""), env.get("GITHUB_REF", ""))
    sha: str | None = None
    if source is not None:
        kind, sha = source
        if kind == "pr":
            pr = _gh_json(f"repos/{repo}/pulls/{sha}")
            head = pr.get("head") if isinstance(pr, dict) else None
            head_sha = head.get("sha") if isinstance(head, dict) else None
            if not isinstance(head_sha, str) or not _SHA.fullmatch(head_sha):
                raise NightlyError(f"PR #{sha} has no 40-hex head sha")
            sha = head_sha
    reasons: list[str] = []
    for producer in PRODUCERS:
        reasons += producer_errors(repo, producer, sha, now)
    return reasons


def _strip_expr(text: str) -> str:
    return " ".join(text.split())


def triggers_of(workflow: object) -> set[str] | None:
    """Return the workflow's event names, or None when `on:` has no recognised shape.

    PyYAML 1.1 reads the bare key `on` as boolean True.
    """
    if not isinstance(workflow, dict):
        return None
    on = workflow.get(True, workflow.get("on"))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list) and all(isinstance(e, str) for e in on):
        return set(on)
    if isinstance(on, dict):
        return {str(k) for k in on}
    return None


def nightly_workflows(manifest: object) -> list[str]:
    """Return every workflow a `nightly-gate` entry of `manifest` names as its producer."""
    entries = manifest.get("checks") if isinstance(manifest, dict) else None
    listed = entries if isinstance(entries, list) else []
    return sorted(
        {str(e.get("producer")) for e in listed if isinstance(e, dict) and e.get("disposition") == NIGHTLY_DISPOSITION}
    )


def derive_producers(manifest: object, triggers: dict[str, set[str] | None]) -> tuple[list[Producer], list[str]]:
    """Derive every producer from `manifest` and each producer workflow's `triggers`; return them and any refusal.

    A producer is every workflow a `nightly-gate` entry names. Its nightly
    events are its triggers among `NIGHTLY_TRIGGERS`, and its recovery event is
    `RECOVERY_TRIGGER` when it has that trigger. A producer without a nightly
    trigger, or whose triggers are unreadable, is refused: nothing would ever
    prove it.
    """
    entries = manifest.get("checks") if isinstance(manifest, dict) else None
    if not isinstance(entries, list):
        return [], ["check-manifest.yml has no `checks` list"]
    checks = [e for e in entries if isinstance(e, dict)]
    producers: list[Producer] = []
    errors: list[str] = []
    for workflow in nightly_workflows(manifest):
        on = triggers.get(workflow)
        if on is None:
            errors.append(f"nightly-gate producer {workflow} has no readable `on:` triggers")
            continue
        events = tuple(t for t in NIGHTLY_TRIGGERS if t in on)
        if not events:
            errors.append(f"nightly-gate producer {workflow} has no {'/'.join(NIGHTLY_TRIGGERS)} trigger")
            continue
        mine = [e for e in checks if e.get("producer") == workflow]
        contexts = [str(e.get("context")) for e in mine]
        errors += [
            f"nightly-gate producer {workflow} declares context {c!r} more than once"
            for c in sorted({c for c in contexts if contexts.count(c) > 1})
        ]
        producers.append(
            Producer(
                workflow=workflow,
                events=events,
                recovery=RECOVERY_TRIGGER if RECOVERY_TRIGGER in on else None,
                gates=frozenset(str(e.get("context")) for e in mine if e.get("disposition") == NIGHTLY_DISPOSITION),
                non_blocking=frozenset(
                    str(e.get("context")) for e in mine if e.get("disposition") in NON_BLOCKING_DISPOSITIONS
                ),
            )
        )
    return producers, errors


def producers_errors(
    manifest: object, triggers: dict[str, set[str] | None], declared: tuple[Producer, ...] = PRODUCERS
) -> list[str]:
    """Return why `declared` (the verdict's `PRODUCERS`) differs from the manifest + trigger derivation, or []."""
    derived, errors = derive_producers(manifest, triggers)
    want = {p.workflow: p for p in derived}
    have: dict[str, Producer] = {}
    for producer in declared:
        if producer.workflow in have:
            errors.append(f"PRODUCERS lists {producer.workflow} twice")
        have[producer.workflow] = producer
    named = set(nightly_workflows(manifest))
    errors += [
        f"PRODUCERS lists {workflow}, which produces no nightly-gate context in check-manifest.yml"
        for workflow in sorted(set(have) - named)
    ]
    errors += [
        f"check-manifest.yml has nightly-gate contexts produced by {workflow}, absent from PRODUCERS"
        for workflow in sorted(named - set(have))
    ]
    errors += [
        f"PRODUCERS entry for {workflow} is {have[workflow]}, but the manifest derives {want[workflow]}"
        for workflow in sorted(set(want) & set(have))
        if have[workflow] != want[workflow]
    ]
    return errors


def wiring_errors(
    workflow: object,
    manifest: object,
    triggers: dict[str, set[str] | None],
    declared: tuple[Producer, ...] = PRODUCERS,
) -> list[str]:
    """Return why nightly-green could pass without `--verdict` passing or judge other producers than the manifest's, or []."""
    errors: list[str] = []
    jobs = workflow.get("jobs") if isinstance(workflow, dict) else None
    if not isinstance(jobs, dict) or len(jobs) != 1:
        return [f"{WORKFLOW_FILE} must define exactly one job"]
    (job_id, job), = jobs.items()
    if not isinstance(job, dict):
        return [f"{WORKFLOW_FILE} job {job_id!r} is not a mapping"]
    if job.get("name", job_id) != CONTEXT:
        errors.append(f"the job must report context {CONTEXT!r}")
    for key in ("if", "continue-on-error", "needs", "strategy"):
        if key in job:
            errors.append(f"the job must not set `{key}` (the gate runs unconditionally, once)")
    steps = job.get("steps")
    if not isinstance(steps, list):
        return errors + ["the job has no steps list"]
    verdict_steps = [s for s in steps if isinstance(s, dict) and VERDICT_INVOCATION in str(s.get("run", ""))]
    if len(verdict_steps) != 1:
        errors.append(f"exactly one step must run `{VERDICT_INVOCATION}`")
    for step in steps:
        if isinstance(step, dict) and ("continue-on-error" in step or "if" in step):
            errors.append(f"step {step.get('name', step.get('uses'))!r} must not set `if` or `continue-on-error`")
    if len(verdict_steps) == 1:
        env = verdict_steps[0].get("env")
        if not isinstance(env, dict) or {k: _strip_expr(str(v)) for k, v in env.items()} != EXPECTED_ENV:
            errors.append(f"the verdict step's env must be exactly {EXPECTED_ENV}")
        run = str(verdict_steps[0].get("run", "")).strip()
        if run != VERDICT_INVOCATION:
            errors.append(f"the verdict step must run only `{VERDICT_INVOCATION}`, got {run!r}")
    entries = manifest.get("checks") if isinstance(manifest, dict) else None
    mine = [e for e in entries or [] if isinstance(e, dict) and e.get("context") == CONTEXT]
    if len(mine) != 1 or mine[0].get("disposition") != "gate" or mine[0].get("producer") != WORKFLOW_FILE:
        errors.append(f"check-manifest.yml must declare {CONTEXT!r} once as a `gate` produced by {WORKFLOW_FILE}")
    return errors + producers_errors(manifest, triggers, declared)


def lint(root: str = REPO_ROOT) -> int:
    sys.path.insert(0, HERE)
    import strict_yaml  # noqa: PLC0415  # PyYAML-backed; only `lint` needs it

    def load(*parts: str) -> object:
        with open(os.path.join(root, *parts), encoding="utf-8") as fh:
            return strict_yaml.safe_load(fh)

    workflows = WORKFLOWS_DIR.split("/")
    try:
        workflow = load(*workflows, WORKFLOW_FILE)
        manifest = load(".github", "ci", "check-manifest.yml")
        triggers = {name: triggers_of(load(*workflows, name)) for name in nightly_workflows(manifest)}
    except Exception as exc:  # noqa: BLE001  # any read or parse failure is a refusal
        print(f"nightly-green lint: unreadable input: {exc}", file=sys.stderr)
        return 1
    errors = wiring_errors(workflow, manifest, triggers)
    for err in errors:
        print(f"nightly-green lint: {err}", file=sys.stderr)
    if errors:
        return 1
    print(
        f"nightly-green lint: {WORKFLOW_FILE} runs the verdict unconditionally; the manifest gates it; "
        f"it judges every nightly-gate producer ({', '.join(p.workflow for p in PRODUCERS)})."
    )
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--verdict"]:
        try:
            reasons = verdict(dict(os.environ), datetime.now(timezone.utc))
        except (NightlyError, OSError, subprocess.SubprocessError) as exc:
            reasons = [str(exc)]
        for reason in reasons:
            print(f"nightly-green: {reason}", file=sys.stderr)
        if reasons:
            print(
                "nightly-green: RED — fix the red nightly on main, or prove this commit by dispatching "
                "each red producer on its branch (`gh workflow run <workflow> --ref <branch>`) and re-run this check.",
                file=sys.stderr,
            )
            return 1
        print("nightly-green: every nightly-gate producer is green.")
        return 0
    if argv == ["--lint"]:
        return lint()
    print("usage: nightly_green.py --verdict | --lint", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
