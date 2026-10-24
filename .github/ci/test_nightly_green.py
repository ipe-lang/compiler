#!/usr/bin/env python3
"""Refusal proofs for `nightly_green.py`, the nightly-green gate SSOT.

Every way the gate must stay red (a red, cancelled, running, stale, future,
missing, or mis-scoped nightly; a malformed listing, event, or queue ref; an
unreadable API) and every way its wiring could be weakened into a pass gets its
own test, per PRINCIPLES.md "Prove the refusals". Pure stdlib `unittest`.
"""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import itertools
import os
import subprocess
import sys
import unittest
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))

_spec = importlib.util.spec_from_file_location("nightly_green", os.path.join(HERE, "nightly_green.py"))
assert _spec is not None and _spec.loader is not None
ng = importlib.util.module_from_spec(_spec)
sys.modules["nightly_green"] = ng
_spec.loader.exec_module(ng)

NOW = datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)
SHA = "a" * 40
OTHER = "b" * 40
REPO = "ipe-lang/compiler"


def _stamp(delta: timedelta) -> str:
    return (NOW - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run(**over: object) -> dict:
    run = {
        "id": 1,
        "event": "workflow_dispatch",
        "path": ".github/workflows/ci.yml",
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 1,
        "head_branch": "main",
        "head_sha": OTHER,
        "created_at": _stamp(timedelta(hours=8)),
        "head_repository": {"full_name": REPO},
    }
    run.update(over)
    return run


def _unattempted(**over: object) -> dict:
    """A run copy that names no attempt at all."""
    run = _run(**over)
    del run["run_attempt"]
    return run


def _listing(*runs: dict) -> dict:
    return {"total_count": len(runs), "workflow_runs": list(runs)}


def _producer(workflow: str) -> ng.Producer:
    (found,) = [p for p in ng.PRODUCERS if p.workflow == workflow]
    return found


CI = _producer("ci.yml")
SANDBOX = _producer("admission-sandbox.yml")
STATIC = _producer("static.yml")
RULESET = _producer("ruleset-admin-read.yml")


def _prun(producer: ng.Producer, **over: object) -> dict:
    """A green main nightly of `producer`, id 900 + its position in `PRODUCERS`."""
    run = _run(
        id=900 + ng.PRODUCERS.index(producer),
        event=producer.events[0],
        path=producer.path,
    )
    run.update(over)
    return run


_JOB_IDS = itertools.count(1)


def _jobs_page(rid: int, *jobs: tuple[str, str], total: int | None = None, attempt: int = 1) -> dict:
    listed = [
        {"id": next(_JOB_IDS), "name": n, "status": "completed", "conclusion": c, "run_id": rid, "run_attempt": attempt}
        for n, c in jobs
    ]
    return {"total_count": len(listed) if total is None else total, "jobs": listed}


def _scope(path: str) -> str | None:
    """The commit or branch filter of a run listing path, or None for an event-only listing."""
    query = path.split("?", 1)[-1].split("&")
    scoped = [q for q in query if q.startswith(("head_sha=", "branch="))]
    return scoped[0] if scoped else None


class FakeApi:
    """Route `gh api` paths: the run listings per producer, event, and scope, a run, its jobs, a PR, a compare.

    For the producer under test (`workflow`, ci.yml by default):
    `main`/`own` answer the workflow listing filtered by event and branch/commit;
    `event_only` answers the workflow listing filtered by event alone;
    `repo_main`/`repo_own` answer the repository listing filtered by event and branch/commit.
    Every other producer's main listing is `others[workflow]`, by default one green run;
    `others_own[workflow]` is its commit listing, empty by default.
    `by_id` answers a run's own document, by default its most recently served listed copy.
    `jobs[rid]` answers run rid's job listing pages; by default one page holding every
    nightly-gate job of its producer, concluded as the run's freshest copy concluded,
    stamped with that copy's attempt. `job_attempts` records the attempt every jobs read names.
    """

    def __init__(
        self,
        main: object,
        own: object = None,
        pr: object = None,
        compare: object = None,
        event_only: object = None,
        repo_main: object = None,
        repo_own: object = None,
        by_id: dict | None = None,
        *,
        workflow: str = "ci.yml",
        others: dict | None = None,
        others_own: dict | None = None,
        jobs: dict | None = None,
    ) -> None:
        self.workflow = workflow
        self.by_id = by_id or {}
        self.jobs = jobs or {}
        self.served: list[object] = []
        self.batch: list[object] = []
        self.scope: tuple[str, str] | None = None
        self.judged: dict[int, dict] = {}
        self.main, self.own, self.pr = main, own if own is not None else _listing(), pr
        self.event_only = event_only if event_only is not None else _listing()
        self.repo_main = repo_main if repo_main is not None else _listing()
        self.repo_own = repo_own if repo_own is not None else _listing()
        self.compare = compare if compare is not None else {"status": "ahead"}
        self.others = {p.workflow: _listing(_prun(p)) for p in ng.PRODUCERS if p.workflow != workflow}
        self.others.update(others or {})
        self.others_own = others_own or {}
        self.calls: list[str] = []
        self.job_attempts: list[int] = []

    def __call__(self, path: str) -> object:
        self.calls.append(path)
        served = self._route(path)
        if "/runs?" in path:
            self.served.append(served)
            scope = _scope(path)
            if "/workflows/" in path and scope is not None:
                key = (path.split("/workflows/", 1)[1].split("/", 1)[0], scope)
                if key != self.scope:
                    self.scope, self.batch = key, []
            self.batch.append(served)
        return served

    def _copies(self, rid: int) -> list[dict]:
        """Copies of run `rid` in the listings served since the last run was re-read."""
        return [
            run
            for listing in self.batch
            for run in (listing.get("workflow_runs", []) if isinstance(listing, dict) else [])
            if isinstance(run, dict) and run.get("id") == rid
        ]

    def _reread(self, rid: int) -> object:
        copies = self._copies(rid)
        if rid in self.by_id:
            doc = self.by_id[rid]
        elif copies:
            doc = copies[-1]
        else:
            raise AssertionError(f"run {rid} was never listed")
        if isinstance(doc, dict) and copies:
            judged = copies[0]
            for copy_ in [*copies[1:], doc]:
                judged = ng._fresher(judged, copy_)
            self.judged[rid] = judged
        self.batch = []
        return doc

    def _job_pages(self, rid: int, page: int) -> object:
        if rid in self.jobs:
            pages = self.jobs[rid]
            return pages[page - 1] if page <= len(pages) else {"total_count": pages[0].get("total_count"), "jobs": []}
        run = self.judged[rid]
        (producer,) = [p for p in ng.PRODUCERS if p.path == run.get("path")]
        gates = ((g, str(run.get("conclusion"))) for g in sorted(producer.gates))
        return _jobs_page(rid, *gates, attempt=ng._attempt(run))

    def _route(self, path: str) -> object:
        if "/pulls/" in path:
            if self.pr is None:
                raise ng.NightlyError("no such PR")
            return self.pr
        if "/compare/" in path:
            return self.compare
        if path.startswith(f"repos/{REPO}/actions/runs/") and "/jobs?" in path:
            rid, rest = path.split("/actions/runs/", 1)[1].split("/", 1)
            if not rest.startswith("attempts/"):
                raise AssertionError(f"jobs read not bound to an attempt: {path}")
            self.job_attempts.append(int(rest.split("/", 2)[1]))
            return self._job_pages(int(rid), int(path.rsplit("page=", 1)[-1]))
        if path.startswith(f"repos/{REPO}/actions/runs/"):
            return self._reread(int(path.rsplit("/", 1)[-1]))
        if f"repos/{REPO}/actions/runs?" in path:
            if "head_sha=" in path:
                return self.repo_own
            if "branch=main" in path:
                return self.repo_main
        for producer in ng.PRODUCERS:
            if f"repos/{REPO}/actions/workflows/{producer.workflow}/runs?" not in path:
                continue
            if producer.workflow != self.workflow:
                if "head_sha=" in path:
                    return self.others_own.get(producer.workflow, _listing())
                return self.others[producer.workflow] if "branch=main" in path else _listing()
            if "head_sha=" in path:
                return self.own
            if "branch=main" in path:
                if isinstance(self.main, Exception):
                    raise self.main
                return self.main
            return self.event_only
        raise AssertionError(f"unexpected path {path}")


def _pick(*listings: object, branch: str | None = "main", sha: str | None = None) -> dict | None:
    return ng.newest_run(list(listings), CI, CI.events, branch=branch, sha=sha)


@contextlib.contextmanager
def _patched(**seams: object) -> Iterator[None]:
    """Replace module attributes of `nightly_green` for the block, restoring them after."""
    saved = {name: getattr(ng, name) for name in seams}
    for name, value in seams.items():
        setattr(ng, name, value)
    try:
        yield
    finally:
        for name, value in saved.items():
            setattr(ng, name, value)


def _verdict(api: FakeApi, **env: str) -> list[str]:
    base = {"EVENT_NAME": "pull_request", "HEAD_SHA": SHA, "GITHUB_REF": "", "REPO": REPO}
    base.update(env)
    saved = ng._gh_json
    ng._gh_json = api
    try:
        return ng.verdict(base, NOW)
    finally:
        ng._gh_json = saved


class RunErrorsTest(unittest.TestCase):
    def check(self, run: dict | None, producer: ng.Producer = CI) -> list[str]:
        return ng.run_errors(run, producer, producer.events, branch="main", sha=None, now=NOW)

    def test_green_fresh_nightly_passes(self) -> None:
        self.assertEqual(self.check(_run()), [])

    def test_missing_nightly_refused(self) -> None:
        self.assertTrue(self.check(None))

    def test_red_nightly_refused(self) -> None:
        for bad in ("cancelled", "timed_out", "skipped", "neutral", "action_required", "startup_failure", None):
            self.assertTrue(self.check(_run(conclusion=bad)), bad)
            self.assertTrue(self.check(_prun(SANDBOX, conclusion=bad), SANDBOX), bad)

    def test_failed_run_left_to_its_jobs_only_with_a_non_blocking_job(self) -> None:
        # A failed run is judged by its jobs only when a non-blocking job could
        # have failed it; a producer with none is red on the run alone.
        self.assertEqual(self.check(_run(conclusion="failure")), [])
        self.assertTrue(self.check(_prun(SANDBOX, conclusion="failure"), SANDBOX))
        self.assertTrue(self.check(_prun(RULESET, conclusion="failure"), RULESET))

    def test_running_nightly_refused(self) -> None:
        self.assertTrue(self.check(_run(status="in_progress", conclusion=None)))

    def test_stale_nightly_refused(self) -> None:
        self.assertTrue(any("older than" in e for e in self.check(_run(created_at=_stamp(timedelta(hours=ng.MAX_AGE_H, seconds=1))))))
        self.assertEqual(self.check(_run(created_at=_stamp(timedelta(hours=ng.MAX_AGE_H)))), [])

    def test_future_nightly_refused(self) -> None:
        self.assertTrue(any("future" in e for e in self.check(_run(created_at=_stamp(-timedelta(hours=1))))))

    def test_malformed_timestamp_refused(self) -> None:
        for bad in (None, "", "2026-09-29", "2026-09-29T12:00:00+00:00", 1759140000):
            self.assertTrue(self.check(_run(created_at=bad)), bad)

    def test_wrong_event_refused(self) -> None:
        for bad in ("push", "pull_request", "schedule", None):
            self.assertTrue(self.check(_run(event=bad)), bad)

    def test_wrong_workflow_refused(self) -> None:
        self.assertTrue(self.check(_run(path=".github/workflows/other.yml")))

    def test_wrong_branch_refused(self) -> None:
        self.assertTrue(self.check(_run(head_branch="feature")))

    def test_wrong_commit_refused(self) -> None:
        self.assertTrue(ng.run_errors(_run(head_sha=OTHER), CI, CI.events, branch=None, sha=SHA, now=None))


class ListingTest(unittest.TestCase):
    def test_empty_listing_is_no_run(self) -> None:
        self.assertIsNone(_pick(_listing()))
        self.assertIsNone(_pick())

    def test_malformed_listing_refused(self) -> None:
        for bad in ({}, [], None, {"workflow_runs": {}}, {"workflow_runs": ["x"]}, _listing(_run(id="1")), _listing(_run(id=True)), _listing(_run(id=0))):
            with self.assertRaises(ng.NightlyError):
                _pick(bad)
            with self.assertRaises(ng.NightlyError):
                _pick(_listing(_run()), bad)

    def test_newest_run_chosen_whatever_the_order(self) -> None:
        old = _run(id=1, created_at="2026-09-22T09:13:24Z")
        new = _run(id=2, created_at="2026-09-29T10:34:21Z")
        for listing in (_listing(old, new), _listing(new, old)):
            chosen = _pick(listing)
            self.assertIsNotNone(chosen)
            self.assertEqual(chosen and chosen["id"], 2)

    def test_unfinished_run_skipped_for_the_newest_completed(self) -> None:
        done = _run(id=1, created_at="2026-09-28T10:50:15Z")
        for status in ("in_progress", "queued", "waiting", None):
            with self.subTest(status):
                running = _run(id=2, status=status, conclusion=None, created_at="2026-09-29T10:34:21Z")
                chosen = _pick(_listing(running, done))
                self.assertEqual(chosen and chosen["id"], 1)
        self.assertIsNone(_pick(_listing(_run(status="in_progress", conclusion=None))))

    def test_listing_is_not_status_filtered(self) -> None:
        api = FakeApi(_listing(_run()))
        _verdict(api)
        self.assertTrue(api.calls)
        for path in api.calls:
            self.assertNotIn("status=", path)

    def test_untimed_entry_refused(self) -> None:
        for created in (None, "yesterday", 5):
            with self.assertRaises(ng.NightlyError):
                _pick(_listing(_run(id=1), _run(id=2, created_at=created)))


class UnionTest(unittest.TestCase):
    """A stale or partial server-side listing can neither hide a fresh nightly nor pass a mis-scoped run."""

    def test_stale_branch_listing_loses_to_fresh_event_listing(self) -> None:
        stale = _listing(_run(id=1, head_sha=SHA, created_at=_stamp(timedelta(days=7))))
        fresh = _run(id=2, created_at=_stamp(timedelta(hours=2)))
        for where in ("event_only", "repo_main"):
            with self.subTest(where):
                api = FakeApi(stale, **{where: _listing(fresh)})
                self.assertEqual(_verdict(api), [])
                self.assertTrue(any(f"/compare/{OTHER}...main" in c for c in api.calls))
        self.assertTrue(any("older than" in r for r in _verdict(FakeApi(stale))))

    def test_mis_scoped_run_never_selected(self) -> None:
        main_green = _run(id=1, created_at=_stamp(timedelta(hours=9)))
        newer = _stamp(timedelta(hours=1))
        for bad in (
            _run(id=2, head_branch="feature", conclusion="failure", created_at=newer),
            _run(id=2, event="push", conclusion="failure", created_at=newer),
            _run(id=2, path=".github/workflows/other.yml", conclusion="failure", created_at=newer),
        ):
            with self.subTest(bad):
                chosen = _pick(_listing(main_green), _listing(bad), _listing(bad))
                self.assertEqual(chosen and chosen["id"], 1)
                api = FakeApi(_listing(main_green), event_only=_listing(bad), repo_main=_listing(bad))
                self.assertEqual(_verdict(api), [])
        for bad in (
            _run(id=2, head_branch="feature", created_at=newer),
            _run(id=2, event="push", created_at=newer),
            _run(id=2, path=".github/workflows/other.yml", created_at=newer),
        ):
            with self.subTest(bad):
                red = _listing(_run(id=1, conclusion="failure"))
                self.assertTrue(_verdict(FakeApi(red, event_only=_listing(bad), repo_main=_listing(bad))))
                self.assertIsNone(_pick(_listing(bad), _listing(bad)))

    def test_commit_scope_never_selects_other_commit(self) -> None:
        other = _run(id=2, head_branch="fix", head_sha=OTHER)
        self.assertIsNone(_pick(_listing(other), branch=None, sha=SHA))
        own = _run(id=3, head_branch="fix", head_sha=SHA, created_at=_stamp(timedelta(days=9)))
        chosen = _pick(_listing(other), _listing(own), branch=None, sha=SHA)
        self.assertEqual(chosen and chosen["id"], 3)

    def test_all_listings_empty_is_red(self) -> None:
        reasons = _verdict(FakeApi(_listing()))
        self.assertTrue(any("no completed workflow_dispatch run of ci.yml exists" in r for r in reasons), reasons)

    def test_every_listing_is_read(self) -> None:
        api = FakeApi(_listing(_run(conclusion="failure")))
        _verdict(api)
        for scope in (f"head_sha={SHA}", "branch=main"):
            for path in ng._listing_paths(REPO, CI, "workflow_dispatch", scope):
                self.assertIn(path, api.calls)

    def test_stale_own_listing_loses_to_repo_listing(self) -> None:
        own = _listing(_run(head_branch="fix-nightly", head_sha=SHA))
        api = FakeApi(_listing(_run(conclusion="failure")), repo_own=own)
        self.assertEqual(_verdict(api), [])

    def test_unreadable_listing_is_red(self) -> None:
        for where in ("event_only", "repo_main"):
            with self.subTest(where):
                with self.assertRaises(ng.NightlyError):
                    _verdict(FakeApi(_listing(_run()), **{where: {"total_count": 0}}))

    def test_fresher_copy_of_a_run_wins(self) -> None:
        stale_green = _run(id=5, run_attempt=1, updated_at=_stamp(timedelta(hours=7)))
        fresh_red = _run(id=5, run_attempt=2, conclusion="failure", updated_at=_stamp(timedelta(hours=1)))
        later_red = _run(id=5, run_attempt=1, conclusion="failure", updated_at=_stamp(timedelta(hours=1)))
        rerunning = _run(id=5, run_attempt=2, status="in_progress", conclusion=None, updated_at=_stamp(timedelta(hours=1)))
        for fresh in (fresh_red, later_red):
            for order in ((stale_green, fresh), (fresh, stale_green)):
                with self.subTest(fresh=fresh, order=order):
                    chosen = _pick(_listing(order[0]), _listing(order[1]))
                    self.assertEqual(chosen and chosen["conclusion"], "failure")
                    self.assertTrue(_verdict(FakeApi(_listing(order[0]), event_only=_listing(order[1]))))
        chosen = _pick(_listing(stale_green), _listing(rerunning))
        self.assertEqual(chosen and chosen["status"], "in_progress")

    def test_rerun_in_flight_shadows_an_older_green(self) -> None:
        # A nightly that concluded red and is being re-run has a verdict not yet
        # known; an older green nightly must not stand in for it.
        older_green = _run(id=4, created_at=_stamp(timedelta(hours=30)))
        rerunning = _run(id=5, run_attempt=2, status="in_progress", conclusion=None)
        chosen = _pick(_listing(older_green, rerunning))
        self.assertEqual(chosen and chosen["id"], 5)
        reasons = _verdict(FakeApi(_listing(older_green, rerunning)))
        self.assertTrue(any("status is 'in_progress'" in r for r in reasons), reasons)
        first_run = _run(id=5, status="in_progress", conclusion=None)
        self.assertEqual(_verdict(FakeApi(_listing(older_green, first_run))), [])

    def test_chosen_run_reread_beats_stale_listed_copy(self) -> None:
        stale_green = _run(id=5, run_attempt=1, updated_at=_stamp(timedelta(hours=7)))
        for fresh in (
            _run(id=5, run_attempt=2, conclusion="failure", updated_at=_stamp(timedelta(hours=1))),
            _run(id=5, run_attempt=2, status="in_progress", conclusion=None, updated_at=_stamp(timedelta(hours=1))),
            _run(id=5, run_attempt=1, conclusion="failure", updated_at=_stamp(timedelta(hours=1))),
        ):
            with self.subTest(fresh):
                api = FakeApi(_listing(stale_green), by_id={5: fresh})
                self.assertTrue(_verdict(api))
                self.assertIn(f"repos/{REPO}/actions/runs/5", api.calls)
        self.assertEqual(_verdict(FakeApi(_listing(stale_green), by_id={5: dict(stale_green)})), [])

    def test_chosen_run_reread_malformed_refused(self) -> None:
        listed = _run(id=5)
        for bad in ([], None, _run(id=6), _run(id="5"), _run(id=5, created_at=None), _run(id=5, conclusion="failure")):
            with self.subTest(bad), self.assertRaises(ng.NightlyError):
                _verdict(FakeApi(_listing(listed), by_id={5: bad}))

    def test_equally_fresh_copies_that_disagree_refused(self) -> None:
        a = _run(id=5, updated_at=_stamp(timedelta(hours=1)))
        b = _run(id=5, conclusion="failure", updated_at=_stamp(timedelta(hours=1)))
        with self.assertRaises(ng.NightlyError):
            _pick(_listing(a), _listing(b))
        self.assertEqual(_pick(_listing(a), _listing(dict(a))), a)

    def test_malformed_copy_rank_refused(self) -> None:
        a = _run(id=5)
        for bad in (_run(id=5, run_attempt=0), _run(id=5, run_attempt="2"), _unattempted(id=5), _run(id=5, updated_at="soon")):
            with self.subTest(bad), self.assertRaises(ng.NightlyError):
                _pick(_listing(a), _listing(bad))

    def test_run_naming_no_attempt_refused(self) -> None:
        # The attempt a run names selects the job listing judged; a copy that
        # names none is never read as attempt 1.
        with self.assertRaises(ng.NightlyError):
            _pick(_listing(_unattempted()))
        fresher = _unattempted(id=5, updated_at=_stamp(timedelta(hours=1)))
        with self.assertRaises(ng.NightlyError):
            _pick(_listing(_run(id=5)), _listing(fresher))
        reads: list[str] = []

        def answer(path: str) -> object:
            reads.append(path)
            return fresher if path.endswith("/runs/5") else _jobs_page(5, ("a", "success"))

        with _patched(_gh_json=answer):
            with self.assertRaises(ng.NightlyError):
                ng._reread(REPO, _run(id=5))
            with self.assertRaises(ng.NightlyError):
                ng._jobs(REPO, _unattempted(id=5))
        self.assertEqual(reads, [f"repos/{REPO}/actions/runs/5"])


class EventTest(unittest.TestCase):
    def test_pull_request_uses_head_sha(self) -> None:
        self.assertEqual(ng.change_sha_source("pull_request", SHA, ""), ("sha", SHA))

    def test_bad_head_sha_refused(self) -> None:
        for bad in ("", "a" * 39, "A" * 40, SHA + "\n", "a" * 41):
            with self.assertRaises(ng.NightlyError):
                ng.change_sha_source("pull_request", bad, "")

    def test_merge_group_parses_queue_ref(self) -> None:
        ref = f"refs/heads/gh-readonly-queue/main/pr-42-{SHA}"
        self.assertEqual(ng.change_sha_source("merge_group", "", ref), ("pr", "42"))

    def test_bad_queue_ref_refused(self) -> None:
        for bad in (
            "",
            f"refs/heads/gh-readonly-queue/dev/pr-42-{SHA}",
            f"refs/heads/gh-readonly-queue/main/pr-0-{SHA}",
            f"refs/heads/gh-readonly-queue/main/pr-x-{SHA}",
            "refs/heads/gh-readonly-queue/main/pr-42-abc",
            f"refs/heads/gh-readonly-queue/main/pr-42-{SHA}/../x",
        ):
            with self.assertRaises(ng.NightlyError):
                ng.change_sha_source("merge_group", "", bad)

    def test_unknown_event_refused(self) -> None:
        for bad in ("", "pull_request_target", "schedule", "workflow_run"):
            with self.assertRaises(ng.NightlyError):
                ng.change_sha_source(bad, SHA, "")


class VerdictTest(unittest.TestCase):
    def test_green_main_nightly_passes(self) -> None:
        self.assertEqual(_verdict(FakeApi(_listing(_run()))), [])

    def test_main_nightly_off_main_refused(self) -> None:
        # A tag or fork branch named `main` reports head_branch "main"; only a
        # commit on main's history proves main.
        for compare in ({"status": "diverged"}, {"status": "behind"}, {}, [], {"status": None}):
            with self.subTest(compare):
                api = FakeApi(_listing(_run()), compare=compare)
                self.assertTrue(any("is not on main" in r for r in _verdict(api)))
                self.assertTrue(any(f"/compare/{OTHER}...main" in c for c in api.calls))

    def test_main_nightly_at_or_behind_main_tip_passes(self) -> None:
        for status in ("identical", "ahead"):
            with self.subTest(status):
                self.assertEqual(_verdict(FakeApi(_listing(_run()), compare={"status": status})), [])

    def test_main_nightly_from_other_repo_refused(self) -> None:
        for head in ({"full_name": "fork/compiler"}, {}, None, "ipe-lang/compiler"):
            with self.subTest(head):
                run = _run(head_repository=head)
                self.assertTrue(any("head repository" in r for r in _verdict(FakeApi(_listing(run)))))

    def test_main_nightly_bad_sha_refused(self) -> None:
        for sha in ("", "zz", None, "A" * 40):
            with self.subTest(sha):
                self.assertTrue(_verdict(FakeApi(_listing(_run(head_sha=sha)))))

    def test_red_main_nightly_blocks(self) -> None:
        self.assertTrue(_verdict(FakeApi(_listing(_run(conclusion="failure")))))

    def test_no_main_nightly_blocks(self) -> None:
        self.assertTrue(_verdict(FakeApi(_listing())))

    def test_own_green_dispatch_recovers_red_nightly(self) -> None:
        own = _listing(_run(head_branch="fix-nightly", head_sha=SHA, created_at=_stamp(timedelta(days=9))))
        self.assertEqual(_verdict(FakeApi(_listing(_run(conclusion="failure")), own=own)), [])

    def test_own_red_dispatch_does_not_recover(self) -> None:
        own = _listing(_run(head_branch="fix-nightly", head_sha=SHA, conclusion="failure"))
        self.assertTrue(_verdict(FakeApi(_listing(_run(conclusion="failure")), own=own)))

    def test_own_dispatch_on_other_commit_does_not_recover(self) -> None:
        own = _listing(_run(head_branch="fix-nightly", head_sha=OTHER))
        self.assertTrue(_verdict(FakeApi(_listing(_run(conclusion="failure")), own=own)))

    def test_merge_group_resolves_pr_head(self) -> None:
        ref = f"refs/heads/gh-readonly-queue/main/pr-7-{OTHER}"
        own = _listing(_run(head_branch="fix", head_sha=SHA))
        api = FakeApi(_listing(_run(conclusion="failure")), own=own, pr={"head": {"sha": SHA}})
        self.assertEqual(_verdict(api, EVENT_NAME="merge_group", HEAD_SHA="", GITHUB_REF=ref), [])
        self.assertTrue(any("/pulls/7" in c for c in api.calls))

    def test_merge_group_bad_pr_head_refused(self) -> None:
        ref = f"refs/heads/gh-readonly-queue/main/pr-7-{OTHER}"
        for pr in ({}, {"head": {}}, {"head": {"sha": "zz"}}, []):
            with self.assertRaises(ng.NightlyError):
                _verdict(FakeApi(_listing(_run()), pr=pr), EVENT_NAME="merge_group", HEAD_SHA="", GITHUB_REF=ref)

    def test_bad_repo_refused(self) -> None:
        for bad in ("", "owner", "a/b/c", "a/b?x=1", "../..", "a/.."):
            with self.assertRaises(ng.NightlyError):
                _verdict(FakeApi(_listing(_run())), REPO=bad)

    def test_unreadable_api_is_red_via_main(self) -> None:
        saved = ng._gh_json

        def boom(path: str) -> object:
            raise ng.NightlyError("gh api down")

        ng._gh_json = boom
        env = {"EVENT_NAME": "pull_request", "HEAD_SHA": SHA, "GITHUB_REF": "", "REPO": REPO}
        saved_env = dict(os.environ)
        try:
            os.environ.update(env)
            self.assertEqual(ng.main(["--verdict"]), 1)
        finally:
            ng._gh_json = saved
            os.environ.clear()
            os.environ.update(saved_env)

    def test_usage_refused(self) -> None:
        self.assertEqual(ng.main([]), 2)
        for argv in (["verdict"], ["lint"], ["--verdict", "x"], ["-verdict"], ["--verdict", "--lint"]):
            self.assertEqual(ng.main(argv), 2, argv)


STEP = {
    "name": "verdict",
    "env": dict(ng.EXPECTED_ENV),
    "run": ng.VERDICT_INVOCATION,
}
WORKFLOW = {
    "jobs": {
        "nightly-green": {
            "name": "nightly-green",
            "runs-on": "ubuntu-latest",
            "steps": [{"uses": "actions/checkout@v7"}, STEP],
        }
    }
}
MANIFEST = {"checks": [{"context": "nightly-green", "disposition": "gate", "producer": "nightly-green.yml"}]}


def _wiring(workflow: object, manifest: object) -> list[str]:
    """The wiring verdict over a manifest that names no nightly-gate producer."""
    return ng.wiring_errors(workflow, manifest, {}, ())


def _job(wf: dict) -> dict:
    return wf["jobs"]["nightly-green"]


class WiringTest(unittest.TestCase):
    def test_ssot_wiring_passes(self) -> None:
        self.assertEqual(_wiring(WORKFLOW, MANIFEST), [])

    def test_repo_wiring_passes(self) -> None:
        self.assertEqual(ng.lint(), 0)

    def test_job_level_escape_refused(self) -> None:
        for key, val in (("if", "false"), ("continue-on-error", True), ("needs", ["x"]), ("strategy", {})):
            wf = copy.deepcopy(WORKFLOW)
            _job(wf)[key] = val
            self.assertTrue(_wiring(wf, MANIFEST), key)

    def test_step_escape_refused(self) -> None:
        for key, val in (("if", "false"), ("continue-on-error", True)):
            wf = copy.deepcopy(WORKFLOW)
            _job(wf)["steps"][1][key] = val
            self.assertTrue(_wiring(wf, MANIFEST), key)

    def test_masked_invocation_refused(self) -> None:
        for run in (f"{ng.VERDICT_INVOCATION} || true", f"{ng.VERDICT_INVOCATION}; exit 0", "true"):
            wf = copy.deepcopy(WORKFLOW)
            _job(wf)["steps"][1]["run"] = run
            self.assertTrue(_wiring(wf, MANIFEST), run)

    def test_duplicate_invocation_refused(self) -> None:
        wf = copy.deepcopy(WORKFLOW)
        _job(wf)["steps"].append(dict(STEP))
        self.assertTrue(_wiring(wf, MANIFEST))

    def test_env_tampering_refused(self) -> None:
        for key, val in (("EVENT_NAME", "pull_request"), ("HEAD_REF", "${{ github.event.merge_group.head_ref }}"), ("GITHUB_REF", "refs/heads/main"), ("HEAD_SHA", "${{ github.sha }}"), ("GH_TOKEN", "${{ secrets.X }}")):
            wf = copy.deepcopy(WORKFLOW)
            _job(wf)["steps"][1]["env"][key] = val
            self.assertTrue(_wiring(wf, MANIFEST), key)
        wf = copy.deepcopy(WORKFLOW)
        del _job(wf)["steps"][1]["env"]["REPO"]
        self.assertTrue(_wiring(wf, MANIFEST))

    def test_renamed_context_refused(self) -> None:
        wf = copy.deepcopy(WORKFLOW)
        _job(wf)["name"] = "nightly"
        self.assertTrue(_wiring(wf, MANIFEST))

    def test_extra_job_refused(self) -> None:
        wf = copy.deepcopy(WORKFLOW)
        wf["jobs"]["other"] = {"steps": []}
        self.assertTrue(_wiring(wf, MANIFEST))

    def test_manifest_downgrade_refused(self) -> None:
        for manifest in (
            {"checks": []},
            {"checks": [{"context": "nightly-green", "disposition": "informational", "producer": "nightly-green.yml"}]},
            {"checks": [{"context": "nightly-green", "disposition": "gate", "producer": "ci.yml"}]},
            {"checks": MANIFEST["checks"] * 2},
            None,
        ):
            self.assertTrue(_wiring(WORKFLOW, manifest), manifest)


def _gates_page(rid: int, producer: ng.Producer, *extra: tuple[str, str], **over: str) -> list[dict]:
    """One job page: every nightly-gate job of `producer` green unless `over` names it, plus `extra` jobs."""
    jobs = [(g, over.get(g, "success")) for g in sorted(producer.gates)]
    return [_jobs_page(rid, *jobs, *extra)]


SANDBOX_ID = 900 + ng.PRODUCERS.index(SANDBOX)
STATIC_ID = 900 + ng.PRODUCERS.index(STATIC)
RULESET_ID = 900 + ng.PRODUCERS.index(RULESET)
WINDOWS = "windows-x64 (Docker Windows container, process isolation)"


class ProducerVerdictTest(unittest.TestCase):
    """Every nightly-gate producer is judged; a red or stale one blocks even when ci.yml is green."""

    def test_every_producer_green_passes(self) -> None:
        api = FakeApi(_listing(_run()))
        self.assertEqual(_verdict(api), [])
        for producer in ng.PRODUCERS:
            for event in producer.events:
                for path in ng._listing_paths(REPO, producer, event, "branch=main"):
                    self.assertIn(path, api.calls)

    def test_red_admission_sandbox_nightly_context_fails(self) -> None:
        red_run = _listing(_prun(SANDBOX, conclusion="failure"))
        reasons = _verdict(FakeApi(_listing(_run()), others={SANDBOX.workflow: red_run}))
        self.assertTrue(any(r.startswith("admission-sandbox.yml main nightly:") for r in reasons), reasons)
        # A run reported green whose nightly-gate job is red is still red.
        for conclusion in ("failure", "cancelled", "skipped", "timed_out"):
            with self.subTest(conclusion):
                jobs = {SANDBOX_ID: _gates_page(SANDBOX_ID, SANDBOX, **{WINDOWS: conclusion})}
                reasons = _verdict(FakeApi(_listing(_run()), jobs=jobs))
                self.assertTrue(any(WINDOWS in r and "admission-sandbox.yml" in r for r in reasons), reasons)

    def test_stale_producer_fails(self) -> None:
        for producer in (SANDBOX, STATIC, RULESET):
            with self.subTest(producer.workflow):
                stale = _listing(_prun(producer, created_at=_stamp(timedelta(hours=ng.MAX_AGE_H, seconds=1))))
                reasons = _verdict(FakeApi(_listing(_run()), others={producer.workflow: stale}))
                self.assertTrue(any(producer.workflow in r and "older than" in r for r in reasons), reasons)

    def test_absent_producer_run_fails(self) -> None:
        for producer in (SANDBOX, STATIC, RULESET):
            with self.subTest(producer.workflow):
                reasons = _verdict(FakeApi(_listing(_run()), others={producer.workflow: _listing()}))
                self.assertTrue(any(f"run of {producer.workflow} exists" in r for r in reasons), reasons)

    def test_producer_run_of_a_non_nightly_event_never_selected(self) -> None:
        # static.yml also runs on push; only its scheduled/dispatched runs are its nightly.
        push = _listing(_prun(STATIC, event="push", created_at=_stamp(timedelta(hours=1))))
        reasons = _verdict(FakeApi(_listing(_run()), others={STATIC.workflow: push}))
        self.assertTrue(any("run of static.yml exists" in r for r in reasons), reasons)

    def test_missing_gate_job_fails(self) -> None:
        jobs = {SANDBOX_ID: [_jobs_page(SANDBOX_ID, ("freebsd-x64 (jail(8) inside vmactions VM)", "success"))]}
        reasons = _verdict(FakeApi(_listing(_run()), jobs=jobs))
        self.assertTrue(any(f"nightly-gate job {WINDOWS!r} did not run" in r for r in reasons), reasons)

    def test_unknown_job_blocks_unless_green_or_skipped(self) -> None:
        for conclusion, red in (("failure", True), ("cancelled", True), ("skipped", False), ("success", False)):
            with self.subTest(conclusion):
                jobs = {SANDBOX_ID: _gates_page(SANDBOX_ID, SANDBOX, ("admission-changes", conclusion))}
                self.assertEqual(bool(_verdict(FakeApi(_listing(_run()), jobs=jobs))), red)

    def test_non_blocking_job_never_decides(self) -> None:
        # A red informational job fails static.yml's run but not the nightly.
        failed = _listing(_prun(STATIC, conclusion="failure"))
        jobs = {STATIC_ID: _gates_page(STATIC_ID, STATIC, ("windows-static (dlmalloc, MSVC +crt-static)", "failure"))}
        self.assertEqual(_verdict(FakeApi(_listing(_run()), others={STATIC.workflow: failed}, jobs=jobs)), [])

    def test_gate_also_listed_non_blocking_is_still_judged(self) -> None:
        both = ng.Producer("x.yml", ("schedule",), None, frozenset({"heavy"}), frozenset({"heavy"}))
        jobs = [{"id": 1, "name": "heavy", "status": "completed", "conclusion": "failure", "run_id": 1}]
        self.assertTrue(ng.job_errors(jobs, both))

    def test_unfinished_job_fails(self) -> None:
        jobs = {STATIC_ID: [{"total_count": 1, "jobs": [{"id": 1, "name": "linux-cfree-gate (refusal is fail-closed)", "status": "in_progress", "conclusion": None, "run_id": STATIC_ID, "run_attempt": 1}]}]}
        self.assertTrue(_verdict(FakeApi(_listing(_run()), jobs=jobs)))

    def test_own_dispatch_recovers_only_its_producer(self) -> None:
        red = {SANDBOX.workflow: _listing(_prun(SANDBOX, conclusion="failure"))}
        own = {SANDBOX.workflow: _listing(_prun(SANDBOX, id=77, event="workflow_dispatch", head_branch="fix", head_sha=SHA))}
        self.assertEqual(_verdict(FakeApi(_listing(_run()), others=red, others_own=own)), [])
        # A green ci.yml dispatch of the change does not stand in for a red admission-sandbox.yml.
        ci_own = _listing(_run(id=78, head_branch="fix", head_sha=SHA))
        reasons = _verdict(FakeApi(_listing(_run()), own=ci_own, others=red))
        self.assertTrue(any(r.startswith("admission-sandbox.yml") for r in reasons), reasons)
        # A scheduled run never proves a change commit, even at its sha.
        scheduled = {SANDBOX.workflow: _listing(_prun(SANDBOX, id=79, head_branch="fix", head_sha=SHA))}
        self.assertTrue(_verdict(FakeApi(_listing(_run()), others=red, others_own=scheduled)))

    def test_producer_without_dispatch_has_no_branch_recovery(self) -> None:
        red = {RULESET.workflow: _listing(_prun(RULESET, conclusion="failure"))}
        own = {RULESET.workflow: _listing(_prun(RULESET, id=80, event="workflow_dispatch", head_branch="fix", head_sha=SHA))}
        api = FakeApi(_listing(_run()), others=red, others_own=own)
        reasons = _verdict(api)
        self.assertTrue(any(r.startswith("ruleset-admin-read.yml main nightly:") for r in reasons), reasons)
        self.assertTrue(all("RECONCILIATION.md" in r for r in reasons if r.startswith("ruleset-admin-read.yml")), reasons)
        self.assertFalse(any("ruleset-admin-read.yml/runs?" in c and "head_sha=" in c for c in api.calls))

    def test_producer_hint_names_the_recovery(self) -> None:
        red = {STATIC.workflow: _listing(_prun(STATIC, conclusion="failure"))}
        reasons = _verdict(FakeApi(_listing(_run()), others=red))
        self.assertTrue(any("gh workflow run static.yml --ref <branch>" in r for r in reasons), reasons)


class JobListingTest(unittest.TestCase):
    def test_pages_cover_the_total(self) -> None:
        jobs = [_jobs_page(5, ("a", "success"), total=2), _jobs_page(5, ("b", "success"), total=2)]
        self.assertEqual([j["name"] for j in ng.jobs_of(jobs, 5, 1)], ["a", "b"])

    def test_short_or_malformed_listing_refused(self) -> None:
        for pages in (
            [],
            [_jobs_page(5, ("a", "success"), total=2)],
            [_jobs_page(5, ("a", "success"), total=1), _jobs_page(5, ("b", "success"), total=2)],
            [{"total_count": 1}],
            [{"total_count": True, "jobs": []}],
            [{"total_count": -1, "jobs": []}],
            [None],
            [{"total_count": 1, "jobs": [{"name": 3, "run_id": 5}]}],
            [{"total_count": 1, "jobs": ["a"]}],
            [_jobs_page(6, ("a", "success"))],
        ):
            with self.subTest(pages), self.assertRaises(ng.NightlyError):
                ng.jobs_of(pages, 5, 1)

    def test_repeated_job_refused(self) -> None:
        # A page that shifted under the read repeats one job where another stood:
        # the count matches, the missing job would go unjudged.
        first = _jobs_page(5, ("a", "success"), total=2)
        again = {"total_count": 2, "jobs": [dict(first["jobs"][0])]}
        with self.assertRaises(ng.NightlyError):
            ng.jobs_of([first, again], 5, 1)

    def test_job_without_an_id_refused(self) -> None:
        for jid in (None, 0, -1, True, "7"):
            with self.subTest(jid):
                page = _jobs_page(5, ("a", "success"))
                page["jobs"][0]["id"] = jid
                with self.assertRaises(ng.NightlyError):
                    ng.jobs_of([page], 5, 1)

    def test_listing_past_the_page_bound_refused(self) -> None:
        total = ng.JOBS_PAGE * ng.MAX_JOB_PAGES + 1
        pages = [
            _jobs_page(SANDBOX_ID, *((f"j{p}-{i}", "success") for i in range(ng.JOBS_PAGE)), total=total)
            for p in range(ng.MAX_JOB_PAGES + 1)
        ]
        api = FakeApi(_listing(_run()), jobs={SANDBOX_ID: pages})
        with self.assertRaises(ng.NightlyError):
            _verdict(api)
        self.assertEqual(sum(f"actions/runs/{SANDBOX_ID}/attempts/1/jobs?" in c for c in api.calls), ng.MAX_JOB_PAGES)

    def test_every_page_read(self) -> None:
        names = sorted(SANDBOX.gates)
        pages = [_jobs_page(SANDBOX_ID, (names[0], "success"), total=2), _jobs_page(SANDBOX_ID, (names[1], "success"), total=2)]
        api = FakeApi(_listing(_run()), jobs={SANDBOX_ID: pages})
        self.assertEqual(_verdict(api), [])
        self.assertIn(ng._jobs_path(REPO, SANDBOX_ID, 1, 2), api.calls)

    def test_jobs_read_the_judged_attempt_listing(self) -> None:
        path = ng._jobs_path(REPO, 5, 2, 1)
        self.assertIn(f"repos/{REPO}/actions/runs/5/attempts/2/jobs?", path)
        self.assertIn("per_page=30", path)
        self.assertNotIn("filter=", path)
        self.assertNotIn("status=", path)

    def test_rerun_attempt_is_the_one_read(self) -> None:
        listed = _run(id=5, run_attempt=1, conclusion="failure", updated_at=_stamp(timedelta(hours=7)))
        document = _run(id=5, run_attempt=2, updated_at=_stamp(timedelta(hours=1)))
        api = FakeApi(_listing(listed), by_id={5: document})
        self.assertEqual(_verdict(api), [])
        ci_reads = [c for c in api.calls if "/actions/runs/5/" in c and "/jobs?" in c]
        self.assertTrue(ci_reads)
        self.assertTrue(all("/actions/runs/5/attempts/2/jobs?" in c for c in ci_reads), ci_reads)

    def test_job_of_another_attempt_refused(self) -> None:
        for bad in (1, None, "2", True, 0, 3):
            with self.subTest(bad):
                page = _jobs_page(5, ("a", "success"), ("b", "success"), attempt=2)
                if bad is None:
                    del page["jobs"][1]["run_attempt"]
                else:
                    page["jobs"][1]["run_attempt"] = bad
                with self.assertRaises(ng.NightlyError) as caught:
                    ng.jobs_of([page], 5, 2)
                self.assertIn("is of attempt", str(caught.exception))
        self.assertEqual(len(ng.jobs_of([_jobs_page(5, ("a", "success"), attempt=2)], 5, 2)), 1)

    def test_failing_judged_attempt_listing_stays_red(self) -> None:
        api = FakeApi(_listing(_run()))

        def gateway(path: str) -> object:
            if "/attempts/" in path and "/jobs?" in path:
                raise ng.NightlyError(f"`gh api {path}` exited 1: gh: Server Error (HTTP 502)")
            return api(path)

        class Frozen(datetime):
            @classmethod
            def now(cls, tz: object = None) -> datetime:
                return NOW

        env = {"EVENT_NAME": "pull_request", "HEAD_SHA": SHA, "GITHUB_REF": "", "REPO": REPO}
        saved_env = dict(os.environ)
        err = io.StringIO()
        try:
            os.environ.update(env)
            with _patched(_gh_json=gateway, datetime=Frozen), contextlib.redirect_stderr(err):
                self.assertEqual(ng.main(["--verdict"]), 1)
        finally:
            os.environ.clear()
            os.environ.update(saved_env)
        self.assertIn("/actions/runs/", err.getvalue())
        self.assertIn("/attempts/1/jobs?", err.getvalue())
        self.assertIn("RED", err.getvalue())


def _done(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["gh", "api"], returncode, stdout, stderr)


GATEWAY = "gh: Server Error (HTTP 502)\n"


class GhReadTest(unittest.TestCase):
    """A transient `gh api` failure is retried a bounded number of times; anything else refuses at once."""

    def read(self, answers: list[Callable[[], subprocess.CompletedProcess[str]]]) -> tuple[object, int, list[int]]:
        """Run `_gh_json` over scripted `gh` answers; return its result, the `gh` runs made, and the pauses."""
        runs: list[str] = []
        pauses: list[int] = []

        def gh(path: str) -> subprocess.CompletedProcess[str]:
            runs.append(path)
            return answers[min(len(runs), len(answers)) - 1]()

        with _patched(_gh_run=gh, _pause=pauses.append):
            try:
                result: object = ng._gh_json("repos/x/y")
            except ng.NightlyError as exc:
                result = exc
        return result, len(runs), pauses

    def test_transient_gh_failure_is_retried_then_green(self) -> None:
        result, runs, pauses = self.read([lambda: _done(1, stderr=GATEWAY), lambda: _done(0, stdout='{"ok": 1}')])
        self.assertEqual(result, {"ok": 1})
        self.assertEqual(runs, 2)
        self.assertEqual(pauses, [2])

    def test_persistent_transient_failure_stays_red(self) -> None:
        result, runs, pauses = self.read([lambda: _done(1, stderr=GATEWAY)])
        self.assertIsInstance(result, ng.NightlyError)
        self.assertIn("HTTP 502", str(result))
        self.assertEqual(runs, ng.GH_TRIES)
        self.assertEqual(pauses, list(ng.GH_BACKOFF_S))

    def test_refused_gh_failure_not_retried(self) -> None:
        for answer in (lambda: _done(1, stderr="gh: Not Found (HTTP 404)\n"), lambda: _done(0, stdout="<html>")):
            result, runs, pauses = self.read([answer, lambda: _done(0, stdout="{}")])
            self.assertIsInstance(result, ng.NightlyError)
            self.assertEqual(runs, 1)
            self.assertEqual(pauses, [])

    def test_stream_reset_and_timeout_are_transient(self) -> None:
        for stderr, want in (
            ("stream error: stream ID 1; CANCEL; received from peer", ng.GhFailure.TRANSIENT),
            ("gh: Service Unavailable (HTTP 503)", ng.GhFailure.TRANSIENT),
            ("gh: Bad Gateway (HTTP 502) after 30s", ng.GhFailure.TRANSIENT),
            ("gh: Not Found (HTTP 404)", ng.GhFailure.REFUSED),
            ("gh: Forbidden (HTTP 403)", ng.GhFailure.REFUSED),
            ("HTTP 502", ng.GhFailure.REFUSED),
            ("", ng.GhFailure.REFUSED),
        ):
            with self.subTest(stderr):
                self.assertEqual(ng.classify(1, stderr), want)
        self.assertEqual(ng.classify(0, GATEWAY), ng.GhFailure.REFUSED)

        def timeout() -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(["gh", "api"], ng.GH_TIMEOUT_S)

        result, runs, pauses = self.read([timeout, lambda: _done(0, stdout="[]")])
        self.assertEqual(result, [])
        self.assertEqual((runs, pauses), (2, [2]))
        result, runs, _ = self.read([timeout])
        self.assertIsInstance(result, ng.NightlyError)
        self.assertEqual(runs, ng.GH_TRIES)


def _manifest(*entries: tuple[str, str, str]) -> dict:
    return {"checks": [{"context": c, "disposition": d, "producer": p} for c, d, p in entries]}


def _triggers(**on: tuple[str, ...]) -> dict:
    return {f"{name.replace('_', '-')}.yml": set(events) for name, events in on.items()}


SYNTH = ng.Producer(
    workflow="nightly-a.yml",
    events=("schedule", "workflow_dispatch"),
    recovery="workflow_dispatch",
    gates=frozenset({"heavy"}),
    non_blocking=frozenset({"note"}),
)
SYNTH_MANIFEST = _manifest(("heavy", "nightly-gate", "nightly-a.yml"), ("note", "informational", "nightly-a.yml"), ("fast", "gate", "nightly-a.yml"))
SYNTH_TRIGGERS = _triggers(nightly_a=("push", "schedule", "workflow_dispatch"))


class ProducersTest(unittest.TestCase):
    """`PRODUCERS` must equal what the manifest and each producer's triggers derive."""

    def check(self, manifest: object = SYNTH_MANIFEST, triggers: dict | None = None, declared: tuple = (SYNTH,)) -> list[str]:
        return ng.producers_errors(manifest, SYNTH_TRIGGERS if triggers is None else triggers, declared)

    def test_derived_producers_pass(self) -> None:
        self.assertEqual(self.check(), [])

    def test_repo_producers_match_the_manifest(self) -> None:
        self.assertEqual(ng.lint(), 0)

    def test_producer_absent_from_manifest_is_refused(self) -> None:
        extra = ng.Producer("gone.yml", ("schedule",), None, frozenset({"x"}), frozenset())
        errors = self.check(declared=(SYNTH, extra))
        self.assertTrue(any("gone.yml" in e and "produces no nightly-gate context" in e for e in errors), errors)

    def test_manifest_producer_absent_from_producers_is_refused(self) -> None:
        errors = self.check(declared=())
        self.assertTrue(any("nightly-a.yml" in e and "absent from PRODUCERS" in e for e in errors), errors)

    def test_duplicate_producer_refused(self) -> None:
        self.assertTrue(self.check(declared=(SYNTH, SYNTH)))

    def test_drifted_entry_refused(self) -> None:
        for drift in (
            {"gates": frozenset()},
            {"gates": frozenset({"heavy", "fast"})},
            {"non_blocking": frozenset()},
            {"events": ("workflow_dispatch",)},
            {"events": ("workflow_dispatch", "schedule")},
            {"recovery": None},
        ):
            with self.subTest(drift):
                declared = (ng.Producer(**{**SYNTH.__dict__, **drift}),)
                self.assertTrue(self.check(declared=declared))

    def test_trigger_drift_refused(self) -> None:
        for on in (("schedule",), ("push", "workflow_dispatch")):
            with self.subTest(on):
                self.assertTrue(self.check(triggers=_triggers(nightly_a=on)))

    def test_producer_without_nightly_trigger_refused(self) -> None:
        for triggers in (_triggers(nightly_a=("push", "pull_request")), {"nightly-a.yml": None}, {}):
            with self.subTest(triggers):
                errors = self.check(triggers=triggers)
                self.assertTrue(any("nightly-a.yml" in e for e in errors), errors)

    def test_context_declared_twice_refused(self) -> None:
        manifest = _manifest(("heavy", "nightly-gate", "nightly-a.yml"), ("heavy", "informational", "nightly-a.yml"), ("note", "informational", "nightly-a.yml"))
        errors = self.check(manifest=manifest)
        self.assertTrue(any("'heavy' more than once" in e for e in errors), errors)

    def test_unreadable_manifest_refused(self) -> None:
        for manifest in (None, {}, {"checks": {}}):
            with self.subTest(manifest):
                self.assertTrue(self.check(manifest=manifest))

    def test_non_blocking_dispositions_derived(self) -> None:
        manifest = _manifest(("heavy", "nightly-gate", "nightly-a.yml"), ("note", "candidate", "nightly-a.yml"), ("old", "delete", "nightly-a.yml"))
        declared = (ng.Producer(**{**SYNTH.__dict__, "non_blocking": frozenset({"note", "old"})}),)
        self.assertEqual(self.check(manifest=manifest, declared=declared), [])

    def test_triggers_of_reads_every_on_shape(self) -> None:
        self.assertEqual(ng.triggers_of({True: {"schedule": None}}), {"schedule"})
        self.assertEqual(ng.triggers_of({"on": ["push", "schedule"]}), {"push", "schedule"})
        self.assertEqual(ng.triggers_of({"on": "schedule"}), {"schedule"})
        for bad in (None, {}, {"on": 3}, {"on": [1]}, []):
            self.assertIsNone(ng.triggers_of(bad), bad)

    def test_wiring_includes_producer_check(self) -> None:
        manifest = {"checks": [*MANIFEST["checks"], *SYNTH_MANIFEST["checks"]]}
        self.assertEqual(ng.wiring_errors(WORKFLOW, manifest, SYNTH_TRIGGERS, (SYNTH,)), [])
        self.assertTrue(ng.wiring_errors(WORKFLOW, manifest, SYNTH_TRIGGERS, ()))


if __name__ == "__main__":
    unittest.main()
