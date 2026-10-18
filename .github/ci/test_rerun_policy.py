#!/usr/bin/env python3
"""Refusal proofs for `rerun_policy.py`, the infra-only automatic-rerun SSOT.

Every way the policy must refuse a rerun (a test failure, an unknown red, a
test failure beside an infra signature, an unreadable job, no failed job, a
malformed job listing) and every way `--lint` must refuse (a fail-open signature,
a configured test retry, a rerun step not gated on the exact verdict) gets its
own test, per PRINCIPLES.md "Prove the refusals". Pure stdlib `unittest`.
"""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

_spec = importlib.util.spec_from_file_location("rerun_policy", os.path.join(HERE, "rerun_policy.py"))
assert _spec is not None and _spec.loader is not None
rp = importlib.util.module_from_spec(_spec)
sys.modules["rerun_policy"] = rp
_spec.loader.exec_module(rp)

TS = "2026-09-29T04:12:33.1234567Z "
TEST_FAIL_LOG = [
    TS + "        PASS [   1.204s] ipe::emit ok_case",
    TS + "        FAIL [  12.881s] ipe::emit broken_case",
    TS + "error: test run failed",
    TS + "##[error]Process completed with exit code 100.",
]
ENOSPC_LOG = [
    TS + "   Compiling tokio v1.47.0",
    TS + "error: failed to write /home/runner/work/target/debug/deps/libtokio.rlib: No space left on device (os error 28)",
    TS + "##[error]Process completed with exit code 101.",
]


def ev(infra: set[str] | None = None, test_failure: bool = False) -> "rp.Evidence":
    return rp.Evidence(frozenset(infra or set()), test_failure)


class ScanTest(unittest.TestCase):
    def test_planted_test_failure_is_not_infra(self) -> None:
        e = rp.scan(TEST_FAIL_LOG)
        self.assertTrue(e.test_failure)
        self.assertFalse(e.infra_only)

    def test_simulated_enospc_is_infra(self) -> None:
        e = rp.scan(ENOSPC_LOG)
        self.assertEqual(e.infra, frozenset({"enospc"}))
        self.assertTrue(e.infra_only)

    def test_every_signature_family_matches_its_sample(self) -> None:
        samples = {
            "lost-runner": "The runner has received a shutdown signal. This can happen when the runner service is stopped",
            "enospc": "Error: ENOSPC: no space left on device, write",
            "cache-5xx": "Warning: Failed to save: Cache service responded with 502",
            "download-5xx": "curl: (22) The requested URL returned error: 503",
            "download-network": "curl: (6) Could not resolve host: github.com",
        }
        for sid, line in samples.items():
            with self.subTest(sid):
                self.assertIn(sid, rp.scan([TS + line]).infra)

    def test_lost_communication_annotation_is_infra(self) -> None:
        line = "The hosted runner: GitHub Actions 12 lost communication with the server."
        self.assertEqual(rp.scan([line]).infra, frozenset({"lost-runner"}))

    def test_4xx_download_is_not_infra(self) -> None:
        for line in (
            "curl: (22) The requested URL returned error: 404",
            "failed to get successful HTTP response from `https://index.crates.io/x`, got 404",
            "Unexpected HTTP response: 403",
        ):
            with self.subTest(line):
                self.assertFalse(rp.scan([line]).infra)

    def test_lint_and_compile_reds_are_not_infra(self) -> None:
        log = [
            TS + "error: this `if` has identical blocks",
            TS + "error: could not compile `ipe` (lib) due to 1 previous error",
            TS + "Diff in src/lib.rs at line 3:",
        ]
        self.assertFalse(rp.scan(log).infra)

    def test_test_marker_beside_infra_vetoes(self) -> None:
        e = rp.scan([*ENOSPC_LOG, *TEST_FAIL_LOG])
        self.assertTrue(e.infra)
        self.assertFalse(e.infra_only)

    def test_every_test_marker_vetoes(self) -> None:
        for line in (
            "     TIMEOUT [ 900.001s] ipe::server_e2e hangs",
            "     SIGSEGV [   0.4s] ipe::runtime crash",
            "   SIGABRT [   2s] x y",
            "test result: FAILED. 3 passed; 1 failed",
            "       FLAKY 2/2 [   3.1s] ipe::x y",
        ):
            with self.subTest(line):
                self.assertTrue(rp.scan([TS + line]).test_failure)

    def test_over_long_log_refused(self) -> None:
        old = rp.MAX_LOG_LINES
        rp.MAX_LOG_LINES = 3
        try:
            with self.assertRaises(rp.PolicyError):
                rp.scan(["a", "b", "c", "d"])
        finally:
            rp.MAX_LOG_LINES = old

    def test_coloured_test_failure_vetoes(self) -> None:
        # ci.yml sets CARGO_TERM_COLOR=always: nextest wraps its status words
        # in SGR codes, which must not hide the marker beside an infra line.
        for line in (
            "\x1b[31;1m        FAIL\x1b[0m [  12.881s] ipe::emit broken_case",
            "\x1b[1m\x1b[31m     TIMEOUT\x1b[0m [ 900.001s] ipe::x y",
            "\x1b[31;1merror\x1b[0m: test run failed",
            "\x1b]8;;https://x\x1b\\       FLAKY\x1b]8;;\x07 2/2 [   3.1s] ipe::x y",
        ):
            with self.subTest(line):
                e = rp.scan([*ENOSPC_LOG, TS + line])
                self.assertTrue(e.test_failure)
                self.assertFalse(e.infra_only)

    def test_control_sequence_strip_is_linear(self) -> None:
        import time

        start = time.monotonic()
        rp.scan(["\x1b]" * 2000 + "\x1b[" + "1;" * 2000] * 50)
        self.assertLess(time.monotonic() - start, 5.0)

    def test_recovered_retry_is_not_infra(self) -> None:
        # A retry cargo recovered from is not why the job failed; the later
        # lint red must stay red.
        log = [
            TS + "warning: spurious network error (2 tries remaining): [6] Could not resolve host: index.crates.io",
            TS + "Retrying in 3 seconds: curl: (56) Recv failure",
            TS + "error: this `if` has identical blocks",
        ]
        self.assertFalse(rp.scan(log).infra)
        self.assertFalse(rp.decide([rp.scan(log)]))

    def test_unrecovered_network_error_is_infra(self) -> None:
        line = TS + "  [6] Could not resolve host: index.crates.io"
        self.assertEqual(rp.scan([line]).infra, frozenset({"download-network"}))

    def test_signature_past_the_line_cap_is_ignored(self) -> None:
        line = "x" * rp.MAX_LINE_CHARS + "No space left on device"
        self.assertFalse(rp.scan([line]).infra)


class BoundedLinesTest(unittest.TestCase):
    def test_long_line_is_read_in_capped_pieces(self) -> None:
        text = "x" * (rp.MAX_LINE_CHARS * 3 + 5) + "\nshort\n"
        pieces = list(rp.bounded_lines(io.StringIO(text)))
        self.assertTrue(all(len(p) <= rp.MAX_LINE_CHARS for p in pieces))
        self.assertEqual("".join(pieces), text)

    def test_marker_past_a_long_prefix_still_vetoes(self) -> None:
        text = "y" * (rp.MAX_LINE_CHARS * 2) + " No space left on device\n        FAIL [ 1.0s] a b\n"
        self.assertTrue(rp.scan(rp.bounded_lines(io.StringIO(text))).test_failure)

    def test_over_long_log_in_characters_refused(self) -> None:
        old = rp.MAX_LOG_CHARS
        rp.MAX_LOG_CHARS = 10
        try:
            with self.assertRaises(rp.PolicyError):
                list(rp.bounded_lines(io.StringIO("abcdef\nghijkl\n")))
        finally:
            rp.MAX_LOG_CHARS = old


class DecideTest(unittest.TestCase):
    def test_all_infra_reruns(self) -> None:
        self.assertTrue(rp.decide([ev({"enospc"}), ev({"lost-runner"})]))

    def test_no_failed_job_refused(self) -> None:
        self.assertFalse(rp.decide([]))

    def test_one_non_infra_job_blocks(self) -> None:
        self.assertFalse(rp.decide([ev({"enospc"}), ev()]))

    def test_one_test_failure_blocks(self) -> None:
        self.assertFalse(rp.decide([ev({"enospc"}), ev({"enospc"}, test_failure=True)]))

    def test_unreadable_job_blocks(self) -> None:
        self.assertFalse(rp.decide([ev({"enospc"}), None]))

    def test_too_many_jobs_refused(self) -> None:
        self.assertFalse(rp.decide([ev({"enospc"})] * (rp.MAX_FAILED_JOBS + 1)))


class JobIdsTest(unittest.TestCase):
    def test_ids_parse(self) -> None:
        self.assertEqual(rp.parse_job_ids("12\n34\n"), [12, 34])
        self.assertEqual(rp.parse_job_ids(""), [])

    def test_malformed_ids_refused(self) -> None:
        for bad in ("12\nabc", "012", " 12", "12 ", "-1", "0", "1.0", "{}", "٣"):
            with self.subTest(bad), self.assertRaises(rp.PolicyError):
                rp.parse_job_ids(bad)

    def test_every_unpassed_conclusion_needs_proof(self) -> None:
        listing = "1\tsuccess\n2\tfailure\n3\ttimed_out\n4\tcancelled\n5\tskipped\n6\tnull\n7\tneutral\n8\tstartup_failure"
        self.assertEqual(rp.failed_job_ids(listing), [2, 3, 4, 6, 8])

    def test_malformed_job_listing_refused(self) -> None:
        for bad in ("12", "12\t", "x\tfailure", "12\tFailure", "12\tfailure\n12\tsuccess", "\tfailure", "12\tfail ure"):
            with self.subTest(bad), self.assertRaises(rp.PolicyError):
                rp.failed_job_ids(bad)

    def test_jobs_jq_emits_id_and_conclusion(self) -> None:
        self.assertEqual(rp.JOBS_JQ, '.jobs[] | "\\(.id)\\t\\(.conclusion)"')

    def test_repeated_id_refused(self) -> None:
        with self.assertRaises(rp.PolicyError):
            rp.parse_job_ids("7\n7")

    def test_bad_repo_or_run_refused(self) -> None:
        for repo, run in (("", "1"), ("a/b; rm", "1"), ("a/b", ""), ("a/b", "1x"), ("a/b/c", "1")):
            with self.subTest((repo, run)), self.assertRaises(rp.PolicyError):
                rp.run_decide(repo, run)

    def _decide(self, output: str | None) -> int:
        keys = ("REPO", "RUN_ID", "GITHUB_OUTPUT")
        old = {k: os.environ.pop(k, None) for k in keys}
        if output is not None:
            os.environ["GITHUB_OUTPUT"] = output
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return rp.main(["--decide"])
        finally:
            for k in keys:
                os.environ.pop(k, None)
                if old[k] is not None:
                    os.environ[k] = old[k]

    def test_decide_writes_false_without_gh_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            self.assertEqual(self._decide(out), 0)
            with open(out, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "rerun=false\n")

    def test_decide_without_output_file_is_red(self) -> None:
        self.assertEqual(self._decide(None), 1)
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self._decide(os.path.join(tmp, "no", "such")), 1)

    def test_unknown_mode_exits_nonzero(self) -> None:
        for argv in ([], ["decide"], ["lint"], ["--decide", "x"], ["-decide"], ["--decide", "--lint"], ["--proven-test-red", "x"]):
            with self.subTest(argv):
                self.assertEqual(rp.main(argv), 2)


class ProvenTestRedTest(unittest.TestCase):
    """The merge-group fail-fast watchers cancel only on a proven test red:
    a readable log showing a test that ran and failed, readable annotations,
    and no infra signature in either. Every other red is no cancel, so the
    run goes on and reports every red it reaches."""

    CLEAN_NOTES = rp.scan([TS + "Process completed with exit code 100."])

    def proven(self, log: list[str] | None, notes: list[str] | None = None) -> bool:
        return rp.proven_test_red(
            None if log is None else rp.scan(log),
            self.CLEAN_NOTES if notes is None else rp.scan(notes),
        )

    def test_test_failure_is_proven(self) -> None:
        self.assertTrue(self.proven(TEST_FAIL_LOG))
        self.assertTrue(self.proven([TS + "test result: FAILED. 3 passed; 1 failed; 0 ignored"]))
        self.assertTrue(self.proven([TS + "\x1b[31;1m        FAIL\x1b[0m [  12.881s] ipe::emit broken_case"]))

    def test_test_marker_beside_infra_signature_is_not_proven(self) -> None:
        self.assertFalse(self.proven([*ENOSPC_LOG, *TEST_FAIL_LOG]))
        self.assertFalse(self.proven(TEST_FAIL_LOG, ["The runner has received a shutdown signal"]))

    def test_infra_only_red_is_not_proven(self) -> None:
        self.assertFalse(self.proven(ENOSPC_LOG))

    def test_unknown_red_is_not_proven(self) -> None:
        for log in (
            [TS + "error: could not compile `ipe` (lib) due to 2 previous errors"],
            [TS + "error: test run failed"],
            [TS + "##[error]Process completed with exit code 1."],
        ):
            with self.subTest(log):
                self.assertFalse(self.proven(log))

    def test_crash_is_not_proven(self) -> None:
        for line in (
            "     TIMEOUT [ 900.001s] ipe::server_e2e hangs",
            "     SIGSEGV [   0.4s] ipe::runtime crash",
            "     SIGKILL [  30.0s] ipe::x oom",
            "     SIGABRT [   2s] x y",
            "       ABORT [   2s] x y",
            "   LEAK-FAIL [   1.0s] ipe::x leaks",
        ):
            with self.subTest(line):
                self.assertFalse(self.proven([TS + line, TS + "error: test run failed"]))

    def test_empty_or_garbled_log_is_not_proven(self) -> None:
        for log in ([], [""], ["\ufffd\ufffd\x00\x07FA\ufffdIL [ 1s]"], [TS + "FAIL[1s] x", TS + "FAIL [ s] x"]):
            with self.subTest(log):
                self.assertFalse(self.proven(log))

    def test_unreadable_source_is_not_proven(self) -> None:
        self.assertFalse(rp.proven_test_red(None, self.CLEAN_NOTES))
        self.assertFalse(rp.proven_test_red(rp.scan(TEST_FAIL_LOG), None))

    def test_marker_tables_pass_and_each_proof_is_a_veto(self) -> None:
        self.assertEqual(rp.proven_marker_errors(rp.PROVEN_TEST_RED_MARKERS, rp.TEST_FAILURE_MARKERS), [])

    def test_fail_open_proven_tables_refused(self) -> None:
        for table, want in (
            ((), "is empty"),
            (((r"error", "error: x"),), "generic text"),
            (((r"SIGSEGV \[", "  SIGSEGV [ 1s] x"),), "crash or generic"),
            (((r"FAIL \[.*\]", "FAIL [ 1s] x"),), "wildcard"),
            (((r"PROVEN-ONLY", "PROVEN-ONLY"),), "matches no veto marker"),
            (((r"test result: FAILED\.", "nope"),), "does not match its sample"),
            (((r"(", "x"),), "does not compile"),
            (((r"test result: FAILED\.", "test result: FAILED."),) * 2, "repeats"),
        ):
            with self.subTest(table):
                errors = rp.proven_marker_errors(table, rp.TEST_FAILURE_MARKERS)
                self.assertTrue(any(want in e for e in errors), errors)


class CancelDecisionTest(unittest.TestCase):
    PROVEN = (rp.scan(TEST_FAIL_LOG), rp.scan([]))
    INFRA = (rp.scan(ENOSPC_LOG), rp.scan([]))
    UNREAD = (None, None)

    def decide(self, failed: list[tuple[int, str]], producer: str, by_id: dict) -> bool:
        return rp.decide_cancel(failed, producer, lambda j: by_id[j])

    def test_proven_leg_of_the_producer_cancels(self) -> None:
        self.assertTrue(self.decide([(1, "test-run (2)")], "test-run", {1: self.PROVEN}))
        self.assertTrue(self.decide([(1, "seal-modset (vendored emit model)")], "seal-modset (vendored emit model)", {1: self.PROVEN}))

    def test_one_proven_leg_beside_unproven_legs_cancels(self) -> None:
        failed = [(1, "e2e (1)"), (2, "e2e (2)"), (3, "e2e (3)")]
        self.assertTrue(self.decide(failed, "e2e", {1: self.UNREAD, 2: self.INFRA, 3: self.PROVEN}))

    def test_infra_only_or_unreadable_legs_never_cancel(self) -> None:
        failed = [(1, "e2e (1)"), (2, "e2e (2)")]
        self.assertFalse(self.decide(failed, "e2e", {1: self.UNREAD, 2: self.INFRA}))

    def test_another_jobs_test_red_never_cancels(self) -> None:
        for name in ("e2e-all", "test-run (1)", "e2e (1", "xe2e (1)", "e2e(1)"):
            with self.subTest(name):
                self.assertFalse(self.decide([(1, name)], "e2e", {1: self.PROVEN}))

    def test_another_jobs_test_red_beside_an_unproven_leg_never_cancels(self) -> None:
        failed = [(1, "e2e-all"), (2, "e2e (1)")]
        self.assertFalse(self.decide(failed, "e2e", {1: self.PROVEN, 2: self.INFRA}))

    def test_leg_rule(self) -> None:
        self.assertTrue(rp.is_leg_of("e2e", "e2e"))
        self.assertTrue(rp.is_leg_of("e2e (14)", "e2e"))
        for name in ("e2e-all", "e2e (1", "e2e(1)", "xe2e (1)", "e2e  (1)x", ""):
            with self.subTest(name):
                self.assertFalse(rp.is_leg_of(name, "e2e"))

    def test_no_failed_leg_or_too_many_never_cancel(self) -> None:
        self.assertFalse(self.decide([], "e2e", {}))
        many = [(i, f"e2e ({i})") for i in range(1, rp.MAX_FAILED_JOBS + 2)]
        self.assertFalse(self.decide(many, "e2e", {i: self.PROVEN for i, _ in many}))

    def test_named_listing_parses_and_refuses(self) -> None:
        listing = "1\tsuccess\tfmt\n2\tfailure\te2e (1)\n3\tskipped\te2e (2)\n4\tcancelled\te2e (3)"
        self.assertEqual(rp.failed_jobs_named(listing), [(2, "e2e (1)"), (4, "e2e (3)")])
        self.assertEqual(rp.failed_jobs_named("5\tfailure\ta\tb"), [(5, "a\tb")])
        for bad in ("12\tfailure", "12\tfailure\t", "x\tfailure\ta", "12\tFailure\ta", "12\tfailure\ta\n12\tsuccess\tb", "\tfailure\ta"):
            with self.subTest(bad), self.assertRaises(rp.PolicyError):
                rp.failed_jobs_named(bad)

    def test_job_rows_jq_reads_every_job_unfiltered(self) -> None:
        self.assertEqual(rp.JOB_ROWS_JQ, '.jobs[] | "\\(.id)\\t\\(.conclusion)\\t\\(.name)"')
        self.assertNotIn("select", rp.JOB_ROWS_JQ)

    def test_bad_inputs_refused(self) -> None:
        for args in (
            ("", "1", "1", "e2e"),
            ("a/b; rm", "1", "1", "e2e"),
            ("a/b", "1x", "1", "e2e"),
            ("a/b", "1", "", "e2e"),
            ("a/b", "1", "1", ""),
            ("a/b", "1", "1", " e2e"),
            ("a/b", "1", "1", "${{ x }}"),
            ("a/b", "1", "1", "e2e\nx"),
        ):
            with self.subTest(args), self.assertRaises(rp.PolicyError):
                rp.run_cancel_decision(*args)

    def _run(self, output: str | None, env: dict[str, str] | None = None) -> int:
        keys = ("REPO", "RUN_ID", "RUN_ATTEMPT", "PRODUCER", "GITHUB_OUTPUT")
        old = {k: os.environ.pop(k, None) for k in keys}
        os.environ.update(env or {})
        if output is not None:
            os.environ["GITHUB_OUTPUT"] = output
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return rp.main(["--proven-test-red"])
        finally:
            for k in keys:
                os.environ.pop(k, None)
                if old[k] is not None:
                    os.environ[k] = old[k]

    def test_unprovable_run_writes_false(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            self.assertEqual(self._run(out), 0)
            with open(out, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "cancel=false\n")

    def test_unreadable_listing_writes_false(self) -> None:
        def refuse(_args: list[str]) -> str:
            raise rp.PolicyError("`gh api` exited 1")

        old = rp._gh_text
        rp._gh_text = refuse
        try:
            with tempfile.TemporaryDirectory() as tmp:
                out = os.path.join(tmp, "out")
                env = {"REPO": "a/b", "RUN_ID": "1", "RUN_ATTEMPT": "1", "PRODUCER": "e2e"}
                self.assertEqual(self._run(out, env), 0)
                with open(out, encoding="utf-8") as fh:
                    self.assertEqual(fh.read(), "cancel=false\n")
        finally:
            rp._gh_text = old

    def test_listing_reads_the_attempt_unfiltered(self) -> None:
        seen: list[list[str]] = []

        def listing(args: list[str]) -> str:
            seen.append(args)
            return "9\tfailure\te2e (3)\n"

        old_text, old_sources = rp._gh_text, rp._job_sources
        rp._gh_text = listing
        rp._job_sources = lambda _repo, _j: self.PROVEN
        try:
            self.assertTrue(rp.run_cancel_decision("a/b", "5", "2", "e2e"))
        finally:
            rp._gh_text, rp._job_sources = old_text, old_sources
        self.assertEqual(seen, [["repos/a/b/actions/runs/5/attempts/2/jobs", "--paginate", "--jq", rp.JOB_ROWS_JQ]])

    def test_without_output_file_is_red(self) -> None:
        self.assertEqual(self._run(None), 1)


class SignatureTableTest(unittest.TestCase):
    def test_repo_tables_pass(self) -> None:
        self.assertEqual(rp.signature_errors(rp.SIGNATURES, rp.TEST_FAILURE_MARKERS), [])

    def test_match_everything_signature_refused(self) -> None:
        for pat in (".*", "error", r"\s*", "FAIL"):
            with self.subTest(pat):
                errs = rp.signature_errors((("x", pat),), rp.TEST_FAILURE_MARKERS)
                self.assertTrue(any("generic" in e for e in errs), errs)

    def test_bad_patterns_refused(self) -> None:
        for pat in ("", " ENOSPC", "(", "a.*b.*c"):
            with self.subTest(pat):
                self.assertTrue(rp.signature_errors((("x", pat),), rp.TEST_FAILURE_MARKERS))

    def test_empty_or_repeated_tables_refused(self) -> None:
        self.assertTrue(rp.signature_errors((), rp.TEST_FAILURE_MARKERS))
        self.assertTrue(rp.signature_errors(rp.SIGNATURES, ()))
        self.assertTrue(rp.signature_errors((("a", "ENOSPC"), ("b", "ENOSPC")), rp.TEST_FAILURE_MARKERS))

    def test_bad_id_refused(self) -> None:
        for sid in ("", "Bad", "a_b", "-a"):
            with self.subTest(sid):
                self.assertTrue(rp.signature_errors(((sid, "ENOSPC"),), rp.TEST_FAILURE_MARKERS))


def _tree(nextest: str | None, workflows: dict[str, str]) -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory()
    root = tmp.name
    os.makedirs(os.path.join(root, ".config"))
    os.makedirs(os.path.join(root, ".github", "workflows"))
    os.makedirs(os.path.join(root, ".github", "actions", "x"))
    if nextest is not None:
        with open(os.path.join(root, ".config", "nextest.toml"), "w", encoding="utf-8") as fh:
            fh.write(nextest)
    for rel, body in workflows.items():
        with open(os.path.join(root, ".github", rel), "w", encoding="utf-8") as fh:
            fh.write(body)
    return tmp


class RetryBanTest(unittest.TestCase):
    def test_repo_has_no_retry(self) -> None:
        self.assertEqual(rp.retry_errors(), [])

    def test_clean_tree_passes(self) -> None:
        with _tree("# retries are banned\n[profile.ci]\nfail-fast = false\n", {"workflows/a.yml": "x: 1\n"}) as root:
            self.assertEqual(rp.retry_errors(root), [])

    def test_nextest_retries_refused(self) -> None:
        for body in ("retries = 1\n", "[profile.ci]\n  retries = { backoff = 'fixed', count = 2 }\n",
                     "[[profile.ci.overrides]]\nfilter = 'all()'\nretries = 1 # one\n"):
            with self.subTest(body), _tree(body, {}) as root:
                self.assertTrue(any("retries" in e for e in rp.retry_errors(root)))

    def test_quoted_or_hidden_nextest_retries_refused(self) -> None:
        for body in ('"retries" = 1\n', "[profile.ci]\n'retries'=2\n", "profile.ci.retries = 1\n",
                     'x = { filter = "#", retries = 1 }\n'):
            with self.subTest(body), _tree(body, {}) as root:
                self.assertTrue(any("retries" in e for e in rp.retry_errors(root)))

    def test_workflow_retry_after_hash_refused(self) -> None:
        with _tree("", {"workflows/a.yml": 'run: echo "#" && cargo nextest run --retries 2\n'}) as root:
            self.assertTrue(any("retry" in e for e in rp.retry_errors(root)))

    def test_workflow_and_action_retries_refused(self) -> None:
        for rel, body in (
            ("workflows/a.yml", "run: cargo nextest run --retries 2\n"),
            ("workflows/b.yaml", "env:\n  NEXTEST_RETRIES: 1\n"),
            ("actions/x/action.yml", "run: cargo nextest run --flaky-result pass\n"),
        ):
            with self.subTest(rel), _tree("", {rel: body}) as root:
                self.assertTrue(any("retry" in e for e in rp.retry_errors(root)))

    def test_missing_nextest_config_refused(self) -> None:
        with _tree(None, {}) as root:
            self.assertTrue(any("unreadable" in e for e in rp.retry_errors(root)))


GATE = {"id": "gate", "env": dict(rp.DECIDE_ENV), "run": rp.DECIDE_INVOCATION}
RERUN = {"if": "${{ steps.gate.outputs.rerun == 'true' }}", "run": 'gh run rerun --failed "$RUN_ID"'}
WORKFLOW = {"jobs": {"rerun": {"steps": [{"uses": "actions/checkout@v7"}, GATE, RERUN]}}}


class WiringTest(unittest.TestCase):
    def test_wired_workflow_passes(self) -> None:
        self.assertEqual(rp.wiring_errors(WORKFLOW), [])

    def test_repo_workflow_passes(self) -> None:
        self.assertEqual(rp.lint(), 0)

    def test_fail_open_rerun_if_refused(self) -> None:
        for cond in (
            None,
            "${{ !cancelled() && steps.gate.outputs.rerun != 'false' }}",
            "always()",
            "${{ steps.gate.outputs.rerun == 'true' }} && x",
            "steps.gate.outputs.rerun == 'true' || true",
        ):
            with self.subTest(cond):
                wf = copy.deepcopy(WORKFLOW)
                step = wf["jobs"]["rerun"]["steps"][2]
                if cond is None:
                    del step["if"]
                else:
                    step["if"] = cond
                self.assertTrue(rp.wiring_errors(wf))

    def test_missing_or_duplicate_decide_refused(self) -> None:
        wf = copy.deepcopy(WORKFLOW)
        wf["jobs"]["rerun"]["steps"].pop(1)
        self.assertTrue(rp.wiring_errors(wf))
        wf = copy.deepcopy(WORKFLOW)
        wf["jobs"]["rerun"]["steps"].insert(1, dict(GATE, id="other"))
        self.assertTrue(rp.wiring_errors(wf))

    def test_decide_without_gate_id_refused(self) -> None:
        wf = copy.deepcopy(WORKFLOW)
        wf["jobs"]["rerun"]["steps"][1]["id"] = "verdict"
        self.assertTrue(rp.wiring_errors(wf))

    def test_decide_run_or_env_tampering_refused(self) -> None:
        for run in (
            f"{rp.DECIDE_INVOCATION} || true",
            f"echo rerun=true >> $GITHUB_OUTPUT; {rp.DECIDE_INVOCATION}",
            f"{rp.DECIDE_INVOCATION} --lint",
        ):
            with self.subTest(run):
                wf = copy.deepcopy(WORKFLOW)
                wf["jobs"]["rerun"]["steps"][1]["run"] = run
                self.assertTrue(rp.wiring_errors(wf))
        for key, val in (("RUN_ID", "1"), ("REPO", "evil/repo"), ("GITHUB_OUTPUT", "/dev/null")):
            with self.subTest(key):
                wf = copy.deepcopy(WORKFLOW)
                wf["jobs"]["rerun"]["steps"][1]["env"][key] = val
                self.assertTrue(rp.wiring_errors(wf))
        wf = copy.deepcopy(WORKFLOW)
        del wf["jobs"]["rerun"]["steps"][1]["env"]
        self.assertTrue(rp.wiring_errors(wf))

    def test_decide_step_if_refused(self) -> None:
        wf = copy.deepcopy(WORKFLOW)
        wf["jobs"]["rerun"]["steps"][1]["if"] = "false"
        self.assertTrue(rp.wiring_errors(wf))

    def test_continue_on_error_refused(self) -> None:
        for idx in (1, 2):
            with self.subTest(idx):
                wf = copy.deepcopy(WORKFLOW)
                wf["jobs"]["rerun"]["steps"][idx]["continue-on-error"] = True
                self.assertTrue(rp.wiring_errors(wf))

    def test_second_rerun_step_refused(self) -> None:
        wf = copy.deepcopy(WORKFLOW)
        wf["jobs"]["other"] = {"steps": [{"run": "gh run rerun 1"}]}
        self.assertTrue(rp.wiring_errors(wf))

    def test_no_jobs_refused(self) -> None:
        self.assertTrue(rp.wiring_errors({}))
        self.assertTrue(rp.wiring_errors({"jobs": {"a": {}}}))


if __name__ == "__main__":
    unittest.main()
