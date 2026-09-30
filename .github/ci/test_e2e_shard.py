#!/usr/bin/env python3
"""Refusal proofs for `e2e_shard.py` (the e2e SEAL shard-partition SSOT), its
weight refresher `e2e_shard_weights.py`, and `tools/scripts/e2e-shard-cover.py`
(its per-run partition proof).

Every way the plan must refuse (a bad shard index, a malformed or mis-sized
weight table, a bucket set that is empty or out of range), every way the
partition proof must refuse (a test no shard runs, a test two shards run, a
shard selecting no test, a shard selecting outside the archive, an empty
archive, a missing shard, a malformed listing or plan) and every way the ci.yml wiring check must
refuse (a dropped or extra shard, a bypassing `nextest run`, a shard or cover
reading its selection off the plan, a masked plan step) gets its own test, per
PRINCIPLES.md "Prove the refusals". Pure stdlib `unittest`.
"""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import os
import random
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))


def _load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


es = _load("e2e_shard", os.path.join(HERE, "e2e_shard.py"))
ec = _load("e2e_shard_cover", os.path.join(REPO, "tools", "scripts", "e2e-shard-cover.py"))
ew = _load("e2e_shard_weights", os.path.join(HERE, "e2e_shard_weights.py"))

ZERO = {cls: [0] * es.MODULUS for cls in es.CLASSES}


def _bucket_set(filt: str) -> tuple[str, set[int]]:
    """Split a shard filter into its class filter and the buckets its regex names."""
    m = re.fullmatch(r"\((.*)\) & test\(/\^\(\?:\.\{(\d+)\}\)\*\(\?:(.*)\)\$/\)", filt)
    assert m is not None, filt
    assert int(m[2]) == es.MODULUS
    return m[1], {int(a[2:-1]) for a in m[3].split("|")}


def _listing(cases: dict[str, dict[str, str]]) -> str:
    """Build a nextest JSON listing: {binary: {test: status}}."""
    return json.dumps(
        {
            "rust-suites": {
                binary: {"testcases": {name: {"filter-match": {"status": status}} for name, status in tests.items()}}
                for binary, tests in cases.items()
            }
        }
    )


FULL = [f"bin t{i}" for i in range(20)]


def _exact_partition() -> dict[int, list[str]]:
    shards: dict[int, list[str]] = {k: [] for k in range(1, es.SHARDS + 1)}
    for i, test in enumerate(FULL):
        shards[i % es.SHARDS + 1].append(test)
    return shards


class SelectionTest(unittest.TestCase):
    def test_every_shard_selects_its_class_and_a_bucket_regex(self) -> None:
        for k in range(1, es.SHARDS + 1):
            with self.subTest(k):
                args = es.selection(k)
                self.assertEqual(args[0], "-E")
                cls, buckets = _bucket_set(args[1])
                self.assertEqual(cls, es.HEAVY if k <= es.HEAVY_SHARDS else f"not ({es.HEAVY})")
                self.assertTrue(buckets)

    def test_out_of_range_shard_refused(self) -> None:
        for bad in (0, -1, es.SHARDS + 1):
            with self.assertRaises(es.ShardError):
                es.selection(bad)

    def test_non_int_shard_refused(self) -> None:
        for bad in (True, 1.0, "1", None):
            with self.assertRaises(es.ShardError):
                es.selection(bad)  # type: ignore[arg-type]

    def test_unknown_mode_exits_nonzero(self) -> None:
        for argv in ([], ["run", "1"], ["plan"], ["lint"], ["matrix"], ["cover"], ["--plan", "x"], ["--plan", "--lint"]):
            with self.subTest(argv):
                self.assertEqual(es.main(argv), 2)

    def test_heavy_class_is_the_heavy_binaries(self) -> None:
        self.assertEqual(es.HEAVY, " | ".join(f"binary({b})" for b in es.HEAVY_BINARIES))
        self.assertEqual(len(set(es.HEAVY_BINARIES)), len(es.HEAVY_BINARIES))


class BucketTest(unittest.TestCase):
    NAMES = ["", "a", "t_1", "x" * (es.MODULUS - 1), "x" * es.MODULUS, "x" * (3 * es.MODULUS + 5), "ünïcødé::名前"]

    def test_regex_selects_exactly_its_buckets(self) -> None:
        rng = random.Random(0)
        names = self.NAMES + ["".join(rng.choice("ab_:") for _ in range(rng.randrange(300))) for _ in range(500)]
        for buckets in ([0], [es.MODULUS - 1], [1, 7, 30], list(range(es.MODULUS))):
            rx = re.compile(es.bucket_regex(buckets))
            for name in names:
                self.assertEqual(bool(rx.search(name)), es.bucket(name) in buckets, (buckets, name))

    def test_empty_or_out_of_range_buckets_refused(self) -> None:
        for bad in ([], [-1], [es.MODULUS], [True], ["1"], [1.0]):
            with self.subTest(bad), self.assertRaises(es.ShardError):
                es.bucket_regex(bad)  # type: ignore[arg-type]


class AssignTest(unittest.TestCase):
    def test_lpt_balances_and_keeps_every_bucket_once(self) -> None:
        weights = [0] * es.MODULUS
        weights[:4] = [10, 10, 5, 5]
        got = es.assign(weights, 2)
        self.assertEqual(sorted(b for o in got for b in o), list(range(es.MODULUS)))
        self.assertEqual([sum(weights[b] for b in o) for o in got], [15, 15])

    def test_no_shard_is_empty_even_with_zero_or_skewed_weights(self) -> None:
        skewed = [0] * es.MODULUS
        skewed[0] = 10**6
        for weights in ([0] * es.MODULUS, skewed):
            for bins in (1, es.HEAVY_SHARDS, es.LIGHT_SHARDS, es.MODULUS):
                with self.subTest(bins=bins):
                    got = es.assign(weights, bins)
                    self.assertEqual(len(got), bins)
                    self.assertTrue(all(got))

    def test_more_shards_than_buckets_refused(self) -> None:
        for bins in (0, es.MODULUS + 1):
            with self.subTest(bins), self.assertRaises(es.ShardError):
                es.assign([0] * es.MODULUS, bins)

    def test_assignment_is_deterministic(self) -> None:
        self.assertEqual(es.plan(), es.plan())


class PlanTest(unittest.TestCase):
    def _assert_classes_tiled(self, plan: dict[str, dict[str, str]]) -> None:
        self.assertEqual(sorted(plan, key=int), [str(k) for k in range(1, es.SHARDS + 1)])
        for cls_filter, first, count in es.CLASSES.values():
            seen: list[int] = []
            for k in range(first, first + count):
                got_cls, buckets = _bucket_set(plan[str(k)]["filter"])
                self.assertEqual(got_cls, cls_filter)
                self.assertTrue(buckets, f"shard {k} owns no bucket")
                seen += buckets
            self.assertEqual(sorted(seen), list(range(es.MODULUS)), "buckets not total and disjoint")

    def test_checked_in_plan_tiles_every_class(self) -> None:
        self._assert_classes_tiled(es.plan())

    def test_any_weight_table_tiles_every_class(self) -> None:
        rng = random.Random(1)
        for _ in range(50):
            table = {cls: [rng.choice((0, 0, 1, 7, 300)) for _ in range(es.MODULUS)] for cls in es.CLASSES}
            self._assert_classes_tiled(es.plan(table))
        self._assert_classes_tiled(es.plan(ZERO))

    def test_plan_is_every_selection(self) -> None:
        plan = es.plan()
        for k in range(1, es.SHARDS + 1):
            self.assertEqual(["-E", plan[str(k)]["filter"]], es.selection(k))

    def test_cover_parses_the_published_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(es.write_plan(out), 0)
            with open(out, encoding="utf-8") as fh:
                key, sep, value = fh.read().rstrip("\n").partition("=")
        self.assertEqual((key, sep), ("plan", "="))
        self.assertNotIn("\n", value)
        self.assertLess(len(value), ec.MAX_PLAN_CHARS)
        parsed = ec.parse_plan(value)
        self.assertEqual({k: ["-E", f] for k, f in parsed.items()}, {k: es.selection(k) for k in range(1, es.SHARDS + 1)})

    def test_plan_without_output_file_is_red(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(es.write_plan(""), 1)
            with tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(es.write_plan(os.path.join(tmp, "no", "such")), 1)


class WeightsTest(unittest.TestCase):
    def test_checked_in_table_parses(self) -> None:
        self.assertEqual(set(es.load_weights()), set(es.CLASSES))

    def test_malformed_table_refused(self) -> None:
        row = [0] * es.MODULUS
        for doc in (
            None,
            [],
            {},
            {"heavy": row},
            {"heavy": row, "light": row, "extra": row},
            {"heavy": row, "light": row[:-1]},
            {"heavy": row, "light": [*row, 0]},
            {"heavy": row, "light": "0"},
            {"heavy": row, "light": [-1, *row[1:]]},
            {"heavy": row, "light": [True, *row[1:]]},
            {"heavy": row, "light": [0.5, *row[1:]]},
            {"heavy": row, "light": [None, *row[1:]]},
        ):
            with self.subTest(doc), self.assertRaises(es.ShardError):
                es.parse_weights(doc)
            if doc is not None:
                with self.subTest(doc), self.assertRaises(es.ShardError):
                    es.plan(doc)  # type: ignore[arg-type]

    def test_unreadable_table_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "w.json")
            with self.assertRaises(es.ShardError):
                es.load_weights(bad)
            with open(bad, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            with self.assertRaises(es.ShardError):
                es.load_weights(bad)

    def test_bad_table_makes_plan_and_lint_red(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "w.json")
            with open(bad, "w", encoding="utf-8") as fh:
                json.dump({"heavy": []}, fh)
            old = es.WEIGHTS_FILE
            es.WEIGHTS_FILE = bad
            try:
                with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(es.write_plan(os.path.join(tmp, "out")), 1)
                    self.assertEqual(es.lint(), 1)
            finally:
                es.WEIGHTS_FILE = old


class RefreshTest(unittest.TestCase):
    LOG = (
        "2026-01-01T00:00:00Z \x1b[32;1m        PASS\x1b[0m [  12.500s] (  1/9) ipe::stdlib_coverage_dynamic big_one\n"
        "e2e (7)\tRun\t2026-01-01T00:00:01Z         FAIL [   3.000s] (  2/9) ipe::g_db some::test\r\n"
        "        PASS [   5.000s] (  3/9) ipe::g_db some::test\n"
        "        SLOW [> 60.000s] ipe::g_db other\n"
        "noise line\n"
    )

    def test_result_lines_are_timed_and_classed(self) -> None:
        t = ew.timings(self.LOG)
        self.assertEqual(dict(t), {("ipe::stdlib_coverage_dynamic", "big_one"): [12.5], ("ipe::g_db", "some::test"): [3.0, 5.0]})
        w = ew.weights(t)
        self.assertEqual(w["heavy"][es.bucket("big_one")], 12)
        self.assertEqual(w["light"][es.bucket("some::test")], 4)
        self.assertEqual(sum(w["heavy"]) + sum(w["light"]), 16)
        self.assertTrue(ew.is_heavy("ipe::verify"))
        self.assertFalse(ew.is_heavy("ipe::verify_extra"))
        self.assertFalse(ew.is_heavy("ipe"))

    def test_logs_timing_nothing_refused(self) -> None:
        with self.assertRaises(es.ShardError):
            ew.weights(ew.timings("no results here\n"))
        with tempfile.TemporaryDirectory() as tmp:
            empty = os.path.join(tmp, "e.log")
            open(empty, "w", encoding="utf-8").close()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(ew.main([empty]), 1)
                self.assertEqual(ew.main([os.path.join(tmp, "missing.log")]), 1)

    def test_bad_args_refused(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            for argv in ([], ["--modulus", "8"], ["-"]):
                with self.subTest(argv):
                    self.assertEqual(ew.main(argv), 2)


class PlanParseTest(unittest.TestCase):
    GOOD = {"1": {"filter": "all()"}, "2": {"filter": "none()"}}

    def test_good_plan_parses(self) -> None:
        self.assertEqual(ec.parse_plan(json.dumps(self.GOOD)), {1: "all()", 2: "none()"})

    def test_malformed_plan_refused(self) -> None:
        entry = {"filter": "all()"}
        for text in (
            "",
            "not json",
            "[]",
            "{}",
            json.dumps({"0": entry}),
            json.dumps({"2": entry}),
            json.dumps({"01": entry}),
            json.dumps({"1": entry, "3": entry}),
            json.dumps({"1": entry, "1 ": entry}),
            json.dumps({"1": {}}),
            json.dumps({"1": dict(entry, partition="count:1/1")}),
            json.dumps({"1": {"filter": ""}}),
            json.dumps({"1": {"filter": " "}}),
            json.dumps({"1": {"filter": 1}}),
            json.dumps({"1": "all()"}),
            json.dumps({str(k): entry for k in range(1, ec.MAX_SHARDS + 2)}),
            " " * (ec.MAX_PLAN_CHARS + 1),
        ):
            with self.subTest(text[:60]), self.assertRaises(ec.CoverError):
                ec.parse_plan(text)

    def test_cover_main_refuses_args_and_bad_plan(self) -> None:
        self.assertEqual(ec.main(["x"]), 2)
        old = os.environ.pop("E2E_PLAN", None)
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(ec.main([]), 1)
        finally:
            if old is not None:
                os.environ["E2E_PLAN"] = old


class ListingTest(unittest.TestCase):
    def test_only_matching_tests_are_selected(self) -> None:
        got = ec.matched_tests(_listing({"a": {"x": "matches", "y": "mismatch"}, "b": {"z": "matches"}}))
        self.assertEqual(got, ["a x", "b z"])

    def test_non_json_refused(self) -> None:
        with self.assertRaises(ec.CoverError):
            ec.matched_tests("not json")

    def test_missing_suites_refused(self) -> None:
        for doc in ("{}", "[]", '{"rust-suites": []}'):
            with self.assertRaises(ec.CoverError):
                ec.matched_tests(doc)

    def test_missing_testcases_refused(self) -> None:
        with self.assertRaises(ec.CoverError):
            ec.matched_tests(json.dumps({"rust-suites": {"a": {}}}))

    def test_unknown_status_refused(self) -> None:
        for status in ("", "match", None):
            doc = json.dumps({"rust-suites": {"a": {"testcases": {"x": {"filter-match": {"status": status}}}}}})
            with self.assertRaises(ec.CoverError):
                ec.matched_tests(doc)

    def test_missing_filter_match_refused(self) -> None:
        doc = json.dumps({"rust-suites": {"a": {"testcases": {"x": {}}}}})
        with self.assertRaises(ec.CoverError):
            ec.matched_tests(doc)


class PartitionTest(unittest.TestCase):
    def test_exact_partition_passes(self) -> None:
        self.assertEqual(ec.partition_errors(FULL, _exact_partition(), es.SHARDS), [])

    def test_test_no_shard_runs_refused(self) -> None:
        shards = _exact_partition()
        shards[1].remove(FULL[0])
        self.assertTrue(any("no shard runs" in e for e in ec.partition_errors(FULL, shards, es.SHARDS)))

    def test_test_two_shards_run_refused(self) -> None:
        shards = _exact_partition()
        shards[2].append(FULL[0])
        self.assertTrue(any("runs in 2 shards" in e for e in ec.partition_errors(FULL, shards, es.SHARDS)))

    def test_selection_outside_archive_refused(self) -> None:
        shards = _exact_partition()
        shards[3].append("bin ghost")
        self.assertTrue(any("does not list" in e for e in ec.partition_errors(FULL, shards, es.SHARDS)))

    def test_shard_selecting_nothing_refused(self) -> None:
        shards = _exact_partition()
        shards[2] = []
        shards[1] += [f"bin t{i}" for i in (1, 15)]
        errors = ec.partition_errors(FULL, shards, es.SHARDS)
        self.assertIn("shard 2 selects no test", errors)

    def test_partition_from_real_names_passes_and_rejects_perturbation(self) -> None:
        rng = random.Random(2)
        heavy = set(es.HEAVY_BINARIES)
        full = [
            f"ipe::{rng.choice([*heavy, 'g_db', 'g_misc'])} m::t{'_' * rng.randrange(3 * es.MODULUS)}{i}"
            for i in range(3000)
        ]
        full = sorted(set(full))
        plan = es.plan()
        shards: dict[int, list[str]] = {}
        for k in range(1, es.SHARDS + 1):
            cls, buckets = _bucket_set(plan[str(k)]["filter"])
            want_heavy = cls == es.HEAVY
            shards[k] = [t for t in full if ew.is_heavy(t.split(" ")[0]) == want_heavy and es.bucket(t.split(" ", 1)[1]) in buckets]
        self.assertEqual(ec.partition_errors(full, shards, es.SHARDS), [])
        shards[1].append(shards[2][0])
        self.assertTrue(any("runs in 2 shards" in e for e in ec.partition_errors(full, shards, es.SHARDS)))

    def test_empty_archive_refused(self) -> None:
        shards: dict[int, list[str]] = {k: [] for k in range(1, es.SHARDS + 1)}
        self.assertTrue(any("empty set" in e for e in ec.partition_errors([], shards, es.SHARDS)))

    def test_missing_shard_refused(self) -> None:
        shards = _exact_partition()
        del shards[es.SHARDS]
        self.assertTrue(any("expected 1.." in e for e in ec.partition_errors(FULL, shards, es.SHARDS)))

    def test_repeated_archive_id_refused(self) -> None:
        self.assertTrue(any("repeats" in e for e in ec.partition_errors([*FULL, FULL[0]], _exact_partition(), es.SHARDS)))


PLAN_STEP = {"name": "plan", "id": es.PLAN_STEP_ID, "run": es.PLAN_INVOCATION}
SHARD_STEP = {"name": "shard", "env": {"IPE_E2E": "1", **es.SHARD_ENV}, "run": es.RUN_COMMAND}
COVER_STEP = {"name": "cover", "if": "needs.test-prep.result == 'success'", "env": dict(es.COVER_ENV), "run": es.COVER_INVOCATION}
WORKFLOW = {
    "jobs": {
        "changes": {
            "outputs": {es.PLAN_OUTPUT: es.PLAN_OUTPUT_VALUE},
            "steps": [{"uses": "actions/checkout@v7"}, PLAN_STEP],
        },
        "e2e": {
            "needs": ["changes", "test-prep"],
            "strategy": {"fail-fast": False, "matrix": {"shard": list(range(1, es.SHARDS + 1))}},
            "steps": [{"uses": "actions/checkout@v7"}, SHARD_STEP],
        },
        "seal-slice": {"needs": ["changes", "e2e"], "steps": [{"run": "gate"}, COVER_STEP]},
    }
}


def _refused(mutate, needle: str = "") -> bool:
    wf = copy.deepcopy(WORKFLOW)
    mutate(wf["jobs"])
    errors = es.wiring_errors(wf)
    return bool(errors) and any(needle in e for e in errors)


class WiringTest(unittest.TestCase):
    def test_ssot_wiring_passes(self) -> None:
        self.assertEqual(es.wiring_errors(WORKFLOW), [])

    def test_repo_ci_yml_passes(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(es.lint(), 0)

    def test_run_command_is_built_from_the_ssot_args(self) -> None:
        self.assertEqual(
            es.RUN_COMMAND,
            "cargo nextest run --archive-file nextest.tar.zst --workspace-remap . --profile ci"
            ' --no-fail-fast --test-threads=2 --no-tests=fail -E "$SHARD_FILTER"',
        )

    def test_missing_jobs_refused(self) -> None:
        self.assertTrue(es.wiring_errors({}))
        for job in ("changes", "e2e", "seal-slice"):
            with self.subTest(job):
                self.assertTrue(_refused(lambda j, job=job: j.pop(job), f"no `{job}` job"))

    def test_dropped_extra_or_string_shard_refused(self) -> None:
        self.assertTrue(_refused(lambda j: j["e2e"]["strategy"]["matrix"]["shard"].pop(), "expected 1.."))
        self.assertTrue(_refused(lambda j: j["e2e"]["strategy"]["matrix"]["shard"].append(es.SHARDS + 1), "expected 1.."))
        self.assertTrue(_refused(lambda j: j["e2e"]["strategy"]["matrix"].update(shard=[str(k) for k in range(1, es.SHARDS + 1)])))

    def test_extra_matrix_key_refused(self) -> None:
        self.assertTrue(_refused(lambda j: j["e2e"]["strategy"]["matrix"].update(include=[{"shard": 99}]), "exactly one key"))

    def test_missing_or_duplicate_shard_run_refused(self) -> None:
        self.assertTrue(_refused(lambda j: j["e2e"].update(steps=[{"run": "echo hi"}]), "exactly one step"))
        self.assertTrue(_refused(lambda j: j["e2e"]["steps"].append(dict(SHARD_STEP)), "exactly one step"))

    def test_second_nextest_run_refused(self) -> None:
        self.assertTrue(_refused(lambda j: j["e2e"]["steps"].append({"run": "cargo nextest run --archive-file nextest.tar.zst"}), "exactly one step"))

    def test_masked_or_widened_shard_run_refused(self) -> None:
        for run in (
            f"{es.RUN_COMMAND} || true",
            f"{es.RUN_COMMAND} -E 'not all()'",
            es.RUN_COMMAND.replace(" --no-tests=fail", ""),
            f"{es.RUN_COMMAND} --partition count:1/2",
            es.RUN_COMMAND.replace('-E "$SHARD_FILTER"', "-E 'all()'"),
        ):
            with self.subTest(run):
                self.assertTrue(_refused(lambda j, run=run: j["e2e"]["steps"][1].update(run=run)))
        self.assertTrue(_refused(lambda j: j["e2e"]["steps"][1].update({"continue-on-error": True}), "continue-on-error"))

    def test_shard_selection_off_the_plan_refused(self) -> None:
        for key, val in (("SHARD_FILTER", "all()"), ("SHARD_FILTER", "${{ matrix.shard }}"), ("SHARD_FILTER", None)):
            with self.subTest(key):

                def mutate(j, key=key, val=val):
                    env = j["e2e"]["steps"][1]["env"]
                    if val is None:
                        del env[key]
                    else:
                        env[key] = val

                self.assertTrue(_refused(mutate, "selection env"))
        self.assertTrue(_refused(lambda j: j["e2e"]["steps"][1].pop("env"), "selection env"))

    def test_e2e_without_changes_need_refused(self) -> None:
        self.assertTrue(_refused(lambda j: j["e2e"].update(needs=["test-prep"]), "must need `changes`"))
        self.assertTrue(_refused(lambda j: j["e2e"].pop("needs"), "must need `changes`"))

    def test_shard_selection_read_elsewhere_refused(self) -> None:
        self.assertTrue(_refused(lambda j: j["seal-slice"]["steps"].append({"run": 'echo "$SHARD_FILTER"'}), "outside `e2e`"))

    def test_plan_step_tampering_refused(self) -> None:
        self.assertTrue(_refused(lambda j: j["changes"]["steps"].pop(1), "exactly one step"))
        self.assertTrue(_refused(lambda j: j["changes"]["steps"].append(dict(PLAN_STEP, id="x")), "exactly one step"))
        self.assertTrue(_refused(lambda j: j["changes"]["steps"][1].update(id="plan"), "id: e2e-plan"))
        self.assertTrue(_refused(lambda j: j["changes"]["steps"][1].update(run=f"{es.PLAN_INVOCATION} || true"), "run only"))
        for key, val in (("if", "false"), ("env", {"GITHUB_OUTPUT": "/dev/null"}), ("continue-on-error", True)):
            with self.subTest(key):
                self.assertTrue(_refused(lambda j, key=key, val=val: j["changes"]["steps"][1].update({key: val})))

    def test_plan_output_tampering_refused(self) -> None:
        for val in (None, "", '{"1": {"filter": "none()"}}', "${{ steps.other.outputs.plan }}"):
            with self.subTest(val):

                def mutate(j, val=val):
                    if val is None:
                        del j["changes"]["outputs"][es.PLAN_OUTPUT]
                    else:
                        j["changes"]["outputs"][es.PLAN_OUTPUT] = val

                self.assertTrue(_refused(mutate, "output `e2e_plan`"))

    def test_cover_tampering_refused(self) -> None:
        self.assertTrue(_refused(lambda j: j["seal-slice"]["steps"].pop(1), "exactly one step"))
        self.assertTrue(_refused(lambda j: j["seal-slice"]["steps"][1].update(run=f"{es.COVER_INVOCATION} || true"), "run only"))
        self.assertTrue(_refused(lambda j: j["seal-slice"]["steps"][1].update({"continue-on-error": True}), "continue-on-error"))
        self.assertTrue(_refused(lambda j: j["seal-slice"]["steps"][1].update(env={"E2E_PLAN": '{"1": {}}'}), "cover step's env"))
        self.assertTrue(_refused(lambda j: j["seal-slice"]["steps"][1].pop("env"), "cover step's env"))
        self.assertTrue(_refused(lambda j: j["seal-slice"].update(needs=["e2e"]), "must need `changes`"))


def _heavy_override(binaries: tuple[str, ...] = es.HEAVY_BINARIES) -> dict:
    return {"test-group": es.HEAVY_TEST_GROUP, "filter": " | ".join(f"binary({b})" for b in binaries)}


NEXTEST_DOC = {
    "profile": {
        "ci": {"overrides": [_heavy_override()]},
        "default": {"overrides": [_heavy_override()]},
    }
}


class NextestLintTest(unittest.TestCase):
    """`nextest.toml`'s `heavy-server-e2e` overrides must be exactly `HEAVY_BINARIES` — the class that
    let `.config/nextest.toml` drift a second, unchecked copy of the SSOT and silently drop a binary."""

    def test_ssot_agreeing_doc_passes(self) -> None:
        self.assertEqual(es.nextest_lint_errors(NEXTEST_DOC), [])

    def test_repo_nextest_toml_agrees_with_the_ssot(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(es.lint(), 0)

    def test_missing_binary_refused(self) -> None:
        doc = copy.deepcopy(NEXTEST_DOC)
        doc["profile"]["ci"]["overrides"] = [_heavy_override(es.HEAVY_BINARIES[:-1])]
        errors = es.nextest_lint_errors(doc)
        self.assertTrue(any(f"missing ['{es.HEAVY_BINARIES[-1]}']" in e for e in errors))

    def test_extra_binary_refused(self) -> None:
        doc = copy.deepcopy(NEXTEST_DOC)
        doc["profile"]["default"]["overrides"] = [_heavy_override((*es.HEAVY_BINARIES, "bogus_binary"))]
        errors = es.nextest_lint_errors(doc)
        self.assertTrue(any("extra ['bogus_binary']" in e for e in errors))

    def test_missing_override_refused(self) -> None:
        for prof in ("ci", "default"):
            with self.subTest(prof):
                doc = copy.deepcopy(NEXTEST_DOC)
                doc["profile"][prof]["overrides"] = []
                errors = es.nextest_lint_errors(doc)
                self.assertTrue(any(f"profile.{prof}.overrides" in e and "found 0" in e for e in errors))

    def test_duplicate_override_refused(self) -> None:
        doc = copy.deepcopy(NEXTEST_DOC)
        doc["profile"]["ci"]["overrides"].append(_heavy_override())
        self.assertTrue(any("found 2" in e for e in es.nextest_lint_errors(doc)))

    def test_malformed_filter_term_refused(self) -> None:
        doc = copy.deepcopy(NEXTEST_DOC)
        doc["profile"]["ci"]["overrides"] = [{"test-group": es.HEAVY_TEST_GROUP, "filter": "test(foo) | binary(bar)"}]
        self.assertTrue(any("binary(NAME)" in e for e in es.nextest_lint_errors(doc)))

    def test_duplicate_binary_in_filter_refused(self) -> None:
        doc = copy.deepcopy(NEXTEST_DOC)
        doc["profile"]["ci"]["overrides"] = [{"test-group": es.HEAVY_TEST_GROUP, "filter": "binary(a) | binary(a)"}]
        self.assertTrue(any("more than once" in e for e in es.nextest_lint_errors(doc)))

    def test_missing_profile_table_refused(self) -> None:
        doc = copy.deepcopy(NEXTEST_DOC)
        del doc["profile"]["default"]
        self.assertTrue(any("profile.default.overrides" in e for e in es.nextest_lint_errors(doc)))

    def test_nextest_toml_unreadable_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.toml")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(es.lint(nextest_path=missing), 1)


if __name__ == "__main__":
    unittest.main()
