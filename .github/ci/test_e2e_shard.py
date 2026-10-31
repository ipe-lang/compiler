#!/usr/bin/env python3
"""Refusal proofs for `e2e_shard.py` (the e2e SEAL shard-partition SSOT) and
`tools/scripts/e2e-shard-cover.py` (its per-run partition proof).

Every way the partition proof must refuse (a test no shard runs, a test two
shards run, a shard selecting outside the archive, an empty archive, a missing
shard, a malformed listing or plan) and every way the ci.yml wiring check must
refuse (a dropped or extra shard, a bypassing `nextest run`, a shard or cover
reading its selection off the plan, a masked plan step, a cover run outside its
job, conditionally, or not needed by the verdict) and every way the shard-group
table must refuse (no complement last, an empty or non-ASCII filter, a
zero-shard group, a width off the matrix) gets its own test, per PRINCIPLES.md
"Prove the refusals". Pure stdlib `unittest`.
"""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import os
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
    def test_each_group_excludes_every_earlier_group(self) -> None:
        filters = es.effective_filters(es.GROUPS)
        self.assertEqual(filters[0], f"({es.GROUPS[0][1]})")
        for i in range(1, len(es.GROUPS)):
            own = f"({es.GROUPS[i][1]})"
            earlier = " | ".join(f"({f})" for _, f, _ in es.GROUPS[:i])
            with self.subTest(group=es.GROUPS[i][0]):
                self.assertEqual(filters[i], f"{own} & not ({earlier})")

    def test_shards_walk_the_groups_in_order(self) -> None:
        filters = es.effective_filters(es.GROUPS)
        want: list[list[str]] = []
        for (_, _, shards), filt in zip(es.GROUPS, filters, strict=True):
            want += [["-E", filt, "--partition", f"count:{k}/{shards}"] for k in range(1, shards + 1)]
        self.assertEqual([es.selection(k) for k in range(1, es.SHARDS + 1)], want)

    def test_groups_are_sized_to_the_matrix_width(self) -> None:
        self.assertEqual(es.TOTAL_SHARDS, 14)
        self.assertEqual(es.SHARDS, es.TOTAL_SHARDS)
        self.assertEqual(es.shard_total(es.GROUPS), es.TOTAL_SHARDS)

    def test_named_groups_split_the_heavy_set(self) -> None:
        # The two multi-minute coverage columns each run on a shard alone, and
        # the rest of the serialized heavy set follows them.
        by_name = {name: (filt, shards) for name, filt, shards in es.GROUPS}
        for name, test in (
            ("coverage-build-run", "build_run_column_over_a_representative_slice"),
            ("coverage-dynamic-columns", "dynamic_columns_pass_over_the_whole_surface"),
        ):
            with self.subTest(name):
                self.assertEqual(by_name[name], (f"binary(stdlib_coverage_dynamic) & test(={test})", 1))
                path = os.path.join(REPO, "src", "ipe-cli", "tests", "stdlib_coverage_dynamic.rs")
                with open(path, encoding="utf-8") as fh:
                    self.assertIn(f"\n#[test]\nfn {test}() {{", fh.read())
        self.assertEqual(by_name["heavy"][0], es.HEAVY)
        self.assertEqual(by_name["db-issues"][0], "binary(g_db) | binary(g_issues)")
        self.assertEqual(es.GROUPS[-1][:2], ("light", es.COMPLEMENT))

    def test_a_named_group_matching_nothing_is_red(self) -> None:
        # A renamed test leaves its one-test group with an empty selection;
        # `--no-tests=fail` makes that shard red rather than a vacuous green.
        self.assertIn("--no-tests=fail", es.RUN_ONLY_ARGS)
        self.assertIn("--no-tests=fail", es.RUN_COMMAND.split())

    def test_heavy_set_equals_every_nextest_heavy_group_filter(self) -> None:
        # `HEAVY` and each `heavy-server-e2e` override filter in
        # `.config/nextest.toml` name the same binaries: a binary in only one
        # of them either runs unserialized on a heavy shard or serialized on a
        # light one.
        import re

        with open(os.path.join(REPO, ".config", "nextest.toml"), encoding="utf-8") as f:
            toml = f.read()
        heavy = set(re.findall(r"binary\(([A-Za-z0-9_]+)\)", es.HEAVY))
        filters = re.findall(r"filter = '([^']*)'\ntest-group = 'heavy-server-e2e'", toml)
        self.assertGreaterEqual(len(filters), 2, "a ci and a default heavy-server-e2e override")
        for flt in filters:
            self.assertEqual(set(re.findall(r"binary\(([A-Za-z0-9_]+)\)", flt)), heavy)

    def test_every_shard_has_a_selection(self) -> None:
        for k in range(1, es.SHARDS + 1):
            self.assertEqual(len(es.selection(k)), 4)

    def test_malformed_group_table_refused_at_selection(self) -> None:
        with self.assertRaises(es.ShardError):
            es.selection(1, (("a", "binary(x)", 1),))
        with self.assertRaises(es.ShardError):
            es.effective_filters(())

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


def _group_refused(groups: object, needle: str) -> bool:
    errors = es.group_errors(groups)
    return bool(errors) and any(needle in e for e in errors)


class GroupTableTest(unittest.TestCase):
    def test_ssot_groups_pass(self) -> None:
        self.assertEqual(es.group_errors(es.GROUPS), [])

    def test_last_filter_not_the_complement_refused(self) -> None:
        for last in ("binary(x)", "all() ", "not none()", ""):
            with self.subTest(last):
                groups = (*es.GROUPS[:-1], ("light", last, 6))
                self.assertTrue(_group_refused(groups, "last group's filter"))
        self.assertTrue(_group_refused(es.GROUPS[:-1], "last group's filter"))

    def test_zero_or_non_int_shard_group_refused(self) -> None:
        for shards in (0, -1, True, 1.0, "1", None):
            with self.subTest(shards=shards):
                groups = (("a", "binary(x)", shards), *es.GROUPS[1:])
                self.assertTrue(_group_refused(groups, "at least one shard"))

    def test_empty_or_non_ascii_filter_refused(self) -> None:
        for filt in ("", "   ", "binary(caf\u00e9)", None, 1):
            with self.subTest(filt=filt):
                groups = (("a", filt, 1), *es.GROUPS[1:])
                self.assertTrue(_group_refused(groups, "filter"))

    def test_bad_or_repeated_name_refused(self) -> None:
        self.assertTrue(_group_refused((("", "binary(x)", 1), *es.GROUPS[1:]), "name"))
        self.assertTrue(_group_refused((("light", "binary(x)", 1), *es.GROUPS[1:]), "repeats the name"))

    def test_malformed_table_refused(self) -> None:
        for groups in ((), [], None, list(es.GROUPS), (("a", "all()"),), ("all()",)):
            with self.subTest(groups=groups):
                self.assertTrue(es.group_errors(groups))

    def test_shard_total_off_the_matrix_refused(self) -> None:
        light = es.GROUPS[-1][2]
        wider = (*es.GROUPS[:-1], ("light", es.COMPLEMENT, light + 1))
        narrower = (*es.GROUPS[:-1], ("light", es.COMPLEMENT, light - 1))
        for groups in (wider, narrower):
            with self.subTest(total=es.shard_total(groups)):
                self.assertTrue(any("expected 1.." in e for e in es.wiring_errors(WORKFLOW, groups)))

    def test_malformed_table_refused_by_the_wiring_check(self) -> None:
        self.assertTrue(es.wiring_errors(WORKFLOW, (*es.GROUPS[:-1], ("light", "binary(x)", 6))))


def _times(*rows: str) -> object:
    return es.parse_times("\n".join(rows) + "\n")


def _nextest_group(specs: tuple, binary_id: str, test: str) -> int:
    """The index of the first group whose filter selects `binary_id test`,
    read off the same spec `spec_filter` writes the filter from."""
    name = es.binary_name(binary_id)
    for i, spec in enumerate(specs):
        if isinstance(spec, es.OneTest) and name == spec.binary and test == spec.test:
            return i
        if isinstance(spec, es.Binaries) and name in spec.binaries:
            return i
        if isinstance(spec, es.Rest):
            return i
    raise AssertionError("the last group is the complement")


class WeightedShardTest(unittest.TestCase):
    def test_committed_table_loads_and_names_every_isolated_test(self) -> None:
        times = es.load_times()
        for spec in es.SPECS:
            if isinstance(spec, es.OneTest):
                with self.subTest(spec.name):
                    self.assertTrue(
                        any(es.binary_name(b) == spec.binary and t == spec.test for b, t in times.tests),
                        "regenerate e2e-shard-times.txt with this group's test line",
                    )

    def test_groups_are_the_allocation_of_the_committed_table(self) -> None:
        self.assertEqual(es.GROUPS, es.allocate(es.SPECS, es.load_times()))
        self.assertEqual([name for name, _, _ in es.GROUPS], [s.name for s in es.SPECS])
        self.assertEqual([f for _, f, _ in es.GROUPS], [es.spec_filter(s) for s in es.SPECS])

    def test_every_test_lands_on_exactly_one_shard(self) -> None:
        # The self-test of the sharder: model every measured binary (and one
        # the table lacks, a library and a `bin/` target) as tests, place
        # each test in its first matching group and then on the shard its
        # `count:k/n` index picks, and require that the shards together hold
        # the whole set, each test once, on shards 1..SHARDS only.
        times = es.load_times()
        universe: list[tuple[str, str]] = [k for k in times.tests]
        for binary in [*times.binaries, "ipe::not_in_the_table", "some_lib", "some_crate::bin/tool"]:
            universe += [(binary, f"t{i}") for i in range(7)]
        first = [1]
        for _, _, n in es.GROUPS[:-1]:
            first.append(first[-1] + n)
        placed: dict[tuple[str, str], list[int]] = {t: [] for t in universe}
        index: dict[tuple[int, str], int] = {}
        for binary, test in universe:
            g = _nextest_group(es.SPECS, binary, test)
            n = es.GROUPS[g][2]
            k = index.get((g, binary), 0)
            index[(g, binary)] = k + 1
            placed[(binary, test)].append(first[g] + k % n)
        self.assertEqual(sum(n for _, _, n in es.GROUPS), es.SHARDS)
        self.assertTrue(all(len(v) == 1 for v in placed.values()))
        self.assertEqual(set(placed), set(universe))
        self.assertTrue(all(1 <= v[0] <= es.SHARDS for v in placed.values()))
        # And each shard's plan entry names exactly that group and index.
        plan = es.plan()
        for g, (start, (_, _, n)) in enumerate(zip(first, es.GROUPS, strict=True)):
            for k in range(n):
                entry = plan[str(start + k)]
                self.assertEqual(entry["partition"], f"count:{k + 1}/{n}")
                self.assertEqual(entry["filter"], es.effective_filters(es.GROUPS)[g])

    def test_longest_group_gets_the_spare_shards(self) -> None:
        specs = (
            es.OneTest("one", "b", "t"),
            es.Binaries("serial", ("s",), 1),
            es.Rest("rest", 2),
        )
        times = _times("c::b 100", "c::b t 90", "c::s 600", "c::x 1200")
        # serial: 600 s one at a time; rest: b's other 10 s + x's 1200 s, two at
        # a time (605 s a shard). Spare shards go rest (302.5), serial (300),
        # then rest again.
        self.assertEqual([n for _, _, n in es.allocate(specs, times, total=6)], [1, 2, 3])
        self.assertEqual(es.group_weights(specs, times), [90, 600, 1210])

    def test_unmeasured_named_binary_weighs_the_default(self) -> None:
        specs = (es.Binaries("named", ("absent", "s"), 1), es.Rest("rest", 1))
        times = _times("c::s 10", "c::x 5")
        self.assertEqual(es.group_weights(specs, times), [es.DEFAULT_WEIGHT_S + 10, 5])

    def test_every_sized_group_keeps_a_shard(self) -> None:
        specs = (es.Binaries("tiny", ("s",), 1), es.Rest("rest", 1))
        groups = es.allocate(specs, _times("c::s 0", "c::x 10000"), total=5)
        self.assertEqual([n for _, _, n in groups], [1, 4])

    def test_more_groups_than_shards_is_refused(self) -> None:
        with self.assertRaises(es.ShardError):
            es.allocate(es.SPECS, es.load_times(), total=len(es.SPECS) - 1)

    def test_malformed_specs_are_refused(self) -> None:
        for specs in (
            (),
            (es.Binaries("a", ("x",), 1),),
            (es.Rest("a", 1), es.Rest("b", 1)),
            (es.Binaries("a", (), 1), es.Rest("b", 1)),
            (es.Binaries("a", ("x",), 0), es.Rest("b", 1)),
            (es.Binaries("a", ("x",), True), es.Rest("b", 1)),
            (es.Rest("b", 0),),
            ("all()",),
        ):
            with self.subTest(specs=specs):
                self.assertTrue(es.spec_errors(specs))
                with self.assertRaises(es.ShardError):
                    es.allocate(specs, _times("c::x 1"))  # type: ignore[arg-type]

    def test_malformed_time_tables_are_refused(self) -> None:
        for rows in (
            (),
            ("# only a comment",),
            ("c::x",),
            ("c::x 1 2 3",),
            ("c::x -1",),
            ("c::x 1.5",),
            ("c::x ten",),
            ("c::x \u0661",),
            (f"c::x {es.MAX_WEIGHT_S + 1}",),
            ("c::x 1", "c::x 2"),
            ("c x 1",),
            ("c::bad/path 1",),
            ("c::x t 1",),
            ("c::x 1", "c::x t 2"),
            ("c::x 5", "c::x t 1", "c::x t 1"),
            ("c::x 5", "c::x t(=x) 1"),
            ("c::x  5",),
        ):
            with self.subTest(rows=rows), self.assertRaises(es.ShardError):
                _times(*rows)

    def test_time_table_past_its_ceilings_is_refused(self) -> None:
        with self.assertRaises(es.ShardError):
            es.parse_times("\n".join(f"c::b{i} 1" for i in range(es.MAX_TIMES_ROWS + 1)))
        with self.assertRaises(es.ShardError):
            es.parse_times("#" * (es.MAX_TIMES_BYTES + 1))
        with self.assertRaises(es.ShardError):
            es.load_times(os.path.join(HERE, "no-such-times.txt"))

    def test_binary_names_follow_nextest_binary_ids(self) -> None:
        self.assertEqual(es.binary_name("ipe::g_db"), "g_db")
        self.assertIsNone(es.binary_name("ipe"))
        self.assertIsNone(es.binary_name("ipe_docs::bin/gen_site"))


class PlanTest(unittest.TestCase):
    def test_plan_is_every_selection(self) -> None:
        plan = es.plan()
        self.assertEqual(sorted(plan, key=int), [str(k) for k in range(1, es.SHARDS + 1)])
        for k in range(1, es.SHARDS + 1):
            self.assertEqual(["-E", plan[str(k)]["filter"], "--partition", plan[str(k)]["partition"]], es.selection(k))

    def test_cover_parses_the_published_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(es.write_plan(out), 0)
            with open(out, encoding="utf-8") as fh:
                key, sep, value = fh.read().rstrip("\n").partition("=")
        self.assertEqual((key, sep), ("plan", "="))
        self.assertNotIn("\n", value)
        parsed = ec.parse_plan(value)
        self.assertEqual({k: ["-E", f, "--partition", p] for k, (f, p) in parsed.items()},
                         {k: es.selection(k) for k in range(1, es.SHARDS + 1)})

    def test_plan_without_output_file_is_red(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(es.write_plan(""), 1)
            with tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(es.write_plan(os.path.join(tmp, "no", "such")), 1)


class PlanParseTest(unittest.TestCase):
    GOOD = {"1": {"filter": "all()", "partition": "count:1/2"}, "2": {"filter": "all()", "partition": "count:2/2"}}

    def test_good_plan_parses(self) -> None:
        self.assertEqual(ec.parse_plan(json.dumps(self.GOOD)), {1: ("all()", "count:1/2"), 2: ("all()", "count:2/2")})

    def test_malformed_plan_refused(self) -> None:
        entry = {"filter": "all()", "partition": "count:1/1"}
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
            json.dumps({"1": {"filter": "all()"}}),
            json.dumps({"1": dict(entry, extra="x")}),
            json.dumps({"1": {"filter": "", "partition": "count:1/1"}}),
            json.dumps({"1": {"filter": "all()", "partition": " "}}),
            json.dumps({"1": {"filter": 1, "partition": "count:1/1"}}),
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
COVER_STEP = {"name": "cover", "env": dict(es.COVER_ENV), "run": es.COVER_INVOCATION}
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
        "seal-slice-cover": {
            "needs": ["changes", "test-prep"],
            "steps": [{"uses": "actions/checkout@v7"}, {"uses": "actions/download-artifact@v8"}, COVER_STEP],
        },
        "seal-slice": {"needs": ["changes", "test-prep", "e2e", "seal-slice-cover"], "steps": [{"run": "gate"}]},
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
            'cargo nextest run --binaries-metadata "$RUNNER_TEMP/nextest-x/target/nextest/binaries-metadata.json"'
            ' --cargo-metadata "$RUNNER_TEMP/nextest-x/target/nextest/cargo-metadata.json"'
            ' --target-dir-remap "$RUNNER_TEMP/nextest-x/target" --workspace-remap . --profile ci'
            ' --no-fail-fast --test-threads=2 --no-tests=fail -E "$SHARD_FILTER" --partition "$SHARD_PARTITION"',
        )
        self.assertNotIn(es.ARCHIVE_FILE, es.RUN_COMMAND)

    def test_missing_jobs_refused(self) -> None:
        self.assertTrue(es.wiring_errors({}))
        for job in ("changes", "e2e", "seal-slice", "seal-slice-cover"):
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
            es.RUN_COMMAND.replace('--partition "$SHARD_PARTITION"', "--partition count:1/1"),
        ):
            with self.subTest(run):
                self.assertTrue(_refused(lambda j, run=run: j["e2e"]["steps"][1].update(run=run)))
        self.assertTrue(_refused(lambda j: j["e2e"]["steps"][1].update({"continue-on-error": True}), "continue-on-error"))

    def test_shard_selection_off_the_plan_refused(self) -> None:
        for key, val in (("SHARD_FILTER", "all()"), ("SHARD_PARTITION", "count:1/1"), ("SHARD_FILTER", None)):
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
        for val in (None, "", '{"1": {"filter": "none()", "partition": "count:1/1"}}', "${{ steps.other.outputs.plan }}"):
            with self.subTest(val):

                def mutate(j, val=val):
                    if val is None:
                        del j["changes"]["outputs"][es.PLAN_OUTPUT]
                    else:
                        j["changes"]["outputs"][es.PLAN_OUTPUT] = val

                self.assertTrue(_refused(mutate, "output `e2e_plan`"))

    def test_cover_tampering_refused(self) -> None:
        cover = lambda j: j["seal-slice-cover"]["steps"][2]  # noqa: E731
        self.assertTrue(_refused(lambda j: j["seal-slice-cover"]["steps"].pop(2), "exactly one step"))
        self.assertTrue(_refused(lambda j: cover(j).update(run=f"{es.COVER_INVOCATION} || true"), "run only"))
        self.assertTrue(_refused(lambda j: cover(j).update({"continue-on-error": True}), "continue-on-error"))
        self.assertTrue(_refused(lambda j: cover(j).update(env={"E2E_PLAN": '{"1": {}}'}), "cover step's env"))
        self.assertTrue(_refused(lambda j: cover(j).pop("env"), "cover step's env"))

    def test_cover_step_with_extra_env_refused(self) -> None:
        self.assertTrue(_refused(lambda j: j["seal-slice-cover"]["steps"][2]["env"].update(EXTRA="1"), "cover step's env"))

    def test_conditional_cover_step_refused(self) -> None:
        for cond in ("needs.test-prep.result == 'success'", "github.event_name == 'workflow_dispatch'", "always()"):
            with self.subTest(cond):
                self.assertTrue(_refused(lambda j, cond=cond: j["seal-slice-cover"]["steps"][2].update({"if": cond}), "no `if:`"))

    def test_cover_step_moved_back_into_the_verdict_refused(self) -> None:
        def mutate(j):
            j["seal-slice"]["steps"].append(j["seal-slice-cover"]["steps"].pop(2))

        self.assertTrue(_refused(mutate, "outside `seal-slice-cover`"))

    def test_cover_copied_into_another_job_refused(self) -> None:
        for job in ("seal-slice", "e2e", "changes"):
            with self.subTest(job):
                self.assertTrue(_refused(lambda j, job=job: j[job]["steps"].append(dict(COVER_STEP)), "outside `seal-slice-cover`"))
        self.assertTrue(_refused(lambda j: j["seal-slice"]["steps"].append({"run": f"E2E_PLAN=x python3 {es.COVER_SCRIPT}"}),
                                 "outside `seal-slice-cover`"))

    def test_cover_step_repeated_refused(self) -> None:
        self.assertTrue(_refused(lambda j: j["seal-slice-cover"]["steps"].append(dict(COVER_STEP)), "exactly one step"))
        self.assertTrue(_refused(lambda j: j["seal-slice-cover"]["steps"].append({"run": f"{es.COVER_INVOCATION} --again"}),
                                 "exactly one step"))

    def test_second_spelling_of_the_cover_in_its_job_refused(self) -> None:
        # A second run of the cover script under another spelling is not the
        # exact invocation, yet still runs the proof twice.
        self.assertTrue(_refused(lambda j: j["seal-slice-cover"]["steps"].append({"run": f"python3 ./{es.COVER_SCRIPT}"}),
                                 "cover in exactly one step"))

    def test_verdict_without_the_cover_need_refused(self) -> None:
        self.assertTrue(_refused(lambda j: j["seal-slice"]["needs"].remove("seal-slice-cover"), "must need `seal-slice-cover`"))
        self.assertTrue(_refused(lambda j: j["seal-slice"].pop("needs"), "must need `seal-slice-cover`"))

    def test_cover_job_without_its_inputs_refused(self) -> None:
        for need in ("changes", "test-prep"):
            with self.subTest(need):
                self.assertTrue(_refused(lambda j, need=need: j["seal-slice-cover"]["needs"].remove(need), f"must need `{need}`"))
        self.assertTrue(_refused(lambda j: j["seal-slice-cover"].update(needs="changes"), "must need `test-prep`"))


ed = _load("e2e_disk", os.path.join(REPO, "tools", "scripts", "e2e-disk.py"))
SHARED = "${{ github.workspace }}/.cache/oracle-shared-target"
DISK_E2E_STEPS = [
    {"uses": "actions/checkout@v7"},
    {"name": "free", "run": es.FREE_DISK_MARKER + "\ndocker image prune -af"},
    {"uses": "actions/download-artifact@v8", "with": {"name": "nextest-archive"}},
    {"name": "unpack", "run": es.EXTRACT_RUN},
    {"name": "floor", "run": es.DISK_FLOOR_INVOCATION},
    {"name": "shard", "env": {"IPE_E2E": "1", es.SHARED_TARGET_VAR: SHARED, **es.SHARD_ENV}, "run": es.RUN_COMMAND},
]


def _disk_wf(steps: list[dict] | None = None, **jobs: dict) -> dict:
    return {"jobs": {"e2e": {"steps": copy.deepcopy(DISK_E2E_STEPS if steps is None else steps)}, **jobs}}


class SharedTargetLintTest(unittest.TestCase):
    def test_wired_e2e_job_passes(self) -> None:
        self.assertEqual(es.shared_target_errors(_disk_wf()), [])
        self.assertEqual(es.disk_order_errors(_disk_wf()), [])

    def test_lint_refuses_ipe_e2e_step_without_shared_target(self) -> None:
        shapes = {
            "matrix step": {"strategy": {"matrix": {"shard": [1, 2]}}, "steps": [{"name": "m", "env": {"IPE_E2E": "1"}, "run": "x"}]},
            "single-job step": {"steps": [{"name": "s", "env": {"IPE_E2E": "1"}, "run": "x"}]},
            "job-level env": {"env": {"IPE_E2E": "1"}, "steps": [{"name": "j", "run": "x"}]},
            "workflow expression": {"steps": [{"name": "e", "env": {"IPE_E2E": "${{ matrix.e2e }}"}, "run": "x"}]},
        }
        for what, job in shapes.items():
            with self.subTest(what):
                errors = es.shared_target_errors({"jobs": {"other": job}})
                self.assertTrue(any("without IPE_ORACLE_SHARED_TARGET" in e for e in errors), errors)

    def test_job_level_shared_target_covers_its_steps(self) -> None:
        job = {"env": {"IPE_E2E": "1", es.SHARED_TARGET_VAR: SHARED}, "steps": [{"name": "j", "run": "x"}]}
        self.assertEqual(es.shared_target_errors({"jobs": {"other": job}}), [])

    def test_lint_refuses_relative_or_non_workspace_shared_target(self) -> None:
        for value in (".cache/t", "/tmp/t", "${{ runner.temp }}/t", "${{ github.workspace }}/../t", ""):
            with self.subTest(value):
                job = {"steps": [{"name": "s", "env": {"IPE_E2E": "1", es.SHARED_TARGET_VAR: value}, "run": "x"}]}
                self.assertTrue(es.shared_target_errors({"jobs": {"other": job}}))

    def test_unarmed_step_needs_no_shared_target(self) -> None:
        for value in ("", "0"):
            job = {"steps": [{"name": "s", "env": {"IPE_E2E": value}, "run": "x"}]}
            self.assertEqual(es.shared_target_errors({"jobs": {"other": job}}), [])


def _order_refused(mutate, needle: str) -> bool:
    steps = copy.deepcopy(DISK_E2E_STEPS)
    mutate(steps)
    errors = es.disk_order_errors(_disk_wf(steps))
    return any(needle in e for e in errors)


class DiskOrderLintTest(unittest.TestCase):
    def test_lint_refuses_step_order_drift(self) -> None:
        self.assertTrue(_order_refused(lambda s: s.insert(5, s.pop(4)) or s.insert(1, s.pop(4)), "out of order"))
        self.assertTrue(_order_refused(lambda s: s.insert(1, s.pop(2)), "out of order"))

    def test_lint_refuses_a_missing_or_doubled_step(self) -> None:
        for i, what in ((1, "free-disk"), (3, "unpack-then-delete"), (4, "disk floor")):
            with self.subTest(what):
                self.assertTrue(_order_refused(lambda s, i=i: s.pop(i), f"be {('the ' + what)}"))
        self.assertTrue(_order_refused(lambda s: s.insert(4, dict(s[4])), "found 2"))

    def test_lint_refuses_a_conditional_floor_or_unpack(self) -> None:
        for i in (3, 4):
            with self.subTest(i):
                self.assertTrue(_order_refused(lambda s, i=i: s[i].update({"if": "always()"}), "no `if:`"))
                self.assertTrue(_order_refused(lambda s, i=i: s[i].update({"continue-on-error": True}), "no `if:`"))

    def test_lint_refuses_archive_kept_during_run(self) -> None:
        kept = es.EXTRACT_COMMAND
        self.assertTrue(_order_refused(lambda s: s[3].update(run=kept), "unpack-then-delete"))
        self.assertTrue(
            _order_refused(lambda s: s.insert(4, {"name": "again", "uses": "actions/download-artifact@v8"}), "download")
        )
        self.assertTrue(_order_refused(lambda s: s.insert(4, {"name": "cp", "run": "cp x nextest.tar.zst"}), "still names"))

    def test_disk_script_drift_refused(self) -> None:
        class Drift:
            TEST_THREADS = es.TEST_THREADS + 1
            EXTRACT_DIR = es.EXTRACT_DIR

        class DriftDir:
            TEST_THREADS = es.TEST_THREADS
            EXTRACT_DIR = "/tmp/x"

        self.assertEqual(es.disk_script_errors(), [])
        self.assertTrue(es.disk_script_errors(lambda: Drift))
        self.assertTrue(es.disk_script_errors(lambda: DriftDir))

    def test_disk_floor_invocation_is_the_scripts_own_mode(self) -> None:
        self.assertEqual(es.DISK_FLOOR_INVOCATION, f"python3 {es.DISK_SCRIPT} --disk-floor")


class NextestPinLintTest(unittest.TestCase):
    def _wf(self, step: dict) -> dict[str, dict]:
        return {"x.yml": {"jobs": {"j": {"steps": [step]}}}}

    def test_lint_refuses_unpinned_nextest(self) -> None:
        for step in (
            {"uses": es.NEXTEST_INSTALL_REF},
            {"uses": es.NEXTEST_INSTALL_REF, "with": {"tool": "nextest"}},
            {"uses": "taiki-e/install-action@abc", "with": {"tool": "cargo-deny@1, nextest@0.9.1"}},
            {"uses": "taiki-e/install-action@abc", "with": {"tool": "cargo-nextest"}},
        ):
            with self.subTest(step):
                self.assertTrue(es.nextest_pin_errors(self._wf(step)))

    def test_pinned_nextest_and_other_tools_pass(self) -> None:
        for step in (
            {"uses": es.NEXTEST_INSTALL_REF, "with": {"tool": es.NEXTEST_TOOL}},
            {"uses": "taiki-e/install-action@abc", "with": {"tool": "cargo-deny@0.20.2"}},
        ):
            with self.subTest(step):
                self.assertEqual(es.nextest_pin_errors(self._wf(step)), [])


def _tree(root: str, *dirs: str) -> None:
    for d in dirs:
        os.makedirs(os.path.join(root, d), exist_ok=True)
        with open(os.path.join(root, d, ed.CACHEDIR_TAG), "w", encoding="utf-8") as fh:
            fh.write("Signature: 8a477f597d28d172789f06886806bc55\n")


def _census(roots: list[str], env: dict[str, str]) -> tuple[int, str]:
    err = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
        rc = ed.census(roots, env)
    return rc, err.getvalue()


class CensusTest(unittest.TestCase):
    def test_census_reports_leftover_target(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            _tree(root, "x/target")
            rc, err = _census([root], {})
            self.assertEqual(rc, 1)
            self.assertIn(os.path.join(root, "x", "target"), err)

    def test_clean_roots_pass(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "a", "b"))
            self.assertEqual(_census([root, os.path.join(root, "missing")], {})[0], 0)

    def test_census_excludes_shared_target_by_canonical_path(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            _tree(root, "real/shared")
            os.symlink(os.path.join(root, "real"), os.path.join(root, "link"))
            env = {"IPE_ORACLE_SHARED_TARGET": os.path.join(root, "link", "shared")}
            self.assertEqual(_census([root], env)[0], 0)

    def test_census_excludes_the_unpacked_archive(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            _tree(root, "nextest-x/target")
            self.assertEqual(_census([root], {"RUNNER_TEMP": root})[0], 0)
            self.assertEqual(_census([root], {})[0], 1)

    def test_census_does_not_follow_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            _tree(outside, "t")
            os.symlink(outside, os.path.join(root, "out"))
            self.assertEqual(_census([root], {})[0], 0)

    def test_census_depth_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            deep = os.path.join(*(["d"] * (ed.CENSUS_MAX_DEPTH + 2)))
            os.makedirs(os.path.join(root, deep))
            rc, err = _census([root], {})
            self.assertEqual(rc, 1)
            self.assertIn("deeper than", err)

    def test_census_without_roots_is_a_usage_error(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ed.main(["--census"]), 2)
            self.assertEqual(ed.main([]), 2)


class DiskFloorTest(unittest.TestCase):
    def test_disk_floor_refuses_below_budget(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ed.disk_floor(["/a"], reader=lambda _p: ed.DISK_FLOOR_BYTES - 1), 1)
            self.assertEqual(ed.disk_floor(["/a"], reader=lambda _p: ed.DISK_FLOOR_BYTES), 0)
            self.assertEqual(ed.disk_floor(["/a", "/b"], reader=lambda p: 0 if p == "/b" else ed.DISK_FLOOR_BYTES), 1)

    def test_unreadable_mount_is_refused(self) -> None:
        def boom(_p: str) -> int:
            raise OSError("gone")

        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ed.disk_floor(["/a"], reader=boom), 1)

    def test_disk_floor_formula_terms(self) -> None:
        self.assertEqual(ed.DISK_FLOOR_BYTES, sum(b for _, b in ed.DISK_FLOOR_TERMS))
        self.assertIn(ed.TEST_THREADS * ed.APP_CRATE_BYTES, [b for _, b in ed.DISK_FLOOR_TERMS])
        self.assertEqual(
            ed.DISK_FLOOR_BYTES,
            ed.SHARED_DEP_TREE_BYTES + ed.TEST_THREADS * ed.APP_CRATE_BYTES + ed.ISOLATED_TREE_BYTES + ed.RESULTS_SLACK_BYTES,
        )


if __name__ == "__main__":
    unittest.main()
