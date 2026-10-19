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
        self.assertEqual(es.SHARDS, 14)
        self.assertEqual(es.shard_total(es.GROUPS), 14)

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
        self.assertEqual(by_name["heavy"], (es.HEAVY, 3))
        self.assertEqual(by_name["db-issues"], ("binary(g_db) | binary(g_issues)", 3))
        self.assertEqual(es.GROUPS[-1], ("light", es.COMPLEMENT, 6))

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
        wider = (*es.GROUPS[:-1], ("light", es.COMPLEMENT, 7))
        narrower = (*es.GROUPS[:-1], ("light", es.COMPLEMENT, 5))
        for groups in (wider, narrower):
            with self.subTest(total=es.shard_total(groups)):
                self.assertTrue(any("expected 1.." in e for e in es.wiring_errors(WORKFLOW, groups)))

    def test_malformed_table_refused_by_the_wiring_check(self) -> None:
        self.assertTrue(es.wiring_errors(WORKFLOW, (*es.GROUPS[:-1], ("light", "binary(x)", 6))))


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
            "cargo nextest run --archive-file nextest.tar.zst --workspace-remap . --profile ci"
            ' --no-fail-fast --test-threads=2 --no-tests=fail -E "$SHARD_FILTER" --partition "$SHARD_PARTITION"',
        )

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


if __name__ == "__main__":
    unittest.main()
