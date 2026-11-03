#!/usr/bin/env python3
"""Refusal proofs for the filter-liveness half of `tools/scripts/e2e-shard-cover.py`.

The cover lists the archive once per `.config/nextest.toml` override filter
and per shard group, and must refuse a filter that selects nothing (it names
a binary, module or test that moved), a `PLATFORM_ONLY` entry that no override
carries or that the archive does hold, a shard group that selects nothing,
and an override table it cannot read. Each refusal gets its own test, per
PRINCIPLES.md "Prove the refusals"; the partition half is proved in
`test_e2e_shard.py`. Pure stdlib `unittest`.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))

_spec = importlib.util.spec_from_file_location("e2e_shard_cover_r6", os.path.join(REPO, "tools", "scripts", "e2e-shard-cover.py"))
assert _spec is not None and _spec.loader is not None
ec = importlib.util.module_from_spec(_spec)
sys.modules["e2e_shard_cover_r6"] = ec
_spec.loader.exec_module(ec)

JUNCTION = next(iter(ec.PLATFORM_ONLY))
CONFIG = f"""
[profile.ci]
slow-timeout = "60s"

[[profile.ci.overrides]]
filter = 'binary(a)'
test-group = 'g'

[[profile.default.overrides]]
filter = "binary(a) & test(=m::t)"

[[profile.ci.overrides]]
filter = '{JUNCTION}'
test-group = 'windows-junction'

[test-groups]
g = {{ max-threads = 1 }}
"""


class OverrideFilters(unittest.TestCase):
    def test_reads_every_override_filter_in_order(self) -> None:
        self.assertEqual(ec.override_filters(CONFIG), ["binary(a)", "binary(a) & test(=m::t)", JUNCTION])

    def test_the_live_config_reads(self) -> None:
        with open(os.path.join(REPO, ".config", "nextest.toml"), encoding="utf-8") as handle:
            filters = ec.override_filters(handle.read())
        self.assertTrue(ec.PLATFORM_ONLY <= set(filters))

    def test_an_unreadable_or_missing_filter_is_refused(self) -> None:
        for text in (
            "[[profile.ci.overrides]]\nfilter = '''binary(a)'''\n",
            "[[profile.ci.overrides]]\nfilter = \"binary(\\\"a\\\")\"\n",
            "[[profile.ci.overrides]]\nfilter = binary(a)\n",
            "[[profile.ci.overrides]]\ntest-group = 'g'\n",
            "[[profile.ci.overrides]]\nfilter = 'binary(a)'\nfilter = 'binary(b)'\n",
            "[[profile.ci.overrides]]\ntest-group = 'g'\n[[profile.ci.overrides]]\nfilter = 'binary(a)'\n",
            "[profile.ci]\nslow-timeout = '60s'\n",
        ):
            with self.subTest(text), self.assertRaises(ec.CoverError):
                ec.override_filters(text)


class FilterLiveness(unittest.TestCase):
    def test_live_filters_pass(self) -> None:
        self.assertEqual(ec.filter_errors({"binary(a)": 3, JUNCTION: 0}), [])

    def test_a_zero_match_override_is_refused(self) -> None:
        errors = ec.filter_errors({"binary(a)": 3, "binary(gone)": 0, JUNCTION: 0})
        self.assertEqual(len(errors), 1)
        self.assertIn("binary(gone)", errors[0])

    def test_a_stale_platform_only_entry_is_refused(self) -> None:
        errors = ec.filter_errors({"binary(a)": 3})
        self.assertEqual(len(errors), 1)
        self.assertIn("drop the stale entry", errors[0])

    def test_a_platform_only_filter_the_archive_holds_is_refused(self) -> None:
        errors = ec.filter_errors({"binary(a)": 3, JUNCTION: 2})
        self.assertEqual(len(errors), 1)
        self.assertIn("drop it from PLATFORM_ONLY", errors[0])


class GroupLiveness(unittest.TestCase):
    PLAN = {1: ("binary(a)", "count:1/1"), 2: ("all()", "count:1/2"), 3: ("all()", "count:2/2")}

    def test_every_group_selecting_a_test_passes(self) -> None:
        self.assertEqual(ec.group_errors(self.PLAN, {1: ["a x"], 2: [], 3: ["b y"]}), [])

    def test_a_group_selecting_nothing_is_refused(self) -> None:
        errors = ec.group_errors(self.PLAN, {1: [], 2: ["b y"], 3: []})
        self.assertEqual(len(errors), 1)
        self.assertIn("binary(a)", errors[0])


class Cover(unittest.TestCase):
    """`cover` end to end over a stubbed archive listing."""

    LISTINGS = {
        (): ["b x", "a y", "a z"],
        ("-E", "binary(a)", "--partition", "count:1/1"): ["a y", "a z"],
        ("-E", "not binary(a)", "--partition", "count:1/1"): ["b x"],
        ("-E", "binary(a)"): ["a y", "a z"],
        ("-E", "binary(a) & test(=m::t)"): ["a y"],
        ("-E", JUNCTION): [],
    }
    PLAN = json.dumps({"1": {"filter": "binary(a)", "partition": "count:1/1"}, "2": {"filter": "not binary(a)", "partition": "count:1/1"}})

    def run_cover(self, listings: dict[tuple[str, ...], list[str]]) -> tuple[int, str, str]:
        old_list, old_config, cwd = ec._list, ec.NEXTEST_CONFIG, os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            config = os.path.join(tmp, "nextest.toml")
            with open(config, "w", encoding="utf-8") as handle:
                handle.write(CONFIG)
            ec._list = lambda extra: listings[tuple(extra)]
            ec.NEXTEST_CONFIG = config
            os.chdir(tmp)
            err = io.StringIO()
            try:
                with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                    code = ec.cover(self.PLAN)
                with open(ec.TEST_IDS_FILE, encoding="utf-8") as handle:
                    ids = handle.read()
            finally:
                ec._list, ec.NEXTEST_CONFIG = old_list, old_config
                os.chdir(cwd)
        return code, ids, err.getvalue()

    def test_a_live_tree_passes_and_writes_the_sorted_ids(self) -> None:
        code, ids, err = self.run_cover(self.LISTINGS)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(ids, "a y\na z\nb x\n")

    def test_a_dead_override_fails_the_cover(self) -> None:
        listings = {**self.LISTINGS, ("-E", "binary(a) & test(=m::t)"): []}
        code, _, err = self.run_cover(listings)
        self.assertEqual(code, 1)
        self.assertIn("test(=m::t)", err)


if __name__ == "__main__":
    unittest.main()
