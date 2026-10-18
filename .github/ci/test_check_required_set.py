#!/usr/bin/env python3
"""Refusal proofs for `check_required_set.py`'s live-ruleset parse: the
merge-queue pins.

Every `merge_queue` parameter the parse reads is pinned by `MERGE_QUEUE`, so a
live queue changed by hand fails `--fetch`, `--fetch-admin` and `--live`. Each
parameter one step off its pin, retyped, missing, or joined by an unknown one
gets its own refusal (PRINCIPLES.md "Prove the refusals"); a positive control
pins the ruleset that must pass, and `render_put` is shown to write the pins.

Pure stdlib `unittest` plus the module's own imports, no network.
"""

from __future__ import annotations

import copy
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_required_set as crs  # noqa: E402

PAIRS = [("artifact-guard", crs.GITHUB_ACTIONS_APP_ID), ("fmt", crs.GITHUB_ACTIONS_APP_ID)]


def _ruleset(queue: dict | None = None) -> dict:
    """An admin-read ruleset GET body the parse accepts, its queue parameters
    `queue` (default: `MERGE_QUEUE`)."""
    return {
        "id": crs.RULESET_ID,
        "name": "main-protection",
        "target": "branch",
        "source_type": "Repository",
        "source": "ipe-lang/compiler",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 0,
                    "dismiss_stale_reviews_on_push": False,
                    "required_reviewers": [],
                    "require_code_owner_review": False,
                    "dismissal_restriction": {},
                    "require_last_push_approval": False,
                    "required_review_thread_resolution": False,
                    "require_extra_approval_for_unattributed_changes": False,
                    "allowed_merge_methods": ["squash"],
                },
            },
            {"type": "merge_queue", "parameters": dict(crs.MERGE_QUEUE if queue is None else queue)},
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": False,
                    "do_not_enforce_on_create": False,
                    "required_status_checks": [{"context": c, "integration_id": a} for c, a in PAIRS],
                },
            },
        ],
        "bypass_actors": [],
        "current_user_can_bypass": "never",
    }


def _queue_of(body: dict) -> dict:
    (rule,) = [r for r in body["rules"] if r["type"] == "merge_queue"]
    return rule["parameters"]


def _off_by_one(value: object) -> object:
    """A value of the same JSON type one step from `value`."""
    if type(value) is int:
        return value + 1
    if type(value) is str:
        return value + "X"
    raise AssertionError(f"MERGE_QUEUE holds {value!r}, a type this suite cannot step")


class QueuePins(unittest.TestCase):
    def assertRefused(self, body: dict, needle: str) -> None:
        for admin_read in (False, True):
            with self.subTest(admin_read=admin_read), self.assertRaises(crs.Refused) as cm:
                crs.parse_ruleset(body, admin_read=admin_read)
            self.assertIn(needle, str(cm.exception))

    def test_the_pinned_queue_passes(self) -> None:
        for admin_read in (False, True):
            got = crs.parse_ruleset(_ruleset(), admin_read=admin_read)
            self.assertEqual(list(got.required), PAIRS)

    def test_the_pin_table_holds_every_live_queue_parameter(self) -> None:
        # The seven parameters GitHub returns for a `merge_queue` rule.
        self.assertEqual(
            set(crs.MERGE_QUEUE),
            {
                "merge_method",
                "max_entries_to_build",
                "min_entries_to_merge",
                "max_entries_to_merge",
                "min_entries_to_merge_wait_minutes",
                "grouping_strategy",
                "check_response_timeout_minutes",
            },
        )

    def test_the_pin_table_covers_the_parse_table(self) -> None:
        # Every parameter the parse admits is pinned: dropping any one pin
        # leaves a queue the parse refuses for a missing key, never one it
        # admits unread, and an admitted parameter outside the table is
        # refused as unexamined.
        for key in crs.MERGE_QUEUE:
            with self.subTest(key=key):
                queue = {k: v for k, v in crs.MERGE_QUEUE.items() if k != key}
                self.assertRefused(_ruleset(queue), f"lacks {key}")

    def test_each_parameter_one_step_off_its_pin_is_refused(self) -> None:
        for key, want in crs.MERGE_QUEUE.items():
            with self.subTest(key=key):
                queue = dict(crs.MERGE_QUEUE) | {key: _off_by_one(want)}
                self.assertRefused(_ruleset(queue), f"merge_queue rule's {key} is")

    def test_each_integer_parameter_one_step_below_its_pin_is_refused(self) -> None:
        for key, want in crs.MERGE_QUEUE.items():
            if type(want) is int:
                with self.subTest(key=key):
                    queue = dict(crs.MERGE_QUEUE) | {key: want - 1}
                    self.assertRefused(_ruleset(queue), f"merge_queue rule's {key} is")

    def test_each_parameter_retyped_with_an_equal_value_is_refused(self) -> None:
        # `True == 1` and `2.0 == 2` in Python; the JSON type is part of the pin.
        for key, want in crs.MERGE_QUEUE.items():
            if type(want) is int:
                retyped: list[object] = [float(want), str(want)] + ([True] if want == 1 else [])
            else:
                retyped = [[want], None]
            for value in retyped:
                with self.subTest(key=key, value=value):
                    queue = dict(crs.MERGE_QUEUE) | {key: value}
                    self.assertRefused(_ruleset(queue), f"merge_queue rule's {key} is")

    def test_headgreen_grouping_is_refused(self) -> None:
        queue = dict(crs.MERGE_QUEUE) | {"grouping_strategy": "HEADGREEN"}
        self.assertRefused(_ruleset(queue), "grouping_strategy is 'HEADGREEN'")

    def test_a_missing_parameter_is_refused(self) -> None:
        queue = {k: v for k, v in crs.MERGE_QUEUE.items() if k != "max_entries_to_build"}
        self.assertRefused(_ruleset(queue), "lacks max_entries_to_build")

    def test_an_unknown_parameter_is_refused(self) -> None:
        queue = dict(crs.MERGE_QUEUE) | {"max_entries_to_queue": 10}
        self.assertRefused(_ruleset(queue), "carries max_entries_to_queue, which this check does not examine")

    def test_a_queue_rule_without_parameters_is_refused(self) -> None:
        body = _ruleset()
        body["rules"] = [r for r in body["rules"] if r["type"] != "merge_queue"] + [{"type": "merge_queue"}]
        self.assertRefused(body, "lacks parameters")

    def test_a_ruleset_without_a_queue_is_refused(self) -> None:
        body = _ruleset()
        body["rules"] = [r for r in body["rules"] if r["type"] != "merge_queue"]
        self.assertRefused(body, "0 merge_queue rules, not 1")


class RenderPutWritesThePins(unittest.TestCase):
    def test_a_drifted_queue_is_rendered_back_to_the_pins(self) -> None:
        drifted = dict(crs.MERGE_QUEUE) | {"max_entries_to_build": 5, "grouping_strategy": "HEADGREEN"}
        body = json.loads(crs.render_put(_ruleset(drifted), PAIRS))
        self.assertEqual(_queue_of(body), crs.MERGE_QUEUE)
        crs.parse_ruleset({**body, "id": crs.RULESET_ID}, admin_read=True)

    def test_a_queue_missing_a_parameter_is_rendered_with_it(self) -> None:
        queue = {k: v for k, v in crs.MERGE_QUEUE.items() if k != "merge_method"}
        body = json.loads(crs.render_put(_ruleset(queue), PAIRS))
        self.assertEqual(_queue_of(body), crs.MERGE_QUEUE)

    def test_an_unknown_queue_parameter_is_still_refused(self) -> None:
        queue = dict(crs.MERGE_QUEUE) | {"max_entries_to_queue": 10}
        with self.assertRaises(crs.Refused) as cm:
            crs.render_put(_ruleset(queue), PAIRS)
        self.assertIn("max_entries_to_queue", str(cm.exception))

    def test_render_put_leaves_its_input_unchanged(self) -> None:
        drifted = dict(crs.MERGE_QUEUE) | {"max_entries_to_merge": 5}
        rs = _ruleset(drifted)
        before = copy.deepcopy(rs)
        crs.render_put(rs, PAIRS)
        self.assertEqual(rs, before)


class ReconciliationBlock(unittest.TestCase):
    def test_the_documented_queue_block_is_the_pin_table(self) -> None:
        with open(os.path.join(HERE, "RECONCILIATION.md"), encoding="utf-8") as f:
            text = f.read()
        blocks = [b for b in re.findall(r"```json\n(.*?)```", text, re.S) if '"grouping_strategy"' in b]
        self.assertEqual(len(blocks), 1, "RECONCILIATION.md must carry exactly one queue block")
        self.assertEqual(json.loads(blocks[0]), crs.MERGE_QUEUE)


if __name__ == "__main__":
    unittest.main()
