#!/usr/bin/env python3
"""Tests for `cache_prune`: only a superseded lock generation is picked, and a
malformed input picks nothing."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cache_prune  # noqa: E402
from cache_prune import Entry, Refused  # noqa: E402

NEW = "a" * 64
OLD = "b" * 64
MAIN = "refs/heads/main"


def page(*entries: tuple[int, str, str], total: int | None = None) -> str:
    caches = [{"id": i, "key": k, "ref": r} for i, k, r in entries]
    return json.dumps({"total_count": len(caches) if total is None else total, "actions_caches": caches})


def line(eid: int, key: str, ref: str = MAIN) -> str:
    return page((eid, key, ref))


class TestSuperseded(unittest.TestCase):
    def picked(self, *entries: Entry) -> list[int]:
        return [e.id for e in cache_prune.superseded(list(entries), NEW)]

    def test_old_generation_beside_a_current_one_is_picked(self) -> None:
        self.assertEqual(
            self.picked(Entry(1, f"Linux-static-dlmalloc-{NEW}", MAIN), Entry(2, f"Linux-static-dlmalloc-{OLD}", MAIN)),
            [2],
        )

    def test_family_without_a_current_entry_keeps_its_old_one(self) -> None:
        self.assertEqual(self.picked(Entry(1, f"freebsd-cross-{OLD}", MAIN)), [])

    def test_families_are_judged_apart(self) -> None:
        self.assertEqual(
            self.picked(
                Entry(1, f"Linux-static-dlmalloc-{NEW}", MAIN),
                Entry(2, f"Linux-static-mimalloc-{OLD}", MAIN),
                Entry(3, f"Linux-static-dlmalloc-{OLD}", MAIN),
            ),
            [3],
        )

    def test_entries_off_main_are_never_picked(self) -> None:
        self.assertEqual(
            self.picked(Entry(1, f"Linux-cfree-{NEW}", MAIN), Entry(2, f"Linux-cfree-{OLD}", "refs/pull/7/merge")),
            [],
        )

    def test_keys_without_a_lock_hash_are_never_picked(self) -> None:
        self.assertEqual(
            self.picked(
                Entry(1, f"x-{NEW}", MAIN),
                Entry(2, "x-deadbeef", MAIN),
                Entry(3, "v0-rust-quick-check-Linux-x64-0123abcd-4567ef01", MAIN),
                Entry(4, f"x-{OLD.upper()}", MAIN),
            ),
            [],
        )

    def test_current_entry_is_never_picked(self) -> None:
        self.assertEqual(self.picked(Entry(1, f"windows-static-dlmalloc-{NEW}", MAIN)), [])


class TestRefusals(unittest.TestCase):
    def test_malformed_locks_are_refused(self) -> None:
        for bad in ("", "a" * 63, "a" * 65, "A" * 64, "g" * 64, NEW + "\n"):
            with self.subTest(bad=bad), self.assertRaises(Refused):
                cache_prune.parse_lock(bad)

    def test_malformed_listings_are_refused(self) -> None:
        for bad in (
            "not json",
            "[]",
            json.dumps({"actions_caches": []}),
            json.dumps({"total_count": 0, "actions_caches": [], "extra": 0}),
            json.dumps({"total_count": True, "actions_caches": []}),
            json.dumps({"total_count": -1, "actions_caches": []}),
            json.dumps({"total_count": 1, "actions_caches": {}}),
            json.dumps({"total_count": 1, "actions_caches": [{"id": 1, "key": "k"}]}),
            json.dumps({"total_count": 1, "actions_caches": [{"id": 1, "key": "k", "ref": MAIN, "x": 0}]}),
            json.dumps({"total_count": 1, "actions_caches": [{"id": "1", "key": "k", "ref": MAIN}]}),
            json.dumps({"total_count": 1, "actions_caches": [{"id": True, "key": "k", "ref": MAIN}]}),
            json.dumps({"total_count": 1, "actions_caches": [{"id": 0, "key": "k", "ref": MAIN}]}),
            json.dumps({"total_count": 1, "actions_caches": [{"id": 1, "key": "", "ref": MAIN}]}),
            json.dumps({"total_count": 1, "actions_caches": [{"id": 1, "key": "k", "ref": None}]}),
            page((1, "a", MAIN), total=2) + "\n" + page((1, "b", MAIN), total=2),
        ):
            with self.subTest(bad=bad), self.assertRaises(Refused):
                cache_prune.parse_listing(bad)

    def test_partial_listing_is_refused(self) -> None:
        # A page short of its total_count: a page was lost or the cache changed.
        with self.assertRaises(Refused):
            cache_prune.parse_listing(page((1, f"k-{NEW}", MAIN), (2, f"k-{OLD}", MAIN), total=3))
        # Pages that disagree on total_count: an entry appeared mid-listing.
        with self.assertRaises(Refused):
            cache_prune.parse_listing(page((1, f"k-{NEW}", MAIN), total=2) + "\n" + page((2, f"k-{OLD}", MAIN), total=3))

    def test_full_listing_over_pages_loads(self) -> None:
        text = page((1, f"k-{NEW}", MAIN), total=2) + "\n" + page((2, f"k-{OLD}", MAIN), total=2)
        self.assertEqual([e.id for e in cache_prune.parse_listing(text)], [1, 2])

    def test_listing_past_its_ceilings_is_refused(self) -> None:
        over = [(i, "k", MAIN) for i in range(1, cache_prune.MAX_ENTRIES + 2)]
        with self.assertRaises(Refused):
            cache_prune.parse_listing(page(*over))
        with self.assertRaises(Refused):
            cache_prune.parse_listing(" " * (cache_prune.MAX_LISTING_BYTES + 1))

    def test_listing_at_its_entry_ceiling_loads(self) -> None:
        at = [(i, "k", MAIN) for i in range(1, cache_prune.MAX_ENTRIES + 1)]
        self.assertEqual(len(cache_prune.parse_listing(page(*at))), cache_prune.MAX_ENTRIES)

    def test_empty_listing_picks_nothing(self) -> None:
        self.assertEqual(cache_prune.superseded(cache_prune.parse_listing(""), NEW), [])
        self.assertEqual(cache_prune.superseded(cache_prune.parse_listing(page()), NEW), [])


SHA = "c" * 40


class TestMain(unittest.TestCase):
    def setUp(self) -> None:
        fd, self.out = tempfile.mkstemp()
        os.close(fd)
        self.replies: dict[str, str | Refused] = {}
        self.calls: list[list[str]] = []
        self._gh = cache_prune._gh

        def fake(args: list[str]) -> str:
            self.calls.append(args)
            path = next(a for a in args if a.startswith("repos/"))
            reply = self.replies[path.split("?")[0]]
            if isinstance(reply, Refused):
                raise reply
            return reply

        cache_prune._gh = fake

    def tearDown(self) -> None:
        cache_prune._gh = self._gh
        os.unlink(self.out)

    def env(self, **over: str) -> dict[str, str]:
        base = {"REPO": "o/r", "GITHUB_SHA": SHA, "CACHE_LOCK": NEW, "GITHUB_OUTPUT": self.out}
        base.update(over)
        return base

    def output(self) -> str:
        with open(self.out, encoding="utf-8") as f:
            return f.read()

    def serve(self, head: str, listing: str | Refused) -> None:
        self.replies["repos/o/r/commits/main"] = head + "\n"
        self.replies["repos/o/r/actions/caches"] = listing

    def test_superseded_ids_are_written(self) -> None:
        self.serve(SHA, page((1, f"k-{NEW}", MAIN), (2, f"k-{OLD}", MAIN), (3, f"j-{OLD}", MAIN)))
        self.assertEqual(cache_prune.main([], self.env()), 0)
        self.assertEqual(self.output(), "ids=2\n")
        listing_args = self.calls[-1]
        self.assertIn("--paginate", listing_args)
        self.assertIn(f"repos/o/r/actions/caches?ref={MAIN}&per_page=100", listing_args)

    def test_moved_head_deletes_nothing_and_skips_the_listing(self) -> None:
        self.serve("d" * 40, page((1, f"k-{NEW}", MAIN), (2, f"k-{OLD}", MAIN)))
        self.assertEqual(cache_prune.main([], self.env()), 0)
        self.assertEqual(self.output(), "ids=\n")
        self.assertEqual(len(self.calls), 1)

    def test_refusals_delete_nothing(self) -> None:
        cases = (
            (self.env(CACHE_LOCK="nope"), page()),
            (self.env(REPO="o/r; rm"), page()),
            (self.env(GITHUB_SHA="HEAD"), page()),
            (self.env(), "garbage"),
            (self.env(), page((1, f"k-{NEW}", MAIN), (2, f"k-{OLD}", MAIN), total=3)),
            (self.env(), Refused("gh api exited 1")),
        )
        for env, listing in cases:
            with self.subTest(env=env, listing=listing):
                open(self.out, "w").close()
                self.serve(SHA, listing)
                self.assertEqual(cache_prune.main([], env), 0)
                self.assertEqual(self.output(), "ids=\n")

    def test_failed_head_lookup_deletes_nothing(self) -> None:
        self.replies["repos/o/r/commits/main"] = Refused("gh api exited 1")
        self.assertEqual(cache_prune.main([], self.env()), 0)
        self.assertEqual(self.output(), "ids=\n")

    def test_unwritable_output_exits_one(self) -> None:
        self.serve(SHA, page())
        self.assertEqual(cache_prune.main([], self.env(GITHUB_OUTPUT="")), 1)
        self.assertEqual(cache_prune.main([], self.env(GITHUB_OUTPUT="/nonexistent/dir/out")), 1)

    def test_arguments_are_refused(self) -> None:
        self.assertEqual(cache_prune.main(["--lock", NEW], self.env()), 2)
        self.assertEqual(self.output(), "")


if __name__ == "__main__":
    unittest.main()
