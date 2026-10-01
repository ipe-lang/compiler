#!/usr/bin/env python3
"""Tests for `claims_table`: every malformed claims table is refused."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import claims_table  # noqa: E402

_CELL = """  - package: p
    target: {test: t}
    platform: wasm32-unknown-unknown
    features: [a]
    owner: j
    expect_tests: 2
"""


def _load(table: str) -> list[claims_table.Cell] | str:
    fd, path = tempfile.mkstemp(suffix=".yml")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(table)
        return claims_table.load_cells(path)
    finally:
        os.unlink(path)


class TestLoadCells(unittest.TestCase):
    def test_valid_table_loads(self) -> None:
        got = _load("cells:\n" + _CELL)
        self.assertEqual(
            got,
            [claims_table.Cell("p", "test:t", "wasm32-unknown-unknown", frozenset({"a"}), "j", 2)],
        )

    def test_bad_tables_refused(self) -> None:
        for name, table, needle in (
            ("empty", "cells: []\n", "non-empty `cells`"),
            ("extra top key", "cells:\n" + _CELL + "more: 1\n", "exactly a non-empty"),
            ("twice", "cells:\n" + _CELL + _CELL, "claimed twice"),
            ("bad target", "cells:\n" + _CELL.replace("{test: t}", "tests"), "neither `lib`"),
            ("host platform", "cells:\n" + _CELL.replace("wasm32-unknown-unknown", "x86_64-unknown-linux-gnu"), "not a wasm32 triple"),
            ("bool expect", "cells:\n" + _CELL.replace("expect_tests: 2", "expect_tests: true"), "positive integer"),
            ("zero expect", "cells:\n" + _CELL.replace("expect_tests: 2", "expect_tests: 0"), "positive integer"),
            ("feature twice", "cells:\n" + _CELL.replace("[a]", "[a, a]"), "names a feature twice"),
            ("missing key", "cells:\n" + _CELL.replace("    owner: j\n", ""), "exactly"),
            ("unknown key", "cells:\n" + _CELL + "    note: x\n", "exactly"),
            ("duplicate yaml key", "cells:\n" + _CELL + "    owner: k\n", "unreadable"),
        ):
            with self.subTest(name):
                got = _load(table)
                assert isinstance(got, str), got
                self.assertIn(needle, got)

    def test_repo_table_loads(self) -> None:
        cells = claims_table.load_cells()
        assert isinstance(cells, list), cells
        self.assertTrue(all(c.platform.startswith("wasm32-") for c in cells))


if __name__ == "__main__":
    unittest.main()
