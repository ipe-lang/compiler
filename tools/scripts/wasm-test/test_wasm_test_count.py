#!/usr/bin/env python3
"""Tests for `wasm_test_count`: the runner count proof and every count it refuses."""

from __future__ import annotations

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import wasm_test_count  # noqa: E402

_OK = "running 2 tests\ntest a ... ok\ntest b ... ok\n\ntest result: ok. 2 passed; 0 failed; 0 ignored\n"


def _run(argv: list[str], stdin: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = wasm_test_count.main(argv, io.StringIO(stdin), out, err)
    return code, out.getvalue(), err.getvalue()


class TestCount(unittest.TestCase):
    def test_exact_count_passes_and_echoes(self) -> None:
        code, out, err = _run(["2"], _OK)
        self.assertEqual(code, 0, err)
        self.assertEqual(out, _OK)
        self.assertIn("2 passed, as claimed", err)

    def test_refusals(self) -> None:
        for name, stdin, needle in (
            ("zero", "test result: ok. 0 passed; 0 failed; 0 ignored\n", "0 test(s) passed, but the cell claims 2"),
            ("missing", "running 2 tests\n", "no `test result:` line"),
            ("empty", "", "no `test result:` line"),
            ("short", "test result: ok. 1 passed; 0 failed;\n", "1 test(s) passed, but the cell claims 2"),
            ("long", "test result: ok. 3 passed; 0 failed;\n", "3 test(s) passed, but the cell claims 2"),
            ("failed", "test result: FAILED. 2 passed; 1 failed;\n", "1 test(s) failed"),
            ("two", _OK + _OK, "2 `test result:` lines"),
            ("oversized", "x" * (wasm_test_count.MAX_LINE + 1) + "test result: ok. 2 passed; 0 failed;\n", "no `test result:`"),
        ):
            with self.subTest(name):
                code, _, err = _run(["2"], stdin)
                self.assertEqual(code, 1, err)
                self.assertIn(needle, err)

    def test_bad_arguments_refused(self) -> None:
        for argv in ([], ["2", "3"], ["0"], ["-2"], ["02"], ["2x"], ["x"], ["1234567"], ["²"]):
            with self.subTest(argv=argv):
                code, out, err = _run(argv, _OK)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn("usage", err)


if __name__ == "__main__":
    unittest.main()
