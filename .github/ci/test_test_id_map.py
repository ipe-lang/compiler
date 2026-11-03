#!/usr/bin/env python3
"""Refusal proofs for `tools/scripts/test-id-map.py`, the acceptance check of a
test-binary consolidation.

The id map must refuse a base-run test that reappears in no harness (or in
two), a new-run test that maps to no base-run test, a total that changed, a
repeated or malformed id and an empty listing; the static check must refuse a
moved or modified test file whose test count changed and a deleted test file.
Each refusal gets its own test, per PRINCIPLES.md "Prove the refusals". Pure
stdlib `unittest`.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))

_spec = importlib.util.spec_from_file_location("test_id_map", os.path.join(REPO, "tools", "scripts", "test-id-map.py"))
assert _spec is not None and _spec.loader is not None
tm = importlib.util.module_from_spec(_spec)
sys.modules["test_id_map"] = tm
_spec.loader.exec_module(tm)

BEFORE = "ipe ipe::lib_test\nipe::alpha one\nipe::alpha two\nipe::beta three\nipe::g_misc golden::x\n"
AFTER = "ipe ipe::lib_test\nipe::scans alpha::one\nipe::scans alpha::two\nipe::scans beta::three\nipe::g_misc golden::x\n"


def ids(text: str) -> list[tuple[str, str]]:
    parsed, errors = tm.read_ids(text, "t")
    assert errors == [], errors
    return parsed


class IdMap(unittest.TestCase):
    def test_a_bijection_maps_every_id(self) -> None:
        errors, moves = tm.map_ids(ids(BEFORE), ids(AFTER))
        self.assertEqual(errors, [])
        self.assertEqual(moves, {"unchanged": 2, "ipe::alpha -> ipe::scans": 2, "ipe::beta -> ipe::scans": 1})

    def test_an_unmapped_old_id_is_refused(self) -> None:
        after = AFTER.replace("ipe::scans beta::three\n", "ipe::scans gamma::three\n")
        errors, _ = tm.map_ids(ids(BEFORE), ids(after))
        self.assertTrue(any("`ipe::beta three` is in no harness" in e for e in errors), errors)
        self.assertTrue(any("`ipe::scans gamma::three` of the new run maps to no test" in e for e in errors), errors)

    def test_an_unmapped_new_id_is_refused(self) -> None:
        errors, _ = tm.map_ids(ids(BEFORE), ids(AFTER + "ipe::scans alpha::extra\n"))
        self.assertTrue(any("`ipe::scans alpha::extra` of the new run maps to no test" in e for e in errors), errors)

    def test_a_count_mismatch_is_refused(self) -> None:
        errors, _ = tm.map_ids(ids(BEFORE), ids(AFTER.replace("ipe::scans beta::three\n", "")))
        self.assertTrue(any("lists 5 tests, the new run 4" in e for e in errors), errors)

    def test_a_test_in_two_harnesses_is_refused(self) -> None:
        after = AFTER + "ipe::other beta::three\n"
        errors, _ = tm.map_ids(ids(BEFORE), ids(after))
        self.assertTrue(any("`ipe::beta three` is in 2 harnesses" in e for e in errors), errors)

    def test_a_move_across_crates_is_refused(self) -> None:
        after = AFTER.replace("ipe::scans beta::three", "ipe_db::scans beta::three")
        errors, _ = tm.map_ids(ids(BEFORE), ids(after))
        self.assertTrue(any("`ipe::beta three` is in no harness" in e for e in errors), errors)

    def test_a_duplicate_id_is_refused(self) -> None:
        _, errors = tm.read_ids(AFTER + "ipe::scans alpha::one\n", "after")
        self.assertTrue(any("listed 2 times" in e for e in errors), errors)

    def test_a_malformed_or_empty_listing_is_refused(self) -> None:
        for text in ("ipe::alpha\n", " one\n", ""):
            with self.subTest(text):
                _, errors = tm.read_ids(text, "t")
                self.assertNotEqual(errors, [])

    def test_the_cli_exits_one_on_a_refusal_and_zero_on_a_bijection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            before, after, bad = (os.path.join(tmp, n) for n in ("before.txt", "after.txt", "bad.txt"))
            for path, text in ((before, BEFORE), (after, AFTER), (bad, AFTER + "ipe::scans alpha::one\n")):
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(text)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(tm.main(["--ids", before, after]), 0)
                self.assertEqual(tm.main(["--ids", before, bad]), 1)
                self.assertEqual(tm.main(["--ids", before]), 2)


ONE = "#[test]\nfn a() {}\n"
TWO = "#[test]\nfn a() {}\n    #[tokio::test(flavor = \"multi_thread\")]\nasync fn b() {}\n"


class Static(unittest.TestCase):
    def test_counts_every_test_attribute_shape(self) -> None:
        self.assertEqual(tm.test_count(TWO), 2)
        self.assertEqual(tm.test_count("// #[test] in a comment\n#[testing]\nfn a() {}\n"), 0)

    def check(self, entries, base, head):
        return tm.static_errors(entries, base.__getitem__, head.__getitem__)

    def test_a_rename_keeping_its_tests_passes(self) -> None:
        errors, report = self.check([("R", ["c/tests/a.rs", "c/tests/h/a.rs"])], {"c/tests/a.rs": TWO}, {"c/tests/h/a.rs": TWO})
        self.assertEqual(errors, [])
        self.assertEqual(report, ["c/tests/a.rs -> c/tests/h/a.rs: 2 tests"])

    def test_a_rename_losing_a_test_is_refused(self) -> None:
        errors, _ = self.check([("R", ["c/tests/a.rs", "c/tests/h/a.rs"])], {"c/tests/a.rs": TWO}, {"c/tests/h/a.rs": ONE})
        self.assertEqual(errors, ["c/tests/a.rs -> c/tests/h/a.rs: 2 tests before, 1 after"])

    def test_a_modified_file_losing_a_test_is_refused(self) -> None:
        errors, _ = self.check([("M", ["c/tests/a.rs"])], {"c/tests/a.rs": TWO}, {"c/tests/a.rs": ONE})
        self.assertEqual(len(errors), 1)

    def test_a_deleted_test_file_is_refused(self) -> None:
        errors, _ = self.check([("D", ["c/tests/a.rs"])], {}, {})
        self.assertIn("deleted, not moved", errors[0])

    def test_a_non_test_file_is_ignored(self) -> None:
        self.assertEqual(self.check([("D", ["c/src/a.rs"]), ("M", ["README.md"])], {}, {}), ([], []))

    def test_the_static_check_reads_a_real_git_rename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            git = ["git", "-C", tmp, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]
            subprocess.run([*git, "init", "-q"], check=True)
            os.makedirs(os.path.join(tmp, "c", "tests", "h"))
            with open(os.path.join(tmp, "c", "tests", "a.rs"), "w", encoding="utf-8") as handle:
                handle.write(TWO * 8)
            subprocess.run([*git, "add", "-A"], check=True)
            subprocess.run([*git, "commit", "-qm", "base"], check=True)
            subprocess.run([*git, "mv", "c/tests/a.rs", "c/tests/h/a.rs"], check=True)
            subprocess.run([*git, "commit", "-qm", "head"], check=True)
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(tm.main(["--static", "HEAD~1", "HEAD"]), 0)
            finally:
                os.chdir(cwd)
            self.assertIn("c/tests/a.rs -> c/tests/h/a.rs: 16 tests", out.getvalue())


if __name__ == "__main__":
    unittest.main()
