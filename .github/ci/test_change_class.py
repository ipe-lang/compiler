#!/usr/bin/env python3
"""Refusal proofs for `change_class.py`, the fail-closed CI change classifier.

Every way a scope must be forced to run (an unknown path, an unreadable or
empty diff, a non-PR event, a crash) and every way the PROSE-set guard must
refuse (a reader of a PROSE path, a crate under it, a foreign path filter) gets
its own test, per PRINCIPLES.md "Prove the refusals". Pure stdlib `unittest`
plus the `git` CLI; each diff test builds a scratch repository.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))

_spec = importlib.util.spec_from_file_location("change_class", os.path.join(HERE, "change_class.py"))
assert _spec is not None and _spec.loader is not None
cc = importlib.util.module_from_spec(_spec)
sys.modules["change_class"] = cc
_spec.loader.exec_module(cc)

ALL_SCOPES = tuple(cc.SCOPES)


def _git(root: str, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
    }
    return subprocess.run(
        ["git", "-C", root, *args], check=True, capture_output=True, text=True, env=env
    ).stdout.strip()


def _write(root: str, rel: str, text: str = "x\n") -> None:
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)


class PrRepo:
    """A scratch repo whose HEAD is the base + PR-head merge commit CI checks out."""

    def __init__(self, changed: dict[str, str]) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        _git(self.root, "init", "-q", "-b", "main")
        _write(self.root, "README.md")
        _git(self.root, "add", "-A")
        _git(self.root, "commit", "-q", "-m", "base")
        self.base = _git(self.root, "rev-parse", "HEAD")
        _git(self.root, "checkout", "-q", "-b", "pr")
        for rel, text in changed.items():
            _write(self.root, rel, text)
        if changed:
            _git(self.root, "add", "-A")
            _git(self.root, "commit", "-q", "-m", "pr")
        else:
            _git(self.root, "commit", "-q", "--allow-empty", "-m", "pr")
        self.head = _git(self.root, "rev-parse", "HEAD")
        _git(self.root, "checkout", "-q", "main")
        _git(self.root, "merge", "-q", "--no-ff", "-m", "merge", "pr")

    def env(self, **extra: str) -> dict[str, str]:
        return {"EVENT_NAME": "pull_request", "PR_HEAD_SHA": self.head, **extra}

    def close(self) -> None:
        self._tmp.cleanup()


class ClassifyTest(unittest.TestCase):
    def classify(self, changed: dict[str, str], **env: str) -> dict[str, bool]:
        repo = PrRepo(changed)
        self.addCleanup(repo.close)
        return cc.classify(repo.root, {**repo.env(), **env}, ALL_SCOPES)

    def test_prose_only_pr_skips_every_scope(self) -> None:
        result = self.classify({"docs/adr/0999-x.md": "a\n", "CONTRIBUTING.md": "b\n", "misc/n.md": "c\n"})
        self.assertEqual(result, dict.fromkeys(ALL_SCOPES, False))

    def test_unlisted_ci_input_runs_every_scope(self) -> None:
        for path in ("tools/e2e-support/src/lib.rs", ".config/nextest.toml", "tests/x.rs", "examples/a/Main.ipe"):
            with self.subTest(path=path):
                self.assertEqual(self.classify({path: "x\n"}), dict.fromkeys(ALL_SCOPES, True))

    def test_unknown_top_level_path_runs_every_scope(self) -> None:
        self.assertEqual(self.classify({"brand-new-dir/thing.txt": "x\n"}), dict.fromkeys(ALL_SCOPES, True))

    def test_read_markdown_is_not_prose(self) -> None:
        for path in ("README.md", "AGENTS.md", "PRINCIPLES.md", "docs/constructs/let.md", "CHANGELOG.md"):
            with self.subTest(path=path):
                self.assertTrue(self.classify({path: "changed\n"})["code"])

    def test_narrow_scope_skips_only_on_an_unrelated_scoped_root(self) -> None:
        result = self.classify({"src/ipe-fmt/src/lib.rs": "x\n"})
        self.assertTrue(result["code"])
        self.assertTrue(result["panic_scan"])
        self.assertTrue(result["playground"])
        self.assertFalse(result["emit"])
        self.assertFalse(result["sanitize"])
        self.assertFalse(result["wasm"])
        self.assertFalse(result["editors"])
        self.assertFalse(result["grammar"])

    def test_narrow_scope_runs_on_its_pattern(self) -> None:
        self.assertTrue(self.classify({"src/runtime/rust/src/lib.rs": "x\n"})["emit"])
        self.assertTrue(self.classify({"editors/tree-sitter-ipe/grammar.js": "x\n"})["grammar"])
        self.assertTrue(self.classify({"src/stdlib/Ipe/List.ipe": "x\n"})["grammar"])

    def test_runtime_closure_forces_every_runtime_scope(self) -> None:
        # The runtime compiles against these crates, so each runtime tier runs.
        for path in ("src/compiler/diagnostics/src/lib.rs", "src/compiler/path-core/src/lib.rs"):
            with self.subTest(path=path):
                result = self.classify({path: "x\n"})
                self.assertTrue(result["emit"])
                self.assertTrue(result["sanitize"])
                self.assertTrue(result["wasm"])

    def test_sanitize_covers_its_crates_beyond_emit(self) -> None:
        for path in ("src/compiler/canon/src/lib.rs", "src/compiler/ffi/src/lib.rs", "src/compiler/fs_open/src/lib.rs", "src/ffi-bindgen-macro/src/lib.rs"):
            with self.subTest(path=path):
                result = self.classify({path: "x\n"})
                self.assertTrue(result["sanitize"])
                self.assertFalse(result["emit"])

    def test_empty_diff_runs_every_scope(self) -> None:
        self.assertEqual(self.classify({}), dict.fromkeys(ALL_SCOPES, True))

    def test_wrong_pr_head_runs_every_scope(self) -> None:
        result = self.classify({"misc/n.md": "x\n"}, PR_HEAD_SHA="0" * 40)
        self.assertEqual(result, dict.fromkeys(ALL_SCOPES, True))

    def test_missing_pr_head_runs_every_scope(self) -> None:
        result = self.classify({"misc/n.md": "x\n"}, PR_HEAD_SHA="")
        self.assertEqual(result, dict.fromkeys(ALL_SCOPES, True))

    def test_non_merge_head_runs_every_scope(self) -> None:
        repo = PrRepo({"misc/n.md": "x\n"})
        self.addCleanup(repo.close)
        _git(repo.root, "checkout", "-q", repo.head)
        result = cc.classify(repo.root, repo.env(), ALL_SCOPES)
        self.assertEqual(result, dict.fromkeys(ALL_SCOPES, True))

    def test_non_pr_event_runs_every_scope(self) -> None:
        for event in ("push", "schedule", "workflow_dispatch", ""):
            with self.subTest(event=event):
                result = self.classify({"misc/n.md": "x\n"}, EVENT_NAME=event)
                self.assertEqual(result, dict.fromkeys(ALL_SCOPES, True))

    def test_merge_group_without_base_runs_every_scope(self) -> None:
        result = self.classify({"misc/n.md": "x\n"}, EVENT_NAME="merge_group")
        self.assertEqual(result, dict.fromkeys(ALL_SCOPES, True))

    def test_merge_group_with_unfetched_base_runs_every_scope(self) -> None:
        result = self.classify({"misc/n.md": "x\n"}, EVENT_NAME="merge_group", MERGE_GROUP_BASE_SHA="1" * 40)
        self.assertEqual(result, dict.fromkeys(ALL_SCOPES, True))

    def test_merge_group_prose_only_skips(self) -> None:
        repo = PrRepo({"misc/n.md": "x\n"})
        self.addCleanup(repo.close)
        env = {"EVENT_NAME": "merge_group", "MERGE_GROUP_BASE_SHA": repo.base}
        self.assertFalse(cc.classify(repo.root, env, ("code",))["code"])

    def test_unreadable_repository_runs_every_scope(self) -> None:
        with tempfile.TemporaryDirectory() as empty:
            result = cc.classify(empty, {"EVENT_NAME": "pull_request", "PR_HEAD_SHA": "a"}, ALL_SCOPES)
        self.assertEqual(result, dict.fromkeys(ALL_SCOPES, True))

    def test_classifier_crash_runs_every_scope(self) -> None:
        with mock.patch.object(cc, "read_diff", side_effect=RuntimeError("boom")):
            result = cc.classify(REPO, {}, ALL_SCOPES)
        self.assertEqual(result, dict.fromkeys(ALL_SCOPES, True))

    def test_unknown_scope_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            cc.classify(REPO, {}, ("code", "no-such-scope"))


class ScopeFlagsTest(unittest.TestCase):
    def test_every_scope_has_its_flag(self) -> None:
        flags = ["--" + s.replace("_", "-") for s in ALL_SCOPES]
        self.assertEqual(cc.scope_flags(flags), ALL_SCOPES)
        self.assertEqual(cc.scope_flags(["--panic-scan"]), ("panic_scan",))

    def test_malformed_scope_flags_are_refused(self) -> None:
        for argv in (
            [],
            ["code"],
            ["-code"],
            ["--panic_scan"],
            ["--Code"],
            ["--no-such-scope"],
            ["--code", "--code"],
            ["--code", "classify"],
            ["--code="],
        ):
            with self.subTest(argv=argv):
                self.assertIsNone(cc.scope_flags(argv))

    def test_usage_error_exits_nonzero_and_writes_no_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": out}), mock.patch("sys.stderr"):
                self.assertEqual(cc.main(["classify", "code"]), 2)
            self.assertFalse(os.path.exists(out))


class ProseGuardToolTest(unittest.TestCase):
    """`prose_guard.py`, the verdict tool over `guard()`."""

    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location("prose_guard", os.path.join(HERE, "prose_guard.py"))
        assert spec is not None and spec.loader is not None
        self.pg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.pg)

    def test_guard_error_fails_the_verdict(self) -> None:
        with mock.patch.object(self.pg.change_class, "guard", return_value=["a reader"]), mock.patch("sys.stderr"):
            self.assertEqual(self.pg.main([]), 1)

    def test_sound_set_passes(self) -> None:
        with mock.patch.object(self.pg.change_class, "guard", return_value=[]), mock.patch("sys.stdout"):
            self.assertEqual(self.pg.main([]), 0)

    def test_any_argument_is_refused(self) -> None:
        with mock.patch("sys.stderr"):
            self.assertEqual(self.pg.main(["guard"]), 2)


class GlobTest(unittest.TestCase):
    def test_star_stays_within_one_segment(self) -> None:
        self.assertIsNone(cc.glob_regex("src/*.rs").match("src/a/b.rs"))
        self.assertIsNotNone(cc.glob_regex("src/**/*.rs").match("src/b.rs"))
        self.assertIsNotNone(cc.glob_regex("src/**/*.rs").match("src/a/b.rs"))
        self.assertIsNone(cc.glob_regex("src/**/*.rs").match("src/a/b.rsx"))


class GuardTest(unittest.TestCase):
    """The guard, run over a scratch tree seeded with the real scope targets."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        self.files: list[str] = []
        for pattern in (p for ps in cc.SCOPES.values() for p in ps):
            stem = pattern.replace("**/", "").replace("**", "f").replace("*", "x")
            self.add(stem if "." in os.path.basename(stem) else stem + ".rs")
        self.add("docs/adr/0001-a.md", "prose\n")
        self.add("misc/notes.md", "prose\n")

    def add(self, rel: str, text: str = "x\n") -> None:
        _write(self.root, rel, text)
        self.files.append(rel)

    def errors(self) -> list[str]:
        return cc.guard(self.root, self.files)

    def assert_refused(self, fragment: str) -> None:
        errors = self.errors()
        self.assertTrue(any(fragment in e for e in errors), errors)

    def test_clean_tree_passes(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_real_tree_passes(self) -> None:
        self.assertEqual(cc.guard(REPO, cc.tracked_files(REPO)), [])

    def test_crate_under_prose_is_refused(self) -> None:
        self.add("misc/tool/Cargo.toml", "[package]\n")
        self.assert_refused("crate 'misc/tool'")

    def test_include_str_into_prose_is_refused(self) -> None:
        self.add("src/a/src/lib.rs", 'const T: &str = include_str!("../../../misc/notes.md");\n')
        self.assert_refused("includes 'misc/notes.md'")

    def test_manifest_dir_include_into_prose_is_refused(self) -> None:
        self.add("src/a/Cargo.toml", "[package]\n")
        self.add(
            "src/a/src/lib.rs",
            'static D: Dir = include_dir!("$CARGO_MANIFEST_DIR/../../docs/adr");\n',
        )
        self.assert_refused("includes 'docs/adr'")

    def test_concat_manifest_dir_include_into_prose_is_refused(self) -> None:
        self.add("src/a/Cargo.toml", "[package]\n")
        self.add(
            "src/a/src/lib.rs",
            'const T: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../CONTRIBUTING.md"));\n',
        )
        self.assert_refused("includes 'CONTRIBUTING.md'")

    def test_drift_check_over_prose_is_refused(self) -> None:
        self.add(".github/workflows/w.yml", "      - run: tools/scripts/generated-unchanged.sh docs/adr/\n")
        self.assert_refused("drift check reads 'docs/adr/'")

    def test_drift_check_over_a_prose_ancestor_is_refused_in_every_spelling(self) -> None:
        for line in (
            "      - run: tools/scripts/generated-unchanged.sh docs/\n",
            "      - run: ./tools/scripts/generated-unchanged.sh docs/reference/x.md ./docs\n",
            "        - 'tools/scripts/generated-unchanged.sh \"docs/\"'\n",
            "  bash -c 'tools/scripts/generated-unchanged.sh docs/'\n",
            "      - run: git --no-pager diff --exit-code -- docs/\n",
            "      - run: git -C . diff --quiet docs/\n",
            "      - run: git diff-index --quiet HEAD -- docs\n",
        ):
            with self.subTest(line=line):
                self.add(".github/workflows/w.yml", line)
                self.assert_refused("drift check reads")

    def test_drift_check_off_prose_passes(self) -> None:
        self.add(".github/workflows/w.yml", "      - run: tools/scripts/generated-unchanged.sh docs/reference/x.md\n")
        self.assertEqual(self.errors(), [])

    def test_script_naming_prose_is_refused(self) -> None:
        self.add("tools/read.sh", "cat LICENSE\n")
        self.assert_refused("names PROSE entry 'LICENSE'")

    def test_commented_mention_is_not_a_reader(self) -> None:
        self.add("tools/read.sh", "# see LICENSE\n")
        self.assertEqual(self.errors(), [])

    def test_non_prose_file_type_under_prose_dir_is_refused(self) -> None:
        self.add("misc/gen.py", "print(1)\n")
        self.assert_refused("'misc/gen.py' under PROSE")

    def test_dead_scope_pattern_is_refused(self) -> None:
        with mock.patch.dict(cc.SCOPES, {"emit": ("src/nowhere/**",)}):
            self.assert_refused("pattern 'src/nowhere/**' matches no tracked file")

    def test_scope_pattern_outside_scoped_roots_is_refused(self) -> None:
        with mock.patch.dict(cc.SCOPES, {"emit": ("tools/**",)}):
            self.assert_refused("pattern 'tools/**' lies outside SCOPED_ROOTS")

    def test_ci_consumed_path_in_prose_is_refused(self) -> None:
        with mock.patch.object(cc, "PROSE_FILES", cc.PROSE_FILES | {"README.md"}):
            self.assert_refused("CI-consumed path 'README.md'")

    def test_ci_consumed_dir_in_prose_is_refused(self) -> None:
        with mock.patch.object(cc, "PROSE_DIRS", (*cc.PROSE_DIRS, "tools/")):
            self.assert_refused("CI-consumed path 'tools/'")

    def test_foreign_path_filter_is_refused(self) -> None:
        self.add(".github/workflows/w.yml", "      - uses: dorny/paths-filter@v3\n")
        self.assert_refused("path filter outside change_class.py")


if __name__ == "__main__":
    unittest.main()
