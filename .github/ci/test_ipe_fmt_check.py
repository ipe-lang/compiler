#!/usr/bin/env python3
"""Tests for `tools/scripts/ipe-fmt-check.py`: drift, a timeout, an empty discovery, a missing binary and a non-Cargo `tests` exemption all fail."""

from __future__ import annotations

import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Sequence

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import strict_yaml  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SPEC = importlib.util.spec_from_file_location(
    "ipe_fmt_check", os.path.join(_REPO, "tools", "scripts", "ipe-fmt-check.py")
)
assert _SPEC is not None and _SPEC.loader is not None
ipe_fmt_check = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ipe_fmt_check)

STEP_RUN = "python3 tools/scripts/ipe-fmt-check.py"
FLOOR_JOB = "first-party-check-floor"
FLOOR_CONTEXT = "first-party check floor (ipe type-check only)"

# A stand-in `ipe` that reports drift (exit 1) for every directory named in
# $FAKE_IPE_DIRTY and is clean (exit 0) otherwise; it records each call.
FAKE_IPE = """#!/usr/bin/env python3
import os, sys
with open(os.environ["FAKE_IPE_LOG"], "a") as f:
    f.write(" ".join(sys.argv[1:]) + "\\n")
dirty = [d for d in os.environ.get("FAKE_IPE_DIRTY", "").split(":") if d]
sys.exit(1 if sys.argv[-1] in dirty else 0)
"""


def _git(root: str, *args: str) -> None:
    subprocess.run(["git", "-C", root, *args], check=True, capture_output=True)


class Repo:
    """A throwaway git repo with the given tracked files and a fake `ipe`."""

    def __init__(self, files: Sequence[str]) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self._tmp.name, "repo")
        os.makedirs(self.root)
        _git(self.root, "init", "-q")
        for rel in files:
            path = os.path.join(self.root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write("x\n")
        if files:
            _git(self.root, "add", "--", *files)
        self.ipe = os.path.join(self._tmp.name, "ipe")
        with open(self.ipe, "w") as f:
            f.write(FAKE_IPE)
        os.chmod(self.ipe, os.stat(self.ipe).st_mode | stat.S_IXUSR)
        self.log = os.path.join(self._tmp.name, "calls.log")
        open(self.log, "w").close()

    def run(self, dirty: Sequence[str] = (), ipe_bin: str | None = None) -> int:
        os.environ["FAKE_IPE_LOG"] = self.log
        os.environ["FAKE_IPE_DIRTY"] = ":".join(dirty)
        env = {"IPE_BIN": self.ipe if ipe_bin is None else ipe_bin}
        return ipe_fmt_check.main([], env, root=self.root)

    def calls(self) -> list[str]:
        with open(self.log) as f:
            return f.read().splitlines()

    def close(self) -> None:
        self._tmp.cleanup()


class TestDiscovery(unittest.TestCase):
    def test_projects_are_the_tracked_manifest_dirs_outside_tests(self) -> None:
        got = ipe_fmt_check.projects(
            [
                "Cargo.toml",
                "src/ipe-cli/Cargo.toml",
                "tools/code-review/package.ipe",
                "tools/code-review/src/Main.ipe",
                "tools/code-review/tests/Main.ipe",
                "examples/shapes/web/a/package.ipe",
                "tests/golden/x/package.ipe",
                "src/ipe-cli/tests/fixtures/y/package.ipe",
                "examples/z/package.ipe.bak",
                "examples/my-package.ipe",
            ]
        )
        self.assertEqual(got, ["examples/shapes/web/a", "tools/code-review"])

    def test_a_tests_dir_outside_a_cargo_test_tree_hides_no_project(self) -> None:
        got = ipe_fmt_check.projects(
            [
                "examples/tests/app/package.ipe",
                "tests/golden/x/package.ipe",
                "tools/mytests/b/package.ipe",
                "src/lib/tests/c/package.ipe",
                "src/lib/Cargo.toml.bak",
                "src/other/Cargo.toml",
                "src/other/sub/tests/d/package.ipe",
            ]
        )
        self.assertEqual(
            got,
            [
                "examples/tests/app",
                "src/lib/tests/c",
                "src/other/sub/tests/d",
                "tests/golden/x",
                "tools/mytests/b",
            ],
        )

    def test_repo_discovery_matches_an_independent_walk(self) -> None:
        tracked = set(ipe_fmt_check.tracked_files(ipe_fmt_check.ROOT))
        walked = set()
        for dirpath, dirnames, filenames in os.walk(ipe_fmt_check.ROOT):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            rel_dir = os.path.relpath(dirpath, ipe_fmt_check.ROOT).replace(os.sep, "/")
            parts = [] if rel_dir == "." else rel_dir.split("/")
            in_cargo_tests = any(
                p == "tests" and "/".join([*parts[:i], "Cargo.toml"]) in tracked for i, p in enumerate(parts)
            )
            if "package.ipe" in filenames and not in_cargo_tests:
                rel = "/".join([*parts, "package.ipe"])
                if rel in tracked:
                    walked.add(rel_dir)
        got = ipe_fmt_check.projects(tracked)
        self.assertEqual(set(got), walked)
        self.assertIn("tools/code-review", got)
        self.assertIn("packages/ipe-list-extra", got)
        self.assertTrue(any(d.startswith("examples/shapes/") for d in got), got)
        self.assertTrue(any(d.startswith("examples/wasm/") for d in got), got)
        self.assertFalse(any(d.startswith("tests/") for d in got), got)


class TestVerdict(unittest.TestCase):
    FILES = ("Cargo.toml", "a/package.ipe", "a/src/Main.ipe", "b/c/package.ipe", "tests/golden/g/package.ipe")

    def setUp(self) -> None:
        self.repo = Repo(self.FILES)

    def tearDown(self) -> None:
        self.repo.close()

    def test_clean_projects_pass_and_each_is_checked_in_machine_mode(self) -> None:
        self.assertEqual(self.repo.run(), 0)
        self.assertEqual(self.repo.calls(), ["fmt --check --plain a", "fmt --check --plain b/c"])

    def test_an_unformatted_project_fails(self) -> None:
        self.assertEqual(self.repo.run(dirty=["b/c"]), 1)
        self.assertEqual(len(self.repo.calls()), 2)

    def test_a_missing_binary_fails_before_any_check(self) -> None:
        missing = os.path.join(os.path.dirname(self.repo.ipe), "absent")
        self.assertEqual(self.repo.run(ipe_bin=missing), 2)
        self.assertEqual(self.repo.run(ipe_bin=""), 2)
        self.assertEqual(self.repo.calls(), [])

    def test_a_non_executable_binary_fails(self) -> None:
        os.chmod(self.repo.ipe, stat.S_IRUSR | stat.S_IWUSR)
        self.assertEqual(self.repo.run(), 2)

    def test_an_unexpected_argument_is_refused(self) -> None:
        self.assertEqual(ipe_fmt_check.main(["--fix"], {"IPE_BIN": self.repo.ipe}, root=self.repo.root), 2)

    def test_a_signal_or_unrunnable_binary_fails_the_project(self) -> None:
        def killed(argv: Sequence[str], cwd: str) -> int:
            return -9

        self.assertEqual(ipe_fmt_check.unformatted("ipe", ".", ["a"], killed), ["a"])
        self.assertEqual(ipe_fmt_check.run_ipe([os.path.join(self.repo.root, "nope")], self.repo.root), 1)

    def test_a_timed_out_check_fails_the_project(self) -> None:
        saved = ipe_fmt_check.TIMEOUT_SECS
        ipe_fmt_check.TIMEOUT_SECS = 0.2
        try:
            got = ipe_fmt_check.run_ipe([sys.executable, "-c", "import time; time.sleep(30)"], self.repo.root)
        finally:
            ipe_fmt_check.TIMEOUT_SECS = saved
        self.assertEqual(got, 1)


class TestEmptyDiscovery(unittest.TestCase):
    def test_no_project_fails(self) -> None:
        for name, files in (
            ("no files", ()),
            ("only test inputs", ("Cargo.toml", "x/Cargo.toml", "tests/golden/g/package.ipe", "x/tests/p/package.ipe")),
            ("untracked manifest only", ("README.md",)),
        ):
            with self.subTest(name):
                repo = Repo(files)
                try:
                    with open(os.path.join(repo.root, "package.ipe"), "w") as f:
                        f.write("x\n")
                    self.assertEqual(repo.run(), 2)
                    self.assertEqual(repo.calls(), [])
                finally:
                    repo.close()

    def test_not_a_git_repo_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ipe = os.path.join(tmp, "ipe")
            with open(ipe, "w") as f:
                f.write(FAKE_IPE)
            os.chmod(ipe, stat.S_IRWXU)
            root = os.path.join(tmp, "plain")
            os.makedirs(root)
            self.assertEqual(ipe_fmt_check.main([], {"IPE_BIN": ipe}, root=root), 2)


class TestCiStepAndManifestAgree(unittest.TestCase):
    """The check runs unconditionally in the required floor job, mirrored by the local gate."""

    def _load(self, *rel: str) -> object:
        with open(os.path.join(ipe_fmt_check.ROOT, *rel)) as f:
            return strict_yaml.safe_load(f)

    def test_ci_step_is_unconditional_in_the_required_floor_job(self) -> None:
        ci = self._load(".github", "workflows", "ci.yml")
        assert isinstance(ci, dict)
        job = ci["jobs"][FLOOR_JOB]
        self.assertEqual(job.get("name"), FLOOR_CONTEXT)
        self.assertNotIn("continue-on-error", job)
        steps = [s for s in job["steps"] if isinstance(s, dict) and s.get("run", "").strip() == STEP_RUN]
        self.assertEqual(len(steps), 1, steps)
        step = steps[0]
        for key in ("if", "continue-on-error", "working-directory", "shell"):
            self.assertNotIn(key, step)
        self.assertEqual(step.get("env"), {"IPE_BIN": "${{ runner.temp }}/ipe-release/ipe"})

    def test_manifest_gate_mirrors_the_ci_step(self) -> None:
        manifest = self._load(".github", "ci", "check-manifest.yml")
        assert isinstance(manifest, dict)
        entries = [e for e in manifest["checks"] if e.get("context") == FLOOR_CONTEXT]
        self.assertEqual(len(entries), 1, entries)
        entry = entries[0]
        self.assertEqual(entry["disposition"], "gate")
        self.assertEqual(entry["producer"], "ci.yml")
        runs = [r for r in entry["local"]["run"] if isinstance(r, dict) and r.get("cmd") == STEP_RUN]
        self.assertEqual(len(runs), 1, entry["local"]["run"])
        self.assertNotIn("differs", runs[0])
        self.assertEqual(runs[0]["env"].get("IPE_BIN"), "{ipe_bin}")


if __name__ == "__main__":
    unittest.main()
