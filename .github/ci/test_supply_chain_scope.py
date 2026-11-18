#!/usr/bin/env python3
"""Refusal proofs for `supply_chain_scope.py`, the release-graph coverage proof.

Every way the proof must refuse (an empty release graph, one without its
sentinel, a release crate the judged graph omits, no crate judged, a line
that is not JSON, a diagnostic without a code, a child over its time or
output ceiling, an unexpected exit) gets its own test, beside the one
covered case that keeps the refusals from being vacuous. The runner is
injected, so no test runs cargo. The diagnostic fixtures are the shape the
CI-pinned cargo-deny 0.20 writes to stderr under `--format json`. Pure stdlib
`unittest`.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from collections.abc import Sequence

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

_spec = importlib.util.spec_from_file_location("supply_chain_scope", os.path.join(HERE, "supply_chain_scope.py"))
assert _spec is not None and _spec.loader is not None
scs = importlib.util.module_from_spec(_spec)
sys.modules["supply_chain_scope"] = scs
_spec.loader.exec_module(scs)
import release_build  # noqa: E402

K = scs.ScopeErrorKind

DENY_TOML = """\
# head comment
[graph]
all-features = false
no-default-features = false
features = ["full", "wasi_run"]

[advisories]
ignore = ["RUSTSEC-2025-0141"]

[bans]
multiple-versions = "warn"
deny = [{ crate = "openssl", reason = "rustls only" }]

[[bans.features]]
crate = "reqwest"
deny = ["native-tls"]

[sources]
unknown-registry = "deny"
"""

RELEASE = {("wasmtime", "48.0.9"), ("cranelift-codegen", "0.135.9"), ("serde", "1.0.229")}

TREE = """\
ipe v0.7.4 (/work/src/ipe-cli)
wasmtime v48.0.9
cranelift-codegen v0.135.9
serde v1.0.229
serde_derive v1.0.229 (proc-macro) (*)
ipe_env v0.7.4 (/work/src/compiler/env) (*)
serde v1.0.229 (*)

ipe-ffi-inspector v0.2.0 (/work/tools/ipe-ffi-inspector)
"""
TREE_CRATES = RELEASE | {("serde_derive", "1.0.229")}


def banned_line(name: str, version: str) -> str:
    """A cargo-deny 0.20 `banned` diagnostic line."""
    return json.dumps(
        {
            "type": "diagnostic",
            "fields": {
                "code": "banned",
                "labels": [{"message": "banned here", "span": f"{name}@{version}", "line": 9, "column": 15}],
                "message": f"crate '{name} = {version}' is explicitly banned",
                "severity": "error",
            },
        }
    )


SUMMARY = json.dumps({"type": "summary", "fields": {"bans": {"errors": 1, "warnings": 0, "notes": 0, "helps": 0}}})
LOG = json.dumps({"type": "log", "fields": {"level": "WARN", "message": "unable to find a config"}})


def deny_stderr(crates: set[tuple[str, str]], extra: Sequence[str] = ()) -> bytes:
    lines = [LOG, *(banned_line(n, v) for n, v in sorted(crates)), *extra, SUMMARY]
    return ("\n".join(lines) + "\n").encode()


class FakeRunner:
    """Answers `cargo tree` and `cargo deny` from fixtures and records each call."""

    def __init__(
        self,
        tree: str = TREE,
        deny: bytes | None = None,
        deny_rc: int | None = scs.DENY_EXIT_BANS_FAILED,
        **deny_flags: bool,
    ) -> None:
        self.tree = tree
        self.deny = deny_stderr(TREE_CRATES) if deny is None else deny
        self.deny_rc = deny_rc
        self.deny_flags = deny_flags
        self.calls: list[list[str]] = []
        self.config: str | None = None

    def __call__(self, argv: Sequence[str], cwd: str) -> scs.RunResult:
        argv = list(argv)
        self.calls.append(argv)
        if argv[1] == "tree":
            return scs.RunResult(0, self.tree.encode(), b"")
        with open(argv[argv.index("--config") + 1], encoding="utf-8") as f:
            self.config = f.read()
        return scs.RunResult(self.deny_rc, b"", self.deny, **self.deny_flags)


class ScopeCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.write_deny(DENY_TOML)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write_deny(self, text: str) -> None:
        with open(os.path.join(self.root, "deny.toml"), "w", encoding="utf-8") as f:
            f.write(text)

    def refused(self, runner: FakeRunner, kind: scs.ScopeErrorKind) -> scs.ScopeError:
        with self.assertRaises(scs.ScopeError) as cm:
            scs.prove_scope(runner, self.root)
        self.assertIs(cm.exception.kind, kind, str(cm.exception))
        return cm.exception


class Accepts(ScopeCase):
    def test_banned_equal_to_release_is_covered(self) -> None:
        self.assertEqual(scs.prove_scope(FakeRunner(), self.root), TREE_CRATES)

    def test_path_and_git_crates_are_not_release_registry_crates(self) -> None:
        tree = TREE + "gitdep v0.1.0 (https://github.com/o/r#abcdef)\nwinpath v0.1.0 (C:\\work\\x)\n"
        self.assertEqual(scs.parse_tree(tree), TREE_CRATES)


class RefusesTheReleaseGraph(ScopeCase):
    def test_empty_release_is_refused(self) -> None:
        tree = "ipe v0.7.4 (/work/src/ipe-cli)\nipe_env v0.7.4 (/work/src/compiler/env)\n"
        err = self.refused(FakeRunner(tree=tree), K.EMPTY_RELEASE)
        self.assertEqual(err.kind.exit_code, 2)

    def test_release_without_the_sentinel_is_refused(self) -> None:
        tree = "ipe v0.7.4 (/work/src/ipe-cli)\nserde v1.0.229\n"
        err = self.refused(FakeRunner(tree=tree), K.NO_SENTINEL)
        self.assertIn(scs.SENTINEL_CRATE, err.detail)

    def test_an_unparseable_tree_line_is_refused(self) -> None:
        self.refused(FakeRunner(tree=TREE + "[build-dependencies]\n"), K.TREE_LINE)

    def test_a_failing_tree_is_refused(self) -> None:
        class TreeFails(FakeRunner):
            def __call__(self, argv: Sequence[str], cwd: str) -> scs.RunResult:
                return scs.RunResult(101, b"", b"error: package not found")

        self.refused(TreeFails(), K.TOOL_EXIT)

    def test_features_and_packages_come_from_release_build(self) -> None:
        saved = (release_build.RELEASE_FEATURE, release_build.RELEASE_PACKAGES)
        try:
            release_build.RELEASE_FEATURE = "sentinel-pkg/sentinel-feature"
            release_build.RELEASE_PACKAGES = ("pkg-a", "pkg-b")
            runner = FakeRunner()
            scs.prove_scope(runner, self.root)
        finally:
            release_build.RELEASE_FEATURE, release_build.RELEASE_PACKAGES = saved
        tree = runner.calls[0]
        self.assertEqual(tree[tree.index("--features") + 1], "sentinel-pkg/sentinel-feature")
        self.assertEqual([tree[i + 1] for i, a in enumerate(tree) if a == "-p"], ["pkg-a", "pkg-b"])

    def test_the_tree_reads_only_normal_and_build_edges_on_every_target(self) -> None:
        # A dev edge (a self dev-dependency keyed by the package's own name)
        # can carry the release feature while the shipped binary lacks it, so
        # the sentinel must be found on the edges a release build links.
        tree = scs.tree_argv()
        self.assertEqual(tree[tree.index("-e") + 1], "normal,build")
        self.assertEqual(tree.count("-e") + tree.count("--edges"), 1)
        self.assertEqual(tree[tree.index("--target") + 1], "all")
        self.assertNotIn("--all-features", tree)

    def test_every_parsed_invocation_turns_colour_off_itself(self) -> None:
        # CI exports CARGO_TERM_COLOR=always; the argv must override it, or
        # escape codes reach the strict line parsers.
        for argv in (scs.tree_argv(), scs.deny_argv("/r/Cargo.toml", "/t/deny.toml")):
            self.assertEqual(argv[argv.index("--color") + 1], "never", argv)

    def test_a_coloured_tree_line_is_refused_not_misread(self) -> None:
        with self.assertRaises(scs.ScopeError) as cm:
            scs.parse_tree("windows-sys v0.61.2 \x1b[33m\x1b[2m(*)\x1b[39m\x1b[22m\n")
        self.assertIs(cm.exception.kind, K.TREE_LINE)


class RefusesTheJudgedGraph(ScopeCase):
    def test_a_release_crate_never_banned_is_refused_by_name(self) -> None:
        runner = FakeRunner(deny=deny_stderr(TREE_CRATES - {("wasmtime", "48.0.9")}))
        err = self.refused(runner, K.NOT_COVERED)
        self.assertIn("wasmtime@48.0.9", err.detail)
        self.assertEqual(err.kind.exit_code, 1)

    def test_zero_banned_diagnostics_are_refused(self) -> None:
        err = self.refused(FakeRunner(deny=deny_stderr(set())), K.NO_BANNED)
        self.assertEqual(err.kind.exit_code, 1)

    def test_a_non_json_line_is_refused(self) -> None:
        self.refused(FakeRunner(deny=deny_stderr(TREE_CRATES, ["error: not json"])), K.NOT_JSON)

    def test_a_json_line_that_is_not_an_object_is_refused(self) -> None:
        self.refused(FakeRunner(deny=deny_stderr(TREE_CRATES, ["[1, 2]"])), K.NOT_JSON)

    def test_a_diagnostic_without_a_code_is_refused(self) -> None:
        line = json.dumps({"type": "diagnostic", "fields": {"message": "x", "severity": "error"}})
        self.refused(FakeRunner(deny=deny_stderr(TREE_CRATES, [line])), K.NO_CODE)

    def test_a_banned_diagnostic_naming_no_crate_is_refused(self) -> None:
        line = json.dumps({"type": "diagnostic", "fields": {"code": "banned", "message": "banned", "severity": "error"}})
        self.refused(FakeRunner(deny=deny_stderr(TREE_CRATES, [line])), K.BAD_LABEL)

    def test_a_timeout_is_refused(self) -> None:
        self.refused(FakeRunner(deny_rc=None, timed_out=True), K.TIMEOUT)

    def test_an_output_overflow_is_refused(self) -> None:
        self.refused(FakeRunner(deny_rc=None, overflowed=True), K.OUTPUT_CEILING)

    def test_an_exit_other_than_bans_failed_is_refused(self) -> None:
        for rc in (0, 1, 3, 101):
            with self.subTest(rc=rc):
                self.refused(FakeRunner(deny_rc=rc), K.TOOL_EXIT)


class TheTemporaryConfig(ScopeCase):
    def test_graph_is_byte_identical_and_a_narrow_graph_is_passed_through(self) -> None:
        narrow = DENY_TOML.replace('features = ["full", "wasi_run"]', 'features = ["full"]')
        self.write_deny(narrow)
        runner = FakeRunner()
        scs.prove_scope(runner, self.root)
        assert runner.config is not None
        graph = narrow[narrow.index("[graph]") : narrow.index("[advisories]")]
        self.assertIn(graph, runner.config)
        self.assertIn('features = ["full"]\n', runner.config)
        self.assertNotIn('"wasi_run"', runner.config)

    def test_bans_are_replaced_and_every_other_table_kept(self) -> None:
        runner = FakeRunner()
        scs.prove_scope(runner, self.root)
        derived = scs.tomllib.loads(runner.config or "")
        self.assertEqual(
            derived["bans"],
            {
                "multiple-versions": "allow",
                "wildcards": "allow",
                "deny": [{"crate": f"{n}@{v}"} for n, v in sorted(TREE_CRATES)],
            },
        )
        original = scs.tomllib.loads(DENY_TOML)
        for table in ("graph", "advisories", "sources"):
            self.assertEqual(derived[table], original[table], table)

    def test_an_unparseable_deny_toml_is_refused(self) -> None:
        self.write_deny("[graph\n")
        self.refused(FakeRunner(), K.CONFIG)

    def test_the_deny_invocation_is_the_cargo_deny_0_20_layout(self) -> None:
        argv = scs.deny_argv("/r/Cargo.toml", "/t/deny.toml")
        check = argv.index("check")
        for flag in ("--manifest-path", "--config", "--locked", "--offline", "--format"):
            self.assertLess(argv.index(flag), check, flag)
        self.assertEqual(argv[check + 1 :], ["bans", "--hide-inclusion-graph"])
        self.assertEqual(argv[argv.index("--format") + 1], "json")


class TheBoundedRunner(unittest.TestCase):
    def test_a_child_past_its_time_ceiling_is_killed(self) -> None:
        saved = scs.CHILD_TIMEOUT_S
        try:
            scs.CHILD_TIMEOUT_S = 1
            result = scs.bounded_run([sys.executable, "-c", "import time; time.sleep(60)"], HERE)
        finally:
            scs.CHILD_TIMEOUT_S = saved
        self.assertTrue(result.timed_out)
        self.assertIsNone(result.returncode)

    def test_a_child_past_its_output_ceiling_is_killed(self) -> None:
        saved = scs.CHILD_OUTPUT_CEILING
        try:
            scs.CHILD_OUTPUT_CEILING = 1024
            code = "import sys, time\nsys.stderr.write('x' * 4096); sys.stderr.flush(); time.sleep(60)"
            result = scs.bounded_run([sys.executable, "-c", code], HERE)
        finally:
            scs.CHILD_OUTPUT_CEILING = saved
        self.assertTrue(result.overflowed)
        self.assertIsNone(result.returncode)
        self.assertLessEqual(len(result.stderr), 1024)

    def test_a_child_within_its_ceilings_is_returned_whole(self) -> None:
        code = "import sys; print('out'); sys.stderr.write('err'); sys.exit(2)"
        result = scs.bounded_run([sys.executable, "-c", code], HERE)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b"out\n", b"err"))
        self.assertFalse(result.timed_out or result.overflowed)


if __name__ == "__main__":
    unittest.main()
