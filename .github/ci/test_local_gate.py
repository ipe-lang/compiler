#!/usr/bin/env python3
"""Refusal proofs for `local_gate.py`, the manifest's typed `local:` layer.

Each shape the verifier must turn away (a gate without a disposition, two
dispositions at once, an unknown placeholder, a command, env value or working
directory CI does not run) has its own test, per PRINCIPLES.md "Prove the
refusals". The planner tests pin the fail-closed package selection: a file no
crate owns selects the whole workspace. One test proves the live manifest
verifies clean against the live workflows.

Pure stdlib `unittest`, no network, no cargo.
"""

from __future__ import annotations

import contextlib
import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import local_gate as lg  # noqa: E402

WORKFLOW = textwrap.dedent(
    """\
    name: ci
    on: push
    env:
      CARGO_TERM_COLOR: always
    jobs:
      fmt:
        runs-on: ubuntu-latest
        steps:
          - run: cargo fmt --all -- --check
      clippy:
        runs-on: ubuntu-latest
        env:
          IPE_E2E: "1"
        steps:
          - run: |
              # lint everything
              cargo clippy --all-targets --workspace --offline \\
                -- -D warnings
          - run: cargo run -p gen -- --repo-root ${{ github.workspace }}
            env:
              IPE_BIN: ${{ github.workspace }}/target/release/ipe
          - run: tree-sitter test
            working-directory: editors/grammar
      shard:
        name: shard (1)
        runs-on: ubuntu-latest
        steps:
          - run: cargo nextest run --workspace
    """
)


def gate(ctx: str, local: object, **extra: object) -> dict:
    return {"context": ctx, "disposition": "gate", "producer": "ci.yml", "local": local, **extra}


def run(*cmds: object, tier: str = "quick") -> dict:
    return {"tier": tier, "run": list(cmds)}


class Fixture(unittest.TestCase):
    """A temporary `.github` tree holding one synthetic workflow."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        os.makedirs(os.path.join(self.tmp.name, "workflows"))
        with open(os.path.join(self.tmp.name, "workflows", "ci.yml"), "w") as f:
            f.write(WORKFLOW)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def errors(self, *entries: dict) -> list[str]:
        errs: list[str] = []
        lg.check_local_dispositions(list(entries), errs, github_dir=self.tmp.name)
        return errs

    def refuses(self, needle: str, *entries: dict) -> None:
        errs = self.errors(*entries)
        self.assertTrue(any(needle in e for e in errs), f"expected {needle!r} in {errs}")

    def accepts(self, *entries: dict) -> None:
        self.assertEqual(self.errors(*entries), [])


class ShapeRefusals(Fixture):
    def test_gate_without_local(self) -> None:
        self.refuses("gate has no `local:`", {"context": "fmt", "disposition": "gate", "producer": "ci.yml"})

    def test_local_on_non_gate(self) -> None:
        self.refuses(
            "only a `gate` entry",
            {"context": "fmt", "disposition": "informational", "owner": "x", "local": {"ci-only": "platform"}},
        )

    def test_empty_local(self) -> None:
        self.refuses("must be a mapping", gate("fmt", {}))

    def test_two_dispositions(self) -> None:
        self.refuses("not exactly one disposition", gate("fmt", {"ci-only": "platform", "covered-by": "x"}))

    def test_unknown_local_key(self) -> None:
        self.refuses("not exactly one disposition", gate("fmt", {**run("cargo fmt --all -- --check"), "why": "x"}))

    def test_bad_tier(self) -> None:
        self.refuses("tier 'nightly'", gate("fmt", run("cargo fmt --all -- --check", tier="nightly")))

    def test_empty_run(self) -> None:
        self.refuses("non-empty list", gate("fmt", {"tier": "quick", "run": []}))

    def test_bad_ci_only_reason(self) -> None:
        self.refuses("ci-only reason 'slow'", gate("fmt", {"ci-only": "slow"}))

    def test_unhashable_ci_only_reason(self) -> None:
        self.refuses("ci-only reason ['platform']", gate("fmt", {"ci-only": ["platform"]}))

    def test_non_mapping_entry(self) -> None:
        self.refuses("checks[0]: an entry is a mapping", "fmt")  # type: ignore[arg-type]

    def test_covered_by_self(self) -> None:
        self.refuses("covered-by 'fmt'", gate("fmt", {"covered-by": "fmt"}))

    def test_covered_by_unknown(self) -> None:
        self.refuses("covered-by 'nope'", gate("fmt", {"covered-by": "nope"}))

    def test_covered_by_non_run(self) -> None:
        self.refuses(
            "covered-by 'clippy'",
            gate("fmt", {"covered-by": "clippy"}),
            gate("clippy", {"ci-only": "platform"}),
        )


class CommandRefusals(Fixture):
    def test_unknown_placeholder(self) -> None:
        self.refuses("unknown placeholder {crates}", gate("fmt", run("cargo fmt {crates}")))

    def test_workflow_expression(self) -> None:
        self.refuses("workflow expression", gate("fmt", run("cargo run -- ${{ github.workspace }}")))

    def test_embedded_package_placeholder(self) -> None:
        self.refuses("must be a whole word", gate("fmt", run("cargo clippy --pkgs={packages}")))

    def test_unknown_command_key(self) -> None:
        self.refuses("unknown command key", gate("fmt", run({"cmd": "cargo fmt --all -- --check", "shell": "sh"})))

    def test_empty_cmd(self) -> None:
        self.refuses("`cmd` must be a non-empty string", gate("fmt", run({"cmd": "  "})))

    def test_bad_env_name(self) -> None:
        self.refuses(
            "not an UPPER_SNAKE",
            gate("fmt", run({"cmd": "cargo fmt --all -- --check", "env": {"lower": "1"}})),
        )

    def test_package_placeholder_in_env(self) -> None:
        self.refuses(
            "disallowed placeholder",
            gate("fmt", run({"cmd": "cargo fmt --all -- --check", "env": {"PKGS": "{packages}"}})),
        )

    def test_absolute_cwd(self) -> None:
        self.refuses("relative path inside the repo", gate("fmt", run({"cmd": "tree-sitter test", "cwd": "/tmp"})))

    def test_parent_cwd(self) -> None:
        self.refuses("relative path inside the repo", gate("fmt", run({"cmd": "tree-sitter test", "cwd": "../x"})))

    def test_empty_differs(self) -> None:
        self.refuses("must state why", gate("fmt", run({"cmd": "cargo fmt", "differs": ""})))


class ShellHazardRefusals(Fixture):
    """A command runs as an argv with no shell; shell syntax would run literally."""

    def refused(self, text: str) -> None:
        self.refuses("is not inert without a shell", gate("fmt", run(text)))

    def test_variable(self) -> None:
        self.refused("cargo nextest run $FILTER")

    def test_braced_variable(self) -> None:
        self.refused("cargo nextest run ${FILTER}")

    def test_variable_in_double_quotes(self) -> None:
        self.refused('cargo nextest run "$FILTER"')

    def test_command_substitution(self) -> None:
        self.refused("cargo nextest run `cat filter`")

    def test_operators(self) -> None:
        for text in ("cargo doc && cargo test", "cargo doc | tee log", "cargo doc; true", "cargo doc > log", "(cargo doc)"):
            with self.subTest(text=text):
                self.refused(text)

    def test_glob(self) -> None:
        for text in ("git diff --exit-code docs/*.md", "ls a?", "ls [ab]"):
            with self.subTest(text=text):
                self.refused(text)

    def test_brace_expansion(self) -> None:
        self.refused("git diff --exit-code docs/{a,b}.md")

    def test_home_comment_negation(self) -> None:
        for text in ("ls ~/x", "cargo doc # trailing", "! cargo test"):
            with self.subTest(text=text):
                self.refused(text)

    def test_backslash(self) -> None:
        self.refused("cargo test a\\ b")

    def test_newline(self) -> None:
        self.refused("cargo doc\ncargo test")

    def test_assignment_prefix(self) -> None:
        self.refused("IPE_E2E=1 cargo nextest run --workspace")

    def test_inert_quoting_and_placeholders_accepted(self) -> None:
        self.assertIsNone(lg.shell_hazard("cargo nextest run -E 'test(/a$b*/)' {packages} --root={repo_root}"))
        self.assertIsNone(lg.shell_hazard('cargo run -- "a b" --flag=x'))


class DriftRefusals(Fixture):
    def test_command_not_in_ci(self) -> None:
        self.refuses("matches no command CI runs", gate("fmt", run("cargo fmt --all")))

    def test_command_from_another_job(self) -> None:
        self.refuses("matches no command CI runs", gate("fmt", run("cargo nextest run {packages}")))

    def test_env_mismatch(self) -> None:
        self.refuses(
            "not the CI value of IPE_E2E",
            gate("clippy", run({"cmd": "cargo clippy --all-targets {packages} -- -D warnings", "env": {"IPE_E2E": "0"}})),
        )

    def test_env_absent_in_ci(self) -> None:
        self.refuses(
            "not the CI value of EXTRA",
            gate("fmt", run({"cmd": "cargo fmt --all -- --check", "env": {"EXTRA": "1"}})),
        )

    def test_cwd_mismatch(self) -> None:
        self.refuses("matches no command CI runs", gate("clippy", run("tree-sitter test")))

    def test_differs_still_checks_cwd(self) -> None:
        self.refuses(
            "is not the working directory",
            gate("clippy", run({"cmd": "anything", "cwd": "elsewhere", "differs": "local variant"})),
        )

    def test_differs_still_checks_env(self) -> None:
        self.refuses(
            "not the CI value of IPE_E2E",
            gate("clippy", run({"cmd": "anything", "env": {"IPE_E2E": "0"}, "differs": "local variant"})),
        )

    def test_missing_producer_workflow(self) -> None:
        self.refuses("producer workflow 'gone.yml' not found", {**gate("fmt", run("x")), "producer": "gone.yml"})


class DriftAccepts(Fixture):
    def test_exact_mirror(self) -> None:
        self.accepts(gate("fmt", run("cargo fmt --all -- --check")))

    def test_placeholders_continuation_comment_and_ci_only_flag(self) -> None:
        self.accepts(gate("clippy", run("cargo clippy --all-targets {packages} -- -D warnings")))

    def test_repo_root_and_target_dir_in_env(self) -> None:
        self.accepts(
            gate(
                "clippy",
                run(
                    {
                        "cmd": "cargo run -p gen -- --repo-root {repo_root}",
                        "env": {"IPE_BIN": "{target_dir}/release/ipe", "IPE_E2E": "1", "CARGO_TERM_COLOR": "always"},
                    }
                ),
            )
        )

    def test_working_directory(self) -> None:
        self.accepts(gate("clippy", run({"cmd": "tree-sitter test", "cwd": "editors/grammar"})))

    def test_aggregated_matrix_job(self) -> None:
        self.accepts(gate("test", run("cargo nextest run {packages}"), aggregates=["shard"]))

    def test_differs_waives_only_tokens(self) -> None:
        self.accepts(gate("clippy", run({"cmd": "cargo clippy -p one", "differs": "local variant"})))

    def test_workflow_working_directory_survives_job_defaults(self) -> None:
        doc = {
            "defaults": {"run": {"working-directory": "editors/grammar"}},
            "jobs": {"g": {"defaults": {"run": {"shell": "bash"}}, "steps": [{"run": "tree-sitter test"}]}},
        }
        self.assertEqual([ln.cwd for ln in lg.ci_lines(doc, "g", [])], ["editors/grammar"])

    def test_job_working_directory_wins(self) -> None:
        doc = {
            "defaults": {"run": {"working-directory": "a"}},
            "jobs": {"g": {"defaults": {"run": {"working-directory": "b"}}, "steps": [{"run": "x"}]}},
        }
        self.assertEqual([ln.cwd for ln in lg.ci_lines(doc, "g", [])], ["b"])

    def test_covered_by_and_ci_only(self) -> None:
        self.accepts(
            gate("fmt", run("cargo fmt --all -- --check")),
            gate("slice", {"covered-by": "fmt"}),
            gate("win", {"ci-only": "platform"}),
        )


class CompleteMirror(Fixture):
    """`complete: true` holds the converse: every CI command has a local twin."""

    CLIPPY_JOB = (
        "cargo clippy --all-targets {packages} -- -D warnings",
        {
            "cmd": "cargo run -p gen -- --repo-root {repo_root}",
            "env": {"IPE_BIN": "{target_dir}/release/ipe"},
        },
        {"cmd": "tree-sitter test", "cwd": "editors/grammar"},
    )

    @staticmethod
    def complete(*cmds: object, **extra: object) -> dict:
        return {"tier": "quick", "run": list(cmds), "complete": True, **extra}

    def test_every_ci_command_mirrored(self) -> None:
        self.accepts(gate("fmt", self.complete("cargo fmt --all -- --check")))
        self.accepts(gate("clippy", self.complete(*self.CLIPPY_JOB)))

    def test_ci_command_without_twin(self) -> None:
        self.refuses(
            "CI runs 'tree-sitter test' (cwd 'editors/grammar') for this gate with no local twin",
            gate("clippy", self.complete(*self.CLIPPY_JOB[:2])),
        )

    def test_twin_in_another_cwd_is_no_twin(self) -> None:
        self.refuses(
            "with no local twin",
            gate("clippy", self.complete(*self.CLIPPY_JOB[:2], "tree-sitter test")),
        )

    def test_without_complete_the_match_stays_one_directional(self) -> None:
        self.accepts(gate("clippy", run(*self.CLIPPY_JOB[:2])))

    def test_complete_is_true_or_absent(self) -> None:
        for value in (False, "yes", 1):
            with self.subTest(value=value):
                self.refuses(
                    "`complete` is `true` or absent",
                    gate("fmt", self.complete("cargo fmt --all -- --check", complete=value)),
                )

    def test_complete_refuses_differs(self) -> None:
        self.refuses(
            "a `complete` gate mirrors CI token for token",
            gate("fmt", self.complete("cargo fmt --all -- --check", {"cmd": "x", "differs": "local variant"})),
        )

    def test_complete_only_on_run(self) -> None:
        self.refuses("are not exactly one disposition", gate("fmt", {"ci-only": "platform", "complete": True}))

    def test_runtime_feature_combos_is_one_set_at_quick(self) -> None:
        """The lean gate runs exactly CI's runtime feature-combination clippy set."""
        errs: list[str] = []
        parsed = lg.parse_manifest_locals(lg.load_manifest_entries(), errs)
        self.assertEqual(errs, [])
        disp = parsed["runtime-feature-combos"]
        assert isinstance(disp, lg.RunLocal)
        self.assertIs(disp.tier, lg.Tier.QUICK)
        self.assertTrue(disp.complete)
        self.assertIn(("--features", "full"), {c.argv[4:6] for c in disp.commands})


def workspace() -> lg.Workspace:
    return lg.Workspace(
        root="/r",
        target_dir="/t",
        member_dirs={"root": "", "core": "src/core", "back": "src/back", "rust": "src/back/rust", "cli": "src/cli"},
        doctest=frozenset({"core", "back", "rust"}),
        path_deps={
            "root": frozenset(),
            "core": frozenset(),
            "back": frozenset({"core"}),
            "rust": frozenset({"back"}),
            "cli": frozenset({"rust"}),
        },
    )


PLAN_ENTRIES = [
    gate("fmt", run("cargo fmt --all -- --check")),
    gate("clippy", run("cargo clippy --all-targets {packages} -- -D warnings")),
    gate("test", run("cargo nextest run {packages}", "cargo test --doc {lib_packages}", tier="affected")),
    gate("e2e", run({"cmd": "cargo nextest run --workspace", "env": {"BIN": "{target_dir}/ipe", "IPE": "{ipe_bin}"}}, tier="full")),
    gate("dup", run("cargo fmt --all -- --check", tier="full")),
    gate("win", {"ci-only": "platform"}),
]


def planned(tier: lg.Tier, changed: list[str]) -> list[lg.Step]:
    errs: list[str] = []
    parsed = lg.parse_manifest_locals(PLAN_ENTRIES, errs)
    assert errs == [], errs
    return lg.plan(tier, PLAN_ENTRIES, parsed, changed, workspace())


def words(tier: lg.Tier, changed: list[str]) -> list[str]:
    return [" ".join(s.argv) for s in planned(tier, changed)]


class Selection(unittest.TestCase):
    def test_deepest_member_owns_a_file(self) -> None:
        ws = workspace()
        self.assertEqual(ws.owner("src/back/rust/lib.rs"), "rust")
        self.assertEqual(ws.owner("src/back/mod.rs"), "back")
        self.assertIsNone(ws.owner("src/backend.rs"))

    def test_root_package_owns_nothing_by_prefix(self) -> None:
        self.assertIsNone(workspace().owner("Cargo.lock"))

    def test_unowned_file_selects_the_workspace(self) -> None:
        sel = lg.select_packages(lg.Tier.QUICK, ["src/core/a.rs", "Cargo.toml"], workspace())
        self.assertIsNone(sel.packages)

    def test_quick_selects_owners_only(self) -> None:
        sel = lg.select_packages(lg.Tier.QUICK, ["src/back/x.rs"], workspace())
        self.assertEqual(sel.packages, frozenset({"back"}))

    def test_affected_adds_reverse_dependencies(self) -> None:
        sel = lg.select_packages(lg.Tier.AFFECTED, ["src/back/x.rs"], workspace())
        self.assertEqual(sel.packages, frozenset({"back", "rust", "cli"}))

    def test_full_is_the_workspace(self) -> None:
        self.assertIsNone(lg.select_packages(lg.Tier.FULL, ["src/core/a.rs"], workspace()).packages)


class SourceReaders(unittest.TestCase):
    """A crate reading another crate's file with no cargo edge is affected by it."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        files = {
            "src/core/src/lib.rs": "",
            "src/core/data/table.txt": "",
            "src/back/src/lib.rs": "",
            "src/back/rust/src/lib.rs": "",
            "src/back/rust/templates/main.rs": "",
            # include_str! relative to the file, and a manifest-dir concat.
            "src/cli/tests/ssot.rs": (
                'const T: &str = include_str!("../../core/data/table.txt");\n'
                'const U: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../back/rust/templates");\n'
            ),
            # Path-traversal strings and names of absent files add no edge.
            "src/core/tests/paths.rs": '"a/../../.."; "../.."; "../back/gone.rs"; "../../cli/tests/ssot.rs";',
        }
        for rel, text in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(text)
        self.ws = lg.Workspace(
            root=root,
            target_dir=os.path.join(root, "target"),
            member_dirs={"core": "src/core", "back": "src/back", "rust": "src/back/rust", "cli": "src/cli"},
            doctest=frozenset(),
            path_deps={"core": frozenset(), "back": frozenset(), "rust": frozenset(), "cli": frozenset()},
        ).with_source_readers()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_edges(self) -> None:
        self.assertEqual(
            self.ws.readers,
            {"core": frozenset({"cli"}), "rust": frozenset({"cli"}), "cli": frozenset({"core"})},
        )

    def test_affected_selects_the_reader(self) -> None:
        sel = lg.select_packages(lg.Tier.AFFECTED, ["src/core/data/table.txt"], self.ws)
        self.assertEqual(sel.packages, frozenset({"core", "cli"}))

    def test_nested_member_files_are_not_the_parents(self) -> None:
        sel = lg.select_packages(lg.Tier.AFFECTED, ["src/back/src/lib.rs"], self.ws)
        self.assertEqual(sel.packages, frozenset({"back"}))


class _TmpRepo(unittest.TestCase):
    def setUp(self) -> None:
        # Every git the test runs, directly or through the code under test,
        # reads only the throwaway repository's config.
        isolated = mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
        isolated.start()
        self.addCleanup(isolated.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.git("init", "-q", "-b", "main")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        ident = ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]
        return subprocess.run(["git", *ident, *args], cwd=self.root, check=check, capture_output=True, text=True)

    def write(self, rel: str, text: str) -> None:
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)


class ChangedFiles(_TmpRepo):
    """`changed_files` against a real throwaway repository."""

    def setUp(self) -> None:
        super().setUp()
        os.makedirs(os.path.join(self.root, "src/a"))
        with open(os.path.join(self.root, "src/a/moved.rs"), "w") as f:
            f.write("fn moved() {}\n" * 20)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "base")
        self.git("checkout", "-q", "-b", "topic")

    def test_a_rename_reports_both_paths(self) -> None:
        os.makedirs(os.path.join(self.root, "src/b"))
        self.git("mv", "src/a/moved.rs", "src/b/moved.rs")
        self.git("commit", "-q", "-m", "move")
        self.assertEqual(lg.changed_files(self.root, "main"), ["src/a/moved.rs", "src/b/moved.rs"])

    def test_untracked_and_unusual_names_are_verbatim(self) -> None:
        with open(os.path.join(self.root, "src/a/sp ace\u00e9.rs"), "w") as f:
            f.write("")
        self.assertEqual(lg.changed_files(self.root, "main"), ["src/a/sp ace\u00e9.rs"])

    def test_option_shaped_base_is_a_revision(self) -> None:
        with self.assertRaises(subprocess.CalledProcessError):
            lg.changed_files(self.root, "--output=/tmp/x")


class Plan(unittest.TestCase):
    def test_quick_runs_quick_only(self) -> None:
        self.assertEqual(
            words(lg.Tier.QUICK, ["src/core/a.rs"]),
            ["cargo fmt --all -- --check", "cargo clippy --all-targets -p core -- -D warnings"],
        )

    def test_affected_widens_every_command_and_filters_doctests(self) -> None:
        self.assertEqual(
            words(lg.Tier.AFFECTED, ["src/back/rust/a.rs"]),
            [
                "cargo fmt --all -- --check",
                "cargo clippy --all-targets -p cli -p rust -- -D warnings",
                "cargo nextest run -p cli -p rust",
                "cargo test --doc -p rust",
            ],
        )

    def test_no_change_skips_package_commands(self) -> None:
        self.assertEqual(words(lg.Tier.AFFECTED, []), ["cargo fmt --all -- --check"])

    def test_no_doctest_crate_skips_the_doc_command(self) -> None:
        self.assertNotIn("cargo test --doc", " ".join(words(lg.Tier.AFFECTED, ["src/cli/a.rs"])))

    def test_full_runs_workspace_and_dedupes(self) -> None:
        steps = words(lg.Tier.FULL, ["src/core/a.rs"])
        self.assertEqual(steps.count("cargo fmt --all -- --check"), 1)
        self.assertIn("cargo clippy --all-targets --workspace -- -D warnings", steps)
        self.assertIn("cargo test --doc --workspace", steps)

    def test_local_placeholders_expand(self) -> None:
        e2e = [s for s in planned(lg.Tier.FULL, []) if s.context == "e2e"]
        self.assertEqual([s.env for s in e2e], [(("BIN", "/t/ipe"), ("IPE", "/t/release/ipe"))])


class LiveManifest(unittest.TestCase):
    def test_live_manifest_verifies_against_live_workflows(self) -> None:
        errs: list[str] = []
        parsed = lg.check_local_dispositions(lg.load_manifest_entries(), errs)
        self.assertEqual(errs, [])
        self.assertTrue(any(isinstance(d, lg.RunLocal) and d.tier is lg.Tier.QUICK for d in parsed.values()))

    def test_live_source_readers_include_known_cross_crate_reads(self) -> None:
        # kernels' veneer SSOT tests read the stdlib `.ipe` sources; ffi reads
        # the inspector's model; neither has a cargo edge in that direction.
        ws = lg.Workspace(
            root=lg.REPO_ROOT,
            target_dir="",
            member_dirs={
                "ipe_kernels": "src/compiler/kernels",
                "ipe_stdlib": "src/stdlib",
                "ipe_ffi": "src/compiler/ffi",
                "ipe-ffi-inspector": "tools/ipe-ffi-inspector",
            },
            doctest=frozenset(),
            path_deps={},
        ).with_source_readers()
        self.assertIn("ipe_kernels", ws.readers.get("ipe_stdlib", frozenset()))
        self.assertIn("ipe_ffi", ws.readers.get("ipe-ffi-inspector", frozenset()))


class RuntimeScanAtQuick(unittest.TestCase):
    """`gate quick` also runs the runtime crate's own scan tests (the
    registry/secret/env drift suites under `src/runtime/rust/tests/`) when a
    runtime file changed, so they fail locally instead of first in the merge
    queue — and only then, never for an unrelated change."""

    WS = lg.Workspace(
        root=lg.REPO_ROOT,
        target_dir="",
        member_dirs={"ipe-runtime-rust": "src/runtime/rust", "ipe": "src/ipe-cli"},
        doctest=frozenset(),
        path_deps={"ipe-runtime-rust": frozenset(), "ipe": frozenset()},
    )

    @classmethod
    def setUpClass(cls) -> None:
        cls.entries = lg.load_manifest_entries()
        errs: list[str] = []
        cls.parsed = lg.check_local_dispositions(cls.entries, errs)
        assert errs == [], errs

    def quick_scan_command(self) -> lg.Command:
        disp = self.parsed["runtime-full-features"]
        assert isinstance(disp, lg.RunLocal)
        hits = [c for c in disp.commands if c.package == "ipe-runtime-rust" and c.tier is lg.Tier.QUICK]
        self.assertEqual(len(hits), 1, "runtime-full-features has exactly one quick-tier, package-scoped command")
        return hits[0]

    def test_command_names_the_crate_its_package_condition_names(self) -> None:
        """`package:` names the same crate the command's own `-p` invokes —
        catches a future rename of one without the other."""
        cmd = self.quick_scan_command()
        self.assertEqual(cmd.argv[cmd.argv.index("-p") + 1], cmd.package)

    def test_present_when_a_runtime_file_changed(self) -> None:
        steps = lg.plan(lg.Tier.QUICK, self.entries, self.parsed, ["src/runtime/rust/tests/sync_bound_registry.rs"], self.WS)
        self.assertIn(self.quick_scan_command().argv, [s.argv for s in steps])

    def test_absent_when_an_unrelated_crate_changed(self) -> None:
        """Honours the runtime-change condition: a change to another crate
        does not run the runtime crate's scan suite at `quick`."""
        steps = lg.plan(lg.Tier.QUICK, self.entries, self.parsed, ["src/ipe-cli/x.rs"], self.WS)
        self.assertNotIn(self.quick_scan_command().argv, [s.argv for s in steps])

    def test_absent_when_nothing_changed(self) -> None:
        steps = lg.plan(lg.Tier.QUICK, self.entries, self.parsed, [], self.WS)
        self.assertNotIn(self.quick_scan_command().argv, [s.argv for s in steps])

    def test_absent_if_the_command_is_removed_from_the_manifest(self) -> None:
        """Pins the command's presence: deleting it from `check-manifest.yml`
        (or dropping it from `quick` entirely) removes it from the plan,
        catching a future edit that silently drops the step."""
        entries = [dict(e) for e in self.entries]
        for e in entries:
            if e.get("context") == "runtime-full-features":
                e["local"] = {**e["local"], "run": list(e["local"]["run"][:2])}
        errs: list[str] = []
        parsed = lg.check_local_dispositions(entries, errs)
        self.assertEqual(errs, [])
        steps = lg.plan(
            lg.Tier.QUICK, entries, parsed, ["src/runtime/rust/tests/sync_bound_registry.rs"], self.WS
        )
        self.assertFalse(any("kind(test)" in s.argv for s in steps))



def _load_gate_runner():
    path = os.path.join(lg.REPO_ROOT, "tools", "scripts", "gate")
    loader = importlib.machinery.SourceFileLoader("gate_runner", path)
    spec = importlib.util.spec_from_loader("gate_runner", loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@contextlib.contextmanager
def _silenced():
    """Send this process's and its children's stdout/stderr to /dev/null."""
    saved = [os.dup(1), os.dup(2)]
    with open(os.devnull, "w") as null:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(null.fileno(), 1)
        os.dup2(null.fileno(), 2)
        try:
            yield
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
            os.dup2(saved[0], 1)
            os.dup2(saved[1], 2)
            os.close(saved[0])
            os.close(saved[1])


class QuickCatchesPlantedErrors(_TmpRepo):
    """`gate quick`, run by `tools/scripts/gate` on the plan the live
    manifest yields, goes red on a planted manifest/lock desync and on every
    planted generated-output drift: a changed, a deleted, and a newly
    generated (untracked) file under each drift gate's paths.

    The generators need a cargo build, so the plan's drift *assertions* run
    against a tree in which the planted file stands for what a generator
    wrote.
    """

    DRIFT_CONTEXTS = (
        "stdlib-docs-drift",
        "env-docs-drift",
        "capabilities-docs-drift",
        "cli-docs-drift",
        "requirements-docs-drift",
        "cli-transcripts-drift",
        "markdown-parity",
    )

    @classmethod
    def setUpClass(cls) -> None:
        cls.entries = lg.load_manifest_entries()
        errs: list[str] = []
        cls.parsed = lg.check_local_dispositions(cls.entries, errs)
        assert errs == [], errs
        cls.runner = _load_gate_runner()

    def setUp(self) -> None:
        super().setUp()
        ws = lg.Workspace(self.root, os.path.join(self.root, "target"), {}, frozenset(), {})
        self.steps = lg.plan(lg.Tier.QUICK, self.entries, self.parsed, ["Cargo.lock"], ws)
        for rel in (".github/ci/manifest-lock-consistency.sh", "tools/scripts/generated-unchanged.sh", "Cargo.toml", "Cargo.lock"):
            os.makedirs(os.path.dirname(os.path.join(self.root, rel)), exist_ok=True)
            shutil.copy2(os.path.join(lg.REPO_ROOT, rel), os.path.join(self.root, rel))
        self.paths: list[str] = []
        for step in self.drift_checks():
            for rel in step.argv[1:]:
                src = os.path.join(lg.REPO_ROOT, rel)
                if os.path.isdir(src):
                    shutil.copytree(src, os.path.join(self.root, rel), dirs_exist_ok=True)
                    self.paths.append(rel)
                else:
                    os.makedirs(os.path.dirname(os.path.join(self.root, rel)), exist_ok=True)
                    shutil.copy2(src, os.path.join(self.root, rel))
                    self.paths.append(rel)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "base")

    def of(self, ctx: str) -> list[lg.Step]:
        found = [s for s in self.steps if s.context == ctx]
        self.assertTrue(found, f"`gate quick` plans no {ctx!r} step")
        return found

    def drift_checks(self) -> list[lg.Step]:
        out: list[lg.Step] = []
        for ctx in self.DRIFT_CONTEXTS:
            steps = self.of(ctx)
            self.assertGreater(len(steps), 1, f"{ctx}: no generator runs before the drift assertion")
            self.assertEqual(steps[-1].argv[0], "tools/scripts/generated-unchanged.sh", ctx)
            self.assertGreater(len(steps[-1].argv), 1, ctx)
            out.append(steps[-1])
        return out

    def run_gate(self, steps: list[lg.Step]) -> int:
        """`tools/scripts/gate quick` exit status, planning `steps`."""
        r = self.runner.local_gate
        ws = lg.Workspace(self.root, "", {}, frozenset(), {})
        with (
            mock.patch.object(r, "load_manifest_entries", return_value=self.entries),
            mock.patch.object(r, "check_local_dispositions", return_value=self.parsed),
            mock.patch.object(r, "load_workspace", return_value=ws),
            mock.patch.object(r, "changed_files", return_value=["Cargo.lock"]),
            mock.patch.object(r, "plan", return_value=steps),
            mock.patch.object(sys, "argv", ["gate", "quick", "--keep-going"]),
            _silenced(),
        ):
            return self.runner.main()

    def planted_steps(self) -> list[lg.Step]:
        return self.of("manifest-lock-consistency") + self.drift_checks()

    def test_clean_tree_passes(self) -> None:
        self.assertEqual(self.run_gate(self.planted_steps()), 0)

    def test_planted_manifest_lock_desync_fails_quick(self) -> None:
        lock = os.path.join(self.root, "Cargo.lock")
        with open(lock) as f:
            text = f.read()
        marker = 'name = "ipe"\nversion = "'
        self.assertIn(marker, text)
        with open(lock, "w") as f:
            f.write(text.replace(marker, marker + "9999.", 1))
        self.assertEqual(self.run_gate(self.planted_steps()), 1)

    def test_planted_doc_drift_fails_quick(self) -> None:
        for rel in self.paths:
            target = os.path.join(self.root, rel)
            files = (
                [os.path.join(target, sorted(os.listdir(target))[0])] if os.path.isdir(target) else [target]
            )
            for f in files:
                with open(f) as fh:
                    original = fh.read()
                for plant in ("changed", "deleted"):
                    with self.subTest(path=rel, plant=plant):
                        if plant == "changed":
                            with open(f, "a") as fh:
                                fh.write("\nplanted drift\n")
                        else:
                            os.remove(f)
                        self.assertEqual(self.run_gate(self.planted_steps()), 1)
                        with open(f, "w") as fh:
                            fh.write(original)
                        self.assertEqual(self.run_gate(self.planted_steps()), 0)

    def test_planted_new_generated_file_fails_quick(self) -> None:
        for rel in self.paths:
            if not rel.endswith("/"):
                continue
            with self.subTest(path=rel):
                new = os.path.join(self.root, rel, "PlantedNew.md")
                with open(new, "w") as f:
                    f.write("a generated file never committed\n")
                self.assertEqual(self.run_gate(self.planted_steps()), 1)
                os.remove(new)
                self.assertEqual(self.run_gate(self.planted_steps()), 0)
        self.assertTrue(any(p.endswith("/") for p in self.paths), "no drift gate covers a directory")


class GeneratedUnchanged(_TmpRepo):
    """`tools/scripts/generated-unchanged.sh` refusals."""

    SCRIPT = os.path.join(lg.REPO_ROOT, "tools", "scripts", "generated-unchanged.sh")

    def setUp(self) -> None:
        super().setUp()
        self.write("docs/a.md", "a\n")
        self.write("docs/d/b.md", "b\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "base")

    def status(self, *paths: str, cwd: str | None = None) -> int:
        return subprocess.run([self.SCRIPT, *paths], cwd=cwd or self.root, capture_output=True).returncode

    def test_clean_passes(self) -> None:
        self.assertEqual(self.status("docs/a.md", "docs/d/"), 0)

    def test_staged_regenerated_content_is_clean(self) -> None:
        self.write("docs/a.md", "regenerated\n")
        self.git("add", "docs/a.md")
        self.assertEqual(self.status("docs/a.md"), 0)

    def test_modified_deleted_and_untracked_refused(self) -> None:
        self.write("docs/a.md", "x\n")
        self.assertEqual(self.status("docs/a.md"), 1)
        self.git("checkout", "--", "docs/a.md")
        os.remove(os.path.join(self.root, "docs/d/b.md"))
        self.assertEqual(self.status("docs/d/"), 1)
        self.git("checkout", "--", "docs/d/b.md")
        self.write("docs/d/sub/new.md", "n\n")
        self.assertEqual(self.status("docs/d/"), 1)

    def test_ignored_output_refused(self) -> None:
        self.write(".gitignore", "*.gen\nhidden/\n")
        self.git("add", ".gitignore")
        self.git("commit", "-q", "-m", "ignore")
        self.assertEqual(self.status("docs/d/"), 0)
        self.write("docs/d/new.gen", "n\n")
        self.assertEqual(self.status("docs/d/"), 1)
        os.remove(os.path.join(self.root, "docs/d/new.gen"))
        self.write("docs/d/hidden/deep.md", "n\n")
        out = subprocess.run([self.SCRIPT, "docs/d/"], cwd=self.root, capture_output=True, text=True)
        self.assertEqual(out.returncode, 1)
        self.assertIn("ignored: docs/d/hidden/", out.stderr)

    def test_unusual_file_names_are_read_whole(self) -> None:
        for name in ("docs/d/sp ace.md", 'docs/d/q"uote.md', "docs/d/new\nline.md", "docs/d/tab\t.md"):
            with self.subTest(name=name):
                self.write(name, "n\n")
                out = subprocess.run([self.SCRIPT, "docs/d/"], cwd=self.root, capture_output=True, text=True)
                self.assertEqual(out.returncode, 1, out.stderr)
                self.assertIn("untracked: " + name, out.stderr)
                self.git("add", name)
                self.git("commit", "-q", "-m", "add")
                self.assertEqual(self.status("docs/d/"), 0)
                self.write(name, "changed\n")
                out = subprocess.run([self.SCRIPT, "docs/d/"], cwd=self.root, capture_output=True, text=True)
                self.assertEqual(out.returncode, 1, out.stderr)
                self.assertIn("changed: " + name, out.stderr)
                self.git("checkout", "--", name)

    def test_unmerged_path_refused(self) -> None:
        self.git("checkout", "-q", "-b", "side")
        self.write("docs/a.md", "side\n")
        self.git("commit", "-q", "-am", "side")
        self.git("checkout", "-q", "-")
        self.write("docs/a.md", "main\n")
        self.git("commit", "-q", "-am", "main")
        self.git("merge", "-q", "side", check=False)
        self.assertTrue(self.git("ls-files", "-u", "--", "docs/a.md").stdout, "the fixture merge must leave docs/a.md unmerged")
        out = subprocess.run([self.SCRIPT, "docs/a.md"], cwd=self.root, capture_output=True, text=True)
        self.assertEqual(out.returncode, 1, out.stderr)
        self.assertIn("unmerged: docs/a.md", out.stderr)

    def test_change_outside_the_paths_is_not_drift(self) -> None:
        self.write("docs/other.md", "o\n")
        self.assertEqual(self.status("docs/a.md", "docs/d/"), 0)

    def test_no_path_or_untracked_path_refused(self) -> None:
        self.assertEqual(self.status(), 2)
        self.assertEqual(self.status("docs/missing.md"), 2)
        self.assertEqual(self.status("docs/a.md", "nope/"), 2)

    def test_outside_a_repository_refused(self) -> None:
        with tempfile.TemporaryDirectory() as bare:
            self.assertNotEqual(self.status("docs/a.md", cwd=bare), 0)


if __name__ == "__main__":
    unittest.main()
