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

import os
import sys
import tempfile
import textwrap
import unittest

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

    def test_covered_by_and_ci_only(self) -> None:
        self.accepts(
            gate("fmt", run("cargo fmt --all -- --check")),
            gate("slice", {"covered-by": "fmt"}),
            gate("win", {"ci-only": "platform"}),
        )


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
    gate("e2e", run({"cmd": "cargo nextest run --workspace", "env": {"BIN": "{target_dir}/ipe"}}, tier="full")),
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
        self.assertEqual([s.env for s in e2e], [(("BIN", "/t/ipe"),)])


class LiveManifest(unittest.TestCase):
    def test_live_manifest_verifies_against_live_workflows(self) -> None:
        errs: list[str] = []
        parsed = lg.check_local_dispositions(lg.load_manifest_entries(), errs)
        self.assertEqual(errs, [])
        self.assertTrue(any(isinstance(d, lg.RunLocal) and d.tier is lg.Tier.QUICK for d in parsed.values()))


if __name__ == "__main__":
    unittest.main()
