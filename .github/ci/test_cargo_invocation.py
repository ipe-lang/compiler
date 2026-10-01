#!/usr/bin/env python3
"""Tests for `cargo_invocation` and the `shell_lex` scopes it reads."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cargo_invocation  # noqa: E402
import shell_lex  # noqa: E402

_LAYOUT = cargo_invocation.layout(
    {"workspace": {"members": ["src/a", "src/b"]}},
    ["Cargo.toml", "src/a/Cargo.toml", "src/a/src/lib.rs", "src/b/Cargo.toml", "ext/c/Cargo.toml", "docs/x.md"],
    lambda d: d.startswith("docs/out"),
)


def _parse(line: str) -> cargo_invocation.CargoInvocation | str:
    return cargo_invocation.parse(line.split()[1:])


class TestParse(unittest.TestCase):
    def test_selection_spellings(self) -> None:
        for line, pkgs in (
            ("cargo build -p a", ("a",)),
            ("cargo b --package=a -pb", ("a", "b")),
            ("cargo +nightly --locked -q test -p=a@1", ("a@1",)),
            ("cargo nextest run -p a -E test(x)", ("a",)),
            ("cargo run -p a -- -p b", ("a",)),
        ):
            with self.subTest(line=line):
                inv = _parse(line)
                assert isinstance(inv, cargo_invocation.CargoInvocation), inv
                self.assertEqual(inv.packages, pkgs)

    def test_globals_bins_manifest_workspace(self) -> None:
        inv = _parse("cargo -C x --config k=v build --bin z --manifest-path m/Cargo.toml --workspace")
        assert isinstance(inv, cargo_invocation.CargoInvocation), inv
        self.assertEqual((inv.directory, inv.bins, inv.manifest_path, inv.workspace), ("x", ("z",), "m/Cargo.toml", True))
        self.assertEqual(_parse("cargo run --release").subcommand, "run")  # type: ignore[union-attr]

    def test_install_reads_crates_and_path(self) -> None:
        inv = _parse("cargo install tree-sitter-cli --version ^0.27.0 --locked")
        assert isinstance(inv, cargo_invocation.CargoInvocation), inv
        self.assertEqual((inv.install_crates, inv.install_path), (("tree-sitter-cli",), None))
        inv = _parse("cargo install --path src/a")
        assert isinstance(inv, cargo_invocation.CargoInvocation), inv
        self.assertEqual(inv.install_path, "src/a")

    def test_inert_subcommands_are_not_read(self) -> None:
        for line in ("cargo fmt --all -- --check", "cargo deny check advisories", "cargo update --workspace"):
            with self.subTest(line=line):
                self.assertIsInstance(_parse(line), cargo_invocation.CargoInvocation)

    def test_unreadable_shapes_refused(self) -> None:
        for line, needle in (
            ("cargo --frob build", "global option"),
            ("cargo -C", "lacks its value"),
            ("cargo bld", "cargo alias"),
            ("cargo nextest frob", "nextest subcommand"),
            ("cargo build --frob", "option '--frob'"),
            ("cargo build -p", "lacks its value"),
            ("cargo build stray", "operand 'stray'"),
            ("cargo test --frob --lib", "option '--frob'"),
            ("cargo test --target", "lacks its value"),
            ("cargo test --target=", "--target lacks its value"),
            ("cargo test --target a --target b", "more than one --target"),
            ("cargo test --features=", "names no feature"),
            ("cargo test -F ,", "names no feature"),
            ("cargo test --test=", "--test lacks its value"),
            ("cargo nextest run --frob", "option '--frob'"),
        ):
            with self.subTest(line=line):
                got = _parse(line)
                self.assertIsInstance(got, str)
                self.assertIn(needle, got)  # type: ignore[arg-type]


class TestTargetsAndFeatures(unittest.TestCase):
    def test_target_features_and_flags(self) -> None:
        inv = _parse("cargo test -p a --target wasm32-unknown-unknown -F x,y --features=z -Fw --no-default-features --lib")
        assert isinstance(inv, cargo_invocation.CargoInvocation), inv
        self.assertEqual(inv.target, "wasm32-unknown-unknown")
        self.assertEqual(inv.features, frozenset({"x", "y", "z", "w"}))
        self.assertTrue(inv.no_default_features)
        self.assertFalse(inv.all_features)
        inv = _parse("cargo test --all-features --no-run filt")
        assert isinstance(inv, cargo_invocation.CargoInvocation), inv
        self.assertEqual((inv.all_features, inv.no_run, inv.filtered, inv.target), (True, True, True, None))

    def test_selection(self) -> None:
        for line, lib, named, other in (
            ("cargo test", True, True, True),
            ("cargo test --lib", True, False, False),
            ("cargo test --test n", False, True, False),
            ("cargo test --test m", False, False, False),
            ("cargo test --tests", False, True, False),
            ("cargo test --all-targets", True, True, True),
            ("cargo test --bins", False, False, True),
            ("cargo test --lib --test=n", True, True, False),
        ):
            with self.subTest(line=line):
                inv = _parse(line)
                assert isinstance(inv, cargo_invocation.CargoInvocation), inv
                sel = inv.selection
                self.assertEqual((sel.selects("lib"), sel.selects("test:n")), (lib, named))
                self.assertFalse(sel.selects("n"))
                if isinstance(sel, cargo_invocation.ExplicitTargets):
                    self.assertEqual(sel.other, other)
                else:
                    self.assertTrue(other)


class TestResolve(unittest.TestCase):
    def test_paths(self) -> None:
        r = cargo_invocation.resolve
        self.assertEqual(r("", "src/a/"), "src/a")
        self.assertEqual(r("src", "./a/../b"), "src/b")
        self.assertEqual(r("src/a", "$GITHUB_WORKSPACE/x"), "x")
        self.assertEqual(r("src", ".."), "")
        for cwd, path in (("", ".."), ("", "/abs"), ("", "$D/x"), ("", "~/x"), ("", "a*"), (None, "x")):
            with self.subTest(path=path):
                self.assertIsNone(r(cwd, path))


class TestInShell(unittest.TestCase):
    def cwds(self, text: str) -> list[tuple[str | None, str]]:
        out = []
        for f in cargo_invocation.in_shell(text):
            inv = f.invocation
            out.append((f.cwd, inv if isinstance(inv, str) else inv.subcommand))
        return out

    def test_directory_tracking(self) -> None:
        self.assertEqual(self.cwds("cd src/a && cargo build"), [("src/a", "build")])
        self.assertEqual(self.cwds("(cd src/a); cargo build"), [("", "build")])
        self.assertEqual(self.cwds("cd src; (cd a && cargo build); cargo check"), [("src/a", "build"), ("src", "check")])
        self.assertEqual(self.cwds('cd "$d"; cargo build'), [(None, "build")])
        self.assertEqual(self.cwds("pushd src/a; popd; cargo build"), [(None, "build")])
        self.assertEqual(self.cwds("cd ${{ github.workspace }}/src/b\ncargo build"), [("src/b", "build")])

    def test_wrappers_and_bodies(self) -> None:
        for text in (
            "RUSTFLAGS=x env -u Y timeout 5m nice cargo build",
            "sh -c 'cargo build'",
            "bash -ec \"cd src/a && cargo build\"",
            "eval cargo build",
            "x=$(cargo build)",
            'y="$(cargo build)"',
        ):
            with self.subTest(text=text):
                got = self.cwds(text)
                self.assertEqual(len(got), 1, got)
                self.assertEqual(got[0][1], "build")

    def test_data_is_not_a_command(self) -> None:
        for text in ("echo cargo build", "printf 'cargo build'", "command -v cargo", "test -x cargo"):
            with self.subTest(text=text):
                self.assertEqual(self.cwds(text), [])

    def test_unread_carrier_refused(self) -> None:
        for text in ("xargs cargo build", "env -C src/a cargo build", "find . -exec cargo build \\;"):
            with self.subTest(text=text):
                got = self.cwds(text)
                self.assertTrue(got and all(isinstance(g[1], str) and " " in g[1] for g in got), got)

    def test_nesting_bound(self) -> None:
        text = "cargo build"
        for _ in range(cargo_invocation.NESTING_LIMIT + 1):
            text = "sh -c " + shell_lex_quote(text)
        got = self.cwds(text)
        self.assertTrue(any("nests shell bodies" in g[1] for g in got), got)


def shell_lex_quote(text: str) -> str:
    return "'" + text.replace("'", "'\\''") + "'"


class TestSelect(unittest.TestCase):
    def sel(self, line: str, cwd: str | None = "") -> cargo_invocation.Selection | str:
        inv = _parse(line)
        assert isinstance(inv, cargo_invocation.CargoInvocation), inv
        return cargo_invocation.select(inv, cwd, _LAYOUT)

    def test_directory_defaults(self) -> None:
        self.assertTrue(self.sel("cargo build").whole_workspace)  # type: ignore[union-attr]
        self.assertEqual(self.sel("cargo build", "src/a/src").dirs, ("src/a",))  # type: ignore[union-attr]
        self.assertEqual(self.sel("cargo -C src/b build").dirs, ("src/b",))  # type: ignore[union-attr]
        self.assertEqual(self.sel("cargo build --manifest-path ../b/Cargo.toml", "src/a").dirs, ("src/b",))  # type: ignore[union-attr]
        self.assertEqual(self.sel("cargo build --bin z").bins, ("z",))  # type: ignore[union-attr]
        self.assertFalse(self.sel("cargo build --bin z").whole_workspace)  # type: ignore[union-attr]

    def test_outside_the_workspace(self) -> None:
        for line, cwd, known in (
            ("cargo build", "ext/c", True),
            ("cargo build", "docs/out/rust", True),
            ("cargo build", None, False),
            ("cargo build --manifest-path $X/Cargo.toml", "", False),
        ):
            with self.subTest(line=line, cwd=cwd):
                got = self.sel(line, cwd)
                assert isinstance(got, cargo_invocation.Selection), got
                self.assertEqual((got.in_workspace, got.known), (False, known))

    def test_unheld_unreserved_directory_searches_upward(self) -> None:
        self.assertTrue(self.sel("cargo build", "new/dir").whole_workspace)  # type: ignore[union-attr]

    def test_refusals(self) -> None:
        self.assertIn("names no Cargo.toml", self.sel("cargo build --manifest-path src/a"))  # type: ignore[arg-type]
        top = cargo_invocation.layout({"workspace": {"members": ["src/a"], "default-members": ["src/a"]}}, ["Cargo.toml"])
        inv = _parse("cargo build")
        assert isinstance(inv, cargo_invocation.CargoInvocation)
        self.assertIsInstance(cargo_invocation.select(inv, "", top), str)


class TestShellLexScopes(unittest.TestCase):
    def test_subshells_are_numbered(self) -> None:
        got = [(c.words, c.subshell) for c in shell_lex.split_commands("cd a; (cd b && cargo build); x `y`")]
        self.assertEqual(got[0], (["cd", "a"], ()))
        self.assertEqual(got[1][1], got[2][1])
        self.assertNotEqual(got[1][1], ())
        self.assertEqual(got[3], (["x"], ()))
        self.assertNotEqual(got[4][1], ())

    def test_substitution_pass_ends_at_its_closer(self) -> None:
        text = 'd="$(dirname "$t")"\ne="`basename q`"; ( cd "$d" && cargo build )\ncat <<E\n`id` $(date)\nE\n'
        words = [c.words for c in shell_lex.split_commands(text)]
        for expect in (["dirname", "$t"], ["basename", "q"], ["id"], ["date"], ["cargo", "build"]):
            self.assertIn(expect, words)
        # No pass reads past a closer into the quoted text after it.
        self.assertEqual(sum(w == ["cargo", "build"] for w in words), 1, words)


if __name__ == "__main__":
    unittest.main()
