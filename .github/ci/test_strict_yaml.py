#!/usr/bin/env python3
"""Refusal proofs for `strict_yaml.py`, the loader every `.github/ci/*.py`
manifest verifier shares.

Each shape `yaml.safe_load` resolves silently but GitHub Actions does not
parse the same way — a duplicate key (top-level and nested), a `<<` merge
key, an anchor/alias pair — gets its own test, per PRINCIPLES.md "Prove the
refusals". `refuse_expression_assembly` (the separate check for a `run:`/
`env:` value that builds its target through a GitHub Actions expression
function instead of naming it literally) gets the same treatment. One
positive case proves the happy path still loads cleanly.

Pure stdlib `unittest` + PyYAML (already a CI dependency). No network.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import strict_yaml


class TestStrictSafeLoader(unittest.TestCase):
    # ---- happy path --------------------------------------------------

    def test_ordinary_document_loads_cleanly(self) -> None:
        # No top-level `on:` key here: under YAML 1.1's implicit-boolean
        # resolution (a plain PyYAML property, not this loader's concern)
        # a bare `on` scalar resolves to `True`, not the string "on" — that
        # gotcha is orthogonal to what this test proves.
        doc = strict_yaml.safe_load(
            "name: ci\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: cargo build\n      - run: cargo test\n"
        )
        self.assertEqual(
            doc,
            {
                "name": "ci",
                "jobs": {
                    "build": {
                        "runs-on": "ubuntu-latest",
                        "steps": [{"run": "cargo build"}, {"run": "cargo test"}],
                    }
                },
            },
        )

    # ---- duplicate keys ------------------------------------------------

    def test_duplicate_top_level_key_is_refused(self) -> None:
        with self.assertRaises(strict_yaml.StrictYAMLError) as ctx:
            strict_yaml.safe_load("run: echo safe\nrun: echo evil\n")
        self.assertIn("duplicate key", str(ctx.exception))
        self.assertIn("'run'", str(ctx.exception))

    def test_duplicate_nested_key_is_refused(self) -> None:
        with self.assertRaises(strict_yaml.StrictYAMLError) as ctx:
            strict_yaml.safe_load(
                "jobs:\n  build:\n    env:\n      RUSTC_WRAPPER: sccache\n"
                "      RUSTC_WRAPPER: evil\n"
            )
        self.assertIn("duplicate key", str(ctx.exception))

    def test_duplicate_key_is_still_refused_via_yaml_error_handler(self) -> None:
        # StrictYAMLError subclasses yaml.YAMLError so an unmodified
        # `except yaml.YAMLError` callsite still catches it.
        import yaml

        with self.assertRaises(yaml.YAMLError):
            strict_yaml.safe_load("a: 1\na: 2\n")

    # ---- merge keys -----------------------------------------------------

    def test_merge_key_via_alias_is_refused(self) -> None:
        with self.assertRaises(strict_yaml.StrictYAMLError):
            strict_yaml.safe_load(
                "base: &base\n  runs-on: ubuntu-latest\n"
                "job:\n  <<: *base\n  steps: []\n"
            )

    def test_merge_key_with_inline_mapping_is_refused(self) -> None:
        with self.assertRaises(strict_yaml.StrictYAMLError) as ctx:
            strict_yaml.safe_load("job:\n  <<:\n    runs-on: ubuntu-latest\n  steps: []\n")
        self.assertIn("merge key", str(ctx.exception))

    # ---- anchors and aliases --------------------------------------------

    def test_anchor_definition_is_refused(self) -> None:
        with self.assertRaises(strict_yaml.StrictYAMLError) as ctx:
            strict_yaml.safe_load("a: &anchor 1\nb: 2\n")
        self.assertIn("anchor", str(ctx.exception))

    def test_alias_is_refused(self) -> None:
        with self.assertRaises(strict_yaml.StrictYAMLError):
            strict_yaml.safe_load("a: &anchor 1\nb: *anchor\n")

    # ---- unhashable key (defense against a crash on malformed input) ----

    def test_unhashable_key_is_refused_not_a_crash(self) -> None:
        with self.assertRaises(strict_yaml.StrictYAMLError):
            strict_yaml.safe_load("? [a, b]\n: 1\n")


    def test_key_spelled_twice_with_different_quoting_is_refused(self) -> None:
        # `1` and `'1'` construct distinct Python keys but are one key to a
        # YAML 1.2 reader.
        with self.assertRaises(strict_yaml.StrictYAMLError) as ctx:
            strict_yaml.safe_load("env:\n  1: a\n  '1': b\n")
        self.assertIn("duplicate key", str(ctx.exception))

    def test_implicit_bool_key_colliding_with_on_is_refused(self) -> None:
        with self.assertRaises(strict_yaml.StrictYAMLError):
            strict_yaml.safe_load("on: push\ntrue: x\n")

    # ---- explicit tags ---------------------------------------------------

    def test_null_tag_hiding_scalar_text_is_refused(self) -> None:
        with self.assertRaises(strict_yaml.StrictYAMLError) as ctx:
            strict_yaml.safe_load("env:\n  X: !!null \"${{ format('RUSTC_{0}','WRAPPER') }}\"\n")
        self.assertIn("explicit tag", str(ctx.exception))

    def test_omap_tag_carrying_duplicate_keys_is_refused(self) -> None:
        with self.assertRaises(strict_yaml.StrictYAMLError):
            strict_yaml.safe_load("env: !!omap\n  - K: 1\n  - K: 2\n")

    def test_binary_tag_key_is_refused(self) -> None:
        with self.assertRaises(strict_yaml.StrictYAMLError):
            strict_yaml.safe_load("env:\n  !!binary UlVTVENfV1JBUFBFUg==: x\n")

    def test_explicit_merge_tag_is_refused(self) -> None:
        with self.assertRaises(strict_yaml.StrictYAMLError):
            strict_yaml.safe_load("job:\n  !!merge x:\n    runs-on: evil\n")

    def test_local_tag_is_refused(self) -> None:
        with self.assertRaises(strict_yaml.StrictYAMLError):
            strict_yaml.safe_load("a: !foo x\n")

    def test_str_tag_is_refused(self) -> None:
        with self.assertRaises(strict_yaml.StrictYAMLError):
            strict_yaml.safe_load("a: !!str x\n")

    # ---- YAML 1.1-only plain scalars ----------------------------------------

    def test_scalar_read_differently_by_yaml_1_2_is_refused(self) -> None:
        # Each loads under YAML 1.1 as a value GitHub's YAML 1.2 reader does
        # not produce: `yes` a bool (1.2: the string), `0x2`/`010`/`1_000`
        # an int (1.2: another int or a string), `1:30` a sexagesimal int,
        # `2001-01-01` a date, `1e3` a string (1.2: a float), `0o7` a string
        # (1.2: an int).
        for text in ("yes", "No", "on", "off", "0x2", "010", "1_000", "1:30", "2001-01-01", "1e3", "1.0e3", "0o7", "1_0.5"):
            with self.subTest(text=text):
                with self.assertRaises(strict_yaml.StrictYAMLError) as ctx:
                    strict_yaml.safe_load(f"a: {text}\n")
                self.assertIn("spell it as YAML 1.2 does", str(ctx.exception))
        for text in ("yes", "0x2"):
            with self.subTest(sequence=text):
                with self.assertRaises(strict_yaml.StrictYAMLError):
                    strict_yaml.safe_load(f"a: [{text}]\n")

    def test_scalar_both_readers_agree_on_loads(self) -> None:
        doc = strict_yaml.safe_load(
            "a: true\nb: false\nc: null\nd: ~\ne:\nf: 0\ng: -12\nh: 1.5\ni: 'yes'\nj: \"0x2\"\nk: x86_64\nl: --cfg x\n"
        )
        self.assertEqual(
            doc,
            {"a": True, "b": False, "c": None, "d": None, "e": None, "f": 0, "g": -12, "h": 1.5,
             "i": "yes", "j": "0x2", "k": "x86_64", "l": "--cfg x"},
        )
        # A mapping key keeps its YAML 1.1 reading: the workflow `on:` key.
        self.assertEqual(strict_yaml.safe_load("on: push\n"), {True: "push"})

    # ---- bounded nesting ---------------------------------------------------

    def test_over_deep_nesting_is_a_typed_refusal(self) -> None:
        with self.assertRaises(strict_yaml.StrictYAMLError) as ctx:
            strict_yaml.safe_load("[" * 5000 + "]" * 5000)
        self.assertIn("nested too deeply", str(ctx.exception))

    def test_multiple_documents_are_refused(self) -> None:
        import yaml

        with self.assertRaises(yaml.YAMLError):
            strict_yaml.safe_load("a: 1\n---\na: 2\n")


class TestRefuseExpressionAssembly(unittest.TestCase):
    def assertRefused(self, text: str) -> None:
        self.assertIsNotNone(strict_yaml.refuse_expression_assembly(text, "loc"), text)

    def test_function_names_match_case_insensitively(self) -> None:
        for fn in ("FORMAT", "Format", "JOIN", "tojson", "ToJson"):
            self.assertRefused(f"echo ${{{{ {fn}('RUSTC_{{0}}','WRAPPER') }}}}")

    def test_brace_inside_string_literal_does_not_end_the_scan(self) -> None:
        self.assertRefused("echo ${{ ('}') && format('RUSTC_{0}','WRAPPER') }}")
        self.assertRefused("echo ${{ '}}' && format('RUSTC_{0}','WRAPPER') }}")
        self.assertRefused("echo ${{ 'it''s }}' && format('x') }}")

    def test_later_expression_is_scanned(self) -> None:
        self.assertRefused("${{ github.ref }} ${{ format('RUSTC_{0}','WRAPPER') }}")

    def test_multiline_expression_is_refused(self) -> None:
        self.assertRefused("echo ${{\n  format(\n'RUSTC_{0}', 'WRAPPER') }}")

    def test_fromjson_over_a_literal_is_refused(self) -> None:
        self.assertRefused("echo ${{ fromJSON('\"RUSTC\\u005fWRAPPER\"') }}=x >> $GITHUB_ENV")
        self.assertRefused("echo ${{ fromjson(('\"RUSTC\\u005fWRAPPER\"')) }}")
        self.assertRefused("echo ${{ fromJSON(x || '\"a\"') }}")

    def test_fromjson_over_context_only_is_not_refused(self) -> None:
        self.assertIsNone(
            strict_yaml.refuse_expression_assembly(
                "${{ fromJSON(needs.release-please.outputs.pr).headBranchName }}", "loc"
            )
        )

    def test_call_name_inside_a_literal_is_not_refused(self) -> None:
        self.assertIsNone(
            strict_yaml.refuse_expression_assembly("${{ github.ref == 'format(x)' }}", "loc")
        )

    def test_call_outside_any_expression_is_not_refused(self) -> None:
        self.assertIsNone(
            strict_yaml.refuse_expression_assembly("python3 -c 'print(format(1))'", "loc")
        )

    def test_format_call_is_refused(self) -> None:
        msg = strict_yaml.refuse_expression_assembly(
            "echo \"${{ format('RUSTC_{0}','WRAPPER') }}=sccache\" >> \"$GITHUB_ENV\"",
            "ci.yml:build:Build",
        )
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertIn("ci.yml:build:Build", msg)
        self.assertIn("format", msg)

    def test_join_call_is_refused(self) -> None:
        msg = strict_yaml.refuse_expression_assembly(
            "${{ join(github.event.inputs.*, '_') }}", "loc"
        )
        self.assertIsNotNone(msg)

    def test_tojson_call_is_refused(self) -> None:
        msg = strict_yaml.refuse_expression_assembly("${{ toJSON(github.event) }}", "loc")
        self.assertIsNotNone(msg)

    def test_plain_literal_text_is_not_refused(self) -> None:
        self.assertIsNone(
            strict_yaml.refuse_expression_assembly(
                "echo \"RUSTC_WRAPPER=sccache\" >> \"$GITHUB_ENV\"", "loc"
            )
        )

    def test_unrelated_expression_is_not_refused(self) -> None:
        self.assertIsNone(
            strict_yaml.refuse_expression_assembly("${{ github.ref }}", "loc")
        )

    def test_none_text_is_not_refused(self) -> None:
        self.assertIsNone(strict_yaml.refuse_expression_assembly(None, "loc"))


if __name__ == "__main__":
    unittest.main()
