#!/usr/bin/env python3
"""Refusal proofs for `verify-manifest.py`'s sccache-wiring check (check 6).

Each rejection the guard is supposed to make (a raw sccache-action reference,
a case-variant `uses:`, an env key at workflow/job/step level, a `$GITHUB_ENV`
write, a deterministic job pulling in sccache, a broken composite) gets its
own fixture tree and its own test, per PRINCIPLES.md "Prove the refusals": a
guard no test drives is a guard one edit away from silently vanishing. One
positive case proves the happy path still passes cleanly.

Pure stdlib `unittest`, no network, no PyYAML dependency beyond what
verify-manifest.py itself already requires.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(HERE, "verify-manifest.py")

_spec = importlib.util.spec_from_file_location("verify_manifest", MODULE_PATH)
assert _spec is not None and _spec.loader is not None
verify_manifest = importlib.util.module_from_spec(_spec)
sys.modules["verify_manifest"] = verify_manifest
_spec.loader.exec_module(verify_manifest)

check_sccache_wiring = verify_manifest.check_sccache_wiring

# The live sanctioned composite is the fixture: the canonical form is proven
# against the file CI actually runs, never a hand-kept copy.
with open(os.path.join(os.path.dirname(HERE), "actions", "sccache", "action.yml")) as _f:
    VALID_COMPOSITE = _f.read()


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


class SccacheFixture:
    """A scratch repository whose `.github/` holds workflows/, actions/sccache/,
    ci/ — `repo` is the repository root local `uses: ./...` resolve against."""

    def __init__(self, tmp: str, *, composite: str | None = VALID_COMPOSITE):
        self.repo = tmp
        self.root = os.path.join(tmp, ".github")
        os.makedirs(self.root, exist_ok=True)
        tmp = self.root
        if composite is not None:
            _write(os.path.join(tmp, "actions", "sccache", "action.yml"), composite)
        self.deterministic_checks(context="unrelated", step="Unrelated step")

    def workflow(self, fname: str, content: str) -> None:
        _write(os.path.join(self.root, "workflows", fname), content)

    def composite(self, name: str, content: str) -> None:
        """Write an arbitrary local composite action at
        `.github/actions/<name>/action.yml` — for wrapper/nesting/escape
        fixtures, distinct from the sanctioned sccache composite itself."""
        _write(os.path.join(self.root, "actions", name, "action.yml"), content)

    def deterministic_checks(self, *, context: str, step: str) -> None:
        import json

        _write(
            os.path.join(self.root, "ci", "deterministic-checks.json"),
            json.dumps({"about": "fixture", "checks": [{"context": context, "step": step}]}),
        )

    def errors(self) -> list[str]:
        errors: list[str] = []
        check_sccache_wiring(errors, root=self.root)
        return errors


class TestSccacheWiringRefusals(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.fx = SccacheFixture(self._tmpdir.name)

    # ---- positive case ------------------------------------------------

    def test_composite_in_non_deterministic_job_passes_cleanly(self) -> None:
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/checkout@v7
                      - uses: ./.github/actions/sccache
                      - run: cargo build
                """
            ),
        )
        self.assertEqual(self.fx.errors(), [])

    # ---- (a) raw action reference outside the composite ----------------

    def test_raw_sccache_action_outside_composite_is_refused(self) -> None:
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: mozilla-actions/sccache-action@v0.0.9
                      - run: cargo build
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any("runs the raw" in e and "build" in e for e in errors), errors
        )

    def test_case_variant_uses_is_still_refused(self) -> None:
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: Mozilla-Actions/Sccache-Action@v0.0.9
                      - run: cargo build
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(any("runs the raw" in e for e in errors), errors)

    # ---- (b) env key at each scope --------------------------------------

    def test_workflow_level_env_is_refused(self) -> None:
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                env:
                  RUSTC_WRAPPER: sccache
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: ./.github/actions/sccache
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any("workflow-level env sets" in e and "rustc_wrapper" in e for e in errors),
            errors,
        )

    def test_job_level_env_is_refused(self) -> None:
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    env:
                      SCCACHE_GHA_ENABLED: "true"
                    steps:
                      - uses: ./.github/actions/sccache
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any(
                "job 'build' env sets" in e and "sccache_gha_enabled" in e
                for e in errors
            ),
            errors,
        )

    def test_step_level_env_is_refused(self) -> None:
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: ./.github/actions/sccache
                      - name: Some step
                        env:
                          RUSTC_WRAPPER: ""
                        run: cargo build
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any("step 'Some step' env sets" in e for e in errors), errors
        )

    # ---- (c) $GITHUB_ENV write outside the composite --------------------

    def test_github_env_write_outside_composite_is_refused(self) -> None:
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - name: Sneak the wrapper in
                        run: |
                          echo "RUSTC_WRAPPER=sccache" >> "$GITHUB_ENV"
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any("writes RUSTC_WRAPPER" in e and "GITHUB_ENV" in e for e in errors),
            errors,
        )

    # ---- (d) composite in a job owning a deterministic check step -------

    def test_composite_in_deterministic_job_is_refused(self) -> None:
        self.fx.deterministic_checks(context="clippy", step="Run clippy")
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                jobs:
                  clippy:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: ./.github/actions/sccache
                      - name: Run clippy
                        run: cargo clippy
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any(
                "job 'clippy' uses ./.github/actions/sccache" in e
                and "Run clippy" in e
                for e in errors
            ),
            errors,
        )

    def test_composite_in_non_deterministic_job_is_fine_even_with_the_file_present(
        self,
    ) -> None:
        # Same deterministic-checks.json as above, but the composite is used by
        # a DIFFERENT job that does not own the named step — must not false-positive.
        self.fx.deterministic_checks(context="clippy", step="Run clippy")
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                jobs:
                  clippy:
                    runs-on: ubuntu-latest
                    steps:
                      - name: Run clippy
                        run: cargo clippy
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: ./.github/actions/sccache
                      - run: cargo build
                """
            ),
        )
        self.assertEqual(self.fx.errors(), [])

    # ---- composite self-validation --------------------------------------

    def test_missing_composite_file_is_refused(self) -> None:
        empty_tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(empty_tmpdir.cleanup)
        fx = SccacheFixture(empty_tmpdir.name, composite=None)
        fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - run: cargo build
                """
            ),
        )
        errors = fx.errors()
        self.assertTrue(any("does not exist" in e for e in errors), errors)

    def test_composite_not_actually_composite_is_refused(self) -> None:
        fx = SccacheFixture(
            self._tmpdir.name,
            composite=textwrap.dedent(
                """\
                name: not composite
                runs:
                  using: node20
                  main: index.js
                """
            ),
        )
        fx.workflow(
            "ci.yml",
            "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: x\n",
        )
        errors = fx.errors()
        self.assertTrue(any("must be 'composite'" in e for e in errors), errors)

    def test_composite_missing_env_write_is_refused(self) -> None:
        fx = SccacheFixture(
            self._tmpdir.name,
            composite=textwrap.dedent(
                """\
                name: incomplete
                runs:
                  using: composite
                  steps:
                    - uses: mozilla-actions/sccache-action@v0.0.9
                """
            ),
        )
        fx.workflow(
            "ci.yml",
            "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: x\n",
        )
        errors = fx.errors()
        self.assertTrue(
            any("exactly two steps" in e for e in errors), errors
        )

    # ---- (1) normalized local `uses:` path, not raw-string, comparison ---

    def test_trailing_slash_composite_path_is_still_caught_by_rule_d(self) -> None:
        self.fx.deterministic_checks(context="clippy", step="Run clippy")
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                jobs:
                  clippy:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: ./.github/actions/sccache/
                      - name: Run clippy
                        run: cargo clippy
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any(
                "job 'clippy' uses ./.github/actions/sccache" in e
                and "Run clippy" in e
                for e in errors
            ),
            errors,
        )

    def test_dotted_composite_path_is_still_caught_by_rule_d(self) -> None:
        self.fx.deterministic_checks(context="clippy", step="Run clippy")
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                jobs:
                  clippy:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: ./.github/actions/./sccache
                      - name: Run clippy
                        run: cargo clippy
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any(
                "job 'clippy' uses ./.github/actions/sccache" in e
                and "Run clippy" in e
                for e in errors
            ),
            errors,
        )

    # ---- (2) other local composite actions are audited, not just workflows

    def test_other_composite_running_raw_sccache_action_is_refused(self) -> None:
        self.fx.composite(
            "leaky",
            textwrap.dedent(
                """\
                name: leaky
                description: not the sanctioned composite
                runs:
                  using: composite
                  steps:
                    - uses: mozilla-actions/sccache-action@v0.0.9
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any("runs the raw" in e and "leaky" in e for e in errors), errors
        )

    def test_other_composite_writing_github_env_is_refused(self) -> None:
        self.fx.composite(
            "sneaky",
            textwrap.dedent(
                """\
                name: sneaky
                description: hand-wires the wrapper itself
                runs:
                  using: composite
                  steps:
                    - name: Wire it by hand
                      shell: bash
                      run: |
                        echo "RUSTC_WRAPPER=sccache" >> "$GITHUB_ENV"
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any("writes RUSTC_WRAPPER" in e and "sneaky" in e for e in errors), errors
        )

    def test_other_composite_nesting_sccache_is_reachable_via_rule_d(self) -> None:
        self.fx.composite(
            "wrapper",
            textwrap.dedent(
                """\
                name: wrapper
                description: wraps the sanctioned composite one level deep
                runs:
                  using: composite
                  steps:
                    - uses: ./.github/actions/sccache
                """
            ),
        )
        self.fx.deterministic_checks(context="clippy", step="Run clippy")
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                jobs:
                  clippy:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: ./.github/actions/wrapper
                      - name: Run clippy
                        run: cargo clippy
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any(
                "job 'clippy' uses" in e
                and "via" in e
                and "wrapper" in e
                and "Run clippy" in e
                for e in errors
            ),
            errors,
        )

    # ---- (3) a $GITHUB_ENV write need not use `KEY=` assignment syntax ----

    def test_printf_style_github_env_write_is_refused(self) -> None:
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - name: Sneak the wrapper in
                        run: |
                          printf '%s=%s\\n' RUSTC_WRAPPER sccache >> "$GITHUB_ENV"
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any(
                "writes RUSTC_WRAPPER" in e and "GITHUB_ENV" in e and "build" in e
                for e in errors
            ),
            errors,
        )

    # ---- (4) the fuller wrapper-var SSOT is enforced, not just RUSTC_WRAPPER

    def test_cargo_build_rustc_wrapper_env_key_is_refused(self) -> None:
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    env:
                      CARGO_BUILD_RUSTC_WRAPPER: sccache
                    steps:
                      - uses: ./.github/actions/sccache
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any(
                "job 'build' env sets" in e and "cargo_build_rustc_wrapper" in e
                for e in errors
            ),
            errors,
        )

    # ---- (5) `.yaml` workflows are scanned, not just `.yml` ---------------

    def test_dot_yaml_workflow_extension_is_scanned(self) -> None:
        self.fx.workflow(
            "nightly.yaml",
            textwrap.dedent(
                """\
                name: nightly
                on: schedule
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: mozilla-actions/sccache-action@v0.0.9
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any("runs the raw" in e and "nightly.yaml" in e for e in errors), errors
        )

    # ---- (6) container:/services: env scopes are scanned too --------------

    def test_container_env_is_refused(self) -> None:
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    container:
                      image: rust:latest
                      env:
                        RUSTC_WRAPPER: sccache
                    steps:
                      - uses: ./.github/actions/sccache
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any(
                "job 'build' container env sets" in e and "rustc_wrapper" in e
                for e in errors
            ),
            errors,
        )

    def test_service_env_is_refused(self) -> None:
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    services:
                      db:
                        image: postgres
                        env:
                          SCCACHE_GHA_ENABLED: "true"
                    steps:
                      - uses: ./.github/actions/sccache
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any(
                "job 'build' service 'db' env sets" in e
                and "sccache_gha_enabled" in e
                for e in errors
            ),
            errors,
        )

    # ---- (7) a non-mapping `env:` fails closed instead of defaulting empty

    def test_non_mapping_workflow_env_fails_closed(self) -> None:
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                env: ${{ fromJSON(vars.E) }}
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: ./.github/actions/sccache
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any("not a plain mapping" in e and "ci.yml" in e for e in errors), errors
        )

    def test_non_mapping_step_env_fails_closed(self) -> None:
        self.fx.workflow(
            "ci.yml",
            textwrap.dedent(
                """\
                name: ci
                on: push
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: ./.github/actions/sccache
                      - name: Some step
                        env: ${{ fromJSON(vars.E) }}
                        run: cargo build
                """
            ),
        )
        errors = self.fx.errors()
        self.assertTrue(
            any(
                "not a plain mapping" in e and "Some step" in e for e in errors
            ),
            errors,
        )



def _ci(job_body: str, *, top: str = "") -> str:
    """A one-job `ci.yml` (job id `clippy`) with `job_body` under the job."""
    return (
        "name: ci\non: push\n"
        + top
        + "jobs:\n  clippy:\n    runs-on: ubuntu-latest\n"
        + textwrap.indent(textwrap.dedent(job_body), "    ")
    )


class TestSccacheWiringClosure(unittest.TestCase):
    """Each class of wiring check 6 must refuse, one fixture per shape."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.fx = SccacheFixture(self._tmpdir.name)

    def assertRefused(self, *needles: str) -> list[str]:
        errors = self.fx.errors()
        self.assertTrue(any(all(n in e for n in needles) for e in errors), errors)
        return errors

    def ci(self, job_body: str, **kw: str) -> None:
        self.fx.workflow("ci.yml", _ci(job_body, **kw))

    def repo_action(self, rel_dir: str, content: str, fname: str = "action.yml") -> None:
        _write(os.path.join(self.fx.repo, rel_dir, fname), textwrap.dedent(content))

    # ---- positive: benign shapes stay clean ------------------------------

    def test_yaml_comment_naming_the_wrapper_is_not_scanned(self) -> None:
        self.fx.workflow(
            "ci.yml",
            "# a job that wants RUSTC_WRAPPER uses ./.github/actions/sccache\n"
            + _ci("steps:\n  - uses: ./.github/actions/sccache\n  - run: cargo build\n"),
        )
        self.assertEqual(self.fx.errors(), [])

    def test_benign_composite_outside_github_actions_passes(self) -> None:
        self.repo_action(
            "tools/ci/setup",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: rustc --version\n",
        )
        self.ci("steps:\n  - uses: ./tools/ci/setup\n  - run: cargo build\n")
        self.assertEqual(self.fx.errors(), [])

    # ---- (c) free-text wiring, no $GITHUB_ENV needed ----------------------

    def test_inline_env_in_run_is_refused(self) -> None:
        self.ci("steps:\n  - name: Build\n    run: RUSTC_WRAPPER=sccache cargo build\n")
        self.assertRefused("step 'Build' run:", "RUSTC_WRAPPER")

    def test_export_in_run_is_refused(self) -> None:
        self.ci("steps:\n  - name: Build\n    run: export rustc_workspace_wrapper=sccache\n")
        self.assertRefused("step 'Build' run:")

    def test_step_shell_wrapper_is_refused(self) -> None:
        self.ci(
            "steps:\n  - name: Build\n    shell: env RUSTC_WRAPPER=sccache bash -e {0}\n"
            "    run: cargo build\n"
        )
        self.assertRefused("step 'Build' shell:")

    def test_job_defaults_run_shell_is_refused(self) -> None:
        self.ci(
            "defaults:\n  run:\n    shell: env RUSTC_WRAPPER=sccache bash {0}\n"
            "steps:\n  - run: cargo build\n"
        )
        self.assertRefused("job 'clippy' defaults.run.shell")

    def test_workflow_defaults_run_shell_is_refused(self) -> None:
        self.ci(
            "steps:\n  - run: cargo build\n",
            top="defaults:\n  run:\n    shell: env SCCACHE_GHA_ENABLED=true bash {0}\n",
        )
        self.assertRefused("ci.yml defaults.run.shell")

    def test_cargo_config_flag_is_refused(self) -> None:
        self.ci("steps:\n  - name: Build\n    run: cargo --config build.rustc-wrapper='\"sccache\"' build\n")
        self.assertRefused("step 'Build' run:", "rustc-wrapper")

    def test_cargo_config_file_write_is_refused(self) -> None:
        self.ci(
            "steps:\n  - name: Cfg\n"
            "    run: printf '[build]\\nrustc-wrapper = \"sccache\"\\n' >> ~/.cargo/config.toml\n"
        )
        self.assertRefused("step 'Cfg' run:")

    def test_with_input_naming_the_wrapper_is_refused(self) -> None:
        self.ci("steps:\n  - uses: some/action@v1\n    with:\n      rustc-wrapper: sccache\n")
        self.assertRefused("with.rustc-wrapper")

    def test_composite_step_shell_wrapper_is_refused(self) -> None:
        self.fx.composite(
            "w",
            "runs:\n  using: composite\n  steps:\n"
            "    - shell: env RUSTC_WRAPPER=sccache bash {0}\n      run: cargo build\n",
        )
        self.ci("steps:\n  - uses: ./.github/actions/w\n")
        self.assertRefused("./.github/actions/w/action.yml", "shell:")

    # ---- (b) every wrapper key, every scope ------------------------------

    def test_workspace_wrapper_env_keys_are_refused(self) -> None:
        for key in ("RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER"):
            with self.subTest(key=key):
                self.ci(f"env:\n  {key}: sccache\nsteps:\n  - run: cargo build\n")
                self.assertRefused("job 'clippy' env sets", key.casefold())

    def test_env_key_inside_other_composite_is_refused(self) -> None:
        self.fx.composite(
            "w",
            "runs:\n  using: composite\n  steps:\n"
            "    - name: B\n      shell: bash\n      run: cargo build\n"
            "      env:\n        RUSTC_WRAPPER: sccache\n",
        )
        self.ci("steps:\n  - uses: ./.github/actions/w\n")
        self.assertRefused("./.github/actions/w/action.yml: step 'B' env sets")

    def test_non_mapping_env_at_every_scope_fails_closed(self) -> None:
        expr = "${{ fromJSON(vars.E) }}"
        cases = {
            "job": f"env: {expr}\nsteps: []\n",
            "container": f"container:\n  image: rust\n  env: {expr}\nsteps: []\n",
            "service": f"services:\n  db:\n    image: pg\n    env: {expr}\nsteps: []\n",
        }
        for scope, body in cases.items():
            with self.subTest(scope=scope):
                self.ci(body)
                self.assertRefused("not a plain mapping")
        self.ci("steps:\n  - uses: ./.github/actions/w\n")
        self.fx.composite(
            "w",
            f"runs:\n  using: composite\n  steps:\n    - name: B\n      shell: bash\n"
            f"      run: x\n      env: {expr}\n",
        )
        self.assertRefused("./.github/actions/w/action.yml: step 'B'", "not a plain mapping")

    # ---- local `uses:` resolution (F1) -----------------------------------

    def test_unresolved_local_action_is_refused(self) -> None:
        for uses in ("./.github/actions/sccache@main", "./tools/ci/cache", "./.github/actions/nope"):
            with self.subTest(uses=uses):
                self.ci(f"steps:\n  - uses: {uses}\n")
                self.assertRefused("does not exist")

    def test_local_action_escaping_repo_is_refused(self) -> None:
        self.ci("steps:\n  - uses: ./../elsewhere\n")
        self.assertRefused("escapes the repository root")

    def test_node_and_docker_local_actions_are_refused(self) -> None:
        for using in ("node20", "docker"):
            with self.subTest(using=using):
                self.fx.composite("opaque", f"runs:\n  using: {using}\n  main: index.js\n")
                self.ci("steps:\n  - uses: ./.github/actions/opaque\n")
                self.assertRefused("must be 'composite'", repr(using))

    def test_both_action_yml_and_yaml_is_refused(self) -> None:
        self.fx.composite("w", "runs:\n  using: composite\n  steps: []\n")
        _write(
            os.path.join(self.fx.root, "actions", "w", "action.yaml"),
            "runs:\n  using: composite\n  steps: []\n",
        )
        self.ci("steps:\n  - uses: ./.github/actions/w\n")
        self.assertRefused("both action.yml and action.yaml")

    def test_action_yaml_extension_is_resolved(self) -> None:
        _write(
            os.path.join(self.fx.root, "actions", "w", "action.yaml"),
            "runs:\n  using: composite\n  steps:\n    - uses: mozilla-actions/sccache-action@v1\n",
        )
        self.ci("steps:\n  - uses: ./.github/actions/w\n")
        self.assertRefused("./.github/actions/w/action.yml", "runs the raw")

    def test_composite_outside_github_actions_reaching_sccache_hits_rule_d(self) -> None:
        self.fx.deterministic_checks(context="clippy", step="Run clippy")
        self.repo_action(
            "tools/ci/cache",
            "runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/sccache\n",
        )
        self.ci("steps:\n  - uses: ./tools/ci/cache\n  - name: Run clippy\n    run: cargo clippy\n")
        self.assertRefused("job 'clippy' uses", "via ./tools/ci/cache", "Run clippy")

    def test_nested_path_composite_running_raw_action_is_refused(self) -> None:
        self.fx.composite("x/y", "runs:\n  using: composite\n  steps:\n    - uses: mozilla-actions/sccache-action@v1\n")
        self.ci("steps:\n  - uses: ./.github/actions/x/y\n")
        self.assertRefused("./.github/actions/x/y/action.yml", "runs the raw")

    def test_case_variant_sanctioned_path_hits_rule_d(self) -> None:
        self.fx.deterministic_checks(context="clippy", step="Run clippy")
        self.ci(
            "steps:\n  - uses: ./.github/actions/sccache\n  - uses: ./.github/Actions/SCCACHE\n"
            "  - name: Run clippy\n    run: cargo clippy\n"
        )
        self.assertRefused("job 'clippy' uses ./.github/actions/sccache", "Run clippy")

    def test_nesting_past_the_bound_is_refused(self) -> None:
        self.fx.deterministic_checks(context="clippy", step="Run clippy")
        limit = verify_manifest.LOCAL_ACTION_DEPTH_LIMIT
        for i in range(limit + 5):
            self.fx.composite(
                f"c{i}", f"runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/c{i + 1}\n"
            )
        self.fx.composite(
            f"c{limit + 5}", "runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/sccache\n"
        )
        self.ci("steps:\n  - uses: ./.github/actions/c0\n  - name: Run clippy\n    run: cargo clippy\n")
        self.assertRefused("nesting exceeds")

    def test_nesting_at_the_bound_is_decided(self) -> None:
        self.fx.deterministic_checks(context="clippy", step="Run clippy")
        limit = verify_manifest.LOCAL_ACTION_DEPTH_LIMIT
        for i in range(limit - 1):
            self.fx.composite(
                f"c{i}", f"runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/c{i + 1}\n"
            )
        self.fx.composite(
            f"c{limit - 1}", "runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/sccache\n"
        )
        self.ci("steps:\n  - uses: ./.github/actions/c0\n  - name: Run clippy\n    run: cargo clippy\n")
        errors = self.assertRefused("job 'clippy' uses", "via ./.github/actions/c0")
        self.assertFalse(any("nesting exceeds" in e for e in errors), errors)

    def test_local_action_cycle_is_refused(self) -> None:
        self.fx.composite("a", "runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/b\n")
        self.fx.composite("b", "runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/a\n")
        self.ci("steps:\n  - uses: ./.github/actions/a\n")
        self.assertRefused("local action cycle")

    def test_job_level_reusable_workflow_is_refused(self) -> None:
        self.fx.workflow("called.yml", _ci("steps:\n  - run: cargo build\n"))
        for call in (
            "./.github/workflows/gone.yml",
            "./.github/workflows/called.yml",
            "owner/repo/.github/workflows/w.yml@v1",
        ):
            with self.subTest(call=call):
                self.fx.workflow("ci.yml", f"name: ci\non: push\njobs:\n  a:\n    uses: {call}\n")
                self.assertRefused("job 'a': calls a reusable workflow", call)

    # ---- byte-exact local-action identity ---------------------------------

    def test_referenced_case_variant_of_sanctioned_composite_is_refused(self) -> None:
        self.fx.composite(
            "SCCACHE",
            "runs:\n  using: composite\n  steps:\n    - uses: mozilla-actions/sccache-action@v1\n"
            "    - shell: bash\n      run: echo \"RUSTC_WRAPPER=\" >> \"$GITHUB_ENV\"\n",
        )
        self.ci("steps:\n  - uses: ./.github/actions/SCCACHE\n")
        errors = self.assertRefused("'./.github/actions/SCCACHE' is case-fold-equal to '.github/actions/sccache'")
        self.assertTrue(any("holds case-fold-equal entries 'SCCACHE' and 'sccache'" in e for e in errors), errors)

    def test_unreferenced_case_variant_sibling_is_refused(self) -> None:
        self.fx.composite("SCCACHE", "runs:\n  using: composite\n  steps: []\n")
        self.ci("steps:\n  - uses: ./.github/actions/sccache\n  - run: cargo build\n")
        self.assertRefused("holds case-fold-equal entries 'SCCACHE' and 'sccache'")

    def test_case_variant_exemption_needs_the_sanctioned_file_absent_too(self) -> None:
        fx = SccacheFixture(self._tmpdir.name + "/bare", composite=None)
        fx.composite("SCCACHE", "runs:\n  using: composite\n  steps:\n    - uses: mozilla-actions/sccache-action@v1\n")
        fx.workflow("ci.yml", _ci("steps:\n  - uses: ./.github/actions/SCCACHE\n"))
        errors = fx.errors()
        self.assertTrue(any("case-fold-equal" in e or "runs the raw" in e for e in errors), errors)
        self.assertFalse(any("uses ./.github/actions/sccache" in e for e in errors), errors)

    def test_reference_differing_in_case_from_disk_is_refused(self) -> None:
        self.repo_action("tools/w", "runs:\n  using: composite\n  steps: []\n")
        self.ci("steps:\n  - uses: ./tools/W\n")
        self.assertRefused("names 'W' but the directory holds 'w'", "byte-exact")

    def test_case_variant_twin_directory_on_reference_path_is_refused(self) -> None:
        benign = "runs:\n  using: composite\n  steps: []\n"
        self.repo_action("tools/ci/setup", benign)
        self.repo_action("tools/CI/setup", benign)
        self.ci("steps:\n  - uses: ./tools/ci/setup\n")
        self.assertRefused("passes through", "case-fold-equal entries ['CI', 'ci']")

    # ---- env values and rustc-replacing keys ------------------------------

    def test_env_value_naming_a_wiring_key_is_refused_at_every_scope(self) -> None:
        write = "run: echo \"$K=sccache\" >> \"$GITHUB_ENV\"\n"
        cases = {
            "workflow": ({"top": "env:\n  K: RUSTC_WRAPPER\n"}, f"steps:\n  - {write}", "workflow-level env.K"),
            "job": ({}, f"env:\n  K: RUSTC_WRAPPER\nsteps:\n  - {write}", "job 'clippy' env.K"),
            "step": ({}, f"steps:\n  - name: S\n    env:\n      K: RUSTC_WRAPPER\n    {write}", "step 'S' env.K"),
            "container": (
                {},
                f"container:\n  image: rust\n  env:\n    K: RUSTC_WRAPPER\nsteps:\n  - {write}",
                "job 'clippy' container env.K",
            ),
            "service": (
                {},
                f"services:\n  db:\n    image: pg\n    env:\n      K: SCCACHE_DIR\nsteps:\n  - {write}",
                "job 'clippy' service 'db' env.K",
            ),
        }
        for scope, (kw, body, needle) in cases.items():
            with self.subTest(scope=scope):
                self.ci(body, **kw)
                self.assertRefused(needle)

    def test_env_value_in_other_composite_is_refused(self) -> None:
        self.fx.composite(
            "w",
            "runs:\n  using: composite\n  steps:\n    - name: B\n      shell: bash\n"
            "      env:\n        K: cargo_build_rustc_wrapper\n"
            "      run: echo \"$K=sccache\" >> \"$GITHUB_ENV\"\n",
        )
        self.ci("steps:\n  - uses: ./.github/actions/w\n")
        self.assertRefused("./.github/actions/w/action.yml: step 'B' env.K")

    def test_rustc_replacing_env_keys_are_refused(self) -> None:
        for key in ("RUSTC", "CARGO_BUILD_RUSTC", "rustc", "Cargo_Build_Rustc"):
            with self.subTest(key=key):
                self.ci(f"env:\n  {key}: /tmp/fake-rustc\nsteps:\n  - run: cargo build\n")
                self.assertRefused("job 'clippy' env sets", repr(key.casefold()))

    def test_rustc_replacing_text_is_refused(self) -> None:
        for run in (
            "RUSTC=/tmp/r cargo build",
            "export CARGO_BUILD_RUSTC=/tmp/r",
            "echo \"RUSTC=/tmp/r\" >> \"$GITHUB_ENV\"",
            "cargo --config build.rustc='\"/tmp/r\"' build",
            "printf '[build]\\nrustc = \"/tmp/r\"\\n' >> ~/.cargo/config.toml",
        ):
            with self.subTest(run=run):
                self.ci(f"steps:\n  - name: Build\n    run: {run}\n")
                self.assertRefused("step 'Build' run:")
        self.ci("steps:\n  - uses: some/action@v1\n    with:\n      rustc: /tmp/r\n")
        self.assertRefused("with.rustc")

    def test_benign_rustc_mentions_pass(self) -> None:
        self.ci("env:\n  RUSTFLAGS: -Dwarnings\nsteps:\n  - run: rustc --version && cargo build\n")
        self.assertEqual(self.fx.errors(), [])

    # ---- strict positive proof of the sanctioned composite (F2) ----------

    def _sanctioned(self, steps: str) -> None:
        _write(
            os.path.join(self.fx.root, "actions", "sccache", "action.yml"),
            "runs:\n  using: composite\n  steps:\n" + textwrap.indent(textwrap.dedent(steps), "    "),
        )
        self.ci("steps:\n  - run: cargo build\n")

    def test_composite_writing_only_one_var_is_refused(self) -> None:
        self._sanctioned(
            "- uses: mozilla-actions/sccache-action@v0.0.9\n"
            "- shell: bash\n  run: echo SCCACHE_GHA_ENABLED=true >> $GITHUB_ENV\n"
        )
        self.assertRefused("step 2 is not the canonical wiring step")

    def test_composite_loose_write_is_not_proof(self) -> None:
        self._sanctioned(
            "- uses: mozilla-actions/sccache-action@v0.0.9\n"
            "- shell: bash\n  run: |\n"
            "    # RUSTC_WRAPPER=sccache SCCACHE_GHA_ENABLED=true $GITHUB_ENV\n"
            "    printf '%s=%s\\n' RUSTC_WRAPPER sccache >> \"$GITHUB_ENV\"\n"
        )
        self.assertRefused("step 2 is not the canonical wiring step")

    def test_composite_conditional_wiring_is_not_proof(self) -> None:
        self._sanctioned(
            "- uses: mozilla-actions/sccache-action@v0.0.9\n"
            "- shell: bash\n  if: false\n  run: |\n"
            "    echo \"RUSTC_WRAPPER=sccache\" >> \"$GITHUB_ENV\"\n"
            "    echo \"SCCACHE_GHA_ENABLED=true\" >> \"$GITHUB_ENV\"\n"
        )
        self.assertRefused("step 2 is not the canonical wiring step")

    def test_composite_conditional_install_is_not_proof(self) -> None:
        self._sanctioned(
            "- uses: mozilla-actions/sccache-action@v0.0.9\n  if: false\n"
            "- shell: bash\n  run: |\n"
            "    echo \"RUSTC_WRAPPER=sccache\" >> \"$GITHUB_ENV\"\n"
            "    echo \"SCCACHE_GHA_ENABLED=true\" >> \"$GITHUB_ENV\"\n"
        )
        self.assertRefused("step 1 must be exactly")

    _WIRE = (
        "- name: Wire rustc through sccache\n  shell: bash\n  run: |\n"
        + textwrap.indent(verify_manifest.SCCACHE_WIRE_RUN, "    ")
    )

    def test_canonical_composite_with_other_install_ref_passes(self) -> None:
        self._sanctioned("- uses: mozilla-actions/sccache-action@v0.0.10\n" + self._WIRE)
        self.assertEqual(self.fx.errors(), [])

    def test_composite_wiring_under_dead_branch_is_refused(self) -> None:
        self._sanctioned(
            "- uses: mozilla-actions/sccache-action@v0.0.9\n"
            "- name: Wire rustc through sccache\n  shell: bash\n  run: |\n"
            "    if false; then\n"
            + textwrap.indent(verify_manifest.SCCACHE_WIRE_RUN, "    ")
            + "    fi\n"
        )
        self.assertRefused("step 2 is not the canonical wiring step")

    def test_composite_later_step_unwiring_is_refused(self) -> None:
        self._sanctioned(
            "- uses: mozilla-actions/sccache-action@v0.0.9\n"
            + self._WIRE
            + "- shell: bash\n  run: echo \"RUSTC_WRAPPER=\" >> \"$GITHUB_ENV\"\n"
        )
        self.assertRefused("exactly two steps")

    def test_composite_nested_local_uses_is_refused(self) -> None:
        self.repo_action(
            "tools/act",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo \"RUSTC_WRAPPER=\" >> \"$GITHUB_ENV\"\n",
        )
        self._sanctioned("- uses: mozilla-actions/sccache-action@v0.0.9\n" + self._WIRE + "- uses: ./tools/act\n")
        self.assertRefused("exactly two steps")
        self._sanctioned("- uses: ./tools/act\n" + self._WIRE)
        self.assertRefused("step 1 must be exactly")

    def test_composite_install_step_with_extra_keys_is_refused(self) -> None:
        for extra in ("  with:\n    version: v0.8.0\n", "  continue-on-error: true\n", "  name: x\n"):
            with self.subTest(extra=extra):
                self._sanctioned("- uses: mozilla-actions/sccache-action@v0.0.9\n" + extra + self._WIRE)
                self.assertRefused("step 1 must be exactly")

    def test_composite_reordered_or_env_bearing_wire_is_refused(self) -> None:
        self._sanctioned(self._WIRE + "- uses: mozilla-actions/sccache-action@v0.0.9\n")
        self.assertRefused("step 1 must be exactly")
        self._sanctioned(
            "- uses: mozilla-actions/sccache-action@v0.0.9\n" + self._WIRE + "  env:\n    RUSTC_WRAPPER: ''\n"
        )
        self.assertRefused("step 2 is not the canonical wiring step")

    def test_composite_extra_document_or_runs_keys_are_refused(self) -> None:
        body = "  steps:\n" + textwrap.indent("- uses: mozilla-actions/sccache-action@v0.0.9\n" + self._WIRE, "    ")
        path = os.path.join(self.fx.root, "actions", "sccache", "action.yml")
        self.ci("steps:\n  - run: cargo build\n")
        _write(path, "inputs:\n  x:\n    default: y\nruns:\n  using: composite\n" + body)
        self.assertRefused("keys ['inputs'] are outside the canonical composite")
        _write(path, "runs:\n  using: composite\n  post: x\n" + body)
        self.assertRefused("`runs:` keys must be exactly")

    # ---- deterministic-checks SSOT (F4) -----------------------------------

    def test_missing_deterministic_checks_file_is_refused(self) -> None:
        os.remove(os.path.join(self.fx.root, "ci", "deterministic-checks.json"))
        self.ci("steps:\n  - uses: ./.github/actions/sccache\n  - name: Run clippy\n    run: cargo clippy\n")
        self.assertRefused("cannot establish the deterministic check steps")

    def test_malformed_deterministic_checks_file_is_refused(self) -> None:
        _write(os.path.join(self.fx.root, "ci", "deterministic-checks.json"), '{"checks": "x"}')
        self.ci("steps:\n  - run: cargo build\n")
        self.assertRefused("cannot establish the deterministic check steps")

    # ---- malformed shapes (F5) --------------------------------------------

    def test_malformed_shapes_are_refused(self) -> None:
        cases = {
            "doc": ("- a\n- b\n", "the workflow document is not a mapping"),
            "jobs": ("name: ci\non: push\njobs: [1]\n", "jobs: is not a non-empty mapping"),
            "job": ("name: ci\non: push\njobs:\n  clippy: 3\n", "the job is not a mapping"),
            "steps": (_ci("steps: oops\n"), "steps: is not a list"),
            "step": (_ci("steps:\n  - just-a-string\n"), "steps[0] is not a mapping"),
            "services": (_ci("services: [pg]\nsteps: []\n"), "services: is not a mapping"),
            "container": (_ci("container: [rust]\nsteps: []\n"), "container: is not"),
            "defaults": (_ci("defaults: x\nsteps: []\n"), "defaults: is not a mapping"),
            "run": (_ci("steps:\n  - run: [a]\n"), "run: is not a string"),
        }
        for what, (doc, needle) in cases.items():
            with self.subTest(what=what):
                self.fx.workflow("ci.yml", doc)
                self.assertRefused(needle)

    def test_malformed_composite_steps_are_refused(self) -> None:
        self.fx.composite("w", "runs:\n  using: composite\n  steps: nope\n")
        self.ci("steps:\n  - uses: ./.github/actions/w\n")
        self.assertRefused("steps: is not a list")

    # ---- expression-assembly in run:/env: (strict_yaml.refuse_expression_assembly) --

    def test_format_assembly_in_run_is_refused(self) -> None:
        self.ci(
            "steps:\n  - name: Build\n"
            "    run: echo \"${{ format('RUSTC_{0}', 'WRAPPER') }}=sccache\" >> \"$GITHUB_ENV\"\n"
        )
        self.assertRefused("step 'Build' run:", "expression-assembly")

    def test_join_assembly_in_env_is_refused(self) -> None:
        self.ci(
            "steps:\n  - name: Build\n    env:\n"
            "      X: \"${{ join(github.event.inputs.*, '_') }}\"\n"
            "    run: cargo build\n"
        )
        self.assertRefused("step 'Build' env.X", "expression-assembly")

    def test_tojson_assembly_in_run_is_refused(self) -> None:
        self.ci(
            "steps:\n  - name: Build\n"
            "    run: echo '${{ toJSON(github.event) }}' >> \"$GITHUB_ENV\"\n"
        )
        self.assertRefused("step 'Build' run:", "expression-assembly")

    # ---- YAML structural ambiguities feed the workflow loader closed
    # (strict_yaml.StrictSafeLoader), not just check_sccache_wiring's text scan --

    def test_duplicate_key_workflow_is_refused_not_silently_resolved(self) -> None:
        self.fx.workflow(
            "ci.yml",
            "name: ci\non: push\njobs:\n  clippy:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: cargo build\n"
            "    steps:\n      - run: RUSTC_WRAPPER=evil cargo build\n",
        )
        self.assertRefused("ci.yml is not valid YAML", "duplicate key")

    def test_merge_key_workflow_is_refused(self) -> None:
        self.fx.workflow(
            "ci.yml",
            "base: &base\n  runs-on: ubuntu-latest\n"
            "name: ci\non: push\njobs:\n  clippy:\n"
            "    <<: *base\n    steps:\n      - run: cargo build\n",
        )
        self.assertRefused("ci.yml is not valid YAML")

    def test_anchor_alias_workflow_is_refused(self) -> None:
        self.fx.workflow(
            "ci.yml",
            "name: ci\non: push\njobs:\n  clippy: &clippy\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: cargo build\n  clippy2: *clippy\n",
        )
        self.assertRefused("ci.yml is not valid YAML")


if __name__ == "__main__":
    unittest.main()
