//! Float-literal parity gate: Elm-style float literals (`1.5`, `3.0`,
//! `1.5e3`, `2e-2`) lex to [`ipe_syntax::ast::Expr_::Float`], type as the `Float`
//! constructor, and lower to an f64-typed Rust literal — a whole-number value
//! keeps its decimal point (`1500.0`) so it never types as an integer.
//!
//! Three programs exercise the surface end to end:
//!
//! * `float_literal` — `half = 3.0 / 2.0`, float division, prints `1.5`.
//! * `float_area` — `area r = 3.14 * r * r`, float multiplication, prints
//!   `12.56` at `area 2.0`.
//! * `float_compare` — a `Float` `>` comparison selecting between the
//!   exponent literals `1.5e3` and `2e-2`, prints `1500`.
//! * `float_exp` — `String.fromFloat` of `0.00001` and `1.0e21`, which the
//!   `'g'`-format runtime renders in exponent form, prints `1e-05|1e+21`. This
//!   pins the exponent branch so the float-to-string port cannot regress to
//!   positional-only coverage.
//!
//! Each emitted `main.rs` must be byte-identical to the checked-in golden, and
//! (behind `IPE_E2E=1`) the emitted project must build and print the value the
//! the reference compiler produces.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` files to the same stdout:
//!
//! ```text
//! $ ipe dev run Main.ipe
//! 1.5            # float_literal
//! 12.56          # float_area
//! 1500           # float_compare
//! 1e-05|1e+21    # float_exp
//! ```

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe` and assert the emitted `src/main.rs`
/// equals the checked-in `tests/golden/<name>/main.rs` byte-for-byte.
fn assert_byte_identical(name: &str) {
    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    // Directory-diff the emitted project against the golden dir (byte-compares
    // the emitted `src/main.rs` against the golden `main.rs`). Replaces the
    // former hand-rolled `read_to_string` + `assert_eq!` pair with the shared
    // harness helper. `dir` IS the golden dir (`golden` was `dir.join("main.rs")`,
    // so `golden.parent()` was provably `dir`) — pass it directly, no fallible
    // `.parent().expect(...)` re-derivation.
    crate::support::assert_emitted_project_matches_golden_dir(&out, &dir);
}

/// Full spine: compile, build the emitted Cargo project, run it, and assert its
/// stdout matches the golden's CACHED golden oracle (`expected_go.txt`) via the
/// staleness-gated `crate::support::assert_go_parity` — NO live oracle run in this path.
/// Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
fn assert_runs_and_matches_oracle(name: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

#[test]
fn float_division_emits_byte_identical_main_rs() {
    assert_byte_identical("float_literal");
}

#[test]
fn float_multiplication_emits_byte_identical_main_rs() {
    assert_byte_identical("float_area");
}

#[test]
fn float_compare_and_exponents_emit_byte_identical_main_rs() {
    assert_byte_identical("float_compare");
}

#[test]
fn float_exponent_branch_emits_byte_identical_main_rs() {
    assert_byte_identical("float_exp");
}

#[test]
fn float_division_builds_and_prints_one_point_five() {
    assert_runs_and_matches_oracle("float_literal");
}

/// Exponent-branch parity floor: `String.fromFloat` of a sub-`1e-4` value and a
/// `>= 1e21` value must render in `'g'` exponent form (`1e-05` / `1e+21`), the
/// exact bytes the golden oracle produces. This guards against the float-to-string
/// port regressing to exponent-free coverage only.
#[test]
fn float_exponent_branch_builds_and_prints_g_form() {
    assert_runs_and_matches_oracle("float_exp");
}

#[test]
fn float_multiplication_builds_and_prints_twelve_point_five_six() {
    assert_runs_and_matches_oracle("float_area");
}

#[test]
fn float_compare_builds_and_prints_fifteen_hundred() {
    assert_runs_and_matches_oracle("float_compare");
}
