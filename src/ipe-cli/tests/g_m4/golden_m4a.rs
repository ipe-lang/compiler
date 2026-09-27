//! Stdlib-foundation parity gate: the Prelude-exposed built-in
//! constructors (`True` / `False`, `Just` / `Nothing`, `Ok` / `Err`) usable as
//! VALUE expressions and in `case` patterns (closing IPE-N0001 / IPE-N0003), and
//! the built-in `List` type with `[]` / `[a, b, c]` literals and the `::` cons
//! operator.
//!
//! Four programs exercise the surface end to end:
//!
//! * `maybe_stdlib` — `case (Just 42) of Just n -> n ; Nothing -> 0`, prints `42`.
//!   `Maybe a` lowers to the runtime's `IpeMaybe<T>`; the construction and the
//!   pattern both route to it.
//! * `result_stdlib` — `case (Ok 7) of Ok n -> n ; Err _ -> 0`, prints `7`.
//!   `Result e a` lowers to the runtime's `IpeResult<E, A>`.
//! * `bool_stdlib` — `if True then "yes" else "no"`, prints `yes`. `True` / `False`
//!   lower to the Rust `true` / `false` keyword constants.
//! * `list_stdlib` — `1 :: 2 :: [3, 4, 5]` built and passed to a function, prints
//!   `7`. The list literal lowers to `vec![…]` and `::` to the runtime's
//!   `ipe_list_cons`, over the runtime's `Vec<T>` list representation.
//!
//! Each emitted `main.rs` must be byte-identical to the checked-in golden, and
//! (behind `IPE_E2E=1`) the emitted project must build and print the value the
//! the reference compiler produces — captured in each golden's `expected_go.txt`
//! / `oracle.meta` via the cached-oracle infra (no live in this gate).

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
    let golden = dir.join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve: {:?}", runtime.err());
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    // Directory-diff the emitted project against the golden dir (byte-compares
    // the emitted `src/main.rs` against the golden `main.rs`). Replaces the
    // former hand-rolled `read_to_string` + `assert_eq!` pair with the shared
    // harness helper.
    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// Full spine: compile, build the emitted Cargo project, run it, and assert its
/// stdout matches the golden's CACHED golden oracle via the staleness-gated
/// `crate::support::assert_go_parity` — NO live oracle run. Gated on `IPE_E2E=1`.
fn assert_runs_and_matches_oracle(name: &str) {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

#[test]
fn maybe_value_and_pattern_emit_byte_identical_main_rs() {
    assert_byte_identical("maybe_stdlib");
}

#[test]
fn result_value_and_pattern_emit_byte_identical_main_rs() {
    assert_byte_identical("result_stdlib");
}

#[test]
fn bool_value_emits_byte_identical_main_rs() {
    assert_byte_identical("bool_stdlib");
}

#[test]
fn list_literal_and_cons_emit_byte_identical_main_rs() {
    assert_byte_identical("list_stdlib");
}

#[test]
fn maybe_builds_and_prints_forty_two() {
    assert_runs_and_matches_oracle("maybe_stdlib");
}

#[test]
fn result_builds_and_prints_seven() {
    assert_runs_and_matches_oracle("result_stdlib");
}

#[test]
fn bool_builds_and_prints_yes() {
    assert_runs_and_matches_oracle("bool_stdlib");
}

#[test]
fn list_builds_and_prints_seven() {
    assert_runs_and_matches_oracle("list_stdlib");
}
