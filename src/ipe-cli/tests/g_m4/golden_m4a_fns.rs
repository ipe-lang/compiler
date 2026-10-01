//! Stdlib-functions parity gate: the kernel-anchored `Ipe.List`,
//! `Ipe.Maybe`, and `Ipe.Result` combinators compile and run with
//! golden-verified output.
//!
//! The `List` type + literals + `::`, the `Maybe` / `Result` /
//! `Bool` builtins, and cons/list patterns are covered elsewhere. This gate
//! covers the standard-library FUNCTIONS over them. As in the reference
//! compiler, the higher-order ones
//! (`map` / `filter` / `foldl` / `foldr`) stay kernel-anchored — they route to the
//! generic runtime functions (`list_foldl`, …) rather than to monomorphised user
//! Ipê code, which the front end cannot yet produce for a cross-module
//! polymorphic HOF.
//!
//! Functions exercised across the goldens (every one verified golden-verified):
//!
//! * `List` — `map`, `filter`, `foldl`, `foldr`, `length`, `head`, `tail`,
//!   `member`, `range`, `reverse`.
//! * `Maybe` — `withDefault`, `map`, `andThen`.
//! * `Result` — `withDefault`, `map`.
//!
//! The four mandated programs and their values:
//!
//! * `fns_foldl` — `List.foldl (\acc x -> acc + x) 0 [1,2,3,4]` → `10`. A
//!   lambda flows into the runtime HOF as a boxed closure (`Box<…>` satisfies the
//!   `impl Fn + Clone` runtime bound when its captures are `Clone`).
//! * `fns_filter_length` — `List.length (List.filter (\x -> x > 2) [1,2,3,4])`
//!   → `2`.
//! * `fns_maybe_default` — `Maybe.withDefault 0 (Just 5)` → `5`.
//! * `fns_result_map` — `Result.withDefault 0 (Result.map (\x -> x + 1) (Ok 2))`
//!   → `3`. `Ok 2`'s `Result e a` error type is unconstrained, so the lowerer
//!   pins it to the project `IpeError` via the runtime's `ok_res` (avoiding
//!   rustc's E0282 ambiguity); `Result.map`'s runtime takes the container first,
//!   so the backend re-points the two arguments.
//!
//! Five further goldens cover the remaining functions — `map`, `foldr`, the
//! `range`/`member` pair, the `head`/`tail`/`reverse` trio, and the
//! `Maybe.map`/`andThen` chain.
//!
//! Each emitted `main.rs` must be byte-identical to the checked-in golden, and
//! (behind `IPE_E2E=1`) the emitted project must build and print the expected
//! reference compiler produces — captured in each golden's `expected_go.txt` /
//! `oracle.meta` via the cached-oracle infra (no live in this gate).

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

    let runtime = e2e_support::require_runtime().into_path_buf();

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

// ── Byte-identical emission ──────────────────────────────────────────────────

#[test]
fn foldl_emits_byte_identical_main_rs() {
    assert_byte_identical("fns_foldl");
}

#[test]
fn filter_length_emits_byte_identical_main_rs() {
    assert_byte_identical("fns_filter_length");
}

#[test]
fn maybe_default_emits_byte_identical_main_rs() {
    assert_byte_identical("fns_maybe_default");
}

#[test]
fn result_map_emits_byte_identical_main_rs() {
    assert_byte_identical("fns_result_map");
}

#[test]
fn list_map_emits_byte_identical_main_rs() {
    assert_byte_identical("fns_map");
}

#[test]
fn foldr_emits_byte_identical_main_rs() {
    assert_byte_identical("fns_foldr");
}

#[test]
fn list_ops_emits_byte_identical_main_rs() {
    assert_byte_identical("fns_list_ops");
}

#[test]
fn head_tail_reverse_emits_byte_identical_main_rs() {
    assert_byte_identical("fns_head_tail_reverse");
}

#[test]
fn maybe_chain_emits_byte_identical_main_rs() {
    assert_byte_identical("fns_maybe_chain");
}

// ── Build + run + oracle parity (IPE_E2E=1) ───────────────────────────────

#[test]
fn foldl_builds_and_prints_ten() {
    assert_runs_and_matches_oracle("fns_foldl");
}

#[test]
fn filter_length_builds_and_prints_two() {
    assert_runs_and_matches_oracle("fns_filter_length");
}

#[test]
fn maybe_default_builds_and_prints_five() {
    assert_runs_and_matches_oracle("fns_maybe_default");
}

#[test]
fn result_map_builds_and_prints_three() {
    assert_runs_and_matches_oracle("fns_result_map");
}

#[test]
fn list_map_builds_and_prints_twelve() {
    assert_runs_and_matches_oracle("fns_map");
}

#[test]
fn foldr_builds_and_prints_two() {
    assert_runs_and_matches_oracle("fns_foldr");
}

#[test]
fn list_ops_builds_and_prints_two() {
    assert_runs_and_matches_oracle("fns_list_ops");
}

#[test]
fn head_tail_reverse_builds_and_prints_three() {
    assert_runs_and_matches_oracle("fns_head_tail_reverse");
}

#[test]
fn maybe_chain_builds_and_prints_fifty_one() {
    assert_runs_and_matches_oracle("fns_maybe_chain");
}
