//! `++` string-concat parity gate: the append operator `++` lexes to a
//! single [`ipe_parse`] token (never two `+`), parses as a binary operator at the
//! reference precedence (level 5, right-associative — see
//! `/home/arthur/Documentos/comp/ipe/src/Ipê/Parse/Symbol.hs`), canonicalises to
//! the `append` kernel, types as `String -> String -> String`, and emits a Rust
//! `format!` concatenation that yields a fresh `String`.
//!
//! Two programs exercise the surface end to end:
//!
//! * `append` — `greet name = "hi, " ++ name ++ "!"`, a mixed
//!   literal/variable chain, prints `hi, world!` at `greet "world"`.
//! * `append_chain` — `"a" ++ "b" ++ "c" ++ "d"`, an all-literal chain
//!   that confirms right-associative nesting, prints `abcd`.
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
//! $ ipe run Main.ipe
//! hi, world!   # append
//! abcd         # append_chain
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
/// stdout matches the golden's CACHED golden oracle (`expected_go.txt`) via the
/// staleness-gated `crate::support::assert_go_parity` — NO live oracle run in this path.
/// Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
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
fn append_chain_emits_byte_identical_main_rs() {
    assert_byte_identical("append");
}

#[test]
fn append_literal_chain_emits_byte_identical_main_rs() {
    assert_byte_identical("append_chain");
}

#[test]
fn append_chain_builds_and_prints_greeting() {
    assert_runs_and_matches_oracle("append");
}

#[test]
fn append_literal_chain_builds_and_prints_abcd() {
    assert_runs_and_matches_oracle("append_chain");
}
