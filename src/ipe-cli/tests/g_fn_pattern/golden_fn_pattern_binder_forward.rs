//! Capture normalization for match-arm PATTERN binders: a function extracted
//! from an enum variant by a pattern (`Codec f -> …`) and then FORWARDED into a
//! higher-order function (captured by a mapper closure that hands it onward,
//! not calling it in place). A bare `Box` carrier would move the capture out of
//! the mapper's env per call and collapse it to `FnOnce`; the arm binder is
//! promoted to the `Clone` `Arc<dyn Fn>` carrier on demand, so the forwarding
//! closure clones the pointer and stays `Fn`. This is the `varN`-projection
//! shape the codec combinators depend on.
//!
//! The gate stays closed for a genuinely non-`Clone` binder: a pattern binder
//! carrying a `Task` (no `Clone` carrier) forwarded the same way STILL fails
//! closed IPE-L0126. A `Decoder`-valued binder, by contrast, is now `Clone` (an
//! `Arc`-backed carrier) and forwards soundly — the gate is narrowed to what
//! genuinely lacks a `Clone` carrier, never removed.
//!
//! `List.sum (run (Codec (\n -> n+1)) [1,2,3])` = `2 + 3 + 4` = `9`.

use std::path::{Path, PathBuf};

use ipe::CliError;

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("fn_pattern_binder_forward")
        .join("Main.ipe")
}

#[test]
fn pattern_binder_forward_emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("fn_pattern_binder_forward")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fn_pattern_binder_forward_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

#[test]
fn pattern_binder_forward_end_to_end_prints_nine() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_fn_pattern_binder_forward_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("fn_pattern_binder_forward", &out);
    assert_eq!(
        outcome.stdout, "9\n",
        "forwarded arm-bound function maps and sums"
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0 (THE SEAL)");
}

/// Build a one-file program to a fresh temp dir and return the driver result.
#[allow(clippy::expect_used)] // an unwritable scratch dir is the test failure
fn build_source(name: &str, source: &str) -> Result<(), CliError> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the fixture scratch dir must be writable");
    let entry = dir.join("Main.ipe");
    std::fs::write(&entry, source).expect("the fixture scratch dir must be writable");
    let out = dir.join("out");
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, &out, &runtime)
}

#[test]
fn decoder_pattern_capture_forward_is_admitted() {
    // A `Decoder` VALUE extracted by a match-arm pattern and forwarded into a
    // closure is now sound: the runtime `Decoder<E, T>` is an `Arc`-backed
    // `Clone` carrier, so the whole binder clones at the closure boundary. This
    // is the exact P1 unblock — it must be accepted (and, under the SEAL, build).
    let src = "module Main exposing (main)\n\
               import Ipe.Io as Io\n\
               import Ipe.Json.Decode as Decode\n\
               import Ipe.List as List\n\
               type Wrap = Wrap (Decode.Decoder Int)\n\
               useTwice : Wrap -> List (Decode.Decoder Int)\n\
               useTwice w =\n\
               \x20   case w of\n\
               \x20       Wrap d ->\n\
               \x20           List.map (\\_ -> d) [1, 2]\n\
               main =\n\
               \x20   Io.println \"x\"\n";
    let built = build_source("fn_pattern_binder_decoder_forward", src);
    assert!(
        built.is_ok(),
        "a `Decoder`-valued pattern binder forwarded through a closure is now \
         `Clone` and must be accepted, got: {built:?}"
    );
}

#[test]
fn non_clone_pattern_capture_forward_stays_fail_closed() {
    // A `Task` VALUE (genuinely non-`Clone`, no carrier) extracted by a match-arm
    // pattern and forwarded into a closure has no `Clone` carrier — it must STILL
    // fail closed IPE-L0126. The gate is narrowed to what has a `Clone` carrier,
    // never removed.
    let src = "module Main exposing (main)\n\
               import Ipe.Io as Io\n\
               import Ipe.List as List\n\
               type Wrap = Wrap (Task Int)\n\
               useTwice : Wrap -> List (Task Int)\n\
               useTwice w =\n\
               \x20   case w of\n\
               \x20       Wrap t ->\n\
               \x20           List.map (\\_ -> t) [1, 2]\n\
               main =\n\
               \x20   Io.println \"x\"\n";
    let built = build_source("fn_pattern_binder_noncl_forward_gate", src);
    let code = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        code,
        Some(ipe_diagnostics::IPE_L0126),
        "a non-Clone (Task) pattern capture forward must stay IPE-L0126, got: {built:?}"
    );
}
