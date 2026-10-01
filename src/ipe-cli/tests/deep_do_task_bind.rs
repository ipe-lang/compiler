//! Regression test: a do-block with many sequential `Task` binds must compile
//! without super-linear rustc type-checking work.
//!
//! Each `x <- task` bind desugars to `Task.andThen (\ x -> cont) task`. The
//! emitter previously wrapped every continuation lambda in
//! `{ let __ipe_fn: Box<dyn Fn(T) -> R + …> = Box::new(…); __ipe_fn }`.
//! Rustc's type-checker processes this pattern in super-linear time relative to
//! the nesting depth: N=8 binds caused ~10 s of rustc compile time, N=9 ~29 s.
//!
//! The fix emits `Box::new(move |x: T| -> R { … })` directly — the same form
//! `TaskSeq` (bare do-runs) already used. Rustc infers the trait-object coercion
//! from the `task_and_then` parameter type and processes the chain in linear time.
//!
//! This test checks two properties:
//!   1. `ipe::build` succeeds on a 20-bind do-block without error.
//!   2. The emitted `main.rs` contains `Box::new(move |` for continuations and
//!      does NOT contain `__ipe_fn` type-annotation wrappers.

use std::fmt::Write as _;
use std::path::PathBuf;

fn make_do_src(n: usize) -> String {
    let mut src = String::new();
    src.push_str(
        "module Main exposing (main)\n\
         import Ipe.Task as Task\n\
         import Ipe.Io as Io\n\
         import Ipe.String as String\n\n\
         main =\n    do\n",
    );
    for i in 0..n {
        let _ = writeln!(src, "        x{i} <- Task.succeed {i}");
    }
    let _ = writeln!(src, "        Io.println (String.fromInt x{})", n - 1);
    src
}

/// `ipe::build` must succeed on a 20-bind do-block and the emitted Rust must
/// use `Box::new(move |…|` for continuations (not `__ipe_fn` wrappers).
#[test]
fn deep_do_task_bind_emit_is_linear() {
    const N: usize = 20;

    let runtime = e2e_support::require_runtime().into_path_buf();

    let src = make_do_src(N);

    // Write source to a temp file.
    let out_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("deep_do_task_bind");
    let _ = std::fs::remove_dir_all(&out_dir);
    let src_dir = out_dir.join("src_input");
    std::fs::create_dir_all(&src_dir).expect("create src dir");
    let entry = src_dir.join("Main.ipe");
    std::fs::write(&entry, &src).expect("write Main.ipe");

    let emit_dir = out_dir.join("emit");
    let built = ipe::build(&entry, &emit_dir, &runtime);
    assert!(
        built.is_ok(),
        "ipe::build must succeed for a {N}-bind do-block: {:?}",
        built.err()
    );

    // Read all emitted Rust sources; compiled-source stdlib imports split
    // user code into src/ipe_mods/ipe_mod_main.rs alongside src/main.rs.
    let emitted_rs = emit_dir.join("src").join("main.rs");
    let mut content = std::fs::read_to_string(&emitted_rs)
        .expect("emitted main.rs must exist after a successful build");
    let mod_main = emit_dir
        .join("src")
        .join("ipe_mods")
        .join("ipe_mod_main.rs");
    if let Ok(extra) = std::fs::read_to_string(&mod_main) {
        content.push_str(&extra);
    }

    // The old emit path produced `let __ipe_fn: Box<dyn Fn…> = Box::new(…)` for
    // every Task.andThen continuation. The fix produces `Box::new(move |…| …)` directly.
    assert!(
        !content.contains("let __ipe_fn"),
        "emitted code must not contain `let __ipe_fn` type-annotation wrappers \
         in Task.andThen continuations"
    );
    assert!(
        content.contains("Box::new(move |"),
        "emitted code must contain `Box::new(move |…|` for Task.andThen continuations"
    );

    let _ = std::fs::remove_dir_all(&out_dir);
}

/// `ipe::build` then `cargo build` must succeed on a 20-bind do-block.
/// Gated on `IPE_E2E=1` for the full cargo seal.
#[test]
fn deep_do_task_bind_e2e_seal() {
    const N: usize = 20;

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let runtime = e2e_support::require_runtime().into_path_buf();
        let src = make_do_src(N);

        let out_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("deep_do_task_bind_e2e");
        let _ = std::fs::remove_dir_all(&out_dir);
        let src_dir = out_dir.join("src_input");
        std::fs::create_dir_all(&src_dir).expect("create src dir");
        let entry = src_dir.join("Main.ipe");
        std::fs::write(&entry, &src).expect("write Main.ipe");

        let emit_dir = out_dir.join("emit");
        let built = ipe::build(&entry, &emit_dir, &runtime);
        assert!(
            built.is_ok(),
            "ipe::build must succeed for a {N}-bind do-block: {:?}",
            built.err()
        );

        // THE SEAL: emitted Rust must compile with cargo. Built through the shared
        // e2e_support core — a unique package name gives this emitted crate its own
        // fresh fingerprint (a broken emit still fails to build), while the heavy
        // dependency tree is reused from the warm shared target instead of being
        // cold-compiled and thrown away per run.
        let built = e2e_support::build_rust_binary("deep_do_task_bind", &emit_dir);
        assert!(
            built.is_ok(),
            "cargo build on emitted {N}-bind do-block must succeed: {}",
            built.err().unwrap_or_default()
        );

        let _ = std::fs::remove_dir_all(&out_dir);
    }
}
