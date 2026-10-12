//! A synthetic eta closure's inlined argument reads its captures by clone.
//!
//! `x |> Maybe.andThen (addLabel (labelOf s))` lowers to the residual closure
//! `\m -> andThen m (addLabel (labelOf s))`. The function-typed argument is not
//! hoisted out of the closure (a boxed closure is not `Clone`), so it is rebuilt
//! on every call and `labelOf s` reads the captured `s : String` inside the `Fn`
//! body. Without the capture-clone rewrite over the eta body that read moves `s`
//! out of the `Fn` environment: ipe exits 0 and cargo fails with E0507.
//!
//! The fixture drives each eta builder with an argument rebuilt per call: a
//! function-typed and a `Copy`-typed argument of a named partial, a value
//! partial of a local function, and an over-application of a curried def.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("eta_inline_arg_capture")
        .join("Main.ipe")
}

/// ipe-0: the residual closure clones the captured `s` at its inlined read.
#[test]
fn eta_inline_arg_capture_ipec_clones_capture() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("eta_inline_arg_capture_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for eta_inline_arg_capture: {:?}",
        built.err()
    );

    let emitted = crate::support::read_all_emitted_src(&out);
    assert!(
        emitted.contains("label_of(s.clone())"),
        "the inlined `labelOf s` read inside the residual `Fn` closure must clone \
         `s`; got:\n{emitted}"
    );
}

/// cargo-0 and run-correct: gated on `IPE_E2E=1` (THE SEAL).
#[test]
fn eta_inline_arg_capture_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_eta_inline_arg_capture_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("eta_inline_arg_capture", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "eta_inline_arg_capture must build and exit 0 (no E0507); stdout: {:?}",
        outcome.stdout
    );
    // checkLen "abc" 1 = 2; addLabel (Label "abc!") 2 = 2 + 4; count "abc" = 4:
    // plus 4 [1,2], add 4 [1,2] (product), curry3 1 4 [1,2].
    assert!(
        outcome.stdout.contains("score=6 sums=5,6,4,8,6,7"),
        "must print the score and sums line; got: {:?}",
        outcome.stdout
    );
}
