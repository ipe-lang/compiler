//! Soundness gate: a function value reaching a record field THROUGH a type
//! variable, laundered through a RETURNING function's result, must NEVER emit
//! cargo-failing Rust silently.
//!
//! The shape — `pick : Bool -> (a -> { value : a })` returning the generic
//! `wrap`, then `mk = pick True; mk (\n -> n + 1)` — instantiates `wrap`'s field
//! `value : a` to `Int -> Int` at the application. The callee (`mk`) is a
//! computed value (the result of applying `pick`), so no declared template is
//! recoverable at the application site: the direct-call, point-free, and reify
//! gates all miss it. The computed-callee gate
//! (`reject_value_callee_fn_into_carrier`) sees that the callee's solved arrow
//! threads a function-typed argument into a derive-carrier field of its result
//! and rejects (IPE-L0107).
//!
//! This pins the regression: the driver must produce EITHER a clean Ipê
//! diagnostic (IPE-L0107) OR — should proper support land later — Rust that
//! builds and runs with the semantically-correct output (`42`). It must NEVER
//! accept the program and then cargo-fail.

use std::path::{Path, PathBuf};

use ipe::CliError;

/// The `ipe-lang` workspace root (two levels up from this crate's manifest).
fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("fn_value_return_reify_typevar")
        .join("Main.ipe")
}

#[test]
fn rejects_cleanly_or_builds_and_runs_never_silent_cargo_fail() {
    let root = repo_root();
    let entry = example_entry(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fn_value_return_reify_typevar_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);

    // The minimal sound outcome: a clean first-class-function diagnostic.
    if let Err(CliError::Pipeline { diag, .. }) = &built {
        assert_eq!(
            diag.code(),
            ipe_diagnostics::IPE_L0107,
            "a function value laundered into a record field through a returning \
             function's result must surface IPE-L0107, got: {diag:?}"
        );
    } else {
        // The only other acceptable outcome is full acceptance — never another
        // driver error, and never a silent accept that later cargo-fails.
        assert!(
            built.is_ok(),
            "must reject cleanly (IPE-L0107) or accept fully — never another error: {:?}",
            built.err()
        );

        // With proper support the emitted crate MUST build and run with the
        // semantically-correct output. Gated on IPE_E2E so default runs stay fast.
        if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
            let outcome =
                crate::support::build_and_run_emitted("fn_value_return_reify_typevar", &out);
            assert_eq!(
                outcome.stdout.trim(),
                "42",
                "(pick True (\\n -> n + 1)).value is (\\n -> n + 1) and f 41 == 42"
            );
            assert_eq!(outcome.exit_code, Some(0), "exit 0");
        }
    }
}
