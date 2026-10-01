//! Soundness gate: a function value reaching a record field THROUGH a type
//! variable, via a REIFIED generic function (an alias `let mk = wrap`), must
//! NEVER emit cargo-failing Rust silently.
//!
//! The shape — `wrap : a -> { value : a }`, aliased as `mk = wrap` then applied
//! `mk (\n -> n + 1)` — reifies `wrap` into a `Box::new(main_wrap)` first-class
//! value before applying it, so the field `value : a` instantiates to
//! `Int -> Int`. The synthesised generic `fn main_wrap<T1: Clone>(..)` is then
//! instantiated at `T1 = Box<dyn Fn>` (not `Clone`), while the field read
//! (`r.value`) expects the `Arc` carrier — the emitted crate fails `cargo`
//! (E0271/E0277). The direct-call gate (`reject_fn_through_generic_slot`) and
//! its point-free-call twin do not see it: the value is reified, never applied
//! at their call site. The reify twin (`reject_fn_value_reify_generic_slot`)
//! catches it at the reference site.
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
        .join("fn_value_reify_typevar")
        .join("Main.ipe")
}

#[test]
fn rejects_cleanly_or_builds_and_runs_never_silent_cargo_fail() {
    let root = repo_root();
    let entry = example_entry(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fn_value_reify_typevar_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);

    // The minimal sound outcome: a clean first-class-function diagnostic.
    if let Err(CliError::Pipeline { diag, .. }) = &built {
        assert_eq!(
            diag.code(),
            ipe_diagnostics::IPE_L0107,
            "a function value reaching a record field through a type variable via \
             a reified generic function must surface IPE-L0107, got: {diag:?}"
        );
    } else {
        // The only other acceptable outcome is full acceptance — never another
        // driver error, and never a silent accept that later cargo-fails.
        assert!(
            built.is_ok(),
            "must reject cleanly (IPE-L0107) or accept fully — never another error: {:?}",
            built.err()
        );

        // With proper support (an eager `Arc<dyn Fn>` coercion of the reified
        // value), the emitted crate MUST build and run with the semantically-correct
        // output. Gated on IPE_E2E so default runs stay fast.
        if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
            let outcome = crate::support::build_and_run_emitted("fn_value_reify_typevar", &out);
            assert_eq!(
                outcome.stdout.trim(),
                "42",
                "(wrap (\\n -> n + 1)).value is (\\n -> n + 1) and f 41 == 42"
            );
            assert_eq!(outcome.exit_code, Some(0), "exit 0");
        }
    }
}
