//! `toString` on a wildcard `any` param.
//!
//! Without the fix, `ipe build` exits 0, but the emitted Rust fails `cargo build`
//! with E0277 at the `basics_to_string(x)` call inside a function whose only
//! generic is the wildcard `any` PARAM (`render : any -> String; render x =
//! toString x`).
//!
//! Root cause: the runtime's stringifier is generic over a bound the emitted
//! enclosing function's `<T1: Clone>` param did not carry, so its body's
//! `basics_to_string(x)` could not prove the bound on `x`.
//!
//! Fix: `basics_to_string` is bound `<T: IpeStringify>` (the same total-`%v`
//! path as `basics_error_to_string`); the enclosing generic gains the
//! `IpeStringify` (`BoundSet::SHOW`) bound. The bound is decided STRUCTURALLY,
//! at IR level, by the GENERAL kernel->bound map
//! (`apply_kernel_type_param_bounds` / `body_calls_kernel_on_param`) that
//! generalises the `Db.get*`->`IpeRow` machinery: it fires ONLY when the fn
//! body contains an actual `Basics.toString` KERNEL application whose sole
//! argument (arg 0) is a `Var`/`CloneVar` reference to the param. Unlike the
//! wildcard-only `IpeRow`, `IpeStringify` applies to wildcard `any` AND named
//! tvars alike — `toString` is legitimate on any polymorphic value, and
//! `IpeStringify` is satisfiable by every scalar AND every composite caller.
//!
//! Run:
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_display_bound
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("display_bound")
        .join("Main.ipe")
}

/// ipe-0: the compiler must accept the program AND emit the `IpeStringify`
/// bound on the wildcard-`any` renderer function's own generic — checked
/// unconditionally (cheap, no `cargo`), independent of the `IPE_E2E` gate.
#[test]
fn i186_ipec_accepts_and_bounds_fn_display() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i186_display_bound_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP display_bound: runtime not available");
        return;
    };

    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for display_bound: {:?}",
        built.err()
    );

    let emitted = crate::support::read_all_emitted_src(&out);

    // The renderer function's wildcard-`any` generic gains the `IpeStringify`
    // bound so its `basics_to_string(x)` body type-checks (the E0277 half).
    // `IpeStringify` (not `Display`) is the correct bound — satisfiable by every
    // scalar AND every composite, so no caller can exit-0-then-cargo-fail.
    //
    // Under the default dependency-model emit the runtime is reached through the
    // extern prelude (`ipe_runtime::…`); the vendored fallback spells the same
    // path crate-locally (`crate::ipe_runtime::…`). Accept either so the bound
    // is asserted independent of the emit model.
    assert!(
        emitted.contains("ipe_runtime::stringify::IpeStringify"),
        "the wildcard-`any` renderer function must carry the `IpeStringify` \
         bound so its `basics_to_string` body type-checks; got emitted user source:\n{emitted}"
    );
    assert!(
        emitted.contains("fn main_render<T1: ipe_runtime::stringify::IpeStringify + Clone>")
            || emitted.contains(
                "fn main_render<T1: crate::ipe_runtime::stringify::IpeStringify + Clone>"
            ),
        "the bound belongs on the renderer FUNCTION's generic param; got \
         emitted user source:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0: the emitted project actually compiles with `rustc` and
/// prints the rendered value. Gated on `IPE_E2E=1` — the only check that would
/// have caught the original SEAL violation (E0277, `ipe build` clean).
#[test]
fn i186_cargo_builds_and_runs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_i186_display_bound_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for display_bound: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("display_bound", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "display_bound binary must exit 0 (no E0277); got {:?} (stdout: {:?})",
        outcome.exit_code,
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim(),
        "value=42",
        "must print the `toString`-rendered value through the wildcard-`any` \
         renderer; got: {:?}",
        outcome.stdout
    );
}
