//! Clone-relay across an intermediate closure boundary — SEAL regression.
//!
//! A `let`-bound function (`insertRow`) read only at lambda-nesting depth >= 2,
//! reached through a pipeline-synthesized intermediate `move` closure
//! (`|> Task.andThen (\ts -> insertRow x ts)`) whose callback also captures a
//! NON-Copy enclosing-lambda param (`x : String`).
//!
//! `needs_shared_capture` promotes `insertRow` to a `SharedLambda`
//! (`Arc<dyn Fn>`); the pipeline stage synthesizes a real intermediate closure
//! via `eta_expand_partial` (the non-Copy `x` pre-clone wrap defeats the
//! direct-call collapse). Without the fix, `wrap_shared_lambda_if_needed` decided
//! `needs_wrap` on the PRE-recursion body via the lambda-opaque
//! `sym_referenced_directly`, so the intermediate closure — which reaches
//! `insertRow` only through a DEEPER lambda — never got its pre-clone and
//! move-captured `insertRow` out of the enclosing `Fn` env → E0507.
//!
//! So it recurses FIRST and decides `needs_wrap` on the PROCESSED body — the
//! inner lambda's wrap plants a direct `CloneVar(insertRow)` read in the
//! intermediate closure's body, so the intermediate's post-recursion check sees
//! it and wraps too. The pre-clone relays outward through every boundary.
//!
//! THE SEAL: ipe-0 => cargo-0. Without the fix this program is ipe-0 but
//! cargo-101 (E0507 on `insertRow`), the 18-job-queue failure shape.
//!
//! Run:
//! ```text
//! # fast (no cargo):
//! cargo test -p ipe --test golden_i218_clone_relay_intermediate_eta
//!
//! # full E2E (THE SEAL):
//! IPE_E2E=1 cargo test -p ipe --test golden_i218_clone_relay_intermediate_eta
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("clone_relay_intermediate_eta")
        .join("Main.ipe")
}

/// ipe-0: the compiler must accept the intermediate-boundary clone-relay
/// program, and emit a pre-clone for the shared-capture `insertRow` binding.
#[test]
fn i218_clone_relay_ipec_accepts() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("i218_clone_relay_intermediate_eta_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP clone_relay_intermediate_eta: runtime not available");
        return;
    };

    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for clone_relay_intermediate_eta: {:?}",
        built.err()
    );

    let emitted = crate::support::read_all_emitted_src(&out);

    // The shared-capture `insertRow` fn must be pre-cloned (Arc::clone shadow)
    // at least once so no `move` closure moves it out of an `Fn` env.
    assert!(
        emitted.contains("insertRow.clone()"),
        "reused shared-capture `insertRow` must have at least one `.clone()` \
         in emitted user source; got:\n{emitted}"
    );
}

/// cargo-0 ∧ run-correct: gated on `IPE_E2E=1` — THE SEAL.
#[test]
fn i218_clone_relay_cargo_builds_and_runs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_i218_clone_relay_intermediate_eta_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(built.is_ok(), "ipe build must succeed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("clone_relay_intermediate_eta", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "clone_relay_intermediate_eta must exit 0 (no E0507); stdout: {:?}",
        outcome.stdout
    );
    // save "abc": insertRow "seed" ts = len("seed") + len("abc") + ts.
    // ts is a live unix-millis timestamp, so only assert the stable prefix.
    assert!(
        outcome.stdout.contains("total="),
        "must print the total line; got: {:?}",
        outcome.stdout
    );
}
