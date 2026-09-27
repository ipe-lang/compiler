//! Seal — `List.filter` / `List.any` with a partial-application
//! predicate must compile AND run.
//!
//! Root cause: `ipe_backend_rust::emit_expr::emit_lambda` always lowers a
//! Ipê closure VALUE to `Box<dyn Fn(..) -> .. + Send + 'static>` regardless
//! of what it captures. `Box<dyn Fn>` can never implement `Clone` (trait
//! objects can't derive it), so any kernel whose Rust signature demanded
//! `impl Fn(..) -> .. + Clone` on the callback rejected EVERY boxed closure
//! at `cargo build` with E0277 — not just partial applications (the shape
//! the original bug report used), but plain non-capturing lambdas too.
//!
//! `ipe_runtime::list::list_filter` / `list_any` (plus `list_all` /
//! `list_foldl` / `list_foldr` / `list_indexed_map` / `list_concat_map` /
//! `list_find`) declared that `+ Clone` bound without ever actually cloning
//! the callback — each calls it through a shared `&self` borrow (a `for`
//! loop, or `Iterator::filter`/`any`/`all`/`map`/`flat_map`, all of which
//! only need `Fn`/`FnMut`). The fix drops the bound from all eight kernels
//! in `src/runtime/rust/src/list.rs`.
//!
//! Fixture shape: `List.filter (isAbove 3) items` / `List.any (isAbove N)
//! items`, where `isAbove threshold x = x > threshold` — `isAbove 3` is a
//! genuine partial application (a closure over `threshold`), the exact shape
//! from the bug report (`List.filter (isVisible session) items`).
//!
//! ```text
//! # compile-only check (fast, no IPE_E2E needed):
//! cargo test -p ipe --test golden_i161_list_filter_partial_app
//!
//! # full E2E (build the emitted crate with cargo AND run it):
//! IPE_E2E=1 cargo test -p ipe --test golden_i161_list_filter_partial_app
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Assert that `ipe::build(fixture)` SUCCEEDS (exit-0 from the lowerer).
/// Runs without `IPE_E2E` so the compile check is always fast.
#[test]
fn list_filter_partial_app_compiles() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("list_filter_partial_app")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i161_list_filter_partial_app_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // runtime unavailable — skip silently
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for list_filter_partial_app: {:?}",
        built.err()
    );

    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    // Re-emit into a stable temp dir for the cargo build/run leg (the
    // CARGO_TARGET_TMPDIR copy above is fine for the compile-only check but
    // `crate::support::build_and_run_emitted` wants a dedicated directory it can
    // freely rewrite the manifest of).
    let e2e_out = crate::support::scratch_root().join("ipec_i161_list_filter_partial_app_e2e");
    let _ = std::fs::remove_dir_all(&e2e_out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &e2e_out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for list_filter_partial_app (E2E leg): {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("list_filter_partial_app", &e2e_out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "#161: emitted crate must build with cargo and exit 0 (was E0277 \
         `Box<dyn Fn> is not Clone` before the fix)"
    );
    assert!(
        outcome.stdout.contains("3TF"),
        "#161: List.filter (isAbove 3) [1..6] must keep [4,5,6] (len 3), \
         List.any (isAbove 5) must be true, List.any (isAbove 10) must be \
         false — expected \"3TF\" in stdout; got:\n{}",
        outcome.stdout
    );
}
