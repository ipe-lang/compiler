//! A generic union's inner record-of-function has no `Clone` impl (SEAL).
//!
//! Without the fix, `ipe build` exits 0, but the emitted Rust fails `cargo build`:
//! a generic union `Box a` whose inner record stores a first-class function keyed
//! on `a` (`read : String -> Result Error a`) ALONGSIDE a bare generic field
//! (`seed : a`) synthesised a `Rec…<T1>` struct with NEITHER a `#[derive(Clone)]`
//! NOR a hand-written `impl Clone`. Cloning the enclosing union (an ordinary
//! reuse across two closures) then autoref-cloned a `&Rec…<T1>` reference, an
//! E0308 whose note reads `Rec…<T1> does not implement Clone`.
//!
//! Root cause: the record `is_clone` fixpoint (the backend's `lib.rs`)
//! consulted the bare `ipe_ir::carrier_is_clone` leaf test, which returns `false`
//! for a bare type-variable field — even though the emitted hand-written
//! `impl<Tn: Clone> Clone` bounds every parameter `Tn: Clone`. The sibling
//! function-carrier ENUM already consulted `enum_field_is_clone`, which admits a
//! bare generic under that bound; the record did not.
//!
//! Fix: the record fixpoint consults `record_field_is_clone` (the record twin of
//! `enum_field_is_clone`), and `emit_record_struct` stamps `Tn: Clone` on the
//! hand-written `impl Clone` — sound because every emitted generic instantiation
//! is `Clone`-bounded at the caller, and the `Arc<dyn Fn>` `SharedFun` carrier is
//! itself `Clone` (a refcount bump) for any `Tn`.
//!
//! Run:
//! ```text
//! # fast (no cargo):
//! cargo test -p ipe --test g_record_generic fncarrier_record_generic_clone
//!
//! # full E2E (real `cargo build` of the emitted project — the only check that
//! # would have caught the original SEAL: ipe-0 then E0308):
//! IPE_E2E=1 cargo test -p ipe --test g_record_generic fncarrier_record_generic_clone
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("fncarrier_record_generic_clone")
}

fn entry_path(root: &Path) -> PathBuf {
    golden_dir(root).join("Main.ipe")
}

/// ipe-0 + emitted-source assertion (unconditional, cheap — no `cargo`): the
/// compiler must accept the program AND emit the synthesized record with a
/// generic, `Clone`-bounded hand-written `impl Clone`. This directly asserts the
/// E0308 (`does not implement Clone`) trigger is gone, independent of `IPE_E2E`.
#[test]
fn fncarrier_record_generic_clone_ipec_accepts_and_impls_clone() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fncarrier_record_generic_clone_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP fncarrier_record_generic_clone: runtime not available");
        return;
    };

    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for fncarrier_record_generic_clone: {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");

    // The synthesized inner record struct must carry a hand-written, generic
    // `Clone` impl whose type parameter is `Clone`-bounded. Without the fix the
    // struct had NO `impl Clone` at all (the enclosing union's clone then failed).
    let clone_head = emitted
        .lines()
        .find(|l| l.contains("Clone for RecReadSeed"));
    assert!(
        clone_head.is_some(),
        "emitted must hand-write a `Clone` impl for the fn-carrier record; got main.rs:\n{emitted}"
    );
    let clone_head = clone_head.unwrap_or_default();
    assert!(
        clone_head.contains("T1: Clone"),
        "the record's hand-written `Clone` impl must bound its type parameter \
         `T1: Clone`; got: {clone_head}"
    );
}

/// cargo-0 ∧ run-0 ∧ self-regression: the emitted project actually compiles with
/// `rustc` (no E0308), runs, and prints the expected token. Gated on `IPE_E2E=1`
/// — a real `cargo build`, the only check that would have caught the original
/// SEAL violation (ipe-0 then `RecReadSeed<T1> does not implement Clone`).
#[test]
fn fncarrier_record_generic_clone_cargo_builds_and_runs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let gdir = golden_dir(&root);
    let out = crate::support::scratch_root().join("ipec_fncarrier_record_generic_clone_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for fncarrier_record_generic_clone: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("fncarrier_record_generic_clone", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "fncarrier_record_generic_clone binary must exit 0 (no E0308); got {:?} (stdout: {:?})",
        outcome.exit_code,
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim(),
        "1,0",
        "must print the reused generic union's read result and seed (`runBox \"7\"` \
         = 1, `seedOf` = 0); got: {:?}",
        outcome.stdout
    );

    // Self-regression: ipe's stdout must byte-match the captured `expected.txt`.
    crate::support::assert_go_parity("fncarrier_record_generic_clone", &gdir, &outcome.stdout);
}
