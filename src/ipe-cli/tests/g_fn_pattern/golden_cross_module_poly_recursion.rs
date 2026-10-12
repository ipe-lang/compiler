//! A mutually-recursive,
//! UNANNOTATED, cross-module function pair polymorphic in the list-element type
//! (`evenLen`/`oddLen : List a -> Bool`), used by an importer at TWO different
//! element types (`List Int` and `List String`).
//!
//! Without the fix, `ipe dev build` FAILED with IPE-L0102 ("polymorphic value's type could
//! not be determined") at the `[] ->` arm inside `Lib.ipe`. The type-checker
//! (`ipe_types`) correctly generalized the boundary scheme — its
//! `untyped_type_params` entry listed the element var — but `ipe_lower`'s
//! `lower_case` carried a stale gate that rejected ANY list `case` binding a
//! value (`_ :: rest`) whose element type lowered to `IrType::Generic(_)`,
//! believing "function generics emit bound-free" so `rest.to_vec()` would fail
//! `cargo build`. That premise is false: every emitted function type parameter
//! carries a `Clone` bound (`render_fn_generics`'s `bounds.with_clone()`), and
//! `list_elem_ir` returns `IrType::Generic(sym)` ONLY for a var that IS one of
//! the enclosing function's declared type parameters (a free var maps to
//! `IrType::Json`). So the emitted `fn even_len<T1: Clone>(xs: Vec<T1>) -> bool`
//! with `rest.to_vec()` builds fine — the gate rejected sound programs.
//!
//! Fix (`crates/ipe_lower/src/lower.rs`, `lower_case`): remove the stale
//! generic-element list-binding IPE-L0102 gate. A `Generic` element that reaches
//! `lower_case` is, by construction, a `Clone`-bounded declared type parameter,
//! so the owned-rebind (`rest.to_vec()` / `x.clone()`) is sound. Cross-module
//! polymorphic recursion (Boundary Scheme Promotion) now lowers to a real Rust
//! generic instead of failing closed.
//!
//! Run:
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_i201_cross_module_poly_recursion
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("cross_module_poly_recursion")
        .join("src")
        .join("Main.ipe")
}

/// ipe-0: the compiler must accept the 2-module program (no IPE-L0102) AND emit
/// `even_len` as a `Clone`-bounded Rust generic. Checked unconditionally (cheap,
/// no `cargo`), independent of the `IPE_E2E` gate below.
#[test]
fn i201_ipec_accepts_and_emits_clone_bounded_generic() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("i201_cross_module_poly_recursion_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for cross_module_poly_recursion (no IPE-L0102): {:?}",
        built.err()
    );

    // `Lib`'s recursive pair lowers to its own Rust file under `src/ipe_mods/`
    // once the per-Ipê-module split fires — scan the whole emitted Ipê-side tree.
    let emitted = crate::support::read_all_emitted_src(&out);

    // The recursive pair must lower to a `Clone`-bounded Rust generic — the
    // element var reached the generic path (not IPE-L0102) and the emitted
    // `Vec<T1>` `rest.to_vec()` needs `T1: Clone`.
    assert!(
        emitted.contains("fn lib_even_len<T1: Clone>(xs: Vec<T1>) -> bool"),
        "even_len must lower to a `Clone`-bounded Rust generic \
         (`fn lib_even_len<T1: Clone>(xs: Vec<T1>) -> bool`); got emitted src:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0: the emitted project actually compiles with `rustc` (no
/// IPE-L0102 fail-closed, no `cargo` error on the generic `rest.to_vec()`) and
/// prints the two parity results. Gated on `IPE_E2E=1` — the check that proves
/// the seal (ipe-0 ⇒ cargo-0) end to end.
#[test]
fn i201_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_i201_cross_module_poly_recursion_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for cross_module_poly_recursion: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("cross_module_poly_recursion", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "cross_module_poly_recursion binary must exit 0 (no IPE-L0102, no cargo error); \
         got {:?} (stdout: {:?})",
        outcome.exit_code,
        outcome.stdout
    );
    // `evenLen [90, 35, 32, 77]` — 4 elements, even → "E"; `evenLen ["ors"]` —
    // 1 element, odd → "O". The mutually-recursive pair, used at `List Int` and
    // `List String`, prints "EO".
    assert!(
        outcome.stdout.contains("EO"),
        "must print the two parity results through the cross-module polymorphic \
         mutual recursion; got: {:?}",
        outcome.stdout
    );
}
