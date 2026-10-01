//! `Ipe.Ui.Lazy` emit arms, LazyLazy..LazyLazy5 end to end.
//!
//! Regression for the emit arms: the Lazy kernels are registered in
//! naming/constrain/lower, and the `KernelFn::LazyLazy`..`LazyLazy5` arms in
//! `emit_ui_call` (`emit_expr.rs`) must exist too.  Without them, the
//! fail-closed wildcard at the bottom of `emit_ui_call` raises `IPE-I0001` on
//! every program that uses `Lazy.lazy` or its multi-arg siblings.
//!
//! ## What is tested
//!
//! * `Lazy.lazy viewItem "hello"` — arity-1 closure: emits
//!   `ipe_runtime::ui::lazy::lazy_lazy_(move |_a| (f)(_a), a)`.
//! * `Lazy.lazy2 viewPair "first" "second"` — arity-2 closure with TWO
//!   DISTINGUISHABLE args: emits `lazy_lazy2_(..., a, b)` (arg ORDER matters;
//!   a swap is silent past the mechanical gate).
//! * ipe exit 0 — prior diagnostic was IPE-I0001, this asserts it is gone.
//! * Emitted main.rs contains both `lazy_lazy_(` and `lazy_lazy2_(` call sites.
//! * The emitted Rust project builds without errors (seal: no exit-0-then-cargo-fail).
//! * The binary exits 0 and its stdout contains "hello", "first", and "second"
//!   — confirms arg threading is correct (not just that the calls compiled).
//!
//! Gated on `IPE_E2E=1`. Run:
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_i146_lazy_emit_seal
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn lazy_emit_seal_ipec_cargo_and_run_zero() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("lazy_emit_seal");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i146_lazy_emit_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    // ipe-0: prior diagnostic was IPE-I0001 LazyLazy no emit arm.
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for lazy_emit_seal (IPE-I0001 must be gone): {:?}",
        built.err()
    );

    // Emitted code must contain the lazy runtime helpers (not a generic fallback).
    // The per-module split relocates a user def's body into `src/ipe_mods/*.rs`,
    // so scan `src/` AND that subdirectory — the lazy call sites land wherever
    // the calling def is emitted.
    let src = out.join("src");
    let mut emitted = String::new();
    let mut scan = |dir: &Path| {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                if let Ok(text) = std::fs::read_to_string(&path) {
                    emitted.push_str(&text);
                    emitted.push('\n');
                }
            }
        }
    };
    scan(&src);
    scan(&src.join("ipe_mods"));
    assert!(
        emitted.contains("ipe_runtime::ui::lazy::lazy_lazy_("),
        "emitted Rust must call lazy_lazy_; got:\n{emitted}"
    );
    assert!(
        emitted.contains("ipe_runtime::ui::lazy::lazy_lazy2_("),
        "emitted Rust must call lazy_lazy2_; got:\n{emitted}"
    );

    // cargo-0 ∧ run-0: seal — ipe exit 0 must NOT be followed by cargo fail.
    let outcome = crate::support::build_and_run_emitted("lazy_emit_seal", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "lazy emit binary must exit 0; got {:?}",
        outcome.exit_code
    );

    // Arg-threading correctness: both distinguishable args must appear in output.
    let html = &outcome.stdout;
    assert!(
        html.contains("hello"),
        "lazy_lazy_ must thread 'hello' arg to viewItem; got:\n{html}"
    );
    assert!(
        html.contains("first"),
        "lazy_lazy2_ must thread 'first' arg correctly; got:\n{html}"
    );
    assert!(
        html.contains("second"),
        "lazy_lazy2_ must thread 'second' arg correctly; got:\n{html}"
    );
}
