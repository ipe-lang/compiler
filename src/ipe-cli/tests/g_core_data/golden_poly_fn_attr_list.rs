//! Seal — polymorphic-function attribute lists.
//!
//! Regression: `IrType::Ui { msg }` inside an annotated-polymorphic function
//! was lowering `msg` to `IrType::Unit`, emitting `Attribute<()>` instead of
//! `Attribute<T1>` — E0308 ×4 at `cargo build`.
//!
//! Root cause: `ir_type_from_ty_ui_msg` resolved a `Ty::Var(rep)` against
//! `current_poly_tvars` only when the per-def map was installed, but
//! `current_poly_tvars` was never populated for `Def::Typed` entries.
//!
//! Fix: `lower_def` for `Def::Typed` now installs the annotation's rigid
//! type vars into `current_poly_tvars` before lowering the body, so
//! `Attribute<T1>` is emitted instead of `Attribute<()>`.
//!
//! Gated on `IPE_E2E=1`:
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_i139_poly_fn_attr_list
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// `counterView : (InnerMsg -> parentMsg) -> Int -> Html parentMsg` with
/// attribute lists must:
///
/// * compile through `ipe` (exit 0)
/// * emit `Attribute<T1>` — not `Attribute<()>` — in attribute-list positions
/// * build through `cargo build` (exit 0; E0308 without the fix)
/// * run and print rendered HTML that contains "counter"
#[test]
fn poly_fn_attr_list_ipec_and_cargo_zero() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("poly_fn_attr_list")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i139_poly_fn_attr_list_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    // ipe-0: compiler must succeed.
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for poly_fn_attr_list: {:?}",
        built.err()
    );

    // Regression guard: the emitted Rust must use `Attribute<T1>`, not
    // `Attribute<()>`, in the polymorphic attribute lists. The per-module split
    // relocates a user def's body into `src/ipe_mods/*.rs`, so scan `src/` AND
    // that subdirectory — `Attribute<T1>` lands wherever `counterView` is emitted.
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
        emitted.contains("Attribute<T1>"),
        "emitted Rust must contain Attribute<T1> (poly msg param) — \
         regression would emit Attribute<()>.\nRelevant lines:\n{}",
        emitted
            .lines()
            .filter(|l| l.contains("Attribute") || l.contains("counter_view") || l.contains("T1"))
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
    );

    // cargo-0 + run-0: emitted project must build and the binary must exit 0.
    let outcome = crate::support::build_and_run_emitted("poly_fn_attr_list", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "binary must exit 0; stdout:\n{}",
        outcome.stdout
    );
    // Sanity: the rendered HTML should contain the CSS class we assigned.
    assert!(
        outcome.stdout.contains("counter"),
        "rendered HTML must contain 'counter'; got:\n{}",
        outcome.stdout
    );
}
