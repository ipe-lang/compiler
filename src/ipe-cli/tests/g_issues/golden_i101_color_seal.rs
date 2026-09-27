//! Seal — the home-aware enum guard in `ipe_lower::ir_type_from_ty` must
//! win over the bare-name Ipe.Ui / Ipe.Web opaque arms.
//!
//! Matching the bare name `"Color"` (→ `IrType::UiPlain(UiPlain::Color)`)
//! BEFORE the `enum_variants` guard would hijack a program-defined `type Color`
//! that flows through the INFERRED lowering path to the opaque Ipe.Ui `Color`:
//!
//! * (i) a boxed `Fn(Color)` HOF argument emitted `Box<dyn
//!   Fn(ipe_runtime::color::Color) -> _>` → ipe-0 / cargo-101 (E0433).
//! * (ii) a record field literal `{ c = Cyan }` lowered the field via the
//!   ty-path (→ `UiPlain::Color`) while the annotation lowered it via
//!   `ir_type_from_canon` (→ `MainColor`) — the two disagreed → IPE-I0001.
//!
//! The `enum_variants.contains_key(&(home, name))` guard sits AHEAD of the
//! nullary opaque arms (mirroring `ir_type_from_canon`), so a program union
//! resolves to its OWN enum by `(home, name)` identity while the genuine Ipe.Ui
//! builtin (no union entry) still falls through to `UiPlain`.
//!
//! Both goldens ALSO assert the coexistence invariant: the emitted Rust carries
//! the user enum `MainColor` AND the runtime `ipe_runtime::color::Color`
//! (proof iii — the real Ipe.Ui Color is unchanged).
//!
//! Gated on `IPE_E2E=1`. Run:
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_i101_color_seal
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Concatenate every emitted Rust source under `out/src`, including the
/// per-module-split bodies under `out/src/ipe_mods` (skipping the copied
/// `ipe_runtime` subtree), so the test can assert on the generated program text
/// regardless of how the backend splits modules across files.
fn emitted_program_source(out: &Path) -> String {
    let mut acc = String::new();
    let mut scan = |dir: &Path| {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&path) {
                acc.push_str(&text);
                acc.push('\n');
            }
        }
    };
    let src = out.join("src");
    scan(&src);
    scan(&src.join("ipe_mods"));
    acc
}

/// Proof (i): a user `type Color` used via a HOF (lambda argument → inferred
/// lowering path) resolves to `MainColor` and BUILDS + RUNS; the genuine Ipe.Ui
/// `Color` in the same module still lowers to `UiPlain::Color`.
#[test]
fn user_color_via_hof_resolves_to_own_enum() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("user_color_hof");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i101_user_color_hof_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    // ipe must succeed (it always did — the hole was cargo-side).
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for user_color_hof: {:?}",
        built.err()
    );

    let program = emitted_program_source(&out);
    // The user enum is emitted as its own `MainColor` type. The per-module split
    // relocates it into `src/ipe_mods/*.rs` with `pub(crate)` visibility, so match
    // the declaration itself rather than any one visibility qualifier.
    assert!(
        program.contains("enum MainColor"),
        "user `type Color` must emit its own `MainColor` enum"
    );
    // …and the HOF's boxed `Fn(Color)` argument now takes `MainColor` (THE fix);
    // pre-it was `Box<dyn Fn(ipe_runtime::color::Color) -> _>` → E0433.
    assert!(
        program.contains("Fn(MainColor)"),
        "the inferred boxed HOF argument must take `MainColor`, not the opaque \
         Ipe.Ui Color"
    );
    assert!(
        !program.contains("Fn(ipe_runtime::color::Color)"),
        "the pre-#101 hijack (`Fn(ipe_runtime::color::Color)`) must be gone"
    );
    // The genuine Ipe.Ui Color path (Ui.rgb / Background.color) is unchanged —
    // it flows through the runtime helpers (proof iii, coexistence).
    assert!(
        program.contains("ui_rgb_") && program.contains("ui_background_color_"),
        "the genuine Ipe.Ui Color path must still emit the runtime UI helpers"
    );

    // cargo build + run must succeed (pre-#101: cargo-101 / E0433).
    let outcome = crate::support::build_and_run_emitted("user_color_hof", &out);
    assert_eq!(outcome.exit_code, Some(0), "must exit 0 (was cargo-101)");
    assert!(
        outcome.stdout.contains("magenta"),
        "user Color HOF must print `magenta`; got:\n{}",
        outcome.stdout
    );
    assert!(
        outcome
            .stdout
            .contains("background-color:rgba(0,128,255,1)"),
        "genuine Ipe.Ui Color must still render its CSS; got:\n{}",
        outcome.stdout
    );
}

/// Proof (ii): a user `type Color` in a record FIELD (inferred record-literal
/// path) agrees with the annotated (canon) path — was IPE-I0001.
#[test]
fn user_color_in_record_field_agrees_across_paths() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("user_color_record");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i101_user_color_record_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for user_color_record: {:?}",
        built.err()
    );

    let program = emitted_program_source(&out);
    assert!(
        program.contains("MainColor"),
        "record field `c : Color` must resolve to `MainColor` on both paths"
    );

    let outcome = crate::support::build_and_run_emitted("user_color_record", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "must exit 0 (was IPE-I0001 ty-vs-canon disagreement)"
    );
    assert!(
        outcome.stdout.contains("ipe:cyan"),
        "record program must print `ipe:cyan`; got:\n{}",
        outcome.stdout
    );
}
