//! A non-Copy binding captured into an Input `Arc`
//! callback AND reused by a sibling.
//!
//! Without the fix, `ipe build` exits 0, but the emitted Rust fails `cargo build` with
//! E0382 ("use of moved value: `habit`"). The lowerer pre-clones the checkbox
//! `onChange` callback's captured `habit`
//! (`let habit = habit.clone(); Lambda { … }`), but `arc_callback_wrap` then
//! re-wrapped the WHOLE block in
//! `Arc::new(move |_x| ({ let habit = habit.clone(); … })(_x))` — the outer
//! `move` still move-captured the FREE outer `habit`, so a later sibling use
//! (`RemoveHabit habit.id`, the button `onPress`) hit use-after-move.
//!
//! Fix (`emit_arc_callback_field` in `crates/ipe_backend_rust/src/emit_expr.rs`):
//! hoist the leading capture-clone `let`s OUTSIDE the `Arc`'s `move` closure —
//! `{ let habit = habit.clone(); ::std::sync::Arc::new(move |_x| (INNER)(_x)) }`
//! — so the `Arc` owns the pre-made clone and the original binding survives for
//! the sibling.
//!
//! Run:
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_i191_input_arc_capture
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("input_arc_capture")
        .join("Main.ipe")
}

/// ipe-0: the compiler must accept the program AND emit the capture-clone `let`
/// OUTSIDE the `Arc`'s `move` closure — checked unconditionally (cheap, no
/// `cargo`), independent of the `IPE_E2E` gate. This is the exact assertion that
/// the E0382 SEAL break cannot recur: the pre-clone must sit before `Arc::new`,
/// never inside its `move |_x|` body.
#[test]
fn i191_ipec_accepts_and_hoists_capture_clone() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i191_input_arc_capture_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP input_arc_capture: runtime not available");
        return;
    };

    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for input_arc_capture: {:?}",
        built.err()
    );

    // A layout builder (`Ui.row`) is compiled-source Ipê now, so its home lowers
    // to `src/ipe_mods/*.rs` and `main_habit_row` lands there — scan the WHOLE
    // emitted Ipê-side tree (main.rs + ipe_mods/*.rs).
    let emitted = crate::support::read_all_emitted_src(&out);

    // Post-emit rustfmt reflows long lines, so the two statements can land on
    // separate (indented) lines rather than the single-line span ipec first
    // emits — match on rustfmt-normalized text (`crate::support::
    // normalize_rustfmt_whitespace`) so the check tracks *token adjacency*,
    // not a fixed line layout (same stale-substring class as #269), while
    // still verifying the exact thing #191 requires: order and immediate
    // adjacency between the clone and the `Arc::new` it precedes.
    let normalized = crate::support::normalize_rustfmt_whitespace(&emitted);

    // The pre-clone must be HOISTED outside the `Arc`'s `move` closure — the
    // `let habit = habit.clone();` statement immediately precedes
    // `::std::sync::Arc::new` (the fix), so the Arc owns the clone and the
    // original survives.
    assert!(
        normalized.contains(&crate::support::normalize_rustfmt_whitespace(
            "let habit = habit.clone(); ::std::sync::Arc::new"
        )),
        "the capture-clone must be hoisted OUTSIDE the Arc `move` closure (#191); \
         got main.rs:\n{emitted}"
    );
    // Guard against the unfixed shape: the clone must NOT sit inside the Arc's
    // `move |_x|` body (which would re-move the free outer `habit`).
    assert!(
        !normalized.contains(&crate::support::normalize_rustfmt_whitespace(
            "Arc::new(move |_x| (({ let habit = habit.clone();"
        )),
        "the capture-clone must NOT sit inside the Arc `move` closure (the #191 \
         use-after-move shape); got main.rs:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0: the emitted project actually compiles with `rustc` (no
/// E0382) and renders the row. Gated on `IPE_E2E=1` — the only check that would
/// have caught the original SEAL violation (E0382, `ipe build` clean).
#[test]
fn i191_cargo_builds_and_runs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_i191_input_arc_capture_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for input_arc_capture: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("input_arc_capture", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "input_arc_capture binary must exit 0 (no E0382); got {:?} (stdout: {:?})",
        outcome.exit_code,
        outcome.stdout
    );
    // The reused `habit` renders the checkbox label AND the Remove button — proof
    // the binding survived every consuming site.
    assert!(
        outcome.stdout.contains("water") && outcome.stdout.contains("Remove"),
        "must render the row (checkbox label `water` + `Remove` button) through \
         the reused `habit` binding; got: {:?}",
        outcome.stdout
    );
}
