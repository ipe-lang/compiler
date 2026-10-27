//! D5 regression — `Ui.onInput`/`Ui.onChange` inline-wrap emitter sites.
//!
//! A non-Copy record captured into a `Ui.onInput` callback AND reused by a
//! sibling `onPress` button in the same view.
//!
//! **Without the fix, ** `ipe` exits 0, but the emitted Rust fails `cargo build` with
//! E0382 ("use of moved value") whenever the multi-use-clone rewrite's
//! `let item = item.clone();` lands inside a `move` closure that captures the
//! free outer `item`, so the sibling `onPress` hits use-after-move.
//!
//! The `onInput` handler is an adapted slot in handler normal form (`let`s
//! around one closure literal): the emitter emits the leading `let`s OUTSIDE
//! the closure it places in the `Arc`, the same rule every adapted slot
//! (`Ui.on*`, `Input.*` callback fields) follows.
//!
//! Run:
//! ```text
//! # fast (no cargo):
//! cargo test -p ipe --test golden_i193_oninput_reused_capture
//!
//! # full E2E:
//! IPE_E2E=1 cargo test -p ipe --test golden_i193_oninput_reused_capture
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("oninput_reused_capture")
}

/// ipe-0: the compiler must accept the program AND emit the capture-clone `let`
/// OUTSIDE the `ui_on_input_` Arc closure — checked unconditionally (no cargo).
///
/// This is the exact assertion that the E0382 SEAL break cannot recur for the
/// `Ui.onInput` inline-wrap path: the pre-clone must sit before `Arc::new`,
/// never inside its `move |_x|` body.
#[test]
fn i193_oninput_ipec_accepts_and_hoists_capture_clone() {
    let root = repo_root();
    let golden = golden_dir(&root);
    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i193_oninput_reused_capture_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = crate::support::build_golden(&golden, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for oninput_reused_capture: {:?}",
        built.err()
    );

    // A layout builder is compiled-source Ipê now, so the capturing home lowers
    // to `src/ipe_mods/*.rs` — scan the WHOLE emitted Ipê-side tree.
    let emitted = crate::support::read_all_emitted_src(&out);

    // Post-emit rustfmt reflows long lines, so the two statements can land on
    // separate (indented) lines rather than the single-line span ipec first
    // emits — match on rustfmt-normalized text (`crate::support::
    // normalize_rustfmt_whitespace`) so the check tracks *token adjacency*,
    // not a fixed line layout (same stale-substring class as #269 / #191),
    // while still verifying order and immediate adjacency between the clone
    // and the `Arc::new` it precedes.
    let normalized = crate::support::normalize_rustfmt_whitespace(&emitted);

    // The capture-clone `let` must be HOISTED outside the `ui_on_input_` Arc
    // closure — `let item = item.clone(); ::std::sync::Arc::new(…)`.
    // The same hoist the onChange FIELD path uses, applied to the UiOnInput
    // inline-wrap path.
    assert!(
        normalized.contains(&crate::support::normalize_rustfmt_whitespace(
            "let item = item.clone(); ::std::sync::Arc::new"
        )),
        "capture-clone must be hoisted OUTSIDE the Arc `move` closure (#193 D5); \
         got main.rs:\n{emitted}"
    );

    // Guard against the unfixed shape: the clone must NOT sit inside the Arc's
    // `move |_x|` body, which would re-move the free outer `item`.
    assert!(
        !normalized.contains(&crate::support::normalize_rustfmt_whitespace(
            "Arc::new(move |_x| (({ let item = item.clone();"
        )),
        "capture-clone must NOT sit inside the Arc `move` closure (the pre-fix \
         E0382 shape); got main.rs:\n{emitted}"
    );
}

/// cargo-0 ∧ run-correct: emitted project compiles (no E0382) and renders the
/// row.  Gated on `IPE_E2E=1` — the only check that catches the original SEAL
/// violation (E0382 from `cargo build`, invisible to `ipe`).
#[test]
fn i193_oninput_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let golden = golden_dir(&root);
    let out = crate::support::scratch_root().join("ipec_i193_oninput_reused_capture_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = crate::support::build_golden(&golden, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("oninput_reused_capture", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "oninput_reused_capture must exit 0 (no E0382); stdout: {:?}",
        outcome.stdout
    );
    // The reused `item` renders both the input label AND the Remove button label
    // — proof the binding survived every consuming site.
    let stdout = &outcome.stdout;
    assert!(
        stdout.contains("apple") && stdout.contains("Remove"),
        "must render the row (item name `apple` + `Remove` button) through the \
         reused `item` binding; got: {stdout:?}"
    );
}
