//! SEAL: a use that leaves a generic view helper's message slot open names `()` for it.
//!
//! A helper generic over a `msg` that occurs only in its signature's message
//! slots stays a Rust generic when some use keeps it generic. A use that renders
//! it straight to a `String` never chooses a message type: the use's own node
//! type lowers that slot to `()`, so the emitted call must carry `::<()>` or
//! rustc cannot infer the helper's generic (E0283) after ipe accepted the
//! program. Covered shapes: a saturated call, a nullary helper, a parameter-slot
//! `msg`, a function value, and typed and untyped helpers from another module.
//!
//! The emit gate asserts each pinned call; under `IPE_E2E=1` the emitted crate
//! must build and print every rendering (`expected.txt`).

use std::path::{Path, PathBuf};

const GOLDEN: &str = "use_site_msg_pin_seal";

/// The emitted calls whose message slot this program leaves open, each pinned to `()`.
const PINNED: [&str; 6] = [
    "main_leaf::<()>(",
    "main_nav::<()>(",
    "main_boxed::<()>(",
    "main_framed::<()>(",
    "widgets_badge::<()>(",
    "widgets_chip::<()>(",
];

/// The calls a generic caller makes: its own `msg` reaches the helper, so no pin.
const UNPINNED: [&str; 3] = ["main_boxed(", "widgets_row(", "widgets_chip("];

fn golden_dir(root: &Path) -> PathBuf {
    root.join("tests").join("golden").join(GOLDEN)
}

/// Emit gate: every open message slot is pinned to `()`; a generic caller's use is not.
#[test]
fn use_site_msg_pin_emitted() {
    let root = crate::support::repo_root();
    let golden = golden_dir(&root);
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&golden, &out, &runtime);
    assert!(
        built.is_ok(),
        "{GOLDEN}: ipe dev build must accept the program, got: {built:?}"
    );

    let emitted = crate::support::read_all_emitted_src(&out);
    for call in PINNED {
        assert!(
            emitted.contains(call),
            "{GOLDEN}: a use leaving the message slot open must emit `{call}`; got:\n{emitted}"
        );
    }
    for call in UNPINNED {
        assert!(
            emitted.contains(call),
            "{GOLDEN}: a generic caller's use must stay unpinned as `{call}`; got:\n{emitted}"
        );
    }
}

/// Refusal: an open instantiation outside a message slot gets no `()` pin; ipe refuses it.
#[test]
fn use_site_open_non_msg_var_refused() {
    let name = "use_site_open_non_msg_refused";
    let root = crate::support::repo_root();
    let golden = root.join("tests").join("golden").join(name);
    let out = crate::support::scratch_root().join(format!("ipec_{name}"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&golden, &out, &runtime);
    let code = match &built {
        Err(ipe::CliError::Pipeline { diag, .. }) => Some(diag.code()),
        Ok(()) | Err(_) => None,
    };
    assert_eq!(
        code,
        Some(ipe_diagnostics::IPE_L0102),
        "{name}: ipe must refuse the open non-message instantiation with IPE-L0102; got {built:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1` the emitted crate must `cargo build` and print every rendering.
#[test]
fn use_site_msg_pin_seal_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = crate::support::repo_root();
    let golden = golden_dir(&root);
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&golden, &out, &runtime);
    assert!(
        built.is_ok(),
        "{GOLDEN}: ipe dev build must accept the program, got: {built:?}"
    );

    let run = crate::support::build_and_run_emitted(GOLDEN, &out);
    assert_eq!(
        run.exit_code,
        Some(0),
        "{GOLDEN}: the emitted program must exit 0"
    );
    crate::support::assert_self_regression(GOLDEN, &golden, &run.stdout);
}
