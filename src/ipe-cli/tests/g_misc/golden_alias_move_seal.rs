//! IPE-L0105 by-VALUE alias binding — the partial-move (E0382) SEAL regression.
//!
//! An `as`-alias over a destructure (`(a, b) as whole`) in a by-VALUE binding
//! position binds BOTH the whole and its sub-parts. Rust's `name @ (a, b)`
//! spelling moves them from the SAME value — a partial move (E0382) for any
//! non-`Copy` payload. Emitting `let whole @ (a, b) = arg;` for `((a, b) as
//! whole)` over `(String, String)` is `ipe`-0 then `cargo`-101. So the whole
//! binds first and the sub-parts destructure from a CLONE, so every binder is
//! independently owned:
//!
//! ```ignore
//! let whole = arg;
//! let (a, b) = whole.clone();
//! ```
//!
//! The fixture exercises ALL FOUR by-value binding shapes with the non-`Copy`
//! `(String, String)` payload, every binder used in the body:
//!
//! * PARAM — `f ((a, b) as whole) = …` (a function parameter pattern).
//! * CASE — a single-arm product `case`, an irrefutable destructure.
//! * LET — an irrefutable `let` destructure with an alias.
//! * NESTED — `(h, ((c, d) as inner))`, an alias nested inside a tuple, driving
//!   the fresh-temp (`__ipe_bind_N`) path.
//!
//! Two locks:
//!
//! 1. `ipe` emits `main.rs` byte-identical to the checked-in golden — which
//!    records that NO by-value alias renders as `name @ inner`; every alias
//!    binds the whole then clones the sub-shape.
//! 2. Behind `IPE_E2E=1` the emitted project BUILDS (the seal: was `cargo`-101)
//!    and prints `pqpqrsrstutuhcdcd`, exit 0 — proving whole AND parts are live.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn fixture_dir(root: &Path) -> PathBuf {
    root.join("tests").join("golden").join("alias_move_seal")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = fixture_dir(&root).join("Main.ipe");
    let golden = fixture_dir(&root).join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("l0105_alias_move_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    // Directory-diff the emitted project against the golden dir (byte-compares
    // the emitted `src/main.rs` against the golden `main.rs`). Replaces the
    // former hand-rolled `read_to_string` + `assert_eq!` pair with the shared
    // harness helper.
    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// The seal invariant asserted independently of the byte lock: NO by-value
/// alias binding renders as Rust's moving `name @ (…)` subpattern, and every
/// alias binds the whole then clones the destructured sub-shape.
#[test]
fn no_by_value_alias_uses_at_subpattern() {
    let root = repo_root();
    let entry = fixture_dir(&root).join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("l0105_alias_move_seal_shapes");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());
    let src = std::fs::read_to_string(out.join("src").join("main.rs")).expect("main.rs");

    // The partial-move spelling must NOT appear in any by-value binding. `@ (`
    // (binding-with-tuple-subpattern) is exactly the E0382 shape the seal
    // removes; a legitimate slice rest binder is `@ ..`, never `@ (`.
    assert!(
        !src.contains("@ ("),
        "a by-value alias must never render as the moving `name @ (…)`:\n{src}"
    );
    // Top-level alias → bind whole, then clone the sub-shape. Post-emit
    // rustfmt puts each `let` on its own line, so match the stable fragments
    // rather than a single-line span.
    assert!(
        src.contains("let whole = arg_0;") && src.contains("let (a, b) = whole.clone();"),
        "PARAM alias must bind the whole then clone-destructure:\n{src}"
    );
    // Nested alias inside a tuple → fresh temps, then clone the inner shape.
    assert!(
        src.contains("let (__ipe_bind_0, __ipe_bind_1) = arg_1;")
            && src.contains("let inner = __ipe_bind_1;")
            && src.contains("let (c, d) = inner.clone();"),
        "NESTED alias must bind fresh temps then clone the inner shape:\n{src}"
    );
}

/// Full spine: build the emitted Cargo project, run it, assert it prints
/// `pqpqrsrstutuhcdcd`, exit 0. Gated on `IPE_E2E=1`. This is the SEAL: before
/// the fix the by-value alias binding was `ipe`-0 then `cargo`-101 (E0382);
/// the clean build + correct output prove whole AND parts are independently
/// owned and live.
#[test]
fn end_to_end_builds_and_prints_the_concatenation() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let entry = fixture_dir(&root).join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_l0105_alias_move_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("alias_move_seal", &out);
    assert_eq!(
        outcome.stdout.trim_end(),
        "pqpqrsrstutuhcdcd",
        "concatenated whole+parts across PARAM/CASE/LET/NESTED positions"
    );
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "clean exit — the E0382 seal holds"
    );
}
