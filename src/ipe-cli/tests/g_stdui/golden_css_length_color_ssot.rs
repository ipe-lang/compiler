//! Cross-language SSOT equivalence gate for `Ipe.Css.lengthToString` /
//! `Ipe.Css.colorToString` versus the native `ui::element::Length::css` /
//! `Color::css` renderers.
//!
//! PRINCIPLES §SSOT: two representations that cannot import each other —
//! the pure-Ipê `Ipe.Css` fold and the native Rust renderer — must have
//! their equality ASSERTED IN A TEST, never hand-synced. This fixture is
//! that test for the CSS-value domain.
//!
//! Shared shapes covered:
//! - `Length`: `Px n`, `Vh n`, `Vw n`.
//! - `Color`: `Rgba r g b a` (alpha via the shortest-decimal float rule:
//!   `1.0` → `"1"`, `0.5` → `"0.5"`, `0.0` → `"0"`).
//!
//! Out of scope: `Fill`/`Content`/`Min`/`Max` are layout-intent lengths in
//! `Ipe.Ui` with no `Ipe.Css` counterpart — the two vocabularies express
//! different domains for those shapes.
//!
//! The native-side assertions live in
//! `src/runtime/rust/src/ui/element.rs` (`tests` module).
//!
//! Run (emit-only, no cargo build of the emitted project):
//! ```text
//! cargo nextest run -p ipe -E 'binary(g_stdui)' css_length_color_ssot
//! ```
//! Run with full E2E SEAL:
//! ```text
//! IPE_E2E=1 cargo nextest run -p ipe -E 'binary(g_stdui)' css_length_color_ssot
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir() -> PathBuf {
    repo_root()
        .join("tests")
        .join("golden")
        .join("css_length_color_ssot")
}

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    ipe::resolve_runtime().expect("runtime must resolve for css_length_color_ssot golden")
}

/// Compile `tests/golden/css_length_color_ssot/Main.ipe` and assert the
/// emitted `src/main.rs` plus every `src/ipe_mods/*.rs` file matches the
/// checked-in golden byte-for-byte. This proves the `Ipe.Css` fold lowers
/// and emits unchanged.
#[test]
fn css_length_color_ssot_emits_byte_identical() {
    let dir = golden_dir();
    let entry = dir.join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("css_length_color_ssot_emit");
    let _ = std::fs::remove_dir_all(&out);

    let rt = runtime();
    let built = ipe::build(&entry, &out, &rt);
    assert!(
        built.is_ok(),
        "ipe build must succeed for css_length_color_ssot: {:?}",
        built.err()
    );

    crate::support::assert_emitted_project_matches_golden_dir(&out, &dir);
}

/// Full E2E SEAL (`IPE_E2E=1`): build and run the emitted project; assert
/// stdout matches the expected CSS strings byte-for-byte. The expected
/// values are the SAME strings asserted by the native `Length::css` /
/// `Color::css` unit tests in `element.rs`, proving cross-language equivalence
/// end-to-end.
#[test]
fn css_length_color_ssot_e2e_output_matches_native_table() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let dir = golden_dir();
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_css_length_color_ssot_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let rt = runtime();
    let built = ipe::build(&entry, &out, &rt);
    assert!(
        built.is_ok(),
        "ipe build must succeed for css_length_color_ssot E2E: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("css_length_color_ssot", &out);
    assert_eq!(outcome.exit_code, Some(0), "emitted binary must exit 0");

    let stdout = &outcome.stdout;

    // Length shapes — values must match `Length::css` assertions in element.rs.
    for (shape, expected) in [
        ("Px 0", "0px"),
        ("Px 16", "16px"),
        ("Px 100", "100px"),
        ("Vh 50", "50vh"),
        ("Vh 100", "100vh"),
        ("Vw 50", "50vw"),
        ("Vw 100", "100vw"),
    ] {
        assert!(
            stdout.contains(expected),
            "Ipe.Css.lengthToString ({shape}) must render {expected:?}; got:\n{stdout}"
        );
    }

    // Color shapes — values must match `Color::css` assertions in element.rs.
    for (shape, expected) in [
        ("Rgba 0 0 0 1.0", "rgba(0,0,0,1)"),
        ("Rgba 255 0 0 1.0", "rgba(255,0,0,1)"),
        ("Rgba 0 128 255 1.0", "rgba(0,128,255,1)"),
        ("Rgba 0 0 0 0.0", "rgba(0,0,0,0)"),
        ("Rgba 255 128 0 0.5", "rgba(255,128,0,0.5)"),
    ] {
        assert!(
            stdout.contains(expected),
            "Ipe.Css.colorToString ({shape}) must render {expected:?}; got:\n{stdout}"
        );
    }
}
