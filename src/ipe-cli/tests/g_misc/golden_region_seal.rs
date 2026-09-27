//! Seal — all 8 `Ipe.Ui.Region` kernel members exercised inside
//! `Ui.layout`.  Asserts ipe-0 ∧ cargo-0.
//!
//! Kernels under test:
//! * `Region.mainContent`, `navigation`, `footer`, `aside` — nullary landmark attrs
//! * `Region.heading : Int -> Attribute msg`
//! * `Region.label : String -> Attribute msg`
//! * `Region.announce`, `announceUrgently` — nullary live-region attrs
//!
//! Gated on `IPE_E2E=1`. Run:
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_i117_region_seal
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn region_all_members_ipec_and_cargo_zero() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("region_seal");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i117_region_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    // ipe-0: compiler must succeed.
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for region_seal: {:?}",
        built.err()
    );

    // Verify the emitted source calls the Region helpers. The per-module split
    // relocates a user def's body into `src/ipe_mods/*.rs`, so scan `src/` AND
    // that subdirectory — the Region calls land wherever the view is emitted.
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
    for helper in &[
        "ui_region_main_content_",
        "ui_region_navigation_",
        "ui_region_footer_",
        "ui_region_aside_",
        "ui_region_heading_",
        "ui_region_label_",
        "ui_region_announce_",
        "ui_region_announce_urgently_",
    ] {
        assert!(
            emitted.contains(helper),
            "emitted Rust must contain `{helper}`"
        );
    }

    // cargo-0: emitted project must build and run.
    let outcome = crate::support::build_and_run_emitted("region_seal", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "must exit 0 (cargo-0); stdout:\n{}",
        outcome.stdout
    );
    // Sanity: at least one landmark appears in the rendered HTML.
    assert!(
        outcome.stdout.contains("main") || outcome.stdout.contains("nav"),
        "program output must contain rendered content; got:\n{}",
        outcome.stdout
    );
}
