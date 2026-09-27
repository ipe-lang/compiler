//! `stdui_input` seal — `Ui.input` + `Ui.describe` + `desc*` constructors.
//!
//! Kernels under test:
//! * `Ui.input : List (Attribute msg) -> Element msg` — void `<input>` element
//! * `Ui.describe : Description -> Attribute msg`
//! * `Ui.descMain`, `descNavigation`, `descContentInfo`, `descComplementary`,
//!   `descLivePolite`, `descLiveAssertive` — nullary `Description` constructors
//! * `Ui.descHeading : Int -> Description`
//! * `Ui.descLabel : String -> Description`
//!
//! Gated on `IPE_E2E=1`. Run:
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_m7_stdui_input
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn ui_input_and_describe_ipec_and_cargo_zero() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("stdui_input");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m7_stdui_input_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    // ipe-0: compiler must succeed.
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for stdui_input: {:?}",
        built.err()
    );

    // Verify the emitted source calls the new helpers. The per-module split
    // relocates a user def's body into `src/ipe_mods/*.rs`, so scan `src/` AND
    // that subdirectory — the Ui helper calls land wherever the view is emitted.
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
    // `Ui.input` is a stdlib-source `.ipe` function (`Ipe/Ui.ipe`), so it lowers
    // to the user-space `user_ipe_ui_input` call, not a `ui_input_` kernel helper.
    assert!(
        emitted.contains("user_ipe_ui_input"),
        "emitted Rust must call the stdlib-source `Ui.input` (`user_ipe_ui_input`)"
    );
    // `Ui.describe` and the `desc*` constructors are kernel helpers.
    for helper in &[
        "ui_describe_",
        "ui_desc_main_",
        "ui_desc_navigation_",
        "ui_desc_content_info_",
        "ui_desc_complementary_",
        "ui_desc_live_polite_",
        "ui_desc_live_assertive_",
        "ui_desc_heading_",
        "ui_desc_label_",
    ] {
        assert!(
            emitted.contains(helper),
            "emitted Rust must contain `{helper}`"
        );
    }

    // cargo-0: emitted project must build and run.
    let outcome = crate::support::build_and_run_emitted("stdui_input", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "must exit 0 (cargo-0); stdout:\n{}",
        outcome.stdout
    );
    // Sanity: the rendered HTML contains an <input> and at least one landmark.
    assert!(
        outcome.stdout.contains("<input") || outcome.stdout.contains("main content"),
        "program output must contain rendered content; got:\n{}",
        outcome.stdout
    );
}
