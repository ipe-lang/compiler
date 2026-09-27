//! End-to-end gate for the type-constructor kernel families: Ipe.Ui `Length`,
//! Ipe.Ui `Color`, and the `Ipe.Json.Encode` `Value` encoders.
//!
//! Without a `stdlib_scheme` entry these kernels would be `Ty::Var(u32::MAX)`
//! scheme holes in `ipe_types::constrain`. Their schemes make
//! `Length` / `Color` lower to `IrType::UiPlain(_)` and the JSON `Value` type to
//! `IrType::Json` — so the whole `type -> lower -> emit -> run` path is
//! typed. This golden proves the pipeline end-to-end:
//!
//! * `Ui.px 120` (a `Length`) fed to `Ui.width`   → `width:120px`
//! * `Ui.minimum 40 Ui.fill` (a `Length`)         → `height:min(40px,100%)`
//! * `Ui.rgb 0 128 255` (a `Color`) fed to
//!   `Background.color`                            → `background-color:rgba(0,128,255,1)`
//! * `JsonEnc.object`/`string`/`int`/`encode`      → `{"name":"ada","age":36}`
//!   (keys in the list order given to `object`)
//!
//! Asserts on semantic substrings rather than an exact HTML oracle: the Ipe.Ui
//! HTML skeleton is a sanctioned sanctioned-divergence (see `tests/golden/stdui`),
//! but the CSS fragments emitted for `Length` / `Color` values and the compact
//! JSON line are byte-stable and are what this slice actually exercises.
//!
//! Gated on `IPE_E2E=1`. Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m7_ui_length_color_json
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Compile / build / run `tests/golden/ui_length_color_json/Main.ipe` and
/// assert the emitted binary renders the `Length` / `Color` CSS fragments and
/// the compact JSON line. Gated on `IPE_E2E=1`.
#[test]
fn ui_length_color_and_json_value_render_end_to_end() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = root
        .join("tests")
        .join("golden")
        .join("ui_length_color_json");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m7_ui_length_color_json_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for ui_length_color_json: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("ui_length_color_json", &out);
    assert_eq!(outcome.exit_code, Some(0), "must exit 0");

    let stdout = &outcome.stdout;
    // `Length` values (Ui.px / Ui.minimum / Ui.fill) rendered into CSS.
    assert!(
        stdout.contains("width:120px"),
        "Ui.px 120 (Length) must render `width:120px`; got:\n{stdout}"
    );
    assert!(
        stdout.contains("height:min(40px,100%)"),
        "Ui.minimum 40 Ui.fill (Length) must render `height:min(40px,100%)`; got:\n{stdout}"
    );
    // `Color` value (Ui.rgb) rendered into CSS.
    assert!(
        stdout.contains("background-color:rgba(0,128,255,1)"),
        "Ui.rgb 0 128 255 (Color) must render `background-color:rgba(0,128,255,1)`; got:\n{stdout}"
    );
    // `Value` program (JsonEnc.object/string/int/encode). Keys in list order.
    assert!(
        stdout.contains(r#"{"name":"ada","age":36}"#),
        "JsonEnc program must encode `{{\"name\":\"ada\",\"age\":36}}`; got:\n{stdout}"
    );
}
