//! SEAL for `Ipe.Http.StatusCode` and the media `src` boundary
//! (`Ipe.Html.Attributes.imageSrc` / `MediaTarget`).
//!
//! `Ipe.Http.StatusCode` is a compiled-source opaque newtype over `Int`.
//! `fromInt` is total; `code` recovers the integer; the four `is*` predicates
//! classify 2xx/3xx/4xx/5xx ranges.  Pure Ipê, no feature gate.
//!
//! `Ipe.Html.Attributes.MediaTarget` is a compiled-source closed sum:
//! `MediaAbsolute Url | MediaRelative Relative`, narrowed to `http`/`https` only
//! (a media `src` is a FETCH sink, distinct from a navigation `href`).  Because
//! `MediaAbsolute` embeds `Ipe.Url.Url`, any program that constructs one forces
//! the `url` runtime feature via the type-driven SSOT
//! (`ir_type_feature_requirement`) — without a single `Ffi.kernel` call.
//!
//! The frontend-accepts assertions run in the default gate.  Build-and-run proofs
//! are `IPE_E2E`-gated, matching every other golden in this suite.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn built_statuscode(root: &Path, out: &Path) -> Result<(), ipe::CliError> {
    let entry = root
        .join("tests")
        .join("golden")
        .join("statuscode_seal")
        .join("Main.ipe");
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, out, &runtime)
}

fn built_imagesrc(root: &Path, out: &Path) -> Result<(), ipe::CliError> {
    let entry = root
        .join("tests")
        .join("golden")
        .join("imagesrc_seal")
        .join("Main.ipe");
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, out, &runtime)
}

// ── Ipe.Http.StatusCode ──────────────────────────────────────────────────────

/// Emit assertion: the frontend must accept a program that drives `StatusCode`
/// through `fromInt`, `code`, and all four classifiers.
#[test]
fn statuscode_seal_emits() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_statuscode_seal_emit");
    let built = built_statuscode(&root, &out);
    assert!(
        built.is_ok(),
        "statuscode_seal: must be accepted + emitted, got: {built:?}"
    );
}

/// Load-bearing SEAL: under `IPE_E2E=1` the emitted crate must `cargo build`,
/// run, and produce the pinned output (range probes + mutual-exclusion check).
#[test]
fn statuscode_seal_builds_and_runs() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_statuscode_seal_e2e");
    let built = built_statuscode(&root, &out);
    assert!(
        built.is_ok(),
        "statuscode_seal: must be accepted, got: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("statuscode_seal", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "statuscode_seal: emitted crate must build and exit 0; stdout:\n{}",
            outcome.stdout
        );
        let expected = "code=200 ok=true\n\
                    code=301 redirect=true\n\
                    code=404 client=true\n\
                    code=500 server=true\n\
                    neg=false";
        assert_eq!(
            outcome.stdout.trim(),
            expected,
            "statuscode_seal: round-trips and classifiers produced wrong output"
        );
    }
}

// ── Ipe.Html.Attributes media src (`imageSrc` / `MediaTarget`) ───────────────

/// Emit assertion: the frontend must accept a program that constructs both
/// `MediaTarget` arms (absolute + same-origin relative) and recovers the
/// `src` attribute-value string.
#[test]
fn imagesrc_seal_emits() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_imagesrc_seal_emit");
    let built = built_imagesrc(&root, &out);
    assert!(
        built.is_ok(),
        "imagesrc_seal: must be accepted + emitted, got: {built:?}"
    );
}

/// Load-bearing SEAL: under `IPE_E2E=1` the emitted crate must `cargo build`
/// (proving the `url` feature is forced by the `Url`-embedding type), run, and
/// produce the pinned `<img src>` output for both `MediaAbsolute` and
/// `MediaRelative` variants.
#[test]
fn imagesrc_seal_builds_and_runs() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_imagesrc_seal_e2e");
    let built = built_imagesrc(&root, &out);
    assert!(
        built.is_ok(),
        "imagesrc_seal: must be accepted, got: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("imagesrc_seal", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "imagesrc_seal: emitted crate must build and exit 0; stdout:\n{}",
            outcome.stdout
        );
        let expected = "<img alt=\"x\" src=\"https://example.com/img.png\" />\n\
                    <img alt=\"y\" src=\"/static/logo.png\" />";
        assert_eq!(
            outcome.stdout.trim(),
            expected,
            "imagesrc_seal: MediaAbsolute and MediaRelative src attribute-values produced wrong output"
        );
    }
}
