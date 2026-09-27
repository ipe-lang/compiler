//! REFUSAL SEAL for the typed URL sinks (`Ipe.Html.Attributes.href`,
//! `Ipe.Html.Attributes.src` / `imageSrc`, `Ipe.Ui.link`,
//! `Ipe.Browser.Share.shareUrl`, the `<head>` `href` sinks
//! `Ipe.Web.Head.canonical` / `Ipe.Web.Head.rss`) and the shared same-origin
//! relative-reference predicate (`Ipe.Url.relative`).
//!
//! A navigation `href` narrows through the anchor allowlist
//! (`http`/`https`/`mailto`/`tel`); a media `src` is a distinct FETCH role with
//! its own tighter allowlist (`http`/`https` only), so a `mailto:` / `tel:`
//! target accepted at `href` must fail closed at `imageSrc`. Every unsafe target
//! — a `javascript:` / `data:` / `file:` / `vbscript:` / `blob:` scheme, a
//! protocol-relative `//host`, a backslash-folded path, a scheme-before-slash, a
//! control char, an empty string — must fail closed at its typed constructor;
//! every safe one must pass. The pinned matrix output is the standing proof of
//! the refusals (a regression that opens one flips a row).
//!
//! The frontend-accepts assertion runs in the default gate; the build-and-run
//! proof is `IPE_E2E`-gated, matching every other seal in this suite.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn built_url_scheme(root: &Path, out: &Path) -> Option<Result<(), ipe::CliError>> {
    let entry = root
        .join("tests")
        .join("golden")
        .join("url_scheme_seal")
        .join("Main.ipe");
    let _ = std::fs::remove_dir_all(out);
    let runtime = ipe::resolve_runtime().ok()?;
    Some(ipe::build(&entry, out, &runtime))
}

/// Emit assertion: the frontend must accept the whole refusal matrix — every
/// typed constructor and the relative-ref predicate resolve, scheme, and emit.
#[test]
fn url_scheme_seal_emits() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_url_scheme_seal_emit");
    let Some(built) = built_url_scheme(&root, &out) else {
        return;
    };
    assert!(
        built.is_ok(),
        "url_scheme_seal: must be accepted + emitted, got: {built:?}"
    );
}

/// Load-bearing REFUSAL SEAL: under `IPE_E2E=1` the emitted crate must build,
/// run, and produce the pinned matrix — proving each unsafe URL is rejected and
/// each safe one accepted at the typed boundary.
#[test]
fn url_scheme_seal_builds_and_runs() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_url_scheme_seal_e2e");
    let Some(built) = built_url_scheme(&root, &out) else {
        return;
    };
    assert!(
        built.is_ok(),
        "url_scheme_seal: must be accepted, got: {built:?}"
    );

    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let outcome = crate::support::build_and_run_emitted("url_scheme_seal", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "url_scheme_seal: emitted crate must build and exit 0; stdout:\n{}",
        outcome.stdout
    );
    let expected = "href_https=OK\n\
                    href_http=OK\n\
                    href_mailto=OK\n\
                    href_tel=OK\n\
                    href_javascript=ERR\n\
                    href_data=ERR\n\
                    href_file=ERR\n\
                    href_vbscript=ERR\n\
                    href_blob=ERR\n\
                    link_https=OK\n\
                    link_mailto=OK\n\
                    link_javascript=ERR\n\
                    img_https=OK\n\
                    img_relative=OK\n\
                    img_mailto=ERR\n\
                    img_tel=ERR\n\
                    img_javascript=ERR\n\
                    share_https=OK\n\
                    share_mailto=ERR\n\
                    canonical_https=OK\n\
                    canonical_javascript=ERR\n\
                    canonical_file=ERR\n\
                    rss_https=OK\n\
                    rss_javascript=ERR\n\
                    rel_path=OK\n\
                    rel_dot=OK\n\
                    rel_fragment=OK\n\
                    rel_query=OK\n\
                    rel_protocol_rel=ERR\n\
                    rel_backslash=ERR\n\
                    rel_scheme=ERR\n\
                    rel_empty=ERR\n\
                    rel_control=ERR";
    assert_eq!(
        outcome.stdout.trim(),
        expected,
        "url_scheme_seal: the refusal matrix produced wrong output"
    );
}
