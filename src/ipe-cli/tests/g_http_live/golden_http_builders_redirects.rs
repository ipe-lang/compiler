//! `Http` builders: `withUrl` / `withRedirects`.
//!
//! `withRedirects` is a pure single-field record update on `HttpRequest`,
//! emitted through `emit_http_builder_call`'s clone-and-reassign block like
//! its siblings (`withMethod` / `withTimeout` / `withBody`).  `withUrl` is
//! the typed-target retarget: it takes a typed `Url`, re-narrows the scheme to
//! http/https at the API layer (fail-closed), and is emitted as a call to the
//! runtime fn `http_with_url` returning `Result Error HttpRequest`.
//!
//! Compile-tier assertion runs always; the run-tier requires `IPE_E2E=1`:
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_m5b_http_builders_redirects
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn redirect_builders_compile_and_run() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("http_builders_redirects")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m5b_http_builders_redirects_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    // ipe-0: the builders must resolve through the kernel path.
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for http_builders_redirects: {:?}",
        built.err()
    );

    // Emission regression: `withRedirects` must emit its clone-and-reassign
    // block targeting the `redirects` field.
    let emitted = std::fs::read_to_string(out.join("src").join("main.rs")).unwrap_or_default();
    assert!(
        emitted.contains("__ipe_rec.redirects = "),
        "emitted Rust must contain `__ipe_rec.redirects = ` (builder record update).\n\
         Relevant lines:\n{}",
        emitted
            .lines()
            .filter(|l| l.contains("__ipe_rec"))
            .take(10)
            .collect::<Vec<_>>()
            .join("\n")
    );
    // `withUrl` is the typed-target retarget: it must emit a call to the runtime
    // fn that performs the fail-closed http/https scheme narrowing, not a raw
    // record update (a raw update would skip the narrowing).
    assert!(
        emitted.contains("http_with_url"),
        "emitted Rust must call `http_with_url` (typed-target retarget with \
         API-layer scheme narrowing).\n--- src/main.rs ---\n{emitted}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        // cargo-0 + run-0 with the exact expected chain result.
        let outcome = crate::support::build_and_run_emitted("http_builders_redirects", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "binary must exit 0; stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(
            outcome.stdout.trim(),
            // `withUrl` carries the typed `Url`'s canonical serialization; the two
            // blocks exercise both `RedirectPolicy` variants (NoRedirects and
            // FollowRedirects Int).
            "http://example.org/\nnoredirect\nhttp://example.org/\nfollow 3",
            "builder chain must override url and both redirect-policy variants"
        );
    }
}
