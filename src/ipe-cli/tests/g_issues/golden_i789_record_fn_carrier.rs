//! Regression: a bare function stored in a record LITERAL via a non-literal fn
//! value (an application returning a function, `wrap (\n -> n)`) was type-checked
//! (ipe exit 0) but then failed `cargo build` with `E0308` — the field's
//! `SharedFun` `Arc<dyn Fn>` carrier received a `Box<dyn Fn>` value because the
//! record-literal value side only re-carriered the two LITERAL leaves (an inline
//! lambda and a bare top-level-function reference), leaving every other
//! function-value leaf on the `Box` carrier.
//!
//! The fix routes the record-literal (and record-update) field value through the
//! same eta-expansion that already normalizes enum-payload / tuple / collection
//! stored functions (`promote_stored_fn_carrier`): a non-literal fn value is
//! wrapped in `Arc::new(move |eta_0, …| (value)(eta_0, …))`, so field type and
//! field value agree on the `Arc` carrier by construction. This is general to
//! ANY bare-fn record field, independent of the `RetryPolicy` kernel path — a
//! non-`RetryPolicy` `shouldRetry` field builds identically.
//!
//! The load-bearing proof is the SEAL: under `IPE_E2E=1` the emitted crate must
//! `cargo build`, run, and exit 0.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("fcf_record_fn")
        .join("Main.ipe")
}

/// Emit gate + byte-identity golden: the frontend must accept the bare-fn
/// record-literal program and re-emit the checked-in `main.rs` byte-for-byte (the
/// `Arc::new(move |eta_0| …)` carrier normalization is locked in the golden). The
/// `E0308` this closed was a `cargo`-time failure invisible to an accept-only
/// check, so this alone is not the SEAL proof — see the E2E test.
#[test]
fn record_fn_literal_emits_byte_identical() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("fcf_record_fn")
        .join("main.rs");
    let out = crate::support::scratch_root().join("ipec_i789_fcf_record_fn_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a bare function stored in a record literal via `wrap (\\n -> n)` must be \
         accepted + emitted (the field value is normalized onto the `SharedFun` \
         `Arc` carrier), got: {built:?}"
    );

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` and run the emitted crate.
/// Before the fix this was `ipe`-accept then `cargo` `E0308` (`Box` into `Arc`).
/// `runner.run 3` = `(wrap (\n -> n*2)) 3` = `(3*2)+1` = `7`;
/// `guard.shouldRetry 3` = `(wrap (\n -> n+10)) 3` = `(3+10)+1` = `14`.
#[test]
fn record_fn_literal_builds_and_runs() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i789_fcf_record_fn_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "fcf_record_fn must be accepted, got: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("fcf_record_fn", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "emitted crate must build and exit 0 — a bare-fn record literal via a \
         non-literal fn value must not be `ipe`-accept-then-`cargo`-fail; \
         stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(
            outcome.stdout.trim(),
            "7,14",
            "wrong runtime output — the two normalized fn fields compute 7 and 14"
        );
    }
}
