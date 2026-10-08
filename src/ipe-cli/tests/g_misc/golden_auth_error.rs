//! A token refusal reaches Ipê code as a typed `AuthError`.
//!
//! The `auth_error_typed` golden verifies a token under another key, a token
//! with a spliced payload, a zero-lifetime token, a token whose `nbf` is far in
//! the future, text that is not a token and a key below the minimum, and prints
//! the `AuthError` constructor each is refused with, the untouched token under
//! its own key as the control. A second module names `AuthError` in a type
//! annotation and matches every constructor without calling `verifyToken`.
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test g_misc golden_auth_error
//! ```

use crate::support::repo_root;

const GOLDEN: &str = "auth_error_typed";

/// Build and run the `auth_error_typed` golden under `IPE_E2E=1`, asserting its
/// stdout matches the oracle.
///
/// Each refusal line names the constructor `case` read from the `Err`, so a
/// misclassified refusal or a token that no longer fails turns its line red.
/// Under `IPE_E2E=1` the emitted project is built and run, so `ipe` accepting
/// a match over `AuthError` is proven to `cargo build`.
#[test]
fn auth_error_matches_oracle() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let dir = root.join("tests").join("golden").join(GOLDEN);
    let entry = dir.join("src").join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "build failed for {GOLDEN}: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted(GOLDEN, &out);
    crate::support::assert_go_parity(GOLDEN, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}
