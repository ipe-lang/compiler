//! D3 seal: `count_fn_value_uses` Match arms must stay SUM (not MAX).
//!
//! A pure fn-typed param passed as an argument (consuming position) in each of
//! two case arms sums to 2 total consuming uses. Under the fn-value
//! `Arc`-carrier promotion, the SUM (2 > 1) drives the param's
//! promotion to the `Clone` `Arc<dyn Fn>` carrier — the program compiles and
//! runs (`applyEither True (+1)` = `43`) instead of fail-closing IPE-L0127.
//!
//! The SUM-not-MAX pin survives with its polarity flipped: if
//! `count_fn_value_uses`'s Match arm were accidentally changed to MAX,
//! `max(1,1)=1` would skip the promotion, the param would stay a bare
//! `Box<dyn Fn>` moved once per arm, and the emitted source would carry NO
//! `Arc<dyn Fn>` rebind — the default (fast) test run asserts that rebind is
//! present, and the `IPE_E2E=1` run would catch the resulting cargo E0382.
//!
//! Run:
//! ```text
//! cargo test -p ipe --test golden_i193_nonclone_fn_once_per_arm
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// The per-arm consuming uses must SUM to 2 and Arc-promote the param: the
/// build succeeds and the emitted program carries the `Arc<dyn Fn>` rebind.
/// Behind `IPE_E2E=1` the emitted project must build and print `43`.
#[test]
fn i193_nonclone_fn_once_per_arm_rejected() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("nonclone_fn_once_per_arm")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i193_nonclone_fn_once_per_arm_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "per-arm fn-value uses must SUM to 2 and Arc-promote the param \
         (was IPE-L0127 under the Box-only carrier): {built:?}"
    );

    let emitted = crate::support::read_all_emitted_src(&out);
    assert!(
        emitted.contains("::std::sync::Arc<dyn Fn"),
        "the promoted param must carry the `Arc<dyn Fn>` rebind — its absence \
         means the Match-arm counter regressed from SUM to MAX (max(1,1)=1 \
         skips the promotion and re-opens the per-arm double-move E0382)"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("nonclone_fn_once_per_arm", &out);
        assert_eq!(outcome.exit_code, Some(0), "exit 0");
        assert_eq!(outcome.stdout.trim(), "43", "applyEither True (+1) = 43");
    }
}
