//! Seal regression — the post-catch-all arm truncation in `lower_case`
//! must key off the CANONICAL `is_irrefutable` predicate, not a hand-rolled
//! `PAnything | PVar` match.
//!
//! The hand-rolled form missed `PAlias` over an irrefutable inner
//! (`_ as w` / `other as w`). The exhaustiveness pass treats such an alias
//! head as a catch-all (maps to `Wild`) and only WARNS (`IPE-T0011`) about the
//! arms after it — but the truncation left those arms alive, so they reached
//! `Match::new_flat`, whose structural backstop raised `IPE-I0001`
//! (`CompilerBug`) on well-typed source. Both shapes must now build.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn assert_builds(fixture: &str) {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(fixture);
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{fixture}: alias catch-all + trailing arm must warn (IPE-T0011) and \
         build (was IPE-I0001 ICE): {:?}",
        built.err()
    );
}

/// `Red -> …; other as w -> …; Blue -> …` — named-alias catch-all head.
#[test]
fn named_alias_catchall_truncates_and_builds() {
    assert_builds("alias_catchall");
}

/// `Red -> …; _ as w -> …; Blue -> …` — wildcard-alias catch-all head.
#[test]
fn underscore_alias_catchall_truncates_and_builds() {
    assert_builds("underscore_alias");
}
