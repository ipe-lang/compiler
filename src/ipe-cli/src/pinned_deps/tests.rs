//! The pinned set's parse and judge, against a small fixture set.

mod closure;

use super::{
    Admission, FfiPosture, LockDrift, LockField, LockParseError, LockRefusal, PinnedSet,
    PinnedSetError, Requester, SEED, pinned_set,
};

/// A checksum of 64 `a`s.
const SUM_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// A small pinned set: `serde_json` 1.0.140 and `itoa` 1.0.15, plus a path member.
const SET: &[u8] = b"version = 4\n\n\
    [[package]]\nname = \"member\"\nversion = \"0.1.0\"\ndependencies = [\"serde_json\"]\n\n\
    [[package]]\nname = \"itoa\"\nversion = \"1.0.15\"\n\
    source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
    checksum = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\n\
    [[package]]\nname = \"serde_json\"\nversion = \"1.0.140\"\n\
    source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
    checksum = \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n\
    dependencies = [\"itoa\"]\n";

/// The small set, parsed.
fn set() -> Option<PinnedSet> {
    PinnedSet::from_seed(SET).ok()
}

/// One crates.io `[[package]]` table.
fn registry(name: &str, version: &str, sum: &str, deps: &str) -> String {
    format!(
        "[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
         checksum = \"{sum}\"\ndependencies = [{deps}]\n\n"
    )
}

/// A lock whose root `app` depends on `deps`, then `packages`.
fn lock(deps: &str, packages: &str) -> String {
    format!(
        "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
         dependencies = [{deps}]\n\n{packages}"
    )
}

#[test]
fn the_embedded_set_parses_within_the_lock_cap() {
    let set = pinned_set();
    assert!(set.is_ok(), "the workspace lock is a pinned set: {set:?}");
    let Ok(set) = set else { return };
    assert_eq!(set.seed_bytes(), SEED);
    assert!(
        u64::try_from(SEED.len()).is_ok_and(|len| len <= super::LOCK_CAP.get()),
        "the seed fits the lock read cap"
    );
}

#[test]
fn a_strict_subset_of_the_set_agrees() {
    let Some(set) = set() else {
        assert!(set().is_some(), "the small set parses");
        return;
    };
    let text = lock("\"itoa\"", &registry("itoa", "1.0.15", SUM_A, ""));
    assert!(set.judge_text(&text, FfiPosture::FfiFree).is_ok());
}

#[test]
fn an_unpinned_name_is_refused_unless_ffi_brings_it() {
    let Some(set) = set() else {
        assert!(set().is_some(), "the small set parses");
        return;
    };
    let text = lock("\"extra\"", &registry("extra", "2.0.0", SUM_A, ""));
    assert!(matches!(
        set.judge_text(&text, FfiPosture::FfiFree),
        Err(LockDrift::Unpinned { name, .. }) if name.as_str() == "extra"
    ));
    assert!(set.judge_text(&text, FfiPosture::FfiBearing).is_ok());
    let other_major = lock("\"itoa\"", &registry("itoa", "2.0.0", SUM_A, ""));
    assert!(matches!(
        set.judge_text(&other_major, FfiPosture::FfiFree),
        Err(LockDrift::Unpinned { .. })
    ));
}

#[test]
fn a_moved_pin_is_refused_naming_the_pin_the_requester_and_the_fix() {
    let Some(set) = set() else {
        assert!(set().is_some(), "the small set parses");
        return;
    };
    let text = lock(
        "\"user_crate\"",
        &format!(
            "{}{}",
            registry("user_crate", "3.1.0", SUM_A, "\"serde_json\""),
            registry("serde_json", "1.0.100", SUM_A, ""),
        ),
    );
    for posture in [FfiPosture::FfiFree, FfiPosture::FfiBearing] {
        let verdict = set.judge_text(&text, posture);
        assert!(
            matches!(
                &verdict,
                Err(LockDrift::Moved { name, locked, pinned, requested_by: Some(by) })
                    if name.as_str() == "serde_json"
                        && locked.to_string() == "1.0.100"
                        && pinned.to_string() == "1.0.140"
                        && matches!(&**by, Requester::Crate { name, .. } if name.as_str() == "user_crate")
            ),
            "a moved pin is refused under {posture:?}: {verdict:?}"
        );
        let Err(drift) = verdict else { return };
        let shown = drift.to_string();
        assert!(
            shown.contains("serde_json 1.0.140"),
            "names the pin: {shown}"
        );
        assert!(shown.contains("user_crate"), "names the requester: {shown}");
        assert!(
            shown.contains("relax user_crate's `serde_json` requirement"),
            "names the fix: {shown}"
        );
    }
    let direct = lock(
        "\"serde_json\"",
        &registry("serde_json", "1.0.100", SUM_A, ""),
    );
    let verdict = set.judge_text(&direct, FfiPosture::FfiBearing);
    assert!(matches!(
        &verdict,
        Err(LockDrift::Moved { requested_by: Some(by), .. })
            if matches!(&**by, Requester::Project { name } if name.as_str() == "app")
    ));
    let Err(drift) = verdict else { return };
    let shown = drift.to_string();
    assert!(
        shown.contains("relax app's `serde_json` requirement") && shown.contains("1.0.140"),
        "names the project fix: {shown}"
    );
}

#[test]
fn a_pinned_version_with_another_checksum_is_refused() {
    let Some(set) = set() else {
        assert!(set().is_some(), "the small set parses");
        return;
    };
    let text = lock("\"itoa\"", &registry("itoa", "1.0.15", &"c".repeat(64), ""));
    for posture in [FfiPosture::FfiFree, FfiPosture::FfiBearing] {
        assert!(matches!(
            set.judge_text(&text, posture),
            Err(LockDrift::ChecksumDiffers { name, .. }) if name.as_str() == "itoa"
        ));
    }
    let no_sum = lock(
        "\"itoa\"",
        "[[package]]\nname = \"itoa\"\nversion = \"1.0.15\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
    );
    assert!(matches!(
        set.judge_text(&no_sum, FfiPosture::FfiBearing),
        Err(LockDrift::ChecksumDiffers { .. })
    ));
}

#[test]
fn a_foreign_source_is_refused_under_every_posture() {
    let Some(set) = set() else {
        assert!(set().is_some(), "the small set parses");
        return;
    };
    let text = lock(
        "\"itoa\"",
        "[[package]]\nname = \"itoa\"\nversion = \"1.0.15\"\n\
         source = \"git+https://example.invalid/itoa#abc\"\n",
    );
    for posture in [FfiPosture::FfiFree, FfiPosture::FfiBearing] {
        assert!(matches!(
            set.judge_text(&text, posture),
            Err(LockDrift::ForeignSource { name, source })
                if name.as_str() == "itoa" && source.starts_with("git+")
        ));
    }
}

#[test]
fn a_lock_outside_the_grammar_is_unparsable() {
    let Some(set) = set() else {
        assert!(set().is_some(), "the small set parses");
        return;
    };
    for (text, reason) in [
        ("not toml [", LockParseError::NotToml),
        (
            "version = 4\n[metadata]\n",
            LockParseError::UnknownKey("metadata".to_owned()),
        ),
        (
            "version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\npatch = 1\n",
            LockParseError::UnknownKey("patch".to_owned()),
        ),
        (
            "version = 4\n[[package]]\nname = \"a b\"\nversion = \"1.0.0\"\n",
            LockParseError::Malformed(LockField::Name),
        ),
        (
            "version = 4\n[[package]]\nname = \"a\"\nversion = \"one\"\n",
            LockParseError::Malformed(LockField::Version),
        ),
    ] {
        assert_eq!(
            set.judge_text(text, FfiPosture::FfiBearing),
            Err(LockDrift::Unparsable(reason)),
            "{text}"
        );
    }
}

#[test]
fn a_set_with_a_git_source_a_missing_checksum_or_format_3_is_refused() {
    let git: &[u8] = b"version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n\
        source = \"git+https://example.invalid/a#abc\"\n";
    assert!(matches!(
        PinnedSet::from_seed(git),
        Err(PinnedSetError::ForeignSource { name, .. }) if name.as_str() == "a"
    ));
    let unsummed: &[u8] = b"version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n\
        source = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
    assert!(matches!(
        PinnedSet::from_seed(unsummed),
        Err(PinnedSetError::MissingChecksum { name, .. }) if name.as_str() == "a"
    ));
    let format_3: &[u8] = b"version = 3\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n";
    assert!(matches!(
        PinnedSet::from_seed(format_3),
        Err(PinnedSetError::Parse(LockParseError::FormatVersion))
    ));
    let unversioned: &[u8] = b"[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n";
    assert!(matches!(
        PinnedSet::from_seed(unversioned),
        Err(PinnedSetError::Parse(LockParseError::FormatVersion))
    ));
}

#[test]
fn only_an_ffi_bearing_crate_admits_and_only_an_unpinned_name() {
    let Some(set) = set() else {
        assert!(set().is_some(), "the small set parses");
        return;
    };
    let text = lock("\"extra\"", &registry("extra", "2.0.0", SUM_A, ""));
    let verdict = set.judge_text(&text, FfiPosture::FfiFree);
    assert!(verdict.is_err(), "an unpinned name is refused without FFI");
    let Err(unpinned) = verdict else { return };
    assert_eq!(FfiPosture::FfiBearing.admits(&unpinned), Admission::Admit);
    assert_eq!(FfiPosture::FfiFree.admits(&unpinned), Admission::Refuse);
    assert_eq!(
        FfiPosture::FfiBearing.admits(&LockDrift::WrapperDiffers),
        Admission::Refuse
    );
    let refusal = LockRefusal {
        lock: "Cargo.lock".into(),
        posture: FfiPosture::FfiFree,
        drift: unpinned,
    };
    assert_eq!(refusal.fault(), crate::screen::Fault::Internal);
}

/// One path `[[package]]` table.
fn local(name: &str, deps: &str) -> String {
    format!("[[package]]\nname = \"{name}\"\nversion = \"0.1.0\"\ndependencies = [{deps}]\n\n")
}

#[test]
fn the_forcing_user_crate_is_named_never_the_root_or_the_bundled_runtime() {
    let Some(set) = set() else {
        assert!(set().is_some(), "the small set parses");
        return;
    };
    let runtime = crate::runtime_embed::RUNTIME_PACKAGE;
    let forced = format!(
        "version = 4\n\n{}{}{}{}",
        local(
            "ipe-app",
            &format!("\"{runtime}\", \"serde_json\", \"zstd_user\""),
        ),
        local(runtime, "\"serde_json\""),
        registry("serde_json", "1.0.100", SUM_A, ""),
        registry("zstd_user", "1.0.0", SUM_A, "\"serde_json\""),
    );
    for posture in [FfiPosture::FfiFree, FfiPosture::FfiBearing] {
        let verdict = set.judge_text(&forced, posture);
        assert!(
            matches!(
                &verdict,
                Err(LockDrift::Moved { requested_by: Some(by), .. })
                    if matches!(&**by, Requester::Crate { name, version }
                        if name.as_str() == "zstd_user" && version.to_string() == "1.0.0")
            ),
            "the user crate that forced the move is named under {posture:?}: {verdict:?}"
        );
    }
    // The runtime written first: lock order must not choose it.
    let own = format!(
        "version = 4\n\n{}{}{}",
        local(runtime, "\"serde_json\""),
        local("ipe-app", &format!("\"{runtime}\", \"serde_json\"")),
        registry("serde_json", "1.0.100", SUM_A, ""),
    );
    let verdict = set.judge_text(&own, FfiPosture::FfiBearing);
    assert!(
        matches!(
            &verdict,
            Err(LockDrift::Moved { requested_by: Some(by), .. })
                if matches!(&**by, Requester::Project { name } if name.as_str() == "ipe-app")
        ),
        "the root is named, never the bundled runtime: {verdict:?}"
    );
    let only_runtime = format!(
        "version = 4\n\n{}{}{}",
        local("ipe-app", &format!("\"{runtime}\"")),
        local(runtime, "\"serde_json\""),
        registry("serde_json", "1.0.100", SUM_A, ""),
    );
    assert!(
        matches!(
            set.judge_text(&only_runtime, FfiPosture::FfiBearing),
            Err(LockDrift::Moved {
                requested_by: None,
                ..
            })
        ),
        "a move only the runtime asks for names no requester to relax"
    );
}

#[test]
fn a_move_in_ipes_own_graph_is_worded_as_ipes_not_the_users() {
    let Some(set) = set() else {
        assert!(set().is_some(), "the small set parses");
        return;
    };
    let text = lock(
        "\"serde_json\"",
        &registry("serde_json", "1.0.100", SUM_A, ""),
    );
    for (posture, fault) in [
        (FfiPosture::FfiFree, crate::screen::Fault::Internal),
        (FfiPosture::FfiBearing, crate::screen::Fault::User),
    ] {
        let verdict = set.judge_text(&text, posture);
        assert!(
            matches!(&verdict, Err(LockDrift::Moved { .. })),
            "{verdict:?}"
        );
        let Err(drift) = verdict else { return };
        let refusal = LockRefusal {
            lock: "Cargo.lock".into(),
            posture,
            drift,
        };
        assert_eq!(refusal.fault(), fault);
        let shown = refusal.to_string();
        match fault {
            crate::screen::Fault::Internal => assert!(
                shown.contains("ipe's own dependency graph")
                    && shown.contains("serde_json 1.0.140")
                    && !shown.contains("relax"),
                "an internal move names no user remedy: {shown}"
            ),
            crate::screen::Fault::User => assert!(
                shown.contains("relax app's `serde_json` requirement"),
                "a user move names the user's remedy: {shown}"
            ),
        }
    }
}

#[test]
fn an_unpinned_crate_without_a_checksum_is_refused_under_every_posture() {
    let Some(set) = set() else {
        assert!(set().is_some(), "the small set parses");
        return;
    };
    let text = lock(
        "\"extra\"",
        "[[package]]\nname = \"extra\"\nversion = \"2.0.0\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
    );
    for (posture, fault) in [
        (FfiPosture::FfiFree, crate::screen::Fault::Internal),
        (FfiPosture::FfiBearing, crate::screen::Fault::User),
    ] {
        let verdict = set.judge_text(&text, posture);
        assert!(
            matches!(
                &verdict,
                Err(LockDrift::Unchecksummed { name, .. }) if name.as_str() == "extra"
            ),
            "a checksum-less addition is refused under {posture:?}: {verdict:?}"
        );
        let Err(drift) = verdict else { return };
        assert_eq!(posture.admits(&drift), Admission::Refuse);
        let refusal = LockRefusal {
            lock: "Cargo.lock".into(),
            posture,
            drift,
        };
        assert_eq!(refusal.fault(), fault);
        assert!(refusal.to_string().contains("without a checksum"));
    }
}
