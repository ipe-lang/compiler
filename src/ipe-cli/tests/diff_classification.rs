#![forbid(unsafe_code)]
//! Change detection, classification, and required-bump derivation over the
//! canonical [`PublicApi`] — the `ipe diff` core, driven with hand-built API
//! surfaces so each classification rule is exercised in isolation.

use std::collections::BTreeMap;

use ipe::api_surface::{ModuleApi, PublicApi, UnionApi};
use ipe::diff::{
    ApiChange, Compatibility, FloorOverflow, Predecessor, RequiredBump, SemverReport, bump_floor,
    diff_api, magnitude, required_bump,
};
use semver::Version;

/// [`ipe::diff::report`] over versions whose floors cannot overflow.
#[allow(clippy::expect_used)] // test helper: a non-overflowing fixture
fn report(old: &PublicApi, new: &PublicApi, old_v: &Version, new_v: &Version) -> SemverReport {
    ipe::diff::report(old, new, old_v, new_v).expect("floor does not overflow")
}

#[allow(clippy::expect_used)] // test helper: literal fixture versions
fn parse(raw: &str) -> Version {
    Version::parse(raw).expect("valid version")
}

/// A one-module API with the given values and unions.
fn api(values: &[(&str, &str)], unions: &[(&str, UnionApi)]) -> PublicApi {
    let mut module = ModuleApi::default();
    for (name, sig) in values {
        module.values.insert((*name).to_owned(), (*sig).to_owned());
    }
    for (name, union) in unions {
        module.unions.insert((*name).to_owned(), union.clone());
    }
    let mut modules = BTreeMap::new();
    modules.insert(vec!["Lib".to_owned()], module);
    PublicApi { modules }
}

fn union(params: usize, ctors: &[(&str, &[&str])]) -> UnionApi {
    let ctors = ctors
        .iter()
        .map(|(name, args)| {
            (
                (*name).to_owned(),
                args.iter().map(|a| (*a).to_owned()).collect(),
            )
        })
        .collect();
    // `ctor_types` is threaded for `ipe doc`'s cross-references; `ipe diff` reads
    // only the string form, so these classification tests leave it empty.
    UnionApi {
        params,
        ctors,
        ctor_types: BTreeMap::new(),
    }
}

#[test]
fn value_added_is_compatible() {
    let old = api(&[("f", "Int -> Int")], &[]);
    let new = api(&[("f", "Int -> Int"), ("g", "Int -> Int")], &[]);
    let changes = diff_api(&old, &new);
    assert_eq!(
        changes,
        vec![ApiChange::ValueAdded {
            module: "Lib".to_owned(),
            name: "g".to_owned(),
        }]
    );
    assert_eq!(magnitude(&changes), Compatibility::Compatible);
}

#[test]
fn value_removed_is_breaking() {
    let old = api(&[("f", "Int -> Int"), ("g", "Int -> Int")], &[]);
    let new = api(&[("f", "Int -> Int")], &[]);
    let changes = diff_api(&old, &new);
    assert_eq!(
        changes,
        vec![ApiChange::ValueRemoved {
            module: "Lib".to_owned(),
            name: "g".to_owned(),
        }]
    );
    assert_eq!(magnitude(&changes), Compatibility::Breaking);
}

#[test]
fn value_signature_change_is_breaking() {
    let old = api(&[("f", "Int -> Int")], &[]);
    let new = api(&[("f", "Int -> String")], &[]);
    let changes = diff_api(&old, &new);
    assert_eq!(
        changes,
        vec![ApiChange::ValueChanged {
            module: "Lib".to_owned(),
            name: "f".to_owned(),
            old: "Int -> Int".to_owned(),
            new: "Int -> String".to_owned(),
        }]
    );
    assert_eq!(magnitude(&changes), Compatibility::Breaking);
}

#[test]
fn module_added_is_compatible_and_removed_is_breaking() {
    let one = api(&[("f", "Int")], &[]);
    let mut two_modules = one.modules.clone();
    two_modules.insert(vec!["Extra".to_owned()], ModuleApi::default());
    let two = PublicApi {
        modules: two_modules,
    };

    let added = diff_api(&one, &two);
    assert_eq!(
        added,
        vec![ApiChange::ModuleAdded {
            module: "Extra".to_owned(),
        }]
    );
    assert_eq!(magnitude(&added), Compatibility::Compatible);

    let removed = diff_api(&two, &one);
    assert_eq!(
        removed,
        vec![ApiChange::ModuleRemoved {
            module: "Extra".to_owned(),
        }]
    );
    assert_eq!(magnitude(&removed), Compatibility::Breaking);
}

#[test]
fn union_added_is_compatible_removed_is_breaking() {
    let no_union = api(&[], &[]);
    let with_union = api(&[], &[("Shape", union(0, &[("Circle", &["Int"])]))]);

    let added = diff_api(&no_union, &with_union);
    assert_eq!(
        added,
        vec![ApiChange::UnionAdded {
            module: "Lib".to_owned(),
            name: "Shape".to_owned(),
        }]
    );
    assert_eq!(magnitude(&added), Compatibility::Compatible);

    let removed = diff_api(&with_union, &no_union);
    assert_eq!(
        removed,
        vec![ApiChange::UnionRemoved {
            module: "Lib".to_owned(),
            name: "Shape".to_owned(),
        }]
    );
    assert_eq!(magnitude(&removed), Compatibility::Breaking);
}

#[test]
fn union_arity_change_is_breaking() {
    // Arity changes while the (nullary) constructor's argument list stays equal,
    // isolating the arity change from any constructor-argument change.
    let mono = api(&[], &[("Empty", union(0, &[("Empty", &[])]))]);
    let poly = api(&[], &[("Empty", union(1, &[("Empty", &[])]))]);
    let changes = diff_api(&mono, &poly);
    assert_eq!(
        changes,
        vec![ApiChange::UnionArityChanged {
            module: "Lib".to_owned(),
            name: "Empty".to_owned(),
            old: 0,
            new: 1,
        }]
    );
    assert_eq!(magnitude(&changes), Compatibility::Breaking);
}

#[test]
fn constructor_added_is_breaking() {
    let old = api(&[], &[("Shape", union(0, &[("Circle", &["Int"])]))]);
    let new = api(
        &[],
        &[(
            "Shape",
            union(0, &[("Circle", &["Int"]), ("Square", &["Int"])]),
        )],
    );
    let changes = diff_api(&old, &new);
    assert_eq!(
        changes,
        vec![ApiChange::ConstructorAdded {
            module: "Lib".to_owned(),
            union: "Shape".to_owned(),
            ctor: "Square".to_owned(),
        }]
    );
    // A new constructor to an exposed union breaks exhaustive matches.
    assert_eq!(magnitude(&changes), Compatibility::Breaking);
}

#[test]
fn constructor_removed_and_arg_change_are_breaking() {
    let old = api(
        &[],
        &[(
            "Shape",
            union(0, &[("Circle", &["Int"]), ("Rect", &["Int", "Int"])]),
        )],
    );
    let removed_ctor = api(&[], &[("Shape", union(0, &[("Circle", &["Int"])]))]);
    let removed = diff_api(&old, &removed_ctor);
    assert_eq!(
        removed,
        vec![ApiChange::ConstructorRemoved {
            module: "Lib".to_owned(),
            union: "Shape".to_owned(),
            ctor: "Rect".to_owned(),
        }]
    );
    assert_eq!(magnitude(&removed), Compatibility::Breaking);

    let changed_arg = api(
        &[],
        &[(
            "Shape",
            union(0, &[("Circle", &["String"]), ("Rect", &["Int", "Int"])]),
        )],
    );
    let changed = diff_api(&old, &changed_arg);
    assert_eq!(
        changed,
        vec![ApiChange::ConstructorChanged {
            module: "Lib".to_owned(),
            union: "Shape".to_owned(),
            ctor: "Circle".to_owned(),
        }]
    );
    assert_eq!(magnitude(&changed), Compatibility::Breaking);
}

#[test]
fn identical_apis_have_no_changes_and_are_compatible() {
    let a = api(&[("f", "Int -> Int")], &[]);
    let b = api(&[("f", "Int -> Int")], &[]);
    let changes = diff_api(&a, &b);
    assert!(changes.is_empty());
    assert_eq!(magnitude(&changes), Compatibility::Compatible);
}

#[test]
fn required_bump_maps_pre_one_zero() {
    assert_eq!(
        required_bump(Compatibility::Compatible),
        RequiredBump::Patch
    );
    assert_eq!(required_bump(Compatibility::Breaking), RequiredBump::Minor);
}

#[test]
fn bump_floors_are_pre_one_zero() {
    let old = Predecessor::of(&Version::new(0, 3, 2));
    assert_eq!(
        bump_floor(&old, RequiredBump::Patch),
        Ok(Version::new(0, 3, 3)),
        "a patch floor is the next patch"
    );
    assert_eq!(
        bump_floor(&old, RequiredBump::Minor),
        Ok(Version::new(0, 4, 0)),
        "a minor floor resets patch"
    );
}

#[test]
fn predecessor_classifies_a_prerelease_by_its_core() {
    assert_eq!(
        Predecessor::of(&parse("0.0.1-rc.1")),
        Predecessor::PrereleaseOf(Version::new(0, 0, 1))
    );
    assert_eq!(
        Predecessor::of(&parse("0.0.1+build.7")),
        Predecessor::Release(Version::new(0, 0, 1)),
        "build metadata is not a prerelease"
    );
}

#[test]
fn a_prerelease_graduates_to_its_own_release() {
    let old_api = api(&[("f", "Int")], &[]);
    let rc = parse("0.0.1-rc.1");

    let graduated = report(&old_api, &old_api, &rc, &Version::new(0, 0, 1));
    assert_eq!(graduated.floor, Version::new(0, 0, 1));
    assert!(
        graduated.satisfied,
        "0.0.1-rc.1 -> 0.0.1 is the stable graduation"
    );

    let backwards = report(&old_api, &old_api, &rc, &Version::new(0, 0, 0));
    assert!(
        !backwards.satisfied,
        "a release below the prerelease's core is refused"
    );
}

#[test]
fn a_release_does_not_admit_itself_as_successor() {
    let old_api = api(&[("f", "Int")], &[]);
    let same = report(
        &old_api,
        &old_api,
        &Version::new(0, 0, 1),
        &Version::new(0, 0, 1),
    );
    assert_eq!(same.floor, Version::new(0, 0, 2));
    assert!(!same.satisfied, "0.0.1 -> 0.0.1 is refused");
}

#[test]
fn a_breaking_change_over_a_prerelease_still_requires_a_minor_bump() {
    let old_api = api(&[("f", "Int"), ("g", "Int")], &[]);
    let new_api = api(&[("f", "Int")], &[]);
    let rc = parse("1.0.0-rc.1");

    let graduated = report(&old_api, &new_api, &rc, &Version::new(1, 0, 0));
    assert_eq!(graduated.required, RequiredBump::Minor);
    assert_eq!(graduated.floor, Version::new(1, 1, 0));
    assert!(
        !graduated.satisfied,
        "graduating a prerelease does not clear a breaking delta"
    );

    let bumped = report(&old_api, &new_api, &rc, &Version::new(1, 1, 0));
    assert!(bumped.satisfied);
}

#[test]
fn a_floor_that_overflows_is_refused() {
    let top_patch = Predecessor::of(&Version::new(0, 0, u64::MAX));
    assert!(matches!(
        bump_floor(&top_patch, RequiredBump::Patch),
        Err(FloorOverflow {
            required: RequiredBump::Patch,
            ..
        })
    ));

    let top_minor = Predecessor::of(&Version::new(0, u64::MAX, 0));
    assert!(matches!(
        bump_floor(&top_minor, RequiredBump::Minor),
        Err(FloorOverflow {
            required: RequiredBump::Minor,
            ..
        })
    ));

    let old_api = api(&[("f", "Int")], &[]);
    assert!(
        ipe::diff::report(
            &old_api,
            &old_api,
            &Version::new(0, 0, u64::MAX),
            &Version::new(0, 1, 0),
        )
        .is_err(),
        "an overflowing floor refuses every successor"
    );
}

#[test]
fn report_rejects_underbump_and_accepts_sufficient_bump() {
    // A breaking change (removed value) from 0.3.2.
    let old_api = api(&[("f", "Int"), ("g", "Int")], &[]);
    let new_api = api(&[("f", "Int")], &[]);
    let old_v = Version::new(0, 3, 2);

    // A patch bump does NOT clear a breaking change's minor floor.
    let under = report(&old_api, &new_api, &old_v, &Version::new(0, 3, 3));
    assert_eq!(under.required, RequiredBump::Minor);
    assert_eq!(under.floor, Version::new(0, 4, 0));
    assert!(
        !under.satisfied,
        "a patch bump under-bumps a breaking change"
    );

    // A minor bump clears it.
    let ok = report(&old_api, &new_api, &old_v, &Version::new(0, 4, 0));
    assert!(ok.satisfied);

    // A larger-than-required bump also satisfies.
    let over = report(&old_api, &new_api, &old_v, &Version::new(0, 9, 0));
    assert!(over.satisfied);
}

#[test]
fn compatible_change_requires_only_a_patch() {
    let old_api = api(&[("f", "Int")], &[]);
    let new_api = api(&[("f", "Int"), ("g", "Int")], &[]);
    let old_v = Version::new(0, 3, 2);

    let stale = report(&old_api, &new_api, &old_v, &old_v);
    assert_eq!(stale.required, RequiredBump::Patch);
    assert!(
        !stale.satisfied,
        "the same version does not clear the floor"
    );

    let bumped = report(&old_api, &new_api, &old_v, &Version::new(0, 3, 3));
    assert!(bumped.satisfied);
}
