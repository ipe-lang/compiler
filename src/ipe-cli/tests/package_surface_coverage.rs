#![forbid(unsafe_code)]
//! The package surface coverage-matrix gate: the package surface enumerates
//! every declared dependency (Ipê packages and native Rust crates) from a
//! project's manifest, and the aspect columns judge each on
//! pinned-and-hashed, semver-satisfied, capability-declared, and
//! provenance-scanned.
//!
//! Tests run over the `fixtures/sp2_manifest` project — a manifest that has
//! index, git-escape, path-escape, and native deps in one file — so the full
//! column vocabulary exercises every [`Cell`] variant. Unit tests check
//! individual column verdicts with synthetic items; the integration test runs
//! the matrix runner over the fixture project.

use std::path::PathBuf;

use ipe::coverage::contract::{AspectCheck, Cell, Surface};
use ipe::coverage::matrix;
use ipe::coverage::package_surface::{
    CapabilityDeclaredColumn, DepKindLabel, PackageItem, PackageSurface, PinnedAndHashedColumn,
    ProvenanceScannedColumn, SemverSatisfiedColumn,
};
use ipe::project::{IpeDep, RustDep};

/// Path to the `sp2_manifest` fixture project, which has index/git/path/native
/// deps in one manifest and no `ipe.lock`.
fn fixture_root() -> PathBuf {
    e2e_support::manifest_dir!().join("tests/fixtures/sp2_manifest")
}

// ── surface enumeration ───────────────────────────────────────────────────────

#[test]
fn surface_enumerates_all_dep_kinds() {
    let surface = PackageSurface::new(fixture_root());
    let items = surface.all();

    // The fixture declares: http (index), local (path), mylib (git) as Ipe deps
    // and stripe, uuid as native Rust deps.
    let ipe_names: Vec<&str> = items
        .iter()
        .filter(|i| i.kind == DepKindLabel::Ipe)
        .map(|i| i.name.as_str())
        .collect();
    let native_names: Vec<&str> = items
        .iter()
        .filter(|i| i.kind == DepKindLabel::Native)
        .map(|i| i.name.as_str())
        .collect();

    assert!(
        ipe_names.contains(&"http"),
        "http index dep must appear on the package surface"
    );
    assert!(
        ipe_names.contains(&"local"),
        "local path dep must appear on the package surface"
    );
    assert!(
        ipe_names.contains(&"mylib"),
        "mylib git dep must appear on the package surface"
    );
    assert!(
        native_names.contains(&"stripe"),
        "stripe native dep must appear on the package surface"
    );
    assert!(
        native_names.contains(&"uuid"),
        "uuid native dep must appear on the package surface"
    );
}

#[test]
fn surface_is_deterministic_and_sorted() {
    let surface = PackageSurface::new(fixture_root());
    let first = surface.all();
    let second = surface.all();

    let names_first: Vec<&str> = first.iter().map(|i| i.name.as_str()).collect();
    let names_second: Vec<&str> = second.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(
        names_first, names_second,
        "two enumerations must be identical"
    );

    let mut sorted = names_first.clone();
    sorted.sort_unstable();
    assert_eq!(names_first, sorted, "items must be name-sorted");
}

// ── pinned-and-hashed column ──────────────────────────────────────────────────

#[test]
fn pinned_and_hashed_is_not_applicable_for_path_dep() {
    let col = PinnedAndHashedColumn::new(fixture_root());
    let path_item = PackageItem {
        name: "local".to_owned(),
        kind: DepKindLabel::Ipe,
        ipe_dep: Some(IpeDep::Path(PathBuf::from("../local"))),
        rust_dep: None,
    };
    assert!(
        matches!(col.check(&path_item), Cell::NotApplicable { .. }),
        "a path-escape dep has no lockfile pin — must be NotApplicable"
    );
}

#[test]
fn pinned_and_hashed_is_not_applicable_for_native_dep() {
    let col = PinnedAndHashedColumn::new(fixture_root());
    let native_item = PackageItem {
        name: "stripe".to_owned(),
        kind: DepKindLabel::Native,
        ipe_dep: None,
        rust_dep: Some(RustDep {
            version: "=1.0.0".to_owned(),
            features: vec!["blocking".to_owned()],
        }),
    };
    assert!(
        matches!(col.check(&native_item), Cell::NotApplicable { .. }),
        "a native Rust dep is pinned by cargo — must be NotApplicable"
    );
}

#[test]
fn pinned_and_hashed_holes_an_unlocked_index_dep() {
    // The fixture has no ipe.lock, so http is not pinned.
    let col = PinnedAndHashedColumn::new(fixture_root());
    let http_item = PackageItem {
        name: "http".to_owned(),
        kind: DepKindLabel::Ipe,
        ipe_dep: Some(IpeDep::Index("^1.2".parse().expect("valid version req"))),
        rust_dep: None,
    };
    assert!(
        matches!(col.check(&http_item), Cell::Hole(_)),
        "an index dep absent from ipe.lock must be a pinned-and-hashed hole"
    );
}

// ── semver-satisfied column ───────────────────────────────────────────────────

#[test]
fn semver_satisfied_is_not_applicable_for_path_dep() {
    let col = SemverSatisfiedColumn::new(fixture_root());
    let path_item = PackageItem {
        name: "local".to_owned(),
        kind: DepKindLabel::Ipe,
        ipe_dep: Some(IpeDep::Path(PathBuf::from("../local"))),
        rust_dep: None,
    };
    assert!(
        matches!(col.check(&path_item), Cell::NotApplicable { .. }),
        "a path-escape dep has no version req — must be NotApplicable"
    );
}

#[test]
fn semver_satisfied_is_not_applicable_for_git_dep() {
    let col = SemverSatisfiedColumn::new(fixture_root());
    let git_item = PackageItem {
        name: "mylib".to_owned(),
        kind: DepKindLabel::Ipe,
        ipe_dep: Some(IpeDep::Git {
            url: "https://example.com/mylib.git".to_owned(),
            rev: Some("abc123".to_owned()),
        }),
        rust_dep: None,
    };
    assert!(
        matches!(col.check(&git_item), Cell::NotApplicable { .. }),
        "a git-escape dep has a rev pin, not a version req — must be NotApplicable"
    );
}

#[test]
fn semver_satisfied_is_not_applicable_for_native_dep() {
    let col = SemverSatisfiedColumn::new(fixture_root());
    let native_item = PackageItem {
        name: "uuid".to_owned(),
        kind: DepKindLabel::Native,
        ipe_dep: None,
        rust_dep: Some(RustDep {
            version: "1.10".to_owned(),
            features: vec![],
        }),
    };
    assert!(
        matches!(col.check(&native_item), Cell::NotApplicable { .. }),
        "a native dep's version req goes to cargo — must be NotApplicable"
    );
}

// ── capability-declared column ────────────────────────────────────────────────

#[test]
fn capability_declared_is_not_applicable_for_ipe_dep() {
    let col = CapabilityDeclaredColumn::new(fixture_root());
    let ipe_item = PackageItem {
        name: "http".to_owned(),
        kind: DepKindLabel::Ipe,
        ipe_dep: Some(IpeDep::Index("^1.2".parse().expect("valid version req"))),
        rust_dep: None,
    };
    assert!(
        matches!(col.check(&ipe_item), Cell::NotApplicable { .. }),
        "capability is compiler-inferred for Ipê deps — must be NotApplicable"
    );
}

#[test]
fn capability_declared_is_ok_when_manifest_declares_capabilities() {
    // The fixture declares Network + Clock, so the column must pass for any native dep.
    let col = CapabilityDeclaredColumn::new(fixture_root());
    let native_item = PackageItem {
        name: "stripe".to_owned(),
        kind: DepKindLabel::Native,
        ipe_dep: None,
        rust_dep: Some(RustDep {
            version: "=1.0.0".to_owned(),
            features: vec![],
        }),
    };
    assert!(
        matches!(col.check(&native_item), Cell::Ok),
        "a native dep with capabilities declared must pass the capability-declared column"
    );
}

// ── provenance-scanned column ─────────────────────────────────────────────────

#[test]
fn provenance_scanned_is_not_applicable_for_path_dep() {
    let col = ProvenanceScannedColumn::new(fixture_root());
    let path_item = PackageItem {
        name: "local".to_owned(),
        kind: DepKindLabel::Ipe,
        ipe_dep: Some(IpeDep::Path(PathBuf::from("../local"))),
        rust_dep: None,
    };
    assert!(
        matches!(col.check(&path_item), Cell::NotApplicable { .. }),
        "a path-escape dep has no lockfile hash — must be NotApplicable"
    );
}

#[test]
fn provenance_scanned_is_not_applicable_for_native_dep() {
    let col = ProvenanceScannedColumn::new(fixture_root());
    let native_item = PackageItem {
        name: "uuid".to_owned(),
        kind: DepKindLabel::Native,
        ipe_dep: None,
        rust_dep: Some(RustDep {
            version: "1.10".to_owned(),
            features: vec![],
        }),
    };
    assert!(
        matches!(col.check(&native_item), Cell::NotApplicable { .. }),
        "a native dep's integrity is cargo's concern — must be NotApplicable"
    );
}

#[test]
fn provenance_scanned_is_not_applicable_when_dep_not_in_lockfile() {
    // The fixture has no ipe.lock, so any dep absent from the lockfile is N/A
    // here (pinned-and-hashed owns that gap).
    let col = ProvenanceScannedColumn::new(fixture_root());
    let http_item = PackageItem {
        name: "http".to_owned(),
        kind: DepKindLabel::Ipe,
        ipe_dep: Some(IpeDep::Index("^1.2".parse().expect("valid version req"))),
        rust_dep: None,
    };
    assert!(
        matches!(col.check(&http_item), Cell::NotApplicable { .. }),
        "a dep absent from the lockfile has no hash to assert — must be NotApplicable"
    );
}

// ── matrix runner ─────────────────────────────────────────────────────────────

/// Allowlisted holes: known gaps in the fixture project that are intentional
/// (the fixture has no `ipe.lock`, so index and git-escape deps are unpinned).
/// Each entry is `(aspect, dep-name, reason)`.
const ALLOWLIST: &[(&str, &str, &str)] = &[
    (
        "pinned-and-hashed",
        "http",
        "fixture has no ipe.lock — http is deliberately not pinned",
    ),
    (
        "pinned-and-hashed",
        "mylib",
        "fixture has no ipe.lock — mylib is deliberately not pinned",
    ),
];

#[test]
fn package_surface_matrix_passes_over_fixture_or_matches_allowlist() {
    use std::fmt::Write as _;

    let report = matrix::run_package(fixture_root());

    let mut unexpected = String::new();
    for h in report.holes.iter().filter(|h| {
        !ALLOWLIST
            .iter()
            .any(|(aspect, symbol, _)| *aspect == h.aspect && *symbol == h.symbol)
    }) {
        let _ = writeln!(
            unexpected,
            "  HOLE [{}] {}: {}",
            h.aspect, h.symbol, h.message
        );
    }

    assert!(
        unexpected.is_empty(),
        "the package coverage columns must pass over the fixture surface (or be \
         recorded in the allowlist with a tracking reason):\n{unexpected}\n\
         (allowlist has {} entr(y/ies))",
        ALLOWLIST.len(),
    );
}

#[test]
fn allowlisted_holes_are_still_real() {
    let report = matrix::run_package(fixture_root());
    for (aspect, symbol, reason) in ALLOWLIST {
        let present = report
            .holes
            .iter()
            .any(|h| h.aspect == *aspect && h.symbol == *symbol);
        assert!(
            present,
            "allowlisted hole [{aspect}] {symbol} ({reason}) is no longer \
             reported — remove the stale allowlist entry",
        );
    }
}

#[test]
fn package_surface_label_is_dep_name() {
    let item = PackageItem {
        name: "my-package".to_owned(),
        kind: DepKindLabel::Ipe,
        ipe_dep: None,
        rust_dep: None,
    };
    assert_eq!(PackageSurface::label(&item), "my-package");
}
