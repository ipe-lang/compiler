#![forbid(unsafe_code)]
//! The CLI coverage-matrix gate: the CLI surface enumerates every `ipe`
//! subcommand and each of its flags (the SSOT is the `help::COMMANDS` table),
//! and the aspect columns judge each on documented, tested, and
//! not-advertised-unimplemented.
//!
//! This is the CLI sibling of the stdlib and env-var coverage matrices: one
//! enumeration, one `surface × aspect` grid, a hole named at its coordinate.
//! Adding a subcommand or flag to `help::COMMANDS` automatically brings it
//! under this gate.

use ipe::coverage::cli_surface::{CliItem, CliSurface};
use ipe::coverage::contract::Surface;
use ipe::coverage::matrix;

/// Allowlisted holes: a `(aspect, label, reason)` coordinate that is a known,
/// tracked gap rather than fresh drift.
///
/// Empty means every column is green over the whole CLI surface. Add an entry
/// here (with a tracking reason) only for a gap that is intentionally deferred,
/// never to suppress a real untracked regression.
const ALLOWLIST: &[(&str, &str, &str)] = &[
    // ── tested gaps ──────────────────────────────────────────────────────────
    // These subcommands have no standing integration test invoking them yet.
    (
        "tested",
        "release eject",
        "no integration test for ipe-release-eject path yet",
    ),
];

#[test]
fn cli_surface_is_non_empty() {
    let items = CliSurface.all();
    assert!(
        !items.is_empty(),
        "the CLI surface must enumerate at least one item",
    );
}

#[test]
fn cli_surface_contains_known_subcommands() {
    let items = CliSurface.all();
    let labels: Vec<String> = items.iter().map(CliSurface::label).collect();

    // These are stable subcommands — their absence means the SSOT drifted.
    for expected in [
        "dev build",
        "dev run",
        "dev watch",
        "release build",
        "release run",
        "fmt",
        "init",
        "version",
    ] {
        assert!(
            labels.contains(&expected.to_owned()),
            "CLI surface must include subcommand `{expected}`",
        );
    }
}

#[test]
fn cli_surface_is_deterministic() {
    let first: Vec<String> = CliSurface.all().iter().map(CliSurface::label).collect();
    let second: Vec<String> = CliSurface.all().iter().map(CliSurface::label).collect();
    assert_eq!(
        first, second,
        "two enumerations of the CLI surface must be identical",
    );
}

#[test]
fn subcommand_and_flag_items_are_distinct_kinds() {
    let items = CliSurface.all();
    let has_subcommand = items
        .iter()
        .any(|i| matches!(i, CliItem::Subcommand { .. }));
    let has_flag = items.iter().any(|i| matches!(i, CliItem::Flag { .. }));
    assert!(
        has_subcommand,
        "CLI surface must contain at least one subcommand item"
    );
    assert!(has_flag, "CLI surface must contain at least one flag item");
}

#[test]
fn cli_columns_pass_over_the_whole_surface() {
    use std::fmt::Write as _;

    let report = matrix::run_cli_surface();

    let mut unexpected = String::new();
    for h in report.holes.iter().filter(|h| {
        !ALLOWLIST
            .iter()
            .any(|(aspect, label, _)| *aspect == h.aspect && *label == h.symbol)
    }) {
        let _ = writeln!(
            unexpected,
            "  HOLE [{}] {}: {}",
            h.aspect, h.symbol, h.message
        );
    }

    assert!(
        unexpected.is_empty(),
        "the CLI coverage columns must pass over the whole surface (or be recorded \
         in the allowlist with a tracking reason):\n{unexpected}\n\
         (allowlist has {} entr(y/ies))",
        ALLOWLIST.len(),
    );
}

#[test]
fn allowlisted_holes_are_still_real() {
    let report = matrix::run_cli_surface();
    for (aspect, label, reason) in ALLOWLIST {
        let present = report
            .holes
            .iter()
            .any(|h| h.aspect == *aspect && h.symbol == *label);
        assert!(
            present,
            "allowlisted hole [{aspect}] {label} ({reason}) is no longer \
             reported — remove the stale allowlist entry",
        );
    }
}

#[test]
fn not_advertised_unimplemented_column_passes_today() {
    // Every current command must have a real implementation — no `todo!()`
    // or `unimplemented!()` in any handler. This pins that the anti-advertise
    // gate is green and alerts immediately if a stub slips in.
    let report = matrix::run_cli_surface();
    let stubs: Vec<&ipe::coverage::matrix::Hole> = report
        .holes
        .iter()
        .filter(|h| h.aspect == "not-advertised-unimplemented")
        .collect();
    assert!(
        stubs.is_empty(),
        "every `ipe` command must have a real implementation:\n{}",
        stubs
            .iter()
            .map(|h| format!("  {}: {}", h.symbol, h.message))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}
