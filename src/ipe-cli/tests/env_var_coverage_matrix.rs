#![forbid(unsafe_code)]
//! The env-var coverage-matrix gate: the env-var surface enumerates every `IPE_*`
//! variable the runtime reads (plus any orphan read), and the aspect columns
//! judge each on registered, read-in-code, documented, truthy-parse-consistent,
//! and prod-safety-gated.
//!
//! This is the env-var sibling of the stdlib coverage matrix: one enumeration,
//! one `surface × aspect` grid, a hole named at its coordinate. The registered
//! and read-in-code columns turn the registry-drift gate into standing cells; the
//! truthy-parse and prod-safety columns surface advisory debt without failing.

use std::collections::BTreeSet;

use ipe::coverage::contract::{Cell, Surface};
use ipe::coverage::env_surface::{EnvItem, EnvVarSurface, SourceReads};
use ipe::coverage::matrix;
use ipe_docs::env_vars::{Class, ENV_VARS, EXCLUDED_NAMES, EnvVar, Subsystem};

/// Allowlisted holes: a `(aspect, variable, reason)` coordinate that is a known,
/// tracked gap rather than fresh drift. Empty means every column is green over
/// the whole env-var surface.
const ALLOWLIST: &[(&str, &str, &str)] = &[];

#[test]
fn env_surface_is_non_empty() {
    let items = EnvVarSurface.all();
    assert!(
        !items.is_empty(),
        "the env-var surface must enumerate at least one variable",
    );
}

#[test]
fn env_surface_is_deterministic_and_sorted() {
    let first = EnvVarSurface.all();
    let second = EnvVarSurface.all();
    let names_first: Vec<String> = first.iter().map(|i| i.name().to_owned()).collect();
    let names_second: Vec<String> = second.iter().map(|i| i.name().to_owned()).collect();
    assert_eq!(
        names_first, names_second,
        "two enumerations must be byte-identical"
    );
    let mut sorted = names_first.clone();
    sorted.sort();
    assert_eq!(names_first, sorted, "the surface must be name-sorted");
}

#[test]
fn a_known_variable_is_registered_on_the_surface() {
    let items = EnvVarSurface.all();
    let known = items
        .iter()
        .find(|i| i.name() == "IPE_WEB_PORT")
        .expect("IPE_WEB_PORT must appear on the env-var surface");
    assert!(
        matches!(known, EnvItem::Registered(_)),
        "IPE_WEB_PORT must be a registered entry, not an orphan read",
    );
}

#[test]
fn env_columns_pass_over_the_whole_surface() {
    use std::fmt::Write as _;

    let report = matrix::run_env();

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
        "the env-var coverage columns must pass over the whole surface (or be \
         recorded in the allowlist with a tracking reason):\n{unexpected}\n\
         (allowlist has {} entr(y/ies))",
        ALLOWLIST.len(),
    );
}

#[test]
fn allowlisted_holes_are_still_real() {
    let report = matrix::run_env();
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
fn advisories_are_reported_not_failing() {
    // The truthy-parse and prod-safety columns emit advisories (Warn), which the
    // runner collects without failing the gate. This pins that a Warn never
    // becomes a hole and that at least the dev-only vars surface as advisories.
    let report = matrix::run_env();
    assert!(
        report.passed(),
        "advisories must not fail the gate: {}",
        report.render()
    );
    assert!(
        report
            .advisories
            .iter()
            .any(|a| a.aspect == "prod-safety-gated"),
        "at least one dev-only variable must surface a prod-safety advisory",
    );
}

#[test]
fn registered_column_flags_an_orphan_read() {
    // A synthetic orphan is a hole on the registered column and not-applicable on
    // the registry-only columns.
    use ipe::coverage::columns_env::RegisteredColumn;
    use ipe::coverage::contract::AspectCheck;
    // The name is spelled in two pieces so the source scans never read this
    // fixture as a variable the tree reads.
    let orphan = EnvItem::OrphanRead(concat!("IPE", "_DEFINITELY_NOT_REGISTERED_PROBE").to_owned());
    let col = RegisteredColumn;
    assert!(
        matches!(col.check(&orphan), Cell::Hole(_)),
        "an orphan read must be a hole on the registered column",
    );
}

// Probe names are spelled in two pieces so the source scans never read a fixture as
// a variable the tree reads.
const REAL_PORT: &str = concat!("IPE", "_REAL_PORT");
const OTHER_PORT: &str = concat!("IPE", "_OTHER_PORT");
const SUPERVISOR_PORT: &str = concat!("IPE", "_SUPERVISOR_PORT");

/// Every `IPE_*` variable name written in `text`.
fn ipe_names_in(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| {
            word.strip_prefix("IPE_").is_some_and(|suffix| {
                !suffix.is_empty()
                    && suffix
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            })
        })
}

/// The `IPE_*` names in registry text that have no home in the registry or the exclusion list.
fn unhomed_names_in_text(vars: &[EnvVar], excluded: &[&str]) -> BTreeSet<String> {
    let homed: BTreeSet<&str> = vars
        .iter()
        .map(|v| v.name)
        .chain(excluded.iter().copied())
        .collect();
    vars.iter()
        .flat_map(|v| [v.default, v.purpose])
        .flat_map(ipe_names_in)
        .filter(|name| !homed.contains(name))
        .map(str::to_owned)
        .collect()
}

/// The excluded names that no source file reads.
fn unread_exclusions<'a>(excluded: &[&'a str], reads: &BTreeSet<String>) -> Vec<&'a str> {
    excluded
        .iter()
        .copied()
        .filter(|name| !reads.contains(*name))
        .collect()
}

#[test]
fn registry_text_names_only_registered_or_excluded_variables() {
    let unhomed = unhomed_names_in_text(ENV_VARS, EXCLUDED_NAMES);
    assert!(
        unhomed.is_empty(),
        "registry text mentions `IPE_*` names that are neither registered nor excluded (a \
         deprecated alias or rename nothing reads is a promise the runtime never keeps; delete \
         the mention, or wire the read and register the name): {unhomed:?}",
    );
}

#[test]
fn every_excluded_name_is_read_in_the_source() {
    let reads = SourceReads::scan();
    let unread = unread_exclusions(EXCLUDED_NAMES, reads.all_reads());
    assert!(
        unread.is_empty(),
        "EXCLUDED_NAMES lists names no source file reads; an exclusion covers a read, so a \
         stale one only hides a name the registry no longer needs (remove them): {unread:?}",
    );
}

#[test]
fn a_documented_alias_with_no_registry_home_is_refused() {
    // The alias sits in backticked prose, the way the registry once wrote it.
    let phantom = EnvVar {
        name: REAL_PORT,
        default: "unset",
        purpose: "Listen port. Deprecated alias: `IPE_PHANTOM_PORT`.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    };
    let refused = unhomed_names_in_text(&[phantom], &[]);
    assert_eq!(
        refused.into_iter().collect::<Vec<_>>(),
        vec![concat!("IPE", "_PHANTOM_PORT").to_owned()],
        "an alias named only in prose must be refused, and the entry's own name must not",
    );
}

#[test]
fn a_prose_mention_of_a_registered_or_excluded_name_is_accepted() {
    let first = EnvVar {
        name: REAL_PORT,
        default: "unset",
        purpose: "Outranked by `IPE_SUPERVISOR_PORT`; see also `IPE_OTHER_PORT`.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    };
    let second = EnvVar {
        name: OTHER_PORT,
        default: "unset",
        purpose: "The glob `IPE_*` and a lowercase `IPE_word` are not names.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    };
    assert!(
        unhomed_names_in_text(&[first, second], &[SUPERVISOR_PORT]).is_empty(),
        "registered and excluded names are homed; `IPE_*` and `IPE_word` are not names",
    );
}

#[test]
fn an_excluded_name_no_source_reads_is_refused() {
    let read = concat!("IPE", "_READ_PROBE");
    let unread = concat!("IPE", "_UNREAD_PROBE");
    let reads: BTreeSet<String> = BTreeSet::from([read.to_owned()]);
    assert_eq!(
        unread_exclusions(&[read, unread], &reads),
        vec![unread],
        "only the exclusion no source reads is refused",
    );
    assert_eq!(
        unread_exclusions(&[unread], &BTreeSet::new()),
        vec![unread],
        "an empty scan refuses every exclusion, never passes them",
    );
}
