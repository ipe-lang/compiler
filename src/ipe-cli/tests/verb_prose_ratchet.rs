#![forbid(unsafe_code)]
//! Refuses every tracked mention of a verb form the CLI no longer accepts.
//!
//! The build, run, and watch verbs live under `dev`, and the shipping verbs
//! under `release`; the bare forms are refused at parse time. A doc, script,
//! template, or comment that still spells a bare form teaches a command that
//! fails, so this scan walks the tracked tree (`git ls-files`, minus the
//! history files `CHANGELOG.md` and `docs/adr/`) and fails on each line that
//! names `ipe` followed by a bare `build`, `run`, `exec`, `watch`, or `eject`,
//! or names `ipe release` followed by anything but one of its verbs.
//!
//! Exemptions name a file exactly, and a companion test fails once an exempt
//! file stops matching, so an exemption cannot outlive its reason.

use std::path::{Path, PathBuf};

use ipe::CliError;
use ipe::io_bounded::{SOURCE_READ_CAP, read_to_string_capped};

/// Files allowed to spell a refused form: this scan, whose fixtures must.
const EXEMPT: &[&str] = &["src/ipe-cli/tests/verb_prose_ratchet.rs"];

/// History files that record the forms as they were.
const HISTORY_FILE: &str = "CHANGELOG.md";

/// The directory of decision records, history by design.
const HISTORY_DIR: &str = "docs/adr/";

/// Verbs refused when they follow `ipe` directly.
const BARE_VERBS: &[&str] = &["build", "run", "exec", "watch", "eject"];

/// The words that may follow `ipe release`.
const RELEASE_MEMBERS: &[&str] = &["build", "run", "eject", "--help"];

/// Ceiling on the number of tracked files the scan reads.
const MAX_FILES: usize = 20_000;

/// Whether `c` is a regex word character.
fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Whether `line` names a refused verb form.
fn refused(line: &str) -> bool {
    line.match_indices("ipe ").any(|(at, _)| {
        let starts_word = line
            .get(..at)
            .and_then(|before| before.chars().next_back())
            .is_none_or(|c| !is_word(c));
        let Some(rest) = line.get(at + "ipe ".len()..) else {
            return false;
        };
        starts_word && (bare_verb(rest) || foreign_release_word(rest))
    })
}

/// Whether `rest` opens with a whole bare verb.
fn bare_verb(rest: &str) -> bool {
    BARE_VERBS.iter().any(|verb| {
        rest.strip_prefix(verb)
            .is_some_and(|tail| tail.chars().next().is_none_or(|c| !is_word(c)))
    })
}

/// Whether `rest` is `release ` followed by a word that is not its verb.
fn foreign_release_word(rest: &str) -> bool {
    let Some(tail) = rest.strip_prefix("release ") else {
        return false;
    };
    let end = tail
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .unwrap_or(tail.len());
    let word = tail.get(..end).unwrap_or_default();
    !RELEASE_MEMBERS.contains(&word)
}

/// The workspace root.
fn workspace() -> PathBuf {
    e2e_support::manifest_dir!().join("../..")
}

/// Every tracked workspace-relative path the scan covers.
fn tracked() -> Vec<String> {
    let listed = std::process::Command::new("git")
        .arg("-C")
        .arg(workspace())
        .args(["ls-files", "-z"])
        .output();
    assert!(
        matches!(&listed, Ok(out) if out.status.success()),
        "git ls-files must list the workspace checkout: {listed:?}"
    );
    let Ok(listed) = listed else {
        return Vec::new();
    };
    let listed = String::from_utf8(listed.stdout);
    assert!(
        listed.is_ok(),
        "git ls-files listed a non-UTF-8 path: {listed:?}"
    );
    let Ok(listed) = listed else {
        return Vec::new();
    };
    let paths: Vec<String> = listed
        .split('\0')
        .filter(|rel| !rel.is_empty() && *rel != HISTORY_FILE && !rel.starts_with(HISTORY_DIR))
        .map(str::to_owned)
        .collect();
    assert!(
        paths.len() <= MAX_FILES,
        "the tracked tree holds {} files, past the scan ceiling {MAX_FILES}",
        paths.len()
    );
    paths
}

/// The text of `path`, `None` for a file that is not UTF-8.
fn text_of(path: &Path) -> Option<String> {
    let read = read_to_string_capped(path, SOURCE_READ_CAP);
    let binary = matches!(
        &read,
        Err(CliError::Io { source, .. }) if source.kind() == std::io::ErrorKind::InvalidData
    );
    assert!(
        read.is_ok() || binary,
        "{} must be readable within the source cap: {read:?}",
        path.display()
    );
    read.ok()
}

/// The `file:line` of each refused form in `text`.
fn hits(rel: &str, text: &str) -> Vec<String> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| refused(line))
        .map(|(n, line)| format!("{rel}:{}: {}", n + 1, line.trim()))
        .collect()
}

#[test]
fn tracked_tree_names_no_refused_verb_form() {
    let root = workspace();
    let found: Vec<String> = tracked()
        .iter()
        .filter(|rel| !EXEMPT.contains(&rel.as_str()))
        .filter_map(|rel| text_of(&root.join(rel)).map(|text| hits(rel, &text)))
        .flatten()
        .collect();
    assert!(
        found.is_empty(),
        "these lines name a verb form the CLI refuses; spell the grouped form \
         (`ipe dev build`, `ipe release run`, ...):\n{}",
        found.join("\n")
    );
}

#[test]
fn every_exempt_file_still_matches() {
    let root = workspace();
    let tracked = tracked();
    for rel in EXEMPT {
        assert!(
            tracked.iter().any(|t| t == rel),
            "exempt file {rel} is not tracked"
        );
        let text = text_of(&root.join(rel));
        assert!(
            text.is_some_and(|text| !hits(rel, &text).is_empty()),
            "exempt file {rel} no longer names a refused form; drop its exemption"
        );
    }
}

#[test]
fn a_bare_verb_in_prose_is_reported() {
    assert_eq!(
        hits("fixture.md", "ok\nrun `ipe build` now"),
        vec!["fixture.md:2: run `ipe build` now".to_owned()]
    );
    for line in [
        "ipe run src/Main.ipe",
        "ipe exec dist/app",
        "ipe watch",
        "ipe eject out/",
        "`ipe release src/Main.ipe`",
        "ipe release --emit-permissions",
        "ipe release ",
    ] {
        assert!(refused(line), "{line:?} must be reported");
    }
}

#[test]
fn a_grouped_verb_is_not_reported() {
    for line in [
        "run `ipe dev build` now",
        "ipe dev run src/Main.ipe",
        "ipe release build src/Main.ipe",
        "ipe release run dist/app",
        "ipe release eject out/",
        "ipe release --help",
        "recipe builds",
        "pipe run",
        "ipe builder",
        "ipe release",
    ] {
        assert!(!refused(line), "{line:?} must not be reported");
    }
}
