#![forbid(unsafe_code)]
//! Refuses every tracked mention of a verb form the CLI no longer accepts.
//!
//! The build, run, and watch verbs live under `dev`, and the shipping verbs
//! under `release`; the bare forms are refused at parse time. A doc, script,
//! template, or comment that still spells a bare form teaches a command that
//! fails, so this scan walks the tracked tree (`git ls-files`, minus the
//! trees that carry a reader-facing spelling) and fails on each line that
//! names the `ipe` binary followed by a bare `build`, `run`, `exec`, `watch`,
//! or `eject`, or by `release` and anything but one of its verbs.
//!
//! The scan reads only the trees it lists. A tracked tree it neither lists nor
//! sets aside is refused, so a new tree cannot slip past unscanned; the files
//! it sets aside are history or licensing text that no build or test reads.
//!
//! The binary is every spelling a command line opens with: `ipe`, `ipe.exe`,
//! a quoted one, and a shell variable naming it (`$IPE`, `"$ipe_bin"`,
//! `${IPEC_BIN}`), separated from the verb by any run of blanks. A backticked
//! `` `ipe` `` is also the binary's name in prose ("an `ipe` build"), so it
//! counts as a command only when an argument follows the verb.
//!
//! Exemptions name a file exactly, and a companion test fails once an exempt
//! file stops matching, so an exemption cannot outlive its reason. The
//! transcript goldens snapshot stdout only and a refusal prints to stderr, so
//! no refusal transcript spells a refused form and none is exempt.

use std::path::{Path, PathBuf};

use ipe::CliError;
use ipe::io_bounded::{SOURCE_READ_CAP, read_leaf_capped};

/// Files allowed to spell a refused form: this scan, whose fixtures must.
const EXEMPT: &[&str] = &["src/ipe-cli/tests/verb_prose_ratchet.rs"];

/// Top-level trees whose every tracked file is scanned.
const SCANNED_TREES: &[&str] = &[
    "src", "tests", "examples", "tools", ".github", "editors", "packages", ".config", ".cargo",
];

/// Subtrees of the documentation tree that are scanned.
const SCANNED_DOCS: &[&str] = &["guide", "reference", "idioms", "topics", "constructs"];

/// Subtrees of the documentation tree that are set aside: decision records,
/// images, and the divergence note.
const SET_ASIDE_DOCS: &[&str] = &["adr", "assets", "divergences-from-elm.md"];

/// The documentation tree.
const DOCS_TREE: &str = "docs";

/// Root files that are scanned; every other root file is configuration,
/// licensing text, or the generated changelog.
const SCANNED_ROOT_FILES: &[&str] = &["README.md", "AGENTS.md", "PRINCIPLES.md", "install.sh"];

/// What the scan does with one tracked path.
#[derive(Debug, PartialEq, Eq)]
enum Scope {
    Scanned,
    SetAside,
    Unclassified,
}

/// The scan's decision for the workspace-relative `rel`.
fn scope_of(rel: &str) -> Scope {
    let mut parts = rel.split('/');
    let (Some(top), second) = (parts.next(), parts.next()) else {
        return Scope::Unclassified;
    };
    match second {
        None => {
            if SCANNED_ROOT_FILES.contains(&top) {
                Scope::Scanned
            } else {
                Scope::SetAside
            }
        }
        Some(sub) if top == DOCS_TREE => {
            if SCANNED_DOCS.contains(&sub) {
                Scope::Scanned
            } else if SET_ASIDE_DOCS.contains(&sub) {
                Scope::SetAside
            } else {
                Scope::Unclassified
            }
        }
        Some(_) if SCANNED_TREES.contains(&top) => Scope::Scanned,
        Some(_) => Scope::Unclassified,
    }
}

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

/// One spelling of the `ipe` binary in a line.
struct Invocation {
    /// Byte offset just past the spelling.
    end: usize,
    /// Whether the spelling is a backticked `` `ipe` ``, a command only when
    /// an argument follows its verb.
    ticked: bool,
}

/// Every spelling of the `ipe` binary in `line`.
fn invocations(line: &str) -> Vec<Invocation> {
    line.char_indices()
        .filter_map(|(at, c)| match c {
            '$' => {
                variable_end(line, at + c.len_utf8()).map(|end| Invocation { end, ticked: false })
            }
            'i' => binary(line, at),
            _ => None,
        })
        .collect()
}

/// The end of a shell variable naming the binary whose name starts at `from`.
///
/// The name is braced or bare, and one of its `_`-separated parts opens with
/// `ipe` in any case (`IPE`, `ipe_bin`, `IPEC_BIN`); a closing quote is part
/// of the spelling.
fn variable_end(line: &str, from: usize) -> Option<usize> {
    let rest = line.get(from..)?;
    let (braced, body) = rest
        .strip_prefix('{')
        .map_or((false, rest), |body| (true, body));
    let len = body.find(|c: char| !is_word(c)).unwrap_or(body.len());
    let name = body.get(..len)?;
    let after = body.get(len..)?;
    let after = if braced {
        after.strip_prefix('}')?
    } else {
        after
    };
    let names_ipe = name.split('_').any(|part| {
        part.get(..3)
            .is_some_and(|head| head.eq_ignore_ascii_case("ipe"))
    });
    names_ipe.then(|| {
        let after = after.strip_prefix(['"', '\'', '`']).unwrap_or(after);
        line.len() - after.len()
    })
}

/// The `ipe` or `ipe.exe` word starting at `at`, with its closing quote.
fn binary(line: &str, at: usize) -> Option<Invocation> {
    let starts_word = line
        .get(..at)?
        .chars()
        .next_back()
        .is_none_or(|c| !is_word(c));
    let rest = line.get(at..)?.strip_prefix("ipe")?;
    if !starts_word {
        return None;
    }
    let rest = rest.strip_prefix(".exe").unwrap_or(rest);
    let (ticked, rest) = rest.strip_prefix('`').map_or_else(
        || (false, rest.strip_prefix(['"', '\'']).unwrap_or(rest)),
        |rest| (true, rest),
    );
    Some(Invocation {
        end: line.len() - rest.len(),
        ticked,
    })
}

/// `text` without its leading blanks, `None` when it has none.
fn after_blanks(text: &str) -> Option<&str> {
    let rest = text.trim_start_matches([' ', '\t']);
    (rest.len() < text.len()).then_some(rest)
}

/// Whether `line` names a refused verb form.
fn refused(line: &str) -> bool {
    invocations(line).iter().any(|inv| {
        let Some(rest) = line.get(inv.end..).and_then(after_blanks) else {
            return false;
        };
        (!inv.ticked || argued(rest)) && (bare_verb(rest) || foreign_release_word(rest))
    })
}

/// Whether the word opening `rest` is followed by an argument: the end of the
/// line, a flag, a path, a placeholder, a variable, or a quoted word.
fn argued(rest: &str) -> bool {
    let tail = rest.trim_start_matches(|c: char| c.is_ascii_alphabetic());
    let Some(next) = after_blanks(tail) else {
        return tail.is_empty();
    };
    let token = next.split_whitespace().next().unwrap_or_default();
    token.is_empty()
        || token.starts_with(['-', '.', '/', '<', '[', '$', '"', '\''])
        || token.contains('/')
        || Path::new(token)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("ipe"))
}

/// Whether `rest` opens with a whole bare verb.
fn bare_verb(rest: &str) -> bool {
    BARE_VERBS.iter().any(|verb| {
        rest.strip_prefix(verb)
            .is_some_and(|tail| tail.chars().next().is_none_or(|c| !is_word(c)))
    })
}

/// Whether `rest` is `release` and blanks followed by a word not its verb.
fn foreign_release_word(rest: &str) -> bool {
    let Some(tail) = rest.strip_prefix("release").and_then(after_blanks) else {
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
    let all: Vec<&str> = listed.split('\0').filter(|rel| !rel.is_empty()).collect();
    let unclassified: Vec<&str> = all
        .iter()
        .copied()
        .filter(|rel| scope_of(rel) == Scope::Unclassified)
        .collect();
    assert!(
        unclassified.is_empty(),
        "these tracked paths sit in a tree the verb scan neither scans nor sets \
         aside; classify the tree in `scope_of`'s tables: {unclassified:?}"
    );
    let paths: Vec<String> = all
        .into_iter()
        .filter(|rel| scope_of(rel) == Scope::Scanned)
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
    let read = read_leaf_capped(path, SOURCE_READ_CAP);
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
fn a_tree_outside_every_table_is_unclassified() {
    for rel in [
        "newtree/file.md",
        "docs/newdocs/page.md",
        "docs/page.md",
        ".hidden/x",
    ] {
        assert_eq!(scope_of(rel), Scope::Unclassified, "{rel}");
    }
}

#[test]
fn each_table_routes_its_paths() {
    assert_eq!(scope_of("src/ipe-cli/src/main.rs"), Scope::Scanned);
    assert_eq!(scope_of("docs/guide/file.md"), Scope::Scanned);
    assert_eq!(scope_of("README.md"), Scope::Scanned);
    assert_eq!(
        scope_of(&format!("{DOCS_TREE}/adr/0007-x.md")),
        Scope::SetAside
    );
    assert_eq!(
        scope_of(&format!("{DOCS_TREE}/assets/logo.svg")),
        Scope::SetAside
    );
    assert_eq!(scope_of("Cargo.toml"), Scope::SetAside);
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
        "ipe.exe build",
        "C:\\bin\\ipe.exe run app",
        "\"$ipe_bin\" run src/Main.ipe",
        "$IPE build",
        "${IPE_BIN} watch",
        "\"$IPEC_BIN\" build src/Main.ipe --out out/rust",
        "ipe  build",
        "ipe\trun",
        "\"ipe\" eject out/",
        "`ipe` build src/Main.ipe",
        "`ipe` run Main.ipe",
        "`ipe` build --target wasm",
        "`ipe` exec",
        "$IPE release  src/Main.ipe",
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
        "ipe.exe dev build",
        "\"$ipe_bin\" dev run src/Main.ipe",
        "$IPE release build",
        "${IPEC_BIN} release run dist/app",
        "ipe  dev  build",
        "ipe release  build",
        "$RECIPE build",
        "$PIPELINE run",
        "$CARGO build",
        "ipe.example run",
        "a missing entry fails at `ipe` build time",
        "One `ipe` run of the parity serializer",
        "the `ipe` build-tools compile once",
        "one `ipe` build: the producer",
    ] {
        assert!(!refused(line), "{line:?} must not be reported");
    }
}
