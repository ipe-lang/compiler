#![forbid(unsafe_code)]
//! Refuses a retired delivery word in every file the CLI renders or ships.
//!
//! `solo`, `spa` and `live` are refused by the delivery grammar, the retired
//! `Package.ipe` builders and constructors by the manifest reader, and the
//! wasm mode `Solo` by the `wasm` block reader. A help page, guide, template,
//! explain page or example that still spells one teaches a form that fails.
//!
//! The needles are derived, never listed: each [`RetiredRuntimeWord`] in its
//! delivery positions (`web <word>`, a code span `` `<word>` ``, and the bare
//! word when its replacement is `client`, since `live` is also English), every
//! retired builder and constructor derived from [`ShipEntry::BUILDERS`], and
//! [`WasmMode::RETIRED_RENDER`]. A match is case-sensitive and whole-word,
//! where a word also spans `-` and `/`, so a kebab package name or a path
//! segment is not a delivery word.
//!
//! The scan has no allowlist. History lives in `docs/adr/` and `CHANGELOG.md`,
//! which it does not read.

mod support;

use ipe::delivery::{RetiredRuntimeWord, Runtime};
use ipe::delivery_set::{ShipEntry, ship_constructor};
use ipe::project::WasmMode;
use std::path::{Path, PathBuf};

/// The deepest directory the example walk descends.
const MAX_EXAMPLE_DEPTH: usize = 8;

/// One needle and the form it is matched in.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Needle {
    /// A whole word.
    Word(String),
    /// A literal phrase, whole-word at both ends.
    Phrase(String),
}

impl Needle {
    /// The text this needle matches.
    fn text(&self) -> &str {
        match self {
            Self::Word(text) | Self::Phrase(text) => text,
        }
    }
}

/// Every retired word, builder, constructor and wasm mode the scan refuses.
fn needles() -> Vec<Needle> {
    let mut needles = Vec::new();
    for word in RetiredRuntimeWord::ALL {
        needles.push(Needle::Phrase(format!("web {}", word.text())));
        needles.push(Needle::Phrase(format!("`{}`", word.text())));
        if word.replacement() == Runtime::Client {
            needles.push(Needle::Word(word.text().to_owned()));
        }
    }
    for builder in retired_builders() {
        needles.push(Needle::Word(ship_constructor(&builder)));
        needles.push(Needle::Word(builder));
    }
    needles.push(Needle::Word(WasmMode::RETIRED_RENDER.to_owned()));
    needles.sort_by(|a, b| a.text().cmp(b.text()));
    needles.dedup();
    needles
}

/// Every retired builder: a retired word the client runtime replaces, then the
/// camel form of each client builder's host.
fn retired_builders() -> Vec<String> {
    let mut builders = Vec::new();
    for entry in ShipEntry::BUILDERS {
        let Some((Runtime::Client, host)) = entry.axes() else {
            continue;
        };
        for word in RetiredRuntimeWord::ALL {
            if word.replacement() == Runtime::Client {
                builders.push(format!(
                    "{}{}",
                    word.text(),
                    host.camel().unwrap_or_default()
                ));
            }
        }
    }
    builders
}

/// Whether `c` continues a word: a needle next to one is not a whole word.
const fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '/')
}

/// Whether `line` holds `needle` with no word character on either side.
fn line_hits(line: &str, needle: &Needle) -> bool {
    let text = needle.text();
    line.match_indices(text).any(|(at, _)| {
        let before = line.get(..at).and_then(|head| head.chars().next_back());
        let after = line
            .get(at.saturating_add(text.len())..)
            .and_then(|tail| tail.chars().next());
        !before.is_some_and(is_word_char) && !after.is_some_and(is_word_char)
    })
}

/// Each `(line number, needle)` hit in `source`.
fn hits(source: &str, needles: &[Needle]) -> Vec<(usize, String)> {
    source
        .lines()
        .enumerate()
        .flat_map(|(index, line)| {
            needles
                .iter()
                .filter(|needle| line_hits(line, needle))
                .map(move |needle| (index.saturating_add(1), needle.text().to_owned()))
        })
        .collect()
}

/// The markdown files directly under `dir`.
fn markdown_in(dir: &Path) -> Vec<PathBuf> {
    files_in(dir)
        .into_iter()
        .filter(|path| path.extension().is_some_and(|ext| ext == "md"))
        .collect()
}

/// The regular files directly under `dir`; a missing directory fails the test.
fn files_in(dir: &Path) -> Vec<PathBuf> {
    let entries = std::fs::read_dir(dir);
    assert!(entries.is_ok(), "read {}: {entries:?}", dir.display());
    let Ok(entries) = entries else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    files.sort();
    files
}

/// Every `package.ipe` under `dir`, to [`MAX_EXAMPLE_DEPTH`] levels.
fn package_manifests(dir: &Path, depth: usize, found: &mut Vec<PathBuf>) {
    assert!(
        depth <= MAX_EXAMPLE_DEPTH,
        "examples nest deeper than {MAX_EXAMPLE_DEPTH} levels at {}",
        dir.display()
    );
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            package_manifests(&path, depth.saturating_add(1), found);
        } else if path.file_name().is_some_and(|name| name == "package.ipe") {
            found.push(path);
        }
    }
}

/// Every file the scan reads.
fn scanned_files() -> Vec<PathBuf> {
    let root = support::repo_root();
    let cli = root.join("src").join("ipe-cli");
    let mut files = vec![
        cli.join("text").join("messages.md"),
        cli.join("templates").join("AGENTS.md.in"),
        root.join("src")
            .join("stdlib")
            .join("Ipe")
            .join("Package.ipe"),
        root.join("README.md"),
    ];
    files.extend(markdown_in(&cli.join("help")));
    files.extend(markdown_in(
        &root
            .join("src")
            .join("compiler")
            .join("diagnostics")
            .join("explain"),
    ));
    files.extend(markdown_in(&root.join("docs").join("guide")));
    files.extend(markdown_in(&root.join("docs").join("topics")));
    let mut manifests = Vec::new();
    package_manifests(&root.join("examples"), 0, &mut manifests);
    assert!(
        !manifests.is_empty(),
        "the example walk found no package.ipe"
    );
    files.extend(manifests);
    files
}

/// No rendered or shipped file spells a retired delivery word.
#[test]
fn retired_delivery_words_scan() {
    let needles = needles();
    let mut found = Vec::new();
    for path in scanned_files() {
        let source = std::fs::read_to_string(&path);
        assert!(source.is_ok(), "read {}: {source:?}", path.display());
        let Ok(source) = source else {
            continue;
        };
        for (line, needle) in hits(&source, &needles) {
            found.push(format!("{}:{line}: `{needle}`", path.display()));
        }
    }
    assert!(
        found.is_empty(),
        "retired delivery words are refused by the CLI; write `client` (or `web` \
         alone for served), the `client*` builders, and `mode = Render`:\n{}",
        found.join("\n")
    );
}

/// The derived needles agree with the refusals that own them.
///
/// Each retired builder and constructor is one the manifest reader refuses,
/// and every needle injected into a line is found.
#[test]
fn retired_delivery_words_scan_bites() {
    for builder in retired_builders() {
        assert!(
            ShipEntry::retired_builder(&builder).is_some(),
            "`{builder}` is a needle the manifest reader does not refuse"
        );
        let constructor = ship_constructor(&builder);
        assert!(
            ShipEntry::retired_builder(&constructor).is_some(),
            "`{constructor}` is a needle the manifest reader does not refuse"
        );
    }
    let needles = needles();
    for needle in &needles {
        let line = format!("deliver it as {} today.", needle.text());
        assert!(
            !hits(&line, &needles).is_empty(),
            "an injected `{}` must be found",
            needle.text()
        );
    }
    for clean in [
        "a live region announces the change",
        "see examples/wasm/spa for a client app",
        "{ name = \"wasm-spa\" }",
        "ipe dev build web client ios",
        "wasm = On { mode = Render }",
    ] {
        assert!(
            hits(clean, &needles).is_empty(),
            "`{clean}` holds no retired delivery word: {:?}",
            hits(clean, &needles)
        );
    }
}
