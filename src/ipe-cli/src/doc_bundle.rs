//! Unified documentation bundle: entry index, kind-qualified resolver,
//! and `[[kind:key]]` cross-reference rewriter.
//!
//! Every documentation entity is a [`DocEntry`] in one of eight per-kind maps
//! inside a [`DocBundle`]. The bundle is built once per `ipe doc` invocation.
//!
//! Cross-references in Markdown bodies use `[[kind:key]]` or
//! `[[kind:key|display text]]` syntax. [`rewrite_refs`] resolves every
//! reference against the bundle and rewrites it in the target format.
//! A reference to an unknown kind or a missing key is a build error -- the
//! bundle never emits a dangling or passthrough link.
//!
//! Ranking entries against a free-text `ipe doc` term is
//! [`crate::doc_search`]'s job; this module only holds and resolves them.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use include_dir::{Dir, include_dir};
use ipe_docs::{html, markdown_text};

use crate::cli_args::json;

// == Embedded doc-corpus ======================================================

/// Language construct pages, embedded at compile time from `docs/constructs/`.
///
/// This is the single source of truth for construct pages in both `ipe doc
/// <key>` (CLI lookup) and `ipe doc serve` / `ipe doc --write-format html`
/// (the HTML site). Adding a `docs/constructs/<name>.md` file automatically
/// makes it available everywhere — no hand-maintained table needed.
pub(crate) static EMBEDDED_CONSTRUCTS: Dir<'static> =
    include_dir!("$CARGO_MANIFEST_DIR/../../docs/constructs");

/// Idiom pages, embedded at compile time from `docs/idioms/`.
pub(crate) static EMBEDDED_IDIOMS: Dir<'static> =
    include_dir!("$CARGO_MANIFEST_DIR/../../docs/idioms");

/// Topic pages, embedded at compile time from `docs/topics/`.
pub(crate) static EMBEDDED_TOPICS: Dir<'static> =
    include_dir!("$CARGO_MANIFEST_DIR/../../docs/topics");

/// Guide pages, embedded at compile time from `docs/guide/`.
pub(crate) static EMBEDDED_GUIDES: Dir<'static> =
    include_dir!("$CARGO_MANIFEST_DIR/../../docs/guide");

// == DocKind ==================================================================

/// The eight documentation kinds. Each kind has its own lookup namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DocKind {
    /// A stdlib module (e.g. `Ipe.List`).
    Module,
    /// An exposed symbol from a stdlib module (e.g. `Ipe.List.map`).
    Symbol,
    /// A compiler diagnostic code (e.g. `IPE-L0107`).
    Diagnostic,
    /// A language construct page (from `docs/constructs/` or `docs/content/`).
    Construct,
    /// An idiom page (from `docs/idioms/`).
    Idiom,
    /// A topic page (from `docs/topics/`).
    Topic,
    /// A guide page (from `docs/guide/`).
    Guide,
    /// A CLI subcommand (e.g. `build`).
    Cli,
}

impl DocKind {
    /// The lowercase prefix used in `kind:key` qualified references.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Module => "module",
            Self::Symbol => "symbol",
            Self::Diagnostic => "diagnostic",
            Self::Construct => "construct",
            Self::Idiom => "idiom",
            Self::Topic => "topic",
            Self::Guide => "guide",
            Self::Cli => "cli",
        }
    }

    /// Parse a lowercase prefix string into a [`DocKind`], or `None` for an
    /// unrecognised prefix.
    #[must_use]
    pub fn from_prefix(s: &str) -> Option<Self> {
        match s {
            "module" => Some(Self::Module),
            "symbol" => Some(Self::Symbol),
            "diagnostic" => Some(Self::Diagnostic),
            "construct" => Some(Self::Construct),
            "idiom" => Some(Self::Idiom),
            "topic" => Some(Self::Topic),
            "guide" => Some(Self::Guide),
            "cli" => Some(Self::Cli),
            _ => None,
        }
    }
}

impl fmt::Display for DocKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.prefix())
    }
}

// == DocEntry =================================================================

/// One documentation entry in the unified bundle index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocEntry {
    /// Which documentation kind this entry belongs to.
    pub kind: DocKind,
    /// The canonical lookup key within its kind (unique per kind).
    pub key: String,
    /// The human-readable title -- the first `# ` heading, a humanised slug,
    /// or an overridden `title:` from YAML front-matter.
    pub title: String,
    /// The raw Markdown body (front-matter already stripped when present).
    pub body: String,
    /// Optional sort position from front-matter `order:` -- lower values sort
    /// first. Absent means the entry sorts after all explicitly ordered entries,
    /// then alphabetically by title.
    pub order: Option<i64>,
}

// == DocBundle ================================================================

/// The unified in-memory index for one `ipe doc` invocation.
///
/// Eight per-kind maps, each keyed by the canonical key string. Built once
/// via [`DocBundle::build`]; queried via [`DocBundle::resolve_qualified`] and
/// ranked by [`crate::doc_search::rank`].
pub struct DocBundle {
    maps: BTreeMap<DocKind, BTreeMap<String, DocEntry>>,
    /// Extra spellings that open an entry, per kind: alias -> canonical key.
    /// An alias is never listed; only the canonical key is an entry.
    aliases: BTreeMap<DocKind, BTreeMap<String, String>>,
}

impl DocBundle {
    /// Build the bundle from all sources.
    ///
    /// Modules, symbols, diagnostics, and CLI commands come from the
    /// compile-time index already populated by the caller. Constructs,
    /// idioms, topics, and guide pages are always ingested from the compile-time
    /// embedded corpus (`docs/{constructs,idioms,topics,guide}/`), so `ipe doc
    /// serve` and `ipe doc --write-format html` render those sections correctly
    /// regardless of the working directory.
    ///
    /// When `docs_root` exists on disk (the typical in-repo case), entries from
    /// the on-disk tree that do not already appear in the embedded corpus are
    /// merged in as an additive overlay. This lets a developer preview a new page
    /// before committing it without modifying the binary. The embedded corpus is
    /// always present; the on-disk overlay is optional.
    ///
    /// # Errors
    ///
    /// Returns a [`BundleError`] for any hard error: a duplicate `(kind, key)`,
    /// a malformed front-matter block, or a slug outside `[a-z0-9-]`.
    pub fn build(
        docs_root: &Path,
        modules: &[BundleSource],
        symbols: &[BundleSource],
        diagnostics: &[BundleSource],
        cli_commands: &[BundleSource],
    ) -> Result<Self, BundleError> {
        let mut maps: BTreeMap<DocKind, BTreeMap<String, DocEntry>> = BTreeMap::new();
        let mut aliases: BTreeMap<DocKind, BTreeMap<String, String>> = BTreeMap::new();

        for src in modules {
            insert_entry(
                &mut maps,
                DocKind::Module,
                src.key.clone(),
                src.title.clone(),
                src.body.clone(),
                None,
            )?;
        }
        for src in symbols {
            insert_entry(
                &mut maps,
                DocKind::Symbol,
                src.key.clone(),
                src.title.clone(),
                src.body.clone(),
                None,
            )?;
        }
        for src in symbols {
            for alias in &src.aliases {
                insert_alias(&maps, &mut aliases, DocKind::Symbol, alias, &src.key)?;
            }
        }
        for src in diagnostics {
            insert_entry(
                &mut maps,
                DocKind::Diagnostic,
                src.key.clone(),
                src.title.clone(),
                src.body.clone(),
                None,
            )?;
        }
        for src in cli_commands {
            insert_entry(
                &mut maps,
                DocKind::Cli,
                src.key.clone(),
                src.title.clone(),
                src.body.clone(),
                None,
            )?;
        }

        // Always ingest from the compile-time embedded corpus first.  This
        // guarantees non-empty curated sections no matter the working directory.
        ingest_embedded_dir(&EMBEDDED_CONSTRUCTS, DocKind::Construct, &mut maps)?;
        ingest_embedded_dir(&EMBEDDED_IDIOMS, DocKind::Idiom, &mut maps)?;
        ingest_embedded_dir(&EMBEDDED_TOPICS, DocKind::Topic, &mut maps)?;
        ingest_embedded_dir(&EMBEDDED_GUIDES, DocKind::Guide, &mut maps)?;

        // Additive on-disk overlay: merge any file whose key is not already
        // present (the embedded corpus wins on conflict).  Absent or
        // unreadable directories are silently skipped.
        if docs_root.is_dir() {
            // Prefer `docs/constructs/`; fall back to `docs/content/`.
            let construct_dir = docs_root.join("constructs");
            let construct_root = if construct_dir.is_dir() {
                construct_dir
            } else {
                docs_root.join("content")
            };
            ingest_markdown_dir_additive(&construct_root, DocKind::Construct, &mut maps)?;
            ingest_markdown_dir_additive(&docs_root.join("idioms"), DocKind::Idiom, &mut maps)?;
            ingest_markdown_dir_additive(&docs_root.join("topics"), DocKind::Topic, &mut maps)?;
            ingest_markdown_dir_additive(&docs_root.join("guide"), DocKind::Guide, &mut maps)?;
        }

        Ok(Self { maps, aliases })
    }

    /// Build an empty bundle (for tests).
    #[cfg(test)]
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            maps: BTreeMap::new(),
            aliases: BTreeMap::new(),
        }
    }

    /// Resolve a `kind:key` qualified reference.
    ///
    /// Returns `Ok(&DocEntry)` on a hit, [`BundleError::UnknownKind`] for an
    /// unrecognised prefix, and [`BundleError::UnknownKey`] for a known kind
    /// with no entry under `key`.
    ///
    /// # Errors
    ///
    /// [`BundleError::UnknownKind`] or [`BundleError::UnknownKey`].
    pub fn resolve_qualified(&self, qualified: &str) -> Result<&DocEntry, BundleError> {
        let (kind_str, key) = split_qualified(qualified)
            .ok_or_else(|| BundleError::UnknownKind(qualified.to_owned()))?;
        let kind = DocKind::from_prefix(kind_str)
            .ok_or_else(|| BundleError::UnknownKind(kind_str.to_owned()))?;
        self.entry(kind, key)
            .ok_or_else(|| BundleError::UnknownKey {
                kind,
                key: key.to_owned(),
            })
    }

    /// The entry of `kind` that `key` opens: its own key, or an alias of it.
    fn entry(&self, kind: DocKind, key: &str) -> Option<&DocEntry> {
        let canonical = self
            .aliases
            .get(&kind)
            .and_then(|m| m.get(key))
            .map_or(key, String::as_str);
        self.maps.get(&kind).and_then(|m| m.get(canonical))
    }

    /// All entries across all kinds, in kind + key order.
    pub fn all_entries(&self) -> impl Iterator<Item = &DocEntry> {
        self.maps.values().flat_map(|m| m.values())
    }

    /// All entries for a specific kind.
    pub fn entries_for_kind(&self, kind: DocKind) -> impl Iterator<Item = &DocEntry> {
        self.maps.get(&kind).into_iter().flat_map(|m| m.values())
    }

    /// Every alias across all kinds with the entry it opens, in kind + alias
    /// order.
    pub fn all_aliases(&self) -> impl Iterator<Item = (&str, &DocEntry)> {
        self.aliases
            .keys()
            .flat_map(move |&kind| self.aliases_for_kind(kind))
    }

    /// Every alias of `kind` with the entry it opens, in alias order.
    pub fn aliases_for_kind(&self, kind: DocKind) -> impl Iterator<Item = (&str, &DocEntry)> {
        let entries = self.maps.get(&kind);
        self.aliases
            .get(&kind)
            .into_iter()
            .flat_map(|m| m.iter())
            .filter_map(move |(alias, canonical)| {
                entries
                    .and_then(|e| e.get(canonical))
                    .map(|entry| (alias.as_str(), entry))
            })
    }

    /// Insert a single entry from a pre-computed source.
    ///
    /// # Errors
    ///
    /// [`BundleError::DuplicateKey`] when a `(kind, key)` pair already exists.
    pub fn insert(
        &mut self,
        kind: DocKind,
        key: String,
        title: String,
        body: String,
    ) -> Result<(), BundleError> {
        insert_entry(&mut self.maps, kind, key, title, body, None)
    }
}

// == BundleSource =============================================================

/// A pre-built entry to seed the bundle from a non-filesystem source (modules,
/// symbols, diagnostics, CLI commands).
pub struct BundleSource {
    /// Canonical lookup key.
    pub key: String,
    /// Human-readable title.
    pub title: String,
    /// Raw Markdown body.
    pub body: String,
    /// Other spellings that open this entry; never listed as entries.
    pub aliases: Vec<String>,
}

impl BundleSource {
    /// Construct a source with key and title; no prose body.
    pub fn titled(key: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            title: title.into(),
            body: String::new(),
            aliases: Vec::new(),
        }
    }

    /// Construct a source with key, title, and body.
    pub fn with_body(
        key: impl Into<String>,
        title: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            title: title.into(),
            body: body.into(),
            aliases: Vec::new(),
        }
    }

    /// The same source, also opened by each of `aliases`.
    #[must_use]
    pub fn with_aliases(mut self, aliases: Vec<String>) -> Self {
        self.aliases = aliases;
        self
    }
}

// == BundleError ==============================================================

/// A typed error produced during bundle build or reference resolution.
#[derive(Debug, PartialEq, Eq)]
pub enum BundleError {
    /// A `kind:` prefix is not one of the eight known kinds.
    UnknownKind(String),
    /// A known kind has no entry for `key`.
    UnknownKey { kind: DocKind, key: String },
    /// Two entries share the same `(kind, key)`.
    DuplicateKey {
        kind: DocKind,
        key: String,
        source: String,
    },
    /// A filename slug contains characters outside `[a-z0-9-]`.
    InvalidSlug { slug: String, source: String },
    /// A YAML front-matter block is structurally malformed.
    MalformedFrontMatter { source: String, detail: String },
    /// A cross-reference `[[kind:key]]` in a body names an unknown ref.
    UnknownRef {
        reference: String,
        source_file: String,
    },
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKind(prefix) => write!(
                f,
                "unknown doc kind `{prefix}` \
                 (want: module, symbol, diagnostic, construct, idiom, topic, guide, cli)"
            ),
            Self::UnknownKey { kind, key } => {
                write!(f, "no `{kind}` entry for key `{key}`")
            }
            Self::DuplicateKey { kind, key, source } => {
                write!(f, "duplicate doc entry ({kind}:{key}) in `{source}`")
            }
            Self::InvalidSlug { slug, source } => write!(
                f,
                "filename slug `{slug}` in `{source}` contains characters outside [a-z0-9-]"
            ),
            Self::MalformedFrontMatter { source, detail } => {
                write!(f, "malformed front-matter in `{source}`: {detail}")
            }
            Self::UnknownRef {
                reference,
                source_file,
            } => write!(
                f,
                "unresolved cross-reference `[[{reference}]]` in `{source_file}`"
            ),
        }
    }
}

// == Ingestion ================================================================

/// Ingest all `.md` files from a compile-time embedded [`Dir`] as `kind` entries.
///
/// Non-slug filenames (e.g. `README.md`) are silently skipped. A malformed
/// front-matter block, an invalid slug in front-matter, or a duplicate key is a
/// hard error. Every `include_dir` file whose content is valid UTF-8 is
/// guaranteed present at compile time, so a read failure here is a bug — it is
/// treated as a malformed-front-matter error with a descriptive detail string.
pub(crate) fn ingest_embedded_dir(
    dir: &Dir<'_>,
    kind: DocKind,
    maps: &mut BTreeMap<DocKind, BTreeMap<String, DocEntry>>,
) -> Result<(), BundleError> {
    // Collect and sort by filename for deterministic ordering.
    let mut files: Vec<&include_dir::File<'_>> = dir
        .files()
        .filter(|f| {
            f.path()
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("md"))
        })
        .collect();
    files.sort_by_key(|f| f.path());

    for file in files {
        let file_name = file
            .path()
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let slug = file_name.strip_suffix(".md").unwrap_or(file_name);
        let source_label = file.path().display().to_string();

        if !is_valid_slug(slug) {
            // Skip housekeeping files (e.g. `README.md`).
            continue;
        }

        let raw = file
            .contents_utf8()
            .ok_or_else(|| BundleError::MalformedFrontMatter {
                source: source_label.clone(),
                detail: "embedded file is not valid UTF-8".to_owned(),
            })?;

        let ParsedMarkdown {
            key,
            title,
            body,
            order,
        } = parse_markdown_file(slug, raw, &source_label)?;
        insert_entry(maps, kind, key, title, body, order)?;
    }
    Ok(())
}

/// Scan `dir` for `.md` files whose key is not already in `maps` and insert
/// each as a `kind` entry (additive, non-overwriting overlay over the embedded
/// corpus).
///
/// An absent or non-directory `dir` yields zero entries (never an error). A
/// malformed slug, bad front-matter, or a key that is already present in the
/// embedded corpus are silently skipped (the embedded version wins).
fn ingest_markdown_dir_additive(
    dir: &Path,
    kind: DocKind,
    maps: &mut BTreeMap<DocKind, BTreeMap<String, DocEntry>>,
) -> Result<(), BundleError> {
    if !dir.is_dir() {
        return Ok(());
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    let mut paths: Vec<std::path::PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("md"))
        })
        .collect();
    paths.sort();

    for path in paths {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let slug = file_name.strip_suffix(".md").unwrap_or(file_name);
        let source_label = path.display().to_string();

        if !is_valid_slug(slug) {
            continue;
        }

        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };

        let Ok(ParsedMarkdown {
            key,
            title,
            body,
            order,
        }) = parse_markdown_file(slug, &raw, &source_label)
        else {
            continue;
        };

        // Embedded corpus wins: skip if the key is already present.
        if maps.get(&kind).is_some_and(|m| m.contains_key(&key)) {
            continue;
        }

        insert_entry(maps, kind, key, title, body, order)?;
    }
    Ok(())
}

/// Scan `dir` for `.md` files and insert each as a `kind` entry.
///
/// An absent or non-directory `dir` yields zero entries (never an error).
/// A malformed slug, duplicate key, or bad front-matter is a hard error.
///
/// Used directly in tests to exercise the parsing/validation semantics in
/// isolation. Production ingestion routes through [`ingest_embedded_dir`]
/// (always) and [`ingest_markdown_dir_additive`] (on-disk overlay).
#[cfg(test)]
fn ingest_markdown_dir(
    dir: &Path,
    kind: DocKind,
    maps: &mut BTreeMap<DocKind, BTreeMap<String, DocEntry>>,
) -> Result<(), BundleError> {
    if !dir.is_dir() {
        return Ok(());
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    let mut paths: Vec<std::path::PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("md"))
        })
        .collect();
    paths.sort();

    for path in paths {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let slug = file_name.strip_suffix(".md").unwrap_or(file_name);
        let source_label = path.display().to_string();

        if !is_valid_slug(slug) {
            // Skip housekeeping files (README.md, etc.) that are not bundle entries.
            continue;
        }

        let raw =
            std::fs::read_to_string(&path).map_err(|_| BundleError::MalformedFrontMatter {
                source: source_label.clone(),
                detail: "could not read file".to_owned(),
            })?;

        let ParsedMarkdown {
            key,
            title,
            body,
            order,
        } = parse_markdown_file(slug, &raw, &source_label)?;
        insert_entry(maps, kind, key, title, body, order)?;
    }
    Ok(())
}

/// Parse one markdown file's optional YAML front-matter and extract key, title,
/// and body.
///
/// Front-matter is `---\n...\n---\n` at the very start of the file. Only
/// `key:` and `title:` fields are read; other fields are ignored. When
/// front-matter is absent: key = slug, title = first `# ` heading (fallback:
/// humanised slug), body = full file text.
fn parse_markdown_file(
    slug: &str,
    raw: &str,
    source_label: &str,
) -> Result<ParsedMarkdown, BundleError> {
    let (front_matter_str, body_start) = if raw.starts_with("---\n") || raw.starts_with("---\r\n") {
        let after_open = raw.find('\n').map_or(raw.len(), |i| i + 1);
        raw[after_open..].find("\n---\n").map_or((None, 0), |rel| {
            let fm_end = after_open + rel;
            // Skip the full closing `\n---\n` (5 bytes) to land on the content.
            let close_len = "\n---\n".len();
            (Some(&raw[after_open..fm_end]), after_open + rel + close_len)
        })
    } else {
        (None, 0)
    };

    let body = raw[body_start..].to_owned();

    let mut fm_key: Option<String> = None;
    let mut fm_title: Option<String> = None;
    let mut fm_order: Option<i64> = None;
    if let Some(fm) = front_matter_str {
        for line in fm.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Some(colon_pos) = line.find(':') else {
                return Err(BundleError::MalformedFrontMatter {
                    source: source_label.to_owned(),
                    detail: format!("line `{line}` has no colon separator"),
                });
            };
            let field = line[..colon_pos].trim();
            let value = line[colon_pos + 1..].trim().to_owned();
            match field {
                "key" => fm_key = Some(value),
                "title" => fm_title = Some(value),
                "order" => {
                    fm_order = value.parse::<i64>().ok();
                }
                _ => {}
            }
        }
    }

    let key = match fm_key {
        Some(k) if !k.is_empty() => {
            if !is_valid_slug(&k) {
                return Err(BundleError::InvalidSlug {
                    slug: k,
                    source: source_label.to_owned(),
                });
            }
            k
        }
        _ => slug.to_owned(),
    };

    let title = fm_title
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| extract_h1_title(&body).unwrap_or_else(|| humanise_slug(&key)));

    Ok(ParsedMarkdown {
        key,
        title,
        body,
        order: fm_order,
    })
}

struct ParsedMarkdown {
    key: String,
    title: String,
    body: String,
    order: Option<i64>,
}

/// Return the text of the first `# ` heading in `body`, or `None` when absent.
fn extract_h1_title(body: &str) -> Option<String> {
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("# ") {
            let title = rest.trim();
            if !title.is_empty() {
                return Some(title.to_owned());
            }
        }
    }
    None
}

/// Convert a slug like `getting-started` to a human-readable title.
fn humanise_slug(slug: &str) -> String {
    let mut out = String::new();
    for (i, word) in slug.split('-').enumerate() {
        if word.is_empty() {
            continue;
        }
        if i == 0 {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                out.extend(first.to_uppercase());
                out.push_str(chars.as_str());
            }
        } else {
            out.push(' ');
            out.push_str(word);
        }
    }
    out
}

/// Return `true` when `slug` consists only of `[a-z0-9-]` and is non-empty.
fn is_valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Insert an entry into the per-kind map, returning a hard error on a duplicate.
fn insert_entry(
    maps: &mut BTreeMap<DocKind, BTreeMap<String, DocEntry>>,
    kind: DocKind,
    key: String,
    title: String,
    body: String,
    order: Option<i64>,
) -> Result<(), BundleError> {
    let map = maps.entry(kind).or_default();
    if map.contains_key(&key) {
        return Err(BundleError::DuplicateKey {
            kind,
            key,
            source: String::from("<in-memory>"),
        });
    }
    map.insert(
        key.clone(),
        DocEntry {
            kind,
            key,
            title,
            body,
            order,
        },
    );
    Ok(())
}

/// Record `alias` as another spelling of the `canonical` entry of `kind`.
///
/// Refuses an alias that names no entry, shadows an entry's own key, or is
/// already another entry's alias: one spelling opens exactly one entry.
fn insert_alias(
    maps: &BTreeMap<DocKind, BTreeMap<String, DocEntry>>,
    aliases: &mut BTreeMap<DocKind, BTreeMap<String, String>>,
    kind: DocKind,
    alias: &str,
    canonical: &str,
) -> Result<(), BundleError> {
    let entries = maps.get(&kind);
    let duplicate = || BundleError::DuplicateKey {
        kind,
        key: alias.to_owned(),
        source: String::from("<alias>"),
    };
    if !entries.is_some_and(|m| m.contains_key(canonical)) {
        return Err(BundleError::UnknownKey {
            kind,
            key: canonical.to_owned(),
        });
    }
    if entries.is_some_and(|m| m.contains_key(alias)) {
        return Err(duplicate());
    }
    let map = aliases.entry(kind).or_default();
    if map.contains_key(alias) {
        return Err(duplicate());
    }
    map.insert(alias.to_owned(), canonical.to_owned());
    Ok(())
}

// == Qualified key parsing ====================================================

/// Split `"kind:rest"` into `("kind", "rest")`, or `None` when no `:` is present.
#[must_use]
pub fn split_qualified(s: &str) -> Option<(&str, &str)> {
    s.find(':').map(|pos| (&s[..pos], &s[pos + 1..]))
}

/// Return `true` when `s` looks like a qualified `kind:key` reference.
#[must_use]
pub fn is_qualified(s: &str) -> bool {
    split_qualified(s)
        .and_then(|(prefix, _)| DocKind::from_prefix(prefix))
        .is_some()
}

// == Cross-reference rewriting ================================================

/// The output format for `[[kind:key]]` rewriting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefTarget {
    /// `<a href="{kind}/{key}.html">disp</a>`
    Html,
    /// `[disp]({kind}/{key}.md)`
    Markdown,
    /// A structured JSON object embedded in the body string.
    Json,
    /// `<a href="/{kind}/{key}">disp</a>` (serve route).
    Serve,
    /// `disp (ipe doc {kind}:{key})` (terminal plain text).
    Terminal,
}

/// Scan `body` for `[[kind:key]]` and `[[kind:key|display]]` cross-references,
/// resolve each against `bundle`, and rewrite in `target` format.
///
/// `source_file` appears in error messages only.
///
/// # Errors
///
/// [`BundleError::UnknownRef`] when any reference cannot be resolved. Never
/// emits a dangling or passthrough link.
pub fn rewrite_refs(
    body: &str,
    bundle: &DocBundle,
    target: RefTarget,
    source_file: &str,
) -> Result<String, BundleError> {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;

    loop {
        match rest.find("[[") {
            None => {
                out.push_str(rest);
                break;
            }
            Some(open_pos) => {
                out.push_str(&rest[..open_pos]);
                rest = &rest[open_pos + 2..];

                let Some(close_pos) = rest.find("]]") else {
                    // No closing `]]`: treat `[[` as literal text.
                    out.push_str("[[");
                    continue;
                };

                let inner = &rest[..close_pos];
                rest = &rest[close_pos + 2..];

                let (qualified, display_override) = inner.find('|').map_or((inner, None), |pipe| {
                    (&inner[..pipe], Some(inner[pipe + 1..].trim()))
                });

                let (kind_str, key) =
                    split_qualified(qualified).ok_or_else(|| BundleError::UnknownRef {
                        reference: inner.to_owned(),
                        source_file: source_file.to_owned(),
                    })?;
                let kind =
                    DocKind::from_prefix(kind_str).ok_or_else(|| BundleError::UnknownRef {
                        reference: inner.to_owned(),
                        source_file: source_file.to_owned(),
                    })?;

                let entry = bundle
                    .entry(kind, key)
                    .ok_or_else(|| BundleError::UnknownRef {
                        reference: inner.to_owned(),
                        source_file: source_file.to_owned(),
                    })?;

                let display = display_override
                    .filter(|d| !d.is_empty())
                    .unwrap_or(entry.title.as_str());

                out.push_str(&format_ref(kind, &entry.key, display, target));
            }
        }
    }

    Ok(out)
}

/// Produce the format-aware rewriting of one resolved cross-reference.
///
/// Every markup target escapes `key` and `display` for its own grammar: HTML
/// through [`html::escape`] (attribute and text alike), Markdown through
/// [`markdown_text::link_text`] and [`markdown_text::link_destination`], JSON
/// through [`json::string`].
fn format_ref(kind: DocKind, key: &str, display: &str, target: RefTarget) -> String {
    match target {
        RefTarget::Html => format!(
            "<a href=\"{}/{}.html\">{}</a>",
            kind.prefix(),
            html::escape(key),
            html::escape(display)
        ),
        RefTarget::Markdown => format!(
            "[{}]({})",
            markdown_text::link_text(display),
            markdown_text::link_destination(&format!("{}/{}.md", kind.prefix(), key))
        ),
        RefTarget::Json => format!(
            "{{\"ref\":{{\"kind\":{},\"key\":{}}},\"text\":{}}}",
            json::string(kind.prefix()),
            json::string(key),
            json::string(display)
        ),
        RefTarget::Serve => format!(
            "<a href=\"/{}/{}\">{}</a>",
            kind.prefix(),
            html::escape(key),
            html::escape(display)
        ),
        RefTarget::Terminal => format!("{display} (ipe doc {}:{})", kind.prefix(), key),
    }
}

// == Tests ====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir = ipe_test_temp::temp_root()
            .join(format!("ipe-doc-bundle-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // -- Ingestion ------------------------------------------------------------

    #[test]
    fn ingest_topic_without_front_matter() {
        let tmp = tempdir("ingest_no_fm");
        fs::write(tmp.join("foo.md"), "# Foo topic\n\nSome prose.\n").unwrap();
        let mut maps = BTreeMap::new();
        ingest_markdown_dir(&tmp, DocKind::Topic, &mut maps).expect("ingest");
        let map = maps.get(&DocKind::Topic).expect("topic map");
        let entry = map.get("foo").expect("foo entry");
        assert_eq!(entry.key, "foo");
        assert_eq!(entry.title, "Foo topic");
        assert!(entry.body.contains("Some prose."));
    }

    #[test]
    fn ingest_topic_with_front_matter_key_and_title() {
        let tmp = tempdir("ingest_fm");
        fs::write(
            tmp.join("bar.md"),
            "---\nkey: overridden\ntitle: Overridden Title\n---\n# Bar\n\nBody text.\n",
        )
        .unwrap();
        let mut maps = BTreeMap::new();
        ingest_markdown_dir(&tmp, DocKind::Topic, &mut maps).expect("ingest");
        let map = maps.get(&DocKind::Topic).expect("topic map");
        assert!(map.contains_key("overridden"), "key overridden: {map:?}");
        assert_eq!(map["overridden"].title, "Overridden Title");
    }

    #[test]
    fn ingest_absent_dir_yields_zero_entries() {
        let tmp = tempdir("ingest_absent");
        let nonexistent = tmp.join("doesnotexist");
        let mut maps = BTreeMap::new();
        ingest_markdown_dir(&nonexistent, DocKind::Topic, &mut maps).expect("absent dir is ok");
        assert!(maps.is_empty(), "no entries from absent dir");
    }

    #[test]
    fn ingest_empty_dir_yields_zero_entries() {
        let tmp = tempdir("ingest_empty");
        let mut maps = BTreeMap::new();
        ingest_markdown_dir(&tmp, DocKind::Topic, &mut maps).expect("empty dir is ok");
        assert!(maps.is_empty(), "no entries from empty dir");
    }

    #[test]
    fn ingest_duplicate_key_is_error() {
        let tmp = tempdir("ingest_dup");
        fs::write(tmp.join("alpha.md"), "# Alpha\n").unwrap();
        fs::write(
            tmp.join("beta.md"),
            "---\nkey: alpha\ntitle: Beta as alpha\n---\n# Beta\n",
        )
        .unwrap();
        let mut maps = BTreeMap::new();
        let err = ingest_markdown_dir(&tmp, DocKind::Topic, &mut maps)
            .expect_err("duplicate key must error");
        assert!(
            matches!(err, BundleError::DuplicateKey { .. }),
            "expected DuplicateKey: {err}"
        );
    }

    // -- Aliases --------------------------------------------------------------

    fn symbol_bundle(symbols: &[BundleSource]) -> Result<DocBundle, BundleError> {
        DocBundle::build(Path::new("/nonexistent"), &[], symbols, &[], &[])
    }

    #[test]
    fn an_alias_opens_its_canonical_entry_and_is_never_listed() {
        let bundle = symbol_bundle(
            &[BundleSource::with_body("Ipe.Time.now", "Ipe.Time.now", "")
                .with_aliases(vec!["Time.now".to_owned()])],
        )
        .expect("a well-formed alias builds");
        let opened = bundle.resolve_qualified("symbol:Time.now");
        assert!(
            matches!(opened, Ok(e) if e.key == "Ipe.Time.now"),
            "the alias opens the canonical entry: {opened:?}"
        );
        let keys: Vec<&str> = bundle
            .entries_for_kind(DocKind::Symbol)
            .map(|e| e.key.as_str())
            .collect();
        assert_eq!(keys, ["Ipe.Time.now"], "one entry, under its canonical key");
    }

    #[test]
    fn an_alias_that_shadows_an_entry_key_is_refused() {
        let built = symbol_bundle(&[
            BundleSource::with_body("Ipe.A.x", "Ipe.A.x", "")
                .with_aliases(vec!["Ipe.B.x".to_owned()]),
            BundleSource::with_body("Ipe.B.x", "Ipe.B.x", ""),
        ]);
        assert!(
            matches!(built, Err(BundleError::DuplicateKey { ref key, .. }) if key == "Ipe.B.x"),
            "an alias never hides another entry: {:?}",
            built.err()
        );
    }

    #[test]
    fn a_cross_ref_through_an_alias_links_the_canonical_page() {
        let bundle = symbol_bundle(
            &[BundleSource::with_body("Ipe.Time.now", "Ipe.Time.now", "")
                .with_aliases(vec!["Time.now".to_owned()])],
        )
        .expect("a well-formed alias builds");
        let via_alias = rewrite_refs("[[symbol:Time.now]]", &bundle, RefTarget::Markdown, "a.md");
        let via_key = rewrite_refs(
            "[[symbol:Ipe.Time.now]]",
            &bundle,
            RefTarget::Markdown,
            "a.md",
        );
        assert!(
            via_alias.is_ok(),
            "an alias reference resolves: {via_alias:?}"
        );
        assert_eq!(via_alias, via_key, "both spellings link the one page");
    }

    #[test]
    fn one_alias_for_two_entries_is_refused() {
        let built = symbol_bundle(&[
            BundleSource::with_body("Ipe.A.x", "Ipe.A.x", "").with_aliases(vec!["x".to_owned()]),
            BundleSource::with_body("Ipe.B.x", "Ipe.B.x", "").with_aliases(vec!["x".to_owned()]),
        ]);
        assert!(
            matches!(built, Err(BundleError::DuplicateKey { ref key, .. }) if key == "x"),
            "one spelling opens exactly one entry: {:?}",
            built.err()
        );
    }

    // -- Resolution -----------------------------------------------------------

    #[test]
    fn resolve_qualified_hit() {
        let mut bundle = DocBundle::empty();
        bundle
            .insert(
                DocKind::Topic,
                "foo".to_owned(),
                "Foo".to_owned(),
                String::new(),
            )
            .unwrap();
        let entry = bundle.resolve_qualified("topic:foo").expect("hit");
        assert_eq!(entry.key, "foo");
    }

    #[test]
    fn resolve_qualified_unknown_key_is_error() {
        let bundle = DocBundle::empty();
        let err = bundle
            .resolve_qualified("topic:nope")
            .expect_err("unknown key");
        assert!(
            matches!(
                err,
                BundleError::UnknownKey {
                    kind: DocKind::Topic,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn resolve_qualified_unknown_kind_is_error() {
        let bundle = DocBundle::empty();
        let err = bundle
            .resolve_qualified("bogus:x")
            .expect_err("unknown kind");
        assert!(matches!(err, BundleError::UnknownKind(_)), "{err}");
    }

    #[test]
    fn resolve_qualified_unqualified_is_unknown_kind() {
        let bundle = DocBundle::empty();
        let err = bundle.resolve_qualified("nocolon").expect_err("no colon");
        assert!(matches!(err, BundleError::UnknownKind(_)), "{err}");
    }

    // -- Ref rewriting --------------------------------------------------------

    fn bundle_with_module_entry() -> DocBundle {
        let mut b = DocBundle::empty();
        b.insert(
            DocKind::Module,
            "Ipe.Db.Store".to_owned(),
            "the store".to_owned(),
            String::new(),
        )
        .unwrap();
        b
    }

    #[test]
    fn rewrite_html_uses_href_with_kind_prefix() {
        let bundle = bundle_with_module_entry();
        let out = rewrite_refs(
            "See [[module:Ipe.Db.Store|the store]].",
            &bundle,
            RefTarget::Html,
            "test",
        )
        .expect("rewrite");
        assert_eq!(
            out,
            "See <a href=\"module/Ipe.Db.Store.html\">the store</a>."
        );
    }

    #[test]
    fn rewrite_markdown_uses_md_link() {
        let bundle = bundle_with_module_entry();
        let out = rewrite_refs(
            "See [[module:Ipe.Db.Store|the store]].",
            &bundle,
            RefTarget::Markdown,
            "test",
        )
        .expect("rewrite");
        assert_eq!(out, "See [the store](<module/Ipe.Db.Store.md>).");
    }

    #[test]
    fn rewrite_json_emits_structured_object() {
        let bundle = bundle_with_module_entry();
        let out = rewrite_refs(
            "[[module:Ipe.Db.Store|the store]]",
            &bundle,
            RefTarget::Json,
            "test",
        )
        .expect("rewrite");
        assert_eq!(
            out,
            "{\"ref\":{\"kind\":\"module\",\"key\":\"Ipe.Db.Store\"},\"text\":\"the store\"}"
        );
    }

    #[test]
    fn rewrite_serve_uses_route_href() {
        let bundle = bundle_with_module_entry();
        let out = rewrite_refs(
            "[[module:Ipe.Db.Store|the store]]",
            &bundle,
            RefTarget::Serve,
            "test",
        )
        .expect("rewrite");
        assert_eq!(out, "<a href=\"/module/Ipe.Db.Store\">the store</a>");
    }

    #[test]
    fn rewrite_terminal_uses_ipe_doc_hint() {
        let bundle = bundle_with_module_entry();
        let out = rewrite_refs(
            "[[module:Ipe.Db.Store|the store]]",
            &bundle,
            RefTarget::Terminal,
            "test",
        )
        .expect("rewrite");
        assert_eq!(out, "the store (ipe doc module:Ipe.Db.Store)");
    }

    #[test]
    fn rewrite_default_display_uses_entry_title() {
        let bundle = bundle_with_module_entry();
        let out = rewrite_refs(
            "[[module:Ipe.Db.Store]]",
            &bundle,
            RefTarget::Terminal,
            "test",
        )
        .expect("rewrite");
        assert_eq!(out, "the store (ipe doc module:Ipe.Db.Store)");
    }

    #[test]
    fn rewrite_unknown_ref_is_build_error() {
        let bundle = DocBundle::empty();
        let err = rewrite_refs(
            "[[topic:does-not-exist]]",
            &bundle,
            RefTarget::Html,
            "myfile.md",
        )
        .expect_err("error");
        assert!(
            matches!(err, BundleError::UnknownRef { .. }),
            "expected UnknownRef: {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains("topic:does-not-exist"), "{msg}");
        assert!(msg.contains("myfile.md"), "{msg}");
    }

    // -- No-panic witness -----------------------------------------------------

    #[test]
    fn non_slug_filename_is_skipped_not_an_error() {
        // Files whose stem is not a valid slug (e.g. README.md, CHANGELOG.md)
        // are housekeeping files, not bundle entries; they are skipped silently.
        let tmp = tempdir("ingest_non_slug");
        fs::write(tmp.join("README.md"), "# README\n").unwrap();
        fs::write(tmp.join("valid-entry.md"), "# Valid\n").unwrap();
        let mut maps = BTreeMap::new();
        let result = ingest_markdown_dir(&tmp, DocKind::Topic, &mut maps);
        assert!(
            result.is_ok(),
            "non-slug filename must be skipped, not an error"
        );
        assert!(
            maps.get(&DocKind::Topic)
                .is_some_and(|m| m.contains_key("valid-entry")),
            "valid entry is still ingested"
        );
        assert!(
            !maps
                .get(&DocKind::Topic)
                .is_some_and(|m| m.contains_key("README")),
            "README is not ingested"
        );
    }

    #[test]
    fn invalid_fm_key_returns_typed_error() {
        // A file with a valid slug filename but an explicit bad `key:` in
        // front-matter must still return an error.
        let tmp = tempdir("ingest_bad_fm_key");
        fs::write(
            tmp.join("valid.md"),
            "---\nkey: Bad Key!\ntitle: t\n---\nbody\n",
        )
        .unwrap();
        let mut maps = BTreeMap::new();
        let result = ingest_markdown_dir(&tmp, DocKind::Topic, &mut maps);
        assert!(result.is_err(), "invalid fm key must return Err");
        assert!(
            matches!(result, Err(BundleError::InvalidSlug { .. })),
            "expected InvalidSlug"
        );
    }

    #[test]
    fn missing_key_returns_typed_error() {
        let bundle = DocBundle::empty();
        let result = bundle.resolve_qualified("topic:missing");
        assert!(result.is_err(), "missing key must return Err");
        assert!(
            matches!(result, Err(BundleError::UnknownKey { .. })),
            "expected UnknownKey"
        );
    }

    // -- Embedded-corpus regression tests ------------------------------------

    /// The bug: with a nonexistent `docs_root` the four directory-convention kinds
    /// previously yielded zero entries.  The fix embeds the corpus at compile
    /// time, so all four kinds are non-empty regardless of the working directory.
    #[test]
    fn embedded_corpus_populates_curated_kinds_when_docs_root_is_absent() {
        // Pass a docs_root that provably does not exist so the on-disk overlay
        // path is completely bypassed.
        let absent_root = std::path::Path::new("/nonexistent-ipe-doc-test-root-$$");
        let bundle = DocBundle::build(absent_root, &[], &[], &[], &[])
            .expect("bundle with absent docs_root must not error");

        for kind in [
            DocKind::Construct,
            DocKind::Idiom,
            DocKind::Topic,
            DocKind::Guide,
        ] {
            let count = bundle.entries_for_kind(kind).count();
            assert!(
                count > 0,
                "{kind} must have entries from the embedded corpus even with absent docs_root \
                 (got 0 — this is the regression this test pins)"
            );
        }
    }

    /// Each embedded corpus file count must match what the directory contains.
    /// This pins the expectation so adding a file without updating the embed
    /// path produces a clear failure at test time rather than a silent runtime gap.
    #[test]
    fn embedded_corpus_file_counts_match_embedded_dirs() {
        // Count valid-slug `.md` entries in each embedded Dir.
        fn slug_count(dir: &include_dir::Dir<'_>) -> usize {
            dir.files()
                .filter(|f| {
                    let stem = f.path().file_stem().and_then(|s| s.to_str()).unwrap_or("");
                    let is_md = f
                        .path()
                        .extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| e.eq_ignore_ascii_case("md"));
                    is_md && is_valid_slug(stem)
                })
                .count()
        }

        let absent_root = std::path::Path::new("/nonexistent-ipe-doc-test-root-counts");
        let bundle = DocBundle::build(absent_root, &[], &[], &[], &[])
            .expect("bundle builds from embedded corpus");

        for (kind, dir) in [
            (DocKind::Construct, &EMBEDDED_CONSTRUCTS),
            (DocKind::Idiom, &EMBEDDED_IDIOMS),
            (DocKind::Topic, &EMBEDDED_TOPICS),
            (DocKind::Guide, &EMBEDDED_GUIDES),
        ] {
            let expected = slug_count(dir);
            let actual = bundle.entries_for_kind(kind).count();
            assert_eq!(
                actual, expected,
                "{kind}: bundle has {actual} entries but embedded dir has {expected} slug files"
            );
        }
    }

    /// A specific well-known key from each kind must resolve and have a non-empty body.
    #[test]
    fn embedded_corpus_known_keys_resolve_with_non_empty_body() {
        let absent_root = std::path::Path::new("/nonexistent-ipe-doc-test-root-keys");
        let bundle = DocBundle::build(absent_root, &[], &[], &[], &[])
            .expect("bundle builds from embedded corpus");

        let cases = [
            (DocKind::Construct, "case"),
            (DocKind::Idiom, "pipe"),
            (DocKind::Topic, "effects"),
            (DocKind::Guide, "basics"),
        ];
        for (kind, key) in cases {
            let qualified = format!("{kind}:{key}");
            assert!(
                bundle.resolve_qualified(&qualified).is_ok(),
                "expected {qualified} to resolve"
            );
            let entry = bundle
                .resolve_qualified(&qualified)
                .expect("resolution checked directly above");
            assert!(
                !entry.body.is_empty(),
                "{qualified} resolved but body is empty"
            );
        }
    }

    /// `ingest_embedded_dir` directly: the embedded constructs dir must produce
    /// at least as many entries as the hand-maintained table it replaced.
    #[test]
    fn ingest_embedded_constructs_yields_at_least_former_hand_table_count() {
        // The old CONSTRUCT_PAGES table had 14 entries.
        const FORMER_COUNT: usize = 14;
        let mut maps = BTreeMap::new();
        ingest_embedded_dir(&EMBEDDED_CONSTRUCTS, DocKind::Construct, &mut maps)
            .expect("ingest_embedded_dir must not error on well-formed embedded corpus");
        let count = maps.get(&DocKind::Construct).map_or(0, BTreeMap::len);
        assert!(
            count >= FORMER_COUNT,
            "embedded constructs corpus has {count} entries but expected >= {FORMER_COUNT} \
             (the former hand-maintained table count)"
        );
    }

    // -- Ref escaping ---------------------------------------------------------

    /// A key and display holding markup are escaped in both HTML targets: the
    /// key cannot close the `href` attribute, the display cannot open a tag.
    #[test]
    fn html_ref_escapes_key_in_href_and_display_in_text() {
        let html_out = format_ref(DocKind::Module, "a\"b", "x<y", RefTarget::Html);
        assert_eq!(html_out, "<a href=\"module/a&quot;b.html\">x&lt;y</a>");
        let serve_out = format_ref(DocKind::Module, "a\"b", "x<y", RefTarget::Serve);
        assert_eq!(serve_out, "<a href=\"/module/a&quot;b\">x&lt;y</a>");
    }

    /// A display or key holding control characters still yields valid JSON
    /// that decodes back to the original strings.
    #[test]
    fn json_ref_with_control_chars_parses_and_round_trips() {
        let out = format_ref(DocKind::Module, "k\"\\\n", "a\u{1}b", RefTarget::Json);
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        let field = |pointer: &str| parsed.pointer(pointer).and_then(serde_json::Value::as_str);
        assert_eq!(field("/ref/kind"), Some("module"));
        assert_eq!(field("/ref/key"), Some("k\"\\\n"));
        assert_eq!(field("/text"), Some("a\u{1}b"));
    }

    /// Percent-decode an ASCII `%XX`-escaped string.
    ///
    /// The inverse of [`markdown_text::link_destination`]'s encoding, used by
    /// a test that checks the Markdown output without a Markdown parser
    /// dependency.
    fn percent_decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while let Some(&b) = bytes.get(i) {
            let decoded_escape = if b == b'%' {
                bytes
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
            } else {
                None
            };
            if let Some(decoded) = decoded_escape {
                out.push(decoded);
                i += 3;
            } else {
                out.push(b);
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// The index of the first `target` in `s` not preceded by an unescaped
    /// `\`.
    ///
    /// A faithful-enough stand-in for how a Markdown parser finds the `]`
    /// that closes link text: it must not be the backslash-escaped kind.
    fn first_unescaped(s: &str, target: char) -> Option<usize> {
        let mut escaped = false;
        for (i, c) in s.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if c == '\\' {
                escaped = true;
                continue;
            }
            if c == target {
                return Some(i);
            }
        }
        None
    }

    /// A `]` in the display and a `)` or space in the key cannot end the
    /// Markdown link early.
    ///
    /// The link text decodes back to the display, and the angle-bracket
    /// destination decodes back to the key, unmangled. Red before the fix:
    /// the raw splice put an unescaped `]` right after the display's `a`
    /// (not followed by `(`, so no parser would even read the rest as a
    /// link), and the key's `)` would end an unwrapped destination early.
    #[test]
    fn markdown_ref_escapes_link_text_and_destination() {
        let out = format_ref(DocKind::Module, "k) x", "a]b", RefTarget::Markdown);

        let rest = out.strip_prefix('[').expect("starts with [");
        let close = first_unescaped(rest, ']').expect("link text has a closing ]");
        assert_eq!(
            rest.as_bytes().get(close + 1),
            Some(&b'('),
            "the real closing ] of the link text must be followed by ( — an \
             earlier unescaped ] (from an unescaped display) breaks the link"
        );

        let decoded_text = rest[..close]
            .replace("\\]", "]")
            .replace("\\[", "[")
            .replace("\\\\", "\\");
        assert_eq!(decoded_text, "a]b");

        let dest_part = rest[close + 2..]
            .strip_suffix(')')
            .expect("link ends with a closing )");
        let dest_inner = dest_part
            .strip_prefix('<')
            .and_then(|s| s.strip_suffix('>'))
            .expect("destination is wrapped in <...>");
        assert_eq!(percent_decode(dest_inner), "module/k) x.md");
    }
}
