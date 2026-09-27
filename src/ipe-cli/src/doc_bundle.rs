//! Unified documentation bundle: entry index, kind-qualified resolver,
//! `[[kind:key]]` cross-reference rewriter, and fuzzy CLI search.
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
//! `ipe doc <bare-word>` calls [`fuzzy_rank`], which scores every entry
//! against the query and returns the ranked candidates.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use include_dir::{Dir, include_dir};

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
/// [`fuzzy_rank`].
pub struct DocBundle {
    maps: BTreeMap<DocKind, BTreeMap<String, DocEntry>>,
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

        Ok(Self { maps })
    }

    /// Build an empty bundle (for tests).
    #[cfg(test)]
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            maps: BTreeMap::new(),
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
        self.maps
            .get(&kind)
            .and_then(|m| m.get(key))
            .ok_or_else(|| BundleError::UnknownKey {
                kind,
                key: key.to_owned(),
            })
    }

    /// All entries across all kinds, in kind + key order.
    pub fn all_entries(&self) -> impl Iterator<Item = &DocEntry> {
        self.maps.values().flat_map(|m| m.values())
    }

    /// All entries for a specific kind.
    pub fn entries_for_kind(&self, kind: DocKind) -> impl Iterator<Item = &DocEntry> {
        self.maps.get(&kind).into_iter().flat_map(|m| m.values())
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
}

impl BundleSource {
    /// Construct a source with key and title; no prose body.
    pub fn titled(key: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            title: title.into(),
            body: String::new(),
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
        }
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
                    .maps
                    .get(&kind)
                    .and_then(|m| m.get(key))
                    .ok_or_else(|| BundleError::UnknownRef {
                        reference: inner.to_owned(),
                        source_file: source_file.to_owned(),
                    })?;

                let display = display_override
                    .filter(|d| !d.is_empty())
                    .unwrap_or(entry.title.as_str());

                out.push_str(&format_ref(kind, key, display, target));
            }
        }
    }

    Ok(out)
}

/// Produce the format-aware rewriting of one resolved cross-reference.
fn format_ref(kind: DocKind, key: &str, display: &str, target: RefTarget) -> String {
    match target {
        RefTarget::Html => format!(
            "<a href=\"{}/{}.html\">{}</a>",
            kind.prefix(),
            key,
            html_escape_ref(display)
        ),
        RefTarget::Markdown => format!("[{}]({}/{}.md)", display, kind.prefix(), key),
        RefTarget::Json => format!(
            "{{\"ref\":{{\"kind\":\"{}\",\"key\":\"{}\"}},\"text\":\"{}\"}}",
            kind.prefix(),
            json_escape_ref(key),
            json_escape_ref(display)
        ),
        RefTarget::Serve => format!(
            "<a href=\"/{}/{}\">{}</a>",
            kind.prefix(),
            key,
            html_escape_ref(display)
        ),
        RefTarget::Terminal => format!("{display} (ipe doc {}:{})", kind.prefix(), key),
    }
}

/// Minimal HTML escaping for ref display text.
fn html_escape_ref(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Minimal JSON string escaping: backslash and double-quote.
fn json_escape_ref(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// == Fuzzy search =============================================================

/// A ranked candidate from a fuzzy search.
#[derive(Debug, Clone)]
pub struct FuzzyMatch<'a> {
    /// The matched entry.
    pub entry: &'a DocEntry,
    /// Score: higher is a better match. The exact value is an implementation
    /// detail; only the ordering is meaningful to callers.
    pub score: u32,
}

/// The score of an exact key match — the one score that names the entry the
/// query asked for rather than a neighbour of it.
pub const EXACT_SCORE: u32 = 1000;

/// The most suggestions a miss lists: enough to cover a bare name shared by a
/// few modules, few enough to read at a glance.
pub const SUGGESTION_LIMIT: usize = 8;

/// The longest query (in characters) the edit-distance tiers consider.
///
/// Longer input still ranks by exact, prefix, substring, and token match; the bound keeps a pasted
/// blob from buying an unbounded distance computation.
const DISTANCE_QUERY_CAP: usize = 64;

/// Rank all entries in `bundle` against `query`, case-insensitively.
///
/// Matches each entry's key, the key's last `.` segment (a bare member name),
/// and its title.
///
/// Tiers, best first: exact key ([`EXACT_SCORE`]); exact last segment; prefix;
/// exact or prefix title; substring; every query word a word of the key or
/// title; then a small edit distance (a typo). Returns the matching entries,
/// best first, ties broken by kind then key so the order is deterministic.
/// An entry that matches no tier is left out — see [`nearest`] for the
/// always-non-empty fallback.
#[must_use]
pub fn fuzzy_rank<'a>(bundle: &'a DocBundle, query: &str) -> Vec<FuzzyMatch<'a>> {
    let q = query.trim().to_lowercase();
    let mut results: Vec<FuzzyMatch<'a>> = bundle
        .all_entries()
        .filter_map(|entry| {
            let score = score_entry(entry, &q);
            (score > 0).then_some(FuzzyMatch { entry, score })
        })
        .collect();
    results.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.entry.kind.cmp(&b.entry.kind))
            .then_with(|| a.entry.key.cmp(&b.entry.key))
    });
    results
}

/// The `limit` entries closest to `query` by edit distance, closest first.
///
/// Distance is over key, last segment, and title — the fallback that makes a
/// miss never a dead end. Non-empty whenever the bundle is.
#[must_use]
pub fn nearest<'a>(bundle: &'a DocBundle, query: &str, limit: usize) -> Vec<FuzzyMatch<'a>> {
    let q: String = query
        .trim()
        .to_lowercase()
        .chars()
        .take(DISTANCE_QUERY_CAP)
        .collect();
    let mut scored: Vec<(usize, &'a DocEntry)> = bundle
        .all_entries()
        .map(|entry| (entry_distance(entry, &q), entry))
        .collect();
    scored.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.kind.cmp(&b.1.kind))
            .then_with(|| a.1.key.cmp(&b.1.key))
    });
    scored
        .into_iter()
        .take(limit)
        .map(|(distance, entry)| FuzzyMatch {
            entry,
            score: u32::try_from(distance).map_or(0, |d| 100_u32.saturating_sub(d)),
        })
        .collect()
}

/// The last `.` segment of a key (`Ipe.Time.unixMillis` → `unixMillis`), or the
/// whole key when it has none.
fn last_segment(key: &str) -> &str {
    key.rsplit_once('.').map_or(key, |(_, last)| last)
}

/// The words of `text`: its alphanumeric runs.
fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
}

/// The smallest edit distance from `query` (already lowercased and capped) to
/// the entry's key, last segment, or title.
fn entry_distance(entry: &DocEntry, query: &str) -> usize {
    let key = entry.key.to_lowercase();
    let title = entry.title.to_lowercase();
    [
        crate::driver::levenshtein(query, &key),
        crate::driver::levenshtein(query, last_segment(&key)),
        crate::driver::levenshtein(query, &title),
    ]
    .into_iter()
    .min()
    .unwrap_or(usize::MAX)
}

/// Compute the tiered score of a lowercased query against one entry (0 = no
/// match).
fn score_entry(entry: &DocEntry, query: &str) -> u32 {
    if query.is_empty() {
        return 0;
    }
    let key = entry.key.to_lowercase();
    let member = last_segment(&key);
    let title = entry.title.to_lowercase();
    if key == query {
        return EXACT_SCORE;
    }
    if member == query {
        return 950;
    }
    if key.starts_with(query) || member.starts_with(query) {
        return 800;
    }
    if title == query {
        return 750;
    }
    if title.starts_with(query) {
        return 600;
    }
    if key.contains(query) || title.contains(query) {
        return 500;
    }
    let mut query_words = words(query).peekable();
    if query_words.peek().is_some()
        && query_words.all(|w| words(&key).chain(words(&title)).any(|kw| kw == w))
    {
        return 450;
    }
    let length = query.chars().count();
    if length > DISTANCE_QUERY_CAP {
        return 0;
    }
    let threshold = (length / 3).max(1);
    let distance =
        crate::driver::levenshtein(query, &key).min(crate::driver::levenshtein(query, member));
    if distance <= threshold {
        let penalty = u32::try_from(distance).map_or(u32::MAX, |d| d.saturating_mul(40));
        return 300_u32.saturating_sub(penalty).max(1);
    }
    0
}

/// One suggestion for a documentation miss: the exact command that shows the
/// entry, and the entry's title.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocSuggestion {
    /// The `ipe doc …` argument that opens the entry exactly.
    pub key: String,
    /// The entry's kind, for the reader's orientation.
    pub kind: DocKind,
    /// The entry's human title.
    pub title: String,
}

impl DocSuggestion {
    /// The suggestion for `entry`: a module or symbol by its own key (`ipe doc`
    /// resolves both directly), any other kind by its `kind:key` reference.
    #[must_use]
    pub fn for_entry(entry: &DocEntry) -> Self {
        let key = match entry.kind {
            DocKind::Module | DocKind::Symbol => entry.key.clone(),
            DocKind::Diagnostic
            | DocKind::Construct
            | DocKind::Idiom
            | DocKind::Topic
            | DocKind::Guide
            | DocKind::Cli => format!("{}:{}", entry.kind.prefix(), entry.key),
        };
        Self {
            key,
            kind: entry.kind,
            title: entry.title.clone(),
        }
    }
}

/// The lines listing `suggestions` under the doc-miss header, keys in one column.
#[must_use]
pub fn suggestion_lines(suggestions: &[DocSuggestion]) -> Vec<String> {
    let width = suggestions
        .iter()
        .map(|s| s.key.chars().count())
        .max()
        .unwrap_or(0);
    suggestions
        .iter()
        .map(|s| {
            let key = format!("{:width$}", s.key);
            crate::text::cli_doc_suggestion_line(&key, &s.title, &s.kind)
        })
        .collect()
}

/// The suggestions for a query that named no entry.
///
/// The ranked matches, or — when nothing matches any tier — the nearest entries
/// by edit distance, so a miss always offers somewhere to go. At most
/// [`SUGGESTION_LIMIT`].
#[must_use]
pub fn suggestions_for(bundle: &DocBundle, query: &str) -> Vec<DocSuggestion> {
    let ranked = fuzzy_rank(bundle, query);
    let chosen = if ranked.is_empty() {
        nearest(bundle, query, SUGGESTION_LIMIT)
    } else {
        ranked.into_iter().take(SUGGESTION_LIMIT).collect()
    };
    chosen
        .iter()
        .map(|m| DocSuggestion::for_entry(m.entry))
        .collect()
}

// == Tests ====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ipe-doc-bundle-{name}-{}", std::process::id()));
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
        assert_eq!(out, "See [the store](module/Ipe.Db.Store.md).");
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

    // -- Fuzzy search ---------------------------------------------------------

    fn bundle_with_select_entries() -> DocBundle {
        let mut b = DocBundle::empty();
        b.insert(
            DocKind::Construct,
            "select".to_owned(),
            "Select expression".to_owned(),
            String::new(),
        )
        .unwrap();
        b.insert(
            DocKind::Construct,
            "case".to_owned(),
            "Case expression".to_owned(),
            String::new(),
        )
        .unwrap();
        b.insert(
            DocKind::Guide,
            "getting-started".to_owned(),
            "Getting started".to_owned(),
            String::new(),
        )
        .unwrap();
        b
    }

    #[test]
    fn fuzzy_rank_typo_suggests_correct_key() {
        let bundle = bundle_with_select_entries();
        let results = fuzzy_rank(&bundle, "slect");
        assert!(!results.is_empty(), "should find suggestions for 'slect'");
        let top = results.first().expect("at least one result");
        assert_eq!(
            top.entry.key,
            "select",
            "top result is 'select': {:?}",
            results.iter().map(|r| &r.entry.key).collect::<Vec<_>>()
        );
    }

    #[test]
    fn fuzzy_rank_exact_key_is_top() {
        let bundle = bundle_with_select_entries();
        let results = fuzzy_rank(&bundle, "case");
        assert!(!results.is_empty());
        let top = results.first().expect("at least one result");
        assert_eq!(top.entry.key, "case");
        assert_eq!(top.score, 1000);
    }

    #[test]
    fn fuzzy_rank_no_match_returns_empty() {
        let bundle = bundle_with_select_entries();
        let results = fuzzy_rank(&bundle, "zzzzzzzzzzz");
        assert!(results.is_empty(), "no match for nonsense query");
    }

    #[test]
    fn fuzzy_rank_ambiguous_returns_multiple() {
        let bundle = bundle_with_select_entries();
        let results = fuzzy_rank(&bundle, "e");
        assert!(
            results.len() > 1,
            "ambiguous query returns multiple: {:?}",
            results.iter().map(|r| &r.entry.key).collect::<Vec<_>>()
        );
    }

    #[test]
    fn fuzzy_rank_matches_a_bare_member_name() {
        let mut bundle = DocBundle::empty();
        for key in ["Ipe.Time.unixMillis", "Ipe.Time.now", "Ipe.List.map"] {
            let inserted = bundle.insert(
                DocKind::Symbol,
                key.to_owned(),
                key.to_owned(),
                String::new(),
            );
            assert!(inserted.is_ok(), "{inserted:?}");
        }
        let results = fuzzy_rank(&bundle, "unixmillis");
        assert!(
            matches!(results.first(), Some(m) if m.entry.key == "Ipe.Time.unixMillis"),
            "{:?}",
            results.iter().map(|r| &r.entry.key).collect::<Vec<_>>()
        );
        let typo = fuzzy_rank(&bundle, "unixMilis");
        assert!(
            matches!(typo.first(), Some(m) if m.entry.key == "Ipe.Time.unixMillis"),
            "a one-letter typo still finds the member"
        );
    }

    #[test]
    fn a_miss_always_suggests_the_nearest_entries() {
        let bundle = bundle_with_select_entries();
        assert!(fuzzy_rank(&bundle, "zzzzzzzzzzz").is_empty());
        let suggestions = suggestions_for(&bundle, "zzzzzzzzzzz");
        assert!(!suggestions.is_empty(), "never a dead end");
        assert!(suggestions.len() <= SUGGESTION_LIMIT);
    }

    #[test]
    fn suggestions_are_bounded_and_deterministic() {
        let bundle = bundle_with_select_entries();
        let first = suggestions_for(&bundle, "e");
        assert!(first.len() <= SUGGESTION_LIMIT);
        assert_eq!(first, suggestions_for(&bundle, "e"));
    }

    #[test]
    fn a_suggestion_names_an_exact_lookup() {
        let entry = DocEntry {
            kind: DocKind::Topic,
            key: "pipelines".to_owned(),
            title: "Pipelines".to_owned(),
            body: String::new(),
            order: None,
        };
        assert_eq!(DocSuggestion::for_entry(&entry).key, "topic:pipelines");
        let symbol = DocEntry {
            kind: DocKind::Symbol,
            key: "Ipe.List.map".to_owned(),
            ..entry
        };
        assert_eq!(DocSuggestion::for_entry(&symbol).key, "Ipe.List.map");
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
}
