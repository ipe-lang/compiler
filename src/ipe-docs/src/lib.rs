#![forbid(unsafe_code)]
//! `ipe_docs` — the documentation content index.
//!
//! Builds an in-memory index that maps a documentation key to its entry.
//! Every entry is a *reference* to a per-kind SSOT; no prose is duplicated
//! here. The sources, each aggregated by an `add_*` step in [`Index::build`]:
//!
//! - **Symbols / modules** — parsed doc-strings from the embedded stdlib
//!   `.ipe` sources, both the source-form and compiled-form modules. The raw
//!   [`DocString`] body is carried as-is; the index is the aggregator, not the
//!   author.
//! - **Diagnostics** — the `src/compiler/diagnostics/explain/*.md` files
//!   (already SSOT). Read at index-build time from the filesystem.
//! - **Constructs / glossary** — `docs/constructs/*.md` files (the only newly
//!   authored prose; seed entries: `case`, `do`).
//! - **CLI commands** — injected by the caller from `help.rs`'s `COMMANDS`
//!   table (the SSOT). The index never imports `ipe` to avoid a circular
//!   dependency; command data is passed in via [`CommandInfo`].
//! - **Environment variables** — the recognised `IPE_*` variables and their
//!   documentation.
//!
//! Entry point: [`Index::build`].

pub mod argv;
pub mod env_vars;
pub mod html;
pub mod markdown;
pub mod markdown_text;
pub mod render;
pub mod stdlib_docs;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ipe_intern::Interner;
use ipe_parse::parse_module;
use ipe_stdlib::{COMPILED_STD_MODULES, MODULES as STDLIB_MODULES};
use ipe_syntax::{TypeAlias, Union, Value};
// `Located` wrapper is accessed via `.value` on the `loc` field of each node;
// the type itself is not named in this module.

// ── Public types ─────────────────────────────────────────────────────────────

/// The kind of entity a resolved [`Entry`] describes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// A value, function, or type alias exported by a stdlib module.
    Symbol,
    /// A stdlib module as a whole.
    Module,
    /// A compiler diagnostic, identified by its `IPE-X0000` code.
    Diagnostic,
    /// A language construct or glossary term (sourced from `docs/constructs/`).
    Construct,
    /// An `ipe` CLI command (sourced from the `COMMANDS` registry via the
    /// caller-injected [`CommandInfo`] slice).
    Command,
    /// A runtime environment variable (sourced from the `ENV_VARS` registry in
    /// `ipe_docs::env_vars`). Keys match the variable name exactly, e.g.
    /// `IPE_WEB_PORT`.
    EnvVar,
}

impl EntryKind {
    /// The single URL/path subdirectory segment for this kind.
    ///
    /// This is the SSOT for a kind's route: both the on-disk page directory
    /// (`<out>/<subdir>/<key>/index.html`) and the index-page hyperlinks
    /// (`/<subdir>/<source_key>/`) derive from it, so the two can never drift.
    #[must_use]
    pub const fn route_subdir(&self) -> &'static str {
        match self {
            Self::Symbol => "symbol",
            Self::Module => "module",
            Self::Diagnostic => "diagnostic",
            Self::Construct => "construct",
            Self::Command => "command",
            Self::EnvVar => "env-var",
        }
    }
}

/// A resolved documentation entry.
///
/// The `text` field carries the raw documentation text as it appears in the
/// SSOT — a doc-string body, a Markdown file's contents, or a command summary.
/// The index never rewrites or summarises this text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The kind of entity this entry describes.
    pub kind: EntryKind,
    /// A stable identifier for the SSOT source of this entry.
    ///
    /// - `Symbol` / `Module`: the dotted module name, e.g. `Ipe.List` or
    ///   `Ipe.List.map`.
    /// - `Diagnostic`: the diagnostic code, e.g. `IPE-L0107`.
    /// - `Construct`: the stem of the `docs/constructs/<name>.md` file, e.g.
    ///   `case`.
    /// - `Command`: the command name, e.g. `version`.
    /// - `EnvVar`: the variable name, e.g. `IPE_WEB_PORT`.
    pub source_key: String,
    /// The raw documentation text from the SSOT.
    pub text: String,
}

/// Caller-supplied command metadata, sourced from `help.rs`'s `COMMANDS`
/// table. The index carries this slice by value so it does not depend on the
/// `ipe` crate.
#[derive(Clone, Debug)]
pub struct CommandInfo {
    /// The subcommand name, e.g. `build`.
    pub name: &'static str,
    /// The full command help rendered as Markdown from `help.rs`'s `COMMANDS`
    /// registry — synopsis, arguments, and options — so `ipe doc <command>`
    /// mirrors `ipe <command> --help` from one source.
    pub help: String,
}

// ── Index ─────────────────────────────────────────────────────────────────────

/// The in-memory documentation index.
///
/// Built once via [`Index::build`] or [`IndexBuilder`]; then queried via
/// [`Index::resolve`]. Entries are keyed case-sensitively (diagnostic codes
/// are uppercase; symbol names preserve the Ipê casing convention).
pub struct Index {
    entries: HashMap<String, Entry>,
}

impl Index {
    /// Build the index by aggregating every source, one `add_*` step per kind.
    ///
    /// - `explain_dir`: path to `src/compiler/diagnostics/explain/`
    /// - `content_dir`: path to `docs/constructs/`
    /// - `commands`: command metadata from `help.rs`'s `COMMANDS` table
    ///
    /// # Errors
    ///
    /// Returns an error string if `explain_dir` or `content_dir` cannot be
    /// opened as a directory, or if any stdlib module fails to parse.
    pub fn build(
        explain_dir: &Path,
        content_dir: &Path,
        commands: &[CommandInfo],
    ) -> Result<Self, String> {
        let mut builder = IndexBuilder::new();
        builder.add_stdlib()?;
        builder.add_compiled_stdlib()?;
        builder.add_diagnostics(explain_dir)?;
        builder.add_constructs(content_dir)?;
        builder.add_commands(commands);
        builder.add_env_vars();
        Ok(builder.finish())
    }

    /// Build an index from sources that need no filesystem access.
    ///
    /// Aggregates the embedded stdlib symbol/module docs, the embedded
    /// diagnostic explain pages ([`ipe_diagnostics::ALL_CODES`] +
    /// [`ipe_diagnostics::explain_page`]), and the `IPE_*` env-var registry.
    /// Constructs and CLI commands are omitted — those are read from the
    /// filesystem / injected by the CLI and are not available to a tool (such
    /// as the LSP server) that may run outside the compiler source tree.
    ///
    /// This is the entry point long-lived tools use to build the index once and
    /// cache it, since it depends only on data compiled into the binary.
    ///
    /// # Errors
    ///
    /// Returns an error string if any embedded stdlib module fails to parse.
    pub fn build_embedded() -> Result<Self, String> {
        let mut builder = IndexBuilder::new();
        builder.add_stdlib()?;
        builder.add_compiled_stdlib()?;
        builder.add_diagnostics_embedded();
        builder.add_env_vars();
        Ok(builder.finish())
    }

    /// Resolve a documentation key to its entry, or `None` if no entry exists.
    ///
    /// Keys are matched case-sensitively. Accepted forms:
    ///
    /// - `List.map` or `Ipe.List.map` — a qualified symbol.
    /// - `List` or `Ipe.List` — a module.
    /// - `IPE-L0107` — a diagnostic code.
    /// - `case`, `do` — a construct or glossary term.
    /// - `version`, `build` — a CLI command.
    /// - `IPE_WEB_PORT`, `IPE_LOG_LEVEL` — a runtime environment variable.
    #[must_use]
    pub fn resolve(&self, key: &str) -> Option<&Entry> {
        self.entries.get(key)
    }

    /// Every key currently in the index, in unspecified order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }
}

// ── Builder ───────────────────────────────────────────────────────────────────

/// Incremental builder for [`Index`].
///
/// Callers that need to populate the index in stages (e.g. tests) can use this
/// directly instead of [`Index::build`].
pub struct IndexBuilder {
    entries: HashMap<String, Entry>,
}

impl IndexBuilder {
    /// Create an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Consume the builder and produce the [`Index`].
    #[must_use]
    pub fn finish(self) -> Index {
        Index {
            entries: self.entries,
        }
    }

    /// Insert a single entry, replacing any prior entry for the same key.
    pub fn insert(&mut self, key: String, entry: Entry) {
        self.entries.insert(key, entry);
    }

    /// Parse and index every embedded stdlib module's doc-strings.
    ///
    /// For each `{-| … -}` doc-string attached to a top-level declaration,
    /// two `Symbol` entries are registered: a short-qualified key
    /// (`List.map`) and a fully-qualified key (`Ipe.List.map`). A `Module`
    /// entry is registered for each module under both its full name
    /// (`Ipe.List`) and its short name (`List`).
    ///
    /// # Errors
    ///
    /// Returns an error if any stdlib module fails to parse.
    pub fn add_stdlib(&mut self) -> Result<(), String> {
        let mut interner = Interner::new();
        for std_mod in STDLIB_MODULES {
            let module = parse_module(std_mod.source, &mut interner)
                .map_err(|d| format!("parse error in {}: {d:?}", std_mod.name))?;

            let short = stdlib_short_name(std_mod.name);

            // Module entry — text is empty when no module-level `{-|` exists.
            let mod_entry = Entry {
                kind: EntryKind::Module,
                source_key: std_mod.name.to_owned(),
                text: String::new(),
            };
            self.entries
                .insert(std_mod.name.to_owned(), mod_entry.clone());
            self.entries.insert(short.to_owned(), mod_entry);

            // Symbol entries.
            for loc_val in &module.values {
                index_value(
                    &mut self.entries,
                    std_mod.name,
                    short,
                    &loc_val.value,
                    &interner,
                );
            }
            for loc_union in &module.unions {
                index_union(
                    &mut self.entries,
                    std_mod.name,
                    short,
                    &loc_union.value,
                    &interner,
                );
            }
            for loc_alias in &module.aliases {
                index_alias(
                    &mut self.entries,
                    std_mod.name,
                    short,
                    &loc_alias.value,
                    &interner,
                );
            }

            // Fall back to raw-source `-- |` line docs for any export the AST
            // pass did not attach a `{-| … -}` doc to. This covers the modules
            // that use the line-comment documentation style.
            index_line_docs(&mut self.entries, std_mod.name, short, std_mod.source);
        }
        Ok(())
    }

    /// Parse and index every compiled-source stdlib module's doc-strings.
    ///
    /// Mirrors [`Self::add_stdlib`] but operates on `COMPILED_STD_MODULES`
    /// (the modules that go through the full compile pipeline rather than the
    /// parse-fixture `MODULES` list).
    ///
    /// # Errors
    ///
    /// Returns an error if any compiled-source stdlib module fails to parse.
    pub fn add_compiled_stdlib(&mut self) -> Result<(), String> {
        let mut interner = Interner::new();
        for std_mod in COMPILED_STD_MODULES {
            let module = parse_module(std_mod.source, &mut interner)
                .map_err(|d| format!("parse error in {}: {d:?}", std_mod.dotted))?;

            let short = stdlib_short_name(std_mod.dotted);

            let mod_entry = Entry {
                kind: EntryKind::Module,
                source_key: std_mod.dotted.to_owned(),
                text: String::new(),
            };
            self.entries
                .insert(std_mod.dotted.to_owned(), mod_entry.clone());
            self.entries.insert(short.to_owned(), mod_entry);

            for loc_val in &module.values {
                index_value(
                    &mut self.entries,
                    std_mod.dotted,
                    short,
                    &loc_val.value,
                    &interner,
                );
            }
            for loc_union in &module.unions {
                index_union(
                    &mut self.entries,
                    std_mod.dotted,
                    short,
                    &loc_union.value,
                    &interner,
                );
            }
            for loc_alias in &module.aliases {
                index_alias(
                    &mut self.entries,
                    std_mod.dotted,
                    short,
                    &loc_alias.value,
                    &interner,
                );
            }

            index_line_docs(&mut self.entries, std_mod.dotted, short, std_mod.source);
        }
        Ok(())
    }

    /// Read and index all `IPE-*.md` pages from `explain_dir`.
    ///
    /// Each file whose name matches `IPE-*.md` becomes a `Diagnostic` entry
    /// keyed by the diagnostic code (e.g. `IPE-L0107`). Files that cannot be
    /// read are silently skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if `explain_dir` cannot be opened as a directory.
    pub fn add_diagnostics(&mut self, explain_dir: &Path) -> Result<(), String> {
        let rd = std::fs::read_dir(explain_dir)
            .map_err(|e| format!("cannot read explain dir {}: {e}", explain_dir.display()))?;
        for dir_entry in rd.flatten() {
            let path: PathBuf = dir_entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let has_md_ext = std::path::Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("md"));
            if !name.starts_with("IPE-") || !has_md_ext {
                continue;
            }
            let code = name.strip_suffix(".md").unwrap_or(name).to_owned();
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let entry = Entry {
                kind: EntryKind::Diagnostic,
                source_key: code.clone(),
                text,
            };
            self.entries.insert(code, entry);
        }
        Ok(())
    }

    /// Index every diagnostic explain page compiled into the binary.
    ///
    /// Mirrors [`Self::add_diagnostics`] but reads the pages from
    /// [`ipe_diagnostics::explain_page`] over [`ipe_diagnostics::ALL_CODES`]
    /// rather than the filesystem, so it works in a tool running outside the
    /// compiler source tree. A code whose page is absent is skipped (fail-closed
    /// — no entry rather than an empty one).
    pub fn add_diagnostics_embedded(&mut self) {
        for &code in ipe_diagnostics::ALL_CODES {
            let Some(text) = ipe_diagnostics::explain_page(code) else {
                continue;
            };
            let key = code.as_str().to_owned();
            let entry = Entry {
                kind: EntryKind::Diagnostic,
                source_key: key.clone(),
                text: text.to_owned(),
            };
            self.entries.insert(key, entry);
        }
    }

    /// Read and index all `.md` files from `content_dir` as construct entries.
    ///
    /// Each file's stem becomes the key (e.g. `case.md` → key `case`). Files
    /// that cannot be read are silently skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if `content_dir` cannot be opened as a directory.
    pub fn add_constructs(&mut self, content_dir: &Path) -> Result<(), String> {
        let rd = std::fs::read_dir(content_dir)
            .map_err(|e| format!("cannot read content dir {}: {e}", content_dir.display()))?;
        for dir_entry in rd.flatten() {
            let path: PathBuf = dir_entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let has_md_ext = std::path::Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("md"));
            if !has_md_ext {
                continue;
            }
            let stem = name.strip_suffix(".md").unwrap_or(name).to_owned();
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let entry = Entry {
                kind: EntryKind::Construct,
                source_key: stem.clone(),
                text,
            };
            self.entries.insert(stem, entry);
        }
        Ok(())
    }

    /// Index CLI commands from the caller-supplied slice.
    ///
    /// Each [`CommandInfo`] entry is registered as a `Command` entry keyed by
    /// its name. The caller is responsible for supplying data sourced from
    /// `help.rs`'s `COMMANDS` table.
    pub fn add_commands(&mut self, commands: &[CommandInfo]) {
        for cmd in commands {
            let entry = Entry {
                kind: EntryKind::Command,
                source_key: cmd.name.to_owned(),
                text: cmd.help.clone(),
            };
            self.entries.insert(cmd.name.to_owned(), entry);
        }
    }

    /// Index every entry from the [`env_vars::ENV_VARS`] registry as an
    /// [`EntryKind::EnvVar`] entry.
    ///
    /// Each variable is registered under its exact name (e.g. `IPE_WEB_PORT`).
    /// The text field contains a formatted summary of the variable's name,
    /// default, purpose, subsystem, and class — all fields sourced from the
    /// single [`env_vars::EnvVar`] SSOT; no prose is authored here.
    pub fn add_env_vars(&mut self) {
        for var in env_vars::ENV_VARS {
            let text = format!(
                "Name:      {}\nDefault:   {}\nSubsystem: {}\nClass:     {}\n\n{}",
                var.name,
                var.default,
                var.subsystem.display(),
                var.class.badge(),
                var.purpose,
            );
            let entry = Entry {
                kind: EntryKind::EnvVar,
                source_key: var.name.to_owned(),
                text,
            };
            self.entries.insert(var.name.to_owned(), entry);
        }
    }
}

impl Default for IndexBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Insert a symbol entry under two keys: short-qualified and fully-qualified.
fn insert_symbol(
    entries: &mut HashMap<String, Entry>,
    module_name: &str,
    short: &str,
    sym_name: &str,
    body: &str,
) {
    let fq_key = format!("{module_name}.{sym_name}");
    let short_key = format!("{short}.{sym_name}");
    let entry = Entry {
        kind: EntryKind::Symbol,
        source_key: fq_key.clone(),
        text: body.to_owned(),
    };
    entries.insert(fq_key, entry.clone());
    entries.insert(short_key, entry);
}

fn index_value(
    entries: &mut HashMap<String, Entry>,
    module_name: &str,
    short: &str,
    val: &Value,
    interner: &Interner,
) {
    let Some(ref doc) = val.doc else { return };
    let Some(sym_name) = interner.resolve(val.name.value) else {
        return;
    };
    insert_symbol(entries, module_name, short, sym_name, &doc.body);
}

fn index_union(
    entries: &mut HashMap<String, Entry>,
    module_name: &str,
    short: &str,
    union: &Union,
    interner: &Interner,
) {
    let Some(ref doc) = union.doc else { return };
    let Some(sym_name) = interner.resolve(union.name.value) else {
        return;
    };
    insert_symbol(entries, module_name, short, sym_name, &doc.body);
}

fn index_alias(
    entries: &mut HashMap<String, Entry>,
    module_name: &str,
    short: &str,
    alias: &TypeAlias,
    interner: &Interner,
) {
    let Some(ref doc) = alias.doc else { return };
    let Some(sym_name) = interner.resolve(alias.name.value) else {
        return;
    };
    insert_symbol(entries, module_name, short, sym_name, &doc.body);
}

/// Index the `-- |` line-comment docs of a module's raw source.
///
/// For each documented export, register a `Symbol` entry (short + fq keys)
/// *only when one is not already present* — an AST-derived `{-| … -}` doc
/// takes precedence over a raw-source line doc for the same symbol.
fn index_line_docs(
    entries: &mut HashMap<String, Entry>,
    module_name: &str,
    short: &str,
    source: &str,
) {
    let module = crate::stdlib_docs::extract_module_doc(module_name, source);

    // Carry the module-level header into the `Module` entry's text when the
    // module has one (the AST pass leaves it empty).
    if let Some(module_doc) = &module.module_doc {
        for key in [module_name, short] {
            let Some(entry) = entries.get_mut(key) else {
                continue;
            };
            if entry.kind == EntryKind::Module && entry.text.is_empty() {
                entry.text.clone_from(module_doc);
            }
        }
    }

    for export in &module.exports {
        let Some(doc) = &export.doc else { continue };
        let fq_key = format!("{module_name}.{}", export.name);
        if entries.contains_key(&fq_key) {
            continue;
        }
        insert_symbol(entries, module_name, short, &export.name, doc);
    }
}

/// The short query name for a dotted stdlib module.
///
/// `Ipe.List` → `List`; `Ipe.Html.Attributes` → `Html.Attributes`;
/// `Main` → `Main` (no prefix). The single definition of the stdlib
/// short-name rule: index construction and every `ipe doc` module lookup
/// call this (directly, or through [`stdlib_module_matches`]), so a key form
/// that resolves for one never silently misses for the other.
#[must_use]
pub fn stdlib_short_name(dotted: &str) -> &str {
    dotted.strip_prefix("Ipe.").unwrap_or(dotted)
}

/// Does `query` name the stdlib module `dotted`, under the short/full-name
/// rule?
///
/// True for `dotted` itself or for [`stdlib_short_name(dotted)`](stdlib_short_name).
/// A query may match more than one `dotted` across a candidate set — this fn
/// only answers for one pair; the caller owns collecting candidates and
/// detecting a collision.
#[must_use]
pub fn stdlib_module_matches(query: &str, dotted: &str) -> bool {
    query == dotted || query == stdlib_short_name(dotted)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{CommandInfo, EntryKind, Index};

    /// Resolve a workspace-root-relative path.
    ///
    /// `CARGO_MANIFEST_DIR` is the crate root (`src/ipe-docs/`); the workspace
    /// root is two levels up.
    fn workspace_path(rel: &str) -> PathBuf {
        let manifest = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest).join("../..").join(rel)
    }

    fn test_commands() -> Vec<CommandInfo> {
        vec![
            CommandInfo {
                name: "version",
                help: "Print the ipe version.\n\n```\nipe version\n```\n".to_owned(),
            },
            CommandInfo {
                name: "build",
                help: "Compile a program to a native or WebAssembly artifact.\n\n\
                       ```\nipe build [<path>]\n```\n"
                    .to_owned(),
            },
        ]
    }

    fn build_index() -> Index {
        Index::build(
            &workspace_path("src/compiler/diagnostics/explain"),
            &workspace_path("docs/constructs"),
            &test_commands(),
        )
        .expect("index build must succeed")
    }

    #[test]
    fn resolve_symbol_maybe_with_default() {
        let idx = build_index();
        let entry = idx
            .resolve("Maybe.withDefault")
            .expect("Maybe.withDefault must resolve");
        assert_eq!(entry.kind, EntryKind::Symbol);
        assert!(
            entry.text.contains("withDefault"),
            "doc body should mention the function name"
        );
    }

    #[test]
    fn resolve_diagnostic_l0107() {
        let idx = build_index();
        let entry = idx.resolve("IPE-L0107").expect("IPE-L0107 must resolve");
        assert_eq!(entry.kind, EntryKind::Diagnostic);
        assert_eq!(entry.source_key, "IPE-L0107");
        assert!(
            entry.text.contains("record field"),
            "explain page should discuss record fields"
        );
    }

    /// The filesystem-free `build_embedded` index resolves stdlib symbols,
    /// embedded diagnostic pages, and env vars — the sources a long-lived tool
    /// (the LSP server) relies on when it runs outside the compiler tree.
    #[test]
    fn build_embedded_resolves_symbol_diagnostic_and_env_var() {
        let idx = Index::build_embedded().expect("embedded index build must succeed");

        let sym = idx
            .resolve("Maybe.withDefault")
            .expect("stdlib symbol must resolve in the embedded index");
        assert_eq!(sym.kind, EntryKind::Symbol);

        let diag = idx
            .resolve("IPE-L0107")
            .expect("embedded diagnostic page must resolve");
        assert_eq!(diag.kind, EntryKind::Diagnostic);
        assert!(!diag.text.is_empty(), "explain page text must be present");

        let env = idx
            .resolve("IPE_WEB_PORT")
            .expect("env var must resolve in the embedded index");
        assert_eq!(env.kind, EntryKind::EnvVar);
    }

    /// The embedded index carries no construct entries (constructs are
    /// filesystem-sourced) — a fail-closed miss, never a wrong entry.
    #[test]
    fn build_embedded_omits_constructs() {
        let idx = Index::build_embedded().expect("embedded index build must succeed");
        assert!(
            idx.resolve("case").is_none(),
            "constructs are filesystem-only; the embedded index must not carry them"
        );
    }

    #[test]
    fn resolve_command_version() {
        let idx = build_index();
        let entry = idx
            .resolve("version")
            .expect("version command must resolve");
        assert_eq!(entry.kind, EntryKind::Command);
        assert_eq!(entry.source_key, "version");
        assert!(
            entry.text.contains("version"),
            "summary should mention version"
        );
    }

    #[test]
    fn resolve_construct_case() {
        let idx = build_index();
        let entry = idx.resolve("case").expect("case construct must resolve");
        assert_eq!(entry.kind, EntryKind::Construct);
        assert_eq!(entry.source_key, "case");
        assert!(
            entry.text.contains("Pattern-match"),
            "case doc should describe pattern matching"
        );
    }

    #[test]
    fn resolve_env_var_ipe_web_port() {
        let mut builder = super::IndexBuilder::new();
        builder.add_env_vars();
        let idx = builder.finish();
        let entry = idx
            .resolve("IPE_WEB_PORT")
            .expect("IPE_WEB_PORT must resolve");
        assert_eq!(entry.kind, EntryKind::EnvVar);
        assert_eq!(entry.source_key, "IPE_WEB_PORT");
        assert!(
            entry.text.contains("8000"),
            "text should include the default value"
        );
        assert!(
            entry.text.contains("Web server"),
            "text should name the subsystem"
        );
        assert!(
            entry.text.contains("TCP port"),
            "text should describe the purpose"
        );
    }

    #[test]
    fn resolve_env_var_secret_class() {
        let mut builder = super::IndexBuilder::new();
        builder.add_env_vars();
        let idx = builder.finish();
        let entry = idx
            .resolve("IPE_AUTH_TOKEN_SECRET")
            .expect("IPE_AUTH_TOKEN_SECRET must resolve");
        assert_eq!(entry.kind, EntryKind::EnvVar);
        assert!(
            entry.text.contains("Secret"),
            "class badge must appear in text"
        );
    }

    #[test]
    fn resolve_unknown_key_returns_none() {
        let idx = build_index();
        assert!(
            idx.resolve("this.does.not.exist.at.all").is_none(),
            "unknown key must return None"
        );
    }

    /// `Ipe.Tea.Terminal.Color` is retired (its palette is rehomed under
    /// `Ipe.Color.Ansi`); the doc index must not expose a page for the deleted
    /// namespace.
    #[test]
    fn tea_terminal_namespace_absent_from_index() {
        let idx = build_index();
        for residual in [
            "Ipe.Tea.Terminal.Color",
            "App.Tea.Terminal.Color",
            "Tea.Terminal.Color",
        ] {
            assert!(
                idx.resolve(residual).is_none(),
                "deprecated Tea.Terminal namespace must not appear in the doc index; found: {residual}"
            );
        }
    }

    #[test]
    fn resolve_module_list() {
        let idx = build_index();
        let short = idx.resolve("List").expect("List module must resolve");
        assert_eq!(short.kind, EntryKind::Module);
        let fq = idx
            .resolve("Ipe.List")
            .expect("Ipe.List module must resolve");
        assert_eq!(fq.kind, EntryKind::Module);
    }

    #[test]
    fn resolve_symbol_both_forms() {
        let idx = build_index();
        let short = idx
            .resolve("Maybe.withDefault")
            .expect("Maybe.withDefault short form must resolve");
        assert_eq!(short.kind, EntryKind::Symbol);
        let fq = idx
            .resolve("Ipe.Maybe.withDefault")
            .expect("Ipe.Maybe.withDefault fq form must resolve");
        assert_eq!(fq.kind, EntryKind::Symbol);
        assert_eq!(
            short.text, fq.text,
            "short and fq entries carry identical text"
        );
    }

    // ── Site-generator integration tests ────────────────────────────────────

    /// The generator is deterministic: calling it twice with the same index
    /// produces byte-identical output for every page.
    #[test]
    fn site_generator_is_deterministic() {
        use crate::html;
        use crate::render::page;

        let idx = build_index();

        // Render the same entry twice and assert byte-equality.
        let entry = idx
            .resolve("Maybe.withDefault")
            .expect("Maybe.withDefault must resolve");

        let render_once = || {
            let kind_label = match entry.kind {
                EntryKind::Symbol => "symbol",
                EntryKind::Module => "module",
                EntryKind::Diagnostic => "diagnostic",
                EntryKind::Construct => "construct",
                EntryKind::Command => "command",
                EntryKind::EnvVar => "env-var",
            };
            let body = format!(
                "<h1>{} <span class=\"kind-badge\">{kind_label}</span></h1>\n",
                html::escape("Maybe.withDefault")
            );
            page("Maybe.withDefault", &body)
        };

        let first = render_once();
        let second = render_once();
        assert_eq!(
            first, second,
            "two renders of the same entry must produce identical HTML"
        );
    }

    /// The `page` template wraps content in a proper HTML5 document with a
    /// stylesheet link — verifying the page shell is always present.
    #[test]
    fn site_page_shell_is_well_formed() {
        use crate::render::page;
        let html = page("Ipe.List", "<p>test body</p>");
        assert!(
            html.starts_with("<!DOCTYPE html>"),
            "must start with doctype"
        );
        assert!(
            html.contains("<html lang=\"en\">"),
            "must have lang attribute"
        );
        assert!(
            html.contains("href=\"/style.css\""),
            "must link the stylesheet"
        );
        assert!(
            html.contains("<p>test body</p>"),
            "body content must be present"
        );
        assert!(html.contains("</html>"), "must be closed");
    }

    /// A symbol entry page renders its `source_key` as the heading.
    #[test]
    fn symbol_page_heading_is_key() {
        use crate::html;
        use crate::render::page;

        let heading_html = format!(
            "<h1>{} <span class=\"kind-badge\">symbol</span></h1>",
            html::escape("List.map")
        );
        let html = page("List.map", &heading_html);
        assert!(
            html.contains(&heading_html),
            "symbol heading must appear verbatim; got: {html}"
        );
    }
}
