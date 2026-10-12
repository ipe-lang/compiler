#![forbid(unsafe_code)]
//! Static HTML site generator for Ipê documentation.
//!
//! Emits a self-contained HTML tree under `<out-dir>/`:
//!
//! ```text
//! <out-dir>/
//!   index.html          — top-level navigation page
//!   style.css           — shared stylesheet
//!   symbol/<key>/index.html   — per-symbol / per-module pages
//!   diagnostic/<code>/index.html
//!   construct/<name>/index.html
//!   command/<name>/index.html
//!   env-var/<name>/index.html
//! ```
//!
//! Every code snippet is syntax-highlighted by feeding it through
//! [`ipe_annotate::annotate_syntax_only`]; names with a [`DefKey`] link to
//! the target page.  No hand-rolled tokenizer or linker is involved.
//!
//! ## Usage
//!
//! ```text
//! gen_site <out-dir> <explain-dir> <content-dir>
//! ```
//!
//! - `<out-dir>`: where the HTML tree is written (created if absent)
//! - `<explain-dir>`: path to `src/compiler/diagnostics/explain/`
//! - `<content-dir>`: path to `docs/constructs/`
//!
//! ## Follow-up
//!
//! `ipe doc serve` (component E) will add a lightweight HTTP server that
//! serves the generated tree locally; that subcommand lands with component E.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ipe_docs::html;
use ipe_docs::render::{STYLESHEET, highlight_snippet, page};
use ipe_docs::{Entry, EntryKind, Index};

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<(), String> {
    let args = ipe_docs::argv::host_args().map_err(|e| e.to_string())?;
    let (out_dir, explain_dir, content_dir) = parse_args(&args)?;

    // No commands are known from this binary's context; the caller (ipe CLI)
    // would inject them.  The binary accepts an optional fourth argument with
    // a colon-separated list of `name=summary` pairs for testing; omit in
    // production.
    let commands = parse_commands(args.get(3).map(String::as_str));

    let index = Index::build(&explain_dir, &content_dir, &commands)
        .map_err(|e| format!("index build failed: {e}"))?;

    generate(&index, &out_dir)
}

// ── Argument parsing ──────────────────────────────────────────────────────────

fn parse_args(args: &[String]) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    match args {
        [out, explain, content] | [out, explain, content, _] => Ok((
            PathBuf::from(out),
            PathBuf::from(explain),
            PathBuf::from(content),
        )),
        _ => Err("usage: gen_site <out-dir> <explain-dir> <content-dir> [commands]".to_owned()),
    }
}

/// Parse an optional colon-separated `name=summary` list into `CommandInfo`
/// structs.  Used by tests and the CLI wrapper; the format is
/// `build=Compile a program:version=Print the version`.
fn parse_commands(raw: Option<&str>) -> Vec<ipe_docs::CommandInfo> {
    let Some(s) = raw else {
        return Vec::new();
    };
    s.split(':')
        .filter_map(|pair| {
            let (name, summary) = pair.split_once('=')?;
            // Leak the name into 'static so `CommandInfo::name` is satisfied.
            let name: &'static str = Box::leak(name.to_owned().into_boxed_str());
            Some(ipe_docs::CommandInfo {
                name,
                help: summary.to_owned(),
            })
        })
        .collect()
}

// ── Site generation ───────────────────────────────────────────────────────────

fn generate(index: &Index, out_dir: &Path) -> Result<(), String> {
    create_dir_all(out_dir)?;

    // Emit stylesheet.
    write_file(&out_dir.join("style.css"), STYLESHEET)?;

    // Collect entries by kind for the index page.
    let mut modules: Vec<&Entry> = Vec::new();
    let mut symbols: Vec<&Entry> = Vec::new();
    let mut diagnostics: Vec<&Entry> = Vec::new();
    let mut constructs: Vec<&Entry> = Vec::new();
    let mut commands: Vec<&Entry> = Vec::new();
    let mut env_vars: Vec<&Entry> = Vec::new();

    for key in sorted_keys(index) {
        let Some(entry) = index.resolve(key) else {
            continue;
        };
        match entry.kind {
            EntryKind::Module => modules.push(entry),
            EntryKind::Symbol => symbols.push(entry),
            EntryKind::Diagnostic => diagnostics.push(entry),
            EntryKind::Construct => constructs.push(entry),
            EntryKind::Command => commands.push(entry),
            EntryKind::EnvVar => env_vars.push(entry),
        }
        // Emit the per-entry page.
        emit_entry_page(out_dir, key, entry)?;
    }

    // Emit the index page.
    let index_html = render_index(
        &modules,
        &symbols,
        &diagnostics,
        &constructs,
        &commands,
        &env_vars,
    );
    write_file(&out_dir.join("index.html"), &page("Index", &index_html))?;

    Ok(())
}

/// Collect all index keys in deterministic order (sorted).
fn sorted_keys<'i>(index: &'i Index) -> Vec<&'i str> {
    let mut keys: Vec<&'i str> = index.keys().collect();
    keys.sort_unstable();
    keys
}

// ── Per-entry page emission ───────────────────────────────────────────────────

fn emit_entry_page(out_dir: &Path, key: &str, entry: &Entry) -> Result<(), String> {
    let page_dir = out_dir.join(entry.kind.route_subdir()).join(key);
    create_dir_all(&page_dir)?;
    let html = render_entry(key, entry);
    write_file(&page_dir.join("index.html"), &page(key, &html))
}

// ── Entry renderer ────────────────────────────────────────────────────────────

/// Render the body HTML for a single entry page.
fn render_entry(key: &str, entry: &Entry) -> String {
    let kind_label = kind_label(&entry.kind);
    let mut body = format!(
        "<h1>{} <span class=\"kind-badge\">{kind_label}</span></h1>\n",
        html::escape(key)
    );

    // Body text: highlight fenced ipe blocks, escape everything else.
    body.push_str(&render_text(&entry.text));

    body
}

/// Render an entry's raw text, highlighting ```` ```ipe ```` fenced blocks.
///
/// Sections between fenced blocks are rendered as escaped plain text wrapped
/// in `<p>` tags.
fn render_text(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    let mut remaining = text;

    loop {
        // Find the opening fence.
        let Some(open_pos) = remaining.find("```ipe") else {
            // No more fences — emit the rest as prose.
            emit_prose(&mut out, remaining);
            break;
        };

        // Emit prose before the fence.
        emit_prose(&mut out, &remaining[..open_pos]);

        // Advance past the opening fence line.
        let after_open = &remaining[open_pos + "```ipe".len()..];
        let code_start = after_open.find('\n').map_or(0, |n| n + 1);
        let code_body = &after_open[code_start..];

        // Find the closing fence.
        if let Some(close_pos) = code_body.find("```") {
            let snippet = &code_body[..close_pos];
            out.push_str("<pre>");
            out.push_str(&highlight_snippet(snippet));
            out.push_str("</pre>\n");
            remaining = &code_body[close_pos + "```".len()..];
            // Skip optional trailing newline after closing fence.
            remaining = remaining.strip_prefix('\n').unwrap_or(remaining);
        } else {
            // Unclosed fence — emit the rest as prose.
            emit_prose(&mut out, remaining);
            break;
        }
    }

    out
}

/// Emit `text` as escaped prose paragraphs, split on blank lines.
fn emit_prose(out: &mut String, text: &str) {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return;
    }
    // Split on blank lines to produce paragraphs.
    for paragraph in trimmed.split("\n\n") {
        let p = paragraph.trim();
        if !p.is_empty() {
            out.push_str("<p>");
            out.push_str(&html::escape(p));
            out.push_str("</p>\n");
        }
    }
}

// ── Index page ────────────────────────────────────────────────────────────────

fn render_index(
    modules: &[&Entry],
    symbols: &[&Entry],
    diagnostics: &[&Entry],
    constructs: &[&Entry],
    commands: &[&Entry],
    env_vars: &[&Entry],
) -> String {
    let mut out = String::from("<h1>Ipê documentation</h1>\n");

    // Sections in fixed presentation order. Every list item links to
    // `/<route_subdir>/<source_key>/`, so each entry's kind is the single
    // source of its URL prefix — no hard-coded path fragment lives here.
    render_index_section(&mut out, "Modules", modules, ListStyle::Name);
    render_index_section(&mut out, "Language constructs", constructs, ListStyle::Name);
    render_index_section(&mut out, "Diagnostics", diagnostics, ListStyle::Name);
    render_index_section(&mut out, "CLI commands", commands, ListStyle::NameSummary);
    render_index_section(&mut out, "Environment variables", env_vars, ListStyle::Name);
    render_index_section(&mut out, "Symbols", symbols, ListStyle::Name);

    out
}

/// Whether an index list item shows only the name or `name: summary`.
#[derive(Clone, Copy)]
enum ListStyle {
    Name,
    NameSummary,
}

/// Emit one `<h2>` + `<ul>` index section, or nothing when `entries` is empty.
fn render_index_section(out: &mut String, title: &str, entries: &[&Entry], style: ListStyle) {
    if entries.is_empty() {
        return;
    }
    let _ = writeln!(
        out,
        "<h2>{}</h2>\n<ul class=\"index-list\">",
        html::escape(title)
    );
    for e in entries {
        let subdir = e.kind.route_subdir();
        let key = &e.source_key;
        let href = html::escape(&format!("/{subdir}/{key}/"));
        let name = html::escape(key);
        match style {
            ListStyle::Name => {
                let _ = writeln!(out, "<li><a href=\"{href}\">{name}</a></li>");
            }
            ListStyle::NameSummary => {
                let summary = html::escape(&e.text);
                let _ = writeln!(out, "<li><a href=\"{href}\">{name}: {summary}</a></li>");
            }
        }
    }
    out.push_str("</ul>\n");
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const fn kind_label(kind: &EntryKind) -> &'static str {
    match kind {
        EntryKind::Symbol => "symbol",
        EntryKind::Module => "module",
        EntryKind::Diagnostic => "diagnostic",
        EntryKind::Construct => "construct",
        EntryKind::Command => "command",
        EntryKind::EnvVar => "env-var",
    }
}

fn create_dir_all(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path)
        .map_err(|e| format!("cannot create directory {}: {e}", path.display()))
}

fn write_file(path: &Path, content: &str) -> Result<(), String> {
    std::fs::write(path, content).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use ipe_docs::{Entry, EntryKind};

    use super::{ListStyle, render_index_section};

    /// A key or title holding markup cannot close the `href` attribute or open
    /// a tag in the index list.
    #[test]
    fn index_section_escapes_key_in_href_and_title() {
        let entry = Entry {
            kind: EntryKind::Construct,
            source_key: "a\"b".to_owned(),
            text: String::new(),
        };
        let mut out = String::new();
        render_index_section(&mut out, "x<y", &[&entry], ListStyle::Name);
        assert!(out.contains("<h2>x&lt;y</h2>"), "{out}");
        assert!(out.contains("href=\"/construct/a&quot;b/\""), "{out}");
        assert!(!out.contains("a\"b"), "{out}");
    }
}
