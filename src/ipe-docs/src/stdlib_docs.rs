#![forbid(unsafe_code)]
//! Raw-source extraction of stdlib documentation.
//!
//! Two documentation-comment conventions coexist in the embedded `.ipe`
//! stdlib sources:
//!
//! - The block form `{-| … -}` immediately above a declaration. The parser
//!   attaches this to the declaration's `doc` field, so it is available from
//!   the AST.
//! - The line form `-- | …` (with `--` continuation lines) immediately above a
//!   declaration. The parser treats these as ordinary comments and discards
//!   them, so they never reach the AST.
//!
//! Most stdlib modules use the line form, so an AST-only view sees no
//! documented symbols for them. This module recovers both the module-level
//! header comment and each declaration's `-- |` doc block straight from the
//! raw source text, keyed by the declaration name, so the documentation
//! surfaces regardless of which comment style a module happens to use.
//!
//! The extractor never authors prose: it only relays comment text and the
//! `name : Type` signature line exactly as they appear in the source.

use ipe_stdlib::{COMPILED_STD_MODULES, DOC_ONLY_MODULES, MODULES as STDLIB_MODULES};

/// A single documented export of a stdlib module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportDoc {
    /// The export's name within the module (e.g. `sha256`).
    pub name: String,
    /// The `name : Type` signature line as written in the source, when the
    /// declaration carries a type annotation; `None` for a declaration with no
    /// annotation (rare in the stdlib).
    pub signature: Option<String>,
    /// The declaration's documentation body, gathered from either a `{-| … -}`
    /// block or a `-- |` line block. `None` when the declaration is
    /// undocumented.
    pub doc: Option<String>,
}

/// A stdlib module's documentation, extracted from its raw source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleDoc {
    /// The dotted module name, e.g. `Ipe.Http`.
    pub dotted: String,
    /// The short module name with the `Ipe.` prefix stripped, e.g. `Http`.
    pub short: String,
    /// The module-level header documentation (the leading comment block above
    /// the `module` keyword), or `None` when the module has no header comment.
    pub module_doc: Option<String>,
    /// Every top-level declaration the module defines, in source order.
    pub exports: Vec<ExportDoc>,
}

/// Extract documentation for every embedded stdlib module (both the
/// kernel-veneer `MODULES` and the compiled-source `COMPILED_STD_MODULES`),
/// sorted by short module name.
#[must_use]
pub fn all_module_docs() -> Vec<ModuleDoc> {
    let mut out: Vec<ModuleDoc> = Vec::new();

    for m in STDLIB_MODULES {
        out.push(extract_module_doc(m.name, m.source));
    }
    for m in COMPILED_STD_MODULES {
        out.push(extract_module_doc(m.dotted, m.source));
    }
    for m in DOC_ONLY_MODULES {
        out.push(extract_module_doc(m.dotted, m.source));
    }

    out.sort_by(|a, b| a.short.cmp(&b.short));
    // A module may appear in both `MODULES` (kernel veneer) and
    // `COMPILED_STD_MODULES` (compiled source) — e.g. `Ipe.Char`, which shares
    // one embedded source. Emit each short name once.
    out.dedup_by(|a, b| a.short == b.short);
    out
}

/// Extract documentation for one module from its dotted name and raw source.
#[must_use]
pub fn extract_module_doc(dotted: &str, source: &str) -> ModuleDoc {
    let short = dotted.strip_prefix("Ipe.").unwrap_or(dotted).to_owned();
    let module_doc = extract_module_header(source);
    let exports = extract_exports(source);
    ModuleDoc {
        dotted: dotted.to_owned(),
        short,
        module_doc,
        exports,
    }
}

/// Parse the names listed in the module's `exposing ( … )` clause, in source
/// order. Type exports keep just the bare type name (a trailing `(..)` or
/// `(A, B)` constructor spec is dropped). Returns `None` for an `exposing (..)`
/// clause (export-everything) so the caller lists every declaration instead.
fn parse_exposing(source: &str) -> Option<Vec<String>> {
    // Anchor on the `module` keyword at the START of a line: the substring
    // `module ` also appears in prose (e.g. "this module re-exports …") inside
    // the header comment, and `exposing` likewise, so a bare `find` would latch
    // onto the wrong occurrence.
    let module_kw = line_anchored_module_offset(source)?;
    let exposing_kw = source[module_kw..].find("exposing")? + module_kw;
    let open = source[exposing_kw..].find('(')? + exposing_kw;
    // A `--`-to-end-of-line comment may sit between exposed names (section
    // headers inside the list). Mask those comment spans to spaces — keeping
    // byte length so the paren depth counter and comma splitter below see only
    // the real clause, not stray parens or names absorbed from comment text.
    let masked = mask_line_comments(source);
    // Match the closing paren of the exposing clause (it may span lines).
    let mut depth = 0usize;
    let mut close = None;
    for (i, c) in masked[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + i);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close?;
    let inner = &masked[open + 1..close];
    if inner.trim() == ".." {
        return None;
    }

    // Split on top-level commas only (a `Type(A, B)` constructor spec has its
    // own nested parens).
    let mut names: Vec<String> = Vec::new();
    let mut depth = 0usize;
    let mut token = String::new();
    for c in inner.chars() {
        match c {
            '(' => {
                depth += 1;
                token.push(c);
            }
            ')' => {
                depth = depth.saturating_sub(1);
                token.push(c);
            }
            ',' if depth == 0 => {
                push_exposed_name(&mut names, &token);
                token.clear();
            }
            _ => token.push(c),
        }
    }
    push_exposed_name(&mut names, &token);
    Some(names)
}

/// Replace every `--`-to-end-of-line comment with spaces, preserving byte
/// length and newlines so byte offsets into the result still index the
/// original source. Used to keep exposing-clause parsing blind to section
/// comments interleaved in a multi-line `exposing ( … )` list.
fn mask_line_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    for line in source.split_inclusive('\n') {
        match line.find("--") {
            Some(at) => {
                // Everything before the marker stays; the comment (up to but
                // not including any trailing newline) becomes spaces of equal
                // byte width so offsets into the result match the original.
                let (kept, comment) = line.split_at(at);
                out.push_str(kept);
                let trailing_newline = comment.ends_with('\n');
                let body = if trailing_newline {
                    comment.strip_suffix('\n').unwrap_or(comment)
                } else {
                    comment
                };
                for _ in 0..body.len() {
                    out.push(' ');
                }
                if trailing_newline {
                    out.push('\n');
                }
            }
            None => out.push_str(line),
        }
    }
    out
}

/// Byte offset of the `module` declaration keyword — the first line whose
/// first non-whitespace token is `module`. Prose containing the word "module"
/// inside a leading comment is skipped.
fn line_anchored_module_offset(source: &str) -> Option<usize> {
    let mut offset = 0usize;
    for line in source.split_inclusive('\n') {
        if line.trim_start().starts_with("module ") {
            return Some(offset);
        }
        offset += line.len();
    }
    None
}

/// Push the bare exported name from one `exposing` token (dropping any
/// `(..)` / `(A, B)` constructor spec), when the token is non-empty.
fn push_exposed_name(names: &mut Vec<String>, token: &str) {
    let t = token.trim();
    if t.is_empty() {
        return;
    }
    let bare = t.split('(').next().unwrap_or(t).trim();
    if !bare.is_empty() {
        names.push(bare.to_owned());
    }
}

/// Extract the module-level header comment: the block that ends at the last
/// comment line immediately preceding the `module` keyword.
///
/// Both the `-- |`/`--` line form and the `{-| … -}` block form are accepted.
fn extract_module_header(source: &str) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    let module_idx = lines
        .iter()
        .position(|l| l.trim_start().starts_with("module "))?;

    // Prefer a `{-| … -}` block ending just above the `module` line.
    if let Some(doc) = block_doc_ending_before(&lines, module_idx) {
        return Some(doc);
    }

    // Otherwise gather the contiguous run of leading comment lines directly
    // above the `module` keyword (a blank line breaks the run).
    let mut start = module_idx;
    while start > 0 {
        let prev = lines.get(start - 1).map(|l| l.trim_start());
        if prev.is_some_and(|p| p.starts_with("--")) {
            start -= 1;
        } else {
            break;
        }
    }
    if start == module_idx {
        return None;
    }
    gather_line_doc(lines.get(start..module_idx).unwrap_or(&[]))
}

/// Extract the module's exported declarations, in `exposing` order.
///
/// A value export is recognised by a `name : Type` signature line (or, absent
/// that, a `name = …` binding) at column 0; a type export by a `type Name` /
/// `type alias Name` declaration at column 0. Each export carries its
/// signature line (values only) and its documentation body, gathered from the
/// `{-| … -}` or `-- |` comment block immediately above the declaration.
///
/// When the module declares an explicit `exposing ( … )` list, only the listed
/// names are emitted, in list order. A module with `exposing (..)` (none do at
/// present) falls back to every declaration in source order.
fn extract_exports(source: &str) -> Vec<ExportDoc> {
    let lines: Vec<&str> = source.lines().collect();

    // Collect every top-level declaration head, keyed by name, first
    // occurrence wins (a `name : T` signature precedes its `name = …` body).
    let mut decls: std::collections::HashMap<String, ExportDoc> = std::collections::HashMap::new();
    let mut source_order: Vec<String> = Vec::new();

    // Track `{- … -}` block-comment nesting so that a `{-| … -}` doc-block's
    // example code (e.g. `withDefault 0 (Ok 42)` at column 0) is not mistaken
    // for a declaration head.
    let mut block_depth = 0usize;

    for (idx, raw) in lines.iter().enumerate() {
        let inside_block_at_line_start = block_depth > 0;
        block_depth = update_block_depth(block_depth, raw);
        if inside_block_at_line_start {
            continue;
        }

        let Some((name, signature)) = declaration_head(raw) else {
            continue;
        };
        if decls.contains_key(&name) {
            continue;
        }
        let doc = declaration_doc(&lines, idx);
        source_order.push(name.clone());
        decls.insert(
            name.clone(),
            ExportDoc {
                name,
                signature,
                doc,
            },
        );
    }

    // An explicit `exposing ( … )` list drives both membership and order; a
    // module with `exposing (..)` falls back to declaration source order.
    let order = parse_exposing(source).unwrap_or(source_order);
    order
        .into_iter()
        .filter_map(|name| decls.get(&name).cloned())
        .collect()
}

/// Update the running `{- … -}` block-comment nesting depth for one line.
///
/// Scans the line left to right, counting `{-` openers and `-}` closers. A
/// line-comment `--` marker is left alone (it does not open a block); the
/// stdlib never places a `{-` after a `--` on the same line, so a simple
/// left-to-right scan is sufficient here.
fn update_block_depth(mut depth: usize, line: &str) -> usize {
    // Two-character state machine over the bytes: `prev` holds the previous
    // byte only when it could still open (`{`) or close (`-`) a marker. A
    // matched marker consumes both bytes by resetting `prev` to `0`, so
    // `{-}` / `-}-}` cannot be mis-paired.
    let mut prev = 0u8;
    for &b in line.as_bytes() {
        match (prev, b) {
            (b'{', b'-') => {
                depth += 1;
                prev = 0;
            }
            (b'-', b'}') => {
                depth = depth.saturating_sub(1);
                prev = 0;
            }
            _ => prev = b,
        }
    }
    depth
}

/// If `line` begins a top-level declaration at column 0, return its exported
/// name and, for a value signature line, that full `name : Type` signature.
///
/// Recognises `name : Type` (a value signature), `name arg… = …` / `name = …`
/// (a value binding), and `type Name …` / `type alias Name …` (a type
/// declaration). Indented lines are never declaration heads.
fn declaration_head(line: &str) -> Option<(String, Option<String>)> {
    // Column 0 only: a leading space means a continuation / body line.
    if line.starts_with(char::is_whitespace) {
        return None;
    }

    // `type Name …` / `type alias Name …` — the exported name is the type name.
    if let Some(rest) = line.strip_prefix("type ") {
        let rest = rest.strip_prefix("alias ").unwrap_or(rest).trim_start();
        let name = rest
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .next()
            .unwrap_or("");
        if name.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
            // A type declaration has no `name : Type` value signature.
            return Some((name.to_owned(), None));
        }
        return None;
    }

    // Value declarations begin with a lowercase identifier at column 0.
    let first = line.chars().next()?;
    if !first.is_ascii_lowercase() {
        return None;
    }

    let ident_end = line
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
        .map_or(line.len(), |(i, _)| i);
    let name = &line[..ident_end];
    // A reserved word at column 0 never heads a value declaration; any other
    // name (`port`, `where`) is an ordinary value, per the lexer's own table.
    if name.is_empty() || ipe_parse::is_keyword(name) {
        return None;
    }
    let rest = line[ident_end..].trim_start();

    if rest.starts_with(':') {
        // `name : Type` — a signature line. Keep the whole line as the
        // signature text.
        return Some((name.to_owned(), Some(line.trim_end().to_owned())));
    }
    if rest == "="
        || rest.starts_with("= ")
        || rest.starts_with(|c: char| c.is_ascii_alphanumeric())
    {
        // `name = …` or `name arg … = …` — a binding with no separate
        // signature line.
        return Some((name.to_owned(), None));
    }
    None
}

/// The documentation body for the declaration whose head is at `decl_idx`.
///
/// Looks for a `{-| … -}` block or a `-- |` line block ending on the line
/// directly above `decl_idx` (no intervening blank line).
fn declaration_doc(lines: &[&str], decl_idx: usize) -> Option<String> {
    if decl_idx == 0 {
        return None;
    }
    if let Some(doc) = block_doc_ending_before(lines, decl_idx) {
        return Some(doc);
    }

    // A `-- |` line block: the run of comment lines directly above the
    // declaration, provided the run's first line opens with `-- |`. A `-- ──`
    // section-rule line or a blank line breaks the run.
    let mut start = decl_idx;
    while start > 0 {
        let Some(prev) = lines.get(start - 1).map(|l| l.trim_start()) else {
            break;
        };
        if !prev.starts_with("--") {
            break;
        }
        if is_section_rule(prev) {
            break;
        }
        start -= 1;
    }
    if start == decl_idx {
        return None;
    }
    let block = lines.get(start..decl_idx).unwrap_or(&[]);
    // Only treat it as a doc when the block actually opens with `-- |`.
    if !block
        .first()
        .is_some_and(|l| l.trim_start().starts_with("-- |"))
    {
        return None;
    }
    gather_line_doc(block)
}

/// If a `{-| … -}` block closes on the line directly above `idx`, return its
/// body (delimiters stripped, blank-line-separated intervening lines allowed
/// inside the block but not between the block and `idx`).
fn block_doc_ending_before(lines: &[&str], idx: usize) -> Option<String> {
    if idx == 0 {
        return None;
    }
    let close_line = lines.get(idx - 1)?;
    if !close_line.trim_end().ends_with("-}") {
        return None;
    }
    // Walk upward to the `{-|` opener.
    let mut open = idx - 1;
    loop {
        if lines.get(open).is_some_and(|l| l.contains("{-|")) {
            break;
        }
        if open == 0 {
            return None;
        }
        open -= 1;
    }
    let raw = lines.get(open..idx).unwrap_or(&[]).join("\n");
    let body = raw
        .trim_start()
        .strip_prefix("{-|")
        .unwrap_or(&raw)
        .trim_end()
        .strip_suffix("-}")
        .unwrap_or(&raw)
        .trim()
        .to_owned();
    if body.is_empty() { None } else { Some(body) }
}

/// Join a run of `-- |` / `--` comment lines into a documentation body,
/// stripping the leading comment markers and preserving relative structure.
fn gather_line_doc(block: &[&str]) -> Option<String> {
    let mut body_lines: Vec<String> = Vec::new();
    for line in block {
        let t = line.trim_start();
        let stripped = if let Some(rest) = t.strip_prefix("-- |") {
            rest
        } else if let Some(rest) = t.strip_prefix("--") {
            rest
        } else {
            continue;
        };
        // Drop exactly one leading space (the conventional `-- text` gap).
        let stripped = stripped.strip_prefix(' ').unwrap_or(stripped);
        body_lines.push(stripped.trim_end().to_owned());
    }
    // Trim leading/trailing blank lines.
    while body_lines.first().is_some_and(String::is_empty) {
        body_lines.remove(0);
    }
    while body_lines.last().is_some_and(String::is_empty) {
        body_lines.pop();
    }
    let joined = body_lines.join("\n");
    if joined.trim().is_empty() {
        None
    } else {
        Some(joined)
    }
}

/// A `-- ── … ──` (or `-- ---`) section-rule comment: a visual divider, not
/// documentation.
fn is_section_rule(trimmed: &str) -> bool {
    let after = trimmed.trim_start_matches('-').trim_start();
    // A run of box-drawing or dash rule characters after the `--` marker.
    !after.is_empty()
        && after
            .chars()
            .all(|c| c == '─' || c == '-' || c == '=' || c.is_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Non-keyword names such as `port`/`where` are documented values;
    /// every lexer keyword at column 0 is never a declaration head.
    #[test]
    fn declaration_head_uses_the_lexer_keyword_table() {
        for name in ["port", "where", "alias"] {
            let line = format!("{name} : Int");
            assert_eq!(
                declaration_head(&line).map(|(n, _)| n).as_deref(),
                Some(name),
                "{name:?} must head a value declaration"
            );
        }
        for kw in ipe_parse::KEYWORDS {
            let line = format!("{kw} : Int");
            assert!(declaration_head(&line).is_none(), "{kw:?} headed a decl");
        }
    }

    #[test]
    fn line_doc_and_signature_extracted() {
        let src = "\
module Ipe.Demo exposing (foo)

-- | Adds one to `n`.
foo : Int -> Int
foo n = n + 1
";
        let m = extract_module_doc("Ipe.Demo", src);
        assert_eq!(m.short, "Demo");
        let foo = m
            .exports
            .iter()
            .find(|e| e.name == "foo")
            .expect("foo export");
        assert_eq!(foo.signature.as_deref(), Some("foo : Int -> Int"));
        assert_eq!(foo.doc.as_deref(), Some("Adds one to `n`."));
    }

    #[test]
    fn block_depth_tracks_open_and_close() {
        assert_eq!(update_block_depth(0, "{-| doc"), 1);
        assert_eq!(update_block_depth(1, "still inside"), 1);
        assert_eq!(update_block_depth(1, "closes -}"), 0);
        // Open and close on one line nets zero.
        assert_eq!(update_block_depth(0, "{- inline -}"), 0);
        // A stray `}` or `{` alone does not shift depth.
        assert_eq!(update_block_depth(0, "a } b { c"), 0);
    }

    #[test]
    fn block_doc_example_not_mistaken_for_declaration() {
        // The `{-| … -}` doc block contains example code that starts at
        // column 0 with the function name; that must not shadow the real
        // signature line below it.
        let src = "\
module Ipe.Demo exposing (withDefault)

{-| `withDefault fallback result` — the value, or `fallback`.

```ipe
withDefault 0 (Ok 42) --> 42
withDefault 0 (Err e) --> 0
```
-}
withDefault : a -> Result b a -> a
withDefault = Kernel.kernel \"Result_withDefault\"
";
        let m = extract_module_doc("Ipe.Demo", src);
        let wd = m
            .exports
            .iter()
            .find(|e| e.name == "withDefault")
            .expect("withDefault export");
        assert_eq!(
            wd.signature.as_deref(),
            Some("withDefault : a -> Result b a -> a"),
            "the real signature must win over the doc-block example line"
        );
        assert!(
            wd.doc.as_deref().is_some_and(|d| d.contains("fallback")),
            "the block doc must be captured"
        );
    }

    #[test]
    fn exposing_list_with_interleaved_comments() {
        // Section comments interleaved in a multi-line exposing list must not
        // be absorbed into export names or unbalance the paren counter.
        let src = "\
module Ipe.Demo exposing
    ( config
    -- Event constructors (Pii etc.)
    , trackEvent
    , erase
    )

config : Int
config = 0

trackEvent : Int -> Int
trackEvent n = n

erase : Int -> Int
erase n = n
";
        let names = parse_exposing(src).expect("explicit exposing list");
        assert_eq!(names, vec!["config", "trackEvent", "erase"]);
        let m = extract_module_doc("Ipe.Demo", src);
        for want in ["config", "trackEvent", "erase"] {
            assert!(
                m.exports.iter().any(|e| e.name == want),
                "export {want} must survive the interleaved comment"
            );
        }
    }

    #[test]
    fn block_doc_extracted() {
        let src = "\
module Ipe.Demo exposing (foo)

{-| Adds one. -}
foo : Int -> Int
foo n = n + 1
";
        let m = extract_module_doc("Ipe.Demo", src);
        let foo = m.exports.iter().find(|e| e.name == "foo").unwrap();
        assert_eq!(foo.doc.as_deref(), Some("Adds one."));
    }

    #[test]
    fn multiline_line_doc_joined() {
        let src = "\
module Ipe.Demo exposing (foo)

-- | First line.
-- Second line.
foo : Int -> Int
foo n = n
";
        let m = extract_module_doc("Ipe.Demo", src);
        let foo = m.exports.iter().find(|e| e.name == "foo").unwrap();
        assert_eq!(foo.doc.as_deref(), Some("First line.\nSecond line."));
    }

    #[test]
    fn section_rule_breaks_doc_run() {
        let src = "\
module Ipe.Demo exposing (foo)

-- ── Section ────
foo : Int -> Int
foo n = n
";
        let m = extract_module_doc("Ipe.Demo", src);
        let foo = m.exports.iter().find(|e| e.name == "foo").unwrap();
        assert_eq!(foo.doc, None, "a section rule is not documentation");
    }

    #[test]
    fn undocumented_export_still_listed_with_signature() {
        let src = "\
module Ipe.Demo exposing (foo)

foo : Int -> Int
foo n = n
";
        let m = extract_module_doc("Ipe.Demo", src);
        let foo = m.exports.iter().find(|e| e.name == "foo").unwrap();
        assert_eq!(foo.doc, None);
        assert_eq!(foo.signature.as_deref(), Some("foo : Int -> Int"));
    }

    #[test]
    fn module_header_extracted() {
        let src = "\
-- | Ipe.Demo — a demo module.
-- More detail here.
module Ipe.Demo exposing (foo)

foo : Int -> Int
foo n = n
";
        let m = extract_module_doc("Ipe.Demo", src);
        assert_eq!(
            m.module_doc.as_deref(),
            Some("Ipe.Demo — a demo module.\nMore detail here.")
        );
    }

    #[test]
    fn signature_line_not_double_counted_as_binding() {
        let src = "\
module Ipe.Demo exposing (foo)

foo : Int -> Int
foo n = n
";
        let m = extract_module_doc("Ipe.Demo", src);
        let count = m.exports.iter().filter(|e| e.name == "foo").count();
        assert_eq!(count, 1, "signature + binding is one export, not two");
    }

    #[test]
    fn only_exposed_names_are_listed() {
        let src = "\
module Ipe.Demo exposing (public)

-- | Public API.
public : Int -> Int
public n = helper n

-- | Internal helper, not exposed.
helper : Int -> Int
helper n = n
";
        let m = extract_module_doc("Ipe.Demo", src);
        let names: Vec<&str> = m.exports.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["public"], "only exposed names appear");
    }

    #[test]
    fn exposed_names_keep_exposing_order() {
        let src = "\
module Ipe.Demo exposing (beta, alpha)

alpha : Int
alpha = 1

beta : Int
beta = 2
";
        let m = extract_module_doc("Ipe.Demo", src);
        let names: Vec<&str> = m.exports.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["beta", "alpha"], "order follows exposing list");
    }

    #[test]
    fn exposed_types_are_listed() {
        let src = "\
module Ipe.Demo exposing (Shade(..), Config, make)

-- | A colour shade.
type Shade = Light | Dark

-- | Configuration record.
type alias Config = { size : Int }

-- | Build a default config.
make : Config
make = { size = 1 }
";
        let m = extract_module_doc("Ipe.Demo", src);
        let names: Vec<&str> = m.exports.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["Shade", "Config", "make"]);
        let shade = m.exports.iter().find(|e| e.name == "Shade").unwrap();
        assert_eq!(shade.doc.as_deref(), Some("A colour shade."));
        assert_eq!(
            shade.signature, None,
            "a type export has no value signature"
        );
    }

    #[test]
    fn all_real_modules_extract_nonempty() {
        let docs = all_module_docs();
        assert!(docs.len() >= 70, "expected the full stdlib module set");
        // Http uses the `-- |` line style; it must now surface exports.
        let http = docs
            .iter()
            .find(|m| m.short == "Http")
            .expect("Http module present");
        assert!(
            http.exports.iter().any(|e| e.doc.is_some()),
            "Http must surface at least one documented export"
        );
        assert!(
            http.exports.iter().any(|e| e.name == "get"),
            "Http must list its `get` export"
        );

        // A module whose header comment contains the word "module" and an
        // `exposing` example must still parse the real `module … exposing`
        // clause, not the prose occurrence.
        let result = docs
            .iter()
            .find(|m| m.short == "Result")
            .expect("Result module present");
        assert!(
            result.exports.iter().any(|e| e.name == "withDefault"),
            "Result must list `withDefault` (header-prose `module`/`exposing` must not mislead the parser)"
        );
    }

    #[test]
    fn header_prose_module_word_does_not_mislead_exposing() {
        let src = "\
-- | This module re-exports things.
-- `import Ipe.Demo exposing (thing)` works.
module Ipe.Demo exposing (thing)

thing : Int
thing = 1
";
        let names: Vec<String> = parse_exposing(src).expect("explicit exposing list");
        assert_eq!(names, vec!["thing".to_owned()]);
    }
}
