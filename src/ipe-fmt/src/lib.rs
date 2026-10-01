//! The Ipê source formatter engine.
//!
//! Parses a `.ipe` source string into an [`ipe_syntax::Module`] via
//! [`ipe_parse::parse_module`] and pretty-prints it in canonical (elm-format
//! style) form. The single public entry point is [`format_source`]; the CLI
//! `ipe fmt` command and the LSP formatting provider both drive it, so one
//! engine — comment-preserving and semantics-guarded — serves both.
//!
//! The engine is path-agnostic: it works on a bare source string and reports a
//! typed [`FmtError`]. A caller that knows the file (the CLI) attaches the path
//! at its own boundary.

use std::fmt;
use std::fmt::Write as _;

use ipe_diagnostics::{Diagnostic, Located, render};
use ipe_intern::Interner;
use ipe_syntax::{
    Ctor, Exposed, Exposing, Expr, Expr_, Import, LetBinding, Module, Pattern, Pattern_, Privacy,
    TypeAlias, TypeAnnotation, Union, Value,
};

/// The column budget elm-format targets before breaking a construct onto
/// multiple lines.
const MAX_WIDTH: usize = 80;

/// A formatter-level error.
///
/// Path-agnostic: the engine operates on a source string and never sees a file
/// path. A caller that knows the file (the CLI) renders these with the real
/// path; [`RoundTrip`](Self::RoundTrip) also models the `--check` "unformatted"
/// outcome the CLI surfaces.
#[derive(Debug)]
pub enum FmtError {
    /// The source could not be parsed — formatting a syntactically invalid file
    /// would risk changing its meaning, so the formatter refuses.
    Parse { src: String, diag: Diagnostic },
    /// The formatter's own output failed to re-parse or did not round-trip to
    /// the same AST — a formatter bug, surfaced rather than written to disk.
    RoundTrip { detail: String },
}

impl fmt::Display for FmtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse { src, diag } => f.write_str(&render(diag, "<source>", src)),
            Self::RoundTrip { detail } => {
                write!(f, "ipe fmt: internal error while formatting: {detail}")
            }
        }
    }
}
// ---------------------------------------------------------------------------
// Comment scanning
// ---------------------------------------------------------------------------

/// A source comment recovered by [`scan_comments`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct Comment {
    /// Byte offset of the comment's first character.
    lo: usize,
    /// The comment text VERBATIM (including the `--` / `{- -}` delimiters, with
    /// no trailing newline). A line comment keeps any interior spacing; a block
    /// comment keeps its full multi-line body.
    text: String,
    /// A line comment (`-- …`) versus a block comment (`{- … -}`). A line
    /// comment always occupies its own emitted line; a block comment likewise
    /// prints on its own line(s) in this core.
    line: bool,
}

/// Recover every comment in `src`, in source order.
///
/// This reproduces the comment shapes `ipe_parse`'s lexer `skip_trivia`
/// recognises — `-- …` to end of line, and nestable `{- … -}` — but keeps their
/// text and position instead of discarding them. It skips over string and
/// character literals so a `--` inside `"a--b"` or a `{-` inside a string is not
/// mistaken for a comment (parity with the lexer, which lexes strings before it
/// can see trivia inside them).
fn scan_comments(src: &str) -> Vec<Comment> {
    let chars: Vec<(usize, char)> = src.char_indices().collect();
    let mut i = 0usize;
    let mut out = Vec::new();
    let peek = |i: usize| chars.get(i).map(|&(_, c)| c);
    // Byte offset of the char at index `i`, or `src.len()` at end of input.
    let offset = |i: usize| chars.get(i).map_or(src.len(), |&(o, _)| o);
    while let Some(&(_, c)) = chars.get(i) {
        match c {
            '"' => {
                // Skip a string literal (single- or triple-quoted).
                if peek(i + 1) == Some('"') && peek(i + 2) == Some('"') {
                    i += 3;
                    while i < chars.len() {
                        if peek(i) == Some('"')
                            && peek(i + 1) == Some('"')
                            && peek(i + 2) == Some('"')
                        {
                            i += 3;
                            break;
                        }
                        i += 1;
                    }
                } else {
                    i += 1;
                    while i < chars.len() {
                        match peek(i) {
                            Some('\\') => i += 2,
                            Some('"') => {
                                i += 1;
                                break;
                            }
                            Some(_) => i += 1,
                            None => break,
                        }
                    }
                }
            }
            '\'' => {
                // Skip a character literal `'x'` / `'\n'`.
                i += 1;
                while i < chars.len() {
                    match peek(i) {
                        Some('\\') => i += 2,
                        Some('\'') => {
                            i += 1;
                            break;
                        }
                        Some(_) => i += 1,
                        None => break,
                    }
                }
            }
            '-' if peek(i + 1) == Some('-') => {
                let lo = offset(i);
                let mut text = String::new();
                while let Some(ch) = peek(i) {
                    if ch == '\n' {
                        break;
                    }
                    text.push(ch);
                    i += 1;
                }
                // Trim trailing whitespace so re-emission is idempotent.
                let trimmed = text.trim_end().to_owned();
                out.push(Comment {
                    lo,
                    text: trimmed,
                    line: true,
                });
            }
            '{' if peek(i + 1) == Some('-') => {
                let lo = offset(i);
                let mut text = String::new();
                let mut depth = 0u32;
                while let Some(ch) = peek(i) {
                    if ch == '{' && peek(i + 1) == Some('-') {
                        text.push('{');
                        text.push('-');
                        depth += 1;
                        i += 2;
                    } else if ch == '-' && peek(i + 1) == Some('}') {
                        text.push('-');
                        text.push('}');
                        depth = depth.saturating_sub(1);
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        text.push(ch);
                        i += 1;
                    }
                }
                out.push(Comment {
                    lo,
                    text,
                    line: false,
                });
            }
            _ => i += 1,
        }
    }
    out
}

/// Strip a leading run of `(`, whitespace, and comments (line or nestable
/// block) from `text`, mirroring the lexer's `skip_trivia` shapes.
///
/// Used to look past a `do` block's opening parens for its keyword even when
/// a comment sits between them — the same trivia a comment-free `(  do …)`
/// already tolerates via whitespace alone.
fn skip_paren_trivia(mut text: &str) -> &str {
    loop {
        let stripped = text.trim_start_matches(|c: char| c == '(' || c.is_whitespace());
        if let Some(rest) = stripped.strip_prefix("--") {
            let line_end = rest.find('\n').map_or(rest.len(), |i| i + 1);
            text = rest.get(line_end..).unwrap_or_default();
            continue;
        }
        if let Some(rest) = stripped.strip_prefix("{-") {
            text = skip_block_comment_body(rest);
            continue;
        }
        return stripped;
    }
}

/// Skip a nestable block comment's body, already past its opening `{-`, and
/// return what follows the matching `-}` (or the input's end, if unterminated
/// — malformed input the parser will itself refuse, so any position is safe).
fn skip_block_comment_body(mut rest: &str) -> &str {
    let mut depth = 1u32;
    while depth > 0 {
        if let Some(after) = rest.strip_prefix("{-") {
            depth += 1;
            rest = after;
        } else if let Some(after) = rest.strip_prefix("-}") {
            depth -= 1;
            rest = after;
        } else {
            let mut chars = rest.chars();
            if chars.next().is_none() {
                break;
            }
            rest = chars.as_str();
        }
    }
    rest
}

// ---------------------------------------------------------------------------
// The formatter entry point
// ---------------------------------------------------------------------------

/// Format one `.ipe` source string into canonical style.
///
/// # Errors
/// [`FmtError::Parse`] if `src` does not parse; [`FmtError::RoundTrip`] if the
/// formatted output does not re-parse to the same AST (a formatter bug — caught
/// rather than written).
pub fn format_source(src: &str) -> Result<String, FmtError> {
    let mut interner = Interner::new();
    let module = ipe_parse::parse_module(src, &mut interner).map_err(|diag| FmtError::Parse {
        src: src.to_owned(),
        diag,
    })?;
    let comments = scan_comments(src);

    let p = Printer {
        interner: &interner,
        comments: &comments,
        src: Some(src),
        emitted: std::cell::RefCell::new(std::collections::HashSet::new()),
    };
    let out = p.module(&module);

    // Comment-count guard: the formatted output must not drop any comments.
    // This fires BEFORE the AST equivalence check so a comment-dropping bug
    // surfaces as a clear "comment lost" message rather than an AST mismatch.
    let input_count = comments.len();
    let output_comments = scan_comments(&out);
    let output_count = output_comments.len();
    if output_count < input_count {
        return Err(FmtError::RoundTrip {
            detail: format!(
                "formatter dropped comments: input had {input_count}, output has {output_count}"
            ),
        });
    }

    // Semantics guard: the formatted output must re-parse to the same AST.
    let mut verify_interner = Interner::new();
    match ipe_parse::parse_module(&out, &mut verify_interner) {
        Ok(reparsed) => {
            if !modules_equivalent(&module, &interner, &reparsed, &verify_interner) {
                return Err(FmtError::RoundTrip {
                    detail: "formatted output parsed to a different AST".to_owned(),
                });
            }
        }
        Err(diag) => {
            return Err(FmtError::RoundTrip {
                detail: format!("formatted output did not re-parse: {diag:?}"),
            });
        }
    }
    Ok(out)
}

/// Format `src` WITHOUT the round-trip semantics guard. Test-only: lets a test
/// inspect the raw printer output even when the guard would reject it, so a
/// divergence can be localised rather than hidden behind a compiler-bug error.
#[cfg(test)]
pub(crate) fn format_source_unchecked(src: &str) -> Result<String, FmtError> {
    let mut interner = Interner::new();
    let module = ipe_parse::parse_module(src, &mut interner).map_err(|diag| FmtError::Parse {
        src: src.to_owned(),
        diag,
    })?;
    let comments = scan_comments(src);
    let p = Printer {
        interner: &interner,
        comments: &comments,
        src: Some(src),
        emitted: std::cell::RefCell::new(std::collections::HashSet::new()),
    };
    Ok(p.module(&module))
}

/// Compare two modules parsed with (possibly different) interners for
/// structural equivalence, resolving symbols to their strings so that a
/// different interning ORDER between the two parses does not read as a
/// difference. Spans are ignored throughout.
fn modules_equivalent(a: &Module, ai: &Interner, b: &Module, bi: &Interner) -> bool {
    ModuleText::of(a, ai) == ModuleText::of(b, bi)
}

/// A fully symbol-resolved, span-free projection of a module, used only for the
/// round-trip equivalence check. Deriving `PartialEq`/`Eq` on this gives a
/// structural comparison that is immune to interning-order and span drift.
#[derive(PartialEq, Debug)]
struct ModuleText(String);

impl ModuleText {
    fn of(m: &Module, i: &Interner) -> Self {
        // Reuse the printer with an EMPTY comment set: the projection is a
        // canonical string form, and two ASTs are equivalent iff their
        // comment-free canonical forms are byte-identical. (Comments are checked
        // separately by the comment-preservation test, not by this guard.)
        let no_comments: Vec<Comment> = Vec::new();
        let p = Printer {
            interner: i,
            comments: &no_comments,
            src: None,
            emitted: std::cell::RefCell::new(std::collections::HashSet::new()),
        };
        Self(p.module(m))
    }
}

// ---------------------------------------------------------------------------
// The printer
// ---------------------------------------------------------------------------

struct Printer<'a> {
    interner: &'a Interner,
    comments: &'a [Comment],
    /// The original source text, used to recover elm-format's MODAL layout
    /// decision: a list / record / tuple / union that spanned more than one
    /// line in the source stays multi-line even when it would fit, and one that
    /// was single-line stays single-line when it fits. `None` in the round-trip
    /// equivalence guard, where a purely width-driven canonical form is wanted
    /// (the guard compares STRUCTURE, so it must not depend on original layout).
    src: Option<&'a str>,
    /// Start offsets of comments already emitted. A comment recovered in an
    /// inner gap (a `let`/`case`/annotation node) must never be re-emitted by an
    /// overlapping outer range (the module-trailing pass claims everything after
    /// the last declaration's span, which underestimates a body that ends in a
    /// nested comment). Consuming on emit makes the print-each-comment-exactly-once
    /// invariant hold by construction rather than by span accuracy.
    emitted: std::cell::RefCell<std::collections::HashSet<usize>>,
}

impl Printer<'_> {
    fn sym(&self, s: ipe_intern::Symbol) -> String {
        self.interner.resolve(s).unwrap_or("?").to_owned()
    }

    /// Whether the node at `span` occupied more than one line in the original
    /// source — elm-format's modal multi-line trigger. Always `false` when no
    /// source is threaded (the equivalence guard's width-only mode).
    fn was_multiline(&self, span: ipe_diagnostics::Span) -> bool {
        let Some(src) = self.src else { return false };
        let lo = span.lo as usize;
        let hi = (span.hi as usize).min(src.len());
        if lo >= hi {
            return false;
        }
        src.get(lo..hi).is_some_and(has_layout_newline)
    }

    fn dotted(&self, segs: &[ipe_intern::Symbol]) -> String {
        segs.iter()
            .map(|s| self.sym(*s))
            .collect::<Vec<_>>()
            .join(".")
    }

    /// Render a whole module.
    fn module(&self, m: &Module) -> String {
        let mut out = String::new();

        // Any comment before the module header prints first, on its own
        // line(s). elm-format then separates the comment block from the header
        // with exactly two blank lines, however the source spaced them.
        let header_lo = usize::try_from(m.name.span.lo).unwrap_or(0);
        let pre_header = self.comments_before(0, header_lo);
        if !pre_header.is_empty() {
            for c in &pre_header {
                out.push_str(&c.text);
                out.push('\n');
            }
            out.push_str("\n\n");
        }

        // module <Name> exposing (…)
        out.push_str("module ");
        out.push_str(&self.dotted(&m.name.value));
        out.push_str(&self.module_exposing(&m.exposing));
        out.push('\n');

        // A module documentation comment (or any comment) written between the
        // header and the first import belongs *above* the import block, not
        // attached to the first declaration. Bound it by the earliest import
        // start (or the first declaration when there are no imports).
        let first_import_lo = m.imports.iter().map(|imp| imp.name.span.lo as usize).min();
        let header_end = usize::try_from(m.name.span.hi).unwrap_or(header_lo);
        let mut consumed_hi = header_end;
        if let Some(imp_lo) = first_import_lo {
            let between = self.comments_before(header_end, imp_lo);
            if !between.is_empty() {
                out.push('\n');
                for c in &between {
                    out.push_str(&c.text);
                    out.push('\n');
                }
                consumed_hi = imp_lo;
            }
        }

        // Import block: elm-format sorts imports by module path and prints them
        // directly under the header (one blank line separates the header from
        // the first import only when imports exist).
        if !m.imports.is_empty() {
            out.push('\n');
            let mut imports: Vec<&Import> = m.imports.iter().collect();
            imports.sort_by_key(|imp| self.dotted(&imp.name.value));
            for imp in imports {
                out.push_str(&self.import(imp));
                out.push('\n');
            }
            consumed_hi = m
                .imports
                .iter()
                .map(|imp| imp.name.span.hi as usize)
                .max()
                .unwrap_or(consumed_hi)
                .max(consumed_hi);
        }

        // Declarations in source order, each separated by a blank line and each
        // preceded by two blank lines from the imports (elm-format's top-level
        // spacing). We interleave unions / aliases / values by their span order.
        let mut decls: Vec<Decl<'_>> = Vec::new();
        for u in &m.unions {
            decls.push(Decl::Union(u));
        }
        for a in &m.aliases {
            decls.push(Decl::Alias(a));
        }
        for v in &m.values {
            decls.push(Decl::Value(v));
        }
        decls.sort_by_key(Decl::lo);

        for decl in &decls {
            // elm-format: two blank lines before every top-level declaration.
            out.push('\n');
            out.push('\n');
            // Leading comments attach to the declaration they precede. The
            // floor is raised past anything already emitted above the imports
            // (a module doc comment) so it is not repeated here.
            let decl_lo = decl.lo() as usize;
            let prev_hi = decls_prev_hi(&decls, decl).max(consumed_hi);
            for c in self.comments_before(prev_hi, decl_lo) {
                out.push_str(&c.text);
                out.push('\n');
            }
            out.push_str(&self.decl(decl));
            out.push('\n');
        }

        // Trailing comments after the last declaration.
        let last_hi = decls
            .iter()
            .map(|d| d.hi() as usize)
            .max()
            .unwrap_or(header_lo);
        let trailing = self.comments_before(last_hi, usize::MAX);
        if !trailing.is_empty() {
            out.push('\n');
            for c in trailing {
                out.push_str(&c.text);
                out.push('\n');
            }
        }

        // A formatted file ends with exactly one trailing newline (POSIX text
        // file, no trailing blank lines) — the fixed-point invariant.
        while out.ends_with("\n\n") {
            out.pop();
        }
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out
    }

    /// Comments whose start offset lies in the half-open range `[after, before)`
    /// and have not already been emitted. Returned comments are marked emitted,
    /// so a later overlapping range (the module-trailing pass over everything
    /// after the last declaration span) cannot print them a second time — the
    /// print-each-comment-exactly-once invariant. Inner gaps are visited before
    /// the trailing pass, so a comment nested in a `let`/`case` body is claimed
    /// at its correct site and skipped by the outer range.
    fn comments_before(&self, after: usize, before: usize) -> Vec<&Comment> {
        let mut emitted = self.emitted.borrow_mut();
        self.comments
            .iter()
            .filter(|c| c.lo >= after && c.lo < before && emitted.insert(c.lo))
            .collect()
    }

    fn exposing(&self, e: &Exposing) -> String {
        match e {
            Exposing::All => "(..)".to_owned(),
            Exposing::List(items) => {
                let parts: Vec<String> = items.iter().map(|it| self.exposed(&it.value)).collect();
                format!("({})", parts.join(", "))
            }
        }
    }

    /// The module header's ` exposing (…)` clause. elm-format's breaking here is
    /// *modal* (like signatures): a header written on one line stays single-line
    /// however wide, and one written across multiple lines keeps its layout —
    /// `exposing` alone on the header line, then a four-space-indented
    /// leading-comma block. Within that block elm-format preserves the SOURCE
    /// GROUPING: exposed items that shared a source line stay on one line, so
    /// the `@docs`-section grouping survives a reformat. The grouping is
    /// recovered from each item's span line.
    fn module_exposing(&self, e: &Located<Exposing>) -> String {
        let items = match &e.value {
            Exposing::All => return " exposing (..)".to_owned(),
            Exposing::List(items) => items,
        };
        // The clause is multi-line iff its items do not all begin on the same
        // source line (a lone `(` or `)` line does not make it multi-line).
        let multiline = items
            .first()
            .zip(items.last())
            .is_some_and(|(a, b)| self.line_of(a.span.lo) != self.line_of(b.span.lo));
        if !multiline || items.is_empty() {
            return format!(" exposing {}", self.exposing(&e.value));
        }
        // Group consecutive items that began on the same source line.
        let mut groups: Vec<Vec<String>> = Vec::new();
        let mut cur_line: Option<usize> = None;
        for it in items {
            let line = self.line_of(it.span.lo);
            let rendered = self.exposed(&it.value);
            if let (Some(g), true) = (groups.last_mut(), Some(line) == cur_line) {
                g.push(rendered);
                continue;
            }
            cur_line = Some(line);
            groups.push(vec![rendered]);
        }
        let mut out = String::from(" exposing\n");
        for (i, g) in groups.iter().enumerate() {
            let lead = if i == 0 { "    ( " } else { "    , " };
            let _ = writeln!(out, "{lead}{}", g.join(", "));
        }
        out.push_str("    )");
        out
    }

    /// The 1-based source line containing byte offset `pos` (0 when no source is
    /// threaded, as in the round-trip guard).
    fn line_of(&self, pos: u32) -> usize {
        let Some(src) = self.src else { return 0 };
        let pos = (pos as usize).min(src.len());
        src.get(..pos)
            .map_or(0, |s| s.bytes().filter(|&b| b == b'\n').count())
    }

    fn exposed(&self, e: &Exposed) -> String {
        match e {
            Exposed::Value(s) | Exposed::Type(s, Privacy::Private) => self.sym(*s),
            Exposed::Type(s, Privacy::Public) => format!("{}(..)", self.sym(*s)),
            Exposed::Type(s, Privacy::PublicCtors(ctors)) => {
                let cs: Vec<String> = ctors.iter().map(|c| self.sym(*c)).collect();
                format!("{}({})", self.sym(*s), cs.join(", "))
            }
        }
    }

    fn import(&self, imp: &Import) -> String {
        let mut s = format!("import {}", self.dotted(&imp.name.value));
        if let Some(alias) = imp.alias {
            let _ = write!(s, " as {}", self.sym(alias));
        }
        match &imp.exposing.value {
            Exposing::List(items) if items.is_empty() => {}
            Exposing::All => s.push_str(" exposing (..)"),
            Exposing::List(_) => {
                s.push_str(" exposing ");
                s.push_str(&self.exposing(&imp.exposing.value));
            }
        }
        s
    }

    fn decl(&self, d: &Decl<'_>) -> String {
        match d {
            Decl::Union(u) => self.union(u),
            Decl::Alias(a) => self.alias(&a.value),
            Decl::Value(v) => self.value(&v.value),
        }
    }

    /// The ` a b c` type-parameter suffix of a `type` / `type alias` head — a
    /// leading space before each variable, empty when there are none.
    fn type_vars(&self, vars: &[Located<ipe_intern::Symbol>]) -> String {
        let mut s = String::new();
        for v in vars {
            s.push(' ');
            s.push_str(&self.sym(v.value));
        }
        s
    }

    /// `type Name vars = A | B c | …` — leading-pipe multiline when it does not
    /// fit, matching elm-format (each constructor on its own line, four-space
    /// indented, aligned `= …` / `| …`).
    fn union(&self, u: &Located<Union>) -> String {
        let uv = &u.value;
        let vars = self.type_vars(&uv.vars);
        // elm-format ALWAYS breaks a union declaration onto multiple lines —
        // the `= Ctor` sits on its own four-space-indented line, and every
        // subsequent constructor is a leading-`|` continuation line — even when
        // there is a single constructor. There is no single-line union form.
        let mut s = format!("type {}{}", self.sym(uv.name.value), vars);
        // A section comment written between two constructors annotates the
        // constructor it precedes: re-emit it on its own four-space-indented
        // line just before that constructor's `| Ctor` line, keeping the
        // author's grouping inside the type. The gap before the FIRST
        // constructor runs from the type name's end; each later gap runs from
        // the previous constructor's end; a comment after the last constructor
        // (still inside the union span) trails on its own line.
        let mut gap_lo = uv.name.span.hi as usize;
        for (idx, c) in uv.ctors.iter().enumerate() {
            let lead = if idx == 0 { "=" } else { "|" };
            for cm in self.comments_before(gap_lo, c.span.lo as usize) {
                let _ = write!(s, "\n    {}", cm.text);
            }
            let _ = write!(s, "\n    {lead} {}", self.ctor(&c.value));
            gap_lo = c.span.hi as usize;
        }
        for cm in self.comments_before(gap_lo, u.span.hi as usize) {
            let _ = write!(s, "\n    {}", cm.text);
        }
        s
    }

    fn ctor(&self, c: &Ctor) -> String {
        if c.args.is_empty() {
            self.sym(c.name)
        } else {
            let args: Vec<String> = c.args.iter().map(|a| self.type_atom(a)).collect();
            format!("{} {}", self.sym(c.name), args.join(" "))
        }
    }

    /// `type alias Name vars = T` — the body goes on the next line, four-space
    /// indented, matching elm-format.
    fn alias(&self, a: &TypeAlias) -> String {
        let vars = self.type_vars(&a.vars);
        // A record alias body honours elm-format's modal multi-line trigger:
        // if the source wrote the record across multiple lines, keep it broken.
        let body = match &a.body.value {
            TypeAnnotation::TRecord(fields) => {
                self.type_record(fields, 1, self.was_multiline(a.body.span))
            }
            other => self.type_annotation(other, 1),
        };
        // Comments written between the `=` sign and the body type live in the
        // gap [head_hi, body.span.lo), where `head_hi` is the end of the last
        // type-variable token (or the name itself when there are no vars).
        // Using the last var's hi rather than the name's hi avoids accidentally
        // pulling in a comment that sits between two var tokens.
        let head_hi = a.vars.last().map_or(a.name.span.hi, |v| v.span.hi) as usize;
        let body_lo = a.body.span.lo as usize;
        let mut pre_body = String::new();
        for c in self.comments_before(head_hi, body_lo) {
            pre_body.push_str(&c.text);
            pre_body.push('\n');
            pre_body.push_str("    ");
        }
        format!(
            "type alias {}{} =\n    {}{}",
            self.sym(a.name.value),
            vars,
            pre_body,
            body
        )
    }

    fn value(&self, v: &Value) -> String {
        let mut s = String::new();
        // Type annotation directly above the definition.
        if let Some(ann) = &v.type_annotation {
            s.push_str(&self.signature(v.name.value, &ann.value, self.was_multiline(ann.span)));
            s.push('\n');
            // A comment written between the type annotation and the binding
            // name (e.g. `-- c` in `main : Int\n-- c\nmain = 42`) lives in
            // the byte gap [ann.span.hi, name.span.lo). Emit it here so it
            // is not silently dropped.
            let ann_hi = ann.span.hi as usize;
            let name_lo = v.name.span.lo as usize;
            for c in self.comments_before(ann_hi, name_lo) {
                s.push_str(&c.text);
                s.push('\n');
            }
        }
        // The definition head: `name p0 p1 …`. Parameters are in ARGUMENT
        // position, so a constructor-with-arguments / cons / alias pattern must
        // be parenthesised — otherwise `f (Cons a)` would print as `f Cons a`,
        // silently turning one parameter into two.
        s.push_str(&self.sym(v.name.value));
        for p in &v.patterns {
            s.push(' ');
            s.push_str(&self.pattern_atom(&p.value));
        }
        s.push_str(" =");
        // The body always goes on the next line, four-space indented — the
        // elm-format canonical form for a top-level definition.
        let body = self.expr(&v.body, 1);
        let _ = write!(s, "\n    {body}");
        s
    }

    // -- Type annotations ---------------------------------------------------

    /// A top-level `name : Type` signature in the elm-format canonical form.
    ///
    /// elm-format's signature breaking is *modal*, not width-driven: a
    /// signature written on one line stays on one line no matter how wide (it
    /// keeps 1000-column function types single-line), and a signature written
    /// across multiple lines keeps `name :` on its own line with the type laid
    /// out four-space indented beneath — an arrow chain becomes one segment per
    /// line, the first bare and each subsequent one with a leading `->`. The
    /// modal trigger (`was_multi`) mirrors the record / list / tuple trigger.
    fn signature(&self, name: ipe_intern::Symbol, ann: &TypeAnnotation, was_multi: bool) -> String {
        let name = self.sym(name);
        if !was_multi {
            // Force a single line irrespective of width (elm-format keeps a
            // single-line signature single-line however wide it is). An arrow
            // chain is joined with ` -> `; anything else prints as one atom.
            let one = match ann {
                TypeAnnotation::TLambda(_, _) => self.arrow_chain(ann, 0).join(" -> "),
                _ => self.type_app(ann, 0),
            };
            // A record type inside the signature may still force its own break;
            // fall through to the multi-line form only if that happened.
            if !one.contains('\n') {
                return format!("{name} : {one}");
            }
        }
        // Multi-line: `name :` then the type indented one level.
        let body = self.type_multiline(ann, 1);
        format!("{name} :\n{body}")
    }

    /// Render `t` broken across lines at indentation `indent`. An arrow chain
    /// lays out one segment per line; a type application whose single-line form
    /// overflows the width budget breaks its arguments one per line (elm-format
    /// indents each argument one level under the applied head); anything else is
    /// a single indented line.
    fn type_multiline(&self, t: &TypeAnnotation, indent: usize) -> String {
        let cur_pad = pad(indent);
        match t {
            TypeAnnotation::TLambda(_, _) => {
                let parts = self.arrow_chain(t, indent);
                let mut it = parts.into_iter();
                let first = it.next().unwrap_or_default();
                let mut out = format!("{cur_pad}{first}");
                for p in it {
                    let _ = write!(out, "\n{cur_pad}-> {p}");
                }
                out
            }
            TypeAnnotation::TType(q, segs, args) if !args.is_empty() => {
                let one = self.type_app(t, indent);
                if fits(&one, indent * 4) {
                    return format!("{cur_pad}{one}");
                }
                // Break the application: head on its own line, each argument one
                // level deeper on its own line.
                let arg_pad = pad(indent + 1);
                let mut out = format!("{cur_pad}{}", self.type_head(*q, segs));
                for a in args {
                    let _ = write!(out, "\n{arg_pad}{}", self.type_atom_indent(a, indent + 1));
                }
                out
            }
            _ => format!("{cur_pad}{}", self.type_app(t, indent)),
        }
    }

    fn type_annotation(&self, t: &TypeAnnotation, indent: usize) -> String {
        match t {
            TypeAnnotation::TLambda(_, _) => {
                // Collect the full arrow chain and join with ` -> ` (single
                // line when it fits).
                let parts = self.arrow_chain(t, indent);
                let one = parts.join(" -> ");
                if fits(&one, indent * 4) {
                    one
                } else {
                    // Multiline arrow: each arrow on its own line, four-space
                    // indented past the current level, `->` leading.
                    let pad = pad(indent + 1);
                    let mut it = parts.into_iter();
                    let first = it.next().unwrap_or_default();
                    let mut out = first;
                    for p in it {
                        let _ = write!(out, "\n{pad}-> {p}");
                    }
                    out
                }
            }
            _ => self.type_app(t, indent),
        }
    }

    fn arrow_chain(&self, t: &TypeAnnotation, indent: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = t;
        while let TypeAnnotation::TLambda(a, b) = cur {
            out.push(self.type_app(a, indent));
            cur = b;
        }
        out.push(self.type_app(cur, indent));
        out
    }

    fn type_app(&self, t: &TypeAnnotation, indent: usize) -> String {
        match t {
            TypeAnnotation::TType(q, segs, args) if !args.is_empty() => {
                let head = self.type_head(*q, segs);
                let arg_strs: Vec<String> = args
                    .iter()
                    .map(|a| self.type_atom_indent(a, indent))
                    .collect();
                format!("{head} {}", arg_strs.join(" "))
            }
            _ => self.type_atom_indent(t, indent),
        }
    }

    fn type_head(&self, q: ipe_intern::Symbol, segs: &[ipe_intern::Symbol]) -> String {
        let qs = self.sym(q);
        let name = self.dotted(segs);
        if qs.is_empty() {
            name
        } else {
            format!("{qs}.{name}")
        }
    }

    fn type_atom(&self, t: &TypeAnnotation) -> String {
        self.type_atom_indent(t, 0)
    }

    /// A type in atom position — parenthesised when it is a compound (arrow,
    /// applied constructor, or tuple) that would otherwise re-associate.
    fn type_atom_indent(&self, t: &TypeAnnotation, indent: usize) -> String {
        match t {
            TypeAnnotation::TVar(s) => self.sym(*s),
            TypeAnnotation::TUnit => "()".to_owned(),
            TypeAnnotation::TType(q, segs, args) if args.is_empty() => self.type_head(*q, segs),
            TypeAnnotation::TType(..) => {
                format!("({})", self.type_app(t, indent))
            }
            TypeAnnotation::TLambda(..) => {
                format!("({})", self.type_annotation(t, indent))
            }
            TypeAnnotation::TTuple(elems) => {
                let parts: Vec<String> = elems
                    .iter()
                    .map(|e| self.type_annotation(e, indent))
                    .collect();
                format!("( {} )", parts.join(", "))
            }
            TypeAnnotation::TRecord(fields) => self.type_record(fields, indent, false),
            TypeAnnotation::TRecordOpen(row_var, fields) => {
                self.type_record_open(*row_var, fields, indent)
            }
        }
    }

    /// Render a row-polymorphic record TYPE `{ r | field : T, … }`. The open
    /// tail always keeps the record on one line — the row var makes it a
    /// signature fragment, never a wide `type alias` body, so the modal
    /// multi-line trigger `type_record` honours does not apply.
    fn type_record_open(
        &self,
        row_var: ipe_intern::Symbol,
        fields: &[(Located<ipe_intern::Symbol>, TypeAnnotation)],
        indent: usize,
    ) -> String {
        let parts: Vec<String> = fields
            .iter()
            .map(|(n, ty)| {
                format!(
                    "{} : {}",
                    self.sym(n.value),
                    self.type_annotation(ty, indent)
                )
            })
            .collect();
        format!("{{ {} | {} }}", self.sym(row_var), parts.join(", "))
    }

    /// Render a record TYPE `{ field : T, … }`. `force_multi` reproduces
    /// elm-format's modal trigger (the record was written across multiple lines
    /// in the source, e.g. a `type alias` body), which breaks it even when it
    /// would fit on one line.
    fn type_record(
        &self,
        fields: &[(Located<ipe_intern::Symbol>, TypeAnnotation)],
        indent: usize,
        force_multi: bool,
    ) -> String {
        if fields.is_empty() {
            return "{}".to_owned();
        }
        let parts: Vec<String> = fields
            .iter()
            .map(|(n, ty)| {
                format!(
                    "{} : {}",
                    self.sym(n.value),
                    self.type_annotation(ty, indent)
                )
            })
            .collect();
        // A comment written between two record-type fields sits in the byte gap
        // that runs from one field name's end to the next field name's start.
        // That range also spans the earlier field's type text, but
        // `scan_comments` yields only comments, so every hit is genuinely
        // inter-field. `leading[i]` collects the comment(s) that precede field
        // `i`; `leading[0]` covers the gap between the opening `{` and the first
        // field name. Claiming them here keeps the comment-count guard from
        // refusing a record whose fields are interleaved with comments (the
        // shipped `type alias Model` body is exactly this shape).
        let leading: Vec<Vec<&Comment>> = fields
            .iter()
            .enumerate()
            .map(|(i, (name, _))| {
                let after = if i == 0 {
                    name.span.lo.saturating_sub(1) as usize
                } else {
                    fields
                        .get(i - 1)
                        .map_or(0, |(prev, _)| prev.span.hi as usize)
                };
                self.comments_before(after, name.span.lo as usize)
            })
            .collect();
        let has_field_comments = leading.iter().any(|cs| !cs.is_empty());
        let one = format!("{{ {} }}", parts.join(", "));
        // Modal, like every other collection: a record type written on one line
        // stays single-line however wide; only a source-multiline record (the
        // `force_multi` trigger), one whose own field broke, or one carrying an
        // inter-field comment (which cannot survive on a single line) lays out
        // one field per leading-comma line.
        if !force_multi && !has_field_comments && !one.contains('\n') {
            return one;
        }
        let pad = pad(indent);
        let inner = pad_in(indent);
        let mut out = String::from("{");
        for (i, (part, lead)) in parts.iter().zip(&leading).enumerate() {
            // The comment block precedes the field it annotates, mirroring the
            // source where the comment sits above its field.
            for c in lead {
                let _ = write!(out, "\n{inner}{}", c.text);
            }
            if i == 0 && lead.is_empty() {
                let _ = write!(out, " {part}");
            } else if i == 0 {
                let _ = write!(out, "\n{inner}  {part}");
            } else {
                let _ = write!(out, "\n{inner}, {part}");
            }
        }
        let _ = write!(out, "\n{pad}}}");
        out
    }

    // -- Patterns -----------------------------------------------------------

    fn pattern(&self, p: &Pattern_) -> String {
        match p {
            Pattern_::PAnything => "_".to_owned(),
            Pattern_::PDebugAnything => "Debug._".to_owned(),
            Pattern_::PUnit => "()".to_owned(),
            Pattern_::PVar(s) => self.sym(*s),
            Pattern_::PInt(n) => n.to_string(),
            Pattern_::PBool(b) => if *b { "True" } else { "False" }.to_owned(),
            Pattern_::PChar(c) => format!("'{c}'"),
            Pattern_::PStr(s) => format!("\"{}\"", escape_str(s)),
            Pattern_::PCtor(name, segs, args) => {
                let head = if segs.is_empty() {
                    self.sym(*name)
                } else {
                    format!("{}.{}", self.dotted(segs), self.sym(*name))
                };
                if args.is_empty() {
                    head
                } else {
                    let a: Vec<String> = args.iter().map(|x| self.pattern_atom(&x.value)).collect();
                    format!("{head} {}", a.join(" "))
                }
            }
            Pattern_::PTuple(elems) => {
                let parts: Vec<String> = elems.iter().map(|e| self.pattern(&e.value)).collect();
                format!("( {} )", parts.join(", "))
            }
            Pattern_::PRecord(fields) => {
                let parts: Vec<String> = fields.iter().map(|f| self.sym(f.value)).collect();
                format!("{{ {} }}", parts.join(", "))
            }
            Pattern_::PList(elems) => {
                if elems.is_empty() {
                    "[]".to_owned()
                } else {
                    let parts: Vec<String> = elems.iter().map(|e| self.pattern(&e.value)).collect();
                    format!("[ {} ]", parts.join(", "))
                }
            }
            Pattern_::PCons(h, t) => {
                format!(
                    "{} :: {}",
                    self.pattern_atom(&h.value),
                    self.pattern(&t.value)
                )
            }
            Pattern_::PAlias(inner, name) => {
                format!("{} as {}", self.pattern(&inner.value), self.sym(name.value))
            }
            Pattern_::POr(alts) => {
                let parts: Vec<String> = alts.iter().map(|a| self.pattern(&a.value)).collect();
                parts.join(" | ")
            }
        }
    }

    /// A pattern in atom position — parenthesised when it is a compound that
    /// would otherwise bind wrongly (ctor-with-args, cons, tuple-as-arg).
    fn pattern_atom(&self, p: &Pattern_) -> String {
        match p {
            Pattern_::PCtor(_, _, args) if !args.is_empty() => format!("({})", self.pattern(p)),
            // An or-pattern binds loosest, so in any atom position (ctor arg,
            // cons head) it must be parenthesised to keep its grouping.
            Pattern_::PCons(..) | Pattern_::PAlias(..) | Pattern_::POr(..) => {
                format!("({})", self.pattern(p))
            }
            _ => self.pattern(p),
        }
    }

    // -- Expressions --------------------------------------------------------

    /// Format an expression at the given indentation (in 4-space units).
    ///
    /// A `do` block reaches the printer already desugared into its
    /// `Task.andThen` / `let` chain; it is re-sugared here so the output keeps
    /// the source's `do` form. The desugared chain is not always printable:
    /// a bare-run line becomes `let _ = task in …`, which the parser rejects
    /// outside a `do` (`BareWildcardBinding`).
    fn expr(&self, e: &Expr, indent: usize) -> String {
        self.do_view(e).map_or_else(
            || self.expr_node(e, indent),
            |view| self.do_block(&view, indent),
        )
    }

    /// The source offset just past the `do` keyword of a block's span.
    ///
    /// `None` when `span` is not a `do` block's. The `do` desugar stamps the
    /// outermost node of its chain with the keyword's own span; a
    /// parenthesised group re-stamps its inner node with the group's span, so
    /// `(do …)` is recognised by its leading keyword — skipping over any
    /// opening parens, whitespace, and comments in between, since a comment
    /// (`( -- note\n do …)`) is as legal there as blank space and must not
    /// hide the keyword.
    /// Always `None` without source: the equivalence guard compares the
    /// desugared form directly.
    fn do_keyword_end(&self, span: ipe_diagnostics::Span) -> Option<usize> {
        let lo = span.lo as usize;
        let text = self.src?.get(lo..span.hi as usize)?;
        if text == "do" {
            return Some(lo + text.len());
        }
        if !text.ends_with(')') {
            return None;
        }
        let inner = text.strip_prefix('(')?;
        let rest = skip_paren_trivia(inner);
        let after = rest.strip_prefix("do")?;
        after
            .starts_with(char::is_whitespace)
            .then_some(lo + (text.len() - after.len()))
    }

    /// Recover the statements of the `do` block whose desugared chain is `e`.
    ///
    /// `None` when `e` is not a `do` block.
    fn do_view<'e>(&self, e: &'e Expr) -> Option<DoView<'e>> {
        let keyword_end = self.do_keyword_end(e.span)?;
        let mut steps = Vec::new();
        let mut cur = e;
        loop {
            let outer = steps.is_empty();
            // A nested `do` in result position carries its own keyword span:
            // it is this block's result, printed as its own `do` block.
            if !outer && self.do_keyword_end(cur.span).is_some() {
                break;
            }
            let Some((step, rest)) = self.do_step(cur, outer) else {
                break;
            };
            steps.push(step);
            cur = rest;
        }
        // A parenthesised node whose text merely starts with `(do` may be an
        // application or access headed by the block (`(do …) x`), which peels
        // no statement: print that node by its own shape. A lone-statement
        // `(do t)` prints as `(t)`, the same tree.
        if steps.is_empty() && keyword_end != e.span.hi as usize {
            return None;
        }
        Some(DoView {
            keyword_end,
            steps,
            result: cur,
        })
    }

    /// Peel one `do` statement off the front of a desugared chain.
    ///
    /// Returns the statement with the rest of the chain. The shapes mirror the
    /// parser's `desugar_do` span discipline:
    /// - bind `p <- t` is `Task.andThen (\p -> rest) t` with a zero-width
    ///   lambda span (no written lambda is zero-width);
    /// - bare run `t` is `let _ = t in rest` whose `_` carries `t`'s own span
    ///   (a written `let _ =` is rejected by the parser);
    /// - pure `p = v` is `let p = v in rest` stamped with the `=` span, which
    ///   lies after the binder (a written `let` starts before its binder). The
    ///   outermost node carries the `do` span instead, so there any
    ///   single-binding `let` over a statement binder is accepted — printing a
    ///   lone `let … in` result as a statement re-parses to the same AST.
    fn do_step<'e>(&self, e: &'e Expr, outer: bool) -> Option<(DoStep<'e>, &'e Expr)> {
        match &e.value {
            Expr_::Call(head, args) => {
                let Expr_::VarQual(module, name) = &head.value else {
                    return None;
                };
                let [lam, task] = args.as_slice() else {
                    return None;
                };
                let Expr_::Lambda(params, cont) = &lam.value else {
                    return None;
                };
                let [pat] = params.as_slice() else {
                    return None;
                };
                let synthetic = lam.span.lo == lam.span.hi
                    && self.sym(*module) == "Task"
                    && self.sym(*name) == "andThen";
                (synthetic && is_do_binder(&pat.value))
                    .then_some((DoStep::Bind(pat, task), cont.as_ref()))
            }
            Expr_::Let(bindings, cont) => {
                let [b] = bindings.as_slice() else {
                    return None;
                };
                if matches!(b.pat.value, Pattern_::PAnything) && b.pat.span == b.body.span {
                    return Some((DoStep::Run(&b.body), cont.as_ref()));
                }
                let stamped_after_binder = e.span.lo >= b.pat.span.hi;
                ((outer || stamped_after_binder) && is_do_binder(&b.pat.value))
                    .then_some((DoStep::Let(&b.pat, &b.body), cont.as_ref()))
            }
            _ => None,
        }
    }

    /// Print a recovered `do` block, one statement per line one level in.
    ///
    /// The result expression comes last; comments written between statements
    /// keep their place.
    fn do_block(&self, view: &DoView<'_>, indent: usize) -> String {
        let stmt_pad = pad(indent + 1);
        let mut out = String::from("do");
        let mut prev_hi = view.keyword_end;
        for step in &view.steps {
            let (lo, line, hi) = match step {
                DoStep::Bind(pat, task) => (
                    pat.span.lo,
                    format!(
                        "{} <- {}",
                        self.pattern(&pat.value),
                        self.expr(task, indent + 1)
                    ),
                    task.span.hi,
                ),
                DoStep::Let(pat, value) => (
                    pat.span.lo,
                    format!(
                        "{} = {}",
                        self.pattern(&pat.value),
                        self.expr(value, indent + 1)
                    ),
                    value.span.hi,
                ),
                DoStep::Run(task) => (task.span.lo, self.expr(task, indent + 1), task.span.hi),
            };
            for c in self.comments_before(prev_hi, lo as usize) {
                let _ = write!(out, "\n{stmt_pad}{}", c.text);
            }
            let _ = write!(out, "\n{stmt_pad}{line}");
            prev_hi = hi as usize;
        }
        // With no statement peeled, the result IS the `do`-stamped node: print
        // its own shape, or `expr` would recognise the block again.
        let result = if view.steps.is_empty() {
            self.expr_node(view.result, indent + 1)
        } else {
            for c in self.comments_before(prev_hi, view.result.span.lo as usize) {
                let _ = write!(out, "\n{stmt_pad}{}", c.text);
            }
            self.expr(view.result, indent + 1)
        };
        let _ = write!(out, "\n{stmt_pad}{result}");
        out
    }

    /// Format an expression node by its own shape, without `do` re-sugaring.
    fn expr_node(&self, e: &Expr, indent: usize) -> String {
        match &e.value {
            Expr_::VarLocal(s) => self.sym(*s),
            Expr_::VarQual(q, n) => format!("{}.{}", self.sym(*q), self.sym(*n)),
            Expr_::Int(n) => n.to_string(),
            Expr_::Float(f) => format_float(*f),
            Expr_::Str(s) => format!("\"{}\"", escape_str(s)),
            Expr_::MultilineStr { raw, .. } => format!("\"\"\"{raw}\"\"\""),
            Expr_::Char(c) => format!("'{c}'"),
            Expr_::Unit => "()".to_owned(),
            Expr_::Call(head, args) => self.call(head, args, indent, e.span),
            Expr_::Binops(chain, last) => self.binops(chain, last, indent, e.span),
            Expr_::Case(scrut, arms) => self.case(scrut, arms, indent),
            Expr_::Lambda(params, body) => self.lambda(params, body, indent, e.span),
            Expr_::Let(bindings, body) => self.let_(bindings, body, indent),
            Expr_::If(branches, else_) => self.if_(branches, else_, indent),
            Expr_::Tuple(elems) => self.tuple(elems, indent, e.span),
            Expr_::List(elems) => self.list(elems, indent, e.span),
            Expr_::Record(fields) => self.record(fields, indent, e.span),
            Expr_::Update(base, fields) => self.update(base, fields, indent, e.span),
            Expr_::Access(base, field) => {
                format!("{}.{}", self.expr_atom(base, indent), self.sym(field.value))
            }
        }
    }

    /// An expression in atom position (application argument, operator operand,
    /// access base): parenthesised when it is a compound that would otherwise
    /// bind incorrectly against its surroundings.
    fn expr_atom(&self, e: &Expr, indent: usize) -> String {
        // A negative numeric literal (`-5`, `-1.0`) prints with a leading `-`,
        // which the parser reads as a binary subtraction operator once the
        // literal sits after another atom — so `f (-5)` bare-printed as `f -5`
        // re-parses as `f - 5`. In atom position the sign must stay wrapped.
        if is_negative_literal(&e.value) {
            return format!("({})", self.expr(e, indent));
        }
        if needs_parens_as_atom(&e.value) {
            let inner = self.expr(e, indent);
            if inner.contains('\n') {
                // A multiline compound in parens: the head follows `(`
                // directly, continuation lines keep their indentation, and the
                // closing `)` sits on its own line at this atom's indent —
                // elm-format's parenthesised-block layout.
                format!("({}\n{})", inner, pad(indent))
            } else {
                format!("({inner})")
            }
        } else {
            self.expr(e, indent)
        }
    }

    fn call(
        &self,
        head: &Expr,
        args: &[Expr],
        indent: usize,
        span: ipe_diagnostics::Span,
    ) -> String {
        let head_s = self.expr_atom(head, indent);
        // Single-line application when the whole thing fits, nothing broke, and
        // the source kept it on one line (elm-format's modal rule).
        let arg_one_strs: Vec<String> =
            args.iter().map(|a| self.expr_atom(a, indent + 1)).collect();
        let one = format!("{head_s} {}", arg_one_strs.join(" "));
        if !has_layout_newline(&one) && !self.was_multiline(span) {
            return one;
        }

        // Multiline application — port of elm-format's `application`:
        //   * `FAJoinFirst` (Case 2): the first argument stays on the function
        //     line, the rest indent — but ONLY when that first argument is a
        //     "trivially joinable" atom (a name / literal / joinable string /
        //     empty collection), never a non-empty list / record / tuple /
        //     parenthesised compound, AND a *later* argument renders as a genuine
        //     multi-line block. When every argument is single-line and the call
        //     only broke on width, elm-format instead stacks all of them.
        //   * otherwise (Case 3): the function stands alone and EVERY argument
        //     goes on its own indented line.
        let inner = pad(indent + 1);
        // `split_first` avoids indexing/slicing panics and cleanly expresses the
        // "first argument joins the head line" branch.
        // The first argument hugs the function line — elm-format's `FAJoinFirst`
        // — when either:
        //   * it is a simple reference (a name / qualified name / accessor): such
        //     a token always joins the broken head line;
        //   * it is itself a multi-line block (a triple-quoted string); or
        //   * a *later* argument renders as a multi-line block.
        // A literal first argument (string / number) that is followed only by
        // single-line arguments does NOT join — elm-format stacks them all.
        let is_simple_ref = |a: &Expr| {
            matches!(
                a.value,
                Expr_::VarLocal(_) | Expr_::VarQual(..) | Expr_::Access(..)
            )
        };
        let first_is_block =
            |a: &Expr| matches!(&a.value, Expr_::MultilineStr { raw, .. } if raw.contains('\n'));
        let later_block = |tail: &[Expr]| {
            tail.iter()
                .any(|a| has_layout_newline(&self.expr_atom(a, indent + 1)))
        };
        let (mut out, rest): (String, &[Expr]) = match args.split_first() {
            Some((first, tail))
                if self.joins_on_head_line(first, indent + 1)
                    && head_line_fits(&head_s, first, indent)
                    && (is_simple_ref(first) || first_is_block(first) || later_block(tail)) =>
            {
                let first_s = self.expr_atom(first, indent + 1);
                (format!("{head_s} {first_s}"), tail)
            }
            _ => (head_s, args),
        };
        for a in rest {
            out.push('\n');
            out.push_str(&inner);
            out.push_str(&self.expr_atom(a, indent + 1));
        }
        out
    }

    /// Whether argument `a` may share the function's line in a broken
    /// application (elm-format's `FAJoinFirst`): a name, qualified name,
    /// literal, unit, or empty collection — anything that renders on a single
    /// line AND is not itself a block form (non-empty list / record / tuple /
    /// update / parenthesised compound).
    fn joins_on_head_line(&self, a: &Expr, indent: usize) -> bool {
        // A triple-quoted string hugs the function line only when it opens with
        // visible content on its first physical line (`interpolate """head\n…"""`).
        // One that opens with a newline (`"""\n…`) — or any string literal that is
        // a single line — drops to its own indented line instead.
        if let Expr_::MultilineStr { raw: s, .. } = &a.value {
            // A triple-quoted string hugs the function line only when its first
            // physical line opens with visible, non-whitespace content
            // (`"""head…`). One that opens with a newline (`"""\n…`) or with
            // leading indentation (`"""    …`) drops to its own line.
            return match s.split_once('\n') {
                Some((first, _)) => first.starts_with(|c: char| !c.is_whitespace()),
                None => false,
            };
        }
        let rendered = self.expr_atom(a, indent);
        if rendered.contains('\n') {
            return false;
        }
        match &a.value {
            Expr_::List(elems) | Expr_::Tuple(elems) => elems.is_empty(),
            Expr_::Record(fields) => fields.is_empty(),
            Expr_::Update(..)
            | Expr_::Call(..)
            | Expr_::Binops(..)
            | Expr_::Case(..)
            | Expr_::Lambda(..)
            | Expr_::Let(..)
            | Expr_::If(..) => false,
            _ => true,
        }
    }

    fn binops(
        &self,
        chain: &[(Expr, Located<ipe_intern::Symbol>)],
        last: &Expr,
        indent: usize,
        span: ipe_diagnostics::Span,
    ) -> String {
        // Build the flat operand/operator sequence.
        let mut one = String::new();
        for (operand, op) in chain {
            one.push_str(&self.binop_operand(operand, indent));
            one.push(' ');
            one.push_str(&self.sym(op.value));
            one.push(' ');
        }
        one.push_str(&self.binop_last_operand(last, indent));
        // Modal, like every other construct: a chain written on one line stays
        // single-line however wide (elm-format keeps 900-column `::` chains
        // intact), and only a source-multiline chain — or one whose operand
        // itself broke — lays out one operator per continuation line.
        if !has_layout_newline(&one) && !self.was_multiline(span) {
            return one;
        }
        // The backward pipe `<|` breaks differently from every other operator:
        // it is right-associative and elm-format leaves it at the END of the
        // left operand's line, dropping the right-hand side onto the next line
        // indented one level (`f x <|\n    g y`). A whole chain of `<|` nests
        // this way. Every other operator (`|>`, `::`, `++`, `==`, …) begins the
        // continuation line instead.
        let all_backward = chain.iter().all(|(_, op)| self.sym(op.value) == "<|");
        let inner = pad(indent + 1);
        if all_backward {
            let mut out = String::new();
            for (operand, op) in chain {
                out.push_str(&self.binop_operand(operand, indent));
                let _ = write!(out, " {}\n{inner}", self.sym(op.value));
            }
            out.push_str(&self.binop_last_operand(last, indent + 1));
            return out;
        }
        // Multiline: the FIRST operand stays on the current line at the base
        // indent; every operator then begins a continuation line indented one
        // level, with its right-hand operand following on that same line. So
        //   { … }
        //       |> Vector
        // keeps the record at the base indent and only the `|>` step indents.
        let mut out = String::new();
        let mut first = true;
        for (operand, op) in chain {
            let opnd_indent = if first { indent } else { indent + 1 };
            out.push_str(&self.binop_operand(operand, opnd_indent));
            let _ = write!(out, "\n{inner}{} ", self.sym(op.value));
            first = false;
        }
        // The trailing operand shares the last operator's continuation line.
        out.push_str(&self.binop_last_operand(last, indent + 1));
        out
    }

    /// An operand of a binary-operator chain. Unlike a general atom, a function
    /// APPLICATION operand needs no parentheses — application binds tighter than
    /// every binary operator, so `List.foldr f start <| toList v` is
    /// unambiguous and elm-format leaves both calls bare. Only a nested operator
    /// chain, `case` / `if` / `let`, or lambda still needs wrapping.
    fn binop_operand(&self, e: &Expr, indent: usize) -> String {
        // A `do` block desugars to a call, but its statement layout would
        // swallow a following operator line: it keeps its parentheses.
        if matches!(e.value, Expr_::Call(..)) && self.do_keyword_end(e.span).is_none() {
            self.expr(e, indent)
        } else {
            self.expr_atom(e, indent)
        }
    }

    /// The final operand of an operator chain. A trailing `\x -> …` needs no
    /// wrapping parens — the operator to its left already delimits it and its
    /// body extends to the end of the expression, so elm-format emits it bare
    /// (`f <| \x -> body`). Every other operand keeps [`Self::binop_operand`].
    fn binop_last_operand(&self, e: &Expr, indent: usize) -> String {
        if matches!(e.value, Expr_::Lambda(..)) {
            self.expr(e, indent)
        } else {
            self.binop_operand(e, indent)
        }
    }

    fn lambda(
        &self,
        params: &[Pattern],
        body: &Expr,
        indent: usize,
        span: ipe_diagnostics::Span,
    ) -> String {
        let ps: Vec<String> = params.iter().map(|p| self.pattern_atom(&p.value)).collect();
        let head = format!("\\{} ->", ps.join(" "));
        // A block-form body (`let` / `case` / `if`) always drops to the next
        // line, indented one level: an inline `-> let …` would place the `let`
        // keyword mid-line, breaking its layout-sensitive block on re-parse.
        // A modal body — one written across multiple source lines — also drops
        // to its own indented line, matching elm-format's `\x ->\n    body`.
        // Any other body stays inline after the arrow.
        let block_body = matches!(body.value, Expr_::Let(..) | Expr_::Case(..) | Expr_::If(..));
        if block_body || self.was_multiline(span) {
            let inner = pad(indent + 1);
            let body_s = self.expr(body, indent + 1);
            format!("{head}\n{inner}{body_s}")
        } else {
            format!("{head} {}", self.expr(body, indent))
        }
    }

    fn case(&self, scrut: &Expr, arms: &[(Pattern, Expr)], indent: usize) -> String {
        let scrut_s = self.expr(scrut, indent);
        let arm_pad = pad(indent + 1);
        let body_pad = pad(indent + 2);
        let mut out = format!("case {scrut_s} of");
        // Track the hi of the previous arm's body to detect comments written
        // between consecutive arms (e.g. `-- separates arm 0 and arm 1`).
        let mut prev_hi: Option<usize> = None;
        for (pat, body) in arms {
            // Blank line between arms, plus any inter-arm comments.
            if let Some(hi) = prev_hi {
                let arm_lo = pat.span.lo as usize;
                // The blank line before the next arm is always emitted; when
                // there are inter-arm comments they each get their own
                // arm-indented line followed by an additional blank line so
                // the next arm is still visually separated.
                out.push('\n');
                for c in self.comments_before(hi, arm_lo) {
                    // Each inter-arm comment sits on its own arm-indented
                    // line, matching elm-format's convention for section
                    // comments inside a `case`.
                    let _ = write!(out, "\n{arm_pad}{}", c.text);
                    out.push('\n');
                }
            }
            let body_s = self.expr(body, indent + 2);
            let _ = write!(
                out,
                "\n{arm_pad}{} ->\n{body_pad}{body_s}",
                self.pattern(&pat.value)
            );
            prev_hi = Some(body.span.hi as usize);
        }
        out
    }

    fn let_(&self, bindings: &[LetBinding], body: &Expr, indent: usize) -> String {
        let bind_pad = pad(indent + 1);
        let body_val_pad = pad(indent + 2);
        let mut out = String::from("let");
        // Track the hi of the previous binding's body to detect comments
        // written between consecutive `let` bindings.
        let mut prev_hi: Option<usize> = None;
        for b in bindings {
            // elm-format separates successive `let` bindings with a blank
            // line; any inter-binding comments replace that blank line.
            if let Some(hi) = prev_hi {
                let next_lo = b.pat.span.lo as usize;
                let between = self.comments_before(hi, next_lo);
                if between.is_empty() {
                    out.push('\n');
                } else {
                    for c in between {
                        let _ = write!(out, "\n{bind_pad}{}", c.text);
                    }
                }
            }
            // A `let` binder that destructures with a constructor pattern must
            // stay parenthesised — `(Decoder d) = …`. Without the parens the
            // re-parse reads `Decoder` as the (illegal, uppercase) binding name.
            let binder = self.let_binder(&b.pat.value);
            // elm-format ALWAYS drops a `let` binding's value onto its own
            // four-space-indented line, however short — `x =\n    1`.
            let val = self.expr(&b.body, indent + 2);
            let _ = write!(out, "\n{bind_pad}{binder} =\n{body_val_pad}{val}");
            prev_hi = Some(b.body.span.hi as usize);
        }
        let in_pad = pad(indent);
        let _ = write!(out, "\n{in_pad}in\n{in_pad}{}", self.expr(body, indent));
        out
    }

    /// A `let` binding's binder pattern. A bare constructor destructure needs
    /// enclosing parens so it re-parses as a destructure rather than an
    /// (illegal) uppercase binding name; other binders print bare.
    fn let_binder(&self, p: &Pattern_) -> String {
        match p {
            Pattern_::PCtor(_, _, args) if !args.is_empty() => format!("({})", self.pattern(p)),
            _ => self.pattern(p),
        }
    }

    fn if_(&self, branches: &[(Expr, Expr)], else_: &Expr, indent: usize) -> String {
        let inner = pad(indent + 1);
        let mut out = String::new();
        for (i, (cond, body)) in branches.iter().enumerate() {
            let lead = if i == 0 { "if" } else { "else if" };
            let _ = write!(
                out,
                "{lead} {} then\n{inner}{}\n\n{}",
                self.expr(cond, indent),
                self.expr(body, indent + 1),
                pad(indent)
            );
        }
        let _ = write!(out, "else\n{inner}{}", self.expr(else_, indent + 1));
        out
    }

    // Collection elements are rendered at the collection's OWN indent (the
    // bracket level), not one level deeper: elm-format treats the leading
    // `[ ` / `, ` separator as cosmetic and indents an element's internal
    // breaks (e.g. a nested application's arguments) by 4 from the bracket
    // column, i.e. to `(indent + 1) * 4`. Rendering elements at `indent + 1`
    // would double-count that step.
    fn tuple(&self, elems: &[Expr], indent: usize, span: ipe_diagnostics::Span) -> String {
        let parts: Vec<String> = elems.iter().map(|e| self.expr(e, indent)).collect();
        let one = format!("( {} )", parts.join(", "));
        if !has_layout_newline(&one) && !self.was_multiline(span) {
            return one;
        }
        comma_multiline("(", ")", &parts, indent)
    }

    fn list(&self, elems: &[Expr], indent: usize, span: ipe_diagnostics::Span) -> String {
        if elems.is_empty() {
            return "[]".to_owned();
        }
        let parts: Vec<String> = elems.iter().map(|e| self.expr(e, indent)).collect();
        let one = format!("[ {} ]", parts.join(", "));
        if !has_layout_newline(&one) && !self.was_multiline(span) {
            return one;
        }
        comma_multiline("[", "]", &parts, indent)
    }

    fn record(
        &self,
        fields: &[(Located<ipe_intern::Symbol>, Expr)],
        indent: usize,
        span: ipe_diagnostics::Span,
    ) -> String {
        if fields.is_empty() {
            return "{}".to_owned();
        }
        let parts: Vec<String> = fields
            .iter()
            .map(|(n, v)| format!("{} = {}", self.sym(n.value), self.expr(v, indent)))
            .collect();
        let one = format!("{{ {} }}", parts.join(", "));
        if !has_layout_newline(&one) && !self.was_multiline(span) {
            return one;
        }
        comma_multiline("{", "}", &parts, indent)
    }

    fn update(
        &self,
        base: &Located<ipe_intern::Symbol>,
        fields: &[(Located<ipe_intern::Symbol>, Expr)],
        indent: usize,
        span: ipe_diagnostics::Span,
    ) -> String {
        let base_s = self.sym(base.value);
        // Field values render at one level deeper than the brace so a value's
        // own line breaks align under the multi-line update body.
        let parts: Vec<String> = fields
            .iter()
            .map(|(n, v)| format!("{} = {}", self.sym(n.value), self.expr(v, indent + 1)))
            .collect();
        let one = format!("{{ {base_s} | {} }}", parts.join(", "));
        if !has_layout_newline(&one) && !self.was_multiline(span) {
            return one;
        }
        // Multiline update: `{ base` on the first line, then the `| field` /
        // `, field` lines indented ONE LEVEL DEEPER than the brace (elm-format
        // aligns the update pipe under the record body, not under the `{`), and
        // the closing `}` back at the brace column.
        let close_pad = pad(indent);
        let inner = pad(indent + 1);
        let mut out = format!("{{ {base_s}");
        for (i, p) in parts.iter().enumerate() {
            let lead = if i == 0 { "|" } else { "," };
            let _ = write!(out, "\n{inner}{lead} {p}");
        }
        let _ = write!(out, "\n{close_pad}}}");
        out
    }
}

/// Whether an expression is a negative numeric literal (`Int` below zero, or a
/// `Float` that carries a minus sign — including `-0.0`). Such a literal renders
/// with a leading `-`, which the parser treats as binary subtraction once the
/// literal follows another atom, so it must be parenthesised in atom position.
const fn is_negative_literal(e: &Expr_) -> bool {
    match e {
        Expr_::Int(n) => *n < 0,
        Expr_::Float(f) => f.is_sign_negative(),
        _ => false,
    }
}

/// One statement of a `do` block recovered from its desugared chain.
enum DoStep<'e> {
    /// `p <- task` — run `task`, bind its result.
    Bind(&'e Pattern, &'e Expr),
    /// `p = value` — a pure binding.
    Let(&'e Pattern, &'e Expr),
    /// `task` — run for effect, result discarded.
    Run(&'e Expr),
}

/// A `do` block recovered from its desugared chain.
struct DoView<'e> {
    /// Source offset just past the `do` keyword.
    keyword_end: usize,
    /// The statements before the result, in source order.
    steps: Vec<DoStep<'e>>,
    /// The block's final (result) expression.
    result: &'e Expr,
}

/// Whether `p` can head a `do` statement: the parser accepts only a lowercase
/// name or `_` before `<-` / `=`.
const fn is_do_binder(p: &Pattern_) -> bool {
    matches!(p, Pattern_::PVar(_) | Pattern_::PAnything)
}

/// Whether an expression needs parentheses when it appears in atom position
/// (an application argument, an operator operand, or an access base) — the
/// compound forms that would otherwise re-associate against their surroundings.
const fn needs_parens_as_atom(e: &Expr_) -> bool {
    matches!(
        e,
        Expr_::Call(..)
            | Expr_::Binops(..)
            | Expr_::Case(..)
            | Expr_::Lambda(..)
            | Expr_::Let(..)
            | Expr_::If(..)
    )
}

/// Whether `s` contains a newline that is part of the source *layout* rather
/// than the *content* of a triple-quoted (`"""…"""`) string. elm-format's modal
/// rule keys the multi-line layout of a construct on whether the construct was
/// written across multiple source lines — but a multi-line string literal is a
/// single logical token, so the `\n`s inside its `"""…"""` delimiters are
/// content, not layout. Counting them would make e.g. `interpolate """…\n…"""`
/// look "source-multiline" and wrongly break the surrounding call.
fn has_layout_newline(s: &str) -> bool {
    let mut in_triple = false;
    let mut rest = s.as_bytes();
    while let Some((&head, tail)) = rest.split_first() {
        if rest.starts_with(b"\"\"\"") {
            in_triple = !in_triple;
            rest = rest.get(3..).unwrap_or(&[]);
            continue;
        }
        if head == b'\n' && !in_triple {
            return true;
        }
        rest = tail;
    }
    false
}

/// Whether the head plus its first argument fits on one line before the
/// argument's own break. For a multi-line triple-quoted string the join line is
/// `head """first-content-line`; elm-format only hugs the string to the function
/// when that opening line stays within the width budget, otherwise the string
/// drops to its own indented line. Other joinable first arguments (names, empty
/// collections) are short and always fit.
fn head_line_fits(head_s: &str, first: &Expr, indent: usize) -> bool {
    let Expr_::MultilineStr { raw: s, .. } = &first.value else {
        return true;
    };
    let first_content = s.split_once('\n').map_or(s.as_str(), |(f, _)| f);
    // column of the head + head + ` ` + `"""` + first content line
    let col = indent * 4 + head_s.chars().count() + 1 + 3 + first_content.chars().count();
    col <= MAX_WIDTH
}

/// Shared leading-comma multiline layout for records / lists / tuples:
/// ```text
/// { a = 1
/// , b = 2
/// }
/// ```
fn comma_multiline(open: &str, close: &str, parts: &[String], indent: usize) -> String {
    let pad = pad(indent);
    let inner = pad_in(indent);
    let mut out = format!(
        "{open} {}",
        hang_element(parts.first().map(String::as_str).unwrap_or_default())
    );
    for p in parts.iter().skip(1) {
        let _ = write!(out, "\n{inner}, {}", hang_element(p));
    }
    let _ = write!(out, "\n{pad}{close}");
    out
}

/// Align a multi-line collection ELEMENT under the two-column content offset
/// created by its `( ` / `, ` / `[ ` prefix. elm-format's box model places an
/// element two spaces past the bracket, so a nested comma-delimited collection
/// (`{ … }`, `[ … ]`, `( … )`) — whose own continuation commas and closing
/// bracket would otherwise sit at the bracket column — must hang two spaces to
/// line up under its opener. Only such a "leading-bracket" element is shifted;
/// an application or pipe element already indents correctly by four, so shifting
/// it would over-indent its continuation lines.
fn hang_element(part: &str) -> String {
    let starts_collection = part.starts_with("{ ") || part.starts_with("[ ");
    if !starts_collection || !part.contains('\n') {
        return part.to_owned();
    }
    // The element opens a comma-delimited collection at the two-space content
    // offset. Its *own* structural lines — the leading-comma continuations and
    // the closing bracket at the collection's base column — must hang two
    // spaces to sit under the opener. Lines that are more deeply indented (a
    // nested application's arguments, or a `|>` pipe step following the
    // collection) are left untouched: shifting them would misalign them.
    let base_indent = part
        .lines()
        .nth(1)
        .map_or(0, |l| l.len() - l.trim_start().len());
    let mut out = String::with_capacity(part.len() + 8);
    for (i, line) in part.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
            let this_indent = line.len() - line.trim_start().len();
            let trimmed = line.trim_start();
            let is_own_structure = this_indent == base_indent
                && (trimmed.starts_with(", ") || trimmed == "}" || trimmed == "]");
            if is_own_structure {
                out.push_str("  ");
            }
        }
        out.push_str(line);
    }
    out
}

/// A top-level declaration, tagged so unions / aliases / values can be
/// interleaved in source (span) order.
enum Decl<'a> {
    Union(&'a Located<Union>),
    Alias(&'a Located<TypeAlias>),
    Value(&'a Located<Value>),
}

impl Decl<'_> {
    fn lo(&self) -> u32 {
        match self {
            Self::Union(u) => u.value.name.span.lo,
            Self::Alias(a) => a.value.name.span.lo,
            Self::Value(v) => {
                // A definition with a type annotation starts at the annotation.
                v.value
                    .type_annotation
                    .as_ref()
                    .map_or(v.value.name.span.lo, |ann| {
                        ann.span.lo.min(v.value.name.span.lo)
                    })
            }
        }
    }

    const fn hi(&self) -> u32 {
        match self {
            Self::Union(u) => u.span.hi,
            Self::Alias(a) => a.span.hi,
            Self::Value(v) => v.span.hi,
        }
    }
}

/// The greatest `hi` among declarations strictly before `d`'s `lo` — the lower
/// bound of the range in which `d`'s leading comments live.
fn decls_prev_hi(decls: &[Decl<'_>], d: &Decl<'_>) -> usize {
    let d_lo = d.lo();
    decls
        .iter()
        .filter(|other| other.hi() <= d_lo)
        .map(|other| other.hi() as usize)
        .max()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Small formatting helpers
// ---------------------------------------------------------------------------

/// Four spaces per indent level.
fn pad(indent: usize) -> String {
    "    ".repeat(indent)
}

/// The indentation of the leading-comma continuation lines inside a multiline
/// record / list / tuple: elm-format aligns the `,` with the opening bracket,
/// which sits at the construct's own indent.
fn pad_in(indent: usize) -> String {
    "    ".repeat(indent)
}

/// Whether `s`, placed at column `col`, fits within [`MAX_WIDTH`]. A multi-line
/// `s` never "fits" as a single line.
fn fits(s: &str, col: usize) -> bool {
    !s.contains('\n') && col + s.chars().count() <= MAX_WIDTH
}

/// Escape a string literal's contents for re-emission inside `"…"`.
fn escape_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out
}

/// Render a float the way the source spelled it back canonically: an integral
/// value keeps a single trailing `.0` (Elm requires the fractional part), and a
/// non-integral value uses Rust's shortest round-trip form.
fn format_float(f: f64) -> String {
    if f.fract() == 0.0 && f.is_finite() {
        format!("{f:.1}")
    } else {
        let s = format!("{f}");
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `fmt(fmt(x)) == fmt(x)` over a spread of constructs.
    #[test]
    fn idempotent_over_constructs() {
        let inputs = [
            "module M exposing (x)\n\n\nx =\n    1\n",
            "module M exposing (r)\n\n\nr =\n    { a = 1, b = 2 }\n",
            "module M exposing (l)\n\n\nl =\n    [ 1, 2, 3 ]\n",
            "module M exposing (f)\n\n\nf x =\n    case x of\n        0 ->\n            \"z\"\n\n        _ ->\n            \"n\"\n",
            "module M exposing (R)\n\n\ntype alias R =\n    { a : Int\n\n    -- mid\n    , b : Int\n    }\n",
        ];
        for src in inputs {
            let once = format_source(src).expect("first pass formats");
            let twice = format_source(&once).expect("second pass");
            assert_eq!(once, twice, "not idempotent for input:\n{src}");
        }
    }

    /// Every comment in the input survives formatting.
    #[test]
    fn comments_are_preserved() {
        let src = "module M exposing (f, g)\n\
                   \n\
                   -- leading on f\n\
                   f =\n    1\n\
                   \n\
                   {- block before g -}\n\
                   g =\n    2\n";
        let out = format_source(src).expect("formats");
        assert!(out.contains("-- leading on f"), "line comment lost:\n{out}");
        assert!(
            out.contains("{- block before g -}"),
            "block comment lost:\n{out}"
        );
    }

    /// A comment written between two fields of a record TYPE (a `type alias`
    /// body) is preserved and the result is idempotent. This is the shipped
    /// `file-browser` shape that previously ICE'd the comment-count guard,
    /// because the record-type field name carried no span for the formatter to
    /// place an inter-field comment against.
    #[test]
    fn record_type_field_comment_is_preserved() {
        let src = "module M exposing (Model)\n\
                   \n\
                   \n\
                   type alias Model =\n\
                   \x20   { entries : List String\n\
                   \x20   , selected : Int\n\
                   \x20   , status : String\n\
                   \n\
                   \x20   -- The selected file's first bytes.\n\
                   \x20   , bytes : List Int\n\
                   \x20   }\n";
        let out = format_source(src).expect("record-field comment formats (was an ICE)");
        assert!(
            out.contains("-- The selected file's first bytes."),
            "inter-field record-type comment lost:\n{out}"
        );
        // The comment survives at its site AND the field ordering is intact.
        assert!(out.contains(", bytes : List Int"), "field lost:\n{out}");
        let twice = format_source(&out).expect("second pass formats");
        assert_eq!(out, twice, "not idempotent:\n{out}");
    }

    /// The comment-count guard is satisfied for a record-type inter-field
    /// comment: the output carries at least as many comments as the input, so
    /// `format_source` does not reject it. Pins the gap directly.
    #[test]
    fn record_type_inter_field_comment_count_is_not_reduced() {
        let src = "module M exposing (R)\n\
                   \n\
                   \n\
                   type alias R =\n\
                   \x20   { a : Int\n\
                   \n\
                   \x20   -- between a and b\n\
                   \x20   , b : Int\n\
                   \x20   }\n";
        let input_count = scan_comments(src).len();
        let out = format_source(src).expect("formats without dropping the comment");
        let output_count = scan_comments(&out).len();
        assert!(
            output_count >= input_count,
            "comment count fell from {input_count} to {output_count}:\n{out}"
        );
    }

    /// The semantics guard rejects nothing valid: a variety of programs all
    /// round-trip (the guard inside `format_source` would error otherwise).
    #[test]
    fn semantics_preserved_round_trip() {
        let src = "module Main exposing (main)\n\nimport Ipe.String as String\n\n\ntype Model\n    = Loading\n    | Ready Int\n\n\nmain : Model -> String\nmain model =\n    case model of\n        Loading ->\n            \"…\"\n\n        Ready n ->\n            String.fromInt n\n";
        // If the formatted output parsed to a different AST, `format_source`
        // returns `Err(RoundTrip)`. Success is the assertion.
        assert!(format_source(src).is_ok());
    }

    /// A negative numeric literal in argument (atom) position keeps its
    /// parentheses: printing `f (-5)` as bare `f -5` re-parses as the binary
    /// subtraction `f - 5`, so the round-trip guard inside `format_source` would
    /// reject it. Success (no `Err(RoundTrip)`) is the assertion, and the output
    /// retains the wrapping.
    #[test]
    fn negative_literal_argument_round_trips() {
        let cases = [
            "module M exposing (x)\n\n\nx =\n    f (-5)\n",
            "module M exposing (x)\n\n\nx =\n    f (-1.0)\n",
            "module M exposing (x)\n\n\nx =\n    g (-1) (-2)\n",
        ];
        for src in cases {
            let out = format_source(src).expect("negative-literal argument round-trips");
            assert!(
                out.contains("(-"),
                "negative literal lost its parens:\n{out}"
            );
            let twice = format_source(&out).expect("second pass formats");
            assert_eq!(out, twice, "not idempotent for input:\n{src}");
        }
    }

    /// A negative literal at TOP-LEVEL body / list-element position (not atom
    /// position) must NOT be over-parenthesised — the comma / definition already
    /// delimits it, so `x = -5` and `[ -5, -3 ]` stay bare and round-trip.
    #[test]
    fn negative_literal_not_over_parenthesised() {
        let bare = "module M exposing (x)\n\n\nx =\n    -5\n";
        let out = format_source(bare).expect("formats");
        assert_eq!(
            out, bare,
            "bare negative body must be a fixed point:\n{out}"
        );

        let list = "module M exposing (l)\n\n\nl =\n    [ -5, -3 ]\n";
        let out = format_source(list).expect("formats");
        assert!(
            !out.contains("[ (-"),
            "list element must not be parenthesised:\n{out}"
        );
    }

    /// `scan_comments` does not mistake a `--` inside a string for a comment.
    #[test]
    fn comment_scan_ignores_string_contents() {
        let comments = scan_comments("x = \"a -- b\" {- real -}\n");
        assert_eq!(comments.len(), 1);
        assert_eq!(
            comments.first().map(|c| c.text.as_str()),
            Some("{- real -}")
        );
    }

    /// `format_source_unchecked` and the checked path agree on well-formed
    /// input (the guard is transparent when the formatter is correct).
    #[test]
    fn unchecked_matches_checked() {
        let src = "module M exposing (x)\n\n\nx =\n    1\n";
        assert_eq!(
            format_source(src).unwrap(),
            format_source_unchecked(src).unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // Comment-preservation tests — each proves a specific comment site
    // -----------------------------------------------------------------------

    /// The minimal repro from the issue: a comment between a type annotation
    /// and the binding name must survive. `main : Int\n-- c\nmain = 42`.
    #[test]
    fn comment_between_annotation_and_definition_survives() {
        let src = "module M exposing (main)\n\n\nmain : Int\n-- c\nmain =\n    42\n";
        let out = format_source(src).expect("formats");
        assert!(
            out.contains("-- c"),
            "comment between annotation and definition was dropped:\n{out}"
        );
        // Idempotent.
        let twice = format_source(&out).expect("second pass");
        assert_eq!(out, twice, "not idempotent:\n{out}");
    }

    /// A block comment between annotation and definition also survives.
    #[test]
    fn block_comment_between_annotation_and_definition_survives() {
        let src = "module M exposing (f)\n\n\nf : Int\n{- block -}\nf =\n    1\n";
        let out = format_source(src).expect("formats");
        assert!(
            out.contains("{- block -}"),
            "block comment between annotation and definition was dropped:\n{out}"
        );
        let twice = format_source(&out).expect("second pass");
        assert_eq!(out, twice, "not idempotent:\n{out}");
    }

    /// A comment written between two `case` arms survives at the arm indent.
    #[test]
    fn comment_between_case_arms_survives() {
        let src = "module M exposing (f)\n\n\nf x =\n    case x of\n        0 ->\n            \"zero\"\n\n        -- separates arms\n        _ ->\n            \"other\"\n";
        let out = format_source(src).expect("formats");
        assert!(
            out.contains("-- separates arms"),
            "inter-arm comment was dropped:\n{out}"
        );
        let twice = format_source(&out).expect("second pass");
        assert_eq!(out, twice, "not idempotent:\n{out}");
    }

    /// A comment written between two `let` bindings survives at the binding
    /// indent.
    #[test]
    fn comment_between_let_bindings_survives() {
        let src = "module M exposing (f)\n\n\nf =\n    let\n        x =\n            1\n\n        -- between bindings\n        y =\n            2\n    in\n    x\n";
        let out = format_source(src).expect("formats");
        assert!(
            out.contains("-- between bindings"),
            "inter-binding comment was dropped:\n{out}"
        );
        let twice = format_source(&out).expect("second pass");
        assert_eq!(out, twice, "not idempotent:\n{out}");
    }

    /// A comment between the `type alias` head and the body type survives.
    #[test]
    fn comment_between_alias_head_and_body_survives() {
        let src = "module M exposing (A)\n\n\ntype alias A =\n    -- body comment\n    Int\n";
        let out = format_source(src).expect("formats");
        assert!(
            out.contains("-- body comment"),
            "alias body comment was dropped:\n{out}"
        );
        let twice = format_source(&out).expect("second pass");
        assert_eq!(out, twice, "not idempotent:\n{out}");
    }

    /// `fmt` never reduces the comment count: the output comment count must be
    /// >= the input comment count for every construct with inline comments.
    #[test]
    fn comment_count_never_decreases() {
        let cases = [
            // annotation gap
            "module M exposing (main)\n\n\nmain : Int\n-- c\nmain =\n    42\n",
            // case arm gap
            "module M exposing (f)\n\n\nf x =\n    case x of\n        0 ->\n            \"z\"\n\n        -- arm sep\n        _ ->\n            \"n\"\n",
            // let binding gap
            "module M exposing (f)\n\n\nf =\n    let\n        x =\n            1\n\n        -- bind sep\n        y =\n            2\n    in\n    x\n",
            // top-level leading comment
            "module M exposing (x)\n\n\n-- top\nx =\n    1\n",
            // trailing comment
            "module M exposing (x)\n\n\nx =\n    1\n\n-- trail\n",
        ];
        for src in cases {
            let input_count = scan_comments(src).len();
            let out = format_source(src).expect("formats");
            let output_count = scan_comments(&out).len();
            assert!(
                output_count >= input_count,
                "comment count decreased from {input_count} to {output_count} for:\n{src}\noutput:\n{out}"
            );
        }
    }

    /// `fmt(fmt(x)) == fmt(x)` AND both passes preserve every comment — the
    /// combined idempotency + comment-preservation fixed-point assertion.
    #[test]
    fn idempotent_and_comment_preserving() {
        let cases = [
            "module M exposing (main)\n\n\nmain : Int\n-- c\nmain =\n    42\n",
            "module M exposing (f)\n\n\nf x =\n    case x of\n        0 ->\n            \"z\"\n\n        -- arm comment\n        _ ->\n            \"n\"\n",
            "module M exposing (f)\n\n\nf =\n    let\n        x =\n            1\n\n        -- bind comment\n        y =\n            2\n    in\n    x\n",
        ];
        for src in cases {
            let once = format_source(src).expect("first pass");
            let twice = format_source(&once).expect("second pass");
            assert_eq!(once, twice, "not idempotent for:\n{src}");
            // Every comment present in the input is present in the output.
            for c in scan_comments(src) {
                assert!(
                    once.contains(&c.text),
                    "comment {:?} lost after fmt for:\n{src}\noutput:\n{once}",
                    c.text
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // `do` blocks — the printer re-sugars the parser's desugared chain
    // -----------------------------------------------------------------------

    /// Wrap `body` (already indented for a top-level definition) as a module.
    fn do_module(body: &str) -> String {
        format!("module M exposing (main)\n\n\nmain =\n{body}")
    }

    /// Format `src` and assert a fixed point that is still a `do` block.
    ///
    /// Returns the first pass's output.
    fn assert_do_round_trips(src: &str) -> String {
        let once = format_source(src).expect("do block formats");
        let twice = format_source(&once).expect("formatted do block re-formats");
        assert_eq!(once, twice, "not idempotent for:\n{src}\noutput:\n{once}");
        assert!(once.contains("do\n"), "`do` form lost:\n{once}");
        once
    }

    /// The reported ICE: a bare-run line and a wildcard bind in a `do` block.
    ///
    /// The bare run desugars to `let _ = task in …`, which the printer used to
    /// emit verbatim and the re-parse rejected with
    /// `MalformedLet(BareWildcardBinding)`.
    #[test]
    fn do_wildcard_bind_and_bare_run_round_trip() {
        let src = do_module(
            "    do\n        x <- Task.succeed 1\n        _ <- Task.succeed 2\n        Io.println \"run\"\n        Task.succeed x\n",
        );
        let out = assert_do_round_trips(&src);
        assert_eq!(out, src, "canonical do block must be a fixed point");
    }

    /// Every statement shape the `do` grammar admits survives in source order.
    ///
    /// Named bind, wildcard bind, bare run, pure `name =`, pure `_ =`.
    #[test]
    fn do_every_statement_shape_is_a_fixed_point() {
        let src = do_module(
            "    do\n        a <- Task.succeed 1\n        _ <- Task.succeed 2\n        Io.println \"step\"\n        b = a + 1\n        _ = b\n        Task.succeed b\n",
        );
        let out = assert_do_round_trips(&src);
        assert_eq!(out, src, "canonical do block must be a fixed point");
    }

    /// Each statement shape is recognised in leading position.
    ///
    /// The first statement's node carries the `do` span, not its own.
    #[test]
    fn do_each_shape_in_leading_position() {
        let leads = [
            "x <- Task.succeed 1",
            "_ <- Task.succeed 1",
            "Io.println \"first\"",
            "x = 1",
            "_ = 1",
        ];
        for lead in leads {
            let src = do_module(&format!("    do\n        {lead}\n        Task.succeed 0\n"));
            let out = assert_do_round_trips(&src);
            assert_eq!(out, src, "leading `{lead}` must be a fixed point");
        }
    }

    /// A single-statement `do` keeps its keyword.
    #[test]
    fn do_single_statement_round_trips() {
        let src = do_module("    do\n        Task.succeed 0\n");
        let out = assert_do_round_trips(&src);
        assert_eq!(out, src, "single-statement do must be a fixed point");
    }

    /// Nested `do` blocks each stay their own block.
    ///
    /// Covers result position, a bind's task, a bare run, and a lambda body.
    #[test]
    fn do_nested_blocks_round_trip() {
        let nested = [
            "    do\n        x <- Task.succeed 1\n        do\n            y <- Task.succeed x\n            Task.succeed y\n",
            "    do\n        x <- do\n            Io.println \"inner\"\n            Task.succeed 1\n        Task.succeed x\n",
            "    do\n        do\n            Io.println \"inner\"\n            Task.succeed 1\n        Task.succeed 2\n",
        ];
        for body in nested {
            let out = assert_do_round_trips(&do_module(body));
            assert_eq!(
                out.matches("do\n").count(),
                2,
                "nested do flattened or lost:\n{out}"
            );
        }
        let in_lambda = "    Task.andThen\n        (\\x ->\n            do\n                Io.println \"in lambda\"\n                Task.succeed x\n        )\n        (Task.succeed 1)\n";
        assert_do_round_trips(&do_module(in_lambda));
    }

    /// A `do` block in atom position keeps its parentheses.
    ///
    /// Bare, its statement layout would swallow the following argument or
    /// operator line.
    #[test]
    fn do_in_atom_position_round_trips() {
        let cases = [
            "    f\n        (do\n            Io.println \"arg\"\n            Task.succeed 1\n        )\n        y\n",
            "    (do\n        Io.println \"operand\"\n        Task.succeed 1\n    )\n        |> Task.map f\n",
        ];
        for body in cases {
            let out = assert_do_round_trips(&do_module(body));
            assert!(
                out.contains("(do\n"),
                "do in atom position lost its parens:\n{out}"
            );
        }
    }

    /// Block-form expressions as statement tasks, bind sources, and results.
    ///
    /// `case`, `if`, and `let` layouts must not collide with statement
    /// alignment.
    #[test]
    fn do_block_form_statements_round_trip() {
        let cases = [
            "    do\n        x <- case m of\n            Just v ->\n                Task.succeed v\n\n            Nothing ->\n                Task.succeed 0\n        Task.succeed x\n",
            "    do\n        x <- if c then\n            Task.succeed 1\n\n        else\n            Task.succeed 2\n        Task.succeed x\n",
            "    do\n        Io.println \"run\"\n        let\n            y =\n                1\n        in\n        Task.succeed y\n",
        ];
        for body in cases {
            assert_do_round_trips(&do_module(body));
        }
    }

    /// A comment between two statements keeps its place in the block.
    #[test]
    fn do_comment_between_statements_survives() {
        let src = do_module(
            "    do\n        x <- Task.succeed 1\n        -- between statements\n        Io.println \"run\"\n        Task.succeed x\n",
        );
        let out = assert_do_round_trips(&src);
        assert_eq!(out, src, "commented do block must be a fixed point");
    }

    /// A tuple or record destructure before `<-` is refused as a parse error.
    ///
    /// The `do` grammar admits only a lowercase name or `_` there.
    #[test]
    fn do_destructuring_bind_is_refused() {
        for binder in ["( a, b )", "{ a }"] {
            let src = do_module(&format!(
                "    do\n        {binder} <- t\n        Task.succeed a\n"
            ));
            assert!(
                matches!(format_source(&src), Err(FmtError::Parse { .. })),
                "destructuring `{binder} <-` must be refused as a parse error"
            );
        }
    }

    /// A whole-pattern `let _ =` outside a `do` stays refused.
    ///
    /// Re-sugaring does not widen what the formatter accepts.
    #[test]
    fn bare_wildcard_let_outside_do_is_refused() {
        let src = do_module("    let\n        _ =\n            1\n    in\n    2\n");
        assert!(
            matches!(format_source(&src), Err(FmtError::Parse { .. })),
            "`let _ =` outside a do must stay a parse error"
        );
    }

    /// #3034: a comment between a `do` block's opening paren and its `do`
    /// keyword used to hide the keyword from `do_keyword_end`'s text match,
    /// falling through to the raw printer and emitting an illegal bare
    /// wildcard `let` for the block's run statement — `IPE-I0001
    /// MalformedLet(BareWildcardBinding)`. `do_keyword_end` now skips
    /// comments (like parens and whitespace) while looking for the keyword.
    #[test]
    fn do_comment_before_keyword_in_parens_round_trips() {
        let src = do_module(
            "    Cmd.perform\n        ( -- comment before do\n        do\n            db <- reviewDb\n            recordDrain db\n            loadQueue\n        )\n        PendingLoaded\n",
        );
        let out = assert_do_round_trips(&src);
        assert!(
            out.contains("-- comment before do"),
            "comment before `do` keyword was dropped:\n{out}"
        );
    }

    /// A block comment between a `do` block's opening paren and its `do`
    /// keyword is tolerated the same way a line comment is.
    #[test]
    fn do_block_comment_before_keyword_in_parens_round_trips() {
        let src = do_module(
            "    Cmd.perform\n        ( {- note -}\n        do\n            db <- reviewDb\n            loadQueue\n        )\n        PendingLoaded\n",
        );
        let out = assert_do_round_trips(&src);
        assert!(
            out.contains("{- note -}"),
            "block comment before `do` keyword was dropped:\n{out}"
        );
    }

    // -----------------------------------------------------------------------
    // Let-binding pattern forms — the class-closing round-trip
    // -----------------------------------------------------------------------

    /// Every let-binding pattern form the parser accepts round-trips through
    /// the printer: a plain name, a tuple destructure, a record destructure, a
    /// parenthesised constructor destructure, and a wildcard nested inside a
    /// larger pattern. A bare whole-pattern `_` binder stays refused (see
    /// `bare_wildcard_let_outside_do_is_refused`) — nested is the only legal
    /// wildcard shape in `let` position, so it is exercised here instead.
    #[test]
    fn let_binding_pattern_forms_round_trip() {
        let cases = [
            "v =\n            1\n",
            "( a, b ) =\n            pair\n",
            "{ a, b } =\n            rec\n",
            "(Just v) =\n            maybeVal\n",
            "( a, _ ) =\n            pair\n",
        ];
        for binder in cases {
            let src = do_module(&format!("    let\n        {binder}    in\n    2\n"));
            let out = format_source(&src).expect("let-binding pattern form round-trips");
            let twice = format_source(&out).expect("second pass formats");
            assert_eq!(out, twice, "not idempotent for:\n{src}\noutput:\n{out}");
        }
    }

    /// There is no `name : Type` annotation line inside a `let` block — unlike
    /// a top-level definition, a `let` binding carries no separate annotation
    /// slot in the grammar, so this stays a parse error rather than a
    /// let-binding pattern form the printer must round-trip.
    #[test]
    fn annotated_let_binding_is_refused() {
        let src =
            do_module("    let\n        v : Int\n        v =\n            1\n    in\n    v\n");
        assert!(
            matches!(format_source(&src), Err(FmtError::Parse { .. })),
            "a `name : T` line inside `let` is not grammar; it must stay a parse error"
        );
    }
}
