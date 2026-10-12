//! Every text the Rust backend splices into emitted Rust goes through the
//! `ipe_intern::rust_literal` owner.
//!
//! A hand-built Rust literal (a `"` glued to a format placeholder, a lone `"`
//! pushed around a value, a raw-literal constructor, an ad hoc
//! `escape_debug`/`escape_default`) carries whatever the spliced value holds,
//! so a bidi control or a bare CR reaches `cargo` raw. This ratchet lexes every
//! non-test function of `backend/rust/src` and refuses each such shape. The
//! TOML and JSON encoders, whose output is not Rust, are allowlisted by
//! `(file, fn, breach, count)`; an entry whose count no longer matches is drift
//! and fails too.

use std::collections::BTreeMap;
use std::path::Path;

use proc_macro2::{Delimiter, TokenStream, TokenTree};

/// One hand-built literal shape the scan refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Breach {
    /// A format-macro string whose placeholder touches a `"`: `"\"{}\""`.
    HandQuote,
    /// A lone `"` pushed onto a buffer (`push('"')`, `push_str("\"")`) or
    /// joined by `concat!`.
    LoneQuote,
    /// A string literal holding a raw-literal opener `r#"`.
    RawLiteral,
    /// A call of `escape_debug` / `escape_default`.
    EscapeMethod,
}

/// Where a breach sits: the file relative to `src`, and the innermost named fn.
type Site = (String, String, Breach);

/// The format macros whose first string literal is a format string.
const FORMAT_MACROS: [&str; 4] = ["format", "format_args", "write", "writeln"];

/// The sanctioned breach sites.
///
/// Each is an encoder whose output is TOML or JSON, never Rust, or the
/// diagnostic excerpt `route_grammar::excerpt`.
const ALLOWED: &[(&str, &str, Breach, usize)] = &[
    (
        "emit_template.rs",
        "write_json_string",
        Breach::LoneQuote,
        2,
    ),
    ("project.rs", "apply_cargo_name", Breach::HandQuote, 1),
    (
        "project.rs",
        "async_runtime_cargo_toml",
        Breach::HandQuote,
        2,
    ),
    ("project.rs", "chrono_tz_cargo_toml", Breach::HandQuote, 1),
    ("project.rs", "compression_cargo_toml", Breach::HandQuote, 1),
    ("project.rs", "config_cargo_toml", Breach::HandQuote, 1),
    ("project.rs", "crypto_cargo_toml", Breach::HandQuote, 1),
    (
        "project.rs",
        "crypto_core_heavy_cargo_toml",
        Breach::HandQuote,
        1,
    ),
    ("project.rs", "csv_cargo_toml", Breach::HandQuote, 1),
    ("project.rs", "db_cargo_toml", Breach::HandQuote, 1),
    ("project.rs", "email_cargo_toml", Breach::HandQuote, 1),
    ("project.rs", "http_client_cargo_toml", Breach::HandQuote, 1),
    ("project.rs", "json_string", Breach::LoneQuote, 2),
    (
        "project.rs",
        "promote_default_feature",
        Breach::HandQuote,
        1,
    ),
    ("project.rs", "jwt_cargo_toml", Breach::HandQuote, 1),
    ("project.rs", "locale_cargo_toml", Breach::HandQuote, 1),
    ("project.rs", "server_cargo_toml", Breach::HandQuote, 3),
    ("project.rs", "ssrf_cargo_toml", Breach::HandQuote, 1),
    (
        "project.rs",
        "substitute_dep_manifest_anchors",
        Breach::HandQuote,
        1,
    ),
    ("project.rs", "tea_cargo_toml", Breach::HandQuote, 2),
    ("project.rs", "tui_cargo_toml", Breach::HandQuote, 3),
    ("project.rs", "url_cargo_toml", Breach::HandQuote, 1),
    ("project.rs", "web_cargo_toml", Breach::HandQuote, 1),
    ("project.rs", "websocket_cargo_toml", Breach::HandQuote, 3),
    ("project.rs", "webview_cargo_toml", Breach::HandQuote, 1),
    ("route_grammar.rs", "excerpt", Breach::EscapeMethod, 1),
    ("static_build.rs", "cargo_config", Breach::HandQuote, 1),
    (
        "static_build.rs",
        "staticize_manifest",
        Breach::LoneQuote,
        1,
    ),
];

/// The value of a string literal token, `None` for any other token.
fn str_value(tok: &TokenTree) -> Option<String> {
    let TokenTree::Literal(lit) = tok else {
        return None;
    };
    match syn::parse2::<syn::Lit>(TokenStream::from(TokenTree::Literal(lit.clone()))) {
        Ok(syn::Lit::Str(s)) => Some(s.value()),
        _ => None,
    }
}

/// Whether `tok` is the literal `"` as a char or a one-character string.
fn is_lone_quote(tok: &TokenTree) -> bool {
    let TokenTree::Literal(lit) = tok else {
        return false;
    };
    match syn::parse2::<syn::Lit>(TokenStream::from(TokenTree::Literal(lit.clone()))) {
        Ok(syn::Lit::Str(s)) => s.value() == "\"",
        Ok(syn::Lit::Char(c)) => c.value() == '"',
        _ => false,
    }
}

/// Whether `tok` is the punctuation `ch`.
fn is_punct(tok: Option<&TokenTree>, ch: char) -> bool {
    matches!(tok, Some(TokenTree::Punct(p)) if p.as_char() == ch)
}

/// One piece of a format string: a literal character or a placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Piece {
    Char(char),
    Placeholder,
}

/// Split a format string into its literal characters and placeholders
/// (`{{`/`}}` are literal braces).
fn pieces(format: &str) -> Vec<Piece> {
    let mut out = Vec::new();
    let mut chars = format.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push(Piece::Char('{'));
            }
            '{' => {
                for inner in chars.by_ref() {
                    if inner == '}' {
                        break;
                    }
                }
                out.push(Piece::Placeholder);
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push(Piece::Char('}'));
            }
            other => out.push(Piece::Char(other)),
        }
    }
    out
}

/// Whether a placeholder of `format` sits right after or right before a `"`.
fn hand_quoted(format: &str) -> bool {
    pieces(format).windows(2).any(|pair| {
        matches!(
            pair,
            [Piece::Char('"'), Piece::Placeholder] | [Piece::Placeholder, Piece::Char('"')]
        )
    })
}

/// Whether an attribute body is `test` or `cfg(test)`.
fn is_test_attr(body: &TokenStream) -> bool {
    let toks: Vec<TokenTree> = body.clone().into_iter().collect();
    match toks.as_slice() {
        [TokenTree::Ident(id)] => id == "test",
        [TokenTree::Ident(id), TokenTree::Group(args)] if id == "cfg" => {
            let inner: Vec<TokenTree> = args.stream().into_iter().collect();
            matches!(inner.as_slice(), [TokenTree::Ident(t)] if t == "test")
        }
        _ => false,
    }
}

/// The breach counter over one file's token tree.
struct Scan<'a> {
    file: &'a str,
    hits: BTreeMap<Site, usize>,
}

impl Scan<'_> {
    /// Count one `breach` in `func`.
    fn hit(&mut self, func: &str, breach: Breach) {
        *self
            .hits
            .entry((self.file.to_owned(), func.to_owned(), breach))
            .or_insert(0) += 1;
    }

    /// Scan one token sequence inside the innermost named fn `func`, skipping
    /// every item gated by `#[test]` or `#[cfg(test)]`.
    #[allow(clippy::too_many_lines)] // one arm per token shape the scan reads
    fn stream(&mut self, stream: &TokenStream, func: &str) {
        let toks: Vec<TokenTree> = stream.clone().into_iter().collect();
        let mut test_gated = false;
        let mut i = 0;
        while let Some(tok) = toks.get(i) {
            // An attribute: `#[..]` (outer) or `#![..]` (inner).
            if is_punct(Some(tok), '#') {
                let inner = is_punct(toks.get(i + 1), '!');
                let at = if inner { i + 2 } else { i + 1 };
                if let Some(TokenTree::Group(g)) = toks.get(at)
                    && g.delimiter() == Delimiter::Bracket
                {
                    if !inner && is_test_attr(&g.stream()) {
                        test_gated = true;
                    }
                    i = at + 1;
                    continue;
                }
            }
            if let TokenTree::Ident(id) = tok {
                let word = id.to_string();
                // A named `fn` or `mod`: its body is the next brace group.
                if (word == "fn" || word == "mod")
                    && let Some(TokenTree::Ident(name)) = toks.get(i + 1)
                {
                    let mut k = i + 2;
                    while let Some(t) = toks.get(k) {
                        if is_punct(Some(t), ';')
                            || matches!(t, TokenTree::Group(g) if g.delimiter() == Delimiter::Brace)
                        {
                            break;
                        }
                        k += 1;
                    }
                    if let Some(TokenTree::Group(body)) = toks.get(k)
                        && body.delimiter() == Delimiter::Brace
                        && !test_gated
                    {
                        let name = name.to_string();
                        let inner_fn = if word == "fn" { name.as_str() } else { func };
                        self.stream(&body.stream(), inner_fn);
                    }
                    test_gated = false;
                    i = k + 1;
                    continue;
                }
                // A macro call `name!(..)`.
                if is_punct(toks.get(i + 1), '!')
                    && let Some(TokenTree::Group(body)) = toks.get(i + 2)
                {
                    let body_toks: Vec<TokenTree> = body.stream().into_iter().collect();
                    if FORMAT_MACROS.contains(&word.as_str())
                        && body_toks
                            .iter()
                            .find_map(str_value)
                            .is_some_and(|format| hand_quoted(&format))
                    {
                        self.hit(func, Breach::HandQuote);
                    }
                    if word == "concat" {
                        for t in &body_toks {
                            if matches!(str_value(t).as_deref(), Some("\"")) {
                                self.hit(func, Breach::LoneQuote);
                            }
                        }
                    }
                    self.stream(&body.stream(), func);
                    test_gated = false;
                    i += 3;
                    continue;
                }
                if word == "escape_debug" || word == "escape_default" {
                    self.hit(func, Breach::EscapeMethod);
                }
            }
            // `.push('"')` / `.push_str("\"")`.
            if is_punct(Some(tok), '.')
                && let (Some(TokenTree::Ident(method)), Some(TokenTree::Group(args))) =
                    (toks.get(i + 1), toks.get(i + 2))
                && (method == "push" || method == "push_str")
            {
                let args: Vec<TokenTree> = args.stream().into_iter().collect();
                if let [only] = args.as_slice()
                    && is_lone_quote(only)
                {
                    self.hit(func, Breach::LoneQuote);
                }
            }
            if str_value(tok).is_some_and(|value| value.contains("r#\"")) {
                self.hit(func, Breach::RawLiteral);
            }
            if let TokenTree::Group(g) = tok {
                let brace = g.delimiter() == Delimiter::Brace;
                if !(brace && test_gated) {
                    self.stream(&g.stream(), func);
                }
                if brace {
                    test_gated = false;
                }
            }
            if is_punct(Some(tok), ';') {
                test_gated = false;
            }
            i += 1;
        }
    }
}

/// The breaches in one source file, keyed by `(file, fn, breach)`.
fn scan_source(file: &str, src: &str) -> Result<BTreeMap<Site, usize>, String> {
    let stream: TokenStream = src
        .parse()
        .map_err(|e| format!("{file} does not lex: {e}"))?;
    let mut scan = Scan {
        file,
        hits: BTreeMap::new(),
    };
    scan.stream(&stream, "<file>");
    Ok(scan.hits)
}

/// Scan every non-test `.rs` file under `dir` (a `tests` directory is test
/// code), naming each file by its `/`-joined path relative to `root`.
fn scan_dir(root: &Path, dir: &Path, hits: &mut BTreeMap<Site, usize>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut paths = Vec::new();
    for entry in entries {
        paths.push(entry.map_err(|e| format!("{}: {e}", dir.display()))?.path());
    }
    paths.sort();
    for path in paths {
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            scan_dir(root, &path, hits)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| format!("{}: {e}", path.display()))?
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let src =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            hits.extend(scan_source(&rel, &src)?);
        }
    }
    Ok(())
}

/// The backend's non-test code holds exactly the allowlisted breaches: a new
/// hand-built literal fails, and so does an allowlist entry gone stale.
#[test]
fn backend_splices_text_only_through_the_literal_owner() -> Result<(), String> {
    let root = e2e_support::manifest_dir!().join("src");
    let mut found = BTreeMap::new();
    scan_dir(&root, &root, &mut found)?;
    let allowed: BTreeMap<Site, usize> = ALLOWED
        .iter()
        .map(|&(file, func, breach, count)| ((file.to_owned(), func.to_owned(), breach), count))
        .collect();
    let unexpected: Vec<_> = found
        .iter()
        .filter(|(site, count)| allowed.get(*site) != Some(*count))
        .collect();
    let stale: Vec<_> = allowed
        .iter()
        .filter(|(site, count)| found.get(*site) != Some(*count))
        .collect();
    assert!(
        unexpected.is_empty() && stale.is_empty(),
        "a text spliced into emitted Rust must go through an `ipe_intern::rust_literal` \
         renderer (`rust_str_lit`, `rust_char_lit`, `rust_fmt_str_lit`, \
         `rust_comment_text`).\nunexpected (site, count): {unexpected:?}\nstale allowlist \
         entries (site, count): {stale:?}"
    );
    Ok(())
}

/// The breaches of a synthetic source, as `(fn, breach, count)`.
fn synthetic(src: &str) -> Result<Vec<(String, Breach, usize)>, String> {
    Ok(scan_source("synthetic.rs", src)?
        .into_iter()
        .map(|((_, func, breach), count)| (func, breach, count))
        .collect())
}

/// Each hand-built literal shape goes red.
#[test]
fn each_hand_built_literal_shape_is_refused() -> Result<(), String> {
    let cases: [(&str, Breach, usize); 6] = [
        (
            r#"fn emit(s: &str) -> String { let mut o = String::new(); o.push_str("\""); o.push_str(s); o.push_str("\""); o }"#,
            Breach::LoneQuote,
            2,
        ),
        (
            r#"fn emit(s: &str) -> String { let mut o = String::new(); o.push('"'); o.push_str(s); o }"#,
            Breach::LoneQuote,
            1,
        ),
        (
            r#"fn emit(s: &str) -> String { format!("\"{}\"", s) }"#,
            Breach::HandQuote,
            1,
        ),
        (
            r#"fn emit() -> &'static str { concat!("\"", "x", "\"") }"#,
            Breach::LoneQuote,
            2,
        ),
        (
            r#"fn emit() -> &'static str { "let x = r#\"" }"#,
            Breach::RawLiteral,
            1,
        ),
        (
            r"fn emit(s: &str) -> String { s.escape_default().to_string() }",
            Breach::EscapeMethod,
            1,
        ),
    ];
    for (src, breach, count) in cases {
        let found = synthetic(src)?;
        assert_eq!(found, vec![("emit".to_owned(), breach, count)], "{src}");
    }
    Ok(())
}

/// One step past each shape: escaped braces, a non-format `"{}"` text, a
/// renderer call and test-only code are accepted.
#[test]
fn owner_rendered_and_test_only_text_is_accepted() -> Result<(), String> {
    for src in [
        r#"fn ok(l: &str, r: &str) -> String { format!("format!(\"{{}}{{}}\", {l}, {r})") }"#,
        r#"fn ok() -> Doc { Doc::text("\"{}{}\"") }"#,
        r#"fn ok(s: &str) -> String { format!("{}.to_string()", rust_str_lit(s)) }"#,
        r#"fn ok(s: &str) -> bool { s.starts_with('"') || s == "\"\"" }"#,
        r#"#[cfg(test)] mod tests { fn t() -> String { format!("\"{}\"", 1) } }"#,
        r#"#[test] fn t() { let _ = format!("\"{}\"", 1); }"#,
    ] {
        assert_eq!(synthetic(src)?, vec![], "{src}");
    }
    Ok(())
}
