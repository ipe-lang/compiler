//! No backend-referenced Rust name can be spelled by an emitted user local.
//!
//! `naming::local_ident` emits a user local with no `_` verbatim and moves
//! every other one to `USER_LOCAL_ESCAPE` + name, so its image starts with
//! `__u_`. A Rust `let` local shadows a same-named fn item, so that keeps a
//! user local apart from the names the backend refers to bare only while
//!
//! - no temporary the backend mints, and no name its templates carry, starts
//!   with `__u_`; and
//! - no emitted call names an `_`-free function bare.
//!
//! This ratchet lexes every non-test function of `backend/rust/src` and refuses
//! each string literal that can spell a name in the escaped namespace: one
//! holding `__u_`, one holding `__u` right before a format placeholder, and one
//! ending in `__u` (a prefix glued on by a push). Its single sanctioned site is
//! the `USER_LOCAL_ESCAPE` const itself. It also refuses each bare call an
//! emitted literal spells with an `_`-free lowercase head (`curry2(`,
//! `curry{n}(`), which a user local of that name would shadow: such a call must
//! go through a path (`ipe_runtime::json::curry2(`). Its sanctioned sites are
//! the non-Rust text the backend emits, listed in `BARE_CALL_ALLOWED`. The
//! emitted templates under `backend/rust/templates` are refused on any `__u_`.

use std::collections::BTreeMap;
use std::path::Path;

use proc_macro2::{Delimiter, TokenStream, TokenTree};

/// Where a refused literal sits: the file relative to `src`, and the innermost
/// named fn or const.
type Site = (String, String);

/// Sites paired with how many refused literals each holds.
type SiteCounts = Vec<(Site, usize)>;

/// The one sanctioned site: the escape prefix const in `naming.rs`.
const ALLOWED: &[(&str, &str, usize)] = &[("naming.rs", "USER_LOCAL_ESCAPE", 1)];

/// The sanctioned bare calls, none of them Rust: the wasm boot module's
/// `init(` is JavaScript, and a tuple-arm diagnostic counts `column(s)`.
const BARE_CALL_ALLOWED: &[(&str, &str, usize)] = &[
    ("emit_expr/patterns.rs", "emit_tuple_arm_head", 1),
    ("project.rs", "shell_boot_js", 1),
];

/// Words a literal may put before `(` that are no value-namespace call: Rust
/// keywords and the attribute and `cfg` predicate words.
const NOT_A_CALL: &[&str] = &[
    "allow", "all", "any", "as", "break", "cfg", "continue", "crate", "deny", "derive", "doc",
    "dyn", "else", "expect", "fn", "for", "if", "impl", "in", "inline", "let", "loop", "match",
    "mod", "move", "mut", "not", "pub", "ref", "repr", "return", "self", "super", "unsafe", "use",
    "warn", "where", "while",
];

/// How many bare calls with an `_`-free lowercase head `text` spells.
///
/// A head is a maximal run of lowercase ASCII letters and digits starting with
/// a letter, optionally followed by one format placeholder, then `(`. It is not
/// bare when an identifier byte, `:`, `.`, `'`, `$`, `#`, `-`, `!` or `}`
/// precedes it (a path, a method, a lifetime, a raw string, a CSS value, a
/// macro, a glued placeholder), nor when it follows `fn ` (a definition).
fn bare_calls(text: &str) -> usize {
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let bytes = text.as_bytes();
    let mut count = 0;
    let mut start = 0;
    while let Some(&first) = bytes.get(start) {
        if !ident(first) {
            start += 1;
            continue;
        }
        let mut end = start;
        while bytes.get(end).copied().is_some_and(ident) {
            end += 1;
        }
        let word = text.get(start..end).unwrap_or_default();
        let before = start.checked_sub(1).and_then(|i| bytes.get(i).copied());
        let mut after = end;
        if bytes.get(after) == Some(&b'{') {
            while bytes.get(after).is_some_and(|&b| b != b'}') {
                after += 1;
            }
            after += 1;
        }
        let head = first.is_ascii_lowercase()
            && word
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        let opens = bytes.get(after) == Some(&b'(');
        let glued = before.is_some_and(|b| b":.'$#-!}".contains(&b));
        let defined = text
            .get(..start)
            .and_then(|pre| pre.trim_end().strip_suffix("fn"))
            .is_some_and(|pre| !pre.bytes().next_back().is_some_and(ident));
        if head && opens && !glued && !defined && !NOT_A_CALL.contains(&word) {
            count += 1;
        }
        start = end;
    }
    count
}

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

/// Whether a literal's text can spell a name inside the escaped namespace.
fn spells_escaped(text: &str) -> bool {
    text.contains("__u_") || text.contains("__u{") || text.ends_with("__u")
}

/// Whether `tok` is the punctuation `ch`.
fn is_punct(tok: Option<&TokenTree>, ch: char) -> bool {
    matches!(tok, Some(TokenTree::Punct(p)) if p.as_char() == ch)
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

/// The refused-literal counter over one file's token tree.
struct Scan<'a> {
    file: &'a str,
    hits: BTreeMap<Site, usize>,
    bare: BTreeMap<Site, usize>,
}

impl Scan<'_> {
    /// Scan one token sequence inside the innermost named item `item`, skipping
    /// attributes (doc comments included) and every item gated by `#[test]` or
    /// `#[cfg(test)]`.
    fn stream(&mut self, stream: &TokenStream, item: &str) {
        let toks: Vec<TokenTree> = stream.clone().into_iter().collect();
        let mut test_gated = false;
        let mut i = 0;
        while let Some(tok) = toks.get(i) {
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
                // A named item whose body runs to the next `;` or brace group.
                let lifetime = i
                    .checked_sub(1)
                    .is_some_and(|prev| is_punct(toks.get(prev), '\''));
                if matches!(word.as_str(), "fn" | "mod" | "const" | "static")
                    && !lifetime
                    && let Some(TokenTree::Ident(name)) = toks.get(i + 1)
                    && !matches!(
                        name.to_string().as_str(),
                        "fn" | "unsafe" | "async" | "extern" | "mut"
                    )
                {
                    let mut k = i + 2;
                    let mut body = TokenStream::new();
                    while let Some(t) = toks.get(k) {
                        if is_punct(Some(t), ';') {
                            break;
                        }
                        if word != "const"
                            && word != "static"
                            && let TokenTree::Group(g) = t
                            && g.delimiter() == Delimiter::Brace
                        {
                            break;
                        }
                        body.extend([t.clone()]);
                        k += 1;
                    }
                    if let Some(TokenTree::Group(g)) = toks.get(k)
                        && g.delimiter() == Delimiter::Brace
                    {
                        body.extend([TokenTree::Group(g.clone())]);
                    }
                    if !test_gated {
                        let name = name.to_string();
                        let inner_item = if word == "mod" { item } else { name.as_str() };
                        self.stream(&body, inner_item);
                    }
                    test_gated = false;
                    i = k + 1;
                    continue;
                }
            }
            if let Some(text) = str_value(tok) {
                let site = (self.file.to_owned(), item.to_owned());
                if spells_escaped(&text) {
                    *self.hits.entry(site.clone()).or_insert(0) += 1;
                }
                let calls = bare_calls(&text);
                if calls > 0 {
                    *self.bare.entry(site).or_insert(0) += calls;
                }
            }
            if let TokenTree::Group(g) = tok {
                let brace = g.delimiter() == Delimiter::Brace;
                if !(brace && test_gated) {
                    self.stream(&g.stream(), item);
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

/// The refused sites of one source file, keyed by `(file, item)`.
struct Refused {
    /// The literals spelling a name in the escaped namespace.
    escaped: BTreeMap<Site, usize>,
    /// The bare calls with an `_`-free head.
    bare: BTreeMap<Site, usize>,
}

/// The refused sites in one source file.
fn scan_source(file: &str, src: &str) -> Result<Refused, String> {
    let stream: TokenStream = src
        .parse()
        .map_err(|e| format!("{file} does not lex: {e}"))?;
    let mut scan = Scan {
        file,
        hits: BTreeMap::new(),
        bare: BTreeMap::new(),
    };
    scan.stream(&stream, "<file>");
    Ok(Refused {
        escaped: scan.hits,
        bare: scan.bare,
    })
}

/// The found sites that disagree with `allowed`, and the allowlist entries no site matches.
fn drift(
    found: &BTreeMap<Site, usize>,
    allowed: &[(&str, &str, usize)],
) -> (SiteCounts, SiteCounts) {
    let allowed: BTreeMap<Site, usize> = allowed
        .iter()
        .map(|&(file, item, count)| ((file.to_owned(), item.to_owned()), count))
        .collect();
    let unexpected = found
        .iter()
        .filter(|(site, count)| allowed.get(*site) != Some(*count))
        .map(|(site, count)| (site.clone(), *count))
        .collect();
    let stale = allowed
        .iter()
        .filter(|(site, count)| found.get(*site) != Some(*count))
        .map(|(site, count)| (site.clone(), *count))
        .collect();
    (unexpected, stale)
}

/// The sorted files under `dir`, recursively, skipping `tests` directories.
fn files_under(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<(), String> {
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
            files_under(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

/// The `/`-joined path of `path` relative to `root`.
fn rel(root: &Path, path: &Path) -> Result<String, String> {
    Ok(path
        .strip_prefix(root)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/"))
}

/// The backend's non-test code spells the escape only in its const, and no
/// emitted template carries a name in the escaped namespace.
#[test]
fn no_backend_name_enters_the_escaped_user_local_namespace() -> Result<(), String> {
    let manifest = e2e_support::manifest_dir!();
    let src_root = manifest.join("src");
    let mut files = Vec::new();
    files_under(&src_root, &mut files)?;
    let mut found = BTreeMap::new();
    let mut bare = BTreeMap::new();
    let mut scanned = 0usize;
    for path in &files {
        if path.extension().is_some_and(|e| e == "rs") {
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let refused = scan_source(&rel(&src_root, path)?, &text)?;
            found.extend(refused.escaped);
            bare.extend(refused.bare);
            scanned += 1;
        }
    }
    assert!(
        scanned > 20,
        "the scan read only {scanned} backend source files"
    );
    let (unexpected, stale) = drift(&found, ALLOWED);
    assert!(
        unexpected.is_empty() && stale.is_empty(),
        "a backend temporary must not start with `__u_`, the escaped user-local prefix of \
         `naming::local_ident`.\nunexpected (site, count): {unexpected:?}\nstale allowlist \
         entries (site, count): {stale:?}"
    );
    let (unexpected, stale) = drift(&bare, BARE_CALL_ALLOWED);
    assert!(
        unexpected.is_empty() && stale.is_empty(),
        "an emitted call to an `_`-free function must go through a path (`ipe_runtime::json::\
         curry2(`): a user local of that name, which `naming::local_ident` emits verbatim, \
         would shadow the bare call.\nunexpected (site, count): {unexpected:?}\nstale \
         allowlist entries (site, count): {stale:?}"
    );

    let templates_root = manifest.join("templates");
    let mut templates = Vec::new();
    files_under(&templates_root, &mut templates)?;
    assert!(!templates.is_empty(), "no emitted templates found");
    for path in &templates {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        assert!(
            !text.contains("__u_"),
            "the emitted template {} carries a name in the escaped user-local namespace `__u_`",
            rel(&templates_root, path)?
        );
    }
    Ok(())
}

/// The refused literals of a synthetic source, as `(item, count)`.
fn synthetic(src: &str) -> Result<Vec<(String, usize)>, String> {
    Ok(scan_source("synthetic.rs", src)?
        .escaped
        .into_iter()
        .map(|((_, item), count)| (item, count))
        .collect())
}

/// The bare calls of a synthetic source, as `(item, count)`.
fn synthetic_bare(src: &str) -> Result<Vec<(String, usize)>, String> {
    Ok(scan_source("synthetic.rs", src)?
        .bare
        .into_iter()
        .map(|((_, item), count)| (item, count))
        .collect())
}

/// Each bare call with an `_`-free head goes red.
#[test]
fn each_bare_underscore_free_call_is_refused() -> Result<(), String> {
    for (src, item, count) in [
        (
            r#"fn emit(n: usize, f: &str) -> String { format!("decode_succeed(curry{n}({f}))") }"#,
            "emit",
            1,
        ),
        (r#"fn emit() -> &'static str { "curry2(f)" }"#, "emit", 1),
        (
            r#"fn emit() -> &'static str { "let y = (helper(x));" }"#,
            "emit",
            1,
        ),
        (r#"fn emit() -> &'static str { "{ drop(x); }" }"#, "emit", 1),
        (r#"fn emit() -> &'static str { "a(b(c))" }"#, "emit", 2),
        (r#"const CALL: &str = "f2(x)";"#, "CALL", 1),
    ] {
        assert_eq!(
            synthetic_bare(src)?,
            vec![(item.to_owned(), count)],
            "{src}"
        );
    }
    Ok(())
}

/// One step past each bare call: a path, a method, an `_`-bearing head, a
/// definition, a macro, an attribute, a CSS value, and test code are accepted.
#[test]
fn qualified_and_non_call_parentheses_are_accepted() -> Result<(), String> {
    for src in [
        r#"fn ok(n: usize) -> String { format!("ipe_runtime::json::curry{n}(f)") }"#,
        r#"fn ok() -> &'static str { "x.len()" }"#,
        r#"fn ok() -> &'static str { "string_from_int(x)" }"#,
        r#"fn ok() -> &'static str { "Some(x)" }"#,
        r#"fn ok() -> &'static str { "fn main() {}" }"#,
        r#"fn ok() -> &'static str { "pub(crate) fn go(x: i64) {}" }"#,
        r#"fn ok() -> &'static str { "vec![x]; format!("{}", x)" }"#,
        r##"fn ok() -> &'static str { "#[cfg(not(any(test)))] #[derive(Clone)]" }"##,
        r#"fn ok() -> &'static str { "cubic-bezier(0, 0, 1, 1)" }"#,
        r#"fn ok(p: &str) -> String { format!("{p}x(y)") }"#,
        r#"fn ok() -> &'static str { "if (x) { match (y) {} }" }"#,
        r#"#[test] fn t() { let _ = "curry2(f)"; }"#,
        r#"#[cfg(test)] mod tests { fn t() -> &'static str { "g(x)" } }"#,
    ] {
        assert_eq!(synthetic_bare(src)?, vec![], "{src}");
    }
    Ok(())
}

/// Each way a backend literal can mint a name in the escaped namespace goes red.
#[test]
fn each_escaped_namespace_spelling_is_refused() -> Result<(), String> {
    for (src, item) in [
        (
            r#"fn emit() -> String { "let __u_tmp = 0;".to_owned() }"#,
            "emit",
        ),
        (
            r#"fn emit(n: u32) -> String { format!("__u__ipe_t{n}") }"#,
            "emit",
        ),
        (
            r#"fn emit(s: &str) -> String { format!("__u{s}") }"#,
            "emit",
        ),
        (
            r#"fn emit(s: &str) -> String { format!("__u{}", s) }"#,
            "emit",
        ),
        (
            r#"fn emit(s: &str) -> String { let mut o = String::from("__u"); o.push_str(s); o }"#,
            "emit",
        ),
        (r#"const PREFIX: &str = "__u";"#, "PREFIX"),
        (
            r#"const fn emit() -> &'static str { "__u_x" } const OTHER: u8 = 0;"#,
            "emit",
        ),
        (
            r#"mod m { fn emit() -> String { format!("{}", "__u_x") } }"#,
            "emit",
        ),
    ] {
        assert_eq!(synthetic(src)?, vec![(item.to_owned(), 1)], "{src}");
    }
    Ok(())
}

/// One step past each spelling: the existing `__u`-led temporaries, a doc
/// comment, and test-only code are accepted.
#[test]
fn temporaries_outside_the_escaped_namespace_are_accepted() -> Result<(), String> {
    for src in [
        r#"fn ok(n: u32) -> String { format!("__ui_f{n}") }"#,
        r#"fn ok() -> &'static str { "__update" }"#,
        r#"fn ok() -> &'static str { "__unmarked" }"#,
        r#"fn ok(n: u32) -> String { format!("__ipe_bind_{n}") }"#,
        r#"fn ok() -> &'static str { "_ipe_recursion_guard" }"#,
        "/// Names start with `__u_`.\nfn ok() {}",
        r#"#[cfg(test)] mod tests { fn t() -> String { "__u_x".to_owned() } }"#,
        r#"#[test] fn t() { let _ = "__u__x"; }"#,
    ] {
        assert_eq!(synthetic(src)?, vec![], "{src}");
    }
    Ok(())
}
