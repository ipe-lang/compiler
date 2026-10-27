//! No backend-minted Rust name enters the escaped user-local namespace.
//!
//! `naming::local_ident` moves every `_`-leading user local to
//! `USER_LOCAL_ESCAPE` + name, so its image starts with `__u_`. That keeps a
//! user local apart from the backend's own temporaries only while no temporary
//! the backend mints, and no name its templates carry, starts with `__u_`
//! itself. This ratchet lexes every non-test function of `backend/rust/src` and
//! refuses each string literal that can spell such a name: one holding `__u_`,
//! one holding `__u` right before a format placeholder, and one ending in
//! `__u` (a prefix glued on by a push). The emitted templates under
//! `backend/rust/templates` are refused on any `__u_`. The single sanctioned
//! site is the `USER_LOCAL_ESCAPE` const itself.

use std::collections::BTreeMap;
use std::path::Path;

use proc_macro2::{Delimiter, TokenStream, TokenTree};

/// Where a refused literal sits: the file relative to `src`, and the innermost
/// named fn or const.
type Site = (String, String);

/// The one sanctioned site: the escape prefix const in `naming.rs`.
const ALLOWED: &[(&str, &str, usize)] = &[("naming.rs", "USER_LOCAL_ESCAPE", 1)];

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
            if str_value(tok).is_some_and(|text| spells_escaped(&text)) {
                *self
                    .hits
                    .entry((self.file.to_owned(), item.to_owned()))
                    .or_insert(0) += 1;
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

/// The refused literals in one source file, keyed by `(file, item)`.
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
    let mut scanned = 0usize;
    for path in &files {
        if path.extension().is_some_and(|e| e == "rs") {
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            found.extend(scan_source(&rel(&src_root, path)?, &text)?);
            scanned += 1;
        }
    }
    assert!(
        scanned > 20,
        "the scan read only {scanned} backend source files"
    );
    let allowed: BTreeMap<Site, usize> = ALLOWED
        .iter()
        .map(|&(file, item, count)| ((file.to_owned(), item.to_owned()), count))
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
        "a backend temporary must not start with `__u_`, the escaped user-local prefix of \
         `naming::local_ident`.\nunexpected (site, count): {unexpected:?}\nstale allowlist \
         entries (site, count): {stale:?}"
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
        .into_iter()
        .map(|((_, item), count)| (item, count))
        .collect())
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
