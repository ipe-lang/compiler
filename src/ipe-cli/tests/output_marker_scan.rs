#![forbid(unsafe_code)]
//! Refuses any reach for the output ownership names outside the one claim owner.
//!
//! `output_dir/held.rs` (with its platform modules under `output_dir/held/`)
//! is the one place that creates, reads, renames, or unlinks the ownership
//! marker and the claim file, through a held directory and the claim protocol.
//! This ratchet lexes every non-test item of the `ipe` crate's `src/` and
//! holds each mention of [`NAMES`] (as an identifier, or as its exact value
//! spelled by a string, byte string, or C string literal or joined by a
//! `concat!` of literals) outside that owner to [`ALLOWED`], by
//! `(file, fn, breach, count)`.
//! It also refuses a definition of a retired path-based ownership check, and a
//! `pub` claim step in the owner, so the protocol cannot be bypassed from a
//! sibling module. An entry whose count no longer matches is drift and fails.

use std::collections::BTreeMap;
use std::path::Path;

use proc_macro2::{Delimiter, TokenStream, TokenTree};

/// The reserved ownership names, as their constant and their string value.
const NAMES: [(&str, &str); 2] = [
    ("OWNERSHIP_MARKER", ".ipe-output"),
    ("CLAIM_FILE", ".ipe-output.claim"),
];

/// The one claim owner, relative to `src/`.
const OWNER: &str = "output_dir/held.rs";

/// The directory of the owner's platform modules, relative to `src/`.
const OWNER_DIR: &str = "output_dir/held/";

/// Retired path-based ownership checks no module may define again.
const RETIRED: [&str; 4] = ["has_marker", "adopt", "is_empty_dir", "write_marker"];

/// The claim steps the owner must keep private.
const PRIVATE_STEPS: [&str; 7] = [
    "publish_marker",
    "mark_finalizing",
    "claim_locked",
    "commit",
    "publish",
    "lock_claim",
    "unlink_ours",
];

/// One reach the scan counts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Breach {
    /// The constant named outside the owner.
    Name(&'static str),
    /// The constant's exact string value written outside the owner.
    Literal(&'static str),
    /// A retired ownership check defined.
    Retired(String),
    /// A claim step of the owner made `pub`.
    PublicStep(String),
}

/// Where a breach sits: the file relative to `src/`, and the innermost named fn.
type Site = (String, String, Breach);

/// The sanctioned reaches outside the owner: the definitions, the refusal
/// messages naming the files, the listing classifier, and the handover that
/// removes the marker of a directory released to the user.
const ALLOWED: &[(&str, &str, Breach, usize)] = &[
    (
        "output_dir.rs",
        "<file>",
        Breach::Name("OWNERSHIP_MARKER"),
        1,
    ),
    ("output_dir.rs", "<file>", Breach::Name("CLAIM_FILE"), 1),
    (
        "output_dir.rs",
        "<file>",
        Breach::Literal("OWNERSHIP_MARKER"),
        1,
    ),
    ("output_dir.rs", "<file>", Breach::Literal("CLAIM_FILE"), 1),
    ("output_dir.rs", "fmt", Breach::Name("OWNERSHIP_MARKER"), 3),
    ("output_dir.rs", "fmt", Breach::Name("CLAIM_FILE"), 3),
    (
        "output_dir.rs",
        "tolerated_entry",
        Breach::Name("OWNERSHIP_MARKER"),
        1,
    ),
    (
        "output_dir.rs",
        "tolerated_entry",
        Breach::Name("CLAIM_FILE"),
        1,
    ),
    (
        "output_dir.rs",
        "release_to_user",
        Breach::Name("OWNERSHIP_MARKER"),
        1,
    ),
];

/// The text a literal token spells, `None` for any other token.
///
/// A string, a byte string, and a C string all spell the name they carry
/// (a byte or C string that is not UTF-8 spells none); a character or a
/// number spells what `concat!` would join for it.
fn literal_text(tok: &TokenTree) -> Option<String> {
    let TokenTree::Literal(lit) = tok else {
        return None;
    };
    match syn::parse2::<syn::Lit>(TokenStream::from(TokenTree::Literal(lit.clone()))) {
        Ok(syn::Lit::Str(s)) => Some(s.value()),
        Ok(syn::Lit::ByteStr(b)) => String::from_utf8(b.value()).ok(),
        Ok(syn::Lit::CStr(c)) => c.value().into_string().ok(),
        Ok(syn::Lit::Char(c)) => Some(c.value().to_string()),
        Ok(syn::Lit::Int(i)) => Some(i.base10_digits().to_owned()),
        Ok(syn::Lit::Float(f)) => Some(f.base10_digits().to_owned()),
        Ok(_) | Err(_) => None,
    }
}

/// The text a `concat!` over `args` joins, `None` when a piece is not a literal.
///
/// Each comma-separated piece is a literal, `true`/`false`, or a nested
/// `concat!`; any other piece (a macro variable, `env!`) has no text a lexer
/// can know.
fn concat_text(args: &proc_macro2::Group) -> Option<String> {
    let toks: Vec<TokenTree> = args.stream().into_iter().collect();
    let mut joined = String::new();
    for piece in toks.split(|t| is_punct(Some(t), ',')) {
        match piece {
            [] => {}
            [lit @ TokenTree::Literal(_)] => joined.push_str(&literal_text(lit)?),
            [TokenTree::Ident(id)] if id == "true" || id == "false" => {
                joined.push_str(&id.to_string());
            }
            [TokenTree::Ident(id), bang, TokenTree::Group(inner)]
                if id == "concat" && is_punct(Some(bang), '!') =>
            {
                joined.push_str(&concat_text(inner)?);
            }
            _ => return None,
        }
    }
    Some(joined)
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

/// Whether the `fn` keyword at `at` follows a `pub` visibility, past any
/// `const`/`async`/`extern` qualifier and a `pub(..)` restriction.
fn is_public_fn(toks: &[TokenTree], at: usize) -> bool {
    let mut k = at;
    while let Some(prev) = k.checked_sub(1) {
        let qualifier = match toks.get(prev) {
            Some(TokenTree::Ident(id)) if id == "pub" => return true,
            Some(TokenTree::Ident(id)) => id == "const" || id == "async" || id == "extern",
            Some(TokenTree::Group(g)) => g.delimiter() == Delimiter::Parenthesis,
            Some(TokenTree::Literal(_)) => true,
            Some(TokenTree::Punct(_)) | None => false,
        };
        if !qualifier {
            return false;
        }
        k = prev;
    }
    false
}

/// The breach counter over one file's token tree.
struct Scan<'a> {
    file: &'a str,
    owner: bool,
    hits: BTreeMap<Site, usize>,
}

impl Scan<'_> {
    /// Count one `breach` in `func`.
    fn hit(&mut self, func: &str, breach: Breach) {
        let seen = self
            .hits
            .entry((self.file.to_owned(), func.to_owned(), breach))
            .or_insert(0);
        *seen = seen.saturating_add(1);
    }

    /// Count a reserved name or value `tok` outside the owner.
    fn reach(&mut self, tok: &TokenTree, func: &str) {
        if self.owner {
            return;
        }
        for (name, value) in NAMES {
            if matches!(tok, TokenTree::Ident(id) if id == name) {
                self.hit(func, Breach::Name(name));
            }
            if literal_text(tok).as_deref() == Some(value) {
                self.hit(func, Breach::Literal(name));
            }
        }
    }

    /// Count a `concat!` over `args` that joins to a reserved value outside the owner.
    fn concat_reach(&mut self, args: &proc_macro2::Group, func: &str) {
        if self.owner {
            return;
        }
        let Some(joined) = concat_text(args) else {
            return;
        };
        for (name, value) in NAMES {
            if joined == value {
                self.hit(func, Breach::Literal(name));
            }
        }
    }

    /// Scan one token sequence inside the innermost named fn `func`, skipping
    /// every item gated by `#[test]` or `#[cfg(test)]`.
    fn stream(&mut self, stream: &TokenStream, func: &str) {
        let toks: Vec<TokenTree> = stream.clone().into_iter().collect();
        let mut test_gated = false;
        let mut i = 0;
        while let Some(tok) = toks.get(i) {
            if is_punct(Some(tok), '#') {
                let inner = is_punct(toks.get(i.saturating_add(1)), '!');
                let at = i.saturating_add(if inner { 2 } else { 1 });
                if let Some(TokenTree::Group(g)) = toks.get(at)
                    && g.delimiter() == Delimiter::Bracket
                {
                    if !inner && is_test_attr(&g.stream()) {
                        test_gated = true;
                    }
                    i = at.saturating_add(1);
                    continue;
                }
            }
            if let TokenTree::Ident(id) = tok {
                let word = id.to_string();
                if (word == "fn" || word == "mod")
                    && let Some(TokenTree::Ident(name)) = toks.get(i.saturating_add(1))
                {
                    let name = name.to_string();
                    if word == "fn" && RETIRED.contains(&name.as_str()) {
                        self.hit(func, Breach::Retired(name.clone()));
                    }
                    if word == "fn"
                        && self.owner
                        && PRIVATE_STEPS.contains(&name.as_str())
                        && is_public_fn(&toks, i)
                    {
                        self.hit(func, Breach::PublicStep(name.clone()));
                    }
                    let mut k = i.saturating_add(2);
                    while let Some(t) = toks.get(k) {
                        if is_punct(Some(t), ';')
                            || matches!(t, TokenTree::Group(g) if g.delimiter() == Delimiter::Brace)
                        {
                            break;
                        }
                        if !test_gated {
                            self.reach(t, func);
                        }
                        k = k.saturating_add(1);
                    }
                    if let Some(TokenTree::Group(body)) = toks.get(k)
                        && body.delimiter() == Delimiter::Brace
                        && !test_gated
                    {
                        let inner_fn = if word == "fn" { name.as_str() } else { func };
                        self.stream(&body.stream(), inner_fn);
                    }
                    test_gated = false;
                    i = k.saturating_add(1);
                    continue;
                }
            }
            if !test_gated
                && matches!(tok, TokenTree::Ident(id) if id == "concat")
                && is_punct(toks.get(i.saturating_add(1)), '!')
                && let Some(TokenTree::Group(args)) = toks.get(i.saturating_add(2))
            {
                self.concat_reach(args, func);
            }
            if let TokenTree::Group(g) = tok {
                let brace = g.delimiter() == Delimiter::Brace;
                if !(test_gated && brace) {
                    self.stream(&g.stream(), func);
                }
                if brace {
                    test_gated = false;
                }
            } else if !test_gated {
                self.reach(tok, func);
            }
            if is_punct(Some(tok), ';') {
                test_gated = false;
            }
            i = i.saturating_add(1);
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
        owner: file == OWNER || file.starts_with(OWNER_DIR),
        hits: BTreeMap::new(),
    };
    scan.stream(&stream, "<file>");
    Ok(scan.hits)
}

/// Directory nesting the walk descends before refusing to go deeper.
const MAX_DEPTH: usize = 16;

/// Scan every non-test `.rs` file under `dir` (a `tests` directory is test
/// code), naming each file by its `/`-joined path relative to `root`.
fn scan_dir(
    root: &Path,
    dir: &Path,
    depth: usize,
    hits: &mut BTreeMap<Site, usize>,
) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!(
            "source tree deeper than {MAX_DEPTH}: {}",
            dir.display()
        ));
    }
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
            scan_dir(root, &path, depth.saturating_add(1), hits)?;
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

/// The `(site, count)` pairs of `found` that differ from [`ALLOWED`], either way.
fn drift(found: &BTreeMap<Site, usize>) -> Vec<String> {
    let allowed: BTreeMap<Site, usize> = ALLOWED
        .iter()
        .map(|(file, func, breach, count)| {
            (
                ((*file).to_owned(), (*func).to_owned(), breach.clone()),
                *count,
            )
        })
        .collect();
    let mut out: Vec<String> = found
        .iter()
        .filter(|(site, count)| allowed.get(*site) != Some(*count))
        .map(|(site, count)| format!("unexpected {site:?} x{count}"))
        .collect();
    out.extend(
        allowed
            .iter()
            .filter(|(site, count)| found.get(*site) != Some(*count))
            .map(|(site, count)| format!("stale allowance {site:?} x{count}")),
    );
    out
}

/// The non-test code reaches the ownership names only through the claim owner.
#[test]
fn ownership_names_are_reached_only_through_the_claim_owner() -> Result<(), String> {
    let root = e2e_support::manifest_dir!().join("src");
    let mut found = BTreeMap::new();
    scan_dir(&root, &root, 0, &mut found)?;
    let drift = drift(&found);
    assert!(
        drift.is_empty(),
        "the ownership marker and the claim file are created, read, and removed only by \
         `output_dir::held` through the claim protocol:\n{}",
        drift.join("\n")
    );
    Ok(())
}

/// The breaches of a synthetic source at `file`.
fn synthetic(file: &str, src: &str) -> Result<Vec<(String, Breach, usize)>, String> {
    Ok(scan_source(file, src)?
        .into_iter()
        .map(|((_, func, breach), count)| (func, breach, count))
        .collect())
}

/// Each reach outside the owner, a retired check, and a public claim step go red.
#[test]
fn each_planted_reach_is_refused() -> Result<(), String> {
    let cases: [(&str, &str, Breach); 11] = [
        (
            "build.rs",
            "fn mark(d: &Path) { std::fs::write(d.join(crate::output_dir::OWNERSHIP_MARKER), b\"\"); }",
            Breach::Name("OWNERSHIP_MARKER"),
        ),
        (
            "clean.rs",
            "fn drop_claim(d: &Path) { let _ = std::fs::remove_file(d.join(CLAIM_FILE)); }",
            Breach::Name("CLAIM_FILE"),
        ),
        (
            "cache.rs",
            "fn owned(d: &Path) -> bool { d.join(\".ipe-output\").is_file() }",
            Breach::Literal("OWNERSHIP_MARKER"),
        ),
        (
            "output_dir.rs",
            "fn sneak(d: &Path) { let _ = d.join(\".ipe-output.claim\"); }",
            Breach::Literal("CLAIM_FILE"),
        ),
        (
            "cache.rs",
            "fn owned(d: &Path) -> bool { d.join(std::str::from_utf8(b\".ipe-output\").unwrap_or_default()).is_file() }",
            Breach::Literal("OWNERSHIP_MARKER"),
        ),
        (
            "clean.rs",
            "fn sneak() -> &'static CStr { c\".ipe-output.claim\" }",
            Breach::Literal("CLAIM_FILE"),
        ),
        (
            "clean.rs",
            "fn sneak(d: &Path) { let _ = d.join(concat!(\".ipe-\", \"output\", \".claim\")); }",
            Breach::Literal("CLAIM_FILE"),
        ),
        (
            "cache.rs",
            "fn owned(d: &Path) -> bool { d.join(concat!(\".ipe-\", concat!(\"out\", \"put\"),)).is_file() }",
            Breach::Literal("OWNERSHIP_MARKER"),
        ),
        (
            "output_dir/held.rs",
            "impl HeldDir { pub fn has_marker(&self) -> bool { true } }",
            Breach::Retired("has_marker".to_owned()),
        ),
        (
            "output_dir/held.rs",
            "impl HeldDir { pub fn publish_marker(&self) {} }",
            Breach::PublicStep("publish_marker".to_owned()),
        ),
        (
            "output_dir/held.rs",
            "impl HeldDir { pub(crate) const fn commit(&self) {} }",
            Breach::PublicStep("commit".to_owned()),
        ),
    ];
    for (file, src, breach) in cases {
        let found = synthetic(file, src)?;
        assert!(
            found.iter().any(|(_, b, _)| *b == breach),
            "{file}: {src} must report {breach:?}, got {found:?}"
        );
        let planted = scan_source(file, src)?;
        assert!(
            !drift(&planted).is_empty(),
            "{file}: {src} must drift from the allowance"
        );
    }
    Ok(())
}

/// The owner, test items, and doc comments may name the files freely.
#[test]
fn the_owner_tests_and_docs_are_not_reaches() -> Result<(), String> {
    let clean = [
        (
            "output_dir/held.rs",
            "fn publish_marker(&self) { let _ = OWNERSHIP_MARKER; let _ = \".ipe-output.claim\"; }",
        ),
        (
            "output_dir/held/unix.rs",
            "pub fn create_claim() { let _ = CLAIM_FILE; }",
        ),
        (
            "clean.rs",
            "#[cfg(test)]\nmod tests { fn t() { let _ = crate::output_dir::CLAIM_FILE; } }",
        ),
        ("cache.rs", "#[test]\nfn t() { let _ = \".ipe-output\"; }"),
        (
            "text.rs",
            "fn m() { let _ = concat!(\".ipe-\", \"out\"); let _ = concat!(\"ipe\", $tail); }",
        ),
        (
            "cache.rs",
            "/// Reads only from a dir holding an [`OWNERSHIP_MARKER`].\nfn read() {}",
        ),
    ];
    for (file, src) in clean {
        let found = synthetic(file, src)?;
        assert!(found.is_empty(), "{file}: {src} is no reach, got {found:?}");
    }
    Ok(())
}
