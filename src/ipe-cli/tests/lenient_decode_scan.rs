#![forbid(unsafe_code)]
//! Pins the runtime's lenient decoders, a second layer beneath the clippy deny.
//!
//! Every URL component the runtime reads is decoded by the one strict core,
//! `encoding::decode_component` / `encoding::decode_form_query`. The runtime
//! `clippy.toml` denies the lenient percent decoders, the lenient query readers,
//! axum's lenient `Query`/`Form` extractors and lossy UTF-8; this scan pins that
//! set independently: no runtime source names a lenient percent decoder or a
//! lenient extractor at all, no runtime source glob-imports a module holding
//! one or re-exports a denied path, and each lenient query reader and lossy
//! UTF-8 conversion appears only at the inventoried sites below.
//!
//! A path counts however it is spelled: through a nested `use` group, an `as`
//! alias, a crate-root re-export, a module alias, a bare call to an imported
//! function, or a `pub use` / `pub(…) use` re-export (a site in its own file,
//! and refused, since the calls it enables elsewhere name no denied path).
//! `src/clippy_paths_resolve.rs` names every denied path on purpose (so a stale
//! `clippy.toml` path is an unresolved-path build error) and is checked against
//! the config instead of scanned.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The runtime crate, relative to the workspace root.
const RUNTIME_ROOT: &str = "src/runtime/rust";

/// The runtime file naming every denied path, so each must resolve.
const PATH_SEAL: &str = "src/clippy_paths_resolve.rs";

/// Spellings of the lenient percent decoders, refused in every runtime source.
const LENIENT_PERCENT_DECODERS: &[&str] =
    &["percent_decode", "percent_decode_str", "decode_utf8_lossy"];

/// axum's lenient request extractors, by every path that names them, refused
/// in every runtime source.
const LENIENT_EXTRACTORS: &[&str] = &["axum::extract::Query", "axum::extract::Form", "axum::Form"];

/// The lossy UTF-8 conversion.
const LOSSY_UTF8: &str = "from_utf8_lossy";

/// Every site that may convert bytes to text lossily, as (runtime-relative
/// file, number of sites), each under a per-site `clippy::disallowed_methods`
/// allow naming its reason.
const LOSSY_TEXT_SITES: &[(&str, usize)] = &[
    // CSV writer output, fed only `String` fields.
    ("src/csv.rs", 1),
    // An email provider's response body.
    ("src/email.rs", 1),
    // HTTP response bodies.
    ("src/http_client.rs", 2),
    // Streamed HTTP response chunks.
    ("src/http_stream.rs", 2),
    // A request body and a WebSocket binary frame.
    ("src/server.rs", 2),
    // Subprocess output.
    ("src/system.rs", 4),
    // Terminal input bytes.
    ("src/tui/key.rs", 1),
    // A test's SSE reader, whose chunks may split a UTF-8 sequence.
    ("src/web/mod.rs", 1),
];

/// The lenient query readers that are methods, matched by name.
const LENIENT_QUERY_METHODS: &[&str] = &["query_pairs"];

/// The lenient query readers that are functions, matched by the path they
/// resolve to.
const LENIENT_QUERY_FUNCTIONS: &[&str] = &[
    "url::form_urlencoded::parse",
    "serde_urlencoded::from_str",
    "serde_urlencoded::from_bytes",
    "serde_urlencoded::from_reader",
];

/// Every site that may read a query leniently, as (runtime-relative file,
/// reader, number of sites).
const LENIENT_QUERY_SITES: &[(&str, &str, usize)] = &[
    // `dom::form::decode_form` re-reading its own `serde_urlencoded` output.
    ("src/dom/form.rs", "serde_urlencoded::from_str", 1),
    // `ssrf::DriverParityQuery`: a database URL read exactly as its driver
    // reads it, so the SSRF gate vets the host the driver dials.
    ("src/ssrf.rs", "query_pairs", 1),
    // A test oracle inverting the query serializer.
    ("src/url.rs", "url::form_urlencoded::parse", 1),
];

/// Every `DriverParityQuery::of` call, as (runtime-relative file, number of
/// calls); each hands it a URL whose userinfo the ambiguity check cleared.
const DRIVER_PARITY_SITES: &[(&str, usize)] = &[
    // A database's SSRF target host.
    ("src/db.rs", 1),
    // The DSN's `sslmode`.
    ("src/dsn.rs", 1),
    // `UnambiguousUrl::query_host`.
    ("src/ssrf.rs", 1),
];

/// The clippy paths the runtime `clippy.toml` denies, exactly.
const DENIED_PATHS: &[&str] = &[
    "std::env::home_dir",
    "percent_encoding::percent_decode_str",
    "percent_encoding::percent_decode",
    "percent_encoding::PercentDecode::decode_utf8_lossy",
    "std::string::String::from_utf8_lossy",
    "url::form_urlencoded::parse",
    "serde_urlencoded::from_str",
    "serde_urlencoded::from_bytes",
    "serde_urlencoded::from_reader",
    "url::Url::query_pairs",
    "axum::extract::Query",
    "axum::extract::Form",
];

/// The paths the runtime `clippy.toml` denies for its other rules (abrupt
/// failure, environment and temp-root reads), which this scan does not own.
const OTHER_RULE_DENIED_PATHS: &[&str] = &[
    "core::option::Option::unwrap_unchecked",
    "core::result::Result::unwrap_unchecked",
    "std::process::abort",
    "std::panic::panic_any",
    "core::hint::unreachable_unchecked",
    "std::env::var",
    "std::env::var_os",
    "std::env::vars",
    "std::env::vars_os",
    "std::env::temp_dir",
];

/// The most alias hops a path is followed through before it counts as
/// resolved.
const MAX_ALIAS_HOPS: usize = 8;

/// The runtime crate's directory.
fn runtime() -> PathBuf {
    e2e_support::manifest_dir!()
        .join("../..")
        .join(RUNTIME_ROOT)
}

/// Whether `c` can continue an identifier.
fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The end of the line comment starting at `i`: the index of its line break.
fn skip_line_comment(chars: &[char], mut i: usize) -> usize {
    while chars.get(i).is_some_and(|&c| c != '\n') {
        i += 1;
    }
    i
}

/// The index past the (nested) block comment opening at `i`, pushing its line
/// breaks to `out`.
fn skip_block_comment(chars: &[char], mut i: usize, out: &mut String) -> usize {
    let mut depth = 0_usize;
    while let Some(&c) = chars.get(i) {
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('*') {
            depth += 1;
            i += 2;
        } else if c == '*' && next == Some('/') {
            depth = depth.saturating_sub(1);
            i += 2;
            if depth == 0 {
                break;
            }
        } else {
            if c == '\n' {
                out.push('\n');
            }
            i += 1;
        }
    }
    i
}

/// The index past the literal whose body starts at `i` and ends at `close`,
/// honouring `\` escapes unless `raw`, pushing its line breaks to `out`.
fn skip_literal_body(
    chars: &[char],
    mut i: usize,
    close: char,
    hashes: usize,
    raw: bool,
    out: &mut String,
) -> usize {
    while let Some(&c) = chars.get(i) {
        if c == '\n' {
            out.push('\n');
        }
        if !raw && c == '\\' {
            if chars.get(i + 1) == Some(&'\n') {
                out.push('\n');
            }
            i += 2;
            continue;
        }
        i += 1;
        if c == close && (0..hashes).all(|k| chars.get(i + k) == Some(&'#')) {
            return i + hashes;
        }
    }
    i
}

/// The raw-string opener at `i` (`r"`, `r#"`, `br"`, `cr#"`, ...): the index of
/// its body and its number of `#`s.
fn raw_string_open(chars: &[char], i: usize) -> Option<(usize, usize)> {
    let mut j = i;
    if matches!(chars.get(j), Some('b' | 'c')) {
        j += 1;
    }
    if chars.get(j) != Some(&'r') {
        return None;
    }
    j += 1;
    let mut hashes = 0;
    while chars.get(j) == Some(&'#') {
        hashes += 1;
        j += 1;
    }
    (chars.get(j) == Some(&'"')).then_some((j + 1, hashes))
}

/// Whether the `'` at `i` opens a character literal rather than a lifetime.
fn opens_char_literal(chars: &[char], i: usize) -> bool {
    chars.get(i + 1) == Some(&'\\') || chars.get(i + 2) == Some(&'\'')
}

/// The code of `src`: every comment dropped and every string, byte-string and
/// character literal's contents blanked, line breaks kept.
fn code_of(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        let next = chars.get(i + 1).copied();
        let after_ident = i
            .checked_sub(1)
            .and_then(|p| chars.get(p))
            .is_some_and(|&p| is_ident(p));
        if c == '/' && next == Some('/') {
            i = skip_line_comment(&chars, i);
        } else if c == '/' && next == Some('*') {
            out.push(' ');
            i = skip_block_comment(&chars, i, &mut out);
        } else if let Some((body, hashes)) = raw_string_open(&chars, i).filter(|_| !after_ident) {
            out.push_str("\"\"");
            i = skip_literal_body(&chars, body, '"', hashes, true, &mut out);
        } else if c == '"' || (matches!(c, 'b' | 'c') && next == Some('"') && !after_ident) {
            let body = if c == '"' { i + 1 } else { i + 2 };
            out.push_str("\"\"");
            i = skip_literal_body(&chars, body, '"', 0, false, &mut out);
        } else if c == 'b' && next == Some('\'') && !after_ident {
            out.push_str("''");
            i = skip_literal_body(&chars, i + 2, '\'', 0, false, &mut out);
        } else if c == '\'' && opens_char_literal(&chars, i) {
            out.push_str("''");
            i = skip_literal_body(&chars, i + 1, '\'', 0, false, &mut out);
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Every `.rs` file under `dir`, as `(runtime-relative path, text)`.
fn rust_sources(dir: &Path, base: &Path, out: &mut Vec<(String, String)>) {
    let entries = std::fs::read_dir(dir);
    assert!(entries.is_ok(), "read {}: {entries:?}", dir.display());
    let Ok(entries) = entries else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let hidden = entry.file_name().to_string_lossy().starts_with('.');
        if hidden {
            continue;
        }
        if path.is_dir() {
            rust_sources(&path, base, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let text = std::fs::read_to_string(&path);
            assert!(text.is_ok(), "read {}: {text:?}", path.display());
            let Ok(text) = text else { continue };
            let rel = path
                .strip_prefix(base)
                .map_or_else(|_| path.clone(), Path::to_path_buf);
            let rel = rel.to_string_lossy().replace('\\', "/");
            out.push((rel, text));
        }
    }
}

/// Every runtime source's code, crate sources and integration tests alike.
fn runtime_code() -> Vec<(String, String)> {
    let root = runtime();
    let mut out = Vec::new();
    rust_sources(&root.join("src"), &root, &mut out);
    rust_sources(&root.join("tests"), &root, &mut out);
    assert!(
        out.iter().any(|(rel, _)| rel == "src/encoding.rs"),
        "the scan must reach the decoder core; scanned {} files",
        out.len()
    );
    out.into_iter()
        .map(|(rel, text)| (rel, code_of(&text)))
        .collect()
}

/// Every runtime source's code except the path seal, which names each denied
/// path on purpose.
fn scanned_code() -> Vec<(String, String)> {
    runtime_code()
        .into_iter()
        .filter(|(rel, _)| rel != PATH_SEAL)
        .collect()
}

/// A lexical token of blanked code.
#[derive(Debug, PartialEq, Eq)]
enum Token {
    /// An identifier, keyword or number.
    Ident(String),
    /// `::`.
    PathSep,
    /// Any other non-space character.
    Punct(char),
}

/// The tokens of `code`, whitespace dropped.
fn tokens(code: &str) -> Vec<Token> {
    let chars: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        if is_ident(c) {
            let start = i;
            while chars.get(i).is_some_and(|&c| is_ident(c)) {
                i += 1;
            }
            let word: String = chars.get(start..i).unwrap_or_default().iter().collect();
            out.push(Token::Ident(word));
        } else if c == ':' && chars.get(i + 1) == Some(&':') {
            out.push(Token::PathSep);
            i += 2;
        } else {
            if !c.is_whitespace() {
                out.push(Token::Punct(c));
            }
            i += 1;
        }
    }
    out
}

/// Whether `tok` is the identifier `word`.
fn is_word(tok: Option<&Token>, word: &str) -> bool {
    matches!(tok, Some(Token::Ident(w)) if w == word)
}

/// What one `use` leaf (or `extern crate … as`) brings into scope.
#[derive(Debug)]
enum Import {
    /// `local` names `path`.
    Name { path: Vec<String>, local: String },
    /// Every public item under the path.
    Glob(Vec<String>),
}

/// Parses the `use` tree at `i` under `prefix`, pushing what it binds; the
/// index past it.
fn use_tree(stream: &[Token], mut i: usize, prefix: &[String], out: &mut Vec<Import>) -> usize {
    let mut path = prefix.to_vec();
    if stream.get(i) == Some(&Token::PathSep) {
        i += 1;
    }
    loop {
        match stream.get(i) {
            Some(Token::Punct('{')) => return use_group(stream, i + 1, &path, out),
            Some(Token::Punct('*')) => {
                out.push(Import::Glob(path));
                return i + 1;
            }
            Some(Token::Ident(segment)) => {
                path.push(segment.clone());
                i += 1;
                if stream.get(i) == Some(&Token::PathSep) {
                    i += 1;
                } else {
                    return use_leaf(stream, i, path, out);
                }
            }
            _ => return i,
        }
    }
}

/// Parses the `use` group whose body starts at `i` under `prefix`; the index
/// past its closing brace.
fn use_group(stream: &[Token], mut i: usize, prefix: &[String], out: &mut Vec<Import>) -> usize {
    loop {
        match stream.get(i) {
            Some(Token::Punct('}')) => return i + 1,
            Some(Token::Punct(',')) => i += 1,
            Some(_) => {
                let next = use_tree(stream, i, prefix, out);
                if next == i {
                    return i;
                }
                i = next;
            }
            None => return i,
        }
    }
}

/// Binds the `use` leaf `path` ending at `i` to its `as` alias, else to its
/// last segment (`self` names the path before it); the index past the leaf.
fn use_leaf(stream: &[Token], i: usize, mut path: Vec<String>, out: &mut Vec<Import>) -> usize {
    if path.last().is_some_and(|last| last == "self") {
        path.pop();
    }
    let alias = match (stream.get(i), stream.get(i + 1)) {
        (Some(Token::Ident(kw)), Some(Token::Ident(name))) if kw == "as" => Some(name.clone()),
        _ => None,
    };
    let end = if alias.is_some() { i + 2 } else { i };
    if let Some(local) = alias.or_else(|| path.last().cloned()) {
        out.push(Import::Name { path, local });
    }
    end
}

/// Every import in `stream`: each `use` item's leaves and each
/// `extern crate … as` alias.
fn imports(stream: &[Token]) -> Vec<Import> {
    let mut out = Vec::new();
    for (at, tok) in stream.iter().enumerate() {
        if is_word(Some(tok), "use") {
            use_tree(stream, at + 1, &[], &mut out);
        } else if is_word(Some(tok), "extern")
            && is_word(stream.get(at + 1), "crate")
            && is_word(stream.get(at + 3), "as")
            && let (Some(Token::Ident(name)), Some(Token::Ident(local))) =
                (stream.get(at + 2), stream.get(at + 4))
        {
            out.push(Import::Name {
                path: vec![name.clone()],
                local: local.clone(),
            });
        }
    }
    out
}

/// The index past the `;` ending the item at `i`.
fn past_semicolon(stream: &[Token], i: usize) -> usize {
    stream
        .iter()
        .skip(i)
        .position(|tok| *tok == Token::Punct(';'))
        .map_or(stream.len(), |at| i + at + 1)
}

/// Every path `stream` names outside its `use` items: a run of identifiers
/// joined by `::`, a method or field after `.` excluded.
fn code_paths(stream: &[Token]) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(tok) = stream.get(i) {
        if is_word(Some(tok), "use") {
            i = past_semicolon(stream, i);
            continue;
        }
        let Token::Ident(first) = tok else {
            i += 1;
            continue;
        };
        let after_dot = i
            .checked_sub(1)
            .and_then(|p| stream.get(p))
            .is_some_and(|prev| *prev == Token::Punct('.'));
        let mut path = vec![first.clone()];
        i += 1;
        while stream.get(i) == Some(&Token::PathSep)
            && let Some(Token::Ident(segment)) = stream.get(i + 1)
        {
            path.push(segment.clone());
            i += 2;
        }
        if !after_dot {
            out.push(path);
        }
    }
    out
}

/// The names one file's imports bind and the modules it declares.
struct Scope {
    imports: Vec<Import>,
    names: BTreeMap<String, Vec<String>>,
    modules: BTreeSet<String>,
}

impl Scope {
    fn of(stream: &[Token]) -> Self {
        let imports = imports(stream);
        let names = imports
            .iter()
            .filter_map(|import| match import {
                Import::Name { path, local } => Some((local.clone(), path.clone())),
                Import::Glob(_) => None,
            })
            .collect();
        let modules = stream
            .windows(2)
            .filter_map(|pair| match pair {
                [Token::Ident(kw), Token::Ident(name)] if kw == "mod" => Some(name.clone()),
                _ => None,
            })
            .collect();
        Self {
            imports,
            names,
            modules,
        }
    }

    /// `path` with its first segment replaced by what an import binds it to,
    /// hop by hop; a first segment naming a module the file declares resolves
    /// under `self`.
    fn resolve(&self, path: &[String]) -> Vec<String> {
        let mut resolved = path.to_vec();
        for _ in 0..MAX_ALIAS_HOPS {
            let Some(first) = resolved.first() else { break };
            if self.modules.contains(first) {
                resolved.insert(0, "self".to_owned());
                break;
            }
            let Some(target) = self.names.get(first) else {
                break;
            };
            let next: Vec<String> = target
                .iter()
                .chain(resolved.iter().skip(1))
                .cloned()
                .collect();
            if next == resolved {
                break;
            }
            resolved = next;
        }
        resolved
    }

    /// Every path the file names, its import leaves included, resolved.
    fn named_paths(&self, stream: &[Token]) -> Vec<Vec<String>> {
        self.imports
            .iter()
            .filter_map(|import| match import {
                Import::Name { path, .. } => Some(path.clone()),
                Import::Glob(_) => None,
            })
            .chain(code_paths(stream))
            .map(|path| self.resolve(&path))
            .collect()
    }
}

/// The segments of a `::`-joined path.
fn segments(path: &str) -> Vec<&str> {
    path.split("::").collect()
}

/// Whether `resolved` names `denied` or an item under it.
fn names_path(resolved: &[String], denied: &str) -> bool {
    let want = segments(denied);
    resolved.len() >= want.len() && resolved.iter().zip(&want).all(|(have, want)| have == want)
}

/// Whether `resolved` is a module strictly above `denied`.
fn holds_path(resolved: &[String], denied: &str) -> bool {
    let want = segments(denied);
    resolved.len() < want.len() && resolved.iter().zip(&want).all(|(have, want)| have == want)
}

/// How many times `code` names each of `denied`, through its imports and its
/// paths alike; paths named nowhere are omitted.
fn named_sites(code: &str, denied: &[&'static str]) -> BTreeMap<&'static str, usize> {
    let stream = tokens(code);
    let scope = Scope::of(&stream);
    let mut sites = BTreeMap::new();
    for resolved in scope.named_paths(&stream) {
        for &path in denied {
            if names_path(&resolved, path) {
                *sites.entry(path).or_insert(0) += 1;
            }
        }
    }
    sites
}

/// Every glob import in `code` of a module holding a denied path or a lenient
/// extractor, resolved.
fn refused_globs(code: &str) -> Vec<String> {
    let stream = tokens(code);
    let scope = Scope::of(&stream);
    scope
        .imports
        .iter()
        .filter_map(|import| match import {
            Import::Glob(path) => Some(scope.resolve(path)),
            Import::Name { .. } => None,
        })
        .filter(|resolved| {
            DENIED_PATHS
                .iter()
                .chain(LENIENT_EXTRACTORS)
                .any(|denied| holds_path(resolved, denied))
        })
        .map(|resolved| resolved.join("::"))
        .collect()
}

/// Whether the `use` at `at` carries a visibility (`pub`, `pub(crate)`,
/// `pub(super)`, `pub(in path)`), so it re-exports what it imports.
fn is_re_export(stream: &[Token], at: usize) -> bool {
    let Some(before) = at.checked_sub(1) else {
        return false;
    };
    if is_word(stream.get(before), "pub") {
        return true;
    }
    if stream.get(before) != Some(&Token::Punct(')')) {
        return false;
    }
    let open = stream
        .iter()
        .take(before)
        .rposition(|tok| *tok == Token::Punct('('));
    open.and_then(|open| open.checked_sub(1))
        .is_some_and(|kw| is_word(stream.get(kw), "pub"))
}

/// Whether the denied `path` is a method, named `Type::method`: its owner
/// segment is a type (upper camel case). A method is matched by name at every
/// site, so re-exporting its type launders nothing.
fn is_denied_method(path: &str) -> bool {
    let segs = segments(path);
    segs.len()
        .checked_sub(2)
        .and_then(|owner| segs.get(owner))
        .and_then(|owner| owner.chars().next())
        .is_some_and(char::is_uppercase)
}

/// Every re-export in `code` (a `pub use` / `pub(…) use` leaf, any alias) of a
/// denied path or a lenient extractor, or of a module holding a denied free
/// item, resolved.
///
/// A re-export gives a denied item a crate-internal name that another file can
/// call without naming the denied path, so each one is a site in its own file
/// (`named_sites` counts the leaf) and is refused outright: no other file's scan
/// would see the calls it enables.
fn denied_re_exports(code: &str) -> Vec<String> {
    let stream = tokens(code);
    let scope = Scope::of(&stream);
    let mut out = Vec::new();
    for (at, tok) in stream.iter().enumerate() {
        if !is_word(Some(tok), "use") || !is_re_export(&stream, at) {
            continue;
        }
        let mut leaves = Vec::new();
        use_tree(&stream, at + 1, &[], &mut leaves);
        for leaf in leaves {
            let Import::Name { path, .. } = leaf else {
                continue;
            };
            let resolved = scope.resolve(&path);
            let denied = DENIED_PATHS.iter().chain(LENIENT_EXTRACTORS).any(|denied| {
                names_path(&resolved, denied)
                    || (!is_denied_method(denied) && holds_path(&resolved, denied))
            });
            if denied {
                out.push(resolved.join("::"));
            }
        }
    }
    out
}

/// The number of whole-identifier occurrences of `word` in `code`.
fn word_count(code: &str, word: &str) -> usize {
    code.match_indices(word)
        .filter(|&(at, _)| {
            let before = code.get(..at).and_then(|s| s.chars().next_back());
            let after = code.get(at + word.len()..).and_then(|s| s.chars().next());
            !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
        })
        .count()
}

/// Whether `src` names a lenient percent decoder in code.
fn names_lenient_percent_decoder(src: &str) -> bool {
    let code = code_of(src);
    LENIENT_PERCENT_DECODERS
        .iter()
        .any(|name| word_count(&code, name) > 0)
}

/// Whether `src` names a lenient axum extractor in code, however imported.
fn names_lenient_extractor(src: &str) -> bool {
    !named_sites(&code_of(src), LENIENT_EXTRACTORS).is_empty()
}

/// Each lenient query reader `code` names, with its number of sites.
fn query_reader_sites(code: &str) -> BTreeMap<&'static str, usize> {
    let mut sites = named_sites(code, LENIENT_QUERY_FUNCTIONS);
    for &method in LENIENT_QUERY_METHODS {
        let count = word_count(code, method);
        if count > 0 {
            sites.insert(method, count);
        }
    }
    sites
}

/// The number of `DriverParityQuery::of` calls in `code`.
fn driver_parity_calls(code: &str) -> usize {
    code_paths(&tokens(code))
        .iter()
        .filter(
            |path| matches!(path.as_slice(), [.., ty, f] if ty == "DriverParityQuery" && f == "of"),
        )
        .count()
}

/// `count` per runtime-relative file, omitting files with none.
fn inventory(code: &[(String, String)], count: impl Fn(&str) -> usize) -> BTreeMap<String, usize> {
    code.iter()
        .filter_map(|(rel, code)| {
            let sites = count(code);
            (sites > 0).then(|| (rel.clone(), sites))
        })
        .collect()
}

/// `pins` as an inventory.
fn pinned(pins: &[(&str, usize)]) -> BTreeMap<String, usize> {
    pins.iter()
        .map(|&(rel, sites)| (rel.to_owned(), sites))
        .collect()
}

/// Every lenient query reader site, per runtime-relative file and reader.
fn query_inventory(code: &[(String, String)]) -> BTreeMap<(String, &'static str), usize> {
    code.iter()
        .flat_map(|(rel, code)| {
            query_reader_sites(code)
                .into_iter()
                .map(move |(reader, sites)| ((rel.clone(), reader), sites))
        })
        .collect()
}

/// Reads a runtime file.
fn read_runtime(rel: &str) -> String {
    let text = std::fs::read_to_string(runtime().join(rel));
    assert!(text.is_ok(), "read the runtime {rel}: {text:?}");
    text.unwrap_or_default()
}

#[test]
fn no_runtime_source_names_a_lenient_percent_decoder() {
    let offenders: Vec<_> = scanned_code()
        .into_iter()
        .filter(|(_, code)| names_lenient_percent_decoder(code))
        .map(|(rel, _)| rel)
        .collect();
    assert!(
        offenders.is_empty(),
        "a lenient percent decoder in the runtime; decode a URL component through \
         `encoding::decode_component`: {offenders:?}"
    );
}

#[test]
fn no_runtime_source_names_a_lenient_extractor() {
    let offenders: Vec<_> = scanned_code()
        .into_iter()
        .filter(|(_, code)| names_lenient_extractor(code))
        .map(|(rel, _)| rel)
        .collect();
    assert!(
        offenders.is_empty(),
        "a lenient axum `Query`/`Form` extractor in the runtime; read the query \
         through `server::strict_url_query`: {offenders:?}"
    );
}

#[test]
fn no_runtime_source_glob_imports_a_lenient_decoder() {
    let offenders: Vec<_> = scanned_code()
        .into_iter()
        .flat_map(|(rel, code)| {
            refused_globs(&code)
                .into_iter()
                .map(move |glob| format!("{rel}: {glob}::*"))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "a glob import brings a lenient decoder into scope unnamed; import each \
         item by name: {offenders:?}"
    );
}

#[test]
fn lossy_utf8_stays_at_its_pinned_sites() {
    assert_eq!(
        inventory(&scanned_code(), |code| code.matches(LOSSY_UTF8).count()),
        pinned(LOSSY_TEXT_SITES),
        "lossy UTF-8 must stay at its pinned sites: a URL component goes through \
         `encoding::decode_component`; other text needs a reasoned per-site allow \
         and a pin here"
    );
}

#[test]
fn lenient_query_readers_stay_at_their_pinned_sites() {
    let pins: BTreeMap<(String, &str), usize> = LENIENT_QUERY_SITES
        .iter()
        .map(|&(rel, reader, sites)| ((rel.to_owned(), reader), sites))
        .collect();
    assert_eq!(
        query_inventory(&scanned_code()),
        pins,
        "a lenient query reader outside its pinned sites: decode a query through \
         `encoding::decode_form_query`, or a driver-parity read through \
         `ssrf::DriverParityQuery`"
    );
}

#[test]
fn driver_parity_reads_stay_at_their_pinned_calls() {
    assert_eq!(
        inventory(&scanned_code(), driver_parity_calls),
        pinned(DRIVER_PARITY_SITES),
        "a new `DriverParityQuery::of` call: a driver-parity read is for a database \
         URL the ambiguity check cleared; pin it here with its reason"
    );
}

#[test]
fn the_denied_paths_are_exactly_the_runtime_clippy_config() {
    let config = read_runtime("clippy.toml");
    let configured: BTreeSet<&str> = config
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| line.split_once("path = \""))
        .filter_map(|(_, rest)| rest.split_once('"'))
        .map(|(path, _)| path)
        .collect();
    let denied: BTreeSet<&str> = DENIED_PATHS
        .iter()
        .chain(OTHER_RULE_DENIED_PATHS)
        .copied()
        .collect();
    assert_eq!(
        configured, denied,
        "the runtime clippy.toml must deny exactly the scan's paths and the other \
         rules' paths; a new entry is classified in one of the two lists"
    );
}

#[test]
fn every_denied_path_is_named_by_the_path_seal() {
    let seal = tokens(&code_of(&read_runtime(PATH_SEAL)));
    let named: BTreeSet<String> = code_paths(&seal)
        .iter()
        .map(|path| path.join("::"))
        .collect();
    let unnamed: Vec<_> = DENIED_PATHS
        .iter()
        .filter(|path| !named.contains(**path))
        .collect();
    assert!(
        unnamed.is_empty(),
        "{PATH_SEAL} must name every denied path, so a stale one breaks the build: \
         {unnamed:?}"
    );
    let root = tokens(&code_of(&read_runtime("src/mod.rs")));
    assert!(
        root.windows(2)
            .any(|pair| matches!(pair, [Token::Ident(kw), Token::Ident(name)] if kw == "mod" && name == "clippy_paths_resolve")),
        "src/mod.rs must declare the path seal, or it is never compiled"
    );
}

#[test]
fn a_planted_lenient_decoder_is_detected() {
    assert!(names_lenient_percent_decoder(
        "let d = percent_encoding::percent_decode_str(raw).decode_utf8();"
    ));
    assert!(names_lenient_percent_decoder(
        "let d = p.decode_utf8_lossy();"
    ));
    // A `//` inside a string does not hide the call after it.
    assert!(names_lenient_percent_decoder(
        "let u = \"http://x\"; let d = percent_decode_str(u);"
    ));
    assert!(names_lenient_percent_decoder(
        "let u = r#\"a\"//b\"#; let d = percent_decode(u);"
    ));
    // A lifetime is not a character literal that could swallow code.
    assert!(names_lenient_percent_decoder(
        "fn f<'a>(s: &'a str) { percent_decode(s) }"
    ));
    // The runtime's own strict kernels share the stem, not the name.
    assert!(!names_lenient_percent_decoder(
        "pub fn ipe_percent_decode(s: String) -> R { path_decode(s) }"
    ));
    // A mention in a comment or a string is not a call.
    assert!(!names_lenient_percent_decoder(
        "// never `percent_decode_str` here"
    ));
    assert!(!names_lenient_percent_decoder(
        "/* outer /* nested */ percent_decode */ let x = 1;"
    ));
    assert!(!names_lenient_percent_decoder(
        "let msg = \"no \\\"percent_decode\\\" here\";"
    ));
    // A `'"'` character literal does not open a string that hides the call.
    assert!(names_lenient_percent_decoder(
        "let c = '\"'; percent_decode(x); let s = \"y\";"
    ));
    let lossy = code_of("let t = String::from_utf8_lossy(&b); // from_utf8_lossy");
    assert_eq!(lossy.matches(LOSSY_UTF8).count(), 1, "one site: {lossy}");
}

#[test]
fn a_planted_lenient_extractor_is_detected_however_imported() {
    assert!(names_lenient_extractor(
        "async fn h(axum::extract::Query(q): axum::extract::Query<M>) {}"
    ));
    assert!(names_lenient_extractor("use axum::extract::{State, Form};"));
    // A nested group.
    assert!(names_lenient_extractor(
        "use axum::{extract::{ws::WebSocket, Query}, Router};"
    ));
    // The crate-root re-export, by path and by import.
    assert!(names_lenient_extractor(
        "async fn h(axum::Form(f): axum::Form<M>) {}"
    ));
    assert!(names_lenient_extractor("use axum::{Form, Router};"));
    assert!(names_lenient_extractor("use ::axum::Form;"));
    // An `as` alias, and the aliased name at its use.
    assert_eq!(
        named_sites(
            &code_of("use axum::extract::Query as Q; async fn h(Q(q): Q<M>) {}"),
            LENIENT_EXTRACTORS
        ),
        BTreeMap::from([("axum::extract::Query", 3)])
    );
    // A module alias, through `as`, `self` and `extern crate`.
    assert!(names_lenient_extractor(
        "use axum::extract as ex; async fn h(q: ex::Query<M>) {}"
    ));
    assert!(names_lenient_extractor(
        "use axum::extract::{self as ex}; async fn h(f: ex::Form<M>) {}"
    ));
    assert!(names_lenient_extractor(
        "extern crate axum as ax; async fn h(f: ax::extract::Form<M>) {}"
    ));
    // A second hop: an import through an aliased module.
    assert!(names_lenient_extractor(
        "use axum::extract as ex; use ex::Query; async fn h(q: Query<M>) {}"
    ));
    // Neighbours that are not the lenient extractors.
    assert!(!names_lenient_extractor(
        "use axum::extract::{State, QueryPlan}; // extract::Query"
    ));
    assert!(!names_lenient_extractor(
        "type DbQuery<'q> = sqlx::query::Query<'q, D, A>;"
    ));
    assert!(!names_lenient_extractor(
        "use sqlx::query::Query; fn f(q: Query) { let r: axum::extract::RawQuery = r; }"
    ));
    assert!(!names_lenient_extractor(
        "fn f(req: axum::extract::Request) { let s = \"axum::Form\"; }"
    ));
}

#[test]
fn a_planted_glob_import_of_a_lenient_module_is_refused() {
    assert_eq!(refused_globs("use axum::extract::*;"), ["axum::extract"]);
    assert_eq!(refused_globs("use axum::*;"), ["axum"]);
    assert_eq!(
        refused_globs("use serde_urlencoded::*;"),
        ["serde_urlencoded"]
    );
    assert_eq!(
        refused_globs("use url::{Url, form_urlencoded::*};"),
        ["url::form_urlencoded"]
    );
    assert_eq!(
        refused_globs("use percent_encoding::*;"),
        ["percent_encoding"]
    );
    // Through a module alias.
    assert_eq!(
        refused_globs("use axum::extract as ex; use ex::*;"),
        ["axum::extract"]
    );
    // A local module of the same name, and ordinary globs, are not refused.
    assert!(refused_globs("pub mod url; pub use url::*;").is_empty());
    assert!(refused_globs("use super::*; use proptest::prelude::*;").is_empty());
    assert!(refused_globs("use axum::extract::ws::*;").is_empty());
}

#[test]
fn a_planted_lenient_query_reader_is_counted_per_site() {
    let reader = code_of("for p in u.query_pairs() {} let s = \"query_pairs\";");
    assert_eq!(
        query_reader_sites(&reader),
        BTreeMap::from([("query_pairs", 1)])
    );
    // A bare call after importing the function counts the import and each call.
    let bare = code_of(
        "use url::form_urlencoded::parse; let a = parse(b); let c = parse(d); let e = x.parse();",
    );
    assert_eq!(
        query_reader_sites(&bare),
        BTreeMap::from([("url::form_urlencoded::parse", 3)])
    );
    // A module alias and a nested group.
    let aliased = code_of(
        "use url::{Url as U, form_urlencoded as fu}; let p = fu::parse(b); \
         let s = fu::Serializer::new(String::new());",
    );
    assert_eq!(
        query_reader_sites(&aliased),
        BTreeMap::from([("url::form_urlencoded::parse", 1)])
    );
    let serde_reads = code_of(
        "use serde_urlencoded::{from_bytes as fb, to_string}; let a: T = fb(x)?; \
         let b = serde_urlencoded::from_str::<T>(s); let c = serde_urlencoded::from_reader(r); \
         let e = to_string(&v);",
    );
    assert_eq!(
        query_reader_sites(&serde_reads),
        BTreeMap::from([
            ("serde_urlencoded::from_bytes", 2),
            ("serde_urlencoded::from_reader", 1),
            ("serde_urlencoded::from_str", 1),
        ])
    );
    assert!(query_reader_sites(&code_of("let q = s.parse::<u16>(); fn parse() {}")).is_empty());
}

#[test]
fn a_planted_driver_parity_call_is_counted() {
    let code = code_of(
        "for p in DriverParityQuery::of(u).pairs() {} \
         let q = crate::ssrf::DriverParityQuery::of(v); fn of() {} // DriverParityQuery::of(w)",
    );
    assert_eq!(driver_parity_calls(&code), 2);
}

#[test]
fn no_runtime_source_re_exports_a_denied_path() {
    let offenders: Vec<_> = scanned_code()
        .into_iter()
        .flat_map(|(rel, code)| {
            denied_re_exports(&code)
                .into_iter()
                .map(move |path| format!("{rel}: {path}"))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "a re-export gives a denied path a name other files call unscanned; call \
         the strict core instead: {offenders:?}"
    );
}

#[test]
fn a_planted_re_export_of_a_denied_path_is_a_refused_site() {
    // Each visibility, with and without an alias, counts as a site.
    assert_eq!(
        named_sites(
            &code_of("pub(crate) use serde_urlencoded::from_str as lenient;"),
            LENIENT_QUERY_FUNCTIONS
        ),
        BTreeMap::from([("serde_urlencoded::from_str", 1)])
    );
    assert!(names_lenient_extractor("pub use axum::extract::Query;"));
    assert!(names_lenient_extractor(
        "pub(in crate::web) use axum::extract::{State, Form as F};"
    ));
    // And is refused, however spelled.
    assert_eq!(
        denied_re_exports(&code_of("pub use axum::extract::Query;")),
        ["axum::extract::Query"]
    );
    assert_eq!(
        denied_re_exports(&code_of(
            "pub(crate) use serde_urlencoded::from_str as lenient;"
        )),
        ["serde_urlencoded::from_str"]
    );
    assert_eq!(
        denied_re_exports(&code_of(
            "pub(super) use ::percent_encoding::{percent_decode_str as pd, utf8_percent_encode};"
        )),
        ["percent_encoding::percent_decode_str"]
    );
    assert_eq!(
        denied_re_exports(&code_of("pub(in crate::web) use axum::Form as F;")),
        ["axum::Form"]
    );
    // Through a private module alias.
    assert_eq!(
        denied_re_exports(&code_of(
            "use url::form_urlencoded as fu; pub(crate) use fu::parse as p;"
        )),
        ["url::form_urlencoded::parse"]
    );
    // A module holding a denied free item, re-exported whole.
    assert_eq!(
        denied_re_exports(&code_of("pub use url::form_urlencoded::{self as fu};")),
        ["url::form_urlencoded"]
    );
    assert_eq!(
        denied_re_exports(&code_of("pub use serde_urlencoded as su;")),
        ["serde_urlencoded"]
    );
    // Neighbours that are not denied re-exports.
    for clean in [
        "use serde_urlencoded::from_str;",
        "pub struct S; use axum::extract::Query;",
        "pub fn f() {} use url::form_urlencoded::parse;",
        "pub use crate::encoding::decode_component;",
        "pub use axum::extract::{State, RawQuery};",
        "pub mod url; pub use url::form_urlencoded::parse;",
        "pub use serde_urlencoded::to_string;",
        // A denied method's owner type: the method is matched by name anywhere.
        "pub use url::Url;",
        "pub(crate) use std::string::String as S;",
        "let s = \"pub use axum::extract::Query;\"; // pub use axum::Form;",
    ] {
        assert!(
            denied_re_exports(&code_of(clean)).is_empty(),
            "not a denied re-export: {clean}"
        );
    }
}
