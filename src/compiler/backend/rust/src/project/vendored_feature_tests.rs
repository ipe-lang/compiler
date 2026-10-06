//! Every cargo feature a vendored runtime file names in a `cfg` is one the
//! vendored manifest declares.
//!
//! rustc evaluates a `feature = "x"` predicate naming an undeclared feature to
//! false, with only an `unexpected_cfgs` warning, so a gate naming a feature the
//! vendored `Cargo.toml` never declares compiles its code out of every vendored
//! build without a word. The scan lexes each vendored source (the runtime tree
//! the driver copies into `src/ipe_runtime/`, the trimmed `ipe_runtime/mod.rs`
//! and stub `config.rs` templates, and the `RUNTIME_MOD_RS_*` appends) and
//! refuses any feature name outside the set the vendored manifest and its
//! augmenters declare.

#![cfg(test)]

use super::{
    CARGO_TOML, RUNTIME_CONFIG_RS, RUNTIME_MOD_RS, async_runtime_cargo_toml, jwt_cargo_toml,
    locale_cargo_toml, server_cargo_toml,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Runtime source files the driver copies but no vendored module tree declares.
///
/// Each entry names the file (relative to the runtime `src/`) and why rustc never
/// compiles it in a vendored build. The stale-entry check refuses an entry whose
/// file is gone, is declared by the vendored module tree, or no longer names an
/// undeclared feature.
const EXCLUDED: &[(&str, &str)] = &[(
    "clippy_paths_resolve.rs",
    "declared only by the runtime crate's own `mod.rs` under `cfg(test)`; the \
     trimmed vendored `mod.rs` never declares it",
)];

/// Runtime files the emitter overwrites in EVERY vendored emit, so their
/// runtime copies never reach a vendored build (the template replaces them).
///
/// `config.rs` is absent on purpose: a sqlite db emit vendors the runtime copy
/// verbatim, so it is scanned like any other file.
const REPLACED: &[&str] = &["mod.rs"];

/// The backend source, lexed for its `RUNTIME_MOD_RS_*` append constants.
const PROJECT_RS: &str = include_str!("../project.rs");

/// The runtime crate's `src/` directory, the tree the driver vendors.
fn runtime_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../runtime/rust/src")
}

/// One lexed Rust token: what the feature scan needs and nothing more.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    /// A string literal's decoded contents (normal, byte, C or raw).
    Str(String),
    Punct(char),
}

/// Lex `src` into tokens, dropping whitespace, comments, char literals,
/// lifetimes and numbers.
///
/// Comments (line, doc and nested block) never yield tokens, so a feature name
/// in prose is never read as a gate; string contents become one [`Tok::Str`],
/// never tokens of their own.
fn lex(src: &str) -> Vec<(usize, Tok)> {
    let chars: Vec<char> = src.chars().collect();
    let mut lexer = Lexer {
        chars: &chars,
        i: 0,
        line: 1,
        toks: Vec::new(),
    };
    while let Some(c) = lexer.at(0) {
        match c {
            '\n' => {
                lexer.line += 1;
                lexer.i += 1;
            }
            '/' if lexer.at(1) == Some('/') => lexer.skip_line_comment(),
            '/' if lexer.at(1) == Some('*') => lexer.skip_block_comment(),
            '"' => {
                lexer.i += 1;
                lexer.cooked();
            }
            '\'' => lexer.skip_char_or_lifetime(),
            _ if c.is_alphabetic() || c == '_' => lexer.word(),
            _ if c.is_whitespace() || c.is_ascii_digit() => lexer.skip_word_or_space(c),
            _ => {
                lexer.toks.push((lexer.line, Tok::Punct(c)));
                lexer.i += 1;
            }
        }
    }
    lexer.toks
}

/// The lexer's cursor over one source text.
struct Lexer<'a> {
    chars: &'a [char],
    i: usize,
    line: usize,
    toks: Vec<(usize, Tok)>,
}

impl Lexer<'_> {
    /// The character `ahead` positions past the cursor.
    fn at(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.i + ahead).copied()
    }

    /// Advance past every identifier character at the cursor.
    fn skip_ident_chars(&mut self) {
        while self
            .at(0)
            .is_some_and(|ch| ch.is_alphanumeric() || ch == '_')
        {
            self.i += 1;
        }
    }

    /// Skip one whitespace character, or a whole number literal.
    fn skip_word_or_space(&mut self, c: char) {
        if c.is_whitespace() {
            self.i += 1;
        } else {
            self.skip_ident_chars();
        }
    }

    fn skip_line_comment(&mut self) {
        while self.at(0).is_some_and(|ch| ch != '\n') {
            self.i += 1;
        }
    }

    /// Skip a block comment, honouring nesting.
    fn skip_block_comment(&mut self) {
        let mut depth = 1u32;
        self.i += 2;
        while depth > 0 {
            match (self.at(0), self.at(1)) {
                (Some('/'), Some('*')) => {
                    depth += 1;
                    self.i += 2;
                }
                (Some('*'), Some('/')) => {
                    depth -= 1;
                    self.i += 2;
                }
                (Some(ch), _) => {
                    if ch == '\n' {
                        self.line += 1;
                    }
                    self.i += 1;
                }
                (None, _) => break,
            }
        }
    }

    /// Skip a char literal (`'x'`, `'\n'`, `'\''`, `'"'`) or a lifetime (`'a`).
    fn skip_char_or_lifetime(&mut self) {
        if self.at(1) == Some('\\') {
            // The escaped char goes with the backslash, so `'\''` does not
            // end at its own escaped quote.
            self.i += 3;
            while self.at(0).is_some_and(|ch| ch != '\'') {
                self.i += 1;
            }
            self.i += 1;
        } else if self.at(2) == Some('\'') {
            self.i += 3;
        } else {
            self.i += 1;
            self.skip_ident_chars();
        }
    }

    /// Read a normal string literal whose body starts at the cursor.
    fn cooked(&mut self) {
        let (text, next, lines) = cooked_string(self.chars, self.i);
        self.toks.push((self.line, Tok::Str(text)));
        self.line += lines;
        self.i = next;
    }

    /// Lex an identifier, a raw identifier, or a prefixed string literal.
    fn word(&mut self) {
        let begin = self.i;
        self.skip_ident_chars();
        let word: String = self
            .chars
            .get(begin..self.i)
            .unwrap_or_default()
            .iter()
            .collect();
        let raw_prefix = matches!(word.as_str(), "r" | "br" | "cr");
        if raw_prefix && matches!(self.at(0), Some('"' | '#')) {
            let mut hashes = 0usize;
            while self.at(hashes) == Some('#') {
                hashes += 1;
            }
            if self.at(hashes) == Some('"') {
                let (text, next, lines) = raw_string(self.chars, self.i + hashes + 1, hashes);
                self.toks.push((self.line, Tok::Str(text)));
                self.line += lines;
                self.i = next;
            } else {
                // `r#ident`: a raw identifier.
                self.i += 1;
                let id_begin = self.i;
                self.skip_ident_chars();
                let id: String = self
                    .chars
                    .get(id_begin..self.i)
                    .unwrap_or_default()
                    .iter()
                    .collect();
                self.toks.push((self.line, Tok::Ident(id)));
            }
        } else if matches!(word.as_str(), "b" | "c") && self.at(0) == Some('"') {
            self.i += 1;
            self.cooked();
        } else if word == "b" && self.at(0) == Some('\'') {
            // A byte literal `b'x'`: the char arm consumes it next.
        } else {
            self.toks.push((self.line, Tok::Ident(word)));
        }
    }
}

/// Decode a normal string literal whose body starts at `i`.
///
/// Returns the contents, the index past the closing quote, and the newlines
/// consumed. A backslash-newline continuation drops the newline and the
/// following whitespace, as rustc does.
fn cooked_string(chars: &[char], mut i: usize) -> (String, usize, usize) {
    let mut out = String::new();
    let mut lines = 0usize;
    while let Some(&c) = chars.get(i) {
        match c {
            '"' => return (out, i + 1, lines),
            '\\' => {
                let escaped = chars.get(i + 1).copied();
                i += 2;
                match escaped {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('r') => out.push('\r'),
                    Some('0') => out.push('\0'),
                    Some('\n') => {
                        lines += 1;
                        while chars.get(i).is_some_and(|ch| ch.is_whitespace()) {
                            if chars.get(i) == Some(&'\n') {
                                lines += 1;
                            }
                            i += 1;
                        }
                    }
                    Some(other) => out.push(other),
                    None => {}
                }
            }
            _ => {
                if c == '\n' {
                    lines += 1;
                }
                out.push(c);
                i += 1;
            }
        }
    }
    (out, i, lines)
}

/// Read a raw string literal whose body starts at `i`, closed by `"` plus
/// `hashes` `#` characters.
fn raw_string(chars: &[char], mut i: usize, hashes: usize) -> (String, usize, usize) {
    let mut out = String::new();
    let mut lines = 0usize;
    while let Some(&c) = chars.get(i) {
        if c == '"' && (1..=hashes).all(|k| chars.get(i + k) == Some(&'#')) {
            return (out, i + 1 + hashes, lines);
        }
        if c == '\n' {
            lines += 1;
        }
        out.push(c);
        i += 1;
    }
    (out, i, lines)
}

/// Every `feature = "name"` inside a `cfg` / `cfg_attr` attribute or a `cfg!`
/// macro, with the line it sits on.
fn cfg_features(src: &str) -> Vec<(usize, String)> {
    let toks = lex(src);
    let mut found = Vec::new();
    let mut i = 0usize;
    while let Some((_, tok)) = toks.get(i) {
        let is_cfg = matches!(tok, Tok::Ident(w) if w == "cfg" || w == "cfg_attr");
        let in_attr = i > 0 && matches!(toks.get(i - 1), Some((_, Tok::Punct('['))));
        let as_macro = matches!(toks.get(i + 1), Some((_, Tok::Punct('!'))));
        let open = if as_macro { i + 2 } else { i + 1 };
        if is_cfg && (in_attr || as_macro) && matches!(toks.get(open), Some((_, Tok::Punct('(')))) {
            let mut depth = 0usize;
            let mut j = open;
            while let Some((line, t)) = toks.get(j) {
                match t {
                    Tok::Punct('(') => depth += 1,
                    Tok::Punct(')') => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    Tok::Ident(w) if w == "feature" => {
                        if let (Some((_, Tok::Punct('='))), Some((_, Tok::Str(name)))) =
                            (toks.get(j + 1), toks.get(j + 2))
                        {
                            found.push((*line, name.clone()));
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            i = j;
        }
        i += 1;
    }
    found
}

/// The feature names a manifest's `[features]` table declares.
fn declared_features(manifest: &str) -> BTreeSet<String> {
    manifest
        .lines()
        .skip_while(|l| l.trim() != "[features]")
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with('['))
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('=').map(|(name, _)| name.trim().to_owned()))
        .collect()
}

/// The string contents of every `const RUNTIME_MOD_RS*` item in `project.rs`.
fn mod_rs_appends() -> Vec<(String, String)> {
    let toks = lex(PROJECT_RS);
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some((_, tok)) = toks.get(i) {
        if let (Tok::Ident(kw), Some((_, Tok::Ident(name)))) = (tok, toks.get(i + 1))
            && kw == "const"
            && name.starts_with("RUNTIME_MOD_RS")
        {
            let mut body = String::new();
            let mut j = i + 2;
            while let Some((_, t)) = toks.get(j) {
                match t {
                    Tok::Punct(';') => break,
                    Tok::Str(s) => body.push_str(s),
                    _ => {}
                }
                j += 1;
            }
            out.push((name.clone(), body));
            i = j;
        }
        i += 1;
    }
    out
}

/// Every `.rs` file under `root`, as paths relative to it.
fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && let Ok(rel) = path.strip_prefix(root)
            {
                out.push(rel.to_path_buf());
            }
        }
    }
    out.sort();
    out
}

/// The union of features the vendored manifest declares in any emit: the
/// template's own table plus the entries the augmenters insert.
fn vendored_declared() -> BTreeSet<String> {
    let async_base = async_runtime_cargo_toml(CARGO_TOML).expect("async base must build");
    let mut declared = declared_features(CARGO_TOML);
    for manifest in [
        server_cargo_toml(&async_base).expect("server manifest must build"),
        jwt_cargo_toml(CARGO_TOML).expect("jwt manifest must build"),
        locale_cargo_toml(CARGO_TOML).expect("locale manifest must build"),
    ] {
        declared.extend(declared_features(&manifest));
    }
    declared
}

/// The vendored runtime tree, the `mod.rs` template and every append name only
/// declared features; the exclusion list carries no stale entry.
#[test]
fn vendored_cfg_features_are_declared() {
    let declared = vendored_declared();
    let root = runtime_src();
    let files = rust_files(&root);
    assert!(
        files.len() > 50,
        "the runtime tree at {} must be scanned, found {} files",
        root.display(),
        files.len()
    );

    let mut drift = Vec::new();
    let mut scanned = 0usize;
    for rel in &files {
        let rel_s = rel.to_string_lossy().replace('\\', "/");
        if REPLACED.contains(&rel_s.as_str()) || EXCLUDED.iter().any(|(f, _)| *f == rel_s) {
            continue;
        }
        let src = std::fs::read_to_string(root.join(rel)).expect("runtime source must read");
        for (line, name) in cfg_features(&src) {
            scanned += 1;
            if !declared.contains(&name) {
                drift.push(format!("{rel_s}:{line}: feature {name:?}"));
            }
        }
    }
    for (template, text) in [
        ("templates/ipe_runtime/mod.rs", RUNTIME_MOD_RS),
        ("templates/ipe_runtime/config.rs", RUNTIME_CONFIG_RS),
    ] {
        for (line, name) in cfg_features(text) {
            scanned += 1;
            if !declared.contains(&name) {
                drift.push(format!("{template}:{line}: feature {name:?}"));
            }
        }
    }
    let appends = mod_rs_appends();
    assert!(
        appends
            .iter()
            .any(|(n, _)| n == "RUNTIME_MOD_RS_WEB_APPEND"),
        "the append scan must find the RUNTIME_MOD_RS_* constants: {:?}",
        appends.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );
    for (const_name, body) in &appends {
        for (_, name) in cfg_features(body) {
            scanned += 1;
            if !declared.contains(&name) {
                drift.push(format!("project.rs {const_name}: feature {name:?}"));
            }
        }
    }
    assert!(
        scanned > 100,
        "the scan must read the gates, read {scanned}"
    );
    assert!(
        drift.is_empty(),
        "vendored sources name features the vendored Cargo.toml never declares, so \
         rustc compiles their gates off in every vendored build; declare each in \
         templates/Cargo.toml (or the augmenter that promotes it) or restate the gate:\n{}",
        drift.join("\n")
    );
}

/// Every exclusion still names a file the vendored module tree never declares
/// and that names an undeclared feature; every replacement is still emitted.
#[test]
fn exclusion_and_replacement_lists_are_current() {
    let declared = vendored_declared();
    let root = runtime_src();
    let appends = mod_rs_appends();
    for (file, why) in EXCLUDED {
        let path = root.join(file);
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            !src.is_empty(),
            "stale exclusion: {file} ({why}) is not in the runtime tree"
        );
        let module = file.trim_end_matches(".rs");
        let declares = |text: &str| {
            let toks = lex(text);
            toks.windows(2).any(|w| {
                matches!(
                    (w.first(), w.get(1)),
                    (Some((_, Tok::Ident(m))), Some((_, Tok::Ident(n)))) if m == "mod" && n == module
                )
            })
        };
        assert!(
            !declares(RUNTIME_MOD_RS) && !appends.iter().any(|(_, body)| declares(body)),
            "stale exclusion: the vendored module tree declares {file}, so it must be scanned"
        );
        assert!(
            cfg_features(&src)
                .iter()
                .any(|(_, name)| !declared.contains(name)),
            "stale exclusion: {file} names only declared features, so it needs no exclusion"
        );
    }
    for file in REPLACED {
        assert!(
            root.join(file).is_file(),
            "stale replacement entry: runtime {file} is gone"
        );
        let emitted = format!("src/ipe_runtime/{file}");
        assert!(
            lex(PROJECT_RS)
                .iter()
                .any(|(_, t)| matches!(t, Tok::Str(s) if *s == emitted)),
            "stale replacement entry: the backend no longer emits {emitted}"
        );
    }
}

/// The scan reads gates in every `cfg` form and nothing in comments, strings,
/// or char literals.
#[test]
fn cfg_scan_reads_gates_and_skips_prose() {
    let src = r##"
        // #[cfg(feature = "line_comment")]
        /// #[cfg(feature = "doc_comment")]
        /* outer /* #[cfg(feature = "nested")] */ still comment */
        const S: &str = "#[cfg(feature = \"in_string\")]";
        const R: &str = r#"#[cfg(feature = "in_raw")]"#;
        const Q: char = '"';
        const E: [char; 2] = ['\'','"'];
        #[cfg(feature = "after_escaped_quote")]
        fn c() {}
        fn lt<'a>(x: &'a str) -> &'a str { x }
        #[cfg(all(feature = "attr", not(feature = "negated")))]
        fn a() {}
        #[cfg_attr(feature = "attr_pred", allow(dead_code))]
        fn b() { if cfg!(feature = "mac") {} }
        #![cfg(feature = "inner")]
        fn cfg(feature: u8) {}
    "##;
    let names: Vec<String> = cfg_features(src).into_iter().map(|(_, n)| n).collect();
    assert_eq!(
        names,
        [
            "after_escaped_quote",
            "attr",
            "negated",
            "attr_pred",
            "mac",
            "inner"
        ],
        "only real gates are read"
    );
}

/// The appended `mod.rs` text is decoded through its escapes and continuations,
/// so a gate inside an append constant is read like one in a file.
#[test]
fn cfg_scan_reads_escaped_append_strings() {
    let decoded = lex(
        "const X: &str = \"#[cfg(feature = \\\"web\\\")]\\npub mod a;\\n\\\n     #[cfg(feature = \\\"tui\\\")]\\npub mod b;\\n\";",
    );
    let body = decoded
        .iter()
        .find_map(|(_, t)| match t {
            Tok::Str(s) => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let names: Vec<String> = cfg_features(&body).into_iter().map(|(_, n)| n).collect();
    assert_eq!(names, ["web", "tui"]);
}

/// A gate naming an undeclared feature is reported, which is what makes the
/// class check go red.
#[test]
fn undeclared_feature_is_drift() {
    let declared = declared_features("[features]\ndefault = [\"json\"]\njson = []\n\n[deps]\n");
    assert_eq!(
        declared,
        BTreeSet::from(["default".to_owned(), "json".to_owned()])
    );
    let gates =
        cfg_features("#[cfg(all(feature = \"json\", feature = \"http_client\"))]\nfn f() {}");
    let undeclared: Vec<&str> = gates
        .iter()
        .filter(|(_, n)| !declared.contains(n))
        .map(|(_, n)| n.as_str())
        .collect();
    assert_eq!(undeclared, ["http_client"]);
}
