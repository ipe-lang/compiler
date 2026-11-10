//! The one Rust lexer the feature-liveness scans read source through.
//!
//! Comments (line, doc and nested block) never yield tokens and a string
//! literal's contents stay one [`Tok::Str`], so prose or text naming a feature or
//! a crate is never read as a gate or a path. Both the vendored-manifest scan
//! (`src/project/vendored_feature_tests.rs`) and the runtime featureset closure
//! (`tests/runtime_featureset_closure.rs`) include this file, so the two read
//! code through one grammar.

/// One lexed Rust token: what the feature scan needs and nothing more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
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
pub fn lex(src: &str) -> Vec<(usize, Tok)> {
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

/// When `toks[at..]` opens a `#[cfg(test)]` attribute, the index of the last
/// token of the item it gates, which no vendored build compiles.
///
/// The item ends at its matching `}` or, with no body, at its `;`. Only the
/// exact `cfg(test)` form is skipped, so `cfg(not(test))` and a gate that
/// combines `test` with other predicates stay scanned.
pub fn test_only_item_end(toks: &[(usize, Tok)], at: usize) -> Option<usize> {
    let word =
        |k: usize, name: &str| matches!(toks.get(at + k), Some((_, Tok::Ident(w))) if w == name);
    let punct = |k: usize, c: char| matches!(toks.get(at + k), Some((_, Tok::Punct(p))) if *p == c);
    let is_attr = punct(0, '#')
        && punct(1, '[')
        && word(2, "cfg")
        && punct(3, '(')
        && word(4, "test")
        && punct(5, ')')
        && punct(6, ']');
    if !is_attr {
        return None;
    }
    let mut depth = 0usize;
    for (k, (_, tok)) in toks.iter().enumerate().skip(at + 7) {
        match tok {
            Tok::Punct('{') => depth += 1,
            Tok::Punct('}') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(k);
                }
            }
            Tok::Punct(';') if depth == 0 => return Some(k),
            _ => {}
        }
    }
    Some(toks.len().saturating_sub(1))
}

/// Every `feature = "name"` inside a `cfg` / `cfg_attr` attribute or a `cfg!`
/// macro, `#[cfg(test)]` items read too only when `with_tests` holds.
pub fn gate_features(src: &str, with_tests: bool) -> Vec<(usize, String)> {
    let toks = lex(src);
    let mut found = Vec::new();
    let mut i = 0usize;
    while let Some((_, tok)) = toks.get(i) {
        if !with_tests && let Some(end) = test_only_item_end(&toks, i) {
            i = end + 1;
            continue;
        }
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
