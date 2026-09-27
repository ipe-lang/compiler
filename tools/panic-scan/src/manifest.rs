//! The production build targets a `Cargo.toml` names explicitly.
//!
//! A conservative reader for the TOML subset crate manifests use: tables,
//! arrays of tables, dotted and quoted keys, inline tables, arrays, and all four
//! string forms. Anything outside that subset is refused rather than guessed,
//! so a target path the reader cannot see is never taken as absent.

use std::fmt;
use std::iter::Peekable;
use std::path::{Component, Path};
use std::str::Chars;

/// Deepest array or inline-table nesting a manifest may use.
const MAX_DEPTH: usize = 32;

/// The production build targets a manifest names explicitly.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ManifestTargets {
    /// `[lib] path`.
    pub lib: Option<String>,
    /// Every `[[bin]] path`.
    pub bins: Vec<String>,
    /// Every `[package] build` script path (`build = false` names none).
    pub build: Vec<String>,
    /// Every non-dev dependency, patch, or replacement `path`.
    pub path_dependencies: Vec<String>,
}

impl ManifestTargets {
    /// Every explicit production path, library first.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.lib
            .iter()
            .chain(self.bins.iter())
            .chain(self.build.iter())
            .chain(self.path_dependencies.iter())
            .map(String::as_str)
    }

    /// The first production path that names test code.
    ///
    /// A path names test code when any component is `tests` or its last is
    /// `tests.rs`. The literal is judged as written, never resolved.
    #[must_use]
    pub fn first_test_path(&self) -> Option<&str> {
        self.paths().find(|path| names_test_code(Path::new(path)))
    }
}

/// Whether a written path names test code or is ambiguous about it.
///
/// A path names test code when any component is `tests` or its last is
/// `tests.rs`, compared case-insensitively because a case-insensitive file
/// system resolves `Tests` to the same directory. A path is ambiguous, and so
/// judged as test code, when it is empty, is not UTF-8, holds a `\` or `:`
/// that another platform reads as a separator or drive, or has a component
/// ending in `.` or a space that Windows silently strips.
pub fn names_test_code(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return true;
    };
    if text.is_empty() || text.contains(['\\', ':']) {
        return true;
    }
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        let is_last = components.peek().is_none();
        let Component::Normal(name) = component else {
            continue;
        };
        let name = name.to_string_lossy();
        if name.ends_with(['.', ' '])
            || name.eq_ignore_ascii_case("tests")
            || (is_last && name.eq_ignore_ascii_case("tests.rs"))
        {
            return true;
        }
    }
    false
}

/// Why a manifest cannot be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError {
    /// 1-based line the reader stopped on.
    pub line: usize,
    /// What the reader expected there.
    pub reason: &'static str,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.reason)
    }
}

impl std::error::Error for ManifestError {}

/// Read the explicit production build targets out of manifest source `src`.
///
/// # Errors
///
/// [`ManifestError`] when `src` leaves the supported TOML subset, nests deeper
/// than the reader allows, or gives a target key a value that is not a path.
pub fn parse_manifest(src: &str) -> Result<ManifestTargets, ManifestError> {
    let entries = Parser::new(src).document()?;
    let mut targets = ManifestTargets::default();
    for entry in entries {
        collect(&mut targets, &entry.key, entry.value, entry.line)?;
    }
    Ok(targets)
}

/// One TOML value, kept only as finely as target extraction needs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Str(String),
    Bool(bool),
    Array(Vec<Value>),
    Table(Vec<(Vec<String>, Value)>),
    /// A number, date, or other bare scalar.
    Scalar,
}

/// A `key = value` line, its key already prefixed by the enclosing table.
struct Entry {
    line: usize,
    key: Vec<String>,
    value: Value,
}

/// Record the target paths `value` at dotted `key` contributes.
fn collect(
    targets: &mut ManifestTargets,
    key: &[String],
    value: Value,
    line: usize,
) -> Result<(), ManifestError> {
    let not_a_path = ManifestError {
        line,
        reason: "a build-target path is not a string",
    };
    let parts: Vec<&str> = key.iter().map(String::as_str).collect();
    match (key_role(&parts), value) {
        (KeyRole::NonProduction, _)
        | (KeyRole::BuildScript, Value::Bool(_))
        | (KeyRole::Other, Value::Str(_) | Value::Bool(_) | Value::Scalar) => {}
        (KeyRole::Lib, Value::Str(path)) => targets.lib = Some(path),
        (KeyRole::Bin, Value::Str(path)) => targets.bins.push(path),
        (KeyRole::BuildScript, Value::Str(path)) => targets.build.push(path),
        (KeyRole::PathDependency, Value::Str(path)) => targets.path_dependencies.push(path),
        (KeyRole::BuildScript, Value::Array(scripts)) => {
            for script in scripts {
                let Value::Str(path) = script else {
                    return Err(not_a_path);
                };
                targets.build.push(path);
            }
        }
        (KeyRole::Lib | KeyRole::Bin | KeyRole::BuildScript | KeyRole::PathDependency, _) => {
            return Err(not_a_path);
        }
        (KeyRole::Other, Value::Table(entries)) => {
            for (sub, value) in entries {
                let mut full = key.to_vec();
                full.extend(sub);
                collect(targets, &full, value, line)?;
            }
        }
        (KeyRole::Other, Value::Array(items)) => {
            for item in items {
                if matches!(item, Value::Table(_)) {
                    collect(targets, key, item, line)?;
                }
            }
        }
    }
    Ok(())
}

/// What a dotted manifest key means for the production build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyRole {
    Lib,
    Bin,
    BuildScript,
    /// A dependency, patch, or replacement source directory.
    PathDependency,
    /// A test, bench, example, dev-dependency, or metadata key.
    NonProduction,
    /// Any other key; values nested under it may still name a target.
    Other,
}

/// Classify dotted manifest key `key`.
fn key_role(key: &[&str]) -> KeyRole {
    let non_production = matches!(key.first(), Some(&("test" | "bench" | "example")))
        || matches!(key, ["package" | "workspace", "metadata", ..])
        || key.contains(&"dev-dependencies");
    if non_production {
        return KeyRole::NonProduction;
    }
    match key {
        ["lib", "path"] => KeyRole::Lib,
        ["bin", "path"] => KeyRole::Bin,
        ["package", "build"] => KeyRole::BuildScript,
        [_, .., "path"] => KeyRole::PathDependency,
        _ => KeyRole::Other,
    }
}

/// A character cursor over manifest source that tracks its line.
struct Parser<'a> {
    chars: Peekable<Chars<'a>>,
    line: usize,
}

impl<'a> Parser<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            chars: src.chars().peekable(),
            line: 1,
        }
    }

    const fn err(&self, reason: &'static str) -> ManifestError {
        ManifestError {
            line: self.line,
            reason,
        }
    }

    fn peek(&mut self) -> Option<char> {
        self.chars.peek().copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.chars.next();
        if c == Some('\n') {
            self.line = self.line.saturating_add(1);
        }
        c
    }

    fn eat(&mut self, want: char) -> bool {
        if self.peek() == Some(want) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn skip_blanks(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.bump();
        }
    }

    fn skip_comment(&mut self) {
        if self.peek() == Some('#') {
            while !matches!(self.peek(), None | Some('\n')) {
                self.bump();
            }
        }
    }

    /// Skip blanks, comments, and line breaks.
    fn skip_trivia(&mut self) {
        loop {
            self.skip_blanks();
            self.skip_comment();
            if matches!(self.peek(), Some('\n' | '\r')) {
                self.bump();
            } else {
                return;
            }
        }
    }

    /// Consume the rest of a line that must hold nothing but a comment.
    fn end_of_line(&mut self) -> Result<(), ManifestError> {
        self.skip_blanks();
        self.skip_comment();
        match self.peek() {
            None => Ok(()),
            Some('\n') => {
                self.bump();
                Ok(())
            }
            Some('\r') => {
                self.bump();
                if self.eat('\n') {
                    Ok(())
                } else {
                    Err(self.err("a bare carriage return"))
                }
            }
            Some(_) => Err(self.err("expected the end of the line")),
        }
    }

    /// Every `key = value` entry, each key prefixed by its table header.
    fn document(&mut self) -> Result<Vec<Entry>, ManifestError> {
        let mut entries = Vec::new();
        let mut table: Vec<String> = Vec::new();
        loop {
            self.skip_trivia();
            match self.peek() {
                None => return Ok(entries),
                Some('[') => {
                    self.bump();
                    let array = self.eat('[');
                    self.skip_blanks();
                    table = self.key()?;
                    self.skip_blanks();
                    if !self.eat(']') || (array && !self.eat(']')) {
                        return Err(self.err("an unterminated table header"));
                    }
                    self.end_of_line()?;
                }
                Some(_) => {
                    let line = self.line;
                    let mut key = table.clone();
                    key.extend(self.key()?);
                    self.skip_blanks();
                    if !self.eat('=') {
                        return Err(self.err("expected `=` after a key"));
                    }
                    self.skip_blanks();
                    let value = self.value(0)?;
                    entries.push(Entry { line, key, value });
                    self.end_of_line()?;
                }
            }
        }
    }

    /// A dotted key: one or more simple keys joined by `.`.
    fn key(&mut self) -> Result<Vec<String>, ManifestError> {
        let mut parts = vec![self.simple_key()?];
        loop {
            self.skip_blanks();
            if !self.eat('.') {
                return Ok(parts);
            }
            self.skip_blanks();
            parts.push(self.simple_key()?);
        }
    }

    /// A bare key or a single-line quoted key.
    fn simple_key(&mut self) -> Result<String, ManifestError> {
        if matches!(self.peek(), Some('"' | '\'')) {
            return self.string();
        }
        let mut key = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                key.push(c);
                self.bump();
            } else {
                break;
            }
        }
        if key.is_empty() {
            Err(self.err("expected a key"))
        } else {
            Ok(key)
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ManifestError> {
        if depth > MAX_DEPTH {
            return Err(self.err("arrays or inline tables nest too deep"));
        }
        let inner = depth.saturating_add(1);
        match self.peek() {
            Some('"' | '\'') => self.string().map(Value::Str),
            Some('[') => {
                self.bump();
                let mut items = Vec::new();
                loop {
                    self.skip_trivia();
                    if self.eat(']') {
                        return Ok(Value::Array(items));
                    }
                    items.push(self.value(inner)?);
                    self.skip_trivia();
                    if self.eat(']') {
                        return Ok(Value::Array(items));
                    }
                    if !self.eat(',') {
                        return Err(self.err("expected `,` or `]` in an array"));
                    }
                }
            }
            Some('{') => {
                self.bump();
                let mut entries = Vec::new();
                self.skip_trivia();
                if self.eat('}') {
                    return Ok(Value::Table(entries));
                }
                loop {
                    self.skip_trivia();
                    let key = self.key()?;
                    self.skip_blanks();
                    if !self.eat('=') {
                        return Err(self.err("expected `=` in an inline table"));
                    }
                    self.skip_blanks();
                    entries.push((key, self.value(inner)?));
                    self.skip_trivia();
                    if self.eat('}') {
                        return Ok(Value::Table(entries));
                    }
                    if !self.eat(',') {
                        return Err(self.err("expected `,` or `}` in an inline table"));
                    }
                }
            }
            _ => self.scalar(),
        }
    }

    /// A bare scalar: a boolean, number, or date.
    fn scalar(&mut self) -> Result<Value, ManifestError> {
        let mut text = String::new();
        while let Some(c) = self.peek() {
            if c.is_whitespace() || matches!(c, ',' | ']' | '}' | '#') {
                break;
            }
            text.push(c);
            self.bump();
        }
        match text.as_str() {
            "" => Err(self.err("expected a value")),
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => Ok(Value::Scalar),
        }
    }

    /// Any of the four string forms, decoded; the cursor is on the opening quote.
    fn string(&mut self) -> Result<String, ManifestError> {
        let Some(quote) = self.bump() else {
            return Err(self.err("expected a string"));
        };
        let mut multiline = false;
        if self.eat(quote) {
            if !self.eat(quote) {
                return Ok(String::new());
            }
            multiline = true;
            self.eat('\r');
            self.eat('\n');
        }
        let mut out = String::new();
        loop {
            let Some(c) = self.bump() else {
                return Err(self.err("an unterminated string"));
            };
            if c == quote {
                if !multiline {
                    return Ok(out);
                }
                if !self.eat(quote) {
                    out.push(quote);
                    continue;
                }
                if !self.eat(quote) {
                    out.push(quote);
                    out.push(quote);
                    continue;
                }
                // Up to two quotes may directly precede the closing delimiter.
                for _ in 0..2 {
                    if self.eat(quote) {
                        out.push(quote);
                    }
                }
                return Ok(out);
            }
            if c == '\n' && !multiline {
                return Err(self.err("a line break inside a single-line string"));
            }
            if c == '\\' && quote == '"' {
                self.escape(&mut out, multiline)?;
            } else {
                out.push(c);
            }
        }
    }

    /// Decode one basic-string escape; the cursor is just past the backslash.
    fn escape(&mut self, out: &mut String, multiline: bool) -> Result<(), ManifestError> {
        match self.bump() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('e') => out.push('\u{1b}'),
            Some('u') => out.push(self.unicode(4)?),
            Some('U') => out.push(self.unicode(8)?),
            Some(c) if multiline && matches!(c, ' ' | '\t' | '\r' | '\n') => {
                // A line-ending backslash trims the break and following blanks.
                let mut saw_break = c == '\n';
                while let Some(next) = self.peek() {
                    match next {
                        ' ' | '\t' | '\r' => {}
                        '\n' => saw_break = true,
                        _ => break,
                    }
                    self.bump();
                }
                if !saw_break {
                    return Err(self.err("a backslash before blanks that end no line"));
                }
            }
            _ => return Err(self.err("an invalid string escape")),
        }
        Ok(())
    }

    /// A `\u`/`\U` escape's scalar value from its `digits` hex digits.
    fn unicode(&mut self, digits: usize) -> Result<char, ManifestError> {
        let mut code: u32 = 0;
        for _ in 0..digits {
            let digit = self.bump().and_then(|c| c.to_digit(16));
            code = digit
                .and_then(|d| code.checked_mul(16).and_then(|c| c.checked_add(d)))
                .ok_or_else(|| self.err("an invalid unicode escape"))?;
        }
        char::from_u32(code).ok_or_else(|| self.err("an invalid unicode scalar"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(src: &str) -> ManifestTargets {
        let parsed = parse_manifest(src);
        assert!(parsed.is_ok(), "{src:?} must parse: {parsed:?}");
        parsed.unwrap_or_default()
    }

    #[test]
    fn a_plain_manifest_names_its_explicit_targets() {
        let src = r#"
# A crate.
[package]
name = "demo"   # trailing comment
version = "0.1.0"
build = false
description = """
multi-line "quoted" text
"""

[lib]
path = "src/lib.rs"
crate-type = ["rlib", 'cdylib']

[[bin]]
name = "a"
path = "src/main.rs"

[[bin]]
name = "b"
path = 'src/bin/b.rs'

[dependencies]
serde = { version = "1", features = ["derive"] }
local = { path = "../tests-helper" }
nested = [
    [1, 2],
    { a = { b = "c" } },
]

[[test]]
name = "it"
path = "tests/it.rs"
"#;
        assert_eq!(
            targets(src),
            ManifestTargets {
                lib: Some("src/lib.rs".to_owned()),
                bins: vec!["src/main.rs".to_owned(), "src/bin/b.rs".to_owned()],
                build: Vec::new(),
                path_dependencies: vec!["../tests-helper".to_owned()],
            }
        );
        assert_eq!(targets(src).first_test_path(), None);
    }

    #[test]
    fn test_only_keys_never_name_production_targets() {
        let src = r#"
[dev-dependencies]
helper = { path = "tests/helper" }

[target.'cfg(unix)'.dev-dependencies]
unix-helper = { path = "tests/unix" }

[[test]]
path = "tests/it.rs"

[[bench]]
path = "tests/bench.rs"

[[example]]
path = "tests/example.rs"

[package.metadata.tool]
path = 7
"#;
        assert_eq!(targets(src), ManifestTargets::default());
    }

    #[test]
    fn a_production_path_under_tests_is_named() {
        for src in [
            "[lib]\npath = \"tests/lib.rs\"",
            "[[bin]]\npath = \"src/../tests/main.rs\"",
            "[package]\nbuild = \"tests/build.rs\"",
            "[lib]\npath = \"src/tests.rs\"",
            "[dependencies]\nx = { path = \"tests/x\" }",
            "[dependencies]\nx = { path = \"../tests\" }",
            "[dependencies.x]\npath = \"tests/x\"",
            "[build-dependencies]\nx = { path = \"tests/x\" }",
            "[target.'cfg(unix)'.dependencies]\nx = { path = \"tests/x\" }",
            "[workspace.dependencies]\nx = { path = \"tests/x\" }",
            "[patch.crates-io]\nx = { path = \"tests/x\" }",
        ] {
            assert!(targets(src).first_test_path().is_some(), "{src:?}");
        }
        for src in [
            "[lib]\npath = \"src/lib.rs\"",
            "[lib]\npath = \"src/contests.rs\"",
            "[dependencies]\nx = { path = \"../tests-helper\" }",
        ] {
            assert_eq!(targets(src).first_test_path(), None, "{src:?}");
        }
    }

    #[test]
    fn every_target_spelling_is_read() {
        for (src, want) in [
            ("[lib]\npath = \"tests/lib.rs\"", "tests/lib.rs"),
            ("lib = { path = \"tests/lib.rs\" }", "tests/lib.rs"),
            ("lib.path = 'tests/lib.rs'", "tests/lib.rs"),
            ("[lib]\n\"path\" = \"tests/lib.rs\"", "tests/lib.rs"),
            ("[lib]\npath = \"\\u0074ests/lib.rs\"", "tests/lib.rs"),
            ("[[bin]]\npath = \"tests/main.rs\"", "tests/main.rs"),
            (
                "bin = [{ name = \"x\", path = \"tests/x.rs\" }]",
                "tests/x.rs",
            ),
            ("[package]\nbuild = \"tests/build.rs\"", "tests/build.rs"),
            ("package.build = [\"tests/build.rs\"]", "tests/build.rs"),
            ("[package]\nbuild = '''tests/build.rs'''", "tests/build.rs"),
        ] {
            let found = targets(src);
            assert!(found.paths().any(|p| p == want), "{src:?} -> {found:?}");
        }
    }

    #[test]
    fn manifests_outside_the_subset_are_refused() {
        for src in [
            "[lib]\npath = \"tests/lib.rs",
            "[lib]\npath =",
            "[lib\npath = \"src/lib.rs\"",
            "[lib]\npath = [\"tests/lib.rs\"]",
            "[[bin]]\npath = 5",
            "[package]\nbuild = [1]",
            "[lib]\npath = \"a\\qb\"",
            "[lib]\npath = \"src/lib.rs\" extra",
            "key = \"line\nbreak\"",
        ] {
            assert!(parse_manifest(src).is_err(), "{src:?} must be refused");
        }
    }

    #[test]
    fn ambiguous_or_case_folded_test_paths_name_test_code() {
        for path in [
            "",
            "Tests/lib.rs",
            "TESTS/lib.rs",
            "src/Tests.RS",
            "tests\\lib.rs",
            "src\\..\\tests\\lib.rs",
            "C:tests/lib.rs",
            "c:/src/lib.rs",
            "tests./lib.rs",
            "tests /lib.rs",
            "src/lib.rs.",
            "src/lib.rs ",
        ] {
            assert!(names_test_code(Path::new(path)), "{path:?}");
        }
        for path in [
            "src/lib.rs",
            "../../runtime/rust/src/path_core.rs",
            "./src/contests.rs",
            "src/tests.rs/../lib.rs.bak",
            "../tests-helper",
        ] {
            assert!(!names_test_code(Path::new(path)), "{path:?}");
        }
    }

    /// Every `Cargo.toml` under the repository's `src` tree stays inside the
    /// subset the reader accepts, and none names test code as a production
    /// target, so the reader never refuses a real crate.
    #[test]
    fn every_repository_manifest_parses_and_names_no_test_code() -> std::io::Result<()> {
        let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../src");
        let mut pending = vec![src_root];
        let mut seen = 0_usize;
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let kind = entry.file_type()?;
                let path = entry.path();
                if kind.is_dir() && entry.file_name() != "target" {
                    pending.push(path);
                } else if kind.is_file() && entry.file_name() == "Cargo.toml" {
                    let src = std::fs::read_to_string(&path)?;
                    let parsed = parse_manifest(&src);
                    assert!(parsed.is_ok(), "{}: {parsed:?}", path.display());
                    assert_eq!(
                        parsed.unwrap_or_default().first_test_path(),
                        None,
                        "{}",
                        path.display()
                    );
                    seen = seen.saturating_add(1);
                }
            }
        }
        assert!(
            seen > 0,
            "no manifest found under the repository `src` tree"
        );
        Ok(())
    }

    #[test]
    fn nesting_past_the_limit_is_refused() {
        let deep = format!(
            "x = {}{}",
            "[".repeat(MAX_DEPTH + 2),
            "]".repeat(MAX_DEPTH + 2)
        );
        assert!(parse_manifest(&deep).is_err());
        let shallow = format!("x = {}{}", "[".repeat(4), "]".repeat(4));
        assert!(parse_manifest(&shallow).is_ok());
    }
}
