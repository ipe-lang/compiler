#![forbid(unsafe_code)]
//! Pins every read of the process command line to its audited decode point.
//!
//! `std::env::args()` aborts the process on an argument that is not valid
//! UTF-8, so a workspace binary reads its command line through
//! `ipe_docs::argv::host_args`, which refuses such an argument with a typed
//! error naming its position. The scan is an inventory, never a denylist of one
//! spelling: it lexes every tracked `.rs` file under [`SCANNED_ROOTS`]
//! (comments and literals dropped) and refuses
//!
//! - an `env::args` path in any form (a call, an import, a function value),
//!   outside the pinned [`ARGS_DEBT`] sites;
//! - an `env::{..}` group naming `args`, `args_os` or `self as ..`, an
//!   `env::*` glob, and an `env as ..` alias, under which a read would no
//!   longer spell `env::args`;
//! - an `env::args_os` read outside the pinned [`ARGS_OS_OWNERS`] counts;
//! - an `env::$name` macro path, which names a reader only once expanded.
//!
//! A file whose pinned count moves, or a pinned file that no longer holds its
//! site, goes red, so the inventory only ever shrinks to the truth. A reader
//! named only inside an external macro's own expansion is beyond a lexical scan.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// The files that read the raw argument vector, with the count of
/// `env::args_os` reads each holds and why the site is sound.
const ARGS_OS_OWNERS: &[(&str, usize, &str)] = &[
    (
        "src/ipe-docs/src/argv.rs",
        1,
        "the one host decode point: every argument after the program name is decoded as UTF-8 or refused by position",
    ),
    (
        "src/runtime/rust/src/system.rs",
        2,
        "the standalone runtime's `System.args`/`getArg`, decoded per argument with a typed refusal",
    ),
    (
        "src/ipe-wrapper/src/main.rs",
        1,
        "forwards the arguments as `OsString` to the real binary without decoding them",
    ),
    (
        "examples/wasm/language-playground/jail-runner/src/main.rs",
        1,
        "the playground jail runner, outside the host crates: every argument is decoded as UTF-8 or the run is refused without echoing its bytes",
    ),
    (
        "src/runtime/rust/tests/spawn_fd_floor.rs",
        1,
        "compares each argument as `OsStr` with the exec-probe marker, never decoding it",
    ),
];

/// Standalone tool and example binaries outside the workspace's host crates
/// that still read `std::env::args()`, with their site counts.
///
/// A ratchet: each entry is removed once its binary reads through a decoding
/// point, never added to.
const ARGS_DEBT: &[(&str, usize)] = &[
    ("tools/ipe-ffi-inspector/src/main.rs", 1),
    ("tools/panic-scan/src/main.rs", 1),
];

/// One lexical token: an identifier or keyword, or a punctuation mark (`::`
/// is one token).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Ident(String),
    Punct(&'static str),
}

/// What a file's tokens hold.
#[derive(Default, Debug, PartialEq, Eq)]
struct Findings {
    /// `env::args` paths.
    args: usize,
    /// `env::args_os` paths.
    args_os: usize,
    /// Imports or aliases that would hide a read from the path rules.
    hiding: Vec<&'static str>,
}

/// Lex Rust source into identifiers and the punctuation the rules read.
///
/// Comments, string/char/byte literals and raw strings are dropped; a
/// lifetime's quote is skipped.
fn lex(src: &str) -> Vec<Token> {
    let chars: Vec<char> = src.chars().collect();
    let at = |i: usize| chars.get(i).copied();
    let mut tokens = Vec::new();
    let mut i = 0;
    while let Some(c) = at(i) {
        let next = at(i + 1);
        if c == '/' && next == Some('/') {
            while at(i).is_some_and(|c| c != '\n') {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            i = skip_block_comment(&chars, i);
        } else if c == '"' {
            i = skip_quoted(&chars, i + 1, '"');
        } else if c == '\'' {
            i = skip_char_or_lifetime(&chars, i);
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while at(i).is_some_and(|c| c.is_alphanumeric() || c == '_') {
                i += 1;
            }
            let word: String = chars.get(start..i).unwrap_or_default().iter().collect();
            match literal_after_prefix(&chars, &word, i) {
                Some(end) => i = end,
                None if word == "r" && at(i) == Some('#') => {
                    // A raw identifier `r#name`: the name follows.
                    i += 1;
                }
                None => tokens.push(Token::Ident(word)),
            }
        } else if c == ':' && next == Some(':') {
            tokens.push(Token::Punct("::"));
            i += 2;
        } else {
            match c {
                '{' => tokens.push(Token::Punct("{")),
                '}' => tokens.push(Token::Punct("}")),
                '*' => tokens.push(Token::Punct("*")),
                ',' => tokens.push(Token::Punct(",")),
                ';' => tokens.push(Token::Punct(";")),
                '$' => tokens.push(Token::Punct("$")),
                _ if !c.is_whitespace() => tokens.push(Token::Punct("other")),
                _ => {}
            }
            i += 1;
        }
    }
    tokens
}

/// The end of a (possibly nested) block comment opening at `start`.
fn skip_block_comment(chars: &[char], start: usize) -> usize {
    let mut depth = 0usize;
    let mut i = start;
    while let Some(c) = chars.get(i).copied() {
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('*') {
            depth += 1;
            i += 2;
        } else if c == '*' && next == Some('/') {
            depth = depth.saturating_sub(1);
            i += 2;
            if depth == 0 {
                return i;
            }
        } else {
            i += 1;
        }
    }
    i
}

/// The index after the closing `quote` of an escaped literal whose body starts
/// at `start`.
fn skip_quoted(chars: &[char], start: usize, quote: char) -> usize {
    let mut i = start;
    while let Some(c) = chars.get(i).copied() {
        if c == '\\' {
            i += 2;
        } else if c == quote {
            return i + 1;
        } else {
            i += 1;
        }
    }
    i
}

/// Skip a char literal (`'x'`, `'\n'`, `'\u{..}'`) or a lifetime's quote at
/// `start`.
fn skip_char_or_lifetime(chars: &[char], start: usize) -> usize {
    let first = chars.get(start + 1).copied();
    if first == Some('\\') {
        return skip_quoted(chars, start + 1, '\'');
    }
    if chars.get(start + 2).copied() == Some('\'') {
        return start + 3;
    }
    start + 1
}

/// The end of a literal opened by a prefix word (`r"`, `r#"`, `b"`, `br#"`,
/// `c"`, `cr"`, `b'`) ending at `i`, or `None` when the word opens no literal.
fn literal_after_prefix(chars: &[char], word: &str, i: usize) -> Option<usize> {
    let raw = matches!(word, "r" | "br" | "cr");
    let plain = matches!(word, "b" | "c");
    if plain && chars.get(i).copied() == Some('"') {
        return Some(skip_quoted(chars, i + 1, '"'));
    }
    if word == "b" && chars.get(i).copied() == Some('\'') {
        return Some(skip_quoted(chars, i + 1, '\''));
    }
    if !raw {
        return None;
    }
    let mut hashes = 0usize;
    while chars.get(i + hashes).copied() == Some('#') {
        hashes += 1;
    }
    if chars.get(i + hashes).copied() != Some('"') {
        return None;
    }
    let mut j = i + hashes + 1;
    while let Some(c) = chars.get(j).copied() {
        if c == '"' && (1..=hashes).all(|k| chars.get(j + k).copied() == Some('#')) {
            return Some(j + 1 + hashes);
        }
        j += 1;
    }
    Some(j)
}

/// Whether `token` is the identifier `name`.
fn is_ident(token: Option<&Token>, name: &str) -> bool {
    matches!(token, Some(Token::Ident(word)) if word == name)
}

/// Apply the scan's rules to one file's tokens.
fn findings(src: &str) -> Findings {
    let tokens = lex(src);
    let mut found = Findings::default();
    for (i, token) in tokens.iter().enumerate() {
        if !is_ident(Some(token), "env") {
            continue;
        }
        let after = tokens.get(i + 1);
        if is_ident(after, "as") {
            found.hiding.push("`env as ..` aliases the module");
            continue;
        }
        if after != Some(&Token::Punct("::")) {
            continue;
        }
        let item = tokens.get(i + 2);
        if is_ident(item, "args") {
            found.args += 1;
        } else if is_ident(item, "args_os") {
            found.args_os += 1;
        } else if item == Some(&Token::Punct("$")) {
            found
                .hiding
                .push("`env::$..` names a reader through a macro metavariable");
        } else if item == Some(&Token::Punct("*")) {
            found.hiding.push("`env::*` glob-imports the readers");
        } else if item == Some(&Token::Punct("{")) {
            found
                .hiding
                .extend(group_hiding(tokens.get(i + 3..).unwrap_or_default()));
        }
    }
    found
}

/// What an `env::{..}` group (its tokens after the `{`) hides.
fn group_hiding(rest: &[Token]) -> Vec<&'static str> {
    let mut hiding = Vec::new();
    let mut depth = 1usize;
    for (k, token) in rest.iter().enumerate() {
        match token {
            Token::Punct("{") => depth += 1,
            Token::Punct("}") => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            }
            Token::Ident(word) if word == "args" || word == "args_os" => {
                hiding.push("`env::{..}` imports an argument reader");
            }
            Token::Ident(word) if word == "self" && is_ident(rest.get(k + 1), "as") => {
                hiding.push("`env::{self as ..}` aliases the module");
            }
            Token::Ident(_) | Token::Punct(_) => {}
        }
    }
    hiding
}

/// The top-level directories whose tracked `.rs` files the scan reads: every
/// directory of the checkout that holds Rust source, emitted goldens included.
const SCANNED_ROOTS: &[&str] = &["src", "tools", "examples", "editors", "tests"];

/// The top-level directory of every tracked `.rs` file in the checkout.
fn tracked_rust_roots() -> std::collections::BTreeSet<String> {
    let listed = std::process::Command::new("git")
        .arg("-C")
        .arg(workspace())
        .args(["ls-files", "-z", "--cached", "--", "*.rs"])
        .output();
    assert!(
        matches!(&listed, Ok(out) if out.status.success()),
        "git ls-files must list the tracked Rust files: {listed:?}"
    );
    let stdout = listed.map(|out| out.stdout).unwrap_or_default();
    String::from_utf8_lossy(&stdout)
        .split('\0')
        .filter(|rel| !rel.is_empty())
        .filter_map(|rel| rel.split('/').next())
        .map(str::to_owned)
        .collect()
}

/// The workspace root.
fn workspace() -> PathBuf {
    e2e_support::manifest_dir!().join("../..")
}

/// Every scanned `.rs` file, as `(workspace-relative path, text)`.
///
/// The set is what git would commit: tracked files plus untracked ones not
/// ignored, so build output is never scanned while a new, unadded source is.
fn scanned_files() -> Vec<(String, String)> {
    let root = workspace();
    let listed = std::process::Command::new("git")
        .arg("-C")
        .arg(&root)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .arg("--")
        .args(SCANNED_ROOTS)
        .output();
    assert!(
        matches!(&listed, Ok(out) if out.status.success()),
        "git ls-files must list the workspace checkout: {listed:?}"
    );
    let stdout = listed.map(|out| out.stdout).unwrap_or_default();
    let listed = String::from_utf8(stdout);
    assert!(
        listed.is_ok(),
        "git ls-files listed a non-UTF-8 path: {listed:?}"
    );
    let listed = listed.unwrap_or_default();
    let mut files = Vec::new();
    let mut unreadable = Vec::new();
    for rel in listed.split('\0') {
        let is_rust = std::path::Path::new(rel)
            .extension()
            .is_some_and(|ext| ext == "rs");
        if rel.is_empty() || !is_rust {
            continue;
        }
        let path = root.join(rel);
        match std::fs::read_to_string(&path) {
            Ok(text) => files.push((rel.to_owned(), text)),
            // `--cached` still lists a tracked file deleted from the worktree.
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound && path.symlink_metadata().is_err() => {
            }
            Err(e) => unreadable.push(format!("{rel}: {e}")),
        }
    }
    assert!(
        unreadable.is_empty(),
        "unreadable scanned files: {unreadable:?}"
    );
    files
}

#[test]
fn every_command_line_read_goes_through_a_pinned_decode_point() {
    let files = scanned_files();
    assert!(
        files
            .iter()
            .any(|(rel, _)| rel == "src/ipe-docs/src/argv.rs"),
        "the scan must see the decode point it pins"
    );
    let tracked_rust_roots = tracked_rust_roots();
    assert!(
        tracked_rust_roots
            .iter()
            .all(|root| SCANNED_ROOTS.contains(&root.as_str())),
        "a top-level directory holds tracked Rust the scan skips: {tracked_rust_roots:?}"
    );
    let mut args: BTreeMap<String, usize> = BTreeMap::new();
    let mut args_os: BTreeMap<String, usize> = BTreeMap::new();
    let mut hiding = Vec::new();
    for (rel, text) in &files {
        let found = findings(text);
        if found.args > 0 {
            args.insert(rel.clone(), found.args);
        }
        if found.args_os > 0 {
            args_os.insert(rel.clone(), found.args_os);
        }
        hiding.extend(
            found
                .hiding
                .into_iter()
                .map(|what| format!("{rel}: {what}")),
        );
    }
    let debt: BTreeMap<String, usize> = ARGS_DEBT
        .iter()
        .map(|(rel, n)| ((*rel).to_owned(), *n))
        .collect();
    let owners: BTreeMap<String, usize> = ARGS_OS_OWNERS
        .iter()
        .map(|(rel, n, _)| ((*rel).to_owned(), *n))
        .collect();
    assert_eq!(
        args, debt,
        "`std::env::args()` aborts on a non-UTF-8 argument; read the command line through \
         `ipe_docs::argv::host_args` (a fixed debt site leaves `ARGS_DEBT`)"
    );
    assert_eq!(
        args_os, owners,
        "a raw `env::args_os` read outside `ARGS_OS_OWNERS`; decode through \
         `ipe_docs::argv::host_args`"
    );
    assert!(
        hiding.is_empty(),
        "imports that hide an argument read: {hiding:?}"
    );
}

#[test]
fn every_spelling_of_an_args_read_is_seen() {
    let reads = [
        "fn main() { let a: Vec<String> = std::env::args().collect(); }",
        "fn main() { let a = ::std::env::args(); }",
        "use std::env; fn main() { let a = env::args(); }",
        "use std::env::args;",
        "fn main() { let f = std::env::args; }",
        "use std::env::r#args;",
    ];
    for src in reads {
        assert_eq!(
            findings(src).args,
            1,
            "an `env::args` read went unseen: {src:?}"
        );
    }
    assert_eq!(findings("fn f() { std::env::args_os(); }").args_os, 1);
    assert_eq!(findings("fn f() { std::env::args_os(); }").args, 0);
}

#[test]
fn every_import_that_hides_a_read_is_refused() {
    let hidden = [
        "use std::env as e; fn main() { e::args(); }",
        "use std::{env as e, fs};",
        "use std::env::{self as e};",
        "use std::env::{args};",
        "use std::env::{var, args_os};",
        "use std::{env::{self, args}};",
        "use std::env::*;",
        "macro_rules! read { ($r:ident) => { std::env::$r() }; }",
    ];
    for src in hidden {
        assert!(
            !findings(src).hiding.is_empty(),
            "a hiding import went unseen: {src:?}"
        );
    }
}

#[test]
fn comments_literals_and_other_env_modules_are_not_reads() {
    let clean = [
        "// std::env::args() aborts",
        "/* outer /* std::env::args() */ still comment */ fn f() {}",
        "let s = \"std::env::args()\";",
        "let s = r#\"std::env::args() \"quoted\" \"#;",
        "let s = b\"env::args\";",
        "let c = '\"'; let s = \"env::args\";",
        "fn f<'a>(x: &'a str) -> &'a str { x }",
        "use crate::env::{Scope, Frame};",
        "pub use env::{CtorHome, Env};",
        "let bin_args_os = ipe_env::args;",
    ];
    for src in clean {
        assert_eq!(
            findings(src),
            Findings::default(),
            "a non-read was flagged: {src:?}"
        );
    }
}
