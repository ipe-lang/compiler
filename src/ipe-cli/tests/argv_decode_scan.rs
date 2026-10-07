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
//! - a ban-proof naming outside the pinned [`BAN_PROOFS`] counts, and a macro
//!   or a non-`expect` attribute in a ban-proof file;
//! - an `env::$name` macro path, which names a reader only once expanded.
//!
//! A file whose pinned count moves, or a pinned file that no longer holds its
//! site, goes red, so the inventory only ever shrinks to the truth. A reader
//! named only inside an external macro's own expansion is beyond a lexical scan.

use std::collections::{BTreeMap, BTreeSet};
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

/// The files that name a reader only to prove a crate's `clippy.toml` ban on
/// it, with the `env::args` and `env::args_os` namings each holds and why.
///
/// A naming is exactly the statement
/// `#[expect(clippy::disallowed_methods)] let _ = ::std::env::<reader>;`: it
/// discards the function item and calls nothing, so it reads no argument. Any
/// other spelling in such a file is a read and is judged as one. A listed file
/// holds no `!` and no attribute other than `#[expect(..)]`, since a macro
/// could rewrite a naming into a call.
const BAN_PROOFS: &[(&str, usize, usize, &str)] = &[(
    "src/compiler/db/src/clippy_paths_resolve.rs",
    1,
    1,
    "names both readers so the `ipe_db` ban on argument reads resolves and fires under `-D warnings`",
)];

/// The tokens of `#[expect(clippy::disallowed_methods)] let _ = ::std::` that
/// open a ban-proof naming, ahead of its `env`.
const NAMING_HEAD: [&str; 15] = [
    "#",
    "[",
    "expect",
    "(",
    "clippy",
    "::",
    "disallowed_methods",
    ")",
    "]",
    "let",
    "_",
    "=",
    "::",
    "std",
    "::",
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
    /// `env::args` paths named by a ban-proof statement.
    args_named: usize,
    /// `env::args_os` paths named by a ban-proof statement.
    args_os_named: usize,
    /// `!` marks and attributes other than `#[expect(..)]`: each may be a macro
    /// that rewrites a naming into a read, so a ban-proof file holds none.
    rewriters: usize,
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
                '#' => tokens.push(Token::Punct("#")),
                '!' => tokens.push(Token::Punct("!")),
                '=' => tokens.push(Token::Punct("=")),
                '(' => tokens.push(Token::Punct("(")),
                ')' => tokens.push(Token::Punct(")")),
                '[' => tokens.push(Token::Punct("[")),
                ']' => tokens.push(Token::Punct("]")),
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

/// Whether `token` is the identifier or punctuation mark `text`.
fn is_text(token: Option<&Token>, text: &str) -> bool {
    match token {
        Some(Token::Ident(word)) => word == text,
        Some(Token::Punct(mark)) => *mark == text,
        None => false,
    }
}

/// Whether the `env` at `at` is the path of a ban-proof naming, the whole
/// statement `#[expect(clippy::disallowed_methods)] let _ = ::std::env::<reader>;`.
fn is_ban_naming(tokens: &[Token], at: usize) -> bool {
    let Some(start) = at.checked_sub(NAMING_HEAD.len()) else {
        return false;
    };
    NAMING_HEAD
        .iter()
        .enumerate()
        .all(|(k, text)| is_text(tokens.get(start + k), text))
        && is_text(tokens.get(at + 1), "::")
        && is_text(tokens.get(at + 3), ";")
}

/// Whether the token at `at` may rewrite the code around it: a `!` (a macro
/// call, or anything else a ban-proof file never needs) or a `#` that opens
/// no `#[expect(..)]`.
fn is_rewriter(tokens: &[Token], at: usize) -> bool {
    let token = tokens.get(at);
    is_text(token, "!")
        || (is_text(token, "#")
            && !(is_text(tokens.get(at + 1), "[")
                && is_text(tokens.get(at + 2), "expect")
                && is_text(tokens.get(at + 3), "(")))
}

/// Apply the scan's rules to one file's tokens.
fn findings(src: &str) -> Findings {
    let tokens = lex(src);
    let mut found = Findings::default();
    for (i, token) in tokens.iter().enumerate() {
        if is_rewriter(&tokens, i) {
            found.rewriters += 1;
        }
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
        let named = is_ban_naming(&tokens, i);
        if is_ident(item, "args") && named {
            found.args_named += 1;
        } else if is_ident(item, "args") {
            found.args += 1;
        } else if is_ident(item, "args_os") && named {
            found.args_os_named += 1;
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
    let violations = inventory_violations(&files);
    assert!(
        violations.is_empty(),
        "the command-line read inventory drifted: {violations:#?}"
    );
}

/// Every way `files` departs from the pinned inventory: [`ARGS_DEBT`],
/// [`ARGS_OS_OWNERS`], [`BAN_PROOFS`] and the hiding rules.
fn inventory_violations(files: &[(String, String)]) -> Vec<String> {
    let proof_files: BTreeSet<&str> = BAN_PROOFS.iter().map(|(rel, ..)| *rel).collect();
    let mut args: BTreeMap<String, usize> = BTreeMap::new();
    let mut args_os: BTreeMap<String, usize> = BTreeMap::new();
    let mut named: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut violations = Vec::new();
    for (rel, text) in files {
        let found = findings(text);
        if found.args > 0 {
            args.insert(rel.clone(), found.args);
        }
        if found.args_os > 0 {
            args_os.insert(rel.clone(), found.args_os);
        }
        if found.args_named > 0 || found.args_os_named > 0 {
            named.insert(rel.clone(), (found.args_named, found.args_os_named));
        }
        if proof_files.contains(rel.as_str()) && found.rewriters > 0 {
            violations.push(format!(
                "{rel}: a ban-proof file holds a `!` or an attribute other than \
                 `#[expect(..)]`, either of which can rewrite a naming into a read"
            ));
        }
        violations.extend(
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
    let proofs: BTreeMap<String, (usize, usize)> = BAN_PROOFS
        .iter()
        .map(|(rel, a, o, _)| ((*rel).to_owned(), (*a, *o)))
        .collect();
    if args != debt {
        violations.push(format!(
            "`std::env::args()` aborts on a non-UTF-8 argument; read the command line through \
             `ipe_docs::argv::host_args` (a fixed debt site leaves `ARGS_DEBT`): found {args:?}, \
             pinned {debt:?}"
        ));
    }
    if args_os != owners {
        violations.push(format!(
            "a raw `env::args_os` read outside `ARGS_OS_OWNERS`; decode through \
             `ipe_docs::argv::host_args`: found {args_os:?}, pinned {owners:?}"
        ));
    }
    if named != proofs {
        violations.push(format!(
            "a ban-proof naming outside `BAN_PROOFS`: found {named:?}, pinned {proofs:?}"
        ));
    }
    violations
}

/// The proof naming of `env::args`.
const ARGS_NAMING: &str = "#[expect(clippy::disallowed_methods)] let _ = ::std::env::args;";

/// The proof naming of `env::args_os`.
const ARGS_OS_NAMING: &str = "#[expect(clippy::disallowed_methods)] let _ = ::std::env::args_os;";

/// A tree holding exactly the pinned sites: each debt and owner file reads its
/// pinned count, and each proof file names its pinned readers.
fn pinned_tree() -> Vec<(String, String)> {
    let debt = ARGS_DEBT.iter().map(|(rel, n)| {
        let body = "std::env::args();".repeat(*n);
        ((*rel).to_owned(), format!("fn f() {{ {body} }}"))
    });
    let owners = ARGS_OS_OWNERS.iter().map(|(rel, n, _)| {
        let body = "std::env::args_os();".repeat(*n);
        ((*rel).to_owned(), format!("fn f() {{ {body} }}"))
    });
    let proofs = BAN_PROOFS.iter().map(|(rel, a, o, _)| {
        let body = format!("{}{}", ARGS_NAMING.repeat(*a), ARGS_OS_NAMING.repeat(*o));
        ((*rel).to_owned(), format!("const _P: () = {{ {body} }};"))
    });
    debt.chain(owners).chain(proofs).collect()
}

/// `tree` with `text` appended to the file at `rel`, which is added when absent.
fn appended(tree: &[(String, String)], rel: &str, text: &str) -> Vec<(String, String)> {
    let mut out = tree.to_vec();
    if !out.iter().any(|(path, _)| path.as_str() == rel) {
        out.push((rel.to_owned(), String::new()));
    }
    for (path, body) in &mut out {
        if path.as_str() == rel {
            body.push_str(text);
        }
    }
    out
}

#[test]
fn the_pinned_tree_matches_the_inventory() {
    assert!(
        BAN_PROOFS.iter().all(|(_, a, o, _)| a + o > 0),
        "a `BAN_PROOFS` row pins no naming"
    );
    let violations = inventory_violations(&pinned_tree());
    assert!(
        violations.is_empty(),
        "the control tree must be clean: {violations:#?}"
    );
}

#[test]
fn a_ban_proof_file_launders_no_read() {
    let tree = pinned_tree();
    let Some(&(proof, ..)) = BAN_PROOFS.first() else {
        return;
    };
    let db_lib = "src/compiler/db/src/lib.rs";
    let drifts = [
        (db_lib, "fn g() { std::env::args(); }"),
        (db_lib, "fn g() { std::env::args_os(); }"),
        (db_lib, ARGS_NAMING),
        (db_lib, ARGS_OS_NAMING),
        (proof, "fn g() { std::env::args(); }"),
        (proof, "fn g() { std::env::args_os(); }"),
        (proof, "const _Q: () = { let _ = ::std::env::args; };"),
        (proof, ARGS_NAMING),
        (proof, "fn g() { read!(); }"),
        (proof, "#[allow(dead_code)] fn g() {}"),
    ];
    for (rel, text) in drifts {
        assert!(
            !inventory_violations(&appended(&tree, rel, text)).is_empty(),
            "`{text}` in {rel} passed the inventory"
        );
    }
}

#[test]
fn a_ban_naming_is_seen_only_in_its_exact_shape() {
    let args = findings(ARGS_NAMING);
    assert_eq!((args.args_named, args.args), (1, 0));
    let args_os = findings(ARGS_OS_NAMING);
    assert_eq!((args_os.args_os_named, args_os.args_os), (1, 0));
    assert_eq!(args.rewriters + args_os.rewriters, 0);
    let reads = [
        "#[expect(clippy::disallowed_methods)] let _ = ::std::env::args();",
        "#[expect(clippy::disallowed_methods)] let r = ::std::env::args;",
        "#[expect(clippy::disallowed_types)] let _ = ::std::env::args;",
        "#[expect(clippy::disallowed_methods)] let _ = std::env::args;",
        "let _ = ::std::env::args;",
        "const R: fn() -> std::env::Args = ::std::env::args;",
    ];
    for src in reads {
        let found = findings(src);
        assert_eq!(
            (found.args, found.args_named),
            (1, 0),
            "a read passed as a ban naming: {src:?}"
        );
    }
    for src in [
        "m!(x);",
        "#[allow(dead_code)] fn f() {}",
        "#![allow(dead_code)]",
    ] {
        assert!(
            findings(src).rewriters > 0,
            "a possible rewriter went unseen: {src:?}"
        );
    }
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
