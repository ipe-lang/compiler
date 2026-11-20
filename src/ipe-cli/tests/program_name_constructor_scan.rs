#![forbid(unsafe_code)]
//! Pins that a program name is built only by its parser.
//!
//! `ProgramName` holds only a name the shared name grammar accepts. Its field
//! is private, so outside `src/program_name.rs` the compiler already refuses
//! the tuple constructor; this scan is the second, independent gate. It lexes
//! every `.rs` file under `src/` and refuses the token pair `ProgramName (`
//! anywhere but `src/program_name.rs`, so a value cannot be minted from an
//! unparsed `String` even by code moved into that module's scope.

use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use proc_macro2::{Delimiter, TokenStream, TokenTree};

/// The type whose tuple constructor is confined.
const TYPE: &str = "ProgramName";

/// The one file allowed to call the constructor, relative to `src/`.
const OWNER: &str = "program_name.rs";

/// The deepest directory level below `src/` the walk descends.
const MAX_DEPTH: usize = 32;

/// Every `.rs` file under `dir`, at most [`MAX_DEPTH`] levels below it.
#[allow(clippy::expect_used)] // test helper: an unreadable source tree IS the failure
fn rust_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    assert!(depth <= MAX_DEPTH, "{} is nested too deep", dir.display());
    let entries = std::fs::read_dir(dir).expect("read a source directory");
    for entry in entries {
        let entry = entry.expect("read a directory entry");
        let path = entry.path();
        let kind = entry.file_type().expect("read an entry's type");
        if kind.is_dir() {
            rust_files(&path, depth + 1, out);
        } else if kind.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// How many times `tokens` holds `ProgramName` followed by a parenthesised group.
fn constructor_calls(tokens: TokenStream) -> usize {
    let mut count = 0;
    let mut previous_is_type = false;
    for tree in tokens {
        if let TokenTree::Group(group) = &tree {
            if previous_is_type && group.delimiter() == Delimiter::Parenthesis {
                count += 1;
            }
            count += constructor_calls(group.stream());
        }
        previous_is_type = matches!(&tree, TokenTree::Ident(ident) if ident == TYPE);
    }
    count
}

#[test]
fn program_name_is_built_only_by_its_parser() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, 0, &mut files);
    let owner = src.join(OWNER);
    assert!(files.contains(&owner), "{OWNER} defines the type");
    let mut offenders = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read a source file");
        let tokens = TokenStream::from_str(&text).expect("a source file lexes");
        let calls = constructor_calls(tokens);
        if file == &owner {
            assert!(calls > 0, "the scan sees the definition in {OWNER}");
        } else if calls > 0 {
            offenders.push(file.display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "`{TYPE}(` outside src/{OWNER}: {offenders:?}"
    );
}

#[test]
fn the_scan_sees_a_constructor_call() {
    let built = TokenStream::from_str("fn f() -> ProgramName { ProgramName(String::new()) }")
        .expect("lexes");
    assert_eq!(constructor_calls(built), 1);
    let parsed = TokenStream::from_str("fn f() { ProgramName::parse(\"a\"); }").expect("lexes");
    assert_eq!(constructor_calls(parsed), 0);
}
