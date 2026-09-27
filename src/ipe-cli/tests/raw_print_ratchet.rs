#![forbid(unsafe_code)]
//! No raw terminal printing in the `ipe` CLI.
//!
//! Human output goes through the one renderer (`ipe::screen`): a framed,
//! guttered, toned screen. Machine output goes through
//! `ipe::screen::emit_machine`. A raw `print!` / `println!` / `eprint!` /
//! `eprintln!` bypasses both, so its output escapes the frame (no header, no
//! gutter, no tone, no sanitising, no bug footer).
//!
//! No source file may print raw: a raw print fails the test, and the fix is to
//! route it through `ipe::screen`.

use std::path::{Path, PathBuf};

/// The raw print macros the check counts.
const MACROS: &[&str] = &["print!(", "println!(", "eprint!(", "eprintln!("];

/// Count the raw print macro invocations in `text`.
///
/// An occurrence counts only when it is not the tail of a longer identifier (`eprint!(` is not a
/// `print!(`).
fn count_raw_prints(text: &str) -> usize {
    MACROS
        .iter()
        .map(|mac| {
            text.match_indices(mac)
                .filter(|(at, _)| {
                    text.get(..*at)
                        .and_then(|before| before.chars().next_back())
                        .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
                })
                .count()
        })
        .sum()
}

/// Every `.rs` file under `dir`, recursively, relative to `root` with `/`
/// separators.
fn rust_files(root: &Path) -> Vec<(String, PathBuf)> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && let Ok(rel) = path.strip_prefix(root)
            {
                let rel = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                found.push((rel, path));
            }
        }
    }
    found.sort();
    found
}

#[test]
fn no_source_file_prints_raw() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = rust_files(&src);
    assert!(
        !files.is_empty(),
        "no sources found under {}",
        src.display()
    );

    let mut raw = Vec::new();
    for (rel, path) in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            raw.push(format!("{rel}: unreadable"));
            continue;
        };
        let count = count_raw_prints(&text);
        if count != 0 {
            raw.push(format!("{rel}: {count} raw prints"));
        }
    }
    assert!(
        raw.is_empty(),
        "raw terminal printing — route this output through `ipe::screen`:\n  {}",
        raw.join("\n  ")
    );
}

#[test]
fn the_counter_ignores_longer_macro_names() {
    assert_eq!(count_raw_prints("eprintln!(x); println!(y);"), 2);
    assert_eq!(count_raw_prints("eprint!(a) print!(b)"), 2);
    assert_eq!(count_raw_prints("my_println!(z)"), 0);
    assert_eq!(count_raw_prints("write!(out, x)"), 0);
}
