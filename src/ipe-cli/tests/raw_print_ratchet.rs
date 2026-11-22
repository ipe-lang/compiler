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
//!
//! Nor may a source file reach a std stream behind the terminal row: bytes go
//! through `progress::Door`, which clears and repaints a live stage around them.

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

/// Every `.rs` file under `root`, relative to `root` with `/` separators.
#[allow(clippy::expect_used)] // a tree the walker refuses leaves nothing the ratchet can certify
fn rust_files(root: &Path) -> Vec<(String, PathBuf)> {
    panic_scan::rust_sources(root, panic_scan::Want::RustFiles)
        .expect("the source tree is listed whole")
        .into_iter()
        .map(|path| {
            let rel = path
                .strip_prefix(root)
                .expect("a listed file lies under its root")
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            (rel, path)
        })
        .collect()
}

#[test]
fn no_source_file_prints_raw() {
    let src = e2e_support::manifest_dir!().join("src");
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

/// The std stream constructors a call, a path, or an import can name.
const STREAMS: &[&str] = &["stdout", "stderr"];

/// The files that own the terminal row: the door and the renderer behind it.
const ROW_OWNERS: &[&str] = &["progress.rs", "screen.rs"];

/// Every other file that names a std stream, with how many times.
///
/// Each admitted site is a terminal or palette probe, the writer a progress stage takes (which
/// registers on the row), a child's stdio, or a test child's report line; none writes bytes the
/// row does not see. A new site fails the scan until it routes through `progress::Door` or is
/// admitted here with that reason.
const ADMITTED: &[(&str, usize)] = &[
    ("cargo_step.rs", 2),
    ("doc.rs", 2),
    ("driver/commands.rs", 13),
    ("driver/commands_pkg.rs", 12),
    ("driver/driver_error.rs", 5),
    ("ffi.rs", 3),
    ("fmt.rs", 1),
    ("health.rs", 2),
    ("help.rs", 1),
    ("init.rs", 1),
    ("remote_ingest.rs", 2),
    ("ssh_signing_key.rs", 1),
    ("terminate.rs", 1),
    ("unsafe_ack.rs", 1),
    ("watch.rs", 2),
];

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The code of `text` with comment lines dropped and whitespace kept only between two words.
fn collapse(text: &str) -> String {
    let mut out = String::new();
    for token in text
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .flat_map(str::split_whitespace)
    {
        let between_words = out.chars().next_back().is_some_and(is_ident)
            && token.chars().next().is_some_and(is_ident);
        if between_words {
            out.push(' ');
        }
        out.push_str(token);
    }
    out
}

/// Each whole-word stream name in `code`, as the code before it and the code after it.
fn stream_names(code: &str) -> Vec<(&str, &str)> {
    STREAMS
        .iter()
        .flat_map(|name| {
            code.match_indices(name).filter_map(move |(at, _)| {
                let before = code.get(..at)?;
                let after = code.get(at..)?.strip_prefix(name)?;
                let whole = !before.chars().next_back().is_some_and(is_ident)
                    && !after.chars().next().is_some_and(is_ident);
                whole.then_some((before, after))
            })
        })
        .collect()
}

/// Count the std stream names `text` reaches.
///
/// A name counts as a path segment (`std::io::stderr`, `io::stdout`, an aliasing import), as a
/// bare call (`stderr()` after a glob import), or as a member of an import group
/// (`use std::io::{stdout as out}`); a method or field of the same name (`cmd.stdout(..)`,
/// `child.stderr`) does not.
fn count_stream_names(text: &str) -> usize {
    let code = collapse(text);
    let reached = stream_names(&code)
        .into_iter()
        .filter(|(before, after)| {
            before.ends_with("::") || (!before.ends_with('.') && after.starts_with('('))
        })
        .count();
    let grouped = code
        .match_indices("use ")
        .filter(|(at, _)| {
            code.get(..*at)
                .is_none_or(|before| !before.chars().next_back().is_some_and(is_ident))
        })
        .filter_map(|(at, _)| code.get(at..))
        .map(|from| from.split(';').next().unwrap_or(from))
        .map(|import| {
            stream_names(import)
                .into_iter()
                .filter(|(before, _)| !before.ends_with("::"))
                .count()
        })
        .sum::<usize>();
    reached.saturating_add(grouped)
}

#[test]
fn no_source_file_touches_a_std_stream_outside_the_door() {
    let src = e2e_support::manifest_dir!().join("src");
    let files = rust_files(&src);
    assert!(
        !files.is_empty(),
        "no sources found under {}",
        src.display()
    );

    let mut drift = Vec::new();
    let mut seen = Vec::new();
    for (rel, path) in &files {
        if ROW_OWNERS.contains(&rel.as_str()) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            drift.push(format!("{rel}: unreadable"));
            continue;
        };
        let count = count_stream_names(&text);
        let admitted = ADMITTED
            .iter()
            .find(|(file, _)| file == rel)
            .map_or(0, |(_, n)| *n);
        if count != admitted {
            drift.push(format!(
                "{rel}: {count} std stream sites, {admitted} admitted"
            ));
        }
        if count != 0 {
            seen.push(rel.clone());
        }
    }
    for (file, _) in ADMITTED {
        if !seen.iter().any(|rel| rel == file) {
            drift.push(format!("{file}: admitted but names no std stream"));
        }
    }
    assert!(
        drift.is_empty(),
        "a std stream outside the terminal door — write through `progress::Door`, or admit a \
         probe here with its reason:\n  {}",
        drift.join("\n  ")
    );
}

#[test]
fn the_stream_counter_follows_every_spelling_of_a_std_stream() {
    let reached = [
        "std::io::stderr().write_all(b\"x\");",
        "let e = io::stderr();",
        "use std::io::stdout as o;\no().flush();",
        "use std::io::{\n    stderr as e,\n    Write,\n};\ne().flush();",
        "use std::io::*;\nstderr().flush();",
        "let f = std::io::stderr;",
        "std :: io ::\n    stdout ()",
    ];
    for fixture in reached {
        assert_eq!(count_stream_names(fixture), 1, "{fixture}");
    }
    let inert = [
        "cmd.stdout(Stdio::piped());",
        "child.stderr.take();",
        "let stdout = x; ChildStdout;",
        "// std::io::stderr().write_all(x)",
        "my_stdout(); stderr_line();",
    ];
    for fixture in inert {
        assert_eq!(count_stream_names(fixture), 0, "{fixture}");
    }
}
