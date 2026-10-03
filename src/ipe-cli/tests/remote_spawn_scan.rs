#![forbid(unsafe_code)]
//! Refuses every remote transfer in the `ipe` crate that bypasses `remote_ingest`.
//!
//! `remote_ingest` is the one place a `git` or `curl` child is built: it
//! isolates the child from user and system configuration, bounds it by one
//! deadline per transfer, measures what it writes, and kills its whole process
//! group on refusal. An HTTP body read through `ureq` is bounded only by
//! `remote_ingest::read_capped`.
//!
//! Every `Command::new` under `src/` but `src/remote_ingest.rs` is held to
//! [`SPAWN_INVENTORY`]: the program expression of each site, per file, with its
//! exact count. A site the inventory does not list is refused whatever names
//! its program — a `"git"` literal, an absolute path, a constant, a variable, an
//! `OsStr` — so a new child process is admitted only by a reviewed inventory
//! edit. A `Command` alias, which would spawn under another spelling, is
//! refused outright, and a `Command::new` that is not called in place counts as
//! a site of its own. An unbounded `ureq` body read (`into_json`,
//! `into_string`, or an `into_reader` not handed straight to `read_capped`) is
//! refused too. Sources are compared with all whitespace removed, so line
//! breaks and spacing cannot split a match.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The one module allowed to build a `git` or `curl` child, relative to `src/`.
const SPAWN_OWNER: &str = "remote_ingest.rs";

/// The `Command` constructor every child process starts from, whitespace removed.
const SPAWN_CALL: &str = "Command::new";

/// The spelling that renames `Command`, so a spawn would escape [`SPAWN_CALL`].
const COMMAND_ALIAS: &str = "Commandas";

/// Every reviewed child-process site outside [`SPAWN_OWNER`]: the file relative
/// to `src/`, the whitespace-free program expression, and how often it occurs.
///
/// None runs `git`, `curl`, `ssh` or another remote-transfer tool. A literal
/// names a local tool; a variable names a program the CLI resolved itself (its
/// own binary, the toolchain's `cargo`, a wasm tool, the FFI inspector payload,
/// a `doctor` install `argv`, a platform opener). The `sh` site runs the
/// installer script `remote_ingest` already downloaded within its ceilings; the
/// `/bin/ps` site reads the CLI's own signal dispositions through
/// `remote_ingest::run_probe`. A mention of `Command::new` that is not called
/// in place is listed under the empty expression.
const SPAWN_INVENTORY: &[(&str, &str, usize)] = &[
    ("audit.rs", "\"cargo-deny\"", 2),
    ("audit_native.rs", "&cargo", 1),
    ("build_plan.rs", "\"rustup\"", 1),
    ("cache.rs", "\"mkfifo\"", 1),
    ("cache.rs", "\"rustc\"", 1),
    ("cargo_step.rs", "build.get_program()", 1),
    ("cargo_step.rs", "cargo", 1),
    ("cargo_step.rs", "cargo.path()", 1),
    ("coverage/probe.rs", "&ipe_bin", 1),
    ("doc.rs", "&ipe_bin", 1),
    ("doc.rs", "opener", 1),
    ("driver/commands.rs", "", 1),
    ("driver/commands.rs", "&bin", 4),
    ("driver/commands.rs", "tools.bindgen", 1),
    ("driver/commands.rs", "tools.opt", 1),
    ("driver/commands_pkg.rs", "\"sh\"", 1),
    ("driver/commands_pkg.rs", "&bin", 2),
    ("driver/commands_pkg.rs", "&exe", 1),
    ("driver/tests/mod.rs", "\"cargo\"", 1),
    ("driver/tests/mod.rs", "&bin", 1),
    ("ffi.rs", "program", 1),
    ("health.rs", "\"rustc\"", 2),
    ("health.rs", "program", 1),
    ("io_bounded.rs", "\"mkfifo\"", 1),
    ("login.rs", "\"cmd\"", 1),
    ("login.rs", "\"open\"", 1),
    ("login.rs", "\"xdg-open\"", 1),
    ("loose_file.rs", "\"mkfifo\"", 1),
    ("lsp.rs", "\"mkfifo\"", 1),
    ("output_dir.rs", "\"powershell\"", 1),
    ("output_dir.rs", "junction_helper()", 1),
    ("project.rs", "\"mkfifo\"", 2),
    ("publish.rs", "\"cmd\"", 1),
    ("publish.rs", "\"open\"", 1),
    ("publish.rs", "\"xdg-open\"", 1),
    ("secret_file/tests.rs", "\"mkfifo\"", 1),
    ("terminate.rs", "\"/bin/ps\"", 1),
    ("terminate.rs", "\"/bin/sh\"", 3),
    ("terminate.rs", "\"sleep\"", 2),
    ("toolchain.rs", "", 1),
    ("toolchain.rs", "\"cargo\"", 1),
    ("watch.rs", "OsStr::new(\"cargo\")", 3),
    ("watch.rs", "exe_path", 1),
];

/// Directory nesting the walk descends before refusing to go deeper.
const MAX_DEPTH: usize = 16;

/// Unbounded `ureq` body reads, whitespace removed.
const UNBOUNDED_BODY_READS: &[&str] = &[".into_json(", ".into_string()"];

/// The one bounded body read: a response reader handed straight to `read_capped`.
const READER: &str = ".into_reader()";

/// The only call an `into_reader` may appear as the first argument of.
const CAPPED_CALL: &str = "read_capped(";

/// The `ipe` crate's `src/` directory.
fn src_root() -> PathBuf {
    e2e_support::manifest_dir!().join("src")
}

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if depth > MAX_DEPTH {
        return Err(std::io::Error::other(format!(
            "source tree deeper than {MAX_DEPTH}: {}",
            dir.display()
        )));
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            rust_files(&path, depth + 1, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// `source` with every whitespace character removed.
fn flatten(source: &str) -> String {
    source.chars().filter(|c| !c.is_whitespace()).collect()
}

/// The first argument of a call whose argument list starts at `args`: the text
/// up to the first top-level `,` or the closer of the list, outside string
/// literals, or `None` when the list never closes.
fn first_argument(args: &str) -> Option<&str> {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for (at, c) in args.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '(' | '[' | '{' => depth = depth.checked_add(1)?,
            ')' | ']' | '}' => match depth.checked_sub(1) {
                Some(outer) => depth = outer,
                None => return args.get(..at),
            },
            ',' if depth == 0 => return args.get(..at),
            _ => {}
        }
    }
    None
}

/// The program expression of every [`SPAWN_CALL`] in one flattened source: the
/// call's first argument, the empty string for a mention not called in place,
/// or `None` for a call whose argument list never closes.
fn spawn_programs(flat: &str) -> Vec<Option<String>> {
    flat.match_indices(SPAWN_CALL)
        .map(|(at, _)| {
            let after = flat
                .get(at.saturating_add(SPAWN_CALL.len())..)
                .unwrap_or_default();
            after.strip_prefix('(').map_or_else(
                || Some(String::new()),
                |args| first_argument(args).map(str::to_owned),
            )
        })
        .collect()
}

/// The spawn sites of `files` (paths under `root`, sources flattened) that
/// differ from [`SPAWN_INVENTORY`], one line per drifted site.
fn inventory_drift(root: &Path, files: &[(PathBuf, String)]) -> Vec<String> {
    let mut found: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut drift = Vec::new();
    for (path, flat) in files {
        let Ok(rel) = path.strip_prefix(root) else {
            drift.push(format!("{}: outside the scanned root", path.display()));
            continue;
        };
        let rel = rel.to_string_lossy().replace('\\', "/");
        if rel == SPAWN_OWNER {
            continue;
        }
        for program in spawn_programs(flat) {
            match program {
                Some(program) => {
                    let seen = found.entry((rel.clone(), program)).or_default();
                    *seen = seen.saturating_add(1);
                }
                None => drift.push(format!("{rel}: an unclosed `{SPAWN_CALL}(` call")),
            }
        }
    }
    let expected: BTreeMap<(String, String), usize> = SPAWN_INVENTORY
        .iter()
        .map(|(file, program, count)| (((*file).to_owned(), (*program).to_owned()), *count))
        .collect();
    let keys: BTreeSet<&(String, String)> = found.keys().chain(expected.keys()).collect();
    for key in keys {
        let got = found.get(key).copied().unwrap_or(0);
        let want = expected.get(key).copied().unwrap_or(0);
        if got != want {
            drift.push(format!(
                "{}: `{SPAWN_CALL}({})` x{got} (inventory: {want})",
                key.0, key.1
            ));
        }
    }
    drift
}

/// Whether the `into_reader` ending at `before` is the first argument of `read_capped`.
fn reader_is_capped(before: &str) -> bool {
    let receiver = before.trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '_');
    receiver.len() < before.len() && receiver.ends_with(CAPPED_CALL)
}

/// Every refused spelling in one flattened source, apart from its spawn sites.
fn violations(flat: &str) -> Vec<String> {
    let mut found = Vec::new();
    if flat.contains(COMMAND_ALIAS) {
        found.push(COMMAND_ALIAS.to_owned());
    }
    if flat.contains("ureq") {
        found.extend(
            UNBOUNDED_BODY_READS
                .iter()
                .filter(|needle| flat.contains(*needle))
                .map(|needle| (*needle).to_owned()),
        );
    }
    found.extend(
        flat.match_indices(READER)
            .filter(|(at, _)| !flat.get(..*at).is_some_and(reader_is_capped))
            .map(|_| READER.to_owned()),
    );
    found
}

/// Flattened sources holding exactly the [`SPAWN_INVENTORY`] sites, under `root`,
/// for every file but `except`.
fn inventory_sources(root: &Path, except: &str) -> Vec<(PathBuf, String)> {
    SPAWN_INVENTORY
        .iter()
        .filter(|(file, _, _)| *file != except)
        .map(|(file, program, count)| {
            let site = if program.is_empty() {
                "`Command::new`".to_owned()
            } else {
                format!("Command::new({program});")
            };
            (root.join(file), flatten(&site.repeat(*count)))
        })
        .collect()
}

#[test]
fn no_remote_transfer_bypasses_remote_ingest() {
    let root = src_root();
    let mut paths = Vec::new();
    rust_files(&root, 0, &mut paths).expect("source tree walkable");
    let owner = root.join(SPAWN_OWNER);
    assert!(
        paths.contains(&owner),
        "the scan must see src/{SPAWN_OWNER}, or it is scanning the wrong tree"
    );
    let files: Vec<(PathBuf, String)> = paths
        .into_iter()
        .map(|path| {
            let source = std::fs::read_to_string(&path).expect("source readable");
            let flat = flatten(&source);
            (path, flat)
        })
        .collect();
    let mut offenders = inventory_drift(&root, &files);
    offenders.extend(
        files
            .iter()
            .filter(|(path, _)| *path != owner)
            .flat_map(|(path, flat)| {
                violations(flat)
                    .into_iter()
                    .map(move |needle| format!("{}: {needle}", path.display()))
            }),
    );
    assert!(
        offenders.is_empty(),
        "remote transfers must go through remote_ingest (Git / Curl / read_capped), and every \
         other child process must match SPAWN_INVENTORY:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_inventory_admits_exactly_its_listed_sites() {
    let root = PathBuf::from("src");
    let mut files = inventory_sources(&root, "");
    files.push((
        root.join(SPAWN_OWNER),
        flatten("Command::new(\"git\"); Command::new(\"curl\");"),
    ));
    let drift = inventory_drift(&root, &files);
    assert!(drift.is_empty(), "{}", drift.join("\n"));
}

#[test]
fn the_inventory_refuses_each_unlisted_spawn() {
    let root = PathBuf::from("src");
    let refused = [
        ("ffi.rs", "Command::new(program); Command::new(\"git\");"),
        (
            "ffi.rs",
            "Command::new(program); Command::new(\"/usr/bin/git\");",
        ),
        ("ffi.rs", "Command::new(program); Command::new(GIT);"),
        (
            "ffi.rs",
            "Command::new(program); Command::new(OsStr::new(\"curl\"));",
        ),
        ("ffi.rs", "Command::new(program); Command::new(\"ssh\");"),
        ("ffi.rs", "Command::new(program); Command::new(r\"git\");"),
        ("ffi.rs", "Command::new(program); Command::new(program);"),
        ("ffi.rs", "Command::new(program); let spawn = Command::new;"),
        ("ffi.rs", "Command::new(program); Command::new(\"git\""),
        ("ffi.rs", ""),
        ("new_module.rs", "Command::new(\"rustc\");"),
        ("sub/remote_ingest.rs", "Command::new(\"git\");"),
    ];
    for (rel, sample) in refused {
        let mut files = inventory_sources(&root, rel);
        files.push((root.join(rel), flatten(sample)));
        assert!(
            !inventory_drift(&root, &files).is_empty(),
            "the inventory must refuse in {rel}: {sample}"
        );
    }
}

#[test]
fn matcher_refuses_each_bypass() {
    let refused = [
        "use std::process::Command as Spawn;",
        "use std::process::{Command as Spawn, Stdio};",
        "use ureq; let v: Value = resp.into_json()?;",
        "use ureq; let s = resp.into_string()?;",
        "let r = resp.into_reader();",
        "read_capped(std::io::empty()).and(resp.into_reader())",
        "read_capped(\n  (resp).into_reader(), 4)",
    ];
    for sample in refused {
        assert!(
            !violations(&flatten(sample)).is_empty(),
            "matcher must refuse: {sample}"
        );
    }
}

#[test]
fn matcher_admits_the_bounded_forms() {
    let admitted = [
        "remote_ingest::read_capped(\n    response.into_reader(),\n    MAX,\n)",
        "Git::isolated(dir).args([\"fetch\"])",
        "use std::process::Command;",
        "let s = value.into_string();",
    ];
    for sample in admitted {
        assert!(
            violations(&flatten(sample)).is_empty(),
            "matcher must admit: {sample}"
        );
    }
}
