#![forbid(unsafe_code)]
//! Refuses every `cargo` child in the `ipe` crate built outside `cargo_step`.
//!
//! `cargo_step` is the one module that builds a `cargo build` child: its
//! program, subcommand, profile, target, output mode, environment, lockfile
//! policy, crate proof, pipe drains and reap are decided there once, from typed
//! values.
//!
//! Every `Command::new` under `src/` but `src/cargo_step.rs` whose program
//! expression names cargo (any case, so a `"cargo"` literal, a path ending in
//! `cargo`, a `CARGO` constant, a `cargo_bin` variable) or reuses another
//! command's program (`get_program`) is held to [`CARGO_INVENTORY`]: per file,
//! the program expression, the first literal argument its call chain passes
//! (the subcommand), and the exact count. A new cargo site, a listed site
//! gaining a `build` subcommand, and a site moved to another file are refused.
//! A `Command::new` whose program expression names neither is held by
//! `child_runner_scan`'s per-site runner proof instead. The subcommand is
//! read only from the call chain of the `Command::new` statement itself, so an
//! argument added in a later statement is not seen. Sources are compared with
//! all whitespace removed, so line breaks and spacing cannot split a match.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The one module allowed to build a `cargo build` child, relative to `src/`.
const CARGO_OWNER: &str = "cargo_step.rs";

/// The `Command` constructor every child process starts from, whitespace removed.
const SPAWN_CALL: &str = "Command::new";

/// Every reviewed cargo site outside [`CARGO_OWNER`]: the file relative to
/// `src/`, the whitespace-free program expression, the first subcommand of its
/// call chain (empty when the chain passes none), and how often it occurs.
///
/// None is a production `cargo build`. `cargo-deny` runs the dependency
/// audit, the `build` site is the `cfg(test)` driver harness compiling a
/// fixture crate, and the rest are environment-mapping test commands and a doc
/// comment that never spawn.
const CARGO_INVENTORY: &[(&str, &str, &str, usize)] = &[
    ("audit.rs", "cargo_deny", "", 2),
    ("driver/tests/mod.rs", "\"cargo\"", "build", 1),
    ("toolchain.rs", "\"cargo\"", "", 1),
    ("watch.rs", "OsStr::new(\"cargo\")", "", 3),
];

/// Directory nesting the walk descends before refusing to go deeper.
const MAX_DEPTH: usize = 16;

/// One cargo site: file, program expression, first subcommand.
type Site = (String, String, String);

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

/// The byte offset in `text` of the first top-level `stop` character outside
/// string literals, or of the closer that ends the enclosing list; `None` when
/// neither occurs.
fn top_level_end(text: &str, stop: char) -> Option<usize> {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for (at, c) in text.char_indices() {
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
                None => return Some(at),
            },
            _ if c == stop && depth == 0 => return Some(at),
            _ => {}
        }
    }
    None
}

/// Whether a program expression names cargo or reuses another command's program.
fn is_cargo_program(program: &str) -> bool {
    program.to_ascii_lowercase().contains("cargo") || program.contains("get_program")
}

/// The first string-literal subcommand `.arg(..)` or `.args([..])` passes in
/// `chain`, raw strings included, or the empty string when there is none.
fn first_subcommand(chain: &str) -> String {
    let opener = [".arg(", ".args(["]
        .iter()
        .filter_map(|call| chain.find(*call).map(|at| at.saturating_add(call.len())))
        .min();
    let Some(literal) = opener.and_then(|at| chain.get(at..)) else {
        return String::new();
    };
    let unraw = literal
        .strip_prefix('r')
        .map_or(literal, |raw| raw.trim_start_matches('#'));
    unraw
        .strip_prefix('"')
        .and_then(|body| body.split('"').next())
        .unwrap_or_default()
        .to_owned()
}

/// Every cargo site in one flattened source: its program expression and first
/// subcommand, or `None` for a call whose argument list never closes.
fn cargo_sites(flat: &str) -> Vec<Option<(String, String)>> {
    flat.match_indices(SPAWN_CALL)
        .filter_map(|(at, _)| {
            let after = flat
                .get(at.saturating_add(SPAWN_CALL.len())..)
                .unwrap_or_default();
            let args = after.strip_prefix('(')?;
            // `)` is a closer, so the stop never fires before the list ends.
            let Some(close) = top_level_end(args, ')') else {
                return Some(None);
            };
            let program = args
                .get(..top_level_end(args, ',').unwrap_or(close))
                .unwrap_or_default();
            if !is_cargo_program(program) {
                return None;
            }
            let rest = args.get(close.saturating_add(1)..).unwrap_or_default();
            let chain = top_level_end(rest, ';')
                .and_then(|end| rest.get(..end))
                .unwrap_or(rest);
            Some(Some((program.to_owned(), first_subcommand(chain))))
        })
        .collect()
}

/// The cargo sites of `files` (paths under `root`, sources flattened) that
/// differ from [`CARGO_INVENTORY`], one line per drifted site.
fn inventory_drift(root: &Path, files: &[(PathBuf, String)]) -> Vec<String> {
    let mut found: BTreeMap<Site, usize> = BTreeMap::new();
    let mut drift = Vec::new();
    for (path, flat) in files {
        let Ok(rel) = path.strip_prefix(root) else {
            drift.push(format!("{}: outside the scanned root", path.display()));
            continue;
        };
        let rel = rel.to_string_lossy().replace('\\', "/");
        if rel == CARGO_OWNER {
            continue;
        }
        for site in cargo_sites(flat) {
            match site {
                Some((program, subcommand)) => {
                    let seen = found.entry((rel.clone(), program, subcommand)).or_default();
                    *seen = seen.saturating_add(1);
                }
                None => drift.push(format!("{rel}: an unclosed `{SPAWN_CALL}(` call")),
            }
        }
    }
    let expected: BTreeMap<Site, usize> = CARGO_INVENTORY
        .iter()
        .map(|(file, program, subcommand, count)| {
            (
                (
                    (*file).to_owned(),
                    (*program).to_owned(),
                    (*subcommand).to_owned(),
                ),
                *count,
            )
        })
        .collect();
    let keys: BTreeSet<&Site> = found.keys().chain(expected.keys()).collect();
    for key in keys {
        let got = found.get(key).copied().unwrap_or(0);
        let want = expected.get(key).copied().unwrap_or(0);
        if got != want {
            drift.push(format!(
                "{}: `{SPAWN_CALL}({})` subcommand `{}` x{got} (inventory: {want})",
                key.0, key.1, key.2
            ));
        }
    }
    drift
}

/// The listed sites of `file`, as source.
fn listed_sites(file: &str) -> String {
    CARGO_INVENTORY
        .iter()
        .filter(|(listed, _, _, _)| *listed == file)
        .map(|(_, program, subcommand, count)| {
            let site = if subcommand.is_empty() {
                format!("Command::new({program});")
            } else {
                format!("Command::new({program}).arg(\"{subcommand}\");")
            };
            site.repeat(*count)
        })
        .collect()
}

/// Flattened sources holding exactly the [`CARGO_INVENTORY`] sites, under
/// `root`, for every file but `except`.
fn inventory_sources(root: &Path, except: &str) -> Vec<(PathBuf, String)> {
    let files: BTreeSet<&str> = CARGO_INVENTORY
        .iter()
        .map(|(file, _, _, _)| *file)
        .collect();
    files
        .into_iter()
        .filter(|file| *file != except)
        .map(|file| (root.join(file), flatten(&listed_sites(file))))
        .collect()
}

/// The inventory's sources with `sample` appended to `rel`'s listed sites.
fn planted(root: &Path, rel: &str, sample: &str) -> Vec<(PathBuf, String)> {
    let mut files = inventory_sources(root, rel);
    files.push((
        root.join(rel),
        flatten(&format!("{}{sample}", listed_sites(rel))),
    ));
    files
}

#[test]
fn every_cargo_child_outside_cargo_step_is_inventoried() {
    let root = src_root();
    let mut paths = Vec::new();
    rust_files(&root, 0, &mut paths).expect("source tree walkable");
    assert!(
        paths.contains(&root.join(CARGO_OWNER)),
        "the scan must see src/{CARGO_OWNER}, or it is scanning the wrong tree"
    );
    let files: Vec<(PathBuf, String)> = paths
        .into_iter()
        .map(|path| {
            let source = std::fs::read_to_string(&path).expect("source readable");
            let flat = flatten(&source);
            (path, flat)
        })
        .collect();
    let drift = inventory_drift(&root, &files);
    assert!(
        drift.is_empty(),
        "every `cargo build` goes through cargo_step::CargoBuild or WatchBuild, and every other \
         cargo child must match CARGO_INVENTORY:\n{}",
        drift.join("\n")
    );
}

#[test]
fn the_inventory_admits_exactly_its_listed_sites() {
    let root = PathBuf::from("src");
    let mut files = inventory_sources(&root, "");
    files.push((
        root.join(CARGO_OWNER),
        flatten("Command::new(cargo).arg(\"build\"); Command::new(build.get_program());"),
    ));
    let drift = inventory_drift(&root, &files);
    assert!(drift.is_empty(), "{}", drift.join("\n"));
}

#[test]
fn a_cargo_build_outside_cargo_step_is_refused() {
    let root = PathBuf::from("src");
    let refused = [
        (
            "driver/commands.rs",
            "let mut c = Command::new(cargo_bin.path()); c.arg(\"build\");",
        ),
        (
            "driver/commands.rs",
            "Command::new(cargo_bin.path()).arg(\"build\").current_dir(dir);",
        ),
        (
            "driver/commands.rs",
            "std::process::Command::new(\"/usr/bin/cargo\").args([\"build\", \"-q\"]);",
        ),
        (
            "driver/commands.rs",
            "Command::new(CARGO_BIN).arg(\"build\");",
        ),
        (
            "driver/commands.rs",
            "Command::new(build_cmd.get_program()).arg(\"build\");",
        ),
        (
            "driver/commands.rs",
            "Command::new(r\"cargo\").arg(r\"build\");",
        ),
        (
            "driver/commands.rs",
            "Command::new(OsStr::new(\"Cargo\")).arg(\"build\");",
        ),
        (
            "driver/commands.rs",
            "Command::new(cargo_bin.path()).arg(\"build\"",
        ),
        ("watch.rs", "Command::new(cargo_path).arg(\"build\");"),
        ("new_module.rs", "Command::new(\"cargo\").arg(\"build\");"),
        ("sub/cargo_step.rs", "Command::new(cargo).arg(\"build\");"),
    ];
    for (rel, sample) in refused {
        let files = planted(&root, rel, sample);
        assert!(
            !inventory_drift(&root, &files).is_empty(),
            "the inventory must refuse in {rel}: {sample}"
        );
    }
}

#[test]
fn a_listed_site_gaining_a_build_subcommand_is_refused() {
    let root = PathBuf::from("src");
    let reshaped = [
        (
            "driver/commands.rs",
            "Command::new(\"cargo\").arg(\"build\");",
        ),
        (
            "watch.rs",
            "Command::new(OsStr::new(\"cargo\")).arg(\"build\"); \
             Command::new(OsStr::new(\"cargo\")); Command::new(OsStr::new(\"cargo\"));",
        ),
        (
            "audit_native.rs",
            "Command::new(&cargo).args([\"build\", \"--offline\"]);",
        ),
    ];
    for (rel, sample) in reshaped {
        let mut files = inventory_sources(&root, rel);
        files.push((root.join(rel), flatten(sample)));
        assert!(
            !inventory_drift(&root, &files).is_empty(),
            "the inventory must refuse in {rel}: {sample}"
        );
    }
}

#[test]
fn a_program_not_naming_cargo_is_left_to_the_spawn_inventory() {
    let flat = flatten("Command::new(\"rustc\").arg(\"build\"); Command::new(tools.opt);");
    assert!(cargo_sites(&flat).is_empty());
}
