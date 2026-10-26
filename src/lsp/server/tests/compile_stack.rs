#![forbid(unsafe_code)]
//! Every thread the language server spawns outside its tests runs on the
//! declared compile stack, the one the at-ceiling shapes are proven on.

use std::path::{Path, PathBuf};

/// The token a spawn site's builder chain must name.
const STACK_CONSTANT: &str = "COMPILE_STACK_BYTES";

/// The token that opens a spawn site.
const BUILDER: &str = "thread::Builder::new()";

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The part of `text` before its `#[cfg(test)]` module.
fn production_part(text: &str) -> &str {
    text.find("\n#[cfg(test)]\nmod ")
        .and_then(|at| text.get(..at))
        .unwrap_or(text)
}

/// The builder chain of each spawn site in `text`, from the builder to its
/// `.spawn(`.
fn spawn_chains(text: &str) -> Vec<&str> {
    let mut chains = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(BUILDER) {
        let Some(site) = rest.get(at..) else {
            break;
        };
        let end = site.find(".spawn(").unwrap_or(site.len());
        chains.push(site.get(..end).unwrap_or(site));
        rest = site.get(BUILDER.len()..).unwrap_or("");
    }
    chains
}

/// Every production `thread::Builder` under `src/lsp` sets its stack to
/// [`STACK_CONSTANT`].
#[test]
fn diagnostics_worker_runs_on_the_compile_stack() {
    let lsp = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for crate_dir in std::fs::read_dir(&lsp).into_iter().flatten().flatten() {
        rust_files(&crate_dir.path().join("src"), &mut files);
    }
    assert!(!files.is_empty(), "the scan finds the server sources");
    let mut sites = 0_usize;
    for file in &files {
        let read = std::fs::read_to_string(file);
        assert!(read.is_ok(), "{} must be readable", file.display());
        let Ok(text) = read else {
            continue;
        };
        for chain in spawn_chains(production_part(&text)) {
            sites += 1;
            assert!(
                chain.contains(STACK_CONSTANT),
                "{}: a spawned thread must run on `{STACK_CONSTANT}`: {chain}",
                file.display()
            );
        }
    }
    assert!(
        sites > 0,
        "the scan finds the diagnostics worker's spawn site"
    );
}
