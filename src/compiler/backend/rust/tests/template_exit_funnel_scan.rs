//! Every emitted process ends through `ipe_runtime::system::exit_process`.
//!
//! The runtime's clippy ban on `std::process::exit` does not reach emitted
//! code, and `process::exit` skips Drop, so an emitted path that ends the
//! process itself skips the exit hook (terminal restore) and the bounded
//! exporter flush the funnel runs. This scan lexes every Rust file under
//! `templates/` and refuses each token that names a process-ending act other
//! than the funnel; every other template file is refused on the raw call's
//! text. A site admitted past the scan is listed in [`ADMITTED`] by
//! `(file, token, count)`; an entry whose count no longer matches is drift
//! and fails too.

use std::collections::BTreeMap;
use std::path::Path;

use proc_macro2::{TokenStream, TokenTree};

/// The identifiers that name a process end outside the funnel: the std
/// `process` module (`exit`, `abort`, an alias of it), the C entry points,
/// and a bare `exit`/`abort` brought in by a `use`.
const REFUSED_IDENTS: &[&str] = &["process", "libc", "exit", "_exit", "abort", "exit_group"];

/// The raw call refused in a template file that is not Rust source.
const REFUSED_TEXT: &str = "process::exit";

/// Template sites admitted past the scan, as `(file, token, count)`.
const ADMITTED: &[(&str, &str, usize)] = &[];

/// How deep the template tree may nest before the walk refuses it.
const MAX_DEPTH: usize = 8;

/// One refused site: the template file and the token it holds.
type Site = (String, String);

/// The refused tokens of one Rust source, counted per identifier.
fn scan_rust(file: &str, src: &str, hits: &mut BTreeMap<Site, usize>) -> Result<(), String> {
    let stream: TokenStream = src
        .parse()
        .map_err(|e| format!("{file} does not lex: {e}"))?;
    let mut pending = vec![stream];
    while let Some(stream) = pending.pop() {
        for tok in stream {
            match tok {
                TokenTree::Group(g) => pending.push(g.stream()),
                TokenTree::Ident(id) => {
                    let name = id.to_string();
                    if REFUSED_IDENTS.contains(&name.as_str()) {
                        *hits.entry((file.to_owned(), name)).or_insert(0) += 1;
                    }
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }
    Ok(())
}

/// The number of `exit_process` identifiers in one Rust source.
fn funnel_calls(src: &str) -> Result<usize, String> {
    let stream: TokenStream = src.parse().map_err(|e| format!("does not lex: {e}"))?;
    let mut count = 0;
    let mut pending = vec![stream];
    while let Some(stream) = pending.pop() {
        for tok in stream {
            match tok {
                TokenTree::Group(g) => pending.push(g.stream()),
                TokenTree::Ident(id) if id == "exit_process" => count += 1,
                TokenTree::Ident(_) | TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }
    Ok(count)
}

/// Scan every file under `dir`, naming each by its `/`-joined path relative to
/// `root`. A symlink or any entry that is neither a file nor a directory is
/// refused, so the scan never reads a file outside the template tree.
fn scan_dir(
    root: &Path,
    dir: &Path,
    depth: usize,
    hits: &mut BTreeMap<Site, usize>,
) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("{} nests past {MAX_DEPTH} levels", dir.display()));
    }
    let mut entries = BTreeMap::new();
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let kind = entry
            .file_type()
            .map_err(|e| format!("{}: {e}", entry.path().display()))?;
        entries.insert(entry.path(), kind);
    }
    for (path, kind) in entries {
        if kind.is_dir() {
            scan_dir(root, &path, depth + 1, hits)?;
        } else if kind.is_file() {
            scan_file(root, &path, hits)?;
        } else {
            return Err(format!(
                "{} is neither a file nor a directory",
                path.display()
            ));
        }
    }
    Ok(())
}

/// Scan one template file: a Rust source by its tokens, any other file by the
/// raw call's text.
fn scan_file(root: &Path, path: &Path, hits: &mut BTreeMap<Site, usize>) -> Result<(), String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/");
    let src = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if path.extension().is_some_and(|e| e == "rs") {
        return scan_rust(&rel, &src, hits);
    }
    let count = src.matches(REFUSED_TEXT).count();
    if count > 0 {
        hits.insert((rel, REFUSED_TEXT.to_owned()), count);
    }
    Ok(())
}

/// No template ends the process outside the funnel, and an admitted entry gone
/// stale fails too.
#[test]
fn templates_end_the_process_only_through_the_runtime_exit_funnel() -> Result<(), String> {
    let root = e2e_support::manifest_dir!().join("templates");
    let mut found = BTreeMap::new();
    scan_dir(&root, &root, 0, &mut found)?;
    let admitted: BTreeMap<Site, usize> = ADMITTED
        .iter()
        .map(|&(file, token, count)| ((file.to_owned(), token.to_owned()), count))
        .collect();
    let unexpected: Vec<_> = found
        .iter()
        .filter(|(site, count)| admitted.get(*site) != Some(*count))
        .collect();
    let stale: Vec<_> = admitted
        .iter()
        .filter(|(site, count)| found.get(*site) != Some(*count))
        .collect();
    assert!(
        unexpected.is_empty() && stale.is_empty(),
        "an emitted process ends only through `ipe_runtime::system::exit_process`.\n\
         unexpected (site, count): {unexpected:?}\nstale admitted entries (site, count): \
         {stale:?}"
    );
    Ok(())
}

/// The entry point reaches the funnel on both `fn main` outcomes, so a tail
/// that returns without it (and skips the flush) is refused too.
#[test]
fn the_entry_point_calls_the_funnel_on_both_outcomes() -> Result<(), String> {
    let main = e2e_support::manifest_dir!().join("templates/main.rs");
    let src = std::fs::read_to_string(&main).map_err(|e| format!("{}: {e}", main.display()))?;
    assert_eq!(
        funnel_calls(&src)?,
        2,
        "`fn main` calls `exit_process` on Ok and on Err"
    );
    Ok(())
}

/// The refused tokens of a synthetic source.
fn synthetic(src: &str) -> Result<Vec<String>, String> {
    let mut hits = BTreeMap::new();
    scan_rust("synthetic.rs", src, &mut hits)?;
    Ok(hits.into_keys().map(|(_, token)| token).collect())
}

/// Each spelling of a process end outside the funnel goes red; the funnel
/// itself does not.
#[test]
fn each_spelling_of_a_raw_process_end_is_refused() -> Result<(), String> {
    let cases: [(&str, &[&str]); 6] = [
        ("fn main() { std::process::exit(1); }", &["exit", "process"]),
        (
            "use std::process as p;\nfn main() { p::exit(0); }",
            &["exit", "process"],
        ),
        (
            "use std::process::exit as quit;\nfn main() { quit(0); }",
            &["exit", "process"],
        ),
        (
            "fn main() { std::process::abort(); }",
            &["abort", "process"],
        ),
        ("fn main() { libc::_exit(1); }", &["_exit", "libc"]),
        (
            "fn main() { rustix::runtime::exit_group(1); }",
            &["exit_group"],
        ),
    ];
    for (src, want) in cases {
        assert_eq!(synthetic(src)?, want.to_vec(), "{src}");
    }
    assert!(
        synthetic("fn main() { ipe_runtime::system::exit_process(1) }")?.is_empty(),
        "the funnel call is admitted"
    );
    Ok(())
}
