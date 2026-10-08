//! The wildcard's spelling `any` is read in exactly one place.
//!
//! Canon's `is_wildcard_spelling` turns an unbound `any` into
//! `Type::Wildcard`; every later stage matches the variant, never the name. A
//! stage that compares a symbol's spelling against `any` again would treat a
//! declared parameter spelled `any` as the wildcard, so this scan refuses any
//! such comparison in production source.

use std::path::{Path, PathBuf};

/// Production source roots scanned, relative to this crate's manifest.
const ROOTS: &[&str] = &[
    "../types/src",
    "../canon/src",
    "../lower/src",
    "../ir/src",
    "../backend",
    "../kernels/src",
    "../ffi/src",
    "../db/src",
    "../../lsp",
];

/// Lines that legitimately compare against the spelling, by exact trimmed text.
///
/// The three callee tuples resolve the kernel functions named `any`
/// (`String.any`, `List.any`, `Server.any`) — a value name, not a type
/// variable. The fourth is the one read of the type wildcard's spelling.
const ALLOWED: &[&str] = &[
    r#"("String", "any") => Ok(Callee::Kernel(KernelFn::StringAny)),"#,
    r#"("List", "any") => Ok(Callee::Kernel(KernelFn::ListAny)),"#,
    r#"("Server", "any") => Ok(Callee::Kernel(KernelFn::ServerAny)),"#,
    "interner.resolve(v) == Some(canon::WILDCARD_SPELLING)",
];

/// Whether `line` compares, matches, or interns the wildcard's spelling.
fn reads_spelling(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return false;
    }
    ["\"any\"", "WILDCARD_SPELLING"].iter().any(|needle| {
        line.find(needle).is_some_and(|at| {
            let compares = line.contains("==")
                || line.contains("!=")
                || line.contains("intern")
                || line.contains("matches!")
                || line.contains(".eq(")
                || line.contains(&format!("Some({needle})"));
            // A needle before `=>` is a match-arm pattern on the spelling.
            let is_pattern = line.find("=>").is_some_and(|arrow| at < arrow);
            compares || is_pattern
        })
    })
}

/// Every `.rs` file under `dir`, skipping test-only directories and files.
fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name != "tests" && name != "target" {
                rust_sources(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") && name != "tests.rs" {
            out.push(path);
        }
    }
}

/// The production lines of `text`, with every `#[cfg(test)]` module dropped.
///
/// A test module is the `mod name {` item after `#[cfg(test)]`, closed by the
/// `}` at its own indentation (the formatter's layout).
fn production_lines(text: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut pending_cfg_test = false;
    let mut skip_until: Option<String> = None;
    for (n, line) in text.lines().enumerate() {
        if let Some(close) = skip_until.as_deref() {
            if line == close {
                skip_until = None;
            }
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(test)]") {
            pending_cfg_test = true;
            continue;
        }
        if pending_cfg_test && !trimmed.starts_with("#[") {
            pending_cfg_test = false;
            if trimmed.starts_with("mod ") && trimmed.ends_with('{') {
                let indent = line.len().saturating_sub(trimmed.len());
                skip_until = Some(format!("{}}}", " ".repeat(indent)));
                continue;
            }
        }
        out.push((n.saturating_add(1), line));
    }
    out
}

#[test]
fn wildcard_spelling_is_read_once() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for root in ROOTS {
        let dir = manifest.join(root);
        assert!(dir.is_dir(), "scan root `{root}` must exist");
        rust_sources(&dir, &mut files);
    }
    let mut offending = Vec::new();
    let mut seen_allowed = vec![false; ALLOWED.len()];
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read a scanned source");
        for (n, line) in production_lines(&text) {
            if !reads_spelling(line) {
                continue;
            }
            match ALLOWED.iter().position(|a| *a == line.trim()) {
                Some(k) => {
                    if let Some(seen) = seen_allowed.get_mut(k) {
                        *seen = true;
                    }
                }
                None => offending.push(format!("{}:{n}: {}", file.display(), line.trim())),
            }
        }
    }
    assert!(
        offending.is_empty(),
        "the wildcard spelling `any` is read only by canon's `is_wildcard_spelling`; \
         match `Type::Wildcard` / `Ty::Wildcard` instead:\n{}",
        offending.join("\n")
    );
    let stale: Vec<&str> = ALLOWED
        .iter()
        .zip(&seen_allowed)
        .filter_map(|(a, seen)| (!seen).then_some(*a))
        .collect();
    assert!(
        stale.is_empty(),
        "allowlisted lines no longer exist: {stale:?}"
    );
}

#[test]
fn spelling_reads_are_detected() {
    // Each shape a stage could re-read the spelling through is flagged.
    for line in [
        r#"    if interner.resolve(v) == Some("any") {"#,
        r#"    .is_some_and(|n| n != "any")"#,
        r#"    let any_sym = interner.intern("any")?;"#,
        r#"    "any" => Ty::Wildcard,"#,
        "    if name == canon::WILDCARD_SPELLING {",
    ] {
        assert!(reads_spelling(line), "must flag: {line}");
    }
    // A comment, a rendering, and a kernel-table row are not reads.
    for line in [
        r#"    // compares against "any" == the wildcard"#,
        "    Type::Wildcard => canon::WILDCARD_SPELLING.into(),",
        r#"    Self::ListAny => d("List", "any", 2, Pure, "list_any", IpeOrder),"#,
        r#"    "any","#,
    ] {
        assert!(!reads_spelling(line), "must not flag: {line}");
    }
}

#[test]
fn test_modules_are_not_production_lines() {
    let text = "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn b() {}\n}\nfn c() {}\n";
    let kept: Vec<&str> = production_lines(text).into_iter().map(|(_, l)| l).collect();
    assert_eq!(kept, ["fn a() {}", "fn c() {}"]);
}
