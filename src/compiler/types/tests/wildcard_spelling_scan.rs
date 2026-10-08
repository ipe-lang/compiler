//! The wildcard's spelling `any` is read in exactly one place.
//!
//! Canon's `is_wildcard_spelling` turns an unbound `any` into
//! `Type::Wildcard`; every later stage matches the variant, never the name. A
//! stage that compares a symbol's spelling against `any` again would treat a
//! declared parameter spelled `any` as the wildcard, so this scan refuses every
//! production line naming the spelling outside a fixed allowlist.

use std::path::{Path, PathBuf};

/// Production source roots scanned, relative to this crate's manifest: every
/// crate that sees a parsed, canonical, inferred, or lowered type.
const ROOTS: &[&str] = &[
    "../syntax/src",
    "../parse/src",
    "../types/src",
    "../canon/src",
    "../lower/src",
    "../ir/src",
    "../backend",
    "../kernels/src",
    "../ffi/src",
    "../db/src",
    "../lint/src",
    "../annotate/src",
    "../diagnostics/src",
    "../../lsp",
    "../../ipe-cli/src",
];

/// The only production lines that may name the spelling, by exact trimmed
/// text. Every other line carrying the literal (in any letter case) or the
/// constant is refused, whatever it does with it: an alias, an import rename,
/// or a case-folded compare re-reads the spelling just as an `==` does.
///
/// - the constant's definition and its one read in `is_wildcard_spelling`;
/// - the renderings of the variant back to its source spelling;
/// - the kernel value names `String.any`, `List.any`, `Server.any` (a value,
///   never a type variable): their registry rows, callee tuples, and the
///   `Server` module's export list;
/// - the manifest's `Any` screen orientation, an unrelated word.
const ALLOWED: &[&str] = &[
    r#"pub const WILDCARD_SPELLING: &str = "any";"#,
    "interner.resolve(v) == Some(canon::WILDCARD_SPELLING)",
    "canon::Type::Wildcard => canon::WILDCARD_SPELLING.into(),",
    "Ty::Wildcard => Ok(TyDoc::Var(canon::WILDCARD_SPELLING.into())),",
    "canon::Type::Wildcard => Ok(TyDoc::Var(canon::WILDCARD_SPELLING.into())),",
    "Type::Wildcard => Ok(ipe_canon::ast::WILDCARD_SPELLING.to_owned()),",
    r#"Self::StringAny => d("String", "any", 2, Pure, "string_any", IpeOrder),"#,
    r#"Self::ListAny => d("List", "any", 2, Pure, "list_any", IpeOrder),"#,
    r#"Self::ServerAny => d("Server", "any", 2, Server, "server_any", IpeOrder),"#,
    r#"("String", "any") => Ok(Callee::Kernel(KernelFn::StringAny)),"#,
    r#"("List", "any") => Ok(Callee::Kernel(KernelFn::ListAny)),"#,
    r#"("Server", "any") => Ok(Callee::Kernel(KernelFn::ServerAny)),"#,
    r#""any","#,
    r#""Any" => Ok(ScreenOrientation::Any),"#,
];

/// Whether `line` names the wildcard's spelling: the string literal in any
/// letter case, or the constant holding it.
fn reads_spelling(line: &str) -> bool {
    if line.trim_start().starts_with("//") {
        return false;
    }
    line.to_ascii_lowercase().contains("\"any\"") || line.contains("WILDCARD_SPELLING")
}

/// Every `.rs` file under `dir`, skipping test-only directories and files.
///
/// # Errors
///
/// When a directory or one of its entries cannot be read: an unread directory
/// is an unscanned one, so the scan fails rather than passing over it.
fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name != "tests" && name != "target" {
                rust_sources(&path, out)?;
            }
        } else if path.extension().is_some_and(|e| e == "rs") && name != "tests.rs" {
            out.push(path);
        }
    }
    Ok(())
}

/// The production lines of `text`, with every `#[cfg(test)]` module dropped,
/// or `None` when a test module never closes.
///
/// A test module is the `mod name {` item after `#[cfg(test)]`, closed by the
/// `}` at its own indentation (the formatter's layout). A module whose close is
/// never found would hide the rest of the file, so it fails the scan.
fn production_lines(text: &str) -> Option<Vec<(usize, &str)>> {
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
    skip_until.is_none().then_some(out)
}

#[test]
fn wildcard_spelling_is_read_once() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for root in ROOTS {
        let dir = manifest.join(root);
        assert!(dir.is_dir(), "scan root `{root}` must exist");
        rust_sources(&dir, &mut files).expect("every directory under a scan root must be readable");
    }
    let mut offending = Vec::new();
    let mut seen_allowed = vec![false; ALLOWED.len()];
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read a scanned source");
        let Some(lines) = production_lines(&text) else {
            offending.push(format!(
                "{}: a `#[cfg(test)]` module never closes at its own indentation",
                file.display()
            ));
            continue;
        };
        for (n, line) in lines {
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
    // Each shape a stage could re-read the spelling through is flagged,
    // including those that alias, rename, or case-fold it with no `==`.
    for line in [
        r#"    if interner.resolve(v) == Some("any") {"#,
        r#"    .is_some_and(|n| n != "any")"#,
        r#"    let any_sym = interner.intern("any")?;"#,
        r#"    "any" => Ty::Wildcard,"#,
        "    if name == canon::WILDCARD_SPELLING {",
        r#"    const SPELLED: &str = "any";"#,
        "    const SPELLED: &str = canon::WILDCARD_SPELLING;",
        "use ipe_canon::ast::WILDCARD_SPELLING as SPELLED;",
        r#"    if name.eq_ignore_ascii_case("ANY") {"#,
        r#"    Some(n) if n.starts_with("any") => Ty::Wildcard,"#,
        r#"    let spelled = r"any";"#,
        r#"    let spelled = b"any";"#,
    ] {
        assert!(reads_spelling(line), "must flag: {line}");
    }
    // A comment, a longer kernel name, and a variant match are not reads.
    for line in [
        r#"    // compares against "any" == the wildcard"#,
        r#"    ("List", "anyOf") => Ok(Callee::Kernel(KernelFn::ListAnyOf)),"#,
        "    Ty::Wildcard => false,",
    ] {
        assert!(!reads_spelling(line), "must not flag: {line}");
    }
}

#[test]
fn test_modules_are_not_production_lines() {
    let text = "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn b() {}\n}\nfn c() {}\n";
    let kept: Option<Vec<&str>> =
        production_lines(text).map(|lines| lines.into_iter().map(|(_, l)| l).collect());
    assert_eq!(kept, Some(vec!["fn a() {}", "fn c() {}"]));
}

#[test]
fn an_unclosed_test_module_fails_the_scan() {
    // A test module whose close is not at its own indentation would hide every
    // later line from the scan, so the file is refused instead.
    let text = "#[cfg(test)]\nmod tests {\n    fn b() {}\n  }\nfn c() { x == \"any\" }\n";
    assert_eq!(production_lines(text), None);
}
