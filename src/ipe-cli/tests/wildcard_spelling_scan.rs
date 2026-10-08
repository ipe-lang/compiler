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
    "../compiler/syntax/src",
    "../compiler/parse/src",
    "../compiler/types/src",
    "../compiler/canon/src",
    "../compiler/lower/src",
    "../compiler/ir/src",
    "../compiler/backend",
    "../compiler/kernels/src",
    "../compiler/ffi/src",
    "../compiler/db/src",
    "../compiler/lint/src",
    "../compiler/annotate/src",
    "../compiler/diagnostics/src",
    "../lsp",
    "src",
];

/// The only production lines that may name the spelling, each keyed by the
/// file it lives in (a path suffix) and its exact trimmed text, and each
/// required exactly once. Every other line carrying the literal (in any letter
/// case) or the constant is refused, whatever it does with it: an alias, an
/// import rename, or a case-folded compare re-reads the spelling just as an
/// `==` does. A copy of an allowed line in another file, or a second copy in
/// its own file, is refused too.
///
/// - the constant's definition and its one read in `is_wildcard_spelling`;
/// - the renderings of the variant back to its source spelling;
/// - the kernel value names `String.any`, `List.any`, `Server.any` (a value,
///   never a type variable): their registry rows, callee tuples, and the
///   `Server` module's export list;
/// - the manifest's `Any` screen orientation, an unrelated word.
const ALLOWED: &[(&str, &str)] = &[
    (
        "canon/src/ast.rs",
        r#"pub const WILDCARD_SPELLING: &str = "any";"#,
    ),
    (
        "canon/src/resolve.rs",
        "interner.resolve(v) == Some(canon::WILDCARD_SPELLING)",
    ),
    (
        "canon/src/resolve.rs",
        "canon::Type::Wildcard => canon::WILDCARD_SPELLING.into(),",
    ),
    (
        "types/src/doc.rs",
        "Ty::Wildcard => Ok(TyDoc::Var(canon::WILDCARD_SPELLING.into())),",
    ),
    (
        "types/src/doc.rs",
        "canon::Type::Wildcard => Ok(TyDoc::Var(canon::WILDCARD_SPELLING.into())),",
    ),
    (
        "ipe-cli/src/api_surface.rs",
        "Type::Wildcard => Ok(ipe_canon::ast::WILDCARD_SPELLING.to_owned()),",
    ),
    (
        "kernels/src/lib.rs",
        r#"Self::StringAny => d("String", "any", 2, Pure, "string_any", IpeOrder),"#,
    ),
    (
        "kernels/src/lib.rs",
        r#"Self::ListAny => d("List", "any", 2, Pure, "list_any", IpeOrder),"#,
    ),
    (
        "kernels/src/lib.rs",
        r#"Self::ServerAny => d("Server", "any", 2, Server, "server_any", IpeOrder),"#,
    ),
    (
        "lower/src/lower.rs",
        r#"("String", "any") => Ok(Callee::Kernel(KernelFn::StringAny)),"#,
    ),
    (
        "lower/src/lower.rs",
        r#"("List", "any") => Ok(Callee::Kernel(KernelFn::ListAny)),"#,
    ),
    (
        "lower/src/lower.rs",
        r#"("Server", "any") => Ok(Callee::Kernel(KernelFn::ServerAny)),"#,
    ),
    ("canon/src/env.rs", r#""any","#),
    (
        "ipe-cli/src/package_manifest.rs",
        r#""Any" => Ok(ScreenOrientation::Any),"#,
    ),
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

/// Every problem the scan finds in `files` (path, text): an unallowed spelling
/// read, a test module that never closes, or an allowlisted line not seen
/// exactly once in its own file.
fn audit(files: &[(PathBuf, String)]) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen = vec![0_usize; ALLOWED.len()];
    for (file, text) in files {
        let Some(lines) = production_lines(text) else {
            problems.push(format!(
                "{}: a `#[cfg(test)]` module never closes at its own indentation",
                file.display()
            ));
            continue;
        };
        for (n, line) in lines {
            if !reads_spelling(line) {
                continue;
            }
            let allowed = ALLOWED
                .iter()
                .position(|(home, text)| file.ends_with(home) && *text == line.trim());
            match allowed.and_then(|k| seen.get_mut(k)) {
                Some(count) => *count = count.saturating_add(1),
                None => problems.push(format!("{}:{n}: {}", file.display(), line.trim())),
            }
        }
    }
    for ((home, text), count) in ALLOWED.iter().zip(&seen) {
        if *count != 1 {
            problems.push(format!(
                "allowlisted line must occur exactly once in `{home}`, found {count}: {text}"
            ));
        }
    }
    problems
}

#[test]
fn wildcard_spelling_is_read_once() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = Vec::new();
    for root in ROOTS {
        let dir = manifest.join(root);
        assert!(dir.is_dir(), "scan root `{root}` must exist");
        rust_sources(&dir, &mut paths).expect("every directory under a scan root must be readable");
    }
    let files: Vec<(PathBuf, String)> = paths
        .into_iter()
        .map(|p| {
            let text = std::fs::read_to_string(&p).expect("read a scanned source");
            (p, text)
        })
        .collect();
    let problems = audit(&files);
    assert!(
        problems.is_empty(),
        "the wildcard spelling `any` is read only by canon's `is_wildcard_spelling`; \
         match `Type::Wildcard` / `Ty::Wildcard` instead:\n{}",
        problems.join("\n")
    );
}

/// A synthetic tree holding exactly the allowlisted lines, each in its own
/// file.
fn allowed_files() -> Vec<(PathBuf, String)> {
    let mut files: Vec<(PathBuf, String)> = Vec::new();
    for (home, text) in ALLOWED {
        let path = PathBuf::from("src/compiler").join(home);
        match files.iter_mut().find(|(p, _)| *p == path) {
            Some((_, body)) => {
                body.push_str(text);
                body.push('\n');
            }
            None => files.push((path, format!("{text}\n"))),
        }
    }
    files
}

#[test]
fn an_allowed_line_is_allowed_only_once_in_its_own_file() {
    assert_eq!(audit(&allowed_files()), Vec::<String>::new());

    // The one spelling read copied into another crate is a second read.
    let mut moved = allowed_files();
    moved.push((
        PathBuf::from("src/compiler/lower/src/lower.rs"),
        "    interner.resolve(v) == Some(canon::WILDCARD_SPELLING)\n".to_owned(),
    ));
    assert_eq!(
        audit(&moved).len(),
        1,
        "a copy in another file must be refused"
    );

    // A second copy in its own file is a second read too.
    let mut doubled = allowed_files();
    let resolve = doubled
        .iter_mut()
        .find(|(p, _)| p.ends_with("canon/src/resolve.rs"))
        .expect("the allowlist names canon's resolver");
    resolve
        .1
        .push_str("    interner.resolve(v) == Some(canon::WILDCARD_SPELLING)\n");
    assert_eq!(
        audit(&doubled).len(),
        1,
        "a second copy in the same file must be refused"
    );

    // A removed allowed line is a stale entry.
    let mut missing = allowed_files();
    missing.retain(|(p, _)| !p.ends_with("canon/src/ast.rs"));
    assert_eq!(
        audit(&missing).len(),
        1,
        "a vanished allowed line must be reported"
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
