#![forbid(unsafe_code)]
//! Refuses a fixed-name `temp_dir()` output path anywhere in the e2e test
//! tree: two gates building from different `CARGO_TARGET_DIR` pools share the
//! process-wide `/tmp`, so a fixed name there lets one gate's build clobber
//! another's. Every e2e test must root its output under the per-binary
//! `CARGO_TARGET_TMPDIR` instead, via `crate::support::scratch_root()` (test
//! binaries that carry `mod support;`) or an inline
//! `env!("CARGO_TARGET_TMPDIR")` (those that do not).
//!
//! Also refuses a scratch tree bound under one of those roots and emptied with
//! a bare `remove_dir_all`: it outlives its test, so a run's disk grows with
//! its test count. `e2e_support::scratch::fresh` empties it and removes it when
//! the test ends.

/// Paths (relative to `tests/`) allowed to contain the literal `temp_dir()`
/// text without being a live call: `support/mod.rs`'s own doc comment
/// describes the design this scan enforces, and this scan test's own source
/// names the banned literal in its doc comment, allow-list, and message.
const ALLOWED_SUFFIXES: &[&str] = &["support/mod.rs", "e2e_scratch_dir_scan.rs"];

#[test]
fn no_fixed_temp_dir_in_e2e_tests() {
    let tests_dir = e2e_support::manifest_dir!().join("tests");
    let files = panic_scan::rust_sources(&tests_dir, panic_scan::Want::RustFiles)
        .expect("the e2e test tree is listed whole");

    let mut offenders = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(&tests_dir)
            .expect("a listed file lies under its root")
            .to_string_lossy()
            .replace('\\', "/");
        if ALLOWED_SUFFIXES.iter().any(|s| rel.ends_with(s)) {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))
            .expect("every listed test source is readable");
        if text.contains("temp_dir()") {
            offenders.push(rel);
        }
    }

    assert!(
        offenders.is_empty(),
        "fixed-name temp_dir() found in e2e tests (use crate::support::scratch_root() \
         or env!(\"CARGO_TARGET_TMPDIR\") instead): {offenders:?}"
    );
}

/// The scratch roots a test's emitted tree is joined under.
const SCRATCH_ROOTS: &[&str] = &["CARGO_TARGET_TMPDIR", "scratch_root()"];

/// The 1-based lines of `text` that empty a scratch tree with a bare
/// `remove_dir_all` right after binding it under a scratch root.
///
/// Such a tree is emptied when its test starts and left behind when it ends,
/// so a run's disk grows with its test count (each emitted project bundles the
/// whole runtime crate). `e2e_support::scratch::fresh` empties it the same way
/// and also removes it when the test ends.
fn bare_scratch_pre_cleans(text: &str) -> Vec<usize> {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let mut hits = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(var) = line
            .strip_prefix("let _ = std::fs::remove_dir_all(&")
            .or_else(|| line.strip_prefix("let _ = fs::remove_dir_all(&"))
            .and_then(|rest| rest.strip_suffix(");"))
        else {
            continue;
        };
        if var.is_empty() || !var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let Some(binding) = previous_let(&lines, i) else {
            continue;
        };
        let bound = binding
            .first()
            .and_then(|first| first.strip_prefix("let "))
            .map(|rest| rest.strip_prefix("mut ").unwrap_or(rest))
            .and_then(|rest| rest.strip_prefix(var))
            .is_some_and(|rest| !rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_'));
        if bound
            && binding
                .iter()
                .any(|l| SCRATCH_ROOTS.iter().any(|root| l.contains(root)))
        {
            hits.push(i + 1);
        }
    }
    hits
}

/// The lines of the `let` statement that ends on the line just before `at`, or
/// `None` when that line does not end one.
fn previous_let<'a>(lines: &'a [&'a str], at: usize) -> Option<&'a [&'a str]> {
    let end = at.checked_sub(1)?;
    if !lines.get(end)?.ends_with(';') {
        return None;
    }
    let mut start = end;
    loop {
        let line = lines.get(start)?;
        if line.starts_with("let ") {
            return lines.get(start..at);
        }
        if line.is_empty()
            || line.starts_with("//")
            || line.ends_with('{')
            || line.ends_with('}')
            || (start != end && line.ends_with(';'))
        {
            return None;
        }
        start = start.checked_sub(1)?;
    }
}

#[test]
fn no_bare_scratch_pre_clean_in_e2e_tests() {
    let tests_dir = e2e_support::manifest_dir!().join("tests");
    let files = panic_scan::rust_sources(&tests_dir, panic_scan::Want::RustFiles)
        .expect("the e2e test tree is listed whole");

    let mut offenders = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(&tests_dir)
            .expect("a listed file lies under its root")
            .to_string_lossy()
            .replace('\\', "/");
        if ALLOWED_SUFFIXES.iter().any(|s| rel.ends_with(s)) {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))
            .expect("every listed test source is readable");
        offenders.extend(
            bare_scratch_pre_cleans(&text)
                .into_iter()
                .map(|line| format!("{rel}:{line}")),
        );
    }

    assert!(
        offenders.is_empty(),
        "a scratch tree emptied with a bare remove_dir_all outlives its test \
         (use e2e_support::scratch::fresh, which also removes it when the test \
         ends): {offenders:?}"
    );
}

#[test]
fn the_pre_clean_scan_refuses_a_bare_pre_clean_in_either_layout() {
    let one_line = "    let out = crate::support::scratch_root().join(\"x_emit\");\n    \
                    let _ = std::fs::remove_dir_all(&out);\n";
    assert_eq!(bare_scratch_pre_cleans(one_line), vec![2]);

    let wrapped = "        let mut out = PathBuf::from(env!(\"CARGO_TARGET_TMPDIR\"))\n            \
                   .join(format!(\"{name}_emit\"));\n        \
                   let _ = fs::remove_dir_all(&out);\n";
    assert_eq!(bare_scratch_pre_cleans(wrapped), vec![3]);
}

#[test]
fn the_pre_clean_scan_admits_a_claimed_tree_and_other_trees() {
    let claimed = "let out = crate::support::scratch_root().join(\"x_emit\");\n\
                   e2e_support::scratch::fresh(&out);\n";
    assert!(bare_scratch_pre_cleans(claimed).is_empty());

    let post_clean = "let out = crate::support::scratch_root().join(\"x\");\n\
                      build(&out);\n\
                      let _ = std::fs::remove_dir_all(&out);\n";
    assert!(bare_scratch_pre_cleans(post_clean).is_empty());

    let other_binding = "let out = crate::support::scratch_root().join(\"x\");\n\
                         let _ = std::fs::remove_dir_all(&outer);\n";
    assert!(bare_scratch_pre_cleans(other_binding).is_empty());

    let not_scratch = "let out = repo_root().join(\"dist\");\n\
                       let _ = std::fs::remove_dir_all(&out);\n";
    assert!(bare_scratch_pre_cleans(not_scratch).is_empty());
}
