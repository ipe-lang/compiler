//! The working-tree metadata parse reads the filesystem through held handles only.
//!
//! Every fact the parse records about a carved entry is read from the one
//! handle it was opened by, through the walk's held parent. A path-based
//! query in the parse would read a second object a renamed ancestor can put in
//! the first one's place, so non-test `src/vcs_metadata.rs` holds none: no
//! `std::fs` call, no `rustix` open, no `Path` metadata or existence query.
//! The one path open it may make is `HeldDir::open_root`, and only at its
//! sanctioned roots: the working tree (`walk`), a pointer's canonical target
//! (`target`), and a recorded path's canonical parent (`prove_named`).
//!
//! The scan is lexical: comments, string literals and character literals are
//! blanked first, so only code is matched. A control fixture holding each
//! refused form proves the scan turns red on it.

use std::path::Path;

/// The tokens of a path-based filesystem query.
const FORBIDDEN: [&str; 9] = [
    "fs::",
    "File::open",
    "rustix::",
    "symlink_metadata",
    ".metadata(",
    ".is_dir(",
    ".is_file(",
    ".exists(",
    ".try_exists(",
];

/// The one path open the parse may make.
const PATH_OPEN: &str = "open_root(";

/// The functions that make it, each exactly once, in source order.
const PATH_OPEN_SITES: [&str; 3] = ["walk", "target", "prove_named"];

/// One match in the scanned code: the token, the function it is in, its line.
#[derive(Debug)]
struct Hit {
    token: &'static str,
    function: String,
    line: usize,
}

/// What one scan found.
#[derive(Debug)]
struct Findings {
    forbidden: Vec<Hit>,
    path_opens: Vec<Hit>,
}

impl Findings {
    /// Every rule the scanned code breaks, one line each.
    fn violations(&self) -> Vec<String> {
        let mut found: Vec<String> = self
            .forbidden
            .iter()
            .map(|hit| {
                format!(
                    "line {}: `{}` in `{}` queries a path",
                    hit.line, hit.token, hit.function
                )
            })
            .collect();
        let sites: Vec<&str> = self
            .path_opens
            .iter()
            .map(|hit| hit.function.as_str())
            .collect();
        if sites != PATH_OPEN_SITES {
            found.push(format!(
                "`{PATH_OPEN}` is called from {sites:?}, not exactly {PATH_OPEN_SITES:?}"
            ));
        }
        found
    }
}

/// The source before its `mod tests`; `None` when the module is missing.
fn production(source: &str) -> Option<&str> {
    source.find("\nmod tests {").and_then(|at| source.get(..at))
}

const fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The index just past the string literal opening at `start`.
fn string_end(chars: &[char], start: usize) -> usize {
    let mut i = start.saturating_add(1);
    loop {
        match chars.get(i) {
            Some('\\') => i = i.saturating_add(2),
            Some('"') => return i.saturating_add(1),
            Some(_) => i = i.saturating_add(1),
            None => return i,
        }
    }
}

/// The index just past the raw string literal whose `r` is at `start`;
/// `None` when no raw string opens there.
fn raw_string_end(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start.saturating_add(1);
    let mut hashes = 0_usize;
    while chars.get(i) == Some(&'#') {
        hashes = hashes.saturating_add(1);
        i = i.saturating_add(1);
    }
    if chars.get(i) != Some(&'"') {
        return None;
    }
    i = i.saturating_add(1);
    loop {
        match chars.get(i) {
            Some('"') => {
                let close = i.saturating_add(1);
                let closing = (0..hashes).all(|k| chars.get(close.saturating_add(k)) == Some(&'#'));
                if closing {
                    return Some(close.saturating_add(hashes));
                }
                i = close;
            }
            Some(_) => i = i.saturating_add(1),
            None => return Some(i),
        }
    }
}

/// The index just past the block comment opening at `start`, nesting counted.
fn block_comment_end(chars: &[char], start: usize) -> usize {
    let mut i = start;
    let mut depth = 0_u32;
    loop {
        match (chars.get(i), chars.get(i.saturating_add(1))) {
            (Some('/'), Some('*')) => {
                depth = depth.saturating_add(1);
                i = i.saturating_add(2);
            }
            (Some('*'), Some('/')) => {
                depth = depth.saturating_sub(1);
                i = i.saturating_add(2);
                if depth == 0 {
                    return i;
                }
            }
            (Some(_), _) => i = i.saturating_add(1),
            (None, _) => return i,
        }
    }
}

/// The index just past the character literal opening at `start`; `None` for
/// a lifetime.
fn char_end(chars: &[char], start: usize) -> Option<usize> {
    let after = |n: usize| chars.get(start.saturating_add(n)).copied();
    if after(1) == Some('\\') {
        let mut i = start.saturating_add(3);
        while chars.get(i).is_some_and(|&c| c != '\'') {
            i = i.saturating_add(1);
        }
        return Some(i.saturating_add(1));
    }
    (after(2) == Some('\'')).then(|| start.saturating_add(3))
}

/// `source` with every comment and literal blanked, its line breaks kept.
fn code_only(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut code = String::with_capacity(source.len());
    let mut i = 0_usize;
    while let Some(&c) = chars.get(i) {
        let next = chars.get(i.saturating_add(1)).copied();
        let after_ident = i
            .checked_sub(1)
            .and_then(|before| chars.get(before))
            .is_some_and(|&before| is_ident(before));
        let skipped = match c {
            '/' if next == Some('/') => {
                let mut end = i;
                while chars.get(end).is_some_and(|&c| c != '\n') {
                    end = end.saturating_add(1);
                }
                Some((end, ""))
            }
            '/' if next == Some('*') => Some((block_comment_end(&chars, i), " ")),
            '"' => Some((string_end(&chars, i), "\"\"")),
            'r' if !after_ident => raw_string_end(&chars, i).map(|end| (end, "\"\"")),
            '\'' => char_end(&chars, i).map(|end| (end, "' '")),
            _ => None,
        };
        if let Some((end, blank)) = skipped {
            code.push_str(blank);
            let breaks = chars.get(i..end).unwrap_or_default();
            code.extend(breaks.iter().filter(|&&c| c == '\n'));
            i = end;
        } else {
            code.push(c);
            i = i.saturating_add(1);
        }
    }
    code
}

/// The name of the last function declared before byte `at` of `code`.
fn enclosing_fn(code: &str, at: usize) -> String {
    let before = code.get(..at).unwrap_or_default();
    before
        .match_indices("fn ")
        .filter(|&(i, _)| {
            i.checked_sub(1)
                .and_then(|j| before.get(j..i))
                .is_none_or(|prev| !prev.chars().any(is_ident))
        })
        .last()
        .and_then(|(i, _)| before.get(i.saturating_add(3)..))
        .map(|rest| rest.chars().take_while(|&c| is_ident(c)).collect())
        .unwrap_or_default()
}

/// Every match of `token` in `code`.
fn hits(code: &str, token: &'static str) -> Vec<(usize, Hit)> {
    code.match_indices(token)
        .map(|(at, _)| {
            let line = code
                .get(..at)
                .unwrap_or_default()
                .matches('\n')
                .count()
                .saturating_add(1);
            let hit = Hit {
                token,
                function: enclosing_fn(code, at),
                line,
            };
            (at, hit)
        })
        .collect()
}

/// Scan the code of `source` before its `mod tests`.
fn scan(source: &str) -> Option<Findings> {
    let code = code_only(production(source)?);
    let mut forbidden: Vec<(usize, Hit)> = FORBIDDEN
        .iter()
        .flat_map(|&token| hits(&code, token))
        .collect();
    forbidden.sort_by_key(|&(at, _)| at);
    Some(Findings {
        forbidden: forbidden.into_iter().map(|(_, hit)| hit).collect(),
        path_opens: hits(&code, PATH_OPEN)
            .into_iter()
            .map(|(_, hit)| hit)
            .collect(),
    })
}

#[allow(clippy::expect_used)] // the scanned files ship with this crate
fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(path).expect("a scanned file of this crate reads")
}

#[test]
fn the_metadata_parse_queries_no_path() {
    let findings = scan(&read("src/vcs_metadata.rs"));
    assert!(
        findings.is_some(),
        "src/vcs_metadata.rs lost its `mod tests`"
    );
    let violations = findings.map(|found| found.violations()).unwrap_or_default();
    assert!(
        violations.is_empty(),
        "the metadata parse reads a path, not a held handle:\n{}",
        violations.join("\n")
    );
}

#[test]
#[allow(clippy::expect_used)] // the fixture is this crate's own
fn the_scan_refuses_the_control_fixture() {
    let findings = scan(&read(
        "tests/fixtures/vcs_metadata_handle_scan/path_query.rs.txt",
    ))
    .expect("the control fixture holds a `mod tests`");
    let forbidden: Vec<(&str, &str)> = findings
        .forbidden
        .iter()
        .map(|hit| (hit.token, hit.function.as_str()))
        .collect();
    assert_eq!(
        forbidden,
        [
            ("fs::", "entry_at"),
            ("symlink_metadata", "entry_at"),
            (".exists(", "entry_at"),
        ],
        "each refused form in code is found, and none in a comment, string, or test"
    );
    let sites: Vec<&str> = findings
        .path_opens
        .iter()
        .map(|hit| hit.function.as_str())
        .collect();
    assert_eq!(sites, ["walk", "entry_at"]);
    assert_eq!(
        findings.violations().len(),
        4,
        "{:?}",
        findings.violations()
    );
}
