#![forbid(unsafe_code)]
//! INV-1 (no hidden inputs): the crate's `clippy.toml` keeps every root ban,
//! adds the ambient-input bans, and the proof module names each one.
//!
//! The test reads only through `include_str!`, since the filesystem APIs it
//! guards are banned in this crate's own tests.

const DB_CONFIG: &str = include_str!("../clippy.toml");
const ROOT_CONFIG: &str = include_str!("../../../../clippy.toml");
const PROOF: &str = include_str!("../src/clippy_paths_resolve.rs");
const LIB: &str = include_str!("../src/lib.rs");

/// The reason every INV-1 entry carries.
const REASON: &str = "INV-1: salsa queries are pure";

/// The marker of a ban entry line in either config.
const ENTRY_PREFIX: &str = "{ path = \"";

/// The array key of the method bans.
const METHODS_KEY: &str = "disallowed-methods";

/// The array key of the type bans.
const TYPES_KEY: &str = "disallowed-types";

/// The expectation each proof line carries, by the lint its entry configures.
const EXPECT_METHOD: &str = "#[expect(clippy::disallowed_methods)]";
const EXPECT_TYPE: &str = "#[expect(clippy::disallowed_types)]";

/// The declaration that compiles the proof module into the crate.
const PROOF_MODULE_DECL: &str = "mod clippy_paths_resolve;";

/// Every path INV-1 bans in `ipe_db`: 40 methods, then 5 types.
const INV1_PATHS: &[&str] = &[
    "std::fs::read",
    "std::fs::read_to_string",
    "std::fs::read_dir",
    "std::fs::read_link",
    "std::fs::metadata",
    "std::fs::symlink_metadata",
    "std::fs::canonicalize",
    "std::fs::exists",
    "std::fs::write",
    "std::fs::create_dir",
    "std::fs::create_dir_all",
    "std::fs::remove_file",
    "std::fs::remove_dir",
    "std::fs::remove_dir_all",
    "std::fs::rename",
    "std::fs::copy",
    "std::fs::hard_link",
    "std::fs::set_permissions",
    "std::path::Path::exists",
    "std::path::Path::try_exists",
    "std::path::Path::is_file",
    "std::path::Path::is_dir",
    "std::path::Path::is_symlink",
    "std::path::Path::metadata",
    "std::path::Path::symlink_metadata",
    "std::path::Path::read_dir",
    "std::path::Path::read_link",
    "std::path::Path::canonicalize",
    "std::path::absolute",
    "std::env::current_dir",
    "std::env::set_current_dir",
    "std::env::current_exe",
    "std::env::args",
    "std::env::args_os",
    "std::process::id",
    "std::io::stdin",
    "std::time::SystemTime::now",
    "std::time::SystemTime::elapsed",
    "std::time::Instant::now",
    "std::time::Instant::elapsed",
    "std::fs::File",
    "std::fs::OpenOptions",
    "std::fs::DirBuilder",
    "std::fs::ReadDir",
    "std::fs::DirEntry",
];

/// One `clippy.toml` line, by the closed set of shapes the configs use.
#[derive(Debug, PartialEq, Eq)]
enum ConfigLine<'a> {
    /// An empty or whitespace-only line.
    Blank,
    /// A `#` comment.
    Comment,
    /// A top-level `key = value` line; `value` is `[` when it opens an array.
    Key { key: &'a str, value: &'a str },
    /// A one-line `{ path = "..", .. },` ban entry.
    Entry(&'a str),
    /// The `]` that closes an array.
    Close,
}

/// Why a `clippy.toml` refuses to parse into policy items.
#[derive(Debug, PartialEq, Eq)]
enum ConfigRefusal<'a> {
    /// A line of no known shape (a `[table]`, a spaceless `key=value`, ..).
    Unclassified { line: usize, text: &'a str },
    /// A ban entry outside any array.
    EntryOutsideArray { line: usize, text: &'a str },
    /// A key line inside an open array.
    KeyInsideArray { line: usize, text: &'a str },
    /// A `]` with no open array.
    CloseOutsideArray { line: usize },
    /// An array still open at the end of the file.
    UnclosedArray { key: &'a str },
}

impl ConfigRefusal<'_> {
    /// The refusal as a sentence naming its line.
    fn describe(&self) -> String {
        match self {
            Self::Unclassified { line, text } => format!("line {line} has no known shape: {text}"),
            Self::EntryOutsideArray { line, text } => {
                format!("line {line} is a ban entry outside any array: {text}")
            }
            Self::KeyInsideArray { line, text } => {
                format!("line {line} is a key inside an open array: {text}")
            }
            Self::CloseOutsideArray { line } => format!("line {line} closes no open array"),
            Self::UnclosedArray { key } => format!("the `{key}` array is never closed"),
        }
    }
}

/// One policy item: a ban entry under the key of its enclosing array, or a
/// top-level key line (`array` is `None`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Policy<'a> {
    array: Option<&'a str>,
    line: &'a str,
}

/// Whether `c` can appear in a TOML bare key.
const fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

/// The shape of one config line, or `None` when it has no known shape.
fn classify(text: &str) -> Option<ConfigLine<'_>> {
    let text = text.trim();
    if text.is_empty() {
        return Some(ConfigLine::Blank);
    }
    if text.starts_with('#') {
        return Some(ConfigLine::Comment);
    }
    if text == "]" {
        return Some(ConfigLine::Close);
    }
    if text.starts_with(ENTRY_PREFIX) && text.ends_with("},") {
        return Some(ConfigLine::Entry(text));
    }
    text.split_once(" = ")
        .filter(|(key, _)| !key.is_empty() && key.chars().all(is_key_char))
        .map(|(key, value)| ConfigLine::Key { key, value })
}

/// The policy items of a config, each entry paired with its array's key, or
/// the first line that does not fit the closed shape set.
fn policy(config: &str) -> Result<Vec<Policy<'_>>, ConfigRefusal<'_>> {
    let mut open: Option<&str> = None;
    let mut items = Vec::new();
    for (line, raw) in (1usize..).zip(config.lines()) {
        let text = raw.trim();
        let Some(shape) = classify(raw) else {
            return Err(ConfigRefusal::Unclassified { line, text });
        };
        match (shape, open) {
            (ConfigLine::Blank | ConfigLine::Comment, _) => {}
            (ConfigLine::Key { key, value }, None) => {
                items.push(Policy {
                    array: None,
                    line: text,
                });
                if value == "[" {
                    open = Some(key);
                }
            }
            (ConfigLine::Key { .. }, Some(_)) => {
                return Err(ConfigRefusal::KeyInsideArray { line, text });
            }
            (ConfigLine::Entry(entry), Some(array)) => items.push(Policy {
                array: Some(array),
                line: entry,
            }),
            (ConfigLine::Entry(_), None) => {
                return Err(ConfigRefusal::EntryOutsideArray { line, text });
            }
            (ConfigLine::Close, Some(_)) => open = None,
            (ConfigLine::Close, None) => return Err(ConfigRefusal::CloseOutsideArray { line }),
        }
    }
    open.map_or(Ok(items), |key| Err(ConfigRefusal::UnclosedArray { key }))
}

/// The policy items of the config `name`, asserting it parses.
fn parsed<'a>(name: &str, config: &'a str) -> Vec<Policy<'a>> {
    let items = policy(config);
    assert!(
        items.is_ok(),
        "{name} refused: {}",
        items
            .as_ref()
            .err()
            .map(ConfigRefusal::describe)
            .unwrap_or_default()
    );
    items.unwrap_or_default()
}

/// The items of `root` that `own` does not repeat in the same array.
fn missing_from<'a>(root: &[Policy<'a>], own: &[Policy<'a>]) -> Vec<Policy<'a>> {
    root.iter()
        .filter(|item| !own.contains(item))
        .copied()
        .collect()
}

/// Whether a banned path is a type: its last segment is capitalised.
fn is_type_path(path: &str) -> bool {
    path.rsplit("::")
        .next()
        .is_some_and(|leaf| leaf.starts_with(|c: char| c.is_ascii_uppercase()))
}

/// Whether the proof line `line` names `path` as the whole path of a
/// `let _ = ::path;` value, with an optional turbofish.
fn names_method(line: &str, path: &str) -> bool {
    line.strip_prefix(&format!("let _ = ::{path}"))
        .is_some_and(|rest| rest == ";" || rest.starts_with("::<"))
}

/// Whether the proof line `line` names the type `path` in a typed `let`.
fn names_type(line: &str, path: &str) -> bool {
    line == format!("let _: Option<::{path}> = None;")
}

/// Whether `lib` compiles the proof module unconditionally.
///
/// Exactly one unindented line is the declaration; the code before it (each
/// line cut at its first `//`) closes every brace it opens, so no enclosing
/// item can be configured away; and the nearest non-empty code line above it
/// ends an item (`;` or `}`) or is one lone inner attribute, so no outer
/// attribute (a `#[cfg(..)]` above, one spread over several lines, or one
/// sharing a line with an inner attribute) applies to it.
fn declares_proof_module(lib: &str) -> bool {
    let lines: Vec<&str> = lib.lines().collect();
    let mut decls = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == PROOF_MODULE_DECL);
    let (Some((at, _)), None) = (decls.next(), decls.next()) else {
        return false;
    };
    let code_above: Vec<&str> = lines
        .iter()
        .take(at)
        .copied()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code).trim())
        .filter(|line| !line.is_empty())
        .collect();
    let opened: usize = code_above
        .iter()
        .map(|line| line.matches('{').count())
        .sum();
    let closed: usize = code_above
        .iter()
        .map(|line| line.matches('}').count())
        .sum();
    opened == closed
        && code_above.last().is_none_or(|above| {
            above.ends_with(';')
                || above.ends_with('}')
                || (above.starts_with("#![")
                    && above.ends_with(']')
                    && above.matches('#').count() == 1)
        })
}

#[test]
fn the_crate_config_keeps_every_root_policy_line() {
    let root = parsed("the root `clippy.toml`", ROOT_CONFIG);
    let own = parsed("the crate `clippy.toml`", DB_CONFIG);
    let root_entries = root
        .iter()
        .filter(|item| item.array == Some(METHODS_KEY))
        .count();
    assert!(
        root_entries >= 10,
        "the root `clippy.toml` parsed to {root_entries} `{METHODS_KEY}` entries; the \
         superset check would pass on nothing"
    );
    let missing = missing_from(&root, &own);
    assert!(
        missing.is_empty(),
        "the crate `clippy.toml` replaces the root file, so it must repeat every root \
         policy line in the same array; missing: {missing:?}"
    );
}

#[test]
fn a_dropped_or_moved_root_line_is_reported_missing() {
    let entry = "{ path = \"std::process::abort\", reason = \"a\" },";
    let root_text = format!(
        "allow-unwrap-in-tests = true\n{METHODS_KEY} = [\n    {entry}\n]\n{TYPES_KEY} = [\n]\n"
    );
    let dropped_text =
        format!("allow-unwrap-in-tests = true\n{METHODS_KEY} = [\n]\n{TYPES_KEY} = [\n]\n");
    let moved_text = format!(
        "allow-unwrap-in-tests = true\n{METHODS_KEY} = [\n]\n{TYPES_KEY} = [\n    {entry}\n]\n"
    );
    let root = parsed("the synthetic root", &root_text);
    let dropped = parsed("the config that drops the entry", &dropped_text);
    let moved = parsed("the config that moves the entry", &moved_text);
    let lost = Policy {
        array: Some(METHODS_KEY),
        line: entry,
    };
    assert_eq!(missing_from(&root, &dropped), vec![lost]);
    assert_eq!(
        missing_from(&root, &moved),
        vec![lost],
        "an entry moved into another array still counts as missing from its own"
    );
    assert!(missing_from(&root, &root).is_empty());
    assert_eq!(
        policy(""),
        Ok(Vec::new()),
        "an empty config parses to nothing"
    );
}

#[test]
fn a_line_outside_the_closed_set_is_refused() {
    let entry = "{ path = \"std::fs::read\", reason = \"a\" },";
    let unclassified = [
        "allow-unwrap-in-tests=true\n".to_owned(),
        "[[disallowed-methods]]\npath = \"std::fs::read\"\n".to_owned(),
        "[table]\n".to_owned(),
        "\"std::fs::read\",\n".to_owned(),
        format!("{METHODS_KEY} = [\n    \"std::fs::read\",\n]\n"),
        format!("{METHODS_KEY} = [\n    {{ path = \"std::fs::read\" }}\n]\n"),
    ];
    for text in &unclassified {
        let refused = policy(text);
        assert!(
            matches!(refused, Err(ConfigRefusal::Unclassified { .. })),
            "an unclassifiable line parsed: {text:?} -> {refused:?}"
        );
    }
    assert!(matches!(
        policy(&format!("{entry}\n")),
        Err(ConfigRefusal::EntryOutsideArray { line: 1, .. })
    ));
    assert!(matches!(
        policy(&format!(
            "{METHODS_KEY} = [\nallow-unwrap-in-tests = true\n]\n"
        )),
        Err(ConfigRefusal::KeyInsideArray { line: 2, .. })
    ));
    assert!(matches!(
        policy("]\n"),
        Err(ConfigRefusal::CloseOutsideArray { line: 1 })
    ));
    assert!(matches!(
        policy(&format!("{METHODS_KEY} = [\n    {entry}\n")),
        Err(ConfigRefusal::UnclosedArray { key: METHODS_KEY })
    ));
}

#[test]
fn every_inv1_path_is_banned_and_proved() {
    assert_eq!(
        INV1_PATHS.len(),
        45,
        "INV-1 bans 40 methods and 5 types in `ipe_db`"
    );
    let own = parsed("the crate `clippy.toml`", DB_CONFIG);
    let proof_lines: Vec<&str> = PROOF.lines().map(str::trim).collect();
    for path in INV1_PATHS {
        let (array, expect) = kind_of(path);
        let entry = format!("{{ path = \"{path}\", reason = \"{REASON}\" }},");
        let wanted = Policy {
            array: Some(array),
            line: entry.as_str(),
        };
        assert_eq!(
            own.iter().filter(|item| **item == wanted).count(),
            1,
            "the crate `clippy.toml` must hold the INV-1 entry for `{path}` once, in its \
             `{array}` array"
        );
        assert_eq!(
            proof_line_above(&proof_lines, path).as_deref(),
            Some(expect),
            "`clippy_paths_resolve.rs` must name `{path}` with `{expect}` directly above it"
        );
    }
}

/// The `clippy.toml` array and the proof expectation of a banned path's kind.
fn kind_of(path: &str) -> (&'static str, &'static str) {
    if is_type_path(path) {
        (TYPES_KEY, EXPECT_TYPE)
    } else {
        (METHODS_KEY, EXPECT_METHOD)
    }
}

/// The trimmed proof line directly above the one naming `path`, if the proof
/// names it at all.
fn proof_line_above(proof_lines: &[&str], path: &str) -> Option<String> {
    let at = proof_lines.iter().position(|line| {
        if is_type_path(path) {
            names_type(line, path)
        } else {
            names_method(line, path)
        }
    })?;
    let before = at.checked_sub(1)?;
    proof_lines.get(before).map(|line| (*line).to_owned())
}

#[test]
fn the_proof_holds_one_expectation_per_inv1_path() {
    let types = INV1_PATHS.iter().filter(|p| is_type_path(p)).count();
    let methods = INV1_PATHS.iter().filter(|p| !is_type_path(p)).count();
    assert_eq!(
        PROOF.matches(EXPECT_METHOD).count(),
        methods,
        "one `{EXPECT_METHOD}` per banned method, and no other"
    );
    assert_eq!(
        PROOF.matches(EXPECT_TYPE).count(),
        types,
        "one `{EXPECT_TYPE}` per banned type, and no other"
    );
}

#[test]
fn the_proof_module_is_compiled_unconditionally() {
    assert!(
        declares_proof_module(LIB),
        "`src/lib.rs` must declare `{PROOF_MODULE_DECL}` once, unindented, at the crate \
         root, with no attribute on it; a `#[cfg(..)]` there disables every ban proof"
    );
}

#[test]
fn a_configured_or_nested_proof_module_is_refused() {
    let refused = [
        "",
        "#[cfg(any())]\nmod clippy_paths_resolve;",
        "#[cfg(any())]\n\n// note\nmod clippy_paths_resolve;",
        "#[cfg(\n    any()\n)]\nmod clippy_paths_resolve;",
        "#[cfg(any())] /* note */\nmod clippy_paths_resolve;",
        "#[cfg(any())] mod clippy_paths_resolve;",
        "    mod clippy_paths_resolve;",
        "mod outer {\nmod clippy_paths_resolve;\n}",
        "#[cfg(any())]\nmod outer {\n#![allow(dead_code)]\nmod clippy_paths_resolve;\n}",
        "mod clippy_paths_resolve;\nmod clippy_paths_resolve;",
        "#[cfg(any())] // ;\nmod clippy_paths_resolve;",
        "#![forbid(unsafe_code)] #[cfg(any())]\nmod clippy_paths_resolve;",
    ];
    for lib in refused {
        assert!(
            !declares_proof_module(lib),
            "a configured or nested proof module passed: {lib:?}"
        );
    }
    let accepted = [
        "mod clippy_paths_resolve;",
        "#![forbid(unsafe_code)]\n//! Doc.\n\nmod clippy_paths_resolve;\nmod metadata;",
        "mod a;\nmod clippy_paths_resolve;",
        "mod a {}\n\n// note\nmod clippy_paths_resolve;",
        "mod a; // trailing note\nmod clippy_paths_resolve;",
    ];
    for lib in accepted {
        assert!(
            declares_proof_module(lib),
            "a plain declaration was refused: {lib:?}"
        );
    }
}

#[test]
fn a_path_prefix_is_not_the_path() {
    assert!(names_method(
        "let _ = ::std::fs::read::<String>;",
        "std::fs::read"
    ));
    assert!(names_method(
        "let _ = ::std::env::current_dir;",
        "std::env::current_dir"
    ));
    assert!(!names_method(
        "let _ = ::std::fs::read_dir::<String>;",
        "std::fs::read"
    ));
    assert!(!names_method(
        "let _ = ::std::path::Path::exists;",
        "std::fs::exists"
    ));
    assert!(names_type(
        "let _: Option<::std::fs::File> = None;",
        "std::fs::File"
    ));
    assert!(!names_type(
        "let _: Option<::std::fs::FileType> = None;",
        "std::fs::File"
    ));
}
