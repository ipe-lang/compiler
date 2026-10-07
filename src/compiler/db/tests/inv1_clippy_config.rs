#![forbid(unsafe_code)]
//! INV-1 (no hidden inputs): the crate's `clippy.toml` keeps every root ban,
//! adds the filesystem, environment and clock bans, and the proof module names
//! each one.
//!
//! The test reads only through `include_str!`, since the filesystem APIs it
//! guards are banned in this crate's own tests.

const DB_CONFIG: &str = include_str!("../clippy.toml");
const ROOT_CONFIG: &str = include_str!("../../../../clippy.toml");
const PROOF: &str = include_str!("../src/clippy_paths_resolve.rs");

/// The reason every INV-1 entry carries.
const REASON: &str = "INV-1: salsa queries are pure";

/// The marker of a ban entry line in either config.
const ENTRY_PREFIX: &str = "{ path = \"";

/// The `disallowed-types` array header, which ends the methods array.
const TYPES_HEADER: &str = "disallowed-types = [";

/// The expectation each proof line carries, by the lint its entry configures.
const EXPECT_METHOD: &str = "#[expect(clippy::disallowed_methods)]";
const EXPECT_TYPE: &str = "#[expect(clippy::disallowed_types)]";

/// Every path INV-1 bans in `ipe_db`: 35 methods, then 5 types.
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
    "std::env::current_dir",
    "std::env::set_current_dir",
    "std::env::current_exe",
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

/// Whether a banned path is a type: its last segment is capitalised.
fn is_type_path(path: &str) -> bool {
    path.rsplit("::")
        .next()
        .is_some_and(|leaf| leaf.starts_with(|c: char| c.is_ascii_uppercase()))
}

/// Whether `c` can appear in a TOML bare key.
const fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

/// The policy lines of a config: every ban entry and every top-level key line.
fn policy_lines(config: &str) -> Vec<&str> {
    config
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.starts_with(ENTRY_PREFIX)
                || line
                    .split_once(" = ")
                    .is_some_and(|(key, _)| !key.is_empty() && key.chars().all(is_key_char))
        })
        .collect()
}

/// The policy lines of `root` that `own` does not repeat verbatim.
fn missing_from<'a>(root: &'a str, own: &str) -> Vec<&'a str> {
    let kept = policy_lines(own);
    policy_lines(root)
        .into_iter()
        .filter(|line| !kept.contains(line))
        .collect()
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

#[test]
fn the_crate_config_keeps_every_root_policy_line() {
    let root = policy_lines(ROOT_CONFIG);
    let root_entries = root
        .iter()
        .filter(|line| line.starts_with(ENTRY_PREFIX))
        .count();
    assert!(
        root_entries >= 10,
        "the root `clippy.toml` parsed to {root_entries} ban entries; the superset check \
         would pass on nothing"
    );
    assert!(
        root.contains(&"disallowed-methods = ["),
        "the root `clippy.toml` parsed without its `disallowed-methods` key"
    );
    let missing = missing_from(ROOT_CONFIG, DB_CONFIG);
    assert!(
        missing.is_empty(),
        "the crate `clippy.toml` replaces the root file, so it must repeat every root \
         policy line; missing: {missing:?}"
    );
}

#[test]
fn a_dropped_root_line_is_reported_missing() {
    let root = "allow-unwrap-in-tests = true\n\
                disallowed-methods = [\n    { path = \"std::process::abort\", reason = \"a\" },\n]\n";
    let own = "allow-unwrap-in-tests = true\ndisallowed-methods = [\n]\n";
    assert_eq!(
        missing_from(root, own),
        vec!["{ path = \"std::process::abort\", reason = \"a\" },"]
    );
    assert!(missing_from(root, root).is_empty());
    assert!(
        policy_lines("").is_empty(),
        "an empty config parses to nothing"
    );
}

#[test]
fn every_inv1_path_is_banned_and_proved() {
    assert_eq!(
        INV1_PATHS.len(),
        40,
        "INV-1 bans 35 methods and 5 types in `ipe_db`"
    );
    let split = DB_CONFIG.split_once(TYPES_HEADER);
    assert!(
        split.is_some(),
        "the crate `clippy.toml` has no `{TYPES_HEADER}` array"
    );
    let Some((methods_part, types_part)) = split else {
        return;
    };
    let proof_lines: Vec<&str> = PROOF.lines().map(str::trim).collect();
    for path in INV1_PATHS {
        let (array, expect) = kind_of(path);
        let section = if is_type_path(path) {
            types_part
        } else {
            methods_part
        };
        let entry = format!("{{ path = \"{path}\", reason = \"{REASON}\" }},");
        assert!(
            section.lines().any(|line| line.trim() == entry),
            "the crate `clippy.toml` lacks the INV-1 entry for `{path}` in its `{array}` array"
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
        ("disallowed-types", EXPECT_TYPE)
    } else {
        ("disallowed-methods", EXPECT_METHOD)
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
