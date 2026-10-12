// The shared HOME-parsing agreement table.
//
// One set of rows, `include!`d verbatim by the tests of both
// `ipe_runtime_rust::system` and `ipe_sandbox::home`, so both home readers are
// driven through identical rows on top of the one shared parser in
// `src/home_core.rs`. `raw` and `expected` are UTF-8 text; each crate pins its
// own non-UTF-8 refusal beside this table.
//
// Every includer sits two modules below the module that holds `home_core`
// (`system::home_dir_tests` in the runtime, `home::tests::shared` in the
// sandbox), so the one `use` below names the shared parser in both.
//
// Regular (`//`) comments, not inner docs (`//!`): this file is `include!`d
// after other items, where an inner doc is an illegal mid-file attribute.

use super::super::home_core::{HOME_VAR, HomeDir, HomeRefusal};

/// Platform-independent `(raw env value, expected home)` rows.
///
/// `None` on the left is unset; `None` on the right names no directory.
const HOME_PARSE_CASES: &[(Option<&str>, Option<&str>)] = &[
    (None, None),
    (Some(""), None),
    (Some("."), None),
    (Some("~"), None),
    (Some("relative/x"), None),
    (Some("home/u"), None),
    (Some("./home"), None),
    (Some("../home"), None),
];

/// Unix `(raw env value, expected home)` rows.
///
/// An absolute value is kept verbatim, trailing separators included; a `..`
/// component or a NUL byte names no directory.
#[cfg(not(windows))]
const HOME_PARSE_PLATFORM_CASES: &[(Option<&str>, Option<&str>)] = &[
    (Some("/home/u"), Some("/home/u")),
    (Some("/home/u/"), Some("/home/u/")),
    (Some("/home/../home"), None),
    (Some("/home/u/../v"), None),
    (Some("/home/u\0x"), None),
    (Some(" /home/u"), None),
    (Some(r"C:\Users\u"), None),
];

/// Windows `(raw env value, expected home)` rows.
///
/// Root-relative and drive-relative values are not absolute; a UNC path names
/// a network share, not a local profile.
#[cfg(windows)]
const HOME_PARSE_PLATFORM_CASES: &[(Option<&str>, Option<&str>)] = &[
    (Some(r"C:\Users\u"), Some(r"C:\Users\u")),
    (Some(r"\\srv\share\u"), None),
    (Some(r"C:\Users\..\u"), None),
    (Some("C:\\Users\\u\0"), None),
    (Some(r"\Users\u"), None),
    (Some(r"C:Users\u"), None),
    (Some("/home/u"), None),
    // Verbatim / device-namespace prefixes: `Path::is_absolute` accepts them,
    // but they name a raw device or an unparsed literal path, not a directory.
    (Some(r"\\?\C:\Users\u"), None),
    (Some(r"\\.\pipe\x"), None),
    (Some(r"\\?\UNC\srv\s"), None),
];

/// Platform-independent `(raw env value, refusal)` rows.
const HOME_REFUSAL_CASES: &[(Option<&str>, HomeRefusal)] = &[
    (None, HomeRefusal::Unset),
    (Some(""), HomeRefusal::NotAbsolute),
    (Some("relative/x"), HomeRefusal::NotAbsolute),
    (Some("../home"), HomeRefusal::NotAbsolute),
    (Some("/home/u\0x"), HomeRefusal::ContainsNul),
];

/// Unix `(raw env value, refusal)` rows.
#[cfg(not(windows))]
const HOME_REFUSAL_PLATFORM_CASES: &[(Option<&str>, HomeRefusal)] = &[
    (Some("/home/u/../v"), HomeRefusal::ParentComponent),
    (Some("/home/../home"), HomeRefusal::ParentComponent),
];

/// Windows `(raw env value, refusal)` rows.
#[cfg(windows)]
const HOME_REFUSAL_PLATFORM_CASES: &[(Option<&str>, HomeRefusal)] = &[
    (Some(r"C:\Users\..\u"), HomeRefusal::ParentComponent),
    (Some("C:\\Users\\u\0"), HomeRefusal::ContainsNul),
    (Some(r"\\srv\share\u"), HomeRefusal::WindowsUnc),
    (
        Some(r"\\?\C:\Users\u"),
        HomeRefusal::WindowsDeviceOrVerbatim,
    ),
    (Some(r"\\.\pipe\x"), HomeRefusal::WindowsDeviceOrVerbatim),
    (Some(r"\\?\UNC\srv\s"), HomeRefusal::WindowsDeviceOrVerbatim),
];

/// Each refused row earns exactly its refusal, whose message names the home
/// variable and a reason no other refusal shares.
#[test]
fn every_refusal_names_its_reason() {
    let prefix = format!("`{HOME_VAR}` ");
    let mut phrases = Vec::new();
    for (raw, expected) in HOME_REFUSAL_CASES.iter().chain(HOME_REFUSAL_PLATFORM_CASES) {
        assert_eq!(
            HomeDir::try_parse(raw.map(std::ffi::OsString::from)),
            Err(*expected),
            "{raw:?}"
        );
        let phrase = expected.to_string();
        assert!(
            phrase.len() > prefix.len() && phrase.starts_with(&prefix),
            "{phrase:?}"
        );
        phrases.push((*expected, phrase));
    }
    for (refusal, phrase) in &phrases {
        assert!(
            phrases
                .iter()
                .all(|(other, other_phrase)| other == refusal || other_phrase != phrase),
            "{refusal:?} shares its message: {phrase:?}"
        );
    }
}
