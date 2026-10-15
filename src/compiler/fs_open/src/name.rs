//! One plain entry name: the only name a held directory handle opens.

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path};

use crate::OpenRefusal;

/// One plain path component a held directory handle opens relative to itself.
///
/// Never empty, `.`, `..`, or holding a separator or NUL; on Windows also
/// never a name Win32 reads as another entry, a stream, or a device
/// ([`crate::win32_name::is_verbatim_entry_name`]), and always valid Unicode.
/// Every entry act takes one, so an act can name only an entry directly
/// inside the held directory.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EntryName(OsString);

impl EntryName {
    /// The single component `name`, or `None` when it is not one.
    #[must_use]
    pub fn new(name: &OsStr) -> Option<Self> {
        (is_component(name) && platform_admits(name)).then(|| Self(name.to_os_string()))
    }

    /// The single component `name`.
    ///
    /// # Errors
    /// [`OpenRefusal::BadName`] when it is not one.
    pub fn parse(name: &OsStr) -> Result<Self, OpenRefusal> {
        Self::new(name).ok_or(OpenRefusal::BadName)
    }

    /// The name as an OS string.
    #[must_use]
    pub fn as_os_str(&self) -> &OsStr {
        &self.0
    }
}

impl AsRef<OsStr> for EntryName {
    fn as_ref(&self) -> &OsStr {
        &self.0
    }
}

/// Whether `name` reads back as exactly one component that opens as the entry it spells.
///
/// The one rule for a name pushed onto a path a later open resolves by text.
/// Refused: the empty name, `.`, `..`, a separator or NUL, anything
/// [`Path::components`] reads as more or other than one `Normal` component
/// equal to `name` (a root, a Windows prefix such as `C:`), and on Windows
/// every name [`crate::win32_name::opens_as_spelled`] refuses (a trailing `.`
/// or space, a stream `:`, a reserved device) or that is not valid Unicode.
/// Stricter than [`EntryName::new`], whose handle-relative opens never strip a
/// trailing `.` or space. An 8.3 short alias (`PROGRA~1`) passes: it names an
/// entry of the same directory.
#[must_use]
pub fn is_one_spelled_name(name: &OsStr) -> bool {
    let mut parts = Path::new(name).components();
    let single = matches!(
        (parts.next(), parts.next()),
        (Some(Component::Normal(only)), None) if only == name
    );
    single && is_component(name) && opens_as_spelled(name)
}

/// Whether Win32 opens `name` through any path form as exactly the entry it spells.
///
/// A name that is not valid Unicode cannot be checked, so it is refused.
#[cfg(windows)]
fn opens_as_spelled(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(crate::win32_name::opens_as_spelled)
}

/// Every one-component name opens as spelled outside Windows.
#[cfg(not(windows))]
const fn opens_as_spelled(_name: &OsStr) -> bool {
    true
}

/// Whether `name` is one component: not empty, `.`, or `..`, and free of separators and NUL.
fn is_component(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    !bytes.is_empty()
        && bytes != b"."
        && bytes != b".."
        && !bytes
            .iter()
            .any(|&b| b == 0 || std::path::is_separator(char::from(b)))
}

/// Whether Win32 opens `name` relative to a handle as exactly the entry it spells.
///
/// A name that is not valid Unicode cannot be checked, so it is refused.
#[cfg(windows)]
fn platform_admits(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(crate::win32_name::is_verbatim_entry_name)
}

/// Every component is a plain name outside Windows.
#[cfg(not(windows))]
const fn platform_admits(_name: &OsStr) -> bool {
    true
}

/// Whether a case-insensitive volume may open `name` as the entry the ASCII name `spelled` names.
///
/// The one rule for matching a name against a reserved ASCII name. A char of
/// `name` stands for a char of `spelled` when the two are equal in ASCII case,
/// or when its one-char lowercase or uppercase mapping is that char in the
/// same case (`ſ` for `s`, `ı` for `i`, the Kelvin sign for `k`), as
/// Unicode-folding and upcase-table volumes compare names. A code point HFS+
/// ignores (zero-width joiners, direction marks, the byte-order mark) stands
/// for nothing. The match over-reaches on a case-sensitive volume, which only
/// treats a few more exotic names as reserved.
#[must_use]
pub fn may_open_as(name: &OsStr, spelled: &str) -> bool {
    let text = name.to_string_lossy();
    let mut want = spelled.chars();
    for got in text.chars().filter(|got| !hfs_ignorable(*got)) {
        match want.next() {
            Some(want) if stands_for(got, want) => {}
            Some(_) | None => return false,
        }
    }
    want.next().is_none()
}

/// Whether a volume folding case may compare `got` equal to `want`.
fn stands_for(got: char, want: char) -> bool {
    got.eq_ignore_ascii_case(&want)
        || one_char(got.to_lowercase()) == Some(want.to_ascii_lowercase())
        || one_char(got.to_uppercase()) == Some(want.to_ascii_uppercase())
}

/// The sole char of a case mapping, or `None` when it maps to several.
fn one_char(mut mapped: impl Iterator<Item = char>) -> Option<char> {
    match (mapped.next(), mapped.next()) {
        (Some(only), None) => Some(only),
        (Some(_), Some(_)) | (None, _) => None,
    }
}

/// Whether HFS+ drops `c` when it compares names.
const fn hfs_ignorable(c: char) -> bool {
    matches!(
        c,
        '\u{200C}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{206A}'..='\u{206F}' | '\u{FEFF}'
    )
}
