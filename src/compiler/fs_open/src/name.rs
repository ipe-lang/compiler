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
