// The single source of truth for which variable names the invoking user's home
// directory and how its raw value parses into a `HomeDir`.
//
// Both the runtime's `system::home_dir` and the compiler sandbox's
// `ipe_sandbox::home::home_dir` resolve the home through `HomeDir::try_parse`,
// the ONE constructor for the type, so the two cannot disagree on the variable
// (per OS), on the UTF-8 decode, or on which values name a directory. The file
// is std-only: the runtime references it as a sibling module
// (`super::home_core`), so it vendors with `mod ipe_runtime` into every emitted
// app, and the sandbox `include!`s this exact file because the runtime cannot
// depend on the compiler.
//
// Regular (`//`) comments, not inner docs (`//!`): this file is `include!`d
// verbatim into a sandbox module, where an inner doc after the `include!` item
// is an illegal mid-file inner attribute.

/// The variable naming the invoking user's profile directory on Windows.
pub const WINDOWS_HOME_VAR: &str = "USERPROFILE";

/// The platform variable naming the invoking user's home directory.
#[cfg(windows)]
pub const HOME_VAR: &str = WINDOWS_HOME_VAR;

/// The platform variable naming the invoking user's home directory.
#[cfg(not(windows))]
pub const HOME_VAR: &str = "HOME";

/// A verified home directory: absolute, UTF-8, free of NUL and `..`.
///
/// On Windows it also carries no verbatim, device-namespace or UNC prefix.
/// [`HomeDir::try_parse`] is the only constructor, so every holder already
/// knows its path names a local directory rather than re-deriving that
/// judgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeDir(std::path::PathBuf);

/// Why a raw home value is not a [`HomeDir`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeRefusal {
    /// The variable is unset.
    Unset,
    /// The value is not valid UTF-8.
    NotUtf8,
    /// The value holds a NUL byte, which no OS path can carry.
    ContainsNul,
    /// The value is relative or empty, so it would resolve against the working
    /// directory.
    NotAbsolute,
    /// The value has a `..` component, so its spelling is not the directory it
    /// names.
    ParentComponent,
    /// A Windows verbatim (`\\?\...`) or device-namespace (`\\.\...`) prefix.
    ///
    /// It names a raw device or an unparsed literal path, not a directory.
    WindowsDeviceOrVerbatim,
    /// A Windows UNC (`\\server\share\...`) prefix.
    ///
    /// It names a network share whose access the remote server controls, not a
    /// local profile.
    WindowsUnc,
}

impl std::fmt::Display for HomeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            Self::Unset => "is unset",
            Self::NotUtf8 => "is not valid UTF-8",
            Self::ContainsNul => "contains a NUL byte",
            Self::NotAbsolute => "is not an absolute path",
            Self::ParentComponent => "contains a `..` component",
            Self::WindowsDeviceOrVerbatim => "is a Windows device or verbatim path",
            Self::WindowsUnc => "is a network (UNC) path",
        };
        write!(f, "`{HOME_VAR}` {reason}")
    }
}

impl std::error::Error for HomeRefusal {}

impl HomeDir {
    /// Parse a raw home value into a `HomeDir`, or say why it names none.
    ///
    /// The checks run in a fixed order, so each value earns one refusal: unset,
    /// then the one UTF-8 decode, then NUL, absoluteness, `..`, and on Windows
    /// the prefix. An accepted value is kept verbatim (no normalisation), so
    /// every consumer sees the same path.
    ///
    /// # Errors
    /// The first [`HomeRefusal`] the value meets.
    pub fn try_parse(raw: Option<std::ffi::OsString>) -> Result<Self, HomeRefusal> {
        let text = raw
            .ok_or(HomeRefusal::Unset)?
            .into_string()
            .ok()
            .ok_or(HomeRefusal::NotUtf8)?;
        if text.contains('\0') {
            return Err(HomeRefusal::ContainsNul);
        }
        let path = std::path::PathBuf::from(text);
        if !path.is_absolute() {
            return Err(HomeRefusal::NotAbsolute);
        }
        if path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(HomeRefusal::ParentComponent);
        }
        #[cfg(windows)]
        if let Some(refusal) = windows_prefix_refusal(&path) {
            return Err(refusal);
        }
        Ok(Self(path))
    }

    /// The verified path.
    #[must_use]
    pub fn as_path(&self) -> &std::path::Path {
        &self.0
    }

    /// The path `tail` names beneath this home.
    ///
    /// Only a literal tail is accepted, so no runtime-computed absolute value
    /// can stand in for the home.
    #[must_use]
    pub fn join(&self, tail: &'static str) -> std::path::PathBuf {
        self.0.join(tail)
    }
}

/// The refusal a Windows path prefix earns, if any.
///
/// A verbatim or device-namespace prefix (`\\?\...`, `\\.\...`,
/// `\\?\UNC\...`) names a raw device or an unparsed literal path, and a UNC
/// prefix (`\\server\share\...`) names a network share, even though
/// `Path::is_absolute` accepts every one of them. Only a plain drive
/// (`C:\...`) names a local directory.
#[cfg(windows)]
fn windows_prefix_refusal(path: &std::path::Path) -> Option<HomeRefusal> {
    use std::path::{Component, Prefix};
    let Some(Component::Prefix(prefix)) = path.components().next() else {
        return None;
    };
    match prefix.kind() {
        Prefix::Verbatim(_)
        | Prefix::VerbatimUNC(_, _)
        | Prefix::VerbatimDisk(_)
        | Prefix::DeviceNS(_) => Some(HomeRefusal::WindowsDeviceOrVerbatim),
        Prefix::UNC(_, _) => Some(HomeRefusal::WindowsUnc),
        Prefix::Disk(_) => None,
    }
}
