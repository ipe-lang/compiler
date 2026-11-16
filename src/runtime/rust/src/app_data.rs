//! The desktop shell's storage location: one parsed key under one parsed root.
//!
//! A shell's webview keeps its cookies, `localStorage` and caches in a
//! directory that is a total function of a [`StorageKey`] (the app's bundle
//! id) and an [`AppDataRoot`] (the OS user's app-data directory). Every step
//! on the way is a typed refusal raised before any window opens; no shared or
//! default profile has a representation here.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::home_core::{HomeDir, HomeRefusal};
use crate::path_core::{ChildElement, ElementRefusal, Regime};
use crate::scratch_core::{PrivateDirError, ScratchRefusal, private_dir_under};

/// The longest bundle identifier, in bytes, any shell admits.
pub const MAX_BUNDLE_ID_LEN: usize = 128;

/// The directory under a key's own directory the webview engine writes into.
const WEBVIEW_LEAF: &str = "webview";

/// A bundle id proven to name exactly one directory on every OS.
///
/// Folded to ASCII lowercase, so two ids differing only in case are one key
/// on case-sensitive and case-insensitive file systems alike.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageKey(String);

/// Why a text is not a [`StorageKey`]; no variant carries the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageKeyRefusal {
    /// The text is empty.
    Empty,
    /// The text is longer than [`MAX_BUNDLE_ID_LEN`] bytes.
    TooLong,
    /// A byte outside ASCII letters, digits and `.`.
    Byte,
    /// Two `.` in a row, or a leading or trailing `.`.
    EmptyLabel,
    /// Fewer than two labels.
    OneLabel,
    /// The key is not a plain file name under one of the path regimes.
    Element(ElementRefusal),
    /// The key is a path token (`.`) rather than a name.
    NotAName,
}

impl fmt::Display for StorageKeyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the storage key is empty"),
            Self::TooLong => write!(
                f,
                "the storage key is longer than {MAX_BUNDLE_ID_LEN} bytes"
            ),
            Self::Byte => {
                f.write_str("the storage key holds a byte outside letters, digits and `.`")
            }
            Self::EmptyLabel => f.write_str("the storage key has an empty label"),
            Self::OneLabel => f.write_str("the storage key has fewer than two labels"),
            Self::Element(_) | Self::NotAName => {
                f.write_str("the storage key is not a plain file name on every OS")
            }
        }
    }
}

impl StorageKey {
    /// Parse `text` into a storage key.
    ///
    /// # Errors
    /// In judging order: `Empty`, `TooLong`, `Byte`, `EmptyLabel`,
    /// `OneLabel`, then the first refusal of the Unix and the Windows element
    /// grammars, which turns back DOS device names with any extension.
    pub fn parse(text: &str) -> Result<Self, StorageKeyRefusal> {
        if text.is_empty() {
            return Err(StorageKeyRefusal::Empty);
        }
        if text.len() > MAX_BUNDLE_ID_LEN {
            return Err(StorageKeyRefusal::TooLong);
        }
        let folded = text.to_ascii_lowercase();
        if !folded
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.')
        {
            return Err(StorageKeyRefusal::Byte);
        }
        if folded.split('.').any(str::is_empty) {
            return Err(StorageKeyRefusal::EmptyLabel);
        }
        if folded.split('.').nth(1).is_none() {
            return Err(StorageKeyRefusal::OneLabel);
        }
        for regime in [Regime::Unix, Regime::Windows] {
            match ChildElement::parse(folded.as_bytes(), regime) {
                Ok(ChildElement::Name) => {}
                Ok(ChildElement::Empty | ChildElement::Current) => {
                    return Err(StorageKeyRefusal::NotAName);
                }
                Err(refusal) => return Err(StorageKeyRefusal::Element(refusal)),
            }
        }
        Ok(Self(folded))
    }
}

impl std::ops::Deref for StorageKey {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

/// The OS whose app-data convention a root follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppDataOs {
    /// Linux and every other Unix: the XDG data home.
    Unix,
    /// macOS: the engine's own store, keyed by the `.app` bundle identifier.
    MacOs,
    /// Windows: the local (never roaming) app-data directory.
    Windows,
}

impl AppDataOs {
    /// The OS this runtime was built for.
    pub const HOST: Self = if cfg!(target_os = "macos") {
        Self::MacOs
    } else if cfg!(windows) {
        Self::Windows
    } else {
        Self::Unix
    };
}

/// The variable an app-data root was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppDataVar {
    /// `XDG_DATA_HOME`.
    XdgDataHome,
    /// `HOME`, for the `$HOME/.local/share` fallback.
    Home,
    /// `LOCALAPPDATA`.
    LocalAppData,
}

impl AppDataVar {
    /// The variable's name; `None` for the home variable, which the home
    /// refusal names itself.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        match self {
            Self::XdgDataHome => Some("XDG_DATA_HOME"),
            Self::Home => None,
            Self::LocalAppData => Some("LOCALAPPDATA"),
        }
    }
}

/// Why no app-data root could be read: the variable and its refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppDataRefusal {
    /// The variable read.
    pub var: AppDataVar,
    /// Why its value names no root.
    pub refusal: HomeRefusal,
}

impl fmt::Display for AppDataRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.var.name() {
            Some(name) => write!(f, "`{name}` {}", self.refusal.reason()),
            None => write!(f, "{}", self.refusal),
        }
    }
}

/// Where the OS user's app data lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppDataRoot {
    /// A verified absolute directory the shell creates its key under.
    Dir(PathBuf),
    /// The engine's own store, which the OS keys by the app's bundle identifier.
    BundleStore,
}

impl AppDataRoot {
    /// Read the root of `os` from raw variable values.
    ///
    /// On Unix a set, non-empty `xdg_data_home` is the root and is refused,
    /// never skipped, when it is relative or holds `..`, NUL or non-UTF-8; an
    /// empty one counts as unset, and then `home` names `$HOME/.local/share`.
    /// On Windows `local_app_data` is required.
    ///
    /// # Errors
    /// The [`AppDataRefusal`] of the variable read.
    pub fn from_vars(
        os: AppDataOs,
        xdg_data_home: Option<OsString>,
        home: Option<OsString>,
        local_app_data: Option<OsString>,
    ) -> Result<Self, AppDataRefusal> {
        Self::from_parts(
            os,
            xdg_data_home,
            || HomeDir::try_parse(home),
            local_app_data,
        )
    }

    /// [`Self::from_vars`] with the home directory read only when it is the root.
    fn from_parts(
        os: AppDataOs,
        xdg_data_home: Option<OsString>,
        home: impl FnOnce() -> Result<HomeDir, HomeRefusal>,
        local_app_data: Option<OsString>,
    ) -> Result<Self, AppDataRefusal> {
        let parse = |var: AppDataVar, raw: Option<OsString>| {
            HomeDir::try_parse(raw).map_err(|refusal| AppDataRefusal { var, refusal })
        };
        match os {
            AppDataOs::MacOs => Ok(Self::BundleStore),
            AppDataOs::Windows => parse(AppDataVar::LocalAppData, local_app_data)
                .map(|dir| Self::Dir(dir.as_path().to_path_buf())),
            AppDataOs::Unix => match xdg_data_home.filter(|raw| !raw.is_empty()) {
                Some(raw) => parse(AppDataVar::XdgDataHome, Some(raw))
                    .map(|dir| Self::Dir(dir.as_path().to_path_buf())),
                None => home()
                    .map_err(|refusal| AppDataRefusal {
                        var: AppDataVar::Home,
                        refusal,
                    })
                    .map(|dir| Self::Dir(dir.join(".local/share"))),
            },
        }
    }

    /// Read the root of this host from the process environment.
    ///
    /// # Errors
    /// The [`AppDataRefusal`] of the variable read.
    #[cfg(feature = "webview-shell")]
    pub fn from_env() -> Result<Self, AppDataRefusal> {
        use crate::system::read_env_var_os;
        Self::from_parts(
            AppDataOs::HOST,
            read_env_var_os("XDG_DATA_HOME"),
            crate::system::home_dir,
            read_env_var_os("LOCALAPPDATA"),
        )
    }
}

/// A webview data directory proven private to the OS user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateDataDir(PathBuf);

/// The storage a shell's webview context is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoragePlan {
    /// The key's own private directory.
    Private(PrivateDataDir),
    /// The engine's own store, keyed by the app's bundle identifier.
    BundleStore,
}

/// Why the shell has no storage to start with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageRefusal {
    /// No app-data root could be read.
    Root(AppDataRefusal),
    /// The bundle id is no storage key.
    Key(StorageKeyRefusal),
    /// Creating a directory failed.
    Create(std::io::ErrorKind),
    /// A directory on the way is not private to the OS user.
    NotPrivate(ScratchRefusal),
    /// The directory's path is not UTF-8, which the engine would rewrite.
    NotUtf8,
}

impl fmt::Display for StorageRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root(refusal) => write!(f, "no app-data directory: {refusal}"),
            Self::Key(refusal) => write!(f, "{refusal}"),
            Self::Create(kind) => write!(f, "the app-data directory could not be created ({kind})"),
            Self::NotPrivate(refusal) => write!(f, "the app-data directory is {refusal}"),
            Self::NotUtf8 => f.write_str("the app-data directory path is not UTF-8"),
        }
    }
}

impl PrivateDataDir {
    /// Create `<root>/<key>/webview`, every created directory private to the OS user.
    ///
    /// # Errors
    /// `Create` when a directory cannot be made, `NotPrivate` when one on the
    /// way is a symlink, foreign-owned or open to others, and `NotUtf8` when
    /// the path is not UTF-8.
    pub fn ensure(root: &Path, key: &StorageKey) -> Result<Self, StorageRefusal> {
        let dir = private_dir_under(root, &[key, WEBVIEW_LEAF]).map_err(|e| match e {
            PrivateDirError::Io(kind) => StorageRefusal::Create(kind),
            PrivateDirError::NotPrivate(refusal) => StorageRefusal::NotPrivate(refusal),
        })?;
        if dir.to_str().is_none() {
            return Err(StorageRefusal::NotUtf8);
        }
        Ok(Self(dir))
    }

    /// The proven directory.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl StoragePlan {
    /// Resolve the storage of `key` under `root`.
    ///
    /// # Errors
    /// The [`StorageRefusal`] of [`PrivateDataDir::ensure`].
    pub fn resolve(root: &AppDataRoot, key: &StorageKey) -> Result<Self, StorageRefusal> {
        match root {
            AppDataRoot::BundleStore => Ok(Self::BundleStore),
            AppDataRoot::Dir(dir) => PrivateDataDir::ensure(dir, key).map(Self::Private),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn os(text: &str) -> Option<OsString> {
        Some(OsString::from(text))
    }

    /// A fresh directory under the test temp root, unique to this test.
    #[allow(clippy::expect_used)] // a test directory the test cannot create is a test failure
    fn fresh_dir(tag: &str) -> PathBuf {
        let dir = crate::scratch_core::test_temp_root().join(format!(
            "ipe-app-data-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    #[test]
    fn storage_key_refuses_traversal_and_device_names() {
        for (text, refusal) in [
            ("", StorageKeyRefusal::Empty),
            ("..", StorageKeyRefusal::EmptyLabel),
            (".", StorageKeyRefusal::EmptyLabel),
            ("a..b", StorageKeyRefusal::EmptyLabel),
            (".acme.app", StorageKeyRefusal::EmptyLabel),
            ("acme.app.", StorageKeyRefusal::EmptyLabel),
            ("acme", StorageKeyRefusal::OneLabel),
            ("a/b.c", StorageKeyRefusal::Byte),
            ("a\\b.c", StorageKeyRefusal::Byte),
            ("a:b.c", StorageKeyRefusal::Byte),
            ("a b.c", StorageKeyRefusal::Byte),
            ("a\0b.c", StorageKeyRefusal::Byte),
            ("acme.\u{e9}t\u{e9}", StorageKeyRefusal::Byte),
            (
                "con.acme",
                StorageKeyRefusal::Element(ElementRefusal::DosDevice),
            ),
            (
                "nul.x",
                StorageKeyRefusal::Element(ElementRefusal::DosDevice),
            ),
            (
                "com1.y",
                StorageKeyRefusal::Element(ElementRefusal::DosDevice),
            ),
            (
                "LPT9.app",
                StorageKeyRefusal::Element(ElementRefusal::DosDevice),
            ),
        ] {
            assert_eq!(StorageKey::parse(text), Err(refusal), "{text:?}");
        }
        let long = format!("a.{}", "b".repeat(MAX_BUNDLE_ID_LEN - 1));
        assert_eq!(StorageKey::parse(&long), Err(StorageKeyRefusal::TooLong));
        let at = format!("a.{}", "b".repeat(MAX_BUNDLE_ID_LEN - 2));
        assert!(StorageKey::parse(&at).is_ok());
        assert!(StorageKey::parse("com.acme.notes").is_ok());
        assert!(StorageKey::parse("console.acme").is_ok());
    }

    #[test]
    fn storage_key_folds_ascii_case() {
        let upper = StorageKey::parse("Com.Acme.Notes");
        let lower = StorageKey::parse("com.acme.notes");
        assert_eq!(upper, lower);
        assert_eq!(upper.as_deref().ok(), Some("com.acme.notes"));
    }

    #[test]
    fn app_data_root_refuses_a_relative_or_unc_root() {
        let xdg = |raw: Option<OsString>| {
            AppDataRoot::from_vars(AppDataOs::Unix, raw, os("/home/u"), None)
        };
        for (raw, refusal) in [
            ("data", HomeRefusal::NotAbsolute),
            ("./data", HomeRefusal::NotAbsolute),
            ("/home/u/../v", HomeRefusal::ParentComponent),
            ("/home/u\0/x", HomeRefusal::ContainsNul),
        ] {
            assert_eq!(
                xdg(os(raw)),
                Err(AppDataRefusal {
                    var: AppDataVar::XdgDataHome,
                    refusal
                }),
                "{raw:?}"
            );
        }
        let unc = if cfg!(windows) {
            HomeRefusal::WindowsUnc
        } else {
            HomeRefusal::NotAbsolute
        };
        assert_eq!(
            AppDataRoot::from_vars(AppDataOs::Windows, None, None, os(r"\\srv\share\data")),
            Err(AppDataRefusal {
                var: AppDataVar::LocalAppData,
                refusal: unc
            })
        );
        assert_eq!(
            AppDataRoot::from_vars(AppDataOs::Windows, os("/x"), os("/home/u"), None),
            Err(AppDataRefusal {
                var: AppDataVar::LocalAppData,
                refusal: HomeRefusal::Unset
            })
        );
        assert_eq!(
            AppDataRoot::from_vars(AppDataOs::Unix, None, None, None),
            Err(AppDataRefusal {
                var: AppDataVar::Home,
                refusal: HomeRefusal::Unset
            })
        );
        assert_eq!(
            AppDataRoot::from_vars(AppDataOs::MacOs, os("data"), None, None),
            Ok(AppDataRoot::BundleStore)
        );
        assert_eq!(
            AppDataRefusal {
                var: AppDataVar::XdgDataHome,
                refusal: HomeRefusal::NotAbsolute
            }
            .to_string(),
            "`XDG_DATA_HOME` is not an absolute path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn app_data_root_refuses_a_non_utf8_xdg_root() {
        use std::os::unix::ffi::OsStringExt as _;
        let raw = OsString::from_vec(b"/home/\xff".to_vec());
        assert_eq!(
            AppDataRoot::from_vars(AppDataOs::Unix, Some(raw), os("/home/u"), None),
            Err(AppDataRefusal {
                var: AppDataVar::XdgDataHome,
                refusal: HomeRefusal::NotUtf8
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn app_data_root_empty_xdg_means_unset() {
        assert_eq!(
            AppDataRoot::from_vars(AppDataOs::Unix, os(""), os("/home/u"), None),
            Ok(AppDataRoot::Dir(PathBuf::from("/home/u/.local/share")))
        );
        assert_eq!(
            AppDataRoot::from_vars(AppDataOs::Unix, None, os("/home/u"), None),
            Ok(AppDataRoot::Dir(PathBuf::from("/home/u/.local/share")))
        );
        assert_eq!(
            AppDataRoot::from_vars(AppDataOs::Unix, os("/data"), os("/home/u"), None),
            Ok(AppDataRoot::Dir(PathBuf::from("/data")))
        );
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // a fixture the test cannot plant is a test failure
    fn private_data_dir_refuses_a_symlinked_or_foreign_leaf() {
        use std::os::unix::fs::PermissionsExt as _;
        let Ok(key) = StorageKey::parse("com.acme.notes") else {
            return;
        };
        let root = fresh_dir("symlink");
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("create target");
        std::os::unix::fs::symlink(&elsewhere, root.join("com.acme.notes")).expect("plant link");
        assert_eq!(
            PrivateDataDir::ensure(&root, &key),
            Err(StorageRefusal::NotPrivate(ScratchRefusal::NotADirectory))
        );

        let open = fresh_dir("open");
        let key_dir = open.join("com.acme.notes");
        std::fs::create_dir(&key_dir).expect("create key dir");
        std::fs::set_permissions(&key_dir, std::fs::Permissions::from_mode(0o755))
            .expect("open the key dir");
        assert_eq!(
            PrivateDataDir::ensure(&open, &key),
            Err(StorageRefusal::NotPrivate(ScratchRefusal::NotPrivate))
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&open);
    }

    #[cfg(unix)]
    #[test]
    fn private_data_dir_creates_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let Ok(key) = StorageKey::parse("com.acme.notes") else {
            return;
        };
        let root = fresh_dir("owner");
        let made = PrivateDataDir::ensure(&root, &key);
        let Ok(dir) = made else {
            assert!(made.is_ok(), "{made:?}");
            return;
        };
        assert_eq!(dir.as_path(), root.join("com.acme.notes").join("webview"));
        for path in [root.join("com.acme.notes"), dir.as_path().to_path_buf()] {
            let mode = std::fs::symlink_metadata(&path).map(|m| m.permissions().mode() & 0o777);
            assert_eq!(mode.ok(), Some(0o700), "{}", path.display());
        }
        assert_eq!(PrivateDataDir::ensure(&root, &key), Ok(dir));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn two_keys_never_share_a_dir() {
        let root = fresh_dir("two");
        let keys = ["com.acme.notes", "com.acme.note", "com.acme.notes2"]
            .map(|text| StorageKey::parse(text).ok());
        let dirs: Vec<Option<PathBuf>> = keys
            .iter()
            .map(|key| {
                key.as_ref()
                    .and_then(|key| PrivateDataDir::ensure(&root, key).ok())
                    .map(|dir| dir.as_path().to_path_buf())
            })
            .collect();
        assert!(dirs.iter().all(Option::is_some), "{dirs:?}");
        for (i, a) in dirs.iter().enumerate() {
            for b in dirs.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
