//! The one acceptance rule for a Windows path prefix that may hold output or a held root.
//!
//! A prefix names a place on a disk or a share only when it is a drive letter
//! or a `\\server\share` whose server and share are well formed. A device
//! namespace (`\\.\pipe`), any other verbatim root (`\\?\GLOBALROOT`,
//! `\\?\Volume{..}`), and a share Win32 would open as another name are
//! refused, each with its own [`PrefixRefusal`]. The rule is pure over
//! [`Prefix`] values, so it is decided, and tested, identically on every
//! platform.
//!
//! The runtime's `path_core::Volume` is a second grammar for program input in
//! a crate graph this one does not reach; its UNC refusal cases are mirrored
//! by this module's tests, and this module's by its.

use std::ffi::OsStr;
use std::net::Ipv4Addr;
use std::path::Prefix;

use crate::win32_name::opens_as_spelled;

/// The most bytes a server host name may hold.
const MAX_HOST_BYTES: usize = 253;
/// The most bytes one label of a server host name may hold.
const MAX_LABEL_BYTES: usize = 63;

/// A Windows path prefix proven to name a place on a disk or a share.
///
/// Built only by [`PlaceablePrefix::parse`]. It is a value for the proof, not
/// a path builder: a caller keeps the prefix as spelled, so the path it
/// proves is the path a held handle later opens.
#[derive(Debug, Clone)]
pub enum PlaceablePrefix {
    /// A drive: `C:` or `\\?\C:`.
    Disk(DriveLetter),
    /// A share: `\\server\share` or `\\?\UNC\server\share`.
    Share {
        /// The server the share lives on.
        server: ServerName,
        /// The share on that server.
        share: ShareName,
    },
}

/// A drive letter, upper-cased once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriveLetter(u8);

impl DriveLetter {
    /// The drive letter `byte`, upper-cased; `None` for a byte that is not an ASCII letter.
    #[must_use]
    pub const fn new(byte: u8) -> Option<Self> {
        if byte.is_ascii_alphabetic() {
            Some(Self(byte.to_ascii_uppercase()))
        } else {
            None
        }
    }

    /// The upper-case letter.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// A share's server: a dotted IPv4 address or an ASCII host name.
#[derive(Debug, Clone)]
pub struct ServerName(Box<str>);

impl ServerName {
    /// The server as spelled.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A share name Win32 opens as exactly the share it spells.
#[derive(Debug, Clone)]
pub struct ShareName(Box<str>);

impl ShareName {
    /// The share as spelled.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why a prefix names no place output may live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixRefusal {
    /// A verbatim root other than a drive or a share (`\\?\GLOBALROOT`, `\\?\Volume{..}`).
    Verbatim,
    /// A device namespace (`\\.\pipe`, `\\.\C:`).
    Device,
    /// A drive prefix whose letter is not an ASCII letter.
    BadDrive,
    /// A share prefix with an empty share name.
    EmptyShare,
    /// A server that is neither a dotted IPv4 address nor an ASCII host name.
    BadServer,
    /// A share name Win32 would open as another name or a device.
    BadShare,
    /// A server or share that is not valid Unicode.
    NotUnicode,
}

impl PlaceablePrefix {
    /// The placeable form of `prefix`.
    ///
    /// # Errors
    /// The [`PrefixRefusal`] naming why `prefix` holds no output.
    pub fn parse(prefix: Prefix<'_>) -> Result<Self, PrefixRefusal> {
        match prefix {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => DriveLetter::new(letter)
                .map(Self::Disk)
                .ok_or(PrefixRefusal::BadDrive),
            Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
                let server = server_name(server)?;
                let share = share_name(share)?;
                Ok(Self::Share { server, share })
            }
            Prefix::Verbatim(_) => Err(PrefixRefusal::Verbatim),
            Prefix::DeviceNS(_) => Err(PrefixRefusal::Device),
        }
    }
}

/// The server `raw`, when it is a dotted IPv4 address or an ASCII host name.
fn server_name(raw: &OsStr) -> Result<ServerName, PrefixRefusal> {
    let text = raw.to_str().ok_or(PrefixRefusal::NotUnicode)?;
    if text.parse::<Ipv4Addr>().is_ok() || is_host_name(text) {
        Ok(ServerName(text.into()))
    } else {
        Err(PrefixRefusal::BadServer)
    }
}

/// Whether `text` is a host name: dot-separated labels of ASCII letters, digits, and inner hyphens.
fn is_host_name(text: &str) -> bool {
    (1..=MAX_HOST_BYTES).contains(&text.len()) && text.split('.').all(is_host_label)
}

/// Whether `label` is one host-name label.
fn is_host_label(label: &str) -> bool {
    (1..=MAX_LABEL_BYTES).contains(&label.len())
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// The share `raw`, when Win32 opens it as exactly the share it spells.
fn share_name(raw: &OsStr) -> Result<ShareName, PrefixRefusal> {
    if raw.is_empty() {
        return Err(PrefixRefusal::EmptyShare);
    }
    let text = raw.to_str().ok_or(PrefixRefusal::NotUnicode)?;
    if text != "." && text != ".." && opens_as_spelled(text) {
        Ok(ShareName(text.into()))
    } else {
        Err(PrefixRefusal::BadShare)
    }
}

#[cfg(test)]
mod tests {
    //! The UNC cases mirror the runtime's `path_core` volume tests, which mirror these.

    use std::ffi::OsStr;
    use std::path::Prefix;

    use super::{PlaceablePrefix, PrefixRefusal};

    /// The acceptance of the share prefix `\\server\share`.
    fn unc(server: &str, share: &str) -> Result<PlaceablePrefix, PrefixRefusal> {
        PlaceablePrefix::parse(Prefix::UNC(OsStr::new(server), OsStr::new(share)))
    }

    /// The acceptance of the share prefix `\\?\UNC\server\share`.
    fn verbatim_unc(server: &str, share: &str) -> Result<PlaceablePrefix, PrefixRefusal> {
        PlaceablePrefix::parse(Prefix::VerbatimUNC(OsStr::new(server), OsStr::new(share)))
    }

    /// The refusal of `result`, `None` when it was accepted.
    fn refusal(result: &Result<PlaceablePrefix, PrefixRefusal>) -> Option<PrefixRefusal> {
        result.as_ref().err().copied()
    }

    #[test]
    fn a_verbatim_unc_dotdot_server_is_refused() {
        for server in ["..", "."] {
            let result = verbatim_unc(server, "x");
            assert_eq!(
                refusal(&result),
                Some(PrefixRefusal::BadServer),
                "\\\\?\\UNC\\{server}\\x must be refused, got {result:?}"
            );
        }
    }

    #[test]
    fn a_device_share_is_refused() {
        for share in ["con", "CON", "nul.txt", "COM1", "lpt9.log"] {
            for result in [unc("srv", share), verbatim_unc("srv", share)] {
                assert_eq!(
                    refusal(&result),
                    Some(PrefixRefusal::BadShare),
                    "share {share:?} must be refused, got {result:?}"
                );
            }
        }
    }

    #[test]
    fn an_empty_share_is_refused() {
        for result in [unc("srv", ""), verbatim_unc("srv", "")] {
            assert_eq!(
                refusal(&result),
                Some(PrefixRefusal::EmptyShare),
                "an empty share must be refused, got {result:?}"
            );
        }
    }

    #[test]
    fn a_share_win32_rewrites_is_refused() {
        for share in ["x.", "x ", ".", "..", "a:b", "a*b", "a?b", "a\u{1}b"] {
            let result = unc("srv", share);
            assert_eq!(
                refusal(&result),
                Some(PrefixRefusal::BadShare),
                "share {share:?} must be refused, got {result:?}"
            );
        }
    }

    #[test]
    fn a_bad_server_is_refused() {
        let long_label = "a".repeat(64);
        let long_host = ["a"; 128].join(".");
        for server in [
            "",
            ".",
            "..",
            "?",
            "-a",
            "a-",
            "a..b",
            "srv.",
            "a_b",
            "a b",
            "wsl$",
            "srv@SSL",
            "::1",
            "h\u{e9}llo",
            long_label.as_str(),
            long_host.as_str(),
        ] {
            let result = unc(server, "share");
            assert_eq!(
                refusal(&result),
                Some(PrefixRefusal::BadServer),
                "server {server:?} must be refused, got {result:?}"
            );
        }
    }

    #[test]
    fn a_device_or_verbatim_prefix_is_refused() {
        for (prefix, expected) in [
            (Prefix::DeviceNS(OsStr::new("pipe")), PrefixRefusal::Device),
            (Prefix::DeviceNS(OsStr::new("C:")), PrefixRefusal::Device),
            (
                Prefix::Verbatim(OsStr::new("Volume{00000000-0000-0000-0000-000000000000}")),
                PrefixRefusal::Verbatim,
            ),
            (
                Prefix::Verbatim(OsStr::new("GLOBALROOT")),
                PrefixRefusal::Verbatim,
            ),
            (Prefix::Disk(b'1'), PrefixRefusal::BadDrive),
            (Prefix::VerbatimDisk(b':'), PrefixRefusal::BadDrive),
        ] {
            let result = PlaceablePrefix::parse(prefix);
            assert_eq!(
                refusal(&result),
                Some(expected),
                "{prefix:?} must be refused, got {result:?}"
            );
        }
    }

    /// A share Win32 opens as spelled, on a well-formed server, is placeable.
    #[test]
    fn a_well_formed_share_is_placeable() {
        let max_label = "a".repeat(63);
        let max_host = ["a"; 127].join(".");
        assert_eq!(
            max_host.len(),
            253,
            "the host fixture sits at the byte ceiling"
        );
        for (result, server, share) in [
            (unc("localhost", "C$"), "localhost", "C$"),
            (unc("10.0.0.1", "build"), "10.0.0.1", "build"),
            (verbatim_unc("srv", "out"), "srv", "out"),
            (
                unc("srv-01.corp.example", "ADMIN$"),
                "srv-01.corp.example",
                "ADMIN$",
            ),
            (
                unc("fe80--1.ipv6-literal.net", "share"),
                "fe80--1.ipv6-literal.net",
                "share",
            ),
            (unc(&max_label, "s"), max_label.as_str(), "s"),
            (unc(&max_host, "s"), max_host.as_str(), "s"),
            (unc("srv", "caf\u{e9}"), "srv", "caf\u{e9}"),
        ] {
            assert!(
                matches!(&result, Ok(PlaceablePrefix::Share { server: s, share: t })
                    if s.as_str() == server && t.as_str() == share),
                "\\\\{server}\\{share} must be placeable, got {result:?}"
            );
        }
    }

    #[test]
    fn a_drive_letter_is_upper_cased_once() {
        for prefix in [
            Prefix::Disk(b'c'),
            Prefix::Disk(b'C'),
            Prefix::VerbatimDisk(b'c'),
        ] {
            let result = PlaceablePrefix::parse(prefix);
            assert!(
                matches!(&result, Ok(PlaceablePrefix::Disk(letter)) if letter.get() == b'C'),
                "{prefix:?} must be drive C, got {result:?}"
            );
        }
    }
}
