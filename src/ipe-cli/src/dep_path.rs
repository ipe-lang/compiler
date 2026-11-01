//! The location of a `depPath` dependency, parsed once at the manifest boundary.
//!
//! A `depPath` names a library directory relative to the package that declares
//! it. The grammar is `("../")* name ("/" name)*` with `/` the only separator on
//! every host, so one manifest names the same directory everywhere and never a
//! network share, a device, a drive, or an absolute root. Ascent is a prefix
//! only, bounded by [`MAX_DEP_ASCENT`], and the path ends in a named directory.

use std::ffi::OsStr;

use ipe_path_core::{ElementClass, Regime};

use crate::lockfile::{LocalSource, MAX_LOCAL_SOURCE_LEN};
use crate::package_name::PackageName;
use crate::style::TerminalSafe;
use crate::text;

/// The most leading `..` components a `depPath` may hold.
pub const MAX_DEP_ASCENT: usize = 8;

/// A `depPath` location that obeys the dependency path grammar.
///
/// Built on [`LocalSource`], so a value is also recordable in `ipe.lock` as it
/// was written. The only constructor is [`DepPath::parse`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepPath(LocalSource);

/// Which rule of the dependency path grammar a `depPath` breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepPathRefusal {
    /// The path is empty.
    Empty,
    /// The path is longer than [`MAX_LOCAL_SOURCE_LEN`] bytes.
    TooLong,
    /// The path holds a character a lockfile cannot record.
    Unrecordable,
    /// The path names a network share or a device namespace.
    Remote,
    /// The path holds a `\`.
    Backslash,
    /// The path starts at a root `/`.
    Absolute,
    /// The path starts with a drive designator (`C:`).
    DrivePrefix,
    /// The path holds an empty component (`a//b`, a trailing `/`).
    EmptyComponent,
    /// The path holds a `.` component.
    DotComponent,
    /// A `..` follows a named component.
    AscentAfterName,
    /// The path climbs more than [`MAX_DEP_ASCENT`] levels.
    TooManyAscents,
    /// A component names a Windows device (`con`, `nul.txt`).
    Device,
    /// A component is not a plain directory name.
    NotAName,
    /// The path names no directory after its ascent.
    NoName,
}

impl DepPath {
    /// Parse the `depPath` location `raw` of dependency `name`.
    ///
    /// # Errors
    /// The [`DepPathRefusal`] naming the first grammar rule `raw` breaks.
    pub fn parse(name: &PackageName, raw: &str) -> Result<Self, DepPathRefusal> {
        if raw.is_empty() {
            return Err(DepPathRefusal::Empty);
        }
        if raw.len() > MAX_LOCAL_SOURCE_LEN {
            return Err(DepPathRefusal::TooLong);
        }
        if crate::index::remote_path(raw).is_some() {
            return Err(DepPathRefusal::Remote);
        }
        if raw.contains('\\') {
            return Err(DepPathRefusal::Backslash);
        }
        if raw.starts_with('/') {
            return Err(DepPathRefusal::Absolute);
        }
        if !raw.chars().all(crate::index::is_recordable_path_char) {
            return Err(DepPathRefusal::Unrecordable);
        }
        check_components(raw)?;
        let source = LocalSource::parse(name, raw).map_err(|_| DepPathRefusal::Unrecordable)?;
        if source.opens_a_device(Regime::Windows) {
            return Err(DepPathRefusal::Device);
        }
        Ok(Self(source))
    }

    /// The path exactly as the manifest wrote it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Check each `/`-separated component of `raw` against the grammar.
fn check_components(raw: &str) -> Result<(), DepPathRefusal> {
    let mut ascents: usize = 0;
    let mut named = false;
    for (index, element) in raw.split('/').enumerate() {
        match ElementClass::of(element.as_bytes()) {
            ElementClass::Empty => return Err(DepPathRefusal::EmptyComponent),
            ElementClass::Current => return Err(DepPathRefusal::DotComponent),
            ElementClass::Parent if named => return Err(DepPathRefusal::AscentAfterName),
            ElementClass::Parent => {
                ascents = ascents.saturating_add(1);
                if ascents > MAX_DEP_ASCENT {
                    return Err(DepPathRefusal::TooManyAscents);
                }
            }
            ElementClass::Colon if index == 0 => return Err(DepPathRefusal::DrivePrefix),
            ElementClass::DosDevice => return Err(DepPathRefusal::Device),
            ElementClass::Colon
            | ElementClass::DisguisedParent
            | ElementClass::DisguisedCurrent
            | ElementClass::StrippedTail => return Err(DepPathRefusal::NotAName),
            ElementClass::Name => {
                if ipe_fs_open::EntryName::new(OsStr::new(element)).is_none() {
                    return Err(DepPathRefusal::NotAName);
                }
                named = true;
            }
        }
    }
    if named {
        Ok(())
    } else {
        Err(DepPathRefusal::NoName)
    }
}

impl DepPathRefusal {
    /// The refusal text for dependency `name` written at `raw`.
    #[must_use]
    pub fn message(self, name: &PackageName, raw: &str) -> text::Message {
        let path = TerminalSafe::sanitize(raw);
        let name = name.as_str();
        match self {
            Self::Empty => text::msg::dep_path_empty(&name),
            Self::TooLong => text::msg::dep_path_too_long(&name, &MAX_LOCAL_SOURCE_LEN),
            Self::Unrecordable => text::msg::dep_path_unrecordable(&name, &path),
            Self::Remote => text::msg::dep_path_remote(&name, &path),
            Self::Backslash => text::msg::dep_path_backslash(&name, &path),
            Self::Absolute => text::msg::dep_path_absolute(&name, &path),
            Self::DrivePrefix => text::msg::dep_path_drive_prefix(&name, &path),
            Self::EmptyComponent => text::msg::dep_path_empty_component(&name, &path),
            Self::DotComponent => text::msg::dep_path_dot_component(&name, &path),
            Self::AscentAfterName => text::msg::dep_path_ascent_after_name(&name, &path),
            Self::TooManyAscents => {
                text::msg::dep_path_too_many_ascents(&name, &path, &MAX_DEP_ASCENT)
            }
            Self::Device => text::msg::dep_path_device(&name, &path),
            Self::NotAName => text::msg::dep_path_not_a_name(&name, &path),
            Self::NoName => text::msg::dep_path_no_name(&name, &path),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::expect_used)] // a fixed, valid test name
    fn lib() -> PackageName {
        PackageName::parse("s-lib").expect("valid name")
    }

    fn refusal(raw: &str) -> Option<DepPathRefusal> {
        DepPath::parse(&lib(), raw).err()
    }

    #[test]
    fn each_grammar_rule_is_refused_by_name() {
        let nine = "../".repeat(MAX_DEP_ASCENT + 1);
        let nine_then_name = format!("{nine}s-lib");
        let cases: [(&str, DepPathRefusal); 17] = [
            ("/abs", DepPathRefusal::Absolute),
            ("C:/x", DepPathRefusal::DrivePrefix),
            ("\\\\srv\\x", DepPathRefusal::Remote),
            ("a\\b", DepPathRefusal::Backslash),
            ("./a", DepPathRefusal::DotComponent),
            ("a/./b", DepPathRefusal::DotComponent),
            ("a//b", DepPathRefusal::EmptyComponent),
            ("a/", DepPathRefusal::EmptyComponent),
            ("a/../b", DepPathRefusal::AscentAfterName),
            ("..", DepPathRefusal::NoName),
            ("../..", DepPathRefusal::NoName),
            ("", DepPathRefusal::Empty),
            ("../con", DepPathRefusal::Device),
            ("nul/x", DepPathRefusal::Device),
            (nine.trim_end_matches('/'), DepPathRefusal::TooManyAscents),
            (&nine_then_name, DepPathRefusal::TooManyAscents),
            ("../a:b", DepPathRefusal::NotAName),
        ];
        for (raw, want) in cases {
            assert_eq!(
                refusal(raw),
                Some(want),
                "`{raw}` must be refused as {want:?}"
            );
        }
    }

    #[test]
    fn a_path_past_the_length_ceiling_is_refused() {
        let long = "a".repeat(MAX_LOCAL_SOURCE_LEN.saturating_add(1));
        assert_eq!(refusal(&long), Some(DepPathRefusal::TooLong));
    }

    #[test]
    fn a_disguised_or_tail_stripped_component_is_not_a_name() {
        for raw in ["../...", "../a.", "../a ", "lib/. "] {
            assert_eq!(refusal(raw), Some(DepPathRefusal::NotAName), "`{raw}`");
        }
    }

    #[test]
    fn a_device_namespace_path_is_remote() {
        assert_eq!(refusal("//./pipe/x"), Some(DepPathRefusal::Remote));
        assert_eq!(refusal("//srv/share"), Some(DepPathRefusal::Remote));
    }

    #[test]
    fn the_edge_of_the_grammar_is_accepted() {
        let eight = format!("{}s-lib", "../".repeat(MAX_DEP_ASCENT));
        for raw in ["../s_lib", "libs/s-lib", eight.as_str(), "lib", "../a/b/c"] {
            let parsed = DepPath::parse(&lib(), raw);
            assert!(
                parsed.as_ref().is_ok_and(|path| path.as_str() == raw),
                "`{raw}` must parse and keep its spelling, got {parsed:?}"
            );
        }
    }

    #[test]
    fn the_render_round_trips_including_a_non_ascii_name() {
        for raw in ["../s_lib", "libs/bibliothèque", "../../日本/lib"] {
            let first = DepPath::parse(&lib(), raw);
            let again = first
                .as_ref()
                .map_err(|refusal| *refusal)
                .and_then(|path| DepPath::parse(&lib(), path.as_str()));
            assert!(first.is_ok(), "`{raw}` must parse");
            assert_eq!(first, again, "`{raw}` must round-trip");
        }
    }

    #[test]
    fn every_refusal_names_the_dependency_and_the_path() {
        let shown = DepPathRefusal::Absolute.message(&lib(), "/abs").to_string();
        assert!(
            shown.contains("s-lib") && shown.contains("/abs"),
            "the refusal must name the dependency and its path: {shown}"
        );
    }
}
