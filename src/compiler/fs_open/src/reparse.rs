//! What a Windows directory listing's attributes and reparse tag say an entry is.
//!
//! Compiled on every target: the decision is pure arithmetic over the
//! listing's typed facts, so its table is proven on every host, not only where
//! a listing can produce it.
//!
//! A reparse point comes in two kinds. A name surrogate (a symbolic link, a
//! junction, a volume mount point) names another entry, and is reported as a
//! link. Any other tag, known or not, lets a filter driver answer for the entry
//! (a cloud placeholder, an app execution alias), and is reported as
//! [`HintedKind::Transparent`]: what the listing shows is not what the volume
//! holds.

use crate::HintedKind;

/// `FILE_ATTRIBUTE_DIRECTORY`.
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
/// `FILE_ATTRIBUTE_DEVICE`.
pub const FILE_ATTRIBUTE_DEVICE: u32 = 0x40;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// The reparse tag bit marking a name surrogate (`IsReparseTagNameSurrogate`).
pub const NAME_SURROGATE_BIT: u32 = 0x2000_0000;

/// Whether the reparse `tag` names another entry rather than handing the entry to a driver.
#[must_use]
pub const fn is_name_surrogate(tag: u32) -> bool {
    tag & NAME_SURROGATE_BIT != 0
}

/// What a listed entry is, from its find-data `attributes` and whether its reparse tag is a name surrogate.
///
/// `name_surrogate` is read only for an entry whose attributes mark a reparse
/// point. A reparse point is never a directory or a file here, whatever else
/// its attributes say.
#[must_use]
pub const fn hint_of_find_data(attributes: u32, name_surrogate: bool) -> HintedKind {
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        if name_surrogate {
            HintedKind::Link
        } else {
            HintedKind::Transparent
        }
    } else if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        HintedKind::Dir
    } else if attributes & FILE_ATTRIBUTE_DEVICE != 0 {
        HintedKind::Other
    } else {
        HintedKind::Regular
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        hint_of_find_data, is_name_surrogate,
    };
    use crate::HintedKind;

    /// `FILE_ATTRIBUTE_ARCHIVE`: a plain file's usual attribute.
    const ARCHIVE: u32 = 0x20;
    /// `IO_REPARSE_TAG_MOUNT_POINT`: a junction or volume mount point.
    const MOUNT_POINT: u32 = 0xA000_0003;
    /// `IO_REPARSE_TAG_SYMLINK`.
    const SYMLINK: u32 = 0xA000_000C;
    /// `IO_REPARSE_TAG_CLOUD_6`: a cloud-files placeholder.
    const CLOUD: u32 = 0x9000_001A;
    /// `IO_REPARSE_TAG_APPEXECLINK`: an app execution alias.
    const APP_EXEC_LINK: u32 = 0x8000_001B;
    /// A tag no Windows release defines.
    const UNKNOWN: u32 = 0x0000_7777;

    /// A name-surrogate tag lists as a link; every other tag, unknown ones included, as transparent.
    #[test]
    fn a_reparse_point_is_a_link_only_when_its_tag_is_a_name_surrogate() {
        let reparse_dir = FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY;
        let table = [
            (MOUNT_POINT, reparse_dir, HintedKind::Link),
            (SYMLINK, reparse_dir, HintedKind::Link),
            (
                SYMLINK,
                FILE_ATTRIBUTE_REPARSE_POINT | ARCHIVE,
                HintedKind::Link,
            ),
            (CLOUD, reparse_dir, HintedKind::Transparent),
            (
                CLOUD,
                FILE_ATTRIBUTE_REPARSE_POINT | ARCHIVE,
                HintedKind::Transparent,
            ),
            (
                APP_EXEC_LINK,
                FILE_ATTRIBUTE_REPARSE_POINT,
                HintedKind::Transparent,
            ),
            (UNKNOWN, reparse_dir, HintedKind::Transparent),
            (
                UNKNOWN,
                FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE,
                HintedKind::Transparent,
            ),
        ];
        for (tag, attributes, expected) in table {
            assert_eq!(
                hint_of_find_data(attributes, is_name_surrogate(tag)),
                expected,
                "tag {tag:#010x} under attributes {attributes:#x}"
            );
        }
    }

    /// An entry with no reparse attribute is read from its other attributes, whatever tag is passed.
    #[test]
    fn a_plain_entry_is_read_from_its_attributes() {
        for surrogate in [false, true] {
            assert_eq!(
                hint_of_find_data(FILE_ATTRIBUTE_DIRECTORY, surrogate),
                HintedKind::Dir
            );
            assert_eq!(hint_of_find_data(ARCHIVE, surrogate), HintedKind::Regular);
            assert_eq!(hint_of_find_data(0, surrogate), HintedKind::Regular);
            assert_eq!(
                hint_of_find_data(FILE_ATTRIBUTE_DEVICE, surrogate),
                HintedKind::Other
            );
        }
    }
}
