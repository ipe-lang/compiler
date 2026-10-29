//! The installable app icon: a PNG read beneath the project root, proven square and large enough.
//!
//! [`parse`] is the one constructor of [`PwaIcon`], so an icon value always
//! holds bytes that opened as a regular file below the root (never through a
//! symlink), fit the [`ICON_READ_CAP`], carry the PNG signature and an `IHDR`
//! chunk, and describe a square of at least [`MIN_ICON_SIDE`] pixels. Each
//! failure is one [`PwaIconRefusal`] variant.

use std::num::NonZeroU64;
use std::path::Path;

use ipe_fs_open::ByteCap;
use sha2::{Digest, Sha256};

use crate::CliError;

/// The largest icon file read, in bytes: 2 MiB.
pub const ICON_READ_CAP: u64 = 2 * 1024 * 1024;

/// The smallest side an installable icon may have, in pixels.
pub const MIN_ICON_SIDE: u32 = 192;

/// [`ICON_READ_CAP`] as a [`ByteCap`].
const ICON_CAP: ByteCap =
    ByteCap::from_nonzero(const { NonZeroU64::MIN.saturating_add(ICON_READ_CAP - 1) });

/// The eight bytes every PNG file opens with.
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n'];

/// The data length of an `IHDR` chunk.
const IHDR_LEN: [u8; 4] = 13_u32.to_be_bytes();

/// The type of the header chunk, which must come first.
const IHDR_TYPE: [u8; 4] = *b"IHDR";

/// The side of a square icon, at least [`MIN_ICON_SIDE`] pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IconSide(u32);

impl IconSide {
    /// The side in pixels.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A PNG icon proven fit for a web app manifest and a home screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PwaIcon {
    png: Vec<u8>,
    side: IconSide,
    digest: [u8; 32],
}

impl PwaIcon {
    /// The PNG file's bytes, exactly as read.
    #[must_use]
    pub fn png(&self) -> &[u8] {
        &self.png
    }

    /// The icon's side in pixels.
    #[must_use]
    pub const fn side(&self) -> IconSide {
        self.side
    }

    /// The SHA-256 digest of [`Self::png`].
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Why an icon file is not an installable icon.
#[derive(Debug)]
pub enum PwaIconRefusal {
    /// The file could not be opened or read beneath the project root.
    Unreadable(Box<CliError>),
    /// The file is larger than [`ICON_READ_CAP`].
    TooLarge,
    /// The file does not open with the PNG signature.
    NotPng,
    /// The PNG `IHDR` chunk is missing, cut short, or not the first chunk.
    TruncatedHeader,
    /// The PNG declares a width or a height of zero.
    ZeroSide,
    /// The PNG is not square.
    NotSquare {
        /// The declared width in pixels.
        width: u32,
        /// The declared height in pixels.
        height: u32,
    },
    /// The PNG is square but smaller than [`MIN_ICON_SIDE`].
    TooSmall {
        /// The declared side in pixels.
        side: u32,
    },
}

/// Read the icon at `path` beneath `root` and prove it an installable PNG.
///
/// Every level below `root` is opened through the held level above it, so a
/// symlink swapped in after the manifest named the path is refused.
///
/// # Errors
///
/// One [`PwaIconRefusal`] per rule the file breaks.
pub fn parse(root: &Path, path: &Path) -> Result<PwaIcon, PwaIconRefusal> {
    let png = crate::io_bounded::read_bytes_beneath(root, path, ICON_CAP).map_err(|error| {
        if matches!(error, CliError::FileTooLarge { .. }) {
            PwaIconRefusal::TooLarge
        } else {
            PwaIconRefusal::Unreadable(Box::new(error))
        }
    })?;
    let side = png_side(&png)?;
    let digest = Sha256::digest(&png).into();
    Ok(PwaIcon { png, side, digest })
}

/// The square side the PNG `bytes` declare in their `IHDR` chunk.
fn png_side(bytes: &[u8]) -> Result<IconSide, PwaIconRefusal> {
    let Some((signature, rest)) = bytes.split_first_chunk::<8>() else {
        return Err(PwaIconRefusal::NotPng);
    };
    if *signature != PNG_SIGNATURE {
        return Err(PwaIconRefusal::NotPng);
    }
    let (len, rest) = rest
        .split_first_chunk::<4>()
        .ok_or(PwaIconRefusal::TruncatedHeader)?;
    let (kind, rest) = rest
        .split_first_chunk::<4>()
        .ok_or(PwaIconRefusal::TruncatedHeader)?;
    if *len != IHDR_LEN || *kind != IHDR_TYPE {
        return Err(PwaIconRefusal::TruncatedHeader);
    }
    // The 13 data bytes and the 4-byte CRC must all be present.
    let header = rest.get(..17).ok_or(PwaIconRefusal::TruncatedHeader)?;
    let (width, rest) = header
        .split_first_chunk::<4>()
        .ok_or(PwaIconRefusal::TruncatedHeader)?;
    let (height, _) = rest
        .split_first_chunk::<4>()
        .ok_or(PwaIconRefusal::TruncatedHeader)?;
    let width = u32::from_be_bytes(*width);
    let height = u32::from_be_bytes(*height);
    if width == 0 || height == 0 {
        return Err(PwaIconRefusal::ZeroSide);
    }
    if width != height {
        return Err(PwaIconRefusal::NotSquare { width, height });
    }
    if width < MIN_ICON_SIDE {
        return Err(PwaIconRefusal::TooSmall { side: width });
    }
    Ok(IconSide(width))
}

/// The signature and a whole `IHDR` chunk of a `width` by `height` PNG, for tests.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
#[must_use]
pub fn test_png(width: u32, height: u32) -> Vec<u8> {
    let mut bytes = PNG_SIGNATURE.to_vec();
    bytes.extend_from_slice(&IHDR_LEN);
    bytes.extend_from_slice(&IHDR_TYPE);
    bytes.extend_from_slice(&width.to_be_bytes());
    bytes.extend_from_slice(&height.to_be_bytes());
    // Bit depth, colour type, compression, filter, interlace.
    bytes.extend_from_slice(&[8, 6, 0, 0, 0]);
    // The chunk CRC; the icon parse reads the header, not the CRC.
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    bytes
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// A fresh directory for one test.
    fn scratch(tag: &str) -> PathBuf {
        let dir =
            ipe_test_temp::temp_root().join(format!("ipe_pwa_icon_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    /// Parse `bytes` written as `icon.png` in a fresh directory.
    fn parse_bytes(tag: &str, bytes: &[u8]) -> Result<PwaIcon, PwaIconRefusal> {
        let dir = scratch(tag);
        let path = dir.join("icon.png");
        std::fs::write(&path, bytes).expect("write icon");
        let parsed = parse(&dir, &path);
        let _ = std::fs::remove_dir_all(&dir);
        parsed
    }

    #[test]
    fn jpeg_gif_and_svg_are_not_png() {
        let jpeg: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10, b'J', b'F', b'I', b'F', 0];
        let gif: &[u8] = b"GIF89a\x00\x02\x00\x02\x80\x00\x00";
        let svg: &[u8] =
            b"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"512\" height=\"512\"/>";
        for (tag, bytes) in [("jpeg", jpeg), ("gif", gif), ("svg", svg)] {
            let parsed = parse_bytes(tag, bytes);
            assert!(
                matches!(parsed, Err(PwaIconRefusal::NotPng)),
                "{tag}: {parsed:?}"
            );
        }
    }

    #[test]
    fn a_png_cut_inside_ihdr_is_truncated() {
        let whole = test_png(512, 512);
        for cut in [8, 12, 16, 20, whole.len() - 1] {
            let parsed = parse_bytes("cut", whole.get(..cut).expect("cut within header"));
            assert!(
                matches!(parsed, Err(PwaIconRefusal::TruncatedHeader)),
                "cut at {cut}: {parsed:?}"
            );
        }
    }

    #[test]
    fn a_first_chunk_other_than_ihdr_is_truncated() {
        let mut bytes = test_png(512, 512);
        let kind = bytes.get_mut(12..16).expect("chunk type bytes");
        kind.copy_from_slice(b"IDAT");
        let parsed = parse_bytes("idat", &bytes);
        assert!(
            matches!(parsed, Err(PwaIconRefusal::TruncatedHeader)),
            "{parsed:?}"
        );
    }

    #[test]
    fn a_wide_png_is_not_square() {
        let parsed = parse_bytes("wide", &test_png(512, 256));
        assert!(
            matches!(
                parsed,
                Err(PwaIconRefusal::NotSquare {
                    width: 512,
                    height: 256
                })
            ),
            "{parsed:?}"
        );
    }

    #[test]
    fn one_pixel_under_the_minimum_is_too_small() {
        let parsed = parse_bytes("small", &test_png(191, 191));
        assert!(
            matches!(parsed, Err(PwaIconRefusal::TooSmall { side: 191 })),
            "{parsed:?}"
        );
    }

    #[test]
    fn a_zero_side_is_refused() {
        for (width, height) in [(0, 0), (512, 0), (0, 512)] {
            let parsed = parse_bytes("zero", &test_png(width, height));
            assert!(
                matches!(parsed, Err(PwaIconRefusal::ZeroSide)),
                "{width}x{height}: {parsed:?}"
            );
        }
    }

    #[test]
    fn one_byte_past_the_cap_is_too_large() {
        let mut bytes = test_png(512, 512);
        let cap = usize::try_from(ICON_READ_CAP).expect("cap fits usize");
        bytes.resize(cap + 1, 0);
        let parsed = parse_bytes("large", &bytes);
        assert!(
            matches!(parsed, Err(PwaIconRefusal::TooLarge)),
            "{parsed:?}"
        );
        bytes.truncate(cap);
        let parsed = parse_bytes("at-cap", &bytes);
        assert!(parsed.is_ok(), "exactly at the cap: {parsed:?}");
    }

    #[test]
    fn a_missing_file_is_unreadable() {
        let dir = scratch("missing");
        let parsed = parse(&dir, &dir.join("icon.png"));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(parsed, Err(PwaIconRefusal::Unreadable(_))),
            "{parsed:?}"
        );
    }

    #[test]
    fn the_minimum_and_a_large_square_are_accepted() {
        for side in [MIN_ICON_SIDE, 512] {
            let bytes = test_png(side, side);
            let parsed = parse_bytes("ok", &bytes).expect("a square PNG at or past the minimum");
            assert_eq!(parsed.side().get(), side);
            assert_eq!(parsed.png(), bytes.as_slice());
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            assert_eq!(parsed.digest(), &digest);
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_icon_swapped_to_a_symlink_out_of_the_root_is_refused() {
        let dir = scratch("swap");
        let root = dir.join("project");
        let outside = dir.join("outside.png");
        std::fs::create_dir_all(root.join("assets")).expect("create assets");
        std::fs::write(&outside, test_png(512, 512)).expect("write outside icon");
        let icon = root.join("assets").join("icon.png");
        std::os::unix::fs::symlink(&outside, &icon).expect("plant icon link");
        let leaf = parse(&root, &icon);
        // A swapped directory level is refused as well as a swapped leaf.
        std::fs::remove_file(&icon).expect("drop icon link");
        std::fs::remove_dir(root.join("assets")).expect("drop assets");
        std::os::unix::fs::symlink(&dir, root.join("assets")).expect("plant dir link");
        let level = parse(&root, &root.join("assets").join("outside.png"));
        let _ = std::fs::remove_dir_all(&dir);
        for parsed in [leaf, level] {
            assert!(
                matches!(
                    &parsed,
                    Err(PwaIconRefusal::Unreadable(error))
                        if matches!(**error, CliError::SourceRefused { .. })
                ),
                "{parsed:?}"
            );
        }
    }
}
