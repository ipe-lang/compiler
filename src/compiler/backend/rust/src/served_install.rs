//! The browser-install offer a served build carries: the app name and its proven icon.
//!
//! [`ServedIcon::from_png`] is the one constructor of [`ServedIcon`], so an icon
//! reaching the emitter always holds at most [`ICON_MAX_BYTES`] bytes that open
//! with the PNG signature and an `IHDR` chunk describing a square of at least
//! [`MIN_ICON_SIDE`] pixels. The CLI reads the file beneath the project root and
//! hands the bytes here; the emitter re-reads nothing.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use ipe_backend::{Asset, RelPath};
use ipe_diagnostics::{DResult, Diagnostic};
use sha2::{Digest, Sha256};

use crate::rust_str_lit;

/// The largest icon accepted, in bytes: 2 MiB.
pub const ICON_MAX_BYTES: u64 = 2 * 1024 * 1024;

/// The smallest side an installable icon may have, in pixels.
pub const MIN_ICON_SIDE: u32 = 192;

/// The eight bytes every PNG file opens with.
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n'];

/// The data length of an `IHDR` chunk.
const IHDR_LEN: [u8; 4] = 13_u32.to_be_bytes();

/// The type of the header chunk, which must come first.
const IHDR_TYPE: [u8; 4] = *b"IHDR";

/// Whether a served build offers browser install.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ServedInstall {
    /// No install offer: the page carries no manifest link and no icon route.
    Off,
    /// The app offers install under `name` with `icon`.
    On {
        /// The package name the manifest shows.
        name: String,
        /// The home-screen icon.
        icon: ServedIcon,
    },
}

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
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ServedIcon {
    png: Arc<[u8]>,
    side: IconSide,
    digest: [u8; 32],
}

impl fmt::Debug for ServedIcon {
    /// The side and digest only: the bytes never reach a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServedIcon")
            .field("side", &self.side)
            .field("digest", &hex(&self.digest))
            .finish_non_exhaustive()
    }
}

/// Why a byte string is not an installable icon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IconRefusal {
    /// The bytes are more than [`ICON_MAX_BYTES`].
    TooLarge,
    /// The bytes do not open with the PNG signature.
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

impl ServedIcon {
    /// Prove `png` an installable PNG icon.
    ///
    /// # Errors
    ///
    /// One [`IconRefusal`] per rule the bytes break.
    pub fn from_png(png: Vec<u8>) -> Result<Self, IconRefusal> {
        if u64::try_from(png.len())
            .ok()
            .is_none_or(|len| len > ICON_MAX_BYTES)
        {
            return Err(IconRefusal::TooLarge);
        }
        let side = png_side(&png)?;
        let digest = Sha256::digest(&png).into();
        Ok(Self {
            png: Arc::from(png),
            side,
            digest,
        })
    }

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

/// The square side the PNG `bytes` declare in their `IHDR` chunk.
fn png_side(bytes: &[u8]) -> Result<IconSide, IconRefusal> {
    let Some((signature, rest)) = bytes.split_first_chunk::<8>() else {
        return Err(IconRefusal::NotPng);
    };
    if *signature != PNG_SIGNATURE {
        return Err(IconRefusal::NotPng);
    }
    let (len, rest) = rest
        .split_first_chunk::<4>()
        .ok_or(IconRefusal::TruncatedHeader)?;
    let (kind, rest) = rest
        .split_first_chunk::<4>()
        .ok_or(IconRefusal::TruncatedHeader)?;
    if *len != IHDR_LEN || *kind != IHDR_TYPE {
        return Err(IconRefusal::TruncatedHeader);
    }
    // The 13 data bytes and the 4-byte CRC must all be present.
    let header = rest.get(..17).ok_or(IconRefusal::TruncatedHeader)?;
    let (width, rest) = header
        .split_first_chunk::<4>()
        .ok_or(IconRefusal::TruncatedHeader)?;
    let (height, _) = rest
        .split_first_chunk::<4>()
        .ok_or(IconRefusal::TruncatedHeader)?;
    let width = u32::from_be_bytes(*width);
    let height = u32::from_be_bytes(*height);
    if width == 0 || height == 0 {
        return Err(IconRefusal::ZeroSide);
    }
    if width != height {
        return Err(IconRefusal::NotSquare { width, height });
    }
    if width < MIN_ICON_SIDE {
        return Err(IconRefusal::TooSmall { side: width });
    }
    Ok(IconSide(width))
}

/// The emitted project's icon file, relative to the crate root. The project
/// writer writes it from [`install_assets`] and the web app leaf names it in
/// [`register_stmt`]'s `include_bytes!`: one constant, both sides.
pub const INSTALL_ICON_FILE: &str = "src/ipe_install_icon.png";

/// The binary files `install` adds to an emitted project: the icon, or none.
///
/// # Errors
///
/// [`Diagnostic::CompilerBug`] when a text file of `files` already holds the
/// icon's path.
pub fn install_assets(
    install: &ServedInstall,
    files: &BTreeMap<RelPath, String>,
) -> DResult<BTreeMap<RelPath, Asset>> {
    match install {
        ServedInstall::Off => Ok(BTreeMap::new()),
        ServedInstall::On { name: _, icon } => {
            if files.contains_key(INSTALL_ICON_FILE) {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::served_install::install_assets",
                    detail: format!(
                        "a text file already holds the install icon's path {INSTALL_ICON_FILE}"
                    ),
                });
            }
            Ok(BTreeMap::from([(
                RelPath::new(INSTALL_ICON_FILE)?,
                Asset::new(icon.png().to_vec()),
            )]))
        }
    }
}

/// The statements a web app leaf opens with to register `install`: a static
/// `InstallFacts` whose icon is the [`INSTALL_ICON_FILE`] bytes, then the
/// runtime's `register`. Empty for [`ServedInstall::Off`], so a build without
/// the offer emits byte-identical Rust.
///
/// The name goes through [`rust_str_lit`]; the icon is never inlined.
pub fn register_stmt(install: &ServedInstall) -> String {
    match install {
        ServedInstall::Off => String::new(),
        ServedInstall::On { name, icon } => {
            let name = rust_str_lit(name);
            let side = icon.side().get();
            let file = rust_str_lit(&format!("/{INSTALL_ICON_FILE}"));
            format!(
                "static INSTALL_FACTS: ipe_runtime::web::install::InstallFacts = \
                 ipe_runtime::web::install::InstallFacts {{ name: {name}, icon_png: \
                 include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), {file})), \
                 icon_side: {side} }}; ipe_runtime::web::install::register(&INSTALL_FACTS); "
            )
        }
    }
}

/// Lower-case hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0F])
        .map(|nibble| {
            DIGITS
                .get(usize::from(nibble))
                .copied()
                .map_or('0', char::from)
        })
        .collect()
}

/// The signature and a whole `IHDR` chunk of a `width` by `height` PNG, for tests.
#[doc(hidden)]
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
mod tests {
    use super::*;

    #[test]
    fn one_byte_past_the_cap_is_too_large_and_the_cap_is_accepted() {
        let mut bytes = test_png(512, 512);
        let cap = usize::try_from(ICON_MAX_BYTES).expect("cap fits usize");
        bytes.resize(cap + 1, 0);
        assert_eq!(
            ServedIcon::from_png(bytes.clone()),
            Err(IconRefusal::TooLarge)
        );
        bytes.truncate(cap);
        assert!(ServedIcon::from_png(bytes).is_ok());
    }

    #[test]
    fn each_header_rule_has_its_own_refusal() {
        assert_eq!(
            ServedIcon::from_png(b"GIF89a".to_vec()),
            Err(IconRefusal::NotPng)
        );
        let whole = test_png(512, 512);
        for cut in [8, 12, 16, 20, whole.len() - 1] {
            let cut = whole.get(..cut).expect("cut within header").to_vec();
            assert_eq!(ServedIcon::from_png(cut), Err(IconRefusal::TruncatedHeader));
        }
        assert_eq!(
            ServedIcon::from_png(test_png(512, 0)),
            Err(IconRefusal::ZeroSide)
        );
        assert_eq!(
            ServedIcon::from_png(test_png(512, 256)),
            Err(IconRefusal::NotSquare {
                width: 512,
                height: 256
            })
        );
        assert_eq!(
            ServedIcon::from_png(test_png(191, 191)),
            Err(IconRefusal::TooSmall { side: 191 })
        );
    }

    #[test]
    fn the_debug_form_never_carries_the_bytes() {
        let mut bytes = test_png(512, 512);
        bytes.extend_from_slice(b"SECRET-PIXELS");
        let icon = ServedIcon::from_png(bytes).expect("square PNG");
        let shown = format!("{icon:?}");
        assert!(!shown.contains("SECRET"), "{shown}");
        assert!(!shown.contains("137, 80"), "{shown}");
        assert!(shown.contains(&hex(icon.digest())), "{shown}");
    }
}
