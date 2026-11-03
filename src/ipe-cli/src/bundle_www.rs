//! The client bundle: the one held, bounded collector of a `web client` build's `www/`.
//!
//! The emitted crate's `www/` is an intermediate. [`SpaBundle::from_crate`]
//! walks it through held directory handles, refusing a link, a special file, a
//! name the bundle cannot carry, and a tree past its depth or entry ceiling.
//! Every read of what the walk admitted goes through one [`HeldSpa`], capped
//! per file and charged to one [`MAX_BUNDLE_TOTAL_BYTES`] sum. Every consumer
//! reads through it: [`publish_www`] copies the bundle to the artifact
//! (`out/www/`, or `release/<slug>/www/`), and a mobile pack copies it into its
//! native shell.

use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};

use ipe_fs_open::{ByteCap, EntryCap, EntryName, FileId, FileKind, HeldDir, OpenRefusal};

use crate::CliError;
use crate::output_dir::{OutputArea, OutputRoot, OwnedDir, ReleaseMember};
use crate::text::{self, Message};

/// Where a `web client` build publishes its bundle.
#[derive(Debug, Clone)]
pub enum BundleHome {
    /// A development build: the bundle lands at `<out>/www/`.
    Dev(OutputRoot),
    /// A release build: the bundle lands at `<out>/release/<slug>/www/`.
    Release(ReleaseMember),
}

impl BundleHome {
    /// Claim the directory the bundle's `www/` is published into, now.
    ///
    /// # Errors
    /// As [`OutputRoot::claim`] and [`ReleaseMember::claim`].
    pub fn claim(&self) -> Result<OwnedDir, CliError> {
        match self {
            Self::Dev(root) => root.claim(),
            Self::Release(member) => member.claim(),
        }
    }
}

/// Publish the bundle collected from the `www/` of the owned emitted crate `crate_dir` as `www/` under `into`.
///
/// The bundle is exactly the files the held walk admitted, each read through
/// the held `www/` and written into one staged directory that replaces any
/// previous `www/` whole in one rename. A refusal at any file leaves the
/// previous bundle exactly as it was, and no staging entry.
///
/// # Errors
/// [`CliError::ProjectRefused`] carrying the [`BundleError`] for a crate
/// replaced since its claim, a crate `www/` the walk refuses, a read past a
/// cap, or a `www/` replaced during the copy; [`CliError::OutputRefused`] for
/// a link or a swapped directory under `into`; [`CliError::Io`] on a
/// filesystem failure.
pub fn publish_www(crate_dir: &OwnedDir, into: &OwnedDir) -> Result<PathBuf, CliError> {
    publish_www_with(crate_dir, into, AssetLimits::PRODUCTION)
}

/// [`publish_www`] under the ceilings `limits`.
fn publish_www_with(
    crate_dir: &OwnedDir,
    into: &OwnedDir,
    limits: AssetLimits,
) -> Result<PathBuf, CliError> {
    let refused = |e: BundleError| CliError::ProjectRefused(Message::relay(&e));
    let bundle = SpaBundle::from_crate_with(crate_dir, limits).map_err(refused)?;
    let mut www = bundle.spa.hold().map_err(refused)?;
    let staged = into.stage_dir(OutputArea::Www.dir_name())?;
    for asset in &bundle.assets {
        let bytes = www.read_asset(&asset.path).map_err(refused)?;
        let rel: PathBuf = asset
            .path
            .segments()
            .iter()
            .map(EntryName::as_os_str)
            .collect();
        staged.path_to(rel)?.write(&bytes)?;
    }
    bundle.spa.verify_unreplaced().map_err(refused)?;
    staged.promote()
}

/// How deep below `www/` the asset walk descends, in directory levels.
///
/// A wasm SPA holds `index.html`, a boot script and `pkg/*`, so a few levels
/// suffice; a deeper tree is refused rather than walked.
pub const MAX_ASSET_DEPTH: NonZeroUsize = NonZeroUsize::MIN.saturating_add(31);

/// How many entries, files and directories alike, the asset walk visits in all.
///
/// Each listing is charged to this budget in full the moment it is read, so
/// the listings held along the open path never hold more names than it.
pub const MAX_ASSETS: NonZeroU32 = NonZeroU32::MIN.saturating_add(65_535);

/// How many bytes every asset of one bundle holds in all.
///
/// Each read is capped at what is left of this sum, so the per-asset cap times
/// the entry ceiling never bounds a bundle; past it the read is refused.
pub const MAX_BUNDLE_TOTAL_BYTES: u64 = 512 * 1024 * 1024;

/// [`MAX_BUNDLE_TOTAL_BYTES`] as the ceiling a walk carries.
const BUNDLE_TOTAL: NonZeroU64 =
    NonZeroU64::MIN.saturating_add(MAX_BUNDLE_TOTAL_BYTES.saturating_sub(1));

/// The ceilings one asset walk, and every read of what it admitted, runs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AssetLimits {
    /// The deepest directory level below `www/` the walk enters.
    depth: NonZeroUsize,
    /// The most entries the walk visits, and the most one directory may list.
    entries: NonZeroU32,
    /// The most bytes the reads through one hold return in all.
    total: NonZeroU64,
}

impl AssetLimits {
    /// The ceilings every bundle is collected under.
    const PRODUCTION: Self = Self {
        depth: MAX_ASSET_DEPTH,
        entries: MAX_ASSETS,
        total: BUNDLE_TOTAL,
    };
}

/// An asset's identity: its entry names below `www/`, one per directory level.
///
/// Built name by name during the walk, never stripped or joined from an
/// absolute path, and only from names that are UTF-8, so its `/`-joined shell
/// form spells exactly the entries it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetPath {
    /// The entry names, outermost directory first; never empty.
    segments: Vec<EntryName>,
    /// The names joined by `/`.
    shell_rel: String,
}

impl AssetPath {
    /// The asset path `segments` spells, or `None` when it is empty or a name is not UTF-8.
    fn new(segments: Vec<EntryName>) -> Option<Self> {
        if segments.is_empty() {
            return None;
        }
        let mut shell_rel = String::new();
        for (index, name) in segments.iter().enumerate() {
            if index > 0 {
                shell_rel.push('/');
            }
            shell_rel.push_str(name.as_os_str().to_str()?);
        }
        Some(Self {
            segments,
            shell_rel,
        })
    }

    /// The entry names, outermost directory first.
    #[must_use]
    pub fn segments(&self) -> &[EntryName] {
        &self.segments
    }

    /// The `/`-joined form the shell layout places the asset under.
    #[must_use]
    pub fn to_shell_rel(&self) -> &str {
        &self.shell_rel
    }

    /// Whether this is the top-level `index.html`.
    #[must_use]
    pub fn is_index_html(&self) -> bool {
        matches!(self.segments.as_slice(), [only] if only.as_os_str() == "index.html")
    }
}

impl Ord for AssetPath {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.segments
            .iter()
            .map(EntryName::as_os_str)
            .cmp(other.segments.iter().map(EntryName::as_os_str))
    }
}

impl PartialOrd for AssetPath {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// One file a bundled SPA asset carries, named by its path below `www/`.
///
/// A typed value rather than a loose string so the asset set is inspectable and
/// a test can assert the full copied file set without materialising bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetFile {
    /// The asset's entry names below `www/`, which are also its path below the
    /// native project's web-asset root.
    pub path: AssetPath,
}

/// The emitted `www/` directory an SPA bundle was collected from, with its identity then.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaRoot {
    /// The `www/` path the walk opened.
    path: PathBuf,
    /// The identity of the directory the walk held.
    id: FileId,
    /// The ceilings the walk ran under, which every read through a hold keeps.
    limits: AssetLimits,
}

impl SpaRoot {
    /// Prove the path still names the directory the bundle was collected from.
    ///
    /// # Errors
    /// [`BundleError::Replaced`] when `www/` is gone or now names another
    /// object; [`BundleError::Io`] when it cannot be opened or identified.
    pub fn verify_unreplaced(&self) -> Result<(), BundleError> {
        self.held_dir().map(drop)
    }

    /// Hold `www/`, proven to be the directory the bundle was collected from.
    ///
    /// Every asset is read through the returned hold, so an entry swapped for
    /// a link after the walk is refused rather than followed, and every read
    /// through it is charged to one [`MAX_BUNDLE_TOTAL_BYTES`] budget.
    ///
    /// # Errors
    /// As [`SpaRoot::verify_unreplaced`].
    pub fn hold(&self) -> Result<HeldSpa<'_>, BundleError> {
        Ok(HeldSpa {
            spa: self,
            dir: self.held_dir()?,
            left: self.limits.total.get(),
        })
    }

    /// The `www/` directory handle, proven to be the directory collected.
    ///
    /// # Errors
    /// As [`SpaRoot::verify_unreplaced`].
    fn held_dir(&self) -> Result<HeldDir, BundleError> {
        match open_www(&self.path).and_then(|dir| dir.id().map(|id| (dir, id))) {
            Ok((dir, id)) if id == self.id => Ok(dir),
            Ok(_) | Err(OpenRefusal::Absent | OpenRefusal::Link | OpenRefusal::NotRegular(_)) => {
                Err(BundleError::Replaced {
                    path: self.path.clone(),
                })
            }
            Err(refusal) => Err(BundleError::Io {
                path: self.path.clone(),
                source: refusal.into_io(),
            }),
        }
    }

    /// The path of `asset` below this root, joined from its entry names.
    ///
    /// For messages only, never reopened.
    #[must_use]
    pub fn shown(&self, asset: &AssetPath) -> PathBuf {
        joined(&self.path, asset.segments())
    }
}

/// The emitted `www/` held open, with what is left of its byte budget.
///
/// The only way to read an asset's bytes: each read goes through the held
/// handle, never following a link at any level, and is capped at the lesser
/// of its own cap and what is left of the bundle's total.
#[derive(Debug)]
pub struct HeldSpa<'spa> {
    /// The root the handle was proven against.
    spa: &'spa SpaRoot,
    /// The held `www/` directory.
    dir: HeldDir,
    /// How many bytes the reads through this hold may still return.
    left: u64,
}

impl HeldSpa<'_> {
    /// The path of `asset` below the held root, for messages only.
    #[must_use]
    pub fn shown(&self, asset: &AssetPath) -> PathBuf {
        self.spa.shown(asset)
    }

    /// The bytes of `asset`, at most [`MAX_ASSET_BYTES`].
    ///
    /// # Errors
    /// [`BundleError::Io`] past [`MAX_ASSET_BYTES`], never read;
    /// [`BundleError::TooLarge`] past what is left of the bundle's total; the
    /// refusal of a link, another kind of entry, or a read failure.
    pub fn read_asset(&mut self, asset: &AssetPath) -> Result<Vec<u8>, BundleError> {
        let entries = self.spa.limits.entries;
        self.read(asset, ASSET_CAP, |path| {
            bundle_refusal(path, OpenRefusal::TooLarge(ASSET_CAP), entries)
        })
    }

    /// The bytes of the page `asset`, at most [`MAX_INDEX_HTML_BYTES`].
    ///
    /// # Errors
    /// [`BundleError::IndexTooLarge`] past [`MAX_INDEX_HTML_BYTES`], never
    /// read; otherwise as [`HeldSpa::read_asset`].
    pub fn read_index(&mut self, asset: &AssetPath) -> Result<Vec<u8>, BundleError> {
        self.read(asset, INDEX_HTML_CAP, |path| BundleError::IndexTooLarge {
            path,
            cap: MAX_INDEX_HTML_BYTES,
        })
    }

    /// The bytes of `asset`, capped at `cap` and at what is left of the total.
    ///
    /// When the remainder is the tighter bound, a refusal reports the total.
    ///
    /// # Errors
    /// `past_cap` of the asset's path past `cap`; [`BundleError::TooLarge`]
    /// past the remainder; the refusal met opening or reading it.
    fn read(
        &mut self,
        asset: &AssetPath,
        cap: ByteCap,
        past_cap: impl FnOnce(PathBuf) -> BundleError,
    ) -> Result<Vec<u8>, BundleError> {
        let limits = self.spa.limits;
        let past_total = || BundleError::TooLarge {
            limit: limits.total,
        };
        let file = self
            .dir
            .open_rel(asset.segments())
            .map_err(|refusal| bundle_refusal(self.spa.shown(asset), refusal, limits.entries))?;
        let by_total = self.left < cap.get();
        // A spent budget still reads one byte, which the charge below refuses.
        let bound = if by_total {
            ByteCap::new(self.left).unwrap_or(ByteCap::from_nonzero(NonZeroU64::MIN))
        } else {
            cap
        };
        let bytes = file.read_bytes(bound).map_err(|refusal| match refusal {
            OpenRefusal::TooLarge(_) if by_total => past_total(),
            OpenRefusal::TooLarge(_) => past_cap(self.spa.shown(asset)),
            refusal => bundle_refusal(self.spa.shown(asset), refusal, limits.entries),
        })?;
        let read = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.left = self.left.checked_sub(read).ok_or_else(past_total)?;
        Ok(bytes)
    }
}

/// The offline SPA bundle: the ordered asset files of a `web client` build's `www/`.
///
/// A `web client` build publishes these files and a mobile shell hosts them.
/// Pure data derived from the emitted `www/` directory, so a test can assert the
/// full asset set without running a device toolchain. The webview serves these
/// and only these — local assets, no remote URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaBundle {
    /// The `www/` directory the assets were collected from.
    spa: SpaRoot,
    /// The asset files, sorted by [`AssetPath`].
    assets: Vec<AssetFile>,
}

impl SpaBundle {
    /// Collect the SPA asset set from the emitted `www/` directory at `www_dir`,
    /// opened by path: the walk of [`SpaBundle::from_crate`] with no claimed
    /// crate to prove the levels above `www/` against.
    ///
    /// # Errors
    /// As [`SpaBundle::from_crate`], [`BundleError::Replaced`] aside.
    #[cfg(test)]
    pub fn from_www_dir(www_dir: &Path) -> Result<Self, BundleError> {
        Self::from_www_dir_with(www_dir, AssetLimits::PRODUCTION)
    }

    /// [`SpaBundle::from_www_dir`] under the ceilings `limits`.
    #[cfg(test)]
    fn from_www_dir_with(www_dir: &Path, limits: AssetLimits) -> Result<Self, BundleError> {
        let root = open_www(www_dir)
            .map_err(|refusal| bundle_refusal(www_dir.to_path_buf(), refusal, limits.entries))?;
        Self::collect(www_dir, &root, limits)
    }

    /// Collect the SPA asset set from the `www/` of the owned emitted crate `crate_dir`.
    ///
    /// The crate directory is opened and proven to be the directory that was
    /// claimed before its `www/` is opened through that handle, so a crate
    /// path swapped since its claim is refused, never walked.
    ///
    /// The walk holds the crate's `www/` and every directory below it as an
    /// open handle and names each asset by the entry names it descended
    /// through. Every
    /// regular file becomes one [`AssetFile`]; a link, FIFO, socket, device or
    /// other special file, or a name the shell cannot place, is refused rather
    /// than skipped. The set is sorted for determinism. An `index.html` is
    /// required — its absence means the input was not a `web client` bundle,
    /// a fail-closed error rather than an empty shell.
    ///
    /// # Errors
    /// [`BundleError::Replaced`] when the crate path names another directory
    /// than the one claimed;
    /// [`BundleError::NoIndexHtml`] when `www/` has no `index.html`;
    /// [`BundleError::UnplaceableAsset`] for an entry the shell cannot place;
    /// [`BundleError::TooDeep`] past [`MAX_ASSET_DEPTH`];
    /// [`BundleError::TooManyAssets`] past [`MAX_ASSETS`];
    /// [`BundleError::Io`] naming the exact path on any other walk failure.
    pub fn from_crate(crate_dir: &OwnedDir) -> Result<Self, BundleError> {
        Self::from_crate_with(crate_dir, AssetLimits::PRODUCTION)
    }

    /// [`SpaBundle::from_crate`] under the ceilings `limits`.
    fn from_crate_with(crate_dir: &OwnedDir, limits: AssetLimits) -> Result<Self, BundleError> {
        let crate_path = crate_dir.path();
        let www_dir = crate_path.join(CRATE_WWW);
        let at_crate = |refusal: OpenRefusal| {
            bundle_refusal(crate_path.to_path_buf(), refusal, limits.entries)
        };
        let held = HeldDir::open_root(crate_path).map_err(at_crate)?;
        if held.id().map_err(at_crate)? != crate_dir.id() {
            return Err(BundleError::Replaced {
                path: crate_path.to_path_buf(),
            });
        }
        let name = EntryName::new(std::ffi::OsStr::new(CRATE_WWW))
            .ok_or_else(|| at_crate(OpenRefusal::BadName))?;
        let root = held
            .child_dir(&name)
            .map_err(|refusal| bundle_refusal(www_dir.clone(), refusal, limits.entries))?;
        Self::collect(&www_dir, &root, limits)
    }

    /// Walk the held `root`, the `www/` directory at `www_dir`, under `limits`.
    fn collect(www_dir: &Path, root: &HeldDir, limits: AssetLimits) -> Result<Self, BundleError> {
        let mut walk = AssetWalk {
            root: www_dir,
            limits,
            visited: 0,
            assets: Vec::new(),
        };
        let id = root
            .id()
            .map_err(|refusal| walk.refused(www_dir.to_path_buf(), refusal))?;
        walk.descend(root, &mut Vec::new(), 0)?;
        let mut assets = walk.assets;
        assets.sort_by(|a, b| a.path.cmp(&b.path));
        if !assets.iter().any(|a| a.path.is_index_html()) {
            return Err(BundleError::NoIndexHtml {
                dir: www_dir.to_path_buf(),
            });
        }
        Ok(Self {
            spa: SpaRoot {
                path: www_dir.to_path_buf(),
                id,
                limits,
            },
            assets,
        })
    }

    /// The asset files, sorted by [`AssetPath`].
    #[must_use]
    pub fn assets(&self) -> &[AssetFile] {
        &self.assets
    }

    /// The `www/` directory the assets were collected from.
    #[must_use]
    pub const fn root(&self) -> &SpaRoot {
        &self.spa
    }
}

/// The entry name of the client bundle's tree in the emitted crate.
const CRATE_WWW: &str = "www";

/// Open the emitted `www/` directory, its own entry held without following a link.
///
/// Only the levels above `www/` are followed, so a link standing at `www/`
/// itself is refused rather than walked or copied through.
///
/// # Errors
/// [`OpenRefusal::BadName`] when `www_dir` ends in no plain entry name;
/// [`OpenRefusal::Link`] when `www/` is a link; the refusal of any other
/// level that cannot be opened.
fn open_www(www_dir: &Path) -> Result<HeldDir, OpenRefusal> {
    let (Some(parent), Some(name)) = (www_dir.parent(), www_dir.file_name()) else {
        return Err(OpenRefusal::BadName);
    };
    let name = EntryName::new(name).ok_or(OpenRefusal::BadName)?;
    HeldDir::open_root(parent)?.child_dir(&name)
}

/// `root` with `names` appended, one component per name.
fn joined(root: &Path, names: &[EntryName]) -> PathBuf {
    names
        .iter()
        .fold(root.to_path_buf(), |path, name| path.join(name.as_os_str()))
}

/// One bounded walk of an emitted `www/` tree through held directory handles.
struct AssetWalk<'root> {
    /// The `www/` path, for messages only; never reopened.
    root: &'root Path,
    /// The ceilings this walk runs under.
    limits: AssetLimits,
    /// How many entries the walk has visited so far.
    visited: u32,
    /// The regular files found so far.
    assets: Vec<AssetFile>,
}

impl AssetWalk<'_> {
    /// Visit every entry of `dir`, the directory `prefix` names `depth` levels below `www/`.
    fn descend(
        &mut self,
        dir: &HeldDir,
        prefix: &mut Vec<EntryName>,
        depth: usize,
    ) -> Result<(), BundleError> {
        let listing = dir
            .entries(self.listing_cap())
            .map_err(|refusal| self.refused(joined(self.root, prefix), refusal))?;
        self.charge(listing.len())?;
        for (name, kind) in listing {
            let shown = joined(self.root, prefix).join(name.as_os_str());
            if name.as_os_str().to_str().is_none() {
                return Err(BundleError::UnplaceableAsset {
                    path: shown,
                    reason: AssetRefusal::NotUtf8,
                });
            }
            match kind {
                FileKind::Regular => {
                    let mut segments = prefix.clone();
                    segments.push(name);
                    let path = AssetPath::new(segments).ok_or(BundleError::UnplaceableAsset {
                        path: shown,
                        reason: AssetRefusal::NotUtf8,
                    })?;
                    self.assets.push(AssetFile { path });
                }
                FileKind::Dir => {
                    let Some(next) = depth
                        .checked_add(1)
                        .filter(|next| *next <= self.limits.depth.get())
                    else {
                        return Err(BundleError::TooDeep {
                            path: shown,
                            limit: self.limits.depth,
                        });
                    };
                    let child = dir
                        .child_dir(&name)
                        .map_err(|refusal| self.refused(shown, refusal))?;
                    prefix.push(name);
                    let walked = self.descend(&child, prefix, next);
                    prefix.pop();
                    walked?;
                }
                FileKind::Symlink
                | FileKind::Fifo
                | FileKind::Socket
                | FileKind::Device
                | FileKind::Other => {
                    return Err(BundleError::UnplaceableAsset {
                        path: shown,
                        reason: AssetRefusal::Kind(kind),
                    });
                }
            }
        }
        Ok(())
    }

    /// Charge a listing of `listed` names to the entry budget before any of it
    /// is visited, refusing once the budget is exceeded.
    ///
    /// Every listing on the open path is held while the walk descends; charging
    /// each in full on read keeps their names together within the budget.
    fn charge(&mut self, listed: usize) -> Result<(), BundleError> {
        let listed = u32::try_from(listed).unwrap_or(u32::MAX);
        self.visited = self.visited.saturating_add(listed);
        if self.visited > self.limits.entries.get() {
            return Err(BundleError::TooManyAssets {
                limit: self.limits.entries,
            });
        }
        Ok(())
    }

    /// The most names the next directory listing may hold: what is left of the
    /// walk's entry budget. A spent budget still lists one name, which the
    /// charge then refuses.
    fn listing_cap(&self) -> EntryCap {
        let left = self.limits.entries.get().saturating_sub(self.visited);
        EntryCap::new(left).unwrap_or(EntryCap::from_nonzero(NonZeroU32::MIN))
    }

    /// The bundle error for `refusal` met at `path`.
    ///
    /// An entry that turned into a link or another kind between its listing
    /// and its open is refused as that kind, never followed or skipped.
    fn refused(&self, path: PathBuf, refusal: OpenRefusal) -> BundleError {
        bundle_refusal(path, refusal, self.limits.entries)
    }
}

/// The bundle error for `refusal` met at `path`, under an entry budget of `entries`.
///
/// An entry that turned into a link or another kind between its listing and
/// its open is refused as that kind, never followed or skipped.
fn bundle_refusal(path: PathBuf, refusal: OpenRefusal, entries: NonZeroU32) -> BundleError {
    match refusal {
        OpenRefusal::Link => BundleError::UnplaceableAsset {
            path,
            reason: AssetRefusal::Kind(FileKind::Symlink),
        },
        OpenRefusal::NotRegular(kind) => BundleError::UnplaceableAsset {
            path,
            reason: AssetRefusal::Kind(kind),
        },
        OpenRefusal::BadName => BundleError::UnplaceableAsset {
            path,
            reason: AssetRefusal::BadName,
        },
        OpenRefusal::TooManyEntries(_) => BundleError::TooManyAssets { limit: entries },
        OpenRefusal::Absent
        | OpenRefusal::Denied
        | OpenRefusal::InUse
        | OpenRefusal::TooLarge(_)
        | OpenRefusal::NotUtf8
        | OpenRefusal::Io(_) => BundleError::Io {
            path,
            source: refusal.into_io(),
        },
    }
}

/// Why the shell cannot place one entry of the emitted `www/` tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetRefusal {
    /// The entry's name is not valid UTF-8, which a shell asset path cannot carry.
    NotUtf8,
    /// The entry's name is not one plain entry name a held handle can open.
    BadName,
    /// The entry is not a regular file or a directory: this is what it is.
    Kind(FileKind),
}

impl std::fmt::Display for AssetRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotUtf8 => f.write_str(text::mobile_asset_not_utf8()),
            Self::BadName => f.write_str(text::mobile_asset_bad_name()),
            Self::Kind(kind) => f.write_str(&text::mobile_asset_kind(kind)),
        }
    }
}

/// A path shown in a bundle message: escaped, so a control character, a
/// direction override or a byte that is not UTF-8 is spelled out, never shown raw
/// or replaced.
struct EscapedPath<'path>(&'path Path);

impl std::fmt::Display for EscapedPath<'_> {
    // The escaped `Debug` form is the point: `display()` shows control and
    // direction characters raw and replaces a byte that is not UTF-8.
    #[allow(clippy::unnecessary_debug_formatting)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

/// A failure while collecting the SPA bundle from an emitted `www/` tree.
#[derive(Debug)]
pub enum BundleError {
    /// The emitted `www/` directory has no `index.html` — the input was not a
    /// `web client` bundle. Carries the directory inspected.
    NoIndexHtml {
        /// The `www/` directory that lacked an `index.html`.
        dir: PathBuf,
    },
    /// An entry of the `www/` tree the shell cannot place.
    UnplaceableAsset {
        /// The entry's full path, for the message only; never reopened.
        path: PathBuf,
        /// Why it cannot be placed.
        reason: AssetRefusal,
    },
    /// The `www/` tree nests directories deeper than the walk descends.
    TooDeep {
        /// The first directory past the ceiling, for the message only.
        path: PathBuf,
        /// The deepest level the walk enters.
        limit: NonZeroUsize,
    },
    /// The `www/` tree holds more entries than the walk visits.
    TooManyAssets {
        /// The most entries the walk visits.
        limit: NonZeroU32,
    },
    /// The assets read through one hold are larger, in all, than the bundle's total.
    TooLarge {
        /// The most bytes every asset holds in all.
        limit: NonZeroU64,
    },
    /// The `www/` path names another object than the directory collected.
    Replaced {
        /// The `www/` path.
        path: PathBuf,
    },
    /// The bundle's `index.html` does not carry exactly one policy meta the
    /// wasm build renders for the pinned servers and capabilities.
    PolicyMismatch {
        /// The `index.html` path, for the message only.
        path: PathBuf,
    },
    /// The bundle's `index.html` is larger than the pack reads.
    IndexTooLarge {
        /// The `index.html` path, for the message only.
        path: PathBuf,
        /// The most bytes the pack reads.
        cap: u64,
    },
    /// A filesystem error while walking the `www/` tree.
    Io {
        /// The path the walk failed on.
        path: PathBuf,
        /// The underlying OS error.
        source: std::io::Error,
    },
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::NoIndexHtml { dir } => text::mobile_bundle_no_index(&EscapedPath(dir)),
            Self::UnplaceableAsset { path, reason } => {
                text::mobile_bundle_unplaceable(&EscapedPath(path), reason)
            }
            Self::TooDeep { path, limit } => {
                text::mobile_bundle_too_deep(limit, &EscapedPath(path))
            }
            Self::TooManyAssets { limit } => text::mobile_bundle_too_many(limit),
            Self::TooLarge { limit } => text::mobile_bundle_too_large(limit),
            Self::Replaced { path } => text::mobile_bundle_replaced(&EscapedPath(path)),
            Self::PolicyMismatch { path } => {
                text::mobile_bundle_policy_mismatch(&EscapedPath(path))
            }
            Self::IndexTooLarge { path, cap } => {
                text::mobile_bundle_index_too_large(&EscapedPath(path), cap)
            }
            Self::Io { path, source } => text::mobile_bundle_io(&EscapedPath(path), source),
        };
        f.write_str(&message)
    }
}

impl std::error::Error for BundleError {}

/// The most bytes of a bundle's `index.html` a hold reads.
///
/// The emitted page is under 2 KiB, so a larger file is refused unread.
pub const MAX_INDEX_HTML_BYTES: u64 = 64 * 1024;

/// [`MAX_INDEX_HTML_BYTES`] as the cap a held read takes.
const INDEX_HTML_CAP: ByteCap =
    ByteCap::from_nonzero(NonZeroU64::MIN.saturating_add(MAX_INDEX_HTML_BYTES.saturating_sub(1)));

/// The most bytes of any one bundled asset a hold reads.
///
/// An emitted bundle's largest asset, its wasm module, stays far below this;
/// a larger file is refused before it is read.
pub const MAX_ASSET_BYTES: u64 = 256 * 1024 * 1024;

/// [`MAX_ASSET_BYTES`] as the cap a held read takes.
const ASSET_CAP: ByteCap =
    ByteCap::from_nonzero(NonZeroU64::MIN.saturating_add(MAX_ASSET_BYTES.saturating_sub(1)));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output_dir::test_links::{staging_leftovers, tree_snapshot};

    /// A fresh scratch directory unique to this call.
    fn scratch(tag: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = ipe_test_temp::temp_root()
            .join(format!("ipe-bundle-www-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mk scratch");
        dir
    }

    /// A `www/` tree holding `index.html` and the given extra files, in the
    /// claimed crate `rust/` under a fresh scratch dir.
    fn www_with(tag: &str, files: &[&str]) -> (PathBuf, PathBuf) {
        let base = scratch(tag);
        let www = crate_of(&base).path().join("www");
        std::fs::create_dir_all(&www).expect("mk www");
        std::fs::write(www.join("index.html"), b"<html>").expect("write index");
        for rel in files {
            let path = rel.split('/').fold(www.clone(), |p, s| p.join(s));
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("mk parent");
            }
            std::fs::write(&path, b"x").expect("write asset");
        }
        (base, www)
    }

    /// The `/`-joined asset paths of `spa`, in bundle order.
    fn rels(spa: &SpaBundle) -> Vec<&str> {
        spa.assets().iter().map(|a| a.path.to_shell_rel()).collect()
    }

    /// The production ceilings with a bundle total of `total` bytes.
    fn total_of(total: u64) -> AssetLimits {
        AssetLimits {
            total: NonZeroU64::new(total).expect("a non-zero total"),
            ..AssetLimits::PRODUCTION
        }
    }

    /// The claimed emitted crate `rust/` under `base`.
    fn crate_of(base: &Path) -> OwnedDir {
        OwnedDir::claim(&base.join("rust")).expect("claim the crate")
    }

    /// A claimed output root `out/` under `base`.
    fn out_root(base: &Path) -> OwnedDir {
        OwnedDir::claim(&base.join("out")).expect("claim out")
    }

    /// Whether `result` is a project refusal whose message is `error`'s.
    fn refused_with(result: &Result<PathBuf, CliError>, error: &BundleError) -> bool {
        matches!(result, Err(CliError::ProjectRefused(message))
            if message.as_str() == Message::relay(error).as_str())
    }

    // ── Publishing the client bundle ──────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn publish_www_refuses_a_symlink_in_the_crate_www() {
        let (base, www) = www_with("publish-link", &["boot.js"]);
        let out = out_root(&base);
        publish_www(&crate_of(&base), &out).expect("a plain bundle publishes");
        let before = tree_snapshot(&base.join("out").join("www"));
        std::fs::remove_file(www.join("boot.js")).expect("drop boot.js");
        std::os::unix::fs::symlink("/etc/passwd", www.join("boot.js")).expect("plant link");

        let published = publish_www(&crate_of(&base), &out);
        assert!(
            matches!(published, Err(CliError::ProjectRefused(_))),
            "{published:?}"
        );
        assert_eq!(
            tree_snapshot(&base.join("out").join("www")),
            before,
            "the previous bundle is intact"
        );
        assert!(staging_leftovers(&base.join("out")).is_empty());

        let fresh = scratch("publish-link-fresh");
        let out = out_root(&fresh);
        assert!(publish_www(&crate_of(&base), &out).is_err());
        assert!(
            !fresh.join("out").join("www").exists(),
            "nothing is promoted from a linked asset"
        );
    }

    #[cfg(unix)]
    #[test]
    fn publish_www_refuses_a_linked_crate_www() {
        let (base, www) = www_with("publish-linked-www", &["boot.js"]);
        let real = base.join("elsewhere");
        std::fs::rename(&www, &real).expect("move www away");
        std::os::unix::fs::symlink(&real, &www).expect("plant www link");
        let published = publish_www(&crate_of(&base), &out_root(&base));
        assert!(
            matches!(published, Err(CliError::ProjectRefused(_))),
            "{published:?}"
        );
        assert!(!base.join("out").join("www").exists());
    }

    /// A crate path swapped for another directory after its claim is refused,
    /// never walked: the bundle published is the claimed crate's or none.
    #[test]
    fn publish_www_refuses_a_crate_swapped_since_its_claim() {
        let (base, _) = www_with("publish-crate-swap", &["boot.js"]);
        let krate = crate_of(&base);
        std::fs::rename(krate.path(), base.join("rust-claimed")).expect("move the crate away");
        let foreign = krate.path().join("www");
        std::fs::create_dir_all(&foreign).expect("mk the foreign www");
        std::fs::write(foreign.join("index.html"), b"<foreign>").expect("write foreign index");

        let published = publish_www(&krate, &out_root(&base));
        let error = BundleError::Replaced {
            path: krate.path().to_path_buf(),
        };
        assert!(refused_with(&published, &error), "{published:?}");
        assert!(!base.join("out").join("www").exists());
        assert!(staging_leftovers(&base.join("out")).is_empty());
    }

    #[test]
    fn publish_www_refuses_a_bundle_past_the_total_ceiling() {
        // `index.html` is six bytes and `boot.js` one: seven in all.
        let (base, _) = www_with("publish-total", &["boot.js"]);
        let out = out_root(&base);
        publish_www_with(&crate_of(&base), &out, total_of(7))
            .expect("exactly the total is published");

        let limit = NonZeroU64::new(6).expect("a non-zero total");
        let past = publish_www_with(&crate_of(&base), &out, total_of(6));
        assert!(
            refused_with(&past, &BundleError::TooLarge { limit }),
            "{past:?}"
        );

        let fresh = scratch("publish-total-fresh");
        let past = publish_www_with(&crate_of(&base), &out_root(&fresh), total_of(6));
        assert!(past.is_err(), "{past:?}");
        assert!(!fresh.join("out").join("www").exists());
        assert!(staging_leftovers(&fresh.join("out")).is_empty());
    }

    #[test]
    fn publish_www_refuses_a_bundle_past_the_entry_ceiling() {
        let (base, _) = www_with("publish-count", &["boot.js", "pkg/app.wasm"]);
        let limits = AssetLimits {
            entries: NonZeroU32::new(3).expect("a non-zero ceiling"),
            ..AssetLimits::PRODUCTION
        };
        let limit = limits.entries;
        let past = publish_www_with(&crate_of(&base), &out_root(&base), limits);
        assert!(
            refused_with(&past, &BundleError::TooManyAssets { limit }),
            "{past:?}"
        );
        assert!(!base.join("out").join("www").exists());
    }

    #[test]
    fn publish_www_refuses_a_bundle_past_the_depth_ceiling() {
        let (base, _) = www_with("publish-depth", &["d/e/leaf.js"]);
        let limits = AssetLimits {
            depth: NonZeroUsize::MIN,
            ..AssetLimits::PRODUCTION
        };
        let past = publish_www_with(&crate_of(&base), &out_root(&base), limits);
        assert!(
            matches!(&past, Err(CliError::ProjectRefused(_))),
            "{past:?}"
        );
        assert!(!base.join("out").join("www").exists());
    }

    #[test]
    fn publish_www_replaces_a_stale_bundle_atomically() {
        let (base, www) = www_with("publish-stale", &["stale.js", "pkg/app.wasm"]);
        let out = out_root(&base);
        let published = publish_www(&crate_of(&base), &out).expect("first publish");
        assert_eq!(published, base.join("out").join("www"));
        assert!(published.join("stale.js").is_file());

        std::fs::remove_file(www.join("stale.js")).expect("drop stale.js");
        std::fs::write(www.join("boot.js"), b"fresh").expect("write boot.js");
        let published = publish_www(&crate_of(&base), &out).expect("second publish");
        assert!(
            !published.join("stale.js").exists(),
            "a file only the old bundle held is gone"
        );
        assert_eq!(
            std::fs::read(published.join("boot.js")).expect("read boot.js"),
            b"fresh"
        );
        let good = tree_snapshot(&published);

        // `boot.js` is copied first and fits; `index.html` is past what is left.
        std::fs::write(www.join("boot.js"), b"newer").expect("rewrite boot.js");
        let mid_copy = publish_www_with(&crate_of(&base), &out, total_of(5));
        assert!(
            matches!(mid_copy, Err(CliError::ProjectRefused(_))),
            "{mid_copy:?}"
        );
        assert_eq!(
            tree_snapshot(&published),
            good,
            "a refusal mid-copy leaves the old bundle"
        );
        assert!(staging_leftovers(&base.join("out")).is_empty());
    }

    #[test]
    fn a_held_read_is_capped_at_what_is_left_of_the_total() {
        let (_base, www) = www_with("held-total", &["boot.js"]);
        let spa = SpaBundle::from_www_dir_with(&www, total_of(7)).expect("collect");
        let mut held = spa.root().hold().expect("hold www");
        let [boot, index] = spa.assets() else {
            assert_eq!(spa.assets().len(), 2);
            return;
        };
        assert_eq!(held.read_asset(&boot.path).expect("boot.js fits"), b"x");
        assert_eq!(
            held.read_asset(&index.path)
                .expect("index.html fills the rest"),
            b"<html>"
        );
        let limit = NonZeroU64::new(7).expect("a non-zero total");
        assert!(
            matches!(held.read_asset(&boot.path), Err(BundleError::TooLarge { limit: l }) if l == limit),
            "a spent total refuses even a one-byte read"
        );
        let mut fresh = spa.root().hold().expect("a new hold starts a new budget");
        assert!(fresh.read_asset(&index.path).is_ok());
    }

    #[test]
    fn the_total_message_comes_from_the_catalog() {
        let limit = NonZeroU64::new(9).expect("a non-zero total");
        assert_eq!(
            BundleError::TooLarge { limit }.to_string(),
            text::mobile_bundle_too_large(&limit).as_str()
        );
    }

    // ── SPA bundle collection ─────────────────────────────────────────────────

    #[test]
    fn a_www_dir_without_index_html_is_refused() {
        let dir =
            ipe_test_temp::temp_root().join(format!("ipe-mobile-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mk tmp");
        std::fs::write(dir.join("boot.js"), b"x").expect("write");
        let err = SpaBundle::from_www_dir(&dir).expect_err("no index.html is refused");
        assert!(matches!(err, BundleError::NoIndexHtml { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_www_dir_collects_its_files_sorted() {
        let (_base, www) = www_with("ok", &["boot.js", "pkg/app_bg.wasm"]);
        let spa = SpaBundle::from_www_dir(&www).expect("collect");
        assert_eq!(rels(&spa), vec!["boot.js", "index.html", "pkg/app_bg.wasm"]);
        spa.root()
            .verify_unreplaced()
            .expect("an untouched www/ is the directory collected");
    }

    #[cfg(all(unix, not(target_vendor = "apple")))]
    #[test]
    fn non_utf8_dir_name_is_refused_not_collapsed() {
        use std::os::unix::ffi::OsStrExt;
        let (_base, www) = www_with("non-utf8-dir", &[]);
        let odd = www.join(std::ffi::OsStr::from_bytes(b"\xff"));
        std::fs::create_dir_all(&odd).expect("mk non-UTF-8 dir");
        std::fs::write(odd.join("index.html"), b"decoy").expect("write decoy");
        let err = SpaBundle::from_www_dir(&www).expect_err("a non-UTF-8 directory is refused");
        assert!(
            matches!(
                &err,
                BundleError::UnplaceableAsset {
                    reason: AssetRefusal::NotUtf8,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[cfg(all(unix, not(target_vendor = "apple")))]
    #[test]
    fn non_utf8_top_level_file_is_refused() {
        use std::os::unix::ffi::OsStrExt;
        let (_base, www) = www_with("non-utf8-file", &[]);
        std::fs::write(www.join(std::ffi::OsStr::from_bytes(b"\xff")), b"x")
            .expect("write non-UTF-8 file");
        let err = SpaBundle::from_www_dir(&www).expect_err("a non-UTF-8 file is refused");
        assert!(
            matches!(
                &err,
                BundleError::UnplaceableAsset {
                    reason: AssetRefusal::NotUtf8,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_in_www_is_refused() {
        let (base, www) = www_with("symlink", &[]);
        let outside = base.join("outside.js");
        std::fs::write(&outside, b"outside").expect("write outside file");
        std::os::unix::fs::symlink(&outside, www.join("boot.js")).expect("plant link");
        let err = SpaBundle::from_www_dir(&www).expect_err("a link in www/ is refused");
        assert!(
            matches!(
                &err,
                BundleError::UnplaceableAsset {
                    reason: AssetRefusal::Kind(FileKind::Symlink),
                    ..
                }
            ),
            "{err}"
        );
    }

    #[cfg(all(unix, not(target_vendor = "apple")))]
    #[test]
    fn fifo_in_www_is_refused() {
        let (_base, www) = www_with("fifo", &[]);
        rustix::fs::mknodat(
            rustix::fs::CWD,
            www.join("pipe"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .expect("make FIFO");
        let err = SpaBundle::from_www_dir(&www).expect_err("a FIFO in www/ is refused");
        assert!(
            matches!(
                &err,
                BundleError::UnplaceableAsset {
                    reason: AssetRefusal::Kind(FileKind::Fifo),
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn walk_past_max_depth_is_too_deep() {
        let nested = |levels: usize| {
            let mut rel = "d/".repeat(levels);
            rel.push_str("leaf.js");
            rel
        };
        let at_ceiling = nested(MAX_ASSET_DEPTH.get());
        let (_base, www) = www_with("depth-ok", &[&at_ceiling]);
        let spa = SpaBundle::from_www_dir(&www).expect("exactly the ceiling is walked");
        assert!(rels(&spa).contains(&at_ceiling.as_str()));

        let past = nested(MAX_ASSET_DEPTH.get().saturating_add(1));
        let (_base, www) = www_with("depth-past", &[&past]);
        let err = SpaBundle::from_www_dir(&www).expect_err("one level past is refused");
        assert!(
            matches!(&err, BundleError::TooDeep { limit, .. } if *limit == MAX_ASSET_DEPTH),
            "{err}"
        );
    }

    #[test]
    fn more_than_max_assets_is_refused() {
        let limits = |entries: u32| AssetLimits {
            entries: NonZeroU32::new(entries).expect("a non-zero ceiling"),
            ..AssetLimits::PRODUCTION
        };
        // `index.html`, `boot.js`, `pkg/` and `pkg/app.wasm`: four entries.
        let (_base, www) = www_with("ceiling", &["boot.js", "pkg/app.wasm"]);
        SpaBundle::from_www_dir_with(&www, limits(4)).expect("exactly the ceiling is walked");
        let err = SpaBundle::from_www_dir_with(&www, limits(3))
            .expect_err("one entry past the ceiling is refused");
        assert!(
            matches!(&err, BundleError::TooManyAssets { limit } if limit.get() == 3),
            "{err}"
        );
    }

    #[test]
    fn a_listing_is_charged_in_full_before_any_of_it_is_entered() {
        // `www/` lists three names, so with four entries in all the first
        // directory entered may list only one: its two names are refused
        // before its `g/` is ever reached.
        let (_base, www) = www_with("charged", &["a/f", "a/g/x", "b/f", "b/g/x"]);
        let limits = AssetLimits {
            depth: NonZeroUsize::MIN,
            entries: NonZeroU32::new(4).expect("a non-zero ceiling"),
            ..AssetLimits::PRODUCTION
        };
        let err = SpaBundle::from_www_dir_with(&www, limits).expect_err("over budget");
        assert!(
            matches!(&err, BundleError::TooManyAssets { limit } if limit.get() == 4),
            "{err}"
        );
    }

    #[test]
    fn each_listing_is_capped_at_the_entry_budget_left() {
        let walk = |visited: u32| AssetWalk {
            root: Path::new("www"),
            limits: AssetLimits {
                entries: NonZeroU32::new(4).expect("a non-zero ceiling"),
                ..AssetLimits::PRODUCTION
            },
            visited,
            assets: Vec::new(),
        };
        assert_eq!(walk(0).listing_cap().get(), 4);
        assert_eq!(
            walk(3).listing_cap().get(),
            1,
            "a nested listing holds only what the walk may still visit"
        );
        assert_eq!(
            walk(4).listing_cap().get(),
            1,
            "a spent budget lists one name, which the visit refuses"
        );
    }

    #[test]
    fn bundle_messages_come_from_the_catalog_with_escaped_paths() {
        let limit = NonZeroU32::new(3).expect("a non-zero ceiling");
        assert_eq!(
            BundleError::TooManyAssets { limit }.to_string(),
            text::mobile_bundle_too_many(&limit).as_str()
        );
        let hostile = PathBuf::from("www/a\u{1b}[31m\u{202e}b\nc.js");
        let shown = BundleError::UnplaceableAsset {
            path: hostile,
            reason: AssetRefusal::Kind(FileKind::Fifo),
        }
        .to_string();
        assert!(
            shown.contains(r"\u{1b}[31m\u{202e}b\nc.js"),
            "every control and direction character is spelled out: {shown}"
        );
        assert!(
            shown.contains(text::mobile_asset_kind(&FileKind::Fifo).as_str()),
            "{shown}"
        );
        assert!(
            !shown.contains(['\u{1b}', '\u{202e}', '\n']),
            "nothing reaches the terminal raw: {shown}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_path_is_shown_escaped_not_replaced() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(b"www/\xff.js")).to_path_buf();
        let shown = BundleError::Replaced { path }.to_string();
        assert!(shown.contains(r"\xFF.js"), "{shown}");
        assert!(!shown.contains('\u{fffd}'), "{shown}");
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_www_is_refused_not_followed() {
        let (base, real) = www_with("linked-www", &["boot.js"]);
        let link = base.join("www-link");
        std::os::unix::fs::symlink(&real, &link).expect("plant www link");
        let err = SpaBundle::from_www_dir(&link).expect_err("a linked www/ is refused");
        assert!(
            matches!(
                &err,
                BundleError::UnplaceableAsset {
                    reason: AssetRefusal::Kind(FileKind::Symlink),
                    ..
                }
            ),
            "{err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn www_swapped_for_a_link_to_itself_is_replaced() {
        let (base, www) = www_with("www-self-link", &["boot.js"]);
        let spa = SpaBundle::from_www_dir(&www).expect("collect");
        let moved = base.join("www-collected");
        std::fs::rename(&www, &moved).expect("move www away");
        std::os::unix::fs::symlink(&moved, &www).expect("link www to the collected dir");
        assert!(
            matches!(
                spa.root().verify_unreplaced(),
                Err(BundleError::Replaced { .. })
            ),
            "a link at www/ is not the directory collected, even when it reaches it"
        );
    }
}
