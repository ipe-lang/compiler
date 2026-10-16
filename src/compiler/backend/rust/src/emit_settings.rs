//! The one value that carries every emit setting a build chooses.
//!
//! Every production chain configures the backend from an [`EmitSettings`]
//! through [`crate::RustBackend::configured`], and the CLI's project cache key
//! folds the same value through [`EmitSettings::fold_key`]. A setting added
//! here is therefore applied by every chain and keyed by the cache at once:
//! both read the struct through an exhaustive destructure, so a new field
//! that one of them ignores fails the build.

use std::path::Path;

use crate::{
    BuildIntent, CargoPackageName, CrateIdentity, DbDriver, FfiEmit, MountBase, RuntimeDep,
    WebViewWindow,
};

/// The emitted crate's `[package] name`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CrateName {
    /// A single-file build with no manifest: the fixed `ipe-app` name.
    SingleFile,
    /// A single-file build whose caller pinned a unique name
    /// (`IPE_EMIT_PACKAGE_NAME`).
    Pinned(CargoPackageName),
    /// A manifest project: the sanitized name joined with the project's
    /// canonical-path digest, built only by [`crate::crate_identity`].
    Identity(CrateIdentity),
}

impl CrateName {
    /// The name the emitted `Cargo.toml` carries.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::SingleFile => SINGLE_FILE_CRATE_NAME,
            Self::Pinned(name) => name.as_str(),
            Self::Identity(identity) => identity.as_str(),
        }
    }
}

/// The crate name of a single-file build with no pinned name.
pub const SINGLE_FILE_CRATE_NAME: &str = "ipe-app";

/// How the emitted program is hosted.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EmitHost {
    /// The served host: a web program listens over HTTP.
    Served,
    /// The webview-native `web desktop` host, with its desktop window.
    WebView(WebViewWindow),
}

/// Every input a build chooses for one emit.
///
/// There is no `Default`: each production site states every field. Tests
/// inside this crate start from [`Self::unconfigured`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmitSettings {
    /// The SQL driver the emitted project targets.
    pub db_driver: DbDriver,
    /// The consumer-side FFI emission inputs; `None` when no foreign crate is
    /// installed.
    pub ffi: Option<FfiEmit>,
    /// The compilation target.
    pub target: ipe_ir::Target,
    /// The `[wasm] publicEnv` allowlist.
    pub wasm_public_env: Vec<String>,
    /// The mount base the emitted browser shell is served under.
    pub mount_base: MountBase,
    /// `true` when the wasm bundle emits the hydrate export.
    pub wasm_hydrate_mode: bool,
    /// The dependency-model selector; `None` emits the vendored project.
    pub runtime_dep: Option<RuntimeDep>,
    /// `true` when the development-only debugger is compiled in.
    pub debugger: bool,
    /// The emitted crate's package name.
    pub crate_name: CrateName,
    /// `true` when style literals route through the appearance hot-swap table.
    pub hot_appearance: bool,
    /// How the emitted program is hosted.
    pub host: EmitHost,
    /// The verb family the emit serves.
    pub intent: BuildIntent,
}

impl EmitSettings {
    /// The settings of a bare single-file release emit, for in-crate tests and
    /// the internal sweeps that need an emit context but no build.
    #[must_use]
    pub(crate) const fn unconfigured() -> Self {
        Self {
            db_driver: DbDriver::Sqlite,
            ffi: None,
            target: ipe_ir::Target::Native,
            wasm_public_env: Vec::new(),
            mount_base: MountBase::root(),
            wasm_hydrate_mode: false,
            runtime_dep: None,
            debugger: false,
            crate_name: CrateName::SingleFile,
            hot_appearance: false,
            host: EmitHost::Served,
            intent: BuildIntent::Release,
        }
    }

    /// Feed every field to `sink` as a tagged, length-framed record.
    ///
    /// Each field writes a one-byte tag, its payload length as a
    /// little-endian `u64`, then the payload, so two distinct settings never
    /// produce the same byte stream.
    pub fn fold_key(&self, sink: &mut dyn FnMut(&[u8])) {
        let Self {
            db_driver,
            ffi,
            target,
            wasm_public_env,
            mount_base,
            wasm_hydrate_mode,
            runtime_dep,
            debugger,
            crate_name,
            hot_appearance,
            host,
            intent,
        } = self;

        emit_field(
            sink,
            FieldTag::DbDriver,
            &[match db_driver {
                DbDriver::Sqlite => 0,
                DbDriver::Postgres => 1,
            }],
        );

        let mut payload = Vec::new();
        match ffi {
            None => payload.push(0),
            Some(ffi) => {
                payload.push(1);
                // `FfiEmit` holds only ordered collections of strings, so its
                // `Debug` rendering is deterministic and quotes every string.
                push_framed(&mut payload, format!("{ffi:?}").as_bytes());
            }
        }
        emit_field(sink, FieldTag::Ffi, &payload);

        emit_field(sink, FieldTag::Target, format!("{target:?}").as_bytes());

        let mut payload = Vec::new();
        push_len(&mut payload, wasm_public_env.len());
        for name in wasm_public_env {
            push_framed(&mut payload, name.as_bytes());
        }
        emit_field(sink, FieldTag::WasmPublicEnv, &payload);

        emit_field(sink, FieldTag::MountBase, mount_base.prefix().as_bytes());
        emit_field(
            sink,
            FieldTag::WasmHydrateMode,
            &[u8::from(*wasm_hydrate_mode)],
        );

        let mut payload = Vec::new();
        match runtime_dep {
            None => payload.push(0),
            Some(dep) => {
                payload.push(1);
                push_framed(&mut payload, path_bytes(&dep.root));
            }
        }
        emit_field(sink, FieldTag::RuntimeDep, &payload);

        emit_field(sink, FieldTag::Debugger, &[u8::from(*debugger)]);

        let mut payload = Vec::new();
        match crate_name {
            CrateName::SingleFile => payload.push(0),
            CrateName::Pinned(name) => {
                payload.push(1);
                push_framed(&mut payload, name.as_str().as_bytes());
            }
            CrateName::Identity(identity) => {
                payload.push(2);
                push_framed(&mut payload, identity.as_str().as_bytes());
            }
        }
        emit_field(sink, FieldTag::CrateName, &payload);

        emit_field(sink, FieldTag::HotAppearance, &[u8::from(*hot_appearance)]);

        let mut payload = Vec::new();
        match host {
            EmitHost::Served => payload.push(0),
            EmitHost::WebView(window) => {
                let WebViewWindow {
                    title,
                    width,
                    height,
                } = window;
                payload.push(1);
                push_framed(&mut payload, title.as_bytes());
                payload.extend_from_slice(&width.to_le_bytes());
                payload.extend_from_slice(&height.to_le_bytes());
            }
        }
        emit_field(sink, FieldTag::Host, &payload);

        emit_field(
            sink,
            FieldTag::Intent,
            &[match intent {
                BuildIntent::Development => 0,
                BuildIntent::Release => 1,
            }],
        );
    }
}

/// The one-byte tag that opens each field's record in [`EmitSettings::fold_key`].
#[derive(Clone, Copy)]
#[repr(u8)]
enum FieldTag {
    DbDriver = 1,
    Ffi = 2,
    Target = 3,
    WasmPublicEnv = 4,
    MountBase = 5,
    WasmHydrateMode = 6,
    RuntimeDep = 7,
    Debugger = 8,
    CrateName = 9,
    HotAppearance = 10,
    Host = 11,
    Intent = 12,
}

/// Write one field record: tag, payload length, payload.
fn emit_field(sink: &mut dyn FnMut(&[u8]), tag: FieldTag, payload: &[u8]) {
    sink(&[tag as u8]);
    sink(&len_bytes(payload.len()));
    sink(payload);
}

/// Append `bytes` to `buf` behind its length.
fn push_framed(buf: &mut Vec<u8>, bytes: &[u8]) {
    push_len(buf, bytes.len());
    buf.extend_from_slice(bytes);
}

/// Append a length as a little-endian `u64`.
fn push_len(buf: &mut Vec<u8>, len: usize) {
    buf.extend_from_slice(&len_bytes(len));
}

/// A length as little-endian `u64` bytes; saturates on a platform wider than
/// 64 bits.
fn len_bytes(len: usize) -> [u8; 8] {
    u64::try_from(len).unwrap_or(u64::MAX).to_le_bytes()
}

/// A path's platform bytes.
fn path_bytes(path: &Path) -> &[u8] {
    path.as_os_str().as_encoded_bytes()
}
