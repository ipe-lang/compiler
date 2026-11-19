//! The one value that carries every emit setting a build chooses.
//!
//! Every production chain configures the backend from an [`EmitSettings`]
//! through [`crate::RustBackend::configured`], and the CLI's project cache key
//! folds the same value through [`EmitSettings::fold_key`]. A setting added
//! here is therefore applied by every chain and keyed by the cache at once:
//! both read the struct through an exhaustive destructure, so a new field
//! that one of them ignores fails the build.

use crate::{
    BuildIntent, CargoPackageName, CrateIdentity, DbDriver, FfiEmit, MountBase, RuntimeDep,
    ServedInstall, ServerOrigins, WebViewWindow,
};
use ipe_runtime_rust::encoding::{FrameOriginEntries, FrameOriginEntry};

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
    /// The `ipe test` runner: the fixed `ipe-test` name, never read from the
    /// environment.
    Test,
}

impl CrateName {
    /// The name the emitted `Cargo.toml` carries.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::SingleFile => SINGLE_FILE_CRATE_NAME,
            Self::Pinned(name) => name.as_str(),
            Self::Identity(identity) => identity.as_str(),
            Self::Test => TEST_CRATE_NAME,
        }
    }
}

/// The crate name of a single-file build with no pinned name.
pub const SINGLE_FILE_CRATE_NAME: &str = "ipe-app";

/// The crate name of the `ipe test` runner.
pub const TEST_CRATE_NAME: &str = "ipe-test";

/// The build-environment variable whose value the `ipe test` runner embeds.
///
/// The runner's `fn main` reads it through `env!`, so cargo records it as an
/// environment dependency of the crate: a build under a different value always
/// recompiles the runner, and the value lands in the binary for the driver to
/// find before it runs it.
pub const TEST_RUN_KEY_ENV: &str = "IPE_TEST_RUN_KEY";

/// How the emitted program is hosted.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EmitHost {
    /// The served host: a web program listens over HTTP, with or without a
    /// browser-install offer.
    Served(ServedInstall),
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
    /// The `delivery.servers` origins the browser bundle may reach.
    pub server_origins: ServerOrigins,
    /// The `delivery.frameOrigins` a page of the program trusts to frame.
    pub frame_origins: FrameOriginEntries,
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
            server_origins: ServerOrigins::none(),
            frame_origins: FrameOriginEntries::none(),
            wasm_hydrate_mode: false,
            runtime_dep: None,
            debugger: false,
            crate_name: CrateName::SingleFile,
            hot_appearance: false,
            host: EmitHost::Served(ServedInstall::Off),
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
            server_origins,
            frame_origins,
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

        let mut payload = Vec::new();
        push_len(&mut payload, server_origins.len());
        for origin in server_origins.origins() {
            push_framed(&mut payload, origin.authority().as_bytes());
        }
        emit_field(sink, FieldTag::ServerOrigins, &payload);

        let mut payload = Vec::new();
        push_len(&mut payload, frame_origins.len());
        let mut written = String::new();
        for entry in frame_origins.entries() {
            written.clear();
            entry.write(&mut written);
            push_framed(&mut payload, written.as_bytes());
        }
        emit_field(sink, FieldTag::FrameOrigins, &payload);

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
                push_framed(&mut payload, dep.content.as_bytes());
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
            CrateName::Test => payload.push(3),
        }
        emit_field(sink, FieldTag::CrateName, &payload);

        emit_field(sink, FieldTag::HotAppearance, &[u8::from(*hot_appearance)]);

        emit_field(sink, FieldTag::Host, &host_payload(host));

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

/// A frame-origin list a build of one intent, target, and program shape cannot emit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameListRefused {
    /// A release build lists a loopback entry, which only `ipe dev` trusts.
    LoopbackAtRelease {
        /// The refused loopback entry.
        entry: FrameOriginEntry,
    },
    /// A browser-built development client lists a loopback entry, which its
    /// runtime cannot represent.
    LoopbackInBrowserClient {
        /// The refused loopback entry.
        entry: FrameOriginEntry,
    },
    /// The program registers no frame list, so a listed entry would be dropped.
    ///
    /// Only a `Web.tea` or `Web.embed` page a server serves, or a browser
    /// client, trusts the listed origins; any other program frames nothing.
    NoWebLeaf {
        /// The first listed entry.
        entry: FrameOriginEntry,
    },
}

impl std::fmt::Display for FrameListRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (entry, why) = match self {
            Self::LoopbackAtRelease { entry } => (
                entry,
                "a loopback origin that is for served `ipe dev` only; a release build trusts \
                 `https://` origins",
            ),
            Self::LoopbackInBrowserClient { entry } => (
                entry,
                "a loopback origin that is for served `ipe dev` only; a browser-built client \
                 trusts `https://` origins",
            ),
            Self::NoWebLeaf { entry } => (
                entry,
                "but this program serves no page through `Web.tea` or `Web.embed` and builds \
                 no browser client, so no page would trust it; remove `frameOrigins` from \
                 `package.ipe`, or serve the page through `Web.tea` or `Web.embed`",
            ),
        };
        let mut written = String::with_capacity(entry.written_len());
        entry.write(&mut written);
        write!(f, "`delivery.frameOrigins` lists `{written}`, {why}")
    }
}

/// The frame origins a build of `intent` for `target` may emit.
///
/// A development build for `Native` or `WasmWasi` emits every entry (both
/// promote `dev-posture`, so their runtime represents a loopback origin);
/// every other build only `https://` entries.
///
/// # Errors
///
/// [`FrameListRefused`] naming the first loopback entry a release build or a
/// development browser client lists.
pub fn frame_origins_for(
    entries: &FrameOriginEntries,
    intent: BuildIntent,
    target: ipe_ir::Target,
) -> Result<&FrameOriginEntries, FrameListRefused> {
    let refusal: fn(FrameOriginEntry) -> FrameListRefused = match (intent, target) {
        (BuildIntent::Development, ipe_ir::Target::Native | ipe_ir::Target::WasmWasi) => {
            return Ok(entries);
        }
        (BuildIntent::Development, ipe_ir::Target::WasmClient) => {
            |entry| FrameListRefused::LoopbackInBrowserClient { entry }
        }
        (
            BuildIntent::Release,
            ipe_ir::Target::Native | ipe_ir::Target::WasmClient | ipe_ir::Target::WasmWasi,
        ) => |entry| FrameListRefused::LoopbackAtRelease { entry },
    };
    entries
        .entries()
        .find(|entry| matches!(entry, FrameOriginEntry::Loopback(_)))
        .map_or(Ok(entries), |entry| Err(refusal(entry.clone())))
}

/// The frame origins `program` built under `settings` may emit.
///
/// It is [`frame_origins_for`] over the settings' intent and target, plus the
/// program's shape: a listed entry on a program that registers no frame list
/// is refused rather than dropped.
///
/// # Errors
///
/// [`FrameListRefused`] naming the first entry the build refuses.
pub fn frame_origins_of<'s>(
    program: &ipe_ir::Program,
    settings: &'s EmitSettings,
) -> Result<&'s FrameOriginEntries, FrameListRefused> {
    let entries = frame_origins_for(&settings.frame_origins, settings.intent, settings.target)?;
    dropped_frame_origin(program, settings).map_or(Ok(entries), |entry| {
        Err(FrameListRefused::NoWebLeaf {
            entry: entry.clone(),
        })
    })
}

/// The first listed frame origin `program` built under `settings` would drop.
///
/// `None` for an empty list or a program that registers its list.
pub fn dropped_frame_origin<'s>(
    program: &ipe_ir::Program,
    settings: &'s EmitSettings,
) -> Option<&'s FrameOriginEntry> {
    let first = settings.frame_origins.entries().next()?;
    (!registers_frame_list(program, settings)).then_some(first)
}

/// Whether `program` built under `settings` emits a frame-list registration.
///
/// A browser client registers the list at its entry. A served build
/// registers it at each `Web.tea` or `Web.embed` leaf, except a non-mounted
/// leaf a webview host drives, which serves no page.
fn registers_frame_list(program: &ipe_ir::Program, settings: &EmitSettings) -> bool {
    if settings.target == ipe_ir::Target::WasmClient {
        return true;
    }
    let webview = drives_webview(program, &settings.host);
    let mut registers = false;
    let walked = crate::kernel_walk::each_kernel_site(program, &mut |site| {
        if let crate::kernel_walk::KernelSite::Call { kernel, .. } = site
            && kernel.app_entry_surface() == Some(ipe_ir::AppSurface::Web)
            && (!webview || kernel == ipe_ir::KernelFn::WebEmbed)
        {
            registers = true;
        }
        Ok(())
    });
    walked.is_ok() && registers
}

/// Whether `program` built for `host` is driven by the webview-native executor.
///
/// The `web desktop` host drives it, and so does a source module that carries
/// the webview leaf.
pub fn drives_webview(program: &ipe_ir::Program, host: &EmitHost) -> bool {
    matches!(host, EmitHost::WebView(_)) || program.modules.iter().any(|m| m.uses_webview)
}

/// The [`FieldTag::Host`] payload of `host`.
fn host_payload(host: &EmitHost) -> Vec<u8> {
    let mut payload = Vec::new();
    match host {
        // `Off` is the plain served payload; `On` takes the next free
        // discriminant.
        EmitHost::Served(ServedInstall::Off) => payload.push(0),
        EmitHost::Served(ServedInstall::On { name, icon }) => {
            payload.push(2);
            push_framed(&mut payload, name.as_bytes());
            payload.extend_from_slice(&icon.side().get().to_le_bytes());
            payload.extend_from_slice(icon.digest());
        }
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
    payload
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
    ServerOrigins = 13,
    FrameOrigins = 14,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServedIcon, served_install::test_png};

    /// The `fold_key` records of `settings`, one `[tag, length, payload]` each.
    fn records(settings: &EmitSettings) -> Vec<Vec<u8>> {
        let mut chunks = Vec::new();
        settings.fold_key(&mut |chunk| chunks.push(chunk.to_vec()));
        chunks
    }

    /// The unconfigured settings served with `install`.
    fn served(install: ServedInstall) -> EmitSettings {
        EmitSettings {
            host: EmitHost::Served(install),
            ..EmitSettings::unconfigured()
        }
    }

    /// An install offer named `name` with a 512 px icon whose bytes end in `tail`.
    fn offer(name: &str, tail: &[u8]) -> ServedInstall {
        let mut png = test_png(512, 512);
        png.extend_from_slice(tail);
        ServedInstall::On {
            name: name.to_owned(),
            icon: ServedIcon::from_png(png).expect("square PNG"),
        }
    }

    #[test]
    fn the_install_offer_and_its_icon_bytes_split_the_key() {
        let off = records(&served(ServedInstall::Off));
        let on = records(&served(offer("todo", b"a")));
        assert_ne!(off, on);
        assert_ne!(on, records(&served(offer("todo", b"b"))));
        assert_ne!(on, records(&served(offer("done", b"a"))));
        assert_eq!(on, records(&served(offer("todo", b"a"))));
    }

    /// The unconfigured settings linking a runtime whose digest is `bytes`.
    fn linked(bytes: [u8; 16]) -> EmitSettings {
        EmitSettings {
            runtime_dep: Some(crate::RuntimeDep {
                content: crate::RuntimeContentId::from_digest_bytes(bytes),
            }),
            ..EmitSettings::unconfigured()
        }
    }

    /// The `RuntimeDep` record of `settings`: its payload bytes.
    fn runtime_dep_payload(settings: &EmitSettings) -> Option<Vec<u8>> {
        records(settings)
            .chunks(3)
            .find(|record| record.first().map(Vec::as_slice) == Some(&[FieldTag::RuntimeDep as u8]))
            .and_then(|record| record.get(2).cloned())
    }

    #[test]
    fn the_runtime_content_id_splits_the_key_and_nothing_else_enters_it() {
        let base = [7_u8; 16];
        let mut one_byte_off = base;
        if let Some(last) = one_byte_off.last_mut() {
            *last ^= 1;
        }
        assert_ne!(records(&linked(base)), records(&linked(one_byte_off)));
        assert_eq!(records(&linked(base)), records(&linked(base)));
        assert_ne!(
            records(&linked(base)),
            records(&EmitSettings::unconfigured())
        );
        let mut expected = vec![1_u8];
        push_framed(&mut expected, &base);
        assert_eq!(
            runtime_dep_payload(&linked(base)),
            Some(expected),
            "the dependency record is the presence byte and the framed digest alone",
        );
    }

    /// The entries of `texts`, each a well-formed frame origin.
    #[allow(clippy::expect_used)] // every vector is a well-formed origin
    fn frames(texts: &[&str]) -> FrameOriginEntries {
        FrameOriginEntries::new(
            texts
                .iter()
                .map(|text| FrameOriginEntry::parse(text).expect("a frame origin")),
        )
        .expect("a frame list")
    }

    /// R28: a release build refuses a loopback frame origin and names it; a
    /// development native build admits it; a release build admits `https://` entries.
    #[test]
    fn release_refuses_a_loopback_frame_origin() {
        let loopback = frames(&["https://player.example", "http://localhost:3000"]);
        let refused = frame_origins_for(&loopback, BuildIntent::Release, ipe_ir::Target::Native);
        assert!(
            matches!(&refused, Err(FrameListRefused::LoopbackAtRelease { entry }) if matches!(entry, FrameOriginEntry::Loopback(_))),
            "{refused:?}"
        );
        let Err(refusal) = refused else { return };
        let text = refusal.to_string();
        assert!(text.contains("`http://localhost:3000`"), "{text}");
        assert!(text.contains("served `ipe dev` only"), "{text}");
        assert!(text.contains("a release build"), "{text}");
        assert_eq!(
            frame_origins_for(&loopback, BuildIntent::Development, ipe_ir::Target::Native),
            Ok(&loopback)
        );
        let https = frames(&["https://player.example"]);
        assert_eq!(
            frame_origins_for(&https, BuildIntent::Release, ipe_ir::Target::Native),
            Ok(&https)
        );
        let none = FrameOriginEntries::none();
        assert_eq!(
            frame_origins_for(&none, BuildIntent::Release, ipe_ir::Target::Native),
            Ok(&none)
        );
    }

    /// The verdict a refusal row expects.
    #[derive(Clone, Copy, Debug)]
    enum Row {
        Admits,
        AtRelease,
        InBrowserClient,
    }

    /// R38: one row per `(BuildIntent, Target)`; a loopback entry is admitted
    /// only by a development native or WASI build, and an `https://`-only list
    /// by every build.
    #[test]
    fn frame_list_refusal_table() {
        use ipe_ir::Target;
        let loopback = frames(&["https://player.example", "http://localhost:3000"]);
        let https = frames(&["https://player.example"]);
        let table = [
            (BuildIntent::Development, Target::Native, Row::Admits),
            (BuildIntent::Development, Target::WasmWasi, Row::Admits),
            (
                BuildIntent::Development,
                Target::WasmClient,
                Row::InBrowserClient,
            ),
            (BuildIntent::Release, Target::Native, Row::AtRelease),
            (BuildIntent::Release, Target::WasmClient, Row::AtRelease),
            (BuildIntent::Release, Target::WasmWasi, Row::AtRelease),
        ];
        for (intent, target, row) in table {
            let verdict = frame_origins_for(&loopback, intent, target);
            let held = match row {
                Row::Admits => verdict == Ok(&loopback),
                Row::AtRelease => matches!(
                    &verdict,
                    Err(FrameListRefused::LoopbackAtRelease { entry })
                        if matches!(entry, FrameOriginEntry::Loopback(_))
                ),
                Row::InBrowserClient => matches!(
                    &verdict,
                    Err(FrameListRefused::LoopbackInBrowserClient { entry })
                        if matches!(entry, FrameOriginEntry::Loopback(_))
                ),
            };
            assert!(held, "{intent:?} {target:?}: {verdict:?}, expected {row:?}");
            if let Err(refusal) = &verdict {
                let text = refusal.to_string();
                assert!(text.contains("`http://localhost:3000`"), "{text}");
            }
            assert_eq!(
                frame_origins_for(&https, intent, target),
                Ok(&https),
                "{intent:?} {target:?}"
            );
        }
        let browser = frame_origins_for(&loopback, BuildIntent::Development, Target::WasmClient);
        let Err(refusal) = browser else { return };
        let text = refusal.to_string();
        assert!(text.contains("a browser-built client"), "{text}");
    }

    /// The listed frame origins split the key, and an empty list keeps a
    /// record of its own.
    #[test]
    fn the_frame_origins_split_the_key() {
        let with = |entries| EmitSettings {
            frame_origins: entries,
            ..EmitSettings::unconfigured()
        };
        let none = records(&EmitSettings::unconfigured());
        let one = records(&with(frames(&["https://a.example"])));
        assert_ne!(none, one);
        assert_ne!(one, records(&with(frames(&["https://b.example"]))));
        assert_eq!(one, records(&with(frames(&["https://a.example"]))));
        assert!(
            none.chunks(3)
                .any(|record| record.first().map(Vec::as_slice)
                    == Some(&[FieldTag::FrameOrigins as u8])),
            "the empty list writes its record"
        );
    }

    #[test]
    fn a_served_build_without_install_keeps_its_host_payload() {
        let chunks = records(&served(ServedInstall::Off));
        let host = chunks
            .chunks(3)
            .find(|record| record.first().map(Vec::as_slice) == Some(&[FieldTag::Host as u8]))
            .and_then(|record| record.get(2));
        assert_eq!(host.map(Vec::as_slice), Some(&[0_u8][..]));
    }

    /// The frame-shape tests: programs, kernel calls, and settings.
    mod frame_shape {
        use super::{EmitSettings, FrameListRefused, FrameOriginEntries, frame_origins_of, frames};
        use ipe_ir::{CallPin, Callee, Expr, IrType, KernelFn, OnFormKind, Program};

        /// The written form of `entry`.
        fn entry_text(entry: &ipe_runtime_rust::encoding::FrameOriginEntry) -> String {
            let mut text = String::new();
            entry.write(&mut text);
            text
        }

        /// A call of kernel `kernel` with `args`.
        fn call(kernel: KernelFn, args: Vec<Expr>) -> Expr {
            Expr::Call {
                callee: Callee::Kernel(kernel),
                args,
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            }
        }

        /// A `Server.listen` on port 8000 serving `routes`.
        fn listen(routes: Vec<Expr>) -> Expr {
            call(
                KernelFn::ServerListen,
                vec![
                    Expr::Int(8000),
                    Expr::List {
                        elem: IrType::Unit,
                        items: routes,
                    },
                ],
            )
        }

        /// A server serving `Server.html (Html.render page)`, which has no web leaf.
        fn served_html() -> Expr {
            listen(vec![call(
                KernelFn::ServerHtml,
                vec![call(KernelFn::HtmlRender, vec![Expr::Unit])],
            )])
        }

        /// A server mounting a `Web.embed` leaf at `/app`.
        fn mounted_embed() -> Expr {
            listen(vec![call(
                KernelFn::ServerMountApp,
                vec![
                    Expr::Str("/app".to_owned()),
                    call(KernelFn::WebEmbed, vec![Expr::Unit]),
                ],
            )])
        }

        /// A one-module program whose `main` body is `body`, under `names`.
        fn program_in(names: &mut ipe_intern::Interner, body: Expr, webview: bool) -> Program {
            #[allow(clippy::expect_used)] // two short ASCII names always intern
            let (module, main) = (
                names.intern("Main").expect("intern"),
                names.intern("main").expect("intern"),
            );
            Program {
                imports_unsafe_submodule: false,
                imported_web_capabilities: std::collections::BTreeSet::new(),
                modules: vec![ipe_ir::Module {
                    name: ipe_ir::ModPath(vec![module]),
                    types: vec![],
                    funcs: vec![ipe_ir::Func {
                        id: ipe_ir::FuncId::from_raw(0),
                        name: main,
                        home: ipe_ir::ModPath(vec![module]),
                        type_params: vec![],
                        row_params: vec![],
                        params: vec![],
                        ret: IrType::Unit,
                        body,
                    }],
                    entry: Some(ipe_ir::FuncId::from_raw(0)),
                    records: vec![],
                    uses_tea: false,
                    uses_server: false,
                    uses_http: false,
                    uses_config: false,
                    uses_compression: false,
                    uses_csv: false,
                    uses_cache: false,
                    uses_encoding: false,
                    uses_regex: false,
                    uses_uuid: false,
                    uses_random: false,
                    uses_log: false,
                    uses_decimal: false,
                    uses_char_category: false,
                    uses_crypto_core: false,
                    uses_secret: false,
                    uses_json: false,
                    uses_crypto: false,
                    uses_jwt: false,
                    uses_url: false,
                    uses_ui: false,
                    uses_web: false,
                    uses_tui: false,
                    uses_console: false,
                    uses_css: false,
                    uses_auth: false,
                    uses_principal: false,
                    uses_websocket: false,
                    uses_email: false,
                    uses_locale: false,
                    uses_time: false,
                    uses_env_public: false,
                    uses_debug: false,
                    uses_ffi: false,
                    uses_async_runtime: false,
                    uses_webview: webview,
                }],
            }
        }

        /// [`program_in`] under a fresh interner.
        fn program(body: Expr, webview: bool) -> Program {
            program_in(&mut ipe_intern::Interner::new(), body, webview)
        }

        /// Settings for `target` listing `entries`.
        fn settings(entries: FrameOriginEntries, target: ipe_ir::Target) -> EmitSettings {
            EmitSettings {
                target,
                frame_origins: entries,
                ..EmitSettings::unconfigured()
            }
        }

        /// The listed settings under a native served build.
        fn listed() -> EmitSettings {
            settings(
                frames(&["https://player.example", "https://video.example"]),
                ipe_ir::Target::Native,
            )
        }

        /// T16: a listed origin on a program with no web leaf is refused,
        /// naming the first entry, the problem, and both fixes.
        #[test]
        fn a_list_without_a_web_leaf_is_refused() {
            let listed = listed();
            for body in [
                served_html(),
                call(KernelFn::WebRenderStatic, vec![Expr::Unit]),
                Expr::FuncValue {
                    callee: Callee::Kernel(KernelFn::WebApp),
                    ty: IrType::Unit,
                },
            ] {
                let refused = frame_origins_of(&program(body, false), &listed);
                assert!(
                    matches!(&refused, Err(FrameListRefused::NoWebLeaf { entry })
                        if frames(&[entry_text(entry).as_str()]) == frames(&["https://player.example"])),
                    "{refused:?}"
                );
                let Err(refusal) = refused else { return };
                let text = refusal.to_string();
                assert!(
                    text.contains("`delivery.frameOrigins` lists `https://player.example`"),
                    "{text}"
                );
                assert!(
                    text.contains("serves no page through `Web.tea` or `Web.embed`"),
                    "{text}"
                );
                assert!(
                    text.contains("remove `frameOrigins` from `package.ipe`"),
                    "{text}"
                );
            }
        }

        /// T16: an empty list on a program with no web leaf is admitted.
        #[test]
        fn an_empty_list_without_a_web_leaf_is_admitted() {
            let none = settings(FrameOriginEntries::none(), ipe_ir::Target::Native);
            for body in [
                served_html(),
                call(KernelFn::WebRenderStatic, vec![Expr::Unit]),
            ] {
                assert_eq!(
                    frame_origins_of(&program(body, false), &none),
                    Ok(&FrameOriginEntries::none())
                );
            }
        }

        /// T16: a served `Web.tea`/`Web.embed` leaf and a browser client each
        /// register the list, so each is admitted.
        #[test]
        fn a_list_with_a_web_leaf_is_admitted() {
            let listed = listed();
            for kernel in [
                KernelFn::WebApp,
                KernelFn::WebAppRouted,
                KernelFn::WebAppWith,
                KernelFn::WebEmbed,
            ] {
                let leaf = program(call(kernel, vec![Expr::Unit]), false);
                assert_eq!(
                    frame_origins_of(&leaf, &listed),
                    Ok(&listed.frame_origins),
                    "{kernel:?}"
                );
            }
            let client = settings(listed.frame_origins.clone(), ipe_ir::Target::WasmClient);
            for body in [Expr::Unit, served_html()] {
                assert_eq!(
                    frame_origins_of(&program(body, false), &client),
                    Ok(&client.frame_origins)
                );
            }
        }

        /// T16: a webview host drives a `Web.tea` leaf without serving it, so
        /// the list is refused; a mounted `Web.embed` is still served.
        #[test]
        fn a_webview_driven_leaf_registers_no_list() {
            let listed = listed();
            let driven = program(call(KernelFn::WebApp, vec![Expr::Unit]), true);
            assert!(matches!(
                frame_origins_of(&driven, &listed),
                Err(FrameListRefused::NoWebLeaf { .. })
            ));
            assert_eq!(
                frame_origins_of(&program(mounted_embed(), true), &listed),
                Ok(&listed.frame_origins)
            );
        }

        /// The loopback refusal of the intent and target precedes the shape.
        #[test]
        fn the_loopback_refusal_precedes_the_shape() {
            let loopback = EmitSettings {
                frame_origins: frames(&["http://localhost:3000"]),
                ..EmitSettings::unconfigured()
            };
            assert!(matches!(
                frame_origins_of(&program(served_html(), false), &loopback),
                Err(FrameListRefused::LoopbackAtRelease { .. })
            ));
        }

        /// T16, the emitter's own boundary: a listed origin on a program
        /// with no web leaf never reaches emission, whichever chain asks.
        #[test]
        fn emission_refuses_a_list_without_a_web_leaf() {
            const WHERE: &str = "ipe_backend_rust::EmitCtx::build::frame_origins";
            let mut names = ipe_intern::Interner::new();
            let served = program_in(&mut names, served_html(), false);
            let refused = crate::EmitCtx::build(&names, &served, listed());
            assert!(
                matches!(&refused, Err(ipe_diagnostics::Diagnostic::CompilerBug { where_, detail })
                    if *where_ == WHERE && detail.contains("`https://player.example`")),
                "the frame backstop must refuse"
            );
            let none = settings(FrameOriginEntries::none(), ipe_ir::Target::Native);
            let admitted = crate::EmitCtx::build(&names, &served, none);
            assert!(
                !matches!(&admitted, Err(ipe_diagnostics::Diagnostic::CompilerBug { where_, .. })
                    if *where_ == WHERE),
                "an empty list never reaches the frame backstop"
            );
            let mut names = ipe_intern::Interner::new();
            let leaf = program_in(&mut names, call(KernelFn::WebApp, vec![Expr::Unit]), false);
            let admitted = crate::EmitCtx::build(&names, &leaf, listed());
            assert!(
                !matches!(&admitted, Err(ipe_diagnostics::Diagnostic::CompilerBug { where_, .. })
                    if *where_ == WHERE),
                "a web leaf registers its list"
            );
        }
    }
}
