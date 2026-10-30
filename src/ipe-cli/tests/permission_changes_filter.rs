#![forbid(unsafe_code)]
//! Regression: `Ipe.Browser.Permission.changes name` filters its inbound stream
//! to `name`, and ONLY `name`.
//!
//! Issue: `changes` discarded its `name` argument (`changes _ toMsg = ...`), so a
//! subscription for permission X folded in change frames for EVERY watched
//! permission Y. The signature advertised a per-name filter the code did not
//! perform — an app could misread a `Geolocation: granted` frame as its `Camera`
//! subscription reporting `granted` (a Correctness break).
//!
//! The structural fix moves the filter into the decoder — the existing
//! fail-closed trust boundary. `Ipe.Browser.Permission.Internals.subscribeFor
//! name` gates the inbound stream with `inboundFor name`: a frame decodes only
//! when its `name` field equals `name`'s canonical token (`nameToken`), else the
//! decode FAILS and the frame is dropped whole — exactly as a malformed frame is.
//! A frame for a different permission therefore cannot reach the subscription.
//!
//! These gates drive the REAL compiler pipeline (canon → type-check → lower) over
//! the modified stdlib closure, in the fast (non-E2E) path:
//!
//! * the filtered `changes` / `subscribeFor` / `inboundFor` API type-checks
//!   end to end (the SEAL: ipe-accepts ⇒ the emitted Rust compiles); and
//! * `nameToken` is total AND injective — a per-permission gate is only sound if
//!   no two permission names share a wire token (a collision would let one
//!   permission's frames pass another's gate). The Ipê `case` over the closed
//!   `PermissionName` proves totality; the token-distinctness assertion here
//!   proves injectivity of the SSOT the gate compares against.
//!
//! `Ipe.Browser.*` is a browser-host module: importing it from a plain `main`
//! entry is refused by the Library-SSOT placement gate (IPE-N0047), so — as the
//! stdlib-export-resolvability gate does for shape modules — the browser import
//! is routed through a `main`-less helper (exempt from the entry gate) while
//! `Main` stays a plain Program.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ipe::project;

type UserSources = BTreeMap<Vec<String>, String>;
type PreparedSources = BTreeMap<Vec<String>, (PathBuf, String)>;

fn prepared(user: &UserSources) -> (PreparedSources, BTreeSet<Vec<String>>) {
    let mut sources: PreparedSources = user
        .iter()
        .map(|(p, text)| {
            (
                p.clone(),
                (
                    PathBuf::from(format!("<permchg>/{}.ipe", p.join("/"))),
                    text.clone(),
                ),
            )
        })
        .collect();
    let mut discovered: Vec<project::DiscoveredModule> = sources
        .iter()
        .map(|(p, (path, _))| project::DiscoveredModule::user(path.clone(), p.clone()))
        .collect();
    let injected = project::inject_compiled_std_closure(&mut sources, &mut discovered);
    (sources, injected)
}

fn entry_path() -> Vec<String> {
    vec!["Main".to_owned()]
}

/// Compile a plain-`main` `Main` plus extra user modules through the production
/// pipeline; `Ok` iff the whole closure canonicalises, type-checks, and lowers.
fn compile_with_helper(main: &str, extras: &[(Vec<String>, String)]) -> Result<(), String> {
    let mut user = UserSources::new();
    user.insert(entry_path(), main.to_owned());
    for (path, text) in extras {
        user.insert(path.clone(), text.clone());
    }
    let (sources, injected) = prepared(&user);
    let db = ipe_db::IpeDatabase::new();
    let root = ipe::create_source_root(&db, &sources, &injected, &BTreeSet::new());
    let config = ipe_db::BuildConfig::new(
        &db,
        ipe_backend_rust::EmitSettings {
            db_driver: ipe_backend_rust::DbDriver::Sqlite,
            ffi: None,
            target: ipe_ir::Target::Native,
            wasm_public_env: Vec::new(),
            mount_base: ipe_backend_rust::MountBase::root(),
            server_origins: ipe_backend_rust::ServerOrigins::none(),
            wasm_hydrate_mode: false,
            runtime_dep: None,
            debugger: false,
            crate_name: ipe_backend_rust::CrateName::SingleFile,
            hot_appearance: false,
            host: ipe_backend_rust::EmitHost::Served(ipe_backend_rust::ServedInstall::Off),
            intent: ipe_backend_rust::BuildIntent::Development,
        },
    );
    ipe::compile_prepared(
        &db,
        root,
        &sources,
        &entry_path(),
        Path::new("<permchg>"),
        config,
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// The filtered subscription API — `changes name`, and the `subscribeFor` /
/// `inboundFor` / `nameToken` seam it rests on — type-checks end to end.
///
/// The helper (`main`-less, so exempt from IPE-N0047) exercises every new
/// surface: a per-name subscription (`Permission.changes`), the name-gated
/// subscription and decoder (`Internals.subscribeFor`, `Internals.inboundFor`),
/// and the canonical wire token (`Internals.nameToken`). A regression that
/// dropped the `name` gate — e.g. reverting `changes` to `changes _ toMsg` — or
/// a mistyped gate would fail this compile pre-cargo (the SEAL).
#[test]
fn filtered_changes_api_type_checks() {
    let helper = concat!(
        "module Probe exposing (probe)\n",
        "import Ipe.Browser.Permission as Permission\n",
        "import Ipe.Browser.Permission.Internals as Internals\n",
        "import Ipe.Error exposing (Error)\n",
        "import Ipe.Json.Decode as Decode\n",
        "import Ipe.Tea.Web.Sub as Sub\n\n",
        "-- A per-name subscription: the public `changes` now takes its `name`.\n",
        "cameraChanges : (Result Error Permission.PermissionState -> msg) -> Sub.Sub msg\n",
        "cameraChanges toMsg =\n",
        "    Permission.changes Internals.Camera toMsg\n\n",
        "-- The name-gated inbound decoder for a single permission.\n",
        "cameraDecoder : Decode.Decoder Internals.JsMsg\n",
        "cameraDecoder =\n",
        "    Internals.inboundFor Internals.Camera\n\n",
        "-- The name-gated subscription seam.\n",
        "cameraSub : (Internals.JsMsg -> msg) -> Sub.Sub msg\n",
        "cameraSub toMsg =\n",
        "    Internals.subscribeFor Internals.Camera toMsg\n\n",
        "-- The canonical wire token SSOT the gate compares against.\n",
        "cameraToken : String\n",
        "cameraToken =\n",
        "    Internals.nameToken Internals.Camera\n",
    );
    let main = concat!(
        "module Main exposing (main)\n",
        "import Ipe.Io as Io\n",
        "import Probe\n\n",
        "main : Task Error ()\n",
        "main =\n",
        "    Io.println \"ok\"\n",
    );
    let result = compile_with_helper(main, &[(vec!["Probe".to_owned()], helper.to_owned())]);
    assert!(
        result.is_ok(),
        "the filtered `changes`/`subscribeFor`/`inboundFor`/`nameToken` API must \
         type-check through the real pipeline (the SEAL); a failure here means the \
         per-name filter regressed or is mistyped:\n{}",
        result.err().unwrap_or_default(),
    );
}

/// `nameToken` is INJECTIVE across the closed `PermissionName` set: every name
/// maps to a distinct wire token.
///
/// The gate in `inboundFor name` accepts a frame iff its `name` field equals
/// `nameToken name`, so two permissions sharing a token would let one's frames
/// pass the other's gate.
///
/// The parsed `PermissionName` constructors, the parsed `nameToken` arms and the
/// glue's `PERMISSION_NAMES` (the token table the first-party sink queries) are
/// one mapping, and its tokens are pairwise distinct. A constructor, arm or glue
/// row added on one side alone turns this red.
#[test]
#[allow(clippy::expect_used, clippy::panic)] // A test: the stdlib module and its names must exist.
fn name_tokens_are_pairwise_distinct() {
    let source = ipe_stdlib::COMPILED_STD_MODULES
        .iter()
        .find(|m| m.dotted == "Ipe.Browser.Permission.Internals")
        .map(|m| m.source)
        .expect("Permission.Internals is a compiled-source stdlib module");
    let mut interner = ipe_intern::Interner::new();
    let module =
        ipe_parse::parse_module(source, &mut interner).expect("Permission.Internals parses");
    let permission_name = interner.intern("PermissionName").expect("a name interns");
    let name_token = interner.intern("nameToken").expect("a name interns");

    let ctors: BTreeSet<&str> = module
        .unions
        .iter()
        .find(|u| u.value.name.value == permission_name)
        .expect("Permission.Internals declares PermissionName")
        .value
        .ctors
        .iter()
        .filter_map(|c| interner.resolve(c.value.name))
        .collect();

    let body = &module
        .values
        .iter()
        .find(|v| v.value.name.value == name_token)
        .expect("Permission.Internals defines nameToken")
        .value
        .body
        .value;
    let ipe_syntax::Expr_::Case(_, arms) = body else {
        panic!("nameToken is not one case over PermissionName")
    };
    let mut tokens: BTreeMap<&str, &str> = BTreeMap::new();
    for (pattern, rhs) in arms {
        let arm = match (&pattern.value, &rhs.value) {
            (ipe_syntax::Pattern_::PCtor(ctor, _, args), ipe_syntax::Expr_::Str(token))
                if args.is_empty() =>
            {
                interner.resolve(*ctor).map(|ctor| (ctor, token.as_str()))
            }
            _ => None,
        };
        assert!(arm.is_some(), "a nameToken arm is not `Ctor -> \"token\"`");
        if let Some((ctor, token)) = arm {
            assert!(
                tokens.insert(ctor, token).is_none(),
                "nameToken repeats {ctor}"
            );
        }
    }

    let glue: BTreeMap<&str, &str> = ipe_runtime_rust::js_port_glue::PERMISSION_NAMES
        .iter()
        .copied()
        .collect();
    assert_eq!(
        tokens, glue,
        "nameToken and the glue's PERMISSION_NAMES name different tokens"
    );
    assert_eq!(
        ctors,
        tokens.keys().copied().collect::<BTreeSet<_>>(),
        "PermissionName and nameToken name different permissions"
    );
    let distinct: BTreeSet<&str> = tokens.values().copied().collect();
    assert_eq!(
        distinct.len(),
        tokens.len(),
        "two permission names share a wire token"
    );
}
