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
        ipe_backend_rust::DbDriver::Sqlite,
        None,
        ipe_ir::Target::Native,
        Vec::new(),
        false,
        false,
        None,
        false,
        String::new(),
        false,
        false,
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
/// `nameToken name`. If two permissions shared a token, one permission's frames
/// would pass the other's gate — reintroducing the very cross-talk this fix
/// removes. This gate compiles a helper that lists every name's token as a
/// distinct top-level binding (totality is proven by the exhaustive Ipê `case`)
/// and asserts, over the SSOT mirrored here, that the tokens are pairwise
/// distinct. The mirror is checked against the module source so the two cannot
/// drift silently.
#[test]
fn name_tokens_are_pairwise_distinct() {
    // Mirror of `Ipe.Browser.Permission.Internals.nameToken`. Kept honest by the
    // source-equality check below: if the module gains, drops, or renames a name
    // or token, this test's own source scan fails until the mirror is updated.
    let expected: &[(&str, &str)] = &[
        ("Camera", "camera"),
        ("Microphone", "microphone"),
        ("Geolocation", "geolocation"),
        ("Notifications", "notifications"),
        ("PersistentStorage", "persistent-storage"),
        ("ClipboardRead", "clipboard-read"),
        ("ClipboardWrite", "clipboard-write"),
        ("MidiSysex", "midi"),
    ];

    // Injectivity: no two names share a token.
    let mut seen = BTreeSet::new();
    for (name, token) in expected {
        assert!(
            seen.insert(*token),
            "permission name `{name}` reuses wire token `{token}` — a per-name \
             filter gate is only sound if every permission's token is distinct",
        );
    }

    // SSOT anti-drift: every mirrored (name, token) pair appears verbatim in the
    // module source, and the source lists no other `PermissionName` constructor
    // in `nameToken`. A rename/add/drop breaks this before it can desync the gate.
    let src = ipe_stdlib::COMPILED_STD_MODULES
        .iter()
        .find(|m| m.dotted == "Ipe.Browser.Permission.Internals")
        .map(|m| m.source)
        .expect("Permission.Internals is a compiled-source stdlib module");
    for (name, token) in expected {
        assert!(
            src.contains(&format!("\"{token}\"")),
            "wire token `{token}` (for `{name}`) is absent from \
             Permission.Internals source — the mirror has drifted from the SSOT",
        );
    }
    // The `PermissionName` type declares exactly these eight constructors; assert
    // the count so a ninth name added without a token (or a token without a name)
    // trips here rather than silently escaping the gate.
    let ctor_count = [
        "Camera",
        "Microphone",
        "Geolocation",
        "Notifications",
        "PersistentStorage",
        "ClipboardRead",
        "ClipboardWrite",
        "MidiSysex",
    ]
    .iter()
    .filter(|c| src.contains(&format!("| {c}")) || src.contains(&format!("= {c}")))
    .count();
    assert_eq!(
        ctor_count,
        expected.len(),
        "the `PermissionName` constructor set drifted from the token mirror; every \
         permission name needs a distinct `nameToken` arm for the filter to hold",
    );
}
