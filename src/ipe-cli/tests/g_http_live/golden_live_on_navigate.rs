//! Routed `Web.tea` with an explicit `onNavigate : page -> msg` cfg field:
//! every URL-driven route change is turned into a `Msg` and dispatched through
//! `update`, so the app owns navigation instead of the runtime mutating the
//! model's `page` field.
//!
//! ## What this pins
//!
//! * ipe compiles the `onNavigate`-carrying routed app (the field is absorbed
//!   by the open Live cfg row).
//! * The emitted `set_page` closure passed to `web_app_routed` routes the
//!   matched page through the author's `update` (`(update)((onNavigate)(page),
//!   model)`) and returns `update`'s whole `(Model, Cmd)` — the entry Cmd is
//!   kept, never discarded.
//! * The absent-field form (`live_param_routes`) pairs the struct-updated
//!   model with `IpeCmd::None`.
//! * The absent-field magic-page struct-update closure
//!   (`Model { page: __page, ..__model }`) is NOT emitted for this app — that
//!   form is reserved for apps that omit `onNavigate`.
//!
//! Compile-only assertions always run, and an unresolvable runtime tree
//! fails them. Under `IPE_E2E=1` the emitted project (whose `Navigate` arm
//! returns a `Cmd.perform`) must cargo-build.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Compile the on-disk `golden` fixture into `out` and return the whole emitted source.
///
/// `slug` uniquely names the emit directory per test: both tests in this file
/// compile the same golden but run as separate nextest processes sharing one
/// `CARGO_TARGET_TMPDIR`, so a shared output path would let one test's initial
/// `remove_dir_all` delete a directory the other is emitting into or reading.
// test scaffolding: an ipe-compile failure or a missing emitted file IS the
// failure signal we want to surface loudly.
#[allow(clippy::expect_used)]
fn emit_golden(golden: &str, out: &Path) -> String {
    let entry = repo_root()
        .join("tests")
        .join("golden")
        .join(golden)
        .join("Main.ipe");
    let _ = std::fs::remove_dir_all(out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, out, &runtime).expect("routed app must ipe-compile");
    // A layout builder is compiled-source Ipê, so a home may lower to
    // `src/ipe_mods/*.rs` — scan the WHOLE emitted Ipê-side tree.
    crate::support::read_all_emitted_src(out)
}

/// Compile the `live_on_navigate` golden into a per-`slug` dir and return the emitted source.
fn emit_main_rs(slug: &str) -> String {
    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("live_on_navigate_emit_{slug}"));
    emit_golden("live_on_navigate", &out)
}

/// The `onNavigate` cfg field makes the runtime `set_page` closure route the
/// matched page through `update` — the URL navigation is a `Msg`, not a magic
/// `page`-field write.
#[test]
fn on_navigate_dispatches_matched_page_through_update() {
    let main_rs = emit_main_rs("dispatch");
    assert!(
        main_rs.contains("web_app_routed"),
        "a Model with a `page` field must emit `web_app_routed`",
    );
    // The set_page closure captures update + onNavigate and threads the matched
    // page through `update`, returning its `(Model, Cmd)` so the entry Cmd runs.
    assert!(
        main_rs.contains("let __on_navigate ="),
        "onNavigate present ⇒ the set_page closure must bind the handler, \
         got:\n{main_rs}",
    );
    assert!(
        main_rs.contains("(__update)((__on_navigate)(__page), __model)"),
        "onNavigate present ⇒ the matched page must flow \
         `update(onNavigate(page), model)`, got:\n{main_rs}",
    );
    assert!(
        !main_rs.contains(", _cmd) = (__update)"),
        "the entry Cmd must be returned, never bound and dropped, got:\n{main_rs}",
    );
}

/// The magic-page struct-update closure is the ABSENT-field desugaring only;
/// an app that supplies `onNavigate` must never emit it.
#[test]
fn on_navigate_present_suppresses_magic_page_struct_update() {
    let main_rs = emit_main_rs("suppress");
    assert!(
        !main_rs.contains("{ page: __page, ..__model }"),
        "onNavigate present ⇒ the runtime must NOT struct-update the `page` \
         field directly (that is the absent-field desugaring), got:\n{main_rs}",
    );
}

/// The absent-field desugaring pairs the struct-updated model with an empty entry Cmd.
#[test]
fn implicit_set_page_returns_model_and_no_cmd() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("live_on_navigate_implicit_emit");
    let main_rs = emit_golden("live_param_routes", &out);
    assert!(
        main_rs.contains("{ page: __page, ..__model }, ipe_runtime::tea::IpeCmd::None)"),
        "onNavigate absent ⇒ set_page must return `(Model {{ page, .. }}, IpeCmd::None)`, \
         got:\n{main_rs}",
    );
}

/// `IPE_E2E` tier: the app whose `Navigate` arm returns a `Cmd.perform` entry Cmd must cargo-build.
#[test]
fn on_navigate_entry_cmd_app_cargo_builds() {
    if ipe_env::var("IPE_E2E").is_err() {
        return;
    }
    // A PRIVATE dir this test alone owns, so a compile-only sibling cannot
    // delete rustc's working directory mid-build.
    let out = crate::support::scratch_root().join("live_on_navigate_e2e_out");
    emit_golden("live_on_navigate", &out);
    let built = e2e_support::build_rust_binary("live_on_navigate", &out);
    assert!(
        built.is_ok(),
        "the onNavigate entry-Cmd project must cargo-build\n{}",
        built.err().unwrap_or_default(),
    );
}
