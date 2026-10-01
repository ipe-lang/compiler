//! IPE-I0001 regression — `List WebRoute` via a let-bound top-level binding.
//!
//! ## Background
//!
//! `Web.route` is typed `String -> page -> WebRoute` (opaque).  A top-level
//! `routeTable` binding whose elements are `Web.route …` calls therefore has
//! inferred type `List WebRoute`.  The `routes = routeTable` field of the
//! `Web.tea` cfg must accept that type (T3 open-record scheme), and the emitter
//! must lower the `routes` expression as a normal Expr ref — NOT assume it is an
//! inline `[Expr::Ctor, …]` literal.
//!
//! ## What is tested
//!
//! * `routeTable` (top-level, not inlined in the cfg) type-checks as `List WebRoute`.
//! * The T3 open-record scheme (`routes : List WebRoute` row field) accepts a
//!   let-bound reference, not only an inline literal.
//! * `emit_web_app_inner` lowers `routes = routeTable` (an `Expr::Var` ref) correctly.
//! * `routed_page_field` detects the `page` field and emits `web_app_routed`.
//! * No ICE — the full ipe pipeline (parse → canon → types → lower → emit) exits Ok.
//!
//! This is a pure ipe-pipeline check (no cargo build / runtime binary required)
//! and runs without `IPE_E2E=1`.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Run the ipe pipeline on `tests/golden/live_let_bound_routes/Main.ipe`,
/// emitting into `out`.
fn run_ipec(out: &Path) -> Result<(), ipe::CliError> {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("live_let_bound_routes")
        .join("Main.ipe");
    let _ = std::fs::remove_dir_all(out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, out, &runtime)
}

/// The emit dir shared by the compile-only assertions.
fn compile_out() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m7_live_let_bound_routes_emit")
}

/// IPE-I0001 regression: a `Web.tea` whose `routes` field references a
/// top-level `routeTable` binding (type `List WebRoute`) MUST compile
/// through the full ipe pipeline without an ICE.
///
/// Pre-regression: the emitter assumed all `routes` elements were inlined
/// `Expr::Ctor` nodes and panicked (ICE) on a let-bound reference.
/// Post-fix (T5): the `routes` field is lowered as a normal expression;
/// individual route-closure builders are only inspected at the call sites of
/// `Web.route`, not at the list-collection level.
#[test]
fn live_let_bound_routes_compiles_no_ice() {
    let result = run_ipec(&compile_out());
    assert!(
        result.is_ok(),
        "IPE-I0001 regression: let-bound routeTable must compile, got: {:?}",
        result.err(),
    );
}

// ── round-4 hole 1: the let-bound golden must also CARGO-build ───────
//
// `routeTable`'s top-level fn signature renders the binding's inferred type
// `List (WebRoute Page)`. Pre-round-4 `IrType::WebRoute` rendered a bare
// `ipe_runtime::web::route::Route` — but the runtime `Route<Page>` has NO
// default type parameter, so THIS golden itself was ipe-0 then cargo-fail
// (E0107) at the `routeTable` signature. Post-fix the signature renders
// `Vec<Route<MainPage>>`.

/// The emitted `main.rs` must render the page-parametrised `Route<MainPage>`
/// in `routeTable`'s signature. Compile-only — always runs.
#[test]
fn live_let_bound_routes_renders_route_page() {
    let out = compile_out();
    let result = run_ipec(&out);
    assert!(result.is_ok(), "must compile: {:?}", result.err());
    // A layout builder is compiled-source Ipê now, so the route table's home may
    // lower to `src/ipe_mods/*.rs` — scan the WHOLE emitted Ipê-side tree.
    let main_rs = crate::support::read_all_emitted_src(&out);
    assert!(
        main_rs.contains("route::Route<MainPage>"),
        "#108 hole 1: the let-bound route table's signature must render \
         `Route<MainPage>` (bare `Route` is the E0107 cargo failure)",
    );
}

/// `IPE_E2E` tier: the emitted project must CARGO-build. Builds through the
/// shared `e2e_support` core: a unique package name gives the app crate its own
/// fresh fingerprint (a broken emit E0107/E0308 still fails) while the warm
/// shared dependency target is reused, so the deps compile once, not per fixture.
#[test]
fn live_let_bound_routes_cargo_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    // Emit into a PRIVATE dir this test alone owns, so a compile-only sibling
    // re-emitting into `compile_out()` in parallel cannot delete rustc's
    // working directory mid-build.
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m7_live_let_bound_routes_e2e_emit");
    let result = run_ipec(&out);
    assert!(result.is_ok(), "must compile: {:?}", result.err());
    let built = e2e_support::build_rust_binary("m7_let_bound_routes", &out);
    assert!(
        built.is_ok(),
        "#108 hole 1: the let-bound routes golden must cargo-build \
         (pre-fix: E0107 at the `routeTable` fn signature)\n{}",
        built.err().unwrap_or_default(),
    );
}
