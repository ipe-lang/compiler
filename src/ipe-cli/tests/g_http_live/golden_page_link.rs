//! `Web.pageLink` — `ipe` accepts and the emitted crate builds.
//!
//! Three program shapes reach the page-link renderer:
//!
//! * a served routed app whose `routes` and every link name one top-level
//!   binding in another module, with a `let`-bound cfg and a partial
//!   application `List.map (Web.pageLink Routes.routes []) cfgs`;
//! * a crate with no `Web.tea` that renders a page link to a string;
//! * the same routed app built for the wasm client target.
//!
//! Each emits; under `IPE_E2E=1` the native crates also `cargo build` (THE
//! SEAL: `ipe`-accepts ⇒ `cargo`-builds).

use std::path::{Path, PathBuf};

use ipe::project_root::SourceTree;
use ipe::{BuildOptions, CliError};

/// The page type and the one route table every link and the app name.
const ROUTES: &str = "module Routes exposing (Page(..), routes)\n\
     \n\
     import Ipe.Tea.Web as Web\n\
     \n\
     type Page = HomePage | AboutPage | PostPage Int\n\
     \n\
     routes : List (WebRoute Page)\n\
     routes =\n\
     \x20   [ Web.route \"/\" HomePage, Web.route \"/about\" AboutPage, Web.route \"/posts/:id\" PostPage ]\n";

/// A routed app linking every page through `Web.pageLink`.
const ROUTED_APP: &str = "module Main exposing (main)\n\
     \n\
     import Ipe.List as List\n\
     import Ipe.Tea.Web as Web\n\
     import Ipe.Tea.Web.Cmd as Cmd\n\
     import Ipe.Tea.Web.Sub as Sub\n\
     import Ipe.Ui as Ui\n\
     import Routes exposing (Page(..))\n\
     \n\
     type alias Model = { page : Page }\n\
     \n\
     type Msg = Noop\n\
     \n\
     init : WebReq -> ( Model, Cmd.Cmd Msg )\n\
     init _req = ( { page = HomePage }, Cmd.none )\n\
     \n\
     update : Msg -> Model -> ( Model, Cmd.Cmd Msg )\n\
     update _msg model = ( model, Cmd.none )\n\
     \n\
     subscriptions : Model -> Sub.Sub Msg\n\
     subscriptions _model = Sub.none\n\
     \n\
     navItems : Page -> List { to : Page, current : Page, label : Element Msg }\n\
     navItems current =\n\
     \x20   [ { to = HomePage, current = current, label = Ui.text \"Home\" }\n\
     \x20   , { to = PostPage 7, current = current, label = Ui.text \"Post\" }\n\
     \x20   ]\n\
     \n\
     view : Model -> Element Msg\n\
     view model =\n\
     \x20   let\n\
     \x20       about = { to = AboutPage, current = model.page, label = Ui.text \"About\" }\n\
     \x20   in\n\
     \x20   Ui.column []\n\
     \x20       [ Web.pageLink Routes.routes [] about\n\
     \x20       , Ui.column [] (List.map (Web.pageLink Routes.routes []) (navItems model.page))\n\
     \x20       ]\n\
     \n\
     main =\n\
     \x20   Web.tea\n\
     \x20       { init = init\n\
     \x20       , update = update\n\
     \x20       , view = view\n\
     \x20       , subscriptions = subscriptions\n\
     \x20       , routes = Routes.routes\n\
     \x20       , notFound = HomePage\n\
     \x20       }\n";

/// A crate with no `Web.tea`: `main` renders a page link to a string.
const NO_APP: &str = "module Main exposing (main)\n\
     \n\
     import Ipe.Html as Html\n\
     import Ipe.Io as Io\n\
     import Ipe.Tea.Web as Web\n\
     import Ipe.Ui as Ui\n\
     import Routes exposing (Page(..))\n\
     \n\
     type Msg = Noop\n\
     \n\
     link : Element Msg\n\
     link = Web.pageLink Routes.routes [] { to = PostPage 3, current = HomePage, label = Ui.text \"Post\" }\n\
     \n\
     main = Io.println (Html.render (Ui.layout [] link))\n";

/// A fresh emit directory this test alone owns.
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    e2e_support::scratch::fresh(&dir);
    dir
}

/// Emit the two-module project whose `Main` is `main` into `out`.
#[allow(clippy::expect_used)] // test helper: a failed fixture setup IS the failure
fn emit(main: &str, out: &Path, options: &BuildOptions) -> Result<(), CliError> {
    let tree = SourceTree::main(main).module("Routes", ROUTES);
    let fixture = ipe::RootFixture::from_tree(&tree).expect("write and resolve the fixture");
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build_fixture_with_options(&fixture, out, &runtime, options).map(drop)
}

/// Assert that `main` emits under `options`, that the emitted crate renders
/// its links through the page renderer, and return the emit directory.
#[allow(clippy::expect_used)] // test helper: an unreadable emit IS the failure
fn assert_emits(name: &str, main: &str, options: &BuildOptions) -> PathBuf {
    let out = scratch(name);
    let result = emit(main, &out, options);
    assert!(
        result.is_ok(),
        "{name}: ipe must accept: {:?}",
        result.err()
    );
    let emitted = crate::support::read_all_emitted_src(&out);
    assert!(
        emitted.contains("web_page_link(") && emitted.contains("__ipe_render_page("),
        "{name}: every page link renders its href through the table's renderer",
    );
    out
}

/// A served routed app: one binding table across modules, a `let`-bound cfg
/// and a partial application. `ipe` accepts it and the crate builds.
#[test]
#[allow(clippy::expect_used)] // a missing build option set IS the failure
fn page_link_routed_app_builds() {
    let options = BuildOptions::from_env().expect("read the build options");
    let out = assert_emits("page_link_routed_app", ROUTED_APP, &options);
    crate::support::assert_seal_builds("page_link_routed_app", &out);
}

/// A crate with no `Web.tea` renders a page link; `ipe` accepts it and the
/// crate builds.
#[test]
#[allow(clippy::expect_used)] // a missing build option set IS the failure
fn page_link_without_app_builds() {
    let options = BuildOptions::from_env().expect("read the build options");
    let out = assert_emits("page_link_without_app", NO_APP, &options);
    crate::support::assert_seal_builds("page_link_without_app", &out);
}

/// The routed app on the wasm client target emits through the same renderer.
#[test]
fn page_link_wasm_app_emits() {
    let options = BuildOptions {
        target: ipe_ir::Target::WasmClient,
        ..BuildOptions::default()
    };
    assert_emits("page_link_wasm_app", ROUTED_APP, &options);
}
