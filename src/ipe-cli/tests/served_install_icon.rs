//! A served build of an installable app refuses an unfit icon: the build
//! stops with the catalog message, never a silently non-installable app.

use std::path::PathBuf;

use ipe::CliError;

/// A served TEA app, the smallest `web served` program.
const SERVED_APP: &str = "module Main exposing (main)\n\
         import Ipe.String as String\n\
         import Ipe.Tea.Web exposing (tea)\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\
         import Ipe.Ui as Ui\n\
         \n\
         type Page = CounterPage\n\
         type Msg = Increment\n\
         type alias Model = { count : Int }\n\
         \n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req = ( { count = 0 }, Cmd.none )\n\
         \n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update msg model =\n\
         \x20   case msg of\n\
         \x20       Increment -> ( { model | count = model.count + 1 }, Cmd.none )\n\
         \n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model = Sub.none\n\
         \n\
         view : Model -> Element Msg\n\
         view model =\n\
         \x20   Ui.button [] { onPress = Just Increment, label = Ui.text (String.fromInt model.count) }\n\
         \n\
         main =\n\
         \x20   tea\n\
         \x20       { init = init\n\
         \x20       , update = update\n\
         \x20       , view = view\n\
         \x20       , subscriptions = subscriptions\n\
         \x20       , routes = []\n\
         \x20       }\n";

/// The project-relative icon path the fixtures declare.
const ICON: &str = "assets/icon.png";

/// A fresh output directory for `name`.
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The signature and `IHDR` chunk of a square `side` by `side` PNG.
fn png(side: u32) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR".to_vec();
    bytes.extend_from_slice(&side.to_be_bytes());
    bytes.extend_from_slice(&side.to_be_bytes());
    bytes.extend_from_slice(&[8, 6, 0, 0, 0, 0, 0, 0, 0]);
    bytes
}

/// Build the installable served app whose icon file holds `icon`.
#[allow(clippy::expect_used)] // test helper: a failed fixture setup IS the failure
fn build_installable(name: &str, icon: &[u8]) -> Result<(), CliError> {
    let tree = ipe::project_root::SourceTree::main(SERVED_APP)
        .field(&format!("icon = {ICON:?}"))
        .field("delivery = { browser = { installable = True } }");
    let fixture = ipe::RootFixture::from_tree(&tree).expect("write the project fixture");
    let assets = fixture.path().join("assets");
    std::fs::create_dir_all(&assets).expect("create assets/");
    std::fs::write(assets.join("icon.png"), icon).expect("write the icon");
    let out = scratch(name).join("out");
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build_fixture(&fixture, &out, &runtime).map(drop)
}

/// A non-PNG icon stops the served build with the not-PNG catalog message.
#[test]
fn a_non_png_icon_stops_the_served_build() {
    let result = build_installable("served_install_icon_gif", b"GIF89a\x00\x02\x00\x02");
    let expected = ipe::text::msg::manifest_icon_not_png(&format!("{ICON:?}")).to_string();
    assert!(
        matches!(&result, Err(CliError::Usage(msg)) if msg.contains(&expected)),
        "the build is refused with {expected:?}: {result:?}"
    );
}

/// A square PNG of the minimum side is past the icon rule.
#[test]
fn a_fit_icon_is_past_the_icon_rule() {
    let result = build_installable("served_install_icon_fit", &png(192));
    assert!(
        !matches!(&result, Err(CliError::Usage(msg)) if msg.contains("icon")),
        "a fit icon is not refused: {result:?}"
    );
}
