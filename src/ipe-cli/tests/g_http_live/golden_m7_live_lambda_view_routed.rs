//! A ROUTED app whose `view` is an inline LAMBDA must emit `web_app_routed`,
//! not silently fall back to the non-routed `web_app`.
//!
//! ## Background
//!
//! `emit_web::routed_page_field` recovers the Model from the cfg's `view`
//! field via `emit_model_gate::model_ty_of_view`. If that helper matched
//! ONLY `Expr::FuncValue`, a lambda `view` would return `None` and the emitter
//! silently choose the single-page `web_app` — `routes` and `notFound`
//! DISCARDED with no diagnostic (ipe-0, cargo-0, wrong runtime behaviour: a
//! silent wrong-accept, worse than a cargo failure). Meanwhile the type tier's
//! `RoutedWebCheck` reads the SOLVER's Model and classifies the
//! same app as routed — the two tiers would disagree exactly on the lambda-view
//! shape.
//!
//! `fn_param_ty` (matching both `Expr::FuncValue` and `Expr::Lambda`) is shared
//! by the Model gate and `routed_page_field`, so the tiers agree. The Model-gate
//! side is pinned in `model_admissibility.rs` (`live_lambda_view_*`); THIS file
//! pins the routed emit side.
//!
//! Compile-only assertions always run; the cargo build is `IPE_E2E=1`-gated and
//! runs through `e2e_support::build_rust_binary` (unique package name → fresh
//! app fingerprint; warm shared dependency target reused). A broken emit still
//! fails to build, so the SEAL stays sound.

use std::path::{Path, PathBuf};

/// Routed cfg (routes + notFound, Model has `page : Page`) with an inline
/// LAMBDA `view`. Plain-data Model, so the admissibility gate passes —
/// isolating the routed-detection behaviour.
const LIVE_LAMBDA_VIEW_ROUTED: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.String
import Ipe.Tea.Web.Sub
type Page = CounterPage | AboutPage
type Msg = Increment
type alias Model = { page : Page, count : Int }
init : WebReq -> ( Model, Cmd Msg )
init _req = ( { page = CounterPage, count = 0 }, Cmd.none )
update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment -> ( { model | count = model.count + 1 }, Cmd.none )
subscriptions : Model -> Sub Msg
subscriptions _model = Sub.none
main =
    Web.tea
        { init = init, update = update
        , view = \model -> Ui.text (String.fromInt model.count)
        , subscriptions = subscriptions
        , routes = [ Web.route "/" CounterPage, Web.route "/about" AboutPage ]
        , notFound = CounterPage
        }
"#;

fn out_dir() -> PathBuf {
    crate::support::scratch_root().join("m7_live_lambda_view_routed_out")
}

/// Compile the fixture into `out`. `tag` names a private source dir so parallel callers never share
/// the `Main.ipe` staging path.
#[allow(clippy::expect_used)] // an unwritable scratch dir is the test failure
fn compile(tag: &str, out: &Path) -> Result<(), ipe::CliError> {
    let ipe_dir =
        crate::support::scratch_root().join(format!("m7_live_lambda_view_routed_{tag}_ipe"));
    let _ = std::fs::remove_dir_all(&ipe_dir);
    std::fs::create_dir_all(&ipe_dir).expect("the fixture scratch dir must be writable");
    let entry = ipe_dir.join("Main.ipe");
    std::fs::write(&entry, LIVE_LAMBDA_VIEW_ROUTED)
        .expect("the fixture scratch dir must be writable");
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, out, &runtime)
}

/// The lambda-view routed app must be ipe-0 AND emit `web_app_routed` with
/// its routes wired — never silently emit the non-routed `web_app` and drop
/// `routes`/`notFound`.
#[test]
fn lambda_view_routed_app_emits_web_app_routed() {
    let result = compile("main", &out_dir());
    assert!(
        result.is_ok(),
        "#108 hole 2: lambda-view routed app must be ipe-0, got: {:?}",
        result.err(),
    );
    let main_rs = std::fs::read_to_string(out_dir().join("src").join("main.rs"))
        .expect("emitted main.rs must exist");
    assert!(
        main_rs.contains("web_app_routed"),
        "#108 hole 2: a routed app with a LAMBDA `view` must emit \
         `web_app_routed` — the FuncValue-only recovery silently emitted the \
         non-routed `web_app` (routes/notFound discarded, no diagnostic)",
    );
    assert!(
        main_rs.contains("route::Route::new"),
        "#108 hole 2: the routes vec must be wired into the emitted call",
    );
}

/// `IPE_E2E` tier: the emitted project must cargo-build (shared `e2e_support`
/// core: unique package name → fresh app fingerprint, warm dep target reused).
#[test]
fn lambda_view_routed_app_cargo_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    // Emit into a PRIVATE dir this test alone owns, so the compile-only sibling
    // re-emitting into `out_dir()` in parallel cannot delete rustc's working
    // directory mid-build.
    let out = crate::support::scratch_root().join("m7_live_lambda_view_routed_e2e_out");
    let result = compile("e2e", &out);
    assert!(
        result.is_ok(),
        "lambda-view routed app must be ipe-0, got: {:?}",
        result.err(),
    );

    let built = e2e_support::build_rust_binary("m7_lambda_view_routed", &out);
    assert!(
        built.is_ok(),
        "#108 hole 2: lambda-view routed project must cargo-build\n{}",
        built.err().unwrap_or_default(),
    );
}
