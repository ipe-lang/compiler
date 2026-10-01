//! The prescriptive TEA `init` signature.
//!
//! ## Background
//!
//! Ipê pins `Web.tea`'s `init` to `WebReq -> (Model, Cmd Msg)` (mandatory)
//! rather than the reference's permissive free `req` type var. Two properties
//! are pinned here:
//!
//! 1. **Prescription is enforced.** A `Web.tea` whose `init` declares `{}` (or
//!    any non-`WebReq` shape) is a clear compile-time IPE-T0001 at the `init`
//!    cfg field (`expected WebReq, found {}`) — not a raw unification failure
//!    and not a deferred `cargo` break.
//!
//! 2. **`WebReq` fields are readable.** `WebReq` is an opaque nullary `Con`
//!    at the type level (so no bare record literal can masquerade as the runtime
//!    struct — the make-invalid-states-unrepresentable posture shared with the
//!    opaque server `Request`), but its fixed field set is READABLE via the
//!    deferred `FieldAccess` pass (`WebReqFields`). `init req = ... req.path`
//!    type-checks and lowers to `(req).path.clone()`, reading
//!    `ipe_runtime::dom::req::WebReq` directly — no synthesised record.
//!
//! Full design: `docs/adr/0005-delivery-shapes-runtimes-hosts-targets.md`;
//! Sanctioned divergence B24.
//!
//! Compile-only assertions always run; the cargo build is `IPE_E2E=1`-gated and
//! runs through `e2e_support::build_rust_binary`, which gives the fixture a
//! unique package name (fresh app fingerprint) and reuses the warm shared
//! dependency target — a broken emit still fails to build, so the SEAL stays
//! sound while the heavy dep tree compiles once.

use std::path::PathBuf;

/// A `Web.tea` whose `init : WebReq -> …` READS `req.path` into the Model.
/// Non-routed for brevity; plain-data Model so the admissibility gate
/// passes, isolating the init-field + field-access behaviour.
const LIVE_INIT_READS_REQ_PATH: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
type Page = HomePage
type Msg = Noop
type alias Model = { page : Page, path : String }
init : WebReq -> ( Model, Cmd Msg )
init req = ( { page = HomePage, path = req.path }, Cmd.none )
update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model = ( model, Cmd.none )
view : Model -> any
view model = Ui.text model.path
subscriptions : Model -> Sub Msg
subscriptions _model = Sub.none
main =
    Web.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
        , routes = [ Web.route "/" HomePage ]
        , notFound = HomePage
        }
"#;

/// The SAME app but with `init : a -> …` — a free type variable the
/// prescriptive scheme must reject with IPE-N0046.
const LIVE_INIT_POLY_REJECTED: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
type Page = HomePage
type Msg = Noop
type alias Model = { page : Page }
init : a -> ( Model, Cmd Msg )
init _ = ( { page = HomePage }, Cmd.none )
update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model = ( model, Cmd.none )
view : Model -> any
view _model = Ui.text "hi"
subscriptions : Model -> Sub Msg
subscriptions _model = Sub.none
main =
    Web.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
        , routes = [ Web.route "/" HomePage ]
        , notFound = HomePage
        }
"#;

/// The SAME app but with `init : {} -> …` — the non-`WebReq` shape the
/// prescriptive scheme must reject with a clear IPE-T0001.
const LIVE_INIT_UNIT_REJECTED: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
type Page = HomePage
type Msg = Noop
type alias Model = { page : Page }
init : {} -> ( Model, Cmd Msg )
init _ = ( { page = HomePage }, Cmd.none )
update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model = ( model, Cmd.none )
view : Model -> any
view _model = Ui.text "hi"
subscriptions : Model -> Sub Msg
subscriptions _model = Sub.none
main =
    Web.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
        , routes = [ Web.route "/" HomePage ]
        , notFound = HomePage
        }
"#;

fn ok_out_dir() -> PathBuf {
    crate::support::scratch_root().join("i180_init_reads_req_path_out")
}

/// Compile a fixture into its own out dir.
#[allow(clippy::expect_used)] // an unwritable scratch dir is the test failure
fn compile(fixture: &str, tag: &str, out: &PathBuf) -> Result<(), ipe::CliError> {
    let ipe_dir = crate::support::scratch_root().join(format!("i180_{tag}_ipe"));
    let _ = std::fs::remove_dir_all(&ipe_dir);
    std::fs::create_dir_all(&ipe_dir).expect("the fixture scratch dir must be writable");
    let entry = ipe_dir.join("Main.ipe");
    std::fs::write(&entry, fixture).expect("the fixture scratch dir must be writable");
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, out, &runtime)
}

/// `init : WebReq -> …` reading `req.path` must be ipe-0 and emit
/// `(req).path.clone()` against the runtime `WebReq` struct — proving the
/// `WebReqFields` deferred field-access resolution + concrete lowering.
#[test]
fn live_init_reads_req_path_field() {
    let out = ok_out_dir();
    let result = compile(LIVE_INIT_READS_REQ_PATH, "reads_req_path", &out);
    assert!(
        result.is_ok(),
        "#180: `init : WebReq -> …` reading `req.path` must be ipe-0, got: {:?}",
        result.err(),
    );
    let main_rs = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");
    assert!(
        main_rs.contains("ipe_runtime::dom::req::WebReq"),
        "#180: the emitted init must take the concrete `ipe_runtime::dom::req::WebReq`",
    );
    assert!(
        main_rs.contains("(req).path.clone()"),
        "#180: `req.path` must lower to a direct struct field read \
         `(req).path.clone()` — no synthesised record",
    );
}

/// `init : {} -> …` must be rejected with a clear IPE-T0001 naming the expected
/// `WebReq` — the prescriptive scheme, fail-closed at ipe time.
#[test]
fn live_init_unit_is_rejected() {
    let out = crate::support::scratch_root().join("i180_init_unit_out");
    let result = compile(LIVE_INIT_UNIT_REJECTED, "init_unit", &out);
    let err = result.expect_err(
        "#180: `init : {} -> …` on a Web.tea must be a compile error under the \
         prescriptive WebReq scheme",
    );
    let rendered = format!("{err:?}");
    assert!(
        rendered.contains("WebReq"),
        "#180: the rejection must name the expected `WebReq` type, got: {rendered}",
    );
}

/// `init : a -> …` (free type variable) on a `Web.tea` must be rejected with
/// IPE-N0046 — the annotation promises this works for *any* request shape,
/// which is false; the runtime always passes `WebReq`.
#[test]
fn live_init_poly_var_is_rejected() {
    let out = crate::support::scratch_root().join("i180_init_poly_out");
    let result = compile(LIVE_INIT_POLY_REJECTED, "init_poly", &out);
    let err = result.expect_err(
        "#180: `init : a -> …` on a Web.tea must be a compile error (IPE-N0046) \
         under the prescriptive WebReq scheme",
    );
    let rendered = format!("{err:?}");
    assert!(
        rendered.contains("WebInitPolyArg"),
        "#180: the rejection must carry WebInitPolyArg (IPE-N0046), got: {rendered}",
    );
}

/// `IPE_E2E` tier: the `init : WebReq` project must cargo-build — the SEAL
/// check that ipe-0 implies cargo-0. Builds through the shared `e2e_support`
/// (unique package, warm dep target).
///
/// Emits into a PRIVATE dir this test alone owns, so a sibling compile-only
/// test re-emitting into `ok_out_dir()` in parallel can never delete rustc's
/// working directory mid-build.
#[test]
fn live_init_reads_req_path_cargo_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let out = crate::support::scratch_root().join("i180_init_reads_req_path_e2e_out");
    let result = compile(LIVE_INIT_READS_REQ_PATH, "reads_req_path_e2e", &out);
    assert!(
        result.is_ok(),
        "`init : WebReq -> …` reading `req.path` must be ipe-0, got: {:?}",
        result.err(),
    );

    // Build via the shared e2e_support core: it gives this fixture a UNIQUE
    // package name and honours IPE_ORACLE_SHARED_TARGET, so the emitted app
    // crate builds FRESH (its own source hash → its own fingerprint; a broken
    // emit still fails E0308) while the heavy dependency tree is reused from the
    // warm shared target instead of cold-compiling tokio/axum/hyper per fixture.
    // When the env is unset (a plain local run) it fails safe to an isolated
    // ambient target.
    let built = e2e_support::build_rust_binary("i180_init_reads_req_path", &out);
    assert!(
        built.is_ok(),
        "#180: the `init : WebReq` project must cargo-build\n{}",
        built.err().unwrap_or_default(),
    );
}
