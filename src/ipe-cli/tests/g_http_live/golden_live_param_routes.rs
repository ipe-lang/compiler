//! `:param` routes with payload-constructor page builders, the CANONICAL corpus
//! shape (`route "/apps/:slug" AppDetailPage`).
//!
//! ## Background
//!
//! A `Web.route : String -> page -> WebRoute page` scheme sharing ONE type
//! variable between the builder argument and the page type would make
//! `Web.route "/u/:id" UserPage` (with `UserPage : String -> Page`) force
//! `Page ≟ String -> Page` — a false IPE-T0001 on EVERY param-route app, which
//! also makes the emit tier's `route_param_get` conversion path dead code.
//!
//! The fix types the builder with its own variable and relates it to the page
//! by a deferred per-route witness (`RouteWitnessCheck`, resolved post-solve
//! like `RoutedWebCheck`): peel the builder's settled leading arrows, unify
//! the result with the page. Nullary routes witness the page directly; param
//! constructors witness it with their result; wrong-ADT constructors still
//! fail with IPE-T0001.
//!
//! ## Tests
//!
//! * SOLO: a param route alone → ipe-0; emitted builder applies the
//!   `params.get(0)` conversion (compile-only, always runs).
//! * MIXED: nullary + param routes in ONE list → ipe-0 (compile-only).
//! * WRONG-ADT: a param ctor from another ADT → IPE-T0001 (compile-only).
//! * `IPE_E2E=1`: the solo project cargo-builds (through the shared
//!   `e2e_support` core: unique package name → fresh app fingerprint, warm
//!   shared dependency target reused) and, when run, a GET on `/u/42` renders
//!   `user:42` — the captured `:param` delivered through `match_routes` into
//!   the page constructor.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn solo_out() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m7_live_param_routes_emit")
}

/// Compile the on-disk solo golden (`tests/golden/live_param_routes`) into
/// `out`. Returns
fn compile_solo_into(out: &Path) -> Result<(), CliError> {
    let entry = repo_root()
        .join("tests")
        .join("golden")
        .join("live_param_routes")
        .join("Main.ipe");
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, out, &runtime)
}

/// Compile an inline source through the ipe pipeline (no cargo).
#[allow(clippy::expect_used)] // an unwritable scratch dir is the test failure
fn compile_src(test_name: &str, source: &str) -> Result<(), CliError> {
    let ipe_dir = crate::support::scratch_root().join(format!("param_routes_{test_name}_ipe"));
    let _ = std::fs::remove_dir_all(&ipe_dir);
    std::fs::create_dir_all(&ipe_dir).expect("the fixture scratch dir must be writable");
    let entry = ipe_dir.join("Main.ipe");
    std::fs::write(&entry, source).expect("the fixture scratch dir must be writable");
    let out = crate::support::scratch_root().join(format!("param_routes_{test_name}_out"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, &out, &runtime)
}

/// MIXED: one nullary route + one `:param` route in the SAME routes list.
/// Both must witness the same page type (`Page`) — pre-round-4 this was the
/// false-IPE-T0001 shape.
const MIXED_NULLARY_AND_PARAM: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.String
import Ipe.Tea.Web.Sub
type Page = CounterPage | UserPage String
type Msg = Increment
type alias Model = { page : Page, count : Int }
init : WebReq -> ( Model, Cmd Msg )
init _req = ( { page = CounterPage, count = 0 }, Cmd.none )
update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment -> ( { model | count = model.count + 1 }, Cmd.none )
view : Model -> Element Msg
view model = Ui.text (String.fromInt model.count)
subscriptions : Model -> Sub Msg
subscriptions _model = Sub.none
main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [ Web.route "/" CounterPage, Web.route "/u/:id" UserPage ]
        , notFound = CounterPage
        }
"#;

/// WRONG-ADT: the param ctor builds a value of ANOTHER ADT (`Other`, not
/// `Page`). The per-route witness peels `String ->` and then fails
/// `Other ≟ Page` → IPE-T0001. Pins that the witness peel does not blanket-
/// accept every function-shaped builder.
const WRONG_ADT_PARAM_CTOR: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.String
import Ipe.Tea.Web.Sub
type Page = CounterPage
type Other = WrongCtor String
type Msg = Increment
type alias Model = { page : Page, count : Int }
init : WebReq -> ( Model, Cmd Msg )
init _req = ( { page = CounterPage, count = 0 }, Cmd.none )
update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment -> ( { model | count = model.count + 1 }, Cmd.none )
view : Model -> Element Msg
view model = Ui.text (String.fromInt model.count)
subscriptions : Model -> Sub Msg
subscriptions _model = Sub.none
main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [ Web.route "/u/:id" WrongCtor ]
        , notFound = CounterPage
        }
"#;

/// SOLO param route → ipe-0, and the emitted builder closure applies the
/// type-directed `params.get(0)` conversion to the ctor (the `route_param_get`
/// path). Compile-only — always runs.
#[test]
fn param_route_solo_compiles_and_emits_param_conversion() {
    let result = compile_solo_into(&solo_out());
    assert!(
        result.is_ok(),
        "#108 hole 3: a `:param` route with a payload-ctor builder must be \
         ipe-0 (pre-fix: false IPE-T0001 `Page ≟ String -> Page`), got: {:?}",
        result.err(),
    );
    let main_rs = std::fs::read_to_string(solo_out().join("src").join("main.rs"))
        .expect("emitted main.rs must exist");
    assert!(
        main_rs.contains("MainPage::UserPage(params.get(0)"),
        "#108 hole 3: the emitted route builder must apply the captured \
         `:param` to the page constructor (route_param_get path)",
    );
    assert!(
        main_rs.contains("web_app_routed"),
        "#108: the param-route app must emit `web_app_routed`",
    );
    // One typed render arg per payload type the routes decode; the `IPE_E2E`
    // build below proves each arm cargo-builds.
    for arg in [
        "RenderArg::Text(a0.as_str())",
        "RenderArg::Int(*a0)",
        "RenderArg::Bool(*a0)",
        "RenderArg::Float(*a0)",
    ] {
        assert!(
            main_rs.contains(arg),
            "the emitted page renderer must render `{arg}`"
        );
    }
}

/// MIXED nullary + param routes in one list → ipe-0.
#[test]
fn param_route_mixed_with_nullary_compiles() {
    let result = compile_src("mixed", MIXED_NULLARY_AND_PARAM);
    assert!(
        result.is_ok(),
        "#108 hole 3: nullary + `:param` routes must type-check into ONE \
         routes list, got: {:?}",
        result.err(),
    );
}

/// WRONG-ADT param ctor → IPE-T0001 (the witness still rejects).
#[test]
fn param_route_wrong_adt_ctor_is_ipe_t0001() {
    let result = compile_src("wrong_adt", WRONG_ADT_PARAM_CTOR);
    let got = match &result {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0001),
        "#108 hole 3: a wrong-ADT param ctor must still be IPE-T0001, got: {result:?}",
    );
}

// ── IPE_E2E tier — cargo build + runtime param delivery ─────────────────────

/// Read the child's stderr until THE APP's Live listener line appears
/// (bounded). The line must carry the app's own port: with the embedded
/// console enabled the runtime spawns a console child that logs its OWN
/// earlier `[ipe.live] listening on …` line (on an unrelated port), so a bare
/// "listening on" match returns before the app's listener is bound and the
/// subsequent GET races it. Belt-and-braces alongside `IPE_CONSOLE_EMBED=off`.
///
/// The needle keys on the `:{port}` suffix, not the host: the runtime resolves
/// its bind host through `resolve_host_bind` (`127.0.0.1` unless
/// `IPE_HTTP_BIND` or a `Host.bind Host.allInterfaces` setting names another),
/// so pinning the host would miss the readiness line and hang. The port is the
/// app's own and is what disambiguates it from the console child's line.
fn wait_ready(child: &mut std::process::Child, port: u16) -> bool {
    let Some(stderr) = child.stderr.take() else {
        return false;
    };
    let needle = "listening on http://";
    let port_suffix = format!(":{port}");
    let mut reader = BufReader::new(stderr);
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return false,
            Ok(_) if line.contains(needle) && line.contains(&port_suffix) => return true,
            Ok(_) => {}
        }
    }
    false
}

/// Raw one-shot GET; returns the full response text.
fn http_get(port: u16, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )?;
    let mut buf = String::new();
    let _ = stream.read_to_string(&mut buf);
    Ok(buf)
}

/// `IPE_E2E`: cargo-build the solo param-route project (through the shared
/// `e2e_support` core — a unique package name gives the app crate a fresh
/// fingerprint so a broken emit still fails E0308, while the warm shared dep
/// target is reused), run it, and assert GET `/u/42` renders `user:42` — the
/// captured `:param` delivered through `match_routes` into `UserPage`.
#[test]
fn param_route_solo_cargo_builds_and_delivers_param() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    // Emit into a PRIVATE dir this test alone owns, so the compile-only sibling
    // re-emitting into `solo_out()` in parallel cannot delete rustc's working
    // directory mid-build.
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m7_live_param_routes_e2e_emit");
    let result = compile_solo_into(&out);
    assert!(
        result.is_ok(),
        "a `:param` route with a payload-ctor builder must be ipe-0, got: {:?}",
        result.err(),
    );

    // Build through the shared e2e_support core: a unique package name gives the
    // emitted app crate its own fresh fingerprint (a broken emit still fails to
    // build — the warm target never masks a SEAL break), while the heavy runtime
    // dependency tree is reused from the warm shared target instead of being
    // cold-compiled per fixture. Returns the located binary path for the run
    // below. Falls back to an isolated ambient target when the env is unset.
    let built = e2e_support::build_rust_binary("m7_param_routes", &out);
    assert!(
        built.is_ok(),
        "#108 hole 3: the param-route project must cargo-build\n{}",
        built.as_ref().err().cloned().unwrap_or_default(),
    );
    let exe = built.unwrap_or_default();

    // Ephemeral port: bind-then-drop.
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        listener.local_addr().expect("local addr").port()
    };

    let mut child = std::process::Command::new(&exe)
        .env("IPE_WEB_PORT", port.to_string())
        .env("IPE_CSRF", "off")
        // No embedded dev console: the console child is irrelevant here and
        // its own `listening on` log line would race the readiness check.
        .env("IPE_CONSOLE_EMBED", "off")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("emitted binary must spawn");

    let ready = wait_ready(&mut child, port);
    let get = |path: &str| {
        if ready {
            http_get(port, path).unwrap_or_default()
        } else {
            String::new()
        }
    };
    let response = get("/u/42");
    // Non-canonical spellings of typed params redirect to the rendered path.
    let redirects: Vec<(&str, &str, String)> = [
        ("/i/007", "/i/7"),
        ("/u/%34%32", "/u/42"),
        ("/s/1.50", "/s/1.5"),
    ]
    .into_iter()
    .map(|(from, to)| (from, to, get(from)))
    .collect();
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        ready,
        "#108 hole 3: emitted binary must reach `listening on`"
    );
    assert!(
        response.contains("user:42"),
        "#108 hole 3: GET /u/42 must deliver the captured `:param` to the \
         page constructor (expected body to contain `user:42`)\n--- response ---\n{response}",
    );
    for (from, to, resp) in redirects {
        let status_ok = resp.starts_with("HTTP/1.1 308");
        let location_ok = resp
            .lines()
            .any(|l| l.eq_ignore_ascii_case(&format!("location: {to}")));
        assert!(
            status_ok && location_ok,
            "GET {from} must 308 to {to}\n--- response ---\n{resp}"
        );
    }
}
