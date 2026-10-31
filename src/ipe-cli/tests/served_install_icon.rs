//! A served build of an installable app refuses an unfit icon: the build
//! stops with the catalog message, never a silently non-installable app. A fit
//! icon reaches the emitted crate byte-exact, the crate builds, and the running
//! app links and serves its manifest and icon (under `IPE_E2E=1`).

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

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
         \x20       , notFound = CounterPage\n\
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
fn build_installable(name: &str, icon: &[u8]) -> Result<(), CliError> {
    build_installable_into(name, icon).map(drop)
}

/// [`build_installable`], keeping the built fixture.
///
/// The icon rule runs where the manifest is read, so an unfit icon is refused
/// as the project resolves, before any build.
fn build_installable_into(name: &str, icon: &[u8]) -> Result<ipe::BuiltFixture, CliError> {
    let tree = ipe::project_root::SourceTree::main(SERVED_APP)
        .field(&format!("icon = {ICON:?}"))
        .field("delivery = { browser = { installable = True } }")
        .file(ICON, icon);
    let fixture = ipe::RootFixture::from_tree(&tree)?;
    let out = scratch(name).join("out");
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build_fixture(&fixture, &out, &runtime)
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

/// The emitted crate's icon file, written beside the sources.
const EMITTED_ICON: &str = "src/ipe_install_icon.png";

/// The largest answer [`http_get`] reads.
const ANSWER_CAP: u64 = 4 * 1024 * 1024;

/// The running app, killed on drop.
struct App(Child);

impl Drop for App {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One `GET path` against the loopback `port`: the status line and the body.
fn http_get(port: u16, path: &str) -> Option<(String, Vec<u8>)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut answer = Vec::new();
    stream.take(ANSWER_CAP).read_to_end(&mut answer).ok()?;
    let split = answer.windows(4).position(|w| w == b"\r\n\r\n")?;
    let (head, rest) = answer.split_at(split);
    let status = String::from_utf8_lossy(head).lines().next()?.to_owned();
    Some((status, rest.get(4..)?.to_vec()))
}

/// The `href` of the `<link rel="REL" ...>` in `page`.
fn link_href<'p>(page: &'p str, rel: &str) -> Option<&'p str> {
    let needle = format!("<link rel=\"{rel}\" href=\"");
    let start = page.find(&needle)?.checked_add(needle.len())?;
    let tail = page.get(start..)?;
    tail.get(..tail.find('"')?)
}

/// THE SEAL for an installable served build: the icon lands in the emitted
/// crate byte-exact, the crate builds, and the running app's page links a
/// manifest that names the app and an icon route that answers the same bytes.
#[test]
#[allow(clippy::expect_used)] // e2e: every failed step IS the failure
fn an_installable_build_serves_its_manifest_and_icon() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let icon = png(512);
    let built =
        build_installable_into("served_install_icon_e2e", &icon).expect("a fit icon builds");
    let out: &Path = built.out();
    assert_eq!(
        std::fs::read(out.join(EMITTED_ICON)).expect("the icon is written"),
        icon,
        "the emitted icon is the project icon, byte-exact"
    );
    let exe = e2e_support::build_rust_binary("served_install_icon_e2e", out)
        .expect("the emitted crate builds");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("an ephemeral port")
        .port();
    let _app = App(Command::new(&exe)
        .env("IPE_WEB_PORT", port.to_string())
        .env("IPE_CSRF", "off")
        .env("IPE_CONSOLE_EMBED", "off")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the app starts"));
    let mut page = None;
    let ready = e2e_support::wait_for(Duration::from_secs(30), || {
        page = http_get(port, "/").filter(|(status, _)| status.contains(" 200 "));
        page.is_some()
    });
    assert!(ready, "the app answers its page");
    let (_, page) = page.expect("the page");
    let page = String::from_utf8(page).expect("the page is UTF-8");

    let manifest_href = link_href(&page, "manifest").expect("the page links a manifest");
    let icon_href = link_href(&page, "apple-touch-icon").expect("the page links an icon");
    let (status, manifest) = http_get(port, manifest_href).expect("the manifest answers");
    assert!(status.contains(" 200 "), "the manifest is served: {status}");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest).expect("the manifest is JSON");
    let field = |pointer: &str| {
        manifest
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
    };
    assert_eq!(field("/display"), Some("standalone"));
    assert_eq!(field("/icons/0/src"), Some(icon_href));
    assert_eq!(field("/icons/0/sizes"), Some("512x512"));
    let (status, served) = http_get(port, icon_href).expect("the icon answers");
    assert!(status.contains(" 200 "), "the icon is served: {status}");
    assert_eq!(served, icon, "the served icon is the project icon");
}

/// A served build that declares an icon but not `installable` writes no icon
/// into the emitted crate.
#[test]
#[allow(clippy::expect_used)] // the fixture build IS the subject
fn a_build_without_install_carries_no_icon() {
    let tree = ipe::project_root::SourceTree::main(SERVED_APP)
        .field(&format!("icon = {ICON:?}"))
        .file(ICON, &png(512));
    let fixture = ipe::RootFixture::from_tree(&tree).expect("write the project fixture");
    let out = scratch("served_install_icon_off").join("out");
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build_fixture(&fixture, &out, &runtime).expect("the served app builds");
    assert!(
        !built.out().join(EMITTED_ICON).exists(),
        "no install offer, no icon file"
    );
}
