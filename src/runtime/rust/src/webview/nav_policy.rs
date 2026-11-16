//! Where a desktop webview may go: its own origin, the system browser, or nowhere.
//!
//! Every navigation and new-window request is judged by [`NavDecision::of`]:
//! the local origin stays in the window, a public `https` link is handed to
//! the system browser through the one [`ExternalOpener`], and everything else
//! is refused with a fixed line naming its class, never the URL. New windows,
//! downloads and dropped files never happen in the window.

use std::sync::Mutex;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};

use crate::browser_open::{BrowserOrigin, BrowserUrl, BrowserUrlRefusal, MAX_BROWSER_URL_LEN};
use crate::csp::SchemeSpelling;

/// The fewest seconds between two opener starts.
const OPENER_INTERVAL: Duration = Duration::from_secs(1);

/// The fewest seconds between two refusal lines of one class.
const REPORT_INTERVAL: Duration = Duration::from_secs(5);

/// The page origin a webview treats as its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalOrigin {
    /// The shell's bundle under its custom scheme, in one spelling.
    BundleScheme(SchemeSpelling),
    /// A document the host handed the webview inline: `about:blank` alone.
    InlineDocument,
}

/// Why a link was refused, by class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavRefusal {
    /// `http:`, never sent off the device unencrypted.
    PlainHttp,
    /// `javascript:` or `vbscript:`.
    Script,
    /// `file:`.
    File,
    /// `data:` or `blob:`.
    DataOrBlob,
    /// `about:` other than the inline document.
    About,
    /// `ws:` or `wss:`.
    WebSocket,
    /// Any other scheme.
    OtherScheme,
    /// The authority carries userinfo.
    Userinfo,
    /// The host is an IP literal, a `localhost` name or a single label.
    NotPublicHost,
    /// Not a URL the external grammar admits.
    Malformed,
    /// Longer than the URL ceiling.
    TooLong,
    /// A byte outside ASCII.
    NotAscii,
}

impl NavRefusal {
    /// Every class, in declaration order.
    pub const ALL: [Self; 12] = [
        Self::PlainHttp,
        Self::Script,
        Self::File,
        Self::DataOrBlob,
        Self::About,
        Self::WebSocket,
        Self::OtherScheme,
        Self::Userinfo,
        Self::NotPublicHost,
        Self::Malformed,
        Self::TooLong,
        Self::NotAscii,
    ];

    /// The class name a refusal line carries.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::PlainHttp => "plain http",
            Self::Script => "script url",
            Self::File => "file url",
            Self::DataOrBlob => "data or blob url",
            Self::About => "about url",
            Self::WebSocket => "websocket url",
            Self::OtherScheme => "unknown scheme",
            Self::Userinfo => "userinfo in the authority",
            Self::NotPublicHost => "not a public host",
            Self::Malformed => "malformed url",
            Self::TooLong => "url too long",
            Self::NotAscii => "non-ascii url",
        }
    }

    /// The line logged for this refusal; it never holds the URL.
    #[must_use]
    pub fn line(self) -> String {
        format!("refused a link: {}", self.class())
    }

    const fn slot(self) -> usize {
        self as usize
    }
}

/// What becomes of one navigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NavDecision {
    /// The URL is the window's own origin.
    StayLocal,
    /// The URL is a public `https` link for the system browser.
    OpenExternal(BrowserUrl),
    /// The URL goes nowhere.
    Refuse(NavRefusal),
}

impl NavDecision {
    /// Judge `url` under `local`.
    ///
    /// In order: the length ceiling, ASCII, the exact local origin, then the
    /// scheme. Only an exact lowercase `https://` reaches the external grammar.
    #[must_use]
    pub fn of(url: &str, local: LocalOrigin) -> Self {
        if url.len() > MAX_BROWSER_URL_LEN {
            return Self::Refuse(NavRefusal::TooLong);
        }
        if !url.is_ascii() {
            return Self::Refuse(NavRefusal::NotAscii);
        }
        let is_local = match local {
            LocalOrigin::BundleScheme(spelling) => spelling.local_target(url).is_some(),
            LocalOrigin::InlineDocument => url == "about:blank" || url.starts_with("about:blank#"),
        };
        if is_local {
            return Self::StayLocal;
        }
        let Some((scheme, _)) = url.split_once(':') else {
            return Self::Refuse(NavRefusal::Malformed);
        };
        let refusal = match scheme.to_ascii_lowercase().as_str() {
            "https" if url.starts_with("https://") => {
                return match BrowserUrl::parse(url, BrowserOrigin::ExternalHttps) {
                    Ok(external) => Self::OpenExternal(external),
                    Err(BrowserUrlRefusal::Userinfo) => Self::Refuse(NavRefusal::Userinfo),
                    Err(BrowserUrlRefusal::Host) => Self::Refuse(NavRefusal::NotPublicHost),
                    Err(BrowserUrlRefusal::TooLong) => Self::Refuse(NavRefusal::TooLong),
                    Err(
                        BrowserUrlRefusal::Scheme
                        | BrowserUrlRefusal::Port
                        | BrowserUrlRefusal::Byte(_)
                        | BrowserUrlRefusal::Empty,
                    ) => Self::Refuse(NavRefusal::Malformed),
                };
            }
            "http" => NavRefusal::PlainHttp,
            "javascript" | "vbscript" => NavRefusal::Script,
            "file" => NavRefusal::File,
            "data" | "blob" => NavRefusal::DataOrBlob,
            "about" => NavRefusal::About,
            "ws" | "wss" => NavRefusal::WebSocket,
            "https" => NavRefusal::Malformed,
            _ => NavRefusal::OtherScheme,
        };
        Self::Refuse(refusal)
    }
}

/// Judge a navigation: offer an external link to `offer`, report a refusal,
/// and allow the navigation only when it stays local.
pub fn allow_navigation(url: &str, local: LocalOrigin, offer: impl FnOnce(BrowserUrl)) -> bool {
    match NavDecision::of(url, local) {
        NavDecision::StayLocal => true,
        NavDecision::OpenExternal(external) => {
            offer(external);
            false
        }
        NavDecision::Refuse(refusal) => {
            report_refusal(refusal);
            false
        }
    }
}

/// What a request for a new window gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowVerdict {
    /// No window opens.
    Deny,
}

/// Judge a new-window request: an external link goes to `offer`, and no window ever opens.
pub fn new_window(url: &str, local: LocalOrigin, offer: impl FnOnce(BrowserUrl)) -> WindowVerdict {
    match NavDecision::of(url, local) {
        NavDecision::OpenExternal(external) => offer(external),
        NavDecision::Refuse(refusal) => report_refusal(refusal),
        NavDecision::StayLocal => {}
    }
    WindowVerdict::Deny
}

/// When each refusal class last wrote its line.
static LAST_REPORT: Mutex<[Option<Instant>; NavRefusal::ALL.len()]> =
    Mutex::new([None; NavRefusal::ALL.len()]);

/// Log `refusal`'s line, at most once per [`REPORT_INTERVAL`] per class.
fn report_refusal(refusal: NavRefusal) {
    let now = Instant::now();
    let due = {
        let mut last = LAST_REPORT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        last.get_mut(refusal.slot()).is_some_and(|at| {
            let due = at.is_none_or(|then| now.duration_since(then) >= REPORT_INTERVAL);
            if due {
                *at = Some(now);
            }
            due
        })
    };
    if due {
        crate::system::emit_runtime_log("webview", &refusal.line());
    }
}

/// A monotonic clock, so tests can drive time.
pub trait Clock {
    /// Time since an arbitrary fixed start.
    fn now(&self) -> Duration;
}

/// A started opener whose end can be polled.
pub trait LiveOpener {
    /// Whether the opener has ended (or can no longer be watched).
    fn finished(&mut self) -> bool;
}

/// Starts an opener for a URL.
pub trait Launcher {
    /// The started opener.
    type Live: LiveOpener;
    /// Start an opener for `url`, or `None` when none started.
    fn launch(&mut self, url: &BrowserUrl) -> Option<Self::Live>;
}

/// What one offered URL became.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handled {
    /// An opener started.
    Started,
    /// An earlier opener is still running.
    Busy,
    /// An opener started less than [`OPENER_INTERVAL`] ago.
    RateLimited,
    /// No opener started.
    Failed,
}

/// The opener worker's state: at most one live opener, at most one start per interval.
pub struct OpenerWorker<C: Clock, L: Launcher> {
    clock: C,
    launcher: L,
    live: Option<L::Live>,
    last_start: Option<Duration>,
}

impl<C: Clock, L: Launcher> OpenerWorker<C, L> {
    /// A worker with no opener started yet.
    pub const fn new(clock: C, launcher: L) -> Self {
        Self {
            clock,
            launcher,
            live: None,
            last_start: None,
        }
    }

    /// Reap a finished opener.
    pub fn reap(&mut self) {
        if self.live.as_mut().is_some_and(LiveOpener::finished) {
            self.live = None;
        }
    }

    /// Handle one offered URL.
    pub fn handle(&mut self, url: &BrowserUrl) -> Handled {
        self.reap();
        if self.live.is_some() {
            return Handled::Busy;
        }
        let now = self.clock.now();
        if self
            .last_start
            .is_some_and(|at| now.saturating_sub(at) < OPENER_INTERVAL)
        {
            return Handled::RateLimited;
        }
        match self.launcher.launch(url) {
            Some(live) => {
                self.live = Some(live);
                self.last_start = Some(now);
                Handled::Started
            }
            None => Handled::Failed,
        }
    }

    /// Serve offered URLs from `rx` until every sender is gone.
    pub fn run(mut self, rx: &Receiver<BrowserUrl>) {
        loop {
            match rx.recv_timeout(OPENER_INTERVAL) {
                Ok(url) => {
                    let _ = self.handle(&url);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => self.reap(),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    }
}

/// The handle a webview's policy offers external links to.
///
/// Offers beyond the one queued are dropped, so a page cannot queue openers.
#[derive(Debug, Clone)]
pub struct ExternalOpener {
    tx: SyncSender<BrowserUrl>,
}

impl ExternalOpener {
    /// Offer `url`; dropped when an offer is already queued.
    pub fn offer(&self, url: BrowserUrl) {
        match self.tx.try_send(url) {
            Ok(()) | Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {}
        }
    }

    /// A handle and the receiver its worker serves.
    #[must_use]
    pub fn channel() -> (Self, Receiver<BrowserUrl>) {
        let (tx, rx) = sync_channel(1);
        (Self { tx }, rx)
    }

    /// Start the worker thread that opens offered URLs in the system browser.
    ///
    /// # Errors
    /// The OS error when the thread cannot start.
    pub fn start() -> std::io::Result<Self> {
        let (opener, rx) = Self::channel();
        crate::threads::spawn_named("ipe-link-opener", move || {
            OpenerWorker::new(SystemClock(Instant::now()), SystemLauncher).run(&rx);
        })?;
        Ok(opener)
    }
}

/// The process's monotonic clock.
struct SystemClock(Instant);

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

/// The platform opener, started through the hardened spawner.
struct SystemLauncher;

impl LiveOpener for std::process::Child {
    fn finished(&mut self) -> bool {
        !matches!(self.try_wait(), Ok(None))
    }
}

impl Launcher for SystemLauncher {
    type Live = std::process::Child;

    fn launch(&mut self, url: &BrowserUrl) -> Option<std::process::Child> {
        crate::browser_open::start_opener(
            url,
            crate::browser_open::Platform::HOST,
            crate::browser_open::Breakaway::Never,
        )
        .ok()
    }
}

/// Install the whole navigation policy on `builder`.
///
/// Navigations stay only on `local`; external links go to `opener`; no new
/// window opens; no download starts; a dropped file is consumed so it never
/// becomes a `file://` navigation.
#[cfg(feature = "webview-shell")]
pub fn attach_policy(
    builder: wry::WebViewBuilder<'_>,
    local: LocalOrigin,
    opener: ExternalOpener,
) -> wry::WebViewBuilder<'_> {
    let window_opener = opener.clone();
    builder
        .with_navigation_handler(move |url: String| {
            allow_navigation(&url, local, |external| opener.offer(external))
        })
        .with_new_window_req_handler(move |url: String, _features| {
            match new_window(&url, local, |external| window_opener.offer(external)) {
                WindowVerdict::Deny => wry::NewWindowResponse::Deny,
            }
        })
        .with_download_started_handler(|_url: String, _path: &mut std::path::PathBuf| false)
        .with_drag_drop_handler(|_event: wry::DragDropEvent| true)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    fn decide(url: &str, local: LocalOrigin) -> NavDecision {
        NavDecision::of(url, local)
    }

    const SCHEME: LocalOrigin = LocalOrigin::BundleScheme(SchemeSpelling::Scheme);
    const HTTPS_HOST: LocalOrigin = LocalOrigin::BundleScheme(SchemeSpelling::HttpsHost);

    #[test]
    fn nav_decision_table() {
        for (url, local) in [
            ("ipe-app://localhost/", SCHEME),
            ("ipe-app://localhost", SCHEME),
            ("ipe-app://localhost/notes?x=1#y", SCHEME),
            ("https://ipe-app.localhost/x", HTTPS_HOST),
            ("https://ipe-app.localhost", HTTPS_HOST),
            ("about:blank", LocalOrigin::InlineDocument),
            ("about:blank#top", LocalOrigin::InlineDocument),
        ] {
            assert_eq!(decide(url, local), NavDecision::StayLocal, "{url}");
        }
        for url in [
            "https://example.com/",
            "https://docs.example.com:8443/a?b=c&d=e#f",
        ] {
            for local in [SCHEME, HTTPS_HOST, LocalOrigin::InlineDocument] {
                let decision = decide(url, local);
                assert!(
                    matches!(&decision, NavDecision::OpenExternal(u) if u.as_str() == url),
                    "{url}: {decision:?}"
                );
            }
        }
        let long = format!("https://example.com/{}", "a".repeat(MAX_BROWSER_URL_LEN));
        for (url, local, refusal) in [
            ("http://example.com/", SCHEME, NavRefusal::PlainHttp),
            ("HTTPS://example.com/", SCHEME, NavRefusal::Malformed),
            ("https://user@example.com/", SCHEME, NavRefusal::Userinfo),
            (
                "https://example.com@evil.com/",
                SCHEME,
                NavRefusal::Userinfo,
            ),
            ("https://127.0.0.1/", SCHEME, NavRefusal::NotPublicHost),
            ("https://[::1]/", SCHEME, NavRefusal::NotPublicHost),
            ("https://localhost/", SCHEME, NavRefusal::NotPublicHost),
            ("https://a.localhost/", SCHEME, NavRefusal::NotPublicHost),
            ("https://intranet/", SCHEME, NavRefusal::NotPublicHost),
            ("https://1.2.3.4.5/", SCHEME, NavRefusal::NotPublicHost),
            (
                "https://ipe-app.localhost/x",
                SCHEME,
                NavRefusal::NotPublicHost,
            ),
            ("ipe-app://localhost/x", HTTPS_HOST, NavRefusal::OtherScheme),
            ("ipe-app://localhost.evil/", SCHEME, NavRefusal::OtherScheme),
            ("ipe-app://localhost@evil/", SCHEME, NavRefusal::OtherScheme),
            ("ipe-app://localhost:1/", SCHEME, NavRefusal::OtherScheme),
            ("javascript:alert(1)", SCHEME, NavRefusal::Script),
            ("JavaScript:alert(1)", SCHEME, NavRefusal::Script),
            ("vbscript:x", SCHEME, NavRefusal::Script),
            ("file:///etc/passwd", SCHEME, NavRefusal::File),
            ("data:text/html,x", SCHEME, NavRefusal::DataOrBlob),
            ("blob:ipe-app://localhost/1", SCHEME, NavRefusal::DataOrBlob),
            ("about:blank", SCHEME, NavRefusal::About),
            (
                "about:config",
                LocalOrigin::InlineDocument,
                NavRefusal::About,
            ),
            ("wss://example.com/", SCHEME, NavRefusal::WebSocket),
            ("ws://example.com/", SCHEME, NavRefusal::WebSocket),
            ("mailto:a@example.com", SCHEME, NavRefusal::OtherScheme),
            ("example.com", SCHEME, NavRefusal::Malformed),
            ("https://example.com/a b", SCHEME, NavRefusal::Malformed),
            ("https://ex\u{e4}mple.com/", SCHEME, NavRefusal::NotAscii),
            (long.as_str(), SCHEME, NavRefusal::TooLong),
        ] {
            assert_eq!(decide(url, local), NavDecision::Refuse(refusal), "{url}");
        }
    }

    #[test]
    fn navigation_handler_allows_only_stay_local() {
        for (url, allowed, offered) in [
            ("ipe-app://localhost/x", true, false),
            ("https://example.com/", false, true),
            ("http://example.com/", false, false),
            ("file:///etc/passwd", false, false),
        ] {
            let seen = Cell::new(false);
            let allow = allow_navigation(url, SCHEME, |_| seen.set(true));
            assert_eq!((allow, seen.get()), (allowed, offered), "{url}");
        }
    }

    #[test]
    fn new_window_never_allows_a_window() {
        for url in [
            "ipe-app://localhost/x",
            "https://example.com/",
            "http://example.com/",
            "javascript:alert(1)",
            "about:blank",
        ] {
            for local in [SCHEME, HTTPS_HOST, LocalOrigin::InlineDocument] {
                assert_eq!(new_window(url, local, |_| {}), WindowVerdict::Deny, "{url}");
            }
        }
        let seen = Cell::new(false);
        let _ = new_window("https://example.com/", SCHEME, |_| seen.set(true));
        assert!(
            seen.get(),
            "an external link in a new window goes to the browser"
        );
    }

    struct FakeClock(Rc<Cell<Duration>>);

    impl Clock for FakeClock {
        fn now(&self) -> Duration {
            self.0.get()
        }
    }

    struct FakeLive(Rc<Cell<bool>>);

    impl LiveOpener for FakeLive {
        fn finished(&mut self) -> bool {
            self.0.get()
        }
    }

    struct FakeLauncher {
        starts: Rc<RefCell<Vec<String>>>,
        done: Rc<Cell<bool>>,
    }

    impl Launcher for FakeLauncher {
        type Live = FakeLive;

        fn launch(&mut self, url: &BrowserUrl) -> Option<FakeLive> {
            self.starts.borrow_mut().push(url.as_str().to_owned());
            Some(FakeLive(Rc::clone(&self.done)))
        }
    }

    #[test]
    fn external_opener_bounds_live_and_rate() {
        let Ok(url) = BrowserUrl::parse("https://example.com/", BrowserOrigin::ExternalHttps)
        else {
            return;
        };
        let time = Rc::new(Cell::new(Duration::from_secs(10)));
        let done = Rc::new(Cell::new(false));
        let starts = Rc::new(RefCell::new(Vec::new()));
        let mut worker = OpenerWorker::new(
            FakeClock(Rc::clone(&time)),
            FakeLauncher {
                starts: Rc::clone(&starts),
                done: Rc::clone(&done),
            },
        );
        assert_eq!(worker.handle(&url), Handled::Started);
        assert_eq!(
            worker.handle(&url),
            Handled::Busy,
            "one live opener at most"
        );
        time.set(Duration::from_secs(20));
        assert_eq!(worker.handle(&url), Handled::Busy);
        done.set(true);
        time.set(Duration::from_millis(20_500));
        assert_eq!(worker.handle(&url), Handled::Started);
        done.set(true);
        time.set(Duration::from_millis(21_000));
        assert_eq!(
            worker.handle(&url),
            Handled::RateLimited,
            "one start per second at most"
        );
        time.set(Duration::from_millis(21_500));
        assert_eq!(worker.handle(&url), Handled::Started);
        assert_eq!(starts.borrow().len(), 3);

        let (opener, rx) = ExternalOpener::channel();
        for _ in 0..5 {
            opener.offer(url.clone());
        }
        assert_eq!(rx.try_iter().count(), 1, "one offer queued at most");
    }

    #[test]
    fn refusal_line_never_echoes_the_url() {
        for refusal in NavRefusal::ALL {
            let line = refusal.line();
            assert_eq!(line, format!("refused a link: {}", refusal.class()));
            for fragment in ["://", "example", "evil", "@", "?", "#", "%"] {
                assert!(!line.contains(fragment), "{line}");
            }
        }
        let distinct: std::collections::HashSet<&str> = NavRefusal::ALL
            .iter()
            .map(|refusal| refusal.class())
            .collect();
        assert_eq!(distinct.len(), NavRefusal::ALL.len());
        assert!(
            NavRefusal::ALL
                .iter()
                .enumerate()
                .all(|(i, r)| r.slot() == i)
        );
    }

    /// Every policy handler is installed by the one `attach_policy`.
    #[test]
    fn attach_policy_installs_every_policy_handler() {
        let source = include_str!("nav_policy.rs");
        let body = source
            .split_once("pub fn attach_policy(")
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .map(|(body, _)| body);
        let Some(body) = body else {
            assert!(body.is_some(), "attach_policy is defined here");
            return;
        };
        for handler in [
            ".with_navigation_handler(",
            ".with_new_window_req_handler(",
            ".with_download_started_handler(",
            ".with_drag_drop_handler(",
        ] {
            assert_eq!(body.matches(handler).count(), 1, "{handler}");
        }
        assert!(body.contains("wry::NewWindowResponse::Deny"));
        assert!(!body.contains("NewWindowResponse::Allow"));
    }
}
