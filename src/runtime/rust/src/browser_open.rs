//! The one browser opener: a URL parsed once, handed to the platform opener without a shell.
//!
//! Every URL a host asks the desktop to open is a [`BrowserUrl`], parsed at
//! the boundary against the one origin its caller expects, and [`open_url`]
//! and [`start_opener`] are the only functions that start an opener. The
//! opener is the platform's own program (`open`, `explorer.exe`, `gio open`,
//! then `xdg-open`) with the URL as its last argument: no `cmd /C start`, no
//! `sh -c`, so no shell ever re-parses the URL. The byte set a `BrowserUrl`
//! admits refuses the shell metacharacters as well (defence in depth): `&`
//! stands only in the query, as its field separator, and never reaches
//! `xdg-open`, whose legacy xdg-utils paths may hand the URL to a shell.
//!
//! Every opener starts through [`spawn_hardened`] with null stdio.

use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::system::{SpawnRefusal, spawn_hardened};

/// How long a started opener is watched for a failure before it is left running.
pub const OPENER_GRACE: Duration = Duration::from_secs(5);

/// The interval between two checks on a started opener.
const OPENER_POLL: Duration = Duration::from_millis(50);

/// The longest URL any origin admits, judged before any other check.
pub const MAX_BROWSER_URL_LEN: usize = 8 * 1024;

/// The longest host name an external origin admits.
const MAX_HOST_LEN: usize = 253;

/// The longest label of an external host name.
const MAX_LABEL_LEN: usize = 63;

/// The one origin a [`BrowserUrl`] is parsed against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserOrigin {
    /// `https://github.com`, with no userinfo and no port.
    GitHub,
    /// `http://127.0.0.1:<port>` or `http://localhost:<port>`, the port `1..=65535`.
    Loopback,
    /// `https://<public host>[:port]`: a lowercase name of at least two labels
    /// whose last label is not all digits; never an IP literal, `localhost`
    /// or a `*.localhost` name.
    ExternalHttps,
}

/// Why a URL is not a [`BrowserUrl`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserUrlRefusal {
    /// The scheme is not the origin's (`https` for GitHub and external, `http` for loopback).
    Scheme,
    /// The host is not the origin's.
    Host,
    /// A port where none is allowed, or a missing, non-digit or out-of-range one.
    Port,
    /// The authority carries userinfo (`user@host`), which could mask the host.
    Userinfo,
    /// A byte outside the admitted set, or a `%` not followed by two hex digits.
    Byte(u8),
    /// The URL is empty.
    Empty,
    /// The URL is longer than [`MAX_BROWSER_URL_LEN`].
    TooLong,
}

/// A URL proven to be on its expected origin and free of every byte a shell or opener could interpret.
///
/// Admitted after the authority: ASCII alphanumerics, `-._~:/?#@=+`, `%`
/// followed by two hex digits, and `&` inside the query. Refused: space,
/// controls, non-ASCII, `"`, `'`, `` ` ``, `\`, `^`, `|`, `<`, `>`, `{`, `}`,
/// `[`, `]`, `,`, `;`, `$`, `!`, `*`, `(`, `)`, and `&` outside the query. The
/// URL begins with its scheme, so no opener reads it as a flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserUrl(String);

impl BrowserUrl {
    /// Parse `raw` as a URL on `origin`.
    ///
    /// # Errors
    /// A [`BrowserUrlRefusal`] naming the first part of `raw` that is not
    /// admitted.
    pub fn parse(raw: &str, origin: BrowserOrigin) -> Result<Self, BrowserUrlRefusal> {
        if raw.len() > MAX_BROWSER_URL_LEN {
            return Err(BrowserUrlRefusal::TooLong);
        }
        if raw.is_empty() {
            return Err(BrowserUrlRefusal::Empty);
        }
        let scheme = match origin {
            BrowserOrigin::GitHub | BrowserOrigin::ExternalHttps => "https://",
            BrowserOrigin::Loopback => "http://",
        };
        let after_scheme = raw.strip_prefix(scheme).ok_or(BrowserUrlRefusal::Scheme)?;
        // The authority ends at the first `/`, `?`, `#` or `\` (a `\` ends it for
        // a WHATWG parser, so it is never left inside the authority unjudged).
        let authority_end = after_scheme
            .find(['/', '?', '#', '\\'])
            .unwrap_or(after_scheme.len());
        let (authority, rest) = after_scheme
            .split_at_checked(authority_end)
            .ok_or(BrowserUrlRefusal::Host)?;
        check_authority(authority, origin)?;
        check_after_authority(rest)?;
        Ok(Self(raw.to_owned()))
    }

    /// The URL text.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Refuse an `authority` that is not exactly `origin`'s.
fn check_authority(authority: &str, origin: BrowserOrigin) -> Result<(), BrowserUrlRefusal> {
    if authority.contains('@') {
        return Err(BrowserUrlRefusal::Userinfo);
    }
    match origin {
        BrowserOrigin::GitHub => {
            let (host, has_port) = authority
                .split_once(':')
                .map_or((authority, false), |(host, _)| (host, true));
            match (host == "github.com", has_port) {
                (false, _) => Err(BrowserUrlRefusal::Host),
                (true, true) => Err(BrowserUrlRefusal::Port),
                (true, false) => Ok(()),
            }
        }
        BrowserOrigin::Loopback => {
            let (host, port) = authority.split_once(':').ok_or(BrowserUrlRefusal::Port)?;
            if !matches!(host, "127.0.0.1" | "localhost") {
                return Err(BrowserUrlRefusal::Host);
            }
            parse_port(port)
        }
        BrowserOrigin::ExternalHttps => {
            let (host, port) = authority
                .split_once(':')
                .map_or((authority, None), |(host, port)| (host, Some(port)));
            if !is_public_host(host) {
                return Err(BrowserUrlRefusal::Host);
            }
            port.map_or(Ok(()), parse_port)
        }
    }
}

/// Whether `host` is a lowercase name of at least two LDH labels, the last
/// not a number, outside the `localhost` family.
///
/// An IP literal has no representation: a `[` is not an LDH byte, and a
/// browser reads a host whose last label is a number as IPv4 (see
/// [`is_ipv4_number`]).
fn is_public_host(host: &str) -> bool {
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let well_formed = labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    let last_is_name = labels.last().is_some_and(|last| !is_ipv4_number(last));
    well_formed && labels.len() >= 2 && last_is_name && labels.last() != Some(&"localhost")
}

/// Whether a browser's URL parser reads the lowercase LDH `label` as an IPv4 number.
///
/// A host whose last label is one is parsed as an IPv4 address: decimal and
/// octal labels are all digits, and a hex label is `0x` followed by hex
/// digits, none at all included (`https://0x7f.0x1/` is `127.0.0.1`).
fn is_ipv4_number(label: &str) -> bool {
    label.bytes().all(|b| b.is_ascii_digit())
        || label
            .strip_prefix("0x")
            .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Refuse a `port` that is not `1..=65535` written in ASCII digits alone.
fn parse_port(port: &str) -> Result<(), BrowserUrlRefusal> {
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BrowserUrlRefusal::Port);
    }
    match port.parse::<u16>() {
        Ok(n) if n != 0 => Ok(()),
        _ => Err(BrowserUrlRefusal::Port),
    }
}

/// The URL component a byte after the authority sits in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Component {
    Path,
    Query,
    Fragment,
}

/// Refuse a byte of `rest` (path, query, fragment) outside the admitted set.
fn check_after_authority(rest: &str) -> Result<(), BrowserUrlRefusal> {
    let mut component = Component::Path;
    let mut bytes = rest.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'%' => {
                let escaped = (bytes.next(), bytes.next());
                if !matches!(escaped, (Some(hi), Some(lo)) if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit())
                {
                    return Err(BrowserUrlRefusal::Byte(b'%'));
                }
            }
            b'?' if component == Component::Path => component = Component::Query,
            b'#' if component != Component::Fragment => component = Component::Fragment,
            b'&' if component == Component::Query => {}
            _ if is_admitted_anywhere(b) => {}
            refused => return Err(BrowserUrlRefusal::Byte(refused)),
        }
    }
    Ok(())
}

/// Whether `b` is admitted in every component after the authority.
const fn is_admitted_anywhere(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.' | b'_' | b'~' | b':' | b'/' | b'?' | b'#' | b'@' | b'=' | b'+'
        )
}

/// What became of a request to open a URL.
#[derive(Debug)]
#[must_use]
pub enum OpenOutcome {
    /// The opener exited reporting success, or was still running at the grace.
    Opened,
    /// The opener exited reporting failure.
    OpenerFailed(ExitStatus),
    /// No platform opener is installed.
    OpenerMissing,
    /// The hardened spawner refused to start the opener.
    Spawn(SpawnRefusal),
    /// Watching the started opener failed.
    WaitFailed(std::io::ErrorKind),
    /// The platform's opener refused the URL before anything started.
    Refused(OpenerRefusal),
}

/// Why the platform's opener refused a [`BrowserUrl`] before starting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenerRefusal {
    /// The query holds a raw `&`, which a shell-evaluating `xdg-open` splits on.
    QueryAmpersand,
}

impl std::fmt::Display for OpenerRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueryAmpersand => f.write_str(
                "the URL holds `&`, which xdg-open may hand to a shell; open it by hand",
            ),
        }
    }
}

impl std::fmt::Display for OpenOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Opened => f.write_str("the browser opener started"),
            Self::OpenerFailed(status) => write!(f, "the browser opener failed ({status})"),
            Self::OpenerMissing => f.write_str("no browser opener is installed"),
            Self::Spawn(refusal) => write!(f, "the browser opener could not start: {refusal}"),
            Self::WaitFailed(kind) => write!(f, "the browser opener could not be watched ({kind})"),
            Self::Refused(refusal) => write!(f, "{refusal}"),
        }
    }
}

/// The platform whose opener [`open_url`] starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// macOS: `open`.
    MacOs,
    /// Windows: `explorer.exe`.
    Windows,
    /// Every other host: `gio open`, then `xdg-open` when `gio` is not installed.
    Other,
}

impl Platform {
    /// The platform this runtime was built for.
    pub const HOST: Self = if cfg!(target_os = "macos") {
        Self::MacOs
    } else if cfg!(target_os = "windows") {
        Self::Windows
    } else {
        Self::Other
    };

    /// Whether the opener's exit status says whether the URL opened.
    ///
    /// `explorer.exe` exits non-zero after handing a URL to the browser, so
    /// its status carries no failure signal.
    #[must_use]
    pub const fn exit_status_is_verdict(self) -> bool {
        !matches!(self, Self::Windows)
    }

    /// The platform's openers, tried in order; a later one runs only when
    /// the one before it is not installed.
    #[must_use]
    pub const fn openers(self) -> &'static [Opener] {
        match self {
            Self::MacOs => &[Opener::Open],
            Self::Windows => &[Opener::Explorer],
            Self::Other => &[Opener::Gio, Opener::XdgOpen],
        }
    }
}

/// One platform opener program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opener {
    /// macOS `open <url>`.
    Open,
    /// Windows `explorer.exe <url>`.
    Explorer,
    /// GLib `gio open <url>`: no shell on any path, so a query `&` is safe.
    Gio,
    /// `xdg-open <url>`, whose legacy paths may hand the URL to a shell.
    XdgOpen,
}

/// An opener program and its arguments, the URL last.
pub type OpenerArgv<'u> = (&'static str, Vec<&'u str>);

impl Opener {
    /// The program and arguments that open `url`.
    ///
    /// # Errors
    /// [`OpenerRefusal::QueryAmpersand`] for a raw `&` under
    /// [`Opener::XdgOpen`]; a `%26` escape stays admitted.
    pub fn argv(self, url: &BrowserUrl) -> Result<OpenerArgv<'_>, OpenerRefusal> {
        Ok(match self {
            Self::Open => ("open", vec![url.as_str()]),
            Self::Explorer => ("explorer.exe", vec![url.as_str()]),
            Self::Gio => ("gio", vec!["open", url.as_str()]),
            Self::XdgOpen if url.as_str().contains('&') => {
                return Err(OpenerRefusal::QueryAmpersand);
            }
            Self::XdgOpen => ("xdg-open", vec![url.as_str()]),
        })
    }
}

/// The first opener program for `platform` and its arguments, the URL last.
///
/// # Errors
/// The [`OpenerRefusal`] of the platform's first opener.
pub fn opener_argv(platform: Platform, url: &BrowserUrl) -> Result<OpenerArgv<'_>, OpenerRefusal> {
    platform
        .openers()
        .first()
        .map_or(Ok(("", Vec::new())), |opener| opener.argv(url))
}

/// Whether a started opener may leave the job its parent runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Breakaway {
    /// The opener starts in its parent's job, if any.
    Never,
    /// On Windows the opener first tries to break away from its parent's job,
    /// so the browser outlives the parent; where a job forbids breaking away
    /// it starts inside the job. Elsewhere it is [`Self::Never`].
    PreferOutsideJob,
}

/// Open `url` in the desktop's browser through the platform opener, never through a shell.
///
/// The opener starts through the runtime's hardened spawner with every stdio
/// stream null and is watched for at most [`OPENER_GRACE`]; one still running
/// then is left running (an opener may wait on the browser it started) and
/// the call returns, so it never holds the caller. A caller prints the URL
/// whenever the outcome is not [`OpenOutcome::Opened`], a URL the opener
/// refused before starting ([`OpenOutcome::Refused`]) included. Call it from a
/// thread that outlives the opener: a spawning thread's exit signals the
/// opener.
pub fn open_url(url: &BrowserUrl, breakaway: Breakaway) -> OpenOutcome {
    let exit_is_verdict = Platform::HOST.exit_status_is_verdict();
    match start_opener(url, Platform::HOST, breakaway) {
        Ok(child) => watch_opener(child, exit_is_verdict, OPENER_GRACE),
        Err(outcome) => outcome,
    }
}

/// Start the first installed opener of `platform` for `url` and hand back its child unwatched.
///
/// A later opener of the platform runs only when the one before it is not
/// installed; any other outcome is final, so one URL starts at most one
/// opener.
///
/// # Errors
/// The [`OpenOutcome`] that stopped the start: a refusal, a missing opener
/// or a spawn refusal.
pub fn start_opener(
    url: &BrowserUrl,
    platform: Platform,
    breakaway: Breakaway,
) -> Result<Child, OpenOutcome> {
    let mut last = OpenOutcome::OpenerMissing;
    for opener in platform.openers() {
        let (program, args) = opener.argv(url).map_err(OpenOutcome::Refused)?;
        let command = || {
            let mut command = Command::new(program);
            command.args(&args);
            command
        };
        match start_with(command, breakaway) {
            Err(OpenOutcome::OpenerMissing) => last = OpenOutcome::OpenerMissing,
            started => return started,
        }
    }
    Err(last)
}

/// Start the command `command` builds, breaking away from the parent's job when asked.
fn start_with(command: impl Fn() -> Command, breakaway: Breakaway) -> Result<Child, OpenOutcome> {
    #[cfg(windows)]
    if breakaway == Breakaway::PreferOutsideJob {
        return open_breaking_away(
            || {
                use std::os::windows::process::CommandExt as _;
                let mut outside = command();
                outside.creation_flags(CREATE_BREAKAWAY_FROM_JOB);
                spawn_opener(outside)
            },
            || spawn_opener(command()),
        );
    }
    #[cfg(not(windows))]
    let _ = breakaway;
    spawn_opener(command())
}

/// The `CreateProcess` flag that starts a child outside every job its parent is in.
#[cfg(windows)]
const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

/// Start through `breakaway`; only when a job forbade breaking away, so no
/// opener started, start through `inside` instead.
///
/// Any other outcome, a started opener's included, is final: one URL starts
/// at most one opener.
#[cfg(any(windows, test))]
fn open_breaking_away<T>(
    breakaway: impl FnOnce() -> Result<T, OpenOutcome>,
    inside: impl FnOnce() -> Result<T, OpenOutcome>,
) -> Result<T, OpenOutcome> {
    let outcome = breakaway();
    let breakaway_refused = matches!(
        &outcome,
        Err(OpenOutcome::Spawn(SpawnRefusal::Spawn(e)))
            if e.kind() == std::io::ErrorKind::PermissionDenied
    );
    if breakaway_refused { inside() } else { outcome }
}

/// Start `command` hardened with null stdio.
fn spawn_opener(mut command: Command) -> Result<Child, OpenOutcome> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match spawn_hardened(command) {
        Ok(child) => Ok(child),
        Err(SpawnRefusal::Spawn(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(OpenOutcome::OpenerMissing)
        }
        Err(refusal) => Err(OpenOutcome::Spawn(refusal)),
    }
}

/// Start `command` hardened with null stdio and watch it for at most `grace`.
///
/// Test-only: production reaches a process only through [`open_url`] or
/// [`start_opener`], so only a parsed [`BrowserUrl`] starts an opener.
#[cfg(test)]
fn run_opener(command: Command, exit_is_verdict: bool, grace: Duration) -> OpenOutcome {
    match spawn_opener(command) {
        Ok(child) => watch_opener(child, exit_is_verdict, grace),
        Err(outcome) => outcome,
    }
}

/// Watch a started opener for at most `grace`.
fn watch_opener(mut child: Child, exit_is_verdict: bool, grace: Duration) -> OpenOutcome {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() || !exit_is_verdict => return OpenOutcome::Opened,
            Ok(Some(status)) => return OpenOutcome::OpenerFailed(status),
            Ok(None) => {
                let left = grace.saturating_sub(started.elapsed());
                if left.is_zero() {
                    // Dropping a `Child` does not kill it: the opener runs on.
                    return OpenOutcome::Opened;
                }
                std::thread::sleep(OPENER_POLL.min(left));
            }
            Err(e) => return OpenOutcome::WaitFailed(e.kind()),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn github(raw: &str) -> Result<BrowserUrl, BrowserUrlRefusal> {
        BrowserUrl::parse(raw, BrowserOrigin::GitHub)
    }

    fn loopback(raw: &str) -> Result<BrowserUrl, BrowserUrlRefusal> {
        BrowserUrl::parse(raw, BrowserOrigin::Loopback)
    }

    fn external(raw: &str) -> Result<BrowserUrl, BrowserUrlRefusal> {
        BrowserUrl::parse(raw, BrowserOrigin::ExternalHttps)
    }

    #[test]
    fn the_github_verification_uri_is_admitted() {
        let url = github("https://github.com/login/device");
        assert_eq!(
            url.as_ref().map(BrowserUrl::as_str),
            Ok("https://github.com/login/device")
        );
    }

    #[test]
    fn the_prefilled_compare_page_is_admitted_with_its_query_separator() {
        let raw = "https://github.com/o/r/compare/main...octocat:publish/foo-1.2.3+b1\
                   ?quick_pull=1&title=Publish%20foo%201.2.3";
        assert_eq!(
            github(raw).map(|u| u.as_str().to_owned()),
            Ok(raw.to_owned())
        );
    }

    #[test]
    fn a_loopback_server_url_is_admitted() {
        assert!(loopback("http://127.0.0.1:8080/").is_ok());
        assert!(loopback("http://localhost:1/index.html").is_ok());
        assert!(loopback("http://127.0.0.1:65535").is_ok());
    }

    #[test]
    fn a_verification_uri_with_a_shell_metacharacter_is_refused() {
        assert_eq!(
            github("https://github.com/login/device&calc"),
            Err(BrowserUrlRefusal::Byte(b'&'))
        );
    }

    #[test]
    fn an_ampersand_outside_the_query_is_refused() {
        assert_eq!(
            github("https://github.com/a?x=1#y&calc"),
            Err(BrowserUrlRefusal::Byte(b'&'))
        );
    }

    #[test]
    fn every_shell_and_opener_metacharacter_is_refused() {
        for b in [
            b'|', b'^', b'<', b'>', b'\n', b'\r', b'\0', b'\t', b' ', b'"', b'\'', b'`', b'\\',
            b'{', b'}', b'[', b']', b',', b';', b'$', b'!', b'*', b'(', b')', 0x1b, 0x7f,
        ] {
            let raw = format!("https://github.com/login/device?x=1{}calc", char::from(b));
            assert_eq!(
                github(&raw),
                Err(BrowserUrlRefusal::Byte(b)),
                "byte {b:#04x} must be refused"
            );
        }
    }

    #[test]
    fn a_non_ascii_byte_is_refused() {
        assert_eq!(
            github("https://github.com/login/d\u{e9}vice"),
            Err(BrowserUrlRefusal::Byte(0xc3))
        );
        assert_eq!(
            github("https://github.com/x\u{2028}y"),
            Err(BrowserUrlRefusal::Byte(0xe2))
        );
    }

    #[test]
    fn a_percent_not_followed_by_two_hex_digits_is_refused() {
        for raw in [
            "https://github.com/a%2",
            "https://github.com/a%zz",
            "https://github.com/a%",
        ] {
            assert_eq!(github(raw), Err(BrowserUrlRefusal::Byte(b'%')), "{raw}");
        }
        assert!(github("https://github.com/a%2F").is_ok());
    }

    #[test]
    fn an_empty_url_is_refused() {
        assert_eq!(github(""), Err(BrowserUrlRefusal::Empty));
        assert_eq!(loopback(""), Err(BrowserUrlRefusal::Empty));
        assert_eq!(external(""), Err(BrowserUrlRefusal::Empty));
    }

    #[test]
    fn a_foreign_scheme_is_refused() {
        for raw in [
            "http://github.com/login/device",
            "HTTPS://github.com/login/device",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "-https://github.com/",
        ] {
            assert_eq!(github(raw), Err(BrowserUrlRefusal::Scheme), "{raw}");
        }
        assert_eq!(
            loopback("https://127.0.0.1:8080/"),
            Err(BrowserUrlRefusal::Scheme)
        );
    }

    #[test]
    fn another_host_is_refused() {
        for raw in [
            "https://evil.example.com/login/device",
            "https://github.com.evil.com/x",
            "https://notgithub.com/x",
            "https://GitHub.com/x",
            "https:///x",
        ] {
            assert_eq!(github(raw), Err(BrowserUrlRefusal::Host), "{raw}");
        }
        for raw in [
            "http://10.0.0.1:8080/",
            "http://localhost.evil.com:80/",
            "http://127.0.0.1.evil:80/",
            "http://[::1]:80/",
            "http://LOCALHOST:80/",
        ] {
            assert_eq!(loopback(raw), Err(BrowserUrlRefusal::Host), "{raw}");
        }
    }

    #[test]
    fn github_userinfo_is_refused() {
        assert_eq!(
            github("https://github.com@evil.example.com/x"),
            Err(BrowserUrlRefusal::Userinfo)
        );
        assert_eq!(
            github("https://user@github.com/x"),
            Err(BrowserUrlRefusal::Userinfo)
        );
        assert_eq!(
            loopback("http://u@127.0.0.1:80/"),
            Err(BrowserUrlRefusal::Userinfo)
        );
    }

    #[test]
    fn a_backslash_ends_the_authority_and_is_refused() {
        assert_eq!(
            github("https://github.com\\@evil.example.com/"),
            Err(BrowserUrlRefusal::Byte(b'\\'))
        );
    }

    #[test]
    fn a_github_port_is_refused() {
        assert_eq!(
            github("https://github.com:8443/login/device"),
            Err(BrowserUrlRefusal::Port)
        );
        assert_eq!(
            github("https://github.com:/x"),
            Err(BrowserUrlRefusal::Port)
        );
    }

    #[test]
    fn a_loopback_port_with_a_plus_is_refused() {
        assert_eq!(
            loopback("http://127.0.0.1:+8080/"),
            Err(BrowserUrlRefusal::Port)
        );
    }

    #[test]
    fn a_loopback_port_out_of_range_or_absent_is_refused() {
        for raw in [
            "http://127.0.0.1:0/",
            "http://127.0.0.1:65536/",
            "http://127.0.0.1:/",
            "http://127.0.0.1/",
            "http://localhost:8o80/",
        ] {
            assert_eq!(loopback(raw), Err(BrowserUrlRefusal::Port), "{raw}");
        }
    }

    /// An external URL names any public host, with or without a port, and
    /// keeps the one byte grammar after its authority.
    #[test]
    fn external_https_origin_admits_any_public_host() {
        for raw in [
            "https://example.com/",
            "https://example.com",
            "https://docs.example.com:8443/a?b=c&d=e#f",
            "https://a-b.example.co.uk/x",
            "https://xn--bcher-kva.example/",
            "https://123.example/",
            "https://a.0xg/",
            "https://0x7f.example/",
            "https://a.x0/",
        ] {
            assert!(external(raw).is_ok(), "{raw}");
        }
        for (raw, refusal) in [
            ("http://example.com/", BrowserUrlRefusal::Scheme),
            ("HTTPS://example.com/", BrowserUrlRefusal::Scheme),
            ("https://user@example.com/", BrowserUrlRefusal::Userinfo),
            ("https://example.com@evil.com/", BrowserUrlRefusal::Userinfo),
            ("https://127.0.0.1/", BrowserUrlRefusal::Host),
            ("https://[::1]/", BrowserUrlRefusal::Host),
            ("https://localhost/", BrowserUrlRefusal::Host),
            ("https://a.localhost/", BrowserUrlRefusal::Host),
            ("https://intranet/", BrowserUrlRefusal::Host),
            ("https://1.2.3.4.5/", BrowserUrlRefusal::Host),
            ("https://0x7f.0x1/", BrowserUrlRefusal::Host),
            ("https://127.0.0.0x1/", BrowserUrlRefusal::Host),
            ("https://0x7f.0x0.0x0.0x1/", BrowserUrlRefusal::Host),
            ("https://a.0x/", BrowserUrlRefusal::Host),
            ("https://a.0xff:8443/", BrowserUrlRefusal::Host),
            ("https://0177.0.0.01/", BrowserUrlRefusal::Host),
            ("https://Example.com/", BrowserUrlRefusal::Host),
            ("https://-a.example/", BrowserUrlRefusal::Host),
            ("https://a..example/", BrowserUrlRefusal::Host),
            ("https://ex\u{e4}mple.com/", BrowserUrlRefusal::Host),
            ("https://example.com:0/", BrowserUrlRefusal::Port),
            ("https://example.com:/", BrowserUrlRefusal::Port),
            ("https://example.com/a b", BrowserUrlRefusal::Byte(b' ')),
            ("https://example.com/a\r\nb", BrowserUrlRefusal::Byte(b'\r')),
        ] {
            assert_eq!(external(raw), Err(refusal), "{raw}");
        }
    }

    /// The ceiling is judged before any other check, on every origin.
    #[test]
    fn a_url_over_the_ceiling_is_refused_first() {
        let at = format!(
            "https://example.com/{}",
            "a".repeat(MAX_BROWSER_URL_LEN - "https://example.com/".len())
        );
        assert!(external(&at).is_ok());
        let over = format!("{at}a");
        assert_eq!(external(&over), Err(BrowserUrlRefusal::TooLong));
        let hostile = format!("javascript:{}", " ".repeat(MAX_BROWSER_URL_LEN));
        assert_eq!(github(&hostile), Err(BrowserUrlRefusal::TooLong));
    }

    #[test]
    fn the_windows_opener_never_runs_a_shell() {
        let Ok(url) = github("https://github.com/login/device") else {
            return;
        };
        assert_eq!(
            opener_argv(Platform::Windows, &url),
            Ok(("explorer.exe", vec![url.as_str()]))
        );
    }

    #[test]
    fn every_opener_takes_the_url_as_its_one_argument() {
        let Ok(url) = github("https://github.com/login/device") else {
            return;
        };
        for platform in [Platform::MacOs, Platform::Windows, Platform::Other] {
            for opener in platform.openers() {
                let argv = opener.argv(&url);
                assert!(
                    argv.as_ref()
                        .is_ok_and(|(_, args)| args.last() == Some(&url.as_str())),
                    "{opener:?}: {argv:?}"
                );
                assert!(!argv.is_ok_and(|(program, _)| {
                    matches!(program, "cmd" | "cmd.exe" | "sh" | "bash")
                }));
            }
        }
    }

    /// Off macOS and Windows the opener is `gio open`, and `xdg-open` only
    /// after it.
    #[test]
    fn linux_opener_prefers_gio_then_xdg_open() {
        assert_eq!(Platform::Other.openers(), &[Opener::Gio, Opener::XdgOpen]);
        let Ok(url) = external("https://example.com/") else {
            return;
        };
        assert_eq!(
            opener_argv(Platform::Other, &url),
            Ok(("gio", vec!["open", "https://example.com/"]))
        );
        assert_eq!(Platform::MacOs.openers(), &[Opener::Open]);
        assert_eq!(Platform::Windows.openers(), &[Opener::Explorer]);
    }

    #[test]
    fn xdg_open_refuses_a_raw_query_ampersand() {
        let Ok(url) = github("https://github.com/a?x=1&y=2") else {
            return;
        };
        assert_eq!(
            Opener::XdgOpen.argv(&url),
            Err(OpenerRefusal::QueryAmpersand)
        );
    }

    /// The `xdg-open` fallback keeps its refusal of a raw query `&`.
    #[test]
    fn xdg_open_fallback_still_refuses_a_query_ampersand() {
        let Ok(url) = external("https://docs.example.com:8443/a?b=c&d=e#f") else {
            return;
        };
        let fallback = Platform::Other.openers().get(1).copied();
        assert_eq!(fallback, Some(Opener::XdgOpen));
        assert_eq!(
            fallback.map(|opener| opener.argv(&url)),
            Some(Err(OpenerRefusal::QueryAmpersand))
        );
    }

    /// `gio open` runs no shell, so a query `&` reaches it intact.
    #[test]
    fn gio_opener_admits_a_query_ampersand() {
        let Ok(url) = external("https://docs.example.com:8443/a?b=c&d=e#f") else {
            return;
        };
        assert_eq!(
            Opener::Gio.argv(&url),
            Ok((
                "gio",
                vec!["open", "https://docs.example.com:8443/a?b=c&d=e#f"]
            ))
        );
    }

    #[test]
    fn xdg_open_admits_a_percent_encoded_ampersand() {
        let Ok(url) = github("https://github.com/a?x=1%26y=2") else {
            return;
        };
        assert_eq!(
            Opener::XdgOpen.argv(&url),
            Ok(("xdg-open", vec!["https://github.com/a?x=1%26y=2"]))
        );
    }

    #[test]
    fn openers_without_a_shell_path_admit_a_query_ampersand() {
        let Ok(url) = github("https://github.com/a?x=1&y=2") else {
            return;
        };
        for (platform, expected) in [
            (Platform::MacOs, "open"),
            (Platform::Windows, "explorer.exe"),
        ] {
            assert_eq!(
                opener_argv(platform, &url),
                Ok((expected, vec!["https://github.com/a?x=1&y=2"]))
            );
        }
    }

    #[test]
    fn a_refused_url_names_its_by_hand_fallback() {
        assert_eq!(
            OpenOutcome::Refused(OpenerRefusal::QueryAmpersand).to_string(),
            "the URL holds `&`, which xdg-open may hand to a shell; open it by hand"
        );
    }

    #[test]
    fn only_the_windows_opener_status_carries_no_verdict() {
        assert!(Platform::MacOs.exit_status_is_verdict());
        assert!(Platform::Other.exit_status_is_verdict());
        assert!(!Platform::Windows.exit_status_is_verdict());
    }

    #[cfg(unix)]
    fn sh(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        command
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_opener_reports_failure() {
        let outcome = run_opener(sh("exit 3"), true, Duration::from_secs(30));
        assert!(
            matches!(&outcome, OpenOutcome::OpenerFailed(status) if status.code() == Some(3)),
            "{outcome}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_succeeding_opener_reports_opened() {
        let outcome = run_opener(sh("exit 0"), true, Duration::from_secs(30));
        assert!(matches!(outcome, OpenOutcome::Opened), "{outcome}");
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_status_without_a_verdict_is_opened() {
        let outcome = run_opener(sh("exit 1"), false, Duration::from_secs(30));
        assert!(matches!(outcome, OpenOutcome::Opened), "{outcome}");
    }

    /// A breakaway outcome and whether the inside opener then ran.
    fn breaking_away(first: OpenOutcome) -> (OpenOutcome, bool) {
        let inside_ran = std::cell::Cell::new(false);
        let outcome = open_breaking_away::<()>(
            || Err(first),
            || {
                inside_ran.set(true);
                Err(OpenOutcome::Opened)
            },
        );
        (
            outcome.err().unwrap_or(OpenOutcome::Opened),
            inside_ran.get(),
        )
    }

    #[test]
    fn a_refused_breakaway_opens_inside_the_job() {
        let refused = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let (outcome, inside_ran) = breaking_away(OpenOutcome::Spawn(SpawnRefusal::Spawn(refused)));
        assert!(inside_ran, "a refused breakaway opened nothing");
        assert!(matches!(outcome, OpenOutcome::Opened), "{outcome}");
    }

    /// One URL starts at most one opener: only a breakaway refused before
    /// the start is retried.
    #[test]
    fn any_other_breakaway_outcome_is_final() {
        let not_found = std::io::Error::from(std::io::ErrorKind::NotFound);
        let finals = [
            OpenOutcome::Opened,
            OpenOutcome::OpenerMissing,
            OpenOutcome::Spawn(SpawnRefusal::Spawn(not_found)),
            OpenOutcome::WaitFailed(std::io::ErrorKind::PermissionDenied),
        ];
        for first in finals {
            let shown = first.to_string();
            let (outcome, inside_ran) = breaking_away(first);
            assert!(!inside_ran, "a second opener started after: {shown}");
            assert_eq!(outcome.to_string(), shown);
        }
    }

    #[test]
    fn a_missing_opener_is_reported_missing() {
        let outcome = run_opener(
            Command::new("ipe-test-no-such-browser-opener"),
            true,
            Duration::from_secs(30),
        );
        assert!(matches!(outcome, OpenOutcome::OpenerMissing), "{outcome}");
    }

    /// The production text of a module: everything before its test module.
    fn production(source: &'static str) -> &'static str {
        source
            .split_once(concat!("#[cfg(all(test, ", "not(target_arch"))
            .map_or(source, |(production, _)| production)
    }

    /// The opener and the link worker reach a process only through the one hardened runner.
    ///
    /// `browser_open.rs` names one `Command::new` and one `spawn_hardened`
    /// call; `nav_policy.rs` reaches it only through `start_opener` from one
    /// named thread; neither starts a child or a thread any other way.
    #[test]
    fn browser_open_spawns_only_through_spawn_hardened() {
        let opener = production(include_str!("browser_open.rs"));
        let link_worker = production(include_str!("webview/nav_policy.rs"));
        for (file, source) in [("browser_open.rs", opener), ("nav_policy.rs", link_worker)] {
            for banned in [
                "Command::spawn",
                ".spawn()",
                ".output()",
                ".status()",
                ".exec(",
                "std::thread::spawn",
                "thread::Builder",
                "spawn_hardened_naming(",
                "spawn_hardened_tokio(",
                "exec_naming(",
            ] {
                assert!(!source.contains(banned), "{file} must not name {banned}");
            }
        }
        for (file, source, call, count) in [
            ("browser_open.rs", opener, "Command::new(", 1),
            ("browser_open.rs", opener, "spawn_hardened(", 1),
            ("nav_policy.rs", link_worker, "Command::new(", 0),
            ("nav_policy.rs", link_worker, "spawn_hardened(", 0),
            (
                "nav_policy.rs",
                link_worker,
                "browser_open::start_opener(",
                1,
            ),
            ("nav_policy.rs", link_worker, "threads::spawn_named(", 1),
        ] {
            assert_eq!(source.matches(call).count(), count, "{file}: {call}");
        }
    }

    /// The opener writes its marker three seconds after the grace ends, so only an
    /// opener left running past the grace can write it.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // a test directory the test cannot create is a test failure
    fn an_opener_still_running_at_the_grace_is_opened_and_not_killed() {
        let dir = crate::scratch_core::test_temp_root().join(format!(
            "ipe-browser-grace-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        let marker = dir.join("still-running");
        let mut command = sh("sleep 3; : > \"$0\"");
        command.arg(&marker);

        let started = Instant::now();
        let outcome = run_opener(command, true, Duration::from_millis(100));
        assert!(matches!(outcome, OpenOutcome::Opened), "{outcome}");
        assert!(
            started.elapsed() < Duration::from_millis(2500),
            "the opener held the caller past its grace"
        );
        assert!(!marker.exists(), "the opener exited before the grace ended");

        let deadline = Instant::now() + Duration::from_secs(20);
        while !marker.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(marker.exists(), "the opener was killed at the grace");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
