//! The one browser opener: a URL parsed once, handed to the platform opener without a shell.
//!
//! Every URL the CLI asks the desktop to open is a [`BrowserUrl`], parsed at
//! the boundary against the one origin its caller expects, and [`open_url`]
//! is the one function that starts an opener. The opener is the platform's
//! own program (`open`, `explorer.exe`, `xdg-open`) with the URL as its single
//! argument: no `cmd /C start`, no `sh -c`, so no shell ever re-parses the
//! URL. The byte set a `BrowserUrl` admits refuses the shell metacharacters as
//! well (defence in depth): `&` stands only in the query, as its field
//! separator.

use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use ipe_runtime_rust::system::{SpawnRefusal, spawn_hardened};

/// How long a started opener is watched for a failure before it is left running.
pub const OPENER_GRACE: Duration = Duration::from_secs(5);

/// The interval between two checks on a started opener.
const OPENER_POLL: Duration = Duration::from_millis(50);

/// The one origin a [`BrowserUrl`] is parsed against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserOrigin {
    /// `https://github.com`, with no userinfo and no port.
    GitHub,
    /// `http://127.0.0.1:<port>` or `http://localhost:<port>`, the port `1..=65535`.
    Loopback,
}

/// Why a URL is not a [`BrowserUrl`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserUrlRefusal {
    /// The scheme is not the origin's (`https` for GitHub, `http` for loopback).
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
        if raw.is_empty() {
            return Err(BrowserUrlRefusal::Empty);
        }
        let scheme = match origin {
            BrowserOrigin::GitHub => "https://",
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
    }
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
    /// The platform opener is not installed.
    OpenerMissing,
    /// The hardened spawner refused to start the opener.
    Spawn(SpawnRefusal),
    /// Watching the started opener failed.
    WaitFailed(std::io::ErrorKind),
}

impl std::fmt::Display for OpenOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Opened => f.write_str("the browser opener started"),
            Self::OpenerFailed(status) => write!(f, "the browser opener failed ({status})"),
            Self::OpenerMissing => f.write_str("no browser opener is installed"),
            Self::Spawn(refusal) => write!(f, "the browser opener could not start: {refusal}"),
            Self::WaitFailed(kind) => write!(f, "the browser opener could not be watched ({kind})"),
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
    /// Every other host: `xdg-open`.
    Other,
}

impl Platform {
    /// The platform this CLI was built for.
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
}

/// The opener program for `platform` and its one argument, the URL.
const fn opener_argv(platform: Platform, url: &BrowserUrl) -> (&'static str, [&str; 1]) {
    let program = match platform {
        Platform::MacOs => "open",
        Platform::Windows => "explorer.exe",
        Platform::Other => "xdg-open",
    };
    (program, [url.as_str()])
}

/// Open `url` in the desktop's browser through the platform opener, never through a shell.
///
/// The opener starts through the runtime's hardened spawner with every stdio
/// stream null and is watched for at most [`OPENER_GRACE`]; one still running
/// then is left running (an opener may wait on the browser it started) and
/// the call returns, so it never holds the caller. A caller prints the URL
/// whenever the outcome is not [`OpenOutcome::Opened`]. Call it from a thread
/// that outlives the opener: a spawning thread's exit signals the opener.
pub fn open_url(url: &BrowserUrl) -> OpenOutcome {
    let (program, args) = opener_argv(Platform::HOST, url);
    let mut command = Command::new(program);
    command.args(args);
    run_opener(
        command,
        Platform::HOST.exit_status_is_verdict(),
        OPENER_GRACE,
    )
}

/// Start `command` hardened with null stdio and watch it for at most `grace`.
fn run_opener(mut command: Command, exit_is_verdict: bool, grace: Duration) -> OpenOutcome {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = match spawn_hardened(command) {
        Ok(child) => child,
        Err(SpawnRefusal::Spawn(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return OpenOutcome::OpenerMissing;
        }
        Err(refusal) => return OpenOutcome::Spawn(refusal),
    };
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

#[cfg(test)]
mod tests {
    use super::*;

    fn github(raw: &str) -> Result<BrowserUrl, BrowserUrlRefusal> {
        BrowserUrl::parse(raw, BrowserOrigin::GitHub)
    }

    fn loopback(raw: &str) -> Result<BrowserUrl, BrowserUrlRefusal> {
        BrowserUrl::parse(raw, BrowserOrigin::Loopback)
    }

    #[test]
    fn the_github_verification_uri_is_admitted() {
        let url = github("https://github.com/login/device").expect("admitted");
        assert_eq!(url.as_str(), "https://github.com/login/device");
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
        assert_eq!(
            github("https://github.com/a%2"),
            Err(BrowserUrlRefusal::Byte(b'%'))
        );
        assert_eq!(
            github("https://github.com/a%zz"),
            Err(BrowserUrlRefusal::Byte(b'%'))
        );
        assert_eq!(
            github("https://github.com/a%"),
            Err(BrowserUrlRefusal::Byte(b'%'))
        );
        assert!(github("https://github.com/a%2F").is_ok());
    }

    #[test]
    fn an_empty_url_is_refused() {
        assert_eq!(github(""), Err(BrowserUrlRefusal::Empty));
        assert_eq!(loopback(""), Err(BrowserUrlRefusal::Empty));
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

    #[test]
    fn the_windows_opener_never_runs_a_shell() {
        let url = github("https://github.com/login/device").expect("admitted");
        let (program, args) = opener_argv(Platform::Windows, &url);
        assert_eq!(program, "explorer.exe");
        assert_eq!(args, [url.as_str()]);
    }

    #[test]
    fn every_opener_takes_the_url_as_its_one_argument() {
        let url = github("https://github.com/login/device").expect("admitted");
        for (platform, expected) in [
            (Platform::MacOs, "open"),
            (Platform::Windows, "explorer.exe"),
            (Platform::Other, "xdg-open"),
        ] {
            let (program, args) = opener_argv(platform, &url);
            assert_eq!(program, expected);
            assert_eq!(args, [url.as_str()]);
            assert!(!matches!(program, "cmd" | "cmd.exe" | "sh" | "bash"));
        }
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

    #[test]
    fn a_missing_opener_is_reported_missing() {
        let outcome = run_opener(
            Command::new("ipe-test-no-such-browser-opener"),
            true,
            Duration::from_secs(30),
        );
        assert!(matches!(outcome, OpenOutcome::OpenerMissing), "{outcome}");
    }

    /// The opener writes its marker three seconds after the grace ends, so only an
    /// opener left running past the grace can write it.
    #[cfg(unix)]
    #[test]
    fn an_opener_still_running_at_the_grace_is_opened_and_not_killed() {
        let dir = ipe_test_temp::temp_root().join(format!(
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
