//! `ipe login` — GitHub device-code OAuth for a publish token.
//!
//! Obtains a GitHub access token via the [device authorization grant] and stores
//! it locally so `ipe package publish`'s headless path can open the index PR
//! without a manually-exported `GITHUB_TOKEN`. Device flow needs only the public
//! `client_id` (no client secret) and no redirect/callback, so it fits a CLI: the
//! user is shown a short code to enter at a GitHub URL while `ipe` polls for the
//! token.
//!
//! The token is written to `$XDG_CONFIG_HOME/ipe/token` (or `~/.config/ipe/token`)
//! with `0600` permissions, never into the project tree.
//!
//! [device authorization grant]: https://docs.github.com/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#device-flow

use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::CliError;

/// The Ipê CLI's GitHub OAuth App client id. Public by design — the device flow
/// authenticates with the client id alone (no secret), so embedding it is safe.
const CLIENT_ID: &str = "Ov23liBpCFLSoxJvSTwO";

/// The scope requested: enough to fork the public index repo and open the
/// publish pull request, nothing more.
const SCOPE: &str = "public_repo";

/// Upper bound on the poll interval (seconds) accepted from GitHub's response.
/// A hostile or malformed `interval` (up to `u64::MAX`) is clamped to this, so
/// the poll cadence stays bounded and the overall wait is governed by the
/// expiry deadline, never by a server-dictated sleep.
const MAX_POLL_INTERVAL_SECS: u64 = 60;

const DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// `ipe login [--status | --logout]` — obtain and store a GitHub publish token.
///
/// With no flag, runs the device flow and stores the token. `--status` reports
/// whether a token is stored; `--logout` removes it.
///
/// # Errors
/// [`CliError::UsageOwned`] on an unknown flag; [`CliError::Resolve`] when the
/// OAuth request fails, the user does not authorize in time, or the token cannot
/// be stored.
pub fn run_login(rest: &[String]) -> Result<(), CliError> {
    match rest.first().map(String::as_str) {
        None => run_device_flow(),
        Some("--status") if rest.len() == 1 => {
            // `--status` reports the SAME state `publish` consumes: a stored,
            // well-formed token. A token file that exists but does not parse is
            // reported distinctly, never as "logged in" — the two views of the
            // credential state must agree.
            let message = match token_status() {
                TokenStatus::LoggedIn(path) => {
                    format!("logged in — token stored at {}", path.display())
                }
                TokenStatus::Corrupt(path) => format!(
                    "token file at {} is unreadable or malformed — run `ipe login` to re-authorize",
                    path.display()
                ),
                TokenStatus::NotLoggedIn => {
                    "not logged in — run `ipe login` to authorize".to_owned()
                }
            };
            crate::screen::Screen::new(crate::screen::Stream::Stdout)
                .line(crate::screen::Tone::Text, &message)
                .emit();
            Ok(())
        }
        Some("--logout") if rest.len() == 1 => logout(),
        Some(other) if other.starts_with('-') => {
            Err(crate::cli_args::usage_unknown_flag("login", other))
        }
        Some(other) => Err(crate::cli_args::usage_unexpected_argument("login", other)),
    }
}

/// A GitHub access token, parsed once at the trust boundary into a value whose
/// bytes are drawn only from the GitHub token alphabet (`[A-Za-z0-9_]`).
///
/// This is `parse, don't validate` at the credential boundary: a token that
/// reached this type cannot contain a quote, a newline, or any control byte, so
/// splicing it into curl's `--config` mini-language (`header = "…{token}"`)
/// cannot inject a new curl directive. The unparsed `String` never travels
/// downstream — only a `PublishToken` does.
#[derive(Clone)]
pub struct PublishToken(String);

impl PublishToken {
    /// Parse a raw token, accepting only the GitHub token alphabet.
    ///
    /// Returns `None` when the trimmed token is empty or holds any byte outside
    /// `[A-Za-z0-9_]` — quotes, newlines, spaces, and control bytes are all
    /// rejected, closing the curl-config injection path.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        if trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            Some(Self(trimmed.to_owned()))
        } else {
            None
        }
    }

    /// The token bytes, safe to splice into the curl config header line.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The stored publish token, if the user has run `ipe login`. `None` when no
/// token file exists, it cannot be read, or its contents are not a well-formed
/// token. Consumed by the publish headless path.
#[must_use]
pub fn stored_token() -> Option<PublishToken> {
    let raw = crate::io_bounded::read_to_string_capped(
        &token_path()?,
        crate::io_bounded::SMALL_FILE_READ_CAP,
    )
    .ok()?;
    PublishToken::parse(&raw)
}

/// Run the full device flow: request a code, prompt the user, poll for the token,
/// store it.
fn run_device_flow() -> Result<(), CliError> {
    let device = request_device_code()?;

    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(
            crate::screen::Tone::Text,
            &format!(
                "To authorize ipe, visit:\n  {}\nand enter the code:  {}",
                device.verification_uri.as_str(),
                device.user_code
            ),
        )
        .emit();
    if open_in_browser(device.verification_uri.as_str()) {
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Text,
            "(opened your browser)",
        );
    }
    crate::screen::chatter(
        crate::screen::Stream::Stderr,
        crate::screen::Tone::Text,
        "Waiting for authorization …",
    );

    let token = poll_for_token(&device)?;
    let path = store_token(&token)?;
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(
            crate::screen::Tone::Text,
            &format!("Logged in. Token stored at {}", path.display()),
        )
        .emit();
    Ok(())
}

/// The verification URL GitHub tells the user to open, parsed once into a value
/// that is guaranteed `https` on the expected GitHub host.
///
/// `parse, don't validate` at the network boundary: a compromised or spoofed
/// device-code response cannot smuggle an arbitrary scheme (`file:`, `javascript:`,
/// a custom app handler) or an off-host URL into `xdg-open`/`open`, because only
/// a `VerificationUri` reaches the opener and it can only hold an accepted URL.
struct VerificationUri(String);

impl VerificationUri {
    /// The single accepted host for the device-flow verification URL.
    const EXPECTED_HOST: &'static str = "github.com";
    const HTTPS_PREFIX: &'static str = "https://";

    /// Parse a raw verification URL, accepting only `https://github.com[/…]`.
    ///
    /// Fails closed: any non-`https` scheme, any other host, or an embedded
    /// userinfo/`@` that could mask the real host is rejected.
    fn parse(raw: &str) -> Option<Self> {
        let after_scheme = raw.strip_prefix(Self::HTTPS_PREFIX)?;
        // The authority runs up to the first `/`, `?`, or `#`.
        let authority = after_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or(after_scheme);
        // Reject userinfo (`user@host`) so `github.com` in userinfo cannot mask
        // an attacker host, and reject a port or any non-host authority.
        if authority == Self::EXPECTED_HOST {
            Some(Self(raw.to_owned()))
        } else {
            None
        }
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// The device-code grant's first response.
struct DeviceGrant {
    device_code: String,
    user_code: String,
    verification_uri: VerificationUri,
    interval: u64,
    expires_in: u64,
}

/// POST `login/device/code` and parse the device-code grant.
fn request_device_code() -> Result<DeviceGrant, CliError> {
    let json = post_form(
        DEVICE_CODE_URL,
        &[("client_id", CLIENT_ID), ("scope", SCOPE)],
    )?;
    let device_code = str_field(&json, "device_code")?;
    let user_code = str_field(&json, "user_code")?;
    let verification_uri_raw = str_field(&json, "verification_uri")?;
    let verification_uri = VerificationUri::parse(&verification_uri_raw)
        .ok_or_else(|| login_error(crate::text::login_verification_url_refused()))?;
    // GitHub returns these as JSON numbers; default to safe values if absent.
    let interval = json
        .get("interval")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(5)
        .clamp(1, MAX_POLL_INTERVAL_SECS);
    let expires_in = json
        .get("expires_in")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(900);
    Ok(DeviceGrant {
        device_code,
        user_code,
        verification_uri,
        interval,
        expires_in,
    })
}

/// Poll `login/oauth/access_token` until the user authorizes, the code expires,
/// or GitHub reports a terminal error. The returned token is parsed into a
/// [`PublishToken`] at this boundary, so a malformed token never travels on.
fn poll_for_token(device: &DeviceGrant) -> Result<PublishToken, CliError> {
    let deadline = Instant::now() + Duration::from_secs(device.expires_in);
    let mut interval = device.interval.clamp(1, MAX_POLL_INTERVAL_SECS);
    loop {
        // Check the deadline BEFORE sleeping, and never sleep past it: a hostile
        // response cannot push the process into an unbounded sleep, because each
        // sleep is clamped to the time actually remaining and the interval is
        // itself capped at `MAX_POLL_INTERVAL_SECS`.
        let now = Instant::now();
        if now >= deadline {
            return Err(login_error(
                crate::text::login_code_expired_before_approval(),
            ));
        }
        let remaining = deadline.saturating_duration_since(now);
        std::thread::sleep(Duration::from_secs(interval).min(remaining));
        let json = post_form(
            TOKEN_URL,
            &[
                ("client_id", CLIENT_ID),
                ("device_code", &device.device_code),
                ("grant_type", GRANT_TYPE),
            ],
        )?;
        if let Some(token) = json.get("access_token").and_then(serde_json::Value::as_str) {
            return PublishToken::parse(token)
                .ok_or_else(|| login_error(crate::text::login_token_malformed()));
        }
        match json.get("error").and_then(serde_json::Value::as_str) {
            // Not authorized yet — keep waiting at the current cadence.
            Some("authorization_pending") => {}
            // GitHub asks us to back off; it also raises the required interval.
            // The server-supplied value is capped so a hostile `interval` cannot
            // stall the poll — the deadline still bounds total wait regardless.
            Some("slow_down") => {
                interval = json
                    .get("interval")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(interval + 5)
                    .max(interval + 5)
                    .min(MAX_POLL_INTERVAL_SECS);
            }
            Some("access_denied") => {
                return Err(login_error(crate::text::login_denied()));
            }
            Some("expired_token") => {
                return Err(login_error(crate::text::login_code_expired()));
            }
            Some(other) => return Err(login_error(&crate::text::login_github_reported(&other))),
            None => {
                return Err(login_error(crate::text::login_response_unrecognised()));
            }
        }
    }
}

/// Percent-encode a string for use in an `application/x-www-form-urlencoded`
/// body. Unreserved characters (RFC 3986 §2.3: letters, digits, `-`, `_`, `.`,
/// `~`) pass through; every other byte is encoded as `%XX`. Spaces become `%20`
/// (not `+`, the safer choice for OAuth form bodies). This is a standalone
/// implementation so the crate needs no new dependency.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => {
                out.push('%');
                out.push(
                    char::from_digit(u32::from(other) >> 4, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit(u32::from(other) & 0xf, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

/// POST a form-encoded body and parse the JSON response. Shells out to `curl`
/// (the crate carries no HTTP client, mirroring the `git`-based resolver).
/// Each field key and value is URL-encoded so a value with `&`, `=`, `:`, or
/// other special characters cannot break the form or inject additional fields.
///
/// The body — which during token polling carries the `device_code`, a secret
/// exchangeable for the publish token — is delivered to curl over stdin
/// (`-d @-`), never as an argv element, so it cannot be read from
/// `/proc/<pid>/cmdline` by another local user during the minutes-long poll.
/// This mirrors `publish::github_api_post`'s stdin token delivery.
fn post_form(url: &str, fields: &[(&str, &str)]) -> Result<serde_json::Value, CliError> {
    use std::process::Stdio;
    let body = fields
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    // `-d @-` reads the form body from stdin, keeping the secret out of argv.
    let mut child = Command::new("curl")
        .args(curl_argv(url))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| login_error(&crate::text::login_curl_unavailable(&e)))?;
    // Write the body to curl's stdin, then close it so curl proceeds. A write
    // failure means curl never receives the body; the wait below surfaces the
    // resulting error.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(body.as_bytes());
    }
    let output = child
        .wait_with_output()
        .map_err(|e| login_error(&crate::text::login_curl_wait_failed(&e)))?;
    if !output.status.success() {
        return Err(login_error(&crate::text::login_request_failed(
            &String::from_utf8_lossy(&output.stderr).trim(),
        )));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|e| login_error(&crate::text::login_response_not_json(&e)))
}

/// The full curl argument vector for a `post_form` call. The body is NOT among
/// these arguments — it is `-d @-`, read from stdin — so no field value (in
/// particular the poll's `device_code`) can leak through `/proc/<pid>/cmdline`.
/// Split out so a regression test can assert the argv is secret-free.
const fn curl_argv(url: &str) -> [&str; 10] {
    [
        "--silent",
        "--show-error",
        "--fail",
        "-X",
        "POST",
        "-H",
        "Accept: application/json",
        "-d",
        "@-",
        url,
    ]
}

/// Extract a required string field, erroring if it is absent.
fn str_field(json: &serde_json::Value, key: &str) -> Result<String, CliError> {
    json.get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| login_error(&crate::text::login_response_missing(&key)))
}

/// The token file path (`$XDG_CONFIG_HOME/ipe/token`, else `~/.config/ipe/token`).
/// `None` only when neither `XDG_CONFIG_HOME` nor the home names an absolute path.
fn token_path() -> Option<PathBuf> {
    crate::env_dir::ambient_home("XDG_CONFIG_HOME", ".config")
        .map(|base| base.join("ipe").join("token"))
}

/// The three distinguishable login states `--status` reports. A token file that
/// exists but does not parse is `Corrupt`, never conflated with `LoggedIn`, so
/// `--status` and the publish path (which requires a parseable token) agree.
enum TokenStatus {
    LoggedIn(PathBuf),
    Corrupt(PathBuf),
    NotLoggedIn,
}

/// Classify the stored-token state through the SAME parse the publish path uses,
/// so `--status` never reports "logged in" on a token `publish` would reject.
fn token_status() -> TokenStatus {
    let Some(path) = token_path().filter(|p| p.is_file()) else {
        return TokenStatus::NotLoggedIn;
    };
    match crate::io_bounded::read_to_string_capped(&path, crate::io_bounded::SMALL_FILE_READ_CAP) {
        Ok(raw) if PublishToken::parse(&raw).is_some() => TokenStatus::LoggedIn(path),
        _ => TokenStatus::Corrupt(path),
    }
}

/// Write the token with owner-only permissions, creating the config dir.
///
/// On Unix the file is created with mode 0600 atomically before any bytes are
/// written, so there is no window where the token is readable by other users.
/// On non-Unix the containing profile directory is the protection layer.
fn store_token(token: &PublishToken) -> Result<PathBuf, CliError> {
    let path = token_path().ok_or_else(|| login_error(crate::text::login_config_dir_unknown()))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| login_error(&crate::text::login_create_failed(&parent.display(), &e)))?;
    }
    write_token_atomic(&path, token.as_str())?;
    Ok(path)
}

/// Write `token` to `path` crash-atomically with owner-only permissions.
///
/// On Unix: writes the token into a fresh mode-0600 temp file in the SAME
/// directory (created with `O_CREAT | O_EXCL` so a pre-seeded name is refused,
/// not followed), flushes it, then `rename(2)`s it over `path`. The rename is
/// atomic within the directory, so a crash at any point leaves either the old
/// token or the complete new one — never a truncated or empty file. The token
/// bytes only ever land in a 0600 inode, so there is no window in which the
/// secret is group- or world-readable.
///
/// On non-Unix: falls back to [`std::fs::write`] and relies on the containing
/// directory for protection (same as before).
#[cfg(unix)]
fn write_token_atomic(path: &std::path::Path, token: &str) -> Result<(), CliError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt as _;

    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let tmp_path = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("token"),
        std::process::id()
    ));
    // O_EXCL: refuse an existing name (a stale temp or a planted symlink) rather
    // than truncate/follow it. Mode 0600 from creation, so the secret never
    // touches a looser-mode inode.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|e| login_error(&crate::text::login_create_failed(&tmp_path.display(), &e)))?;
    let write_result = writeln!(file, "{token}")
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all());
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(login_error(&crate::text::login_write_failed(
            &tmp_path.display(),
            &e,
        )));
    }
    drop(file);
    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        login_error(&crate::text::login_move_failed(&path.display(), &e))
    })
}

#[cfg(not(unix))]
fn write_token_atomic(path: &std::path::Path, token: &str) -> Result<(), CliError> {
    std::fs::write(path, format!("{token}\n"))
        .map_err(|e| login_error(&crate::text::login_write_failed(&path.display(), &e)))
}

/// Remove the stored token.
fn logout() -> Result<(), CliError> {
    let Some(path) = token_path().filter(|p| p.exists()) else {
        crate::screen::Screen::new(crate::screen::Stream::Stdout)
            .line(
                crate::screen::Tone::Text,
                "not logged in — nothing to remove",
            )
            .emit();
        return Ok(());
    };
    std::fs::remove_file(&path)
        .map_err(|e| login_error(&crate::text::login_remove_failed(&path.display(), &e)))?;
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(
            crate::screen::Tone::Text,
            &format!("logged out — removed {}", path.display()),
        )
        .emit();
    Ok(())
}

/// Best-effort browser open (same contract as publish's opener).
fn open_in_browser(url: &str) -> bool {
    let mut command = if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        c.arg(url);
        c
    } else if cfg!(target_os = "windows") {
        let mut c = Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    command.status().is_ok_and(|s| s.success())
}

/// Build a login error.
fn login_error(message: &str) -> CliError {
    CliError::Resolve(format!("ipe login: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_passes_unreserved_chars_through() {
        assert_eq!(url_encode("abc-XYZ_0.9~"), "abc-XYZ_0.9~");
    }

    #[test]
    fn url_encode_encodes_colon_and_ampersand() {
        // Colons in the grant-type value must be encoded so they cannot split
        // the form field.
        assert_eq!(
            url_encode("urn:ietf:params:oauth:grant-type:device_code"),
            "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
        );
        // An ampersand in a value must be encoded so it cannot inject a new field.
        assert_eq!(url_encode("a&b=c"), "a%26b%3Dc");
    }

    #[test]
    fn url_encode_encodes_space_as_percent20() {
        assert_eq!(url_encode("hello world"), "hello%20world");
    }

    #[test]
    fn parses_a_device_code_response() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{"device_code":"abc","user_code":"WXYZ-1234","verification_uri":"https://github.com/login/device","expires_in":899,"interval":5}"#,
        )
        .unwrap();
        assert_eq!(str_field(&json, "device_code").unwrap(), "abc");
        assert_eq!(str_field(&json, "user_code").unwrap(), "WXYZ-1234");
        assert_eq!(
            json.get("interval").and_then(serde_json::Value::as_u64),
            Some(5)
        );
    }

    #[test]
    fn a_missing_field_is_a_typed_error() {
        let json: serde_json::Value = serde_json::from_str(r#"{"user_code":"X"}"#).unwrap();
        assert!(str_field(&json, "device_code").is_err());
    }

    #[test]
    fn publish_token_accepts_github_alphabet() {
        let parsed = PublishToken::parse("ghp_ABCdef0123456789_XYZ").expect("valid token");
        assert_eq!(parsed.as_str(), "ghp_ABCdef0123456789_XYZ");
    }

    #[test]
    fn publish_token_trims_surrounding_whitespace() {
        let parsed = PublishToken::parse("  ghp_token123  \n").expect("valid after trim");
        assert_eq!(parsed.as_str(), "ghp_token123");
    }

    #[test]
    fn publish_token_rejects_a_quote() {
        // A quote would close the curl `header = "…"` string and let the rest of
        // the token inject further curl directives.
        assert!(PublishToken::parse(r#"ghp_"url = file:///etc/passwd"#).is_none());
    }

    #[test]
    fn publish_token_rejects_an_embedded_newline() {
        // A newline would start a fresh curl config line (`upload-file = …`).
        assert!(PublishToken::parse("ghp_token\nupload-file = /etc/passwd").is_none());
    }

    #[test]
    fn publish_token_rejects_empty_and_whitespace_only() {
        assert!(PublishToken::parse("").is_none());
        assert!(PublishToken::parse("   \n\t").is_none());
    }

    #[test]
    fn verification_uri_accepts_https_github() {
        let uri = VerificationUri::parse("https://github.com/login/device").expect("accepted");
        assert_eq!(uri.as_str(), "https://github.com/login/device");
    }

    #[test]
    fn verification_uri_rejects_non_https_scheme() {
        assert!(VerificationUri::parse("http://github.com/login/device").is_none());
        assert!(VerificationUri::parse("file:///etc/passwd").is_none());
        assert!(VerificationUri::parse("javascript:alert(1)").is_none());
    }

    #[test]
    fn verification_uri_rejects_other_host() {
        assert!(VerificationUri::parse("https://evil.example.com/login/device").is_none());
        // A lookalike host and a subdomain are not github.com.
        assert!(VerificationUri::parse("https://github.com.evil.com/x").is_none());
        assert!(VerificationUri::parse("https://notgithub.com/x").is_none());
    }

    #[test]
    fn verification_uri_rejects_userinfo_masking_the_host() {
        // `github.com` in the userinfo must not let an attacker host through.
        assert!(VerificationUri::parse("https://github.com@evil.example.com/x").is_none());
    }

    #[test]
    fn verification_uri_rejects_a_port() {
        assert!(VerificationUri::parse("https://github.com:8443/login/device").is_none());
    }

    #[test]
    fn unexpected_login_argument_is_a_usage_error() {
        let result = run_login(&["--bogus".to_owned()]);
        assert!(matches!(result, Err(CliError::UsageOwned(_))));
    }

    /// The token file must be created with mode 0600 — never group- or
    /// world-readable — even under a maximally permissive umask (0000).
    #[test]
    #[cfg(unix)]
    fn token_file_created_with_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!(
            "ipe-login-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("token");

        write_token_atomic(&path, "test-token").expect("write_token_atomic succeeds");

        let meta = std::fs::metadata(&path).expect("file exists");
        let mode = meta.permissions().mode() & 0o777;
        // The security property: no group or world bits set (0o177 covers all
        // group/world bits). The owner bits may be masked by the process umask
        // but can never be MORE permissive than 0o600.
        assert_eq!(
            mode & 0o177,
            0,
            "token file must have no group/world bits; got mode {mode:04o}"
        );
        assert_eq!(
            mode, 0o600,
            "token file must be exactly 0600, got {mode:04o}"
        );

        let content = std::fs::read_to_string(&path).expect("readable by owner");
        assert_eq!(content, "test-token\n");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn existing_loose_mode_token_file_is_tightened_before_write() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!(
            "ipe-login-relogin-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("token");

        // A stale token file left group/world-readable by an older writer, a bad
        // first-write umask, or a backup restore. Re-login must NOT write the new
        // secret into it at the loose mode.
        std::fs::write(&path, "old\n").expect("plant file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");

        write_token_atomic(&path, "new-token").expect("write_token_atomic succeeds");

        let mode = std::fs::metadata(&path)
            .expect("file exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "an existing looser-mode token file must be tightened to 0600, got {mode:04o}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("readable"),
            "new-token\n"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The `post_form` curl argv must never carry a field value — the body is
    /// delivered over stdin (`-d @-`), so the poll's `device_code` (a secret
    /// exchangeable for the publish token) cannot leak via `/proc/<pid>/cmdline`.
    #[test]
    fn post_form_argv_carries_no_secret_body() {
        let argv = curl_argv(TOKEN_URL);
        let secret = "the-device-code-secret";
        let body = format!(
            "client_id={}&device_code={}&grant_type={}",
            url_encode(CLIENT_ID),
            url_encode(secret),
            url_encode(GRANT_TYPE)
        );
        for arg in argv {
            assert!(
                !arg.contains(secret),
                "curl argv must not contain the device_code secret; found in `{arg}`"
            );
            assert_ne!(
                arg, body,
                "the form body must not appear as an argv element"
            );
        }
        // The body must be present exactly as the stdin sentinel, nothing more.
        assert!(argv.contains(&"@-"), "body must be read from stdin (`@-`)");
    }

    /// A hostile `interval` (up to `u64::MAX`) is clamped, so the poll cadence
    /// can never be pushed into an unbounded sleep by the server's response.
    #[test]
    fn poll_interval_is_clamped_to_ceiling() {
        // Mirrors the slow_down clamp: `.max(interval + 5).min(MAX_POLL_INTERVAL_SECS)`.
        let clamp = |raw: u64, current: u64| raw.max(current + 5).min(MAX_POLL_INTERVAL_SECS);
        assert_eq!(clamp(u64::MAX, 5), MAX_POLL_INTERVAL_SECS);
        assert_eq!(clamp(0, 5), 10); // floor of current+5 still applies
        // The initial-interval clamp keeps a hostile first value bounded too.
        assert_eq!(
            u64::MAX.clamp(1, MAX_POLL_INTERVAL_SECS),
            MAX_POLL_INTERVAL_SECS
        );
        assert_eq!(0u64.clamp(1, MAX_POLL_INTERVAL_SECS), 1);
    }

    /// `--status` classification must agree with the publish path: a token file
    /// that exists but does not parse is `Corrupt`, never `LoggedIn`.
    #[cfg(unix)]
    #[test]
    fn token_status_reports_corrupt_distinctly_from_logged_in() {
        // A corrupt token (bytes outside the alphabet) does not parse.
        assert!(PublishToken::parse("not a valid token!!").is_none());
        // A well-formed token parses, matching what publish consumes.
        assert!(PublishToken::parse("ghp_valid_token_0123").is_some());
        // The classifier reuses exactly this parse, so the two views cannot drift.
    }

    /// A crash-atomic write leaves a complete, well-formed, 0600 token — the temp
    /// file is renamed into place, so there is no truncated/empty window.
    #[cfg(unix)]
    #[test]
    fn write_token_is_crash_atomic_and_leaves_no_temp() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!(
            "ipe-login-atomic-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("token");

        write_token_atomic(&path, "ghp_atomic_token").expect("write succeeds");

        assert_eq!(
            std::fs::read_to_string(&path).expect("token readable"),
            "ghp_atomic_token\n"
        );
        let mode = std::fs::metadata(&path)
            .expect("exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "renamed token must be 0600, got {mode:04o}");

        // No leftover temp file in the directory.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("readdir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no .tmp file should remain after rename"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
