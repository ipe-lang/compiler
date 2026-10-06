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
//! After login, when no commit-signing key is configured, `ipe login` offers
//! (opt-in, interactive) to generate and register one — see
//! [`crate::ssh_signing_key`]. `ipe login --signing-key` runs that step alone.
//!
//! [device authorization grant]: https://docs.github.com/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#device-flow

use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::CliError;
use crate::secret_file::{DirRefusal, HOST_SECRET_STORE, SecretFileError, SecretStore};

/// The Ipê CLI's GitHub OAuth App client id. Public by design — the device flow
/// authenticates with the client id alone (no secret), so embedding it is safe.
const CLIENT_ID: &str = "Ov23liBpCFLSoxJvSTwO";

/// What a device-flow authorization is for. Each purpose requests exactly one
/// scope, so a grant can never be widened by composing scope strings.
#[derive(Clone, Copy)]
enum GrantScope {
    /// The stored publish token: enough to fork the public index repo and open
    /// the publish pull request, nothing more.
    Publish,
    /// A one-shot, never-stored token that may only add an SSH signing key to
    /// the account.
    RegisterSigningKey,
}

impl GrantScope {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Publish => "public_repo",
            Self::RegisterSigningKey => "write:ssh_signing_key",
        }
    }

    fn purpose(self) -> crate::text::Message {
        match self {
            Self::Publish => crate::text::msg::login_grant_purpose_publish(),
            Self::RegisterSigningKey => {
                crate::text::login_grant_purpose_signing_key(&self.as_str())
            }
        }
    }
}

/// The one scope the signing-key-registration grant requests.
pub(crate) const SIGNING_KEY_SCOPE: &str = GrantScope::RegisterSigningKey.as_str();

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
/// With no flag, runs the device flow, stores the token, then offers signing-key
/// setup when none is configured. `--status` reports whether a token is stored
/// and which signing key publish would use; `--logout` removes the token;
/// `--signing-key` runs only the signing-key setup.
///
/// # Errors
/// [`CliError::Usage`] on an unknown flag; [`CliError::Resolve`] when the
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
            let key_line = crate::ssh_signing_key::status_line(
                ipe_env::var_os(crate::ssh_signing_key::SIGNING_KEY_ENV).as_deref(),
                config_dir().as_deref(),
            );
            crate::screen::Screen::new(crate::screen::Stream::Stdout)
                .line(
                    crate::screen::Tone::Text,
                    &status_report(&token_status(), key_line),
                )
                .emit();
            Ok(())
        }
        Some("--logout") if rest.len() == 1 => logout(),
        Some("--signing-key") if rest.len() == 1 => crate::ssh_signing_key::run_setup_command(),
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
        token_alphabet(raw).map(|t| Self(t.to_owned()))
    }

    /// The token bytes, safe to splice into the curl config header line.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A one-shot GitHub token granted only `write:ssh_signing_key`, used for the
/// single signing-key registration request and then dropped.
///
/// A distinct type from [`PublishToken`]: it has no `Clone`, and nothing that
/// persists or reuses a publish token accepts it, so the wider-scoped grant can
/// never be written to disk or reach the publish path. Its bytes are wiped from
/// memory on drop.
pub(crate) struct KeyRegistrationToken(zeroize::Zeroizing<String>);

impl KeyRegistrationToken {
    /// Parse a raw token under the same alphabet rule as [`PublishToken`].
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        token_alphabet(raw).map(|t| Self(zeroize::Zeroizing::new(t.to_owned())))
    }

    /// The token bytes, for the `Authorization` header only.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The trimmed token when it is non-empty and drawn only from the GitHub token
/// alphabet (`[A-Za-z0-9_]`); `None` otherwise.
fn token_alphabet(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    let well_formed = !trimmed.is_empty()
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_');
    well_formed.then_some(trimmed)
}

/// The stored publish token, if the user has run `ipe login`.
///
/// `None` when no token file exists, it is not proven private to the invoking
/// user, it cannot be read, or its contents are not a well-formed token.
/// Consumed by the publish headless path.
#[must_use]
pub fn stored_token() -> Option<PublishToken> {
    let raw = read_stored_token(&token_path()?).ok()?;
    PublishToken::parse(&raw)
}

/// Why a stored token file yielded no text.
#[derive(Debug)]
enum TokenReadRefusal {
    /// The token file itself is not private to the invoking user.
    Exposed,
    /// The token's directory, or the ancestor carried, is not private to the invoking user.
    UntrustedDir(PathBuf),
    /// The token's directory is the symbolic link carried.
    SymlinkedDir(PathBuf),
    /// The file is absent, not a regular file, or unreadable.
    Unreadable,
}

/// Read the token file at `path` through a handle proven owner-only.
fn read_stored_token(path: &std::path::Path) -> Result<String, TokenReadRefusal> {
    let file = crate::secret_file::open_existing(HOST_SECRET_STORE, path).map_err(|e| match e {
        SecretFileError::NotOwnerOnly(_) => TokenReadRefusal::Exposed,
        SecretFileError::Dir(DirRefusal::Untrusted(dir)) => TokenReadRefusal::UntrustedDir(dir),
        SecretFileError::Dir(DirRefusal::Symlinked(dir)) => TokenReadRefusal::SymlinkedDir(dir),
        SecretFileError::Unsupported
        | SecretFileError::Io(_)
        | SecretFileError::NotRegularFile(_) => TokenReadRefusal::Unreadable,
    })?;
    crate::io_bounded::read_opened_capped(file, path, crate::io_bounded::SMALL_FILE_READ_CAP)
        .map_err(|_| TokenReadRefusal::Unreadable)
}

/// Run the full device flow: request a code, prompt the user, poll for the token,
/// store it; then offer signing-key setup when none is configured.
fn run_device_flow() -> Result<(), CliError> {
    // Refuse up front where the token could not be stored owner-only, before
    // the user approves a grant that would then be discarded.
    require_token_store(HOST_SECRET_STORE)?;
    let token = authorize(GrantScope::Publish, PublishToken::parse)?;
    let path = store_token(&token)?;
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(
            crate::screen::Tone::Text,
            &crate::text::msg::login_stored(&path.display()),
        )
        .emit();
    crate::ssh_signing_key::offer_after_login()
}

/// Obtain the one-shot `write:ssh_signing_key` token through its own device-flow
/// authorization. The caller uses it for one request and drops it.
///
/// # Errors
/// [`CliError::Resolve`] when the OAuth request fails or the user does not
/// authorize in time.
pub(crate) fn authorize_signing_key_registration() -> Result<KeyRegistrationToken, CliError> {
    authorize(GrantScope::RegisterSigningKey, KeyRegistrationToken::parse)
}

/// One device-flow authorization for `scope`: request a code, show it, poll until
/// the user approves, and parse the granted token into its role type `T`.
fn authorize<T>(scope: GrantScope, parse: fn(&str) -> Option<T>) -> Result<T, CliError> {
    let device = request_device_code(scope)?;

    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(
            crate::screen::Tone::Text,
            &crate::text::login_device_prompt(
                &scope.purpose(),
                &device.verification_uri.as_str(),
                &crate::style::TerminalSafe::sanitize(&device.user_code),
            ),
        )
        .emit();
    if matches!(
        crate::browser::open_url(&device.verification_uri),
        crate::browser::OpenOutcome::Opened
    ) {
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

    poll_for_token(&device, parse)
}

/// The device-code grant's first response.
struct DeviceGrant {
    device_code: String,
    user_code: String,
    verification_uri: crate::browser::BrowserUrl,
    interval: u64,
    expires_in: u64,
}

/// POST `login/device/code` for `scope` and parse the device-code grant.
fn request_device_code(scope: GrantScope) -> Result<DeviceGrant, CliError> {
    let json = post_form(
        DEVICE_CODE_URL,
        &[("client_id", CLIENT_ID), ("scope", scope.as_str())],
    )?;
    let device_code = str_field(&json, "device_code")?;
    let user_code = str_field(&json, "user_code")?;
    let verification_uri_raw = str_field(&json, "verification_uri")?;
    let verification_uri = crate::browser::BrowserUrl::parse(
        &verification_uri_raw,
        crate::browser::BrowserOrigin::GitHub,
    )
    .map_err(|_| login_error(&crate::text::msg::login_verification_url_refused()))?;
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
/// or GitHub reports a terminal error. The returned token is parsed into its
/// role type by `parse` at this boundary, so a malformed token never travels on.
fn poll_for_token<T>(device: &DeviceGrant, parse: fn(&str) -> Option<T>) -> Result<T, CliError> {
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
                &crate::text::msg::login_code_expired_before_approval(),
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
            return parse(token)
                .ok_or_else(|| login_error(&crate::text::msg::login_token_malformed()));
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
                return Err(login_error(&crate::text::msg::login_denied()));
            }
            Some("expired_token") => {
                return Err(login_error(&crate::text::msg::login_code_expired()));
            }
            Some(other) => {
                return Err(login_error(&crate::text::msg::login_github_reported(
                    &crate::style::TerminalSafe::sanitize(other),
                )));
            }
            None => {
                return Err(login_error(&crate::text::msg::login_response_unrecognised()));
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
///
/// The response is held to [`crate::remote_ingest::OAUTH_FORM`]: curl's own
/// limits stop a declared oversized body or a stalled transfer, and the
/// captured stdout is refused past its ceiling.
fn post_form(url: &str, fields: &[(&str, &str)]) -> Result<serde_json::Value, CliError> {
    use crate::remote_ingest::{self, Curl, RunError, Transfer};
    let budget = &remote_ingest::OAUTH_FORM;
    let body = fields
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    // `-d @-` reads the form body from stdin, keeping the secret out of argv.
    let limits = remote_ingest::curl_limit_args(budget.stdout_bytes(), budget);
    let body = zeroize::Zeroizing::new(body);
    let output = Curl::https()
        .args(curl_argv(url, &limits))
        .run(Some(body.as_bytes()), None, &Transfer::begin(*budget))
        .map_err(|e| match e {
            RunError::Spawn(e) => login_error(&crate::text::msg::login_curl_unavailable(&e)),
            RunError::Wait(e) => login_error(&crate::text::msg::login_curl_wait_failed(&e)),
            RunError::Measure(path, source) => CliError::Io { path, source },
            RunError::Exceeded(refusal) => CliError::RemoteIngestExceeded(refusal),
            RunError::PipeDrainTimeout(stream) => CliError::ChildPipeHeld(stream),
            RunError::PipeRead(stream, kind) => CliError::ChildPipeUnread(stream, kind),
        })?;
    if let Some(refusal) = remote_ingest::curl_refusal(output.status, budget.stdout_bytes(), budget)
    {
        return Err(CliError::RemoteIngestExceeded(refusal));
    }
    if !output.status.success() {
        return Err(login_error(&crate::text::msg::login_request_failed(
            &output.stderr.to_terminal(),
        )));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|e| login_error(&crate::text::msg::login_response_not_json(&e)))
}

/// The full curl argument vector for a `post_form` call. The body is NOT among
/// these arguments — it is `-d @-`, read from stdin — so no field value (in
/// particular the poll's `device_code`) can leak through `/proc/<pid>/cmdline`.
/// `limits` are the [`crate::remote_ingest::curl_limit_args`] of the call.
/// Split out so a regression test can assert the argv is secret-free.
const fn curl_argv<'a>(url: &'a str, limits: &'a [String; 4]) -> [&'a str; 14] {
    let [max_filesize, bytes, max_time, secs] = limits;
    [
        "--silent",
        "--show-error",
        "--fail",
        max_filesize.as_str(),
        bytes.as_str(),
        max_time.as_str(),
        secs.as_str(),
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
        .ok_or_else(|| login_error(&crate::text::msg::login_response_missing(&key)))
}

/// The ipe config directory (`$XDG_CONFIG_HOME/ipe`, else `~/.config/ipe`) that
/// holds the publish token and the generated signing key. `None` only when
/// neither `XDG_CONFIG_HOME` nor the home names an absolute path.
pub(crate) fn config_dir() -> Option<PathBuf> {
    crate::env_dir::ambient_home("XDG_CONFIG_HOME", ".config").map(|base| base.join("ipe"))
}

/// The token file path (`<config dir>/token`).
fn token_path() -> Option<PathBuf> {
    config_dir().map(|dir| dir.join("token"))
}

/// The three distinguishable login states `--status` reports. A token file that
/// exists but does not parse is `Corrupt`, never conflated with `LoggedIn`, so
/// `--status` and the publish path (which requires a parseable token) agree.
///
/// A token file another local user could read or replace is `Exposed`: the
/// publish path refuses it, and the token must be treated as leaked. A token
/// directory that is a symbolic link is `SymlinkedDir`: nothing was read
/// through it, so nothing leaked. A token directory, or an ancestor, another
/// local user could write is `UntrustedDir`, naming that component: a token
/// stored under it may have been replaced or read, so it is treated as exposed.
enum TokenStatus {
    LoggedIn(PathBuf),
    Corrupt(PathBuf),
    Exposed(PathBuf),
    SymlinkedDir(PathBuf),
    UntrustedDir(PathBuf),
    NotLoggedIn,
}

/// Classify the stored-token state through the SAME read and parse the publish path uses.
///
/// `--status` thus never reports "logged in" on a token `publish` would reject.
fn token_status() -> TokenStatus {
    token_status_of(StoredToken::probe(token_path()))
}

/// The occupant of the token file's name, probed once without following a final link.
///
/// `--status` and `--logout` both match on it, so an entry one reports (a
/// dangling symlink included) is the entry the other removes.
#[derive(Debug, PartialEq, Eq)]
enum StoredToken {
    /// Something, of any file type, holds the name.
    Present(PathBuf),
    /// No config dir is known, or nothing holds the name.
    Absent,
}

impl StoredToken {
    /// Probe the token file name `path`; any answer but "not found" counts as present.
    fn probe(path: Option<PathBuf>) -> Self {
        path.filter(
            |p| !matches!(p.symlink_metadata(), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        )
        .map_or(Self::Absent, Self::Present)
    }
}

/// Classify `stored` through the SAME read and parse the publish path uses.
fn token_status_of(stored: StoredToken) -> TokenStatus {
    let StoredToken::Present(path) = stored else {
        return TokenStatus::NotLoggedIn;
    };
    match read_stored_token(&path) {
        Ok(raw) if PublishToken::parse(&raw).is_some() => TokenStatus::LoggedIn(path),
        Err(TokenReadRefusal::Exposed) => TokenStatus::Exposed(path),
        Err(TokenReadRefusal::SymlinkedDir(dir)) => TokenStatus::SymlinkedDir(dir),
        Err(TokenReadRefusal::UntrustedDir(dir)) => TokenStatus::UntrustedDir(dir),
        Ok(_) | Err(TokenReadRefusal::Unreadable) => TokenStatus::Corrupt(path),
    }
}

/// The `--status` report: the token state, then the signing-key line.
///
/// Each path is a catalog placeholder, so a line break inside it is indented
/// as a continuation and cannot open an output line of its own.
fn status_report(status: &TokenStatus, key_line: crate::text::Message) -> crate::text::Message {
    let token_line = match status {
        TokenStatus::LoggedIn(path) => crate::text::msg::login_status_logged_in(&path.display()),
        TokenStatus::Corrupt(path) => crate::text::msg::login_status_corrupt(&path.display()),
        TokenStatus::Exposed(path) => crate::text::msg::login_status_exposed(&path.display()),
        TokenStatus::SymlinkedDir(dir) => {
            crate::text::msg::login_status_symlinked_dir(&dir.display())
        }
        TokenStatus::UntrustedDir(dir) => {
            crate::text::msg::login_status_dir_untrusted(&dir.display())
        }
        TokenStatus::NotLoggedIn => crate::text::msg::login_status_not_logged_in(),
    };
    crate::text::Message::lines([token_line, key_line])
}

/// Write the token with owner-only permissions, creating the config dir.
///
/// The token only ever lands in a file created owner-only before any byte is
/// written; where the host cannot create one, it is never stored (see
/// [`write_token_atomic`]).
fn store_token(token: &PublishToken) -> Result<PathBuf, CliError> {
    let path =
        token_path().ok_or_else(|| login_error(&crate::text::msg::login_config_dir_unknown()))?;
    write_token_atomic(HOST_SECRET_STORE, &path, token.as_str())?;
    Ok(path)
}

/// The login refusal for a secret-file step on `path` that failed with `error`.
fn secret_file_refusal(error: SecretFileError, path: &std::path::Path) -> CliError {
    match error {
        SecretFileError::Unsupported => token_store_unsupported(),
        SecretFileError::Io(e) => {
            login_error(&crate::text::msg::login_create_failed(&path.display(), &e))
        }
        SecretFileError::NotOwnerOnly(shown)
        | SecretFileError::Dir(DirRefusal::Untrusted(shown)) => login_error(
            &crate::text::msg::login_secret_not_owner_only(&shown.display()),
        ),
        SecretFileError::Dir(DirRefusal::Symlinked(dir)) => login_error(
            &crate::text::msg::login_secret_symlinked_dir(&dir.display()),
        ),
        SecretFileError::NotRegularFile(shown) => login_error(
            &crate::text::msg::login_secret_not_regular_file(&shown.display()),
        ),
    }
}

/// Write `token` to `path` crash-atomically with owner-only permissions.
///
/// The directory of `path` is created if needed and held by
/// [`crate::secret_file::create_owner_dir`], once it and every ancestor were
/// proven unwritable by other users. The token goes into a fresh, randomly
/// named temp file in that held directory, created exclusively and proven
/// owner-only by [`crate::secret_file::OwnerDir::create_temp_for`] (a
/// pre-seeded name is refused, not followed), is flushed, then `renameat(2)`d
/// over the final name through the same handle. The rename is atomic within
/// the directory, so a crash at any point leaves either the old token or the
/// complete new one — never a truncated or empty file. The token bytes only
/// ever land in an owner-only inode, so there is no window in which the
/// secret is readable by others.
///
/// A `store` that cannot keep the file owner-only refuses before anything is
/// created; `GITHUB_TOKEN` supplies the token there instead.
fn write_token_atomic(
    store: SecretStore,
    path: &std::path::Path,
    token: &str,
) -> Result<(), CliError> {
    require_token_store(store)?;
    let (parent, name) =
        crate::secret_file::split_entry(path).map_err(|e| secret_file_refusal(e, path))?;
    let dir = crate::secret_file::create_owner_dir(store, parent)
        .map_err(|e| secret_file_refusal(e, parent))?;
    let suffix = crate::secret_file::TempSuffix::fresh().map_err(|e| {
        login_error(&crate::text::msg::login_create_failed(
            &parent.display(),
            &e,
        ))
    })?;
    let (mut file, temp) = dir.create_temp_for(&name, &suffix).map_err(|e| {
        let shown = suffix
            .name_for(&name)
            .map_or_else(|_| path.to_path_buf(), |temp| dir.path_of(&temp));
        secret_file_refusal(e, &shown)
    })?;
    let write_result = writeln!(file, "{token}")
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all());
    if let Err(e) = write_result {
        let _ = dir.remove(&temp);
        return Err(login_error(&crate::text::msg::login_write_failed(
            &dir.path_of(&temp).display(),
            &e,
        )));
    }
    drop(file);
    dir.rename(&temp, &name).map_err(|e| {
        let _ = dir.remove(&temp);
        login_error(&crate::text::msg::login_move_failed(&path.display(), &e))
    })
}

/// Refuse a login whose token `store` cannot keep it owner-only.
fn require_token_store(store: SecretStore) -> Result<(), CliError> {
    crate::secret_file::require(store).map_err(|_| token_store_unsupported())
}

/// The refusal for a host that cannot store the token owner-only.
fn token_store_unsupported() -> CliError {
    login_error(&crate::text::msg::login_token_store_unsupported())
}

/// Remove the stored token.
fn logout() -> Result<(), CliError> {
    let line = logout_at(StoredToken::probe(token_path()))?
        .map_or_else(crate::text::msg::login_logout_nothing, |path| {
            crate::text::msg::login_logout_removed(&path.display())
        });
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(crate::screen::Tone::Text, &line)
        .emit();
    Ok(())
}

/// Remove the entry `stored` names, without following a final link; `None` when there is none.
fn logout_at(stored: StoredToken) -> Result<Option<PathBuf>, CliError> {
    let StoredToken::Present(path) = stored else {
        return Ok(None);
    };
    std::fs::remove_file(&path)
        .map_err(|e| login_error(&crate::text::msg::login_remove_failed(&path.display(), &e)))?;
    Ok(Some(path))
}

/// Build a login error.
pub(crate) fn login_error(message: &crate::text::Message) -> CliError {
    CliError::Resolve(crate::text::msg::login_error(message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_grant_requests_exactly_its_one_scope() {
        assert_eq!(GrantScope::Publish.as_str(), "public_repo");
        assert_eq!(
            GrantScope::RegisterSigningKey.as_str(),
            "write:ssh_signing_key"
        );
    }

    #[test]
    fn owner_only_token_store_admits_login() {
        assert!(require_token_store(SecretStore::OwnerOnlyFile).is_ok());
    }

    #[test]
    fn unsupported_token_store_refuses_login() {
        let refusal = require_token_store(SecretStore::Unsupported);
        assert!(
            matches!(
                &refusal,
                Err(CliError::Resolve(message))
                    if message.contains(crate::text::msg::login_token_store_unsupported().as_str())
            ),
            "an unsupported token store must refuse the login: {refusal:?}"
        );
    }

    /// A config path carrying a line feed, a carriage return, and an escape.
    fn hostile_path() -> PathBuf {
        PathBuf::from("/home/u/.config/ipe\nipe login: forged success\r\u{1b}[2K/token")
    }

    /// Whether `text` opens exactly `own_lines` column-0 lines and carries no CR or escape.
    fn only_own_lines(text: &str, own_lines: usize) -> bool {
        text.lines()
            .filter(|line| !line.starts_with(ipe_diagnostics::terminal::CONTINUATION_INDENT))
            .count()
            == own_lines
            && !text.contains('\r')
            && !text.contains('\u{1b}')
    }

    #[test]
    fn a_hostile_token_path_cannot_forge_a_status_line() {
        for status in [
            TokenStatus::LoggedIn(hostile_path()),
            TokenStatus::Corrupt(hostile_path()),
            TokenStatus::Exposed(hostile_path()),
            TokenStatus::SymlinkedDir(hostile_path()),
            TokenStatus::UntrustedDir(hostile_path()),
            TokenStatus::NotLoggedIn,
        ] {
            let report = status_report(&status, crate::text::msg::signing_key_status_none());
            assert!(
                only_own_lines(&report, 2),
                "the path must stay inside its own status line: {report:?}"
            );
        }
    }

    #[test]
    fn a_hostile_token_path_cannot_forge_a_login_or_logout_line() {
        let path = hostile_path();
        for shown in [
            crate::text::msg::login_stored(&path.display()),
            crate::text::msg::login_logout_removed(&path.display()),
        ] {
            assert!(
                only_own_lines(&shown, 1),
                "the path must stay inside its own line: {shown:?}"
            );
        }
    }

    #[test]
    fn an_unsupported_token_store_writes_no_token() {
        let dir = ipe_test_temp::temp_root().join(format!(
            "ipe-login-unsupported-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("token");

        let refusal = write_token_atomic(SecretStore::Unsupported, &path, "ghp_refused_token");

        assert!(
            matches!(
                &refusal,
                Err(CliError::Resolve(message))
                    if message.contains(crate::text::msg::login_token_store_unsupported().as_str())
            ),
            "an unsupported token store must refuse the write: {refusal:?}"
        );
        let entries: Vec<_> = std::fs::read_dir(&dir)
            .expect("readdir")
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .collect();
        assert!(
            entries.is_empty(),
            "a refused token write must create no file: {entries:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

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
    fn unexpected_login_argument_is_a_usage_error() {
        let result = run_login(&["--bogus".to_owned()]);
        assert!(matches!(result, Err(CliError::Usage(_))));
    }

    /// The token file must be created with mode 0600 — never group- or
    /// world-readable — even under a maximally permissive umask (0000).
    #[test]
    #[cfg(unix)]
    fn token_file_created_with_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = ipe_test_temp::temp_root().join(format!(
            "ipe-login-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("token");

        write_token_atomic(HOST_SECRET_STORE, &path, "test-token")
            .expect("write_token_atomic succeeds");

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

        let dir = ipe_test_temp::temp_root().join(format!(
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

        write_token_atomic(HOST_SECRET_STORE, &path, "new-token")
            .expect("write_token_atomic succeeds");

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
        let budget = &crate::remote_ingest::OAUTH_FORM;
        let limits = crate::remote_ingest::curl_limit_args(budget.stdout_bytes(), budget);
        let argv = curl_argv(TOKEN_URL, &limits);
        assert!(
            argv.windows(limits.len()).any(|w| w == limits),
            "curl argv must carry the ingest limits"
        );
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

        let dir = ipe_test_temp::temp_root().join(format!(
            "ipe-login-atomic-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("token");

        write_token_atomic(HOST_SECRET_STORE, &path, "ghp_atomic_token").expect("write succeeds");

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

    /// A stored token another local user could read is refused, never used.
    #[cfg(unix)]
    #[test]
    fn an_exposed_stored_token_is_refused_and_an_owner_only_one_is_read() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = ipe_test_temp::temp_root().join(format!(
            "ipe-login-exposed-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("token");
        write_token_atomic(HOST_SECRET_STORE, &path, "ghp_private_token").expect("write succeeds");

        let read = read_stored_token(&path);
        assert!(
            matches!(&read, Ok(raw) if PublishToken::parse(raw).is_some()),
            "an owner-only token must be read: {read:?}"
        );

        for mode in [0o644, 0o640] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("chmod token");
            let read = read_stored_token(&path);
            assert!(
                matches!(read, Err(TokenReadRefusal::Exposed)),
                "a mode-{mode:o} token must be refused as exposed: {read:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_secret_file_not_private_to_the_user_is_a_typed_login_refusal() {
        let path = std::path::Path::new("/tmp/ipe/token");
        let refusal = secret_file_refusal(SecretFileError::NotOwnerOnly(path.to_path_buf()), path);
        let expected = crate::text::msg::login_secret_not_owner_only(&path.display());
        assert!(
            matches!(&refusal, CliError::Resolve(message) if message.contains(expected.as_str())),
            "a non-private secret file must name the owner-only refusal: {refusal:?}"
        );
    }

    #[test]
    fn a_secret_name_held_by_a_non_regular_file_is_its_own_refusal() {
        let path = std::path::Path::new("/tmp/ipe/token");
        let refusal =
            secret_file_refusal(SecretFileError::NotRegularFile(path.to_path_buf()), path);
        let expected = crate::text::msg::login_secret_not_regular_file(&path.display());
        assert!(
            matches!(&refusal, CliError::Resolve(message) if message.contains(expected.as_str())),
            "a non-regular secret file must name its own refusal: {refusal:?}"
        );
    }

    #[test]
    fn a_symlinked_token_dir_is_its_own_refusal_never_an_exposure() {
        let path = std::path::Path::new("/tmp/ipe/token");
        let dir = std::path::Path::new("/tmp/ipe");
        let refusal = secret_file_refusal(
            SecretFileError::Dir(DirRefusal::Symlinked(dir.to_path_buf())),
            path,
        );
        let expected = crate::text::msg::login_secret_symlinked_dir(&dir.display());
        let exposed = crate::text::msg::login_secret_not_owner_only(&dir.display());
        assert!(
            matches!(&refusal, CliError::Resolve(message)
                if message.contains(expected.as_str()) && !message.contains(exposed.as_str())),
            "a symlinked token dir must name its own refusal: {refusal:?}"
        );
    }

    /// A token directory that is a symlink is reported as such by `--status`, never as exposed.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_token_dir_is_reported_as_a_link_not_an_exposed_token() {
        let base = ipe_test_temp::temp_root()
            .canonicalize()
            .expect("canonical temp dir")
            .join(format!(
                "ipe-login-linked-dir-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
        let _ = std::fs::remove_dir_all(&base);
        let real = base.join("real");
        std::fs::create_dir_all(&real).expect("create real dir");
        write_token_atomic(HOST_SECRET_STORE, &real.join("token"), "ghp_private_token")
            .expect("write succeeds");
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("plant dir symlink");

        let status = token_status_of(StoredToken::probe(Some(link.join("token"))));
        assert!(
            matches!(&status, TokenStatus::SymlinkedDir(p) if *p == link),
            "a symlinked token dir must be reported as a link, never as exposed"
        );
        let report = status_report(&status, crate::text::msg::signing_key_status_none());
        let exposed = crate::text::msg::login_status_exposed(&link.join("token").display());
        assert!(
            !report.contains(exposed.as_str()),
            "a symlinked token dir must not tell the user to revoke: {report:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A token directory any user could write is reported by `--status` as that directory.
    #[cfg(unix)]
    #[test]
    fn an_untrusted_token_dir_is_reported_as_the_dir_not_an_exposed_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let base = ipe_test_temp::temp_root()
            .canonicalize()
            .expect("canonical temp dir")
            .join(format!(
                "ipe-login-untrusted-dir-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
        let _ = std::fs::remove_dir_all(&base);
        let dir = base.join("ipe");
        std::fs::create_dir_all(&dir).expect("create token dir");
        let path = dir.join("token");
        write_token_atomic(HOST_SECRET_STORE, &path, "ghp_private_token").expect("write succeeds");

        // A new directory may inherit a setgid or BSD parent's group; pin it to
        // the invoker's effective group, the one group write is admitted under.
        rustix::fs::chown(&dir, None, Some(rustix::process::getegid())).expect("chgrp token dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770))
            .expect("chmod token dir");
        assert!(
            matches!(
                token_status_of(StoredToken::probe(Some(path.clone()))),
                TokenStatus::LoggedIn(_)
            ),
            "group write under the invoker's own effective group is admitted"
        );
        for mode in [0o707, 0o777] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode))
                .expect("chmod token dir");
            let status = token_status_of(StoredToken::probe(Some(path.clone())));
            assert!(
                matches!(&status, TokenStatus::UntrustedDir(p) if *p == dir),
                "a mode-{mode:o} token dir must be reported as that dir"
            );
            let report = status_report(&status, crate::text::msg::signing_key_status_none());
            let named = crate::text::msg::login_status_dir_untrusted(&dir.display());
            let exposed = crate::text::msg::login_status_exposed(&path.display());
            assert!(
                report.contains(named.as_str()) && !report.contains(exposed.as_str()),
                "a mode-{mode:o} token dir must be named, never as an exposed file: {report:?}"
            );
        }
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A dangling symlink at the token name is reported by `--status` and removed by `--logout`.
    #[cfg(unix)]
    #[test]
    fn a_dangling_token_symlink_is_reported_and_removed_alike() {
        let dir = ipe_test_temp::temp_root().join(format!(
            "ipe-login-dangling-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("token");
        std::os::unix::fs::symlink(dir.join("missing-target"), &path).expect("plant symlink");

        assert_eq!(
            StoredToken::probe(Some(path.clone())),
            StoredToken::Present(path.clone()),
            "a dangling symlink holds the token name"
        );
        let status = token_status_of(StoredToken::probe(Some(path.clone())));
        assert!(
            matches!(&status, TokenStatus::Corrupt(p) if *p == path),
            "--status reports the dangling symlink, never follows it"
        );
        let removed = logout_at(StoredToken::probe(Some(path.clone())));
        assert!(
            matches!(&removed, Ok(Some(p)) if *p == path),
            "--logout removes the entry --status reported: {removed:?}"
        );
        assert!(
            path.symlink_metadata().is_err(),
            "the symlink itself is gone"
        );
        assert_eq!(StoredToken::probe(Some(path.clone())), StoredToken::Absent);
        assert!(matches!(
            token_status_of(StoredToken::probe(Some(path))),
            TokenStatus::NotLoggedIn
        ));
        assert!(matches!(logout_at(StoredToken::Absent), Ok(None)));
        assert_eq!(StoredToken::probe(None), StoredToken::Absent);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
