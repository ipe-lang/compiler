#![cfg(unix)]
//! The live-registry smoke's probe programs and typed inputs, proved offline.
//!
//! `tools/scripts/registry/publish-smoke.sh` publishes only tracked fixtures
//! (`tests/fixtures/registry-smoke/`), rendered by `lib/smoke-inputs.sh` from
//! operator values that lib parses once. These tests build every probe in
//! process, drive each parser and template refusal (exit 2, the cause named,
//! nothing on stdout), and run the askpass helper with a shell-shaped user name
//! to show its text stays fixed. Each bash child runs with a cleared environment
//! and a 30 s deadline that kills it.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use ipe::package_name::PackageName;
use ipe::published_version::PublishedVersion;

type TestResult = Result<(), Box<dyn Error>>;

/// The deadline after which a spawned child is killed and the test fails.
const DEADLINE: Duration = Duration::from_secs(30);

/// A shaped probe version every acceptance and single-fault fixture uses.
const GOOD_VERSION: &str = "0.0.0-smoke.20261002120000.1.1";

/// The probes the smoke publishes: the clean one and both halves of the spoof.
const PROBES: &[&str] = &["good", "bad-registered", "bad-working"];

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixtures() -> PathBuf {
    repo_root()
        .join("tests")
        .join("fixtures")
        .join("registry-smoke")
}

fn lib_path() -> PathBuf {
    repo_root()
        .join("tools")
        .join("scripts")
        .join("registry")
        .join("lib")
        .join("smoke-inputs.sh")
}

fn template_path() -> PathBuf {
    fixtures().join("package.ipe.tmpl")
}

/// A fresh scratch directory unique to `tag` and this process.
fn scratch(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("registry_smoke_{tag}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Run `command` to completion under [`DEADLINE`], killing it on expiry.
fn run_with_deadline(command: &mut Command) -> Result<Output, Box<dyn Error>> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let start = Instant::now();
    while child.try_wait()?.is_none() {
        if start.elapsed() > DEADLINE {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("child exceeded the {DEADLINE:?} deadline and was killed").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(child.wait_with_output()?)
}

/// Source the lib in a clean bash and run `script` with `args` as `$1`, `$2`, ….
///
/// Values travel as positional arguments, never spliced into `script`.
fn lib(script: &str, args: &[&str]) -> Result<Output, Box<dyn Error>> {
    lib_with_env(script, args, &[])
}

/// [`lib`] with `extra` environment pairs set on the bash child.
fn lib_with_env(
    script: &str,
    args: &[&str],
    extra: &[(&str, &str)],
) -> Result<Output, Box<dyn Error>> {
    let mut command = Command::new("bash");
    command
        .env_clear()
        .env("PATH", ipe_env::var_os("PATH").unwrap_or_default())
        .envs(extra.iter().copied())
        .env("SMOKE_LIB", lib_path())
        .arg("-c")
        .arg(format!(". \"$SMOKE_LIB\"\n{script}"))
        .arg("bash")
        .args(args);
    run_with_deadline(&mut command)
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Assert a refusal: exit 2, `cause` named on stderr, nothing on stdout.
fn assert_refused(out: &Output, cause: &str, what: &str) {
    assert_eq!(
        out.status.code(),
        Some(2),
        "{what}: expected exit 2, stderr: {}",
        stderr_of(out)
    );
    assert!(
        stderr_of(out).contains(cause),
        "{what}: stderr must name `{cause}`, got: {}",
        stderr_of(out)
    );
    assert!(
        out.stdout.is_empty(),
        "{what}: a refusal prints nothing on stdout, got: {}",
        stdout_of(out)
    );
}

/// Render `template` with `name` and `version` through the lib.
fn render(template: &Path, name: &str, version: &str) -> Result<Output, Box<dyn Error>> {
    let template = template.to_string_lossy();
    lib(
        "render_probe_manifest \"$1\" \"$2\" \"$3\"",
        &[&template, name, version],
    )
}

/// Write a single-fault copy of the real template into `dir`.
fn variant_template(dir: &Path, text: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = dir.join("package.ipe.tmpl");
    fs::write(&path, text)?;
    Ok(path)
}

fn default_names() -> Result<(String, String), Box<dyn Error>> {
    let out = lib(
        "printf '%s\\n%s\\n' \"$PROBE_DEFAULT_NAME\" \"$PROBE_DEFAULT_BAD_NAME\"",
        &[],
    )?;
    assert!(
        out.status.success(),
        "the lib must source cleanly: {}",
        stderr_of(&out)
    );
    let text = stdout_of(&out);
    let mut lines = text.lines();
    let good = lines.next().ok_or("PROBE_DEFAULT_NAME missing")?.to_owned();
    let bad = lines
        .next()
        .ok_or("PROBE_DEFAULT_BAD_NAME missing")?
        .to_owned();
    Ok((good, bad))
}

/// Every probe renders with the reserved names and builds through the pipeline.
#[test]
fn every_probe_renders_and_builds() -> TestResult {
    let (good_name, bad_name) = default_names()?;
    let runtime = e2e_support::require_runtime().into_path_buf();
    for probe in PROBES {
        let name = if *probe == "good" {
            &good_name
        } else {
            &bad_name
        };
        let dir = scratch(&format!("build_{probe}"))?;
        let rendered = render(&template_path(), name, GOOD_VERSION)?;
        assert!(
            rendered.status.success(),
            "{probe}: render must succeed: {}",
            stderr_of(&rendered)
        );
        let manifest = dir.join("package.ipe");
        fs::write(&manifest, &rendered.stdout)?;
        fs::create_dir_all(dir.join("src"))?;
        fs::copy(
            fixtures().join(probe).join("src").join("Main.ipe"),
            dir.join("src").join("Main.ipe"),
        )?;
        let built = ipe::build_project(&manifest, &dir.join("out"), &runtime);
        assert!(built.is_ok(), "{probe}: the probe must build: {built:?}");
        let _ = fs::remove_dir_all(&dir);
    }
    Ok(())
}

/// The lib's reserved defaults pass both the bash grammar and `PackageName`.
#[test]
fn reserved_default_names_parse() -> TestResult {
    let (good, bad) = default_names()?;
    assert_ne!(good, bad, "the two probes must carry distinct names");
    for name in [&good, &bad] {
        assert!(
            PackageName::parse(name).is_ok(),
            "{name} must be a PackageName"
        );
        let out = lib("parse_package_name probe \"$1\"", &[name])?;
        assert!(out.status.success(), "{name}: {}", stderr_of(&out));
        assert_eq!(stdout_of(&out), format!("{name}\n"));
    }
    Ok(())
}

/// The negative leg's spoof needs two different source trees.
#[test]
fn spoof_sources_differ() -> TestResult {
    let registered = fs::read(fixtures().join("bad-registered/src/Main.ipe"))?;
    let working = fs::read(fixtures().join("bad-working/src/Main.ipe"))?;
    assert_ne!(registered, working, "the spoof's two trees must differ");
    Ok(())
}

#[test]
fn render_refuses_injected_name() -> TestResult {
    for name in ["a\"b", "A", "a&b", "a\\b", ""] {
        let out = render(&template_path(), name, GOOD_VERSION)?;
        assert_refused(&out, "probe name", &format!("name {name:?}"));
    }
    Ok(())
}

#[test]
fn render_refuses_off_shape_version() -> TestResult {
    let (name, _) = default_names()?;
    let out = render(&template_path(), &name, "0.0.0-smoke.1")?;
    assert_refused(&out, "probe version", "off-shape version");
    Ok(())
}

#[test]
fn render_refuses_missing_token() -> TestResult {
    let (name, _) = default_names()?;
    let dir = scratch("missing_token")?;
    let text = fs::read_to_string(template_path())?.replace("@version@", GOOD_VERSION);
    let out = render(&variant_template(&dir, &text)?, &name, GOOD_VERSION)?;
    assert_refused(&out, "token @version@ appears 0 times", "missing token");
    Ok(())
}

#[test]
fn render_refuses_duplicate_token() -> TestResult {
    let (name, _) = default_names()?;
    let dir = scratch("duplicate_token")?;
    let text = format!("{}-- @name@\n", fs::read_to_string(template_path())?);
    let out = render(&variant_template(&dir, &text)?, &name, GOOD_VERSION)?;
    assert_refused(&out, "token @name@ appears 2 times", "duplicate token");
    Ok(())
}

#[test]
fn render_refuses_unknown_token() -> TestResult {
    let (name, _) = default_names()?;
    let dir = scratch("unknown_token")?;
    let text = format!("{}-- @other@\n", fs::read_to_string(template_path())?);
    let out = render(&variant_template(&dir, &text)?, &name, GOOD_VERSION)?;
    assert_refused(&out, "unknown @token@", "unknown token");
    Ok(())
}

#[test]
fn parse_refuses_owner_with_shell_meta() -> TestResult {
    let out = lib("parse_gh_owner OWNER_INPUT \"$1\"", &["a\"$(id)\""])?;
    assert_refused(&out, "OWNER_INPUT", "owner with shell meta");
    Ok(())
}

#[test]
fn parse_refuses_repo_dotdot() -> TestResult {
    for slug in ["owner/..", "owner/."] {
        let out = lib("parse_repo_slug SLUG_INPUT \"$1\"", &[slug])?;
        assert_refused(&out, "SLUG_INPUT", slug);
    }
    Ok(())
}

#[test]
fn parse_refuses_http_url() -> TestResult {
    let out = lib(
        "parse_https_url URL_INPUT \"$1\"",
        &["http://example.github.io/registry"],
    )?;
    assert_refused(&out, "URL_INPUT", "plain-http URL");
    Ok(())
}

#[test]
fn parse_refuses_zero_poll() -> TestResult {
    let out = lib("parse_poll_secs POLL_INPUT \"$1\"", &["0"])?;
    assert_refused(&out, "POLL_INPUT", "zero poll budget");
    let out = lib("parse_poll_secs POLL_INPUT \"$1\"", &["1"])?;
    assert!(out.status.success(), "1 s is the smallest legal budget");
    Ok(())
}

/// Build one probe version through the lib from a stamp and a run id + attempt.
fn probe_version(stamp: &str, run: &str, attempt: &str) -> Result<String, Box<dyn Error>> {
    let out = lib(
        "probe_version smoke \"$1\" \"$(parse_run_tag \"$2\" \"$3\")\"",
        &[stamp, run, attempt],
    )?;
    assert!(out.status.success(), "probe_version: {}", stderr_of(&out));
    Ok(stdout_of(&out).trim_end().to_owned())
}

/// Two runs started in the same second get distinct versions.
///
/// A later stamp still exceeds any earlier version whatever the run tag.
#[test]
fn probe_versions_differ_within_one_second() -> TestResult {
    let stamp = "20261002120000";
    let a = probe_version(stamp, "100", "1")?;
    let b = probe_version(stamp, "100", "2")?;
    let c = probe_version(stamp, "101", "1")?;
    assert!(
        a != b && b != c && a != c,
        "same-second runs collided: {a} {b} {c}"
    );
    let parsed: Vec<PublishedVersion> = [&a, &b, &c]
        .into_iter()
        .map(|v| PublishedVersion::parse(v))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("a probe version is not a PublishedVersion: {e:?}"))?;
    assert!(parsed.iter().all(PublishedVersion::is_prerelease));
    let later = PublishedVersion::parse(&probe_version("20261002120001", "1", "0")?)
        .map_err(|e| format!("{e:?}"))?;
    assert!(
        parsed.iter().all(|v| *v < later),
        "a later stamp must exceed every earlier version"
    );
    let earlier_shape =
        PublishedVersion::parse("0.0.0-smoke.20261002115959").map_err(|e| format!("{e:?}"))?;
    assert!(
        parsed.iter().all(|v| earlier_shape < *v),
        "a new version must exceed a stamp-only version from an earlier second"
    );
    Ok(())
}

#[test]
fn parse_refuses_bad_run_tag() -> TestResult {
    for run in ["01", "1a", "1;id", "", "12345678901234567890"] {
        let out = lib("parse_run_tag \"$1\" 1", &[run])?;
        assert_refused(&out, "GITHUB_RUN_ID", &format!("run id {run:?}"));
    }
    for attempt in ["01", "x", "", "100000"] {
        let out = lib("parse_run_tag 1 \"$1\"", &[attempt])?;
        assert_refused(&out, "GITHUB_RUN_ATTEMPT", &format!("attempt {attempt:?}"));
    }
    Ok(())
}

#[test]
fn parse_refuses_version_without_run_tag() -> TestResult {
    for version in [
        "0.0.0-smoke.20261002120000",
        "0.0.0-smoke.20261002120000.1",
        "0.0.0-smoke.20261002120000.01.1",
        "0.0.0-smoke.2026100212000.1.1",
    ] {
        let out = lib("parse_probe_version VERSION_INPUT \"$1\"", &[version])?;
        assert_refused(&out, "VERSION_INPUT", version);
    }
    Ok(())
}

/// The askpass helper's text is fixed: a shell-shaped user name prints raw.
///
/// The owner parser refuses the same value on its own boundary.
#[test]
fn askpass_template_is_static() -> TestResult {
    let dir = scratch("askpass")?;
    let helper = dir.join("askpass.sh");
    let marker = dir.join("ran");
    let hostile = format!("a\"$(touch {})\"", marker.display());
    let helper_arg = helper.to_string_lossy();
    let out = lib("write_askpass \"$1\"", &[&helper_arg])?;
    assert!(out.status.success(), "write_askpass: {}", stderr_of(&out));

    let mut command = Command::new(&helper);
    command
        .env_clear()
        .env("PATH", ipe_env::var_os("PATH").unwrap_or_default())
        .env("IPE_SMOKE_ASKPASS_USER", &hostile)
        .arg("Username for 'https://github.com':");
    let asked = run_with_deadline(&mut command)?;
    assert!(asked.status.success(), "askpass: {}", stderr_of(&asked));
    assert_eq!(stdout_of(&asked), hostile, "the user name must print raw");
    assert!(!marker.exists(), "the user name must never run as code");

    let out = lib("parse_gh_owner FORK_INPUT \"$1\"", &[&hostile])?;
    assert_refused(&out, "FORK_INPUT", "hostile owner");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// The helper's bytes do not depend on the writer's environment, and the token
/// reaches git only on stdout at the password prompt, never the file.
#[test]
fn askpass_text_never_carries_the_token() -> TestResult {
    let dir = scratch("askpass_token")?;
    let token = "ghp_smoke_token_marker_0123456789";
    let plain = dir.join("plain.sh");
    let primed = dir.join("primed.sh");
    let plain_arg = plain.to_string_lossy();
    let primed_arg = primed.to_string_lossy();
    let out = lib("write_askpass \"$1\"", &[&plain_arg])?;
    assert!(out.status.success(), "write_askpass: {}", stderr_of(&out));
    let out = lib_with_env(
        "write_askpass \"$1\"",
        &[&primed_arg],
        &[
            ("IPE_SMOKE_TOKEN", token),
            ("IPE_SMOKE_ASKPASS_USER", "someone"),
        ],
    )?;
    assert!(out.status.success(), "write_askpass: {}", stderr_of(&out));
    let plain_bytes = fs::read(&plain)?;
    assert_eq!(
        plain_bytes,
        fs::read(&primed)?,
        "the helper text must not depend on the environment"
    );
    assert!(
        !String::from_utf8_lossy(&plain_bytes).contains(token),
        "the token must never be written into the helper"
    );
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&primed)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "the helper is owner-only");
    }

    let mut command = Command::new(&primed);
    command
        .env_clear()
        .env("PATH", ipe_env::var_os("PATH").unwrap_or_default())
        .env("IPE_SMOKE_TOKEN", token)
        .arg("Password for 'https://someone@github.com':");
    let asked = run_with_deadline(&mut command)?;
    assert!(asked.status.success(), "askpass: {}", stderr_of(&asked));
    assert_eq!(
        stdout_of(&asked),
        token,
        "the password prompt prints the token"
    );
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// The parsers admit ASCII only, whatever the locale: a non-ASCII letter or
/// digit is refused under `en_US.UTF-8`, where a `[a-z]` range would admit `é`.
#[test]
fn parsers_refuse_non_ascii_under_utf8_locale() -> TestResult {
    let utf8 = [("LC_ALL", "en_US.UTF-8")];
    for name in ["caf\u{e9}", "a\u{ff41}", "a\u{663}"] {
        let out = lib_with_env("parse_package_name NAME_INPUT \"$1\"", &[name], &utf8)?;
        assert_refused(&out, "NAME_INPUT", &format!("name {name:?}"));
    }
    for owner in ["\u{c5}ngstr\u{f6}m", "o\u{663}"] {
        let out = lib_with_env("parse_gh_owner OWNER_INPUT \"$1\"", &[owner], &utf8)?;
        assert_refused(&out, "OWNER_INPUT", &format!("owner {owner:?}"));
    }
    let out = lib_with_env("parse_run_tag \"$1\" 1", &["1\u{663}"], &utf8)?;
    assert_refused(&out, "GITHUB_RUN_ID", "non-ASCII run id");
    let out = lib_with_env("parse_poll_secs POLL_INPUT \"$1\"", &["\u{661}0"], &utf8)?;
    assert_refused(&out, "POLL_INPUT", "non-ASCII poll budget");
    Ok(())
}
