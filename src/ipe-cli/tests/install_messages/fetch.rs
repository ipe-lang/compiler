//! Refusal tests for the installer's prerequisite detection and fetch path.
//!
//! Each whole-script run puts a private stub bin dir ahead of a farm of
//! symlinks to the host's `/usr/bin` and `/bin`, from which the fetchers, the
//! Rust and C toolchains and `uname` are removed. The stubs serve canned
//! release files from a private dir and log every argument line, so each test
//! states which fetcher ran, with which flags, and what it was refused.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::File;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

use ipe_sandbox::scratch::ScratchDir;
use sha2::{Digest as _, Sha256};

use super::{installer_path, installer_script, leaf, marked, mkdir_mode, root, scan_script};

const PREREQ: (&str, &str) = ("# >>> prerequisite commands", "# <<< prerequisite commands");
const FETCH: (&str, &str) = ("# >>> fetch helpers", "# <<< fetch helpers");

/// The host commands no farm holds: every fetcher, the Rust and C
/// toolchains, and `uname`, which a stub answers.
const FARM_DENY: [&str; 10] = [
    "curl", "wget", "fetch", "cargo", "rustc", "rustup", "cc", "gcc", "c99", "uname",
];

/// The SHA-256 tools `sha256_resolve` looks for.
const SHA_TOOLS: [&str; 4] = ["sha256sum", "shasum", "sha256", "openssl"];

/// The size ceiling of the release archive, as `install.sh` spells it.
const ARCHIVE_MAX_BYTES: u64 = 268_435_456;

/// The rustup bootstrap line `install.sh` prints under curl.
const RUSTUP_CURL: &str = "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh";

/// A `uname` that reports `STUB_OS` (default Linux) on x86-64.
const UNAME: &str = r#"#!/bin/sh
case "$1" in -m) echo x86_64 ;; *) echo "${STUB_OS:-Linux}" ;; esac
"#;

/// A curl that logs its arguments and the mode of a `-H @file`, then serves
/// `$SERVE/<url basename>`: `-I` answers the status, `-r` a one-byte range
/// header, `-o` copies the file. A `<name>.size` file extends the copy to that
/// many bytes.
const CURL: &str = r#"#!/bin/sh
if [ "$*" = '-q --version' ]; then echo "curl ${STUB_CURL_VERSION-8.5.0} (x86_64-pc-linux-gnu)"; exit 0; fi
printf 'curl %s\n' "$*" >>"$STUB_LOG"
out=''; head=0; range=0; url=''
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    -H) case "$2" in @*) printf 'header-mode %s\n' "$(ls -l "${2#@}" | cut -c1-10)" >>"$STUB_LOG" ;; esac; shift ;;
    -I) head=1 ;;
    -r) range=1; shift ;;
    -D|--max-time|--max-filesize|--connect-timeout|--proto|--proto-redir) shift ;;
    -*) ;;
    *) url="$1" ;;
  esac
  shift
done
name="${url%%\?*}"; name="${name##*/}"
if [ -n "$out" ] && [ -f "${out%/*}/auth.header" ]; then printf 'token-file-at %s\n' "$name" >>"$STUB_LOG"; fi
src="$SERVE/$name"
[ -f "$src" ] || exit 22
[ "$head" = 1 ] && exit 0
if [ "$range" = 1 ]; then
  printf 'HTTP/1.1 206\r\nContent-Range: bytes 0-0/%s\r\n\r\n' "$(wc -c <"$src" | tr -d ' ')"
  exit 0
fi
cp "$src" "$out" || exit 23
if [ -f "$src.size" ]; then dd if=/dev/null of="$out" bs=1 seek="$(cat "$src.size")" 2>/dev/null; fi
exit 0
"#;

/// A GNU Wget that logs its arguments and the name and mode of its
/// `--config` file, answers `--server-response` lines on stderr and exits 8 on
/// any non-2xx status, as GNU Wget does. A URL holding `STUB_REDIRECT_MATCH`
/// and not starting with `STUB_REDIRECT_TO` answers a 302 to
/// `STUB_REDIRECT_TO/<basename>`.
const WGET: &str = r#"#!/bin/sh
if [ "$1" = --version ]; then echo 'GNU Wget 1.21.2 built on linux-gnu.'; exit 0; fi
printf 'wget %s\n' "$*" >>"$STUB_LOG"
out=''; spider=0; url=''
for a in "$@"; do
  case "$a" in
    --config=*) c="${a#--config=}"; printf 'config-mode %s %s\n' "${c##*/}" "$(ls -l "$c" | cut -c1-10)" >>"$STUB_LOG" ;;
    --spider) spider=1 ;;
    -O) out=next ;;
    -*) ;;
    *) if [ "$out" = next ]; then out="$a"; else url="$a"; fi ;;
  esac
done
if [ -n "${STUB_REDIRECT_MATCH:-}" ]; then
  case "$url" in
    "$STUB_REDIRECT_TO"*) ;;
    *"$STUB_REDIRECT_MATCH"*) printf '  HTTP/1.1 302 Found\n  Location: %s/%s\n' "$STUB_REDIRECT_TO" "${url##*/}" >&2; exit 8 ;;
  esac
fi
name="${url%%\?*}"; name="${name##*/}"
src="$SERVE/$name"
if [ ! -f "$src" ]; then printf '  HTTP/1.1 404 Not Found\n' >&2; exit 8; fi
printf '  HTTP/1.1 200 OK\n' >&2
[ "$spider" = 1 ] && exit 0
cp "$src" "$out" || exit 3
if [ -f "$src.size" ]; then dd if=/dev/null of="$out" bs=1 seek="$(cat "$src.size")" 2>/dev/null; fi
exit 0
"#;

/// A wget that is not GNU Wget, as `BusyBox` ships it: no `--version`.
const OTHER_WGET: &str = "#!/bin/sh\nprintf 'wget %s\\n' \"$*\" >>\"$STUB_LOG\"\nexit 1\n";

/// A `FreeBSD` fetch that logs its arguments and the TLS settings its
/// environment holds, then serves like the curl stub.
const FETCH_STUB: &str = r#"#!/bin/sh
printf 'fetch %s SSL_NO_VERIFY_PEER=%s SSL_ALLOW_SSL3=%s SSL_NO_TLS1=%s SSL_NO_TLS1_1=%s\n' \
  "$*" "${SSL_NO_VERIFY_PEER-unset}" "${SSL_ALLOW_SSL3-unset}" "${SSL_NO_TLS1-unset}" \
  "${SSL_NO_TLS1_1-unset}" >>"$STUB_LOG"
out=''; spider=0; url=''
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    -T) shift ;;
    -s) spider=1 ;;
    -*) ;;
    *) url="$1" ;;
  esac
  shift
done
name="${url##*/}"; src="$SERVE/$name"
[ -f "$src" ] || exit 1
if [ "$spider" = 1 ]; then wc -c <"$src"; exit 0; fi
cp "$src" "$out"
"#;

/// The release files a run serves.
enum Sums {
    /// A `SHA256SUMS` holding the archive's true digest.
    Good,
    /// No `SHA256SUMS` at all.
    Absent,
    /// A `SHA256SUMS` holding this text, `@DIGEST@` replaced by the
    /// archive's true digest.
    Text(&'static str),
}

/// One whole-script run's setup.
struct Host<'a> {
    /// Stub name and script, put ahead of the farm.
    stubs: &'a [(&'a str, &'a str)],
    /// Farm names removed on top of `FARM_DENY`.
    deny: &'a [&'a str],
    /// The release artifact the serve dir holds, if any.
    artifact: Option<&'a str>,
    sums: Sums,
    env: &'a [(&'a str, &'a str)],
    /// The size the served archive grows to once fetched, if not its own.
    archive_size: Option<u64>,
    /// Text fed to a pseudo-terminal the run is attached to, if any.
    tty_input: Option<&'a str>,
    /// Run a plain run under `sh -x`, which traces every command to stderr.
    xtrace: bool,
}

impl Default for Host<'_> {
    fn default() -> Self {
        Host {
            stubs: &[("curl", CURL)],
            deny: &[],
            artifact: Some("ipe-linux-x64.tar.gz"),
            sums: Sums::Good,
            env: &[],
            archive_size: None,
            tty_input: None,
            xtrace: false,
        }
    }
}

/// What one run left behind.
struct FetchRun {
    code: Option<i32>,
    /// Stderr, or the whole terminal transcript of a pseudo-terminal run.
    stderr: String,
    /// Every line the stubs logged.
    log: String,
    /// The install dir, which the run creates only on success.
    install_dir: PathBuf,
}

impl FetchRun {
    fn installed(&self) -> bool {
        self.install_dir.join("ipe").is_file()
    }

    fn lines<'s>(&'s self, prefix: &'s str) -> impl Iterator<Item = &'s str> + 's {
        self.log
            .lines()
            .filter(move |line| line.starts_with(prefix))
    }
}

fn write_exec(path: &Path, body: &str) -> io::Result<()> {
    std::fs::write(path, body)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}

/// A dir of symlinks to every `/usr/bin` and `/bin` entry not in `deny`.
fn farm(dir: &Path, deny: &[&str]) -> io::Result<()> {
    std::fs::create_dir(dir)?;
    for base in ["/usr/bin", "/bin"] {
        for entry in std::fs::read_dir(base)? {
            let entry = entry?;
            let name = entry.file_name();
            if deny.iter().any(|denied| OsStr::new(denied) == name) {
                continue;
            }
            match std::os::unix::fs::symlink(entry.path(), dir.join(&name)) {
                Err(error) if error.kind() != io::ErrorKind::AlreadyExists => return Err(error),
                _ => {}
            }
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// Fill `serve` with the latest-release answer and, for `artifact`, a
/// gzipped tar holding an `ipe` script, plus the `SHA256SUMS` and size
/// marker `host` names.
fn serve(r: &ScratchDir, serve: &Path, host: &Host<'_>) -> io::Result<()> {
    std::fs::create_dir(serve)?;
    std::fs::write(serve.join("latest"), "{\"tag_name\": \"v9.9.9\"}\n")?;
    let Some(artifact) = host.artifact else {
        return Ok(());
    };
    let pkg = leaf(r, "pkg")?;
    std::fs::create_dir(&pkg)?;
    write_exec(&pkg.join("ipe"), "#!/bin/sh\necho ipe\n")?;
    let archive = serve.join(artifact);
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(&pkg)
        .arg("ipe")
        .status()?;
    if !status.success() {
        return Err(io::Error::other("tar could not build the canned archive"));
    }
    let digest = sha256_hex(&std::fs::read(&archive)?);
    if let Some(size) = host.archive_size {
        std::fs::write(serve.join(format!("{artifact}.size")), size.to_string())?;
    }
    let text = match &host.sums {
        Sums::Good => format!("{digest}  {artifact}\n"),
        Sums::Absent => return Ok(()),
        Sums::Text(text) => text.replace("@DIGEST@", &digest),
    };
    std::fs::write(serve.join("SHA256SUMS"), text)
}

/// Run `install.sh` on `host` under the scratch root `r`.
///
/// The environment is cleared: a private `HOME`, `LC_ALL=C`, `PATH` the stub
/// dir then the farm, and `IPE_INSTALL_DIR` a private dir. A plain run has an
/// empty stdin; a terminal run goes through `script` on Linux. A run past
/// 60 s is killed.
fn run_host(r: &ScratchDir, host: &Host<'_>) -> io::Result<FetchRun> {
    let stubs = leaf(r, "stubs")?;
    std::fs::create_dir(&stubs)?;
    write_exec(&stubs.join("uname"), UNAME)?;
    for (name, body) in host.stubs {
        write_exec(&stubs.join(name), body)?;
    }
    let farm_dir = leaf(r, "farm")?;
    let deny: Vec<&str> = FARM_DENY.iter().chain(host.deny).copied().collect();
    farm(&farm_dir, &deny)?;
    let served = leaf(r, "serve")?;
    serve(r, &served, host)?;
    let home = leaf(r, "home")?;
    mkdir_mode(&home, 0o700)?;
    let install_dir = leaf(r, "inst")?;
    let log = leaf(r, "stub.log")?;
    File::create(&log)?;
    let stderr_path = leaf(r, "stderr")?;
    let stdout_path = leaf(r, "stdout")?;
    let mut path = stubs.into_os_string();
    path.push(":");
    path.push(&farm_dir);

    let mut command = match host.tty_input {
        None => {
            let mut plain = Command::new("sh");
            if host.xtrace {
                plain.arg("-x");
            }
            plain.arg(installer_path()).stdin(Stdio::null());
            plain
        }
        Some(input) => {
            let installer = installer_path();
            let shown = installer.to_string_lossy();
            if shown.contains('\'') {
                return Err(io::Error::other("the installer path holds a quote"));
            }
            let input_path = leaf(r, "tty-input")?;
            std::fs::write(&input_path, input)?;
            let mut tty = Command::new("/usr/bin/script");
            tty.arg("-qec")
                .arg(format!("sh '{shown}'"))
                .arg("/dev/null")
                .stdin(File::open(input_path)?);
            tty
        }
    };
    command
        .process_group(0)
        .env_clear()
        .env("PATH", path)
        .env("HOME", &home)
        .env("LC_ALL", "C")
        .env("STUB_LOG", &log)
        .env("SERVE", &served)
        .env("IPE_INSTALL_DIR", &install_dir)
        .envs(host.env.iter().copied())
        .stdout(File::create(&stdout_path)?)
        .stderr(File::create(&stderr_path)?);
    if host.tty_input.is_some() {
        command.env("SHELL", "/bin/sh").env("TERM", "xterm");
    }
    let mut child = command.spawn()?;
    let mut status = None;
    let finished = e2e_support::wait_for(Duration::from_secs(60), || {
        status = child.try_wait().ok().flatten();
        status.is_some()
    });
    if !finished {
        child.kill()?;
        child.wait()?;
    }
    let mut stderr = String::from_utf8_lossy(&std::fs::read(stderr_path)?).into_owned();
    if host.tty_input.is_some() {
        stderr.push_str(&String::from_utf8_lossy(&std::fs::read(stdout_path)?));
    }
    Ok(FetchRun {
        code: status.as_ref().and_then(ExitStatus::code),
        stderr,
        log: std::fs::read_to_string(log)?,
        install_dir,
    })
}

/// The output of `sh` running `program` with `args` as `$@`, in `LC_ALL=C`.
fn run_sh(program: &str, args: &[&OsStr]) -> io::Result<String> {
    let output = Command::new("sh")
        .env("LC_ALL", "C")
        .arg("-c")
        .arg(program)
        .arg("sh")
        .args(args)
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The command the prerequisite block names for `kind` on this host's
/// `/etc/os-release` family, or on debian when the family is unknown, where
/// the installer prints every family's row.
fn host_family_command(kind: &str) -> io::Result<String> {
    let script = installer_script()?;
    let program = format!(
        "{}\nos_family /etc/os-release\n[ \"$OS_FAMILY\" != unknown ] || OS_FAMILY=debian\n\
         prereq_command \"$1\" \"$OS_FAMILY\"\nprintf '%s' \"$PREREQ_CMD\"\n",
        marked(&script, PREREQ)?
    );
    let command = run_sh(&program, &[OsStr::new(kind)])?;
    if command.is_empty() {
        return Err(io::Error::other(format!("no prerequisite row for {kind}")));
    }
    Ok(command)
}

/// The text of the shell function `name` in `script`, from its `name() {`
/// line to its closing `}` line.
fn function_text<'s>(script: &'s str, name: &str) -> io::Result<&'s str> {
    let open = format!("\n{name}() {{\n");
    script
        .find(&open)
        .and_then(|start| {
            let body = start + 1;
            script
                .get(body..)
                .and_then(|tail| tail.find("\n}\n"))
                .and_then(|end| script.get(body..body + end + 3))
        })
        .ok_or_else(|| io::Error::other(format!("install.sh lost its `{name}` function")))
}

fn assert_code(run: &FetchRun, code: i32, why: &str) {
    assert_eq!(
        run.code,
        Some(code),
        "{why}: the installer must exit {code}; stderr: {}\nlog: {}",
        run.stderr,
        run.log
    );
}

/// A1: with no fetcher the installer exits 3, naming curl, wget and the
/// family's install command, and leaves the install dir uncreated.
#[test]
fn a1_no_fetcher_is_a_missing_prerequisite() -> io::Result<()> {
    let r = root("install-fetch-a1")?;
    let run = run_host(
        &r,
        &Host {
            stubs: &[],
            ..Host::default()
        },
    )?;
    assert_code(&run, 3, "no fetcher");
    assert!(
        run.stderr.contains("[prerequisite fetcher]")
            && run.stderr.contains("curl")
            && run.stderr.contains("wget"),
        "the refusal must name curl and wget: {}",
        run.stderr
    );
    let remedy = host_family_command("curl")?;
    assert!(
        run.stderr.contains(&remedy),
        "the refusal must name `{remedy}`: {}",
        run.stderr
    );
    assert!(
        !run.install_dir.exists(),
        "a refused host must leave the install dir uncreated"
    );
    assert!(run.log.is_empty(), "nothing may be fetched: {}", run.log);
    Ok(())
}

/// A2: a GNU Wget-only host installs through Wget with its private config,
/// HTTPS only, TLS 1.2, no automatic redirect and a timeout; an HTTPS
/// redirect is followed hop by hop.
#[test]
fn a2_gnu_wget_installs_with_every_guarantee() -> io::Result<()> {
    let r = root("install-fetch-a2")?;
    let run = run_host(
        &r,
        &Host {
            stubs: &[("wget", WGET)],
            env: &[
                ("STUB_REDIRECT_MATCH", "/releases/download/"),
                ("STUB_REDIRECT_TO", "https://objects.example/x"),
            ],
            ..Host::default()
        },
    )?;
    assert_code(&run, 0, "a GNU Wget host");
    assert!(run.installed(), "the canned binary must be installed");
    let calls: Vec<&str> = run.lines("wget ").collect();
    assert!(calls.len() >= 4, "every fetch must run wget: {}", run.log);
    for call in &calls {
        for flag in [
            "--config=",
            "--https-only",
            "--secure-protocol=TLSv1_2",
            "--max-redirect=0",
            "--timeout=",
            "--tries=1",
        ] {
            assert!(call.contains(flag), "`{call}` must carry `{flag}`");
        }
    }
    assert!(
        run.lines("config-mode ")
            .all(|line| line.starts_with("config-mode wgetrc ")),
        "an anonymous run reads only the installer's own wgetrc: {}",
        run.log
    );
    assert!(
        calls
            .iter()
            .any(|call| call.contains("https://objects.example/x/ipe-linux-x64.tar.gz")),
        "the HTTPS redirect must be followed: {}",
        run.log
    );
    Ok(())
}

/// A3: a redirect to an `http://` Location is refused; nothing requests it
/// and nothing is installed.
#[test]
fn a3_wget_redirect_off_https_is_refused() -> io::Result<()> {
    let r = root("install-fetch-a3")?;
    let run = run_host(
        &r,
        &Host {
            stubs: &[("wget", WGET)],
            env: &[
                ("STUB_REDIRECT_MATCH", "/releases/download/"),
                ("STUB_REDIRECT_TO", "http://objects.example/x"),
            ],
            ..Host::default()
        },
    )?;
    assert!(
        run.code.is_some_and(|code| code != 0),
        "a redirect off HTTPS must fail the install: {}",
        run.stderr
    );
    assert!(!run.installed(), "nothing may be installed");
    assert!(
        run.lines("wget ").all(|call| !call.contains("http://")),
        "no request may go to the http:// target: {}",
        run.log
    );
    Ok(())
}

/// A4: a wget that is not GNU Wget is refused as a missing prerequisite,
/// naming the Alpine command.
#[test]
fn a4_other_wget_is_refused() -> io::Result<()> {
    let r = root("install-fetch-a4")?;
    let run = run_host(
        &r,
        &Host {
            stubs: &[("wget", OTHER_WGET)],
            ..Host::default()
        },
    )?;
    assert_code(&run, 3, "a non-GNU wget");
    assert!(
        run.stderr.contains("apk add curl") && run.stderr.contains("GNU Wget"),
        "the refusal must name GNU Wget and `apk add curl`: {}",
        run.stderr
    );
    assert!(
        run.lines("wget ")
            .all(|call| call.trim_end() == "wget --version"),
        "the other wget may only be asked its version, never fetch: {}",
        run.log
    );
    Ok(())
}

/// A5: on `FreeBSD` with only fetch, the certificate and protocol overrides
/// never reach it, TLS 1.0 and 1.1 are switched off, and every call carries a
/// timeout.
#[test]
fn a5_freebsd_fetch_runs_with_verification_held_on() -> io::Result<()> {
    let r = root("install-fetch-a5")?;
    let run = run_host(
        &r,
        &Host {
            stubs: &[("fetch", FETCH_STUB)],
            artifact: Some("ipe-freebsd-x64.tar.gz"),
            env: &[
                ("STUB_OS", "FreeBSD"),
                ("SSL_NO_VERIFY_PEER", "1"),
                ("SSL_NO_VERIFY_HOSTNAME", "1"),
                ("SSL_ALLOW_SSL3", "1"),
            ],
            ..Host::default()
        },
    )?;
    assert_code(&run, 0, "a FreeBSD fetch host");
    assert!(run.installed(), "the canned binary must be installed");
    let calls: Vec<&str> = run.lines("fetch ").collect();
    assert!(calls.len() >= 4, "every fetch must run fetch: {}", run.log);
    for call in &calls {
        assert!(
            call.ends_with(
                " SSL_NO_VERIFY_PEER=unset SSL_ALLOW_SSL3=unset SSL_NO_TLS1=1 SSL_NO_TLS1_1=1"
            ) && call.contains(" -T "),
            "`{call}` must run with the overrides unset, TLS 1.2 or later and a timeout"
        );
    }
    Ok(())
}

/// The flags every curl call must hold, after its leading `-q`.
const CURL_FLAGS: [&str; 5] = [
    "--proto =https",
    "--proto-redir =https",
    "--tlsv1.2",
    "--max-time ",
    "--connect-timeout ",
];

fn assert_curl_calls(run: &FetchRun, at_least: usize) {
    let calls: Vec<&str> = run.lines("curl ").collect();
    assert!(
        calls.len() >= at_least,
        "every fetch must run curl: {}",
        run.log
    );
    for call in calls {
        assert!(call.starts_with("curl -q "), "`{call}` must begin `-q`");
        for flag in CURL_FLAGS {
            assert!(call.contains(flag), "`{call}` must carry `{flag}`");
        }
    }
}

/// A6: every curl call ignores `.curlrc` and holds HTTPS-only transport and
/// redirects, TLS 1.2 and a time ceiling.
#[test]
fn a6_every_curl_call_holds_the_transport_flags() -> io::Result<()> {
    let r = root("install-fetch-a6")?;
    let run = run_host(&r, &Host::default())?;
    assert_code(&run, 0, "a curl host");
    assert!(run.installed(), "the canned binary must be installed");
    assert_curl_calls(&run, 4);
    assert!(
        run.lines("curl ")
            .filter(|call| call.contains(" -o ") && !call.contains("/dev/null"))
            .all(|call| call.contains("--max-filesize ")),
        "every body fetch must carry a size ceiling: {}",
        run.log
    );
    Ok(())
}

/// A6 on a terminal: the progress path's range probe and background
/// download hold the same flags.
#[cfg(target_os = "linux")]
#[test]
fn a6_curl_flags_hold_on_the_terminal_path() -> io::Result<()> {
    let r = root("install-fetch-a6-tty")?;
    let run = run_host(
        &r,
        &Host {
            tty_input: Some("n\nn\n"),
            ..Host::default()
        },
    )?;
    assert_code(&run, 0, "a curl host on a terminal");
    assert!(run.installed(), "the canned binary must be installed");
    assert!(
        run.lines("curl ").any(|call| call.contains(" -r 0-0 ")),
        "the terminal path must probe the size: {}",
        run.log
    );
    assert_curl_calls(&run, 5);
    Ok(())
}

fn assert_refused_before_extract(run: &FetchRun, marker: &str, why: &str) {
    assert_code(run, 1, why);
    assert!(
        run.stderr.contains(marker),
        "{why}: stderr must carry `{marker}`: {}",
        run.stderr
    );
    assert!(!run.installed(), "{why}: nothing may be installed");
}

/// A7: a release with no `SHA256SUMS` is never installed.
#[test]
fn a7_absent_checksum_list_is_refused() -> io::Result<()> {
    let r = root("install-fetch-a7")?;
    let run = run_host(
        &r,
        &Host {
            sums: Sums::Absent,
            ..Host::default()
        },
    )?;
    assert_refused_before_extract(&run, "[checksum-unavailable]", "no SHA256SUMS");
    Ok(())
}

/// A8: an entry for another name, a suffix match included, is no entry.
#[test]
fn a8_checksum_entry_matches_the_exact_name() -> io::Result<()> {
    let r = root("install-fetch-a8")?;
    let run = run_host(
        &r,
        &Host {
            sums: Sums::Text(
                "@DIGEST@  xipe-linux-x64.tar.gz\n@DIGEST@  ipe-linux-x64.tar.gz.sig\n",
            ),
            ..Host::default()
        },
    )?;
    assert_refused_before_extract(&run, "[checksum-entry-missing]", "no exact entry");
    Ok(())
}

/// A9: a digest that differs, and an entry that is not one 64-digit digest,
/// are both refused before extraction.
#[test]
fn a9_mismatched_or_malformed_checksum_is_refused() -> io::Result<()> {
    let wrong =
        "0000000000000000000000000000000000000000000000000000000000000000  ipe-linux-x64.tar.gz\n";
    let short =
        "000000000000000000000000000000000000000000000000000000000000000  ipe-linux-x64.tar.gz\n";
    let twice = "@DIGEST@  ipe-linux-x64.tar.gz\n@DIGEST@ *ipe-linux-x64.tar.gz\n";
    for (label, text, marker) in [
        ("install-fetch-a9-wrong", wrong, "Checksum mismatch"),
        (
            "install-fetch-a9-short",
            short,
            "[checksum-entry-malformed]",
        ),
        (
            "install-fetch-a9-twice",
            twice,
            "[checksum-entry-malformed]",
        ),
    ] {
        let r = root(label)?;
        let run = run_host(
            &r,
            &Host {
                sums: Sums::Text(text),
                ..Host::default()
            },
        )?;
        assert_refused_before_extract(&run, marker, label);
    }
    Ok(())
}

/// A10: a host with no SHA-256 tool is a missing prerequisite.
#[test]
fn a10_no_sha256_tool_is_a_missing_prerequisite() -> io::Result<()> {
    let r = root("install-fetch-a10")?;
    let run = run_host(
        &r,
        &Host {
            deny: &SHA_TOOLS,
            ..Host::default()
        },
    )?;
    assert_code(&run, 3, "no SHA-256 tool");
    assert!(
        run.stderr.contains("[prerequisite sha256]"),
        "the refusal must name the sha256 prerequisite: {}",
        run.stderr
    );
    assert!(run.log.is_empty(), "nothing may be fetched: {}", run.log);
    Ok(())
}

/// A11: a GitHub token reaches curl and Wget only through a file private to
/// the user, never an argument or the terminal.
#[test]
fn a11_token_stays_out_of_every_argument() -> io::Result<()> {
    for (label, fetcher, body, private_line) in [
        (
            "install-fetch-a11-curl",
            "curl",
            CURL,
            "header-mode -rw-------",
        ),
        (
            "install-fetch-a11-wget",
            "wget",
            WGET,
            "config-mode auth.wgetrc -rw-------",
        ),
    ] {
        let r = root(label)?;
        let run = run_host(
            &r,
            &Host {
                stubs: &[(fetcher, body)],
                env: &[("GITHUB_TOKEN", "s3cr3t")],
                ..Host::default()
            },
        )?;
        assert_code(&run, 0, label);
        assert!(
            !run.log.contains("s3cr3t") && !run.stderr.contains("s3cr3t"),
            "{label}: the token must reach no argument and no message: {}",
            run.log
        );
        assert!(
            run.log.lines().any(|line| line.starts_with(private_line)),
            "{label}: the token file must be mode 0600: {}",
            run.log
        );
    }
    Ok(())
}

/// A11b: under GNU Wget, a redirect off the API host reads the anonymous
/// config, so the token reaches only the host it was meant for.
#[test]
fn a11b_wget_drops_the_token_on_a_redirect_to_another_host() -> io::Result<()> {
    let r = root("install-fetch-a11b")?;
    let run = run_host(
        &r,
        &Host {
            stubs: &[("wget", WGET)],
            env: &[
                ("GITHUB_TOKEN", "s3cr3t"),
                ("STUB_REDIRECT_MATCH", "/releases/latest"),
                ("STUB_REDIRECT_TO", "https://elsewhere.example/x"),
            ],
            ..Host::default()
        },
    )?;
    assert_code(&run, 0, "a redirected API request");
    let lines: Vec<&str> = run.log.lines().collect();
    let configs = |host: &str| -> Vec<&str> {
        lines
            .windows(2)
            .filter_map(|pair| match pair {
                [call, config] if call.starts_with("wget ") && call.contains(host) => Some(*config),
                _ => None,
            })
            .collect()
    };
    let api = configs("https://api.github.com/");
    let elsewhere = configs("https://elsewhere.example/");
    assert!(
        !api.is_empty()
            && api
                .iter()
                .all(|line| line.starts_with("config-mode auth.wgetrc ")),
        "the API request itself carries the token: {}",
        run.log
    );
    assert!(
        !elsewhere.is_empty()
            && elsewhere
                .iter()
                .all(|line| line.starts_with("config-mode wgetrc ")),
        "the hop to another host must read the anonymous config: {}",
        run.log
    );
    Ok(())
}

/// A11c: a run under `sh -x` traces no line holding the token.
#[test]
fn a11c_token_stays_out_of_the_shell_trace() -> io::Result<()> {
    for (label, fetcher, body) in [
        ("install-fetch-a11c-curl", "curl", CURL),
        ("install-fetch-a11c-wget", "wget", WGET),
    ] {
        let r = root(label)?;
        let run = run_host(
            &r,
            &Host {
                stubs: &[(fetcher, body)],
                env: &[("GITHUB_TOKEN", "s3cr3t")],
                xtrace: true,
                ..Host::default()
            },
        )?;
        assert_code(&run, 0, label);
        assert!(
            run.stderr.contains("+ fetch_auth_setup"),
            "{label}: the run must be traced: {}",
            run.stderr
        );
        assert!(
            !run.stderr.contains("s3cr3t"),
            "{label}: the trace must not hold the token: {}",
            run.stderr
        );
    }
    Ok(())
}

/// A curl that, asked for the latest release, sends `STUB_SIGNAL` to the
/// installer's whole process group, as a terminal's Ctrl-C or Ctrl-\ or a
/// closing session does.
const CURL_KILLED: &str = r#"#!/bin/sh
if [ "$*" = '-q --version' ]; then echo 'curl 8.5.0 (x86_64-pc-linux-gnu)'; exit 0; fi
case "$*" in *releases/latest*) kill -"$STUB_SIGNAL" 0; sleep 5 ;; esac
exit 22
"#;

/// A11d: a run killed while the token file exists still removes its scratch,
/// so no token is left on disk.
#[test]
fn a11d_a_killed_run_leaves_no_token_on_disk() -> io::Result<()> {
    for (signal, code) in [("TERM", 143), ("QUIT", 131)] {
        let r = root(&format!("install-fetch-a11d-{signal}"))?;
        let base = leaf(&r, "tmpbase")?;
        mkdir_mode(&base, 0o700)?;
        let base_text = base
            .to_str()
            .ok_or_else(|| io::Error::other("the scratch path is not UTF-8"))?;
        let run = run_host(
            &r,
            &Host {
                stubs: &[("curl", CURL_KILLED)],
                env: &[
                    ("GITHUB_TOKEN", "s3cr3t"),
                    ("TMPDIR", base_text),
                    ("STUB_SIGNAL", signal),
                ],
                ..Host::default()
            },
        )?;
        let left: Vec<PathBuf> = std::fs::read_dir(&base)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<_>>()?;
        assert!(
            left.is_empty(),
            "a run killed by {signal} must remove its scratch: {left:?}"
        );
        assert_code(&run, code, signal);
    }
    Ok(())
}

/// A11e: the token file exists only for the release lookup, so a run killed
/// later, by a signal no trap catches, leaves no token on disk.
#[test]
fn a11e_token_file_lives_only_for_the_release_lookup() -> io::Result<()> {
    let r = root("install-fetch-a11e")?;
    let run = run_host(
        &r,
        &Host {
            stubs: &[("curl", CURL)],
            env: &[("GITHUB_TOKEN", "s3cr3t")],
            ..Host::default()
        },
    )?;
    assert_code(&run, 0, "a curl host with a token");
    let present: Vec<&str> = run.lines("token-file-at ").collect();
    assert!(
        !present.is_empty()
            && present
                .iter()
                .all(|line| line.trim_end() == "token-file-at latest"),
        "the token file must exist during the lookup and only then: {}",
        run.log
    );
    Ok(())
}

/// A11f: a curl older than 7.58, which sends a custom header on to a
/// redirect's other host, or one whose version cannot be read, resolves the
/// release without the token.
#[test]
fn a11f_old_curl_resolves_the_release_anonymously() -> io::Result<()> {
    for (label, version, sends) in [
        ("7_57", "7.57.0", false),
        ("7_9", "7.9.99", false),
        ("6_99", "6.99.0", false),
        ("garbled", "x.y", false),
        ("empty", "", false),
        ("7_58", "7.58.0", true),
        ("7_81", "7.81.0", true),
        ("8_0", "8.0.1", true),
    ] {
        let r = root(&format!("install-fetch-a11f-{label}"))?;
        let run = run_host(
            &r,
            &Host {
                stubs: &[("curl", CURL)],
                env: &[("GITHUB_TOKEN", "s3cr3t"), ("STUB_CURL_VERSION", version)],
                ..Host::default()
            },
        )?;
        assert_code(&run, 0, label);
        let sent = run.lines("curl ").any(|call| call.contains(" -H @"));
        assert_eq!(sent, sends, "curl {version}: token sent: {}", run.log);
        assert_eq!(
            run.log.contains("token-file-at"),
            sends,
            "curl {version}: a token file exists only when sent: {}",
            run.log
        );
    }
    Ok(())
}

/// A12: a non-terminal run on a host with no cargo and no C compiler still
/// installs, then prints the rustup line and the family's C toolchain
/// command without fetching rustup.
#[test]
fn a12_missing_build_prerequisites_are_named_after_install() -> io::Result<()> {
    let r = root("install-fetch-a12")?;
    let run = run_host(&r, &Host::default())?;
    assert_code(&run, 0, "no cargo and no cc");
    assert!(run.installed(), "the canned binary must be installed");
    let c_toolchain = host_family_command("c-toolchain")?;
    for want in ["Before your first build", RUSTUP_CURL, c_toolchain.as_str()] {
        assert!(
            run.stderr.contains(want),
            "the closing block must name `{want}`: {}",
            run.stderr
        );
    }
    assert!(
        !run.log.contains("sh.rustup.rs"),
        "a non-terminal run must never fetch rustup: {}",
        run.log
    );
    Ok(())
}

/// A13: when the rustup fetch fails after consent, the run reports that
/// rustup failed and never that Rust is available.
#[cfg(target_os = "linux")]
#[test]
fn a13_failed_rustup_fetch_is_reported() -> io::Result<()> {
    let r = root("install-fetch-a13")?;
    let run = run_host(
        &r,
        &Host {
            artifact: None,
            tty_input: Some("y\n"),
            ..Host::default()
        },
    )?;
    assert!(
        run.stderr.contains("rustup exited non-zero"),
        "the failed rustup fetch must be reported: {}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("Rust now available") && !run.stderr.contains("Rust installed"),
        "a failed rustup fetch must never claim Rust: {}",
        run.stderr
    );
    assert!(
        run.lines("curl -q ")
            .any(|call| call.contains("https://sh.rustup.rs")),
        "rustup-init must be fetched through the fetch helpers: {}",
        run.log
    );
    Ok(())
}

/// A14: each README install line fails on a host with neither curl nor wget,
/// so no partial install starts.
#[test]
fn a14_readme_install_lines_fail_without_a_fetcher() -> io::Result<()> {
    let readme = std::fs::read_to_string(e2e_support::manifest_dir!().join("../../README.md"))?;
    let lines: Vec<&str> = readme
        .lines()
        .filter(|line| {
            (line.starts_with("curl ") || line.starts_with("wget "))
                && line.contains("ipe-install.sh")
        })
        .collect();
    assert!(
        lines.iter().any(|line| line.starts_with("curl ")),
        "README must document the curl install line"
    );
    let r = root("install-fetch-a14")?;
    let farm_dir = leaf(&r, "farm")?;
    farm(&farm_dir, &FARM_DENY)?;
    let home = leaf(&r, "home")?;
    mkdir_mode(&home, 0o700)?;
    for line in lines {
        let output = Command::new("sh")
            .arg("-c")
            .arg(line)
            .current_dir(&home)
            .env_clear()
            .env("PATH", &farm_dir)
            .env("HOME", &home)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .output()?;
        assert!(
            !output.status.success(),
            "`{line}` must fail without a fetcher"
        );
        assert!(
            !home.join("ipe-install.sh").exists(),
            "`{line}` must leave no installer behind"
        );
    }
    Ok(())
}

/// A15: outside the fetch helpers, `install.sh` runs no fetcher by name.
#[test]
fn a15_only_the_fetch_helpers_run_a_fetcher() -> io::Result<()> {
    let script = installer_script()?;
    let whole = scan_script(&script);
    for fetcher in ["curl", "wget", "fetch"] {
        assert!(
            whole.ran.iter().any(|name| name == fetcher),
            "the scan must see `{fetcher}` run inside the fetch helpers"
        );
    }
    let block = marked(&script, FETCH)?;
    let outside = script.replacen(block, "", 1);
    let scan = scan_script(&outside);
    for fetcher in ["curl", "wget", "fetch"] {
        assert!(
            !scan.ran.iter().any(|name| name == fetcher),
            "`{fetcher}` must run only inside the fetch helpers"
        );
    }
    Ok(())
}

/// A16: an archive over the size ceiling from a fetcher with no in-flight
/// ceiling is removed before the checksum list is fetched.
#[test]
fn a16_oversized_archive_is_refused_before_checksum() -> io::Result<()> {
    let r = root("install-fetch-a16")?;
    let run = run_host(
        &r,
        &Host {
            stubs: &[("wget", WGET)],
            archive_size: Some(ARCHIVE_MAX_BYTES + 1),
            ..Host::default()
        },
    )?;
    assert_code(&run, 1, "an oversized archive");
    assert!(
        run.stderr.contains("ceiling"),
        "the refusal must name the size ceiling: {}",
        run.stderr
    );
    assert!(
        !run.log.contains("SHA256SUMS"),
        "the checksum list must not be fetched: {}",
        run.log
    );
    assert!(!run.installed(), "nothing may be installed");
    Ok(())
}

/// `os_family` maps the first word of `ID`, then `ID_LIKE`, to a family and
/// every other file to `unknown`.
#[test]
fn os_family_table() -> io::Result<()> {
    let filler = "X=1\n".repeat(64);
    let cases: [(&str, String, &str); 12] = [
        ("ubuntu", "ID=ubuntu\n".to_owned(), "debian"),
        (
            "rocky",
            "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n".to_owned(),
            "fedora",
        ),
        ("like-arch", "ID=weird\nID_LIKE=arch\n".to_owned(), "arch"),
        ("alpine", "ID=alpine\n".to_owned(), "alpine"),
        (
            "tumbleweed",
            "ID=\"opensuse-tumbleweed\"\n".to_owned(),
            "suse",
        ),
        ("nixos", "ID=nixos\n".to_owned(), "unknown"),
        ("glob", "ID='*'\nID_LIKE=?\n".to_owned(), "unknown"),
        ("subst", "ID=$(debian)\n".to_owned(), "debian"),
        ("past-cap", format!("{filler}ID=debian\n"), "unknown"),
        ("no-newline", "ID=fedora".to_owned(), "fedora"),
        ("empty", String::new(), "unknown"),
        ("bytes", "ID=\u{1b}]0;x\u{7}\n".to_owned(), "unknown"),
    ];
    let r = root("install-fetch-os-family")?;
    let mut paths = Vec::new();
    for (name, text, _) in &cases {
        let path = leaf(&r, name)?;
        std::fs::write(&path, text)?;
        paths.push(path);
    }
    paths.push(leaf(&r, "missing")?);
    let script = installer_script()?;
    let program = format!(
        "{}\nfor f; do os_family \"$f\"; printf '%s\\n' \"$OS_FAMILY\"; done\n",
        marked(&script, PREREQ)?
    );
    let args: Vec<&OsStr> = paths.iter().map(|path| path.as_os_str()).collect();
    let got = run_sh(&program, &args)?;
    let want: Vec<&str> = cases
        .iter()
        .map(|(_, _, family)| *family)
        .chain(["unknown"])
        .collect();
    assert_eq!(got.lines().collect::<Vec<_>>(), want, "os_family per file");
    Ok(())
}

/// `sums_entry` takes exactly one well-formed entry for exactly the name.
#[test]
fn sums_entry_table() -> io::Result<()> {
    let hex = "a".repeat(64);
    let cases: [(&str, String, &str); 9] = [
        ("text-mode", format!("{hex}  ipe.tgz\n"), "ok"),
        ("binary-mode", format!("{hex} *ipe.tgz\n"), "ok"),
        (
            "among-others",
            format!("{hex}  other\n{hex}  ipe.tgz\n"),
            "ok",
        ),
        ("suffix", format!("{hex}  xipe.tgz\n"), "missing"),
        ("crlf", format!("{hex}  ipe.tgz\r\n"), "missing"),
        (
            "short",
            format!("{}  ipe.tgz\n", "a".repeat(63)),
            "malformed",
        ),
        (
            "upper",
            format!("{}  ipe.tgz\n", "A".repeat(64)),
            "malformed",
        ),
        (
            "twice",
            format!("{hex}  ipe.tgz\n{hex}  ipe.tgz\n"),
            "malformed",
        ),
        (
            "long",
            format!("{}{hex}  ipe.tgz\n", "x\n".repeat(4096)),
            "malformed",
        ),
    ];
    let r = root("install-fetch-sums")?;
    let mut paths = Vec::new();
    for (name, text, _) in &cases {
        let path = leaf(&r, name)?;
        std::fs::write(&path, text)?;
        paths.push(path);
    }
    let script = installer_script()?;
    let program = format!(
        "{}\n{}\nfor f; do sums_entry \"$f\" ipe.tgz\n\
         if [ -z \"$SUMS_FAULT\" ]; then echo \"ok $SUMS_WANT\"; else echo \"$SUMS_FAULT\"; fi; done\n",
        function_text(&script, "hex_digest_ok")?,
        function_text(&script, "sums_entry")?
    );
    let args: Vec<&OsStr> = paths.iter().map(|path| path.as_os_str()).collect();
    let got = run_sh(&program, &args)?;
    let want: Vec<String> = cases
        .iter()
        .map(|(_, _, fault)| {
            if *fault == "ok" {
                format!("ok {hex}")
            } else {
                (*fault).to_owned()
            }
        })
        .collect();
    assert_eq!(got.lines().collect::<Vec<_>>(), want, "sums_entry per list");
    Ok(())
}

/// `fetch_url_ok` admits only bounded `https://` URLs of plain URL bytes.
#[test]
fn fetch_url_ok_table() -> io::Result<()> {
    let longest = format!("https://x/{}", "a".repeat(2038));
    let too_long = format!("{longest}a");
    let cases: [(&str, bool); 10] = [
        ("https://github.com/ipe-lang/compiler/releases/latest", true),
        ("https://x/a?b=c&d=%2F#f", true),
        (longest.as_str(), true),
        (too_long.as_str(), false),
        ("http://github.com/x", false),
        ("https://", false),
        ("HTTPS://x", false),
        ("https://x/a b", false),
        ("https://x/`id`", false),
        ("https://x/$(id)", false),
    ];
    let script = installer_script()?;
    let program = format!(
        "{}\nfor u; do if fetch_url_ok \"$u\"; then echo y; else echo n; fi; done\n",
        marked(&script, FETCH)?
    );
    let args: Vec<&OsStr> = cases.iter().map(|(url, _)| OsStr::new(url)).collect();
    let got = run_sh(&program, &args)?;
    let want: Vec<&str> = cases
        .iter()
        .map(|(_, ok)| if *ok { "y" } else { "n" })
        .collect();
    assert_eq!(
        got.lines().collect::<Vec<_>>(),
        want,
        "fetch_url_ok per URL"
    );
    Ok(())
}

/// `wget_redirect` follows only a redirect status whose Location is HTTPS,
/// read from the last response.
#[test]
fn wget_redirect_table() -> io::Result<()> {
    let cases: [(&str, &str, &str); 7] = [
        (
            "https",
            "  HTTP/1.1 302 Found\n  Location: https://y/z\n",
            "y https://y/z",
        ),
        (
            "lower",
            "  HTTP/1.1 301 Moved\n  location: https://y/z\n",
            "y https://y/z",
        ),
        (
            "http",
            "  HTTP/1.1 302 Found\n  Location: http://y/z\n",
            "n",
        ),
        ("ok", "  HTTP/1.1 200 OK\n  Location: https://y/z\n", "n"),
        ("no-location", "  HTTP/1.1 307 Temporary\n", "n"),
        (
            "last-wins",
            "  HTTP/1.1 302 Found\n  Location: https://y/z\n  HTTP/1.1 404 Not Found\n",
            "n",
        ),
        ("relative", "  HTTP/1.1 302 Found\n  Location: /z\n", "n"),
    ];
    let r = root("install-fetch-redirect")?;
    let mut paths = Vec::new();
    for (name, text, _) in &cases {
        let path = leaf(&r, name)?;
        std::fs::write(&path, text)?;
        paths.push(path);
    }
    let script = installer_script()?;
    let program = format!(
        "{}\nfor f; do if wget_redirect \"$f\"; then echo \"y $WGET_LOCATION\"; else echo n; fi; done\n",
        marked(&script, FETCH)?
    );
    let args: Vec<&OsStr> = paths.iter().map(|path| path.as_os_str()).collect();
    let got = run_sh(&program, &args)?;
    let want: Vec<&str> = cases.iter().map(|(_, _, verdict)| *verdict).collect();
    assert_eq!(
        got.lines().collect::<Vec<_>>(),
        want,
        "wget_redirect per log"
    );
    Ok(())
}
