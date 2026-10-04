//! Refusal tests for the installer's private-scratch helpers.
//!
//! `install.sh` cannot call the Rust scratch primitive, so it carries the same
//! property in shell between the `private-scratch helpers` markers. These tests
//! extract that block and drive every refusal: a symlinked or group/world
//! accessible directory, a non-sticky world-writable base, and a tag file that
//! is a planted symlink (whose target must stay untouched). The pure verdicts
//! are driven with synthetic `ls -l` facts, so the foreign-owner and
//! foreign-group refusals need no second account. Every refusal also pins the
//! reason token the installer's diagnostic names, and that the printed facts are
//! terminal-safe. The private-scratch block reports through the message helpers,
//! so every run loads both blocks.
#![cfg(unix)]

use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ipe_sandbox::scratch::{LeafName, ScratchDir};

const MESSAGE_BLOCK: (&str, &str) = ("# >>> message helpers", "# <<< message helpers");
const SCRATCH_BLOCK: (&str, &str) = (
    "# >>> private-scratch helpers",
    "# <<< private-scratch helpers",
);

/// The `(begin, end)` marked block of `script`, markers included.
fn block<'s>(script: &'s str, (begin, end): (&str, &str)) -> io::Result<&'s str> {
    script
        .find(begin)
        .and_then(|start| {
            script
                .get(start..)
                .and_then(|tail| tail.find(end).map(|at| (start, start + at + end.len())))
        })
        .and_then(|(start, stop)| script.get(start..stop))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("install.sh lost its `{begin}` markers"),
            )
        })
}

/// The message and private-scratch helper blocks of `install.sh`, in order.
fn helpers() -> io::Result<String> {
    let script = std::fs::read_to_string(e2e_support::manifest_dir!().join("../../install.sh"))?;
    Ok(format!(
        "{}\n{}",
        block(&script, MESSAGE_BLOCK)?,
        block(&script, SCRATCH_BLOCK)?
    ))
}

/// An `sh -c` command over `script` in the C locale, with `$0` set to `sh`.
fn shell(script: &str) -> Command {
    let mut command = Command::new("sh");
    command.env("LC_ALL", "C").arg("-c").arg(script).arg("sh");
    command
}

/// Whether `sh` running the helper `function` on `arg` succeeds.
fn helper_accepts(function: &str, arg: &Path) -> io::Result<bool> {
    let script = format!("{}\n{function} \"$1\"\n", helpers()?);
    let status = shell(&script)
        .arg(arg)
        .stdout(std::process::Stdio::null())
        .status()?;
    Ok(status.success())
}

/// Whether `sh` running the helper `function` on the literal `args` succeeds.
fn verdict_accepts(function: &str, args: &[&str]) -> io::Result<bool> {
    let script = format!("{}\n{function} \"$@\"\n", helpers()?);
    let status = shell(&script)
        .args(args)
        .stdout(std::process::Stdio::null())
        .status()?;
    Ok(status.success())
}

/// The output of `sh` running `body` after the helper blocks in `locale`, with
/// `args` as `$@`.
fn helper_output(body: &str, args: &[&str], locale: &str) -> io::Result<Output> {
    let script = format!("{}\n{body}\n", helpers()?);
    shell(&script).env("LC_ALL", locale).args(args).output()
}

/// The stdout of `sh` running `body` after the helper blocks, with `args` as `$@`.
fn helper_stdout(body: &str, args: &[&str]) -> io::Result<Vec<u8>> {
    Ok(helper_output(body, args, "C")?.stdout)
}

/// The stdout (refused path and reason token) and stderr (refusal sentence)
/// of `body` run on `args`.
fn refusal(body: &str, args: &[&str]) -> io::Result<(String, String)> {
    let output = helper_output(body, args, "C")?;
    Ok((
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

/// The reason token `scratch_base_reason` prints for the literal `args`.
fn base_reason(args: &[&str]) -> io::Result<String> {
    let stdout = helper_stdout("scratch_base_reason \"$@\"", args)?;
    Ok(String::from_utf8_lossy(&stdout).trim_end().to_owned())
}

/// Prints the refused path and reason token `trusted_tmp_base` leaves for `$1`,
/// one per line on stdout, then dies with the refusal sentence on stderr;
/// nothing when `$1` is trusted.
const REFUSAL_REPORT: &str = "trusted_tmp_base \"$1\" >/dev/null || \
     { printf '%s\\n%s\\n' \"$TMP_REFUSED_PATH\" \"$TMP_REFUSED_REASON\"; die_tmp_base_refused; }";

/// A test root under the per-binary target temp dir.
fn root(label: &str) -> io::Result<ScratchDir> {
    ScratchDir::new_under(Path::new(env!("CARGO_TARGET_TMPDIR")), label)
}

/// `name` inside the scratch root `r`.
fn leaf(r: &ScratchDir, name: &str) -> io::Result<PathBuf> {
    Ok(r.child(&LeafName::new(name)?))
}

fn mkdir_mode(path: &Path, mode: u32) -> io::Result<()> {
    std::fs::create_dir(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[test]
fn private_dir_ok_accepts_only_an_owned_0700_directory() -> io::Result<()> {
    let r = root("install-private-dir")?;
    let private = leaf(&r, "private")?;
    mkdir_mode(&private, 0o700)?;
    assert!(helper_accepts("private_dir_ok", &private)?);

    for (name, mode) in [("world", 0o777), ("group", 0o750), ("other", 0o705)] {
        let dir = leaf(&r, name)?;
        mkdir_mode(&dir, mode)?;
        assert!(
            !helper_accepts("private_dir_ok", &dir)?,
            "mode {mode:o} must be refused"
        );
    }

    let link = leaf(&r, "link")?;
    std::os::unix::fs::symlink(&private, &link)?;
    assert!(
        !helper_accepts("private_dir_ok", &link)?,
        "a symlink to a private directory must be refused"
    );
    Ok(())
}

#[test]
fn trusted_tmp_base_refuses_a_non_sticky_world_writable_base() -> io::Result<()> {
    let r = root("install-base")?;
    let open = leaf(&r, "open")?;
    mkdir_mode(&open, 0o777)?;
    assert!(!helper_accepts("trusted_tmp_base", &open)?);

    let nested = open.join("nested");
    mkdir_mode(&nested, 0o700)?;
    assert!(
        !helper_accepts("trusted_tmp_base", &nested)?,
        "a base under a non-sticky world-writable ancestor must be refused"
    );

    let sticky = leaf(&r, "sticky")?;
    mkdir_mode(&sticky, 0o1777)?;
    assert!(helper_accepts("trusted_tmp_base", &sticky)?);
    Ok(())
}

#[test]
fn tag_file_ok_refuses_a_planted_symlink_and_leaves_its_target() -> io::Result<()> {
    let r = root("install-tag")?;
    let canary = leaf(&r, "canary")?;
    std::fs::write(&canary, b"canary")?;

    let private = leaf(&r, "private")?;
    mkdir_mode(&private, 0o700)?;
    let link = private.join("tag");
    std::os::unix::fs::symlink(&canary, &link)?;
    assert!(!helper_accepts("tag_file_ok", &link)?);
    assert_eq!(std::fs::read(&canary)?, b"canary");

    let real = private.join("real");
    std::fs::write(&real, b"")?;
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600))?;
    assert!(helper_accepts("tag_file_ok", &real)?);

    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o644))?;
    assert!(
        !helper_accepts("tag_file_ok", &real)?,
        "a group/other-readable tag file must be refused"
    );

    let open = leaf(&r, "open")?;
    mkdir_mode(&open, 0o755)?;
    let exposed = open.join("tag");
    std::fs::write(&exposed, b"")?;
    std::fs::set_permissions(&exposed, std::fs::Permissions::from_mode(0o600))?;
    assert!(
        !helper_accepts("tag_file_ok", &exposed)?,
        "a tag file outside a private directory must be refused"
    );
    Ok(())
}

#[test]
fn the_installer_routes_its_scratch_through_the_helpers() -> io::Result<()> {
    let script = std::fs::read_to_string(e2e_support::manifest_dir!().join("../../install.sh"))?;
    for needle in [
        "tag_file_ok \"$TAG_FILE\"",
        "trusted_tmp_base \"${TMPDIR:-/tmp}\" >/dev/null || die_tmp_base_refused",
        "scratch_base=\"$TMP_TRUSTED_BASE\"",
        "mktemp -d \"$scratch_base/ipe-install.XXXXXX\"",
        "private_dir_ok \"$tmp\"",
        "mktemp \"$IPE_HOME/.env.XXXXXX\"",
    ] {
        assert!(
            script.contains(needle),
            "install.sh must contain `{needle}`"
        );
    }
    assert!(
        !script.contains("mktemp -d)"),
        "install.sh must not create an unverified `mktemp -d` scratch dir"
    );
    Ok(())
}

/// The uid and primary gid the synthetic facts are judged against.
const ME: &str = "1000";
const MY_GID: &str = "1000";

#[test]
fn scratch_base_verdict_accepts_only_trusted_components() -> io::Result<()> {
    for (mode, owner, group) in [
        ("drwx------", ME, MY_GID),
        ("drwxr-xr-x", "0", "0"),
        ("drwxr-xr-x.", "0", "0"),
        ("drwxrwxrwt", "0", "0"),
        ("drwxrwxrwT", "0", "0"),
        ("drwxrwxr-x", ME, MY_GID),
    ] {
        assert!(
            verdict_accepts("scratch_base_verdict", &[mode, owner, group, ME, MY_GID])?,
            "{mode} {owner}:{group} must be accepted"
        );
        assert_eq!(
            base_reason(&[mode, owner, group, ME, MY_GID])?,
            "ok",
            "{mode} {owner}:{group} must carry the positive `ok` token"
        );
    }
    Ok(())
}

#[test]
fn scratch_base_verdict_refuses_every_untrusted_component_with_its_reason() -> io::Result<()> {
    for (mode, owner, group, reason, why) in [
        (
            "drwxr-xr-x",
            "1001",
            "1001",
            "foreign-owner",
            "a foreign owner",
        ),
        (
            "drwxrwxr-x",
            "0",
            MY_GID,
            "group-writable",
            "a group-writable root-owned directory",
        ),
        (
            "drwxrwxr-x",
            ME,
            "1001",
            "group-writable",
            "a group-writable directory in a foreign group",
        ),
        (
            "drwxrwxr-x+",
            ME,
            MY_GID,
            "acl",
            "an own-group-writable directory carrying an ACL",
        ),
        (
            "drwxrwxrwx",
            ME,
            MY_GID,
            "world-writable-not-sticky",
            "a non-sticky world-writable directory",
        ),
        (
            "drwxrwxrwx",
            "0",
            "0",
            "world-writable-not-sticky",
            "a non-sticky world-writable root directory",
        ),
        ("-rw-------", ME, MY_GID, "not-a-dir", "a regular file"),
        ("lrwxrwxrwx", ME, MY_GID, "symlink", "a symlink"),
        ("", ME, MY_GID, "empty-mode", "an empty mode"),
    ] {
        let args = [mode, owner, group, ME, MY_GID];
        assert!(
            !verdict_accepts("scratch_base_verdict", &args)?,
            "{why} ({mode} {owner}:{group}) must be refused"
        );
        assert_eq!(
            base_reason(&args)?,
            reason,
            "{why} ({mode} {owner}:{group}) must be refused as {reason}"
        );
    }
    let unknown = ["drwx------", "", "", "", ""];
    assert!(
        !verdict_accepts("scratch_base_verdict", &unknown)?,
        "an unknown identity must be refused"
    );
    assert_eq!(base_reason(&unknown)?, "unknown-identity");
    Ok(())
}

#[test]
fn scratch_base_verdict_refuses_empty_or_unexpected_reason_output() -> io::Result<()> {
    let trusted = ["drwx------", ME, MY_GID, ME, MY_GID];
    assert_eq!(
        helper_stdout("scratch_base_verdict \"$@\" && echo accepted", &trusted)?,
        b"accepted\n",
        "the unstubbed verdict must accept the trusted facts"
    );
    for (stub, why) in [
        ("scratch_base_reason() { :; }", "empty output"),
        ("scratch_base_reason() { return 1; }", "a failed reason"),
        (
            "scratch_base_reason() { echo garbage; }",
            "an unknown token",
        ),
        ("scratch_base_reason() { echo; }", "a bare newline"),
        (
            "scratch_base_reason() { echo okay; }",
            "a token merely starting with ok",
        ),
    ] {
        let body = format!("{stub}\nscratch_base_verdict \"$@\" && echo accepted");
        assert!(
            helper_stdout(&body, &trusted)?.is_empty(),
            "{why} from scratch_base_reason must refuse"
        );
    }

    let r = root("install-reason-token")?;
    let base = leaf(&r, "base")?;
    mkdir_mode(&base, 0o700)?;
    let base_arg = base.to_string_lossy().into_owned();
    for stub in [
        "scratch_base_reason() { :; }",
        "scratch_base_reason() { printf 'garbage\\033[2J'; }",
    ] {
        let body = format!("{stub}\n{REFUSAL_REPORT}");
        let (report, sentence) = refusal(&body, &[&base_arg])?;
        for needle in ["failed the private-scratch check", "[unknown]"] {
            assert!(
                sentence.contains(needle),
                "`{stub}` must refuse with `{needle}`, got `{report}`"
            );
        }
        assert!(
            !sentence.contains("garbage") && !sentence.contains('\u{1b}'),
            "the refusal must not echo an unknown token: `{sentence}`"
        );
    }
    Ok(())
}

#[test]
fn trusted_tmp_base_refuses_a_base_nested_too_deep() -> io::Result<()> {
    let r = root("install-too-deep")?;
    let mut deep = leaf(&r, "deep")?;
    for _ in 0..300 {
        deep.push("a");
    }
    std::fs::create_dir_all(&deep)?;
    let deep_arg = deep.to_string_lossy().into_owned();
    let (report, sentence) = refusal(REFUSAL_REPORT, &[&deep_arg])?;
    let mut lines = report.lines();
    assert!(lines.next().is_some(), "a too-deep base must be refused");
    assert_eq!(lines.next(), Some("too-deep"));
    for needle in ["nested too deep to verify", "[too-deep]"] {
        assert!(
            sentence.contains(needle),
            "the refusal `{sentence}` must name `{needle}`"
        );
    }
    Ok(())
}

#[test]
fn trusted_tmp_base_refuses_a_component_ls_cannot_describe() -> io::Result<()> {
    let r = root("install-unreadable")?;
    let base = leaf(&r, "base")?;
    mkdir_mode(&base, 0o700)?;
    let base_arg = base.to_string_lossy().into_owned();
    let body = format!("ls() {{ return 2; }}\n{REFUSAL_REPORT}");
    let (report, sentence) = refusal(&body, &[&base_arg])?;
    let mut lines = report.lines();
    assert!(lines.next().is_some(), "an unlistable base must be refused");
    assert_eq!(lines.next(), Some("unreadable"));
    for needle in ["it could not be listed", "[unreadable]"] {
        assert!(
            sentence.contains(needle),
            "the refusal `{sentence}` must name `{needle}`"
        );
    }
    Ok(())
}

#[test]
fn trusted_tmp_base_names_the_refused_ancestor_not_the_leaf() -> io::Result<()> {
    let r = root("install-refused-ancestor")?;
    let open = leaf(&r, "open")?;
    mkdir_mode(&open, 0o777)?;
    let nested = open.join("leaf");
    mkdir_mode(&nested, 0o700)?;
    let leaf_arg = nested.to_string_lossy().into_owned();
    let (report, sentence) = refusal(REFUSAL_REPORT, &[&leaf_arg])?;
    let open_physical = std::fs::canonicalize(&open)?.to_string_lossy().into_owned();
    let mut lines = report.lines();
    assert_eq!(
        lines.next(),
        Some(open_physical.as_str()),
        "the refused path must be the non-sticky ancestor"
    );
    assert_eq!(lines.next(), Some("world-writable-not-sticky"));
    for needle in [
        open_physical.as_str(),
        "mode drwxrwxrwx",
        "lacks the sticky bit",
        "[world-writable-not-sticky]",
        "Set TMPDIR to a directory you own with mode 700.",
    ] {
        assert!(
            sentence.contains(needle),
            "the refusal `{sentence}` must name `{needle}`"
        );
    }

    let missing = leaf(&r, "missing")?.to_string_lossy().into_owned();
    let report = String::from_utf8_lossy(&helper_stdout(REFUSAL_REPORT, &[&missing])?).into_owned();
    assert_eq!(report.lines().nth(1), Some("unresolvable"));

    let sticky = leaf(&r, "sticky")?;
    mkdir_mode(&sticky, 0o1777)?;
    let sticky_arg = sticky.to_string_lossy().into_owned();
    assert!(
        helper_stdout(REFUSAL_REPORT, &[&sticky_arg])?.is_empty(),
        "a trusted base must leave no refusal"
    );
    Ok(())
}

#[test]
fn tmp_base_refusal_names_an_unmapped_owner() -> io::Result<()> {
    let body = "TMP_REFUSED_PATH=/tmp TMP_REFUSED_OWNER=65534 TMP_REFUSED_MODE=drwxrwxrwt \
                TMP_REFUSED_REASON=foreign-owner; die_tmp_base_refused";
    let (_, sentence) = refusal(body, &[])?;
    for needle in ["owner uid 65534", "[foreign-owner]", "user namespace"] {
        assert!(
            sentence.contains(needle),
            "the refusal `{sentence}` must name `{needle}`"
        );
    }
    Ok(())
}

#[test]
fn the_refusal_escapes_control_bytes_in_printed_facts() -> io::Result<()> {
    let hostile_text = ["a\u{1b}[31mb\u{9b}c\u{7f}\u{e9}\r\u{1}z"];
    let escaped = helper_stdout("safe_text \"$1\"", &hostile_text)?;
    assert_eq!(
        String::from_utf8_lossy(&escaped),
        "a\\033[31mb\\302\\233c\\177\\303\\251\\015\\001z",
        "in the C locale C0, DEL and every byte >= 0x80 must print as octal escapes"
    );
    let utf8 = helper_output("safe_text \"$1\"", &hostile_text, "C.UTF-8")?.stdout;
    assert_eq!(
        String::from_utf8_lossy(&utf8),
        "a\\033[31mb\\302\\233c\\177\u{e9}\\015\\001z",
        "in a UTF-8 locale only a printable character may stay raw; C1 stays escaped"
    );
    // A raw C1 byte after another high byte is CSI on a Latin-1 terminal.
    let raw_body = "safe_text \"$(printf 'a\\240\\233[2J|\\340\\233')\"";
    for locale in ["C", "C.UTF-8"] {
        let raw = helper_output(raw_body, &[], locale)?.stdout;
        assert_eq!(
            String::from_utf8_lossy(&raw),
            "a\\240\\233[2J|\\340\\233",
            "a C1 byte must be escaped whatever byte precedes it ({locale})"
        );
        assert!(
            raw.iter().all(|byte| (0x20..0x7f).contains(byte)),
            "safe_text must print printable ASCII only for invalid UTF-8 ({locale})"
        );
    }

    let r = root("install-escape")?;
    let hostile = r.path().join("open\u{1b}[31m");
    mkdir_mode(&hostile, 0o777)?;
    let hostile_arg = hostile.to_string_lossy().into_owned();
    let sentence = helper_output(REFUSAL_REPORT, &[&hostile_arg], "C")?.stderr;
    assert!(
        !sentence.contains(&0x1b),
        "the refusal must not carry a raw ESC byte"
    );
    assert!(
        String::from_utf8_lossy(&sentence).contains("open\\033[31m"),
        "the refusal must print the ESC byte escaped"
    );
    Ok(())
}

#[test]
fn scratch_private_verdict_refuses_foreign_or_open_entries() -> io::Result<()> {
    const DIR: &str = "d???------*";
    const FILE: &str = "-???------*";
    assert!(verdict_accepts(
        "scratch_private_verdict",
        &["drwx------", ME, ME, DIR]
    )?);
    assert!(verdict_accepts(
        "scratch_private_verdict",
        &["drwx------.", ME, ME, DIR]
    )?);
    assert!(verdict_accepts(
        "scratch_private_verdict",
        &["-rw-------", ME, ME, FILE]
    )?);
    for (mode, owner, pattern, why) in [
        ("drwx------", "1001", DIR, "a foreign-owned directory"),
        ("drwxr-x---", ME, DIR, "a group-readable directory"),
        ("drwx-----x", ME, DIR, "an other-searchable directory"),
        (
            "-rw-------",
            ME,
            DIR,
            "a file where a directory is required",
        ),
        (
            "drwx------",
            ME,
            FILE,
            "a directory where a file is required",
        ),
        ("-rw-r--r--", ME, FILE, "a group/other-readable file"),
        ("-rw-------", "1001", FILE, "a foreign-owned file"),
    ] {
        assert!(
            !verdict_accepts("scratch_private_verdict", &[mode, owner, ME, pattern])?,
            "{why} ({mode} {owner}) must be refused"
        );
    }
    assert!(
        !verdict_accepts("scratch_private_verdict", &["drwx------", "", "", DIR])?,
        "an unknown identity must be refused"
    );
    Ok(())
}

#[test]
fn trusted_tmp_base_refuses_a_non_directory_or_missing_base() -> io::Result<()> {
    let r = root("install-nondir")?;
    let file = leaf(&r, "file")?;
    std::fs::write(&file, b"")?;
    assert!(!helper_accepts("trusted_tmp_base", &file)?);
    assert!(!helper_accepts("trusted_tmp_base", &leaf(&r, "missing")?)?);
    Ok(())
}
