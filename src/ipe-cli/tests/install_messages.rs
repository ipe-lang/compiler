//! Refusal tests for the installer's terminal messages.
//!
//! A message's fixed text and its values are separate arguments: every write
//! `install.sh` makes to the terminal goes through the message-helper block,
//! whose helpers take a single-quoted format plus values and escape each value
//! through `safe_text`. These tests drive the whole script with hostile
//! environment values, drive `safe_text` and the release-tag parser directly,
//! and scan the script statically so that any other message shape is refused.
#![cfg(unix)]

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::time::Duration;

use ipe_sandbox::scratch::{LeafName, ScratchDir};

const BEGIN: &str = "# >>> message helpers";
const END: &str = "# <<< message helpers";
const PARSERS: (&str, &str) = ("# >>> input parsers", "# <<< input parsers");

/// The helpers whose first argument is a message format.
const HELPERS: [&str; 8] = [
    "die",
    "info",
    "say",
    "prompt",
    "stage_start",
    "stage_ok",
    "stage_fail",
    "banner",
];

/// The block-internal helpers, which print text they do not escape.
const INTERNAL: [&str; 5] = [
    "render",
    "msg_text",
    "msg_style",
    "stage_settle_ok",
    "stage_settle_fail",
];

/// The words after which the next word is still in command position.
const KEYWORDS: [&str; 10] = [
    "{", "}", "!", "if", "then", "else", "elif", "do", "while", "until",
];

/// The code points >= U+0080 `safe_text` escapes: C1 (Cc), Cf, Zl and Zp.
const ESCAPED_RANGES: &[(u32, u32)] = &[
    (0x80, 0x9F),
    (0xAD, 0xAD),
    (0x600, 0x605),
    (0x61C, 0x61C),
    (0x6DD, 0x6DD),
    (0x70F, 0x70F),
    (0x890, 0x891),
    (0x8E2, 0x8E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

fn installer_path() -> PathBuf {
    e2e_support::manifest_dir!().join("../../install.sh")
}

fn installer_script() -> io::Result<String> {
    std::fs::read_to_string(installer_path())
}

/// The `(begin, end)` marked block of `script`, markers included.
fn marked<'s>(script: &'s str, (begin, end): (&str, &str)) -> io::Result<&'s str> {
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

/// The output of `sh` running `body` after the message and input-parser
/// blocks in `locale`, with `args` as `$@`.
fn run_block(body: &str, args: &[&OsStr], locale: &str) -> io::Result<Output> {
    block_command(body, locale)?.args(args).output()
}

/// The `sh` command `run_block` runs, before its `$@`.
fn block_command(body: &str, locale: &str) -> io::Result<Command> {
    let script = installer_script()?;
    let program = format!(
        "{}\n{}\n{body}\n",
        marked(&script, (BEGIN, END))?,
        marked(&script, PARSERS)?
    );
    let mut command = Command::new("sh");
    command
        .env("LC_ALL", locale)
        .arg("-c")
        .arg(program)
        .arg("sh");
    Ok(command)
}

/// `safe_text` of each input in `locale`, one output per input.
fn safe_text_each(inputs: &[&[u8]], locale: &str) -> io::Result<Vec<Vec<u8>>> {
    let args: Vec<&OsStr> = inputs
        .iter()
        .map(|bytes| OsStr::from_bytes(bytes))
        .collect();
    let output = run_block(
        "for a in \"$@\"; do safe_text \"$a\"; printf '\\n'; done",
        &args,
        locale,
    )?;
    Ok(output
        .stdout
        .split(|byte| *byte == b'\n')
        .take(inputs.len())
        .map(<[u8]>::to_vec)
        .collect())
}

/// `bytes` written as the `\ooo` octal escapes `safe_text` prints.
fn octal(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        out.push('\\');
        for shift in [6, 3, 0] {
            out.push(char::from(b'0' + ((byte >> shift) & 7)));
        }
    }
    out
}

/// Whether `safe_text` must escape the code point `cp` (>= U+0080).
fn escaped_code_point(cp: u32) -> bool {
    ESCAPED_RANGES
        .iter()
        .any(|&(lo, hi)| (lo..=hi).contains(&cp))
}

/// `ESCAPED_RANGES` spelled as the shell range list.
fn range_list() -> String {
    ESCAPED_RANGES
        .iter()
        .map(|&(lo, hi)| {
            if lo == hi {
                format!("{lo:X}")
            } else {
                format!("{lo:X}-{hi:X}")
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Each escaped range's first and last code point, and its neighbours.
///
/// A first or last code point is paired with `true` (escaped); the neighbour
/// one step outside, when it is not itself escaped, with `false` (raw under
/// UTF-8).
fn range_cases() -> Vec<(char, bool)> {
    let mut cases = Vec::new();
    for &(lo, hi) in ESCAPED_RANGES {
        for cp in [lo, hi] {
            cases.extend(char::from_u32(cp).map(|c| (c, true)));
        }
        for cp in [lo.checked_sub(1), hi.checked_add(1)].into_iter().flatten() {
            if cp >= 0x80 && !escaped_code_point(cp) {
                cases.extend(char::from_u32(cp).map(|c| (c, false)));
            }
        }
    }
    cases
}

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

/// The outcome of one whole-script installer run.
struct Run {
    /// The exit status, or `None` when the run timed out and was killed.
    status: Option<ExitStatus>,
    /// What reached stdout, which the installer never writes to.
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    /// Every argument line the `curl` stub was called with.
    curl_log: Vec<u8>,
}

/// Run `sh install.sh` under the scratch root `r`.
///
/// The environment is cleared: a private `HOME`, `LC_ALL=C`, a `PATH` whose
/// `curl` is a stub that logs its arguments, prints them to stdout and exits
/// 7, then `env` on top.
/// Stdin is empty; a run past 30 s is killed.
fn run_installer(r: &ScratchDir, env: &[(&str, &OsStr)]) -> io::Result<Run> {
    let bin = leaf(r, "bin")?;
    std::fs::create_dir(&bin)?;
    let curl = bin.join("curl");
    std::fs::write(
        &curl,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >>\"$CURL_LOG\"\nprintf 'curl %s\\n' \"$*\"\nexit 7\n",
    )?;
    std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755))?;
    let home = leaf(r, "home")?;
    mkdir_mode(&home, 0o700)?;
    let log = leaf(r, "curl.log")?;
    let stderr_path = leaf(r, "stderr")?;
    let stdout_path = leaf(r, "stdout")?;
    let mut path = OsString::from(bin.as_os_str());
    path.push(":/usr/bin:/bin");

    let mut child = Command::new("sh")
        .arg(installer_path())
        .env_clear()
        .env("PATH", path)
        .env("HOME", home)
        .env("CURL_LOG", &log)
        .env("LC_ALL", "C")
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(File::create(&stdout_path)?)
        .stderr(File::create(&stderr_path)?)
        .spawn()?;
    let mut status = None;
    let finished = e2e_support::wait_for(Duration::from_secs(30), || {
        status = child.try_wait().ok().flatten();
        status.is_some()
    });
    if !finished {
        child.kill()?;
        child.wait()?;
    }
    let curl_log = match std::fs::read(log) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error),
    };
    Ok(Run {
        status,
        stdout: std::fs::read(stdout_path)?,
        stderr: std::fs::read(stderr_path)?,
        curl_log,
    })
}

/// Assert that `run` refused safely and printed `escaped`.
///
/// Safely: exit 1, before any network call, with nothing on stdout and no raw
/// ESC or BEL byte.
fn assert_refused_escaped(run: &Run, escaped: &str, why: &str) {
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        run.stdout.is_empty(),
        "{why}: the installer must write nothing to stdout, got {}",
        String::from_utf8_lossy(&run.stdout)
    );
    assert_eq!(
        run.status.and_then(|status| status.code()),
        Some(1),
        "{why}: the installer must exit 1; stderr: {stderr}"
    );
    assert!(
        !run.stderr.iter().any(|byte| matches!(byte, 0x1b | 0x07)),
        "{why}: stderr must carry no raw ESC or BEL byte: {stderr}"
    );
    assert!(
        stderr.contains(escaped),
        "{why}: stderr must print `{escaped}`: {stderr}"
    );
    assert!(
        run.curl_log.is_empty(),
        "{why}: the refusal must come before any network call, got curl {}",
        String::from_utf8_lossy(&run.curl_log)
    );
}

#[test]
fn install_dir_with_osc_is_refused_and_escaped() -> io::Result<()> {
    let r = root("install-msg-dir")?;
    let dir = OsStr::new("/x\u{1b}]0;x\u{7}");
    let run = run_installer(&r, &[("IPE_INSTALL_DIR", dir)])?;
    assert_refused_escaped(&run, "/x\\033]0;x\\007", "an OSC in IPE_INSTALL_DIR");
    Ok(())
}

#[test]
fn tmpdir_with_osc_is_refused_and_escaped() -> io::Result<()> {
    let r = root("install-msg-tmpdir")?;
    let hostile = r.path().join("a\u{1b}]0;x\u{7}");
    mkdir_mode(&hostile, 0o777)?;
    let run = run_installer(&r, &[("TMPDIR", hostile.as_os_str())])?;
    assert_refused_escaped(&run, "a\\033]0;x\\007", "an OSC in TMPDIR");
    assert!(
        String::from_utf8_lossy(&run.stderr).contains("Refusing the temp directory"),
        "a non-sticky world-writable TMPDIR must be refused at the boundary"
    );
    Ok(())
}

#[test]
fn valid_utf8_prints_raw_only_in_utf8_locale() -> io::Result<()> {
    for (locale, shown) in [("C.UTF-8", "caf\u{e9}-open"), ("C", "caf\\303\\251-open")] {
        let r = root("install-msg-utf8")?;
        let open = r.path().join("caf\u{e9}-open");
        mkdir_mode(&open, 0o777)?;
        let run = run_installer(
            &r,
            &[("TMPDIR", open.as_os_str()), ("LC_ALL", OsStr::new(locale))],
        )?;
        assert_refused_escaped(&run, shown, locale);
    }
    Ok(())
}

#[test]
fn version_tag_outside_grammar_is_refused_before_network() -> io::Result<()> {
    for (tag, shown) in [("v1/../../x", "v1/../../x"), ("v1\u{1b}[2J", "v1\\033[2J")] {
        let r = root("install-msg-tag")?;
        let run = run_installer(&r, &[("IPE_VERSION", OsStr::new(tag))])?;
        assert_refused_escaped(&run, shown, tag);
        assert!(
            String::from_utf8_lossy(&run.stderr).contains("is not a version tag"),
            "IPE_VERSION `{shown}` must be refused as a malformed tag"
        );
    }
    Ok(())
}

#[test]
fn installer_stdout_never_reaches_the_terminal() -> io::Result<()> {
    let r = root("install-msg-stdout")?;
    let run = run_installer(&r, &[("IPE_VERSION", OsStr::new("v0.0.1"))])?;
    assert_eq!(
        run.status.and_then(|status| status.code()),
        Some(2),
        "a tag with no prebuilt binary must end in die_no_prebuilt; stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        !run.curl_log.is_empty(),
        "the run must reach the binary check, whose `curl` prints to stdout"
    );
    assert!(
        run.stdout.is_empty(),
        "a command's stdout must go to /dev/null, got {}",
        String::from_utf8_lossy(&run.stdout)
    );
    Ok(())
}

#[test]
fn release_tag_ok_table() -> io::Result<()> {
    let longest = format!("v1.{}", "0".repeat(125));
    let too_long = format!("v1.{}", "0".repeat(126));
    let cases: [(&str, bool); 13] = [
        ("v0.2.6", true),
        ("ipe-v1.0.0-rc.1", true),
        ("v1.0+build.7", true),
        (longest.as_str(), true),
        ("", false),
        ("1.0", false),
        ("v1/2", false),
        ("v1?x", false),
        ("v1#", false),
        ("v1%2f", false),
        ("v1 2", false),
        ("v1\u{e9}", false),
        (too_long.as_str(), false),
    ];
    let args: Vec<&OsStr> = cases.iter().map(|(tag, _)| OsStr::new(tag)).collect();
    let output = run_block(
        "for a in \"$@\"; do if release_tag_ok \"$a\"; then echo y; else echo n; fi; done",
        &args,
        "C",
    )?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let verdicts: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        verdicts.len(),
        cases.len(),
        "one verdict per tag: {verdicts:?}"
    );
    for ((tag, accepted), verdict) in cases.iter().zip(&verdicts) {
        let expected = if *accepted { "y" } else { "n" };
        assert_eq!(
            *verdict,
            expected,
            "release_tag_ok `{tag}` ({} bytes) must {}",
            tag.len(),
            if *accepted { "accept" } else { "refuse" }
        );
    }
    Ok(())
}

#[test]
fn c1_and_invalid_bytes_are_escaped_in_utf8_locale() -> io::Result<()> {
    let script = installer_script()?;
    let shell_list = script
        .split_once("nr = split(\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(list, _)| list);
    assert_eq!(
        shell_list,
        Some(range_list().as_str()),
        "the safe_text range list must equal ESCAPED_RANGES"
    );

    let invalid: [&[u8]; 6] = [
        b"\xc2\x9b",
        b"\x9b",
        b"\xc0\xaf",
        b"\xed\xa0\x80",
        b"\xf4\x90\x80\x80",
        b"\xe2\x82",
    ];
    let outputs = safe_text_each(&invalid, "C.UTF-8")?;
    assert_eq!(outputs.len(), invalid.len(), "one output per input");
    for (input, output) in invalid.iter().zip(&outputs) {
        assert_eq!(
            String::from_utf8_lossy(output),
            octal(input),
            "C1, malformed, overlong, surrogate, out-of-range and truncated \
             sequences must print byte by byte as escapes"
        );
    }

    let cases = range_cases();
    let encoded: Vec<Vec<u8>> = cases
        .iter()
        .map(|&(c, _)| String::from(c).into_bytes())
        .collect();
    let inputs: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
    for locale in ["C.UTF-8", "C"] {
        let outputs = safe_text_each(&inputs, locale)?;
        assert_eq!(outputs.len(), cases.len(), "one output per code point");
        for (((c, escaped), bytes), output) in cases.iter().zip(&encoded).zip(&outputs) {
            let expected = if *escaped || locale == "C" {
                octal(bytes).into_bytes()
            } else {
                bytes.clone()
            };
            assert_eq!(
                output,
                &expected,
                "U+{:04X} in {locale} must print {}",
                u32::from(*c),
                if *escaped { "escaped" } else { "raw" }
            );
        }
    }
    Ok(())
}

#[test]
fn safe_text_is_independent_of_awk_character_semantics() -> io::Result<()> {
    let r = root("awk-bytes")?;
    let bin = leaf(&r, "bin")?;
    std::fs::create_dir(&bin)?;
    let log = leaf(&r, "awk-input")?;
    let found = Command::new("sh").args(["-c", "command -v awk"]).output()?;
    let real_awk = OsStr::from_bytes(found.stdout.trim_ascii_end()).to_owned();
    assert!(!real_awk.is_empty(), "the test needs an awk on PATH");
    let fake = bin.join("awk");
    std::fs::write(
        &fake,
        "#!/bin/sh\ntee -a \"$AWK_LOG\" | \"$REAL_AWK\" \"$@\"\n",
    )?;
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))?;
    let output = block_command("PATH=\"$FAKE_BIN:$PATH\"; safe_text \"$1\"", "C.UTF-8")?
        .env("FAKE_BIN", &bin)
        .env("AWK_LOG", &log)
        .env("REAL_AWK", &real_awk)
        .arg("\u{c3}\u{90}\u{e9}\u{202e}")
        .output()?;
    assert!(output.status.success(), "safe_text failed: {output:?}");
    let fed = std::fs::read(&log)?;
    assert!(!fed.is_empty(), "safe_text must run awk from PATH");
    assert!(
        fed.is_ascii(),
        "awk must see the text as byte numbers, never as raw bytes it may \
         decode as characters: {fed:?}"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "\u{c3}\\302\\220\u{e9}\\342\\200\\256",
        "printable characters stay raw and C1/Cf code points escape"
    );
    Ok(())
}

#[test]
fn backslash_and_style_token_in_value_stay_literal() -> io::Result<()> {
    let output = run_block(
        "C_BOLD=BOLD; render 'x @B@%s|%s' \"$1\" \"$2\"",
        &[OsStr::new("a\\033@B@"), OsStr::new("%s%n")],
        "C",
    )?;
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "x BOLDa\\\\033@B@|%s%n",
        "a value's backslash must double and its style token and directives stay literal"
    );
    assert!(
        !output.stdout.contains(&0x1b),
        "a value must never expand into an escape byte"
    );
    Ok(())
}

/// How a shell word is quoted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unit {
    /// Exactly one `'…'` segment.
    Single,
    /// Exactly one `"…"` segment.
    Double,
    /// Anything else: bare text, an expansion, or several segments.
    Bare,
}

/// A shell word: its source text, its quoting, and the bodies of the command
/// substitutions it contains.
#[derive(Debug)]
struct Word {
    text: String,
    unit: Unit,
    substitutions: Vec<String>,
}

/// A control operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sep {
    /// `|`: the command's stdout feeds the next command.
    Pipe,
    /// `(`.
    Open,
    /// `)`.
    Close,
    /// `;;`, which ends a `case` arm.
    CaseArm,
    /// A newline, `;`, `&`, `&&` or `||`.
    End,
}

/// One lexed shell token.
#[derive(Debug)]
enum Token {
    Word(Word),
    Sep(Sep),
    /// A redirection operator (with any fd prefix) and its target.
    Redirect {
        op: String,
        target: String,
    },
    /// A here-document body, and whether its delimiter was unquoted (so the
    /// body expands `$(…)` and `` `…` ``).
    Heredoc {
        expands: bool,
        body: String,
    },
    /// Input the lexer cannot follow: an unclosed quote, substitution or
    /// here-document. The scan refuses it rather than guess.
    Unterminated,
}

/// Whether `c` ends a word.
const fn ends_word(c: char) -> bool {
    matches!(
        c,
        ' ' | '\t' | '\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>'
    )
}

/// A here-document whose body starts after the current line.
struct Pending {
    delimiter: String,
    strip_tabs: bool,
    expands: bool,
}

/// A POSIX-sh lexer precise enough for the message scan. A `\`-newline is a
/// line continuation outside single quotes and comments, as in the shell.
struct Lexer {
    chars: Vec<char>,
    at: usize,
    pending: Vec<Pending>,
    broken: bool,
}

impl Lexer {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at + ahead).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.at += 1;
        }
        c
    }

    fn bump_if(&mut self, want: char) -> bool {
        let hit = self.peek() == Some(want);
        if hit {
            self.at += 1;
        }
        hit
    }

    /// Whether a `\`-newline continuation starts here; consume it if so.
    fn continuation(&mut self) -> bool {
        let hit = self.peek() == Some('\\') && self.peek_at(1) == Some('\n');
        if hit {
            self.at += 2;
        }
        hit
    }

    fn tokens(mut self) -> Vec<Token> {
        let mut tokens = Vec::new();
        while let Some(c) = self.peek() {
            if self.continuation() {
                continue;
            }
            match c {
                ' ' | '\t' => self.at += 1,
                '\n' => {
                    self.at += 1;
                    tokens.push(Token::Sep(Sep::End));
                    self.heredoc_bodies(&mut tokens);
                }
                ';' => {
                    self.at += 1;
                    let arm = self.bump_if(';');
                    tokens.push(Token::Sep(if arm { Sep::CaseArm } else { Sep::End }));
                }
                '&' => {
                    self.at += 1;
                    self.bump_if('&');
                    tokens.push(Token::Sep(Sep::End));
                }
                '|' => {
                    self.at += 1;
                    let or = self.bump_if('|');
                    tokens.push(Token::Sep(if or { Sep::End } else { Sep::Pipe }));
                }
                '(' => {
                    self.at += 1;
                    tokens.push(Token::Sep(Sep::Open));
                }
                ')' => {
                    self.at += 1;
                    tokens.push(Token::Sep(Sep::Close));
                }
                '#' => {
                    while self.peek().is_some_and(|n| n != '\n') {
                        self.at += 1;
                    }
                }
                '<' | '>' => tokens.push(self.redirect(String::new())),
                _ => {
                    let word = self.word();
                    let fd = word.unit == Unit::Bare
                        && !word.text.is_empty()
                        && word.text.bytes().all(|b| b.is_ascii_digit());
                    if fd && matches!(self.peek(), Some('<' | '>')) {
                        tokens.push(self.redirect(word.text));
                    } else {
                        tokens.push(Token::Word(word));
                    }
                }
            }
        }
        if !self.pending.is_empty() {
            self.broken = true;
        }
        if self.broken {
            tokens.push(Token::Unterminated);
        }
        tokens
    }

    /// Read the bodies of the here-documents opened on the line just ended.
    fn heredoc_bodies(&mut self, tokens: &mut Vec<Token>) {
        for doc in std::mem::take(&mut self.pending) {
            let mut body = String::new();
            let mut closed = false;
            while self.peek().is_some() {
                let mut line = String::new();
                while let Some(c) = self.bump() {
                    if c == '\n' {
                        break;
                    }
                    line.push(c);
                }
                let compared = if doc.strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    line.as_str()
                };
                if compared == doc.delimiter {
                    closed = true;
                    break;
                }
                body.push_str(&line);
                body.push('\n');
            }
            if !closed {
                self.broken = true;
            }
            tokens.push(Token::Heredoc {
                expands: doc.expands,
                body,
            });
        }
    }

    /// Lex a redirection whose operator starts at the next char, after the fd
    /// prefix `op`.
    fn redirect(&mut self, mut op: String) -> Token {
        let mut heredoc = false;
        if let Some(first) = self.bump() {
            op.push(first);
            if first == '<' && self.bump_if('<') {
                op.push('<');
                heredoc = true;
                if self.bump_if('-') {
                    op.push('-');
                }
            } else if first == '>' && self.bump_if('>') {
                op.push('>');
            }
            if let Some(n) = self
                .peek()
                .filter(|&n| !heredoc && matches!(n, '&' | '|' | '>'))
            {
                self.at += 1;
                op.push(n);
            }
        }
        while self.peek().is_some_and(|n| n == ' ' || n == '\t') || self.continuation() {
            if !self.continuation() {
                self.at += 1;
            }
        }
        let target = if self.peek().is_some_and(|n| !ends_word(n)) {
            self.word().text
        } else {
            String::new()
        };
        if heredoc {
            let delimiter: String = target
                .chars()
                .filter(|c| !matches!(c, '\'' | '"' | '\\'))
                .collect();
            if delimiter.is_empty() {
                self.broken = true;
            }
            self.pending.push(Pending {
                delimiter,
                strip_tabs: op.ends_with('-'),
                expands: !target.contains(['\'', '"', '\\']),
            });
        }
        Token::Redirect { op, target }
    }

    /// Lex one word starting at the next char.
    fn word(&mut self) -> Word {
        let mut text = String::new();
        let mut substitutions = Vec::new();
        let mut segments = 0_usize;
        let mut quote = Unit::Bare;
        let mut bare = false;
        while self.peek().is_some_and(|n| !ends_word(n)) {
            if self.continuation() {
                continue;
            }
            let Some(c) = self.bump() else { break };
            text.push(c);
            match c {
                '\'' => {
                    self.single(&mut text);
                    segments += 1;
                    quote = Unit::Single;
                }
                '"' => {
                    self.double(&mut text, &mut substitutions);
                    segments += 1;
                    quote = Unit::Double;
                }
                '\\' => {
                    bare = true;
                    text.extend(self.bump());
                }
                '$' => {
                    bare = true;
                    self.dollar(&mut text, &mut substitutions);
                }
                '`' => {
                    bare = true;
                    self.backtick(&mut text, &mut substitutions);
                }
                _ => bare = true,
            }
        }
        let unit = if !bare && segments == 1 {
            quote
        } else {
            Unit::Bare
        };
        Word {
            text,
            unit,
            substitutions,
        }
    }

    /// Copy the rest of a `'…'` segment, closing quote included.
    fn single(&mut self, out: &mut String) {
        while let Some(c) = self.bump() {
            out.push(c);
            if c == '\'' {
                return;
            }
        }
        self.broken = true;
    }

    /// Copy the rest of a `"…"` segment, closing quote included, recording
    /// its command substitutions.
    fn double(&mut self, out: &mut String, substitutions: &mut Vec<String>) {
        loop {
            if self.continuation() {
                continue;
            }
            let Some(c) = self.bump() else { break };
            out.push(c);
            match c {
                '"' => return,
                '\\' => out.extend(self.bump()),
                '$' => self.dollar(out, substitutions),
                '`' => self.backtick(out, substitutions),
                _ => {}
            }
        }
        self.broken = true;
    }

    /// Copy the expansion after a `$`: `$((…))`, `$(…)` (recorded as a
    /// command substitution) or `${…}` (whose own substitutions are
    /// recorded); a plain `$name` is left to the caller.
    fn dollar(&mut self, out: &mut String, substitutions: &mut Vec<String>) {
        if self.bump_if('(') {
            out.push('(');
            if self.bump_if('(') {
                out.push('(');
                self.nested(out, ')', true, substitutions);
                if self.bump_if(')') {
                    out.push(')');
                } else {
                    self.broken = true;
                }
            } else {
                let start = out.len();
                // The body is lexed again as a whole, so its own
                // substitutions are found there.
                self.nested(out, ')', false, &mut Vec::new());
                let end = out.len().saturating_sub(1);
                substitutions.push(out.get(start..end).unwrap_or_default().to_owned());
            }
        } else if self.bump_if('{') {
            out.push('{');
            self.nested(out, '}', false, substitutions);
        }
    }

    /// Copy the rest of a `` `…` `` command substitution and record its body.
    fn backtick(&mut self, out: &mut String, substitutions: &mut Vec<String>) {
        let start = out.len();
        let mut closed = false;
        while let Some(c) = self.bump() {
            out.push(c);
            if c == '`' {
                closed = true;
                break;
            }
            if c == '\\' {
                out.extend(self.bump());
            }
        }
        if !closed {
            self.broken = true;
        }
        let end = out.len().saturating_sub(1);
        substitutions.push(out.get(start..end).unwrap_or_default().to_owned());
    }

    /// Copy up to and including the `close` that balances an already-copied
    /// opener, honouring quotes, comments and nested groups, and recording
    /// the substitutions inside. A here-document inside a command
    /// substitution is refused: its body is not shell syntax, so copying it
    /// as such could misplace the substitution's end. `arithmetic` marks a
    /// `$((…))`, where `<<` is a shift.
    fn nested(
        &mut self,
        out: &mut String,
        close: char,
        arithmetic: bool,
        substitutions: &mut Vec<String>,
    ) {
        loop {
            if self.continuation() {
                continue;
            }
            let prev = out.chars().next_back();
            let Some(c) = self.bump() else { break };
            if c == '#'
                && close == ')'
                && !arithmetic
                && prev.is_none_or(|p| matches!(p, ' ' | '\t' | '\n' | ';' | '&' | '|' | '('))
            {
                while self.peek().is_some_and(|n| n != '\n') {
                    self.at += 1;
                }
                continue;
            }
            out.push(c);
            if c == close {
                return;
            }
            if c == '<' && close == ')' && !arithmetic && self.peek() == Some('<') {
                self.broken = true;
            }
            match c {
                '\\' => out.extend(self.bump()),
                '\'' => self.single(out),
                '"' => self.double(out, substitutions),
                '`' => self.backtick(out, substitutions),
                '$' => self.dollar(out, substitutions),
                '(' if close == ')' => self.nested(out, ')', arithmetic, substitutions),
                '{' if close == '}' => self.nested(out, '}', false, substitutions),
                _ => {}
            }
        }
        self.broken = true;
    }
}

/// Lex `source` as shell tokens.
fn lex(source: &str) -> Vec<Token> {
    Lexer {
        chars: source.chars().collect(),
        at: 0,
        pending: Vec::new(),
        broken: false,
    }
    .tokens()
}

/// The shell builtins that write to stdout.
const WRITERS: [&str; 3] = ["printf", "echo", "cat"];

/// The functions outside the message block whose stdout is their return
/// value: each prints only inside its own body, and every call is captured or
/// redirected.
const VALUE_PRINTERS: [&str; 2] = ["scratch_base_reason", "trusted_tmp_base"];

/// The commands that run text the scan cannot see.
const OPAQUE: [&str; 6] = ["eval", "alias", "builtin", ".", "source", "function"];

/// The commands that run another command or program text the scan cannot
/// see: shells, wrappers that exec their arguments, and script interpreters.
const RUNNERS: [&str; 27] = [
    "sh", "bash", "dash", "ash", "ksh", "mksh", "zsh", "busybox", "env", "exec", "xargs", "nohup",
    "nice", "timeout", "time", "stdbuf", "setsid", "chroot", "flock", "sudo", "doas", "su", "perl",
    "python", "python3", "ruby", "node",
];

/// The commands the installer runs outside the message block, an allowlist:
/// none runs another command by its plain use, and a terminal path among
/// their arguments is a `/dev/` word `names_device` refuses. Every other
/// command name must be a function the installer or its message block
/// defines; `cargo` is allowed only as `cargo version`. Options that make one
/// of these run a program (GNU `sed`'s `e`, `tar --to-command`) are not
/// parsed.
const COMMANDS: [&str; 43] = [
    "fi",
    "done",
    "for",
    "return",
    "break",
    "exit",
    "export",
    ":",
    "true",
    "read",
    "[",
    "test",
    "cd",
    "pwd",
    "wait",
    "kill",
    "sleep",
    "uname",
    "id",
    "ls",
    "readlink",
    "dirname",
    "basename",
    "date",
    "mkdir",
    "mktemp",
    "rm",
    "mv",
    "cp",
    "chmod",
    "install",
    "tar",
    "unzip",
    "sha256sum",
    "shasum",
    "cut",
    "head",
    "tail",
    "tr",
    "wc",
    "sed",
    "grep",
    "curl",
];

/// The one shell the installer runs: rustup-init, read from the pipe on its
/// stdin, with `-y` for its own prompt.
const RUSTUP_SHELL: [&str; 4] = ["sh", "-s", "--", "-y"];

/// The one command whose output `RUSTUP_SHELL` may run: rustup's own
/// installer, fetched over HTTPS only.
const RUSTUP_FETCH: [&str; 6] = [
    "curl",
    "--proto",
    "'=https'",
    "--tlsv1.2",
    "-sSf",
    "https://sh.rustup.rs",
];

/// The line that opens the group holding the whole installer, right after
/// `set -eu`.
const GUARD_OPEN: &str = "{";

/// The installer's last line: the group's stdout goes to `/dev/null`, so only
/// what the message helpers write to stderr reaches the terminal.
const GUARD_CLOSE: &str = "} >/dev/null";

/// The variable file targets the installer writes, each a regular file it
/// owns.
///
/// - `"$TAG_FILE"`: `ipe upgrade`'s tag file, checked by `tag_file_ok`.
/// - `"$dl_dest"`: the download destination inside the private scratch dir.
/// - `"$tmp/curl.rc"`: the download's exit code, inside the same dir.
/// - `"$wm_tmp"`: `mktemp` under `IPE_HOME`.
/// - `"$RC_FILE"`: the shell rc file, checked by `refuse_symlink_escape`.
const FILE_TARGETS: [&str; 5] = [
    "\"$TAG_FILE\"",
    "\"$dl_dest\"",
    "\"$tmp/curl.rc\"",
    "\"$wm_tmp\"",
    "\"$RC_FILE\"",
];

/// The one file the installer sources, on the user's say-so: rustup's own
/// `env` script, which puts cargo on `PATH`.
const SOURCED: &str = "\"$HOME/.cargo/env\"";

/// What the message scan found.
#[derive(Debug, Default)]
struct Scan {
    /// The message-helper calls it checked.
    calls: usize,
    /// Every refused shape, described.
    violations: Vec<String>,
    /// The functions the scanned text defines outside the message block.
    defined: Vec<String>,
    /// The command names it runs that are neither `COMMANDS`, a helper, nor
    /// handled by name: each must be one of `defined`.
    called: Vec<String>,
}

/// Scan `script` for message shapes outside the helper contract.
///
/// Its message block must appear exactly once. Outside it, every
/// message-helper call must take a single-quoted format plus one double-quoted
/// value per `%s`, and nothing may write to the terminal: no stderr or
/// `/dev/tty` redirection, and no stdout write that is not captured, piped
/// into a redirected command, or redirected to a file.
fn scan_script(script: &str) -> Scan {
    scan_script_with(script, true)
}

/// `scan_script`, with the check that every command is known or defined
/// switched by `check_commands`, so a fixture can prove the other rules refuse
/// it on their own.
fn scan_script_with(script: &str, check_commands: bool) -> Scan {
    let mut scan = Scan::default();
    let script = match guarded_body(script) {
        Ok(body) => body,
        Err(why) => {
            scan.violations.push(why);
            script
        }
    };
    let once = script.matches(BEGIN).count() == 1 && script.matches(END).count() == 1;
    let (outside, block) = match (script.find(BEGIN), script.find(END)) {
        (Some(begin), Some(end)) if once && begin < end => (
            format!(
                "{}{}",
                script.get(..begin).unwrap_or_default(),
                script.get(end + END.len()..).unwrap_or_default()
            ),
            script.get(begin..end).unwrap_or_default(),
        ),
        _ => {
            scan.violations.push(format!(
                "the `{BEGIN}` and `{END}` markers must each appear once, in order"
            ));
            (script.to_owned(), "")
        }
    };
    let reserved = block_words(block);
    scan_source(&outside, false, &reserved, &mut scan);
    if !check_commands {
        return scan;
    }
    let block_defined = block_functions(block);
    let unknown: Vec<String> = scan
        .called
        .iter()
        .filter(|name| !scan.defined.contains(name) && !block_defined.contains(name))
        .map(|name| {
            format!(
                "`{name}` is neither a command the scan knows nor a function the installer defines"
            )
        })
        .collect();
    scan.violations.extend(unknown);
    scan
}

/// The installer between its stdout guard's lines: everything before the
/// `{` line is `set -eu` alone, and the last line is `} >/dev/null`.
fn guarded_body(script: &str) -> Result<&str, String> {
    let refused = || {
        format!(
            "the script must be `set -eu`, a `{GUARD_OPEN}` line, its body, and a last line `{GUARD_CLOSE}`"
        )
    };
    let mut offset = 0;
    let open = script.split_inclusive('\n').find_map(|line| {
        let start = offset;
        offset += line.len();
        (line.trim_end_matches('\n') == GUARD_OPEN).then_some((start, offset))
    });
    let (open_start, body_start) = open.ok_or_else(refused)?;
    let prefix: Vec<String> = lex(script.get(..open_start).unwrap_or_default())
        .into_iter()
        .filter_map(|token| match token {
            Token::Sep(Sep::End) => None,
            Token::Word(word) => Some(word.text),
            _ => Some(String::new()),
        })
        .collect();
    if prefix != ["set", "-eu"] {
        return Err(refused());
    }
    let trimmed = script.trim_end_matches('\n');
    let close_start = trimmed.rfind('\n').map_or(0, |at| at + 1).max(body_start);
    if trimmed.get(close_start..) != Some(GUARD_CLOSE) {
        return Err(refused());
    }
    Ok(script.get(body_start..close_start).unwrap_or_default())
}

/// The functions the message block defines: each name directly followed by
/// `()`.
fn block_functions(block: &str) -> Vec<String> {
    let tokens = lex(block);
    tokens
        .windows(3)
        .filter_map(|window| match window {
            [
                Token::Word(word),
                Token::Sep(Sep::Open),
                Token::Sep(Sep::Close),
            ] => Some(word.text.clone()),
            _ => None,
        })
        .collect()
}

/// Every literal word of the message block: the helpers it defines and the
/// commands it runs. A function of one of these names defined outside the
/// block would change what the helpers do.
fn block_words(block: &str) -> Vec<String> {
    let mut words: Vec<String> = HELPERS
        .iter()
        .chain(INTERNAL.iter())
        .map(|name| (*name).to_owned())
        .collect();
    literal_words(block, &mut words);
    words
}

/// Push every literal word of `source`, command substitutions included.
fn literal_words(source: &str, words: &mut Vec<String>) {
    for token in lex(source) {
        if let Token::Word(word) = token {
            for body in &word.substitutions {
                literal_words(body, words);
            }
            if is_literal_name(&word) {
                words.push(word.text);
            }
        }
    }
}

/// Scan one source text; `captured` when its stdout is a command
/// substitution's value rather than the terminal.
fn scan_source(source: &str, captured: bool, reserved: &[String], scan: &mut Scan) {
    let tokens = lex(source);
    if captured
        && tokens
            .iter()
            .any(|token| matches!(token, Token::Word(word) if word.text == "case"))
    {
        scan.violations.push(format!(
            "`case` inside a command substitution is not scanned: `{source}`"
        ));
    }
    Scanner::new(captured, reserved, scan).run(&tokens);
}

/// Why the output redirection `op target` is refused, if it is: a
/// duplication onto stderr or stdin (the terminal, when the installer runs as
/// `sh install.sh`), or a file target other than `/dev/null` and the
/// installer's own `FILE_TARGETS`. A duplication is judged by its source
/// alone, whichever way it points: `1<&2` copies stderr onto stdout exactly as
/// `1>&2` does.
fn output_refusal(op: &str, target: &str) -> Option<String> {
    if op.ends_with('&') {
        let source = target.trim_matches(['"', '\'']).trim_end_matches('-');
        return matches!(source, "0" | "2")
            .then(|| format!("`{op}{target}` writes to the terminal outside the message block"));
    }
    if !op.contains('>') {
        return None;
    }
    (target != "/dev/null" && !FILE_TARGETS.contains(&target)).then(|| {
        format!(
            "`{op}{target}` writes to a target that is neither `/dev/null` nor one of the installer's own files"
        )
    })
}

/// Whether `text`, unquoted, names a device or process file other than
/// `/dev/null`: an argument that can name the terminal to a command that
/// writes to it (`tee /dev/stderr`, an awk `print > "/dev/tty"`).
fn names_device(text: &str) -> bool {
    let plain: String = text
        .chars()
        .filter(|c| !matches!(c, '"' | '\'' | '\\'))
        .collect();
    let device = plain.match_indices("/dev/").any(|(at, _)| {
        let rest = plain.get(at + "/dev/".len()..).unwrap_or_default();
        !rest.strip_prefix("null").is_some_and(|after| {
            after
                .chars()
                .next()
                .is_none_or(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-')))
        })
    });
    device || plain.contains("/proc/")
}

/// Why `op target` is refused for the descriptors it names, if it is: a
/// descriptor above 2 can alias the terminal unseen, and a duplication must
/// name its source literally.
fn fd_refusal(op: &str, target: &str) -> Option<String> {
    let fd = op.trim_end_matches(['<', '>', '&', '|', '-']);
    let high = |n: &str| n.parse::<u32>().is_ok_and(|n| n > 2);
    if high(fd) {
        return Some(format!("`{op}{target}` opens descriptor {fd}"));
    }
    if op.ends_with('&') {
        let source = target.trim_matches(['"', '\'']).trim_end_matches('-');
        if !(source.is_empty() || matches!(source, "0" | "1" | "2")) {
            return Some(format!(
                "`{op}{target}` duplicates a descriptor other than 0, 1 or 2"
            ));
        }
    }
    None
}

/// Whether `op target` sends stdout somewhere other than the terminal.
fn redirects_stdout(op: &str, target: &str) -> bool {
    let fd = op.trim_end_matches(['<', '>', '&', '|', '-']);
    let target = target.trim_matches(['"', '\'']);
    op.contains('>') && matches!(fd, "" | "1") && !(op.ends_with('&') && target == "1")
}

/// Whether `text` is a `NAME=value` assignment word.
fn is_assignment(text: &str) -> bool {
    text.split_once('=').is_some_and(|(name, _)| {
        name.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// Whether a command name is a fixed literal (no quoting, escape or
/// expansion), so the scan knows which command runs.
fn is_literal_name(word: &Word) -> bool {
    word.unit == Unit::Bare && !word.text.contains(['$', '`', '\\', '\'', '"'])
}

/// A `{ … }` group, `( … )` subshell or function body whose stdout is
/// decided by what follows its close.
struct Frame {
    /// The function this frame is the body of, if any.
    function: Option<String>,
    /// Closed by `)` rather than `}`.
    paren: bool,
    /// The stdout writes inside it that reach its own stdout.
    writes: Vec<String>,
}

/// The simple command being read.
#[derive(Default)]
struct Cmd {
    /// The stdout writes it makes (its own, or a closed frame's).
    writes: Vec<String>,
    redirected: bool,
    /// The command is `[` or `test`, which only reads its arguments.
    test: bool,
    /// Its name and argument words, as written.
    words: Vec<String>,
}

/// Where a token sits relative to a `case` header.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CaseAt {
    /// Ordinary commands.
    Body,
    /// Between `case` and its `in`.
    Subject,
    /// Reading patterns, up to the `)` that ends them.
    Patterns,
}

/// The token walk behind `scan_source`.
struct Scanner<'a> {
    scan: &'a mut Scan,
    /// The names no function outside the message block may take.
    reserved: &'a [String],
    captured: bool,
    frames: Vec<Frame>,
    cmd: Cmd,
    /// The stdout writes earlier in the current pipeline.
    piped: Vec<String>,
    /// The words of the command whose stdout feeds the current one, when the
    /// current one follows a `|`.
    pipe_source: Option<Vec<String>>,
    /// The next word is in command position.
    command: bool,
    /// Nesting depth of `case … esac`.
    cases: usize,
    /// Where the walk is inside a `case` header.
    case: CaseAt,
    /// The name of a function whose `{` body is about to open.
    defining: Option<String>,
}

impl<'a> Scanner<'a> {
    fn new(captured: bool, reserved: &'a [String], scan: &'a mut Scan) -> Self {
        Scanner {
            scan,
            reserved,
            captured,
            frames: Vec::new(),
            cmd: Cmd::default(),
            piped: Vec::new(),
            pipe_source: None,
            command: true,
            cases: 0,
            case: CaseAt::Body,
            defining: None,
        }
    }

    fn refuse(&mut self, why: String) {
        self.scan.violations.push(why);
    }

    fn run(mut self, tokens: &[Token]) {
        let mut at = 0;
        while let Some(token) = tokens.get(at) {
            at += 1;
            match token {
                Token::Unterminated => self.refuse(
                    "an unclosed quote, substitution or here-document stops the scan".to_owned(),
                ),
                Token::Heredoc { expands, body } => {
                    if *expands && (body.contains("$(") || body.contains('`')) {
                        self.refuse(format!(
                            "an expanding here-document runs a command substitution: `{body}`"
                        ));
                    }
                }
                Token::Redirect { op, target } => {
                    if let Some(why) = fd_refusal(op, target) {
                        self.refuse(why);
                    }
                    if let Some(why) = output_refusal(op, target) {
                        self.refuse(why);
                    }
                    if redirects_stdout(op, target) {
                        self.cmd.redirected = true;
                    }
                }
                Token::Sep(sep) => self.sep(*sep),
                Token::Word(word) => {
                    for body in &word.substitutions {
                        scan_source(body, true, self.reserved, self.scan);
                    }
                    if names_device(&word.text) && !self.cmd.test {
                        self.refuse(format!(
                            "`{}` names a device or process file outside a `[`/`test`",
                            word.text
                        ));
                    }
                    if self.case == CaseAt::Patterns {
                        if word.text == "esac" {
                            self.case = CaseAt::Body;
                            self.cases = self.cases.saturating_sub(1);
                            self.command = false;
                        }
                        continue;
                    }
                    if self.case == CaseAt::Subject {
                        if word.text == "in" {
                            self.case = CaseAt::Patterns;
                        }
                        continue;
                    }
                    if self.command {
                        at += self.command_word(word, tokens.get(at..).unwrap_or_default());
                    } else {
                        self.cmd.words.push(word.text.clone());
                    }
                }
            }
        }
        self.end_command(false);
        if !self.frames.is_empty() {
            self.refuse("an unclosed `{` or `(` group stops the scan".to_owned());
        }
    }

    fn sep(&mut self, sep: Sep) {
        match sep {
            Sep::Pipe if self.case != CaseAt::Patterns => self.end_command(true),
            Sep::Pipe | Sep::Open if self.case == CaseAt::Patterns => {}
            Sep::Close if self.case == CaseAt::Patterns => {
                self.case = CaseAt::Body;
                self.command = true;
            }
            Sep::Open => {
                self.body_not_group();
                self.frames.push(Frame {
                    function: None,
                    paren: true,
                    writes: Vec::new(),
                });
                self.command = true;
            }
            Sep::Close => self.close_frame(true),
            Sep::CaseArm => {
                self.end_command(false);
                if self.cases > 0 {
                    self.case = CaseAt::Patterns;
                }
            }
            Sep::End | Sep::Pipe => self.end_command(false),
        }
    }

    /// Handle the word `word` in command position, followed by `rest`;
    /// return how many tokens of `rest` it consumed.
    fn command_word(&mut self, word: &Word, rest: &[Token]) -> usize {
        let name = word.text.as_str();
        if name != "{" {
            self.body_not_group();
        }
        if KEYWORDS.contains(&name) || is_assignment(name) {
            match name {
                "{" => {
                    self.frames.push(Frame {
                        function: self.defining.take(),
                        paren: false,
                        writes: Vec::new(),
                    });
                }
                "}" => self.close_frame(false),
                _ => {}
            }
            return 0;
        }
        self.command = false;
        self.cmd.test = matches!(name, "[" | "test");
        self.cmd.words.push(name.to_owned());
        if !is_literal_name(word) || name.contains('/') {
            self.refuse(format!(
                "`{name}` is a quoted, escaped, expanded or path command name"
            ));
            return 0;
        }
        if matches!(
            (rest.first(), rest.get(1)),
            (Some(Token::Sep(Sep::Open)), Some(Token::Sep(Sep::Close)))
        ) {
            if self.reserved.iter().any(|word| word == name) {
                self.refuse(format!(
                    "`{name}` is defined outside the message block, which uses that name"
                ));
            }
            self.defining = Some(name.to_owned());
            self.scan.defined.push(name.to_owned());
            self.command = true;
            return 2;
        }
        match name {
            "case" => {
                self.cases += 1;
                self.case = CaseAt::Subject;
            }
            "esac" => self.cases = self.cases.saturating_sub(1),
            "trap" => self.trap(rest),
            "command" if matches!(first_word(rest), Some("-v" | "-V")) => {
                self.cmd.writes.push("`command -v`".to_owned());
            }
            "command" => self.refuse("`command` hides which command runs".to_owned()),
            "." if first_word(rest) == Some(SOURCED) => {}
            "sh" if rustup_shell(rest)
                && self
                    .pipe_source
                    .as_deref()
                    .is_some_and(|source| source == RUSTUP_FETCH) => {}
            _ if RUNNERS.contains(&name) => {
                self.refuse(format!("`{name}` runs a command the scan cannot see"));
            }
            _ if OPAQUE.contains(&name) => {
                self.refuse(format!("`{name}` runs text the scan cannot see"));
            }
            _ if INTERNAL.contains(&name) => {
                self.refuse(format!("`{name}` is internal to the message block"));
            }
            _ if HELPERS.contains(&name) => self.helper_call(name, rest),
            _ if WRITERS.contains(&name) || VALUE_PRINTERS.contains(&name) => {
                self.cmd.writes.push(format!("`{name}`"));
            }
            "cargo" if first_word(rest) == Some("version") => {}
            _ if COMMANDS.contains(&name) => {}
            _ => self.scan.called.push(name.to_owned()),
        }
        0
    }

    /// Refuse a pending function definition whose body is not a `{` group:
    /// its name would otherwise attach to a later, unrelated group.
    fn body_not_group(&mut self) {
        if let Some(name) = self.defining.take() {
            self.refuse(format!("function `{name}` must have a `{{ … }}` body"));
        }
    }

    /// Scan a `trap` action: it runs later, outside any capture.
    fn trap(&mut self, rest: &[Token]) {
        match rest.first() {
            Some(Token::Word(action)) if action.unit == Unit::Single => {
                let body = action
                    .text
                    .strip_prefix('\'')
                    .and_then(|text| text.strip_suffix('\''))
                    .unwrap_or_default();
                scan_source(body, false, self.reserved, self.scan);
            }
            Some(Token::Word(action)) if action.text == "-" => {}
            _ => self.refuse("a `trap` action must be one single-quoted literal".to_owned()),
        }
    }

    fn helper_call(&mut self, name: &str, rest: &[Token]) {
        self.scan.calls += 1;
        let args: Vec<&Word> = rest
            .iter()
            .take_while(|token| !matches!(token, Token::Sep(_)))
            .filter_map(|token| match token {
                Token::Word(word) => Some(word),
                _ => None,
            })
            .collect();
        if let Some(why) = call_refusal(&args) {
            let call: Vec<&str> = args.iter().map(|word| word.text.as_str()).collect();
            self.refuse(format!("`{name} {}`: {why}", call.join(" ")));
        }
    }

    /// End the current simple command; `piped` when its stdout feeds the
    /// next command of the pipeline.
    fn end_command(&mut self, piped: bool) {
        let cmd = std::mem::take(&mut self.cmd);
        self.command = true;
        self.pipe_source = piped.then_some(cmd.words);
        if piped {
            if !cmd.redirected {
                self.piped.extend(cmd.writes);
            }
            return;
        }
        let mut writes = std::mem::take(&mut self.piped);
        writes.extend(cmd.writes);
        if cmd.redirected || writes.is_empty() {
            return;
        }
        match self.frames.last_mut() {
            Some(frame) => frame.writes.extend(writes),
            None if self.captured => {}
            None => {
                let what = writes.join(", ");
                self.refuse(format!(
                    "{what} writes to stdout, which is the terminal, outside the message block"
                ));
            }
        }
    }

    /// Close the innermost frame; its writes become the closing command's,
    /// so a redirection after the close still applies to them.
    fn close_frame(&mut self, paren: bool) {
        self.end_command(false);
        let Some(frame) = self.frames.pop() else {
            self.refuse("an unbalanced `}` or `)` stops the scan".to_owned());
            return;
        };
        if frame.paren != paren {
            self.refuse("mismatched `{`/`(` groups stop the scan".to_owned());
        }
        let value_printer = frame
            .function
            .as_deref()
            .is_some_and(|name| VALUE_PRINTERS.contains(&name));
        if frame.function.is_some() {
            if !value_printer && !frame.writes.is_empty() {
                let name = frame.function.unwrap_or_default();
                self.refuse(format!(
                    "function `{name}` writes to stdout ({}) but is not a value printer",
                    frame.writes.join(", ")
                ));
            }
        } else {
            self.cmd.writes = frame.writes;
        }
        self.command = false;
    }
}

/// Whether `sh` followed by `rest` is exactly `RUSTUP_SHELL`, reading the
/// pipe on its stdin (no input redirection).
fn rustup_shell(rest: &[Token]) -> bool {
    let command: Vec<&Token> = rest
        .iter()
        .take_while(|token| !matches!(token, Token::Sep(_)))
        .collect();
    let words: Vec<&str> = std::iter::once("sh")
        .chain(command.iter().filter_map(|token| match token {
            Token::Word(word) => Some(word.text.as_str()),
            _ => None,
        }))
        .collect();
    words == RUSTUP_SHELL
        && command.iter().all(|token| match token {
            Token::Redirect { op, .. } => !op.contains('<'),
            _ => true,
        })
}

/// The text of the first word of `rest`, if it starts with one.
const fn first_word(rest: &[Token]) -> Option<&str> {
    match rest.first() {
        Some(Token::Word(word)) => Some(word.text.as_str()),
        _ => None,
    }
}

/// Why a message-helper call with `args` is refused, if it is.
fn call_refusal(args: &[&Word]) -> Option<String> {
    let Some((format, values)) = args.split_first() else {
        return Some("no format".to_owned());
    };
    if format.unit != Unit::Single {
        return Some("the format is not one single-quoted literal".to_owned());
    }
    let literal = format
        .text
        .strip_prefix('\'')
        .and_then(|text| text.strip_suffix('\''))
        .unwrap_or_default();
    if literal.contains('$') {
        return Some("the format contains `$`".to_owned());
    }
    let mut fills = 0_usize;
    let mut chars = literal.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            match chars.next() {
                Some('s') => fills += 1,
                Some('%') => {}
                other => {
                    return Some(format!(
                        "the directive `%{}` is neither `%s` nor `%%`",
                        other.map(String::from).unwrap_or_default()
                    ));
                }
            }
        }
    }
    if fills != values.len() {
        return Some(format!("{fills} `%s` for {} values", values.len()));
    }
    values
        .iter()
        .find(|value| value.unit != Unit::Double)
        .map(|value| format!("the value `{}` is not double-quoted", value.text))
}

/// `fixture` after a message block that itself writes to stderr.
fn with_block(fixture: &str) -> String {
    format!(
        "set -eu\n{GUARD_OPEN}\n{BEGIN}\nsay() {{ printf '%s\\n' \"$1\" >&2; }}\n{END}\n{fixture}\n{GUARD_CLOSE}\n"
    )
}

#[test]
fn installer_messages_take_values_as_arguments() -> io::Result<()> {
    let scan = scan_script(&installer_script()?);
    assert!(
        scan.violations.is_empty(),
        "install.sh message shapes outside the helper contract: {:#?}",
        scan.violations
    );
    assert!(
        scan.calls >= 40,
        "the scan must see the installer's message calls, saw {}",
        scan.calls
    );
    Ok(())
}

/// Shapes the message scan must refuse outside the block.
const REFUSED_SHAPES: &[&str] = &[
    "die \"x $y\"",
    "die \"$(f)\"",
    "die $x",
    "die 'x %s'",
    "die 'x %d' \"$v\"",
    "printf '%s' \"$x\" >&2",
    "{ die \"a $b\"; }",
    "foo || die \"$c\"",
    "die \\\n\"$x\"",
    "die 'x' \"$y\"",
    "die 'a'\\''b'",
    "die 'cost $5'",
    "say 'x %s' $v",
    "say 'x %s' \"$a\"b",
    "x=\"$(die \"$y\")\"",
    "if true; then info \"$m\"; fi",
    "echo hi 1>&2",
    "printf x >/dev/tty",
    "printf x >/dev/stderr",
    "msg_text 'x'",
    "stage_settle_ok \"$x\"",
    "die() { :; }",
    "# note \\\ndie \"$x\"",
    "printf x >& 2",
    "printf x >&\"2\"",
    "printf x >&2-",
    "printf x >/proc/self/fd/2",
    "printf x >/dev/stdout",
    "printf x >/dev/fd/1",
    "exec 3>&1",
    "printf x >&3",
    "printf x >&\"$fd\"",
    "eval \"die \\\"\\$x\\\"\"",
    "\"die\" \"$x\"",
    "\\die \"$x\"",
    "command die \"$x\"",
    "$f \"$x\"",
    "builtin printf x",
    ". \"$f\"",
    "function g { :; }",
    "alias d=die",
    "printf() { :; }",
    "trap 'die \"$x\"' EXIT",
    "trap \"$t\" EXIT",
    "cat >\"$wm_tmp\" <<EOF\nit's\nEOF\ndie \"$x\"",
    "cat >\"$wm_tmp\" <<EOF\n$(die \"$x\")\nEOF",
    "cat <<EOF\nhi\nEOF",
    "cat >\"$wm_tmp\" <<EOF\nhi",
    "say 'a %s' \"${x:-$(die \"$y\")}\"",
    "x=$(: # it's\n) ; die \"$x\" ; : ')'",
    "x=$(cat <<E\n)\nE\n)",
    "x=$(case $y in a) die \"$z\" ;; esac)",
    "case $a in\nx) :;;\nesac\ndie \"$x\"",
    "printf '%s\\n' \"$x\"",
    "echo \"$x\"",
    "cat \"$f\"",
    "printf x | sed 1d",
    "( printf x )",
    "while :; do printf x; done",
    "command -v cargo",
    "trusted_tmp_base \"$b\"",
    "f() { printf x; }\nf >/dev/null",
    "printf 'x",
    "x=$(printf x",
    "printf x >&0",
    "printf x >&0-",
    "exec >&0",
    "printf x >/dev/stdin",
    "printf x >//dev/tty",
    "printf x >/dev/pts/0",
    "printf x >/dev/console",
    "printf x >/dev/fd/0",
    "printf x >/proc/self/fd/0",
    "printf x <>/dev/tty",
    "printf x >\"$f\"",
    "printf x >>\"$tmp/x\"",
    "printf x >out",
    "printf x | tee /dev/stderr >/dev/null",
    "cp \"$wm_tmp\" /dev/tty",
    "cp \"$wm_tmp\" \"/de\"v/tty",
    "awk 'BEGIN { print \"x\" > \"/dev/stderr\" }'",
    "cat /proc/self/fd/2 >/dev/null",
    "printf x >/dev/nullx",
    "sed 1d \"$wm_tmp\" 1<&2",
    "tr a b <\"$wm_tmp\" 1<&0",
    "cut -c1 <\"$wm_tmp\" <&2",
    "curl x | sh -s -- -y 2>/dev/null",
    "printf '%s' \"$x\" | sh -s -- -y",
    "sh -s -- -y",
    "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | tee \"$wm_tmp\" | sh -s -- -y",
    "sh -c 'printf \"$1\" >&2' _ \"$x\"",
    "sh -s -- -y </dev/tty",
    "sh -s -- -y -q",
    "bash -c 'die \"$x\"'",
    "env printf x",
    "exec printf x",
    "xargs printf <\"$wm_tmp\"",
    "nohup printf x",
    "/usr/bin/printf x",
    "./x",
    "trusted_tmp_base() ( : )\n{ printf x; }",
    "trusted_tmp_base()\nprintf x\n{ printf y; }",
];

/// Shapes the message scan must accept outside the block.
const ACCEPTED_SHAPES: &[&str] = &[
    "",
    "die 'x %s' \"$y\"",
    "true || die 'a %s %%' \"$b\"",
    "stage_ok 'Found %s.' \"$(uname \"$t\" | cut -d' ' -f2)\"",
    "printf '%s' \"$x\" >\"$TAG_FILE\" 2>/dev/null",
    "IFS= read -r ans </dev/tty",
    "case $x in\n  *) die 'y %s' \"$x\" ;;\nesac",
    "# die \"$x\" in a comment",
    "die 'a %s' \\\n  \"$b\"",
    "x=\"$(printf '%s' \"$y\")\"",
    "printf x >\"$wm_tmp\"",
    "printf x 2>&1 >\"$wm_tmp\"",
    "printf x | sed 1d >\"$dl_dest\"",
    "{ printf a; printf b; } >>\"$RC_FILE\"",
    "( curl x; echo $? > \"$tmp/curl.rc\" ) 2>/dev/null",
    "[ -r /dev/tty ]",
    "test -c /dev/tty",
    "curl -o /dev/null x",
    "printf x 2>/dev/null >/dev/null",
    "printf x >&-",
    "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs 2>/dev/null \\\n  | sh -s -- -y 2>/dev/null",
    "trusted_tmp_base() { printf x; }",
    "trusted_tmp_base \"$b\" >/dev/null",
    "x=$(trusted_tmp_base \"$b\")",
    "case $a in\n''|[Yy]) die 'q' ;;\nesac\ndie 'r'",
    "read -r a b <<EOF\n$v\nEOF",
    "cat <<EOF >\"$wm_tmp\"\nit's\nEOF",
    "command -v cargo >/dev/null 2>&1",
    "x=$((1 << 2))",
    "trap 'rm -rf \"$tmp\"' EXIT",
    ". \"$HOME/.cargo/env\"",
];

/// Commands the scan refuses because it cannot know what they run or write.
const UNKNOWN_COMMANDS: &[&str] = &[
    "foo",
    "awk 'BEGIN { system(\"x\") }'",
    "find . -exec printf x \\;",
    "tee \"$wm_tmp\"",
    "cargo run",
    "x=$(git log)",
    "trap 'git gc' EXIT",
];

/// Commands it accepts: a known one, and a function the script defines.
const KNOWN_COMMANDS: &[&str] = &[
    "uname -s >/dev/null",
    "cargo version >/dev/null",
    "g() { :; }\ng",
    "x=$(g)\ng() { :; }",
];

#[test]
fn message_scan_refuses_unknown_commands() {
    for fixture in UNKNOWN_COMMANDS {
        let scan = scan_script(&with_block(fixture));
        assert!(
            scan.violations
                .iter()
                .any(|why| why.contains("neither a command the scan knows")),
            "the scan must refuse the unknown command in `{fixture}`: {:?}",
            scan.violations
        );
        assert!(
            scan_script_with(&with_block(fixture), false)
                .violations
                .iter()
                .all(|why| !why.contains("neither a command the scan knows")),
            "only the command check may name `{fixture}`"
        );
    }
    for fixture in KNOWN_COMMANDS {
        let scan = scan_script(&with_block(fixture));
        assert!(
            scan.violations.is_empty(),
            "the scan must accept `{fixture}`: {:?}",
            scan.violations
        );
    }
}

#[test]
fn message_scan_refuses_every_bypass() {
    let braced = "info \"${".to_owned() + "A}\"";
    let refused = REFUSED_SHAPES.iter().copied().chain([braced.as_str()]);
    for fixture in refused {
        let scan = scan_script_with(&with_block(fixture), false);
        assert!(
            !scan.violations.is_empty(),
            "the scan must refuse `{fixture}`"
        );
    }

    let accepted = ACCEPTED_SHAPES;
    for fixture in accepted {
        let scan = scan_script(&with_block(fixture));
        assert!(
            scan.violations.is_empty(),
            "the scan must accept `{fixture}`: {:?}",
            scan.violations
        );
    }

    for (script, why) in [
        (
            format!("{BEGIN}\nsay() {{ :; }}\n"),
            "a block with no end marker",
        ),
        (
            format!("{}{}", with_block(""), with_block("")),
            "a second message block",
        ),
        (
            format!("set -eu\n{GUARD_OPEN}\n{END}\n{BEGIN}\n{GUARD_CLOSE}\n"),
            "markers out of order",
        ),
    ] {
        assert!(
            !scan_script(&script).violations.is_empty(),
            "the scan must refuse {why}"
        );
    }
}

#[test]
fn message_scan_refuses_a_script_outside_the_stdout_guard() -> io::Result<()> {
    let block = format!("{BEGIN}\nsay() {{ printf '%s\\n' \"$1\" >&2; }}\n{END}\n");
    let guarded = with_block("");
    assert!(
        scan_script(&guarded).violations.is_empty(),
        "the guarded fixture must pass: {:?}",
        scan_script(&guarded).violations
    );
    for (script, why) in [
        (format!("set -eu\n{block}"), "no guard"),
        (
            format!("{GUARD_OPEN}\n{block}{GUARD_CLOSE}\n"),
            "no `set -eu`",
        ),
        (
            format!("set -eu\n{GUARD_OPEN}\n{block}}}\n"),
            "a close without `>/dev/null`",
        ),
        (
            format!("set -eu\n{GUARD_OPEN}\n{block}}} >/dev/tty\n"),
            "a close onto the terminal",
        ),
        (
            format!("set -eu\nprintf x\n{GUARD_OPEN}\n{block}{GUARD_CLOSE}\n"),
            "a command before the guard",
        ),
        (
            format!("set -eu\n{GUARD_OPEN}\n{block}{GUARD_CLOSE}\nprintf x\n"),
            "a command after the guard",
        ),
        (
            format!("set -eu\n{GUARD_OPEN}\n{block}}}\nprintf x\n{{\n{GUARD_CLOSE}\n"),
            "a body that closes the guard early",
        ),
    ] {
        let scan = scan_script(&script);
        assert!(
            !scan.violations.is_empty(),
            "the scan must refuse {why}: `{script}`"
        );
    }
    let installer = installer_script()?;
    let unguarded = installer.replacen(&format!("\n{GUARD_OPEN}\n"), "\n", 1);
    assert!(
        !scan_script(&unguarded).violations.is_empty(),
        "install.sh without its guard line must be refused"
    );
    Ok(())
}

#[test]
fn message_scan_refuses_redefining_what_the_block_runs() -> io::Result<()> {
    let installer = installer_script()?;
    for name in ["safe_text", "printf", "od", "awk"] {
        let inside = installer.replacen(
            &format!("\n{GUARD_CLOSE}\n"),
            &format!("\n{name}() {{ :; }}\n{GUARD_CLOSE}\n"),
            1,
        );
        let scan = scan_script(&inside);
        assert!(
            scan.violations
                .iter()
                .any(|why| why.contains(&format!("`{name}` is defined outside"))),
            "the scan must refuse redefining `{name}`: {:?}",
            scan.violations
        );
    }
    Ok(())
}
