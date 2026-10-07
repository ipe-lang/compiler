#![forbid(unsafe_code)]
//! Refuses every read of the process environment that bypasses an audited
//! reader, as a second layer beneath the clippy `disallowed-methods` deny.
//!
//! An unset, empty, or relative `HOME` resolves against whatever the current
//! working directory is, so every home read goes through one validated accessor
//! that yields an absolute path or nothing: `ipe_sandbox::home::home_dir` on the
//! compiler side and `system::home_dir` in the standalone runtime. Every other
//! compiler-side variable is read through `ipe_env`, which refuses each home
//! name however it is spelled or computed, and a jail's granted variables are
//! forwarded verbatim by the sandbox-private `ipe_sandbox::host_env::granted`,
//! reachable from outside the sandbox crate only as `granted_env` over a
//! profile's own allowlist, from the pinned WASI launcher and Windows jail e2e.
//!
//! The root `clippy.toml` denies `std::env::{var, var_os, vars, vars_os}`, so
//! the audited readers are the only raw readers. This scan pins that set
//! independently: it refuses a literal home read in production sources, a
//! home-dir crate (`home`, `dirs`, `directories`, `etcetera`, …) as a
//! manifest dependency or a source path, a shared home-name constant outside its pinned files, a raw `std::env` read or
//! whole-environment iterator outside the audited files, the escape-hatch
//! allow outside the pinned allow files, the jail passthrough outside the
//! sandbox crate and its pinned callers, and a `/proc/*/environ` read.
//!
//! [`lexical`] is an independent third layer: a function-granular lexical
//! scan refusing every home-name literal and computed-key read outside its
//! reasoned allowlist.

use std::path::PathBuf;

/// Workspace-relative files that own a validated home accessor.
const ACCESSOR_FILES: &[&str] = &[
    "src/compiler/sandbox/src/home.rs",
    "src/runtime/rust/src/system.rs",
];

/// The runtime file that names every `clippy.toml`-banned path under an
/// `#[expect]` to prove each ban fires. It names the `std` home reader as a
/// value and never calls it, which `ban_proof_file_never_calls_the_home_reader`
/// pins.
const BAN_PROOF_FILE: &str = "src/runtime/rust/src/clippy_paths_resolve.rs";

/// Workspace-relative files that hold the only raw environment reads outside
/// the runtime crate, each under a per-site `clippy::disallowed_methods` allow.
const ENV_ALLOW_FILES: &[&str] = &[
    "src/compiler/env/src/lib.rs",
    "src/compiler/sandbox/src/home.rs",
    "src/compiler/sandbox/src/host_env.rs",
];

/// The runtime crate: built with its own `clippy.toml` and its own home
/// accessor, so the compiler-side env rules do not apply beneath it.
const RUNTIME_ROOT: &str = "src/runtime/rust/";

/// Every `clippy::disallowed_methods` escape hatch in the workspace, as
/// `(workspace-relative file, code-level allow count)`.
///
/// Pinned per site, not per file: a new allow in a listed file changes its
/// count and fails the scan like an allow anywhere else. The sites are the
/// [`ENV_ALLOW_FILES`] readers (`ipe_env`'s `var`/`var_os`/`vars_os`, the
/// sandbox home reader, the jail passthrough); the sandbox's thread-spawn ban
/// proofs; the database crate's filesystem, environment and clock ban proofs;
/// the dev-only temp-root test reader; and in the runtime crate, which has its own `clippy.toml`, the build
/// script, the recursion-limit trip, the temp-root owner and its test reader,
/// the environment accessor's readers, two integration tests with no
/// crate-private accessor, the ban proofs, the one blocking-pool start, the one
/// process exit, and the
/// audited lossy-UTF-8 sites that render bytes already refused or never parsed.
const ESCAPE_HATCH_SITES: &[(&str, usize)] = &[
    ("src/compiler/env/src/lib.rs", 3),
    ("src/compiler/sandbox/src/home.rs", 1),
    ("src/compiler/sandbox/src/host_env.rs", 1),
    ("src/compiler/sandbox/src/clippy_paths_resolve.rs", 2),
    ("src/compiler/db/src/clippy_paths_resolve.rs", 35),
    ("tools/test-temp/src/lib.rs", 1),
    ("src/runtime/rust/build.rs", 1),
    ("src/runtime/rust/src/clippy_paths_resolve.rs", 14),
    ("src/runtime/rust/src/core.rs", 1),
    ("src/runtime/rust/src/csv.rs", 1),
    ("src/runtime/rust/src/dom/form.rs", 1),
    ("src/runtime/rust/src/email.rs", 1),
    ("src/runtime/rust/src/http_client.rs", 2),
    ("src/runtime/rust/src/http_stream.rs", 1),
    ("src/runtime/rust/src/scratch_core.rs", 2),
    ("src/runtime/rust/src/server.rs", 2),
    ("src/runtime/rust/src/ssrf.rs", 1),
    ("src/runtime/rust/src/system.rs", 10),
    ("src/runtime/rust/src/terminal_access.rs", 1),
    ("src/runtime/rust/src/threads.rs", 1),
    ("src/runtime/rust/src/tui/key.rs", 1),
    ("src/runtime/rust/src/url.rs", 1),
    ("src/runtime/rust/tests/debug_behavior.rs", 1),
    ("src/runtime/rust/tests/parent_death_spawner.rs", 1),
];

/// The sandbox crate's sources: the only callers of the crate-private raw
/// passthrough `host_env::granted`.
const SANDBOX_SRC: &str = "src/compiler/sandbox/src/";

/// Workspace-relative files outside the sandbox crate that may forward a
/// profile's granted variables through `host_env::granted_env`: the WASI
/// launcher, and the Windows run-jail e2e, which reads the host values of the
/// launcher's declared base set to compute the environment the child must see.
const JAIL_ENV_CALLERS: &[&str] = &[
    "src/ipe-cli/src/wasi_run.rs",
    "src/compiler/sandbox/tests/run_jail_windows_e2e.rs",
];

/// The profile-scoped passthrough's name.
const JAIL_ENV_FN: &str = "granted_env";

/// Whitespace-free code spellings that reach the raw passthrough
/// `host_env::granted`: its path, or a group or glob import of its module.
const RAW_PASSTHROUGH_PATHS: &[&str] = &["host_env::granted", "host_env::{", "host_env::*"];

/// The files that may name the shared home-name constants: their one source
/// (`home_core`), the two home accessors, the agreement table both accessors'
/// tests `include!`, and the two hosts of the shared scratch core's Windows
/// scratch-root check.
const HOME_VAR_FILES: &[&str] = &[
    "src/runtime/rust/src/home_core.rs",
    "src/runtime/rust/tests/data/home_cases.rs",
    "src/compiler/sandbox/src/home.rs",
    "src/runtime/rust/src/system.rs",
    "src/compiler/sandbox/src/scratch.rs",
    "src/runtime/rust/src/scratch_host.rs",
];

/// The shared home-name constants, defined once in `home_core`.
const HOME_VAR_NAMES: &[&str] = &["HOME_VAR", "WINDOWS_HOME_VAR"];

/// Whitespace-free call openers that read an environment variable named by a
/// literal, `{}` standing for the name.
///
/// Covers `std::env::var`/`var_os` and every wrapper ending in `var`,
/// `env!`/`option_env!`, and libc's `getenv` over a string, C-string, or
/// NUL-terminated byte literal.
const LITERAL_READ_SHAPES: &[&str] = &[
    "var(\"{}\"",
    "var_os(\"{}\"",
    "env!(\"{}\"",
    "getenv(\"{}\"",
    "getenv(\"{}\\0\"",
    "getenv(c\"{}\"",
    "getenv(b\"{}\\0\"",
];

/// Whitespace-free spellings of the deprecated `std` home reader.
const STD_HOME_READS: &[&str] = &["env::home_dir"];

/// Crates whose API resolves the invoking user's home or a directory beneath
/// it, by Cargo package name.
const HOME_DIR_CRATES: &[&str] = &[
    "home",
    "dirs",
    "dirs-next",
    "dirs-sys",
    "dirs-sys-next",
    "directories",
    "directories-next",
    "etcetera",
];

/// The whitespace-free literal home reads: every `LITERAL_READ_SHAPES` opener
/// over every `ipe_env::HOME_NAMES` name.
fn literal_home_reads() -> Vec<String> {
    LITERAL_READ_SHAPES
        .iter()
        .flat_map(|shape| {
            ipe_env::HOME_NAMES
                .iter()
                .map(move |name| shape.replace("{}", name))
        })
        .collect()
}

/// The raw home reads `src` contains, whitespace and line breaks ignored.
///
/// A hit is a literal home read, the `std` home reader, or a crate-root path
/// into a home-dir crate.
fn raw_home_reads(src: &str) -> Vec<String> {
    let flat: String = src.chars().filter(|c| !c.is_whitespace()).collect();
    let mut hits: Vec<String> = literal_home_reads()
        .into_iter()
        .chain(STD_HOME_READS.iter().map(|s| (*s).to_owned()))
        .filter(|needle| flat.contains(needle.as_str()))
        .collect();
    hits.extend(home_crate_paths(src));
    hits
}

/// The home-dir crate paths `src`'s code reaches from a crate root.
///
/// `crate::home::` or `ipe_sandbox::home::` is a sub-path, not the crate; a
/// crate-rooted `home::` or `::home::` is refused, and so, failing closed, is
/// one inside a group import (`{home::`).
fn home_crate_paths(src: &str) -> Vec<String> {
    let code = code_words(src);
    HOME_DIR_CRATES
        .iter()
        .map(|krate| format!("{}::", krate.replace('-', "_")))
        .filter(|needle| {
            code.match_indices(needle.as_str())
                .any(|(at, _)| is_crate_root_path(&code, at))
        })
        .collect()
}

/// Whether the path segment at byte offset `at` of `code` starts at a crate root.
///
/// It must be neither glued to an identifier nor preceded by `<ident>::`.
fn is_crate_root_path(code: &str, at: usize) -> bool {
    if ident_before(code, at) {
        return false;
    }
    let head = code.get(..at).map_or("", str::trim_end);
    head.strip_suffix("::").is_none_or(|parent| {
        !parent
            .trim_end()
            .chars()
            .next_back()
            .is_some_and(is_ident_char)
    })
}

/// The home-dir crates `manifest` depends on.
///
/// A dependency key in either spelling (`dirs-next`, `dirs_next`), a
/// `[…dependencies.<crate>]` table, or a `package = "<crate>"` rename counts.
fn home_crate_deps(manifest: &str) -> Vec<&'static str> {
    let lines: Vec<String> = manifest
        .lines()
        .map(|line| {
            line.split_once('#')
                .map_or(line, |(code, _)| code)
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect()
        })
        .collect();
    HOME_DIR_CRATES
        .iter()
        .copied()
        .filter(|krate| {
            let snake = krate.replace('-', "_");
            [*krate, snake.as_str()].into_iter().any(|name| {
                lines.iter().any(|line| {
                    line.strip_prefix(name)
                        .is_some_and(|rest| rest.starts_with(['=', '.']))
                        || line.contains(&format!("dependencies.{name}]"))
                        || line.contains(&format!("package=\"{name}\""))
                })
            })
        })
        .collect()
}

/// Whitespace-free code spellings that reach the raw environment readers:
/// a path to `var`/`var_os`/`vars`/`vars_os`, a glob or group import of
/// `std::env` that would let them be called unqualified, or libc's `getenv`.
const RAW_ENV_PATHS: &[&str] = &["env::var", "std::env::{", "std::env::*", "libc::getenv"];

/// Whether `c` can continue a Rust identifier.
fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Skip a string literal whose opening quote ends at `start`; returns the
/// index after the closing quote (or the end of input).
fn skip_quoted(chars: &[char], start: usize) -> usize {
    let mut i = start;
    while let Some(&c) = chars.get(i) {
        match c {
            '\\' => i += 2,
            '"' => return i + 1,
            _ => i += 1,
        }
    }
    chars.len()
}

/// Skip a raw string `r#*"…"#*` beginning at `start` (the `r`); `None` when
/// `start` is not a raw-string opener.
fn skip_raw(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start + 1;
    let mut hashes = 0;
    while chars.get(i) == Some(&'#') {
        hashes += 1;
        i += 1;
    }
    if chars.get(i) != Some(&'"') {
        return None;
    }
    i += 1;
    while i < chars.len() {
        let closes =
            chars.get(i) == Some(&'"') && (1..=hashes).all(|k| chars.get(i + k) == Some(&'#'));
        if closes {
            return Some(i + 1 + hashes);
        }
        i += 1;
    }
    Some(chars.len())
}

/// Skip a (possibly nested) block comment beginning at `start`.
fn skip_block_comment(chars: &[char], start: usize) -> usize {
    let mut i = start;
    let mut depth = 0_usize;
    while i < chars.len() {
        match (chars.get(i), chars.get(i + 1)) {
            (Some('/'), Some('*')) => {
                depth += 1;
                i += 2;
            }
            (Some('*'), Some('/')) => {
                depth = depth.saturating_sub(1);
                i += 2;
                if depth == 0 {
                    return i;
                }
            }
            _ => i += 1,
        }
    }
    chars.len()
}

/// The whitespace-free code of `src`: comments dropped, and every string and
/// character literal collapsed to an empty `""`, so a path spelled only inside
/// a literal or comment is never mistaken for a call. A gap between two
/// identifiers stays one space, so `use std` never glues into `usestd`.
fn code_only(src: &str) -> String {
    code_text(src, false)
}

/// [`code_only`], but each whitespace character kept as one space, so two
/// adjacent identifiers (`granted_env as g`) stay two words.
fn code_words(src: &str) -> String {
    code_text(src, true)
}

/// The code of `src` with comments dropped and literals collapsed to `""`;
/// whitespace kept as spaces when `spaced`, else dropped except as one space
/// between two identifier characters.
fn code_text(src: &str, spaced: bool) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::new();
    let mut gap = false;
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        let next = chars.get(i + 1).copied();
        let prev_ident = i > 0 && chars.get(i - 1).is_some_and(|&p| is_ident_char(p));
        if c == '/' && next == Some('/') {
            i = chars
                .iter()
                .skip(i)
                .position(|&ch| ch == '\n')
                .map_or(chars.len(), |off| i + off);
            gap = true;
        } else if c == '/' && next == Some('*') {
            i = skip_block_comment(&chars, i);
            gap = true;
        } else if let Some(end) = (!prev_ident && (c == 'r' || (c == 'b' && next == Some('r'))))
            .then(|| skip_raw(&chars, if c == 'b' { i + 1 } else { i }))
            .flatten()
        {
            out.push_str("\"\"");
            i = end;
        } else if c == '"' || (c == 'b' && next == Some('"') && !prev_ident) {
            out.push_str("\"\"");
            i = skip_quoted(&chars, if c == 'b' { i + 2 } else { i + 1 });
        } else if c == '\'' && next == Some('\\') {
            i = chars
                .iter()
                .skip(i + 2)
                .position(|&ch| ch == '\'')
                .map_or(chars.len(), |off| i + 3 + off);
        } else if c == '\'' && chars.get(i + 2) == Some(&'\'') {
            i += 3;
        } else {
            if !c.is_whitespace() {
                if gap && is_ident_char(c) && out.chars().next_back().is_some_and(is_ident_char) {
                    out.push(' ');
                }
                gap = false;
                out.push(c);
            } else if spaced {
                out.push(' ');
            } else {
                gap = true;
            }
            i += 1;
        }
    }
    out
}

/// Whether `needle` occurs in `code` not glued to a preceding identifier, so
/// `ipe_env::var` is not read as `env::var`.
fn has_path(code: &str, needle: &str) -> bool {
    code.match_indices(needle)
        .any(|(at, _)| !ident_before(code, at))
}

/// Whether an identifier character immediately precedes byte offset `at`.
fn ident_before(code: &str, at: usize) -> bool {
    code.get(..at)
        .and_then(|head| head.chars().next_back())
        .is_some_and(is_ident_char)
}

/// Whether an identifier character immediately follows byte offset `at`.
fn ident_after(code: &str, at: usize) -> bool {
    code.get(at..)
        .and_then(|tail| tail.chars().next())
        .is_some_and(is_ident_char)
}

/// The raw environment reads `src`'s code performs.
fn raw_env_reads(src: &str) -> Vec<&'static str> {
    let code = code_only(src);
    RAW_ENV_PATHS
        .iter()
        .copied()
        .filter(|needle| has_path(&code, needle))
        .collect()
}

/// Whether `src`'s code names the identifier `ident` (not as part of a longer
/// identifier).
fn names_ident(src: &str, ident: &str) -> bool {
    let code = code_words(src);
    code.match_indices(ident)
        .any(|(at, m)| !ident_before(&code, at) && !ident_after(&code, at + m.len()))
}

/// Whether `src`'s code names a shared home-name constant.
fn names_home_var(src: &str) -> bool {
    HOME_VAR_NAMES.iter().any(|name| names_ident(src, name))
}

/// Whether `src`'s code reaches the raw passthrough `host_env::granted`: a
/// path to it, or a group or glob import of its module. Only a direct
/// `host_env::granted_env(..)` call is the profile-scoped form; any other
/// continuation (an alias included) is refused.
fn reaches_raw_passthrough(src: &str) -> bool {
    let code = code_only(src);
    RAW_PASSTHROUGH_PATHS.iter().any(|needle| {
        code.match_indices(needle).any(|(at, m)| {
            let scoped = code
                .get(at + m.len()..)
                .is_some_and(|tail| tail.starts_with("_env("));
            !ident_before(&code, at) && (needle.ends_with(['{', '*']) || !scoped)
        })
    })
}

/// Whether `src` names a procfs environment file (`/proc/self/environ`, a
/// `join("environ")`): literals included, line comments not. The literal's
/// last path component must be exactly `environ`, so a key that merely ends in
/// those letters (`exportableenviron`) is not a procfs read.
fn reads_proc_environ(src: &str) -> bool {
    src.lines()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
        .any(|line| line.contains("\"environ\"") || line.contains("/environ\""))
}

/// How many times `src`'s code (comments and literals aside) names the
/// `disallowed_methods` escape hatch.
fn disallowed_methods_allows(src: &str) -> usize {
    code_only(src).matches("clippy::disallowed_methods").count()
}

/// Whether `src`'s code carries the `disallowed_methods` escape hatch.
fn allows_disallowed_methods(src: &str) -> bool {
    disallowed_methods_allows(src) > 0
}

/// Whether `src`'s code names the `disallowed_methods` escape hatch inside an
/// inner (`#![...]`) attribute, which covers a whole module or crate: one such
/// attribute keeps a file's pinned count while widening it past a single item.
fn inner_disallowed_methods_allow(src: &str) -> bool {
    let code = code_only(src);
    code.match_indices("clippy::disallowed_methods")
        .any(|(at, _)| {
            code.get(..at)
                .and_then(|before| before.rfind('#'))
                .and_then(|hash| code.get(hash + 1..))
                .is_some_and(|rest| rest.starts_with('!'))
        })
}

/// The pinned allow count for workspace-relative `rel` (0 when unlisted).
fn pinned_allows(rel: &str) -> usize {
    ESCAPE_HATCH_SITES
        .iter()
        .find(|(file, _)| *file == rel)
        .map_or(0, |(_, count)| *count)
}

/// The workspace root.
fn workspace() -> PathBuf {
    e2e_support::manifest_dir!().join("../..")
}

/// Every scanned file under `src/`, `tools/`, and `examples/` whose path
/// satisfies `keep`, as `(workspace-relative path, text)`.
///
/// The set is exactly what git would commit — tracked files plus untracked
/// files not ignored — so gitignored build output (a vendored runtime copy
/// under an `out/` dir, a `target/`) is never scanned while a new source file
/// not yet added still is. Hidden directories are skipped; integration-test
/// trees are skipped too unless `with_tests`.
fn scanned_files(with_tests: bool, keep: impl Fn(&str) -> bool) -> Vec<(String, String)> {
    let root = workspace();
    let listed = std::process::Command::new("git")
        .arg("-C")
        .arg(&root)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .args(["--", "src", "tools", "examples"])
        .output();
    assert!(
        matches!(&listed, Ok(out) if out.status.success()),
        "git ls-files must list the workspace checkout: {listed:?}"
    );
    let Ok(listed) = listed else {
        return Vec::new();
    };
    // A lossy decode would turn a non-UTF-8 name into a path that is never
    // read, so the listing must decode exactly.
    let listed = String::from_utf8(listed.stdout);
    assert!(
        listed.is_ok(),
        "git ls-files listed a non-UTF-8 path: {listed:?}"
    );
    let Ok(listed) = listed else {
        return Vec::new();
    };
    listed
        .split('\0')
        .filter(|rel| !rel.is_empty() && keep(rel))
        .filter(|rel| {
            let dir = rel.rsplit_once('/').map_or("", |(dir, _)| dir);
            !dir.split('/')
                .any(|d| d.starts_with('.') || (!with_tests && d == "tests"))
        })
        .filter_map(|rel| match std::fs::read_to_string(root.join(rel)) {
            Ok(text) => Some(Ok((rel.to_owned(), text))),
            // `--cached` still lists a tracked file deleted from the worktree;
            // a dangling symlink still exists, so it is not skipped.
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && root.join(rel).symlink_metadata().is_err() =>
            {
                None
            }
            Err(e) => Some(Err(format!("{rel}: {e}"))),
        })
        .collect::<Result<Vec<_>, String>>()
        .unwrap_or_else(|unreadable| {
            assert!(
                unreadable.is_empty(),
                "unreadable scanned file {unreadable}"
            );
            Vec::new()
        })
}

/// Whether workspace-relative `rel` names a Rust source file.
fn is_rust_source(rel: &str) -> bool {
    std::path::Path::new(rel)
        .extension()
        .is_some_and(|ext| ext == "rs")
}

/// Every `.rs` file under `src/`, `tools/`, and `examples/`, keyed by its
/// workspace-relative `/`-separated path.
fn workspace_sources(with_tests: bool) -> Vec<(String, String)> {
    scanned_files(with_tests, is_rust_source)
}

/// The workspace root manifest and every `Cargo.toml` under `src/`, `tools/`,
/// and `examples/`, keyed by its workspace-relative path.
fn workspace_manifests() -> Vec<(String, String)> {
    let root = workspace();
    let mut files: Vec<(String, String)> = std::fs::read_to_string(root.join("Cargo.toml"))
        .ok()
        .map(|text| ("Cargo.toml".to_owned(), text))
        .into_iter()
        .collect();
    files.extend(scanned_files(true, |rel| {
        rel == "Cargo.toml" || rel.ends_with("/Cargo.toml")
    }));
    files
}

#[test]
fn the_scanned_set_is_the_committable_set() {
    let with_tests = scanned_files(true, is_rust_source);
    let production = scanned_files(false, is_rust_source);
    let this_file = "src/ipe-cli/tests/home_read_scan.rs";
    assert!(
        with_tests.iter().any(|(rel, _)| rel == this_file),
        "the scan must include tracked test sources when asked"
    );
    assert!(
        !production.iter().any(|(rel, _)| rel == this_file),
        "the production scan must skip integration-test trees"
    );
    assert!(
        ACCESSOR_FILES
            .iter()
            .all(|file| production.iter().any(|(rel, _)| rel == file)),
        "the production scan must include every audited home accessor"
    );

    let listed = with_tests
        .iter()
        .map(|(rel, _)| rel.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let checked = std::process::Command::new("git")
        .arg("-C")
        .arg(workspace())
        .args(["check-ignore", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(mut stdin) = child.stdin.take() {
                std::io::Write::write_all(&mut stdin, listed.as_bytes())?;
            }
            child.wait_with_output()
        });
    assert!(
        matches!(&checked, Ok(out) if out.stdout.is_empty()),
        "the scan must never read gitignored build output: {checked:?}"
    );
}

#[test]
fn no_manifest_depends_on_a_home_dir_crate() {
    let manifests = workspace_manifests();
    assert!(
        manifests.iter().any(|(rel, _)| rel == "Cargo.toml"),
        "the scan found no root manifest; the walk root is wrong"
    );
    let offenders: Vec<_> = manifests
        .iter()
        .map(|(rel, text)| (rel, home_crate_deps(text)))
        .filter(|(_, hits)| !hits.is_empty())
        .collect();
    assert!(
        offenders.is_empty(),
        "a home-dir crate resolves the host home outside the validated \
         accessors; use `ipe_sandbox::home::home_dir`: {offenders:?}"
    );
}

#[test]
fn a_planted_home_dir_crate_dependency_is_detected() {
    for manifest in [
        "[dependencies]\nhome = \"0.5\"",
        "[dependencies]\ndirs = { version = \"6\" }",
        "[dev-dependencies]\ndirs-next = \"2\"",
        "[dependencies]\ndirs_sys = \"0.5\"",
        "[dependencies]\ndirectories.workspace = true",
        "[workspace.dependencies]\ndirectories-next = \"2\"",
        "[target.'cfg(unix)'.dependencies]\n  etcetera = \"0.8\"",
        "[dependencies.dirs-sys-next]\nversion = \"0.1\"",
        "[dependencies]\nhd = { package = \"home\", version = \"0.5\" }",
    ] {
        assert!(
            !home_crate_deps(manifest).is_empty(),
            "the scan missed a home-dir crate dependency: {manifest:?}"
        );
    }
    for manifest in [
        "[package]\nhomepage = \"https://example.org\"",
        "[dependencies]\ndirsx = \"1\"",
        "# home = \"0.5\"",
        "[dependencies]\nipe_env = { path = \"../compiler/env\" }",
    ] {
        assert!(
            home_crate_deps(manifest).is_empty(),
            "the scan flagged a non-home-dir manifest line: {manifest:?}"
        );
    }
}

#[test]
fn no_production_source_reads_the_home_directly() {
    let files = workspace_sources(false);
    assert!(
        !files.is_empty(),
        "the scan found no sources; the walk root is wrong"
    );
    let offenders: Vec<_> = files
        .iter()
        .filter(|(rel, _)| !ACCESSOR_FILES.contains(&rel.as_str()) && rel != BAN_PROOF_FILE)
        .map(|(rel, text)| (rel, raw_home_reads(text)))
        .filter(|(_, hits)| !hits.is_empty())
        .collect();
    assert!(
        offenders.is_empty(),
        "raw home reads found; use `ipe_sandbox::home::home_dir` (compiler) or \
         `system::home_dir` (runtime) instead: {offenders:?}"
    );
}

#[test]
fn ban_proof_file_never_calls_the_home_reader() {
    let files = workspace_sources(false);
    let (_, text) = files
        .iter()
        .find(|(rel, _)| rel == BAN_PROOF_FILE)
        .expect("the ban-proof file moved; update `BAN_PROOF_FILE`");
    let flat: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    for read in STD_HOME_READS {
        assert_eq!(
            flat.matches(read).count(),
            flat.matches(&format!("let_=::std::{read};")).count(),
            "`{BAN_PROOF_FILE}` may only name `{read}` as a `let _ = ..;` value"
        );
    }
    assert!(
        literal_home_reads()
            .iter()
            .all(|read| !flat.contains(read.as_str()))
            && home_crate_paths(text).is_empty(),
        "`{BAN_PROOF_FILE}` reads the home beyond naming the `std` reader"
    );
}

#[test]
fn no_source_reads_the_environment_outside_an_audited_reader() {
    let files = workspace_sources(true);
    let offenders: Vec<_> = files
        .iter()
        .filter(|(rel, _)| {
            !rel.starts_with(RUNTIME_ROOT) && !ENV_ALLOW_FILES.contains(&rel.as_str())
        })
        .map(|(rel, text)| (rel, raw_env_reads(text)))
        .filter(|(_, hits)| !hits.is_empty())
        .collect();
    assert!(
        offenders.is_empty(),
        "raw environment reads found; read named keys through `ipe_env`, the \
         home through `ipe_sandbox::home::home_dir`: {offenders:?}"
    );
}

#[test]
fn the_home_name_constant_stays_in_its_module() {
    let files = workspace_sources(true);
    let offenders: Vec<_> = files
        .iter()
        .filter(|(rel, text)| !HOME_VAR_FILES.contains(&rel.as_str()) && names_home_var(text))
        .map(|(rel, _)| rel)
        .collect();
    assert!(
        offenders.is_empty(),
        "a home-name constant named outside {HOME_VAR_FILES:?}; read the home through \
         `ipe_sandbox::home::home_dir` (compiler) or `system::home_dir` (runtime): \
         {offenders:?}"
    );
}

#[test]
fn the_env_escape_hatch_is_pinned_to_the_audited_readers() {
    let files = workspace_sources(true);
    let offenders: Vec<_> = files
        .iter()
        .map(|(rel, text)| (rel, disallowed_methods_allows(text), pinned_allows(rel)))
        .filter(|(_, found, pinned)| found != pinned)
        .collect();
    assert!(
        offenders.is_empty(),
        "`clippy::disallowed_methods` allows differ from the pinned sites \
         (file, found, pinned): {offenders:?}"
    );
    let inner: Vec<_> = files
        .iter()
        .filter(|(_, text)| inner_disallowed_methods_allow(text))
        .map(|(rel, _)| rel)
        .collect();
    assert!(
        inner.is_empty(),
        "a module- or crate-wide `#![allow(clippy::disallowed_methods)]`; allow it on \
         the one audited item instead: {inner:?}"
    );
    for (file, pinned) in ESCAPE_HATCH_SITES {
        assert!(
            files.iter().any(|(rel, _)| rel == file),
            "pinned escape-hatch file `{file}` ({pinned}) is not scanned"
        );
    }
}

#[test]
fn the_jail_passthrough_stays_in_the_sandbox() {
    let files = workspace_sources(true);
    let offenders: Vec<_> = files
        .iter()
        .filter(|(rel, text)| {
            !rel.starts_with(SANDBOX_SRC)
                && (reaches_raw_passthrough(text)
                    || (!JAIL_ENV_CALLERS.contains(&rel.as_str())
                        && names_ident(text, JAIL_ENV_FN)))
        })
        .map(|(rel, _)| rel)
        .collect();
    assert!(
        offenders.is_empty(),
        "the jail env passthrough used outside the sandbox crate and its pinned \
         callers; read named keys through `ipe_env`: {offenders:?}"
    );
}

#[test]
fn no_production_source_reads_a_procfs_environment() {
    let files = workspace_sources(false);
    let offenders: Vec<_> = files
        .iter()
        .filter(|(rel, text)| !rel.starts_with(RUNTIME_ROOT) && reads_proc_environ(text))
        .map(|(rel, _)| rel)
        .collect();
    assert!(
        offenders.is_empty(),
        "a `/proc/*/environ` read hands out the whole environment, home \
         included; read named keys through `ipe_env`: {offenders:?}"
    );
}

#[test]
fn a_planted_passthrough_or_procfs_bypass_is_detected() {
    for src in [
        "let h = ipe_sandbox::host_env::granted(\"HOME\");",
        "let h = host_env::granted(k);",
        "use ipe_sandbox::host_env::{granted};",
        "use ipe_sandbox::host_env::*;",
        "use ipe_sandbox::host_env::granted as g;",
        "use ipe_sandbox::host_env::granted_env as g;",
    ] {
        assert!(
            reaches_raw_passthrough(src),
            "the scan missed a raw passthrough: {src:?}"
        );
    }
    for src in [
        "let e = ipe_sandbox::host_env::granted_env(&p);",
        "use ipe_sandbox::host_env::granted_env as g;",
        "use ipe_sandbox::{host_env::granted_env};",
    ] {
        assert!(
            names_ident(src, JAIL_ENV_FN),
            "the scan missed a jail env passthrough: {src:?}"
        );
    }
    for src in [
        "let e = std::fs::read(\"/proc/self/environ\");",
        "let e = std::fs::read(Path::new(\"/proc/1\").join(\"environ\"));",
    ] {
        assert!(
            reads_proc_environ(src),
            "the scan missed a procfs environment read: {src:?}"
        );
    }
    assert!(!raw_env_reads("let h = unsafe { libc::getenv(k) };").is_empty());
    assert!(!reaches_raw_passthrough(
        "let e = ipe_sandbox::host_env::granted_env(&p);"
    ));
    assert!(!names_ident("let e = granted_envs;", JAIL_ENV_FN));
    assert!(!reads_proc_environ("// read /proc/self/environ\"x\""));
    assert!(!reads_proc_environ("let e = \"the environment\";"));
    assert!(!reads_proc_environ(
        "(\"experimental.exportableenviron\", INERT),"
    ));
    assert!(!reads_proc_environ("let k = \"hooks.subenviron\";"));
}

#[test]
fn every_pinned_file_exists() {
    let root = workspace();
    for rel in ACCESSOR_FILES
        .iter()
        .chain(ENV_ALLOW_FILES)
        .chain(ESCAPE_HATCH_SITES.iter().map(|(file, _)| file))
        .chain(JAIL_ENV_CALLERS)
        .chain(HOME_VAR_FILES)
    {
        assert!(
            root.join(rel).is_file(),
            "pinned file `{rel}` is gone; drop it from the list"
        );
    }
}

#[test]
fn a_planted_raw_home_read_is_detected() {
    let planted = [
        "let h = std::env::var_os(\"HOME\");",
        "let h = std::env::var( \"HOME\" ).ok();",
        "let h = env::var_os(\n    \"USERPROFILE\",\n);",
        "let h = read_env_var_os(\"HOME\");",
        "#[allow(deprecated)] let h = std::env::home_dir();",
        "use std::env::home_dir;",
        "let h = dirs::home_dir();",
        "const H: Option<&str> = option_env!(\"HOME\");",
        "const H: &str = env!(\"HOME\");",
        "const H: &str = env!(\n    \"USERPROFILE\",\n    \"needs a home\",\n);",
        "let h = option_env!(\"HOMEDRIVE\");",
        "let h = std::env::var_os(\"HOMEPATH\");",
        "let h = unsafe { libc::getenv(c\"HOME\".as_ptr()) };",
        "let h = unsafe { getenv(\"USERPROFILE\\0\".as_ptr().cast()) };",
        "let h = unsafe { libc::getenv(b\"HOME\\0\".as_ptr().cast()) };",
        "let h = home::home_dir();",
        "let c = home::cargo_home();",
        "use home::env::home_dir_with_env;",
        "let h = ::home::home_dir();",
        "let c = dirs::config_dir();",
        "let c = dirs::cache_dir();",
        "let d = dirs::data_dir();",
        "let d = dirs::data_local_dir();",
        "let s = dirs::state_dir();",
        "use dirs::{config_local_dir, runtime_dir};",
        "let h = dirs_next::home_dir();",
        "let c = dirs_next::config_dir();",
        "let h = dirs_sys::home_dir();",
        "let b = directories::BaseDirs::new();",
        "let p = directories_next::ProjectDirs::from(q, o, a);",
        "let s = etcetera::choose_base_strategy();",
        "use etcetera::{BaseStrategy, choose_base_strategy};",
        "use ipe_sandbox::{home::home_dir};",
    ];
    for src in planted {
        assert!(
            !raw_home_reads(src).is_empty(),
            "the scan missed a raw home read: {src:?}"
        );
    }
}

#[test]
fn every_home_name_is_a_literal_home_read() {
    let needles = literal_home_reads();
    for name in ipe_env::HOME_NAMES {
        for shape in LITERAL_READ_SHAPES {
            assert!(
                needles.contains(&shape.replace("{}", name)),
                "`{shape}` over `{name}` is not scanned"
            );
        }
    }
}

#[test]
fn a_planted_environment_bypass_is_detected() {
    let planted = [
        // The constant path: the home name held in a constant.
        "let h = std::env::var_os(HOME_VAR);",
        // The alias: the home name bound to a local first.
        "let k = \"HOME\";\nlet h = std::env::var(k);",
        // The whole-environment iterator: the home under its own name.
        "let h = std::env::vars().find(|(k, _)| k == \"HOME\");",
        "let h = std::env::vars_os().next();",
        "use std::env;\nlet h = env::var_os(key);",
        "use std::env::{var, var_os};",
        "use std::env::*;",
        "let h = ::std::env::var(key);",
    ];
    for src in planted {
        assert!(
            !raw_env_reads(src).is_empty(),
            "the scan missed a raw environment read: {src:?}"
        );
    }
    assert!(names_home_var("let h = home::HOME_VAR;"));
    assert!(names_home_var("let h = home::WINDOWS_HOME_VAR;"));
    assert!(allows_disallowed_methods(
        "#[allow(clippy::disallowed_methods)]\nfn f() {}"
    ));
    assert_eq!(
        disallowed_methods_allows(
            "#[allow(clippy::disallowed_methods)]\nfn f() {}\n\
             // clippy::disallowed_methods in a comment\n\
             #[allow(clippy::disallowed_methods)]\nfn g() {}"
        ),
        2,
        "a second allow in a pinned file changes its count"
    );
    assert_eq!(pinned_allows("src/ipe-cli/src/main.rs"), 0);
    for src in [
        "#![allow(clippy::disallowed_methods)]\nfn f() {}",
        "#![cfg_attr(test, allow(clippy::disallowed_methods))]",
        "#![expect(clippy::disallowed_methods)]",
    ] {
        assert!(
            inner_disallowed_methods_allow(src),
            "the scan missed an inner escape hatch: {src:?}"
        );
    }
    assert!(!inner_disallowed_methods_allow(
        "#![forbid(unsafe_code)]\n#[allow(clippy::disallowed_methods)]\nfn f() {}"
    ));
}

#[test]
fn the_audited_readers_and_non_reads_are_not_flagged() {
    let clean = [
        "let h = ipe_sandbox::home::home_dir();",
        "let v = ipe_env::var_os(\"HOMEBREW_PREFIX\");",
        "let v = ipe_env::var(key).ok();",
        "cmd.env(\"HOME\", scratch);",
        "let s = \"std::env::var_os(\\\"HOME\\\")\";",
        "let s = r#\"::std::env::var(\"IPE\")\"#;",
        "// std::env::vars() walks the whole environment",
        "/* std::env::var_os(HOME_VAR) */",
        "use crate::env::{Scope, Frame};",
        "let c = '\"'; let d = std::env::args();",
    ];
    for src in clean {
        assert!(
            raw_env_reads(src).is_empty() && !names_home_var(src),
            "the scan flagged a sanctioned form: {src:?}"
        );
    }
    assert!(!names_home_var("const HOME_VARS: u8 = 0;"));
    assert!(!allows_disallowed_methods(
        "// allow(clippy::disallowed_methods) only in audited readers"
    ));
}

#[test]
fn a_home_write_and_a_neighbouring_key_are_not_home_reads() {
    let clean = [
        "let h = ipe_sandbox::home::home_dir();",
        "let h = crate::env_dir::home();",
        "cmd.env(\"HOME\", scratch);",
        "let v = std::env::var_os(\"HOMEBREW_PREFIX\");",
        "let h = crate::home::home_dir();",
        "let h = super :: home::home_dir();",
        "let h = my_home::root();",
        "let h = homedir::root();",
        "let s = \"dirs::home_dir()\";",
        "// dirs::home_dir() would read the host home",
    ];
    for src in clean {
        assert!(
            raw_home_reads(src).is_empty(),
            "the scan flagged a sanctioned form: {src:?}"
        );
    }
}

mod lexical {
    //! Refuses a direct read of the home directory anywhere in the workspace's
    //! production sources.
    //!
    //! An unset, empty, or relative `HOME` resolves against whatever the current
    //! working directory is, so every home read goes through one validated accessor
    //! that yields an absolute path or nothing: `ipe_sandbox::home::home_dir` on the
    //! compiler side and `system::home_dir` in the standalone runtime.
    //!
    //! The scan lexes each production file (comments dropped, `#[cfg(test)]` items
    //! skipped, string literals decoded) and refuses:
    //! - any string literal, raw or not, spelling a home variable name — so a
    //!   `var("HOME")`, a `const` key, `env!`/`option_env!`, or a key handed to a
    //!   computed-key reader is caught at the literal;
    //! - the std/`dirs` home helpers and whole-environment iteration;
    //! - an environment read whose key is neither a literal nor a `SCREAMING_CASE`
    //!   constant (whose own literal the first rule sees), and a reader passed or
    //!   imported as a value;
    //! - an alias of the `env` module (`use std::env as e`, `env::{self as e}`),
    //!   under which a read would no longer spell `env::`.
    //!
    //! Each exception names one function or constant in one file with its reason
    //! ([`LITERAL_ALLOWED`], [`DYNAMIC_KEY_ALLOWED`]); the rest of that file is
    //! scanned like any other. A key assembled at run time from pieces
    //! (`concat!`, `format!` over fragments) inside an allowlisted computed-key
    //! reader is beyond a lexical scan.

    use std::ops::Range;
    use std::path::PathBuf;

    /// The environment variable names that carry the user's home directory.
    const HOME_NAMES: &[&str] = &ipe_env::HOME_NAMES;

    /// A function allowed to hold a construct the scan otherwise refuses.
    struct Allowed {
        /// Workspace-relative file.
        file: &'static str,
        /// The function or constant, by name, whose item is exempt.
        func: &'static str,
        /// Why this site is sound.
        reason: &'static str,
    }

    /// Functions and constants allowed to spell a home variable name.
    const LITERAL_ALLOWED: &[Allowed] = &[
        Allowed {
            file: "src/runtime/rust/src/home_core.rs",
            func: "HOME_VAR",
            reason: "the one platform home-name constant, shared by both home accessors; \
                     reads nothing",
        },
        Allowed {
            file: "src/runtime/rust/src/home_core.rs",
            func: "WINDOWS_HOME_VAR",
            reason: "the one Windows home-name constant, shared by both home accessors; \
                     reads nothing",
        },
        Allowed {
            file: "src/compiler/env/src/lib.rs",
            func: "HOME_NAMES",
            reason: "the home names the audited reader refuses; reads nothing",
        },
        Allowed {
            file: "src/ipe-cli/src/audit_native.rs",
            func: "cargo_home_env",
            reason: "writes the accessor's validated home into a child's environment; reads nothing",
        },
        Allowed {
            file: WINDOWS_JAIL_FILE,
            func: "name",
            reason: WINDOWS_JAIL_HOST_ENV,
        },
    ];

    /// The Windows run jail, whose base set forwards host profile variables.
    const WINDOWS_JAIL_FILE: &str = "src/compiler/sandbox/src/run_jail/windows.rs";

    /// The home names the Windows run jail forwards from the host:
    /// `WindowsBaseEnv`'s `AppContainer` profile variables.
    const WINDOWS_JAIL_HOME_NAMES: &[&str] = &["USERPROFILE", "HOMEDRIVE", "HOMEPATH"];

    /// The reason shared by the Unix jail spawners' `host_env` reader closures.
    const JAIL_HOST_ENV: &str = "`host_env` closure: yields only the host's `LANG` and \
         the profile's consented `env_allowlist`";

    /// The reason for the Windows run jail's `host_env` reader and the base-set
    /// names it reads.
    const WINDOWS_JAIL_HOST_ENV: &str = "`host_env` closure: yields only the host values \
         of `WindowsBaseEnv`'s host-valued names (`SystemRoot`, `PATH`, `LANG`, and the \
         `AppContainer` profile variables `LOCALAPPDATA`, `APPDATA`, `USERPROFILE`, \
         `HOMEDRIVE`, `HOMEPATH` that `CreateProcessW` requires) and the profile's \
         consented `env_allowlist`; the values name host profile folders but grant the \
         `AppContainer` token nothing";

    /// The reason shared by the runtime's `System.getenv*` kernels.
    const PROGRAM_GETENV: &str = "a `System.getenv*` kernel: the key is the Ipê program's own \
         choice, under the program's own consented environment capability";

    /// Functions allowed to read the environment under a computed key.
    const DYNAMIC_KEY_ALLOWED: &[Allowed] = &[
        Allowed {
            file: "src/ipe-cli/src/env_dir.rs",
            func: "ambient_home",
            reason: "callers pass `XDG_*` literals, which the literal rule scans",
        },
        Allowed {
            file: "src/compiler/sandbox/src/home.rs",
            func: "tool_home",
            reason: "the one tool-home reader; callers pass `CARGO_HOME`/`RUSTUP_HOME` literals, \
                     which the literal rule scans",
        },
        Allowed {
            file: "src/compiler/env/src/lib.rs",
            func: "var",
            reason: "the audited compiler-side reader; refuses every home key before reading",
        },
        Allowed {
            file: "src/compiler/env/src/lib.rs",
            func: "var_os",
            reason: "the audited compiler-side reader; refuses every home key before reading",
        },
        Allowed {
            file: "src/compiler/sandbox/src/host_env.rs",
            func: "granted",
            reason: "the sandbox-private jail passthrough; callers pass a profile's consented \
                     `env_allowlist` or the jail's fixed names",
        },
        Allowed {
            file: "src/ipe-cli/src/wasi_run.rs",
            func: "build_ctx",
            reason: "forwards the capability-granted names to the guest verbatim; derives no path",
        },
        Allowed {
            file: "src/ipe-cli/src/build_plan.rs",
            func: "preflight",
            reason: "reads `CC_<triple>`, a fixed prefix over a parsed target triple",
        },
        Allowed {
            file: "src/ipe-cli/src/watch.rs",
            func: "env_flag_on",
            reason: "callers pass flag-name literals, which the literal rule scans",
        },
        Allowed {
            file: "src/runtime/rust/src/web/console.rs",
            func: "env",
            reason: "callers pass `IPE_*_TOKEN` literals, which the literal rule scans",
        },
        Allowed {
            file: "src/runtime/rust/src/web/push_exporter.rs",
            func: "raw",
            reason: "reads `ExporterEnv::name`, a closed match over fixed `IPE_*` literals",
        },
        Allowed {
            file: "src/ipe-cli/src/ffi.rs",
            func: "jail_limits",
            reason: "reads the fixed `IPE_FFI_*` cap overrides named in its own body",
        },
        Allowed {
            file: "src/compiler/sandbox/src/build_jail.rs",
            func: "build_in_jail",
            reason: JAIL_HOST_ENV,
        },
        Allowed {
            file: "src/compiler/sandbox/src/run_jail/linux.rs",
            func: "exec_in_run_jail",
            reason: JAIL_HOST_ENV,
        },
        Allowed {
            file: "src/compiler/sandbox/src/run_jail/linux.rs",
            func: "exec_embedded_in_run_jail",
            reason: JAIL_HOST_ENV,
        },
        Allowed {
            file: "src/compiler/sandbox/src/run_jail/macos.rs",
            func: "exec_in_run_jail",
            reason: JAIL_HOST_ENV,
        },
        Allowed {
            file: WINDOWS_JAIL_FILE,
            func: "run_confined",
            reason: WINDOWS_JAIL_HOST_ENV,
        },
        Allowed {
            file: "src/runtime/rust/src/system.rs",
            func: "read_env_var",
            reason: "the runtime's overlay-aware reader; every caller's key is scanned at its site",
        },
        Allowed {
            file: "src/runtime/rust/src/system.rs",
            func: "read_env_var_os",
            reason: "the runtime's overlay-aware reader; every caller's key is scanned at its site",
        },
        Allowed {
            file: "src/runtime/rust/src/system.rs",
            func: "locked_set_var_if_absent",
            reason: "a presence probe before a default write; returns no value",
        },
        Allowed {
            file: "src/runtime/rust/src/system.rs",
            func: "system_getenv",
            reason: PROGRAM_GETENV,
        },
        Allowed {
            file: "src/runtime/rust/src/system.rs",
            func: "system_getenv_or",
            reason: PROGRAM_GETENV,
        },
        Allowed {
            file: "src/runtime/rust/src/system.rs",
            func: "system_getenv_int",
            reason: PROGRAM_GETENV,
        },
        Allowed {
            file: "src/runtime/rust/src/system.rs",
            func: "system_getenv_bool",
            reason: PROGRAM_GETENV,
        },
        Allowed {
            file: "src/runtime/rust/src/app_config.rs",
            func: "ipe_app_from_env",
            reason: "reads the program's declared config variable, typed as a `Secret`",
        },
        Allowed {
            file: "src/runtime/rust/src/app_config.rs",
            func: "ipe_app_from_env_required",
            reason: "reads the program's declared config variable, typed as a `Secret`",
        },
        Allowed {
            file: "src/runtime/rust/src/email.rs",
            func: "email_endpoint",
            reason: "reads a fixed per-provider endpoint override name",
        },
        Allowed {
            file: "src/runtime/rust/src/system.rs",
            func: "lookup",
            reason: "the one raw reader of an `EnvCeiling`'s `&'static str` name; every ceiling is built from a literal the literal rule scans",
        },
    ];

    /// Whitespace-free code fragments that read the home or the whole environment.
    const RAW_HOME_CALLS: &[&str] = &["env::home_dir", "dirs::home_dir", "env::vars"];

    /// One production file, lexed.
    struct Lexed {
        /// The source with comments and literal bodies blanked to spaces; byte
        /// offsets match the original.
        code: Vec<u8>,
        /// Each string literal's starting offset and decoded text.
        literals: Vec<(usize, String)>,
    }

    /// Whether `b` can continue an identifier.
    const fn ident_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80
    }

    /// The byte at `i`, or `0` past the end.
    fn at(bytes: &[u8], i: usize) -> u8 {
        bytes.get(i).copied().unwrap_or(0)
    }

    /// The byte before `i`, or `0` at the start.
    fn before(bytes: &[u8], i: usize) -> u8 {
        i.checked_sub(1).map_or(0, |k| at(bytes, k))
    }

    /// Blank `range` of `code` to spaces, keeping line breaks.
    fn blank(code: &mut [u8], range: Range<usize>) {
        for b in code.get_mut(range).into_iter().flatten() {
            if *b != b'\n' {
                *b = b' ';
            }
        }
    }

    /// Decode the escapes of a non-raw string body.
    fn unescape(body: &str) -> String {
        let mut out = String::new();
        let mut chars = body.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('0') => out.push('\0'),
                Some('x') => {
                    let hex: String = chars.by_ref().take(2).collect();
                    if let Some(ch) = u8::from_str_radix(&hex, 16).ok().map(char::from) {
                        out.push(ch);
                    }
                }
                Some('u') => {
                    let hex: String = chars
                        .by_ref()
                        .skip_while(|c| *c == '{')
                        .take_while(|c| *c != '}')
                        .collect();
                    if let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                        out.push(ch);
                    }
                }
                Some('\n') => while chars.next_if(|c| c.is_whitespace()).is_some() {},
                Some(other) => out.push(other),
                None => {}
            }
        }
        out
    }

    /// The offset of `needle` in `src` at or after `from`, or `src`'s length.
    fn find_from(src: &str, from: usize, needle: &str) -> usize {
        src.get(from..)
            .and_then(|rest| rest.find(needle))
            .map_or(src.len(), |n| from + n)
    }

    /// Lex `src`: drop comments, record and blank string literals, and blank
    /// character literals so a quoted bracket or quote cannot desynchronize the
    /// scan.
    fn lex(src: &str) -> Lexed {
        let bytes = src.as_bytes();
        let mut code = bytes.to_vec();
        let mut literals = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let b = at(bytes, i);
            if b == b'/' && at(bytes, i + 1) == b'/' {
                let end = find_from(src, i, "\n");
                blank(&mut code, i..end);
                i = end;
            } else if b == b'/' && at(bytes, i + 1) == b'*' {
                let start = i;
                let mut depth = 0usize;
                while i < bytes.len() {
                    if at(bytes, i) == b'/' && at(bytes, i + 1) == b'*' {
                        depth += 1;
                        i += 2;
                    } else if at(bytes, i) == b'*' && at(bytes, i + 1) == b'/' {
                        depth = depth.saturating_sub(1);
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
                blank(&mut code, start..i);
            } else if b == b'r' && matches!(at(bytes, i + 1), b'"' | b'#') && raw_prefix(bytes, i) {
                let mut j = i + 1;
                while at(bytes, j) == b'#' {
                    j += 1;
                }
                if at(bytes, j) != b'"' {
                    i = j;
                    continue;
                }
                let closer: String = std::iter::once('"')
                    .chain(std::iter::repeat_n('#', j - i - 1))
                    .collect();
                let body_end = find_from(src, j + 1, &closer);
                let body = src.get(j + 1..body_end).unwrap_or("");
                literals.push((i, body.to_owned()));
                blank(&mut code, j + 1..body_end);
                i = body_end + closer.len();
            } else if b == b'"' {
                let mut j = i + 1;
                while j < bytes.len() && at(bytes, j) != b'"' {
                    j += if at(bytes, j) == b'\\' { 2 } else { 1 };
                }
                let body_end = j.min(bytes.len());
                let body = src.get(i + 1..body_end).unwrap_or("");
                literals.push((i, unescape(body)));
                blank(&mut code, i + 1..body_end);
                i = body_end + 1;
            } else if b == b'\'' && char_quote(bytes, i) {
                i = skip_char_literal(src, &mut code, i);
            } else {
                i += 1;
            }
        }
        Lexed { code, literals }
    }

    /// Whether the `r` at `i` opens a raw string (`r"`, `br"`, `cr"`) rather than
    /// ending an identifier.
    fn raw_prefix(bytes: &[u8], i: usize) -> bool {
        let prev = before(bytes, i);
        !ident_byte(prev)
            || (matches!(prev, b'b' | b'c')
                && !ident_byte(i.checked_sub(1).map_or(0, |k| before(bytes, k))))
    }

    /// Whether the quote at `i` can open a character literal (`'x'`, `b'x'`)
    /// rather than sit inside an identifier.
    fn char_quote(bytes: &[u8], i: usize) -> bool {
        let prev = before(bytes, i);
        !ident_byte(prev)
            || (prev == b'b' && !ident_byte(i.checked_sub(1).map_or(0, |k| before(bytes, k))))
    }

    /// Skip a character literal starting at `i` (blanking it), or step past a
    /// lifetime's quote.
    fn skip_char_literal(src: &str, code: &mut [u8], i: usize) -> usize {
        let bytes = src.as_bytes();
        if at(bytes, i + 1) == b'\\' {
            let end = find_from(src, i + 3, "'");
            blank(code, i + 1..end);
            return end + 1;
        }
        let width = src
            .get(i + 1..)
            .and_then(|rest| rest.chars().next())
            .map_or(1, char::len_utf8);
        if at(bytes, i + 1 + width) == b'\'' {
            blank(code, i + 1..i + 1 + width);
            return i + 2 + width;
        }
        i + 1
    }

    /// The index just past the bracket that closes the one at `open`.
    fn close_of(code: &[u8], open: usize) -> usize {
        let mut depth = 0usize;
        for (k, b) in code.iter().enumerate().skip(open) {
            match b {
                b'{' | b'(' | b'[' => depth += 1,
                b'}' | b')' | b']' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return k + 1;
                    }
                }
                _ => {}
            }
        }
        code.len()
    }

    /// The end of the item starting at `from`: its matching `}` when a body opens
    /// before any top-level `;`, else just past that `;`.
    fn item_end(code: &[u8], from: usize) -> usize {
        let mut k = from;
        while k < code.len() {
            match at(code, k) {
                b'(' | b'[' => k = close_of(code, k),
                b'{' => return close_of(code, k),
                b';' => return k + 1,
                _ => k += 1,
            }
        }
        code.len()
    }

    /// Keywords that open an item or statement ending at its body or its `;`.
    const ITEM_KEYWORDS: &[&str] = &[
        "fn",
        "mod",
        "impl",
        "struct",
        "enum",
        "union",
        "use",
        "const",
        "static",
        "type",
        "trait",
        "unsafe",
        "async",
        "extern",
        "macro_rules",
        "let",
    ];

    /// The end of the attributed element starting at `from`.
    ///
    /// An item or `let` ends as [`item_end`] says. Anything else — an enum
    /// variant, a struct field, a match arm, an expression — also ends at a
    /// top-level `,` or just before an unmatched `}`, so the skip never runs past
    /// the list the element sits in. A `,` inside an unbracketed generic ends such
    /// an element early, which only leaves more code scanned.
    fn attributed_end(code: &[u8], from: usize) -> usize {
        let mut p = skip_ws(code, from);
        if token_at(code, p, "pub") {
            p = skip_ws(code, p + 3);
            if at(code, p) == b'(' {
                p = skip_ws(code, close_of(code, p));
            }
        }
        if ITEM_KEYWORDS.iter().any(|word| token_at(code, p, word)) {
            return item_end(code, from);
        }
        let mut k = from;
        while k < code.len() {
            match at(code, k) {
                b'(' | b'[' => k = close_of(code, k),
                b'{' => return close_of(code, k),
                b';' | b',' => return k + 1,
                b'}' => return k,
                _ => k += 1,
            }
        }
        code.len()
    }

    /// The `{` of the innermost brace block enclosing offset `k`, if any.
    fn enclosing_open(code: &[u8], k: usize) -> Option<usize> {
        let mut depth = 0usize;
        for j in (0..k).rev() {
            match at(code, j) {
                b'}' => depth += 1,
                b'{' => match depth.checked_sub(1) {
                    Some(outer) => depth = outer,
                    None => return Some(j),
                },
                _ => {}
            }
        }
        None
    }

    /// The index just past whitespace starting at `k`.
    fn skip_ws(code: &[u8], mut k: usize) -> usize {
        while at(code, k).is_ascii_whitespace() {
            k += 1;
        }
        k
    }

    /// The index of the last non-whitespace byte before `k`, plus one.
    fn skip_ws_back(code: &[u8], mut k: usize) -> usize {
        while k > 0 && before(code, k).is_ascii_whitespace() {
            k -= 1;
        }
        k
    }

    /// Whether `code` spells `word` as a whole token at `k`.
    fn token_at(code: &[u8], k: usize, word: &str) -> bool {
        let end = k + word.len();
        code.get(k..end) == Some(word.as_bytes())
            && !ident_byte(before(code, k))
            && !ident_byte(at(code, end))
    }

    /// The index past the whitespace-separated tokens `words` at `k`, if they match.
    fn tokens_at(code: &[u8], k: usize, words: &[&str]) -> Option<usize> {
        let mut p = k;
        for word in words {
            p = skip_ws(code, p);
            if code.get(p..p + word.len()) != Some(word.as_bytes()) {
                return None;
            }
            p += word.len();
        }
        Some(p)
    }

    /// The byte ranges of elements under an exact `#[cfg(test)]` (attribute
    /// included), and of the block an inner `#![cfg(test)]` sits in — the rest of
    /// the file at the top level, else the rest of its enclosing `{ .. }`.
    fn test_item_ranges(code: &[u8]) -> Vec<Range<usize>> {
        let mut out = Vec::new();
        let mut k = 0;
        while k < code.len() {
            if at(code, k) != b'#' {
                k += 1;
                continue;
            }
            if tokens_at(code, k + 1, &["!", "[", "cfg", "(", "test", ")", "]"]).is_some() {
                let Some(open) = enclosing_open(code, k) else {
                    out.push(k..code.len());
                    break;
                };
                let end = close_of(code, open).max(k + 1);
                out.push(k..end);
                k = end;
                continue;
            }
            let Some(mut p) = tokens_at(code, k + 1, &["[", "cfg", "(", "test", ")", "]"]) else {
                k += 1;
                continue;
            };
            p = skip_ws(code, p);
            while at(code, p) == b'#' {
                p = skip_ws(code, close_of(code, skip_ws(code, p + 1)));
            }
            let end = attributed_end(code, p).max(k + 1);
            out.push(k..end);
            k = end;
        }
        out
    }

    /// The byte range of every `fn <name>` or `const <name>` item in `code`.
    fn fn_ranges(code: &[u8], name: &str) -> Vec<Range<usize>> {
        let mut out = Vec::new();
        let mut k = 0;
        while k < code.len() {
            let keyword = ["fn", "const"].into_iter().find(|w| token_at(code, k, w));
            if let Some(keyword) = keyword {
                let p = skip_ws(code, k + keyword.len());
                if token_at(code, p, name) {
                    let end = item_end(code, p);
                    out.push(k..end);
                    k = end;
                    continue;
                }
            }
            k += 1;
        }
        out
    }

    /// A refused construct: its line and what it is.
    #[derive(Debug, PartialEq, Eq)]
    struct Hit {
        line: usize,
        what: String,
    }

    /// The 1-based line of byte offset `offset` in `code`.
    #[allow(clippy::naive_bytecount)] // test-only line count, no dep
    fn line_of(code: &[u8], offset: usize) -> usize {
        code.get(..offset)
            .map_or(0, |pre| pre.iter().filter(|b| **b == b'\n').count())
            + 1
    }

    /// Whether the call argument starting at `p` is a literal or a
    /// `SCREAMING_CASE` constant path, rather than a computed key.
    fn key_is_static(code: &[u8], p: usize) -> bool {
        let mut p = skip_ws(code, p);
        if at(code, p) == b'&' {
            p = skip_ws(code, p + 1);
        }
        if at(code, p) == b'"' || (at(code, p) == b'r' && matches!(at(code, p + 1), b'"' | b'#')) {
            return true;
        }
        let mut end = p;
        while ident_byte(at(code, end)) || at(code, end) == b':' {
            end += 1;
        }
        if !matches!(at(code, skip_ws(code, end)), b')' | b',') {
            return false;
        }
        let path = code.get(p..end).unwrap_or(&[]);
        let last = path.rsplit(|b| *b == b':').next().unwrap_or(&[]);
        !last.is_empty()
            && last
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
    }

    /// The path segment ending just before a `::` that ends at `k`, if any.
    fn owner_before(code: &[u8], k: usize) -> Option<&[u8]> {
        let colons = skip_ws_back(code, k);
        if colons < 2 || before(code, colons) != b':' || before(code, colons - 1) != b':' {
            return None;
        }
        let end = skip_ws_back(code, colons - 2);
        let mut start = end;
        while start > 0 && ident_byte(before(code, start)) {
            start -= 1;
        }
        code.get(start..end)
    }

    /// Whether the token at `k` is a std environment reader: `var`/`var_os` under
    /// `env::`, or the runtime's `read_env_var`/`read_env_var_os` called bare or
    /// under `system::` — never a method, a definition, or another type's path.
    fn is_env_reader(code: &[u8], k: usize, name: &str) -> bool {
        let owner = owner_before(code, k);
        match name {
            "var" | "var_os" => owner == Some(b"env".as_slice()),
            _ => {
                let prev_end = skip_ws_back(code, k);
                let prev_start = {
                    let mut s = prev_end;
                    while s > 0 && ident_byte(before(code, s)) {
                        s -= 1;
                    }
                    s
                };
                let prev_word = code.get(prev_start..prev_end).unwrap_or(&[]);
                owner.map_or_else(
                    || before(code, prev_end) != b'.' && prev_word != b"fn",
                    |owner| owner == b"system",
                )
            }
        }
    }

    /// Every refused construct in `src`, outside `#[cfg(test)]` items and outside
    /// the named exempt functions for each rule.
    fn raw_home_reads(src: &str, literal_ok: &[&str], dynamic_ok: &[&str]) -> Vec<Hit> {
        let Lexed { mut code, literals } = lex(src);
        let tests = test_item_ranges(&code);
        let in_any =
            |ranges: &[Range<usize>], offset: usize| ranges.iter().any(|r| r.contains(&offset));
        let literal_exempt: Vec<Range<usize>> = literal_ok
            .iter()
            .flat_map(|n| fn_ranges(&code, n))
            .collect();
        let dynamic_exempt: Vec<Range<usize>> = dynamic_ok
            .iter()
            .flat_map(|n| fn_ranges(&code, n))
            .collect();
        let mut hits = Vec::new();

        for (start, text) in &literals {
            if HOME_NAMES.contains(&text.as_str())
                && !in_any(&tests, *start)
                && !in_any(&literal_exempt, *start)
            {
                hits.push(Hit {
                    line: line_of(&code, *start),
                    what: format!("literal {text:?}"),
                });
            }
        }

        for range in &tests {
            blank(&mut code, range.clone());
        }

        let flat: Vec<(usize, u8)> = code
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, b)| !b.is_ascii_whitespace())
            .collect();
        let flat_bytes: Vec<u8> = flat.iter().map(|(_, b)| *b).collect();
        for needle in RAW_HOME_CALLS {
            for (k, window) in flat_bytes.windows(needle.len()).enumerate() {
                if window == needle.as_bytes() {
                    let offset = flat.get(k).map_or(0, |(o, _)| *o);
                    hits.push(Hit {
                        line: line_of(&code, offset),
                        what: (*needle).to_owned(),
                    });
                }
            }
        }

        for k in 0..code.len() {
            if token_at(&code, k, "env")
                && let Some(open) = tokens_at(&code, k + 3, &["::", "{"])
            {
                let group = code.get(open - 1..close_of(&code, open - 1)).unwrap_or(&[]);
                let imports_reader = (0..group.len())
                    .any(|g| ["var", "var_os"].iter().any(|w| token_at(group, g, w)));
                let aliases_module = (0..group.len()).any(|g| {
                    token_at(group, g, "self") && token_at(group, skip_ws(group, g + 4), "as")
                });
                if imports_reader {
                    hits.push(Hit {
                        line: line_of(&code, k),
                        what: "`env::{..}` imports a reader".to_owned(),
                    });
                }
                if aliases_module && !in_any(&dynamic_exempt, k) {
                    hits.push(Hit {
                        line: line_of(&code, k),
                        what: "`env::{self as ..}` aliases the module".to_owned(),
                    });
                }
            }
            if token_at(&code, k, "env")
                && token_at(&code, skip_ws(&code, k + 3), "as")
                && !in_any(&dynamic_exempt, k)
            {
                hits.push(Hit {
                    line: line_of(&code, k),
                    what: "`env as ..` aliases the module".to_owned(),
                });
            }
            for reader in ["var", "var_os", "read_env_var", "read_env_var_os"] {
                if !token_at(&code, k, reader) || !is_env_reader(&code, k, reader) {
                    continue;
                }
                let open = skip_ws(&code, k + reader.len());
                let dynamic = if at(&code, open) == b'(' {
                    !key_is_static(&code, open + 1)
                } else {
                    matches!(reader, "var" | "var_os")
                };
                if dynamic && !in_any(&dynamic_exempt, k) {
                    hits.push(Hit {
                        line: line_of(&code, k),
                        what: format!("computed key or reader value at `{reader}`"),
                    });
                }
            }
        }
        hits
    }

    /// The exempt function names `list` grants in workspace file `rel`.
    fn exempt_in(list: &[Allowed], rel: &str) -> Vec<&'static str> {
        list.iter()
            .filter(|a| a.file == rel)
            .map(|a| a.func)
            .collect()
    }

    /// The workspace root.
    fn workspace() -> PathBuf {
        e2e_support::manifest_dir!().join("../..")
    }

    #[test]
    fn no_production_source_reads_the_home_directly() {
        let files = super::scanned_files(false, |rel| {
            rel.starts_with("src/") && super::is_rust_source(rel)
        });
        assert!(
            !files.is_empty(),
            "the scan found no sources; the walk root is wrong"
        );

        let mut offenders = Vec::new();
        for (rel, text) in files
            .into_iter()
            .filter(|(rel, _)| rel != super::BAN_PROOF_FILE)
        {
            let hits = raw_home_reads(
                &text,
                &exempt_in(LITERAL_ALLOWED, &rel),
                &exempt_in(DYNAMIC_KEY_ALLOWED, &rel),
            );
            if !hits.is_empty() {
                offenders.push((rel, hits));
            }
        }

        assert!(
            offenders.is_empty(),
            "raw home reads found; use `ipe_sandbox::home::home_dir` (compiler) or \
             `system::home_dir` (runtime), or add a reasoned allowlist entry: {offenders:#?}"
        );
    }

    #[test]
    fn every_allowlisted_function_exists_with_a_reason() {
        let workspace = workspace();
        for entry in LITERAL_ALLOWED.iter().chain(DYNAMIC_KEY_ALLOWED) {
            assert!(
                !entry.reason.trim().is_empty(),
                "`{}::{}` needs a reason",
                entry.file,
                entry.func
            );
            let text = std::fs::read_to_string(workspace.join(entry.file));
            assert!(
                text.is_ok(),
                "allowlisted file `{}` is gone; drop its entry",
                entry.file
            );
            let Ok(text) = text else { continue };
            assert!(
                !fn_ranges(&lex(&text).code, entry.func).is_empty(),
                "allowlisted `fn {}` is gone from `{}`; drop its entry",
                entry.func,
                entry.file
            );
        }
    }

    #[test]
    fn the_windows_jail_base_set_forwards_exactly_the_pinned_home_names() {
        use ipe_sandbox::run_jail::WindowsBaseEnv;
        let base: Vec<&str> = WindowsBaseEnv::ALL
            .into_iter()
            .map(WindowsBaseEnv::name)
            .collect();
        let forwarded_home: Vec<&str> = base
            .iter()
            .copied()
            .filter(|name| HOME_NAMES.contains(name))
            .collect();
        assert_eq!(
            forwarded_home, WINDOWS_JAIL_HOME_NAMES,
            "the Windows jail's base set forwards a different home set than its \
             allowlist entry pins; re-audit `WindowsBaseEnv` and its reason"
        );
        for name in base {
            let scratch_valued = matches!(name, "TMP" | "TEMP");
            assert_eq!(
                WINDOWS_JAIL_HOST_ENV.contains(&format!("`{name}`")),
                !scratch_valued,
                "the Windows jail reason must name exactly the host-valued base \
                 names; `{name}` disagrees"
            );
        }
    }

    #[test]
    fn the_windows_jail_home_literals_sit_only_in_the_base_name_table() {
        let text = std::fs::read_to_string(workspace().join(WINDOWS_JAIL_FILE));
        assert!(text.is_ok(), "`{WINDOWS_JAIL_FILE}` is gone");
        let text = text.unwrap_or_default();
        let mut unexempt: Vec<String> = raw_home_reads(&text, &[], &[])
            .into_iter()
            .map(|hit| hit.what)
            .filter(|what| what.starts_with("literal "))
            .collect();
        unexempt.sort();
        let mut pinned: Vec<String> = WINDOWS_JAIL_HOME_NAMES
            .iter()
            .map(|name| format!("literal {name:?}"))
            .collect();
        pinned.sort();
        assert_eq!(
            unexempt, pinned,
            "`{WINDOWS_JAIL_FILE}` spells a home name beyond its base-set table"
        );
    }

    #[test]
    fn a_home_literal_beside_an_exempt_name_table_is_detected() {
        let src = "const fn name() -> &'static str { \"USERPROFILE\" }\n\
                   fn leak() -> &'static str { \"USERPROFILE\" }\n";
        assert_eq!(
            raw_home_reads(src, &["name"], &[]),
            vec![Hit {
                line: 2,
                what: "literal \"USERPROFILE\"".to_owned(),
            }]
        );
    }

    /// The refused constructs in a planted snippet, with no exemptions.
    fn planted(src: &str) -> Vec<Hit> {
        raw_home_reads(src, &[], &[])
    }

    #[test]
    fn a_planted_raw_home_read_is_detected() {
        let planted_reads = [
            "let h = std::env::var_os(\"HOME\");",
            "let h = std::env::var( \"HOME\" ).ok();",
            "let h = env::var_os(\n    \"USERPROFILE\",\n);",
            "let h = read_env_var_os(\"HOME\");",
            "#[allow(deprecated)] let h = std::env::home_dir();",
            "use std::env::home_dir;",
            "let h = dirs::home_dir();",
            "const K: &str = \"HOME\"; fn f() { let _ = std::env::var(K); }",
            "pub const HOME_VAR: &str = \"HOME\"; fn f() { std::env::var_os(HOME_VAR); }",
            "let h = std::env::var_os(r\"HOME\");",
            "let h = std::env::var_os(r#\"USERPROFILE\"#);",
            "let h = std::env::var_os(\"\\x48OME\");",
            "let h = std::env::var_os(\"\\u{48}OME\");",
            "cmd.env(\"HOME\", scratch);",
            "const H: &str = env!(\"HOME\");",
            "let h = option_env!(\"HOME\");",
            "let h = option_env!(r\"USERPROFILE\");",
            "for (k, v) in std::env::vars() {}",
            "for (k, v) in std::env::vars_os() {}",
            "use std::env::var_os;",
            "use std::env::{self, var};",
            "let h = keys.iter().map(std::env::var_os);",
            "fn f(key: &str) { let _ = std::env::var_os(key); }",
            "fn f(p: &Profile) { let _ = std::env::var(&p.key); }",
            "fn f() { let _ = crate::system::read_env_var(&format!(\"{}\", k)); }",
            "#[cfg(any(test, feature = \"x\"))]\nfn f() { let _ = std::env::var(\"HOME\"); }",
            "use std::env as e; fn f(k: &str) { let _ = e::var(k); }",
            "pub use std::env as e;",
            "use std::{env as e, fs};",
            "use std::env::{self as e};",
            "use std::env::{self as e, args};",
            "use std::{env::{self as e}};",
        ];
        for src in planted_reads {
            assert!(
                !planted(src).is_empty(),
                "the scan missed a raw home read: {src:?}"
            );
        }
    }

    #[test]
    fn the_validated_accessors_and_unrelated_forms_are_not_flagged() {
        let clean = [
            "let h = ipe_sandbox::home::home_dir();",
            "let h = crate::env_dir::home();",
            "let v = std::env::var_os(\"HOMEBREW_PREFIX\");",
            "let v = std::env::var(REGISTRY_URL_ENV);",
            "let v = std::env::var_os(crate::REPLAY_ENV);",
            "let v = std::env::var(Self::ENV);",
            "// std::env::var_os(\"HOME\") in a comment",
            "/// `HOME` names the home: std::env::var_os(\"HOME\")",
            "/* \"HOME\" in a /* nested */ block comment */",
            "let t = Ty::var(id);",
            "let t = self.var(id);",
            "fn var(id: u32) {}",
            "fn read_env_var(key: &str) {}",
            "let css = \"color: var(--fg)\";",
            "let q = '\"'; let b = b'\"'; let v = std::env::var(\"PATH\");",
            "fn f<'a>(x: &'a str) -> &'a str { x }",
            "let s = r#\"a \"quoted\" HOME\"#;",
            "use std::env::{self, args};",
            "use std::{env, fs as f};",
            "let environment = env; let x = y as u8;",
        ];
        for src in clean {
            assert_eq!(
                planted(src),
                Vec::new(),
                "the scan flagged a sanctioned form: {src:?}"
            );
        }
    }

    #[test]
    fn test_items_are_skipped_but_production_code_beside_them_is_not() {
        let src = "#[cfg(test)]\nmod tests {\n    fn t() { let _ = std::env::var(\"HOME\"); }\n}\n\
                   fn prod() { let _ = std::env::var(\"HOME\"); }\n";
        assert_eq!(
            planted(src),
            vec![Hit {
                line: 5,
                what: "literal \"HOME\"".to_owned(),
            }]
        );
        let inner = "#![cfg(test)]\nfn t() { let _ = std::env::var(\"HOME\"); }\n";
        assert_eq!(planted(inner), Vec::new());
    }

    /// The single literal-`HOME` hit on `line`.
    fn home_literal_at(line: usize) -> Vec<Hit> {
        vec![Hit {
            line,
            what: "literal \"HOME\"".to_owned(),
        }]
    }

    #[test]
    fn a_test_variant_field_or_arm_skips_only_itself() {
        let variant = "enum E {\n    #[cfg(test)]\n    T,\n    P,\n}\n\
                       fn prod() { let _ = std::env::var(\"HOME\"); }\n";
        assert_eq!(planted(variant), home_literal_at(6));
        let last_variant = "enum E {\n    P,\n    #[cfg(test)]\n    T\n}\n\
                            fn prod() { let _ = std::env::var(\"HOME\"); }\n";
        assert_eq!(planted(last_variant), home_literal_at(6));
        let field = "struct S {\n    #[cfg(test)]\n    pub t: Vec<u8>,\n    p: u8,\n}\n\
                     fn prod() { let _ = std::env::var(\"HOME\"); }\n";
        assert_eq!(planted(field), home_literal_at(6));
        let arm = "fn prod(x: u8) {\n    match x {\n        #[cfg(test)]\n        0 => (),\n\
                   _ => { let _ = std::env::var(\"HOME\"); }\n    }\n}\n";
        assert_eq!(planted(arm), home_literal_at(5));
        let test_arm = "fn prod(x: u8) {\n    match x {\n        #[cfg(test)]\n\
                        0 => { let _ = std::env::var(\"HOME\"); }\n        _ => (),\n    }\n}\n";
        assert_eq!(planted(test_arm), Vec::new());
    }

    #[test]
    fn an_inner_test_cfg_in_an_inline_module_skips_only_that_module() {
        let src = "mod t {\n    #![cfg(test)]\n    fn t() { let _ = std::env::var(\"HOME\"); }\n}\n\
                   fn prod() { let _ = std::env::var(\"HOME\"); }\n";
        assert_eq!(planted(src), home_literal_at(5));
    }

    #[test]
    fn an_env_alias_is_exempt_only_in_an_allowlisted_function() {
        let src = "fn reader() { use std::env as e; }\nfn stray() { use std::env as e; }\n";
        assert_eq!(
            raw_home_reads(src, &[], &["reader"]),
            vec![Hit {
                line: 2,
                what: "`env as ..` aliases the module".to_owned(),
            }]
        );
    }

    #[test]
    fn an_exemption_covers_its_function_only() {
        let src = "fn home_dir() { let _ = std::env::var_os(\"HOME\"); }\n\
                   fn other() { let _ = std::env::var_os(\"HOME\"); }\n";
        assert_eq!(
            raw_home_reads(src, &["home_dir"], &[]),
            vec![Hit {
                line: 2,
                what: "literal \"HOME\"".to_owned(),
            }]
        );
        let dynamic = "fn reader(k: &str) { let _ = std::env::var(k); }\n\
                       fn stray(k: &str) { let _ = std::env::var(k); }\n";
        assert_eq!(
            raw_home_reads(dynamic, &[], &["reader"]),
            vec![Hit {
                line: 2,
                what: "computed key or reader value at `var`".to_owned(),
            }]
        );
        let constant = "const NAMES: [&str; 1] = [\"HOME\"];\nconst OTHER: &str = \"HOME\";\n";
        assert_eq!(
            raw_home_reads(constant, &["NAMES"], &[]),
            home_literal_at(2)
        );
        let literal_in_dynamic_reader = "fn reader() { let _ = std::env::var(\"HOME\"); }\n";
        assert_eq!(
            raw_home_reads(literal_in_dynamic_reader, &[], &["reader"]).len(),
            1,
            "a computed-key exemption never covers a home literal"
        );
    }
}
