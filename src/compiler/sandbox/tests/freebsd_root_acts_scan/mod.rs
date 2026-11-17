//! The FreeBSD jail launcher makes only the root acts this inventory admits.
//!
//! `mod freebsd_jail` of `src/build_jail.rs` runs as root. Every program it
//! starts, every path it creates, resolves, stats or removes, and every spawn
//! it makes is an act in this inventory: the function it is in and what it
//! calls. The inventory must equal [`ADMITTED`] exactly, so a new by-name act
//! fails the scan until a reviewer admits it with a reason, and an admission
//! whose act is gone fails as stale.
//!
//! Around the inventory, the module may not rename an import (the renamed
//! name would leave the inventory), import a filesystem or process item by
//! its bare name, reach a foreign function interface, or name an ownership
//! change other than the held-handle `fchown` (a check over its raw text,
//! comments and strings included). The `Primitive` table, the one source of
//! every program the launcher runs, must hold exactly [`ADMITTED_PRIMITIVES`].
//!
//! The scan reuses the lexer of the enclosing harness: comments and literals
//! are blanked before the inventory is read. A control fixture holding each
//! refused shape proves the scan turns red on it.

use super::{code_only, enclosing_fn, is_ident};

/// The opening line of the launcher module.
const MODULE_OPEN: &str = "\nmod freebsd_jail {";

/// Path-reading calls on a `Path` receiver the inventory records.
const PATH_QUERIES: [&str; 16] = [
    "canonicalize",
    "create_dir_all",
    "exists",
    "is_dir",
    "is_file",
    "is_symlink",
    "metadata",
    "read_dir",
    "read_link",
    "remove_dir",
    "remove_dir_all",
    "remove_file",
    "rename",
    "set_permissions",
    "symlink_metadata",
    "try_exists",
];

/// Import path segments that bring a filesystem, process or foreign item in.
const SENSITIVE_SEGMENTS: [&str; 6] = ["fs", "process", "os", "libc", "nix", "rustix"];

/// The only words naming an ownership change the module may hold.
const OWNERSHIP_WORDS: [&str; 2] = ["fchown_held", "fchown"];

/// One admitted root act: its function, the act, and why it is sound.
type Admission = (&'static str, &'static str, &'static str);

/// Every root act of the launcher module, with the reason it is sound.
const ADMITTED: [Admission; 33] = [
    (
        "build_in_jail",
        "resolve_primitive(Primitive::Jail)",
        "the jail program, from the fixed root-only primitive table",
    ),
    (
        "build_in_jail",
        "resolve_primitive(Primitive::Rctl)",
        "the rctl program, from the fixed root-only primitive table",
    ),
    (
        "build_in_jail",
        "spawn_and_decode",
        "starts the resolved jail program through the runtime descriptor floor",
    ),
    (
        "mount_nullfs",
        "Command::new(mount_nullfs_bin)",
        "the mount_nullfs primitive `establish` resolved",
    ),
    (
        "mount_devfs",
        "Command::new(mount_bin)",
        "the mount primitive `establish` resolved",
    ),
    (
        "mount_tmpfs",
        "Command::new(mount_bin)",
        "the mount primitive `establish` resolved",
    ),
    (
        "mount_dir_under",
        "fs::DirBuilderExt",
        "the mode trait for the exclusive create below",
    ),
    (
        "mount_dir_under",
        "fs::DirBuilder::new",
        "an exclusive non-recursive create under a root-only per-run directory",
    ),
    (
        "establish",
        "resolve_primitive(Primitive::MountNullfs)",
        "the mount_nullfs program, from the fixed root-only primitive table",
    ),
    (
        "establish",
        "resolve_primitive(Primitive::Mount)",
        "the mount program, from the fixed root-only primitive table",
    ),
    (
        "establish",
        "resolve_primitive(Primitive::Umount)",
        "the umount program, from the fixed root-only primitive table",
    ),
    (
        "establish",
        "fs::canonicalize",
        "the jail root this process just created exclusively; its chain is judged root-only next",
    ),
    (
        "establish",
        "fs::canonicalize",
        "the /proc-mask source this process just created exclusively; its chain is judged root-only next",
    ),
    (
        "mounted_facts",
        "fs::MetadataExt",
        "the inode trait for the held-handle read below",
    ),
    (
        "mounted_facts",
        ".metadata(",
        "read on the held handle of the mounted target, never by name",
    ),
    (
        "mounted_facts",
        "fs::fstatfs",
        "read on the held handle of the mounted target, never by name",
    ),
    (
        "ensure_mountpoint",
        ".is_dir(",
        "a target under the root-only jail root that `untrusted_mount_ancestor` judged first",
    ),
    (
        "ensure_mountpoint",
        "fs::create_dir_all",
        "a target under the root-only jail root that `untrusted_mount_ancestor` judged first",
    ),
    (
        "ensure_mountpoint",
        "fs::canonicalize",
        "confirms the target resolves to itself; a mismatch refuses",
    ),
    (
        "provision_tmpfs_over",
        "fs::create_dir_all",
        "a mountpoint inside the root-owned tmpfs this jail just mounted",
    ),
    (
        "drop",
        "Command::new(bin)",
        "the umount primitive, run only while the target still shows its recorded filesystem",
    ),
    (
        "drop",
        "fs::remove_dir",
        "the jail root, a root-only per-run directory; never a recursive removal",
    ),
    (
        "drop",
        "fs::remove_dir",
        "the /proc-mask source, a root-only per-run directory; never a recursive removal",
    ),
    (
        "drop",
        "fs::remove_dir",
        "the per-run parent of the /proc-mask source; never a recursive removal",
    ),
    (
        "create_exclusive_private_dir",
        "fs::DirBuilderExt",
        "the mode trait for the creates below",
    ),
    (
        "create_exclusive_private_dir",
        "fs::canonicalize",
        "the resolver `trusted_jail_parent` judges the spelled and the resolved chain with",
    ),
    (
        "create_exclusive_private_dir",
        "fs::DirBuilder::new",
        "the parent, after `trusted_jail_parent` admitted its chain",
    ),
    (
        "create_exclusive_private_dir",
        "fs::File::open",
        "the kernel random device, a read-only fixed path",
    ),
    (
        "create_exclusive_private_dir",
        "fs::DirBuilder::new",
        "an exclusive non-recursive create; the whole chain is judged again after",
    ),
    (
        "apply",
        "Command::new(rctl_bin)",
        "the rctl primitive `build_in_jail` resolved",
    ),
    (
        "drop",
        "Command::new(&self.rctl_bin)",
        "the rctl primitive the rule was applied with",
    ),
    (
        "run_host_tool",
        "Command",
        "the one runner every host tool goes through",
    ),
    (
        "run_host_tool",
        "spawn_hardened",
        "the runtime descriptor floor: the tool inherits stdio and nothing else",
    ),
];

/// The programs the launcher may run as root, with their one spelling.
const ADMITTED_PRIMITIVES: [(&str, &str); 5] = [
    ("Jail", "/usr/sbin/jail"),
    ("MountNullfs", "/sbin/mount_nullfs"),
    ("Mount", "/sbin/mount"),
    ("Umount", "/sbin/umount"),
    ("Rctl", "/usr/bin/rctl"),
];

/// Why a statement or word is refused outright.
const RENAMED_IMPORT: &str = "a renamed import";
const BARE_IMPORT: &str = "a filesystem or process item imported by its bare name";
const FOREIGN_CALL: &str = "a foreign function interface";
const OWNERSHIP_BY_NAME: &str = "an ownership change other than the held-handle fchown";

/// One root act found: its line, its function, and what it calls.
#[derive(Debug)]
struct Act {
    line: usize,
    function: String,
    call: String,
}

/// One refused statement or word: its line, the rule, and the text.
#[derive(Debug)]
struct Refusal {
    line: usize,
    rule: &'static str,
    what: String,
}

/// What one scan found.
#[derive(Debug)]
struct Findings {
    acts: Vec<Act>,
    refusals: Vec<Refusal>,
    primitives: Vec<String>,
    spellings: Vec<(String, String)>,
}

impl Findings {
    /// The found acts no admission covers, in source order.
    fn unadmitted(&self) -> Vec<&Act> {
        let mut open: Vec<(&str, &str)> = ADMITTED.iter().map(|&(f, a, _)| (f, a)).collect();
        self.acts
            .iter()
            .filter(|act| {
                open.iter()
                    .position(|&(f, a)| f == act.function && a == act.call)
                    .map(|at| open.swap_remove(at))
                    .is_none()
            })
            .collect()
    }

    /// The admissions no found act uses.
    fn stale(&self) -> Vec<(&'static str, &'static str)> {
        let mut found: Vec<(&str, &str)> = self
            .acts
            .iter()
            .map(|act| (act.function.as_str(), act.call.as_str()))
            .collect();
        ADMITTED
            .iter()
            .map(|&(function, act, _)| (function, act))
            .filter(|&(function, act)| {
                found
                    .iter()
                    .position(|&(f, a)| f == function && a == act)
                    .map(|at| found.swap_remove(at))
                    .is_none()
            })
            .collect()
    }

    /// Every rule the scanned code breaks, one line each.
    fn violations(&self) -> Vec<String> {
        let mut found: Vec<String> = self
            .unadmitted()
            .iter()
            .map(|act| {
                format!(
                    "line {}: `{}` in `{}` is not an admitted root act",
                    act.line, act.call, act.function
                )
            })
            .collect();
        found.extend(self.stale().iter().map(|(function, act)| {
            format!("the admitted `{act}` in `{function}` no longer occurs; remove its row")
        }));
        found.extend(self.refusals.iter().map(|refusal| {
            format!(
                "line {}: {}: `{}`",
                refusal.line, refusal.rule, refusal.what
            )
        }));
        let admitted: Vec<&str> = ADMITTED_PRIMITIVES.iter().map(|&(name, _)| name).collect();
        if self.primitives != admitted {
            found.push(format!(
                "the `Primitive` variants are {:?}, not exactly {admitted:?}",
                self.primitives
            ));
        }
        let spellings: Vec<(&str, &str)> = self
            .spellings
            .iter()
            .map(|(name, path)| (name.as_str(), path.as_str()))
            .collect();
        if spellings != ADMITTED_PRIMITIVES {
            found.push(format!(
                "the `Primitive` spellings are {spellings:?}, not exactly {ADMITTED_PRIMITIVES:?}"
            ));
        }
        found
    }
}

/// `text` with every whitespace run collapsed to one space.
fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Every identifier in `code` with its byte offset.
fn words(code: &str) -> Vec<(usize, &str)> {
    let mut found = Vec::new();
    let mut start: Option<usize> = None;
    for (at, c) in code.char_indices() {
        match (start, is_ident(c)) {
            (None, true) => start = Some(at),
            (Some(from), false) => {
                found.extend(code.get(from..at).map(|word| (from, word)));
                start = None;
            }
            _ => {}
        }
    }
    found.extend(start.and_then(|from| code.get(from..).map(|word| (from, word))));
    found
}

/// The text inside the parentheses opening at byte `open` of `code`, collapsed.
fn call_argument(code: &str, open: usize) -> String {
    let rest = code.get(open..).unwrap_or_default();
    let mut depth = 0_usize;
    for (offset, c) in rest.char_indices() {
        match c {
            '(' => depth = depth.saturating_add(1),
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return collapse(rest.get(1..offset).unwrap_or_default());
                }
            }
            _ => {}
        }
    }
    collapse(rest)
}

/// The `::`-joined path at the start of `rest`.
fn leading_path(rest: &str) -> String {
    rest.chars()
        .take_while(|&c| is_ident(c) || c == ':')
        .collect()
}

/// The 1-based line of byte `at` of `code`.
fn line_of(code: &str, at: usize) -> usize {
    code.get(..at)
        .unwrap_or_default()
        .matches('\n')
        .count()
        .saturating_add(1)
}

/// The launcher module's code and the line it opens on.
fn launcher_module(code: &str) -> Option<(&str, usize)> {
    let from = code.find(MODULE_OPEN)?.saturating_add(1);
    let len = code.get(from..)?.find("\n}")?;
    Some((
        code.get(from..from.saturating_add(len))?,
        line_of(code, from),
    ))
}

/// The root act the word at byte `at` of `module` makes, if any.
fn act_at(module: &str, at: usize, word: &str) -> Option<String> {
    let rest = module
        .get(at.saturating_add(word.len())..)
        .unwrap_or_default();
    let before = module.get(..at).unwrap_or_default();
    if word == "Command" {
        return Some(if rest.starts_with("::new(") {
            format!("Command::new({})", call_argument(rest, "::new".len()))
        } else {
            word.to_owned()
        });
    }
    if word == "fs" && rest.starts_with("::") {
        return Some(format!("fs{}", leading_path(rest)));
    }
    if word == "resolve_primitive" && rest.starts_with('(') && !before.ends_with("fn ") {
        return Some(format!("resolve_primitive({})", call_argument(rest, 0)));
    }
    if word.contains("spawn") {
        return Some(word.to_owned());
    }
    let queried = PATH_QUERIES.contains(&word) && before.ends_with('.') && rest.starts_with('(');
    queried.then(|| format!(".{word}("))
}

/// The refusal the word at byte `at` of `module` opens, if any.
fn refusal_at(module: &str, at: usize, word: &str) -> Option<(&'static str, String)> {
    let rest = module
        .get(at.saturating_add(word.len())..)
        .unwrap_or_default();
    if word != "use" {
        let foreign =
            word == "extern" || (matches!(word, "libc" | "nix") && rest.starts_with("::"));
        return foreign.then(|| (FOREIGN_CALL, word.to_owned()));
    }
    let statement = collapse(
        module
            .get(at..)
            .and_then(|from| from.split(';').next())
            .unwrap_or_default(),
    );
    if statement.ends_with(" as _") {
        return None;
    }
    let sensitive = statement
        .split(|c: char| !is_ident(c))
        .any(|segment| SENSITIVE_SEGMENTS.contains(&segment));
    if statement.contains(" as ") {
        Some((RENAMED_IMPORT, statement))
    } else {
        sensitive.then_some((BARE_IMPORT, statement))
    }
}

/// The ownership words other than `fchown` on `count` lines from `first`.
fn ownership_words(source: &str, first: usize, count: usize) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let lines = source
        .lines()
        .enumerate()
        .skip(first.saturating_sub(1))
        .take(count);
    for (index, line) in lines {
        let lower = line.to_ascii_lowercase();
        for (at, _) in lower.match_indices("chown") {
            let start = line
                .get(..at)
                .unwrap_or_default()
                .char_indices()
                .rev()
                .find(|&(_, c)| !is_ident(c))
                .map_or(0, |(i, c)| i.saturating_add(c.len_utf8()));
            let tail = line.get(at..).unwrap_or_default();
            let end = at.saturating_add(tail.find(|c: char| !is_ident(c)).unwrap_or(tail.len()));
            let word = line.get(start..end).unwrap_or_default();
            if !OWNERSHIP_WORDS.contains(&word) {
                found.push((index.saturating_add(1), word.to_owned()));
            }
        }
    }
    found
}

/// The variants of `enum Primitive` in `code`.
fn primitive_variants(code: &str) -> Vec<String> {
    let open = "enum Primitive {";
    code.find(open)
        .and_then(|at| code.get(at.saturating_add(open.len())..))
        .and_then(|body| body.get(..body.find('}')?))
        .map(|body| {
            body.split(',')
                .map(str::trim)
                .filter(|variant| !variant.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The `(variant, spelling)` arms of `Primitive::spelling` in `source`.
fn primitive_spellings(source: &str) -> Vec<(String, String)> {
    source
        .find("const fn spelling(self)")
        .and_then(|at| source.get(at..))
        .and_then(|body| body.get(..body.find("\n    }\n")?))
        .map(|body| {
            body.split("Self::")
                .skip(1)
                .filter_map(|arm| {
                    let name: String = arm.chars().take_while(|&c| is_ident(c)).collect();
                    let spelling = arm.split('"').nth(1)?;
                    Some((name, spelling.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Scan the launcher module of `source`; `None` when it is missing.
fn scan(source: &str) -> Option<Findings> {
    let code = code_only(source);
    let (module, first_line) = launcher_module(&code)?;
    let line_at = |at: usize| {
        line_of(module, at)
            .saturating_add(first_line)
            .saturating_sub(1)
    };
    let mut acts = Vec::new();
    let mut refusals = Vec::new();
    for (at, word) in words(module) {
        if let Some(act) = act_at(module, at, word) {
            acts.push(Act {
                line: line_at(at),
                function: enclosing_fn(module, at),
                call: act,
            });
        }
        if let Some((rule, what)) = refusal_at(module, at, word) {
            refusals.push(Refusal {
                line: line_at(at),
                rule,
                what,
            });
        }
    }
    let module_lines = module.matches('\n').count().saturating_add(1);
    refusals.extend(
        ownership_words(source, first_line, module_lines)
            .into_iter()
            .map(|(line, what)| Refusal {
                line,
                rule: OWNERSHIP_BY_NAME,
                what,
            }),
    );
    refusals.sort_by_key(|refusal| refusal.line);
    Some(Findings {
        acts,
        refusals,
        primitives: primitive_variants(&code),
        spellings: primitive_spellings(source),
    })
}

const BUILD_JAIL_SOURCE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/build_jail.rs"));
const CONTROL_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/freebsd_root_acts_scan/by_name.rs.txt"
));

#[test]
fn the_freebsd_launcher_makes_only_admitted_root_acts() {
    let findings = scan(BUILD_JAIL_SOURCE);
    assert!(
        findings.is_some(),
        "src/build_jail.rs lost its `mod freebsd_jail`"
    );
    let violations = findings.map(|found| found.violations()).unwrap_or_default();
    assert!(
        violations.is_empty(),
        "the FreeBSD launcher acts as root only through admitted calls:\n{}",
        violations.join("\n")
    );
}

#[test]
#[allow(clippy::expect_used)] // the fixture is this crate's own
fn the_root_act_scan_refuses_the_control_fixture() {
    let findings = scan(CONTROL_FIXTURE).expect("the control fixture holds the launcher module");
    let unadmitted: Vec<(&str, &str)> = findings
        .unadmitted()
        .iter()
        .map(|act| (act.function.as_str(), act.call.as_str()))
        .collect();
    assert_eq!(
        unadmitted,
        [
            ("", "Command"),
            ("", "fs::lchown"),
            ("give_tree", "Command::new(user_bin)"),
            ("give_tree", "fs::canonicalize"),
            ("give_tree", "fs::chown"),
            ("give_tree", ".symlink_metadata("),
            ("give_tree", "resolve_primitive(Primitive::Owner)"),
            ("give_tree", "spawn"),
        ],
        "each by-name act in code is found, collapsed across lines, and none in a comment"
    );
    assert_eq!(
        findings.stale().len(),
        ADMITTED.len(),
        "no admission is satisfied by the fixture"
    );
    let refusals: Vec<(&str, &str)> = findings
        .refusals
        .iter()
        .map(|refusal| (refusal.rule, refusal.what.as_str()))
        .collect();
    assert_eq!(
        refusals,
        [
            (RENAMED_IMPORT, "use std::process::Command as Run"),
            (RENAMED_IMPORT, "use std::fs as files"),
            (BARE_IMPORT, "use std::os::unix::fs::lchown"),
            (OWNERSHIP_BY_NAME, "lchown"),
            (OWNERSHIP_BY_NAME, "chown"),
            (OWNERSHIP_BY_NAME, "lchown"),
            (FOREIGN_CALL, "libc"),
            (OWNERSHIP_BY_NAME, "chown"),
            (FOREIGN_CALL, "extern"),
        ]
    );
    assert_eq!(
        findings.primitives,
        ["Jail", "MountNullfs", "Mount", "Umount", "Rctl", "Owner"]
    );
    assert_eq!(findings.spellings.len(), 6);
    assert_eq!(
        findings.violations().len(),
        8_usize
            .saturating_add(ADMITTED.len())
            .saturating_add(9)
            .saturating_add(2),
        "{:?}",
        findings.violations()
    );
}
