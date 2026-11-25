//! The FreeBSD jail launcher makes only the root acts this inventory admits.
//!
//! The launcher's root code is `mod freebsd_jail` of `src/build_jail.rs`,
//! every top-level item compiled for FreeBSD, and every top-level item any of
//! those names, closed transitively: a helper the launcher calls runs as root
//! too, so moving an act out of the module never moves it out of the scan.
//! Every program that code starts, every path it creates, resolves, stats or
//! removes, every `rustix` or `std::process` item it reaches, every spawn,
//! and every reach into another module or crate is an act in this inventory:
//! the function it is in and what it calls. The inventory must equal
//! [`ADMITTED`] exactly, so a new act fails the scan until a reviewer admits
//! it with a reason, and an admission whose act is gone fails as stale.
//!
//! Around the inventory, that code (and every top-level import of the file)
//! may not rename an import (the renamed name would leave the inventory),
//! import a filesystem or process item by its bare name, reach a foreign
//! function interface, invoke a macro outside [`MACROS`] (a macro can spell
//! any path out of pieces), or name an ownership change other than the
//! held-handle `fchown` (a check over its raw code lines, strings included).
//! The `Primitive` table, the one source of every program the launcher runs,
//! must hold exactly [`ADMITTED_PRIMITIVES`].
//!
//! The scan reuses the lexer of the enclosing harness: comments and literals
//! are blanked before the inventory is read. A control fixture holding each
//! refused shape proves the scan turns red on it.

use super::{code_only, enclosing_fn, is_ident};

/// The opening line of the launcher module, written in this file.
const MODULE_OPEN: &str = "\nmod freebsd_jail {";

/// The name of the launcher module, the first root of the scope.
const MODULE_NAME: &str = "freebsd_jail";

/// The configuration a top-level item compiled for FreeBSD names.
const FREEBSD_CFG: &str = "target_os = \"freebsd\"";

/// Path roots that name no other module or crate: the standard library, this
/// file, the roots read by their own rule, and the primitive types.
const LOCAL_ROOTS: [&str; 29] = [
    "std",
    "core",
    "alloc",
    "super",
    "self",
    "fs",
    "process",
    "rustix",
    "libc",
    "nix",
    "freebsd_jail",
    "u8",
    "u16",
    "u32",
    "u64",
    "u128",
    "usize",
    "i8",
    "i16",
    "i32",
    "i64",
    "i128",
    "isize",
    "str",
    "char",
    "bool",
    "f32",
    "f64",
    "clippy",
];

/// The macros the scoped code may invoke: none of them spells a path.
const MACROS: [&str; 5] = ["format", "matches", "vec", "write", "writeln"];

/// The item keywords whose next word is the item's name.
const ITEM_KEYWORDS: [&str; 10] = [
    "fn",
    "struct",
    "enum",
    "const",
    "static",
    "type",
    "trait",
    "mod",
    "union",
    "macro_rules",
];

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
const ADMITTED: [Admission; 75] = [
    ("", "use crate::JailMounts", "the mount set type; no act"),
    (
        "",
        "use crate::run_jail::JailLaunch",
        "the launch type; its spawn is admitted where it runs",
    ),
    (
        "",
        "use crate::run_jail::{RunJailDefect, RunJailTools, SandboxProfile}",
        "the jail profile and refusal types; no act",
    ),
    (
        "require_jail_primitive",
        "resolve_primitive(Primitive::Jail)",
        "the jail program, from the fixed root-only primitive table",
    ),
    (
        "spawn_and_decode",
        "spawn",
        "starts the jail launch `build_in_jail` built from resolved primitives",
    ),
    (
        "spawn_and_decode",
        "process::Stdio::inherit",
        "the jail writes to this process stdout",
    ),
    (
        "spawn_and_decode",
        "process::Stdio::inherit",
        "the jail writes to this process stderr",
    ),
    (
        "freebsd_mount_ops",
        "use crate::mounts::{Bind, MountStep}",
        "the mount plan types; no act",
    ),
    (
        "of",
        "fs::Metadata",
        "a type name; the facts read from metadata already taken",
    ),
    (
        "of",
        "use std::os::unix::fs::MetadataExt as _",
        "the inode trait for the facts below",
    ),
    ("of", ".is_symlink(", "on a file type already read, no path"),
    ("of", ".is_dir(", "on a file type already read, no path"),
    ("of", ".is_file(", "on a file type already read, no path"),
    (
        "lstat_facts",
        "fs::symlink_metadata",
        "a read that never follows a link; the trusted-chain judges re-read every level after",
    ),
    (
        "held_chain_facts",
        ".metadata(",
        "read on a held handle, never by name",
    ),
    (
        "held_fsid",
        "use std::os::unix::fs::MetadataExt as _",
        "the inode trait for the held-handle read below",
    ),
    (
        "held_fsid",
        ".metadata(",
        "read on a held handle, never by name",
    ),
    (
        "spelling_fits",
        "use std::os::unix::ffi::OsStrExt as _",
        "the byte view of a spelling; no act",
    ),
    (
        "verify_bind",
        "use std::os::unix::ffi::OsStrExt as _",
        "the byte view of a spelling; no act",
    ),
    (
        "held_refusal",
        "use ipe_fs_open::OpenRefusal",
        "the held-open refusal type; no act",
    ),
    (
        "walk_held",
        "use ipe_fs_open::{EntryName, HeldDir}",
        "the held-handle walk every chain read goes through",
    ),
    (
        "hold",
        "use std::os::unix::fs::MetadataExt as _",
        "the inode trait for the held-handle read below",
    ),
    ("hold", ".metadata(", "read on a held handle, never by name"),
    (
        "refuse_cargo_identity",
        "crate::covers::CargoHomeIdentity::read",
        "reads the cargo home identity; a match refuses the bind",
    ),
    (
        "",
        "fs::File",
        "a type name in the held-handle ownership signature",
    ),
    (
        "fchown_held",
        "fs::File",
        "a type name; the handle is already open",
    ),
    (
        "fchown_held",
        "fs::fchown",
        "the one ownership change, on a held handle",
    ),
    (
        "acquire",
        "use std::os::unix::fs::MetadataExt as _",
        "the inode trait for the held-handle read below",
    ),
    (
        "acquire",
        ".metadata(",
        "read on a held handle, never by name",
    ),
    ("", "use crate::JailMounts", "the mount set type; no act"),
    (
        "",
        "use crate::mounts::{TreeBind, jail_binds, mount_plan}",
        "the pure mount planners; no act",
    ),
    (
        "",
        "use crate::run_jail::{JailArgv, JailLaunch, RunJailDefect, SandboxProfile}",
        "the launch types; no act",
    ),
    (
        "",
        "ipe_fs_open::ByteCap::from_nonzero",
        "a const byte ceiling; no act",
    ),
    (
        "read_jail_user",
        "use ipe_fs_open::{EntryName, OpenRefusal}",
        "the held `/etc` read of the jail user",
    ),
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
        "crate::host_env::granted",
        "the env allowlist the scrub keeps",
    ),
    (
        "macos_scrubbed_env",
        "crate::host_env::reexported_names",
        "the env allowlist without the launcher-owned names; a pure filter, no act",
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
        "use std::os::unix::fs::DirBuilderExt as _",
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
        "rustix::process::geteuid",
        "the id the trusted-chain judges admit as owner",
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
        "use std::os::unix::fs::MetadataExt as _",
        "the inode trait for the held-handle read below",
    ),
    (
        "mounted_facts",
        ".metadata(",
        "read on the held handle of the mounted target, never by name",
    ),
    (
        "mounted_facts",
        "rustix::fs::fstatfs",
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
        "private_cache_root",
        "crate::home::home_dir",
        "the home the cache root is judged under; a user-owned home refuses",
    ),
    (
        "create_exclusive_private_dir",
        "use std::os::unix::fs::DirBuilderExt as _",
        "the mode trait for the creates below",
    ),
    (
        "create_exclusive_private_dir",
        "rustix::process::geteuid",
        "the id the trusted-chain judges admit as owner",
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
        "per_run_jail_name",
        "process::id",
        "the per-run jail name; no act",
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
        "process::ExitStatus",
        "a type name; no act",
    ),
    (
        "run_host_tool",
        "ipe_runtime_rust::system::spawn_hardened",
        "the runtime descriptor floor: the tool inherits stdio and nothing else",
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
const MACRO_CALL: &str = "a macro outside the admitted list";
const OUT_OF_FILE: &str = "the launcher module is not written in this file";

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

/// One top-level item of the file: its byte span with its attributes, where
/// its own text opens, its name, and whether it is an import.
#[derive(Debug)]
struct Item {
    start: usize,
    body: usize,
    end: usize,
    name: Option<String>,
    is_use: bool,
}

/// Whether a line of blanked code opens a top-level item or attribute.
fn opens_item(line: &str) -> bool {
    line.chars()
        .next()
        .is_some_and(|c| !c.is_whitespace() && !matches!(c, '}' | ')' | ']' | '{'))
        && !line.starts_with("where")
}

/// The text of `after` past one balanced `<…>` group opening it.
fn past_generics(after: &str) -> &str {
    let trimmed = after.trim_start();
    if !trimmed.starts_with('<') {
        return trimmed;
    }
    let mut depth = 0_usize;
    for (at, c) in trimmed.char_indices() {
        match c {
            '<' => depth = depth.saturating_add(1),
            '>' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return trimmed.get(at.saturating_add(1)..).unwrap_or_default();
                }
            }
            _ => {}
        }
    }
    trimmed
}

/// The type an `impl` header implements for.
fn impl_type(header: &str) -> Option<String> {
    let after = past_generics(header.trim_start().strip_prefix("impl")?);
    let target = after.rsplit(" for ").next().unwrap_or(after);
    let path: String = target
        .trim_start()
        .trim_start_matches('&')
        .chars()
        .take_while(|&c| is_ident(c) || c == ':')
        .collect();
    path.rsplit("::").next().map(str::to_owned)
}

/// The name a top-level item `header` declares.
fn item_name(header: &str) -> Option<String> {
    let trimmed = header.trim_start();
    if let Some(implementation) = trimmed
        .strip_prefix("unsafe ")
        .or(Some(trimmed))
        .filter(|text| text.starts_with("impl"))
    {
        return impl_type(implementation);
    }
    let names: Vec<&str> = words(header).into_iter().map(|(_, word)| word).collect();
    names.windows(2).find_map(|pair| match pair {
        [keyword, name] if ITEM_KEYWORDS.contains(keyword) && !ITEM_KEYWORDS.contains(name) => {
            Some((*name).to_owned())
        }
        _ => None,
    })
}

/// The top-level items of blanked `code`, each with its attributes.
fn items(code: &str) -> Vec<Item> {
    let mut starts = Vec::new();
    let mut offset = 0_usize;
    for line in code.split_inclusive('\n') {
        if opens_item(line) {
            starts.push(offset);
        }
        offset = offset.saturating_add(line.len());
    }
    starts.push(code.len());
    let mut found = Vec::new();
    let mut attributes: Option<usize> = None;
    for span in starts.windows(2) {
        let [from, to] = *span else { continue };
        let text = code.get(from..to).unwrap_or_default();
        if text.starts_with("#[") || text.starts_with("#!") {
            attributes = attributes.or(Some(from));
            continue;
        }
        let header = text.split(['{', ';']).next().unwrap_or_default();
        let bare = header
            .trim_start_matches("pub(crate) ")
            .trim_start_matches("pub(super) ")
            .trim_start_matches("pub ");
        found.push(Item {
            start: attributes.take().unwrap_or(from),
            body: from,
            end: to,
            name: item_name(header),
            is_use: bare.starts_with("use "),
        });
    }
    found
}

/// Whether the word at byte `at` of `code` is the name a definition declares.
fn is_definition(code: &str, at: usize) -> bool {
    let before = code.get(..at).unwrap_or_default();
    ITEM_KEYWORDS.iter().any(|keyword| {
        before
            .strip_suffix(' ')
            .and_then(|rest| rest.strip_suffix(keyword))
            .is_some_and(|rest| !rest.ends_with(is_ident))
    })
}

/// The raw attribute lines of `item`, read from `source`.
fn attributes_of(code: &str, source: &str, item: &Item) -> String {
    let first = line_of(code, item.start).saturating_sub(1);
    let count = line_of(code, item.body)
        .saturating_sub(1)
        .saturating_sub(first);
    source
        .lines()
        .skip(first)
        .take(count)
        .collect::<Vec<_>>()
        .join("\n")
}

/// One token of a `cfg` predicate.
#[derive(Debug, PartialEq, Eq)]
enum CfgToken {
    Word(String),
    Text(String),
    Open,
    Close,
    Comma,
    Equals,
}

/// The tokens of the `cfg` predicate `text`.
fn cfg_tokens(text: &str) -> Vec<CfgToken> {
    let mut tokens = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '(' => tokens.push(CfgToken::Open),
            ')' => tokens.push(CfgToken::Close),
            ',' => tokens.push(CfgToken::Comma),
            '=' => tokens.push(CfgToken::Equals),
            '"' => {
                let value: String = chars.by_ref().take_while(|&c| c != '"').collect();
                tokens.push(CfgToken::Text(value));
            }
            c if is_ident(c) => {
                let mut word = String::from(c);
                while let Some(next) = chars.next_if(|&next| is_ident(next)) {
                    word.push(next);
                }
                tokens.push(CfgToken::Word(word));
            }
            _ => {}
        }
    }
    tokens
}

/// Whether the configuration fact `key = value` (or the bare `key`) holds
/// for a non-test FreeBSD x86-64 build; a fact this scan does not model holds,
/// so an unknown gate keeps its item in scope.
fn cfg_fact(key: &str, value: Option<&str>) -> bool {
    match (key, value) {
        ("target_os", Some(os)) => os == "freebsd",
        ("target_family", Some(family)) => family == "unix",
        ("target_arch", Some(arch)) => arch == "x86_64",
        ("windows" | "test", None) => false,
        _ => true,
    }
}

/// Evaluate the predicate at the front of `tokens`, consuming it.
fn cfg_eval(tokens: &mut std::iter::Peekable<std::vec::IntoIter<CfgToken>>) -> bool {
    let Some(CfgToken::Word(head)) = tokens.next() else {
        return true;
    };
    match tokens.peek() {
        Some(CfgToken::Open) => {
            tokens.next();
            let mut values = Vec::new();
            while !matches!(tokens.peek(), None | Some(CfgToken::Close)) {
                values.push(cfg_eval(tokens));
                tokens.next_if_eq(&CfgToken::Comma);
            }
            tokens.next();
            match head.as_str() {
                "any" => values.contains(&true),
                "not" => !values.contains(&true),
                _ => !values.contains(&false),
            }
        }
        Some(CfgToken::Equals) => {
            tokens.next();
            match tokens.next() {
                Some(CfgToken::Text(value)) => cfg_fact(&head, Some(&value)),
                _ => true,
            }
        }
        _ => cfg_fact(&head, None),
    }
}

/// The `cfg` predicates of the raw attribute text `attributes`.
fn cfg_predicates(attributes: &str) -> Vec<&str> {
    let open = "#[cfg(";
    attributes
        .match_indices(open)
        .filter_map(|(at, _)| {
            let rest = attributes.get(at.saturating_add(open.len())..)?;
            let mut depth = 1_usize;
            let end = rest.char_indices().find_map(|(offset, c)| {
                match c {
                    '(' => depth = depth.saturating_add(1),
                    ')' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            return Some(offset);
                        }
                    }
                    _ => {}
                }
                None
            })?;
            rest.get(..end)
        })
        .collect()
}

/// Whether an item with the raw attribute text `attributes` compiles into a
/// non-test FreeBSD build.
fn compiled_for_freebsd(attributes: &str) -> bool {
    cfg_predicates(attributes)
        .into_iter()
        .all(|predicate| cfg_eval(&mut cfg_tokens(predicate).into_iter().peekable()))
}

/// The items the launcher's root code spans: the launcher module, every item
/// compiled for FreeBSD, and every item a scoped item names, transitively.
///
/// `None` when the launcher module is missing.
fn root_scope<'i>(code: &str, source: &str, items: &'i [Item]) -> Option<Vec<&'i Item>> {
    let module = items
        .iter()
        .position(|item| item.name.as_deref() == Some(MODULE_NAME))?;
    let compiled: Vec<bool> = items
        .iter()
        .map(|item| !item.is_use && compiled_for_freebsd(&attributes_of(code, source, item)))
        .collect();
    let mut scoped: Vec<bool> = items
        .iter()
        .zip(&compiled)
        .enumerate()
        .map(|(index, (item, &compiled))| {
            index == module || (compiled && attributes_of(code, source, item).contains(FREEBSD_CFG))
        })
        .collect();
    loop {
        let named: std::collections::HashSet<&str> = items
            .iter()
            .zip(&scoped)
            .filter(|&(_, &inside)| inside)
            .flat_map(|(item, _)| {
                let text = code.get(item.start..item.end).unwrap_or_default();
                words(text)
                    .into_iter()
                    .filter(move |&(at, _)| !is_definition(text, at))
                    .map(|(_, word)| word)
            })
            .collect();
        let mut grew = false;
        for ((item, inside), &compiled) in items.iter().zip(scoped.iter_mut()).zip(&compiled) {
            let reached = compiled
                && item
                    .name
                    .as_deref()
                    .is_some_and(|name| named.contains(name));
            if reached && !*inside {
                *inside = true;
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    Some(
        items
            .iter()
            .zip(scoped)
            .filter_map(|(item, inside)| inside.then_some(item))
            .collect(),
    )
}

/// The byte spans of the `use` statements in `code`.
fn use_spans(code: &str) -> Vec<(usize, usize)> {
    words(code)
        .into_iter()
        .filter(|&(_, word)| word == "use")
        .map(|(at, _)| {
            let len = code
                .get(at..)
                .and_then(|rest| rest.find(';'))
                .unwrap_or_default();
            (at, at.saturating_add(len))
        })
        .collect()
}

/// The first path segment of the `use` statement `statement`.
fn use_root(statement: &str) -> &str {
    statement
        .trim_start_matches("use ")
        .trim_start_matches("::")
        .split(|c: char| !is_ident(c))
        .next()
        .unwrap_or_default()
}

/// Whether `statement` names a filesystem, process or foreign path segment.
fn names_sensitive(statement: &str) -> bool {
    statement
        .split(|c: char| !is_ident(c))
        .any(|segment| SENSITIVE_SEGMENTS.contains(&segment))
}

/// The identifier ending just before the `::` that closes `before`.
fn path_owner(before: &str) -> String {
    let head = before.trim_end_matches("::");
    let from = head
        .char_indices()
        .rev()
        .find(|&(_, c)| !is_ident(c))
        .map_or(0, |(at, c)| at.saturating_add(c.len_utf8()));
    head.get(from..).unwrap_or_default().to_owned()
}

/// The root act the word at byte `at` of `code` makes, if any.
fn act_at(code: &str, at: usize, word: &str) -> Option<String> {
    let rest = code
        .get(at.saturating_add(word.len())..)
        .unwrap_or_default();
    let before = code.get(..at).unwrap_or_default();
    let path = || format!("{word}{}", leading_path(rest));
    if word == "use" {
        let statement = collapse(code.get(at..)?.split(';').next()?);
        let local = matches!(
            use_root(&statement),
            "std" | "core" | "alloc" | "super" | "self"
        );
        return (!local || names_sensitive(&statement)).then_some(statement);
    }
    if word == "Command" {
        return Some(if rest.starts_with("::new(") {
            format!("Command::new({})", call_argument(rest, "::new".len()))
        } else {
            word.to_owned()
        });
    }
    if word.contains("spawn") && !is_definition(code, at) {
        return Some(word.to_owned());
    }
    let in_path = before.ends_with("::");
    let under_rustix = before.ends_with("rustix::");
    if rest.starts_with("::") {
        let rooted = match word {
            "rustix" => !in_path,
            "fs" => !under_rustix,
            "process" => !under_rustix && !rest.starts_with("::Command"),
            _ => false,
        };
        if rooted {
            return Some(path());
        }
    }
    if word == "resolve_primitive" && rest.starts_with('(') && !before.ends_with("fn ") {
        return Some(format!("resolve_primitive({})", call_argument(rest, 0)));
    }
    if PATH_QUERIES.contains(&word) {
        if before.ends_with('.') && rest.starts_with('(') {
            return Some(format!(".{word}("));
        }
        let owner = path_owner(before);
        let on_a_type = !owner.starts_with(|c: char| c.is_ascii_lowercase());
        if in_path && on_a_type {
            return Some(format!("{owner}::{word}"));
        }
    }
    let calls = leading_path(rest)
        .rsplit("::")
        .next()
        .is_some_and(|last| last.starts_with(|c: char| c.is_ascii_lowercase()));
    let foreign = rest.starts_with("::")
        && rest.get(2..).is_some_and(|tail| tail.starts_with(is_ident))
        && calls
        && !in_path
        && word.starts_with(|c: char| c.is_ascii_lowercase())
        && !LOCAL_ROOTS.contains(&word);
    foreign.then(path)
}

/// The refusal the word at byte `at` of `code` opens, if any.
fn refusal_at(code: &str, at: usize, word: &str) -> Option<(&'static str, String)> {
    let rest = code
        .get(at.saturating_add(word.len())..)
        .unwrap_or_default();
    if rest.starts_with('!') && !rest.starts_with("!=") && !MACROS.contains(&word) {
        return Some((MACRO_CALL, word.to_owned()));
    }
    if word != "use" {
        let foreign =
            word == "extern" || (matches!(word, "libc" | "nix") && rest.starts_with("::"));
        return foreign.then(|| (FOREIGN_CALL, word.to_owned()));
    }
    let statement = collapse(
        code.get(at..)
            .and_then(|from| from.split(';').next())
            .unwrap_or_default(),
    );
    if statement.ends_with(" as _") {
        return None;
    }
    if statement.contains(" as ") {
        Some((RENAMED_IMPORT, statement))
    } else {
        names_sensitive(&statement).then_some((BARE_IMPORT, statement))
    }
}

/// The ownership words other than `fchown` on lines `first..=last` of
/// `source`; a line holding only a comment names no act.
fn ownership_words(source: &str, first: usize, last: usize) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let lines = source
        .lines()
        .enumerate()
        .skip(first.saturating_sub(1))
        .take(last.saturating_add(1).saturating_sub(first));
    for (index, line) in lines {
        if line.trim_start().starts_with("//") {
            continue;
        }
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

/// Scan the launcher's root code in `source`; `None` when the launcher
/// module is missing.
fn scan(source: &str) -> Option<Findings> {
    let code = code_only(source);
    let all = items(&code);
    let scope = root_scope(&code, source, &all)?;
    let mut acts = Vec::new();
    let mut refusals = Vec::new();
    if !code.contains(MODULE_OPEN) {
        refusals.push(Refusal {
            line: 0,
            rule: OUT_OF_FILE,
            what: MODULE_NAME.to_owned(),
        });
    }
    let imports = all
        .iter()
        .filter(|item| item.is_use && compiled_for_freebsd(&attributes_of(&code, source, item)));
    for item in scope.iter().copied().chain(imports) {
        let text = code.get(item.start..item.end).unwrap_or_default();
        let statements = use_spans(text);
        for (local, word) in words(text) {
            let at = item.start.saturating_add(local);
            let line = line_of(&code, at);
            if let Some((rule, what)) = refusal_at(&code, at, word) {
                refusals.push(Refusal { line, rule, what });
            }
            let inside_use = statements
                .iter()
                .any(|&(from, to)| from < local && local < to);
            if inside_use {
                continue;
            }
            if let Some(call) = act_at(&code, at, word) {
                acts.push(Act {
                    line,
                    function: enclosing_fn(text, local),
                    call,
                });
            }
        }
        let first = line_of(&code, item.start);
        let last = line_of(&code, item.end.saturating_sub(1));
        refusals.extend(
            ownership_words(source, first, last)
                .into_iter()
                .map(|(line, what)| Refusal {
                    line,
                    rule: OWNERSHIP_BY_NAME,
                    what,
                }),
        );
    }
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
            ("", "use std::process::Command as Run"),
            ("", "use std::fs as files"),
            ("", "use std::os::unix::fs::lchown"),
            ("give_tree", "Command::new(user_bin)"),
            ("give_tree", "files::remove_dir"),
            ("give_tree", "fs::canonicalize"),
            ("give_tree", "fs::chown"),
            ("give_tree", ".symlink_metadata("),
            ("give_tree", "resolve_primitive(Primitive::Owner)"),
            ("give_tree", "spawn"),
            ("give_tree", "rustix::process::chroot"),
            ("give_tree", "Path::metadata"),
            ("give_tree", "Path::exists"),
            ("give_tree", "crate::elsewhere::act"),
            ("give_tree", "m::remove_dir_all"),
            ("reached_helper", "fs::remove_dir_all"),
            ("", "use std::fs::remove_file"),
        ],
        "each act in the module or a FreeBSD-compiled item it reaches is found, collapsed across \
         lines, and none in a comment, an unreached item, or an item another target compiles"
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
            (BARE_IMPORT, "use std::fs::remove_file"),
            (RENAMED_IMPORT, "use std::process::Command as Run"),
            (RENAMED_IMPORT, "use std::fs as files"),
            (BARE_IMPORT, "use std::os::unix::fs::lchown"),
            (OWNERSHIP_BY_NAME, "lchown"),
            (OWNERSHIP_BY_NAME, "chown"),
            (OWNERSHIP_BY_NAME, "lchown"),
            (FOREIGN_CALL, "libc"),
            (OWNERSHIP_BY_NAME, "chown"),
            (MACRO_CALL, "via"),
            (MACRO_CALL, "macro_rules"),
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
        17_usize
            .saturating_add(ADMITTED.len())
            .saturating_add(12)
            .saturating_add(2),
        "{:?}",
        findings.violations()
    );
}

/// A launcher module declared out of line is outside the scan's reach.
#[test]
#[allow(clippy::expect_used)] // the source is this test's own
fn the_root_act_scan_refuses_an_out_of_line_launcher() {
    let findings = scan("#[cfg(target_os = \"freebsd\")]\nmod freebsd_jail;\n")
        .expect("the module is declared");
    let refusals: Vec<&str> = findings
        .refusals
        .iter()
        .map(|refusal| refusal.rule)
        .collect();
    assert_eq!(refusals, [OUT_OF_FILE]);
}
