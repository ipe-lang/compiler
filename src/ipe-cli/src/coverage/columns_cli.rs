//! The CLI aspect columns: documented, tested, not-advertised-unimplemented.
//!
//! Each column judges one [`CliItem`] of the [`CliSurface`]:
//!
//! - **documented**: the subcommand summary or flag description is non-empty —
//!   a blank help string is a hole.
//! - **tested**: at least one `.rs` file in `tests/` invokes the subcommand
//!   (or flag) by name inside a string literal — a subcommand with no test
//!   coverage is a hole; a flag with no test coverage is a [`Cell::Warn`]
//!   (advisory, not a gate failure).
//! - **not-advertised-unimplemented**: a handler in `src/` that contains
//!   `todo!()` or `unimplemented!()` is advertising a capability it does not
//!   deliver — a hole. Currently a source-level scan; flag items return
//!   [`Cell::NotApplicable`] (the handler check applies per command, not per
//!   flag).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use panic_scan::{Want, rust_sources};

use crate::coverage::cli_surface::CliItem;
use crate::coverage::contract::{AspectCheck, Cell};
use crate::coverage::source_tree::TreeRefusal;

// ── documented ────────────────────────────────────────────────────────────────

/// Column **documented**: the summary (for a subcommand) or description (for a
/// flag) is non-empty.
///
/// Every command and flag in `COMMANDS` carries a `summary`/`desc` field that
/// the help renderer displays verbatim. An empty string means the reader sees a
/// blank line — the help text is missing.
pub struct DocumentedColumn;

impl AspectCheck<CliItem> for DocumentedColumn {
    fn name(&self) -> &'static str {
        "documented"
    }

    fn check(&self, item: &CliItem) -> Cell {
        match item {
            CliItem::Subcommand { name, summary } => {
                if summary.is_empty() {
                    Cell::Hole(format!(
                        "`ipe {name}` has no summary in the help table — add one"
                    ))
                } else {
                    Cell::Ok
                }
            }
            CliItem::Flag {
                command,
                flag,
                desc,
            } => {
                if desc.is_empty() {
                    Cell::Hole(format!(
                        "`ipe {command} {flag}` has no description in the help table — add one"
                    ))
                } else {
                    Cell::Ok
                }
            }
        }
    }
}

// ── tested ────────────────────────────────────────────────────────────────────

/// Column **tested**: at least one `.rs` test file references the subcommand
/// name (or flag token) inside a string literal, indicating a standing test
/// exercises it.
///
/// A subcommand with no test mention is a [`Cell::Hole`] — missing test
/// coverage for a whole command is a hard gap. A flag with no test mention is a
/// [`Cell::Warn`] — advisory debt (flags are often exercised implicitly by
/// command-level tests).
///
/// The scan is a string-literal search over the `tests/` tree, not an AST
/// parse: a name inside `"..."` is sufficient evidence that some test passes
/// the name to the CLI. The registry-authoring and surface-module files are
/// excluded so this module's own string literals are not counted as tests.
pub struct TestedColumn {
    inner: Arc<TestScan>,
}

impl TestedColumn {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: TestScan::scan(),
        }
    }
}

impl Default for TestedColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl AspectCheck<CliItem> for TestedColumn {
    fn name(&self) -> &'static str {
        "tested"
    }

    fn check(&self, item: &CliItem) -> Cell {
        let literals = match self.inner.as_ref() {
            TestScan::Scanned(literals) => literals,
            TestScan::Unscanned(refusal) => {
                return Cell::Hole(format!(
                    "`ipe {}` cannot be checked for a standing test: {refusal}",
                    item_label(item)
                ));
            }
        };
        match item {
            CliItem::Subcommand { name, .. } => {
                if literals.contains(*name) {
                    Cell::Ok
                } else {
                    Cell::Hole(format!(
                        "`ipe {name}` has no standing test that invokes it — add one \
                         (search tests/ for a literal `\"{name}\"`)"
                    ))
                }
            }
            CliItem::Flag { command, flag, .. } => {
                // Extract the bare `--flag` token from the synopsis.
                let bare = bare_flag_token(flag);
                if literals.contains(bare) {
                    Cell::Ok
                } else {
                    Cell::Warn(format!(
                        "`ipe {command} {bare}` has no visible test mention — \
                         advisory (flags are often covered implicitly)"
                    ))
                }
            }
        }
    }
}

/// The result of scanning the `tests/` tree for subcommand and flag mentions.
#[derive(Debug)]
enum TestScan {
    /// Every string literal found in test `.rs` files, deduplicated.
    Scanned(BTreeSet<String>),
    /// The tree could not be read whole, so no mention can be trusted absent.
    Unscanned(TreeRefusal),
}

impl TestScan {
    fn scan() -> Arc<Self> {
        static SCAN: OnceLock<Arc<TestScan>> = OnceLock::new();
        SCAN.get_or_init(|| Arc::new(Self::scan_tree(&workspace_path("src/ipe-cli/tests"))))
            .clone()
    }

    /// Collect the string literals of every non-coverage `.rs` file under `tests_root`.
    fn scan_tree(tests_root: &Path) -> Self {
        let files = match rust_sources(tests_root, Want::RustFiles) {
            Ok(files) => files,
            Err(error) => return Self::Unscanned(TreeRefusal::Walk(error)),
        };
        let mut literals = BTreeSet::new();
        for path in files {
            if is_coverage_file(&path) {
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(src) => collect_string_literals(&src, &mut literals),
                Err(error) => return Self::Unscanned(TreeRefusal::Read { file: path, error }),
            }
        }
        Self::Scanned(literals)
    }
}

/// The `ipe …` words naming `item` in a diagnostic.
fn item_label(item: &CliItem) -> String {
    match item {
        CliItem::Subcommand { name, .. } => (*name).to_owned(),
        CliItem::Flag { command, flag, .. } => format!("{command} {}", bare_flag_token(flag)),
    }
}

/// Extract the bare flag token (`"--out"`) from a synopsis like `"[--out <dir>]"`.
fn bare_flag_token(synopsis: &str) -> &str {
    synopsis
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split_whitespace()
        .next()
        .unwrap_or(synopsis)
}

/// Collect every double-quoted string literal from a Rust source file.
///
/// Parses naively: walks the bytes looking for `"…"` pairs. Raw strings and
/// multiline strings are not distinguished — a name that appears anywhere inside
/// a `"…"` token is counted. This is sufficient for the coverage probe: we are
/// looking for the command/flag name as a literal string, not for a specific
/// call site shape.
///
/// Two literals that follow each other as consecutive argv words (`"dev",
/// "build"`, `.arg("dev").arg("build")`) are also recorded joined by a space,
/// so a grouped verb named `dev build` counts as invoked by a test that passes
/// it as two argv elements.
fn collect_string_literals(src: &str, out: &mut BTreeSet<String>) {
    let mut rest = src;
    let mut previous: Option<&str> = None;
    while let Some(pos) = rest.find('"') {
        let gap = rest.get(..pos).unwrap_or("");
        // Step past the opening quote.
        let Some(after) = rest.get(pos + 1..) else {
            break;
        };
        rest = after;
        // Find the closing quote (naive: ignores backslash-escapes for our
        // purpose — we match whole words, not the exact literal value).
        let end = rest.find('"').unwrap_or(rest.len());
        let content = rest.get(..end);
        if let Some(content) = content
            && content.len() <= 64
        {
            // Only short tokens are plausible command/flag names.
            out.insert(content.to_owned());
            if let Some(first) = previous
                && is_argv_separator(gap)
            {
                out.insert(format!("{first} {content}"));
            }
        }
        previous = content.filter(|c| c.len() <= 64);
        rest = rest.get(end + 1..).unwrap_or("");
    }
}

/// Whether the source text between two literals only separates argv words:
/// commas, whitespace, `.to_owned()` / `.into()` conversions, and
/// `.arg(` / `)` call punctuation.
fn is_argv_separator(gap: &str) -> bool {
    let stripped = gap
        .replace(".to_owned()", "")
        .replace(".to_string()", "")
        .replace(".into()", "")
        .replace(".arg(", "");
    !stripped.is_empty()
        && stripped
            .chars()
            .all(|c| c == ',' || c == ')' || c.is_whitespace())
}

/// Whether `path` is a coverage-module file (excluded from the test scan so
/// the column's own string literals are not counted as tests).
fn is_coverage_file(path: &Path) -> bool {
    let s = path.to_string_lossy().replace('\\', "/");
    s.contains("ipe-cli/src/coverage/") || s.contains("ipe-cli/tests/cli_surface_coverage_matrix")
}

// ── not-advertised-unimplemented ──────────────────────────────────────────────

/// Column **not-advertised-unimplemented**: a subcommand whose handler
/// body contains `todo!()` or `unimplemented!()` is advertising a capability
/// it does not deliver.
///
/// This is a [`Cell::Hole`] for subcommands and [`Cell::NotApplicable`] for
/// flags (the check applies once per command, not per flag). Currently a
/// source-level scan over `src/ipe-cli/src/`.
pub struct NotAdvertisedUnimplementedColumn {
    stubs: Arc<StubScan>,
}

impl NotAdvertisedUnimplementedColumn {
    #[must_use]
    pub fn new() -> Self {
        Self {
            stubs: scan_stub_commands(),
        }
    }
}

impl Default for NotAdvertisedUnimplementedColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl AspectCheck<CliItem> for NotAdvertisedUnimplementedColumn {
    fn name(&self) -> &'static str {
        "not-advertised-unimplemented"
    }

    fn check(&self, item: &CliItem) -> Cell {
        match item {
            CliItem::Subcommand { name, .. } => match self.stubs.as_ref() {
                StubScan::Unreadable(refusal) => Cell::Hole(format!(
                    "`ipe {name}` cannot be cleared of `todo!()` / `unimplemented!()`: \
                     production {refusal}"
                )),
                StubScan::Scanned(stubs) if stubs.contains(*name) => Cell::Hole(format!(
                    "`ipe {name}` is advertised in the help table but its handler \
                     contains `todo!()` or `unimplemented!()` — implement it or \
                     remove it from COMMANDS"
                )),
                StubScan::Scanned(_) => Cell::Ok,
            },
            CliItem::Flag { .. } => Cell::not_applicable(
                "a flag, not a subcommand — the not-advertised-unimplemented check applies \
                 to subcommand handlers",
            ),
        }
    }
}

/// Scan `src/ipe-cli/src/` for commands whose handler files contain
/// `todo!()` or `unimplemented!()`; an unreadable source fails the scan closed.
///
/// The heuristic: for each command `name`, if the combined source of
/// `src/ipe-cli/src/` contains a `run_<name>` symbol next to `todo!()` or
/// `unimplemented!()`, the command is a stub. A global file-level scan is used
/// because a Rust function body can span many lines and the probe is for ANY
/// such macro in ANY production source file — test files are excluded.
fn scan_stub_commands() -> Arc<StubScan> {
    static STUBS: OnceLock<Arc<StubScan>> = OnceLock::new();
    STUBS
        .get_or_init(|| Arc::new(scan_stub_sources(&workspace_path("src/ipe-cli/src"))))
        .clone()
}

/// Outcome of scanning the CLI production sources for stubbed handlers.
#[derive(Debug)]
enum StubScan {
    /// Every production source was read; these commands are stubs.
    Scanned(BTreeSet<String>),
    /// The production sources could not be read whole, so no command can be cleared.
    Unreadable(TreeRefusal),
}

/// Read every CLI production source under `src_root` once and name the stubbed commands.
fn scan_stub_sources(src_root: &Path) -> StubScan {
    let files = match rust_sources(src_root, Want::RustFiles) {
        Ok(files) => files,
        Err(error) => return StubScan::Unreadable(TreeRefusal::Walk(error)),
    };

    // Every Rust production source file: confirmed test modules and the
    // coverage probes themselves are excluded.
    let mut sources = Vec::new();
    for path in files {
        let excluded = path.strip_prefix(src_root).is_ok_and(|rel| {
            panic_scan::is_verified_test_path(src_root, rel) || rel.starts_with("coverage")
        });
        if excluded {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(src) => sources.push(src),
            Err(error) => return StubScan::Unreadable(TreeRefusal::Read { file: path, error }),
        }
    }

    // A file must contain the handler name AND a stub macro to count —
    // prevents false positives from comments or unrelated functions.
    let mut stub_commands = BTreeSet::new();
    for spec in crate::help::all_command_specs() {
        let handler_name = format!("run_{}", spec.name.replace('-', "_"));
        let stubbed = sources.iter().any(|src| {
            src.contains(&handler_name)
                && (src.contains("todo!()") || src.contains("unimplemented!()"))
        });
        if stubbed {
            stub_commands.insert(spec.name.to_owned());
        }
    }
    StubScan::Scanned(stub_commands)
}

// ── shared utilities ──────────────────────────────────────────────────────────

/// Resolve a workspace-root-relative path from this crate's manifest directory.
fn workspace_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A grouped verb passed as two consecutive argv words is recorded under its
    /// joined name; two literals separated by other code are not joined.
    #[test]
    fn consecutive_argv_literals_are_joined() {
        let mut found = BTreeSet::new();
        collect_string_literals(
            "run(&[\"dev\", \"build\"]); cmd.arg(\"release\")\n    .arg(\"run\"); \
             vec![\"release\".to_owned(), \"eject\".to_owned()]; \
             let a = \"dev\"; let b = \"watch\";",
            &mut found,
        );
        for joined in ["dev build", "release run", "release eject"] {
            assert!(
                found.contains(joined),
                "`{joined}` must be recorded: {found:?}"
            );
        }
        assert!(
            !found.contains("dev watch"),
            "literals split by other code must not join: {found:?}"
        );
    }

    /// A tree the walker refuses holes every command and flag rather than reading as untested.
    #[test]
    fn a_missing_tests_tree_holes_every_item() {
        let root = ipe_test_temp::temp_root()
            .join(format!("ipe-cli-tested-missing-{}", std::process::id()));
        let column = TestedColumn {
            inner: Arc::new(TestScan::scan_tree(&root)),
        };
        let items = [
            CliItem::Subcommand {
                name: "build",
                summary: "Build",
            },
            CliItem::Flag {
                command: "build",
                flag: "[--out <dir>]",
                desc: "Output",
            },
        ];
        for item in &items {
            let cell = column.check(item);
            assert!(
                matches!(cell, Cell::Hole(ref why)
                    if why.contains("cannot be listed") && why.contains(&*root.to_string_lossy())),
                "{cell:?}"
            );
        }
    }

    /// Production sources the walker refuses clear no command of a stub.
    #[test]
    fn a_missing_production_tree_clears_no_command() {
        let root = ipe_test_temp::temp_root()
            .join(format!("ipe-cli-stubs-missing-{}", std::process::id()));
        let column = NotAdvertisedUnimplementedColumn {
            stubs: Arc::new(scan_stub_sources(&root)),
        };
        let cell = column.check(&CliItem::Subcommand {
            name: "build",
            summary: "Build",
        });
        assert!(
            matches!(cell, Cell::Hole(ref why)
                if why.contains("cannot be listed") && why.contains(&*root.to_string_lossy())),
            "{cell:?}"
        );
    }
}
