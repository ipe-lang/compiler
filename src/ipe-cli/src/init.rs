//! `ipe init` — scaffold a new Ipê project.
//!
//! `ipe init [directory] [shape] [runtime]` (spec § 8). The positionals mirror
//! the build grammar's prefix and are wizard shortcuts: `directory` is where to
//! scaffold (`.` or omitted → the current directory, as `cargo init`); `shape`
//! picks the template; `runtime` (for `web` only) seeds the declared delivery
//! set (`ships`) and the delivery the next steps build.
//! Host and target are not `init` args — they are delivery choices with defaults
//! written into `package.ipe`'s `delivery` and selected later at build/release.
//!
//! On a TTY with a positional omitted the command prompts in order — shape → (if
//! `web`) runtime. The scaffold is the matching entry for that shape:
//!
//! - `script` — a `Task Error ()` main
//! - `tui`    — a `Tui.tea` main
//! - `cli`    — a `Cli.tea` main
//! - `server` — a `Server.listen` main
//! - `web`    — a `Web.tea` counter (the default)
//!
//! Fully supplied (or a non-TTY run) skips every prompt and defaults each missing
//! positional (`web` / `served`). Templates are embedded at build time via
//! [`include_str!`], so scaffolding is self-contained and offline.
//!
//! Re-run is an idempotent reconcile, never a reset (spec § 8): a fresh directory
//! is scaffolded; an existing project with absent or matching args has only its
//! *missing* files created; an existing project whose args *conflict* with what
//! `main` already pins is refused with a pedagogical error, never silently
//! reshaped.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use ipe_fs_open::ByteCap;

use crate::delivery::{Delivery, Runtime};
use crate::delivery_set::ShipEntry;
use crate::output_dir::held::{
    BackedUp, BackupName, Created, EntryKind, HeldDir, ReadMiss, Unread, read_miss,
};
use crate::project::BundleId;
use crate::screen::Interactive;
use crate::verb::Verb;
use crate::{CliError, health, style, text};

// ── per-shape Main.ipe templates ─────────────────────────────────────────────

const MAIN_WEB_IPE: &str = include_str!("../templates/Main.ipe");
const MAIN_TUI_IPE: &str = include_str!("../templates/Main.tui.ipe");
const MAIN_CLI_IPE: &str = include_str!("../templates/Main.cli.ipe");
const MAIN_SERVER_IPE: &str = include_str!("../templates/Main.server.ipe");
const MAIN_SCRIPT_IPE: &str = include_str!("../templates/Main.script.ipe");
const MAIN_WORKER_IPE: &str = include_str!("../templates/Main.worker.ipe");

// ── per-shape package.ipe templates (carry a `{name}` hole) ──────────────────

const PACKAGE_WEB_IPE: &str = include_str!("../templates/package.web.ipe.in");
const PACKAGE_TUI_IPE: &str = include_str!("../templates/package.tui.ipe.in");
const PACKAGE_CLI_IPE: &str = include_str!("../templates/package.cli.ipe.in");
const PACKAGE_SERVER_IPE: &str = include_str!("../templates/package.server.ipe.in");
const PACKAGE_SCRIPT_IPE: &str = include_str!("../templates/package.script.ipe.in");
const PACKAGE_WORKER_IPE: &str = include_str!("../templates/package.worker.ipe.in");

// ── shared templates ──────────────────────────────────────────────────────────

const README_MD: &str = include_str!("../templates/README.md.in");

const PACKAGE_LIB_IPE: &str = include_str!("../templates/package.lib.ipe.in");
const LIB_IPE: &str = include_str!("../templates/Lib.ipe.in");
const README_LIB_MD: &str = include_str!("../templates/README.lib.md.in");

const GITIGNORE: &str = include_str!("../templates/gitignore.in");

// ── shape model ───────────────────────────────────────────────────────────────

/// The scaffold templates a wizard or `--shape` flag may select.
///
/// The compiler shape is pinned by `main`'s entry function; the manifest's
/// `delivery` sections provide per-host build configuration for each resolved
/// target. `Server` is a scaffold *template* convenience only — a server is the
/// `Direct` (`script`) shape running `Server.listen`, so its generated project
/// is a `script` program with a `Server.listen` starter `main`, not a distinct
/// compiler shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum InitShape {
    /// `main = Web.tea …` — DOM rendering, served or client.
    #[default]
    Web,
    /// `main = Tui.tea …` — terminal cells rendering.
    Tui,
    /// `main = Cli.tea …` — terminal lines rendering.
    Cli,
    /// `main = Worker.tea …` — the view-less TEA loop; no rendering.
    Worker,
    /// `main = Server.listen …` — a `Direct` (`script`) program that runs an HTTP
    /// server; a scaffold-template convenience, not a distinct compiler shape.
    Server,
    /// `main : Task Error ()` — plain task, no rendering.
    Script,
}

impl InitShape {
    /// Every scaffold shape, in wizard order. The single source of truth for
    /// "which shapes exist": the scaffold-build SEAL iterates this so a new
    /// variant cannot silently escape the accept-then-build proof, and
    /// [`InitShape::exhaustiveness_guard`] fails to compile if a variant is added
    /// without being listed here.
    pub const ALL: [Self; 6] = [
        Self::Web,
        Self::Tui,
        Self::Cli,
        Self::Worker,
        Self::Server,
        Self::Script,
    ];

    /// Compile-time proof that [`InitShape::ALL`] lists every variant: the match
    /// is exhaustive, so adding a variant without extending `ALL` fails to
    /// compile here (the new arm has no `ALL` slot to map to). Never called; its
    /// purpose is the type check.
    #[allow(dead_code)] // compile-time exhaustiveness tripwire, not runtime code.
    const fn exhaustiveness_guard(self) -> usize {
        // Each variant maps to its index in `ALL`. A new variant forces a new arm,
        // and a new arm forces a matching `ALL` entry (or the index is wrong and
        // the `Self::ALL[i]` equality assertion below fails at compile time).
        match self {
            Self::Web => 0,
            Self::Tui => 1,
            Self::Cli => 2,
            Self::Worker => 3,
            Self::Server => 4,
            Self::Script => 5,
        }
    }

    /// Parse a `--shape` flag value. Returns `None` for an unrecognised token.
    fn parse(s: &str) -> Option<Self> {
        match s {
            "web" => Some(Self::Web),
            "tui" => Some(Self::Tui),
            "cli" => Some(Self::Cli),
            "worker" => Some(Self::Worker),
            "server" => Some(Self::Server),
            "script" => Some(Self::Script),
            _ => None,
        }
    }

    /// The display name used in prompts and messages.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Tui => "tui",
            Self::Cli => "cli",
            Self::Worker => "worker",
            Self::Server => "server",
            Self::Script => "script",
        }
    }

    /// Whether this shape carries a runtime choice. Only `web` is placed on both
    /// effect-locality columns (served vs client); every other shape has one
    /// runtime, so a `runtime` positional on it is a conflict (spec § 0, § 2).
    const fn has_runtime_choice(self) -> bool {
        matches!(self, Self::Web)
    }

    /// The `Main.ipe` source for this shape (byte-stable, no substitution).
    const fn main_ipe(self) -> &'static str {
        match self {
            Self::Web => MAIN_WEB_IPE,
            Self::Tui => MAIN_TUI_IPE,
            Self::Cli => MAIN_CLI_IPE,
            Self::Worker => MAIN_WORKER_IPE,
            Self::Server => MAIN_SERVER_IPE,
            Self::Script => MAIN_SCRIPT_IPE,
        }
    }

    /// The `package.ipe` template for this shape (carries a `{name}` hole).
    const fn package_ipe(self) -> &'static str {
        match self {
            Self::Web => PACKAGE_WEB_IPE,
            Self::Tui => PACKAGE_TUI_IPE,
            Self::Cli => PACKAGE_CLI_IPE,
            Self::Worker => PACKAGE_WORKER_IPE,
            Self::Server => PACKAGE_SERVER_IPE,
            Self::Script => PACKAGE_SCRIPT_IPE,
        }
    }

    /// The post-init "how to try it" hint for this shape.
    ///
    /// The single source of truth for the text, so a new shape cannot silently
    /// inherit another shape's instructions. `web` is the one shape with a
    /// runtime choice (spec § 0.1): `runtime` picks between its served and
    /// client wording; every other arm ignores it.
    const fn open_hint(self, runtime: Runtime) -> &'static str {
        match self {
            Self::Web => match runtime {
                Runtime::Served => "Then open http://localhost:8000 and click the counter buttons.",
                Runtime::Client => {
                    "This is a `client` app: the run publishes its wasm bundle, serves it \
                     on 127.0.0.1 and opens it in a browser (or prints the address to open); \
                     then click the counter buttons."
                }
            },
            Self::Tui => "Then press the Up/Down arrow keys to change the count; press q to quit.",
            Self::Cli => {
                "Then type a line to echo it back (each line bumps the count); type q to quit."
            }
            Self::Worker => "It logs three ticks and exits on its own — no interaction needed.",
            Self::Server => "Then open http://localhost:8000 (or curl it) to see the response.",
            Self::Script => "It prints its greeting and exits — no interaction needed.",
        }
    }

    /// The `README.md`'s one-sentence description of what `src/Main.ipe` is.
    ///
    /// The single source of truth for that sentence, exhaustively matched like
    /// [`InitShape::open_hint`], so a new shape can't ship a README describing
    /// another shape's app; `web` describes the runtime it was scaffolded for.
    const fn readme_description(self, runtime: Runtime) -> &'static str {
        match self {
            Self::Web => match runtime {
                Runtime::Served => {
                    "a small `Ipe.Web` counter — a Model holding a count, `Increment` and \
                     `Decrement` messages, and a two-button view — that serves its UI over HTTP."
                }
                Runtime::Client => {
                    "a small `Ipe.Web` counter — a Model holding a count, `Increment` and \
                     `Decrement` messages, and a two-button view — that runs in the browser \
                     as a self-contained wasm client."
                }
            },
            Self::Tui => {
                "a small `Ipe.Tea.Tui` counter — a Model holding a count, updated by the \
                 Up/Down arrow keys and rendered to the terminal screen; `q` quits."
            }
            Self::Cli => {
                "a small `Ipe.Tea.Cli` line-echo app — each line you type bumps a counter \
                 and is echoed back; `q` quits."
            }
            Self::Worker => {
                "a small `Ipe.Tea.Worker` — it logs three ticks on a timer, then exits."
            }
            Self::Server => {
                "a small `Ipe.Server.Http` server — it replies `Hello, world!` on `GET /`."
            }
            Self::Script => "a one-shot `Ipe.Task` script — it prints a greeting and exits.",
        }
    }

    /// The command the next steps advise, building the delivery the scaffold declares.
    ///
    /// A `web client` scaffold declares the browser client, so it advises
    /// `ipe dev run` spelled with that delivery's own words, which publishes
    /// the bundle and serves it; every other scaffold declares its shape's
    /// default delivery, which a bare `ipe dev run` builds and runs.
    fn next_step_command(self, runtime: Runtime) -> String {
        let client = match self {
            Self::Web => match runtime {
                Runtime::Served => None,
                Runtime::Client => Some(Delivery::web_client()),
            },
            Self::Tui | Self::Cli | Self::Worker | Self::Server | Self::Script => None,
        };
        client.map_or_else(
            || format!("ipe {}", Verb::DEV_RUN.name()),
            |delivery| {
                let words: Vec<&str> = delivery.words().collect();
                format!("ipe {} {}", Verb::DEV_RUN.name(), words.join(" "))
            },
        )
    }
}

// ── runtime model ──────────────────────────────────────────────────────────────

/// The word a message prints for a runtime: its delivery word, or `served` for
/// the unnamed default.
fn runtime_label(runtime: Runtime) -> &'static str {
    runtime.word().unwrap_or("served")
}

/// The `{ships}` template fill for a web project's `package.ipe` delivery
/// record, so the runtime choice writes the delivery set `ipe release` builds.
///
/// A runtime with a ship builder of its own on the default host (`client`)
/// declares an explicit `ships = [ client ]`; served is the implicit
/// `[ binary ]` singleton, so it fills to nothing and the manifest stays
/// minimal. The fill is spliced before the first delivery sub-field, closing
/// with a `, ` so the record's existing fields follow it unchanged.
fn ships_fill(runtime: Runtime) -> String {
    ShipEntry::BUILDERS
        .into_iter()
        .find(|entry| entry.axes() == Some((runtime, crate::delivery::Host::Default)))
        .map_or_else(String::new, |entry| {
            format!("ships = [ {} ]\n        , ", entry.builder_word())
        })
}

// ── init args ─────────────────────────────────────────────────────────────────

/// Parsed and validated arguments for `ipe init`.
#[derive(Debug)]
struct InitArgs {
    target_arg: Option<String>,
    force: bool,
    lib: bool,
    /// The shape positional (or the `--shape` flag), when supplied — skips the
    /// wizard shape prompt.
    shape: Option<InitShape>,
    /// The runtime positional, when supplied for a `web` shape — skips the wizard
    /// runtime prompt and seeds the declared delivery set.
    runtime: Option<Runtime>,
}

// ── managed-file model ────────────────────────────────────────────────────────

/// The target's subdirectory a managed file lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedDir {
    /// The target directory itself.
    Root,
    /// The target's `src` directory.
    Src,
}

/// The name of the target's source directory.
const SRC_DIR: &str = "src";

/// One file `ipe init` manages: its directory, its single-component name, the
/// content it would write, and the cap its existing copy is read under.
struct ManagedFile {
    dir: ManagedDir,
    name: String,
    /// The exact bytes `init` would write.
    content: String,
    cap: ByteCap,
}

impl ManagedFile {
    /// A managed source or project file, read under [`crate::io_bounded::SOURCE_CAP`].
    fn source(dir: ManagedDir, name: impl Into<String>, content: String) -> Self {
        Self {
            dir,
            name: name.into(),
            content,
            cap: crate::io_bounded::SOURCE_CAP,
        }
    }

    /// The coding-agent guide, read under [`crate::agents_guide::GUIDE_READ_CAP`].
    fn guide() -> Self {
        Self {
            dir: ManagedDir::Root,
            name: crate::agents_guide::FILE_NAME.to_owned(),
            content: crate::agents_guide::rendered(),
            cap: crate::agents_guide::GUIDE_READ_CAP,
        }
    }

    /// The file's path relative to the target, for display only; never opened.
    fn rel(&self) -> PathBuf {
        match self.dir {
            ManagedDir::Root => PathBuf::from(&self.name),
            ManagedDir::Src => Path::new(SRC_DIR).join(&self.name),
        }
    }
}

/// What to do with a managed file that exists and was read.
#[derive(Clone, Copy)]
enum Existing<'a> {
    /// Ask on the terminal; the default is to keep it.
    Ask(&'a Interactive),
    /// Back it up and replace it.
    Force,
    /// Keep it, for the reason given.
    Keep(KeepWhy),
}

/// What to do with a managed file that is absent.
#[derive(Clone, Copy)]
enum Missing<'a> {
    /// Ask on the terminal; the default is to write it.
    Ask(&'a Interactive),
    /// Write it.
    Write,
}

/// Why a policy keeps an existing managed file without asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeepWhy {
    /// No terminal to ask on.
    NoTerminal,
    /// A fresh scaffold without `--force`.
    NotForced,
}

/// What [`place_managed`] did with one managed file.
#[derive(Debug)]
enum Placed {
    /// The absent file was written.
    Created,
    /// The existing file was backed up, then replaced.
    Replaced(BackupName),
    /// Nothing was written.
    Kept(Kept),
}

/// Why [`place_managed`] wrote nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kept {
    /// The question was answered no.
    Declined,
    /// The policy keeps an existing file.
    Policy(KeepWhy),
    /// An entry has the name and was not read: a link, a non-regular file, an
    /// oversize or non-UTF-8 file, or an unreadable one.
    Unread(Unread),
    /// An entry took the name between the read and the create.
    Appeared,
    /// The file changed between the read and the replace.
    Changed,
    /// Every backup slot is taken.
    BackupSlotsFull,
}

// ── template string escaping ─────────────────────────────────────────────────

/// Text safe to splice into a single-line Ipê string literal (`"…"`).
///
/// Templates carry `{name}` holes that live *inside* quoted `.ipe` literals. A
/// project name is a directory basename, so it may hold a quote, backslash, or
/// newline that would otherwise close the literal early or inject syntax. This
/// constructor escapes those characters, so a hole filled with an
/// [`IpeStringLiteral`] cannot produce a malformed or injected literal — the
/// unescaped case is unrepresentable.
///
/// The escapes match the lexer's recognised set (`\n \t \r \\ \" \0`): a
/// carriage return escapes to `\r`; every other control scalar is dropped, as
/// none is valid inside a single-line literal and there is no escape for it.
/// The body is *unquoted*: the template supplies the surrounding quotes.
struct IpeStringLiteral(String);

impl IpeStringLiteral {
    /// Escape `raw` into the body of a single-line Ipê string literal.
    fn escaped(raw: &str) -> Self {
        // Drop every control scalar `ipe_syntax::ESCAPES` has no escape for —
        // a single-line literal has no way to write one — then escape the
        // rest through that shared table, the lexer's own escape set.
        let kept: String = raw
            .chars()
            .filter(|c| !c.is_control() || ipe_syntax::ESCAPES.iter().any(|(_, v)| v == c))
            .collect();
        Self(ipe_syntax::escape_str_body(&kept))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// Fill a template's `{name}` hole, escaping `project_name` for the quoted
/// `.ipe` literals it lands in.
fn fill_name(template: &str, project_name: &str) -> String {
    let escaped = IpeStringLiteral::escaped(project_name);
    // `{name}` is a template placeholder substituted by `.replace`, not a
    // `format!` argument — the formatting-args lint's heuristic misreads it.
    #[allow(clippy::literal_string_with_formatting_args)]
    template.replace("{name}", escaped.as_str())
}

/// Fill a `package.ipe` template's `{bundle_id}`, (web-only) `{ships}`, and
/// `{name}` holes.
///
/// `{ships}` is a fixed builder expression drawn from the runtime's closed set,
/// never user input, so it needs no literal escaping; non-web templates carry no
/// `{ships}` hole, so the substitution is a no-op there. `{bundle_id}` is
/// [`BundleId::derived`] from the name, escaped as the second layer. The fixed
/// holes fill before `{name}`, so a name that spells a hole stays literal text.
fn fill_package(template: &str, project_name: &str, runtime: Runtime) -> String {
    let bundle_id = IpeStringLiteral::escaped(BundleId::derived(project_name).as_str());
    // `{bundle_id}` and `{ships}` are template placeholders substituted by
    // `.replace`, not `format!` arguments — the formatting-args lint's
    // heuristic misreads them.
    #[allow(clippy::literal_string_with_formatting_args)]
    let filled = template
        .replace("{bundle_id}", bundle_id.as_str())
        .replace("{ships}", &ships_fill(runtime));
    fill_name(&filled, project_name)
}

// ── entry point ───────────────────────────────────────────────────────────────

/// `ipe init [<name>] [--force] [--lib] [--shape <shape>]`.
///
/// With `<name>`, create the directory `<name>/` and scaffold inside it. With
/// no argument or `.`, scaffold in the current directory.
///
/// On a TTY, without `--shape`, the wizard prompts for shape (and, for `web`,
/// runtime and host) before scaffolding. With `--shape` or no TTY, the
/// supplied shape (or the default, `web`) is used directly.
///
/// # Errors
/// [`CliError::Usage`] on an unrecognised flag or an unexpected argument;
/// [`CliError::Io`] on any filesystem failure.
pub fn run_init(rest: &[String]) -> Result<(), CliError> {
    let args = parse_init_args(rest)?;

    // Banner: stderr, terminal-only (piped / CI output stays clean).
    if std::io::stderr().is_terminal() {
        style::print_command_header();
    }

    let target = args.target_arg.as_deref().unwrap_or(".");
    let target_dir = PathBuf::from(target);
    let project_name = project_name_for(&target_dir)?;

    if args.lib {
        let files = library_files(&project_name);
        return run_scaffold(
            target,
            &target_dir,
            &project_name,
            &files,
            args.force,
            ScaffoldKind::Library,
        );
    }

    let is_tty = Interactive::detect().is_some();

    // Determine shape: explicit positional/flag → no prompt; TTY → prompt; else
    // default. The wizard prompts only for a positional the caller omitted.
    let shape = match args.shape {
        Some(s) => s,
        None if is_tty && !args.force => wizard_shape()?,
        None => InitShape::default(),
    };

    // Runtime is a `web`-only choice; resolve it (positional → prompt → default)
    // only for the web shape, and record whether it came from the caller so the
    // re-run contract can tell an explicit request from a default.
    let runtime = if shape.has_runtime_choice() {
        match args.runtime {
            Some(rt) => rt,
            None if is_tty && !args.force => wizard_runtime()?,
            None => Runtime::Served,
        }
    } else {
        Runtime::Served
    };

    // Re-run contract: an existing project whose `main` pins a different shape —
    // or a web runtime the caller stated that disagrees is a shape/runtime
    // conflict — is refused, never silently reshaped (spec § 8).
    guard_rerun_conflict(&target_dir, shape, args.shape, args.runtime)?;

    let files = managed_files(&project_name, shape, runtime);
    run_scaffold(
        target,
        &target_dir,
        &project_name,
        &files,
        args.force,
        ScaffoldKind::App { shape, runtime },
    )
}

/// Refuse a re-run whose stated shape/runtime conflicts with the existing
/// project's code (spec § 8). `init` never reshapes what `main` already pins.
///
/// A conflict fires only when the caller *states* a shape (a positional or
/// `--shape`) that differs from the shape the on-disk `src/Main.ipe` classifies
/// to. An absent or matching shape reconciles silently. The runtime is a web-only
/// axis and does not alter the scaffolded files (all delivery sections are
/// present), so a bare runtime restatement is not itself a conflict; a runtime on
/// a now-non-web project is already refused at parse time.
fn guard_rerun_conflict(
    target_dir: &Path,
    resolved_shape: InitShape,
    stated_shape: Option<InitShape>,
    _stated_runtime: Option<Runtime>,
) -> Result<(), CliError> {
    let Some(stated) = stated_shape else {
        return Ok(());
    };
    let Some(existing) = existing_project_shape(target_dir)? else {
        return Ok(());
    };
    if stated != existing {
        return Err(CliError::ProjectRefused(text::msg::init_shape_fixed(
            &existing.label(),
            &stated.label(),
        )));
    }
    // `resolved_shape` equals `stated` here (a stated shape is used verbatim); the
    // parameter documents that the reconcile proceeds with the caller's shape.
    let _ = resolved_shape;
    Ok(())
}

/// The shape an existing project's `src/Main.ipe` *confidently* pins, or `None`
/// when the entry is absent, unparseable, or not confidently classifiable.
///
/// The TEA rendering shapes (`web`/`tui`/`cli`/`worker`) are recognised by a
/// qualified entry head (`Web.tea`/`Tui.tea`/…) via the lenient scaffold-detection
/// classifier ([`ipe_canon::shape_source::scaffold_shape_hint`]) — deliberately
/// NOT the strict capability-gate classifier, so a partially written entry still
/// reads its shape. A genuine `Task Error ()` script, a listening `Server.listen`
/// server, and an un-spellable head all collapse to
/// [`ipe_canon::shape_source::MainShape::Script`], so a `Script` result is
/// ambiguous — refusing on it would risk a false conflict against a project this
/// read merely could not classify. Soundness direction
/// (spec § 5): the re-run guard over-permits toward *reconcile* rather than refuse
/// a project that is not confidently a different shape; the only cost of a missed
/// conflict is a reconcile that leaves every present file untouched anyway.
///
/// The entry is opened beneath `target_dir` level by level, never through a
/// symlink and never blocking on a FIFO, and read under [`crate::io_bounded::SOURCE_CAP`].
///
/// # Errors
/// [`CliError::SourceRefused`] for a symlinked or non-regular `src/Main.ipe`;
/// [`CliError::FileTooLarge`] past the cap; [`CliError::Io`] for another read failure.
fn existing_project_shape(target_dir: &Path) -> Result<Option<InitShape>, CliError> {
    let source = match crate::io_bounded::read_named_in(
        target_dir,
        &["src", "Main.ipe"],
        crate::io_bounded::SOURCE_CAP,
    ) {
        Ok(s) => s,
        Err(CliError::Io { ref source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let mut interner = ipe_intern::Interner::new();
    let Ok(module) = ipe_parse::parse_module(&source, &mut interner) else {
        // A source that does not parse yet pins no shape; the reconcile leaves it
        // untouched and the user's own build reports the real parse error.
        return Ok(None);
    };
    // Scaffold detection is a UX read, never a capability gate: it picks which
    // template a re-run reconciles against. It uses the LENIENT written-qualifier
    // classifier (not the strict `classify_main_shape` the capability gate keys
    // on) so a partially written `src/Main.ipe` — `main = Tui.tea config` before
    // its `import Ipe.Tea.Tui` line is typed — is still recognised as its shape. A
    // wrong read only mis-scaffolds or misses a re-run conflict; it cannot escalate
    // a capability.
    let shape = ipe_canon::shape_source::scaffold_shape_hint(&module, &interner);
    Ok(confidently_pinned_shape(shape))
}

/// Map a classified `main` shape onto the confidently-pinned [`InitShape`], or
/// `None` for the ambiguous `Script` fallback (a real script, a listening
/// `Server.listen` server, *or* an un-pinnable head — all collapse to
/// [`ipe_canon::shape_source::MainShape::Script`]). Only a qualified
/// rendering-entry head yields one of the confident TEA shapes; a server is a
/// `script`, so it reconciles under the ambiguous fallback like any bare `Task`.
const fn confidently_pinned_shape(shape: ipe_canon::shape_source::MainShape) -> Option<InitShape> {
    use ipe_canon::shape_source::MainShape;
    match shape {
        MainShape::Web => Some(InitShape::Web),
        MainShape::Tui => Some(InitShape::Tui),
        MainShape::Cli => Some(InitShape::Cli),
        MainShape::Worker => Some(InitShape::Worker),
        MainShape::Script => None,
    }
}

/// Parse raw `init` arguments into [`InitArgs`].
///
/// Positionals are `[directory] [shape] [runtime]` (spec § 8) — a wizard-shortcut
/// prefix mirroring the build grammar. The first positional is the directory; a
/// following one is the shape word; a third is the runtime word (`web` only). The
/// legacy `--shape <s>` flag still supplies the shape (and, if a shape positional
/// is also given, they must agree). `--force`/`--lib` are unchanged.
fn parse_init_args(rest: &[String]) -> Result<InitArgs, CliError> {
    let mut target_arg: Option<String> = None;
    let mut shape_positional: Option<InitShape> = None;
    let mut runtime_positional: Option<Runtime> = None;
    let mut shape_flag: Option<InitShape> = None;
    let mut force = false;
    let mut lib = false;
    let mut iter = rest.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--force" => force = true,
            "--lib" => lib = true,
            "--shape" => {
                let val = iter
                    .next()
                    .ok_or(CliError::Usage(text::msg::init_shape_needs_value()))?;
                shape_flag = Some(parse_shape_word(val)?);
            }
            flag if flag.starts_with('-') => {
                return Err(crate::cli_args::usage_unknown_flag("init", flag));
            }
            positional if target_arg.is_none() => target_arg = Some(positional.to_owned()),
            positional if shape_positional.is_none() => {
                shape_positional = Some(parse_shape_word(positional)?);
            }
            positional if runtime_positional.is_none() => {
                runtime_positional = Some(parse_runtime_word(positional)?);
            }
            other => {
                return Err(crate::cli_args::usage_unexpected_argument("init", other));
            }
        }
    }

    // The shape positional and the `--shape` flag are two spellings of one input;
    // if both are present they must name the same shape.
    let shape = match (shape_positional, shape_flag) {
        (Some(p), Some(f)) if p != f => {
            return Err(CliError::Usage(text::msg::init_shape_disagrees(
                &p.label(),
                &f.label(),
            )));
        }
        (Some(s), _) | (_, Some(s)) => Some(s),
        (None, None) => None,
    };

    // A runtime positional only makes sense for `web`; on any other named shape
    // it is a conflict, phrased as a lesson (spec § 6).
    if let (Some(rt), Some(sh)) = (runtime_positional, shape)
        && !sh.has_runtime_choice()
    {
        return Err(CliError::Usage(text::msg::init_runtime_needs_web(
            &runtime_label(rt),
            &sh.label(),
        )));
    }

    Ok(InitArgs {
        target_arg,
        force,
        lib,
        shape,
        runtime: runtime_positional,
    })
}

/// Parse a shape word positional or flag value into an [`InitShape`], with the
/// one pedagogical "unknown shape" message.
fn parse_shape_word(word: &str) -> Result<InitShape, CliError> {
    InitShape::parse(word).ok_or_else(|| CliError::Usage(text::msg::init_unknown_shape(&word)))
}

/// Parse a runtime word positional through the delivery grammar's own reader.
///
/// `served` (the unnamed default) and the retired words are refused with the
/// delivery grammar's typed refusals; any other unknown word gets the one
/// pedagogical "unknown runtime" message.
fn parse_runtime_word(word: &str) -> Result<Runtime, CliError> {
    crate::delivery::parse_runtime_word(word)
        .map_err(|err| crate::cli_args::delivery_usage("init", &err))?
        .ok_or_else(|| {
            CliError::Usage(text::msg::init_unknown_runtime(
                &word,
                &Runtime::Client.word().unwrap_or_default(),
            ))
        })
}

/// TTY wizard: prompt the user for shape and (for web) runtime+host.
///
/// Returns the selected [`InitShape`]. The wizard is only called when stdin
/// and stdout are both TTYs and `--shape` was not passed.
fn wizard_shape() -> Result<InitShape, CliError> {
    crate::screen::prompt(
        "What kind of program is this?\n\
             \n\
             [1] web    — browser / desktop / mobile app  (default)\n\
             [2] tui    — terminal UI with cells\n\
             [3] cli    — command-line program with text output\n\
             [4] worker — view-less TEA loop (init/update/subscriptions)\n\
             [5] server — HTTP server\n\
             [6] script — plain task, no rendering\n\
             \n\
             Shape [1]: ",
    );
    let _ = std::io::stdout().flush();
    let line = read_line_trimmed();
    let shape = match line.as_deref().unwrap_or("") {
        "" | "1" | "web" => InitShape::Web,
        "2" | "tui" => InitShape::Tui,
        "3" | "cli" => InitShape::Cli,
        "4" | "worker" => InitShape::Worker,
        "5" | "server" => InitShape::Server,
        "6" | "script" => InitShape::Script,
        other => {
            return Err(CliError::Usage(text::msg::init_unknown_shape_choice(
                &other,
            )));
        }
    };
    Ok(shape)
}

/// The wizard's description of one runtime choice.
const fn runtime_choice_blurb(runtime: Runtime) -> &'static str {
    match runtime {
        Runtime::Served => "a co-located server loop, streamed to the browser  (default)",
        Runtime::Client => "a self-contained client, wasm in the browser",
    }
}

/// TTY wizard: prompt for the `web` runtime (served vs client). Only called for
/// the web shape when the runtime positional was omitted on a TTY.
fn wizard_runtime() -> Result<Runtime, CliError> {
    let mut menu = String::from("How does this web app run?\n\n");
    for (index, runtime) in Runtime::ALL.into_iter().enumerate() {
        let _ = writeln!(
            menu,
            "[{}] {:<6} — {}",
            index.saturating_add(1),
            runtime_label(runtime),
            runtime_choice_blurb(runtime)
        );
    }
    menu.push_str("\nRuntime [1]: ");
    crate::screen::prompt(&menu);
    let _ = std::io::stdout().flush();
    let line = read_line_trimmed();
    runtime_choice(line.as_deref().unwrap_or(""))
}

/// Read a wizard runtime answer: Enter for served, a menu index into
/// [`Runtime::ALL`], or a runtime word read exactly as the delivery grammar
/// reads it.
fn runtime_choice(answer: &str) -> Result<Runtime, CliError> {
    if answer.is_empty() {
        return Ok(Runtime::Served);
    }
    if let Some(runtime) = answer
        .parse::<usize>()
        .ok()
        .and_then(|index| index.checked_sub(1))
        .and_then(|index| Runtime::ALL.get(index).copied())
    {
        return Ok(runtime);
    }
    crate::delivery::parse_runtime_word(answer)
        .map_err(|err| crate::cli_args::delivery_usage("init", &err))?
        .ok_or_else(|| {
            CliError::Usage(text::msg::init_unknown_runtime_choice(
                &answer,
                &Runtime::Client.word().unwrap_or_default(),
            ))
        })
}

/// Read one line from stdin, its terminator removed, or `None` on EOF, a read
/// error, or a line over the answer cap or not UTF-8.
fn read_line_trimmed() -> Option<String> {
    match crate::prompt_reply::read_stdin_reply() {
        crate::prompt_reply::Reply::Line(line) => Some(line),
        crate::prompt_reply::Reply::Ended | crate::prompt_reply::Reply::Refused(_) => None,
    }
}

// ── scaffold helpers ─────────────────────────────────────────────────────────

/// What is being scaffolded: a library has no app shape or runtime to report.
#[derive(Clone, Copy)]
enum ScaffoldKind {
    Library,
    App { shape: InitShape, runtime: Runtime },
}

/// Run the scaffold: fresh → write all; existing → reconcile.
fn run_scaffold(
    target_arg: &str,
    target_dir: &Path,
    project_name: &str,
    files: &[ManagedFile],
    force: bool,
    kind: ScaffoldKind,
) -> Result<(), CliError> {
    let root = hold_target(target_dir)?;
    if is_fresh_target(&root)? || force {
        scaffold(&root, files, force)?;
        let terminal = Interactive::detect();
        let interactive = should_offer_health_check(terminal.is_some(), force);
        match kind {
            ScaffoldKind::Library => print_next_steps_lib(target_arg, project_name),
            ScaffoldKind::App { shape, runtime } => {
                print_next_steps(target_arg, project_name, interactive, shape, runtime);
            }
        }
        if interactive
            && terminal
                .as_ref()
                .is_some_and(|tty| tty.ask_yes_no("Verify your toolchain now?", true))
        {
            let _ = health::run_health_inline();
        }
    } else {
        reconcile_existing(&root, files)?;
    }
    Ok(())
}

/// The complete set of files `init` writes for an application project.
///
/// `shape` selects which `Main.ipe`, `package.ipe`, and `README.md` wording are
/// scaffolded; `runtime` fills the web `package.ipe`'s delivery set (`client`
/// declares an explicit `ships`, `served` stays the implicit default) and picks
/// `README.md`'s open-hint wording. `.gitignore` and `AGENTS.md` are the only
/// shape-independent files.
fn managed_files(project_name: &str, shape: InitShape, runtime: Runtime) -> Vec<ManagedFile> {
    vec![
        ManagedFile::source(
            ManagedDir::Root,
            "package.ipe",
            fill_package(shape.package_ipe(), project_name, runtime),
        ),
        ManagedFile::source(ManagedDir::Src, "Main.ipe", shape.main_ipe().to_owned()),
        ManagedFile::source(
            ManagedDir::Root,
            "README.md",
            README_MD
                .replace("{name}", project_name)
                .replace("{description}", shape.readme_description(runtime))
                .replace("{run_command}", &shape.next_step_command(runtime))
                .replace("{run_hint}", shape.open_hint(runtime)),
        ),
        ManagedFile::source(ManagedDir::Root, ".gitignore", GITIGNORE.to_owned()),
        ManagedFile::guide(),
    ]
}

/// The complete set of files `ipe init --lib` writes.
fn library_files(project_name: &str) -> Vec<ManagedFile> {
    let module = module_name_for(project_name);
    // `{module}` is a derived single-segment module name (ASCII-alphanumeric by
    // construction, hence literal-safe); only the raw `{name}` needs escaping,
    // and only where it lands in a quoted `.ipe` literal.
    //
    // `{module}` is a template placeholder substituted by `.replace`, not a
    // `format!` argument — the formatting-args lint's heuristic misreads it.
    #[allow(clippy::literal_string_with_formatting_args)]
    let fill_ipe = |template: &str| fill_name(template, project_name).replace("{module}", &module);
    #[allow(clippy::literal_string_with_formatting_args)]
    let fill_markdown = |template: &str| {
        template
            .replace("{name}", project_name)
            .replace("{module}", &module)
    };
    vec![
        ManagedFile::source(ManagedDir::Root, "package.ipe", fill_ipe(PACKAGE_LIB_IPE)),
        ManagedFile::source(ManagedDir::Src, format!("{module}.ipe"), fill_ipe(LIB_IPE)),
        ManagedFile::source(ManagedDir::Root, "README.md", fill_markdown(README_LIB_MD)),
        ManagedFile::source(ManagedDir::Root, ".gitignore", GITIGNORE.to_owned()),
        ManagedFile::guide(),
    ]
}

/// Derive a valid single-segment Ipê module name from a project name.
fn module_name_for(project_name: &str) -> String {
    let mut out = String::new();
    for word in project_name.split(|c: char| !c.is_ascii_alphanumeric()) {
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.extend(chars);
        }
    }
    match out.chars().next() {
        Some(c) if c.is_ascii_uppercase() => out,
        _ => "Lib".to_owned(),
    }
}

/// Create the target directory the user named, then hold it.
///
/// # Errors
/// [`CliError::Io`] when it cannot be created or opened.
fn hold_target(target_dir: &Path) -> Result<HeldDir, CliError> {
    std::fs::create_dir_all(target_dir).map_err(|source| CliError::Io {
        path: target_dir.to_path_buf(),
        source,
    })?;
    HeldDir::open_following(target_dir)?.ok_or_else(|| CliError::Io {
        path: target_dir.to_path_buf(),
        source: std::io::ErrorKind::NotFound.into(),
    })
}

/// Whether the held target holds none of `init`'s footprint: no entry at a
/// manifest name (`package.ipe` or a legacy `ipe.toml`, a link included) and
/// no non-empty `src/`.
///
/// # Errors
/// A `src` that is a link or not a directory, or a failed listing.
fn is_fresh_target(root: &HeldDir) -> Result<bool, CliError> {
    for manifest in ["package.ipe", "ipe.toml"] {
        let name = root.entry(OsStr::new(manifest))?;
        if root.kind_of(&name)? != EntryKind::Absent {
            return Ok(false);
        }
    }
    root.child(OsStr::new(SRC_DIR))?
        .map_or(Ok(true), |src| src.is_empty())
}

/// Reconcile an already-populated target against the managed set, one file at
/// a time. Interactive runs ask per file; non-interactive runs write only
/// missing files and report the existing ones left untouched.
fn reconcile_existing(root: &HeldDir, files: &[ManagedFile]) -> Result<(), CliError> {
    let terminal = Interactive::detect();
    let (existing, missing) = terminal.as_ref().map_or(
        (Existing::Keep(KeepWhy::NoTerminal), Missing::Write),
        |tty| (Existing::Ask(tty), Missing::Ask(tty)),
    );
    let placed = place_all(root, files, existing, missing)?;
    let body = placed_report(&placed, true);
    let body = if body.is_empty() {
        format!("{}\n", text::init_nothing_to_do())
    } else {
        body
    };
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(crate::screen::Tone::Text, &body)
        .emit();
    Ok(())
}

/// Place every managed file under one policy, in order.
///
/// `src` is opened, or created, once before any file is placed.
///
/// # Errors
/// A `src` that is a link or not a directory stops the run before any write;
/// otherwise as [`place_managed`].
fn place_all<'f>(
    root: &HeldDir,
    files: &'f [ManagedFile],
    existing: Existing<'_>,
    missing: Missing<'_>,
) -> Result<Vec<(&'f ManagedFile, Placed)>, CliError> {
    let (src, _) = root.create_child(OsStr::new(SRC_DIR))?;
    files
        .iter()
        .map(|file| {
            let dir = match file.dir {
                ManagedDir::Root => root,
                ManagedDir::Src => &src,
            };
            place_managed(dir, file, existing, missing).map(|placed| (file, placed))
        })
        .collect()
}

/// Write the file's content to the staged file and sync it.
fn fill_with(file: &mut std::fs::File, content: &str) -> std::io::Result<()> {
    file.write_all(content.as_bytes())?;
    file.sync_all()
}

/// Place one managed file in the held `dir` under the given policy.
///
/// The existing entry is read once, never through a link, under the file's
/// cap; an entry that cannot be read is kept, never asked about and never
/// written. A replace backs up and replaces only the entry that was read,
/// still holding the bytes read, so the file a question names is the file
/// written.
///
/// # Errors
/// [`CliError::Io`] or [`CliError::OutputRefused`] when the create or the
/// replace fails.
fn place_managed(
    dir: &HeldDir,
    file: &ManagedFile,
    existing: Existing<'_>,
    missing: Missing<'_>,
) -> Result<Placed, CliError> {
    let name = dir.entry(OsStr::new(&file.name))?;
    match dir.read_file_capped_identified(&name, file.cap) {
        Err(err) => match read_miss(&err) {
            ReadMiss::Unread(unread) => Ok(Placed::Kept(Kept::Unread(unread))),
            ReadMiss::Absent => {
                let write = match missing {
                    Missing::Write => true,
                    Missing::Ask(tty) => tty.ask_yes_no(
                        text::msg::init_restore_ask(&file.rel().display()).as_str(),
                        true,
                    ),
                };
                if write {
                    create_managed(dir, file)
                } else {
                    Ok(Placed::Kept(Kept::Declined))
                }
            }
        },
        Ok((bytes, id)) => {
            let replace = match existing {
                Existing::Force => true,
                Existing::Keep(why) => return Ok(Placed::Kept(Kept::Policy(why))),
                Existing::Ask(tty) => tty.ask_yes_no(
                    text::msg::init_overwrite_ask(&file.rel().display()).as_str(),
                    false,
                ),
            };
            if !replace {
                return Ok(Placed::Kept(Kept::Declined));
            }
            let write_content = |staged: &mut std::fs::File| fill_with(staged, &file.content);
            match dir.replace_backed_up(name.as_os_str(), id, &bytes, file.cap, write_content)? {
                BackedUp::Done(backup) => Ok(Placed::Replaced(backup)),
                BackedUp::Changed => Ok(Placed::Kept(Kept::Changed)),
                BackedUp::BackupSlotsFull => Ok(Placed::Kept(Kept::BackupSlotsFull)),
            }
        }
    }
}

/// Create an absent managed file; an entry that took its name first is kept.
///
/// # Errors
/// [`CliError::Io`] or [`CliError::OutputRefused`] when the create fails.
fn create_managed(dir: &HeldDir, file: &ManagedFile) -> Result<Placed, CliError> {
    let write_content = |staged: &mut std::fs::File| fill_with(staged, &file.content);
    match dir.create_if_absent(OsStr::new(&file.name), write_content)? {
        Created::Done => Ok(Placed::Created),
        Created::Exists => Ok(Placed::Kept(Kept::Appeared)),
    }
}

/// The report line for one placed file, or none for a silent creation.
fn placed_line(
    file: &ManagedFile,
    placed: &Placed,
    announce_created: bool,
) -> Option<text::Message> {
    let rel = file.rel();
    let shown = rel.display();
    let beside = |entry: &dyn std::fmt::Display| {
        rel.parent()
            .unwrap_or_else(|| Path::new(""))
            .join(entry.to_string())
    };
    Some(match placed {
        Placed::Created if announce_created => text::msg::init_restored(&shown),
        Placed::Created => return None,
        Placed::Replaced(backup) => text::msg::init_backed_up(&shown, &beside(backup).display()),
        Placed::Kept(Kept::Declined | Kept::Policy(KeepWhy::NotForced)) => {
            text::msg::init_kept_unchanged(&shown)
        }
        Placed::Kept(Kept::Policy(KeepWhy::NoTerminal)) => text::msg::init_kept_no_tty(&shown),
        Placed::Kept(Kept::Unread(unread)) => {
            text::msg::init_kept_unread(&shown, &unread.phrase(file.cap))
        }
        Placed::Kept(Kept::Appeared) => text::msg::init_kept_appeared(&shown),
        Placed::Kept(Kept::Changed) => text::msg::init_kept_changed(&shown),
        Placed::Kept(Kept::BackupSlotsFull) => {
            text::msg::init_kept_backups_full(&shown, &beside(&crate::driver::BACKUP_DIR).display())
        }
    })
}

/// The report for a placement run, one line per reported file.
fn placed_report(placed: &[(&ManagedFile, Placed)], announce_created: bool) -> String {
    let mut body = String::new();
    for (file, outcome) in placed {
        if let Some(line) = placed_line(file, outcome, announce_created) {
            let _ = writeln!(body, "{}", line.as_str());
        }
    }
    body
}

/// Derive the project name from the last path component of the resolved target.
fn project_name_for(target_dir: &Path) -> Result<String, CliError> {
    let absolute = if target_dir.is_absolute() {
        target_dir.to_path_buf()
    } else {
        let cwd = std::env::current_dir().map_err(|e| CliError::Io {
            path: PathBuf::from("."),
            source: e,
        })?;
        cwd.join(target_dir)
    };
    let name = absolute
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned)
        .ok_or_else(|| CliError::Usage(text::msg::init_no_project_name(&target_dir.display())))?;
    Ok(name)
}

/// Write every managed file into a fresh (or `--force`d) target.
///
/// A file that already exists is never silently replaced: without `--force` it
/// is kept as it is (a fresh target can still hold, say, a README), and with
/// `--force` the original is backed up before it is replaced.
fn scaffold(root: &HeldDir, files: &[ManagedFile], force: bool) -> Result<(), CliError> {
    let existing = if force {
        Existing::Force
    } else {
        Existing::Keep(KeepWhy::NotForced)
    };
    let placed = place_all(root, files, existing, Missing::Write)?;
    let body = placed_report(&placed, false);
    if !body.is_empty() {
        crate::screen::Screen::new(crate::screen::Stream::Stdout)
            .line(crate::screen::Tone::Text, &body)
            .emit();
    }
    Ok(())
}

/// Whether to offer the interactive `ipe health` check after scaffolding.
const fn should_offer_health_check(is_tty: bool, force: bool) -> bool {
    is_tty && !force
}

/// The next-steps message for a freshly scaffolded application.
fn next_steps_body(
    target_arg: &str,
    project_name: &str,
    interactive: bool,
    shape: InitShape,
    runtime: Runtime,
) -> String {
    let command = shape.next_step_command(runtime);
    let run_cmd = if target_arg == "." {
        format!("    {command}")
    } else {
        format!("    cd {target_arg} && {command}")
    };
    let health_tip = if interactive {
        String::new()
    } else {
        "\nTip: run  ipe health  to tune your toolchain for faster builds.".to_owned()
    };
    let open_hint = shape.open_hint(runtime);
    let guide = guide_pointer();
    let guide = guide.as_str();
    format!(
        "Created Ipê project `{project_name}`.\n\
         \n\
         Next steps:\n\
         {run_cmd}\n\
         \n\
         {open_hint}\
         {health_tip}\n\
         \n\
         {guide}\n"
    )
}

/// The line pointing coding agents at the authoring guide.
fn guide_pointer() -> text::Message {
    text::msg::init_guide_pointer(&crate::agents_guide::GUIDE_TERM)
}

/// Print the friendly next-steps message, tuned to the resolved shape (and, for
/// `web`, its runtime) so the hint matches how the scaffolded app actually runs.
fn print_next_steps(
    target_arg: &str,
    project_name: &str,
    interactive: bool,
    shape: InitShape,
    runtime: Runtime,
) {
    let body = next_steps_body(target_arg, project_name, interactive, shape, runtime);
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(crate::screen::Tone::Text, &body)
        .emit();
}

/// Print the next-steps message for a freshly scaffolded library.
fn print_next_steps_lib(target_arg: &str, project_name: &str) {
    let body = next_steps_lib_body(target_arg, project_name);
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(crate::screen::Tone::Text, &body)
        .emit();
}

/// The next-steps message for a freshly scaffolded library.
fn next_steps_lib_body(target_arg: &str, project_name: &str) -> String {
    let build_cmd = if target_arg == "." {
        "    ipe dev build".to_owned()
    } else {
        format!("    cd {target_arg} && ipe dev build")
    };
    format!(
        "Created Ipê library `{project_name}`.\n\
         \n\
         Next steps:\n\
         {build_cmd}\n\
         \n\
         Add public modules under src/ and list each in package.ipe's exposedModules.\n\
         \n\
         {guide}\n",
        guide = guide_pointer().as_str()
    )
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: write a minimal src/Main.ipe so the manifest reader's src-root check passes.
    fn write_stub_src(root: &Path) {
        let src = root.join("src");
        std::fs::create_dir_all(&src).expect("create src/");
        std::fs::write(
            src.join("Main.ipe"),
            "module Main exposing (main)\nmain = 0\n",
        )
        .expect("write Main.ipe");
    }

    // Every `.ipe` file `ipe init` writes is an `ipe fmt` fixed point:
    // `ipe verify` opens with `ipe fmt --check`, so a scaffold the formatter
    // would rewrite fails verification before its author touches it. Each shape,
    // runtime and the library scaffold renders through the same file builders
    // `init` writes from, and each `.ipe` file is compared with the formatter's
    // output, so a template edit or a formatter change that splits the two fails.

    /// Project names reaching every hole fill.
    ///
    /// A plain name, one long enough to push the desktop title line past the
    /// formatter's width, and names whose quote, backslash and non-ASCII letter the
    /// literal escapes or the module name drops.
    const FMT_SCAFFOLD_NAMES: [&str; 4] = [
        "demo-app",
        "a-project-name-long-enough-to-push-the-desktop-title-line-past-eighty-columns",
        "we\"ird\\name",
        "café",
    ];

    /// Whether `file` is one `ipe fmt` reads.
    fn is_ipe(file: &ManagedFile) -> bool {
        file.rel().extension().is_some_and(|ext| ext == "ipe")
    }

    /// Each `.ipe` file among `files` that is not its own formatted form, labelled
    /// with `context`.
    fn unformatted(context: &str, files: &[ManagedFile]) -> Vec<String> {
        files
            .iter()
            .filter(|file| is_ipe(file))
            .filter_map(|file| {
                let rel = file.rel();
                let rel = rel.display();
                match crate::fmt::format_source(&file.content) {
                    Ok(formatted) if formatted == file.content => None,
                    Ok(formatted) => Some(format!(
                        "{context} {rel}: `ipe fmt` rewrites it to:\n{formatted}"
                    )),
                    Err(e) => Some(format!("{context} {rel}: `ipe fmt` refuses it: {e:?}")),
                }
            })
            .collect()
    }

    /// Assert `files` holds exactly the manifest and one `src` module.
    ///
    /// This keeps the fixed-point check from passing over a set it never read.
    fn assert_two_ipe_files(context: &str, files: &[ManagedFile]) {
        let ipe: Vec<PathBuf> = files
            .iter()
            .filter(|file| is_ipe(file))
            .map(ManagedFile::rel)
            .collect();
        assert!(
            matches!(ipe.as_slice(), [manifest, module]
                if manifest == Path::new("package.ipe") && module.starts_with("src")),
            "{context}: expected package.ipe and one src module, got {ipe:?}"
        );
    }

    #[test]
    fn every_scaffolded_ipe_file_is_a_fmt_fixed_point() {
        let mut failures = Vec::new();
        for name in FMT_SCAFFOLD_NAMES {
            for shape in InitShape::ALL {
                for runtime in Runtime::ALL {
                    let context = format!("{shape:?}/{runtime:?} `{name}`");
                    let files = managed_files(name, shape, runtime);
                    assert_two_ipe_files(&context, &files);
                    failures.extend(unformatted(&context, &files));
                }
            }
            let context = format!("--lib `{name}`");
            let files = library_files(name);
            assert_two_ipe_files(&context, &files);
            failures.extend(unformatted(&context, &files));
        }
        assert!(
            failures.is_empty(),
            "scaffolded files `ipe fmt --check` rejects:\n\n{}",
            failures.join("\n\n")
        );
    }

    #[test]
    fn an_unformatted_scaffold_file_is_reported() {
        let files = [ManagedFile::source(
            ManagedDir::Src,
            "Main.ipe",
            "module Main exposing (main)\n\nimport Ipe.Task as Task\nimport Ipe.Io as Io\n\n\nmain : Task Error ()\nmain =\n    Io.println \"Hello, world!\"\n".to_owned(),
        )];
        assert_eq!(unformatted("refusal", &files).len(), 1);
    }

    #[test]
    fn a_scaffold_file_fmt_refuses_is_reported() {
        let files = [ManagedFile::source(
            ManagedDir::Root,
            "package.ipe",
            "module Package exposing (package)\n\npackage =\n    {\n".to_owned(),
        )];
        assert_eq!(unformatted("refusal", &files).len(), 1);
    }

    #[test]
    fn scaffolded_web_manifest_is_package_ipe_that_re_parses() {
        let files = managed_files("demo-app", InitShape::Web, Runtime::Served);
        let manifest = files
            .iter()
            .find(|f| f.rel() == Path::new("package.ipe"))
            .expect("init writes a package.ipe");

        let root = ipe_test_temp::temp_root().join("ipe_init_web_roundtrip");
        let _ = std::fs::remove_dir_all(&root);
        write_stub_src(&root);
        let path = root.join("package.ipe");
        std::fs::write(&path, &manifest.content).expect("write scaffolded package.ipe");

        let parsed = crate::project::parse_manifest(&path).expect("scaffolded manifest re-parses");
        assert_eq!(parsed.name, "demo-app");
        assert_eq!(parsed.delivery.desktop.width, 1024);
        assert_eq!(parsed.delivery.desktop.height, 768);
        assert_eq!(
            parsed.delivery.browser.base,
            ipe_runtime_rust::encoding::MountBase::root()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn client_runtime_scaffolds_an_explicit_client_ships_set() {
        let files = managed_files("client-app", InitShape::Web, Runtime::Client);
        let manifest = files
            .iter()
            .find(|f| f.rel() == Path::new("package.ipe"))
            .expect("init writes a package.ipe");

        let root = ipe_test_temp::temp_root().join("ipe_init_client_ships");
        let _ = std::fs::remove_dir_all(&root);
        write_stub_src(&root);
        let path = root.join("package.ipe");
        std::fs::write(&path, &manifest.content).expect("write scaffolded package.ipe");

        let parsed =
            crate::project::parse_manifest(&path).expect("scaffolded client manifest re-parses");
        assert_eq!(
            parsed.delivery.ships_for_render(),
            [ShipEntry::Client],
            "a wizard `web client` choice writes an explicit `ships = [ client ]`"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Every web runtime `init` scaffolds builds for every host its runtime
    /// carries: the scaffolded manifest passes the target derivation `dev
    /// build` and `release build` run, and for a mobile host the packager's
    /// admission gate too. A `web client` scaffold writes no `wasm` field, and
    /// its mobile build is admitted all the same.
    #[test]
    fn every_web_scaffold_is_admitted_on_each_of_its_hosts() {
        use crate::delivery::{Delivery, Host, Shape, TargetTriple};
        use crate::driver::{TargetVerb, derive_target, validate_mobile_pack};
        for runtime in Runtime::ALL {
            let label = format!("ipe_init_admitted_{}", runtime_label(runtime));
            let files = managed_files("admitted-app", InitShape::Web, runtime);
            let manifest = files
                .iter()
                .find(|f| f.rel() == Path::new("package.ipe"))
                .expect("init writes a package.ipe");
            let root = ipe_test_temp::temp_root().join(&label);
            let _ = std::fs::remove_dir_all(&root);
            write_stub_src(&root);
            let path = root.join("package.ipe");
            std::fs::write(&path, &manifest.content).expect("write scaffolded package.ipe");
            let parsed = crate::project::parse_manifest(&path);
            let _ = std::fs::remove_dir_all(&root);
            let parsed = parsed.expect("scaffolded manifest re-parses");
            let wasm_block = parsed.wasm.implies_wasm_target();
            let mut admitted_hosts = 0_usize;
            for host in [Host::Default, Host::Desktop, Host::Ios, Host::Android] {
                let Ok(delivery) = Delivery::resolve(Shape::Web, Some(runtime), host) else {
                    continue;
                };
                admitted_hosts += 1;
                for verb in [TargetVerb::Dev, TargetVerb::Release] {
                    let derived = derive_target(verb, delivery, None, None, wasm_block);
                    assert!(
                        derived.is_ok(),
                        "{label}: {delivery} derives a target under {verb:?}: {derived:?}"
                    );
                    assert_eq!(
                        derived.ok().flatten() == Some(TargetTriple::BrowserWasm),
                        runtime == Runtime::Client,
                        "{label}: {delivery} derives the browser triple iff it is a client"
                    );
                }
                if matches!(host, Host::Ios | Host::Android) {
                    let gated = validate_mobile_pack(&parsed, Shape::Web);
                    assert!(
                        gated.is_ok(),
                        "{label}: the mobile packager admits the {delivery} scaffold: {gated:?}"
                    );
                }
            }
            assert!(admitted_hosts > 0, "{label}: some host carries the runtime");
        }
    }

    /// The runtimes `init` scaffolds `shape` for: both for `web`, served otherwise.
    fn scaffolded_runtimes(shape: InitShape) -> Vec<Runtime> {
        if shape.has_runtime_choice() {
            Runtime::ALL.to_vec()
        } else {
            vec![Runtime::Served]
        }
    }

    /// The delivery shape the build pins for the `src/Main.ipe` an init `shape`
    /// scaffolds, read by the same strict classifier the build keys on.
    fn pinned_shape(shape: InitShape, runtime: Runtime) -> crate::delivery::Shape {
        let files = managed_files("swept-app", shape, runtime);
        let main = files
            .iter()
            .find(|f| f.rel() == Path::new("src").join("Main.ipe"))
            .expect("init writes a src/Main.ipe");
        let mut interner = ipe_intern::Interner::new();
        let module =
            ipe_parse::parse_module(&main.content, &mut interner).expect("scaffold parses");
        crate::delivery::Shape::from_main(ipe_canon::shape_source::classify_main_shape(
            &module, &interner,
        ))
    }

    /// The scaffold's `package.ipe`, read back by the real manifest reader.
    fn scaffolded_manifest(
        tag: &str,
        shape: InitShape,
        runtime: Runtime,
    ) -> Result<crate::project::ProjectManifest, CliError> {
        let files = managed_files("swept-app", shape, runtime);
        let manifest = files
            .iter()
            .find(|f| f.rel() == Path::new("package.ipe"))
            .expect("init writes a package.ipe");
        let root = ipe_test_temp::temp_root().join(format!(
            "ipe_init_{tag}_{}_{}",
            shape.label(),
            runtime_label(runtime)
        ));
        let _ = std::fs::remove_dir_all(&root);
        write_stub_src(&root);
        let path = root.join("package.ipe");
        std::fs::write(&path, &manifest.content).expect("write scaffolded package.ipe");
        let parsed = crate::project::parse_manifest(&path);
        let _ = std::fs::remove_dir_all(&root);
        parsed
    }

    /// Every shape `init` scaffolds, under every runtime it offers, writes a
    /// manifest the real reader accepts and whose `ships` set the build's
    /// delivery-set resolver admits, so no scaffold names a builder the build
    /// refuses.
    #[test]
    fn every_init_shape_scaffolds_a_delivery_set_the_build_admits() {
        for shape in InitShape::ALL {
            for runtime in scaffolded_runtimes(shape) {
                let label = format!("{} {}", shape.label(), runtime_label(runtime));
                let parsed = scaffolded_manifest("admits", shape, runtime);
                assert!(parsed.is_ok(), "{label}: manifest re-parses: {parsed:?}");
                let Ok(parsed) = parsed else { continue };
                let set = parsed.delivery.declared(pinned_shape(shape, runtime));
                assert!(
                    set.is_ok(),
                    "{label}: the build admits the ships set: {set:?}"
                );
            }
        }
    }

    /// The command a scaffold's next steps and README advise builds exactly the
    /// delivery its manifest declares: it is always `dev run` (a `web client`
    /// is served, every other delivery executed), and, parsed by `dev run`'s
    /// own argument parser and resolved by the build's delivery resolver, it
    /// names the one declared delivery.
    #[test]
    fn the_advised_next_step_builds_the_declared_delivery() {
        use crate::delivery::TargetTriple;
        use crate::driver::{ADMIT_ANY, TargetVerb, derive_target, resolve_delivery};
        for shape in InitShape::ALL {
            for runtime in scaffolded_runtimes(shape) {
                let label = format!("{} {}", shape.label(), runtime_label(runtime));
                let pinned = pinned_shape(shape, runtime);
                let parsed =
                    scaffolded_manifest("advice", shape, runtime).expect("manifest re-parses");
                let declared_set = parsed
                    .delivery
                    .declared(pinned)
                    .expect("the build admits the ships set");
                assert_eq!(
                    declared_set.set().len(),
                    1,
                    "{label}: one declared delivery"
                );
                let declared = declared_set.set().head().delivery();

                let command = shape.next_step_command(runtime);
                let rest = command.strip_prefix("ipe ").unwrap_or_default();
                let tail = rest
                    .strip_prefix(Verb::DEV_RUN.name())
                    .expect("the advised command is `ipe dev run`");
                let args: Vec<String> = tail.split_whitespace().map(str::to_owned).collect();
                let positionals = crate::cli_args::parse_run(&args)
                    .map(|a| a.delivery)
                    .expect("`dev run`'s parser reads the command");
                let advised = resolve_delivery(
                    &declared_set,
                    &positionals,
                    None,
                    false,
                    Verb::DEV_RUN.name(),
                    ADMIT_ANY,
                )
                .expect("the advised delivery resolves");
                assert_eq!(
                    advised, declared,
                    "{label}: `{command}` builds the declared delivery"
                );

                let derived = derive_target(TargetVerb::Dev, advised, None, None, false)
                    .expect("the advised delivery derives a dev target");
                assert!(
                    !derived.is_some_and(TargetTriple::is_wasm)
                        || advised == Delivery::web_client(),
                    "{label}: `{command}` runs a delivery `dev run` executes or serves"
                );

                let readme = managed_files("swept-app", shape, runtime)
                    .into_iter()
                    .find(|f| f.rel() == Path::new("README.md"))
                    .expect("init writes a README.md");
                assert!(
                    readme.content.contains(&format!("\n{command}\n")),
                    "{label}: the README advises `{command}`"
                );
            }
        }
    }

    #[test]
    fn served_runtime_leaves_the_delivery_set_implicit() {
        // The default `served` runtime keeps the manifest minimal: no `ships`
        // field, which reads back as the implicit `[ binary ]` singleton.
        let files = managed_files("served-app", InitShape::Web, Runtime::Served);
        let manifest = files
            .iter()
            .find(|f| f.rel() == Path::new("package.ipe"))
            .expect("init writes a package.ipe");
        assert!(
            !manifest.content.contains("ships"),
            "a `served` web project declares no explicit ships set"
        );

        let root = ipe_test_temp::temp_root().join("ipe_init_served_ships");
        let _ = std::fs::remove_dir_all(&root);
        write_stub_src(&root);
        let path = root.join("package.ipe");
        std::fs::write(&path, &manifest.content).expect("write scaffolded package.ipe");
        let parsed =
            crate::project::parse_manifest(&path).expect("scaffolded served manifest re-parses");
        assert!(
            parsed.delivery.ships_for_render().is_empty(),
            "an absent ships field is the implicit default"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn non_web_shape_never_carries_a_ships_hole() {
        // Non-web templates have no `{ships}` hole; the runtime fill is a no-op
        // and no stray placeholder survives regardless of the runtime passed.
        for shape in [
            InitShape::Tui,
            InitShape::Cli,
            InitShape::Worker,
            InitShape::Server,
            InitShape::Script,
        ] {
            let files = managed_files("proj", shape, Runtime::Client);
            let manifest = files
                .iter()
                .find(|f| f.rel() == Path::new("package.ipe"))
                .expect("package.ipe present");
            assert!(
                !manifest.content.contains("{ships}"),
                "shape `{}` left an unfilled ships hole",
                shape.label()
            );
            assert!(
                !manifest.content.contains("ships"),
                "shape `{}` scaffolded a ships set it does not support",
                shape.label()
            );
        }
    }

    #[test]
    fn scaffolded_tui_manifest_re_parses() {
        let files = managed_files("tui-app", InitShape::Tui, Runtime::Served);
        let manifest = files
            .iter()
            .find(|f| f.rel() == Path::new("package.ipe"))
            .expect("init writes a package.ipe");

        let root = ipe_test_temp::temp_root().join("ipe_init_tui_roundtrip");
        let _ = std::fs::remove_dir_all(&root);
        write_stub_src(&root);
        let path = root.join("package.ipe");
        std::fs::write(&path, &manifest.content).expect("write scaffolded package.ipe");

        let parsed =
            crate::project::parse_manifest(&path).expect("scaffolded tui manifest re-parses");
        assert_eq!(parsed.name, "tui-app");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scaffolded_script_manifest_re_parses() {
        let files = managed_files("my-script", InitShape::Script, Runtime::Served);
        let manifest = files
            .iter()
            .find(|f| f.rel() == Path::new("package.ipe"))
            .expect("init writes a package.ipe");

        let root = ipe_test_temp::temp_root().join("ipe_init_script_roundtrip");
        let _ = std::fs::remove_dir_all(&root);
        write_stub_src(&root);
        let path = root.join("package.ipe");
        std::fs::write(&path, &manifest.content).expect("write scaffolded package.ipe");

        let parsed =
            crate::project::parse_manifest(&path).expect("scaffolded script manifest re-parses");
        assert_eq!(parsed.name, "my-script");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scaffolded_worker_manifest_re_parses() {
        let files = managed_files("tick-worker", InitShape::Worker, Runtime::Served);
        let manifest = files
            .iter()
            .find(|f| f.rel() == Path::new("package.ipe"))
            .expect("init writes a package.ipe");

        let root = ipe_test_temp::temp_root().join("ipe_init_worker_roundtrip");
        let _ = std::fs::remove_dir_all(&root);
        write_stub_src(&root);
        let path = root.join("package.ipe");
        std::fs::write(&path, &manifest.content).expect("write scaffolded package.ipe");

        let parsed =
            crate::project::parse_manifest(&path).expect("scaffolded worker manifest re-parses");
        assert_eq!(parsed.name, "tick-worker");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn each_shape_scaffolds_a_distinct_main_ipe() {
        let web = managed_files("x", InitShape::Web, Runtime::Served);
        let tui = managed_files("x", InitShape::Tui, Runtime::Served);
        let cli = managed_files("x", InitShape::Cli, Runtime::Served);
        let worker = managed_files("x", InitShape::Worker, Runtime::Served);
        let server = managed_files("x", InitShape::Server, Runtime::Served);
        let script = managed_files("x", InitShape::Script, Runtime::Served);

        let main = |files: &[ManagedFile]| {
            files
                .iter()
                .find(|f| f.rel() == Path::new("src/Main.ipe"))
                .map(|f| f.content.clone())
                .expect("a Main.ipe is scaffolded")
        };

        let web_main = main(&web);
        let tui_main = main(&tui);
        let cli_main = main(&cli);
        let worker_main = main(&worker);
        let server_main = main(&server);
        let script_main = main(&script);

        // Each shape uses a different entry point.
        assert!(
            web_main.contains("Web.tea") || web_main.contains("Web"),
            "web uses Web.tea"
        );
        assert!(
            tui_main.contains("Tui.tea") || tui_main.contains("Tui"),
            "tui uses Tui.tea"
        );
        assert!(
            cli_main.contains("Cli.tea") || cli_main.contains("Cli"),
            "cli uses Cli.tea"
        );
        assert!(worker_main.contains("Worker.tea"), "worker uses Worker.tea");
        assert!(
            server_main.contains("Server.listen"),
            "server uses Server.listen"
        );
        assert!(script_main.contains("Task"), "script uses Task");

        // All six are distinct.
        let mains = [
            &web_main,
            &tui_main,
            &cli_main,
            &worker_main,
            &server_main,
            &script_main,
        ];
        for (i, a) in mains.iter().enumerate() {
            for (j, b) in mains.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "shapes {i} and {j} produce identical Main.ipe");
                }
            }
        }
    }

    #[test]
    fn positional_shape_and_runtime_parse() {
        let a = parse_init_args(&["my-app".to_owned(), "web".to_owned(), "client".to_owned()])
            .expect("web client positionals parse");
        assert_eq!(a.target_arg.as_deref(), Some("my-app"));
        assert_eq!(a.shape, Some(InitShape::Web));
        assert_eq!(a.runtime, Some(Runtime::Client));
    }

    #[test]
    fn bare_shape_positional_defaults_directory() {
        let a = parse_init_args(&["tui".to_owned()]).expect("shape-only");
        // A single non-shape-first positional is the directory; the shape word is
        // the directory when it is first. Here the first positional is a shape
        // word, but init reads the first positional as the directory (like
        // `cargo init tui`), so shape stays None.
        assert_eq!(a.target_arg.as_deref(), Some("tui"));
        assert_eq!(a.shape, None);
    }

    #[test]
    fn runtime_on_non_web_shape_is_refused() {
        let err = parse_init_args(&["app".to_owned(), "tui".to_owned(), "client".to_owned()])
            .expect_err("runtime on a tui project is a conflict");
        let msg = format!("{err:?}");
        assert!(msg.contains("web runtime"), "pedagogical: {msg}");
    }

    #[test]
    fn unknown_shape_positional_is_pedagogical() {
        let err =
            parse_init_args(&["app".to_owned(), "wat".to_owned()]).expect_err("unknown shape word");
        let msg = format!("{err:?}");
        assert!(msg.contains("unknown shape"), "names the problem: {msg}");
    }

    #[test]
    fn shape_positional_and_flag_must_agree() {
        let ok = parse_init_args(&[
            "app".to_owned(),
            "web".to_owned(),
            "--shape".to_owned(),
            "web".to_owned(),
        ])
        .expect("agreeing shape positional + flag");
        assert_eq!(ok.shape, Some(InitShape::Web));

        let err = parse_init_args(&[
            "app".to_owned(),
            "web".to_owned(),
            "--shape".to_owned(),
            "tui".to_owned(),
        ])
        .expect_err("disagreeing shape positional + flag");
        let msg = format!("{err:?}");
        assert!(msg.contains("disagree"), "names the conflict: {msg}");
    }

    #[test]
    fn runtime_word_round_trips() {
        assert_eq!(parse_runtime_word("client").ok(), Some(Runtime::Client));
        for (answer, runtime) in [
            ("", Runtime::Served),
            ("1", Runtime::Served),
            ("2", Runtime::Client),
        ] {
            assert_eq!(
                runtime_choice(answer).ok(),
                Some(runtime),
                "answer `{answer}`"
            );
        }
        assert_eq!(runtime_choice("client").ok(), Some(Runtime::Client));
        let unknown = parse_runtime_word("nope");
        assert!(
            matches!(&unknown, Err(CliError::Usage(m)) if m.contains("unknown runtime `nope`")),
            "{unknown:?}"
        );
        let out_of_range = runtime_choice("3");
        assert!(
            matches!(&out_of_range, Err(CliError::Usage(m)) if m.contains("unknown runtime `3`")),
            "{out_of_range:?}"
        );
    }

    /// Init reads its runtime word exactly as the delivery grammar does: a
    /// retired word and the unnamed default are refused, positional and wizard
    /// alike, with the delivery grammar's own message.
    #[test]
    fn init_refuses_retired_runtime_words() {
        use crate::delivery::{DeliveryError, RetiredRuntimeWord};
        for retired in RetiredRuntimeWord::ALL {
            let expected = DeliveryError::RetiredRuntimeWord { got: retired }.to_string();
            let positional = parse_init_args(&[
                "app".to_owned(),
                "web".to_owned(),
                retired.text().to_owned(),
            ]);
            assert!(
                matches!(&positional, Err(CliError::Usage(m)) if m.contains(&expected)),
                "positional `{}`: {positional:?}",
                retired.text()
            );
            let wizard = runtime_choice(retired.text());
            assert!(
                matches!(&wizard, Err(CliError::Usage(m)) if m.contains(&expected)),
                "wizard `{}`: {wizard:?}",
                retired.text()
            );
        }
        let served = DeliveryError::ServedNotAWord.to_string();
        let positional =
            parse_init_args(&["app".to_owned(), "web".to_owned(), "served".to_owned()]);
        assert!(
            matches!(&positional, Err(CliError::Usage(m)) if m.contains(&served)),
            "positional `served`: {positional:?}"
        );
        let wizard = runtime_choice("served");
        assert!(
            matches!(&wizard, Err(CliError::Usage(m)) if m.contains(&served)),
            "wizard `served`: {wizard:?}"
        );
    }

    #[test]
    fn existing_project_shape_confidently_classifies_a_qualified_head() {
        let root = ipe_test_temp::temp_root().join("ipe_init_existing_shape");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).expect("mkdir src");
        // A qualified `Tui.tea` head pins the tui shape confidently.
        std::fs::write(
            root.join("src").join("Main.ipe"),
            "module Main exposing (main)\n\nmain =\n    Tui.tea config\n",
        )
        .expect("write tui Main.ipe");
        assert_eq!(
            existing_project_shape(&root).expect("classify"),
            Some(InitShape::Tui)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn existing_project_shape_is_ambiguous_for_a_script_or_unpinnable_head() {
        let root = ipe_test_temp::temp_root().join("ipe_init_ambiguous_shape");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).expect("mkdir src");
        // A bare (unqualified) entry head collapses to the ambiguous `Script`
        // fallback, which the guard treats as "not confidently classified".
        std::fs::write(
            root.join("src").join("Main.ipe"),
            "module Main exposing (main)\n\nmain =\n    app config\n",
        )
        .expect("write unpinnable Main.ipe");
        assert_eq!(existing_project_shape(&root).expect("classify"), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A FIFO planted as `src/Main.ipe` is refused at once, never waited on for a writer.
    #[cfg(unix)]
    #[test]
    fn a_fifo_main_ipe_does_not_hang_init() {
        let root = ipe_test_temp::temp_root().join(format!("ipe_init_fifo_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).expect("mkdir src");
        let made = std::process::Command::new("mkfifo")
            .arg(root.join("src").join("Main.ipe"))
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo creates the fixture");
        let (tx, rx) = std::sync::mpsc::channel();
        let reader_root = root.clone();
        std::thread::Builder::new()
            .spawn(move || {
                let _ = tx.send(existing_project_shape(&reader_root));
            })
            .expect("spawn the bounded reader thread");
        let outcome = rx.recv_timeout(std::time::Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            matches!(
                outcome,
                Ok(Err(CliError::SourceRefused {
                    reason: crate::io_bounded::SourceRefusal::NotRegularFile,
                    ..
                }))
            ),
            "a FIFO entry is refused without blocking: {outcome:?}"
        );
    }

    /// An entry one byte past the source cap is refused, never buffered whole.
    #[test]
    fn an_oversized_main_ipe_is_refused_by_init() {
        let root =
            ipe_test_temp::temp_root().join(format!("ipe_init_oversized_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).expect("mkdir src");
        let file = std::fs::File::create(root.join("src").join("Main.ipe")).expect("create entry");
        file.set_len(crate::io_bounded::SOURCE_READ_CAP + 1)
            .expect("size the entry one byte past the cap");
        drop(file);
        let outcome = existing_project_shape(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            matches!(
                outcome,
                Err(CliError::FileTooLarge { max, .. }) if max == crate::io_bounded::SOURCE_READ_CAP
            ),
            "an oversized entry is refused at the source cap: {outcome:?}"
        );
    }

    /// A symlinked `src/Main.ipe` is refused by name, never read through.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_main_ipe_is_refused_by_init() {
        let root = ipe_test_temp::temp_root().join(format!("ipe_init_link_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).expect("mkdir src");
        let target = root.join("elsewhere.ipe");
        std::fs::write(
            &target,
            "module Main exposing (main)\n\nmain =\n    Tui.tea config\n",
        )
        .expect("write target");
        std::os::unix::fs::symlink(&target, root.join("src").join("Main.ipe"))
            .expect("link the entry");
        let outcome = existing_project_shape(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            matches!(
                outcome,
                Err(CliError::SourceRefused {
                    reason: crate::io_bounded::SourceRefusal::Symlink,
                    ..
                })
            ),
            "a symlinked entry is refused: {outcome:?}"
        );
    }

    #[test]
    fn rerun_refuses_a_confidently_conflicting_shape() {
        let root = ipe_test_temp::temp_root().join("ipe_init_rerun_conflict");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).expect("mkdir src");
        // The project confidently pins `tui`; asking to re-init as `web` conflicts.
        std::fs::write(
            root.join("src").join("Main.ipe"),
            "module Main exposing (main)\n\nmain =\n    Tui.tea config\n",
        )
        .expect("write tui Main.ipe");
        let err = guard_rerun_conflict(&root, InitShape::Web, Some(InitShape::Web), None)
            .expect_err("web re-init on a tui project is refused");
        assert!(
            matches!(err, CliError::ProjectRefused(_)),
            "the pinned shape is project state: {err:?}"
        );
        let msg = format!("{err:?}");
        assert!(msg.contains("already holds"), "names the conflict: {msg}");
        // A matching (or absent) stated shape reconciles silently.
        guard_rerun_conflict(&root, InitShape::Tui, Some(InitShape::Tui), None)
            .expect("matching shape reconciles");
        guard_rerun_conflict(&root, InitShape::Web, None, None)
            .expect("absent stated shape reconciles");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rerun_does_not_refuse_an_ambiguous_script_head() {
        let root = ipe_test_temp::temp_root().join("ipe_init_rerun_ambiguous");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).expect("mkdir src");
        // An unqualified head is not confidently classified, so a re-init that
        // states a different shape reconciles rather than falsely refusing.
        std::fs::write(
            root.join("src").join("Main.ipe"),
            "module Main exposing (main)\n\nmain =\n    app config\n",
        )
        .expect("write unpinnable Main.ipe");
        guard_rerun_conflict(&root, InitShape::Web, Some(InitShape::Web), None)
            .expect("an ambiguous head does not trigger a false conflict");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn shape_parse_round_trips() {
        // Driven from `InitShape::ALL` (the SSOT): every listed shape must parse
        // from its own label and label back to the same token.
        for shape in InitShape::ALL {
            let token = shape.label();
            assert_eq!(InitShape::parse(token), Some(shape), "parse {token}");
        }
        assert_eq!(InitShape::parse("unknown"), None, "unknown shape is None");
    }

    #[test]
    fn all_lists_every_variant_in_index_order() {
        // The exhaustiveness guard maps each variant to its `ALL` index; asserting
        // the two agree keeps `ALL` honest. A new variant forces a new guard arm
        // (exhaustive match) and a new `ALL` slot, or this assertion fails.
        for (index, shape) in InitShape::ALL.into_iter().enumerate() {
            assert_eq!(
                shape.exhaustiveness_guard(),
                index,
                "InitShape::ALL is out of sync with the variant order for {}",
                shape.label()
            );
        }
    }

    #[test]
    fn delivery_defaults_in_scaffolded_manifest() {
        let files = managed_files("proj", InitShape::Web, Runtime::Served);
        let manifest = files
            .iter()
            .find(|f| f.rel() == Path::new("package.ipe"))
            .expect("package.ipe present");

        let root = ipe_test_temp::temp_root().join("ipe_init_delivery_defaults");
        let _ = std::fs::remove_dir_all(&root);
        write_stub_src(&root);
        let path = root.join("package.ipe");
        std::fs::write(&path, &manifest.content).unwrap();

        let parsed = crate::project::parse_manifest(&path).expect("re-parses");
        // desktop defaults
        assert_eq!(parsed.delivery.desktop.width, 1024);
        assert_eq!(parsed.delivery.desktop.height, 768);
        assert_eq!(parsed.delivery.desktop.title, "proj");
        // browser default
        assert_eq!(
            parsed.delivery.browser.base,
            ipe_runtime_rust::encoding::MountBase::root()
        );
        // mobile default orientation: free rotation
        assert_eq!(
            parsed.delivery.mobile.orientation,
            crate::project::ScreenOrientation::Any
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn library_scaffold_manifest_declares_exposed_modules_and_re_parses() {
        let files = library_files("my-cool-lib");
        let manifest = files
            .iter()
            .find(|f| f.rel() == Path::new("package.ipe"))
            .expect("init --lib writes a package.ipe");

        assert!(
            files
                .iter()
                .any(|f| f.rel() == Path::new("src").join("MyCoolLib.ipe")),
            "the public module src/MyCoolLib.ipe is scaffolded"
        );
        assert!(
            !files
                .iter()
                .any(|f| f.rel() == Path::new("src").join("Main.ipe")),
            "a library does not scaffold a runnable src/Main.ipe"
        );

        let root = ipe_test_temp::temp_root().join("ipe_init_lib_roundtrip");
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("src");
        std::fs::create_dir_all(&src).expect("create src/");
        let path = root.join("package.ipe");
        std::fs::write(&path, &manifest.content).expect("write scaffolded package.ipe");

        let parsed =
            crate::project::parse_manifest(&path).expect("scaffolded lib manifest re-parses");
        assert_eq!(parsed.name, "my-cool-lib");
        assert_eq!(parsed.exposed_modules, vec!["MyCoolLib".to_owned()]);
        assert!(
            parsed.programs.is_empty(),
            "a library declares no runnable programs"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn module_name_derivation_produces_a_valid_segment() {
        assert_eq!(module_name_for("my-cool-lib"), "MyCoolLib");
        assert_eq!(module_name_for("json"), "Json");
        assert_eq!(module_name_for("ipe_http"), "IpeHttp");
        assert_eq!(module_name_for("Already"), "Already");
        assert_eq!(module_name_for("123"), "Lib");
        assert_eq!(module_name_for("---"), "Lib");
    }

    #[test]
    fn managed_set_omits_legacy_ipe_toml() {
        let files = managed_files("x", InitShape::default(), Runtime::Served);
        assert!(
            !files.iter().any(|f| f.rel() == Path::new("ipe.toml")),
            "init must not scaffold a legacy ipe.toml"
        );
    }

    #[test]
    fn health_offer_requires_tty() {
        assert!(!should_offer_health_check(false, false));
        assert!(!should_offer_health_check(false, true));
    }

    #[test]
    fn health_offer_suppressed_by_force() {
        assert!(!should_offer_health_check(true, true));
    }

    #[test]
    fn health_offer_on_interactive_non_forced() {
        assert!(should_offer_health_check(true, false));
    }

    #[test]
    fn ipe_string_literal_escapes_literal_breaking_characters() {
        assert_eq!(IpeStringLiteral::escaped("plain").as_str(), "plain");
        assert_eq!(
            IpeStringLiteral::escaped("a\"b\\c").as_str(),
            "a\\\"b\\\\c",
            "quote and backslash must be escaped"
        );
        assert_eq!(
            IpeStringLiteral::escaped("line\ntab\tcr\r").as_str(),
            "line\\ntab\\tcr\\r",
            "newline, tab, and carriage return must be escaped"
        );
        assert_eq!(
            IpeStringLiteral::escaped("bell\u{7}here").as_str(),
            "bellhere",
            "other control scalars are dropped (no valid single-line escape)"
        );
    }

    #[test]
    fn scaffolded_manifest_survives_a_hostile_project_name() {
        // A directory named with a quote, backslash, and newline would break out
        // of the quoted `.ipe` literal without escaping. The scaffolded manifest
        // must still re-parse, and the name must round-trip exactly.
        let hostile = "evil\"\\\n }, injected = True { ";
        let files = managed_files(hostile, InitShape::Web, Runtime::Served);
        let manifest = files
            .iter()
            .find(|f| f.rel() == Path::new("package.ipe"))
            .expect("init writes a package.ipe");

        let root = ipe_test_temp::temp_root().join("ipe_init_hostile_name_roundtrip");
        let _ = std::fs::remove_dir_all(&root);
        write_stub_src(&root);
        let path = root.join("package.ipe");
        std::fs::write(&path, &manifest.content).expect("write scaffolded package.ipe");

        let parsed = crate::project::parse_manifest(&path)
            .expect("scaffolded manifest with a hostile name re-parses");
        assert_eq!(
            parsed.name, hostile,
            "the hostile name round-trips through the escaped literal unchanged"
        );
        assert_eq!(
            parsed.delivery.mobile.bundle_id,
            Some(BundleId::derived(hostile)),
            "the scaffolded bundleId is the name's derived id"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scaffolded_bundle_id_is_the_derived_id_and_re_parses() {
        for (index, name) in ["my-app", "9lives", "class", "{bundle_id}", "{ships}"]
            .into_iter()
            .enumerate()
        {
            let files = managed_files(name, InitShape::Web, Runtime::Served);
            let manifest = files
                .iter()
                .find(|f| f.rel() == Path::new("package.ipe"))
                .expect("init writes a package.ipe");

            let root =
                ipe_test_temp::temp_root().join(format!("ipe_init_derived_bundle_id_{index}"));
            let _ = std::fs::remove_dir_all(&root);
            write_stub_src(&root);
            let path = root.join("package.ipe");
            std::fs::write(&path, &manifest.content).expect("write scaffolded package.ipe");

            let parsed = crate::project::parse_manifest(&path)
                .expect("scaffolded manifest re-parses under the bundle-id grammar");
            assert_eq!(parsed.name, name, "a name spelling a hole stays literal");
            assert_eq!(
                parsed.delivery.mobile.bundle_id,
                Some(BundleId::derived(name)),
                "the scaffolded bundleId for `{name}` is its derived id"
            );
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    // Every quit key a shape's hint advertises is one its `Main.ipe` handles:
    // the key maps to `Quit`, and `Quit` ends the program through `System.exit`.
    #[test]
    fn advertised_quit_key_is_handled_by_the_template() {
        for shape in [
            InitShape::Web,
            InitShape::Tui,
            InitShape::Cli,
            InitShape::Worker,
            InitShape::Server,
            InitShape::Script,
        ] {
            let hint = shape.open_hint(Runtime::Served);
            let main = shape.main_ipe();
            let advertises_q = hint.contains("q to quit");
            let handles_q = main.contains("key.value == \"q\" then\n        Quit")
                || main.contains("\"q\" ->\n            Quit");
            let quit_exits =
                main.contains("Quit ->\n            ( model, Cmd.perform (System.exit 0)");
            assert_eq!(
                advertises_q,
                handles_q,
                "shape '{}': the hint's `q` quit and the template's `q` handler must agree",
                shape.label()
            );
            assert!(
                !handles_q || quit_exits,
                "shape '{}': `Quit` must end the program through `System.exit`",
                shape.label()
            );
            for runtime in Runtime::ALL {
                assert_eq!(
                    advertises_q,
                    shape.readme_description(runtime).contains("`q` quits"),
                    "shape '{}' ({runtime:?}): the README must advertise the same quit key as the hint",
                    shape.label()
                );
            }
        }
    }

    #[test]
    fn all_shape_package_templates_contain_name_hole() {
        for shape in [
            InitShape::Web,
            InitShape::Tui,
            InitShape::Cli,
            InitShape::Worker,
            InitShape::Server,
            InitShape::Script,
        ] {
            assert!(
                shape.package_ipe().contains("{name}"),
                "package template for shape '{}' is missing the {{name}} hole",
                shape.label()
            );
            let template = shape.package_ipe();
            // Exhaustive on purpose: a new shape must decide whether it ships a
            // delivery bundle before this test compiles.
            let delivers = match shape {
                InitShape::Web
                | InitShape::Tui
                | InitShape::Cli
                | InitShape::Server
                | InitShape::Script => true,
                InitShape::Worker => false,
            };
            if delivers {
                assert!(
                    template.matches("bundleId").count() == 1
                        && template.contains("bundleId = \"{bundle_id}\", orientation = Any"),
                    "package template for shape '{}' must declare exactly the derived \
                     `{{bundle_id}}` hole with free rotation",
                    shape.label()
                );
            } else {
                assert!(
                    !template.contains("bundleId"),
                    "package template for shape '{}' has no delivery bundle, so it \
                     declares no bundleId",
                    shape.label()
                );
            }
        }
    }

    // ── held writes ──────────────────────────────────────────────────────────

    /// The marker opening this file's test module; the source before it is production.
    const TESTS_MARKER: &str = "#[cfg(test)]\nmod tests {";

    /// Every `fs` path production may name, each at its one site and count:
    /// the target creation, and the staged-file type the held writer hands to
    /// a fill. A site is pinned with its context, so an alias swapped in for
    /// one of them changes a count.
    const ADMITTED_FS: [(&str, usize); 3] = [
        ("std::fs::create_dir_all(target_dir)", 1),
        ("fn fill_with(file: &mut std::fs::File,", 1),
        ("|staged: &mut std::fs::File|", 2),
    ];

    /// The crate paths production may reach other filesystem helpers through,
    /// each with the items it may name and how often: the byte cap, the one
    /// no-follow by-level read of the re-run's `src/Main.ipe`, and the one
    /// hold of the target.
    const ADMITTED_ITEMS: [(&str, &[(&str, usize)]); 3] = [
        ("ipe_fs_open::", &[("ByteCap", 1)]),
        ("io_bounded::", &[("SOURCE_CAP", 4), ("read_named_in", 1)]),
        ("HeldDir::", &[("open_following", 1)]),
    ];

    /// The crate's by-path writers and `std`'s by-path open options, never named in production.
    const PATH_BASED: [&str; 4] = [
        "rewrite_user_file",
        "backup_user_file",
        "write_atomic",
        "OpenOptions",
    ];

    /// Filesystem calls production may not make, in method (`.name(`) or
    /// path (`::name(`) form: every `std::fs` and `Path` entry point that
    /// opens, probes, lists or changes an entry by path.
    const PATH_CALLS: [&str; 21] = [
        "exists",
        "try_exists",
        "is_dir",
        "is_file",
        "is_symlink",
        "metadata",
        "symlink_metadata",
        "read_link",
        "canonicalize",
        "read_dir",
        "read_to_string",
        "create",
        "open",
        "options",
        "write",
        "remove_file",
        "remove_dir",
        "remove_dir_all",
        "rename",
        "copy",
        "hard_link",
    ];

    /// How many times `word` occurs in `text` as a whole identifier.
    fn word_count(text: &str, word: &str) -> usize {
        let is_ident = |c: char| c.is_alphanumeric() || c == '_';
        text.match_indices(word)
            .filter(|(at, _)| {
                let before = text.get(..*at).and_then(|head| head.chars().next_back());
                let after = text
                    .get(at.saturating_add(word.len())..)
                    .and_then(|tail| tail.chars().next());
                !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
            })
            .count()
    }

    /// How many times `text` calls `name` as `.name(` or `::name(`.
    fn call_count(text: &str, name: &str) -> usize {
        [".", "::"]
            .into_iter()
            .map(|lead| text.matches(&format!("{lead}{name}(")).count())
            .fold(0_usize, usize::saturating_add)
    }

    /// The identifier right after each `prefix` in `text`.
    fn items_after<'t>(text: &'t str, prefix: &str) -> Vec<&'t str> {
        let is_ident = |c: char| c.is_alphanumeric() || c == '_';
        text.match_indices(prefix)
            .filter_map(|(at, _)| text.get(at.saturating_add(prefix.len())..))
            .map(|tail| {
                tail.split(|c: char| !is_ident(c))
                    .next()
                    .unwrap_or_default()
            })
            .collect()
    }

    /// What in `source`'s production part reaches the filesystem by path.
    fn path_based_sites(source: &str) -> Vec<String> {
        let mut found = Vec::new();
        let marked: Vec<_> = source.match_indices(TESTS_MARKER).collect();
        let [(at, _)] = marked.as_slice() else {
            found.push(format!("the test marker occurs {} times", marked.len()));
            return found;
        };
        let production = source.get(..*at).unwrap_or_default();
        let mut admitted = 0_usize;
        for (site, want) in ADMITTED_FS {
            let count = production.matches(site).count();
            admitted = admitted.saturating_add(count);
            if count != want {
                found.push(format!("{count} `{site}` sites, {want} admitted"));
            }
        }
        let named = word_count(production, "fs");
        if named != admitted {
            found.push(format!("{named} `fs` paths, {admitted} admitted"));
        }
        for (prefix, items) in ADMITTED_ITEMS {
            let seen = items_after(production, prefix);
            for item in &seen {
                if !items.iter().any(|(admitted, _)| admitted == item) {
                    found.push(format!("`{prefix}{item}` is not admitted"));
                }
            }
            for (item, want) in items {
                let count = seen.iter().filter(|seen| *seen == item).count();
                if count != *want {
                    found.push(format!("{count} `{prefix}{item}` sites, {want} admitted"));
                }
            }
        }
        for needle in PATH_BASED {
            let count = word_count(production, needle);
            if count != 0 {
                found.push(format!("{count} `{needle}` sites"));
            }
        }
        for name in PATH_CALLS {
            let count = call_count(production, name);
            if count != 0 {
                found.push(format!("{count} `{name}(` calls"));
            }
        }
        found
    }

    #[test]
    fn init_writes_only_through_held_dir() {
        let source = include_str!("init.rs");
        assert_eq!(path_based_sites(source), Vec::<String>::new());
        let plant = |line: &str| {
            path_based_sites(&source.replacen(TESTS_MARKER, &format!("{line}\n{TESTS_MARKER}"), 1))
        };
        let planted = plant("fn planted() { let _ = std::fs::OpenOptions::new(); }");
        assert!(
            planted.contains(&"1 `OpenOptions` sites".to_owned()),
            "{planted:?}"
        );
        for evasion in [
            "use std::fs as disk;",
            "use std::{fs, io};",
            "fn planted() { let _ = tokio::fs::write(\"x\", \"\"); }",
            "fn planted() { let _ = std::fs::metadata(\"x\"); }",
            "fn planted() { let _ = Path::new(\"x\").try_exists(); }",
            "fn planted() { let _ = std::fs::File::options(); }",
            "fn planted() { let _ = Path::new(\"x\").read_dir(); }",
            "fn planted() { let _ = Path::exists(Path::new(\"x\")); }",
            "fn planted() { let _ = Path::is_dir(Path::new(\"x\")); }",
            "fn planted() { let _ = crate::io_bounded::read_user_named(Path::new(\"x\"), crate::io_bounded::SOURCE_CAP); }",
            "fn planted() { let _ = ipe_fs_open::HeldDir::open_root(Path::new(\"x\")); }",
            "fn planted() { let _ = HeldDir::open(Path::new(\"x\")); }",
        ] {
            assert!(!plant(evasion).is_empty(), "{evasion} goes unnoticed");
        }
        let swapped = source
            .replacen(
                "fn fill_with(file: &mut std::fs::File,",
                "use std::fs::File as Disk;\nfn fill_with(file: &mut Disk,",
                1,
            )
            .replacen(
                TESTS_MARKER,
                &format!("fn planted() {{ let _ = Disk::create_new(\"x\"); }}\n{TESTS_MARKER}"),
                1,
            );
        assert!(
            !path_based_sites(&swapped).is_empty(),
            "an alias swapped in for an admitted site goes unnoticed"
        );
    }

    /// A fresh scratch directory for one test.
    fn scratch(tag: &str) -> PathBuf {
        let dir = ipe_test_temp::temp_root()
            .join(format!("ipe_init_managed_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("make scratch");
        dir
    }

    /// `dir`, held.
    fn held(dir: &Path) -> HeldDir {
        HeldDir::open_following(dir)
            .expect("open scratch")
            .expect("scratch exists")
    }

    /// The names in `dir`, sorted; an absent directory lists nothing.
    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// A managed root file `name` holding `content`.
    fn root_file(name: &str, content: &str) -> ManagedFile {
        ManagedFile::source(ManagedDir::Root, name, content.to_owned())
    }

    /// Every placement policy; the asking ones only when a terminal is attached.
    fn every_policy(tty: Option<&Interactive>) -> Vec<(Existing<'_>, Missing<'_>)> {
        let mut policies = vec![
            (Existing::Force, Missing::Write),
            (Existing::Keep(KeepWhy::NoTerminal), Missing::Write),
            (Existing::Keep(KeepWhy::NotForced), Missing::Write),
        ];
        if let Some(tty) = tty {
            policies.push((Existing::Ask(tty), Missing::Ask(tty)));
        }
        policies
    }

    /// A managed name that is a link, live or dangling, is kept unread under every policy.
    #[cfg(unix)]
    #[test]
    fn managed_write_linked_file_kept_under_every_policy() {
        let base = scratch("linked_file");
        let outside = scratch("linked_file_outside");
        std::fs::write(outside.join("victim"), "outside").expect("plant outside file");
        std::os::unix::fs::symlink(outside.join("victim"), base.join("README.md"))
            .expect("plant live link");
        std::os::unix::fs::symlink(outside.join("absent"), base.join(".gitignore"))
            .expect("plant dangling link");
        let dir = held(&base);
        let tty = Interactive::detect();
        for (existing, missing) in every_policy(tty.as_ref()) {
            for name in ["README.md", ".gitignore"] {
                let placed = place_managed(&dir, &root_file(name, "new"), existing, missing);
                assert!(
                    matches!(placed, Ok(Placed::Kept(Kept::Unread(Unread::Link)))),
                    "{name}: {placed:?}"
                );
            }
        }
        assert_eq!(
            std::fs::read_to_string(outside.join("victim"))
                .ok()
                .as_deref(),
            Some("outside")
        );
        assert_eq!(names_in(&outside), vec!["victim".to_owned()]);
        assert_eq!(
            names_in(&base),
            vec![".gitignore".to_owned(), "README.md".to_owned()]
        );
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// A linked `src` stops the run before any write; nothing lands outside.
    #[cfg(unix)]
    #[test]
    fn managed_write_linked_src_refused() {
        let base = scratch("linked_src");
        let outside = scratch("linked_src_outside");
        std::os::unix::fs::symlink(&outside, base.join(SRC_DIR)).expect("plant src link");
        let root = held(&base);
        let fresh = is_fresh_target(&root);
        assert!(
            matches!(&fresh, Err(CliError::OutputRefused(crate::output_dir::OutputRefusal::Symlink(path))) if path.ends_with(SRC_DIR)),
            "{fresh:?}"
        );
        let files = managed_files("demo", InitShape::Cli, Runtime::Served);
        let placed = place_all(&root, &files, Existing::Force, Missing::Write);
        assert!(
            matches!(&placed, Err(CliError::OutputRefused(crate::output_dir::OutputRefusal::Symlink(path))) if path.ends_with(SRC_DIR)),
            "{:?}",
            placed.as_ref().map(Vec::len)
        );
        assert!(names_in(&outside).is_empty(), "nothing lands outside");
        assert_eq!(names_in(&base), vec![SRC_DIR.to_owned()]);
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// A FIFO at a managed name is kept unread, without blocking on it.
    #[cfg(unix)]
    #[test]
    fn managed_write_fifo_kept_without_blocking() {
        let base = scratch("fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(base.join("README.md"))
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo creates the fixture");
        let (sent, received) = std::sync::mpsc::channel();
        let at = base.clone();
        std::thread::Builder::new()
            .spawn(move || {
                let placed = place_managed(
                    &held(&at),
                    &root_file("README.md", "new"),
                    Existing::Force,
                    Missing::Write,
                );
                let _ = sent.send(matches!(
                    placed,
                    Ok(Placed::Kept(Kept::Unread(Unread::NotRegular)))
                ));
            })
            .expect("spawn the worker");
        let kept = received.recv_timeout(std::time::Duration::from_secs(5));
        assert_eq!(kept, Ok(true), "kept unread within the timeout");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A forced placement backs the file up beside it, a fresh slot each time.
    #[test]
    fn managed_write_force_backs_up_then_replaces() {
        let base = scratch("force_backup");
        std::fs::write(base.join("README.md"), "old").expect("plant README");
        let dir = held(&base);
        let backups = base.join(crate::driver::BACKUP_DIR);
        let file = root_file("README.md", "new");
        let placed = place_managed(&dir, &file, Existing::Force, Missing::Write);
        assert!(
            matches!(&placed, Ok(Placed::Replaced(backup)) if backup.slot().as_os_str() == "README.md.bak"),
            "{placed:?}"
        );
        let Ok(placed) = placed else {
            return;
        };
        assert_eq!(
            placed_line(&file, &placed, false).map(|line| line.as_str().to_owned()),
            Some("backed up README.md to .ipe-backup/README.md.bak".to_owned())
        );
        assert_eq!(
            std::fs::read_to_string(backups.join("README.md.bak"))
                .ok()
                .as_deref(),
            Some("old")
        );
        assert_eq!(
            std::fs::read_to_string(base.join("README.md"))
                .ok()
                .as_deref(),
            Some("new")
        );
        let again = place_managed(
            &dir,
            &root_file("README.md", "newer"),
            Existing::Force,
            Missing::Write,
        );
        assert!(
            matches!(&again, Ok(Placed::Replaced(backup)) if backup.slot().as_os_str() == "README.md.bak.1"),
            "{again:?}"
        );
        assert_eq!(
            std::fs::read_to_string(backups.join("README.md.bak.1"))
                .ok()
                .as_deref(),
            Some("new")
        );
        assert_eq!(
            std::fs::read_to_string(base.join("README.md"))
                .ok()
                .as_deref(),
            Some("newer")
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// An entry that takes the name before the create is kept, its bytes untouched.
    #[test]
    fn managed_write_appeared_is_kept() {
        let base = scratch("appeared");
        let dir = held(&base);
        let file = root_file("README.md", "new");
        std::fs::write(base.join("README.md"), "theirs").expect("plant the racing file");
        let placed = create_managed(&dir, &file);
        assert!(
            matches!(placed, Ok(Placed::Kept(Kept::Appeared))),
            "{placed:?}"
        );
        assert_eq!(
            std::fs::read_to_string(base.join("README.md"))
                .ok()
                .as_deref(),
            Some("theirs")
        );
        let missing = place_managed(
            &dir,
            &root_file("Makefile", "new"),
            Existing::Force,
            Missing::Write,
        );
        assert!(matches!(missing, Ok(Placed::Created)), "{missing:?}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Both next-steps messages point coding agents at the guide term.
    #[test]
    fn init_next_steps_name_guide_term() {
        let pointer = format!("ipe doc {}", crate::agents_guide::GUIDE_TERM);
        for shape in InitShape::ALL {
            for runtime in Runtime::ALL {
                for interactive in [false, true] {
                    let body = next_steps_body("app", "demo", interactive, shape, runtime);
                    assert!(body.contains(&pointer), "{shape:?}/{runtime:?}: {body}");
                }
            }
        }
        let body = next_steps_lib_body(".", "demo");
        assert!(body.contains(&pointer), "lib: {body}");
    }
}
