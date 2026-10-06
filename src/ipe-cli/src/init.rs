//! `ipe init` — scaffold a new Ipê project.
//!
//! `ipe init [directory] [shape] [runtime]` (spec § 8). The positionals mirror
//! the build grammar's prefix and are wizard shortcuts: `directory` is where to
//! scaffold (`.` or omitted → the current directory, as `cargo init`); `shape`
//! picks the template; `runtime` (for `web` only) seeds the default delivery.
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

use std::fmt::Write as _;
use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

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
const AGENTS_MD: &str = include_str!("../templates/AGENTS.md.in");

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
    /// `main = Web.tea …` — DOM rendering, served or solo.
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
    /// effect-locality columns (served vs solo); every other shape has one
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
    /// runtime choice (spec § 0.1): `runtime` picks between its served and solo
    /// wording; every other arm ignores it.
    const fn open_hint(self, runtime: InitRuntime) -> &'static str {
        match self {
            Self::Web => match runtime {
                InitRuntime::Served => {
                    "Then open http://localhost:8000 and click the counter buttons."
                }
                InitRuntime::Solo => {
                    "This is a `solo` app: `ipe dev run` serves the wasm bundle at \
                     http://localhost:8000; open it and click the counter buttons."
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
    /// another shape's app.
    const fn readme_description(self) -> &'static str {
        match self {
            Self::Web => {
                "a small `Ipe.Web` counter — a Model holding a count, `Increment` and \
                 `Decrement` messages, and a two-button view — that serves its UI over HTTP."
            }
            Self::Tui => {
                "a small `Ipe.Tea.Tui` counter — a Model holding a count, updated by the \
                 Up/Down arrow keys and rendered to the terminal screen."
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
}

// ── runtime model ──────────────────────────────────────────────────────────────

/// The Web-shape runtime a `web` project's default delivery is seeded with
/// (spec § 2). Only `web` carries this choice; the `runtime` positional is
/// meaningful for it alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum InitRuntime {
    /// The co-located server loop — the unnamed default. `web` with no runtime
    /// word means served.
    #[default]
    Served,
    /// The self-contained client loop — wasm in a browser/webview.
    Solo,
}

impl InitRuntime {
    /// Parse a `runtime` positional into the runtime and whether a deprecated
    /// alias was used. `served` is a valid init input (unlike the build grammar,
    /// where it is the unnamed default and never written) — at `init` the
    /// positional is an explicit wizard shortcut. The retired words `live` and
    /// `spa` are still accepted here for one release as deprecated aliases (the
    /// second element is `Some(alias)` then, so the caller can emit a rename
    /// hint); the build grammar rejects them. `None` for any token outside the
    /// closed set.
    fn parse(s: &str) -> Option<(Self, Option<&'static str>)> {
        match s {
            "served" => Some((Self::Served, None)),
            "solo" => Some((Self::Solo, None)),
            // Deprecated aliases: accepted at `init` only, with a rename hint.
            "live" => Some((Self::Served, Some("live"))),
            "spa" => Some((Self::Solo, Some("spa"))),
            _ => None,
        }
    }

    /// The display word used in prompts and messages.
    const fn label(self) -> &'static str {
        match self {
            Self::Served => "served",
            Self::Solo => "solo",
        }
    }

    /// The `{ships}` template fill for a web project's `package.ipe` delivery
    /// record, so the wizard's runtime choice writes the delivery set the
    /// `ipe release` loop actually builds (spec § delivery).
    ///
    /// `solo` declares an explicit `ships = [ solo ]` — the browser wasm bundle
    /// the user asked for. `served` is the implicit `[ binary ]` singleton, so it
    /// fills to nothing and the manifest stays minimal (a served web project *is*
    /// a co-located binary; declaring it explicitly would be noise). The fill is
    /// spliced before the first delivery sub-field, closing with a `, ` so the
    /// record's existing fields follow it unchanged.
    const fn ships_fill(self) -> &'static str {
        match self {
            Self::Served => "",
            Self::Solo => "ships = [ solo ]\n        , ",
        }
    }
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
    /// runtime prompt and seeds the default delivery.
    runtime: Option<InitRuntime>,
}

// ── managed-file model ────────────────────────────────────────────────────────

/// One file `ipe init` manages: where it lives, relative to the target, and
/// the content it would write there.
struct ManagedFile {
    /// The file's path relative to the target directory.
    rel: PathBuf,
    /// The exact bytes `init` would write.
    content: String,
}

/// What `init` will do with a single managed file, decided once from its
/// on-disk presence and the run's consent mode. Keeping the choice as a value
/// separates the decision (which may prompt) from the write (which never prompts).
enum FileAction {
    /// Write the file — it is absent, or the user consented to overwrite it.
    Write,
    /// Leave the file untouched — the user declined, or a non-interactive run
    /// refused to overwrite silently.
    Skip,
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

/// Fill a `package.ipe` template's `{name}` and (web-only) `{ships}` holes.
///
/// `{ships}` is a fixed builder expression drawn from the runtime's closed set,
/// never user input, so it needs no literal escaping; non-web templates carry no
/// `{ships}` hole, so the substitution is a no-op there.
fn fill_package(template: &str, project_name: &str, runtime: InitRuntime) -> String {
    // `{ships}` is a template placeholder substituted by `.replace`, not a
    // `format!` argument — the formatting-args lint's heuristic misreads it.
    #[allow(clippy::literal_string_with_formatting_args)]
    fill_name(template, project_name).replace("{ships}", runtime.ships_fill())
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

    let is_tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();

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
            None => InitRuntime::default(),
        }
    } else {
        InitRuntime::default()
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
    _stated_runtime: Option<InitRuntime>,
) -> Result<(), CliError> {
    let Some(stated) = stated_shape else {
        return Ok(());
    };
    let Some(existing) = existing_project_shape(target_dir)? else {
        return Ok(());
    };
    if stated != existing {
        return Err(CliError::Usage(text::msg::init_shape_fixed(
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
    let mut runtime_positional: Option<InitRuntime> = None;
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
            &rt.label(),
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

/// Parse a runtime word positional into an [`InitRuntime`], with the one
/// pedagogical "unknown runtime" message. A deprecated alias (`live`/`spa`) is
/// accepted for one release and prints a rename hint to stderr — never a silent
/// acceptance.
fn parse_runtime_word(word: &str) -> Result<InitRuntime, CliError> {
    let (runtime, deprecated) = InitRuntime::parse(word)
        .ok_or_else(|| CliError::Usage(text::msg::init_unknown_runtime(&word)))?;
    if let Some(alias) = deprecated {
        print_runtime_rename_hint(alias, runtime);
    }
    Ok(runtime)
}

/// Print the one-release rename hint for a deprecated runtime alias (`live` →
/// `served`, `spa` → `solo`) to stderr, so a user who typed the retired word
/// learns the new one instead of the alias being silently accepted.
fn print_runtime_rename_hint(alias: &str, runtime: InitRuntime) {
    let _ = writeln!(
        std::io::stderr(),
        "ipe init: `{alias}` is renamed to `{}` — it is accepted for one release; \
         use `{}` from now on.",
        runtime.label(),
        runtime.label(),
    );
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

/// TTY wizard: prompt for the `web` runtime (served vs solo). Only called for the
/// web shape when the runtime positional was omitted on a TTY.
fn wizard_runtime() -> Result<InitRuntime, CliError> {
    crate::screen::prompt(
        "How does this web app run?\n\
             \n\
             [1] served — a co-located server loop, streamed to the browser  (default)\n\
             [2] solo   — a self-contained client, wasm in the browser\n\
             \n\
             Runtime [1]: ",
    );
    let _ = std::io::stdout().flush();
    let line = read_line_trimmed();
    let runtime = match line.as_deref().unwrap_or("") {
        "" | "1" | "served" => InitRuntime::Served,
        "2" | "solo" => InitRuntime::Solo,
        // Deprecated aliases: accepted for one release, with a rename hint.
        "live" => {
            print_runtime_rename_hint("live", InitRuntime::Served);
            InitRuntime::Served
        }
        "spa" => {
            print_runtime_rename_hint("spa", InitRuntime::Solo);
            InitRuntime::Solo
        }
        other => {
            return Err(CliError::Usage(text::msg::init_unknown_runtime_choice(
                &other,
            )));
        }
    };
    Ok(runtime)
}

/// Read one trimmed line from stdin, or `None` on EOF / read error.
fn read_line_trimmed() -> Option<String> {
    let mut buf = String::new();
    match std::io::stdin().read_line(&mut buf) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(buf.trim_end_matches(['\n', '\r']).to_owned()),
    }
}

// ── scaffold helpers ─────────────────────────────────────────────────────────

/// What is being scaffolded: a library has no app shape or runtime to report.
#[derive(Clone, Copy)]
enum ScaffoldKind {
    Library,
    App {
        shape: InitShape,
        runtime: InitRuntime,
    },
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
    let fresh = is_fresh_target(target_dir)?;
    if fresh || force {
        scaffold(target_dir, files, force)?;
        let is_tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
        let interactive = should_offer_health_check(is_tty, force);
        match kind {
            ScaffoldKind::Library => print_next_steps_lib(target_arg, project_name),
            ScaffoldKind::App { shape, runtime } => {
                print_next_steps(target_arg, project_name, interactive, shape, runtime);
            }
        }
        if interactive && prompt_yes_no("Verify your toolchain now?", true) {
            let _ = health::run_health_inline();
        }
    } else {
        reconcile_existing(target_dir, files)?;
    }
    Ok(())
}

/// The complete set of files `init` writes for an application project.
///
/// `shape` selects which `Main.ipe`, `package.ipe`, and `README.md` wording are
/// scaffolded; `runtime` fills the web `package.ipe`'s delivery set (`solo`
/// declares an explicit `ships`, `served` stays the implicit default) and picks
/// `README.md`'s open-hint wording. `.gitignore` and `AGENTS.md` are the only
/// shape-independent files.
fn managed_files(project_name: &str, shape: InitShape, runtime: InitRuntime) -> Vec<ManagedFile> {
    vec![
        ManagedFile {
            rel: PathBuf::from("package.ipe"),
            content: fill_package(shape.package_ipe(), project_name, runtime),
        },
        ManagedFile {
            rel: PathBuf::from("src").join("Main.ipe"),
            content: shape.main_ipe().to_owned(),
        },
        ManagedFile {
            rel: PathBuf::from("README.md"),
            content: README_MD
                .replace("{name}", project_name)
                .replace("{description}", shape.readme_description())
                .replace("{run_hint}", shape.open_hint(runtime)),
        },
        ManagedFile {
            rel: PathBuf::from(".gitignore"),
            content: GITIGNORE.to_owned(),
        },
        ManagedFile {
            rel: PathBuf::from("AGENTS.md"),
            content: AGENTS_MD.to_owned(),
        },
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
        ManagedFile {
            rel: PathBuf::from("package.ipe"),
            content: fill_ipe(PACKAGE_LIB_IPE),
        },
        ManagedFile {
            rel: PathBuf::from("src").join(format!("{module}.ipe")),
            content: fill_ipe(LIB_IPE),
        },
        ManagedFile {
            rel: PathBuf::from("README.md"),
            content: fill_markdown(README_LIB_MD),
        },
        ManagedFile {
            rel: PathBuf::from(".gitignore"),
            content: GITIGNORE.to_owned(),
        },
        ManagedFile {
            rel: PathBuf::from("AGENTS.md"),
            content: AGENTS_MD.to_owned(),
        },
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

/// Whether the target holds none of `init`'s footprint: no manifest
/// (`package.ipe` or a legacy `ipe.toml`) and no non-empty `src/`.
fn is_fresh_target(target_dir: &Path) -> Result<bool, CliError> {
    if target_dir.join("package.ipe").exists() || target_dir.join("ipe.toml").exists() {
        return Ok(false);
    }
    let src = target_dir.join("src");
    if src.is_dir() {
        let mut entries = std::fs::read_dir(&src).map_err(|e| CliError::Io {
            path: src.clone(),
            source: e,
        })?;
        if entries.next().is_some() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Reconcile an already-populated target against the managed set, one file at
/// a time. Interactive runs prompt per file; non-interactive runs write only
/// missing files and report the existing ones left untouched.
fn reconcile_existing(target_dir: &Path, files: &[ManagedFile]) -> Result<(), CliError> {
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let mut restored: Vec<PathBuf> = Vec::new();
    let mut skipped: Vec<PathBuf> = Vec::new();

    for file in files {
        let path = target_dir.join(&file.rel);
        let exists = path.exists();
        let action = decide_action(&file.rel, exists, interactive);
        match action {
            FileAction::Write => {
                if let Some(parent) = path.parent() {
                    create_dir_all(parent)?;
                }
                if exists {
                    replace_file(&path, &file.content)?;
                } else {
                    write_new_file(&path, &file.content)?;
                }
                restored.push(file.rel.clone());
            }
            FileAction::Skip => skipped.push(file.rel.clone()),
        }
    }

    print_reconcile_summary(interactive, &restored, &skipped);
    Ok(())
}

/// Decide what to do with one managed file. Missing files default to being
/// restored; existing ones default to being left alone.
fn decide_action(rel: &Path, exists: bool, interactive: bool) -> FileAction {
    if !exists {
        if !interactive || prompt_yes_no(&format!("Restore {}?", rel.display()), true) {
            return FileAction::Write;
        }
        return FileAction::Skip;
    }
    if interactive && prompt_yes_no(&format!("Overwrite {}?", rel.display()), false) {
        FileAction::Write
    } else {
        FileAction::Skip
    }
}

/// Ask a `[Y/n]` / `[y/N]` question and read the answer.
fn prompt_yes_no(question: &str, default: bool) -> bool {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    crate::screen::prompt(&format!("{question} {hint} "));
    let _ = std::io::stdout().flush();
    crate::read_yes_no_default(default)
}

/// Report what `reconcile_existing` did.
fn print_reconcile_summary(interactive: bool, restored: &[PathBuf], skipped: &[PathBuf]) {
    let mut body = String::new();
    for rel in restored {
        let _ = writeln!(body, "restored {}", rel.display());
    }
    for rel in skipped {
        if interactive {
            let _ = writeln!(body, "kept {} (unchanged)", rel.display());
        } else {
            let _ = writeln!(body, "would overwrite {} (skipped: no TTY)", rel.display());
        }
    }
    if body.is_empty() {
        body.push_str("nothing to do.\n");
    }
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(crate::screen::Tone::Text, &body)
        .emit();
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
/// `--force` the original is backed up before it is overwritten.
fn scaffold(target_dir: &Path, files: &[ManagedFile], force: bool) -> Result<(), CliError> {
    let mut kept: Vec<&Path> = Vec::new();
    for file in files {
        let path = target_dir.join(&file.rel);
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }
        if !path.exists() {
            write_new_file(&path, &file.content)?;
        } else if force {
            replace_file(&path, &file.content)?;
        } else {
            kept.push(&file.rel);
        }
    }
    if !kept.is_empty() {
        let mut body = String::new();
        for rel in kept {
            let _ = writeln!(body, "kept {} (unchanged)", rel.display());
        }
        crate::screen::Screen::new(crate::screen::Stream::Stdout)
            .line(crate::screen::Tone::Text, &body)
            .emit();
    }
    Ok(())
}

fn create_dir_all(path: &Path) -> Result<(), CliError> {
    std::fs::create_dir_all(path).map_err(|e| CliError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

/// Create a file that must not exist yet (`create_new`).
///
/// A file or symlink that appeared at `path` is never overwritten or written
/// through.
fn write_new_file(path: &Path, contents: &str) -> Result<(), CliError> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| file.write_all(contents.as_bytes()))
        .map_err(|e| CliError::Io {
            path: path.to_path_buf(),
            source: e,
        })
}

/// Overwrite an existing user file the user asked to replace.
///
/// Its original is backed up first, and the replacement is atomic.
fn replace_file(path: &Path, contents: &str) -> Result<(), CliError> {
    if let Some(backup) = crate::rewrite_user_file(path, contents, crate::RewriteKind::Lossy)? {
        crate::screen::chatter(
            crate::screen::Stream::Stdout,
            crate::screen::Tone::Text,
            &format!("backed up {} to {}", path.display(), backup.display()),
        );
    }
    Ok(())
}

/// Whether to offer the interactive `ipe health` check after scaffolding.
const fn should_offer_health_check(is_tty: bool, force: bool) -> bool {
    is_tty && !force
}

/// Print the friendly next-steps message, tuned to the resolved shape (and, for
/// `web`, its runtime) so the hint matches how the scaffolded app actually runs
/// (spec § 0.1).
fn print_next_steps(
    target_arg: &str,
    project_name: &str,
    interactive: bool,
    shape: InitShape,
    runtime: InitRuntime,
) {
    let run_cmd = if target_arg == "." {
        "    ipe dev run".to_owned()
    } else {
        format!("    cd {target_arg} && ipe dev run")
    };
    let health_tip = if interactive {
        String::new()
    } else {
        "\nTip: run  ipe health  to tune your toolchain for faster builds.\n".to_owned()
    };
    let open_hint = shape.open_hint(runtime);
    let body = format!(
        "Created Ipê project `{project_name}`.\n\
         \n\
         Next steps:\n\
         {run_cmd}\n\
         \n\
         {open_hint}\
         {health_tip}"
    );
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(crate::screen::Tone::Text, &body)
        .emit();
}

/// Print the next-steps message for a freshly scaffolded library.
fn print_next_steps_lib(target_arg: &str, project_name: &str) {
    let build_cmd = if target_arg == "." {
        "    ipe dev build".to_owned()
    } else {
        format!("    cd {target_arg} && ipe dev build")
    };
    let body = format!(
        "Created Ipê library `{project_name}`.\n\
         \n\
         Next steps:\n\
         {build_cmd}\n\
         \n\
         Add public modules under src/ and list each in package.ipe's exposedModules.\n"
    );
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(crate::screen::Tone::Text, &body)
        .emit();
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

    #[test]
    fn scaffolded_web_manifest_is_package_ipe_that_re_parses() {
        let files = managed_files("demo-app", InitShape::Web, InitRuntime::Served);
        let manifest = files
            .iter()
            .find(|f| f.rel == Path::new("package.ipe"))
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
        assert_eq!(parsed.delivery.browser.base_path, "/");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn solo_runtime_scaffolds_an_explicit_solo_ships_set() {
        use crate::delivery_set::ShipEntry;
        let files = managed_files("solo-app", InitShape::Web, InitRuntime::Solo);
        let manifest = files
            .iter()
            .find(|f| f.rel == Path::new("package.ipe"))
            .expect("init writes a package.ipe");

        let root = ipe_test_temp::temp_root().join("ipe_init_solo_ships");
        let _ = std::fs::remove_dir_all(&root);
        write_stub_src(&root);
        let path = root.join("package.ipe");
        std::fs::write(&path, &manifest.content).expect("write scaffolded package.ipe");

        let parsed =
            crate::project::parse_manifest(&path).expect("scaffolded solo manifest re-parses");
        assert_eq!(
            parsed.delivery.ships,
            vec![ShipEntry::Solo],
            "a wizard `web solo` choice writes an explicit `ships = [ solo ]`"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn served_runtime_leaves_the_delivery_set_implicit() {
        // The default `served` runtime keeps the manifest minimal: no `ships`
        // field, which reads back as the implicit `[ binary ]` singleton.
        let files = managed_files("served-app", InitShape::Web, InitRuntime::Served);
        let manifest = files
            .iter()
            .find(|f| f.rel == Path::new("package.ipe"))
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
            parsed.delivery.ships.is_empty(),
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
            let files = managed_files("proj", shape, InitRuntime::Solo);
            let manifest = files
                .iter()
                .find(|f| f.rel == Path::new("package.ipe"))
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
        let files = managed_files("tui-app", InitShape::Tui, InitRuntime::Served);
        let manifest = files
            .iter()
            .find(|f| f.rel == Path::new("package.ipe"))
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
        let files = managed_files("my-script", InitShape::Script, InitRuntime::Served);
        let manifest = files
            .iter()
            .find(|f| f.rel == Path::new("package.ipe"))
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
        let files = managed_files("tick-worker", InitShape::Worker, InitRuntime::Served);
        let manifest = files
            .iter()
            .find(|f| f.rel == Path::new("package.ipe"))
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
        let web = managed_files("x", InitShape::Web, InitRuntime::Served);
        let tui = managed_files("x", InitShape::Tui, InitRuntime::Served);
        let cli = managed_files("x", InitShape::Cli, InitRuntime::Served);
        let worker = managed_files("x", InitShape::Worker, InitRuntime::Served);
        let server = managed_files("x", InitShape::Server, InitRuntime::Served);
        let script = managed_files("x", InitShape::Script, InitRuntime::Served);

        let main = |files: &[ManagedFile]| {
            files
                .iter()
                .find(|f| f.rel == Path::new("src/Main.ipe"))
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
        let a = parse_init_args(&["my-app".to_owned(), "web".to_owned(), "solo".to_owned()])
            .expect("web solo positionals parse");
        assert_eq!(a.target_arg.as_deref(), Some("my-app"));
        assert_eq!(a.shape, Some(InitShape::Web));
        assert_eq!(a.runtime, Some(InitRuntime::Solo));
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
        let err = parse_init_args(&["app".to_owned(), "tui".to_owned(), "solo".to_owned()])
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
        // The canonical words parse with no deprecation flag.
        assert_eq!(
            InitRuntime::parse("served"),
            Some((InitRuntime::Served, None))
        );
        assert_eq!(InitRuntime::parse("solo"), Some((InitRuntime::Solo, None)));
        assert_eq!(InitRuntime::parse("nope"), None);
    }

    #[test]
    fn deprecated_runtime_aliases_still_parse_flagged() {
        // The retired words map to the new runtime and carry the alias so the
        // caller can emit a rename hint — never a silent accept.
        assert_eq!(
            InitRuntime::parse("live"),
            Some((InitRuntime::Served, Some("live")))
        );
        assert_eq!(
            InitRuntime::parse("spa"),
            Some((InitRuntime::Solo, Some("spa")))
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
        let files = managed_files("proj", InitShape::Web, InitRuntime::Served);
        let manifest = files
            .iter()
            .find(|f| f.rel == Path::new("package.ipe"))
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
        assert_eq!(parsed.delivery.browser.base_path, "/");
        // mobile default orientation
        assert_eq!(
            parsed.delivery.mobile.orientation,
            crate::project::ScreenOrientation::Portrait
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn library_scaffold_manifest_declares_exposed_modules_and_re_parses() {
        let files = library_files("my-cool-lib");
        let manifest = files
            .iter()
            .find(|f| f.rel == Path::new("package.ipe"))
            .expect("init --lib writes a package.ipe");

        assert!(
            files
                .iter()
                .any(|f| f.rel == Path::new("src").join("MyCoolLib.ipe")),
            "the public module src/MyCoolLib.ipe is scaffolded"
        );
        assert!(
            !files
                .iter()
                .any(|f| f.rel == Path::new("src").join("Main.ipe")),
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
        let files = managed_files("x", InitShape::default(), InitRuntime::Served);
        assert!(
            !files.iter().any(|f| f.rel == Path::new("ipe.toml")),
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
        let files = managed_files(hostile, InitShape::Web, InitRuntime::Served);
        let manifest = files
            .iter()
            .find(|f| f.rel == Path::new("package.ipe"))
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
        let _ = std::fs::remove_dir_all(&root);
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
        }
    }
}
