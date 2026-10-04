//! The `ipe` help system — a data-driven renderer for the top-level help
//! screen and every per-command `--help` page.
//!
//! One table ([`COMMANDS`]) binds each command to its handler and its `.md` help
//! page ([`crate::help_page`]): the page holds the synopsis, argument
//! description, and option list; `help/index.md` groups the commands into the
//! overview's sections. Both the overview and the per-command pages render from
//! those pages, so a command or flag is described once, in Markdown.
//!
//! Colour is opt-in per output stream: ANSI escapes are emitted only when the
//! destination is a terminal and `NO_COLOR` is unset. Piped or redirected
//! output — and any run under `NO_COLOR` — is clean, aligned plain text.
//!
//! `--help --json` emits the entire command grammar as a stable JSON object (schema
//! `"ipe.cli.help/1"`), so tooling can discover every command, flag, and section
//! without scraping the human-text screen.

use std::fmt::Write as _;
use std::io::IsTerminal;

use crate::CliError;
use crate::help_page::{self, CommandText, SectionText};
use crate::style::{Palette, gutter};
use crate::verb::{Umbrella, Verb};

/// A command's dispatch handler: it receives the arguments after the command
/// name and runs the command.
pub(crate) type Handler = fn(&[String]) -> Result<(), CliError>;

/// A command's registry entry: the single source of truth binding a command's
/// name and help metadata to the handler that runs it. Because the dispatcher
/// and the help renderer both read this one table, a command that is dispatched
/// but undescribed — or described but undispatched — cannot exist.
pub(crate) struct Command {
    /// The command name (e.g. `fmt`).
    name: &'static str,
    /// The handler that runs the command, given the arguments after its name.
    run: Handler,
    /// The command's `.md` help page (`help/<name>.md`): summary, synopsis,
    /// arguments, options. See [`crate::help_page`].
    page: &'static str,
    /// Whether the command is withheld from the top-level `ipe --help` screen.
    ///
    /// A hidden command is still fully dispatchable (its `--help` page renders, it runs) but is not
    /// listed among the overview's sections, so a command whose only outcome today is a manual-step
    /// message is not advertised as a finished feature. A hidden command belongs to no section.
    hidden: bool,
}

/// A grouped verb's help entry: the typed [`Verb`] and its `.md` page.
///
/// A member carries no handler: [`crate::driver::dispatch`] matches the typed
/// [`Verb`] exhaustively, so a grouped verb is described here and dispatched
/// there from the one [`Verb::ALL`] set.
pub(crate) struct Member {
    /// The verb this entry describes.
    verb: Verb,
    /// The verb's `.md` help page (`help/<group>-<verb>.md`).
    page: &'static str,
}

/// A command group: an umbrella (`dev`, `release`) owning its member verbs.
///
/// A group is invoked as `ipe <group> <verb>`. The umbrella fixes the build
/// posture of every member ([`Umbrella::intent`]), so a posture is a namespace
/// rather than a flag: `watch` is a member of `dev` only, so hot-reloading a
/// shipping build cannot be expressed. A group carries no handler of its own:
/// `ipe <group> --help` renders its subpage, and a bare `ipe <group>` is refused
/// with [`CliError::GroupRequired`].
pub(crate) struct Group {
    /// The umbrella this group is.
    umbrella: Umbrella,
    /// The group's `.md` page (`help/<name>.md`), holding its one-line summary.
    page: &'static str,
    /// The member verbs, in display order.
    members: &'static [Member],
}

/// Every `ipe` command group: one per [`Umbrella`].
const GROUPS: &[Group] = &[
    Group {
        umbrella: Umbrella::Dev,
        page: include_str!("../help/dev.md"),
        members: &[
            Member {
                verb: Verb::DEV_BUILD,
                page: include_str!("../help/dev-build.md"),
            },
            Member {
                verb: Verb::DEV_RUN,
                page: include_str!("../help/dev-run.md"),
            },
            Member {
                verb: Verb::DEV_WATCH,
                page: include_str!("../help/dev-watch.md"),
            },
        ],
    },
    Group {
        umbrella: Umbrella::Release,
        page: include_str!("../help/release.md"),
        members: &[
            Member {
                verb: Verb::RELEASE_BUILD,
                page: include_str!("../help/release-build.md"),
            },
            Member {
                verb: Verb::RELEASE_RUN,
                page: include_str!("../help/release-run.md"),
            },
            Member {
                verb: Verb::RELEASE_EJECT,
                page: include_str!("../help/release-eject.md"),
            },
        ],
    },
];

/// Look up a group by name.
fn find_group(name: &str) -> Option<&'static Group> {
    GROUPS.iter().find(|g| g.name() == name)
}

/// Every grouped verb's help entry, in group then display order.
fn members() -> impl Iterator<Item = &'static Member> {
    GROUPS.iter().flat_map(|g| g.members.iter())
}

/// Whether `name` is a known command group (drives group-aware dispatch and
/// `--help` interception).
#[must_use]
pub fn is_group(name: &str) -> bool {
    find_group(name).is_some()
}

/// The verb `sub` of the group `group`, or `None` when either is unknown.
#[must_use]
pub fn group_member(group: &str, sub: &str) -> Option<Verb> {
    find_group(group)?
        .members
        .iter()
        .map(|m| m.verb)
        .find(|v| v.sub() == sub)
}

/// The member verb words of `group`, in display order, or `None` when `group`
/// is not a known group.
///
/// The candidate set for suggesting a near-miss when an unknown verb follows a
/// group name.
#[must_use]
pub fn group_members(group: &str) -> Option<Vec<&'static str>> {
    find_group(group).map(|g| g.members.iter().map(|m| m.verb.sub()).collect())
}

/// The canonical `'static` name for a known group, or `None` when `name` is not
/// a group.
///
/// Lets a dispatcher carry the interned group name into a typed error
/// without leaking a runtime `String` where a `&'static str` is required.
#[must_use]
pub fn group_name(name: &str) -> Option<&'static str> {
    find_group(name).map(Group::name)
}

/// A flag entry exposed to coverage surfaces: the flag synopsis and its
/// one-line description, both taken directly from [`COMMANDS`].
///
/// Distinct from [`crate::help_page::Opt`] so the coverage module can read the table
/// without coupling to the private render types.
#[derive(Clone, Debug)]
pub struct FlagSpec {
    /// The flag as it appears in the synopsis (e.g. `"[--out <dir>]"`).
    pub flag: &'static str,
    /// A one-line description of the flag.
    pub desc: &'static str,
}

/// A command's public metadata, projected from [`COMMANDS`] for the CLI
/// coverage surface.
#[derive(Clone, Debug)]
pub struct CommandSpec {
    /// The command name (`"fmt"`), or a grouped verb's full name (`"dev build"`).
    pub name: &'static str,
    /// The one-line description shown at the top of `ipe <command> --help`.
    pub summary: &'static str,
    /// The positional-argument synopsis (e.g. `"[<path>]"`), empty when the
    /// command takes no positional.
    pub args: &'static str,
    /// The plain-English description of the positional argument, empty when
    /// there is none.
    pub args_desc: &'static str,
    /// A plain-English note on where the command's primary output lands, shown
    /// under `Output:` in the generated CLI reference. Empty when the command
    /// has no notable output location to document.
    pub output_desc: &'static str,
    /// Whether the command is withheld from the top-level `ipe --help` screen.
    pub hidden: bool,
    /// Every flag the command accepts, in table order.
    pub options: Vec<FlagSpec>,
}

/// A top-level help section, projected from `help/index.md` for the CLI reference generator.
///
/// The command names are in display order and each names a [`CommandSpec`] entry (or a
/// [`GroupSpec`]).
#[derive(Clone, Debug)]
pub struct SectionSpec {
    /// The section heading (e.g. `"Development"`).
    pub title: &'static str,
    /// The command / group names in this section, in display order.
    pub commands: Vec<&'static str>,
}

/// A command group, projected from [`GROUPS`] for the CLI reference generator.
#[derive(Clone, Debug)]
pub struct GroupSpec {
    /// The group name (e.g. `"dev"`).
    pub name: &'static str,
    /// The one-line description shown on the group's subpage.
    pub summary: &'static str,
    /// The member verbs' full names (`"dev build"`), in display order; each
    /// names a [`CommandSpec`].
    pub members: Vec<&'static str>,
}

/// Every `ipe` command's public metadata, projected from the canonical
/// [`COMMANDS`] table.
///
/// The CLI coverage surface reads this instead of the private table so that
/// command names, summaries, and flag lists have one source and the coverage
/// columns can enumerate the full surface without duplicating the registry.
///
/// A grouped verb is listed under its full name (`"dev build"`).
#[must_use]
pub fn all_command_specs() -> Vec<CommandSpec> {
    entries()
        .map(|c| {
            let text = c.text();
            CommandSpec {
                name: c.name(),
                summary: text.summary,
                args: text.args,
                args_desc: text.args_desc,
                output_desc: text.output_desc,
                hidden: c.hidden(),
                options: text
                    .options
                    .iter()
                    .map(|o| FlagSpec {
                        flag: o.flag,
                        desc: o.desc,
                    })
                    .collect(),
            }
        })
        .collect()
}

/// Every top-level help section, projected from `help/index.md`.
///
/// The CLI reference generator reads this instead of the private table so the
/// section grouping in `docs/reference/cli.md` cannot drift from the top-level
/// `ipe --help` screen.
#[must_use]
pub fn all_section_specs() -> Vec<SectionSpec> {
    help_page::sections()
        .into_iter()
        .map(|s| SectionSpec {
            title: s.title,
            commands: s.commands,
        })
        .collect()
}

/// Every command group, projected from the canonical [`GROUPS`] table, for the
/// CLI reference generator.
#[must_use]
pub fn all_group_specs() -> Vec<GroupSpec> {
    GROUPS
        .iter()
        .map(|g| GroupSpec {
            name: g.name(),
            summary: g.summary(),
            members: g.members.iter().map(|m| m.verb.name()).collect(),
        })
        .collect()
}

/// Every top-level `ipe` command, each bound to its handler and its `.md` help
/// page.
///
/// A build-producing verb is not here: it lives under its umbrella in
/// [`GROUPS`], and its bare legacy name is refused by the dispatcher.
const COMMANDS: &[Command] = &[
    Command {
        name: "init",
        run: crate::init::run_init,
        page: include_str!("../help/init.md"),
        hidden: false,
    },
    Command {
        name: "type-check",
        run: crate::run_type_check,
        page: include_str!("../help/type-check.md"),
        hidden: false,
    },
    Command {
        name: "test",
        run: crate::run_test,
        page: include_str!("../help/test.md"),
        hidden: false,
    },
    Command {
        name: "verify",
        run: crate::run_verify,
        page: include_str!("../help/verify.md"),
        hidden: false,
    },
    Command {
        name: "fix",
        run: crate::run_fix,
        page: include_str!("../help/fix.md"),
        hidden: false,
    },
    Command {
        name: "fmt",
        run: crate::fmt::run_fmt,
        page: include_str!("../help/fmt.md"),
        hidden: false,
    },
    Command {
        name: "lint",
        run: crate::lint::run_lint,
        page: include_str!("../help/lint.md"),
        hidden: false,
    },
    Command {
        name: "clean",
        run: crate::clean::run_clean,
        page: include_str!("../help/clean.md"),
        hidden: false,
    },
    // Editing a package.ipe `Package.dependencies` list is not yet
    // automated, so `add`/`remove` today only report the manual step. Kept
    // dispatchable (and documented) but withheld from the top-level screen
    // until the manifest-source rewrite lands.
    Command {
        name: "add",
        run: crate::pkg::run_add,
        page: include_str!("../help/add.md"),
        hidden: true,
    },
    Command {
        name: "remove",
        run: crate::pkg::run_remove,
        page: include_str!("../help/remove.md"),
        hidden: true,
    },
    Command {
        name: "rust",
        run: crate::ffi::run_rust,
        page: include_str!("../help/rust.md"),
        hidden: false,
    },
    Command {
        name: "package",
        run: crate::run_package,
        page: include_str!("../help/package.md"),
        hidden: false,
    },
    Command {
        name: "login",
        run: crate::login::run_login,
        page: include_str!("../help/login.md"),
        hidden: false,
    },
    Command {
        name: "capabilities",
        run: crate::run_capabilities,
        page: include_str!("../help/capabilities.md"),
        hidden: false,
    },
    Command {
        name: "diff",
        run: crate::diff::run_diff,
        page: include_str!("../help/diff.md"),
        hidden: false,
    },
    Command {
        name: "doc",
        run: crate::doc::run_doc,
        page: include_str!("../help/doc.md"),
        hidden: false,
    },
    Command {
        name: "lsp",
        run: crate::lsp::run_lsp,
        page: include_str!("../help/lsp.md"),
        hidden: false,
    },
    Command {
        name: "upgrade",
        run: crate::run_upgrade,
        page: include_str!("../help/upgrade.md"),
        hidden: false,
    },
    Command {
        name: "health",
        run: crate::health::run_health,
        page: include_str!("../help/health.md"),
        hidden: false,
    },
    Command {
        name: "version",
        run: crate::run_version,
        page: include_str!("../help/version.md"),
        hidden: false,
    },
];

impl Command {
    /// The command's parsed help page.
    fn text(&self) -> CommandText {
        help_page::parse_command_page(self.name, self.page).0
    }
}

impl Group {
    /// The group word (`dev`, `release`).
    const fn name(&self) -> &'static str {
        self.umbrella.name()
    }

    /// The group's one-line summary.
    fn summary(&self) -> &'static str {
        help_page::summary_of(self.page)
    }
}

/// One help page: a top-level command or a grouped verb.
#[derive(Clone, Copy)]
enum Entry {
    /// A top-level command.
    Command(&'static Command),
    /// A grouped verb.
    Member(&'static Member),
}

impl Entry {
    /// The name the page's synopsis spells after `ipe` (`fmt`, `dev build`).
    const fn name(self) -> &'static str {
        match self {
            Self::Command(c) => c.name,
            Self::Member(m) => m.verb.name(),
        }
    }

    /// The `.md` page.
    const fn page(self) -> &'static str {
        match self {
            Self::Command(c) => c.page,
            Self::Member(m) => m.page,
        }
    }

    /// Whether the page is withheld from the top-level screen.
    const fn hidden(self) -> bool {
        match self {
            Self::Command(c) => c.hidden,
            Self::Member(_) => false,
        }
    }

    /// The parsed help page.
    fn text(self) -> CommandText {
        help_page::parse_command_page(self.name(), self.page()).0
    }
}

/// Every help page: the top-level commands, then each group's verbs.
fn entries() -> impl Iterator<Item = Entry> {
    COMMANDS
        .iter()
        .map(Entry::Command)
        .chain(members().map(Entry::Member))
}

/// The help page for `name`: a top-level command, or a grouped verb by its full
/// name (`dev build`) or help key (`dev-build`).
fn find_entry(name: &str) -> Option<Entry> {
    find(name).map(Entry::Command).or_else(|| {
        Verb::from_name(name)
            .and_then(|verb| members().find(|m| m.verb == verb))
            .map(Entry::Member)
    })
}

/// The overview's sections, in display order (from `help/index.md`).
fn sections() -> Vec<SectionText> {
    help_page::sections()
}

/// Look up a command's help entry by name.
fn find(name: &str) -> Option<&'static Command> {
    COMMANDS.iter().find(|c| c.name == name)
}

/// Whether `name` is a known command (drives `--help` interception in the
/// dispatcher).
#[must_use]
pub fn is_command(name: &str) -> bool {
    find(name).is_some()
}

/// Every top-level command name, in table order — the candidate set for
/// suggesting a near-miss when an unknown command is typed.
#[must_use]
pub fn command_names() -> Vec<&'static str> {
    COMMANDS.iter().map(|c| c.name).collect()
}

/// Every documented page key: each top-level command name, then each grouped
/// verb's help key (`dev-build`).
///
/// The documentation index keys one page per entry, so `ipe doc dev-build`
/// resolves from the same table as `ipe dev build --help`.
#[must_use]
pub fn documented_command_keys() -> Vec<&'static str> {
    COMMANDS
        .iter()
        .map(|c| c.name)
        .chain(members().map(|m| m.verb.help_key()))
        .collect()
}

/// The canonical static name and handler that run `name`, or `None` when `name`
/// is not a known command. The static name is what misuse output keys its
/// `--help` page on.
///
/// Dispatch and help share this one table, so a command is dispatchable exactly
/// when it is described — the two can never drift apart.
pub(crate) fn handler(name: &str) -> Option<(&'static str, Handler)> {
    find(name).map(|c| (c.name, c.run))
}

/// The one-line summary for `name`, or `None` when `name` is not a known command
/// or grouped verb.
///
/// Used to inject command metadata into the documentation index so that
/// `ipe doc <command>` resolves from the same SSOT as `ipe <command> --help`.
#[must_use]
pub fn command_summary(name: &str) -> Option<&'static str> {
    find_entry(name).map(|c| c.text().summary)
}

/// Render a command's full help as Markdown, or `None` when `name` is unknown.
///
/// This is the documentation projection of [`render_command`]: it reads the same
/// [`Command`] fields (summary, synopsis, arguments, options) from the one
/// [`COMMANDS`] table and lays them out as Markdown, so the HTML command page and
/// the terminal `ipe <command> --help` page describe a command from a single
/// source and cannot drift. No ANSI colour is emitted.
#[must_use]
pub fn command_doc_markdown(name: &str) -> Option<String> {
    find_entry(name).map(render_command_markdown)
}

/// Render one command's help page as Markdown from its parsed `.md` page, with
/// shared flags expanded in place.
fn render_command_markdown(cmd: Entry) -> String {
    let text = cmd.text();
    let mut out = String::new();
    let _ = writeln!(out, "{}\n", text.summary);
    let _ = write!(out, "```\nipe {}", cmd.name());
    if !text.args.is_empty() {
        let _ = write!(out, " {}", text.args);
    }
    out.push_str("\n```\n");
    if !text.args_desc.is_empty() {
        let _ = writeln!(
            out,
            "\n## {}\n\n{}",
            help_page::arguments_heading(),
            text.args_desc
        );
    }
    if !text.options.is_empty() {
        let _ = writeln!(out, "\n## {}\n", help_page::options_heading());
        for opt in &text.options {
            let _ = writeln!(out, "- `{}` — {}", opt.flag, opt.desc);
        }
    }
    out
}

/// Render the top-level help screen for the given output stream.
#[must_use]
pub fn top_level(stream: &impl IsTerminal) -> String {
    render_top_level(Palette::for_stream(stream))
}

/// Render a single command's or grouped verb's `--help` page, or `None` if
/// `name` is unknown.
#[must_use]
pub fn command(name: &str, stream: &impl IsTerminal) -> Option<String> {
    let p = Palette::for_stream(stream);
    find_entry(name).map(|cmd| render_command(cmd, p))
}

/// Render a command group's subpage — its summary, then each member subcommand
/// as a ready-to-run `ipe <group> <verb> --help` line — or `None` if `name` is
/// not a known group.
///
/// This is the `ipe dev --help` screen, and the body of the misuse page shown
/// for `ipe dev <unknown>`.
#[must_use]
pub fn group(name: &str, stream: &impl IsTerminal) -> Option<String> {
    let p = Palette::for_stream(stream);
    find_group(name).map(|g| render_group(g, p))
}

/// Render a group's subpage from its [`Group`] entry: the summary, a synopsis
/// line, and one aligned member line per verb.
fn render_group(g: &Group, p: &Palette) -> String {
    let mut out = String::new();
    out.push('\n');
    let _ = writeln!(out, "{}{}{}", p.dim, g.summary(), p.reset);
    out.push('\n');
    let _ = writeln!(out, "{}ipe {} <verb>{}", p.yellow, g.name(), p.reset);
    out.push('\n');
    out.push_str(crate::text::verbs_label());
    out.push('\n');
    let name_w = g
        .members
        .iter()
        .map(|m| m.verb.name().len())
        .max()
        .unwrap_or(0);
    for member in g.members {
        let entry = Entry::Member(member);
        let pad = name_w.saturating_sub(entry.name().len());
        let _ = writeln!(
            out,
            "  {}ipe {}{}{:pad$}  {}{}{}",
            p.yellow,
            entry.name(),
            p.reset,
            "",
            p.dim,
            entry.text().summary,
            p.reset,
        );
    }
    out.push('\n');
    gutter(&out)
}

/// The synopsis line for command `name`: `ipe <name>` in yellow, then its
/// arguments inline in plain text.
fn command_line(name: &str, args: &str, p: &Palette) -> String {
    let mut line = format!("{}ipe {name}{}", p.yellow, p.reset);
    if !args.is_empty() {
        line.push(' ');
        line.push_str(args);
    }
    line
}

/// Render the top-level overview: every command grouped by section. The
/// product header and the bug footer come from the screen frame
/// ([`crate::screen`]).
fn render_top_level(p: &Palette) -> String {
    let mut out = String::new();

    // The full list: every command by section, each shown as a ready-to-run
    // `ipe <command> --help`. The `--help` suffix aligns into one column within
    // the section (names padded to the section's widest) so the lines read as a
    // tidy block the reader can copy verbatim.
    for section in &sections() {
        out.push('\n');
        let _ = writeln!(out, "{}{}{}", p.bold, section.title, p.reset);
        // A section entry names either a command or a group; both render as a
        // ready-to-run `ipe <name> --help` line. Width is measured across every
        // listed name so the `--help` suffix aligns into one column.
        let name_w = section
            .commands
            .iter()
            .filter(|n| find(n).is_none_or(|c| !c.hidden))
            .map(|n| n.len())
            .max()
            .unwrap_or(0);
        for &name in &section.commands {
            // A hidden command is never listed, even if a section still names it.
            if find(name).is_some_and(|c| c.hidden) {
                continue;
            }
            // A group has no `Command` entry; it is still a valid `--help` node.
            if find(name).is_none() && find_group(name).is_none() {
                continue;
            }
            let pad = name_w - name.len();
            let _ = writeln!(
                out,
                "  {}ipe {}{}{:pad$}  {}--help{}",
                p.yellow, name, p.reset, "", p.dim, p.reset,
            );
        }
    }

    gutter(&out)
}

/// Emit the full command grammar as a compact JSON object (schema `"ipe.cli.help/1"`).
///
/// The payload is a pure read-only view over [`COMMANDS`] and the `.md` pages —
/// the same data the human screen and the dispatch table read — so the JSON
/// grammar cannot drift from what the CLI accepts. The schema tag (`"schema"`)
/// lets a consumer fail closed on a breaking change: additive new fields are
/// minor (no bump); a removed or retyped field bumps the major version number.
///
/// Shape:
/// ```text
/// { "schema": "ipe.cli.help/1",
///   "version": "<cargo-pkg-version>",
///   "sections": [ { "title": "<name>", "commands": ["<name>",…] }, … ],
///   "groups": [ { "name": "<name>", "summary": "<text>", "members": ["<verb>",…] }, … ],
///   "commands": [ { "name": "<name>", "summary": "<text>",
///                   "args": "<synopsis>", "args_desc": "<text>",
///                   "hidden": <bool>,
///                   "options": [ { "flag": "<synopsis>", "desc": "<text>" }, … ]
///                 }, … ] }
/// ```
#[must_use]
pub fn help_json() -> String {
    use crate::cli_args::json;
    let version = env!("CARGO_PKG_VERSION");

    let sections_arr: Vec<String> = sections()
        .iter()
        .map(|s| {
            let cmds = s
                .commands
                .iter()
                .map(|n| json::string(n))
                .collect::<Vec<_>>();
            json::object(&[
                ("title", json::string(s.title)),
                ("commands", json::array(&cmds)),
            ])
        })
        .collect();

    let commands_arr: Vec<String> = entries()
        .map(|c| {
            let text = c.text();
            let opts: Vec<String> = text
                .options
                .iter()
                .map(|o| {
                    json::object(&[
                        ("flag", json::string(o.flag)),
                        ("desc", json::string(o.desc)),
                    ])
                })
                .collect();
            json::object(&[
                ("name", json::string(c.name())),
                ("summary", json::string(text.summary)),
                ("args", json::string(text.args)),
                ("args_desc", json::string(text.args_desc)),
                (
                    "hidden",
                    if c.hidden() {
                        "true".to_owned()
                    } else {
                        "false".to_owned()
                    },
                ),
                ("options", json::array(&opts)),
            ])
        })
        .collect();

    let groups_arr: Vec<String> = GROUPS
        .iter()
        .map(|g| {
            let members = g
                .members
                .iter()
                .map(|m| json::string(m.verb.sub()))
                .collect::<Vec<_>>();
            json::object(&[
                ("name", json::string(g.name())),
                ("summary", json::string(g.summary())),
                ("members", json::array(&members)),
            ])
        })
        .collect();

    let obj = json::object(&[
        ("schema", json::string("ipe.cli.help/1")),
        ("version", json::string(version)),
        ("sections", json::array(&sections_arr)),
        ("groups", json::array(&groups_arr)),
        ("commands", json::array(&commands_arr)),
    ]);
    format!("{obj}\n")
}

/// Emit one command's grammar as a compact JSON object (schema `"ipe.cli.help/1"`).
///
/// Returns `None` when `name` is not a known command (the same condition
/// [`command`] returns `None` for).
#[must_use]
pub fn command_json(name: &str) -> Option<String> {
    use crate::cli_args::json;
    let c = find_entry(name)?;
    let text = c.text();
    let opts: Vec<String> = text
        .options
        .iter()
        .map(|o| {
            json::object(&[
                ("flag", json::string(o.flag)),
                ("desc", json::string(o.desc)),
            ])
        })
        .collect();
    let obj = json::object(&[
        ("schema", json::string("ipe.cli.help/1")),
        ("name", json::string(c.name())),
        ("summary", json::string(text.summary)),
        ("args", json::string(text.args)),
        ("args_desc", json::string(text.args_desc)),
        (
            "hidden",
            if c.hidden() {
                "true".to_owned()
            } else {
                "false".to_owned()
            },
        ),
        ("options", json::array(&opts)),
    ]);
    Some(format!("{obj}\n"))
}

/// Render one command's `--help` page: summary, synopsis, the positional
/// argument, then each option with its description.
///
/// The page is built flush-left, then indented once by the shared [`gutter`]
/// so every human line — this page IS a command's misuse output — sits off the
/// terminal edge at the one SSOT width. Within the gutter, `Arguments:` /
/// `Options:` bodies carry a further two-space indent so they read as nested
/// under their heading.
fn render_command(cmd: Entry, p: &Palette) -> String {
    let text = cmd.text();
    let mut out = String::new();
    out.push('\n');
    let _ = writeln!(out, "{}{}{}", p.dim, text.summary, p.reset);
    out.push('\n');
    out.push_str(&command_line(cmd.name(), text.args, p));
    out.push('\n');
    if !text.args_desc.is_empty() {
        out.push('\n');
        let _ = writeln!(out, "{}:", help_page::arguments_heading());
        let _ = writeln!(out, "  {}{}{}", p.dim, text.args_desc, p.reset);
    }
    if !text.options.is_empty() {
        out.push('\n');
        let _ = writeln!(out, "{}:", help_page::options_heading());
        let width = text.options.iter().map(|o| o.flag.len()).max().unwrap_or(0);
        for opt in &text.options {
            let _ = writeln!(
                out,
                "  {:<width$}  {}{}{}",
                opt.flag, p.dim, opt.desc, p.reset
            );
        }
    }
    out.push('\n');
    gutter(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bare build-producing names that live only in the refusal table.
    const LEGACY: [&str; 6] = ["build", "run", "watch", "exec", "eject", "release"];

    #[test]
    fn plain_top_level_names_every_command_and_section() {
        let plain = render_top_level(&Palette::PLAIN);
        for section in &sections() {
            assert!(
                plain.contains(section.title),
                "missing section {}",
                section.title
            );
        }
        for cmd in COMMANDS {
            if cmd.hidden {
                assert!(
                    !plain.contains(&format!("ipe {} ", cmd.name)),
                    "hidden command {} must not be advertised on the top-level screen",
                    cmd.name
                );
                continue;
            }
            assert!(
                plain.contains(&format!("ipe {}", cmd.name)),
                "missing command {}",
                cmd.name
            );
        }
        // Every group is advertised on the top-level screen as its own node.
        for g in GROUPS {
            assert!(
                plain.contains(&format!("ipe {}", g.name())),
                "missing group {}",
                g.name()
            );
        }
        assert!(!plain.contains('\x1b'), "plain output must carry no ANSI");
    }

    #[test]
    fn colored_palette_emits_ansi_plain_does_not() {
        // The colour vs plain rendering is what we assert here; the TTY /
        // NO_COLOR gating that chooses between them is exercised by the
        // integration tests, which own a real process environment.
        assert!(
            render_top_level(&Palette::COLOR).contains('\x1b'),
            "colour must carry ANSI"
        );
        assert!(
            !render_top_level(&Palette::PLAIN).contains('\x1b'),
            "plain must not"
        );
    }

    #[test]
    fn every_command_has_help_page() {
        for cmd in entries() {
            let page = render_command(cmd, &Palette::PLAIN);
            assert!(page.contains(&format!("ipe {}", cmd.name())));
            assert!(page.contains(cmd.text().summary));
        }
    }

    /// Every embedded `.md` page keeps the page shape.
    ///
    /// A summary, a synopsis naming its own command, one-line paragraphs,
    /// well-formed options, and only shared flags `help/flags.md` defines.
    #[test]
    fn every_help_page_parses_without_defects() {
        for cmd in entries() {
            let (_, defects) = help_page::parse_command_page(cmd.name(), cmd.page());
            assert!(defects.is_empty(), "`ipe {}` page: {defects:?}", cmd.name());
        }
        for g in GROUPS {
            assert!(
                !g.summary().is_empty(),
                "help/{}.md has no summary",
                g.name()
            );
        }
    }

    /// Every `.md` under `help/` is embedded.
    ///
    /// Each is a command page, a grouped verb page, a group page, the shared
    /// flags, or the overview layout — no orphan text a dev could edit to no
    /// effect.
    #[test]
    fn every_help_md_file_is_embedded() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("help");
        let entries = std::fs::read_dir(&dir);
        assert!(entries.is_ok(), "cannot read {}", dir.display());
        for entry in entries.into_iter().flatten().flatten() {
            let path = entry.path();
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            assert!(
                find_entry(stem).is_some() || is_group(stem) || stem == "index" || stem == "flags",
                "help/{stem}.md is not embedded by any command, group, or page"
            );
        }
    }

    /// The terminal page renders the `.md` wording verbatim: the summary line,
    /// the synopsis, and every option's flag and description.
    #[test]
    fn the_terminal_page_carries_the_md_wording() {
        for cmd in entries() {
            let text = cmd.text();
            let page = render_command(cmd, &Palette::PLAIN);
            let first_line = cmd.page().lines().next().unwrap_or_default();
            assert_eq!(text.summary, first_line.trim(), "`ipe {}`", cmd.name());
            assert!(page.contains(first_line.trim()), "{page}");
            for opt in &text.options {
                assert!(
                    page.contains(opt.flag) && page.contains(opt.desc),
                    "`ipe {} --help` omits {opt:?}",
                    cmd.name()
                );
            }
        }
    }

    #[test]
    fn commands_with_an_argument_describe_it() {
        for cmd in entries() {
            let text = cmd.text();
            if text.args_desc.is_empty() {
                continue;
            }
            let page = render_command(cmd, &Palette::PLAIN);
            assert!(
                page.contains("Arguments:") && page.contains(text.args_desc),
                "missing argument description for {}",
                cmd.name()
            );
        }
    }

    #[test]
    fn section_commands_show_an_aligned_help_suffix() {
        let plain = render_top_level(&Palette::PLAIN);
        for section in &sections() {
            // Every command line in a section carries a copy-pasteable `--help`,
            // and within the section the `--help` column is vertically aligned.
            let mut help_columns = Vec::new();
            for &name in &section.commands {
                let needle = format!("ipe {name} ");
                let col = plain
                    .lines()
                    .find(|l| l.trim_start().starts_with(&needle))
                    .and_then(|l| l.find("--help"));
                assert!(
                    col.is_some(),
                    "`ipe {name}` in {} must render a copy-pasteable --help suffix",
                    section.title
                );
                help_columns.extend(col);
            }
            assert!(
                help_columns
                    .windows(2)
                    .all(|w| matches!(w, [a, b] if a == b)),
                "`--help` column misaligned in section {}: {help_columns:?}",
                section.title
            );
        }
    }

    #[test]
    fn sections_reference_only_known_nodes() {
        // A section entry names either a top-level command or a group node.
        for section in &sections() {
            for &name in &section.commands {
                assert!(
                    is_command(name) || is_group(name),
                    "section lists unknown node {name}"
                );
            }
        }
    }

    #[test]
    fn every_command_appears_in_exactly_one_section() {
        for cmd in COMMANDS {
            let in_sections = sections()
                .iter()
                .flat_map(|s| s.commands.iter())
                .filter(|&&n| n == cmd.name)
                .count();
            // A visible command is advertised exactly once; a hidden one nowhere.
            let expected = usize::from(!cmd.hidden);
            assert_eq!(
                in_sections, expected,
                "command {} must appear in {expected} section(s), found {in_sections}",
                cmd.name
            );
        }
    }

    #[test]
    fn every_group_appears_in_exactly_one_section() {
        for g in GROUPS {
            let count = sections()
                .iter()
                .flat_map(|s| s.commands.iter())
                .filter(|&&n| n == g.name())
                .count();
            assert_eq!(
                count,
                1,
                "group {} must appear in exactly one section, found {count}",
                g.name()
            );
        }
    }

    /// Every [`Verb`] is described exactly once, under its own umbrella's
    /// group, and no group lists a verb of another umbrella.
    #[test]
    fn every_verb_belongs_to_exactly_its_umbrella_group() {
        for verb in Verb::ALL {
            let owners: Vec<&Group> = GROUPS
                .iter()
                .filter(|g| g.members.iter().any(|m| m.verb == verb))
                .collect();
            assert!(
                matches!(owners.as_slice(), [g] if g.umbrella == verb.umbrella()),
                "verb {verb} must be in exactly its umbrella's group"
            );
            assert_eq!(group_member(verb.umbrella().name(), verb.sub()), Some(verb));
        }
        assert_eq!(members().count(), Verb::ALL.len());
        for umbrella in Umbrella::ALL {
            assert_eq!(
                GROUPS.iter().filter(|g| g.umbrella == umbrella).count(),
                1,
                "umbrella {} must have exactly one group",
                umbrella.name()
            );
        }
    }

    #[test]
    fn group_subpage_lists_every_verb() {
        for g in GROUPS {
            let page = render_group(g, &Palette::PLAIN);
            assert!(page.contains(&format!("ipe {} <verb>", g.name())));
            for m in g.members {
                assert!(
                    page.contains(&format!("ipe {}", m.verb)),
                    "group {} subpage omits verb {}",
                    g.name(),
                    m.verb
                );
            }
            assert!(!page.contains('\x1b'), "plain subpage must carry no ANSI");
        }
    }

    /// `add`/`remove` are withheld from the top-level screen while their only
    /// outcome is a manual-step message, yet they stay dispatchable and keep a
    /// `--help` page — de-advertised, never removed.
    #[test]
    fn add_and_remove_are_hidden_but_dispatchable() {
        for name in ["add", "remove"] {
            let found = find(name);
            assert!(found.is_some(), "{name} must stay in the registry");
            let Some(cmd) = found else {
                return;
            };
            assert!(
                cmd.hidden,
                "{name} must be hidden from the top-level screen"
            );
            assert!(handler(name).is_some(), "{name} must stay dispatchable");
            // Its per-command help page still renders (documentation survives).
            let page = render_command(Entry::Command(cmd), &Palette::PLAIN);
            assert!(page.contains(&format!("ipe {name}")));
        }
        // Neither appears on the top-level screen.
        let plain = render_top_level(&Palette::PLAIN);
        assert!(!plain.contains("ipe add "), "add must not be advertised");
        assert!(
            !plain.contains("ipe remove "),
            "remove must not be advertised"
        );
    }

    // The single-source-of-truth invariant: dispatch and advertisement are the
    // same table, so every advertised command is dispatchable and vice versa.
    // A command described but unhandled — or handled but undescribed — is not
    // representable, and this pins that the registry is the sole driver.
    #[test]
    fn every_advertised_command_is_dispatchable() {
        for name in command_names() {
            assert!(
                handler(name).is_some(),
                "advertised command {name} has no dispatch handler"
            );
        }
    }

    /// A bare build-producing name has no help page, no handler, and no doc
    /// key: the refusal table is its only representation.
    #[test]
    fn legacy_names_have_no_page_and_no_handler() {
        for name in LEGACY {
            assert!(!is_command(name), "`{name}` must not be a command");
            assert!(handler(name).is_none(), "`{name}` must not dispatch");
            assert!(
                command(name, &std::io::stdout()).is_none(),
                "`{name}` must have no help page"
            );
            assert!(command_json(name).is_none());
            assert!(!documented_command_keys().contains(&name));
        }
    }

    /// `ipe build --help` (and every other legacy name with a help flag) is
    /// refused with [`CliError::GroupRequired`] naming the grouped forms — it
    /// never renders a page.
    #[test]
    fn legacy_help_is_refusal() {
        for name in ["build", "run", "watch", "exec", "eject"] {
            let argv = [name.to_owned(), "--help".to_owned()];
            let result = crate::driver::run_cli(&argv);
            assert!(
                matches!(
                    &result,
                    Err(CliError::GroupRequired { attempted, forms, .. })
                        if attempted.as_str() == name && !forms.is_empty()
                ),
                "`ipe {name} --help` must be refused naming a grouped form, got {result:?}"
            );
        }
    }

    /// `exec` is refused, its hint naming `release run`.
    #[test]
    fn exec_is_refused_with_release_run_hint() {
        assert!(!is_command("exec"));
        let result = crate::driver::run_cli(&["exec".to_owned()]);
        assert!(
            matches!(
                result,
                Err(CliError::GroupRequired {
                    forms: [Verb::RELEASE_RUN],
                    ..
                })
            ),
            "got {result:?}"
        );
    }

    /// Split a help `Opt.flag` field (`[-q|--quiet]`, `[--out <dir>]`,
    /// `[-- <args>...]`) into the dashed option tokens it advertises, dropping the
    /// surrounding brackets, the `<value>` placeholders, and the bare `--`
    /// forwarding separator (which no parser treats as an option).
    fn advertised_flag_tokens(field: &str) -> Vec<String> {
        field
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(['|', ' '])
            .map(str::trim)
            .filter(|tok| tok.starts_with('-') && *tok != "--")
            .map(str::to_owned)
            .collect()
    }

    /// A flag advertised in help must be accepted by the command's parser: run
    /// the parser with just that flag (a dummy value for a value flag) and assert
    /// it never rejects the flag as unknown. This closes the help/parser drift
    /// that let real working flags go undocumented.
    fn assert_help_flags_are_accepted(
        command: &str,
        parse: impl Fn(&[String]) -> Result<(), crate::CliError>,
    ) {
        let found = find_entry(command);
        assert!(found.is_some(), "`ipe {command}` has no help page");
        let Some(cmd) = found else {
            return;
        };
        for opt in &cmd.text().options {
            let takes_value = opt.flag.contains('<');
            for tok in advertised_flag_tokens(opt.flag) {
                let mut argv = vec![tok.clone()];
                if takes_value {
                    argv.push("x".to_owned());
                }
                let unknown = format!("unknown flag `{tok}`");
                if let Err(err) = parse(&argv) {
                    assert!(
                        !err.to_string().contains(&unknown),
                        "`ipe {command}` help advertises `{tok}` but its parser rejects it as unknown"
                    );
                }
            }
        }
    }

    #[test]
    fn advertised_flags_are_accepted_by_their_parser() {
        assert_help_flags_are_accepted(Verb::DEV_BUILD.name(), |a| {
            crate::cli_args::parse_build(a).map(|_| ())
        });
        assert_help_flags_are_accepted(Verb::DEV_RUN.name(), |a| {
            crate::cli_args::parse_run(a).map(|_| ())
        });
        assert_help_flags_are_accepted(Verb::DEV_WATCH.name(), |a| {
            crate::cli_args::parse_watch(a).map(|_| ())
        });
        assert_help_flags_are_accepted(Verb::RELEASE_BUILD.name(), |a| {
            crate::cli_args::parse_release_build(a).map(|_| ())
        });
        assert_help_flags_are_accepted(Verb::RELEASE_EJECT.name(), |a| {
            crate::cli_args::parse_eject(a).map(|_| ())
        });
        assert_help_flags_are_accepted("fix", |a| crate::cli_args::parse_fix(a).map(|_| ()));
        assert_help_flags_are_accepted("type-check", |a| {
            crate::cli_args::parse_type_check(a).map(|_| ())
        });
        assert_help_flags_are_accepted("health", |a| crate::cli_args::parse_health(a).map(|_| ()));
        assert_help_flags_are_accepted("fmt", |a| crate::cli_args::parse_fmt(a).map(|_| ()));
        assert_help_flags_are_accepted("lint", |a| crate::lint::parse_lint_args(a).map(|_| ()));
        assert_help_flags_are_accepted("clean", |a| crate::clean::parse_clean_args(a).map(|_| ()));
    }

    /// `help_json` emits valid JSON covering every command and section.
    #[test]
    fn help_json_covers_all_commands_and_sections() {
        let json = help_json();
        // Schema tag and version must be present.
        assert!(
            json.contains("\"ipe.cli.help/1\""),
            "schema tag missing from help_json"
        );
        // Every command name must appear.
        for cmd in entries() {
            assert!(
                json.contains(&format!("\"{}\"", cmd.name())),
                "command {} missing from help_json",
                cmd.name()
            );
        }
        // Every section title must appear.
        for section in &sections() {
            assert!(
                json.contains(section.title),
                "section {} missing from help_json",
                section.title
            );
        }
        // Output is not empty and ends with a newline.
        assert!(json.ends_with('\n'), "help_json must end with a newline");
        assert!(
            !json.contains('\x1b'),
            "help_json must carry no ANSI escapes"
        );
    }

    /// `command_json` returns a per-command object for every known command and
    /// grouped verb, and `None` for an unknown name.
    #[test]
    fn command_json_returns_per_command_object() {
        let version = command_json("version");
        assert!(
            version
                .as_deref()
                .is_some_and(|j| j.contains("\"ipe.cli.help/1\"")
                    && j.contains("\"version\"")
                    && j.ends_with('\n')),
            "version must be a known command with a schema-tagged page"
        );
        for verb in Verb::ALL {
            let by_name = command_json(verb.name());
            assert!(
                by_name.as_deref().is_some_and(|j| j.contains(verb.name())),
                "{verb} must have a JSON page"
            );
            assert_eq!(command_json(verb.help_key()), by_name);
        }
        // Unknown command returns None.
        assert!(command_json("no-such-command").is_none());
    }
}
