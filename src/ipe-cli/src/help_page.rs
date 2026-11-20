//! The `.md` help pages — the single source of every `ipe` help and usage text.
//!
//! * `help/<command>.md` — one command's summary, synopsis, arguments, options,
//!   and (optionally) where its output lands;
//! * `help/flags.md` — the flags several commands share, described once; a
//!   command page cites one as `- @--flag`;
//! * `help/index.md` — the top-level overview's sections, in display order;
//! * `help/<group>.md` — a command group's one-line summary, then an optional
//!   one-line note.
//!
//! The binary embeds the pages (`include_str!`). The terminal `--help`,
//! `--help --json`, the HTML command pages, `ipe doc <command>`, and the
//! generated `docs/reference/cli.md` all render from them, and tests assert
//! against them. Edit the `.md`, never a Rust string.
//!
//! A command page reads:
//!
//! ````text
//! <summary, one line>
//!
//! ```
//! ipe <command> <arguments synopsis>
//! ```
//!
//! ## Arguments
//!
//! - `<placeholder, exactly as the synopsis spells it>` — <description, one line>
//!
//! ## Subcommands
//!
//! - `<subcommand name>` — <description, one line>
//!
//! ## Notes
//!
//! - <a remark that belongs to no single argument, one line>
//!
//! ## Options
//!
//! - `<flag synopsis>` — <description, one line>
//! - @--<shared flag>
//!
//! ## Output
//!
//! <where the output lands, one line>
//! ````
//!
//! Every section is optional except the summary and the synopsis. Arguments
//! and Subcommands are lists in the same `- `name` — desc` shape as Options;
//! Notes is a list of bare `- <text>` lines. Every `<placeholder>` the
//! synopsis spells without a `|` alternation must have exactly one matching
//! Arguments item, and every Arguments item must name a placeholder the
//! synopsis actually spells. Parsing is total: a page that strays from the
//! shape still renders, and the defects it reports are pinned empty by the
//! page tests, so a malformed page cannot ship.

/// The heading of a page's argument list.
#[must_use]
pub const fn arguments_heading() -> &'static str {
    crate::text::help_arguments_label()
}
/// The heading of a page's subcommand list.
#[must_use]
pub const fn subcommands_heading() -> &'static str {
    crate::text::help_subcommands_label()
}
/// The heading of a page's notes list.
#[must_use]
pub const fn notes_heading() -> &'static str {
    crate::text::help_notes_label()
}
/// The heading of a page's option list.
#[must_use]
pub const fn options_heading() -> &'static str {
    crate::text::help_options_label()
}
/// The heading of a page's output-location note.
#[must_use]
pub const fn output_heading() -> &'static str {
    crate::text::help_output_label()
}

/// The shared-flags page.
pub const FLAGS_PAGE: &str = include_str!("../help/flags.md");
/// The top-level overview's section layout.
pub const INDEX_PAGE: &str = include_str!("../help/index.md");

/// One option: its synopsis (`[--out <dir>]`, keeping the `[]` optional syntax)
/// and a one-line description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opt {
    /// The flag as it appears in a synopsis, with its `[]` and any value
    /// placeholder.
    pub flag: &'static str,
    /// What the flag does, one line.
    pub desc: &'static str,
}

/// One Arguments or Subcommands list item: a synopsis placeholder (or a
/// subcommand's bare name) and its one-line description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArgText {
    /// The placeholder exactly as the synopsis spells it (`[]`/`<>`/`...`
    /// included), or a subcommand's bare name.
    pub name: &'static str,
    /// What it does, one line.
    pub desc: &'static str,
}

/// The text of one command's help page, parsed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommandText {
    /// The one-line description of the command.
    pub summary: &'static str,
    /// The positional-argument synopsis after `ipe <command>`; empty when none.
    pub args: &'static str,
    /// The argument list, in page order; empty when the command takes no
    /// argument.
    pub arguments: Vec<ArgText>,
    /// Remarks that belong to no single argument, in page order.
    pub notes: Vec<&'static str>,
    /// The subcommand list, in page order; empty when the command has none.
    pub subcommands: Vec<ArgText>,
    /// The options, in page order (shared flags resolved).
    pub options: Vec<Opt>,
    /// Where the command's primary output lands; empty when not documented.
    pub output_desc: &'static str,
}

/// One top-level overview section: its title and its command / group names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionText {
    /// The section title.
    pub title: &'static str,
    /// The command and group names, in display order.
    pub commands: Vec<&'static str>,
}

/// A way a page strays from its shape. The page tests pin every page's defect
/// list empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PageDefect {
    /// The page has no summary line before its synopsis.
    MissingSummary,
    /// The page has no fenced `ipe <command>` synopsis.
    MissingSynopsis,
    /// The synopsis fence is never closed.
    UnclosedSynopsis,
    /// The synopsis line does not start with `ipe <command>`.
    SynopsisNamesAnotherCommand(&'static str),
    /// A `##` heading the page shape does not define.
    UnknownSection(&'static str),
    /// A second line where the shape allows exactly one (paragraphs are one
    /// line each), or text outside any section.
    StrayLine(&'static str),
    /// An option line that is neither `- `flag` — desc` nor `- @--flag`.
    MalformedOption(&'static str),
    /// A `- @--flag` citing a flag `flags.md` does not define.
    UnknownSharedFlag(&'static str),
    /// An Arguments line that is not `- `name` — desc`.
    MalformedArgument(&'static str),
    /// A Subcommands line that is not `- `name` — desc`.
    MalformedSubcommand(&'static str),
    /// A Notes line that is not `- <text>`.
    MalformedNote(&'static str),
    /// A synopsis placeholder (no `|` alternation in the synopsis) with no
    /// matching Arguments item.
    ArgumentMissingForPlaceholder(&'static str),
    /// An Arguments item naming a placeholder the synopsis does not spell.
    ArgumentNotInSynopsis(&'static str),
}

/// Parse `- `<name>` — <desc>` into an [`ArgText`] (shared shape with [`Opt`]).
fn parse_item_line(line: &'static str) -> Option<ArgText> {
    parse_option_line(line).map(|opt| ArgText {
        name: opt.flag,
        desc: opt.desc,
    })
}

/// Parse a bare `- <text>` note line.
fn parse_note_line(line: &'static str) -> Option<&'static str> {
    let text = line.trim().strip_prefix("- ")?.trim();
    (!text.is_empty()).then_some(text)
}

/// Parse `- `<flag>` — <desc>` into an [`Opt`].
fn parse_option_line(line: &'static str) -> Option<Opt> {
    let (flag, desc) = line.trim().strip_prefix("- `")?.split_once("` — ")?;
    let desc = desc.trim();
    (!flag.is_empty() && !desc.is_empty()).then_some(Opt { flag, desc })
}

/// The long flag a shared-flag entry is cited by: the first `--name` token of
/// its synopsis (`[-q|--quiet]` → `--quiet`).
#[must_use]
pub fn shared_flag_key(flag: &str) -> Option<&str> {
    flag.split(['|', ' ', '[', ']'])
        .find(|token| token.len() > 2 && token.starts_with("--"))
}

/// The shared flags `help/flags.md` defines.
#[must_use]
pub fn shared_flags() -> Vec<Opt> {
    FLAGS_PAGE.lines().filter_map(parse_option_line).collect()
}

/// Where the parser stands within a command page.
#[derive(Clone, Copy)]
enum At {
    /// Before the synopsis: the summary.
    Lead,
    /// Inside the synopsis fence.
    Synopsis,
    /// After the synopsis, under the named `##` heading (none yet → `None`).
    Section(Option<&'static str>),
}

/// Fill a one-line `slot`, or report a second line as stray.
fn set_once(slot: &mut &'static str, line: &'static str, defects: &mut Vec<PageDefect>) {
    if slot.is_empty() {
        *slot = line.trim();
    } else {
        defects.push(PageDefect::StrayLine(line));
    }
}

/// Parse command `name`'s `page`: its text, plus every defect found. Total —
/// never fails; a defect-free page is what the page tests require.
#[must_use]
pub fn parse_command_page(name: &str, page: &'static str) -> (CommandText, Vec<PageDefect>) {
    let shared = shared_flags();
    let mut text = CommandText::default();
    let mut defects = Vec::new();
    let mut at = At::Lead;
    let mut synopsis_seen = false;

    for line in page.lines() {
        let trimmed = line.trim();
        if matches!(at, At::Synopsis) {
            if trimmed == "```" {
                at = At::Section(None);
            } else if synopsis_seen {
                defects.push(PageDefect::StrayLine(line));
            } else {
                synopsis_seen = true;
                let args = trimmed
                    .strip_prefix("ipe ")
                    .and_then(|rest| rest.strip_prefix(name))
                    .filter(|rest| rest.is_empty() || rest.starts_with(' '));
                match args {
                    Some(args) => text.args = args.trim(),
                    None => defects.push(PageDefect::SynopsisNamesAnotherCommand(line)),
                }
            }
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "```" {
            if matches!(at, At::Lead) {
                at = At::Synopsis;
            } else {
                defects.push(PageDefect::StrayLine(line));
            }
            continue;
        }
        if let Some(heading) = trimmed.strip_prefix("## ") {
            let heading = heading.trim();
            if ![
                arguments_heading(),
                subcommands_heading(),
                notes_heading(),
                options_heading(),
                output_heading(),
            ]
            .contains(&heading)
            {
                defects.push(PageDefect::UnknownSection(heading));
            }
            at = At::Section(Some(heading));
            continue;
        }
        match at {
            At::Lead => set_once(&mut text.summary, line, &mut defects),
            At::Section(Some(heading)) if heading == arguments_heading() => {
                match parse_item_line(line) {
                    Some(item) => text.arguments.push(item),
                    None => defects.push(PageDefect::MalformedArgument(line)),
                }
            }
            At::Section(Some(heading)) if heading == subcommands_heading() => {
                match parse_item_line(line) {
                    Some(item) => text.subcommands.push(item),
                    None => defects.push(PageDefect::MalformedSubcommand(line)),
                }
            }
            At::Section(Some(heading)) if heading == notes_heading() => {
                match parse_note_line(line) {
                    Some(note) => text.notes.push(note),
                    None => defects.push(PageDefect::MalformedNote(line)),
                }
            }
            At::Section(Some(heading)) if heading == output_heading() => {
                set_once(&mut text.output_desc, line, &mut defects);
            }
            At::Section(Some(heading)) if heading == options_heading() => {
                if let Some(key) = trimmed.strip_prefix("- @") {
                    match shared
                        .iter()
                        .find(|opt| shared_flag_key(opt.flag) == Some(key.trim()))
                    {
                        Some(opt) => text.options.push(*opt),
                        None => defects.push(PageDefect::UnknownSharedFlag(line)),
                    }
                } else if let Some(opt) = parse_option_line(line) {
                    text.options.push(opt);
                } else {
                    defects.push(PageDefect::MalformedOption(line));
                }
            }
            At::Section(_) | At::Synopsis => defects.push(PageDefect::StrayLine(line)),
        }
    }

    if matches!(at, At::Synopsis) {
        defects.push(PageDefect::UnclosedSynopsis);
    }
    if !synopsis_seen {
        defects.push(PageDefect::MissingSynopsis);
    }
    if text.summary.is_empty() {
        defects.push(PageDefect::MissingSummary);
    }
    for item in &text.arguments {
        if !text.args.contains(item.name) {
            defects.push(PageDefect::ArgumentNotInSynopsis(item.name));
        }
    }
    // A synopsis that alternates (`|`) describes the alternation by hand
    // (often as a `## Subcommands` list); only a non-alternating synopsis is
    // checked placeholder-by-placeholder.
    if !text.args.contains('|') {
        for token in text.args.split_whitespace().filter(|t| t.contains('<')) {
            if text.arguments.iter().filter(|a| a.name == token).count() != 1 {
                defects.push(PageDefect::ArgumentMissingForPlaceholder(token));
            }
        }
    }
    (text, defects)
}

/// The one-line summary a group page holds: its first non-blank line.
#[must_use]
pub fn summary_of(page: &'static str) -> &'static str {
    page.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
}

/// The optional one-line note a group page holds: its second non-blank line.
#[must_use]
pub fn note_of(page: &'static str) -> Option<&'static str> {
    page.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .nth(1)
}

/// Parse the overview layout (`help/index.md`): `## <title>` headings, each
/// followed by `- <command>` lines. Total, like [`parse_command_page`].
#[must_use]
pub fn parse_index(page: &'static str) -> (Vec<SectionText>, Vec<PageDefect>) {
    let mut sections: Vec<SectionText> = Vec::new();
    let mut defects = Vec::new();
    for line in page.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(title) = trimmed.strip_prefix("## ") {
            sections.push(SectionText {
                title: title.trim(),
                commands: Vec::new(),
            });
        } else if let (Some(name), Some(section)) =
            (trimmed.strip_prefix("- "), sections.last_mut())
        {
            section.commands.push(name.trim());
        } else {
            defects.push(PageDefect::StrayLine(line));
        }
    }
    (sections, defects)
}

/// The top-level overview's sections, in display order.
#[must_use]
pub fn sections() -> Vec<SectionText> {
    parse_index(INDEX_PAGE).0
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "Do a thing.\n\n```\nipe thing [<path>]\n```\n\n## Arguments\n\n\
                        - `[<path>]` — the path\n\n## Notes\n\n- it does the thing\n\n\
                        ## Options\n\n- `[--x]` — the x flag\n- @--quiet\n";

    #[test]
    fn a_well_formed_page_parses_without_defects() {
        let (text, defects) = parse_command_page("thing", GOOD);
        assert!(defects.is_empty(), "{defects:?}");
        assert_eq!(text.summary, "Do a thing.");
        assert_eq!(text.args, "[<path>]");
        assert_eq!(
            text.arguments,
            vec![ArgText {
                name: "[<path>]",
                desc: "the path"
            }]
        );
        assert_eq!(text.notes, vec!["it does the thing"]);
        assert_eq!(text.options.len(), 2);
        assert!(matches!(
            text.options.first(),
            Some(Opt {
                flag: "[--x]",
                desc: "the x flag"
            })
        ));
        assert!(matches!(
            text.options.get(1),
            Some(Opt { flag, .. }) if flag.contains("--quiet")
        ));
    }

    #[test]
    fn arguments_and_notes_refuse_prose() {
        let (_, d) = parse_command_page(
            "thing",
            "Sum.\n```\nipe thing [<path>]\n```\n## Arguments\nThe path.\n",
        );
        assert!(
            d.contains(&PageDefect::MalformedArgument("The path.")),
            "{d:?}"
        );
        let (_, d) = parse_command_page(
            "thing",
            "Sum.\n```\nipe thing [<path>]\n```\n## Arguments\n- `[<path>]` — the path\n\
             ## Notes\nA remark.\n",
        );
        assert!(d.contains(&PageDefect::MalformedNote("A remark.")), "{d:?}");
    }

    #[test]
    fn a_placeholder_and_its_item_must_match_both_ways() {
        // A placeholder with no item.
        let (_, d) = parse_command_page("thing", "Sum.\n```\nipe thing [<path>]\n```\n");
        assert!(
            d.contains(&PageDefect::ArgumentMissingForPlaceholder("[<path>]")),
            "{d:?}"
        );
        // An item naming a placeholder absent from the synopsis.
        let (_, d) = parse_command_page(
            "thing",
            "Sum.\n```\nipe thing\n```\n## Arguments\n- `[<path>]` — the path\n",
        );
        assert!(
            d.contains(&PageDefect::ArgumentNotInSynopsis("[<path>]")),
            "{d:?}"
        );
        // An alternating synopsis is exempt from the forward direction.
        let (_, d) = parse_command_page(
            "thing",
            "Sum.\n```\nipe thing <a|b>\n```\n## Subcommands\n- `a` — does a\n- `b` — does b\n",
        );
        assert!(
            !d.iter()
                .any(|def| matches!(def, PageDefect::ArgumentMissingForPlaceholder(_))),
            "{d:?}"
        );
    }

    #[test]
    fn malformed_pages_report_their_defects() {
        let (_, d) = parse_command_page("thing", "```\nipe other\n```\n");
        assert!(d.contains(&PageDefect::MissingSummary), "{d:?}");
        assert!(
            d.contains(&PageDefect::SynopsisNamesAnotherCommand("ipe other")),
            "{d:?}"
        );
        let (_, d) = parse_command_page("thing", "Sum.\n");
        assert!(d.contains(&PageDefect::MissingSynopsis), "{d:?}");
        let (_, d) = parse_command_page("thing", "Sum.\n```\nipe thing\n");
        assert!(d.contains(&PageDefect::UnclosedSynopsis), "{d:?}");
        let (_, d) = parse_command_page(
            "thing",
            "Sum.\n```\nipe thing\n```\n## Options\n- --bad\n- @--nope\n## Extra\n",
        );
        assert!(d.contains(&PageDefect::MalformedOption("- --bad")), "{d:?}");
        assert!(
            d.contains(&PageDefect::UnknownSharedFlag("- @--nope")),
            "{d:?}"
        );
        assert!(d.contains(&PageDefect::UnknownSection("Extra")), "{d:?}");
        let (_, d) = parse_command_page("thing", "Sum.\nMore.\n```\nipe thing\n```\n");
        assert!(d.contains(&PageDefect::StrayLine("More.")), "{d:?}");
    }

    #[test]
    fn a_synopsis_must_name_the_command_exactly() {
        let (_, d) = parse_command_page("run", "Sum.\n```\nipe runner\n```\n");
        assert!(
            d.contains(&PageDefect::SynopsisNamesAnotherCommand("ipe runner")),
            "{d:?}"
        );
    }

    #[test]
    fn shared_flags_are_unique_by_key_and_well_formed() {
        let flags = shared_flags();
        assert!(!flags.is_empty());
        let option_lines = FLAGS_PAGE
            .lines()
            .filter(|l| l.trim_start().starts_with("- "))
            .count();
        assert_eq!(option_lines, flags.len(), "a malformed flags.md entry");
        for (i, flag) in flags.iter().enumerate() {
            let key = shared_flag_key(flag.flag);
            assert!(key.is_some(), "shared flag without a --name: {flag:?}");
            assert!(
                flags
                    .iter()
                    .skip(i + 1)
                    .all(|other| shared_flag_key(other.flag) != key),
                "two shared flags share the key {key:?}"
            );
        }
    }

    #[test]
    fn the_index_parses_without_defects() {
        let (sections, defects) = parse_index(INDEX_PAGE);
        assert!(defects.is_empty(), "{defects:?}");
        assert!(sections.iter().all(|s| !s.commands.is_empty()));
    }
}
