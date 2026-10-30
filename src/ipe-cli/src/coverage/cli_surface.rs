//! The CLI surface: one reconciled enumeration of every `ipe` subcommand and
//! each of its flags.
//!
//! The surface reads the canonical [`crate::help::COMMANDS`] table (via
//! [`crate::help::all_command_specs`]) so a command or flag added there
//! automatically appears here — there is no separate list to maintain.
//!
//! Each [`CliItem`] is either the subcommand itself (its name + summary are the
//! documented facets) or one of its flags (the flag synopsis + description are
//! the documented facets). The three aspect columns judge every item on:
//!
//! - **documented**: the summary/description is non-empty — a subcommand with
//!   no summary, or a flag with no description, is a hole.
//! - **tested**: at least one standing test in the `tests/` tree invokes this
//!   subcommand or flag.
//! - **not-advertised-unimplemented**: a subcommand or flag whose handler
//!   contains `todo!()` or `unimplemented!()` is a hole — the anti-advertise
//!   gate.

use crate::coverage::contract::Surface;
use crate::help::{CommandSpec, FlagSpec};

/// One item of the CLI surface: a subcommand or one of its flags.
#[derive(Clone, Debug)]
pub enum CliItem {
    /// The subcommand itself, carrying its name and one-line summary.
    Subcommand {
        /// The subcommand name (e.g. `"build"`).
        name: &'static str,
        /// The one-line summary from the help table.
        summary: &'static str,
    },
    /// One flag of a subcommand.
    Flag {
        /// The subcommand the flag belongs to.
        command: &'static str,
        /// The flag synopsis as it appears in the help table (e.g. `"[--out <dir>]"`).
        flag: &'static str,
        /// The flag's one-line description.
        desc: &'static str,
    },
}

impl CliItem {
    /// A stable dotted label: `build` for a subcommand, `build/--out` for a
    /// flag.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Subcommand { name, .. } => (*name).to_owned(),
            Self::Flag { command, flag, .. } => {
                // Strip the `[` `]` wrappers and any value placeholder so the
                // label is just the bare flag token.
                let bare = flag
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .split_whitespace()
                    .next()
                    .unwrap_or(flag);
                format!("{command}/{bare}")
            }
        }
    }

    /// The command name this item belongs to.
    #[must_use]
    pub const fn command_name(&self) -> &'static str {
        match self {
            Self::Subcommand { name, .. } => name,
            Self::Flag { command, .. } => command,
        }
    }
}

/// The CLI surface: zero-sized, reads [`crate::help::all_command_specs`] on
/// each [`Surface::all`].
#[derive(Clone, Copy, Debug, Default)]
pub struct CliSurface;

impl Surface for CliSurface {
    type Item = CliItem;

    fn name(&self) -> &'static str {
        "cli"
    }

    fn all(&self) -> Result<Vec<CliItem>, crate::coverage::error::CoverageError> {
        let mut items = Vec::new();
        for spec in crate::help::all_command_specs() {
            // One row for the subcommand itself.
            items.push(subcommand_item(&spec));
            // One row per flag.
            for flag_spec in &spec.options {
                items.push(flag_item(spec.name, flag_spec));
            }
        }
        // Deterministic: the help table is in declaration order, which is
        // stable across runs. No further sort needed — order is owned by the
        // SSOT.
        Ok(items)
    }

    fn label(item: &CliItem) -> String {
        item.label()
    }
}

const fn subcommand_item(spec: &CommandSpec) -> CliItem {
    CliItem::Subcommand {
        name: spec.name,
        summary: spec.summary,
    }
}

const fn flag_item(command: &'static str, flag: &FlagSpec) -> CliItem {
    CliItem::Flag {
        command,
        flag: flag.flag,
        desc: flag.desc,
    }
}
