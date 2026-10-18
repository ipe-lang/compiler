//! The run guard: an output keeps every comment with its owner, every
//! adjacent pair of comments together with its gap, and every run directly
//! above a head with its gap to that head.
//!
//! Comments are compared by text, so a permutation among comments of equal
//! text is invisible to it.

use std::fmt;

use ipe_syntax::Module;

use super::comments::{Comment, CommentKey, Gap};
use super::{CodeToken, Trivia, decl_start, module_decls};

/// The top-level item a comment belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Owner {
    /// The module header, up to the first import or declaration.
    Header,
    /// The import block.
    Imports,
    /// The declaration at this index, in source order.
    Decl(usize),
    /// The comments after the last token of the file.
    Trailing,
}

impl fmt::Display for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header => f.write_str("the module header"),
            Self::Imports => f.write_str("the imports"),
            Self::Decl(index) => write!(f, "declaration {}", index.saturating_add(1)),
            Self::Trailing => f.write_str("the trailing comments"),
        }
    }
}

/// How an output broke a comment run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunFault {
    /// A comment moved to another owner.
    OwnerMultiset,
    /// Two adjacent comments were split apart or re-spaced.
    Adjacency,
    /// The run directly above a head changed its comments or its gaps.
    HeadRun,
}

impl fmt::Display for RunFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OwnerMultiset => "a comment moved to another owner",
            Self::Adjacency => "two adjacent comments were split apart or re-spaced",
            Self::HeadRun => "the run above a head changed its comments or its gaps",
        })
    }
}

/// Why [`check`] refused an output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The output has another number of declarations.
    DeclCount,
    /// The output broke a comment run of `owner`.
    Run { owner: Owner, fault: RunFault },
}

/// Refuse `output` as a print of `input` unless every comment run survives.
///
/// Returns how many non-empty runs sat directly above a head in the input.
///
/// # Errors
/// [`Refusal::DeclCount`] when the modules differ in declaration count;
/// [`Refusal::Run`] when a comment changed owner, an adjacent pair split or
/// re-spaced, or a head run changed.
pub fn check(
    module: &Module,
    input: &Trivia,
    reparsed: &Module,
    output: &Trivia,
) -> Result<usize, Refusal> {
    let before = Layout::of(module, &input.code);
    let after = Layout::of(reparsed, &output.code);
    if before.starts.len() != after.starts.len() {
        return Err(Refusal::DeclCount);
    }
    owners_kept(&before, &input.comments, &after, &output.comments)?;
    pairs_kept(&before, &input.comments, &after, &output.comments)?;
    head_runs_kept(&before, &input.comments, &after, &output.comments)
}

/// Where a module's top-level items start.
struct Layout {
    module: usize,
    first_import: Option<usize>,
    starts: Vec<usize>,
}

impl Layout {
    fn of(m: &Module, code: &[CodeToken]) -> Self {
        let mut starts: Vec<usize> = module_decls(m)
            .iter()
            .map(|d| decl_start(code, d))
            .collect();
        starts.sort_unstable();
        Self {
            module: m.module_kw.lo as usize,
            first_import: m.imports.iter().map(|imp| imp.import_kw.lo as usize).min(),
            starts,
        }
    }

    /// The owner of a comment anchored at `anchor`.
    fn owner(&self, anchor: Option<usize>) -> Owner {
        let Some(at) = anchor else {
            return Owner::Trailing;
        };
        let decls = self.starts.partition_point(|&s| s <= at);
        match (decls.checked_sub(1), self.first_import) {
            (Some(index), _) => Owner::Decl(index),
            (None, Some(import)) if at >= import => Owner::Imports,
            (None, _) => Owner::Header,
        }
    }

    /// Each head with its owner: `module`, then every declaration.
    fn heads(&self) -> impl Iterator<Item = (Owner, usize)> + '_ {
        std::iter::once((Owner::Header, self.module)).chain(
            self.starts
                .iter()
                .enumerate()
                .map(|(i, &s)| (Owner::Decl(i), s)),
        )
    }
}

/// C1: each owner keeps the same multiset of comments.
fn owners_kept(
    before: &Layout,
    input: &[Comment],
    after: &Layout,
    output: &[Comment],
) -> Result<(), Refusal> {
    let a = owned(before, input);
    let b = owned(after, output);
    if a == b {
        return Ok(());
    }
    let owner = a
        .iter()
        .zip(&b)
        .find(|(x, y)| x != y)
        .map(|(x, y)| x.0.min(y.0))
        .or_else(|| a.get(b.len()).or_else(|| b.get(a.len())).map(|x| x.0))
        .unwrap_or(Owner::Header);
    Err(Refusal::Run {
        owner,
        fault: RunFault::OwnerMultiset,
    })
}

/// Each comment of `list` keyed by its owner, sorted.
fn owned<'a>(layout: &Layout, list: &'a [Comment]) -> Vec<(Owner, CommentKey<'a>)> {
    let mut v: Vec<(Owner, CommentKey<'a>)> = list
        .iter()
        .map(|c| (layout.owner(c.anchor()), c.key()))
        .collect();
    v.sort_unstable();
    v
}

/// An adjacent pair: two consecutive comments at the same anchor.
type Pair<'a> = (Owner, CommentKey<'a>, Gap, CommentKey<'a>);

/// C2: every adjacent pair of the input is an adjacent pair of the output,
/// with the same gap between its comments.
fn pairs_kept(
    before: &Layout,
    input: &[Comment],
    after: &Layout,
    output: &[Comment],
) -> Result<(), Refusal> {
    let need = pairs(before, input);
    let have = pairs(after, output);
    let mut have = have.iter().peekable();
    for pair in &need {
        while have.next_if(|h| *h < pair).is_some() {}
        if have.next_if(|h| *h == pair).is_none() {
            return Err(Refusal::Run {
                owner: pair.0,
                fault: RunFault::Adjacency,
            });
        }
    }
    Ok(())
}

/// The adjacent pairs of `list`, sorted.
fn pairs<'a>(layout: &Layout, list: &'a [Comment]) -> Vec<Pair<'a>> {
    let mut v: Vec<Pair<'a>> = list
        .windows(2)
        .filter_map(|w| match w {
            [a, b] if a.anchor() == b.anchor() => {
                Some((layout.owner(a.anchor()), a.key(), b.gap_before(), b.key()))
            }
            _ => None,
        })
        .collect();
    v.sort_unstable();
    v
}

/// C3: the run directly above each head stays a suffix of the output's run
/// there, with the same inner gaps and gap to the head, and a blank line
/// before it when comments were hoisted above it.
fn head_runs_kept<'a>(
    before: &Layout,
    input: &'a [Comment],
    after: &Layout,
    output: &'a [Comment],
) -> Result<usize, Refusal> {
    let at = |list: &'a [Comment], head: usize| -> Vec<&'a Comment> {
        list.iter().filter(|c| c.anchor() == Some(head)).collect()
    };
    let mut count = 0usize;
    for ((owner, head_in), (_, head_out)) in before.heads().zip(after.heads()) {
        let run_in = at(input, head_in);
        let run_out = at(output, head_out);
        if !head_run_kept(&run_in, &run_out) {
            return Err(Refusal::Run {
                owner,
                fault: RunFault::HeadRun,
            });
        }
        if !run_in.is_empty() {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

/// Whether `run_out` keeps `run_in` as the run above its head.
fn head_run_kept(run_in: &[&Comment], run_out: &[&Comment]) -> bool {
    let last_gap = |run: &[&Comment]| run.last().map(|c| c.gap_to_anchor());
    if run_in.is_empty() {
        return last_gap(run_out).is_none_or(|g| g == Gap::Blank);
    }
    let Some(hoisted) = run_out.len().checked_sub(run_in.len()) else {
        return false;
    };
    let Some(suffix) = run_out.get(hoisted..) else {
        return false;
    };
    let same_keys = run_in.iter().zip(suffix).all(|(a, b)| a.key() == b.key());
    let same_gaps = run_in
        .iter()
        .zip(suffix)
        .skip(1)
        .all(|(a, b)| a.gap_before() == b.gap_before());
    let separated = hoisted == 0 || suffix.first().is_some_and(|c| c.gap_before() == Gap::Blank);
    same_keys && same_gaps && separated && last_gap(run_in) == last_gap(suffix)
}
