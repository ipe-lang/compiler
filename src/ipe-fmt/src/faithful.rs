//! The run guard: an output keeps every end-of-line comment on the line of
//! the code it follows or moves it above its next code, keeps every comment
//! with its owner, every adjacent pair of comments together with its gap, and
//! every run directly above a head with its gap to that head.
//!
//! Comments are compared by text, so a permutation among comments of equal
//! text is invisible to it.

use std::collections::BTreeMap;
use std::fmt;

use ipe_syntax::Module;

use super::comments::{Comment, CommentKey, Gap};
use super::{CodeToken, Trivia, decl_start, module_decls};

/// An input and the output printed from it, each with its source text.
pub struct Printed<'a> {
    /// The input's comments and code tokens.
    pub input: &'a Trivia,
    /// The input text.
    pub input_src: &'a str,
    /// The output's comments and code tokens.
    pub output: &'a Trivia,
    /// The output text.
    pub output_src: &'a str,
}

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
    /// An end-of-line comment left the line of the code it follows for any
    /// place but above its next code, or a comment joined a line's end.
    Attachment,
}

impl fmt::Display for RunFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OwnerMultiset => "a comment moved to another owner",
            Self::Adjacency => "two adjacent comments were split apart or re-spaced",
            Self::HeadRun => "the run above a head changed its comments or its gaps",
            Self::Attachment => "a comment left the line of the code it follows",
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
/// [`Refusal::Run`] when an end-of-line comment left its line for any place
/// but above its next code, a comment changed owner, an adjacent pair split or
/// re-spaced, or a head run changed.
pub fn check(module: &Module, reparsed: &Module, printed: &Printed<'_>) -> Result<usize, Refusal> {
    let before = Layout::of(module, &printed.input.code);
    let after = Layout::of(reparsed, &printed.output.code);
    if before.starts.len() != after.starts.len() {
        return Err(Refusal::DeclCount);
    }
    let sides = attachment_kept(&before, &after, printed)?;
    owners_kept(&before, &sides.input, &after, &sides.output)?;
    pairs_kept(&before, &sides.input.leading, &after, &sides.output.leading)?;
    head_runs_kept(&before, &sides.input.leading, &after, &sides.output.leading)
}

/// One side's comments, split by where they print.
#[derive(Default)]
struct Placement<'a> {
    /// The comments printed on their own line, above their anchor, in source
    /// order.
    leading: Vec<&'a Comment>,
    /// The end-of-line comments printed after their owner token.
    kept: Vec<&'a Comment>,
}

/// Both sides' placements, as C4 matched them.
struct Sides<'a> {
    input: Placement<'a>,
    output: Placement<'a>,
}

/// An end-of-line comment's identity: its owner's name ([`crate::comments::OwnerTok::name`])
/// and its text.
type TrailKey<'a> = (&'a str, CommentKey<'a>);

/// C4: every end-of-line comment of the output trails a token of the text its
/// input owner had, and every input end-of-line comment the output does not
/// keep prints as a leading comment.
///
/// A demoted comment prints where its layout's leading comments go (above
/// its next code, or for a head position above or below the head), so C4
/// matches it by text alone and C1–C3 then judge it as a leading comment of
/// the input: it stays with its declaration, its neighbours and off any head
/// run it did not start in. A comment that joins the end of any line it did
/// not end is refused here.
///
/// Both sides are classified by the same rule, from their text alone, so the
/// check needs nothing from the printer and judges a caller's splice too.
fn attachment_kept<'a>(
    before: &Layout,
    after: &Layout,
    printed: &Printed<'a>,
) -> Result<Sides<'a>, Refusal> {
    let refuse = |owner| Refusal::Run {
        owner,
        fault: RunFault::Attachment,
    };
    let (input, output) = (printed.input, printed.output);
    let trail_key = |c: &'a Comment, src: &'a str| {
        c.owner()
            .and_then(|o| o.name(src))
            .map(|owner| (owner, c.key()))
    };
    let mut eligible: BTreeMap<TrailKey<'a>, Vec<&'a Comment>> = BTreeMap::new();
    for c in input.comments.iter().rev() {
        if let Some(key) = trail_key(c, printed.input_src) {
            eligible.entry(key).or_default().push(c);
        }
    }
    let mut sides = Sides {
        input: Placement::default(),
        output: Placement::default(),
    };
    let mut kept_ords: Vec<usize> = Vec::new();
    for c in &output.comments {
        let Some(owner) = c.owner() else {
            sides.output.leading.push(c);
            continue;
        };
        let matched = trail_key(c, printed.output_src)
            .and_then(|key| eligible.get_mut(&key))
            .and_then(Vec::pop);
        let Some(source) = matched else {
            return Err(refuse(after.owner(Some(owner.lo))));
        };
        kept_ords.push(source.ord());
        sides.input.kept.push(source);
        sides.output.kept.push(c);
    }
    let mut leading_out: BTreeMap<CommentKey<'a>, usize> = BTreeMap::new();
    for c in &sides.output.leading {
        let count = leading_out.entry(c.key()).or_default();
        *count = count.saturating_add(1);
    }
    kept_ords.sort_unstable();
    for c in &input.comments {
        if c.owner().is_some() && kept_ords.binary_search(&c.ord()).is_ok() {
            continue;
        }
        if c.owner().is_some() {
            let demoted = leading_out.get_mut(&c.key()).filter(|count| **count > 0);
            let Some(count) = demoted else {
                return Err(refuse(before.owner(c.anchor())));
            };
            *count = count.saturating_sub(1);
        }
        sides.input.leading.push(c);
    }
    Ok(sides)
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
///
/// A leading comment belongs to the item its anchor starts in, an end-of-line
/// comment to the item its owner token sits in.
fn owners_kept(
    before: &Layout,
    input: &Placement<'_>,
    after: &Layout,
    output: &Placement<'_>,
) -> Result<(), Refusal> {
    let a = owned(before, input);
    let b = owned(after, output);
    first_difference(&a, &b).map_or(Ok(()), |owner| {
        Err(Refusal::Run {
            owner,
            fault: RunFault::OwnerMultiset,
        })
    })
}

/// The owner at the first position where the sorted lists `a` and `b`
/// differ, or `None` when they are equal.
fn first_difference(a: &[(Owner, CommentKey<'_>)], b: &[(Owner, CommentKey<'_>)]) -> Option<Owner> {
    (0..a.len().max(b.len())).find_map(|i| match (a.get(i), b.get(i)) {
        (Some(x), Some(y)) if x == y => None,
        (Some(x), Some(y)) => Some(x.0.min(y.0)),
        (Some(x), None) | (None, Some(x)) => Some(x.0),
        (None, None) => None,
    })
}

/// Each comment of `placement` keyed by its owner, sorted.
fn owned<'a>(layout: &Layout, placement: &Placement<'a>) -> Vec<(Owner, CommentKey<'a>)> {
    let leading = placement
        .leading
        .iter()
        .map(|c| (layout.owner(c.anchor()), c.key()));
    let kept = placement
        .kept
        .iter()
        .map(|c| (layout.owner(c.owner().map(|o| o.lo)), c.key()));
    let mut v: Vec<(Owner, CommentKey<'a>)> = leading.chain(kept).collect();
    v.sort_unstable();
    v
}

/// An adjacent pair: two consecutive comments at the same anchor.
type Pair<'a> = (Owner, CommentKey<'a>, Gap, CommentKey<'a>);

/// C2: every adjacent pair of the input is an adjacent pair of the output,
/// with the same gap between its comments.
fn pairs_kept(
    before: &Layout,
    input: &[&Comment],
    after: &Layout,
    output: &[&Comment],
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
fn pairs<'a>(layout: &Layout, list: &[&'a Comment]) -> Vec<Pair<'a>> {
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
fn head_runs_kept(
    before: &Layout,
    input: &[&Comment],
    after: &Layout,
    output: &[&Comment],
) -> Result<usize, Refusal> {
    let (anchored_in, anchored_out) = (by_anchor(input), by_anchor(output));
    let mut count = 0usize;
    for ((owner, head_in), (_, head_out)) in before.heads().zip(after.heads()) {
        let run_in = run_at(&anchored_in, head_in);
        let run_out = run_at(&anchored_out, head_out);
        if !head_run_kept(run_in, run_out) {
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

/// The comments of `list` grouped by anchor, each group in source order.
///
/// Built in one pass, so the head-run check costs `O(n log n)` in the comment
/// count however many heads the module has.
fn by_anchor<'a>(list: &[&'a Comment]) -> BTreeMap<usize, Vec<&'a Comment>> {
    let mut runs: BTreeMap<usize, Vec<&'a Comment>> = BTreeMap::new();
    for &c in list {
        if let Some(anchor) = c.anchor() {
            runs.entry(anchor).or_default().push(c);
        }
    }
    runs
}

/// The run anchored at `head`, empty when no comment is.
fn run_at<'m, 'a>(runs: &'m BTreeMap<usize, Vec<&'a Comment>>, head: usize) -> &'m [&'a Comment] {
    runs.get(&head).map_or(&[], Vec::as_slice)
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
