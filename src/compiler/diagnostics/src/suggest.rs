//! The one "did you mean" ranker every suggestion site ranks through.
//!
//! A site hands in a parsed [`Query`] and its universe: every spelling its
//! exact lookup accepts, each pointing at the target it opens (an alias points
//! at its canonical target). The ranker scores each spelling with restricted
//! Damerau-Levenshtein (optimal string alignment), aligned segment by segment
//! for dotted names, keeps only the spellings within the site's [`Threshold`],
//! collapses the spellings of one target to its best score, and returns the
//! targets in one total order. A site owns no metric, threshold, or tie-break
//! of its own, so no site can disagree with another about what is close.
//!
//! Every input dimension has a declared ceiling: the query length
//! ([`QUERY_CHARS`]), the spellings scanned ([`MAX_UNIVERSE`]), the characters
//! of a spelling read ([`SPELLING_CHARS`]), the characters one distance
//! compares per side ([`DISTANCE_CHARS`]), and the hits returned ([`Cap`]).

use std::collections::BTreeMap;
use std::num::NonZeroU8;

use crate::terminal::is_display_hazard;

/// The longest query, in characters, the ranker accepts.
pub const QUERY_CHARS: usize = 256;

/// The most spellings one ranking scans.
pub const MAX_UNIVERSE: usize = 20_000;

/// The most characters of a spelling the ranker reads.
///
/// A longer spelling is compared whole on its first [`DISTANCE_CHARS`]
/// characters only: its cut tail hides its real last segments, so it is never
/// aligned segment by segment and never counts as a case-only match.
pub const SPELLING_CHARS: usize = 1024;

/// The most characters per side one edit distance compares.
pub const DISTANCE_CHARS: usize = 64;

/// Why a query was turned away before any ranking ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryRefusal {
    /// The query is empty or only whitespace: it names nothing.
    Empty,
    /// The query is longer than [`QUERY_CHARS`].
    TooLong,
    /// The query carries a control character, an escape sequence, or a
    /// format/bidi hazard.
    ControlChar,
}

/// How a universe's names are segmented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// A name is one segment, compared whole.
    Flat,
    /// A name is `.`-separated segments (`Ipe.List.map`), aligned one by one.
    Dotted,
}

/// A query accepted for ranking.
///
/// Trimmed, non-empty, at most [`QUERY_CHARS`] characters, free of display
/// hazards, and case-folded once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// The trimmed query as written; a case-only match differs from it.
    text: Box<str>,
    /// The trimmed query, case-folded.
    folded: Box<str>,
    /// How the query and its universe are segmented.
    shape: Shape,
    /// The folded query's segments under its [`Shape`].
    segments: Box<[Box<str>]>,
}

impl Query {
    /// Parse a raw query under `shape`.
    ///
    /// The length is checked first (counting at most one character past the
    /// ceiling), then the trimmed text must hold something, then it must be
    /// free of display hazards.
    ///
    /// # Errors
    ///
    /// The [`QueryRefusal`] naming the first check the query failed.
    pub fn parse(raw: &str, shape: Shape) -> Result<Self, QueryRefusal> {
        if raw.chars().nth(QUERY_CHARS).is_some() {
            return Err(QueryRefusal::TooLong);
        }
        let text = raw.trim();
        if text.is_empty() {
            return Err(QueryRefusal::Empty);
        }
        if text.chars().any(is_display_hazard) {
            return Err(QueryRefusal::ControlChar);
        }
        let folded = fold(text);
        let segments = match shape {
            Shape::Flat => vec![Box::from(folded.as_str())].into_boxed_slice(),
            Shape::Dotted => folded.split('.').map(Box::from).collect(),
        };
        Ok(Self {
            text: Box::from(text),
            folded: folded.into_boxed_str(),
            shape,
            segments,
        })
    }

    /// The trimmed query text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The trimmed query, case-folded.
    #[must_use]
    pub fn folded(&self) -> &str {
        &self.folded
    }
}

/// One spelling the exact lookup accepts, pointing at what it opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spelling<'a, T> {
    /// The spelling as the lookup accepts it.
    pub text: &'a str,
    /// The target the spelling opens; an alias carries its canonical target.
    pub target: T,
}

/// The most suggestions one ranking returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cap(NonZeroU8);

impl Cap {
    /// The largest cap.
    pub const MAX: Self = Self(NonZeroU8::MAX);

    /// A cap of `n` suggestions.
    #[must_use]
    pub const fn new(n: NonZeroU8) -> Self {
        Self(n)
    }

    /// The cap as a count.
    #[must_use]
    pub fn get(self) -> usize {
        usize::from(self.0.get())
    }
}

/// How far a spelling may be from the query and still be suggested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Threshold {
    /// Each aligned segment within `max(len, 3) / 3` of its query segment,
    /// `len` the query segment's compared characters (at least 1).
    Relative,
    /// Every spelling within `max` edits, summed over aligned segments.
    ///
    /// Only the doc page's "nearest entries" list uses it, and only when no
    /// entry matched: it is a listing of what exists, never a typo verdict.
    Nearest {
        /// The largest distance kept.
        max: Distance,
    },
}

/// Per-site policy: how many suggestions and how close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// The most suggestions returned.
    pub cap: Cap,
    /// How close a spelling must be.
    pub threshold: Threshold,
}

/// An edit distance, at most [`Distance::CEILING`] per compared pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Distance(u8);

impl Distance {
    /// The largest distance one comparison of [`DISTANCE_CHARS`]-cut sides
    /// can produce.
    pub const CEILING: Self = Self(64);

    /// The distance as a count of edits.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// How sure the ranker is that a hit is what the query meant, best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// The query and a spelling differ only in letter case.
    CaseOnly,
    /// The one hit at one edit, with no other hit within two edits of it and
    /// a complete scan, so no unseen spelling could compete.
    UniqueSingleEdit,
    /// Any other hit, including an exact spelling: the site's exact lookup
    /// answers that one before ranking.
    Plausible,
}

/// One ranked target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit<T> {
    /// The target a spelling within the threshold opens.
    pub target: T,
    /// The best distance over the target's spellings.
    pub distance: Distance,
    /// How sure the ranker is.
    pub confidence: Confidence,
}

/// The outcome of one ranking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ranked<T> {
    /// At most [`Policy::cap`] hits, ordered by `(distance, confidence, target)`.
    pub hits: Vec<Hit<T>>,
    /// Whether the universe held more than [`MAX_UNIVERSE`] spellings.
    pub truncated: bool,
}

/// Rank `universe` against `query` under `policy`.
///
/// Scans at most [`MAX_UNIVERSE`] spellings. A spelling past the threshold is
/// never a hit, so a far query returns no hits. The spellings of one target
/// collapse to its best score before the cap applies, and the order `(distance,
/// confidence, target)` is total, so every run returns the same list. A site
/// whose shorter names should win ties orders its target by length first.
#[must_use]
pub fn rank<'a, T: Ord + Clone>(
    query: &Query,
    universe: impl IntoIterator<Item = Spelling<'a, T>>,
    policy: Policy,
) -> Ranked<T> {
    let query_whole = cut_chars(&query.folded);
    let query_segments: Vec<Vec<char>> = query.segments.iter().map(|s| cut_chars(s)).collect();
    let mut work = Work::default();
    let mut best: BTreeMap<T, Best> = BTreeMap::new();

    let mut scan = universe.into_iter();
    for spelling in scan.by_ref().take(MAX_UNIVERSE) {
        let Some(found) = score(
            query,
            &query_whole,
            &query_segments,
            spelling.text,
            policy.threshold,
            &mut work,
        ) else {
            continue;
        };
        best.entry(spelling.target)
            .and_modify(|held| {
                if found < *held {
                    *held = found;
                }
            })
            .or_insert(found);
    }
    let truncated = scan.next().is_some();

    let mut ordered: Vec<(T, Best)> = best.into_iter().collect();
    ordered.sort_by(|(at, a), (bt, b)| a.cmp(b).then_with(|| at.cmp(bt)));
    let runner_up = ordered.get(1).map(|(_, b)| b.distance);
    let mut hits: Vec<Hit<T>> = ordered
        .into_iter()
        .enumerate()
        .map(|(at, (target, found))| {
            let unique = at == 0
                && !truncated
                && found.distance == Distance(1)
                && runner_up.is_none_or(|next| next.get() >= 3);
            let confidence = if found.case_only {
                Confidence::CaseOnly
            } else if unique {
                Confidence::UniqueSingleEdit
            } else {
                Confidence::Plausible
            };
            Hit {
                target,
                distance: found.distance,
                confidence,
            }
        })
        .collect();
    hits.sort_by(|a, b| {
        (a.distance, a.confidence)
            .cmp(&(b.distance, b.confidence))
            .then_with(|| a.target.cmp(&b.target))
    });
    hits.truncate(policy.cap.get());
    Ranked { hits, truncated }
}

/// A spelling's score: its distance, and whether it is a case-only match.
///
/// Ordered best first: a smaller distance, then a case-only match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Best {
    distance: Distance,
    case_only: bool,
}

impl PartialOrd for Best {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Best {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.distance
            .cmp(&other.distance)
            .then_with(|| other.case_only.cmp(&self.case_only))
    }
}

/// Buffers one ranking reuses across every spelling.
#[derive(Default)]
struct Work {
    folded: String,
    chars: Vec<char>,
    rows: Rows,
}

/// The three distance rows one comparison keeps.
#[derive(Default)]
struct Rows {
    before: Vec<usize>,
    prev: Vec<usize>,
    cur: Vec<usize>,
}

/// The score of `text` against the query, or `None` past the threshold.
///
/// A dotted query is aligned against the spelling's trailing segments of the
/// same count; when the counts differ, the whole folded strings are compared
/// too and the smaller distance wins. A flat query, or a spelling cut at
/// [`SPELLING_CHARS`], is compared whole only.
fn score(
    query: &Query,
    query_whole: &[char],
    query_segments: &[Vec<char>],
    text: &str,
    threshold: Threshold,
    work: &mut Work,
) -> Option<Best> {
    let (head, cut) = match text.char_indices().nth(SPELLING_CHARS) {
        Some((at, _)) => (text.get(..at).unwrap_or(text), true),
        None => (text, false),
    };
    work.folded.clear();
    work.folded
        .extend(head.chars().flat_map(char::to_lowercase));
    if !cut && *work.folded == *query.folded {
        return Some(Best {
            distance: Distance(0),
            case_only: head != query.text(),
        });
    }

    let (by_segment, by_whole) = if cut || query.shape == Shape::Flat {
        (None, whole(query_whole, threshold, work))
    } else {
        let count = work.folded.split('.').count();
        let wanted = query_segments.len();
        let by_segment = if count >= wanted {
            aligned(query_segments, threshold, work)
        } else {
            None
        };
        let by_whole = if count == wanted && threshold == Threshold::Relative {
            None
        } else {
            whole(query_whole, threshold, work)
        };
        (by_segment, by_whole)
    };
    let found = match (by_segment, by_whole) {
        (Some(a), Some(b)) => a.min(b),
        (Some(d), None) | (None, Some(d)) => d,
        (None, None) => return None,
    };
    Some(Best {
        distance: Distance(u8::try_from(found).ok()?),
        case_only: false,
    })
}

/// The distance of the whole folded spelling from the whole query, within
/// the threshold for the query's compared length.
fn whole(query_whole: &[char], threshold: Threshold, work: &mut Work) -> Option<usize> {
    let Work {
        folded,
        chars,
        rows,
    } = work;
    chars.clear();
    chars.extend(folded.chars().take(DISTANCE_CHARS));
    osa(
        query_whole,
        chars,
        limit_for(query_whole.len(), threshold),
        rows,
    )
}

/// The summed distance of the query's segments against the spelling's
/// trailing segments of the same count, each within its own threshold.
fn aligned(query_segments: &[Vec<char>], threshold: Threshold, work: &mut Work) -> Option<usize> {
    let Work {
        folded,
        chars,
        rows,
    } = work;
    let mut total: usize = 0;
    for (wanted, have) in query_segments.iter().rev().zip(folded.rsplit('.')) {
        let limit = match threshold {
            Threshold::Relative => limit_for(wanted.len(), threshold),
            Threshold::Nearest { max } => usize::from(max.get()).checked_sub(total)?,
        };
        chars.clear();
        chars.extend(have.chars().take(DISTANCE_CHARS));
        let d = osa(wanted, chars, limit, rows)?;
        total = total.saturating_add(d);
    }
    Some(total)
}

/// The largest distance kept for a query side of `len` compared characters.
fn limit_for(len: usize, threshold: Threshold) -> usize {
    match threshold {
        Threshold::Relative => len.max(3) / 3,
        Threshold::Nearest { max } => usize::from(max.get()),
    }
}

/// The restricted Damerau-Levenshtein (optimal string alignment) distance
/// between `a` and `b`, or `None` once it must exceed `limit`.
///
/// An adjacent transposition costs one edit. A row whose minimum exceeds
/// `limit` stops the scan: no later row can fall back under it.
fn osa(a: &[char], b: &[char], limit: usize, rows: &mut Rows) -> Option<usize> {
    if a.len().abs_diff(b.len()) > limit {
        return None;
    }
    let Rows { before, prev, cur } = rows;
    before.clear();
    prev.clear();
    prev.extend(0..=b.len());
    let mut a_prev: Option<char> = None;
    for (i, &ca) in a.iter().enumerate() {
        cur.clear();
        let start = i.saturating_add(1);
        cur.push(start);
        let mut row_min = start;
        let mut b_prev: Option<char> = None;
        for (j, &cb) in b.iter().enumerate() {
            let up = prev.get(j.saturating_add(1)).copied().unwrap_or(usize::MAX);
            let diag = prev.get(j).copied().unwrap_or(usize::MAX);
            let left = cur.last().copied().unwrap_or(usize::MAX);
            let mut cell = up
                .saturating_add(1)
                .min(left.saturating_add(1))
                .min(diag.saturating_add(usize::from(ca != cb)));
            if ca != cb && a_prev == Some(cb) && b_prev == Some(ca) {
                let swap = j
                    .checked_sub(1)
                    .and_then(|k| before.get(k))
                    .map_or(usize::MAX, |d| d.saturating_add(1));
                cell = cell.min(swap);
            }
            cur.push(cell);
            row_min = row_min.min(cell);
            b_prev = Some(cb);
        }
        if row_min > limit {
            return None;
        }
        std::mem::swap(before, prev);
        std::mem::swap(prev, cur);
        a_prev = Some(ca);
    }
    prev.last().copied().filter(|d| *d <= limit)
}

/// The Unicode case fold the ranker compares under, character by character,
/// so a query and every name fold by the same rule.
#[must_use]
pub fn fold(text: &str) -> String {
    text.chars().flat_map(char::to_lowercase).collect()
}

/// The first [`DISTANCE_CHARS`] characters of already-folded `text`.
fn cut_chars(text: &str) -> Vec<char> {
    text.chars().take(DISTANCE_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(raw: &str, shape: Shape) -> Query {
        Query::parse(raw, shape).expect("a valid query")
    }

    fn spellings<'a>(names: &[&'a str]) -> Vec<Spelling<'a, &'a str>> {
        names
            .iter()
            .map(|n| Spelling {
                text: n,
                target: *n,
            })
            .collect()
    }

    const RELATIVE: Policy = Policy {
        cap: Cap::MAX,
        threshold: Threshold::Relative,
    };

    fn targets<'a>(raw: &str, shape: Shape, names: &[&'a str]) -> Vec<&'a str> {
        rank(&query(raw, shape), spellings(names), RELATIVE)
            .hits
            .into_iter()
            .map(|h| h.target)
            .collect()
    }

    fn distance(a: &str, b: &str) -> Option<usize> {
        let a: Vec<char> = a.chars().collect();
        let b: Vec<char> = b.chars().collect();
        osa(&a, &b, usize::MAX, &mut Rows::default())
    }

    // -- Query refusals -------------------------------------------------------

    #[test]
    fn an_empty_or_blank_query_is_refused_as_empty() {
        for raw in ["", " ", "  \t ", "\u{a0}"] {
            assert_eq!(
                Query::parse(raw, Shape::Flat),
                Err(QueryRefusal::Empty),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn a_query_carrying_a_hazard_is_refused_as_a_control_char() {
        for raw in ["ma\u{7}p", "a\u{1b}[31m", "a\tb", "\u{202e}x", "\u{9b}31m"] {
            assert_eq!(
                Query::parse(raw, Shape::Dotted),
                Err(QueryRefusal::ControlChar),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn the_longest_query_is_accepted_and_one_more_char_is_refused() {
        assert!(Query::parse(&"é".repeat(QUERY_CHARS), Shape::Flat).is_ok());
        let over = "x".repeat(QUERY_CHARS.saturating_add(1));
        assert_eq!(Query::parse(&over, Shape::Flat), Err(QueryRefusal::TooLong));
        assert_eq!(
            Query::parse(&"x".repeat(1_000_000), Shape::Dotted),
            Err(QueryRefusal::TooLong)
        );
    }

    #[test]
    fn a_query_is_trimmed_folded_and_segmented_by_its_shape() {
        let q = query("  Ipe.List  ", Shape::Dotted);
        assert_eq!(q.text(), "Ipe.List");
        assert_eq!(q.folded(), "ipe.list");
        assert_eq!(q.segments.len(), 2);
        assert_eq!(query("Ipe.List", Shape::Flat).segments.len(), 1);
    }

    // -- Distance -------------------------------------------------------------

    #[test]
    fn an_adjacent_swap_costs_one_edit() {
        assert_eq!(distance("lsit", "list"), Some(1));
        assert_eq!(distance("lenght", "length"), Some(1));
        assert_eq!(distance("lsit", "set"), Some(2));
        assert_eq!(distance("", "map"), Some(3));
        assert_eq!(distance("map", "map"), Some(0));
        assert_eq!(distance("mäp", "map"), Some(1), "char-based, never bytes");
    }

    #[test]
    fn a_distance_past_its_limit_stops_early() {
        let a: Vec<char> = "abcdef".chars().collect();
        let b: Vec<char> = "uvwxyz".chars().collect();
        assert_eq!(osa(&a, &b, 2, &mut Rows::default()), None);
        assert_eq!(osa(&a, &b, 6, &mut Rows::default()), Some(6));
    }

    #[test]
    fn a_long_name_is_compared_on_its_first_chars_and_terminates() {
        let mut name = "a".repeat(100);
        let mut other = name.clone();
        name.replace_range(90..91, "b");
        other.replace_range(90..91, "c");
        let ranked = rank(&query(&name, Shape::Flat), spellings(&[&other]), RELATIVE);
        assert_eq!(
            ranked.hits.first().map(|h| h.distance),
            Some(Distance(0)),
            "only the first {DISTANCE_CHARS} chars are compared"
        );
        let huge = "x.".repeat(SPELLING_CHARS);
        let ranked = rank(&query("x.x", Shape::Dotted), spellings(&[&huge]), RELATIVE);
        assert!(ranked.hits.len() <= 1);
    }

    #[test]
    fn the_distance_ceiling_is_the_compared_width() {
        assert_eq!(usize::from(Distance::CEILING.get()), DISTANCE_CHARS);
        let far = "z".repeat(DISTANCE_CHARS.saturating_add(DISTANCE_CHARS / 2));
        let near = "a".repeat(DISTANCE_CHARS.saturating_mul(2));
        let policy = Policy {
            cap: Cap::MAX,
            threshold: Threshold::Nearest {
                max: Distance::CEILING,
            },
        };
        let ranked = rank(&query(&far, Shape::Flat), spellings(&[&near]), policy);
        assert_eq!(ranked.hits.len(), 1, "every spelling is within the ceiling");
    }

    #[test]
    fn a_nearest_listing_reaches_an_equal_count_spelling() {
        let far = format!("{}.{}", "a".repeat(40), "b".repeat(40));
        let policy = Policy {
            cap: Cap::MAX,
            threshold: Threshold::Nearest {
                max: Distance::CEILING,
            },
        };
        let ranked = rank(&query(&far, Shape::Dotted), spellings(&["c.d"]), policy);
        assert_eq!(ranked.hits.len(), 1);
    }

    // -- Ranking --------------------------------------------------------------

    #[test]
    fn an_exact_spelling_ranks_first_at_distance_zero() {
        let ranked = rank(
            &query("map", Shape::Flat),
            spellings(&["mad", "map"]),
            RELATIVE,
        );
        let first = ranked.hits.first().expect("a hit");
        assert_eq!(first.target, "map");
        assert_eq!(first.distance, Distance(0));
    }

    #[test]
    fn a_case_only_match_ranks_first() {
        let ranked = rank(
            &query("JUST", Shape::Flat),
            spellings(&["Juts", "Just"]),
            RELATIVE,
        );
        let first = ranked.hits.first().expect("a hit");
        assert_eq!(first.target, "Just");
        assert_eq!(first.confidence, Confidence::CaseOnly);
    }

    #[test]
    fn an_empty_universe_has_no_hits() {
        let ranked = rank(&query("map", Shape::Flat), spellings(&[]), RELATIVE);
        assert!(ranked.hits.is_empty());
        assert!(!ranked.truncated);
    }

    #[test]
    fn ties_break_by_target_in_a_total_order() {
        for names in [["map", "mad"], ["mad", "map"]] {
            assert_eq!(targets("mab", Shape::Flat, &names), ["mad", "map"]);
        }
    }

    #[test]
    fn a_transposition_is_a_typo_and_a_two_edit_name_is_not() {
        assert_eq!(targets("lsit", Shape::Flat, &["list", "set"]), ["list"]);
    }

    #[test]
    fn a_qualifier_typo_aligns_segment_by_segment() {
        assert_eq!(
            targets("Lsit.map", Shape::Dotted, &["List.map", "Set.map"]),
            ["List.map"]
        );
    }

    #[test]
    fn each_segment_must_be_within_its_own_threshold() {
        assert!(
            targets("Lsxt.map", Shape::Dotted, &["List.map"]).is_empty(),
            "two edits in a four-char segment are past its threshold of one"
        );
        assert_eq!(
            targets("Lsxt.map", Shape::Flat, &["List.map"]),
            ["List.map"],
            "the same two edits pass the whole-string threshold of an eight-char name"
        );
    }

    #[test]
    fn a_member_typo_matches_the_trailing_segments_once_per_target() {
        let universe = vec![
            Spelling {
                text: "Ipe.List.map",
                target: "Ipe.List.map",
            },
            Spelling {
                text: "List.map",
                target: "Ipe.List.map",
            },
            Spelling {
                text: "Ipe.Math",
                target: "Ipe.Math",
            },
        ];
        let ranked = rank(&query("List.mapp", Shape::Dotted), universe, RELATIVE);
        let hits: Vec<&str> = ranked.hits.iter().map(|h| h.target).collect();
        assert_eq!(
            hits,
            ["Ipe.List.map"],
            "one hit per target, never per spelling"
        );
    }

    #[test]
    fn a_far_name_gets_no_suggestion() {
        assert!(targets("zzzzzz", Shape::Flat, &["map", "list"]).is_empty());
        assert!(targets("Zzzz.qqq", Shape::Dotted, &["List.map"]).is_empty());
    }

    #[test]
    fn a_short_name_gets_only_hits_within_one_edit() {
        let hits = targets("x1", Shape::Flat, &["x", "y1", "ab"]);
        assert_eq!(hits, ["x", "y1"]);
    }

    #[test]
    fn the_cap_cuts_the_hits_in_rank_order() {
        let policy = Policy {
            cap: Cap::new(NonZeroU8::MIN),
            threshold: Threshold::Relative,
        };
        let ranked = rank(
            &query("mab", Shape::Flat),
            spellings(&["map", "mad"]),
            policy,
        );
        let hits: Vec<&str> = ranked.hits.iter().map(|h| h.target).collect();
        assert_eq!(hits, ["mad"]);
    }

    #[test]
    fn the_universe_ceiling_stops_the_scan_and_marks_it_truncated() {
        let names: Vec<String> = (0..=MAX_UNIVERSE).map(|n| format!("k{n}")).collect();
        let over = names.iter().map(|n| Spelling {
            text: n.as_str(),
            target: n.as_str(),
        });
        let last = names.last().expect("a name");
        let ranked = rank(&query(last, Shape::Flat), over, RELATIVE);
        assert!(ranked.truncated);
        assert!(
            ranked.hits.iter().all(|h| h.target != last),
            "the spelling past the ceiling is never scanned"
        );
        let at = names.iter().take(MAX_UNIVERSE).map(|n| Spelling {
            text: n.as_str(),
            target: n.as_str(),
        });
        assert!(!rank(&query("k1", Shape::Flat), at, RELATIVE).truncated);
    }

    #[test]
    fn a_unique_single_edit_needs_no_runner_up_within_two_edits() {
        let confidence = |names: &[&str]| {
            rank(&query("lenght", Shape::Flat), spellings(names), RELATIVE)
                .hits
                .first()
                .map(|h| h.confidence)
        };
        assert_eq!(confidence(&["length"]), Some(Confidence::UniqueSingleEdit));
        assert_eq!(
            confidence(&["length", "lenient"]),
            Some(Confidence::UniqueSingleEdit)
        );
        assert_eq!(
            confidence(&["length", "lengths"]),
            Some(Confidence::Plausible),
            "a runner-up two edits away makes the guess ambiguous"
        );
        assert_eq!(
            confidence(&["length", "lenghs"]),
            Some(Confidence::Plausible)
        );
    }

    #[test]
    fn a_truncated_scan_is_never_a_unique_single_edit() {
        let names: Vec<String> = (0..MAX_UNIVERSE).map(|n| format!("q{n}")).collect();
        let universe = std::iter::once(Spelling {
            text: "length",
            target: "length",
        })
        .chain(names.iter().map(|n| Spelling {
            text: n.as_str(),
            target: n.as_str(),
        }));
        let ranked = rank(&query("lenght", Shape::Flat), universe, RELATIVE);
        assert!(ranked.truncated);
        assert_eq!(
            ranked.hits.first().map(|h| h.confidence),
            Some(Confidence::Plausible)
        );
    }

    #[test]
    fn the_same_query_ranks_the_same_way_every_run() {
        let names = ["mad", "map", "max", "mat", "Map"];
        let mut reversed = names;
        reversed.reverse();
        let first = rank(&query("maq", Shape::Flat), spellings(&names), RELATIVE);
        let again = rank(&query("maq", Shape::Flat), spellings(&reversed), RELATIVE);
        assert_eq!(first, again);
    }
}
