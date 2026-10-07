//! Ranked documentation matching for `ipe doc <term>`.
//!
//! One pure, bounded matcher: a parsed [`DocQuery`] and the bundle's entries go
//! in, the best entries come out in one total order. No I/O and no rendering —
//! the miss list ([`crate::doc_pick`]) and the unique-exact open both read this
//! one ranking, so they can never disagree.
//!
//! The typo tier and the nearest fallback rank through the shared
//! [`ipe_diagnostics::suggest`] ranker, over every spelling the exact lookup
//! accepts: each entry's key and each alias, an alias scoring for its
//! canonical entry and never listed itself.
//!
//! Every input dimension has a declared ceiling: the query length
//! ([`MAX_QUERY_CHARS`]), the entries scanned ([`MAX_CANDIDATES`]), the hits
//! kept ([`RESULT_LIMIT`]), the characters of a key or title any tier reads
//! ([`FIELD_CHARS`]), the text one edit distance compares
//! ([`suggest::DISTANCE_CHARS`]), and a summary's width ([`SUMMARY_CHARS`]). A
//! key or title comes from a `docs/` tree the checkout controls, so its length
//! alone never sets the cost of one comparison.

use std::collections::BTreeMap;

pub use ipe_diagnostics::suggest::QueryRefusal;
use ipe_diagnostics::suggest::{self, Cap, Distance, Policy, Shape, Spelling, Threshold};
use ipe_diagnostics::terminal::is_display_hazard;

use crate::doc_bundle::{DocEntry, DocKind};
use crate::style::TerminalLine;

/// The longest query, in characters, the matcher accepts.
pub const MAX_QUERY_CHARS: usize = suggest::QUERY_CHARS;

/// The most entries one ranking scans, in bundle (kind, key) order.
pub const MAX_CANDIDATES: usize = suggest::MAX_UNIVERSE;

/// The most hits a ranking keeps.
pub const RESULT_LIMIT: usize = 10;

/// The most characters of an entry's key or title the matcher reads.
///
/// A longer field is judged by its first `FIELD_CHARS` characters. It exceeds
/// the longest case-folded query (a character folds to at most three), so a
/// cut field, which folds to at least `FIELD_CHARS` characters, never equals
/// a query: cutting never fabricates an exact match.
pub const FIELD_CHARS: usize = 1024;

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the field ceiling drops to zero or to a length a folded query could equal [ledger #boundary]
const _: () = assert!(FIELD_CHARS > MAX_QUERY_CHARS * MAX_FOLD_EXPANSION);

/// An upper bound on the characters [`char::to_lowercase`] yields for one character.
const MAX_FOLD_EXPANSION: usize = 3;

/// The widest summary, in characters, before it is cut and marked `…`.
pub const SUMMARY_CHARS: usize = 80;

/// The shortest query the subsequence tier considers.
///
/// Two characters in order match nearly every key, so a shorter query would
/// only add noise below the tiers that already matched it.
const SUBSEQUENCE_MIN_CHARS: usize = 3;

/// How many query characters' worth of key one subsequence match may span.
///
/// A match scattered across a long key is not a reading of the query, so it
/// never crowds out a typo or a closer entry.
const SUBSEQUENCE_SPAN_FACTOR: usize = 2;

/// A query proven non-empty, bounded, and free of terminal hazards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocQuery {
    /// The parsed, folded, dotted query the ranker reads.
    query: suggest::Query,
}

impl DocQuery {
    /// Parse a raw query.
    ///
    /// The length is checked first (counting at most one character past the
    /// ceiling), then the raw text must carry no display hazard, even one
    /// trimming would drop, so a listed term parses back unchanged, then it
    /// must hold something besides whitespace.
    ///
    /// # Errors
    ///
    /// The [`QueryRefusal`] naming the first check the query failed.
    pub fn parse(raw: &str) -> Result<Self, QueryRefusal> {
        let parsed = suggest::Query::parse(raw, Shape::Dotted);
        if !matches!(parsed, Err(QueryRefusal::TooLong)) && raw.chars().any(is_display_hazard) {
            return Err(QueryRefusal::ControlChar);
        }
        parsed.map(|query| Self { query })
    }

    /// The trimmed query text.
    #[must_use]
    pub fn text(&self) -> &str {
        self.query.text()
    }

    /// The trimmed query, case-folded.
    fn folded(&self) -> &str {
        self.query.folded()
    }
}

/// How an entry matched a query, best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// The key equals the query.
    ExactKey,
    /// The key's last `.` segment equals the query.
    ExactMember,
    /// The title equals the query.
    ExactTitle,
    /// The key or its last segment starts with the query.
    Prefix,
    /// The title starts with the query.
    TitlePrefix,
    /// A word or camelCase segment of the key or title starts with the query.
    Segment,
    /// The key or title contains the query.
    Substring,
    /// Every word of the query is a word of the key or title.
    AllWords,
    /// A spelling that opens the entry (its key or an alias) is within the
    /// shared ranker's typo threshold.
    Typo,
    /// The query's characters appear in order in the key, within
    /// [`SUBSEQUENCE_SPAN_FACTOR`] times the query's length.
    Subsequence,
}

/// Whether a ranking found matches or fell back to the nearest entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closeness {
    /// At least one entry matched a [`Tier`].
    Match,
    /// No entry matched; the hits are the entries nearest by edit distance.
    Nearest,
}

impl Closeness {
    /// The stable word a machine consumer reads.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Nearest => "nearest",
        }
    }
}

/// The outcome of one ranking: at most [`RESULT_LIMIT`] entries, best first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ranked<'a> {
    /// The kept entries, in rank order.
    pub entries: Vec<&'a DocEntry>,
    /// Whether the entries matched or are the nearest fallback.
    pub closeness: Closeness,
    /// Whether a ceiling cut the scan or the list, so more entries may fit.
    pub truncated: bool,
}

/// One entry's key and title, each cut to [`FIELD_CHARS`] and case-folded.
struct Folded {
    key: String,
    /// Whether the key was cut, so its last `.` segment is not the key's own.
    key_cut: bool,
    title: String,
}

impl Folded {
    fn of(entry: &DocEntry) -> Self {
        let key = field(&entry.key);
        Self {
            key: fold(key),
            key_cut: key.len() < entry.key.len(),
            title: fold(field(&entry.title)),
        }
    }

    /// The key's last `.` segment, or the whole cut key when the cut hid the
    /// real last segment.
    fn member(&self) -> &str {
        if self.key_cut {
            self.key.as_str()
        } else {
            last_segment(&self.key)
        }
    }
}

/// The order a ranked entry takes among its peers: `(key length, kind, key)`.
///
/// Kind and key are unique together, so it names one entry.
type Peer<'a> = (usize, DocKind, &'a str);

/// The [`Peer`] order of `entry`.
fn peer(entry: &DocEntry) -> Peer<'_> {
    (field_len(&entry.key), entry.kind, entry.key.as_str())
}

/// The first [`FIELD_CHARS`] characters of an entry field.
fn field(text: &str) -> &str {
    prefix_chars(text, FIELD_CHARS)
}

/// The length, in characters, of an entry field as the matcher reads it.
fn field_len(text: &str) -> usize {
    field(text).chars().count()
}

/// Rank `entries`, reached also through `aliases`, against `query`.
///
/// Scans at most [`MAX_CANDIDATES`] entries and as many aliases; an alias of
/// an entry outside the scan is ignored, and an alias is never listed: it
/// scores for its canonical entry. Matches are ordered by `(tier, secondary,
/// key length, kind, key)`, where the secondary is the subsequence span or the
/// edit distance (zero for every other tier); kind and key are unique
/// together, so the order is total and every run returns the same list. The
/// key length counts at most [`FIELD_CHARS`] characters.
/// When nothing matches, the hits are the entries nearest by edit distance,
/// within [`Distance::CEILING`], ordered by `(distance, key length, kind,
/// key)`; every spelling no longer than the compared width is within it, so a
/// miss does not dead-end while such an entry exists.
#[must_use]
pub fn rank<'a, I, A>(entries: I, aliases: A, query: &DocQuery) -> Ranked<'a>
where
    I: IntoIterator<Item = &'a DocEntry>,
    A: IntoIterator<Item = (&'a str, &'a DocEntry)>,
{
    let mut scan = entries.into_iter();
    let pool: Vec<&'a DocEntry> = scan.by_ref().take(MAX_CANDIDATES).collect();
    let cut = scan.next().is_some();
    let scanned: BTreeMap<Peer<'a>, &'a DocEntry> = pool.iter().map(|e| (peer(e), *e)).collect();
    let alias_spellings: Vec<(&'a str, Peer<'a>)> = aliases
        .into_iter()
        .take(MAX_CANDIDATES)
        .filter_map(|(alias, entry)| {
            let at = peer(entry);
            scanned.contains_key(&at).then_some((alias, at))
        })
        .collect();
    let universe = || {
        pool.iter()
            .map(|e| Spelling {
                text: e.key.as_str(),
                target: peer(e),
            })
            .chain(
                alias_spellings
                    .iter()
                    .map(|&(text, target)| Spelling { text, target }),
            )
    };

    let typos = suggest::rank(
        &query.query,
        universe(),
        Policy {
            cap: Cap::MAX,
            threshold: Threshold::Relative,
        },
    );
    let typo_of: BTreeMap<Peer<'a>, Distance> =
        typos.hits.iter().map(|h| (h.target, h.distance)).collect();
    let cut = cut || typos.truncated;

    let mut matched: Vec<_> = pool
        .iter()
        .filter_map(|entry| {
            let at = peer(entry);
            let typo = typo_of.get(&at).copied();
            let (tier, secondary) = classify(entry, &Folded::of(entry), query, typo)?;
            Some(((tier, secondary, at), *entry))
        })
        .collect();

    if matched.is_empty() {
        let nearest = suggest::rank(
            &query.query,
            universe(),
            Policy {
                cap: Cap::MAX,
                threshold: Threshold::Nearest {
                    max: Distance::CEILING,
                },
            },
        );
        let mut hits: Vec<(Distance, Peer<'a>)> = nearest
            .hits
            .iter()
            .map(|h| (h.distance, h.target))
            .collect();
        hits.sort_unstable();
        return Ranked {
            entries: hits
                .into_iter()
                .filter_map(|(_, at)| scanned.get(&at).copied())
                .take(RESULT_LIMIT)
                .collect(),
            closeness: Closeness::Nearest,
            truncated: cut || nearest.truncated,
        };
    }

    matched.sort_by(|a, b| a.0.cmp(&b.0));
    let over = matched.len() > RESULT_LIMIT;
    matched.truncate(RESULT_LIMIT);
    Ranked {
        entries: matched.into_iter().map(|(_, entry)| entry).collect(),
        closeness: Closeness::Match,
        truncated: cut || over,
    }
}

/// The one entry whose key equals `query` case-insensitively, or `None` when
/// none or several do.
///
/// Scans at most [`MAX_CANDIDATES`] entries and reads at most [`FIELD_CHARS`]
/// characters of each key; a cut key never equals a query.
#[must_use]
pub fn unique_exact<'a, I>(entries: I, query: &DocQuery) -> Option<&'a DocEntry>
where
    I: IntoIterator<Item = &'a DocEntry>,
{
    let mut hits = entries
        .into_iter()
        .take(MAX_CANDIDATES)
        .filter(|entry| fold(field(&entry.key)) == query.folded());
    let first = hits.next()?;
    hits.next().is_none().then_some(first)
}

/// The best tier `entry` matches `query` in, with its secondary order.
///
/// `typo` is the shared ranker's distance for the entry, when one of its
/// spellings is within the typo threshold.
fn classify(
    entry: &DocEntry,
    folded: &Folded,
    query: &DocQuery,
    typo: Option<Distance>,
) -> Option<(Tier, usize)> {
    let q = query.folded();
    let key = folded.key.as_str();
    let member = folded.member();
    let title = folded.title.as_str();
    let tier = if key == q {
        Tier::ExactKey
    } else if member == q {
        Tier::ExactMember
    } else if title == q {
        Tier::ExactTitle
    } else if key.starts_with(q) || member.starts_with(q) {
        Tier::Prefix
    } else if title.starts_with(q) {
        Tier::TitlePrefix
    } else if segment_starts_with(field(&entry.key), q)
        || segment_starts_with(field(&entry.title), q)
    {
        Tier::Segment
    } else if key.contains(q) || title.contains(q) {
        Tier::Substring
    } else if all_words(q, key, title) {
        Tier::AllWords
    } else if let Some(distance) = typo {
        return Some((Tier::Typo, usize::from(distance.get())));
    } else {
        return subsequence_span(q, key).map(|span| (Tier::Subsequence, span));
    };
    Some((tier, 0))
}

/// The Unicode case fold the matcher compares under: the shared ranker's, so
/// the query and every field fold by the same rule.
fn fold(text: &str) -> String {
    suggest::fold(text)
}

/// The last `.` segment of a key (`ipe.time.unixmillis` → `unixmillis`), or
/// the whole key when it has none.
fn last_segment(key: &str) -> &str {
    key.rsplit_once('.').map_or(key, |(_, last)| last)
}

/// The byte offsets where a word or camelCase segment of `text` starts.
///
/// A segment starts at an alphanumeric character that follows a
/// non-alphanumeric one (or the start), and at an uppercase character that
/// follows a lowercase letter or a digit (`unixMillis` → `unix`, `Millis`).
fn segment_starts(text: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut prev: Option<char> = None;
    for (at, c) in text.char_indices() {
        if !c.is_alphanumeric() {
            prev = None;
            continue;
        }
        let boundary =
            prev.is_none_or(|p| c.is_uppercase() && (p.is_lowercase() || p.is_numeric()));
        if boundary {
            starts.push(at);
        }
        prev = Some(c);
    }
    starts
}

/// Whether the folded text from some segment start of `text` begins with the
/// folded query `q`.
fn segment_starts_with(text: &str, q: &str) -> bool {
    segment_starts(text).into_iter().any(|at| {
        text.get(at..).is_some_and(|rest| {
            let mut folded = rest.chars().flat_map(char::to_lowercase);
            q.chars().all(|qc| folded.next() == Some(qc))
        })
    })
}

/// The alphanumeric words of `text`.
fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
}

/// Whether the query has at least one word and every one is a word of the key
/// or the title (all folded).
fn all_words(q: &str, key: &str, title: &str) -> bool {
    let mut query_words = words(q).peekable();
    query_words.peek().is_some()
        && query_words.all(|w| words(key).chain(words(title)).any(|field| field == w))
}

/// The span, in characters, of the leftmost in-order match of the query's
/// characters in the folded key, or `None` when they do not all appear, the
/// query is shorter than [`SUBSEQUENCE_MIN_CHARS`], or the span is wider than
/// [`SUBSEQUENCE_SPAN_FACTOR`] times the query.
fn subsequence_span(q: &str, key: &str) -> Option<usize> {
    let q_len = q.chars().count();
    if q_len < SUBSEQUENCE_MIN_CHARS {
        return None;
    }
    let widest = q_len.saturating_mul(SUBSEQUENCE_SPAN_FACTOR);
    let mut wanted = q.chars().peekable();
    let mut first: Option<usize> = None;
    for (at, c) in key.chars().enumerate() {
        if wanted.peek() == Some(&c) {
            wanted.next();
            let start = *first.get_or_insert(at);
            if wanted.peek().is_none() {
                let span = at.saturating_sub(start).saturating_add(1);
                return (span <= widest).then_some(span);
            }
        }
    }
    None
}

/// The first `n` characters of `text`, cut on a character boundary.
fn prefix_chars(text: &str, n: usize) -> &str {
    text.char_indices()
        .nth(n)
        .and_then(|(at, _)| text.get(..at))
        .unwrap_or(text)
}

/// One listed entry of a miss: the exact `ipe doc` argument that opens it, its
/// kind, and a one-line summary — each a [`TerminalLine`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocHit {
    /// The `ipe doc` argument that opens the entry exactly.
    pub term: TerminalLine,
    /// The entry's kind.
    pub kind: DocKind,
    /// The entry's one-line summary, at most [`SUMMARY_CHARS`] plus `…`.
    pub summary: TerminalLine,
}

/// A query that opened no entry, with the ranked entries to offer instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocMiss {
    /// The query as shown back to the user.
    pub query: TerminalLine,
    /// The listed entries, best first.
    pub hits: Vec<DocHit>,
    /// Whether the hits matched or are the nearest fallback.
    pub closeness: Closeness,
    /// Whether a ceiling cut the list.
    pub truncated: bool,
}

impl DocMiss {
    /// The miss for the query shown as `shown`, listing `ranked`.
    ///
    /// `term_of` gives the `ipe doc` argument that opens an entry. A term that
    /// is not itself an acceptable query (empty, over-long, carrying a hazard,
    /// or with edge whitespace) could not be passed back, so its entry is left
    /// out rather than listed as a command that cannot run.
    #[must_use]
    pub fn new(shown: &str, ranked: &Ranked<'_>, term_of: impl Fn(&DocEntry) -> String) -> Self {
        let hits = ranked
            .entries
            .iter()
            .filter_map(|entry| {
                let term = term_of(entry);
                let parsed = DocQuery::parse(&term).ok()?;
                (parsed.text() == term).then(|| DocHit {
                    term: TerminalLine::sanitize(&term),
                    kind: entry.kind,
                    summary: summary(entry),
                })
            })
            .collect();
        Self {
            query: TerminalLine::sanitize(shown),
            hits,
            closeness: ranked.closeness,
            truncated: ranked.truncated,
        }
    }
}

/// The one-line summary of `entry`.
///
/// The title when it says more than the key; otherwise the first non-empty
/// body line, a leading Markdown heading marker dropped. Sanitised to one
/// terminal line, then cut to [`SUMMARY_CHARS`] characters with `…` marking
/// the cut.
fn summary(entry: &DocEntry) -> TerminalLine {
    let title = entry.title.trim();
    let source = if title.is_empty() || title == entry.key {
        entry
            .body
            .lines()
            .map(|line| line.trim().trim_start_matches('#').trim())
            .find(|line| !line.is_empty())
            .unwrap_or("")
    } else {
        title
    };
    clip(&TerminalLine::sanitize(source))
}

/// `line` cut to [`SUMMARY_CHARS`] characters, `…` appended when cut.
fn clip(line: &TerminalLine) -> TerminalLine {
    let text = line.as_str();
    match text.char_indices().nth(SUMMARY_CHARS) {
        None => line.clone(),
        Some((at, _)) => {
            let kept = text.get(..at).unwrap_or("").trim_end();
            TerminalLine::sanitize(&format!("{kept}…"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: DocKind, key: &str, title: &str) -> DocEntry {
        DocEntry {
            kind,
            key: key.to_owned(),
            title: title.to_owned(),
            body: String::new(),
            order: None,
        }
    }

    fn query(raw: &str) -> DocQuery {
        DocQuery::parse(raw).expect("the test query parses")
    }

    /// Rank `entries` with no aliases.
    fn plain<'a>(entries: &'a [DocEntry], q: &DocQuery) -> Ranked<'a> {
        rank(entries, std::iter::empty(), q)
    }

    fn keys<'a>(ranked: &Ranked<'a>) -> Vec<&'a str> {
        ranked.entries.iter().map(|e| e.key.as_str()).collect()
    }

    fn select_entries() -> Vec<DocEntry> {
        vec![
            entry(DocKind::Construct, "select", "Select expression"),
            entry(DocKind::Construct, "case", "Case expression"),
            entry(DocKind::Guide, "getting-started", "Getting started"),
        ]
    }

    fn tier_of(e: &DocEntry, raw: &str) -> Option<Tier> {
        let q = query(raw);
        let typo = suggest::rank(
            &q.query,
            [Spelling {
                text: e.key.as_str(),
                target: (),
            }],
            Policy {
                cap: Cap::MAX,
                threshold: Threshold::Relative,
            },
        )
        .hits
        .first()
        .map(|h| h.distance);
        classify(e, &Folded::of(e), &q, typo).map(|(tier, _)| tier)
    }

    // -- Query refusals -------------------------------------------------------

    #[test]
    fn an_empty_or_blank_query_is_refused_as_empty() {
        for raw in ["", " ", "   ", "\u{a0}"] {
            assert_eq!(DocQuery::parse(raw), Err(QueryRefusal::Empty), "{raw:?}");
        }
    }

    #[test]
    fn a_query_carrying_a_hazard_is_refused_as_a_control_char() {
        for raw in [
            "a\u{1b}[31m",
            "a\tb",
            "a\nb",
            "\u{202e}x",
            "x\u{7}",
            "\u{9b}31m",
            "\r",
        ] {
            assert_eq!(
                DocQuery::parse(raw),
                Err(QueryRefusal::ControlChar),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn the_longest_query_is_accepted_and_one_more_char_is_refused() {
        let longest = "é".repeat(MAX_QUERY_CHARS);
        assert!(DocQuery::parse(&longest).is_ok());
        let over = "é".repeat(MAX_QUERY_CHARS.saturating_add(1));
        assert_eq!(DocQuery::parse(&over), Err(QueryRefusal::TooLong));
        let huge = "x".repeat(1_000_000);
        assert_eq!(DocQuery::parse(&huge), Err(QueryRefusal::TooLong));
    }

    #[test]
    fn a_query_is_trimmed_and_folded() {
        let q = query("  Ipe.List  ");
        assert_eq!(q.text(), "Ipe.List");
        assert_eq!(q.folded(), "ipe.list");
    }

    // -- Ranking --------------------------------------------------------------

    #[test]
    fn every_tier_is_reached_and_ordered() {
        let cases = [
            (
                entry(DocKind::Symbol, "Ipe.Time.unixMillis", "x"),
                "ipe.time.unixmillis",
                Tier::ExactKey,
            ),
            (
                entry(DocKind::Symbol, "Ipe.Time.unixMillis", "x"),
                "unixmillis",
                Tier::ExactMember,
            ),
            (
                entry(DocKind::Topic, "pipes", "Pipelines"),
                "pipelines",
                Tier::ExactTitle,
            ),
            (
                entry(DocKind::Symbol, "Ipe.Time.unixMillis", "x"),
                "unix",
                Tier::Prefix,
            ),
            (
                entry(DocKind::Topic, "pipes", "Pipelines"),
                "pipeli",
                Tier::TitlePrefix,
            ),
            (
                entry(DocKind::Symbol, "Ipe.Time.unixMillis", "x"),
                "mill",
                Tier::Segment,
            ),
            (
                entry(DocKind::Symbol, "Ipe.Time.unixMillis", "x"),
                "xmil",
                Tier::Substring,
            ),
            (
                entry(DocKind::Construct, "select", "Select expression"),
                "expression select",
                Tier::AllWords,
            ),
            (
                entry(DocKind::Construct, "select", "Select expression"),
                "slect",
                Tier::Typo,
            ),
            (
                entry(DocKind::Construct, "select", "Select expression"),
                "selcet",
                Tier::Typo,
            ),
            (
                entry(DocKind::Symbol, "Ipe.Time.unixMillis", "x"),
                "unxm",
                Tier::Subsequence,
            ),
        ];
        for (e, raw, want) in &cases {
            assert_eq!(tier_of(e, raw), Some(*want), "{raw:?} against {}", e.key);
        }
        let tiers: Vec<Tier> = cases.iter().map(|(_, _, t)| *t).collect();
        let mut sorted = tiers.clone();
        sorted.sort();
        assert_eq!(tiers, sorted, "the cases above are listed best first");
    }

    #[test]
    fn a_better_tier_ranks_first() {
        let entries = vec![
            entry(DocKind::Symbol, "Ipe.List.mapping", "x"),
            entry(DocKind::Symbol, "Ipe.List.map", "x"),
            entry(DocKind::Symbol, "Ipe.Dict.remap", "x"),
            entry(DocKind::Construct, "map", "Map"),
        ];
        let ranked = plain(&entries, &query("map"));
        assert_eq!(
            keys(&ranked),
            ["map", "Ipe.List.map", "Ipe.List.mapping", "Ipe.Dict.remap"]
        );
        assert_eq!(ranked.closeness, Closeness::Match);
        assert!(!ranked.truncated);
    }

    #[test]
    fn ties_break_by_length_then_kind_then_key() {
        let entries = vec![
            entry(DocKind::Topic, "map-b", "x"),
            entry(DocKind::Guide, "map-a", "x"),
            entry(DocKind::Topic, "map-a", "x"),
            entry(DocKind::Idiom, "map", "x"),
        ];
        let ranked = plain(&entries, &query("ma"));
        let order: Vec<(DocKind, &str)> = ranked
            .entries
            .iter()
            .map(|e| (e.kind, e.key.as_str()))
            .collect();
        assert_eq!(
            order,
            [
                (DocKind::Idiom, "map"),
                (DocKind::Topic, "map-a"),
                (DocKind::Topic, "map-b"),
                (DocKind::Guide, "map-a"),
            ]
        );
    }

    #[test]
    fn the_same_query_ranks_the_same_way_every_run() {
        let entries = select_entries();
        for raw in ["e", "sel", "zzzzzzzz", "expression"] {
            let first = keys(&plain(&entries, &query(raw)));
            let reversed: Vec<DocEntry> = entries.iter().rev().cloned().collect();
            assert_eq!(first, keys(&plain(&entries, &query(raw))), "{raw:?}");
            assert_eq!(
                first,
                keys(&plain(&reversed, &query(raw))),
                "input order never changes the ranking: {raw:?}"
            );
        }
    }

    #[test]
    fn a_typo_ranks_above_a_scattered_subsequence() {
        let entries = vec![
            entry(DocKind::Symbol, "Ipe.List.map", "x"),
            entry(DocKind::Symbol, "Ipe.Task.mapAlp", "x"),
        ];
        let ranked = plain(&entries, &query("mapp"));
        assert_eq!(keys(&ranked), ["Ipe.List.map", "Ipe.Task.mapAlp"]);
        assert!(
            subsequence_span("mapp", "ipe.maybe.andthenmapping").is_none(),
            "a match spread wider than twice the query is no subsequence hit"
        );
        assert_eq!(subsequence_span("unxm", "ipe.time.unixmillis"), Some(5));
    }

    #[test]
    fn an_alias_ranks_its_canonical_entry_and_is_never_listed() {
        let entries = vec![
            entry(DocKind::Symbol, "Ipe.List.foldl", "x"),
            entry(DocKind::Symbol, "Ipe.List.map", "x"),
        ];
        let canonical = entries.first().expect("one entry");
        let aliases = [("Ipe.List.reduce", canonical)];
        let ranked = rank(&entries, aliases, &query("List.redcue"));
        assert_eq!(keys(&ranked), ["Ipe.List.foldl"]);
        assert_eq!(ranked.closeness, Closeness::Match);
    }

    #[test]
    fn a_typo_finds_the_intended_key() {
        let selects = select_entries();
        let ranked = plain(&selects, &query("slect"));
        assert_eq!(keys(&ranked).first(), Some(&"select"));
        let entries = vec![
            entry(
                DocKind::Symbol,
                "Ipe.Time.unixMillis",
                "Ipe.Time.unixMillis",
            ),
            entry(DocKind::Symbol, "Ipe.Time.now", "Ipe.Time.now"),
            entry(DocKind::Symbol, "Ipe.List.map", "Ipe.List.map"),
        ];
        let ranked = plain(&entries, &query("unixMilis"));
        assert_eq!(keys(&ranked).first(), Some(&"Ipe.Time.unixMillis"));
        let ranked = plain(&entries, &query("unixmillis"));
        assert_eq!(keys(&ranked), ["Ipe.Time.unixMillis"]);
    }

    #[test]
    fn unicode_folds_and_never_slices_inside_a_character() {
        let entries = vec![
            entry(DocKind::Topic, "ünïcode", "Ünïcode Straße"),
            entry(DocKind::Topic, "日本語-text", "日本語"),
            entry(DocKind::Topic, "emoji", "🦀🦀🦀 crab"),
        ];
        assert_eq!(keys(&plain(&entries, &query("ÜNÏCODE"))), ["ünïcode"]);
        assert_eq!(keys(&plain(&entries, &query("straße"))), ["ünïcode"]);
        assert_eq!(
            keys(&plain(&entries, &query("本語"))).first(),
            Some(&"日本語-text")
        );
        for raw in ["🦀", "🦀x", "語", "é", "ß"] {
            let _ = plain(&entries, &query(raw));
        }
        let long = "日".repeat(suggest::DISTANCE_CHARS.saturating_mul(3));
        let wide = vec![entry(DocKind::Topic, &long, &long)];
        let ranked = plain(&wide, &query("本"));
        assert_eq!(ranked.closeness, Closeness::Nearest);
        assert_eq!(ranked.entries.len(), 1);
    }

    #[test]
    fn nothing_matching_falls_back_to_the_nearest_entries() {
        let selects = select_entries();
        let ranked = plain(&selects, &query("zzzzzzzzzzz"));
        assert_eq!(ranked.closeness, Closeness::Nearest);
        assert!(!ranked.entries.is_empty(), "never a dead end");
        assert!(ranked.entries.len() <= RESULT_LIMIT);
        let empty: Vec<DocEntry> = Vec::new();
        let ranked = plain(&empty, &query("zzz"));
        assert!(ranked.entries.is_empty());
    }

    #[test]
    fn a_field_longer_than_its_ceiling_is_cut_and_the_ranking_stays_total() {
        fn kinds(ranked: &Ranked<'_>) -> Vec<DocKind> {
            ranked.entries.iter().map(|e| e.kind).collect()
        }
        let huge = "a".repeat(1 << 20);
        let cut = Folded::of(&entry(DocKind::Topic, "huge", &huge));
        assert_eq!(cut.title.chars().count(), FIELD_CHARS);
        let long_key = Folded::of(&entry(DocKind::Topic, &huge, "t"));
        assert_eq!(long_key.key.chars().count(), FIELD_CHARS);
        assert!(long_key.key_cut);
        assert!(!Folded::of(&entry(DocKind::Topic, "huge", "t")).key_cut);

        let entries = vec![
            entry(DocKind::Topic, "huge", &huge),
            entry(DocKind::Guide, "huge", &huge),
            entry(DocKind::Topic, &huge, &huge),
            entry(DocKind::Topic, "alpha", "Alpha"),
        ];
        let mut reversed = entries.clone();
        reversed.reverse();
        for raw in ["a", "aaa", "huge", "zzzz", "alpha"] {
            let first = plain(&entries, &query(raw));
            assert_eq!(keys(&first), keys(&plain(&entries, &query(raw))), "{raw:?}");
            let back = plain(&reversed, &query(raw));
            assert_eq!(keys(&first), keys(&back), "{raw:?}");
            assert_eq!(kinds(&first), kinds(&back), "{raw:?}");
        }
    }

    #[test]
    fn a_cut_field_never_matches_exactly() {
        let at_ceiling = "a".repeat(MAX_QUERY_CHARS);
        let title = "a".repeat(FIELD_CHARS.saturating_add(1));
        let e = entry(DocKind::Topic, "k", &title);
        assert_eq!(tier_of(&e, &at_ceiling), Some(Tier::TitlePrefix));

        let mut key = "x".repeat(FIELD_CHARS.saturating_sub(4));
        key.push_str(".mappings");
        let e = entry(DocKind::Symbol, &key, "t");
        assert_ne!(
            tier_of(&e, "map"),
            Some(Tier::ExactMember),
            "the cut hid the real last segment"
        );
        assert!(unique_exact(std::slice::from_ref(&e), &query("map")).is_none());
    }

    #[test]
    fn the_result_ceiling_cuts_the_list_and_marks_it_truncated() {
        let many: Vec<DocEntry> = (0..30)
            .map(|n| entry(DocKind::Topic, &format!("pipe-{n:02}"), "Pipes"))
            .collect();
        let ranked = plain(&many, &query("pipe"));
        assert_eq!(ranked.entries.len(), RESULT_LIMIT);
        assert!(ranked.truncated);
        let exact: Vec<DocEntry> = many.iter().take(RESULT_LIMIT).cloned().collect();
        let ranked = plain(&exact, &query("pipe"));
        assert_eq!(ranked.entries.len(), RESULT_LIMIT);
        assert!(!ranked.truncated, "exactly the ceiling is not a cut");
        let far: Vec<DocEntry> = (0..30)
            .map(|n| entry(DocKind::Topic, &format!("t{n:02}"), "T"))
            .collect();
        let ranked = plain(&far, &query("zzzzzzzzzzzzz"));
        assert_eq!(ranked.closeness, Closeness::Nearest);
        assert_eq!(ranked.entries.len(), RESULT_LIMIT);
    }

    #[test]
    fn the_candidate_ceiling_stops_the_scan_and_marks_it_truncated() {
        let over: Vec<DocEntry> = (0..MAX_CANDIDATES.saturating_add(1))
            .map(|n| entry(DocKind::Topic, &format!("k{n}"), "T"))
            .collect();
        let last = over.last().map(|e| e.key.clone()).unwrap_or_default();
        let ranked = plain(&over, &query(&last));
        assert!(ranked.truncated);
        assert!(
            ranked.entries.iter().all(|e| e.key != last),
            "the entry past the ceiling is never scanned"
        );
        assert!(unique_exact(&over, &query(&last)).is_none());
    }

    #[test]
    fn unique_exact_opens_one_key_and_refuses_several() {
        let entries = select_entries();
        assert_eq!(
            unique_exact(&entries, &query("SELECT")).map(|e| e.key.as_str()),
            Some("select")
        );
        assert!(unique_exact(&entries, &query("selec")).is_none());
        let twice = vec![
            entry(DocKind::Topic, "select", "A"),
            entry(DocKind::Construct, "select", "B"),
        ];
        assert!(unique_exact(&twice, &query("select")).is_none());
    }

    // -- Misses and summaries -------------------------------------------------

    #[test]
    fn a_miss_lists_only_terms_that_parse_back_unchanged() {
        let entries = vec![
            entry(DocKind::Topic, "pipes", "Pipes"),
            entry(DocKind::Topic, "pipes-two", "Pipes two"),
        ];
        let ranked = plain(&entries, &query("pipes"));
        let miss = DocMiss::new("pipes", &ranked, |e| {
            if e.key == "pipes" {
                format!("topic:{}", e.key)
            } else {
                format!(" topic:{}\u{1b}[2J", e.key)
            }
        });
        let terms: Vec<&str> = miss.hits.iter().map(|h| h.term.as_str()).collect();
        assert_eq!(terms, ["topic:pipes"]);
    }

    #[test]
    fn a_summary_never_carries_a_control_or_escape() {
        let hostile = DocEntry {
            kind: DocKind::Topic,
            key: "x".to_owned(),
            title: "Ti\u{1b}]0;pwned\u{7}tle\u{202e}\r\n\tend".to_owned(),
            body: String::new(),
            order: None,
        };
        let s = summary(&hostile);
        assert!(
            s.as_str().chars().all(|c| !c.is_control()),
            "{:?}",
            s.as_str()
        );
        assert!(!s.as_str().contains('\u{202e}'));
        assert!(s.as_str().starts_with("Ti"));
    }

    #[test]
    fn a_summary_falls_back_to_the_first_body_line_and_is_cut() {
        let e = DocEntry {
            kind: DocKind::Symbol,
            key: "Ipe.List.map".to_owned(),
            title: "Ipe.List.map".to_owned(),
            body: "\n\n# Apply a function\nmore".to_owned(),
            order: None,
        };
        assert_eq!(summary(&e).as_str(), "Apply a function");
        let long = DocEntry {
            title: "é".repeat(SUMMARY_CHARS.saturating_mul(2)),
            ..e
        };
        let cut = summary(&long);
        assert_eq!(
            cut.as_str().chars().count(),
            SUMMARY_CHARS.saturating_add(1)
        );
        assert!(cut.as_str().ends_with('…'));
        let exact = DocEntry {
            title: "a".repeat(SUMMARY_CHARS),
            ..long
        };
        assert_eq!(summary(&exact).as_str(), "a".repeat(SUMMARY_CHARS));
    }
}
