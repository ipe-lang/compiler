//! The layout engine that reads the text it renders, kept to prove the engine
//! reading measures writes the same bytes for every document.

use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use crate::doc::{ChainOperand, Doc, LeafNorm};

use super::RenderConfig;

/// The number of columns a chain's broken operators indent past the chain's
/// begin-line indent. `rustfmt` uses one block-indent step (4).
const CHAIN_BREAK_INDENT: usize = 4;

/// `rustfmt`'s `fn_call_width` (default 60): the maximum width of a function-call
/// (or constructor / tuple) ARGUMENT LIST — the text between the parentheses,
/// excluding the callee and the delimiters — that `rustfmt` keeps on one line.
/// A call whose flat argument list exceeds this breaks one argument per line even
/// when the whole line would still fit `max_width`. Macro (`format!` / `vec!`)
/// argument lists use a different (wrap-to-`max_width`) layout and are not gated
/// by this width.
const FN_CALL_WIDTH: usize = 60;

/// Render `doc` to a string starting at column `col` with block indent `indent`.
/// `col` is where the document's first character will be placed (used for the
/// fit test); `indent` is the number of leading spaces a broken line receives.
pub fn render(doc: &Doc, cfg: RenderConfig) -> String {
    render_bounded(doc, cfg, 0, 0)
}

/// Render `doc` as if its first character lands at column `col` with the given
/// block `indent` for any line it breaks onto. Used to lay out a construct that
/// is spliced after a fixed prefix already occupying the start of its line — the
/// `IpeStringify` `format!` body, which begins after `        ` (record) or after
/// the `… => ` arm head (enum), and whose broken argument lines nest from the
/// enclosing block indent, not from `col`. The returned string carries no leading
/// prefix for `col` (the caller already wrote it); every broken line carries its
/// own absolute indentation.
pub fn render_seeded(doc: &Doc, cfg: RenderConfig, indent: usize, col: usize) -> String {
    render_bounded(doc, cfg, indent, col)
}

/// Lay `doc` out within [`LAYOUT_FUEL`]. A document whose layout search runs the
/// fuel out gets its [`Doc::plain_layout`] instead: one pass, no fit decision, the
/// same tokens — layout never changes what the code means.
fn render_bounded(doc: &Doc, cfg: RenderConfig, indent: usize, col: usize) -> String {
    render_within(doc, cfg, indent, col, LAYOUT_FUEL)
}

/// Lay `doc` out within `fuel`, falling back to its [`Doc::plain_layout`].
fn render_within(doc: &Doc, cfg: RenderConfig, indent: usize, col: usize, fuel: usize) -> String {
    render_within_spend(doc, cfg, indent, col, fuel).0
}

/// What one bounded render spent of its layout fuel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutSpend {
    /// The fuel the layout search spent, the whole fuel when it ran out.
    pub spent: usize,
    /// Whether the search ran out and the render returned its plain layout.
    pub exhausted: bool,
}

/// [`render_seeded`], also reporting what its layout search spent of [`LAYOUT_FUEL`].
pub fn render_seeded_spend(
    doc: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
) -> (String, LayoutSpend) {
    render_within_spend(doc, cfg, indent, col, LAYOUT_FUEL)
}

/// [`render_within`], also reporting what its layout search spent of `fuel`.
///
/// A scope without its memo reads as exhausted, so the render falls back to its
/// plain layout and the report never claims a search that did not run.
fn render_within_spend(
    doc: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    fuel: usize,
) -> (String, LayoutSpend) {
    let _scope = MemoScope::install(doc, fuel);
    let mut out = String::new();
    render_at(doc, cfg, indent, col, false, &mut out);
    let spend = MEMO.with_borrow(|m| {
        m.as_ref().map_or(
            LayoutSpend {
                spent: fuel,
                exhausted: true,
            },
            |m| LayoutSpend {
                spent: fuel.saturating_sub(m.fuel),
                exhausted: m.exhausted,
            },
        )
    });
    if spend.exhausted {
        return (doc.plain_layout(), spend);
    }
    (out, spend)
}

/// The work one render may do before it falls back to its plain layout.
///
/// Counted in bytes: each layout computed or replayed spends the bytes it writes
/// plus the line it measures its cursor on, a leaf included, and every node a
/// shape predicate or a node fact walks spends a step, so the fuel bounds all the
/// work a render does. Flat fit probes read cached per-node measures and cost O(1)
/// each; the fuel bounds the probes that remain — non-flat layouts whose answer
/// depends on the column and indent a node lands at — and a document that
/// exhausts it gets its plain layout instead.
pub const LAYOUT_FUEL: usize = 1 << 26;

/// The byte ceiling on the layouts one render keeps memoized, each entry charged
/// [`memo_entry_bytes`]. Past it the memo stops growing and later nodes render
/// uncached: output is unchanged, only the reuse is capped, so a pathological
/// document cannot grow the memo without bound.
const MEMO_BYTE_CEILING: usize = 64 << 20;

/// What one memoized layout occupies: its bytes plus the key, the [`Layout`]
/// header, and the hash-table slot, so a flood of empty layouts is charged too.
const fn memo_entry_bytes(layout_len: usize) -> usize {
    layout_len
        .saturating_add(size_of::<MemoKey>())
        .saturating_add(size_of::<Layout>())
        .saturating_add(size_of::<u64>())
}

/// What one cut layout occupies: a memo entry whose key also carries its
/// [`CutBound`].
const fn cut_entry_bytes(layout_len: usize) -> usize {
    memo_entry_bytes(layout_len.saturating_add(size_of::<CutBound>()))
}

/// A whole memoized layout, with the width its tail lines need.
struct Layout {
    text: String,
    /// The widest line after the first, without its indentation.
    widest_tail: usize,
}

impl Layout {
    /// The layout `text`, its tail width measured once as it is kept. The walk
    /// is linear in `text`, whose bytes the render that wrote it already spent.
    fn of(text: &str) -> Self {
        Self {
            text: text.to_owned(),
            widest_tail: widest_tail(text),
        }
    }
}

/// The widest line of `text` after its first, without its indentation.
pub(super) fn widest_tail(text: &str) -> usize {
    text.split('\n')
        .skip(1)
        .map(|line| line.trim_start().len())
        .max()
        .unwrap_or_default()
}

/// Every layout decision probes a subtree by a [`trial`] render before rendering
/// it for real, and a probed subtree probes its own children the same way, so
/// without reuse the work doubles with each nesting level. A trial lays the
/// subtree out where the real render will — same buffer, column, cursor, config
/// and budget — so the real render replays what the trial laid out. The memo
/// makes a node's layout a pure function computed once per render: keyed by the
/// node's address and every input its render reads — the config, the indent, the
/// seed column, the [`Pass`], and the buffer's [`Cursor`] — it replays the bytes
/// that render produced.
///
/// Only nodes of the document passed to [`render`] / [`render_seeded`] are keyed:
/// they stay borrowed for the whole render, so no other node can take their
/// address. A document a layout builds on the fly is rendered uncached.
struct Memo {
    nodes: HashSet<usize>,
    layouts: HashMap<MemoKey, Layout>,
    bytes: usize,
    /// [`has_hard_break`] per node, computed once.
    hard_breaks: HashMap<usize, bool>,
    /// [`if_else_construct_width`] per `IfElse` node, computed once.
    if_else_widths: HashMap<usize, usize>,
    /// [`leaf_norm`] per node, computed once, bottom-up.
    leaf_norms: HashMap<usize, LeafNorm>,
    /// The ceiling on `bytes`, [`MEMO_BYTE_CEILING`] for every production render.
    byte_ceiling: usize,
    /// [`flat_fixed`] per node, computed once.
    flat_fixed: HashMap<usize, bool>,
    /// The single-line flat layout of each [`flat_fixed`] node, shared by every
    /// context it renders in; charged to `bytes` like `layouts`.
    flat_layouts: HashMap<FlatKey, String>,
    /// [`flat_measure`] per [`flat_fixed`] node, computed once.
    flat_measures: HashMap<FlatKey, FlatMeasure>,
    /// The first line, through its newline, of each layout a first-line [`trial`]
    /// rendered and saw break; charged to `bytes` like `layouts`.
    first_lines: HashMap<MemoKey, String>,
    /// Where the innermost bounded [`trial`] stops laying out.
    stop_mark: Option<StopMark>,
    /// Whether the innermost width-bounded [`trial`] has cut its layout short
    /// since the innermost open memoized render began.
    cut: bool,
    /// The layouts a width-bounded [`trial`] cut short, apart from `layouts`:
    /// each is laid out only up to where the cut decided its trial, so it is
    /// replayed only under the same cut; charged [`cut_entry_bytes`] to `bytes`.
    cuts: HashMap<CutKey, String>,
    /// [`is_block_like`] per node, computed once.
    block_like: HashMap<usize, bool>,
    /// [`is_glue_shape`] per node, computed once.
    glue_shapes: HashMap<usize, bool>,
    /// [`is_delimited_expr`] per node, computed once.
    delimited_exprs: HashMap<usize, bool>,
    /// [`receiver_is_method_chain`] per node, computed once.
    chain_receivers: HashMap<usize, bool>,
    /// [`LAYOUT_FUEL`] left to spend; once spent the render is abandoned.
    fuel: usize,
    exhausted: bool,
    /// The layout bytes charged for what the open buffers hold: every byte is
    /// charged once, by the innermost memoized render that wrote or replayed it,
    /// so an enclosing layout is charged only its own share.
    charged: usize,
}

/// Everything a node's render reads besides the node itself.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct MemoKey {
    node: usize,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    pass: Pass,
    cursor: Cursor,
}

/// Which renderer laid a node out, with the inputs only that renderer reads.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Pass {
    /// [`render_at`], flat or letting the node's own groups decide.
    Layout { flat: bool },
    /// [`render_forced_break`], under an enclosing call-argument combine.
    ForcedBreak { combine_base: usize, budget: usize },
}

/// What a render reads of the buffer it appends to: whether anything is written
/// yet, the current line's length and whether it is all indentation, and the run
/// of trailing spaces a break may trim before writing its newline.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct Cursor {
    pub(super) empty: bool,
    pub(super) line_len: usize,
    pub(super) blank_line: bool,
    pub(super) trailing_spaces: usize,
}

impl Cursor {
    pub(super) fn of(out: &str) -> Self {
        let line = out.rsplit('\n').next().unwrap_or_default();
        Self {
            empty: out.is_empty(),
            line_len: line.len(),
            blank_line: line.bytes().all(|b| b == b' '),
            trailing_spaces: out.len().saturating_sub(out.trim_end_matches(' ').len()),
        }
    }
}

/// What a [`flat_fixed`] node's flat layout reads besides the node itself.
///
/// `max_width` is carried even though no flat decision reads it, so a shared
/// layout never crosses a change of width.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlatKey {
    node: usize,
    max_width: usize,
    inline_hard: bool,
}

impl FlatKey {
    fn of(doc: &Doc, cfg: RenderConfig) -> Self {
        Self {
            node: node_addr(doc),
            max_width: cfg.max_width,
            inline_hard: cfg.inline_hard,
        }
    }
}

/// The facts the fit probes read of a node's flat layout.
///
/// Every field is read off the one flat render [`flat_measure`] makes through
/// [`render_at`], so a probe answered from it sees the bytes the real render writes.
#[derive(Clone, Copy)]
pub(super) struct FlatMeasure {
    /// The flat layout carries no newline.
    pub(super) single_line: bool,
    /// The length of the flat layout up to its first newline.
    pub(super) first_len: usize,
    /// The flat layout begins with `(`.
    pub(super) starts_paren: bool,
}

impl FlatMeasure {
    pub(super) fn of(layout: &str) -> Self {
        Self {
            single_line: !layout.contains('\n'),
            first_len: layout.find('\n').unwrap_or(layout.len()),
            starts_paren: layout.starts_with('('),
        }
    }

    /// The single-line width, or `None` when the flat layout breaks.
    const fn width(self) -> Option<usize> {
        if self.single_line {
            Some(self.first_len)
        } else {
            None
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Nodes laid out afresh (not replayed) — the bound test's work measure.
    static RENDERED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Work charged summarising leaf streams — the width-fact bound test's measure.
    static NORM_WORK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

thread_local! {
    static MEMO: RefCell<Option<Memo>> = const { RefCell::new(None) };
}

/// Installs a fresh [`Memo`] over one document for the scope's lifetime and
/// restores the enclosing one on drop, so a stale address can never be looked up
/// after its document is gone.
struct MemoScope(Option<Memo>);

impl MemoScope {
    fn install(doc: &Doc, fuel: usize) -> Self {
        Self::install_capped(doc, fuel, MEMO_BYTE_CEILING)
    }

    /// [`MemoScope::install`] with the memo's byte ceiling given.
    fn install_capped(doc: &Doc, fuel: usize, byte_ceiling: usize) -> Self {
        let mut nodes = HashSet::new();
        collect_node_addrs(doc, &mut nodes);
        let memo = Memo {
            nodes,
            layouts: HashMap::new(),
            bytes: 0,
            hard_breaks: HashMap::new(),
            if_else_widths: HashMap::new(),
            leaf_norms: HashMap::new(),
            byte_ceiling,
            flat_fixed: HashMap::new(),
            flat_layouts: HashMap::new(),
            flat_measures: HashMap::new(),
            first_lines: HashMap::new(),
            stop_mark: None,
            cut: false,
            cuts: HashMap::new(),
            block_like: HashMap::new(),
            glue_shapes: HashMap::new(),
            delimited_exprs: HashMap::new(),
            chain_receivers: HashMap::new(),
            fuel,
            exhausted: false,
            charged: 0,
        };
        Self(MEMO.replace(Some(memo)))
    }
}

/// Whether the render under the innermost [`MemoScope`] ran out of
/// [`LAYOUT_FUEL`], leaving its output incomplete.
fn fuel_exhausted() -> bool {
    MEMO.with_borrow(|m| m.as_ref().is_some_and(|m| m.exhausted))
}

impl Drop for MemoScope {
    fn drop(&mut self) {
        MEMO.set(self.0.take());
    }
}

fn node_addr(doc: &Doc) -> usize {
    std::ptr::from_ref(doc).addr()
}

/// Record the address of every composite node under `doc` — the nodes whose render
/// probes or recurses, and so the ones worth memoizing. Leaves render in O(1).
fn collect_node_addrs(doc: &Doc, nodes: &mut HashSet<usize>) {
    match doc {
        Doc::Text(_)
        | Doc::Line
        | Doc::Softline
        | Doc::HardLine
        | Doc::IfBroken(_)
        | Doc::OrPattern { .. } => return,
        Doc::Concat(docs) => {
            for d in docs {
                collect_node_addrs(d, nodes);
            }
        }
        Doc::Nest(_, inner)
        | Doc::Group(inner)
        | Doc::BraceBody(inner)
        | Doc::ElidableParen { inner }
        | Doc::MatchArmTail { body: inner, .. } => collect_node_addrs(inner, nodes),
        Doc::Assign { prefix, rhs, .. } => {
            collect_node_addrs(prefix, nodes);
            collect_node_addrs(rhs, nodes);
        }
        Doc::Chain { operands } => {
            for op in operands {
                collect_node_addrs(&op.doc, nodes);
            }
        }
        Doc::CallArgs {
            open, elems, close, ..
        }
        | Doc::StructLit {
            open,
            fields: elems,
            close,
        } => {
            collect_node_addrs(open, nodes);
            for e in elems {
                collect_node_addrs(e, nodes);
            }
            collect_node_addrs(close, nodes);
        }
        Doc::TypeBound {
            ptr_open,
            head,
            traits,
            close,
        } => {
            collect_node_addrs(ptr_open, nodes);
            collect_node_addrs(head, nodes);
            for t in traits {
                collect_node_addrs(t, nodes);
            }
            collect_node_addrs(close, nodes);
        }
        Doc::MethodChain { receiver, method } => {
            collect_node_addrs(receiver, nodes);
            collect_node_addrs(method, nodes);
        }
        Doc::IfElse { cond, then_, else_ } => {
            collect_node_addrs(cond, nodes);
            collect_node_addrs(then_, nodes);
            collect_node_addrs(else_, nodes);
        }
    }
    nodes.insert(node_addr(doc));
}

/// The current column after the last newline in `out`, i.e. how many characters
/// sit on the line so far. This is the live cursor the fit tests measure.
fn current_col(out: &str) -> usize {
    out.rfind('\n').map_or(out.len(), |nl| out.len() - nl - 1)
}

/// The column the next character will land on. Once anything has been written to
/// `out`, the live cursor ([`current_col`]) is authoritative — including after a
/// break reset it to the fresh line's indent. The seed `col` is used only for an
/// empty buffer (the render root, or a [`first_line_fresh`] measure), where there
/// is no cursor yet. Taking `max` here would leak a pre-newline column past a
/// break, so we deliberately prefer the live cursor.
fn eff_col(out: &str, col: usize) -> usize {
    if out.is_empty() {
        col
    } else {
        current_col(out)
    }
}

/// Render `doc` into `out`. `indent` is the block indent for newlines within
/// `doc`; `flat` is `true` when the nearest enclosing [`Doc::Group`] chose flat,
/// which turns a soft [`Doc::Line`] into a space and a [`Doc::Softline`] into
/// nothing. A [`Doc::HardLine`] ignores `flat` — it always breaks (and its
/// presence already forced every enclosing group broken, so it is never reached
/// with `flat == true` in practice, but it breaks unconditionally regardless).
/// `col` is the column the first char lands on.
fn render_at(
    doc: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    if flat && is_keyed(doc) && flat_fixed(doc) {
        render_flat_shared(doc, cfg, indent, col, out);
        return;
    }
    memoized(doc, cfg, indent, col, Pass::Layout { flat }, out, |out| {
        render_node(doc, cfg, indent, col, flat, out);
    });
}

/// Whether `doc` belongs to the document under the innermost [`MemoScope`].
fn is_keyed(doc: &Doc) -> bool {
    let addr = node_addr(doc);
    MEMO.with_borrow(|m| m.as_ref().is_some_and(|m| m.nodes.contains(&addr)))
}

/// Render a keyed [`flat_fixed`] node flat, appending its shared layout if kept.
///
/// A single-line flat layout of such a node reads nothing of its context (see
/// [`flat_fixed`]) and writes no newline, so it trims nothing before it and is the
/// same bytes appended in every context. A multi-line one places its later lines
/// at `indent`, so it stays with the per-context memo.
fn render_flat_shared(doc: &Doc, cfg: RenderConfig, indent: usize, col: usize, out: &mut String) {
    // A probe past its first line keeps nothing more, and its empty append must
    // not stand in for the node's shared layout.
    if reach(std::ptr::from_ref::<String>(out).addr(), out) == Reach::Done {
        if !spend(1) {
            abandon(out);
        }
        return;
    }
    let key = FlatKey::of(doc, cfg);
    let shared = MEMO.with_borrow(|m| {
        let m = m.as_ref()?;
        if m.exhausted {
            return Some(None);
        }
        m.flat_layouts.get(&key).map(|layout| {
            out.push_str(layout);
            Some(layout.len())
        })
    });
    match shared {
        Some(Some(len)) => {
            if spend(len.saturating_add(1)) {
                hold_charged(len);
            }
            return;
        }
        Some(None) => return,
        None => {}
    }
    let start = out.len();
    let base = out.trim_end_matches(' ').len();
    let cut = cut_during(out, |out| {
        memoized(
            doc,
            cfg,
            indent,
            col,
            Pass::Layout { flat: true },
            out,
            |out| {
                render_node(doc, cfg, indent, col, true, out);
            },
        );
    });
    // A layout a width bound cut short is not the one every context appends.
    if cut {
        return;
    }
    let appended = out
        .get(base..)
        .is_some_and(|written| !written.contains('\n'));
    let Some(layout) = out.get(start..).filter(|_| appended) else {
        return;
    };
    MEMO.with_borrow_mut(|m| {
        let entry = memo_entry_bytes(layout.len());
        if let Some(m) = m.as_mut()
            && !m.exhausted
            && let Some(bytes) = m.bytes.checked_add(entry)
            && bytes <= m.byte_ceiling
        {
            m.bytes = bytes;
            m.flat_layouts.insert(key, layout.to_owned());
        }
    });
}

/// How much more of its layout a render into a buffer must write.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// Every byte: no first-line [`trial`] is open on the buffer.
    Whole,
    /// Up to and including the first newline the open trial writes, which the
    /// buffer does not hold yet.
    FirstLine,
    /// Nothing: the open trial's first line is complete.
    Done,
}

/// The buffer, and the offset in it, from which a [`trial`] watches for where
/// it stops laying out.
#[derive(Clone, Copy)]
struct StopMark {
    addr: usize,
    from: usize,
    bound: StopBound,
}

/// Where a [`trial`] stops laying out, with what it has already scanned.
///
/// A width-bounded trial decides a verdict that fails once one byte lands past
/// its width that no later trim can remove, so it stops there: the rest of the
/// layout could not change the verdict. Its scan state only skips bytes already
/// scanned — nothing below a buffer's trailing-space run is rewritten except by
/// a nested trial's roll back, which restores it.
#[derive(Clone, Copy)]
enum StopBound {
    /// At the first newline.
    FirstLine,
    /// At the first newline, or at the first byte past `width` on the first line
    /// that is not a space or an open delimiter; nothing below `clear` is one.
    FirstLineWithin { width: usize, clear: usize },
    /// Once a line after the first newline carries content wider than `width`;
    /// every line before `tail` is scanned and fits.
    WholeWithin { width: usize, tail: Option<usize> },
}

/// Whether a byte on a line leaves a width verdict open: a space may be trimmed,
/// and an open delimiter ending a head is not counted in its width.
const fn width_neutral(byte: u8) -> bool {
    matches!(byte, b' ' | b'(' | b'{' | b'[')
}

/// The width a line's content takes: without its indentation, nor the trailing
/// spaces a break trims.
pub(super) fn content_width(line: &str) -> usize {
    line.trim_start().trim_end_matches(' ').len()
}

impl StopMark {
    /// The [`Reach`] of a render into `out`, and whether the mark's width bound
    /// has cut the trial short.
    ///
    /// A trial never writes below its `from` offset and a buffer only grows past
    /// its last newline — a break trims trailing spaces, never a newline — so
    /// once a newline sits at or past `from` the trial's first line is final, and
    /// a byte past the width that no trim removes stays on its line.
    fn observe(&mut self, out: &str) -> (Reach, bool) {
        let from = self.from;
        let last_newline = out.rfind('\n');
        let past_first_line = last_newline.is_some_and(|nl| nl >= from);
        match &mut self.bound {
            StopBound::FirstLine | StopBound::FirstLineWithin { .. } if past_first_line => {
                (Reach::Done, false)
            }
            StopBound::FirstLine => (Reach::FirstLine, false),
            StopBound::FirstLineWithin { width, clear } => {
                let line_start = last_newline.map_or(0, |nl| nl.saturating_add(1));
                let scan = (*clear).max(from).max(line_start.saturating_add(*width));
                let over = out.as_bytes().get(scan..).and_then(|rest| {
                    rest.iter()
                        .position(|&b| !width_neutral(b))
                        .map(|at| scan.saturating_add(at))
                });
                let (scanned, observed) = over.map_or_else(
                    || (out.trim_end_matches(' ').len(), (Reach::FirstLine, false)),
                    |at| (at, (Reach::Done, true)),
                );
                *clear = scanned;
                observed
            }
            StopBound::WholeWithin { width, tail } => observe_tail(out, from, *width, tail),
        }
    }

    /// The [`CutBound`] a layout starting at `base` on `out` is cut under, or
    /// `None` when this mark's trial is not width-bounded.
    fn cut_bound(&self, out: &str, base: usize) -> Option<CutBound> {
        match self.bound {
            StopBound::FirstLine => None,
            StopBound::FirstLineWithin { width, .. } => Some(CutBound::FirstLine { width }),
            StopBound::WholeWithin { width, .. } => {
                let prefix = out.get(..base).unwrap_or_default();
                let newline = prefix.rfind('\n');
                let line = newline
                    .and_then(|nl| prefix.get(nl.saturating_add(1)..))
                    .unwrap_or(prefix);
                let content = line.trim_start();
                let lead = line.len().saturating_sub(content.len());
                Some(CutBound::Tail {
                    width,
                    lead: (!content.is_empty()).then_some(lead),
                    counted: newline.is_some_and(|nl| nl >= self.from),
                })
            }
        }
    }
}

/// The [`Reach`] under a [`StopBound::WholeWithin`] mark watching `out` from
/// `from`, and whether a line past its first newline is wider than `width`.
fn observe_tail(out: &str, from: usize, width: usize, tail: &mut Option<usize>) -> (Reach, bool) {
    let first_tail = || {
        out.get(from..)
            .and_then(|rest| rest.find('\n'))
            .map(|nl| from.saturating_add(nl).saturating_add(1))
    };
    let Some(start) = tail.or_else(first_tail) else {
        return (Reach::Whole, false);
    };
    let Some(rest) = out.get(start..) else {
        return (Reach::Whole, false);
    };
    let mut line_start = start;
    for line in rest.split('\n') {
        if content_width(line) > width {
            *tail = Some(line_start);
            return (Reach::Done, true);
        }
        line_start = line_start.saturating_add(line.len()).saturating_add(1);
    }
    *tail = Some(
        rest.rfind('\n')
            .map_or(start, |nl| start.saturating_add(nl).saturating_add(1)),
    );
    (Reach::Whole, false)
}

/// A layout a width-bounded [`trial`] cut short: its node's [`MemoKey`] and the
/// bound that cut it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct CutKey {
    key: MemoKey,
    bound: CutBound,
}

/// Everything a width cut reads of a layout's context beyond its [`MemoKey`].
///
/// A layout's bytes all land at or past its trial's `from`, at the columns its
/// cursor fixes, and every byte before it was scanned when it began, so a
/// first-line cut reads only the width. A tail cut also measures the layout's
/// first line with the content before it: the indentation of that prefix
/// (`None` when it is blank), and whether the line is past the trial's first
/// newline and so scanned at all.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum CutBound {
    FirstLine {
        width: usize,
    },
    Tail {
        width: usize,
        lead: Option<usize>,
        counted: bool,
    },
}

/// The [`Reach`] of a render into `out`, the buffer at address `addr`.
///
/// A width cut is recorded for the memoized renders open on the buffer, so none
/// of them keeps its cut-short layout as the whole one.
fn reach(addr: usize, out: &str) -> Reach {
    MEMO.with_borrow_mut(|m| {
        let Some(m) = m.as_mut() else {
            return Reach::Whole;
        };
        let observed = m
            .stop_mark
            .as_mut()
            .filter(|mark| mark.addr == addr)
            .map(|mark| mark.observe(out));
        observed.map_or(Reach::Whole, |(reach, cut)| {
            m.cut |= cut;
            reach
        })
    })
}

/// The [`CutKey`] of a render of `key` starting at `base` on `out`, the buffer at
/// address `addr`, when the innermost trial on `out` is width-bounded.
fn cut_key(key: MemoKey, addr: usize, out: &str, base: usize) -> Option<CutKey> {
    MEMO.with_borrow(|m| {
        m.as_ref()?
            .stop_mark
            .filter(|mark| mark.addr == addr)?
            .cut_bound(out, base)
            .map(|bound| CutKey { key, bound })
    })
}

/// Run `render` on `out` and return whether a width cut fell inside it, leaving
/// the cut recorded for the enclosing memoized renders too.
fn cut_during(out: &mut String, render: impl FnOnce(&mut String)) -> bool {
    let outer = MEMO.with_borrow_mut(|m| m.as_mut().is_some_and(|m| std::mem::take(&mut m.cut)));
    render(out);
    MEMO.with_borrow_mut(|m| {
        m.as_mut().is_some_and(|m| {
            let inner = m.cut;
            m.cut = outer || inner;
            inner
        })
    })
}

/// Record a width cut for the memoized renders open on the buffer.
fn mark_cut() {
    MEMO.with_borrow_mut(|m| {
        if let Some(m) = m.as_mut() {
            m.cut = true;
        }
    });
}

/// Whether a width cut fell inside the innermost open trial so far.
fn cut_seen() -> bool {
    MEMO.with_borrow(|m| m.as_ref().is_some_and(|m| m.cut))
}

/// `layout` up to and including its first newline, or all of it when it has none.
fn first_line(layout: &str) -> &str {
    layout
        .find('\n')
        .and_then(|nl| layout.get(..=nl))
        .unwrap_or(layout)
}

/// How much of its layout a [`trial`] lays out.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TrialReach {
    /// Up to and including the first newline it writes.
    FirstLine,
    /// Every byte.
    Whole,
    /// As [`TrialReach::FirstLine`], stopping early once a byte past `width` on
    /// the first line fails a verdict that needs the first line to fit it.
    FirstLineWithin { width: usize },
    /// As [`TrialReach::Whole`], stopping early once a line after the first
    /// newline fails a verdict that needs every such line to fit `width`.
    WholeWithin { width: usize },
}

impl TrialReach {
    /// The stop bound a trial of this reach sets, `None` when it lays out whole.
    const fn bound(self) -> Option<StopBound> {
        match self {
            Self::FirstLine => Some(StopBound::FirstLine),
            Self::Whole => None,
            Self::FirstLineWithin { width } => Some(StopBound::FirstLineWithin { width, clear: 0 }),
            Self::WholeWithin { width } => Some(StopBound::WholeWithin { width, tail: None }),
        }
    }
}

/// Where a [`trial`] began on its buffer.
///
/// `start` is the buffer's length then, `stable` that length without the run of
/// trailing spaces a break may trim.
#[derive(Clone, Copy)]
struct Mark {
    start: usize,
    stable: usize,
}

impl Mark {
    /// The mark of a trial beginning on `out` now.
    fn at(out: &str) -> Self {
        Self {
            start: out.len(),
            stable: out.trim_end_matches(' ').len(),
        }
    }

    /// Put `out` back exactly as it was at this mark.
    ///
    /// Nothing below the trailing-space run is ever rewritten (a break trims only
    /// that run; a replay truncates no further), so restoring the run undoes
    /// everything written since.
    fn roll_back(self, out: &mut String) {
        out.truncate(self.stable);
        out.extend(std::iter::repeat_n(
            ' ',
            self.start.saturating_sub(self.stable),
        ));
    }

    /// Everything the trial has written so far, from the cursor it began at.
    ///
    /// When a break trimmed the trailing spaces before the cursor, what is written
    /// begins at the newline that break wrote.
    fn written(self, out: &str) -> &str {
        let intact = out
            .get(self.stable..self.start)
            .is_some_and(|run| run.bytes().all(|b| b == b' '));
        if intact {
            out.get(self.start..).unwrap_or_default()
        } else {
            out.get(self.stable..)
                .unwrap_or_default()
                .trim_start_matches(' ')
        }
    }

    /// The written part of the trial's first line, through its newline if one ends it.
    fn line(self, out: &str) -> &str {
        first_line(self.written(out))
    }
}

/// Run `render` on `out` with the stop mark `reach` asks for, restoring the
/// enclosing mark after.
///
/// A caller discards what `render` writes — a [`trial`] rolls it back, a fresh
/// buffer is dropped — so the bytes charged for it leave the held total with it:
/// an enclosing layout never counts a probe's bytes as its children's. Only an
/// [`attempt`] that keeps its bytes keeps their charge. A width cut inside decides
/// only what `render` reads, so it is not recorded past the trial.
fn with_stop<T>(
    out: &mut String,
    reach: TrialReach,
    render: impl FnOnce(&mut String, Mark) -> T,
) -> T {
    let mark = Mark::at(out);
    let stop = reach.bound().map(|bound| StopMark {
        addr: std::ptr::from_ref::<String>(out).addr(),
        from: mark.stable,
        bound,
    });
    let outer = MEMO.with_borrow_mut(|m| {
        m.as_mut().map(|m| {
            (
                std::mem::replace(&mut m.stop_mark, stop),
                m.charged,
                std::mem::take(&mut m.cut),
            )
        })
    });
    let read = render(out, mark);
    MEMO.with_borrow_mut(|m| {
        if let (Some(m), Some((stop_mark, charged, cut))) = (m.as_mut(), outer) {
            m.stop_mark = stop_mark;
            m.charged = charged;
            m.cut = cut;
        }
    });
    read
}

/// Run `render` on `out` at its live cursor, then roll `out` back exactly to how
/// it was, returning what `render` read of its own bytes.
///
/// The trial writes where the real render writes — the same buffer, column,
/// cursor, and so the same memo keys — so a decision taken on it is the decision
/// the real render meets, and every layout it lays out is one the real render
/// replays. A [`TrialReach::FirstLine`] trial stops laying out past its first
/// newline; a [`TrialReach::Whole`] one lays everything out even inside an
/// enclosing first-line trial.
fn trial<T>(out: &mut String, reach: TrialReach, render: impl FnOnce(&mut String, Mark) -> T) -> T {
    let mark = Mark::at(out);
    let read = with_stop(out, reach, render);
    // An abandoned render's buffer is discarded whole, so it is left as it is.
    if !fuel_exhausted() {
        mark.roll_back(out);
    }
    read
}

/// What an [`attempt`] left on its buffer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Attempt {
    /// The layout was accepted and is the buffer's committed render.
    Kept,
    /// The buffer is as it was; `fits` is whether the layout was accepted.
    RolledBack { fits: bool },
}

/// Lay a whole layout out on `out` at its live cursor and keep it when `render`
/// accepts it, so a probe that proves its layout is also its commit.
///
/// `render` accepts only a layout none of whose lines after the first newline is
/// wider than `width`, so the layout stops at the first such line. A kept layout
/// keeps its charge, as the render that would replay it holds. Inside an open
/// first-line [`trial`] the commit writes only up to its first newline, so the
/// whole layout is rolled back for the caller to commit; `render` is told whether
/// its layout can be kept.
fn attempt(
    out: &mut String,
    width: usize,
    render: impl FnOnce(&mut String, bool) -> bool,
) -> Attempt {
    let mark = Mark::at(out);
    let keeps = reach(std::ptr::from_ref::<String>(out).addr(), out) == Reach::Whole;
    let mut held = None;
    let fits = with_stop(out, TrialReach::WholeWithin { width }, |out, _| {
        let fits = render(out, keeps);
        held = (fits && keeps && !cut_seen()).then(held_charged);
        fits
    });
    if let Some(held) = held {
        set_held_charged(held);
        return Attempt::Kept;
    }
    if !fuel_exhausted() {
        mark.roll_back(out);
    }
    Attempt::RolledBack { fits }
}

/// Whether an open first-line [`trial`] on `out` already holds its first line, so
/// nothing more rendered into `out` is kept and no decision about it matters.
fn first_line_done(out: &String) -> bool {
    reach(std::ptr::from_ref::<String>(out).addr(), out) == Reach::Done
}

/// The first line a render into a fresh buffer writes, with what `render` read.
///
/// Only for a layout that reads nothing of its context, which is the same bytes
/// at every cursor.
fn first_line_fresh<T>(render: impl FnOnce(&mut String) -> T) -> (String, T) {
    let mut fresh = String::new();
    let read = with_stop(&mut fresh, TrialReach::FirstLine, |probe, _| render(probe));
    let end = first_line(&fresh).len();
    fresh.truncate(end);
    (fresh, read)
}

/// Run `render` for `doc` into `out`, or replay the bytes it produced the last time
/// it ran on the same node in the same context. A node outside the memoized
/// document renders directly. Within a first-line [`trial`] only the first line is
/// laid out and replayed.
fn memoized(
    doc: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    pass: Pass,
    out: &mut String,
    render: impl FnOnce(&mut String),
) {
    let addr = node_addr(doc);
    let Some(keyed) = MEMO.with_borrow(|m| {
        m.as_ref().map_or(Some(false), |m| {
            (!m.exhausted).then(|| m.nodes.contains(&addr))
        })
    }) else {
        abandon(out);
        return;
    };
    let reach = reach(std::ptr::from_ref::<String>(out).addr(), out);
    if !keyed {
        // A leaf's caller measures the cursor line to place it, so it is charged
        // that line like a keyed node is.
        if spend(1_usize.saturating_add(current_col(out))) {
            if reach != Reach::Done {
                render(out);
            }
        } else {
            abandon(out);
        }
        return;
    }
    let key = MemoKey {
        node: addr,
        cfg,
        indent,
        col,
        pass,
        cursor: Cursor::of(out),
    };
    if !spend(1_usize.saturating_add(key.cursor.line_len)) {
        abandon(out);
        return;
    }
    if reach == Reach::Done {
        return;
    }
    // A break trims only the trailing spaces before it, so everything before that
    // run is untouched and the render's effect is exactly the bytes from `base` on.
    let base = out.len().saturating_sub(key.cursor.trailing_spaces);
    let cut_key = cut_key(key, std::ptr::from_ref::<String>(out).addr(), out, base);
    if let Some(replayed) = replay(&key, cut_key.as_ref(), reach, out, base) {
        if spend(replayed) {
            hold_charged(replayed);
        }
        return;
    }
    #[cfg(test)]
    RENDERED.with(|n| n.set(n.get() + 1));
    let children = held_charged();
    let cut = cut_during(out, render);
    let Some(layout) = out.get(base..) else {
        return;
    };
    // The bytes the nested renders wrote were charged by them, so only the rest
    // is this layout's own: the charges over a nest sum to its output, not to
    // every level's copy of its subtree.
    let own = layout
        .len()
        .saturating_sub(held_charged().saturating_sub(children));
    if !spend(own) {
        abandon(out);
        return;
    }
    hold_charged(own);
    if cut {
        if let Some(cut_key) = cut_key {
            keep_cut(cut_key, layout);
        }
    } else {
        keep_layout(key, reach, layout);
    }
}

/// Replay onto `out` from `base` the layout kept for `key` under `reach`, or
/// failing that the cut-short one kept under `cut_key`, and return its length.
///
/// A cut-short layout matches a fresh render only up to its cut, and only under
/// the width bound in its key: it holds the byte past the bound that stopped
/// the kept render, so every verdict read under that bound fails the same way
/// and replaying it records the cut again.
fn replay(
    key: &MemoKey,
    cut_key: Option<&CutKey>,
    reach: Reach,
    out: &mut String,
    base: usize,
) -> Option<usize> {
    let (len, cut) = MEMO.with_borrow(|m| {
        let m = m.as_ref()?;
        let whole = m.layouts.get(key).map(|l| l.text.as_str());
        let found = if reach == Reach::FirstLine {
            whole
                .map(first_line)
                .or_else(|| m.first_lines.get(key).map(String::as_str))
        } else {
            whole
        };
        let (layout, cut) = found.map(|l| (l, false)).or_else(|| {
            cut_key
                .and_then(|ck| m.cuts.get(ck))
                .map(|l| (l.as_str(), true))
        })?;
        out.truncate(base);
        out.push_str(layout);
        Some((layout.len(), cut))
    })?;
    if cut {
        mark_cut();
    }
    Some(len)
}

/// Keep a `layout` a width bound cut short for replay under `cut_key`: up to its
/// first newline under a first-line bound, which reads nothing past it.
fn keep_cut(cut_key: CutKey, layout: &str) {
    let kept = match cut_key.bound {
        CutBound::FirstLine { .. } => first_line(layout),
        CutBound::Tail { .. } => layout,
    };
    MEMO.with_borrow_mut(|m| {
        let entry = cut_entry_bytes(kept.len());
        if let Some(m) = m.as_mut()
            && let Some(bytes) = m.bytes.checked_add(entry)
            && bytes <= m.byte_ceiling
        {
            m.bytes = bytes;
            m.cuts.insert(cut_key, kept.to_owned());
        }
    });
}

/// The layout bytes charged for what the open buffers hold.
fn held_charged() -> usize {
    MEMO.with_borrow(|m| m.as_ref().map_or(0, |m| m.charged))
}

/// Set the layout bytes charged for what the open buffers hold to `bytes`.
fn set_held_charged(bytes: usize) {
    MEMO.with_borrow_mut(|m| {
        if let Some(m) = m.as_mut() {
            m.charged = bytes;
        }
    });
}

/// The widest tail line of `written`, the layout just rendered under `key`: read
/// from the memo when it kept the layout, else measured and charged.
fn written_widest_tail(key: &MemoKey, written: &str) -> usize {
    let kept = MEMO.with_borrow(|m| {
        m.as_ref()
            .and_then(|m| m.layouts.get(key).map(|l| l.widest_tail))
    });
    kept.unwrap_or_else(|| {
        spend(written.len());
        widest_tail(written)
    })
}

/// Count `bytes` just charged as held by the open buffers.
fn hold_charged(bytes: usize) {
    MEMO.with_borrow_mut(|m| {
        if let Some(m) = m.as_mut() {
            m.charged = m.charged.saturating_add(bytes);
        }
    });
}

/// Keep a fresh `layout` for replay under `key`: whole, or apart as its first
/// line when a first-line [`trial`] rendered it and it broke.
///
/// A probe's layout without a newline was laid out in full, so it is the whole
/// layout every other render of the key replays.
fn keep_layout(key: MemoKey, reach: Reach, layout: &str) {
    let partial = reach == Reach::FirstLine && layout.contains('\n');
    let kept = if partial { first_line(layout) } else { layout };
    MEMO.with_borrow_mut(|m| {
        let entry = memo_entry_bytes(kept.len());
        if let Some(m) = m.as_mut()
            && let Some(bytes) = m.bytes.checked_add(entry)
            && bytes <= m.byte_ceiling
        {
            m.bytes = bytes;
            if partial {
                m.first_lines.insert(key, kept.to_owned());
            } else {
                m.layouts.insert(key, Layout::of(kept));
            }
        }
    });
}

/// Drop what an abandoned render wrote to `out`.
///
/// The output of a render that ran out of fuel is discarded, so emptying the
/// buffer loses nothing; it keeps every cursor measure the unwinding layouts
/// still take on it constant-time, so abandoning costs no more than the frames
/// in flight.
fn abandon(out: &mut String) {
    out.clear();
}

/// Spend `cost` of the render's [`LAYOUT_FUEL`]; `false` once it is spent, from
/// which point every memoized render returns without writing.
fn spend(cost: usize) -> bool {
    MEMO.with_borrow_mut(|m| {
        m.as_mut().is_none_or(|m| {
            m.exhausted = m.exhausted || cost >= m.fuel;
            m.fuel = m.fuel.saturating_sub(cost);
            !m.exhausted
        })
    })
}

/// A fact about `doc` that depends on the node alone, read from `table` or
/// computed by `compute` — which reports the fact and the work it took, charged to
/// the fuel — and kept for the rest of the render. A node outside the memoized
/// document is computed afresh each time, charged the same. Once the fuel is
/// spent the render's output is discarded, so no fact is computed: the default
/// stands in for it.
fn node_fact<T: Copy + Default>(
    doc: &Doc,
    table: fn(&mut Memo) -> &mut HashMap<usize, T>,
    compute: impl FnOnce() -> (T, usize),
) -> T {
    let addr = node_addr(doc);
    let cached = MEMO.with_borrow_mut(|m| {
        m.as_mut().map(|m| {
            if m.exhausted {
                Fact::Known(T::default())
            } else if m.nodes.contains(&addr) {
                table(m)
                    .get(&addr)
                    .copied()
                    .map_or(Fact::Keyed, Fact::Known)
            } else {
                Fact::Unkeyed
            }
        })
    });
    match cached.unwrap_or(Fact::Unkeyed) {
        Fact::Known(fact) => fact,
        Fact::Keyed => {
            let (fact, work) = compute();
            spend(work);
            MEMO.with_borrow_mut(|m| {
                if let Some(m) = m.as_mut() {
                    table(m).insert(addr, fact);
                }
            });
            fact
        }
        Fact::Unkeyed => {
            let (fact, work) = compute();
            spend(work);
            fact
        }
    }
}

/// Where [`node_fact`] finds a node's fact.
enum Fact<T> {
    /// Already known: cached, or moot because the render is abandoned.
    Known(T),
    /// A memoized node whose fact is computed once and kept.
    Keyed,
    /// A node outside the memoized document, computed afresh.
    Unkeyed,
}

/// Whether `doc`'s flat layout depends only on the node, `inline_hard`, and the
/// indent after a newline.
///
/// Laid out flat, every variant takes its flat form without a fit decision and
/// lays its children out flat, except two whose flat render still measures the
/// cursor: a [`Doc::StructLit`] (its field-width test reads the column) and a
/// [`Doc::MatchArmTail`] (its body fit reads the column, then renders broken).
/// A node is fixed when neither sits anywhere below it; its flat bytes then read no
/// column, cursor, reserve, or seed, so a single-line flat layout is exact in every
/// context and its [`FlatMeasure`] answers every flat fit probe.
fn flat_fixed(doc: &Doc) -> bool {
    match doc {
        Doc::Text(_)
        | Doc::Line
        | Doc::Softline
        | Doc::HardLine
        | Doc::IfBroken(_)
        | Doc::OrPattern { .. } => true,
        Doc::StructLit { .. } | Doc::MatchArmTail { .. } => false,
        _ => node_fact(doc, |m| &mut m.flat_fixed, || (children_flat_fixed(doc), 1)),
    }
}

/// Whether `doc` and every child of it are [`flat_fixed`].
fn children_flat_fixed(doc: &Doc) -> bool {
    match doc {
        Doc::Text(_)
        | Doc::Line
        | Doc::Softline
        | Doc::HardLine
        | Doc::IfBroken(_)
        | Doc::OrPattern { .. } => true,
        Doc::StructLit { .. } | Doc::MatchArmTail { .. } => false,
        Doc::Concat(docs) => docs.iter().all(flat_fixed),
        Doc::Nest(_, inner)
        | Doc::Group(inner)
        | Doc::BraceBody(inner)
        | Doc::ElidableParen { inner } => flat_fixed(inner),
        Doc::Assign { prefix, rhs, .. } => flat_fixed(prefix) && flat_fixed(rhs),
        Doc::Chain { operands } => operands.iter().all(|o| flat_fixed(&o.doc)),
        Doc::CallArgs {
            open, elems, close, ..
        } => flat_fixed(open) && elems.iter().all(flat_fixed) && flat_fixed(close),
        Doc::TypeBound {
            ptr_open,
            head,
            traits,
            close,
        } => {
            flat_fixed(ptr_open)
                && flat_fixed(head)
                && traits.iter().all(flat_fixed)
                && flat_fixed(close)
        }
        Doc::MethodChain { receiver, method } => flat_fixed(receiver) && flat_fixed(method),
        Doc::IfElse { cond, then_, else_ } => {
            flat_fixed(cond) && flat_fixed(then_) && flat_fixed(else_)
        }
    }
}

/// The [`FlatMeasure`] of `doc` laid out flat under `cfg`, or `None` when `doc` is
/// not [`flat_fixed`], so its flat layout depends on where it lands.
///
/// Measured on the first line of the real flat render (through [`render_at`], so
/// a keyed node shares its layout) and kept per keyed node. Every field reads no
/// further than the first newline, so [`first_line_fresh`] measures it.
fn flat_measure(doc: &Doc, cfg: RenderConfig) -> Option<FlatMeasure> {
    if !flat_fixed(doc) {
        return None;
    }
    let key = FlatKey::of(doc, cfg);
    let cached = MEMO.with_borrow(|m| m.as_ref().and_then(|m| m.flat_measures.get(&key).copied()));
    if cached.is_some() {
        return cached;
    }
    let (first, ()) = first_line_fresh(|probe| {
        render_at(doc, cfg.no_reserve(), 0, 0, true, probe);
    });
    let measure = FlatMeasure::of(&first);
    MEMO.with_borrow_mut(|m| {
        if let Some(m) = m.as_mut()
            && !m.exhausted
            && m.nodes.contains(&key.node)
        {
            m.flat_measures.insert(key, measure);
        }
    });
    Some(measure)
}

/// The flat width of a run of pieces laid out on one line, each after its own
/// literal lead-in of the paired width.
enum FlatRun {
    /// Every piece is measured and single-line: the run's total width.
    Width(usize),
    /// Every piece is measured and one breaks, so the run is not single-line.
    Multiline,
    /// Some piece is not [`flat_fixed`]; the caller renders the run instead.
    Unmeasured,
}

/// The [`FlatRun`] of `pieces`, each a node and the width of the literal text
/// written before it.
fn flat_run<'a>(pieces: impl IntoIterator<Item = (&'a Doc, usize)>, cfg: RenderConfig) -> FlatRun {
    let mut total = 0usize;
    let mut multiline = false;
    for (doc, lead) in pieces {
        let Some(measure) = flat_measure(doc, cfg) else {
            return FlatRun::Unmeasured;
        };
        multiline = multiline || !measure.single_line;
        total = total.saturating_add(lead).saturating_add(measure.first_len);
    }
    if multiline {
        FlatRun::Multiline
    } else {
        FlatRun::Width(total)
    }
}

/// Render one node of any variant; [`render_at`] fronts it with the memo.
fn render_node(
    doc: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    match doc {
        Doc::Text(s) => out.push_str(s),
        Doc::Line => {
            if flat {
                out.push(' ');
            } else {
                out.push('\n');
                push_indent(indent, out);
            }
        }
        Doc::Softline => {
            if !flat {
                out.push('\n');
                push_indent(indent, out);
            }
        }
        Doc::HardLine => {
            // A given-up block body inlines onto its single original line: an
            // unconditional break becomes a single space, so `{ let x = …; x }` lays
            // out flat inside the braces `rustfmt` kept on one line.
            if cfg.inline_hard {
                out.push(' ');
            } else {
                out.push('\n');
                push_indent(indent, out);
            }
        }
        Doc::IfBroken(s) => {
            // Renders only when the nearest enclosing group broke (`!flat`) —
            // rustfmt's trailing comma on a broken delimited list. Nothing when
            // flat, so the flat form (and the `fits` measurement of it) carries no
            // trailing comma.
            if !flat {
                out.push_str(s);
            }
        }
        Doc::Concat(docs) => render_concat(docs, cfg, indent, col, flat, out),
        Doc::Nest(n, inner) => {
            render_at(inner, cfg, indent + n, col, flat, out);
        }
        Doc::Group(inner) => {
            let start_col = eff_col(out, col);
            // A group flattens only if its flat form is genuinely single-line and
            // fits AND it carries no `HardLine`. A statement block's `HardLine`s
            // keep it broken; a byte-leaf whose text embeds newlines (an
            // as-yet-unstructured multiline arg carried through the legacy string
            // emitter) makes the flat form multi-line — rustfmt breaks the enclosing
            // delimited list one element per line in that case rather than glue the
            // multiline arg inline. Its own soft `Line`s are what flatten or break
            // as a unit — the standard Wadler `group`, refined to reject an embedded
            // newline the width test alone would miss.
            let group_flat = flat
                || (!has_hard_break(inner) && fits_single_line(inner, cfg, start_col, indent, out));
            render_at(inner, cfg, indent, start_col, group_flat, out);
        }
        Doc::BraceBody(body) => render_brace_body(body, cfg, indent, col, flat, out),
        Doc::MatchArmTail { body, control } => {
            render_match_arm_tail(body, *control, cfg, indent, col, out);
        }
        Doc::Assign {
            prefix,
            rhs,
            trailer,
        } => {
            render_assign(prefix, rhs, *trailer, cfg, indent, col, flat, out);
        }
        Doc::Chain { operands } => {
            render_chain(operands, cfg, indent, col, flat, out);
        }
        Doc::CallArgs {
            open,
            elems,
            close,
            trailing_comma,
        } => {
            render_call_args(
                open,
                elems,
                close,
                *trailing_comma,
                cfg,
                indent,
                col,
                flat,
                out,
            );
        }
        Doc::StructLit {
            open,
            fields,
            close,
        } => {
            render_struct_lit(open, fields, close, cfg, indent, col, out);
        }
        Doc::TypeBound {
            ptr_open,
            head,
            traits,
            close,
        } => {
            render_type_bound(ptr_open, head, traits, close, cfg, indent, col, flat, out);
        }
        Doc::ElidableParen { inner } => render_elidable_paren(inner, cfg, indent, col, flat, out),
        Doc::OrPattern { alts } => render_or_pattern(alts, cfg, col, flat, out),
        Doc::MethodChain { receiver, method } => {
            render_method_chain(receiver, method, cfg, indent, col, flat, out);
        }
        Doc::IfElse { cond, then_, else_ } => {
            render_if_else(doc, cond, then_, else_, cfg, indent, col, flat, out);
        }
    }
}

/// Render a [`Doc::Concat`]: each child in order, threading the reserve budget. A
/// child's own trailing `reserve` is the enclosing reserve PLUS the flat width of
/// every following sibling that lands on the SAME line — the closing delimiter text
/// a wrapper appends after a breakable construct (`Box::new(<closure>)`'s `)`, then
/// the enclosing `;`). Only siblings that render single-line count; once one would
/// break, the reserve no longer applies to earlier children (their tail is that
/// break, not the delimiter). This lets a `BraceBody`/`CallArgs` child re-test its
/// own fit against the width `rustfmt`'s `Shape` leaves after its trailing tokens.
fn render_concat<D: Borrow<Doc>>(
    docs: &[D],
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    // The suffix of child `i` is carried to child `i + 1` by dropping that child's
    // own width when it is text, so a run of text siblings is scanned once, not
    // once per child.
    let mut suffix = trailing_siblings_flat_width(docs.get(1..).unwrap_or(&[]));
    for (i, d) in docs.iter().enumerate() {
        let c = eff_col(out, col);
        let child_cfg = cfg.with_reserve(cfg.reserve.saturating_add(suffix));
        render_at(d.borrow(), child_cfg, indent, c, flat, out);
        suffix = match docs
            .get(i.saturating_add(1))
            .map(<D as Borrow<Doc>>::borrow)
        {
            Some(Doc::Text(t)) => suffix.saturating_sub(t.len()),
            _ => trailing_siblings_flat_width(docs.get(i.saturating_add(2)..).unwrap_or(&[])),
        };
    }
}

/// The columns `rustfmt` reserves out of an arm's width before rewriting its
/// pattern — the ` => {` that may follow the pattern on its line.
const ARM_PATTERN_RESERVE: usize = 5;

/// Render a [`Doc::OrPattern`]: the alternatives joined ` | ` when the flat run
/// fits the arm-pattern width, else one alternative per line at the pattern's
/// begin column, each subsequent line led by `| `.
///
/// The fit test is `rustfmt`'s own arm-pattern shape — `max_width` less
/// [`ARM_PATTERN_RESERVE`] — measured against `cfg.max_width` directly rather
/// than `cfg.margin()`: `rustfmt` builds the pattern's shape fresh from the
/// arm's indent, so the reservation REPLACES the enclosing trailing-sibling
/// reserve (the ` => ` text the arm concat carries) instead of stacking on it.
fn render_or_pattern(
    alts: &[std::borrow::Cow<'static, str>],
    cfg: RenderConfig,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    let start_col = eff_col(out, col);
    // Each ` | ` between two flat alternatives is 3 columns.
    let flat_w: usize =
        alts.iter().map(|a| a.len()).sum::<usize>() + 3 * alts.len().saturating_sub(1);
    if flat || start_col + flat_w + ARM_PATTERN_RESERVE <= cfg.max_width {
        for (i, alt) in alts.iter().enumerate() {
            if i > 0 {
                out.push_str(" | ");
            }
            out.push_str(alt);
        }
        return;
    }
    // Vertical: the pattern begins its arm's fresh line, so the begin-line
    // indent is its start column — every subsequent alternative lands there
    // behind a front-placed `| `.
    let begin = current_line_indent(out).unwrap_or(start_col);
    for (i, alt) in alts.iter().enumerate() {
        if i > 0 {
            out.push('\n');
            push_indent(begin, out);
            out.push_str("| ");
        }
        out.push_str(alt);
    }
}

/// Render a [`Doc::ElidableParen`]: drop the redundant wrapping parens when `inner`
/// already renders parenthesized (a doubled `(( … ))` collapses to `( … )`), matching
/// `rustfmt`; otherwise wrap `inner` in a `(` … `)` pair. The probe measures `inner`'s
/// first rendered character.
fn render_elidable_paren(
    inner: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    if inner_renders_parenthesized(inner, cfg, eff_col(out, col), indent, out) {
        render_at(inner, cfg, indent, col, flat, out);
    } else {
        out.push('(');
        let c = current_col(out);
        render_at(inner, cfg, indent, c, flat, out);
        out.push(')');
    }
}

/// Render a [`Doc::MethodChain`]: the `receiver`, then the trailing `.method(…)`,
/// laid out per `rustfmt`'s method-chain rule. A SINGLE-LINE receiver glues the
/// method inline while the glued `receiver.method` fits the width — whether or not
/// the receiver carries a brace block (`(if a {…} else {…}).ipe_wrapping_add(x)`
/// stays on one line when it fits) — and drops the method to its own line one chain
/// step in only on overflow (`"long"\n    .to_string()`). A MULTILINE receiver
/// always drops the method to its own line: at the receiver's begin-line indent when
/// the receiver is a brace block ending on a de-indented `})` line (the
/// `CELL.get_or_init(|| {…})\n.clone()` shape), or one chain step in when the receiver
/// is ITSELF a broken method chain, so every `.method()` link aligns at the same
/// column (`x\n    .add(y)\n    .add(z)`). See [`Doc::MethodChain`]. `col` is where the
/// receiver's first character lands.
fn render_method_chain(
    receiver: &Doc,
    method: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    // The method's own line aligns with the receiver's begin-line indent — the
    // indentation of the line the receiver starts on. When the buffer is empty the
    // receiver was seeded at `col` (its line's indent); otherwise read the current
    // line's leading-space count, falling back to the block indent mid-line.
    let begin_indent = if out.is_empty() {
        col
    } else {
        current_line_indent(out).unwrap_or(indent)
    };
    // Probe the receiver to decide whether the method glues (a simple non-brace
    // receiver) or breaks to its own line (a block-shaped receiver). The method
    // reserves width against the receiver's last line ONLY when it glues; a broken
    // method lands on a fresh line whose fit is measured separately.
    // A flat enclosing layout forces the whole chain inline: the receiver and the
    // trailing method glue on one line, no shape probe (`rustfmt` never breaks a
    // method chain that its parent laid out flat).
    if flat {
        render_at(receiver, cfg, indent, col, true, out);
        let c = current_col(out);
        render_at(method, cfg, indent, c, true, out);
        return;
    }
    let method_w = flat_leaf_len(method);
    let start_col = eff_col(out, col);
    let shape = receiver_shape(receiver, cfg, start_col, indent, out);
    // A single-line receiver glues the method inline (reserving the method's width
    // against the receiver's fit test); a multiline receiver already spans lines, so
    // the method lands on its own fresh line and needs no receiver-side reserve.
    let recv_reserve = if shape == ReceiverShape::Multiline {
        0
    } else {
        method_w
    };
    render_at(
        receiver,
        cfg.with_reserve(cfg.reserve + recv_reserve),
        indent,
        col,
        flat,
        out,
    );
    // A SINGLE-LINE receiver (plain or brace-carrying) keeps the method glued while
    // the whole `receiver.method` fits, dropping it onto its own line one chain step
    // in only on overflow (`"long"\n    .to_string()`). A MULTILINE receiver always
    // drops the method to its own line: at the begin-line indent when it is a brace
    // block ending on a de-indented `})` line, or one chain step in when it is itself
    // a broken method chain (so every link aligns at the same column). The glue
    // overflow is measured against the FULL `max_width` (the reserve was for the
    // glued case; a broken method lands on a fresh line the caller measures).
    match shape {
        ReceiverShape::Plain | ReceiverShape::SingleLineBrace => {
            // The flat case returned early above, so here the layout is broken: a
            // glued `receiver.method` that overflows drops the method to its own line.
            if current_col(out) + method_w > cfg.max_width {
                out.push('\n');
                push_indent(begin_indent + CHAIN_BREAK_INDENT, out);
            }
        }
        ReceiverShape::Multiline => {
            out.push('\n');
            let method_indent = if receiver_is_method_chain(receiver) {
                begin_indent + CHAIN_BREAK_INDENT
            } else {
                begin_indent
            };
            push_indent(method_indent, out);
        }
    }
    let c = current_col(out);
    render_at(method, cfg, indent, c, flat, out);
}

/// Whether `receiver` is itself a [`Doc::MethodChain`] — every `.method()` link of a
/// broken chain aligns at the same chain-step column, so a method applied to a broken
/// chain lands one step in (not at the chain root's begin-line indent, where a
/// brace-block receiver's method attaches). A transparent `Nest`/`Concat` wrapper is
/// looked through so a chain carried inside a positional wrapper still classifies.
fn receiver_is_method_chain(receiver: &Doc) -> bool {
    node_fact(
        receiver,
        |m| &mut m.chain_receivers,
        || (method_chain_uncached(receiver), 1),
    )
}

/// [`receiver_is_method_chain`] for one node, its children read through the cache.
fn method_chain_uncached(receiver: &Doc) -> bool {
    match receiver {
        Doc::MethodChain { .. } => true,
        Doc::Nest(_, inner) => receiver_is_method_chain(inner),
        Doc::Concat(docs) => docs.last().is_some_and(receiver_is_method_chain),
        _ => false,
    }
}

/// The layout shape of a [`Doc::MethodChain`] receiver, which drives whether its
/// trailing method glues and, when broken, at what indent it lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiverShape {
    /// A single-line non-brace expression (`get_or_init(|| (a / b))`): the method
    /// glues inline while `receiver.method` fits, else breaks one chain step in.
    Plain,
    /// A single-line receiver carrying a brace block (`(if a {…} else {…})`): laid out
    /// exactly like [`ReceiverShape::Plain`] — glued while it fits, one chain step in
    /// on overflow. The variant is kept distinct only to document the brace case.
    SingleLineBrace,
    /// A multiline receiver ending on a de-indented block-closing line (`})`) or a
    /// broken method chain: the method breaks to its own line — at the begin-line
    /// indent for a brace block, one chain step in for a chain receiver.
    Multiline,
}

/// Classify a [`Doc::MethodChain`] receiver's layout shape. A single-line receiver
/// (plain or brace-carrying) glues its trailing method while the line fits; a
/// multiline receiver always breaks the method to its own line. Probed by a
/// [`trial`] of the receiver at the cursor with no method reserve, inspecting its
/// bytes.
fn receiver_shape(
    receiver: &Doc,
    cfg: RenderConfig,
    start_col: usize,
    indent: usize,
    out: &mut String,
) -> ReceiverShape {
    if first_line_done(out) {
        return ReceiverShape::Plain;
    }
    trial(out, TrialReach::Whole, |out, mark| {
        render_at(receiver, cfg, indent, start_col, false, out);
        let written = mark.written(out);
        if written.contains('\n') {
            ReceiverShape::Multiline
        } else if written.contains('{') {
            ReceiverShape::SingleLineBrace
        } else {
            ReceiverShape::Plain
        }
    })
}

/// Whether `inner` renders with a leading `(` at `start_col` — a self-parenthesizing
/// block / paren-expr whose enclosing redundant paren pair `rustfmt` elides. Probed
/// by a [`trial`] of `inner` flat at the cursor, inspecting its first character.
fn inner_renders_parenthesized(
    inner: &Doc,
    cfg: RenderConfig,
    start_col: usize,
    indent: usize,
    out: &mut String,
) -> bool {
    if let Some(measure) = flat_measure(inner, cfg) {
        return measure.starts_paren;
    }
    trial(out, TrialReach::FirstLine, |out, mark| {
        render_at(inner, cfg.no_reserve(), indent, start_col, true, out);
        mark.line(out).starts_with('(')
    })
}

/// Render a [`Doc::TypeBound`] `Ptr<Head + T1 + …>` with `rustfmt`'s angle-bracket
/// break. Flat when it fits; else `Ptr<` then the bound list at one indent step
/// (`Head + T1 + …,`) with `>` dedented; else, when the bound list itself overflows
/// at that step, `Head` and each `+ Ti` on their own lines at a further indent step.
/// The break decision is independent of any enclosing group (`rustfmt` re-tests the
/// annotation against the width on its own line). `col` is where `ptr_open`'s first
/// character lands.
#[allow(
    clippy::too_many_arguments,
    reason = "renderer threads ptr/head/traits/close + col/indent"
)]
fn render_type_bound(
    ptr_open: &Doc,
    head: &Doc,
    traits: &[Doc],
    close: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    let start_col = eff_col(out, col);
    // FLAT: an enclosing group that chose flat forces the inline form (used by the
    // assignment's `flat_width` measurement of its prefix); otherwise the inline
    // form holds only while `Ptr<Head + T1 + …>` fits the (reserve-reduced) width.
    let pieces = TypeBoundPieces {
        ptr_open,
        head,
        traits,
        close,
    };
    if flat || start_col + pieces.flat_width(cfg, indent, start_col, out) <= cfg.margin() {
        pieces.render_flat(cfg, indent, start_col, out);
        return;
    }

    // Overflowing: break the angle brackets. `Ptr<` on this line, the bound list at
    // one indent step, `>` dedented back to `Ptr`'s column.
    render_at(ptr_open, cfg.no_reserve(), indent, start_col, false, out);
    let bound_indent = indent + CHAIN_BREAK_INDENT;

    // ANGLE-BREAK when the whole bound list (plus its trailing `,`) fits on one line
    // at the bound indent; otherwise BOUND-BREAK, each `+ Ti` on its own line at a
    // further indent step. The `head` and the traits open the bound list at
    // `bound_indent` either way.
    let bound_flat_w = pieces.list_flat_width(cfg, bound_indent, out);
    let angle_break = bound_indent + bound_flat_w < cfg.max_width;
    if angle_break {
        // The whole bound list stays on one line at `bound_indent`.
        pieces.render_list_line(cfg, bound_indent, out);
    } else {
        out.push('\n');
        push_indent(bound_indent, out);
        let c = current_col(out);
        render_at(head, cfg.no_reserve(), bound_indent, c, true, out);
        // Each `+ Ti` on its own line at a further indent step.
        let trait_indent = bound_indent + CHAIN_BREAK_INDENT;
        for t in traits {
            out.push('\n');
            push_indent(trait_indent, out);
            out.push_str("+ ");
            let c = current_col(out);
            render_at(t, cfg.no_reserve(), trait_indent, c, false, out);
        }
    }
    out.push(',');
    out.push('\n');
    push_indent(indent, out);
    let c = current_col(out);
    render_at(close, cfg, indent, c, false, out);
}

/// The separator between the traits of an inline bound list.
const BOUND_SEP: &str = " + ";

/// The parts of a [`Doc::TypeBound`] `Ptr<Head + T1 + …>`.
#[derive(Clone, Copy)]
struct TypeBoundPieces<'a> {
    ptr_open: &'a Doc,
    head: &'a Doc,
    traits: &'a [Doc],
    close: &'a Doc,
}

impl TypeBoundPieces<'_> {
    /// Render the inline `Ptr<Head + T1 + …>` from `start_col`.
    fn render_flat(self, cfg: RenderConfig, indent: usize, start_col: usize, out: &mut String) {
        render_at(
            self.ptr_open,
            cfg.no_reserve(),
            indent,
            start_col,
            true,
            out,
        );
        let c = current_col(out);
        render_at(self.head, cfg.no_reserve(), indent, c, true, out);
        for t in self.traits {
            out.push_str(BOUND_SEP);
            let c = current_col(out);
            render_at(t, cfg.no_reserve(), indent, c, true, out);
        }
        let c = current_col(out);
        render_at(self.close, cfg, indent, c, true, out);
    }

    /// Break to a fresh line at `bound_indent` and render the bound list
    /// `Head + T1 + …` on it.
    fn render_list_line(self, cfg: RenderConfig, bound_indent: usize, out: &mut String) {
        out.push('\n');
        push_indent(bound_indent, out);
        let c = current_col(out);
        render_at(self.head, cfg.no_reserve(), bound_indent, c, true, out);
        for t in self.traits {
            out.push_str(BOUND_SEP);
            let c = current_col(out);
            render_at(t, cfg.no_reserve(), bound_indent, c, true, out);
        }
    }

    /// The flat width of `Ptr<Head + T1 + …>` — the single-line footprint of the
    /// bound, for its overflow test — measured, when some piece is not
    /// [`flat_fixed`], by a [`trial`] of the inline form at the cursor.
    fn flat_width(
        self,
        cfg: RenderConfig,
        indent: usize,
        start_col: usize,
        out: &mut String,
    ) -> usize {
        let pieces = [(self.ptr_open, 0), (self.head, 0)]
            .into_iter()
            .chain(self.traits.iter().map(|t| (t, BOUND_SEP.len())))
            .chain([(self.close, 0)]);
        if let FlatRun::Width(w) = flat_run(pieces, cfg) {
            return w;
        }
        if first_line_done(out) {
            return 0;
        }
        trial(out, TrialReach::Whole, |out, mark| {
            self.render_flat(cfg, indent, start_col, out);
            mark.written(out).len()
        })
    }

    /// The flat width of the bound list `Head + T1 + …` alone (no `Ptr<` / `>`), for
    /// the angle-break-vs-bound-break decision — measured, when some piece is not
    /// [`flat_fixed`], by a [`trial`] of the list on the line it breaks to.
    fn list_flat_width(self, cfg: RenderConfig, bound_indent: usize, out: &mut String) -> usize {
        let pieces =
            std::iter::once((self.head, 0)).chain(self.traits.iter().map(|t| (t, BOUND_SEP.len())));
        if let FlatRun::Width(w) = flat_run(pieces, cfg) {
            return w;
        }
        if first_line_done(out) {
            return 0;
        }
        trial(out, TrialReach::Whole, |out, mark| {
            self.render_list_line(cfg, bound_indent, out);
            let lead = 1 + bound_indent;
            mark.written(out).len().saturating_sub(lead)
        })
    }
}

/// Render a [`Doc::StructLit`] with `rustfmt`'s `struct_lit_width` rule: the flat
/// `Name { a: 1, b: 2 }` (spaces hugging the braces) when the FIELD TEXT fits 18
/// columns and the whole line fits `max_width`; otherwise one field per line with a
/// trailing comma, `close` dedented back to `open`'s column. The break decision is
/// independent of any enclosing group (`rustfmt` re-tests the field width on the
/// struct's own line), like [`Doc::CallArgs`].
#[allow(
    clippy::too_many_arguments,
    reason = "renderer threads open/close/col/indent"
)]
fn render_struct_lit(
    open: &Doc,
    fields: &[Doc],
    close: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    out: &mut String,
) {
    let start_col = eff_col(out, col);
    // The `struct_lit_width` gate applies even when the enclosing group chose flat:
    // a struct literal whose field text exceeds 18 columns breaks and forces its
    // enclosing construct broken (like a `HardLine`), so `flat` alone does not force
    // it inline — `struct_lit_flat_fits` is the sole authority.
    if struct_lit_flat_fits(open, fields, close, cfg, start_col, indent, out) {
        render_struct_lit_flat(open, fields, close, cfg, indent, start_col, out);
        return;
    }
    // Broken: one field per line with a trailing comma — the same one-per-line
    // layout as a delimited list.
    render_one_per_line(open, fields, close, true, cfg, indent, start_col, out);
}

/// Render the flat `Name { a: 1, b: 2 }` — a space hugs each brace — from
/// `start_col`, returning the columns `open` and the fields end at.
fn render_struct_lit_flat(
    open: &Doc,
    fields: &[Doc],
    close: &Doc,
    cfg: RenderConfig,
    indent: usize,
    start_col: usize,
    out: &mut String,
) -> (usize, usize) {
    render_at(open, cfg.no_reserve(), indent, start_col, true, out);
    let open_end = current_col(out);
    out.push(' ');
    render_flat_elems(fields, cfg, indent, out);
    let fields_end = current_col(out);
    out.push(' ');
    let c = current_col(out);
    render_at(close, cfg, indent, c, true, out);
    (open_end, fields_end)
}

/// `rustfmt`'s `struct_lit_width` (default 18): the maximum width of a struct
/// literal's FIELD TEXT — the span between the braces, trimmed of the hugging
/// spaces — that stays on one line. A struct literal whose field text exceeds this
/// breaks one field per line even when the whole line still fits `max_width`.
const STRUCT_LIT_WIDTH: usize = 18;

/// Whether a struct literal `Name { fields }` may lay out flat from `start_col`:
/// genuinely single-line, the whole line (with the hugging spaces and the trailing
/// `reserve`) within `max_width`, AND the field text within `struct_lit_width`.
#[allow(
    clippy::too_many_arguments,
    reason = "probe threads open/fields/close + cfg/col/indent + the buffer"
)]
fn struct_lit_flat_fits(
    open: &Doc,
    fields: &[Doc],
    close: &Doc,
    cfg: RenderConfig,
    start_col: usize,
    indent: usize,
    out: &mut String,
) -> bool {
    match list_widths(open, fields, close, cfg) {
        // `open`, ` `, the fields, ` `, `close`; the `open_end..fields_end` span
        // below is the fields plus the leading hugging space.
        ListWidths::Widths(o, f, c) => {
            let line_len = o.saturating_add(f).saturating_add(c).saturating_add(2);
            return start_col.saturating_add(line_len) <= cfg.margin()
                && f.saturating_add(1) <= STRUCT_LIT_WIDTH;
        }
        ListWidths::Multiline => return false,
        ListWidths::Unmeasured => {}
    }
    // Every column read below is taken before the first newline or discarded by
    // the single-line check, so the trial's first line decides the fit.
    trial(out, TrialReach::FirstLine, |out, mark| {
        let (open_end, fields_end) =
            render_struct_lit_flat(open, fields, close, cfg, indent, start_col, out);
        let line = mark.line(out);
        // The field text is the span between the braces, excluding the hugging spaces.
        !line.contains('\n')
            && start_col + line.len() <= cfg.margin()
            && fields_end.saturating_sub(open_end) <= STRUCT_LIT_WIDTH
    })
}

/// Render a [`Doc::BraceBody`]: the body inline (no braces) when it fits flat here,
/// else `{`, the body on its own line at one indent step, `}` dedented back.
/// `rustfmt` re-tests the closure/arm body against the width on its own line, so the
/// decision is independent of any enclosing group; a `HardLine` body always braces.
fn render_brace_body(
    body: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    let start_col = eff_col(out, col);
    // A given-up block body (`inline_hard`) reproduces the ORIGINAL single-line text,
    // which the string emitter always writes WITH the closure braces (`move |_| {
    // rest }`) — `rustfmt` never strips them in a rewrite it abandoned. Keep the
    // braces, body inline.
    if cfg.inline_hard {
        out.push_str("{ ");
        render_at(body, cfg, indent, current_col(out), true, out);
        out.push_str(" }");
        return;
    }
    // The body inlines flat ONLY when its flat form is genuinely single-line — a
    // nested opaque variant (`CallArgs`/`StructLit`/`Chain`) hides its own
    // `HardLine` from `has_hard_break`, so its flat render can still embed a `\n`
    // (a block arg, a one-per-line-broken wide record). A first-line-only fit
    // would drop the braces on such a body; `fits_single_line` rejects the
    // embedded newline, keeping the block form `rustfmt` emits.
    let body_flat =
        flat || (!has_hard_break(body) && fits_single_line(body, cfg, start_col, indent, out));
    if body_flat {
        render_at(body, cfg, indent, start_col, true, out);
        return;
    }
    render_brace_body_broken(body, cfg, indent, start_col, out);
}

/// Render a [`Doc::BraceBody`] in its BROKEN braced form unconditionally: `{`, the
/// body on its own line at one indent step, `}` dedented back. Used both by
/// [`render_brace_body`] when the body does not fit flat and by the call-argument
/// combine, which forces a block-like closure body broken even when it would fit.
fn render_brace_body_broken(
    body: &Doc,
    cfg: RenderConfig,
    indent: usize,
    start_col: usize,
    out: &mut String,
) {
    out.push('{');
    render_at(
        &Doc::Nest(4, Box::new(Doc::HardLine)),
        cfg,
        indent,
        start_col,
        false,
        out,
    );
    let c = current_col(out);
    // SHAPE-BUDGET GIVE-UP: at a deep indent the block body's own broken layout can
    // place an UNBREAKABLE atomic leaf (a string literal / bare identifier that
    // `rustfmt` cannot split) past `max_width`. `rustfmt`'s `Shape`-width recursion
    // then abandons the broken rewrite and leaves the body on its ORIGINAL single
    // line inside the braces (an overflowing but un-splittable line). Model this by
    // rendering the body broken to a probe (whose OWN nested blocks already resolved
    // their give-ups, so a nested give-up's long line is a sealed, breakable-shaped
    // unit that does NOT count here) and checking for a fresh unbreakable-atom
    // overflow. When found, render the body flat instead. Only the block boundary
    // gives up; a nested call's give-up is decided by its own enclosing block, so
    // the decision does not cascade up through breakable constructs.
    if body_broken_forces_flat(body, cfg, indent + 4, c, out) {
        // Keep the whole body on its original single line, inlining even statement-
        // block `HardLine`s to a single space (`rustfmt`'s given-up rewrite).
        let flat_cfg = RenderConfig {
            inline_hard: true,
            ..cfg
        };
        render_at(body, flat_cfg, indent + 4, c, true, out);
    } else {
        render_at(body, cfg, indent + 4, c, false, out);
    }
    out.push('\n');
    push_indent(indent, out);
    out.push('}');
}

/// Whether a block body, rendered in its BROKEN form at `indent`, would place an
/// UNBREAKABLE atomic leaf past `max_width` — the deep-indent case where `rustfmt`
/// abandons the broken rewrite and keeps the body on its original single line.
///
/// The probe renders the body broken (nested blocks resolve their OWN give-ups
/// first, so a sealed give-up line is a breakable-shaped call that does not count);
/// then any resulting line that OVERFLOWS `max_width` AND is a single unbreakable
/// atom (a bare string literal / identifier / type with no top-level break point)
/// is the fresh give-up trigger. A breakable overflowing line (`f(…)`, a call whose
/// own break `rustfmt` would still take) is NOT a trigger — it belongs to that
/// construct's own layout, not this block's give-up.
///
/// The probe is a [`trial`] at the cursor, so the real broken render replays it.
fn body_broken_forces_flat(
    body: &Doc,
    cfg: RenderConfig,
    indent: usize,
    start_col: usize,
    out: &mut String,
) -> bool {
    if first_line_done(out) {
        return false;
    }
    let line_start = out.rfind('\n').map_or(0, |nl| nl + 1);
    trial(out, TrialReach::Whole, |out, _| {
        render_at(body, cfg, indent, start_col, false, out);
        out.get(line_start..)
            .unwrap_or_default()
            .split('\n')
            .any(|line| line.len() > cfg.max_width && line_is_unbreakable_atom(line))
    })
}

/// `rustfmt`'s `single_line_if_else_max_width` (default 50): the maximum width of
/// an `if cond { then } else { else }` construct — measured WITHOUT the outer
/// parentheses the emitter wraps it in — that `rustfmt` keeps on one line. Wider
/// constructs break each branch body onto its own line. The threshold is absolute
/// (column-independent), so the decision is a function of the flat leaf widths.
const SINGLE_LINE_IF_ELSE_MAX_WIDTH: usize = 50;

/// The single-line width of an `if`/`else` construct WITHOUT the outer parens:
/// `if ` + cond + ` { ` + then + ` } else { ` + else + ` }`, from the flat leaf
/// widths (absolute, column-independent). One source of truth for BOTH the
/// render decision and `has_hard_break`, so the two cannot disagree about whether
/// an `IfElse` renders block-form. `node` is the `IfElse` itself, the key its
/// width is kept under.
fn if_else_construct_width(node: &Doc, cond: &Doc, then_: &Doc, else_: &Doc) -> usize {
    node_fact(
        node,
        |m| &mut m.if_else_widths,
        || {
            let width = ["if ", " { ", " } else { ", " }"]
                .into_iter()
                .map(str::len)
                .chain([cond, then_, else_].map(|branch| leaf_norm(branch).width()))
                .fold(0, usize::saturating_add);
            (width, 1)
        },
    )
}

/// The [`LeafNorm`] of `doc`'s SEAL leaf stream: its whitespace-normalized width.
///
/// Composed from the children's summaries, each a [`node_fact`], so every node of
/// the memoized document is summarised once however many enclosing constructs
/// ask for its width, and each summary charges only the node's own bytes.
fn leaf_norm(doc: &Doc) -> LeafNorm {
    node_fact(
        doc,
        |m| &mut m.leaf_norms,
        || {
            let (norm, work) = doc.leaf_norm_with(leaf_norm);
            #[cfg(test)]
            NORM_WORK.with(|n| n.set(n.get() + work));
            (norm, work)
        },
    )
}

/// Render a [`Doc::IfElse`] with `rustfmt`'s `single_line_if_else_max_width` rule.
/// The single-line construct width WITHOUT the outer parens (the `if cond { then }
/// else { else }` text) is measured from the branches' flat leaves; when it is at
/// most [`SINGLE_LINE_IF_ELSE_MAX_WIDTH`] the whole construct stays inline `(if cond
/// { then } else { else })`, otherwise each branch body breaks onto its own line at
/// one indent step. The threshold is absolute, so the decision is independent of the
/// enclosing column (a wider enclosing group cannot force it broken, nor a deep
/// indent).
#[allow(
    clippy::too_many_arguments,
    reason = "renderer threads the three branch docs + cfg/indent/col/flat"
)]
fn render_if_else(
    node: &Doc,
    cond: &Doc,
    then_: &Doc,
    else_: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    let construct_width = if_else_construct_width(node, cond, then_, else_);

    let start_col = eff_col(out, col);
    // The branches are laid out in place (borrowed, never cloned) so they keep
    // their memoized layouts.
    if construct_width <= SINGLE_LINE_IF_ELSE_MAX_WIDTH {
        // Inline `(if cond { then } else { else })`. Soft `Line`s so a wider
        // enclosing group could in principle break it, but the width test already
        // guaranteed it fits.
        let pieces = [
            &Doc::text("(if "),
            cond,
            &Doc::text(" { "),
            then_,
            &Doc::text(" } else { "),
            else_,
            &Doc::text(" })"),
        ];
        render_concat(&pieces, cfg, indent, start_col, flat, out);
        return;
    }

    // Broken block form. Braces sit at the enclosing block `indent`; each branch
    // body indents to `indent + 4`. `HardLine`s force the layout unconditionally,
    // matching `rustfmt`'s block-form `if` once past the single-line threshold.
    let head = [&Doc::text("(if "), cond, &Doc::text(" {")];
    render_concat(&head, cfg, indent, start_col, flat, out);
    render_if_branch(then_, cfg, indent, start_col, flat, out);
    render_at(&Doc::text("} else {"), cfg, indent, start_col, flat, out);
    render_if_branch(else_, cfg, indent, start_col, flat, out);
    render_at(&Doc::text("})"), cfg, indent, start_col, flat, out);
}

/// One branch of a broken [`Doc::IfElse`]: the branch body on its own line one
/// indent step in, then the break back to the enclosing indent for the brace that
/// follows it.
fn render_if_branch(
    branch: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    let c = eff_col(out, col);
    render_concat(&[&Doc::HardLine, branch], cfg, indent + 4, c, flat, out);
    render_at(&Doc::HardLine, cfg, indent, col, flat, out);
}

/// Whether a rendered line, trimmed of indentation, is a single UNBREAKABLE atom:
/// a bare string literal or an identifier/path/type with no TOP-LEVEL break point —
/// no `(` / `[` / `{` group opener and no top-level `, ` separator outside a string
/// or bracket. Such a line cannot be split further, so an overflowing one is where
/// `rustfmt`'s `Shape`-width recursion gives up. A breakable line (a call `f(…)`, a
/// list, a `let … = …`) has a top-level opener/separator and is NOT an atom — its
/// own layout, not this block's give-up, governs it.
pub(super) fn line_is_unbreakable_atom(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.is_empty() {
        return false;
    }
    let mut in_str = false;
    let mut escaped = false;
    let mut depth: i32 = 0;
    let mut prev = ' ';
    for c in trimmed.chars() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            prev = c;
            continue;
        }
        match c {
            '"' => in_str = true,
            // A group opener or a top-level separator is a break point, so the line
            // is a breakable construct (a call / list / `let`), not a single atom. A
            // top-level space between two non-delimiter tokens (`a b`, `x = y`) is a
            // break point too.
            '(' | '[' | '{' | ',' => return false,
            ' ' if depth == 0 => return false,
            '<' => depth += 1,
            '>' if prev != '-' => depth -= 1,
            _ => {}
        }
        prev = c;
    }
    true
}

/// Render a [`Doc::MatchArmTail`]: the body plus its trailing comma per `rustfmt`'s
/// arm brace/comma rule. Inline `body,` when it fits. When it overflows: a CONTROL
/// body is always wrapped in synthesized braces (comma dropped); a DELIMITED-tail
/// body that stays SINGLE-LINE on its own line at one indent step is ALSO wrapped in
/// a synthesized block (`rustfmt` prefers the whole body on its own line over
/// breaking its delimiters, comma dropped), and only a delimited body that STILL
/// overflows at that indent breaks inside its own brackets (comma kept). A
/// `HardLine` body always breaks.
fn render_match_arm_tail(
    body: &Doc,
    control: bool,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    out: &mut String,
) {
    let start_col = eff_col(out, col);
    // Inline `body,` only when the body's flat form is genuinely single-line. A
    // non-control body wrapping an opaque variant (`CallArgs` with a block arg,
    // a wide `StructLit`, a block-bearing `Chain`) hides its `HardLine` from
    // `has_hard_break`, so its flat render can embed a `\n`; a first-line-only fit
    // sees only the short first line and would inline it, dropping the arm braces
    // `rustfmt` keeps. `fits_single_line` rejects the embedded newline.
    let body_flat = !has_hard_break(body) && fits_single_line(body, cfg, start_col, indent, out);
    if body_flat {
        render_at(body, cfg, indent, start_col, true, out);
        out.push(',');
        return;
    }
    // rustfmt decides an overflowing arm body in three tiers (see
    // `emit_types::render_stringify_enum_arm`): a CONTROL body is always
    // brace-wrapped; a delimited CALL/MACRO body whose ARGUMENT TEXT fits
    // `fn_call_width` is brace-wrapped onto its own line (rustfmt prefers the whole
    // body single-line over breaking its delimiters); and a delimited body whose
    // argument text exceeds `fn_call_width` breaks in place inside its own
    // delimiters (comma kept). The gate is the argument-text width against
    // `fn_call_width`, NOT the whole body against `max_width` — a body that fits
    // `max_width` at `indent + 4` but whose args exceed 60 columns still breaks in
    // place. A block-argument body is weighed by `prefer_next_line`. A non-delimited
    // body (chain, `if`/`else`) has no argument list to gate, so it falls back to
    // the single-line-at-`indent + 4` test.
    let block_wrap =
        control || (!has_hard_break(body) && body_block_wraps(body, cfg, indent, start_col, out));
    if block_wrap {
        open_arm_block(cfg, indent, start_col, out);
        let c = current_col(out);
        render_at(body, cfg, indent + 4, c, false, out);
        out.push('\n');
        push_indent(indent, out);
        out.push('}');
    } else {
        render_at(body, cfg, indent, start_col, false, out);
        out.push(',');
    }
}

/// Whether an overflowing, non-control match-arm `body` is brace-wrapped onto its
/// own line (`Pat => { body }`) rather than broken in place inside its own
/// delimiters (`Pat => f(\n …\n),`).
///
/// For a delimited CALL/CTOR/MACRO body the decision is `rustfmt`'s
/// `fn_call_width` gate: the body's ARGUMENT TEXT (the span between its
/// delimiters, seeing through a single-argument combinable wrapper) is
/// brace-wrapped when it fits `fn_call_width` and delimiter-broken when it does
/// not. An argument text that cannot lay out flat (a block argument) has no width
/// to gate, so the in-place and next-line layouts are weighed by `rustfmt`'s
/// `prefer_next_line` ([`arm_prefers_next_line`]). A body with no argument list of
/// its own (a chain, an `if`/`else`) falls back to whether the whole body fits
/// single-line on its own line at `indent + 4`.
///
/// Measured by a [`trial`] that opens the arm block exactly as the brace-wrapped
/// render does, so every width is read at the column the body would land on.
fn body_block_wraps(
    body: &Doc,
    cfg: RenderConfig,
    indent: usize,
    start_col: usize,
    out: &mut String,
) -> bool {
    // See through a `Group` wrapper to the delimited construct it lays out.
    let inner = match body {
        Doc::Group(g) => g.as_ref(),
        other => other,
    };
    if let Doc::CallArgs { open, elems, .. } = inner {
        // Measure the argument text width: the flat span from just after the
        // opening delimiter to just before the closing one, seeing through a
        // single-argument combinable wrapper to the innermost combinable's own
        // argument span (`innermost_args_width`). The absolute column is
        // irrelevant to a width, so measure from column 0.
        let open_w = flat_run([(&**open, 0)], cfg);
        if let (FlatRun::Width(o), FlatRun::Width(e)) = (open_w, flat_run(elem_pieces(elems), cfg))
        {
            return innermost_args_width(elems, o, o.saturating_add(e)) <= FN_CALL_WIDTH;
        }
        // An argument text whose flat form breaks — a block argument — has no
        // single-line width to gate, so the two whole layouts are weighed.
        return arm_prefers_next_line(body, cfg, indent, start_col, out);
    }
    arm_block_trial(cfg, indent, start_col, out, |out| {
        let c = current_col(out);
        fits_single_line(body, cfg.no_reserve(), c, indent + 4, out)
    })
}

/// Trial the brace-wrapped arm layout: open the arm block, then run `measure` on
/// the body's first line inside it.
///
/// The block opens with a newline, so the stop mark is set only after it: a
/// first-line trial begun before the break would already hold its line and lay
/// nothing of the body out.
fn arm_block_trial<T>(
    cfg: RenderConfig,
    indent: usize,
    start_col: usize,
    out: &mut String,
    measure: impl FnOnce(&mut String) -> T,
) -> T {
    trial(out, TrialReach::Whole, |out, _| {
        open_arm_block(cfg, indent, start_col, out);
        with_stop(out, TrialReach::FirstLine, |out, _| measure(out))
    })
}

/// The shape of one whole layout of a match-arm body, as `rustfmt` weighs it.
#[derive(Clone, Copy)]
pub(super) struct BodyShape {
    /// The newlines the layout writes.
    pub(super) newlines: usize,
    /// The last character of its first line.
    pub(super) first_end: Option<char>,
    /// The width of its first line.
    pub(super) first_width: usize,
}

impl BodyShape {
    /// The shape of `written`, a layout that begins at its cursor.
    pub(super) fn of(written: &str) -> Self {
        let first = written.split('\n').next().unwrap_or_default();
        Self {
            newlines: written.bytes().filter(|&b| b == b'\n').count(),
            first_end: first.trim_end().chars().next_back(),
            first_width: first.len(),
        }
    }
}

/// Whether a multi-line match-arm body moves onto its own line in a brace block,
/// by `rustfmt`'s `prefer_next_line` over the two whole layouts.
///
/// The next-line layout wins when it is single-line, when the in-place one takes
/// more than one line more, or when the in-place first line ends in an opener the
/// next-line first line does not end in. Otherwise the body — a call, which
/// `rustfmt` lets extend from the arm head — stays in place while its first line,
/// with the arm's comma, fits the width.
///
/// Each layout is laid out by a [`trial`] at the columns its commit renders at, so
/// the render that follows replays the one chosen.
fn arm_prefers_next_line(
    body: &Doc,
    cfg: RenderConfig,
    indent: usize,
    start_col: usize,
    out: &mut String,
) -> bool {
    let orig = trial(out, TrialReach::Whole, |out, mark| {
        render_at(body, cfg, indent, start_col, false, out);
        BodyShape::of(mark.written(out))
    });
    let next = trial(out, TrialReach::Whole, |out, _| {
        open_arm_block(cfg, indent, start_col, out);
        with_stop(out, TrialReach::Whole, |out, mark| {
            let c = current_col(out);
            render_at(body, cfg, indent + 4, c, false, out);
            BodyShape::of(mark.written(out))
        })
    });
    let opener_lost = orig
        .first_end
        .is_some_and(|end| matches!(end, '(' | '{' | '[') && next.first_end != Some(end));
    next.newlines == 0
        || orig.newlines > next.newlines.saturating_add(1)
        || opener_lost
        || start_col.saturating_add(orig.first_width).saturating_add(1) > cfg.max_width
}

/// Open a brace-wrapped match-arm body: `{`, then a fresh line one indent step in.
fn open_arm_block(cfg: RenderConfig, indent: usize, start_col: usize, out: &mut String) {
    out.push('{');
    render_at(
        &Doc::Nest(4, Box::new(Doc::HardLine)),
        cfg,
        indent,
        start_col,
        false,
        out,
    );
}

/// Whether the RHS renders as one flat line from `glue_col` with `trailer`
/// columns still free before `max_width`.
fn assign_rhs_fits_same_line(
    rhs: &Doc,
    trailer: usize,
    cfg: RenderConfig,
    indent: usize,
    glue_col: usize,
    out: &mut String,
) -> bool {
    flat_measure(rhs, cfg).map_or_else(
        || {
            trial(out, TrialReach::FirstLine, |out, mark| {
                render_at(rhs, cfg, indent, glue_col, true, out);
                let line = mark.line(out);
                !line.contains('\n')
                    && glue_col.saturating_add(line.len()).saturating_add(trailer) <= cfg.max_width
            })
        },
        |measure| {
            measure.width().is_some_and(|w| {
                glue_col.saturating_add(w).saturating_add(trailer) <= cfg.max_width
            })
        },
    )
}

/// Render an assignment with `rustfmt`'s dedicated RHS-break layout axis. See
/// [`Doc::Assign`]. `col` is where the assignment's first character lands;
/// `indent` is the enclosing block indent (broken RHS goes to `indent + 4`).
/// `trailer` is the width reserved after the RHS on its line (the trailing `;`).
#[allow(
    clippy::too_many_arguments,
    reason = "renderer threads col/indent/flat"
)]
fn render_assign(
    prefix: &Doc,
    rhs: &Doc,
    trailer: usize,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    let start_col = eff_col(out, col);
    if flat {
        render_at(prefix, cfg, indent, start_col, true, out);
        let c = current_col(out);
        render_at(rhs, cfg, indent, c, true, out);
        return;
    }

    // The `let name: TYPE = ` prefix stays flat UNLESS its own flat width
    // overflows the line — then `rustfmt` breaks the TYPE's angle brackets (a
    // `Doc::TypeBound` prefix does this) to shorten the prefix before it even
    // reaches the RHS. Rendering the prefix non-flat only when it overflows keeps
    // the RHS-break (which alone fixes a merely-`prefix+rhs`-wide line) preferred,
    // matching `rustfmt`.
    let prefix_flat_w = flat_width(prefix, cfg, start_col, indent, out);
    if start_col + prefix_flat_w > cfg.max_width {
        render_at(prefix, cfg, indent, start_col, false, out);
        // The prefix broke its TYPE across lines, so its last line ends with `> = `
        // and `rustfmt` GLUES the RHS onto it (the type-break already reclaimed the
        // width the RHS-break would have) — the RHS breaks into its own delimiters
        // in place, exactly the delimiter-break form. The trailing `;` (the
        // `trailer`) is reserved on the RHS's last line so a glued closure body
        // re-tests its fit with room for the statement terminator.
        let c = current_col(out);
        render_at(
            rhs,
            cfg.with_reserve(cfg.reserve + trailer),
            indent,
            c,
            false,
            out,
        );
        return;
    }
    render_at(prefix, cfg, indent, start_col, true, out);
    // Every RHS placement below is measured by a trial from here, the column the
    // glued RHS lands on.
    let glue_col = current_col(out);

    // A hard break in either side rules out every form but the delimiter-break (a
    // statement-block RHS never lays out flat).
    let no_hard_break = !has_hard_break(prefix) && !has_hard_break(rhs);
    if !no_hard_break || first_line_done(out) {
        render_at(rhs, cfg, indent, glue_col, false, out);
        return;
    }

    // SAME-LINE: the whole `prefix rhs;` fits on the current line. An RHS wrapping
    // an opaque variant (an applied-lambda `let p: T = foo(let x = 1 in x)`) can
    // embed a `\n` in its flat render; the same-line form requires a genuinely
    // single-line RHS flat render.
    if assign_rhs_fits_same_line(rhs, trailer, cfg, indent, glue_col, out) {
        render_at(rhs, cfg, indent, glue_col, true, out);
        return;
    }

    // `rustfmt`'s `choose_rhs` accepts the next-line placement only when the
    // glued alternative is not strictly required:
    //  - GLUE-UNVIABLE: the RHS head before its open delimiter (a call's callee)
    //    does not fit the width remaining after `prefix` plus the trailer, so the
    //    glued rewrite fails outright and the RHS always drops to the next line —
    //    even with an over-wide body.
    //  - TAIL-FITS: the glued rewrite is viable, so next-line placement must
    //    prove itself better: no line of the RHS body carries content that alone
    //    exceeds `max_width` — an unbreakable run no indent can ever fit (the
    //    body `rustfmt` leaves as an over-wide raw snippet). Such a body makes
    //    the next-line form no better than the glued one, and the glued form wins.
    // Content past the width on the head line fails the glue whatever follows,
    // so the probe stops there.
    let glue_reach = TrialReach::FirstLineWithin {
        width: cfg.max_width,
    };
    let glue_head_core_w = trial(out, glue_reach, |out, mark| {
        render_at(rhs, cfg, indent, glue_col, false, out);
        let head = mark.line(out);
        head.strip_suffix('\n')
            .unwrap_or(head)
            .trim_end_matches(['(', '{', '['])
            .len()
    });
    let glue_viable = glue_col + glue_head_core_w + trailer <= cfg.max_width;

    // RHS-BREAK: dropped onto its own line at one indent step past the block, the
    // RHS's FIRST line (laying out its own internal breaks — e.g. a closure body
    // block) fits the width. `rustfmt` prefers this next-line placement for a
    // value that would otherwise crowd the wide `let name: TYPE = ` prefix. The
    // trailer is charged against the first line only when the RHS does not break
    // internally (a single-line RHS carries the `;` on that one line). Only a
    // viable glue reads the tail lines, so only then is the whole RHS laid out —
    // by an [`attempt`] that keeps it, its tail width read from the memo.
    let rhs_indent = indent + CHAIN_BREAK_INDENT;
    let head_fits = |body: &str| {
        let head_w = body.split('\n').next().unwrap_or_default().len();
        let head_trailer = if body.contains('\n') { 0 } else { trailer };
        rhs_indent
            .saturating_add(head_w)
            .saturating_add(head_trailer)
            <= cfg.max_width
    };
    let rhs_break_fits = if glue_viable {
        let tried = attempt(out, cfg.max_width, |out, keeps| {
            open_rhs_break(rhs_indent, out);
            let key = MemoKey {
                node: node_addr(rhs),
                cfg,
                indent: rhs_indent,
                col: rhs_indent,
                pass: Pass::Layout { flat: false },
                cursor: Cursor::of(out),
            };
            if !keeps && let Some(fits) = kept_rhs_break_fits(&key, cfg.max_width, head_fits) {
                return fits;
            }
            let mark = Mark::at(out);
            render_at(rhs, cfg, rhs_indent, rhs_indent, false, out);
            let body = mark.written(out);
            head_fits(body) && written_widest_tail(&key, body) <= cfg.max_width
        });
        match tried {
            Attempt::Kept => return,
            Attempt::RolledBack { fits } => fits,
        }
    } else {
        trial(out, TrialReach::Whole, |out, _| {
            open_rhs_break(rhs_indent, out);
            let reach = TrialReach::FirstLineWithin {
                width: cfg.max_width,
            };
            with_stop(out, reach, |out, mark| {
                render_at(rhs, cfg, rhs_indent, rhs_indent, false, out);
                head_fits(mark.written(out))
            })
        })
    };
    if rhs_break_fits {
        open_rhs_break(rhs_indent, out);
        render_at(rhs, cfg, rhs_indent, rhs_indent, false, out);
        return;
    }

    // DELIMITER-BREAK: even at `indent + 4` the RHS's first line overflows, so
    // `rustfmt` keeps it glued to `= ` and breaks it into its own delimiters at
    // the block indent.
    render_at(rhs, cfg, indent, glue_col, false, out);
}

/// Whether the RHS-break layout kept under `key` fits, or `None` when no whole
/// layout is kept.
///
/// It fits when `head_fits` its body and no tail line is wider than `width`. Only
/// for an [`attempt`] that cannot keep its bytes, which reads the verdict alone:
/// the replay it stands for would write the kept layout and measure it, so this
/// measures the kept layout in place, charged for its first line.
fn kept_rhs_break_fits(
    key: &MemoKey,
    width: usize,
    head_fits: impl Fn(&str) -> bool,
) -> Option<bool> {
    let (fits, head_len) = MEMO.with_borrow(|m| {
        let m = m.as_ref()?;
        let layout = m.layouts.get(key)?;
        let text = layout.text.as_str();
        let indent = key.cursor.trailing_spaces;
        let intact = text
            .get(..indent)
            .is_some_and(|run| run.bytes().all(|b| b == b' '));
        let body = if intact {
            text.get(indent..).unwrap_or_default()
        } else {
            text.trim_start_matches(' ')
        };
        let fits = head_fits(body) && layout.widest_tail <= width;
        Some((fits, first_line(text).len()))
    })?;
    spend(head_len);
    Some(fits)
}

/// Break an assignment after its `= `, onto a fresh line at `rhs_indent`.
fn open_rhs_break(rhs_indent: usize, out: &mut String) {
    // `rustfmt` leaves no trailing space on the `= ` line, so trim it before the
    // newline (the prefix carries the flat-case space after `=`).
    trim_trailing_spaces(out);
    out.push('\n');
    push_indent(rhs_indent, out);
}

/// The combined flat width of the run of trailing sibling TEXT leaves that follow a
/// `Doc::Concat` child on the same line — the closing-delimiter text a wrapper
/// appends after a breakable child (`Box::new(<closure>)`'s `)`). Only bare text
/// leaves count: they are the delimiter tails that always sit on the child's last
/// line. The scan stops at the first non-text sibling (a nested structure begins its
/// own layout and does not reserve against an earlier child). Restricting to text
/// leaves keeps this O(remaining leaves) rather than re-rendering nested subtrees,
/// avoiding the exponential blowup a full per-child re-render would cause on deeply
/// nested closures. This is the extra `reserve` a child inherits so its own fit test
/// leaves room for its wrapper's tail.
fn trailing_siblings_flat_width<D: Borrow<Doc>>(siblings: &[D]) -> usize {
    let mut total = 0usize;
    for s in siblings {
        match s.borrow() {
            Doc::Text(t) => total = total.saturating_add(t.len()),
            _ => break,
        }
    }
    total
}

/// The width of `doc` rendered entirely flat from column `start_col` up to its
/// first hard break — the single-line footprint the assignment's fit tests
/// measure — by a first-line [`trial`] of that flat render at the cursor.
fn flat_width(
    doc: &Doc,
    cfg: RenderConfig,
    start_col: usize,
    indent: usize,
    out: &mut String,
) -> usize {
    if let Some(measure) = flat_measure(doc, cfg) {
        return measure.first_len;
    }
    trial(out, TrialReach::FirstLine, |out, mark| {
        render_at(doc, cfg, indent, start_col, true, out);
        mark.line(out).trim_end_matches('\n').len()
    })
}

/// Whether `doc` contains a [`Doc::HardLine`] that is NOT enclosed in a nested
/// group — an unconditional break that forces its enclosing group to stay broken.
/// A statement block carries a `HardLine` before each statement, so this returns
/// `true` for it; an inline structure carrying only soft `Line` / `Softline`
/// returns `false` and is free to flatten. Nested groups and chains hide their
/// own breaks (they decide their own layout independently).
fn has_hard_break(doc: &Doc) -> bool {
    node_fact(
        doc,
        |m| &mut m.hard_breaks,
        || (hard_break_uncached(doc), 1),
    )
}

/// [`has_hard_break`] for one node, its children read through the cache.
fn hard_break_uncached(doc: &Doc) -> bool {
    match doc {
        Doc::HardLine => true,
        // A `BraceBody` decides its own layout independently (like `Group` and
        // `Chain`), so it hides its own breaks from the enclosing group — a
        // closure inside a call does not force the call multiline.
        Doc::Text(_)
        | Doc::Line
        | Doc::Softline
        | Doc::IfBroken(_)
        | Doc::Group(_)
        | Doc::BraceBody(_)
        | Doc::MatchArmTail { .. }
        | Doc::Assign { .. }
        | Doc::Chain { .. }
        // A `CallArgs` decides its own layout independently (like `Group`), so it
        // hides its own breaks — a combinable call inside another does not force
        // the outer to break its whole list; the combining rule glues instead.
        | Doc::CallArgs { .. }
        // A `StructLit` decides its own layout independently too (its own
        // `struct_lit_width` re-test), so it hides its breaks like `CallArgs`.
        | Doc::StructLit { .. }
        // A `TypeBound` decides its own angle-bracket break independently; it never
        // carries a `HardLine`.
        | Doc::TypeBound { .. }
        // A `MethodChain` decides its own layout independently (its receiver breaks
        // its own delimiters, the method drops to its own line), so it hides its
        // breaks like `CallArgs`.
        | Doc::MethodChain { .. }
        // An `OrPattern` decides its own flat-vs-vertical layout independently
        // and carries only text alternatives — never a hard break.
        | Doc::OrPattern { .. } => false,
        // An `IfElse` carries a break the enclosing `BraceBody` must see in TWO
        // cases, mirroring the old inline-`build_if` `Concat` whose `has_hard_break`
        // recursed into its children: (a) it renders block-form (wider than the
        // absolute `single_line_if_else_max_width`), or (b) a branch itself carries
        // a hard break (a `let..in` branch emits a `HardLine`). Otherwise `fits`
        // (which measures only the short first line `(if cond {`) would inline a
        // tall body into a closure/CAF brace-body and drop its braces. Width test
        // shared with `render_if_else`.
        Doc::IfElse { cond, then_, else_ } => {
            if_else_construct_width(doc, cond, then_, else_) > SINGLE_LINE_IF_ELSE_MAX_WIDTH
                || has_hard_break(cond)
                || has_hard_break(then_)
                || has_hard_break(else_)
        }
        Doc::Concat(docs) => docs.iter().any(has_hard_break),
        // `Nest` is pure indentation and `ElidableParen` pure wrapping: each forwards
        // its break behavior to its inner (a paren-block carries the statement
        // `HardLine`s that force a break).
        Doc::Nest(_, inner) | Doc::ElidableParen { inner } => has_hard_break(inner),
    }
}

/// Whether a render that started with `out` at `before` bytes wrote a newline.
/// `before` is the trim point: a break trims only the trailing spaces before it,
/// so nothing below it changes.
fn wrote_newline(out: &str, before: usize) -> bool {
    out.get(before..).is_some_and(|s| s.contains('\n'))
}

/// Push `n` spaces of indentation.
fn push_indent(n: usize, out: &mut String) {
    for _ in 0..n {
        out.push(' ');
    }
}

/// Drop trailing spaces from the end of `out`. Used before a break so a line
/// never ends in whitespace (`rustfmt` trims the space after `=` when the RHS
/// moves to the next line).
fn trim_trailing_spaces(out: &mut String) {
    let trimmed = out.trim_end_matches(' ').len();
    out.truncate(trimmed);
}

/// Whether `doc` rendered flat from column `start_col` is genuinely single-line
/// AND fits the width. A flat render that still carries a
/// newline — a byte-leaf whose legacy-emitter text embeds a multiline block — is
/// NOT single-line, so the enclosing [`Doc::Group`] must break its delimited list
/// one element per line rather than glue the multiline element inline. This is the
/// call-argument-head-glue rule: `rustfmt` keeps a call head glued and lays a
/// structured multiline argument out in place ONLY through the dedicated
/// [`Doc::BraceBody`] closure/arm shape; a plain multiline delimited element breaks
/// the whole list. Groups with only soft `Line`/`Softline` breaks never embed a
/// newline in their flat form, so a single-line render is exactly a fitting one.
///
/// Measured by a first-line [`trial`] of the very flat render the caller commits
/// to when it fits.
fn fits_single_line(
    doc: &Doc,
    cfg: RenderConfig,
    start_col: usize,
    indent: usize,
    out: &mut String,
) -> bool {
    if let Some(measure) = flat_measure(doc, cfg) {
        return measure
            .width()
            .is_some_and(|w| start_col.saturating_add(w) <= cfg.margin());
    }
    trial(out, TrialReach::FirstLine, |out, mark| {
        render_at(doc, cfg, indent, start_col, true, out);
        let line = mark.line(out);
        !line.contains('\n') && start_col + line.len() <= cfg.margin()
    })
}

/// Whether a chain's operands rendered flat from `start_col` are genuinely
/// single-line AND fit the width — the whole-chain-flat fast-path probe. Equal to
/// [`fits_single_line`] on a `Doc::Chain` of the same operands (a flat `Doc::Chain`
/// renders through [`render_chain_flat`]), but probes the operands directly rather
/// than cloning them into a fresh `Doc::Chain` just to route through [`render_at`].
fn chain_flat_fits_single_line(
    operands: &[ChainOperand],
    cfg: RenderConfig,
    start_col: usize,
    indent: usize,
    out: &mut String,
) -> bool {
    let run = flat_run(
        operands.iter().enumerate().map(|(i, o)| {
            let op = if i > 0 {
                o.leading_op.as_deref().unwrap_or("").len() + 2
            } else {
                0
            };
            (&o.doc, op)
        }),
        cfg,
    );
    match run {
        FlatRun::Width(w) => return start_col.saturating_add(w) <= cfg.margin(),
        FlatRun::Multiline => return false,
        FlatRun::Unmeasured => {}
    }
    trial(out, TrialReach::FirstLine, |out, mark| {
        render_chain_flat(operands, cfg, indent, out);
        let line = mark.line(out);
        !line.contains('\n') && start_col + line.len() <= cfg.margin()
    })
}

/// Render a binop chain with rustfmt's layout.
///
/// `col` is where the chain's first character (its outermost `(`) lands;
/// `indent` is the enclosing block indent. Broken operators go to
/// `chain_begin_line_indent + CHAIN_BREAK_INDENT`, where the begin-line indent is
/// the indentation of the line the chain starts on.
fn render_chain(
    operands: &[ChainOperand],
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    // Whole-chain-flat fast path: if the entire flattened chain fits on the
    // current line AND no operand carries a hard break (a statement-block always
    // breaks, forcing the chain broken), emit it inline with no operator breaks.
    //
    // The whole-flat and per-operator glue fit tests honor the trailing-delimiter
    // `reserve`: the `,` (or `),`) `rustfmt` appends after the chain reduces the
    // width the chain's single line may occupy. `chain_flat_fits_single_line`/
    // `glue_fits` subtract `cfg.reserve` via `cfg.margin()`.
    //
    // The whole-flat fast path requires the chain to render GENUINELY single-line,
    // not merely first-line-fits: an operand carrying an independent-layout construct
    // (a `CallArgs` whose statement-block argument breaks) hides its `HardLine` from
    // `no_hard_break`, yet its flat render still spans multiple lines. `fits` would
    // measure only the (short) first line and wrongly flatten the whole chain, gluing
    // the block; the single-line check rejects the embedded newline so the chain
    // breaks and each operand lays out its own multiline argument.
    //
    // Both the `no_hard_break` walk and the single-line probe are guarded behind the
    // `flat` short-circuit: an enclosing group that already chose flat takes the fast
    // path directly, so neither the operand scan nor a whole-chain clone runs.
    if flat
        || (operands.iter().all(|o| !has_hard_break(&o.doc))
            && chain_flat_fits_single_line(operands, cfg, eff_col(out, col), indent, out))
    {
        render_chain_flat(operands, cfg, indent, out);
        return;
    }

    // Broken layout. The shared indent for broken operators is the chain
    // begin-line's indentation plus one block step. The begin-line indent is the
    // column the chain starts at when that column IS the line's indentation
    // (chain sits at the start of a fresh continuation line); otherwise it is the
    // enclosing block indent. rustfmt keys the break indent off the block indent
    // of the statement/line the chain begins on.
    let begin_indent = current_line_indent(out).unwrap_or(indent);
    let shared_indent = begin_indent + CHAIN_BREAK_INDENT;

    // Two distinct line-1 packing regimes, both ended permanently by the first
    // break:
    //   * `flat_prefix` — the initial run of single-line operands, packed
    //     greedily while the operator plus operand fits the width (stair,
    //     tinytail). The first operand that overflows ends it.
    //   * multiline glue — once an operand renders multiline, the NEXT operator
    //     glues to that operand's closing line if it fits; but a single-line
    //     operand after a multiline one does NOT re-open the flat prefix, so the
    //     operator after IT breaks (param_patterns: `+ sum_pair` breaks after the
    //     single-line `ignore_arg`).
    // `broken` latches on the first break: no operator glues afterward.
    let mut broken = false;
    let mut flat_prefix = true;
    let mut prev_multiline = false;
    for (i, operand) in operands.iter().enumerate() {
        if i == 0 {
            let c = eff_col(out, col);
            let before = out.trim_end_matches(' ').len();
            render_at(&operand.doc, cfg, indent, c, false, out);
            prev_multiline = wrote_newline(out, before);
            flat_prefix = !prev_multiline;
            continue;
        }
        // Non-first operands always carry a leading operator (the builder
        // invariant); an absent one degrades to no operator rather than panicking.
        let op = operand.leading_op.as_deref().unwrap_or("");

        if !broken {
            let cur = current_col(out);
            let can_glue = if flat_prefix {
                // In the flat prefix, an operator glues to a FOLLOWING operand only
                // when that operand renders single-line and fits. `rustfmt` breaks
                // the chain BEFORE an operand that would itself render multiline — it
                // never opens a multiline operand mid-line in a broken chain (the sole
                // multiline glue is onto a PRECEDING operand's closing line, the
                // `prev_multiline` arm below).
                let (fits, single_line) = glue_fits(&operand.doc, cfg, cur, indent, op, out);
                fits && single_line
            } else {
                // Past the flat prefix, an operator glues only immediately after a
                // multiline operand, at that operand's closing-line column.
                prev_multiline && glue_fits(&operand.doc, cfg, cur, indent, op, out).0
            };
            if can_glue {
                let before = out.trim_end_matches(' ').len();
                glue_operand(&operand.doc, cfg, indent, op, out);
                prev_multiline = wrote_newline(out, before);
                if prev_multiline {
                    flat_prefix = false;
                }
                continue;
            }
            broken = true;
        }
        // Broken: operator on its own line at the shared indent, operand after it.
        out.push('\n');
        push_indent(shared_indent, out);
        out.push_str(op);
        out.push(' ');
        let c = current_col(out);
        render_at(&operand.doc, cfg, shared_indent, c, false, out);
    }
}

/// Render a bracket-delimited argument list with `rustfmt`'s call-argument
/// COMBINING rule. See [`Doc::CallArgs`]. `col` is where `open`'s first character
/// lands; `indent` is the enclosing block indent.
#[allow(
    clippy::too_many_arguments,
    reason = "renderer threads open/close/col/indent/flat"
)]
fn render_call_args(
    open: &Doc,
    elems: &[Doc],
    close: &Doc,
    trailing_comma: bool,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    let start_col = eff_col(out, col);

    // FLAT: the whole `open a, b close` is genuinely single-line, fits the width,
    // and its argument text fits `fn_call_width`. An enclosing group that already
    // chose flat forces this too.
    if flat || call_args_flat_fits(open, elems, close, cfg, start_col, indent, out) {
        render_call_args_flat(open, elems, close, cfg, indent, start_col, out);
        return;
    }

    render_call_args_broken(
        open,
        elems,
        close,
        trailing_comma,
        cfg,
        indent,
        start_col,
        out,
    );
}

/// The broken layout of a [`Doc::CallArgs`]: the multiline-open glue, the last-
/// argument combine, or the one-per-line break, in `rustfmt`'s order. Split out of
/// [`render_call_args`] so the flat-fallback give-up can probe it before committing.
#[allow(
    clippy::too_many_arguments,
    reason = "renderer threads open/close/col/indent"
)]
fn render_call_args_broken(
    open: &Doc,
    elems: &[Doc],
    close: &Doc,
    trailing_comma: bool,
    cfg: RenderConfig,
    indent: usize,
    start_col: usize,
    out: &mut String,
) {
    // MULTILINE-OPEN GLUE: the `open` itself renders multi-line — a `(func)(args)`
    // whose `func` is a `({ … })` block that breaks — but the flat argument list
    // fits on the open's LAST line. `rustfmt` glues `(args)` onto the block's closing
    // `})` line rather than breaking the tiny argument list one-per-line. Render the
    // open non-flat, then the flat args and close on its last line.
    if !elems.is_empty() && !first_line_done(out) {
        // One trial of the glued layout reads the open's multiline-ness, its closing
        // column, and the flat argument run's fit on that line.
        let glued = trial(out, TrialReach::Whole, |out, mark| {
            render_at(open, cfg.no_reserve(), indent, start_col, false, out);
            if !mark.written(out).contains('\n') {
                return false;
            }
            let open_last = current_col(out);
            match flat_run(elem_pieces(elems).chain([(close, 0)]), cfg) {
                FlatRun::Width(w) => open_last.saturating_add(w) <= cfg.margin(),
                FlatRun::Multiline => false,
                FlatRun::Unmeasured => trial(out, TrialReach::FirstLine, |out, mark| {
                    render_glued_args(elems, close, cfg, indent, out);
                    let line = mark.line(out);
                    !line.contains('\n') && open_last + line.len() <= cfg.margin()
                }),
            }
        });
        if glued {
            render_at(open, cfg.no_reserve(), indent, start_col, false, out);
            render_glued_args(elems, close, cfg, indent, out);
            return;
        }
    }

    // COMBINED (last-argument overflow / head-glue): the LAST element is a
    // combinable construct, and the head + every preceding argument (flat) + the
    // last element's own first line all fit on the first line within the width and
    // `fn_call_width`. `rustfmt` glues them and lets the last element break IN PLACE
    // at the current block indent — FORCED broken so it provides the multiline the
    // combine needs — then glues `close` onto its closing line: `f(a, g(\n …\n))` /
    // `f(g(\n …\n))` for the sole-argument case. No trailing comma.
    if let Some((last, prefix)) = elems.split_last() {
        // Outermost combine: the `fn_call_width` budget is measured from where THIS
        // call's arguments begin, and shared by every nested combine below. The
        // recursive `Shape` budget handed to `last` is `min(max_width − arg-start,
        // fn_call_width)`; each nested combine shrinks it one step.
        let open_end = start_col + flat_leaf_len(open);
        let budget = FN_CALL_WIDTH.min(cfg.max_width.saturating_sub(open_end));
        if last_arg_combines(
            open, prefix, last, None, budget, budget, cfg, start_col, indent, out,
        )
        .is_some()
        {
            let base = render_combine_head(open, prefix, cfg, indent, start_col, out);
            render_forced_break(last, base, budget, cfg, indent, current_col(out), out);
            let c = current_col(out);
            render_at(close, cfg, indent, c, false, out);
            return;
        }
    }

    // ONE-PER-LINE: `open`, each element on its own line at one indent step, a
    // break-conditional trailing comma (suppressed for a macro list), the close
    // dedented back to the group's start column.
    render_one_per_line(
        open,
        elems,
        close,
        trailing_comma,
        cfg,
        indent,
        start_col,
        out,
    );
}

/// Glue the flat argument list and `close` onto the current line.
fn render_glued_args(
    elems: &[Doc],
    close: &Doc,
    cfg: RenderConfig,
    indent: usize,
    out: &mut String,
) {
    render_flat_elems(elems, cfg, indent, out);
    let c = current_col(out);
    render_at(close, cfg, indent, c, true, out);
}

/// Lay a delimited list out one element per line: `open`, each element on its own
/// line at one indent step, a trailing `,` after each (suppressed for the final
/// element of a macro list), the `close` dedented back to `start_col`. Each
/// element's last line carries a trailing comma, so it is rendered with a
/// one-column trailing `reserve` — `rustfmt`'s `Shape` width reduced by the comma
/// — while `open`/`close` open the list's own delimiters (enclosing reserve
/// cleared). Shared by the plain one-per-line break and the forced-break fallback.
#[allow(
    clippy::too_many_arguments,
    reason = "renderer threads open/close/col/indent"
)]
fn render_one_per_line(
    open: &Doc,
    elems: &[Doc],
    close: &Doc,
    trailing_comma: bool,
    cfg: RenderConfig,
    indent: usize,
    start_col: usize,
    out: &mut String,
) {
    render_at(open, cfg.no_reserve(), indent, start_col, false, out);
    let inner_indent = indent + CHAIN_BREAK_INDENT;
    let last = elems.len().saturating_sub(1);
    for (i, e) in elems.iter().enumerate() {
        out.push('\n');
        push_indent(inner_indent, out);
        let c = current_col(out);
        let has_comma = i < last || trailing_comma;
        let elem_cfg = if has_comma {
            cfg.with_reserve(1)
        } else {
            cfg.no_reserve()
        };
        render_at(e, elem_cfg, inner_indent, c, false, out);
        if has_comma {
            out.push(',');
        }
    }
    out.push('\n');
    push_indent(indent, out);
    let c = current_col(out);
    render_at(close, cfg, indent, c, false, out);
}

/// Render the flat single-line form `open a, b close` from `start_col`, returning
/// the columns `open` and the elements end at.
fn render_call_args_flat(
    open: &Doc,
    elems: &[Doc],
    close: &Doc,
    cfg: RenderConfig,
    indent: usize,
    start_col: usize,
    out: &mut String,
) -> (usize, usize) {
    render_at(open, cfg, indent, start_col, true, out);
    let open_end = current_col(out);
    render_flat_elems(elems, cfg, indent, out);
    let elems_end = current_col(out);
    render_at(close, cfg, indent, elems_end, true, out);
    (open_end, elems_end)
}

/// Whether the flat single-line form `open a, b close` may lay out flat from
/// `start_col`. Three conditions: it is genuinely single-line (no element embeds a
/// newline — a statement block forces the broken layout); the whole line fits
/// `max_width`; and, for a function-call/ctor/tuple list (`trailing_comma`), the
/// argument text (between the delimiters) fits `fn_call_width`. `rustfmt` breaks a
/// call whose argument list exceeds `fn_call_width` one argument per line even when
/// the whole line would still fit `max_width`. A macro list (`format!` / `vec!`,
/// `trailing_comma == false`) is not gated by `fn_call_width` here — it uses a
/// wrap-to-`max_width` layout decided elsewhere.
#[allow(
    clippy::too_many_arguments,
    reason = "probe threads open/elems/close + cfg/col/indent + the buffer"
)]
fn call_args_flat_fits(
    open: &Doc,
    elems: &[Doc],
    close: &Doc,
    cfg: RenderConfig,
    start_col: usize,
    indent: usize,
    out: &mut String,
) -> bool {
    // The full flat line, for the single-line + `max_width` checks: read off the
    // pieces' measures, or laid out by a first-line [`trial`] of the flat commit
    // when a piece's flat layout reads its column. Every width is relative to
    // `start_col`.
    let (open_end, elems_end, line_len) = match list_widths(open, elems, close, cfg) {
        ListWidths::Widths(o, e, c) => (
            o,
            o.saturating_add(e),
            o.saturating_add(e).saturating_add(c),
        ),
        ListWidths::Multiline => return false,
        ListWidths::Unmeasured => {
            let flat = trial(out, TrialReach::FirstLine, |out, mark| {
                let (open_end, elems_end) =
                    render_call_args_flat(open, elems, close, cfg, indent, start_col, out);
                let line = mark.line(out);
                (!line.contains('\n')).then(|| {
                    (
                        open_end.saturating_sub(start_col),
                        elems_end.saturating_sub(start_col),
                        line.len(),
                    )
                })
            });
            let Some(widths) = flat else {
                return false;
            };
            widths
        }
    };
    if start_col.saturating_add(line_len) > cfg.max_width {
        return false;
    }
    // A sole BLOCK-LIKE argument (a `move |…|` / `|…|` closure or a brace block,
    // possibly behind a `Box::new(` wrapper) is `rustfmt`'s `overflow_delimited_expr`:
    // it is NOT gated by `fn_call_width`. Its flat form holds whenever the whole line
    // fits `max_width` (checked above) and stays single-line (`{ body }` inline) — so
    // `Box::new(move |x| { short_body })` stays on one line even though its argument
    // text exceeds 60 columns, breaking only when the line itself overflows.
    if let [only] = elems
        && is_block_like(only)
    {
        return true;
    }
    // `fn_call_width`: an argument list wider than 60 columns breaks even when the
    // whole line still fits `max_width`. The argument text is the span from just
    // after the opening delimiter to just before the closing one. This gates
    // function calls, constructors, tuples AND macro (`format!` / `vec!`) lists —
    // `rustfmt` applies the same 60-column argument budget to all of them.
    //
    // A single-argument call wrapping another combinable construct (`Box::new((a, b))`,
    // `outer(inner(a, b))`) is TRANSPARENT to this gate: `rustfmt` measures the
    // INNERMOST combinable's argument text, not the wrapper's (which includes the
    // inner delimiters). So `Box::new((a, b))` stays flat when `a, b` fits
    // `fn_call_width`, even though `(a, b)` plus the wrapper does not.
    let args_width = innermost_args_width(elems, open_end, elems_end);
    if args_width > FN_CALL_WIDTH {
        return false;
    }
    true
}

/// The `fn_call_width` argument text width of a call, seeing through a single-argument
/// combinable wrapper (`Box::new(<inner>)`, `outer(<inner>)`) to the INNERMOST
/// combinable's own argument text. `rustfmt` gates the flat layout on that innermost
/// width, not the wrapper's (which would double-count the inner delimiters). `open_end`
/// / `elems_end` bound the current call's own argument span; a single combinable inner
/// element recurses one delimiter step deeper.
fn innermost_args_width(elems: &[Doc], open_end: usize, elems_end: usize) -> usize {
    if let [only @ Doc::CallArgs { open, close, elems: inner, .. }] = elems
        // Only a DELIMITED-LITERAL inner (a tuple `(…)`, array `[…]` / `vec![…]`, or a
        // `Box::new(<delimited>)` wrapper of one) is transparent to `fn_call_width` —
        // `rustfmt`'s `overflow_delimited_expr`. A nested CALL or MACRO is measured with
        // its own delimiters counted (its combining is driven by the recursive `Shape`
        // budget, not this flat gate), so seeing through it would wrongly flatten a call
        // whose deep-nested budget has already run out.
        && is_delimited_expr(only)
    {
        let inner_open = open_end + flat_leaf_len(open);
        let inner_close = elems_end.saturating_sub(flat_leaf_len(close));
        return innermost_args_width(inner, inner_open, inner_close);
    }
    elems_end.saturating_sub(open_end)
}

/// The separator between two flat list elements.
const ELEM_SEP: &str = ", ";

/// The elements of a flat list as [`flat_run`] pieces, each after its separator.
fn elem_pieces(elems: &[Doc]) -> impl Iterator<Item = (&Doc, usize)> {
    elems
        .iter()
        .enumerate()
        .map(|(i, e)| (e, if i > 0 { ELEM_SEP.len() } else { 0 }))
}

/// The flat widths of a delimited list `open elems close`, read off its measures.
enum ListWidths {
    /// Every piece is measured and single-line: the widths of `open`, the
    /// separated elements, and `close`.
    Widths(usize, usize, usize),
    /// Every piece is measured and one breaks, so the list is not single-line.
    Multiline,
    /// Some piece is not [`flat_fixed`]; the caller renders the list instead.
    Unmeasured,
}

/// The [`ListWidths`] of `open`, `elems` (joined by [`ELEM_SEP`]), and `close`.
fn list_widths(open: &Doc, elems: &[Doc], close: &Doc, cfg: RenderConfig) -> ListWidths {
    let runs = [
        flat_run([(open, 0)], cfg),
        flat_run(elem_pieces(elems), cfg),
        flat_run([(close, 0)], cfg),
    ];
    match runs {
        [FlatRun::Width(o), FlatRun::Width(e), FlatRun::Width(c)] => ListWidths::Widths(o, e, c),
        _ if runs.iter().any(|r| matches!(r, FlatRun::Unmeasured)) => ListWidths::Unmeasured,
        _ => ListWidths::Multiline,
    }
}

/// Render the elements flat, separated by [`ELEM_SEP`] — the shared flat body of a
/// [`Doc::CallArgs`] (no trailing comma, matching the string emitter's join).
fn render_flat_elems(elems: &[Doc], cfg: RenderConfig, indent: usize, out: &mut String) {
    for (i, e) in elems.iter().enumerate() {
        if i > 0 {
            out.push_str(ELEM_SEP);
        }
        let c = current_col(out);
        render_at(e, cfg, indent, c, true, out);
    }
}

/// Whether the LAST element of a [`Doc::CallArgs`] can be COMBINED with the head
/// under `rustfmt`'s last-argument-overflow / combining rule — and if so, the
/// column its first character lands on (right after the flat `open a, b, ` head).
/// `open` and every preceding argument glue onto the first line, the last element
/// breaks in place (forced), and `close` glues onto its closing line, rather than
/// the whole list breaking one argument per line.
///
/// Gates, all required:
///
///   * STRUCTURAL — the last element must be a combinable construct: its own
///     braced/bracketed break — a [`Doc::CallArgs`] (call / macro / ctor / tuple /
///     list) or a brace block (a closure body / statement block opening with `{`),
///     possibly behind a leading `Box::new(` / `Some(` wrapper. A [`Doc::Chain`]
///     (a parenthesized operator run) and a parenthesized statement block
///     (`({ … })`) are NOT combinable — `rustfmt` breaks the outer list instead.
///   * PREFIX-FLAT — every preceding argument must sit flat on the first line.
///   * FIRST-LINE FIT — the head + preceding args + the last element's own
///     forced-broken first line must fit `max_width`, and the combined ARGUMENT
///     text on the first line must fit `fn_call_width` (the same budget a flat
///     call list obeys) so a call whose combined head overflows breaks one-per-line
///     instead.
///
/// Every gate reads a first-line [`trial`] of the combined layout the caller
/// commits to — the same head, from the same column, with the same base, and
/// `last` forced broken under the same `tail_budget` the commit hands it — so
/// each column it tests is the column the committed layout lands on.
#[allow(
    clippy::too_many_arguments,
    reason = "renderer threads combine base + col/indent + the buffer"
)]
fn last_arg_combines(
    open: &Doc,
    prefix: &[Doc],
    last: &Doc,
    combine_base: Option<usize>,
    budget: usize,
    tail_budget: usize,
    cfg: RenderConfig,
    start_col: usize,
    indent: usize,
    out: &mut String,
) -> Option<usize> {
    // A SINGLE-argument call glues its argument's head freely (the combine chain
    // "may nest further, as long as all but the innermost construct have only a
    // single argument"); a MULTI-argument call overflows its LAST argument only when
    // that argument is a DELIMITED expression (a block / closure / tuple / array /
    // struct) — not a plain nested function call — subject to `fn_call_width`.
    let single_arg = prefix.is_empty();
    if single_arg {
        if !is_glue_shape(last) {
            return None;
        }
    } else if !is_delimited_expr(last) {
        return None;
    }
    if first_line_done(out) {
        return None;
    }
    trial(out, TrialReach::FirstLine, |out, mark| {
        // The first-line head (`open a, b, `), to find where `last` lands. A
        // multiline head cannot sit on the first line.
        let open_end = render_combine_head(open, prefix, cfg, indent, start_col, out);
        if mark.written(out).contains('\n') {
            return None;
        }
        let last_col = current_col(out);
        if last_col > cfg.max_width {
            return None;
        }
        // The `fn_call_width` budget is measured from the OUTERMOST combining call's
        // argument-start column, shared by this and every nested combine — a deep
        // glue chain shares one 60-column budget, so an over-wide combined head
        // breaks at the level where the budget runs out rather than gluing
        // indefinitely.
        let base = combine_base.unwrap_or(open_end);
        // A single-argument call glues ONLY when its argument cannot itself sit flat
        // within the shared budget — i.e. the argument's flat form (from the shared
        // base) overflows `fn_call_width`, or it is intrinsically multiline. When the
        // argument fits flat within that budget, `rustfmt` breaks the
        // single-argument call one-per-line to give the flat argument its own line
        // rather than gluing. A BLOCK-LIKE argument (a `move |…|` closure or a brace
        // block) is `rustfmt`'s `overflow_delimited_expr`: it is ALWAYS glued onto
        // the call head, with only its OWN body breaking — the call is never broken
        // one-per-line to give it its own line. So the "break to give the flat
        // argument its own line" heuristic below is skipped for it; only the
        // first-line-fit gate (further down) can reject the glue.
        if single_arg && !has_hard_break(last) && !is_block_like(last) {
            let flat_w = flat_measure(last, cfg).map_or_else(
                || {
                    trial(out, TrialReach::FirstLine, |out, mark| {
                        render_at(last, cfg, indent, last_col, true, out);
                        let line = mark.line(out);
                        (!line.contains('\n')).then_some(line.len())
                    })
                },
                FlatMeasure::width,
            );
            if flat_w
                .is_some_and(|w| last_col.saturating_add(w).saturating_sub(base) <= FN_CALL_WIDTH)
            {
                return None;
            }
            // Recursive `Shape` budget: `rustfmt` shrinks the combining width one step
            // per nested single-argument call — `min(width − callee(, fn_call_width)`
            // — and breaks THIS call one-per-line (giving its argument its own line)
            // rather than gluing when the width for THIS call's argument runs out.
            // `budget` is the width the enclosing combine handed this call; shrinking
            // it by this call's own `open` gives the width available to open the
            // argument's combining head. A flat `fn_call_width` from the outermost
            // base cannot see this shrink and keeps gluing an ever-deeper chain past
            // the point `rustfmt` stops. When the shrunk budget cannot open the
            // argument's head, break this call one-per-line.
            if shrink_budget(budget, open) <= flat_leaf_len(last_head(last)) {
                return None;
            }
        }
        // The last element FORCED broken from that column under the commit's
        // `tail_budget`; its first line is the combined head's tail.
        let tail_len = trial(out, TrialReach::FirstLine, |out, mark| {
            render_forced_break(last, base, tail_budget, cfg, indent, last_col, out);
            mark.line(out).trim_end_matches('\n').len()
        });
        let first_line_end = last_col + tail_len;
        if first_line_end > cfg.max_width {
            return None;
        }
        // A multi-argument overflow's combined first line obeys `fn_call_width`; a
        // single-argument glue chain is exempt (it only nests through single-arg
        // heads).
        if !single_arg && first_line_end.saturating_sub(base) > FN_CALL_WIDTH {
            return None;
        }
        Some(last_col)
    })
}

/// Render a combined call's first-line head — `open` in place, then each
/// preceding argument flat followed by [`ELEM_SEP`] — returning the column `open`
/// ends at.
fn render_combine_head(
    open: &Doc,
    prefix: &[Doc],
    cfg: RenderConfig,
    indent: usize,
    start_col: usize,
    out: &mut String,
) -> usize {
    render_at(open, cfg, indent, start_col, false, out);
    let open_end = current_col(out);
    for e in prefix {
        let c = current_col(out);
        render_at(e, cfg, indent, c, true, out);
        out.push_str(ELEM_SEP);
    }
    open_end
}

/// Render `doc` at `col` in FORCED-broken mode: a combinable construct is laid out
/// multiline even when its own width would fit flat, because it is the multiline
/// target of an enclosing call-argument combine. A [`Doc::CallArgs`] recurses the
/// combine on ITS last argument (sharing `combine_base` for the `fn_call_width`
/// budget), else breaks its argument list one per line; any other doc falls back to
/// the standard non-flat render (a statement block / closure body already breaks).
fn render_forced_break(
    doc: &Doc,
    combine_base: usize,
    budget: usize,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    out: &mut String,
) {
    // The combine probe force-breaks the last argument to measure it, then the
    // committed layout force-breaks it again: memoized, the second is a replay.
    let pass = Pass::ForcedBreak {
        combine_base,
        budget,
    };
    memoized(doc, cfg, indent, col, pass, out, |out| {
        render_forced_break_node(doc, combine_base, budget, cfg, indent, col, out);
    });
}

/// One node of [`render_forced_break`]; the wrapper fronts it with the memo.
fn render_forced_break_node(
    doc: &Doc,
    combine_base: usize,
    budget: usize,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    out: &mut String,
) {
    match doc {
        Doc::CallArgs {
            open,
            elems,
            close,
            trailing_comma,
        } => {
            let start_col = eff_col(out, col);
            // Recurse the combine on the last argument first; if it does not apply,
            // fall through to the one-per-line break. The shared `combine_base` keeps
            // the `fn_call_width` budget anchored at the outermost combine; `budget`
            // is the recursive `Shape` width this call received for its argument, and
            // shrinks one step (`shrink_budget`) as the combine descends.
            let inner_budget = shrink_budget(budget, open);
            if let Some((last, prefix)) = elems.split_last()
                && last_arg_combines(
                    open,
                    prefix,
                    last,
                    Some(combine_base),
                    budget,
                    inner_budget,
                    cfg,
                    start_col,
                    indent,
                    out,
                )
                .is_some()
            {
                render_combine_head(open, prefix, cfg, indent, start_col, out);
                render_forced_break(
                    last,
                    combine_base,
                    inner_budget,
                    cfg,
                    indent,
                    current_col(out),
                    out,
                );
                let c = current_col(out);
                render_at(close, cfg, indent, c, false, out);
                return;
            }
            // One argument per line.
            render_one_per_line(
                open,
                elems,
                close,
                *trailing_comma,
                cfg,
                indent,
                start_col,
                out,
            );
        }
        // A struct literal `Name { … }` forced broken: one field per line. Its own
        // `struct_lit_width` re-test does not apply here (the combine forced it
        // multiline), so break its fields directly.
        Doc::StructLit {
            open,
            fields,
            close,
        } => {
            let start_col = eff_col(out, col);
            render_one_per_line(open, fields, close, true, cfg, indent, start_col, out);
        }
        // A wrapper like `Box::new(<CallArgs>)` / `Box::new(<StructLit>)`, or a
        // `move |…| -> R <braced-block>` closure: force-break the inner construct. A
        // leading wrapper text (`Box::new(`) shrinks the recursive `Shape` budget one
        // step before the inner combine. A closure's trailing braced-block `Group`
        // must be FORCED broken (its body onto its own line) — `rustfmt`'s
        // `overflow_delimited_expr` opens a block-like argument's body rather than
        // keeping it flat, even when the flat body alone would fit.
        Doc::Concat(parts) => {
            let is_closure = matches!(parts.first(), Some(Doc::Text(h)) if is_closure_head(h));
            let last = parts.len().saturating_sub(1);
            let mut inner_budget = budget;
            for (i, p) in parts.iter().enumerate() {
                let c = eff_col(out, col);
                if matches!(p, Doc::CallArgs { .. } | Doc::StructLit { .. }) {
                    render_forced_break(p, combine_base, inner_budget, cfg, indent, c, out);
                } else if (is_closure && i == last) || matches!(p, Doc::BraceBody(_)) {
                    // A closure body block, or a `BraceBody` inside a wrapper like
                    // `Box::new(move |_| <body>)`: force it broken. `rustfmt`'s
                    // `overflow_delimited_expr` opens a block-like argument's body onto
                    // its own line rather than keeping it flat, even when the flat body
                    // alone would fit — so the continuation closure of a broken
                    // `task_and_then` always braces (`Box::new(move |_| {\n … })`).
                    render_group_broken(p, cfg, indent, c, out);
                } else {
                    if let Doc::Text(_) = p {
                        inner_budget =
                            FN_CALL_WIDTH.min(inner_budget.saturating_sub(flat_leaf_len(p)));
                    }
                    render_at(p, cfg, indent, c, false, out);
                }
            }
        }
        // Any other doc breaks on its own (a block / closure body carries a
        // `HardLine`); render it non-flat.
        _ => render_at(doc, cfg, indent, col, false, out),
    }
}

/// Render a closure's braced body block with its braces/soft breaks FORCED — the
/// body onto its own line at one indent step, matching `rustfmt`'s
/// `overflow_delimited_expr` which opens a block-like argument even when its flat
/// body would fit. A `Group` body has its soft breaks forced; a `BraceBody` body is
/// forced to its braced multiline form (a `move |…| -> R ` closure carries a `Group`
/// body, a bare `|…| ` closure carries a `BraceBody`). Any other doc (a statement
/// block already carrying `HardLine`s) falls back to the standard non-flat render,
/// which breaks it anyway.
fn render_group_broken(doc: &Doc, cfg: RenderConfig, indent: usize, col: usize, out: &mut String) {
    match doc {
        Doc::Group(inner) => {
            let start_col = eff_col(out, col);
            render_at(inner, cfg, indent, start_col, false, out);
        }
        // A `BraceBody` closure body forced to its braced multiline form: the `|…| `
        // CAF closure body (a statement block) is opened here exactly as the
        // `move |…| -> R` closure's `Group` body is, so the combine glues the head
        // and breaks the body in place.
        Doc::BraceBody(body) => {
            let start_col = eff_col(out, col);
            render_brace_body_broken(body, cfg, indent, start_col, out);
        }
        _ => render_at(doc, cfg, indent, col, false, out),
    }
}

/// The opening head leaf (`f(`, `Box::new((`, `(`) of a combinable construct — the
/// text a nested combine glues onto and whose width shrinks the recursive `Shape`
/// budget one step. A [`Doc::CallArgs`] head is its `open`; a text-wrapped single
/// inner (`Box::new(<inner>)`) head is its leading `(`-terminated text; anything else
/// has no combining head (returns an empty leaf, width 0).
fn last_head(doc: &Doc) -> &Doc {
    match doc {
        Doc::CallArgs { open, .. } | Doc::StructLit { open, .. } => open,
        Doc::Concat(parts) => match parts.first() {
            Some(t @ Doc::Text(h)) if h.ends_with('(') && !h.contains('{') => t,
            _ => &EMPTY_LEAF,
        },
        _ => &EMPTY_LEAF,
    }
}

/// An empty text leaf, the zero-width combining head of a non-combinable construct.
static EMPTY_LEAF: Doc = Doc::Text(std::borrow::Cow::Borrowed(""));

/// The flat-rendered length of a delimiter/head leaf (`f(`, `Box::new((`), used to
/// shrink the recursive combining budget one nesting step.
fn flat_leaf_len(doc: &Doc) -> usize {
    let mut s = String::new();
    let cfg = RenderConfig::default();
    with_stop(&mut s, TrialReach::Whole, |s, _| {
        render_at(doc, cfg, 0, 0, true, s);
    });
    s.len()
}

/// The combining budget handed to a nested call's argument: the parent's budget
/// reduced by the parent call's own opening head, re-clamped to `fn_call_width`.
/// `rustfmt` shrinks the `Shape` width this way one step per nested combine.
fn shrink_budget(parent: usize, open: &Doc) -> usize {
    FN_CALL_WIDTH.min(parent.saturating_sub(flat_leaf_len(open)))
}

/// Whether `head` is a closure's parameter-list head — a `move |…| ` capturing
/// closure or a bare `|…| ` closure — that `rustfmt` glues a call head onto, letting
/// only the closure body break. Both open the same block-like layout; the sole
/// difference is the `move` capture keyword.
fn is_closure_head(head: &str) -> bool {
    head.starts_with("move |") || head == "|| "
}

/// Whether `doc` is a BLOCK-LIKE argument — a `|…|` / `move |…|` closure or a brace
/// block `{ … }` — that `rustfmt`'s `overflow_delimited_expr` always glues onto the
/// call head (breaking only its own body), rather than breaking the call one-per-line
/// to give the argument its own line. A `Box::new(<block-like>)` wrapper counts (the
/// wrapper glues and the inner block breaks). Distinct from [`is_glue_shape`], which
/// also admits nested calls / macros / tuples that DO get their own line when they
/// fit flat within the shared budget.
fn is_block_like(doc: &Doc) -> bool {
    node_fact(doc, |m| &mut m.block_like, || (block_like_uncached(doc), 1))
}

/// [`is_block_like`] for one node, its children read through the cache.
fn block_like_uncached(doc: &Doc) -> bool {
    match doc {
        Doc::BraceBody(_) => true,
        Doc::Group(inner) => is_block_like(inner),
        Doc::Concat(parts) => match parts.first() {
            // A `|…| ` / `move |…| ` closure head, or a brace block `{ … }` that is
            // not a `({` paren-wrapped statement block.
            Some(Doc::Text(head)) if is_closure_head(head) => true,
            Some(Doc::Text(head)) if head.ends_with('{') && !head.starts_with('(') => true,
            // A `Box::new(<block-like>)` / `Some(<block-like>)` wrapper.
            Some(Doc::Text(head)) if head.ends_with('(') && !head.contains('{') => {
                parts.get(1).is_some_and(is_block_like)
            }
            _ => false,
        },
        _ => false,
    }
}

/// Whether `doc` is a GLUE-shaped construct for the SINGLE-argument combine chain:
/// a [`Doc::CallArgs`] (any call / macro / ctor / tuple / list whose own delimiters
/// the outer head glues onto), a brace block (`{ … }`), or either behind a leading
/// `Box::new(` / `Some(` text wrapper. A [`Doc::Chain`] and a parenthesized
/// statement block (`({ … })`) are NOT glue-shaped.
fn is_glue_shape(doc: &Doc) -> bool {
    node_fact(
        doc,
        |m| &mut m.glue_shapes,
        || (glue_shape_uncached(doc), 1),
    )
}

/// [`is_glue_shape`] for one node, its children read through the cache.
fn glue_shape_uncached(doc: &Doc) -> bool {
    match doc {
        // A call/ctor/macro/tuple/list glues onto its own delimiters, and a struct
        // literal (`Name { … }`) is a brace-delimited construct `rustfmt` glues a
        // wrapper's head onto just like a call's `(`.
        Doc::CallArgs { .. } | Doc::StructLit { .. } => true,
        Doc::Group(inner) => is_glue_shape(inner),
        Doc::Concat(parts) => match parts.first() {
            // A `|…| ` / `move |…| ` closure head followed by its braced body — a
            // block-like expression `rustfmt` glues a wrapper's `(` onto, letting the
            // closure body break in place while the head stays on the wrapper's line.
            Some(Doc::Text(head)) if is_closure_head(head) => true,
            // A brace block `{ … }` (closure body / statement block) or a struct
            // literal `Name { … }` — a `{`-terminated head that is NOT a `({`
            // paren-wrapped statement block (which `rustfmt` does NOT combine).
            Some(Doc::Text(head)) if head.ends_with('{') && !head.starts_with('(') => true,
            // A `Box::new(<inner>)` / `Some(<inner>)` wrapper: a `(`-terminated head
            // (NOT a `({` paren-block), the inner glue construct, then a `)` tail.
            Some(Doc::Text(head)) if head.ends_with('(') && !head.contains('{') => {
                parts.get(1).is_some_and(is_glue_shape)
            }
            _ => false,
        },
        _ => false,
    }
}

/// Whether `doc` is a DELIMITED EXPRESSION for the MULTI-argument last-argument
/// overflow rule (`rustfmt`'s `overflow_delimited_expr`): a brace block / closure
/// body (`{ … }`), a tuple (`(…)`), or an array (`vec![…]`). A nested function CALL
/// or constructor is NOT a delimited expr for this rule — a multi-argument call
/// whose last argument is a plain call breaks one argument per line rather than
/// overflowing. A `Box::new(<delimited>)` wrapper counts (its inner is delimited).
fn is_delimited_expr(doc: &Doc) -> bool {
    node_fact(
        doc,
        |m| &mut m.delimited_exprs,
        || (delimited_expr_uncached(doc), 1),
    )
}

/// [`is_delimited_expr`] for one node, its children read through the cache.
fn delimited_expr_uncached(doc: &Doc) -> bool {
    match doc {
        Doc::CallArgs { open, elems, .. } => match open.as_ref() {
            // A tuple `(` or an array `vec![` / `[`.
            Doc::Text(h) if h.as_ref() == "(" || h.ends_with('[') => true,
            // A `Box::new(<delimited>)` / `Some(<delimited>)` single-arg wrapper:
            // delimited iff its inner is (its own `(`-ended named head).
            Doc::Text(h) if h.ends_with('(') && !h.contains('{') && elems.len() == 1 => {
                elems.first().is_some_and(is_delimited_expr)
            }
            _ => false,
        },
        // A struct literal (`Name { … }`) is a brace construct — a delimited expr
        // for the overflow rule.
        Doc::StructLit { .. } => true,
        Doc::Group(inner) => is_delimited_expr(inner),
        Doc::Concat(parts) => match parts.first() {
            // A brace block `{ … }` or a struct literal `Name { … }` — a
            // `{`-terminated head that is NOT a `({` paren-wrapped statement block.
            Some(Doc::Text(head)) if head.ends_with('{') && !head.starts_with('(') => true,
            Some(Doc::Text(head)) if head.ends_with('(') && !head.contains('{') => {
                parts.get(1).is_some_and(is_delimited_expr)
            }
            _ => false,
        },
        _ => false,
    }
}

/// Whether `op operand` glued onto the current line fits, paired with whether the
/// glued operand rendered single-line. The operand may render multiline; the fit
/// test measures only whether `op` plus the operand's FIRST line fits at the
/// current column (a multiline operand's later lines are free to break below). A
/// single-line operand must fit entirely.
///
/// Measured by a first-line [`trial`] of the very glue the chain commits to, so a
/// chain operator glues to a FOLLOWING operand only when that operand, laid out
/// exactly there, is single-line.
fn glue_fits(
    operand: &Doc,
    cfg: RenderConfig,
    col: usize,
    indent: usize,
    op: &str,
    out: &mut String,
) -> (bool, bool) {
    // Column after " op " is appended.
    let after_op = col + 1 + op.len() + 1;
    if after_op > cfg.margin() {
        return (false, false);
    }
    trial(out, TrialReach::FirstLine, |out, mark| {
        glue_operand(operand, cfg, indent, op, out);
        let first = mark.line(out);
        let single_line = !first.contains('\n');
        let operand_w = first
            .trim_end_matches('\n')
            .len()
            .saturating_sub(1 + op.len() + 1);
        // The trailing-delimiter `reserve` bites only when the operand renders
        // single-line here — then this glued line IS the chain's last line and the
        // enclosing `,` sits at its end. A multiline operand ends on a later line,
        // so its glued first line is measured against the full width.
        let margin = if single_line {
            cfg.margin()
        } else {
            cfg.max_width
        };
        (after_op + operand_w <= margin, single_line)
    })
}

/// Glue ` op operand` onto the current line.
fn glue_operand(operand: &Doc, cfg: RenderConfig, indent: usize, op: &str, out: &mut String) {
    out.push(' ');
    out.push_str(op);
    out.push(' ');
    let c = current_col(out);
    render_at(operand, cfg, indent, c, false, out);
}

/// The indentation (leading-space count) of the line currently being written in
/// `out`, or `None` if the current line has non-space content already (the chain
/// starts mid-line, e.g. after `let z = `).
pub(super) fn current_line_indent(out: &str) -> Option<usize> {
    let line_start = out.rfind('\n').map_or(0, |nl| nl + 1);
    let line = out.get(line_start..).unwrap_or_default();
    if line.chars().all(|c| c == ' ') {
        Some(line.len())
    } else {
        // Mid-line start: the break indent is keyed off the enclosing block, not
        // this column. Signal by returning None so the caller falls back to the
        // block indent.
        None
    }
}

/// Render every operand of a chain flat (inline), operators separated by spaces.
fn render_chain_flat(
    operands: &[ChainOperand],
    cfg: RenderConfig,
    indent: usize,
    out: &mut String,
) {
    for (i, operand) in operands.iter().enumerate() {
        if i > 0 {
            out.push(' ');
            out.push_str(operand.leading_op.as_deref().unwrap_or(""));
            out.push(' ');
        }
        let c = current_col(out);
        render_at(&operand.doc, cfg, indent, c, true, out);
    }
}
