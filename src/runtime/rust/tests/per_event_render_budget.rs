//! Per-event cost of charging a session's retained render state.
//!
//! A committed view and its handler index never change, so their measures are
//! taken once, at commit, and a recharge reads them back. These tests count the
//! measure visits of a test message type, deterministically and without a
//! clock, and pin the cached charge to a fresh walk of the same state.
//!
//! Stamping a view's ids is per-event work too: its allocations are counted
//! through an instrumented global allocator, and its id bytes are pinned to
//! the id grammar.

#![cfg(all(feature = "web", not(target_arch = "wasm32")))]

use std::alloc::System;
use std::cell::Cell;

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

use ipe_runtime_rust::dom::{RENDER_HISTORY_DEPTH, Rendered, SessionKeys};
use ipe_runtime_rust::html::{Attribute, Event, Html, assign_ipe_ids};
use ipe_runtime_rust::{Bytes, RetainedBytes};

/// Rows in the queue-rail fixture.
const ROWS: usize = 5000;

/// Nodes in the fixture's handler-free chrome subtree.
const CHROME: usize = 200;

thread_local! {
    /// How many times a [`TestMsg`] has been measured on this thread.
    static MEASURES: Cell<u64> = const { Cell::new(0) };
}

/// The [`TestMsg`] measure visits so far on this thread.
fn measures() -> u64 {
    MEASURES.with(Cell::get)
}

/// A row's click message; each measure of it is counted.
#[derive(Clone)]
enum TestMsg {
    /// Select the row with this key.
    Select(String),
    /// A message with no measure, as a `Msg` holding an unmeasured field has.
    Unmeasured,
}

impl RetainedBytes for TestMsg {
    fn retained_bytes(&self) -> Option<Bytes> {
        MEASURES.with(|n| n.set(n.get().saturating_add(1)));
        match self {
            Self::Select(key) => Bytes::inline::<Self>()?.plus(key),
            Self::Unmeasured => None,
        }
    }
}

/// One rail row: a styled `li` with a click handler over a labelled `span`.
fn row(i: usize, selected: usize, msg: &TestMsg) -> Html<TestMsg> {
    let style = if i == selected {
        "background:#33a"
    } else {
        "background:none"
    };
    let msg = match msg {
        TestMsg::Select(tag) => TestMsg::Select(format!("row-{i}{tag}")),
        TestMsg::Unmeasured => TestMsg::Unmeasured,
    };
    Html::HElement(
        "li".into(),
        vec![
            Attribute::Attr("style".into(), style.into()),
            Attribute::EventAttr(Event::OnMsg("click".into(), Box::new(msg))),
        ],
        vec![Html::HElement(
            "span".into(),
            Vec::new(),
            vec![Html::HText(format!("unit {i}"))],
        )],
    )
}

/// The stamped queue view with row `selected` highlighted, every handler
/// carrying a message shaped like `msg` (a `Select` tag suffixes each row's
/// key), and an optional trailing text node.
fn view_with(selected: usize, msg: &TestMsg, extra: Option<String>) -> Html<TestMsg> {
    let chrome = Html::HElement(
        "header".into(),
        Vec::new(),
        (1..CHROME)
            .map(|_| Html::HElement("span".into(), Vec::new(), Vec::new()))
            .collect(),
    );
    let rail = Html::HElement(
        "ul".into(),
        Vec::new(),
        (0..ROWS).map(|i| row(i, selected, msg)).collect(),
    );
    let mut kids = vec![chrome, rail];
    kids.extend(extra.map(Html::HText));
    let mut view = Html::HElement("main".into(), Vec::new(), kids);
    assign_ipe_ids(&mut view, "r");
    view
}

/// The stamped queue view with row `selected` highlighted.
fn view(selected: usize) -> Html<TestMsg> {
    view_with(selected, &TestMsg::Select(String::new()), None)
}

/// Fresh session keys from the host's entropy.
#[allow(clippy::expect_used)] // a test host always has entropy
fn keys() -> SessionKeys {
    SessionKeys::mint().expect("session keys")
}

/// The handlers one view of the fixture holds, as a measure-visit count.
fn rows() -> u64 {
    u64::try_from(ROWS).unwrap_or(u64::MAX)
}

/// A history moved past its depth, so it holds a full set of retained renders.
#[allow(clippy::expect_used)] // the fixture commits far below the counter's end
fn full_history() -> Rendered<TestMsg> {
    let mut rendered = Rendered::first(keys(), view(0));
    for selected in 1..=RENDER_HISTORY_DEPTH.get().saturating_add(1) {
        rendered.commit(view(selected)).expect("commit");
    }
    rendered
}

// A recharge of a full history reads the commit-time measures: it measures no
// message, whatever the view size or history depth.
#[test]
fn a_recharge_measures_no_retained_message() {
    let rendered = full_history();
    let before = measures();
    let bytes = rendered.resident_bytes();
    assert!(bytes.is_some(), "a measurable history has a charge");
    assert_eq!(measures(), before, "the recharge re-walked retained state");
}

// The counter is live: a commit measures each handler message exactly twice,
// once for the view and once for its new index.
#[test]
fn a_commit_measures_each_handler_once_for_the_view_and_once_for_its_index() {
    let mut rendered = full_history();
    let next = view(ROWS.saturating_sub(1));
    let before = measures();
    assert!(rendered.commit(next).is_ok());
    let visits = measures().saturating_sub(before);
    assert_eq!(Some(visits), rows().checked_mul(2));
}

// After every commit, the cached charge equals a fresh walk of the same view
// and the same retained indexes, through the history's fill and its evictions.
// Each commit's view and index differ in size from every other's, so a measure
// kept from another render cannot match the walk by coincidence.
#[allow(clippy::expect_used)] // the fixture commits far below the counter's end
#[test]
fn the_cached_charge_equals_a_fresh_walk_after_every_commit() {
    let mut rendered = Rendered::first(keys(), view(0));
    assert_eq!(rendered.resident_bytes(), rendered.measured_fresh());
    let mut seen = Vec::new();
    for selected in 1..=20 {
        let sized = view_with(
            selected,
            &TestMsg::Select("k".repeat(selected)),
            Some("t".repeat(selected.saturating_mul(13))),
        );
        rendered.commit(sized).expect("commit");
        let view_bytes = rendered.last_view().view_bytes();
        assert!(
            !seen.contains(&view_bytes),
            "commit {selected} repeats a size"
        );
        seen.push(view_bytes);
        let cached = rendered.resident_bytes();
        assert!(cached.is_some(), "commit {selected} has a charge");
        assert_eq!(cached, rendered.measured_fresh(), "commit {selected}");
        assert!(
            cached.zip(view_bytes).is_some_and(|(all, v)| all > v),
            "the charge covers the view and its indexes: {cached:?} {view_bytes:?}"
        );
    }
}

// A view grown by one 4 KiB text node moves the cached charge and the fresh
// walk by the same delta, the node's own measure, so the cache tracks what it
// charges rather than a stale constant.
#[allow(clippy::expect_used)] // the fixture commits far below the counter's end
#[test]
fn a_grown_view_moves_the_cache_and_the_fresh_walk_alike() {
    let mut rendered = full_history();
    rendered.commit(view(1)).expect("commit");
    let cached = rendered.resident_bytes().map(Bytes::get);
    let fresh = rendered.measured_fresh().map(Bytes::get);
    let plain = rendered.last_view().view_bytes().map(Bytes::get);
    let text = "x".repeat(4096);
    rendered
        .commit(view_with(2, &TestMsg::Select(String::new()), Some(text)))
        .expect("commit");
    let grown = rendered.last_view().view_bytes().map(Bytes::get);
    let delta = |after: Option<u64>, before: Option<u64>| {
        after.zip(before).and_then(|(a, b)| a.checked_sub(b))
    };
    let view_delta = delta(grown, plain);
    assert!(view_delta.is_some_and(|d| d >= 4096), "{view_delta:?}");
    assert_eq!(
        delta(rendered.resident_bytes().map(Bytes::get), cached),
        view_delta
    );
    assert_eq!(
        delta(rendered.measured_fresh().map(Bytes::get), fresh),
        view_delta
    );
}

// A retained render with no measure leaves the whole charge without one, as a
// fresh walk does, until the history evicts that render; the session's own
// ceiling then refuses it, so fail-closed is kept.
#[allow(clippy::expect_used)] // the fixture commits far below the counter's end
#[test]
fn an_unmeasured_render_keeps_the_charge_unmeasured_until_it_is_evicted() {
    let mut rendered = full_history();
    assert!(rendered.resident_bytes().is_some());
    rendered
        .commit(view_with(0, &TestMsg::Unmeasured, None))
        .expect("commit");
    assert_eq!(rendered.resident_bytes(), None);
    assert_eq!(rendered.measured_fresh(), None);
    // The unmeasured render leaves the current view but stays in the history.
    rendered.commit(view(1)).expect("commit");
    assert_eq!(rendered.resident_bytes(), None);
    assert_eq!(rendered.measured_fresh(), None);
    for selected in 2..RENDER_HISTORY_DEPTH.get() {
        rendered.commit(view(selected)).expect("commit");
        assert_eq!(rendered.resident_bytes(), None, "commit {selected}");
    }
    // One more commit evicts the unmeasured render.
    rendered.commit(view(0)).expect("commit");
    assert!(rendered.resident_bytes().is_some());
    assert_eq!(rendered.resident_bytes(), rendered.measured_fresh());
}

/// Every allocation of this test binary goes through the counting wrapper, so
/// a [`Region`] reads the allocations made between two points of one test.
///
/// The counters are process-wide: the reading is exact only while the test is
/// the process's one running thread, as under nextest's process-per-test run.
#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// Rows in the smaller stamping fixture.
const BASE_ROWS: usize = 20;

/// Rows the larger stamping fixture adds.
///
/// Both fixtures' last rows have two-digit indexes, so the longest row id, and
/// with it the shared path buffer's growth, is the same in either fixture.
const ADDED_ROWS: usize = 50;

/// Heap operations an element costs the stamper.
///
/// They are its `ipe-id` key, its id value, and the one growth of an
/// exact-capacity attribute vector.
const STAMP_ALLOCS_PER_ELEMENT: usize = 3;

/// A rail of `rows` leaf `li`s with exact-capacity attributes, beside a header.
fn stamp_rail(rows: usize) -> Html<()> {
    let header = Html::HElement(
        "header".into(),
        Vec::new(),
        vec![Html::HElement("span".into(), Vec::new(), Vec::new())],
    );
    let rail = Html::HElement(
        "ul".into(),
        Vec::new(),
        (0..rows)
            .map(|_| {
                Html::HElement(
                    "li".into(),
                    vec![Attribute::Attr("class".into(), "row".into())],
                    Vec::new(),
                )
            })
            .collect(),
    );
    Html::HElement("main".into(), Vec::new(), vec![header, rail])
}

/// Allocations plus reallocations made while stamping `tree`.
fn stamp_heap_ops(mut tree: Html<()>) -> usize {
    let region = Region::new(GLOBAL);
    assign_ipe_ids(&mut tree, "r");
    let change = region.change();
    change.allocations.saturating_add(change.reallocations)
}

// Each added element costs the stamper exactly its stored id and its id key,
// plus one attribute-vector growth: no per-child path is built, so the shared
// path buffer's own growth is a per-tree constant that cancels in the
// difference.
#[test]
fn stamping_allocates_only_each_elements_stored_id() {
    let base = stamp_heap_ops(stamp_rail(BASE_ROWS));
    let grown = stamp_heap_ops(stamp_rail(BASE_ROWS.saturating_add(ADDED_ROWS)));
    assert!(base > 0, "the allocation counter is live");
    assert_eq!(
        grown.checked_sub(base),
        ADDED_ROWS.checked_mul(STAMP_ALLOCS_PER_ELEMENT),
        "base {base}, grown {grown}"
    );
}

/// The `ipe-id` of every element under `node`, in document order.
fn stamped_ids<M>(node: &Html<M>) -> Vec<String> {
    let mut ids = Vec::new();
    let mut pending = vec![node];
    while let Some(next) = pending.pop() {
        if let Html::HElement(_, attrs, kids) = next {
            ids.extend(attrs.iter().find_map(|a| match a {
                Attribute::Attr(k, v) if k == "ipe-id" => Some(v.clone()),
                _ => None,
            }));
            pending.extend(kids.iter().rev());
        }
    }
    ids
}

/// The ids the grammar `{root}(_{idx}_{tag})*` names under `node`, in document order.
///
/// Each id is built whole by `format!`. It holds for a tree with no key and only
/// alphanumeric tags, whose segments need no escape.
fn grammar_ids<M>(node: &Html<M>, root: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut pending = vec![(node, root.to_owned())];
    while let Some((next, id)) = pending.pop() {
        if let Html::HElement(_, _, kids) = next {
            let mut idx = kids
                .iter()
                .filter(|kid| matches!(kid, Html::HElement(..)))
                .count();
            for kid in kids.iter().rev() {
                if let Html::HElement(tag, _, _) = kid {
                    idx = idx.saturating_sub(1);
                    pending.push((kid, format!("{id}_{idx}_{tag}")));
                }
            }
            ids.push(id);
        }
    }
    ids
}

/// Elements in the deep chain of the identity fixture.
const CHAIN_DEPTH: usize = 600;

/// Rows in the wide list of the identity fixture.
const WIDE_ROWS: usize = 1500;

// The shared path buffer yields, for a chain hundreds deep and a list
// thousands wide, the same id bytes as each id built whole from the grammar:
// every truncate restores the parent's id exactly, and a text node between
// siblings takes no index.
#[test]
fn stamped_ids_of_deep_and_wide_trees_follow_the_grammar() {
    let mut chain: Html<()> = Html::HElement("b".into(), Vec::new(), Vec::new());
    for depth in 0..CHAIN_DEPTH {
        let tag = if depth.is_multiple_of(2) {
            "div"
        } else {
            "section"
        };
        chain = Html::HElement(tag.into(), Vec::new(), vec![chain]);
    }
    let wide = Html::HElement(
        "ul".into(),
        Vec::new(),
        (0..WIDE_ROWS)
            .map(|i| {
                if i.is_multiple_of(7) {
                    Html::HText(format!("gap {i}"))
                } else {
                    Html::HElement(
                        "li".into(),
                        Vec::new(),
                        vec![Html::HElement("span".into(), Vec::new(), Vec::new())],
                    )
                }
            })
            .collect(),
    );
    let mut tree = Html::HElement("main".into(), Vec::new(), vec![chain, wide]);
    let expected = grammar_ids(&tree, "r");
    assign_ipe_ids(&mut tree, "r");
    let ids = stamped_ids(&tree);
    assert!(
        ids.len() > CHAIN_DEPTH.saturating_add(WIDE_ROWS),
        "every element is stamped: {}",
        ids.len()
    );
    assert_eq!(ids, expected);
}

// The id bytes of keyed, named and radio-grouped elements are pinned to the
// literal ids the grammar gives them: the key segment escapes `.` and `_`, and
// a grouped radio's key is the group name its fieldset's id derives.
#[test]
fn stamped_ids_of_keyed_named_and_grouped_elements_are_pinned() {
    let keyed = |key: &str| {
        Html::HElement(
            "li".into(),
            vec![Attribute::Attr("ipe-key".into(), key.into())],
            Vec::new(),
        )
    };
    let radio = || {
        Html::HElement(
            "input".into(),
            vec![Attribute::Attr("type".into(), "radio".into())],
            Vec::new(),
        )
    };
    let mut tree: Html<()> = Html::HElement(
        "main".into(),
        Vec::new(),
        vec![
            Html::HElement("ul".into(), Vec::new(), vec![keyed("a.b"), keyed("c")]),
            Html::HElement(
                "input".into(),
                vec![Attribute::Attr("name".into(), "q".into())],
                Vec::new(),
            ),
            Html::HText("gap".into()),
            Html::HElement(
                "fieldset".into(),
                vec![Attribute::Attr(
                    "data-ipe-radio-group".into(),
                    String::new(),
                )],
                vec![radio(), radio()],
            ),
        ],
    );
    assign_ipe_ids(&mut tree, "r");
    assert_eq!(
        stamped_ids(&tree),
        [
            "r",
            "r_0_ul",
            "r_0_ul_0_li:a.2eb",
            "r_0_ul_1_li:c",
            "r_1_input:q",
            "r_2_fieldset",
            "r_2_fieldset_0_input:ipe-rg-r.5f2.5ffieldset",
            "r_2_fieldset_1_input:ipe-rg-r.5f2.5ffieldset",
        ]
    );
}
