//! Per-event cost of charging a session's retained render state.
//!
//! A committed view and its handler index never change, so their measures are
//! taken once, at commit, and a recharge reads them back. These tests count the
//! measure visits of a test message type, deterministically and without a
//! clock, and pin the cached charge to a fresh walk of the same state.

#![cfg(all(feature = "web", not(target_arch = "wasm32")))]

use std::cell::Cell;

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
    /// Select the row at this position.
    Select(usize),
    /// A message with no measure, as a `Msg` holding an unmeasured field has.
    Unmeasured,
}

impl RetainedBytes for TestMsg {
    fn retained_bytes(&self) -> Option<Bytes> {
        MEASURES.with(|n| n.set(n.get().saturating_add(1)));
        match self {
            Self::Select(_) => Bytes::inline::<Self>(),
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
        TestMsg::Select(_) => TestMsg::Select(i),
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
/// carrying a message shaped like `msg`, and an optional trailing text node.
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
    view_with(selected, &TestMsg::Select(0), None)
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
#[allow(clippy::expect_used)] // the fixture commits far below the counter's end
#[test]
fn the_cached_charge_equals_a_fresh_walk_after_every_commit() {
    let mut rendered = Rendered::first(keys(), view(0));
    assert_eq!(rendered.resident_bytes(), rendered.measured_fresh());
    for selected in 1..=20 {
        rendered.commit(view(selected)).expect("commit");
        let cached = rendered.resident_bytes();
        assert!(cached.is_some(), "commit {selected} has a charge");
        assert_eq!(cached, rendered.measured_fresh(), "commit {selected}");
        let view_bytes = rendered.last_view().view_bytes();
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
        .commit(view_with(2, &TestMsg::Select(0), Some(text)))
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
