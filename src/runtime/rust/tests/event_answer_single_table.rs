//! One reading of an event answer: `__ipeEventAnswer` maps every status to one outcome.
//!
//! The browser client posts each event to `/_ipe/event` and reads the answer's
//! status in exactly one function, `__ipeEventAnswer`, which maps it into the
//! closed set `__IPE_EVENT_ANSWER`. The poster switches over that set with one
//! arm per outcome and a `default` that throws, so a status no row names falls
//! to the table's last row (`REFUSED`), never to the network-failure retry.
//! These checks read `client.js` as text: its line comments are dropped first
//! and whitespace runs are collapsed to one space, so a reflow keeps them true.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeSet;

/// The browser client source the runtime serves.
const CLIENT_JS: &str = include_str!("../src/web/client.js");

/// The one function that reads an event answer's status.
const THE_TABLE: &str = "__ipeEventAnswer";

/// The function that posts an event and dispatches on its answer.
const THE_POSTER: &str = "__ipePostEvent";

/// The client source with `//` line comments dropped and whitespace collapsed.
fn code() -> String {
    let mut out = String::new();
    for line in CLIENT_JS.lines() {
        let kept = line_code(line);
        out.push_str(kept);
        out.push('\n');
    }
    collapse(&out)
}

/// `line` up to a `//` comment that starts the line or follows whitespace.
fn line_code(line: &str) -> &str {
    let mut search = 0;
    while let Some(found) = line.get(search..).and_then(|rest| rest.find("//")) {
        let at = search + found;
        let before = line.get(..at).unwrap_or_default();
        if before.trim().is_empty() || before.ends_with(char::is_whitespace) {
            return before;
        }
        search = at + 2;
    }
    line
}

/// `text` with every whitespace run replaced by one space.
fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The source of `function name(`, from its head through its matching close brace.
fn body_of(source: &str, name: &str) -> String {
    let head = format!("function {name}(");
    let start = source.find(&head);
    assert!(start.is_some(), "client.js defines no `{head}`");
    let rest = source.get(start.unwrap_or_default()..).unwrap_or_default();
    let end = matching_close(rest);
    assert!(end.is_some(), "`{head}` has no matching close brace");
    rest.get(..end.unwrap_or_default())
        .unwrap_or_default()
        .to_owned()
}

/// The byte just past the brace closing the first `{` in `text`, skipping string literals.
fn matching_close(text: &str) -> Option<usize> {
    let mut depth = 0_usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (at, c) in text.char_indices() {
        if let Some(open) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == open {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' | '`' => quote = Some(c),
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(at + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Every `function __ipe` head's byte offset, paired with its name, in source order.
fn function_starts(source: &str) -> Vec<(usize, String)> {
    let mut starts = Vec::new();
    let mut search = 0;
    while let Some(found) = source
        .get(search..)
        .and_then(|rest| rest.find("function __ipe"))
    {
        let at = search + found;
        let name_start = at + "function ".len();
        let name: String = source
            .get(name_start..)
            .unwrap_or_default()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        starts.push((at, name));
        search = at + 1;
    }
    starts
}

/// The name of the top-level function enclosing byte `at`, or empty at top level.
fn enclosing(starts: &[(usize, String)], at: usize) -> String {
    starts
        .iter()
        .take_while(|(start, _)| *start <= at)
        .last()
        .map_or_else(String::new, |(_, name)| name.clone())
}

/// Each `<receiver>.<field>` read in `source`, paired with its byte offset.
fn field_reads(source: &str, field: &str) -> Vec<(usize, String)> {
    let needle = format!(".{field}");
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$';
    let mut reads = Vec::new();
    let mut search = 0;
    while let Some(found) = source.get(search..).and_then(|rest| rest.find(&needle)) {
        let at = search + found;
        search = at + needle.len();
        let after = source.get(search..).and_then(|rest| rest.chars().next());
        if after.is_some_and(is_ident) {
            continue;
        }
        let before = source.get(..at).unwrap_or_default();
        let receiver: String = before
            .chars()
            .rev()
            .take_while(|c| is_ident(*c))
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        reads.push((at, receiver));
    }
    reads
}

/// The keys of the frozen `__IPE_EVENT_ANSWER` outcome set.
fn outcome_keys(source: &str) -> BTreeSet<String> {
    let head = "var __IPE_EVENT_ANSWER = Object.freeze({";
    let start = source.find(head);
    assert!(start.is_some(), "client.js defines no `{head}`");
    let rest = source
        .get(start.unwrap_or_default() + head.len()..)
        .unwrap_or_default();
    let literal = rest
        .get(..rest.find('}').unwrap_or_default())
        .unwrap_or_default();
    literal
        .split(',')
        .filter_map(|entry| entry.split(':').next())
        .map(|key| key.trim().to_owned())
        .filter(|key| !key.is_empty())
        .collect()
}

#[test]
fn the_poster_reads_no_status() {
    let source = code();
    let poster = body_of(&source, THE_POSTER);
    for field in ["status", "ok", "statusText"] {
        let reads = field_reads(&poster, field);
        assert!(
            reads.is_empty(),
            "`{THE_POSTER}` reads `.{field}` ({reads:?}); only `{THE_TABLE}` reads an answer's status"
        );
    }
    assert!(
        poster.contains("var kind = __ipeEventAnswer(r); switch (kind) {"),
        "`{THE_POSTER}` must dispatch on `{THE_TABLE}(r)`"
    );
}

#[test]
fn only_the_table_reads_an_answer_status() {
    let source = code();
    let starts = function_starts(&source);
    let mut table_reads = 0;
    for (at, receiver) in field_reads(&source, "status") {
        let owner = enclosing(&starts, at);
        if owner == THE_TABLE && receiver == "r" {
            table_reads += 1;
            continue;
        }
        // The tab mirror's message names a status string; it is no answer.
        let is_mirror_message = owner == "__ipeLiveOnMessage" && receiver == "m";
        assert!(
            is_mirror_message,
            "`{receiver}.status` is read in `{owner}`; an event answer's status is read only in `{THE_TABLE}`"
        );
    }
    assert!(
        table_reads == 1,
        "`{THE_TABLE}` must read `r.status` exactly once, read {table_reads} times"
    );
}

#[test]
fn every_outcome_has_exactly_one_arm() {
    let source = code();
    let keys = outcome_keys(&source);
    let expected: BTreeSet<String> = [
        "ACCEPTED",
        "STALE",
        "SESSION_LOST",
        "TRANSIENT",
        "TOO_LARGE",
        "REFUSED",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert!(
        keys == expected,
        "`__IPE_EVENT_ANSWER` names {keys:?}, the poster's arms cover {expected:?}"
    );
    let poster = body_of(&source, THE_POSTER);
    for key in &keys {
        let arm = format!("case __IPE_EVENT_ANSWER.{key}:");
        let arms = poster.matches(&arm).count();
        assert!(
            arms == 1,
            "`{THE_POSTER}` has {arms} `{arm}` arms; every outcome has exactly one"
        );
    }
    let cases = poster.matches("case ").count();
    assert!(
        cases == keys.len(),
        "`{THE_POSTER}` has {cases} `case` arms for {} outcomes",
        keys.len()
    );
    assert!(
        poster.contains("default: throw new Error("),
        "`{THE_POSTER}`'s `default` arm must throw, never fall through to acceptance"
    );
}

#[test]
fn the_table_returns_only_named_outcomes_and_ends_refused() {
    let source = code();
    let keys = outcome_keys(&source);
    let table = body_of(&source, THE_TABLE);
    let mut search = 0;
    let needle = "return __IPE_EVENT_ANSWER.";
    let mut returns = 0;
    while let Some(found) = table.get(search..).and_then(|rest| rest.find(needle)) {
        let at = search + found + needle.len();
        search = at;
        let key: String = table
            .get(at..)
            .unwrap_or_default()
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || *c == '_')
            .collect();
        assert!(
            keys.contains(&key),
            "`{THE_TABLE}` returns `{key}`, which `__IPE_EVENT_ANSWER` does not name"
        );
        returns += 1;
    }
    assert!(
        returns > 0,
        "`{THE_TABLE}` returns no `__IPE_EVENT_ANSWER` outcome"
    );
    assert!(
        table
            .trim_end()
            .ends_with("return __IPE_EVENT_ANSWER.REFUSED; }"),
        "`{THE_TABLE}`'s last row must be `REFUSED`, so a status no row names is refused"
    );
    assert!(
        table.matches("return ").count() == returns,
        "every `return` in `{THE_TABLE}` must name an outcome"
    );
}

#[test]
fn a_transient_answer_keeps_the_queue_order() {
    let source = code();
    let poster = body_of(&source, THE_POSTER);
    let failures = poster
        .matches("__ipeOnPostFailure(body, fromQueue);")
        .count();
    assert!(
        failures == 2,
        "`{THE_POSTER}` reaches the retry path from {failures} sites; the `TRANSIENT` arm and the network failure are the two"
    );
    assert!(
        poster.matches("__ipeOnPostFailure(").count() == failures,
        "every retry in `{THE_POSTER}` must carry whether the body is the queue's head"
    );
    let failure = body_of(&source, "__ipeOnPostFailure");
    assert!(
        failure.contains("__ipeEnqueue(body, fromQueue);"),
        "`__ipeOnPostFailure` must put the queue's own head back at the head"
    );
    let enqueue = body_of(&source, "__ipeEnqueue");
    assert!(
        enqueue.contains(
            "if (atHead) __ipeEventQueue.unshift(body); else __ipeEventQueue.push(body);"
        ),
        "`__ipeEnqueue` must keep a failed head at the head and append anything else"
    );
    let drain = body_of(&source, "__ipeDrainQueue");
    assert!(
        drain.contains("if (__ipeQueueInFlight) return;"),
        "`__ipeDrainQueue` must post one queued event at a time"
    );
    assert!(
        drain.contains("__ipePostEvent(head, true);"),
        "`__ipeDrainQueue` must mark the body it posts as the queue's head"
    );
    assert!(
        poster.contains(
            "if (!fromQueue && (__ipeEventQueue.length > 0 || __ipeQueueInFlight)) { __ipeEnqueue(body, false);"
        ),
        "a live event posted while the queue holds or posts events must join its tail"
    );
}

#[test]
fn a_refused_event_is_never_sent_again() {
    let source = code();
    let poster = body_of(&source, THE_POSTER);
    for key in ["TOO_LARGE", "REFUSED"] {
        let arm = format!(
            "case __IPE_EVENT_ANSWER.{key}: __ipeOnPostRefused(body, __IPE_EVENT_ANSWER.{key}); return;"
        );
        assert!(
            poster.contains(&arm),
            "`{THE_POSTER}`'s `{key}` arm must end in `__ipeOnPostRefused` and return"
        );
    }
    let refused = body_of(&source, "__ipeOnPostRefused");
    for retry in [
        "__ipeEnqueue(",
        "__ipeOnPostFailure(",
        "__ipeScheduleRetry(",
        "__ipePostEvent(",
    ] {
        assert!(
            !refused.contains(retry),
            "`__ipeOnPostRefused` calls `{retry}`; a refused event is never sent again"
        );
    }
    assert!(
        refused.contains("e.refusedValue = sent[ids[i]].value;"),
        "`__ipeOnPostRefused` must record each value the refused event carried"
    );
    let snapshot = body_of(&source, "__ipeInputsSnapshot");
    assert!(
        snapshot.contains("if (e.refusedValue !== null) continue;"),
        "`__ipeInputsSnapshot` must leave out a value a refused event carried"
    );
    assert!(
        snapshot.contains(
            "if (e.refusedValue !== null && e.refusedValue !== e.liveValue) e.refusedValue = null;"
        ),
        "`__ipeInputsSnapshot` must release a refused value once the input no longer shows it"
    );
}

#[test]
fn no_answer_field_is_read_by_name() {
    let source = code();
    for field in ["status", "ok", "statusText"] {
        for quote in ['"', '\'', '`'] {
            let read = format!("[{quote}{field}{quote}]");
            assert!(
                !source.contains(&read),
                "client.js reads `{read}`; an event answer's status is read only as `r.status` in `{THE_TABLE}`"
            );
        }
    }
    let ok_reads = field_reads(&source, "ok");
    let stray: Vec<&(usize, String)> = ok_reads
        .iter()
        .filter(|(_, receiver)| receiver != "data")
        .collect();
    assert!(
        stray.is_empty(),
        "`.ok` is read off {stray:?}; only the stream's `data.ok` frame field is read"
    );
    assert!(
        ok_reads.len() == 2,
        "client.js reads `data.ok` {} times, expected the stream frame's 2",
        ok_reads.len()
    );
}

#[test]
fn the_queue_slot_is_released_only_by_the_post_holding_it() {
    let source = code();
    let poster = body_of(&source, THE_POSTER);
    assert!(
        source.contains("var __ipeQueueInFlight = null;"),
        "`__ipeQueueInFlight` must hold the posted body or null"
    );
    assert!(
        poster.contains("if (fromQueue) __ipeQueueInFlight = body;"),
        "`{THE_POSTER}` must hold the queue slot with the body it posts"
    );
    let release = "if (__ipeQueueInFlight === body) __ipeQueueInFlight = null;";
    let releases = poster.matches(release).count();
    assert!(
        releases == 2,
        "`{THE_POSTER}` releases the queue slot from {releases} sites; the answer and the network failure are the two"
    );
    let writes = source.matches("__ipeQueueInFlight = ").count();
    assert!(
        writes == releases + 2,
        "client.js writes `__ipeQueueInFlight` {writes} times; only its declaration, the post holding it and that post's two releases do"
    );
}

#[test]
fn a_refusal_notice_stands_for_a_connection_that_is_up() {
    let source = code();
    let mapping = body_of(&source, "__ipeConnectionStatus");
    assert!(
        mapping.contains("return __ipeStatus === \"refused\" ? \"connected\" : __ipeStatus;"),
        "`__ipeConnectionStatus` must read a refusal notice as a connection that is up"
    );
    assert!(
        !source.contains("__ipeStatus === \"connected\""),
        "a test of `__ipeStatus === \"connected\"` misses the refusal notice; test `__ipeConnectionStatus()`"
    );
    let not_connected = "__ipeStatus !== \"connected\"";
    let setter = format!("{not_connected}) {{ __ipeSetStatus(\"connected\", \"\");");
    let setters = source.matches(&setter).count();
    let tests = source.matches(not_connected).count();
    assert!(
        tests == setters,
        "{tests} tests of `{not_connected}`, {setters} of them only to set \"connected\"; any other must test `__ipeConnectionStatus()`"
    );
    let beat = body_of(&source, "__ipeLiveBeat");
    assert!(
        beat.contains("status: __ipeConnectionStatus()"),
        "the leader must tell the other tabs its connection state, never its own refusal notice"
    );
    let mirror = body_of(&source, "__ipeLiveMirror");
    assert!(
        mirror.contains("var mine = __ipeConnectionStatus(); if (status === mine) return;")
            && !mirror.contains("__ipeLiveStatuses.indexOf(__ipeStatus)"),
        "a tab mirrors the leader's connection against its own connection state, its refusal notice included"
    );
    assert!(
        source.contains("var __ipeLiveStatuses = [\"connected\", \"reconnecting\", \"offline\"];"),
        "the statuses tabs share are the connection's three; a refusal notice is one tab's own"
    );
}
