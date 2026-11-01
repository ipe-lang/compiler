//! Startup-fact single-emitter scan.
//!
//! P6 ("one emitter per startup fact"): the "session store: ..." line is
//! written only by `web::store::choose_store`'s one call to
//! `emit_memory_store_log` for the memory case, and the "listening on ..."
//! line is written only by `server.rs`'s `bind_app_listener`/`startup_lines`.
//! A second writer of either fact drifts from whichever store or listener a
//! caller actually chose — exactly the bug this scan guards against
//! reappearing: `web/mod.rs` once re-logged "listening" beside the real
//! line, and re-logged "session store: memory" at its inline console mount
//! even when a durable store had been picked.
//!
//! `emit_memory_store_log` is module-private to `store.rs` (the compile-time
//! half of this guard, enforced by `rustc` itself); this is the runtime
//! half, over plain source text via the shared [`rust_sources`] walk — a
//! substring/window scan, not a real parser, is enough to catch a second
//! call site or a hand-rolled re-log of either fact.
#![cfg(not(target_arch = "wasm32"))]

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

/// The one file allowed to call `emit_memory_store_log(`.
const MEMORY_LOG_CALLER: &str = "web/store.rs";

/// The one file allowed to log a "listening" fact through
/// `emit_runtime_log`/`_stamped`/`_stdout`.
const LISTENING_EMITTER_FILE: &str = "server.rs";

/// Count of `emit_memory_store_log(` call sites in `content`, excluding its
/// own `fn emit_memory_store_log(` signature line.
fn count_memory_store_log_calls(content: &str) -> usize {
    content.matches("emit_memory_store_log(").count()
        - content.matches("fn emit_memory_store_log(").count()
}

/// True when a `"listening"` literal appears within a short window after an
/// `emit_runtime_log`/`emit_runtime_log_stamped`/`emit_runtime_log_stdout`
/// call in `content` — the shape of the startup "listening on ..." line this
/// scan guards against a second site re-introducing outside `server.rs`'s
/// `startup_lines`/`bind_app_listener`.
fn has_listening_emitter_call(content: &str) -> bool {
    for marker in [
        "emit_runtime_log(",
        "emit_runtime_log_stamped(",
        "emit_runtime_log_stdout(",
    ] {
        let mut rest = content;
        while let Some(rel) = rest.find(marker) {
            let tail = rest.get(rel..).unwrap_or_default();
            let window_end = tail.char_indices().nth(400).map_or(tail.len(), |(i, _)| i);
            if tail
                .get(..window_end)
                .unwrap_or_default()
                .contains("listening")
            {
                return true;
            }
            rest = tail.get(marker.len()..).unwrap_or_default();
        }
    }
    false
}

#[test]
fn startup_fact_single_emitter() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = rust_sources(&root);
    assert!(
        sources.len() > 10,
        "sanity: expected to scan more than 10 files under {}, found {}",
        root.display(),
        sources.len()
    );

    let mut memory_log_call_sites = Vec::new();
    let mut stray_listening_emitters = Vec::new();
    for (name, content) in &sources {
        let calls = count_memory_store_log_calls(content);
        if calls > 0 {
            memory_log_call_sites.push((name.clone(), calls));
        }
        if name != LISTENING_EMITTER_FILE && has_listening_emitter_call(content) {
            stray_listening_emitters.push(name.clone());
        }
    }

    assert_eq!(
        memory_log_call_sites,
        vec![(MEMORY_LOG_CALLER.to_owned(), 1)],
        "emit_memory_store_log must have exactly one caller, inside \
         {MEMORY_LOG_CALLER}'s choose_store — a new call site duplicates the \
         memory-store startup log instead of routing through the one real \
         selector:\n{memory_log_call_sites:?}"
    );
    assert!(
        stray_listening_emitters.is_empty(),
        "found an `emit_runtime_log`/`_stamped`/`_stdout` call logging \
         \"listening\" outside {LISTENING_EMITTER_FILE}'s `startup_lines` — \
         route through `bind_app_listener` instead of re-logging the \
         listening address:\n{}",
        stray_listening_emitters.join("\n")
    );
}
