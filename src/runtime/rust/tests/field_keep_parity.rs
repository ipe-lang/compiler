//! `client.js` keeps form fields by the same tables `dom/keep.rs` declares.
//!
//! The browser client decides which live field survives a swap, and which
//! server attribute write a field the user is editing refuses, from three
//! tables: the field tags, the authority attributes, and the controlled
//! marker. Each is declared once in `dom::keep` and once in `client.js`; these
//! checks render the Rust tables as the JS declarations and require exactly
//! that declaration in the client, so a tag or attribute added on one side
//! alone fails here. The client's own spelled-out copies of the tables are
//! refused, so every client decision reads the declared table.
#![cfg(not(target_arch = "wasm32"))]

use ipe_runtime_rust::dom::keep::{AUTHORITY_ATTRS, CONTROLLED_ATTR, FIELD_TAGS};

/// The browser client source the runtime serves.
const CLIENT_JS: &str = include_str!("../src/web/client.js");

/// The JS declaration `var NAME = ["a", "b"];` of a string list.
fn list_decl(name: &str, items: &[&str]) -> String {
    let quoted: Vec<String> = items.iter().map(|item| format!("\"{item}\"")).collect();
    format!("var {name} = [{}];", quoted.join(", "))
}

/// Exactly one line of the client is `decl`, and no other line declares `name`.
fn assert_declared_once(name: &str, decl: &str) {
    let head = format!("var {name} =");
    let declared: Vec<&str> = CLIENT_JS
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(&head))
        .collect();
    assert_eq!(declared, vec![decl], "client.js must declare `{decl}`");
}

/// The client's field tags are `dom::keep::FIELD_TAGS`, in order.
#[test]
fn client_field_tags_match_the_runtime() {
    assert_declared_once(
        "__IPE_FIELD_TAGS",
        &list_decl("__IPE_FIELD_TAGS", &FIELD_TAGS),
    );
}

/// The client's authority attributes are `dom::keep::AUTHORITY_ATTRS`, in order.
#[test]
fn client_authority_attrs_match_the_runtime() {
    assert_declared_once(
        "__IPE_AUTHORITY_ATTRS",
        &list_decl("__IPE_AUTHORITY_ATTRS", &AUTHORITY_ATTRS),
    );
}

/// The client's controlled marker is `dom::keep::CONTROLLED_ATTR`.
#[test]
fn client_controlled_marker_matches_the_runtime() {
    assert_declared_once(
        "__IPE_CONTROLLED_ATTR",
        &format!("var __IPE_CONTROLLED_ATTR = \"{CONTROLLED_ATTR}\";"),
    );
}

/// No client decision spells a table out instead of reading it.
#[test]
fn client_spells_no_table_out() {
    for spelled in [
        "\"input, textarea, select\"",
        "n === \"value\"",
        "k === \"value\" || k === \"checked\"",
        "hasAttribute(\"value\")",
        "hasAttribute(\"checked\")",
        "hasAttribute(\"selected\")",
        "tag === \"INPUT\" || tag === \"TEXTAREA\"",
        "focusTag === \"INPUT\"",
    ] {
        assert!(
            !CLIENT_JS.contains(spelled),
            "client.js spells `{spelled}` instead of reading the declared table"
        );
    }
}
