//! `ipe fmt` keeps every doc `ipe doc` reads: the module doc and each
//! declaration's doc are the same before and after formatting.

use ipe_docs::stdlib_docs::extract_module_doc;
use ipe_stdlib::{COMPILED_STD_MODULES, DOC_ONLY_MODULES, MODULES};

/// The module doc and every declaration's name and doc, as `ipe doc` reads
/// them from `src`.
fn docs(src: &str) -> (Option<String>, Vec<(String, Option<String>)>) {
    let module = extract_module_doc("Ipe.Fixture", src);
    let exports = module
        .exports
        .into_iter()
        .map(|e| (e.name, e.doc))
        .collect();
    (module.module_doc, exports)
}

/// `src` formatted, failing the test with `what` on a refusal.
#[allow(clippy::expect_used)] // a refusal is the failure this test reports
fn formatted(src: &str, what: &str) -> String {
    ipe_fmt::format_source(src)
        .map_err(|e| e.to_string())
        .expect(what)
}

#[test]
fn every_stdlib_module_keeps_its_docs() {
    let sources = MODULES
        .iter()
        .map(|m| (m.name, m.source))
        .chain(COMPILED_STD_MODULES.iter().map(|m| (m.dotted, m.source)))
        .chain(DOC_ONLY_MODULES.iter().map(|m| (m.dotted, m.source)));
    let mut documented = 0usize;
    for (name, src) in sources {
        let out = formatted(src, name);
        let before = extract_module_doc(name, src);
        let after = extract_module_doc(name, &out);
        assert_eq!(
            before.module_doc, after.module_doc,
            "{name}: module doc changed"
        );
        let doc_of = |m: &ipe_docs::stdlib_docs::ModuleDoc| {
            m.exports
                .iter()
                .map(|e| (e.name.clone(), e.doc.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            doc_of(&before),
            doc_of(&after),
            "{name}: a declaration doc changed"
        );
        documented += before.exports.iter().filter(|e| e.doc.is_some()).count();
    }
    assert!(
        documented >= 100,
        "only {documented} documented declarations were compared"
    );
}

/// Each fixture keeps its docs, and its expected module doc and doc count.
fn keeps(src: &str, module_doc: bool, decl_docs: usize) {
    let before = docs(src);
    let out = formatted(src, src);
    assert_eq!(before, docs(&out), "docs changed:\n{src}\n---\n{out}");
    assert_eq!(before.0.is_some(), module_doc, "module doc:\n{src}");
    let count = before.1.iter().filter(|(_, doc)| doc.is_some()).count();
    assert_eq!(count, decl_docs, "declaration docs:\n{src}");
}

/// A `-- |` comment set apart from its declaration gains no doc.
#[test]
fn a_detached_comment_gains_no_doc() {
    keeps(
        "module M exposing (x)\n\n\n-- | Not a doc.\n\n\nx : Int\nx =\n    1\n",
        false,
        0,
    );
}

/// A doc glued to its declaration, under a detached comment, stays a doc.
#[test]
fn a_glued_doc_is_not_lost() {
    keeps(
        "module M exposing (x)\n\n\n-- note\n\n-- | Doc of x.\nx : Int\nx =\n    1\n",
        false,
        1,
    );
}

/// A section rule above a doc stays apart from it.
#[test]
fn a_section_rule_stays_apart() {
    keeps(
        "module M exposing (x)\n\n\n-- ── Section ──\n\n\n-- | Doc of x.\nx : Int\nx =\n    1\n",
        false,
        1,
    );
}

/// A `-- |` comment moved out of the header becomes no module doc.
#[test]
fn a_hoisted_comment_becomes_no_module_doc() {
    keeps(
        "module M exposing -- | Not a doc.\n    (x)\n\n\nx : Int\nx =\n    1\n",
        false,
        0,
    );
}

/// A comment inside a signature joins no doc above it.
#[test]
fn an_annotation_comment_under_a_doc_keeps_the_doc() {
    keeps(
        "-- | Module doc.\nmodule M exposing (x)\n\n\n-- | Doc of x.\nx : -- ann\n    Int\nx =\n    1\n",
        true,
        1,
    );
}
