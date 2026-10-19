//! A `Ipe.Db.Store.Cond` built in a nested (composed) position lowers to its
//! emitted enum instead of reaching the lowerer as an unhomed type constructor.
//!
//! `Store.eq` returns a `Cond row`; its kernel scheme carries the real
//! `Ipe.Db.Store` home so the lowerer's home-keyed variant lookup finds the
//! emitted `Cond` enum. Referenced in a lambda passed to `List.map` — the
//! nested composition shape — the result type annotation `List (Store.Cond User)`
//! lowers to `List Cond`. Before the home was carried, the unqualified `Cond`
//! missed every home-keyed guard and fell through to the empty-home
//! internal-compiler-error arm (IPE-I0001).

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn fixture_entry(root: &Path, golden: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(golden)
        .join("src")
        .join("Main.ipe")
}

/// A composed `Store.Cond` lowers to its emitted enum — no empty-home ICE.
#[test]
fn cond_in_composed_position_lowers_to_its_enum() {
    const GOLDEN: &str = "db_store_cond_composed_lowers";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);

    let lowered = ipe::emit_ir_text(&entry);
    let ir = lowered.as_deref().unwrap_or("");
    // The emitted enum and its leaf construction are present — proof the `Cond`
    // lowered through the home-keyed enum path, not the empty-home ICE arm. An
    // empty `ir` (a lowering rejection) fails both assertions with the message.
    assert!(
        ir.contains("type Cond ="),
        "a composed `Store.Cond` must lower (its kernel scheme carries the real \
         `Ipe.Db.Store` home so the lowerer finds the emitted enum); the emitted \
         `Cond` enum must appear in the lowered IR, got: {lowered:?}"
    );
    assert!(
        ir.contains("Ctor Cond.Compare"),
        "the composed `Store.eq` must lower to a `Cond.Compare` construction, \
         got: {lowered:?}"
    );
}
