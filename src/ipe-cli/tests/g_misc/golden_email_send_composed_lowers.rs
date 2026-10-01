//! A point-free reference to `Ipe.Email.send` lowers to its emitted enum
//! instead of reaching the lowerer as an unhomed type constructor.
//!
//! `send` takes an `EmailProvider` as its first parameter; the kernel scheme
//! carries the real `Ipe.Email` home so the lowerer's home-keyed variant
//! lookup finds the runtime-backed enum. Aliased unannotated (`dispatch =
//! Email.send`) and kept live in a list, the inferred `EmailProvider` reaches
//! lowering with no annotation to home it. Before the home was carried, that
//! unqualified `EmailProvider` missed every home-keyed guard and fell through
//! to the empty-home internal-compiler-error arm (IPE-I0001).

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("email_send_composed_lowers")
        .join("Main.ipe")
}

/// A point-free `Email.send` lowers — no empty-home ICE.
#[test]
fn point_free_email_send_lowers_to_its_enum() {
    let entry = fixture_entry(&repo_root());

    let lowered = ipe::emit_ir_text(&entry);
    let ir = lowered.as_deref().unwrap_or("");
    // The aliased kernel value and its `EmailProvider` parameter type are
    // present in the lowered IR — proof the type lowered through the home-keyed
    // path, not the empty-home ICE arm. An empty `ir` (a lowering rejection)
    // fails both assertions with the message.
    assert!(
        ir.contains("FuncValue kernel Email.send"),
        "a point-free `Email.send` must lower to a first-class kernel value; \
         the emitted `FuncValue kernel Email.send` must appear in the lowered \
         IR, got: {lowered:?}"
    );
    assert!(
        ir.contains("EmailProvider"),
        "the lowered `send` value must carry its `EmailProvider` parameter type \
         (its kernel scheme homes the constructor at `Ipe.Email`), got: \
         {lowered:?}"
    );
}
