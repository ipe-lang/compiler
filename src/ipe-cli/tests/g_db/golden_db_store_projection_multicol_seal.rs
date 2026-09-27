//! End-to-end SEAL for the typed multi-column projection over a two-store inner
//! join (`Store.join` / `Store.select` / `Store.selectToList`). Two
//! `Codec.auto`-derived stores join on `books.author_id = authors.id`; `select`
//! projects TWO columns as a flat tuple of references
//! (`( book.title, author.name )`), so the join lowers to ONE parameterized
//! statement that selects exactly those two columns
//! (`SELECT a0.title AS p0, a1.name AS p1 FROM …`, column pushdown) over the
//! two-table `FROM`. Each projected row comes back as a `Row` keyed by the output
//! names `p0` / `p1`, decoded caller-side by position; every projected identifier
//! is re-validated at the runtime boundary, and no filter value is interpolated.
//!
//! The decode is concrete/monomorphized: the projection value carries only an
//! ordered `(tag, operand_a, operand_b)` list (a plain `Vec<(String, String, String)>`), never a
//! boxed decoder — the caller reads each `p<index>` cell with its own typed
//! `projRead*`. So the multi-column path introduces no `Box<dyn Fn …>` decoder.
//!
//! THE SEAL: `ipe` accepting the projected program (exit 0) must imply a
//! buildable emitted crate. Under `IPE_E2E=1` the emitted crate must
//! `cargo build` (no live database or network is needed — the projection is
//! assembled, never executed).

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "db_store_projection_multicol_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate: the frontend must accept the multi-column `Store.select` /
/// `Store.selectToList` program (the tuple projection lowers to the ordered
/// `(alias, column)` list, and the `Db.findProjection` kernel schemes, lowers,
/// and emits).
#[test]
fn db_store_projection_multicol_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_projection_multicol_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // resolver unavailable — skip
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a `Store.select` multi-column projection run through `selectToList` \
         must be accepted and emitted, got: {built:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate — the
/// multi-column `SELECT a0.title AS p0, a1.name AS p1` projection over the
/// two-table `FROM` and the positional `p0` / `p1` row decode must all compile.
/// The emitted projection value carries a plain `(alias, column)` list and no
/// boxed decoder, so no `dyn`-decoder obligation ever reaches the emitter.
#[test]
fn db_store_projection_multicol_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_projection_multicol_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);

    // Witness the concrete/monomorphized decode. The projection value the emitted
    // program builds carries the ordered `(alias, column)` list as plain data and
    // NO boxed decoder field, and the projection lowers to the `selectNamed` data
    // constructor with both columns named literally — the decode is caller-side by
    // position (`projRead*`), never a stored `dyn Fn`. (Codec machinery elsewhere
    // in the crate legitimately uses `dyn Fn`; this claim is scoped to the
    // projection's own value and decode.)
    let main_mod = out.join("src").join("ipe_mods").join("ipe_mod_main.rs");
    let module_src = std::fs::read_to_string(&main_mod).expect("emitted main module must exist");
    assert!(
        module_src.contains("\"title\".to_string()") && module_src.contains("\"name\".to_string()"),
        "the emitted projection must name both projected columns as plain data"
    );
    assert!(
        module_src.contains("user_ipe_db_store_select_named"),
        "the projection must lower to the `selectNamed` data constructor"
    );

    // The `Select` projection record struct: its `projections` field is a
    // `Vec<MainProjectionTerm>` (the typed builtin ADT, not the old string
    // triple) and the struct declares no boxed-decoder field.
    let main_rs = out.join("src").join("main.rs");
    let main_src = std::fs::read_to_string(&main_rs).expect("emitted main.rs must exist");
    let struct_body = projection_record_struct_body(&main_src)
        .expect("emitted crate must define the projection record struct");
    assert!(
        struct_body.contains("projections: Vec<MainProjectionTerm>"),
        "the projection record must carry the ordered column list as plain data, \
         got struct body:\n{struct_body}"
    );
    assert!(
        !struct_body.contains("dyn Fn") && !struct_body.contains("Box<dyn"),
        "the projection record must carry NO boxed decoder field — the decode is \
         concrete/monomorphized and caller-side, got struct body:\n{struct_body}"
    );
}

/// Extract the body (between the first `{` and its matching `}`) of the emitted
/// `Select` projection record struct. The generated name encodes all field names
/// alphabetically; the marker used here matches the current field set
/// (`extraBinds`, `frag`, `joinedA`, `joinedB`, `leftTable`, `order`, `poison`,
/// `projections`, `rightTable`). Returns `None` if the struct is absent.
fn projection_record_struct_body(src: &str) -> Option<&str> {
    let marker = "struct RecExtraBindsFragJoinedAJoinedBLeftTableOrderPoisonProjectionsRightTable";
    let start = src.find(marker)?;
    let open = src[start..].find('{')? + start;
    let close = src[open..].find('}')? + open;
    Some(&src[open..=close])
}
