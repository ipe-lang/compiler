//! CONS of an Arc-promoted fn value — the head must ride the same `Arc` carrier
//! as the flipped list-element type and the empty-tail turbofish.
//!
//! `g` is Arc-promoted (moved into `List.map`, then called), so its list-element
//! carrier flips to `Arc<dyn Fn>` (`SharedFun`). Consing `g` onto a list
//! (`g :: []`) emits `ipe_list_cons(HEAD, Vec::<Arc<dyn Fn…>>::new())`. The head
//! fn-value read was shimmed on the default `Box` carrier while the empty-tail
//! turbofish was `Arc` — mismatched carriers into `ipe_list_cons<T>(x: T, xs:
//! Vec<T>)` (E0308), an emitter failure disclosed as IPE-I0001. The storage-aware
//! fn-value shim mints the head on the `Arc` carrier so head and tail agree.
//!
//! `(42 + 1) + (2 + 3 + 4) + 1` = `53`.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const NAME: &str = "i984_cons_fn_value_arc_carrier";

/// A fn value directly in a built-in `Maybe`/`Result` payload keeps the `Box`
/// carrier its runtime enum consumes — the storage-element `Arc` flip that
/// covers user-ADT payloads must NOT reach it, or the same carrier mismatch
/// re-opens in the opposite direction (a `Box`-consuming `ipe_maybe_map` fed an
/// `Arc` shim).
const NAME_MAYBE: &str = "i984_maybe_payload_box_carrier";

fn entry_of(root: &Path, name: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

fn assert_byte_identical(name: &str) {
    let root = repo_root();
    let entry = entry_of(&root, name);
    let golden = root.join("tests").join("golden").join(name).join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve: {:?}", runtime.err());
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// The cons head and the empty-tail turbofish must both be on the `Arc` carrier —
/// no `Box`-carried fn value may sit in the same `ipe_list_cons` element position.
fn assert_cons_head_arc_carrier(name: &str) {
    let root = repo_root();
    let golden = root.join("tests").join("golden").join(name).join("main.rs");
    let read = std::fs::read_to_string(&golden);
    assert!(read.is_ok(), "golden main.rs readable: {:?}", read.err());
    let Ok(src) = read else { return };

    // Locate the `ipe_list_cons(` call that constructs `gs` and split it at the
    // empty-tail turbofish, so `head` is exactly the cons head fn-value.
    let cons = src
        .find("let gs = ipe_runtime::list::ipe_list_cons(")
        .map(|at| &src[at..]);
    assert!(cons.is_some(), "gs cons call present in golden");
    let Some(cons_slice) = cons else { return };
    // The empty-tail turbofish anchors the element type to `Arc`.
    assert!(
        cons_slice.contains("Vec::<::std::sync::Arc<dyn Fn(i64) -> i64"),
        "cons empty tail must be an Arc-element Vec turbofish"
    );
    let head = cons_slice.find("Vec::<").map(|at| &cons_slice[..at]);
    assert!(head.is_some(), "turbofish follows the head");
    let Some(head) = head else { return };
    // The head fn-value read is minted on the Arc carrier, not Box.
    assert!(
        head.contains("::std::sync::Arc<") && head.contains("::std::sync::Arc::new("),
        "cons head fn-value must ride the Arc carrier"
    );
    assert!(
        !head.contains("Box<dyn Fn(i64) -> i64"),
        "cons head fn-value must not ride the Box carrier"
    );
}

fn assert_e2e_prints(name: &str, want_stdout: &str) {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let root = repo_root();
    let entry = entry_of(&root, name);
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.stdout, want_stdout,
        "cons of an Arc-promoted fn builds and prints its value"
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0 (THE SEAL)");
}

#[test]
fn cons_fn_value_emits_byte_identical_main_rs() {
    assert_byte_identical(NAME);
}

#[test]
fn cons_head_and_tail_share_the_arc_carrier() {
    assert_cons_head_arc_carrier(NAME);
}

#[test]
fn cons_fn_value_end_to_end() {
    assert_e2e_prints(NAME, "53\n");
}

/// The `Just g` payload must ride the `Box` carrier `ipe_maybe_map` consumes —
/// no `Arc` fn shim may sit in a built-in `Maybe`/`Result` payload position.
fn assert_maybe_payload_box_carrier(name: &str) {
    let root = repo_root();
    let golden = root.join("tests").join("golden").join(name).join("main.rs");
    let read = std::fs::read_to_string(&golden);
    assert!(read.is_ok(), "golden main.rs readable: {:?}", read.err());
    let Ok(src) = read else { return };
    // The Arc-promoted binding is still emitted `Arc::new` at its own site, but
    // its `Just` payload read must be the plain boxed `Box<dyn Fn…>` carrier the
    // maybe-map kernel expects — the storage flip must not reach a built-in
    // payload.
    assert!(
        src.contains("Box<dyn Fn(i64) -> i64"),
        "the Maybe payload fn-value must ride the Box carrier"
    );
}

#[test]
fn maybe_payload_keeps_box_carrier() {
    assert_maybe_payload_box_carrier(NAME_MAYBE);
}

#[test]
fn maybe_payload_emits_byte_identical_main_rs() {
    assert_byte_identical(NAME_MAYBE);
}

#[test]
fn maybe_payload_end_to_end() {
    assert_e2e_prints(NAME_MAYBE, "153\n");
}
