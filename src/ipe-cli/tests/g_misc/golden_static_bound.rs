//! A generic-typed callback boxed as `+ 'static`.
//!
//! Without the fix, `ipe dev build` exits 0, but the emitted Rust fails `cargo build` with
//! E0310 ("the parameter type `T1` may not live long enough") at the
//! `Box::new(pair_to_attr)` that a `List.map pairToAttr attrs` call emits. The
//! mapper `pairToAttr` is generic over `msg` (its result is `Attribute msg`), so
//! coercing it to the mapper slot
//! `Box<dyn Fn((String,String)) -> Attribute<msg> + Send + 'static>` requires
//! `msg: 'static`; the emitted `linkNode`/`pairToAttr` functions carried only
//! `<T1: Clone>`.
//!
//! This is EXACTLY the `Ipe.Web.Head.link` shape (the two examples
//! `37-composite-live-shop` / `38-composite-ui-multibackend` that surfaced the
//! bug both import `Ipe.Web.Head`).
//!
//! Fix (`crates/ipe_ir/src/ir.rs` `BoundSet::STATIC` + `crates/ipe_lower`'s
//! `body_boxes_generic_callback`): a generic that flows, inside the body, into a
//! boxed `+ 'static` callback gains the `'static` lifetime bound, rendered by
//! `render_bounds` as the leading `'static` in the bound list
//! (`T1: 'static + Clone`). Every concrete Ipê type is `'static`, so the bound is
//! satisfied by every real caller and never introduces a new failure.
//!
//! Run:
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_i190_static_bound
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("static_bound")
        .join("Main.ipe")
}

/// ipe-0: the compiler must accept the program AND emit the `'static` lifetime
/// bound on the generic that flows into the boxed `+ 'static` mapper callback —
/// checked unconditionally (cheap, no `cargo`), independent of the `IPE_E2E`
/// gate. This is the exact assertion that the E0310 SEAL break cannot recur.
#[test]
fn i190_ipec_accepts_and_bounds_fn_static() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i190_static_bound_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for static_bound: {:?}",
        built.err()
    );

    let emitted = crate::support::read_all_emitted_src(&out);

    // The `link`-shaped function's generic gains the `'static` bound (prepended
    // before the trait bounds) so the boxed generic mapper callback coerces to
    // the `+ 'static` trait object (the E0310 half).
    assert!(
        emitted.contains("main_link_node<T1: 'static + Clone>"),
        "the generic that flows into the boxed `+ 'static` mapper callback must \
         carry the leading `'static` lifetime bound (#190); got emitted user source:\n{emitted}"
    );
    // The boxed mapper slot the bound serves. (Every boxed first-class fn value
    // carries `+ Send + Sync + 'static` so a user callback can forward into the
    // runtime's `Arc<dyn Fn + Send + Sync>` UI slots; the `'static` half
    // propagates onto T1.) rustfmt wraps this `Box<dyn Fn(..) -> .. + Send +
    // Sync + 'static>` bound list across several indented lines once it
    // exceeds the line-width limit, so match on rustfmt-normalized text
    // (`crate::support::normalize_rustfmt_whitespace`) rather than the raw source —
    // same stale-substring class as #269/#191/#195.
    let normalized = crate::support::normalize_rustfmt_whitespace(&emitted);
    assert!(
        normalized.contains(&crate::support::normalize_rustfmt_whitespace(
            "Box<dyn Fn((String, String)) -> ipe_runtime::html::Attribute<T1> + Send + Sync + 'static>"
        )),
        "the mapper callback must box into a `+ Send + Sync + 'static` trait object (#190/#184); got \
         emitted user source:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0: the emitted project actually compiles with `rustc` and
/// renders the `<link>`. Gated on `IPE_E2E=1` — the only check that would have
/// caught the original SEAL violation (E0310, `ipe dev build` clean).
#[test]
fn i190_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_i190_static_bound_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for static_bound: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("static_bound", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "static_bound binary must exit 0 (no E0310); got {:?} (stdout: {:?})",
        outcome.exit_code,
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim(),
        "<link href=\"/favicon.svg\" rel=\"icon\" />",
        "must render the `<link>` through the `msg`-generic `linkNode`; got: {:?}",
        outcome.stdout
    );
}
