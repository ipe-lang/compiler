//! Seal — `List.filterMap` and `List.sortBy` kernel wiring.
//!
//! `filterMap : (a -> Maybe b) -> List a -> List b` — applies a function that
//! returns `Maybe b` to every element, keeps only the `Just` results, and
//! unwraps them. Backed by `list_filter_map` in `src/runtime/rust/src/list.rs`.
//!
//! `sortBy : (a -> comparable) -> List a -> List a` — stable sort by a key
//! projection. Backed by `list_sort_by` (decorate-sort-undecorate, NaN-safe,
//! stable via `Vec::sort_by`).
//!
//! `unique : List a -> List a` — removes duplicates, keeping the first
//! occurrence of each element in first-seen order. Backed by `list_unique`
//! (equality-only, `PartialEq`; no `Ord`/`Hash` obligation).
//!
//! Without a `StdlibKernel` variant for each, any call
//! emits `error[IPE-L0108]: kernel function not available yet`.
//!
//! Gated on `IPE_E2E=1`. Run:
//! `IPE_E2E=1 cargo test -p ipe --test golden_i119_list_batch_seal`

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn compile_golden(name: &str) -> PathBuf {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else {
        return out;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());
    out
}

/// `List.filterMap` — only positive numbers survive, mapped to their string repr.
/// inputs: `[-1, 2, 0, 5, -3, 10]` → `["2", "5", "10"]` → `"2,5,10"`
#[test]
fn filter_map_keeps_just_results() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let dir = compile_golden("filter_map_seal");
    let out = crate::support::build_and_run_emitted("filter_map_seal", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "must exit 0; got {:?}",
        out.exit_code
    );
    assert!(
        out.stdout.contains("2,5,10"),
        "filterMap must keep only positive numbers; got: {:?}",
        out.stdout,
    );
}

/// `List.sortBy` — stable sort by `.age`; ties preserve insertion order.
/// [Charlie/30, Alice/25, Bob/25] → [Alice/25, Bob/25, Charlie/30] → "Alice,Bob,Charlie"
#[test]
fn sort_by_stable_by_age() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let dir = compile_golden("sort_by_seal");
    let out = crate::support::build_and_run_emitted("sort_by_seal", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "must exit 0; got {:?}",
        out.exit_code
    );
    assert!(
        out.stdout.contains("Alice,Bob,Charlie"),
        "sortBy must produce stable ascending sort by age; got: {:?}",
        out.stdout,
    );
}

/// `List.unique` — duplicates dropped, first occurrence kept in first-seen order.
/// `[3,1,3,2,1,3,2]` yields `[3,1,2]`; `["a","b","a","c","b"]` yields `["a","b","c"]`.
#[test]
fn unique_keeps_first_occurrence_order() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let dir = compile_golden("unique_seal");
    let out = crate::support::build_and_run_emitted("unique_seal", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "must exit 0; got {:?}",
        out.exit_code
    );
    assert!(
        out.stdout.contains("3,1,2 a,b,c"),
        "unique must drop duplicates keeping first-seen order; got: {:?}",
        out.stdout,
    );
}
