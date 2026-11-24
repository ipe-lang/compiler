//! The Tier-2 link-reachability probe emitter.
//!
//! Tier-2 admission ([`crate::audit_native`] in `ipe-cli`, ADR 0004) must build
//! and link a native-bearing package's OWN foreign surface under a jail scoped
//! to its declared capability set, so a build-time capability reach (a
//! `build.rs`, proc-macro, linker script, or `bindgen` fetch inside a bound
//! crate) is observed as a denial. Linking alone under-observes: the linker
//! dead-strips any wrapper nothing references, taking that wrapper's transitive
//! foreign call — and its build-time reach — with it.
//!
//! This module emits a probe `main` that REFERENCES every surviving wrapper so
//! the linker must retain the whole foreign surface. The reference is an
//! address-of into an opaque sink ([`std::hint::black_box`]); the probe NEVER
//! invokes a wrapper with fabricated inputs — that would run unbounded author
//! logic and cannot synthesise a valid opaque receiver anyway. What is confined
//! is the *build and link* of the package's real surface, never a stand-in whose
//! actions Tier-2 chose.
//!
//! ## Single source of the exercised surface
//!
//! The probe references exactly the wrappers the app crate actually emitted into
//! `src/ffi.rs` — the DCE-trimmed foreign surface the artifact ships. The caller
//! (`audit_native`) reads that emitted set and passes it to [`emit_probe_main`],
//! so the probe's surface is the shipped surface by construction: never wider (a
//! phantom reference would fail to link) and never narrower (an omitted wrapper
//! would let its build-time reach go un-exercised). The package cannot author a
//! narrower probe — it does not write the probe at all.
//!
//! [`surviving_wrapper_paths`] maps the binding-DCE survivor set through the SAME
//! [`crate::naming::wrapper_fn_ident`] the emitter names its `pub fn`s with; it is
//! the reference computation of a bound crate's full wrapper path set, kept for
//! callers that need the untrimmed surface.

use crate::pkginfo::PkgInfo;

/// The fully-qualified path of every surviving wrapper `pub fn` for one bound
/// crate, in the emitted app crate's module tree.
///
/// Each emitted `_bindings.rs` becomes `pub mod <slug> { … }` under the app
/// crate's `crate::ffi`, so a wrapper `pub fn <ident>` is reachable at
/// `crate::ffi::<slug>::<ident>`. The `<ident>` is derived by the SAME
/// [`crate::naming::wrapper_fn_ident`] the emitter uses, keyed off the SAME
/// [`crate::bindings::surviving_ref_names`] survivor set — so this set is
/// exactly the emitted `pub fn` set, never wider (a phantom reference would fail
/// to link) and never narrower (an omitted wrapper would let its build-time
/// reach go un-exercised).
///
/// Returned sorted and deduplicated for a deterministic probe.
#[must_use]
pub fn surviving_wrapper_paths(pkg: &PkgInfo, slug: &str) -> Vec<String> {
    let kernel = crate::naming::rust_kernel_name(pkg.pkg_path());
    let mut paths: Vec<String> = crate::bindings::surviving_ref_names(pkg)
        .iter()
        .map(|ref_name| {
            let ident = crate::naming::wrapper_fn_ident(&kernel, ref_name);
            format!("crate::ffi::{slug}::{ident}")
        })
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

/// Emit the probe `main.rs` that references every wrapper in `wrapper_paths` so
/// the linker retains the whole foreign surface.
///
/// `main` takes each wrapper's address at runtime and feeds the array to
/// [`std::hint::black_box`]. Taking a function's address forces the compiler to
/// codegen and the linker to keep that function (and its transitive foreign
/// call), and `black_box` bars the optimiser from proving the value unused, so
/// each wrapper's bound crate is genuinely built and linked. The address-taking
/// is in `main` (runtime), not a `static` initialiser: a function pointer cannot
/// be cast to an integer during const evaluation, and a raw-pointer `static` is
/// not `Sync` without an `unsafe impl` the probe must not carry. The probe still
/// NEVER invokes a wrapper: taking an address runs no author logic, so the only
/// observable capability demand is whatever *building and linking* the referenced
/// surface demands.
///
/// `crate_prelude` is emitted at the probe crate root right after the inner
/// attributes and before the `mod ffi;` items the caller appends around this
/// output — the probe bin is its own crate root, so it does not inherit the app
/// `main.rs`'s crate-root runtime prelude, yet the shared `src/ffi.rs` names
/// runtime items unqualified through `use crate::*;`. Emitting the prelude here
/// keeps the whole probe crate-root shape (inner attributes first, then prelude,
/// then items) owned by one emitter, so an item can never precede an inner
/// attribute. Pass an empty string for no prelude.
///
/// `wrapper_paths` MUST be non-empty; an empty surface is un-exercisable and the
/// caller rejects it (fail-closed) rather than emit a vacuous probe that would
/// link clean without exercising anything.
///
#[must_use]
pub fn emit_probe_main(wrapper_paths: &[String], crate_prelude: &str) -> String {
    use std::fmt::Write as _;
    // The caller rejects an empty survivor set, so `wrapper_paths` is non-empty
    // here; an empty slice would merely emit a probe that references nothing.
    let count = wrapper_paths.len();
    let mut out = String::new();
    out.push_str(
        "// Code generated by the Tier-2 link-reachability probe emitter. DO NOT EDIT.\n\
         //\n\
         // References — never invokes — every surviving FFI wrapper so the linker\n\
         // retains the package's whole foreign surface under the declared-scoped jail.\n\
         #![allow(unused_imports)]\n\n",
    );
    // The crate-root prelude (the app `main.rs`'s runtime re-exports, or the
    // `mod ffi;` declaration) sits after the inner attributes so no item precedes
    // them, and before the `main` that references the wrappers.
    if !crate_prelude.is_empty() {
        out.push_str(crate_prelude);
        if !crate_prelude.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
    }
    // Each wrapper's address is taken at RUNTIME inside `main` and fed to
    // [`std::hint::black_box`]. Taking a function's address forces the compiler to
    // codegen and the linker to keep that function (and its transitive foreign
    // call), and `black_box` bars the optimiser from proving the value unused and
    // stripping it — so every wrapper's bound crate is genuinely built and linked.
    // The cast lives in `main`, not a `static` initialiser: a function pointer
    // cannot be cast to an integer during const evaluation, and a `static` holding
    // a raw pointer is not `Sync` without an `unsafe impl` the probe must not
    // carry — so the retention is expressed as runtime address-taking, the one
    // form that is both sound and free of `unsafe`. The probe still NEVER invokes
    // a wrapper: taking an address runs no author logic, so the only observable
    // capability demand is whatever building and linking the surface demands.
    // Writing into a String is infallible.
    let _ = writeln!(out, "fn main() {{");
    let _ = writeln!(out, "    let keep: [*const (); {count}] = [");
    for path in wrapper_paths {
        out.push_str("        ");
        out.push_str(path);
        out.push_str(" as *const (),\n");
    }
    out.push_str("    ];\n    std::hint::black_box(&keep);\n}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // The fixture builders move a `serde_json::Value` into the `json!` macro; the
    // by-value take is the natural shape for a test factory.
    #[allow(clippy::needless_pass_by_value)]
    fn pkg_with(name: &str, fns: serde_json::Value) -> PkgInfo {
        PkgInfo::decode_json(
            &json!({
                "pkg": name,
                "name": name,
                "version": "1.0.0",
                "functions": fns,
                "errors": []
            })
            .to_string(),
        )
        .expect("decodes")
    }

    #[test]
    fn probe_references_every_surviving_wrapper_by_address_never_invokes() {
        // A plain fallible fn survives DCE and emits a `pub fn`; the probe must
        // reference it by address-of, not call it.
        let pkg = pkg_with(
            "semver",
            json!([{
                "name": "parse",
                "params": [{"name": "text", "type": "String", "ipeType": "String", "rustType": "&str"}],
                "results": [{"name": "", "type": "Result Error Version", "rustType": "Result<Version, Error>"}],
                "effect": "fallible"
            }]),
        );
        let paths = surviving_wrapper_paths(&pkg, "semver");
        assert!(!paths.is_empty(), "the fn survives DCE");
        assert!(
            paths.iter().all(|p| p.starts_with("crate::ffi::semver::")),
            "every path is app-crate-absolute under the slug's module: {paths:?}"
        );
        let src = emit_probe_main(
            &paths,
            &format!("{}\nmod ffi;", ipe_intern::ffi_crate_scope()),
        );
        // Address-of into a black-box sink — never an invocation (no `(` after a
        // path that would be a call).
        for p in &paths {
            assert!(
                src.contains(&format!("{p} as *const ()")),
                "the probe references `{p}` by address:\n{src}"
            );
            assert!(
                !src.contains(&format!("{p}(")),
                "the probe must NOT invoke `{p}`:\n{src}"
            );
        }
        assert!(
            src.contains("std::hint::black_box(&keep)"),
            "the probe feeds the address array to black_box:\n{src}"
        );
        assert!(src.contains("fn main()"), "{src}");
    }

    #[test]
    fn the_crate_prelude_precedes_every_item_and_follows_the_inner_attribute() {
        // The probe bin is its own crate root: the runtime re-exports the shared
        // `src/ffi.rs` names through `use crate::*;` must land at the crate root,
        // AFTER the inner `#![allow(unused_imports)]` (an item before an inner
        // attribute is a hard rustc error) and BEFORE `main`.
        let paths = vec!["crate::ffi::semver::semver_parse".to_owned()];
        let prelude = format!("{}\nmod ffi;", ipe_intern::ffi_crate_scope());
        let src = emit_probe_main(&paths, &prelude);
        let attr = src
            .find("#![allow(unused_imports)]")
            .expect("inner attribute");
        let prelude_at = src
            .find(ipe_intern::RUNTIME_GLOB_ITEM)
            .expect("prelude present");
        let main_at = src.find("fn main()").expect("probe main");
        assert!(
            attr < prelude_at && prelude_at < main_at,
            "inner attribute, then the crate prelude, then the items:\n{src}"
        );
    }

    #[test]
    fn an_empty_crate_prelude_emits_no_prelude_lines() {
        let paths = vec!["crate::ffi::semver::semver_parse".to_owned()];
        let src = emit_probe_main(&paths, "");
        assert!(
            !src.contains("pub use ipe_runtime"),
            "an empty prelude emits nothing extra:\n{src}"
        );
        assert!(src.contains("fn main()"), "{src}");
    }

    #[test]
    fn wrapper_paths_are_the_surviving_ref_names_mapped_through_the_emitter_ident() {
        // Single source of truth: the path set is exactly the survivor set mapped
        // through the SAME wrapper_fn_ident the emitter uses — it cannot drift.
        let pkg = pkg_with(
            "semver",
            json!([{
                "name": "parse",
                "params": [{"name": "text", "type": "String", "ipeType": "String", "rustType": "&str"}],
                "results": [{"name": "", "type": "Result Error Version", "rustType": "Result<Version, Error>"}],
                "effect": "fallible"
            }]),
        );
        let kernel = crate::naming::rust_kernel_name(pkg.pkg_path());
        let expected: Vec<String> = crate::bindings::surviving_ref_names(&pkg)
            .iter()
            .map(|r| {
                format!(
                    "crate::ffi::semver::{}",
                    crate::naming::wrapper_fn_ident(&kernel, r)
                )
            })
            .collect();
        let mut expected_sorted = expected;
        expected_sorted.sort();
        assert_eq!(surviving_wrapper_paths(&pkg, "semver"), expected_sorted);
    }

    #[test]
    fn an_empty_surface_yields_no_paths() {
        // A package whose every fn drops out of DCE has no probeable surface; the
        // path set is empty and the caller rejects (never emits a vacuous probe).
        let pkg = pkg_with("empty", json!([]));
        assert!(surviving_wrapper_paths(&pkg, "empty").is_empty());
    }

    #[test]
    fn the_probe_output_is_deterministic_and_sorted() {
        // Two fns emitted in either inspection order produce the SAME sorted probe
        // — a certify/reject verdict must be reproducible (design §5).
        let a = pkg_with(
            "multi",
            json!([
                {"name": "beta", "params": [], "results": [{"name": "", "type": "u64", "rustType": "u64"}], "effect": "pure"},
                {"name": "alpha", "params": [], "results": [{"name": "", "type": "u64", "rustType": "u64"}], "effect": "pure"}
            ]),
        );
        let b = pkg_with(
            "multi",
            json!([
                {"name": "alpha", "params": [], "results": [{"name": "", "type": "u64", "rustType": "u64"}], "effect": "pure"},
                {"name": "beta", "params": [], "results": [{"name": "", "type": "u64", "rustType": "u64"}], "effect": "pure"}
            ]),
        );
        assert_eq!(
            surviving_wrapper_paths(&a, "multi"),
            surviving_wrapper_paths(&b, "multi")
        );
    }
}
