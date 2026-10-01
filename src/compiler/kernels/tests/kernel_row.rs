//! Kernel-row invariants: the [`KernelDef`] descriptor must agree with the
//! authoritative per-variant methods it projects, and every kernel whose emitted
//! symbol lives in a declared runtime module must have that symbol actually
//! defined in the vendored runtime source.
//!
//! The second test is the fast pre-cargo tripwire for the exit-0-then-cargo-fail
//! class: a kernel that declares a `runtime_module` but whose `runtime_fn` names
//! no `pub` symbol in that module would let `ipe` accept a program whose emitted
//! crate then fails `cargo build` (E0425/E0412). This scan catches that in the
//! normal test path, before any downstream build.

use std::path::PathBuf;

use ipe_kernels::{RuntimeModule, StdlibKernel};

/// `def()` is a pure projection: every field must equal what the authoritative
/// method it delegates to returns.
#[test]
fn def_projects_the_authoritative_methods() {
    for &k in StdlibKernel::ALL {
        let def = k.def();
        let decl = k.decl();
        assert_eq!(def.qualifier, decl.qualifier, "qualifier drift for {k:?}");
        assert_eq!(def.name, decl.name, "name drift for {k:?}");
        assert_eq!(def.arity, decl.arity, "arity drift for {k:?}");
        assert_eq!(def.class, decl.class, "class drift for {k:?}");
        assert_eq!(def.runtime_fn, decl.emit, "runtime_fn drift for {k:?}");
        assert_eq!(
            def.runtime_module,
            k.required_runtime_module(),
            "runtime_module drift for {k:?}"
        );
        assert_eq!(def.scheme.0, k, "scheme key must point back at the variant");
    }
}

/// The vendored runtime source root, relative to this crate's manifest.
fn runtime_src_root() -> PathBuf {
    e2e_support::manifest_dir!().join("../../runtime/rust/src")
}

/// The set of source files that make up a conditionally-vendored
/// [`RuntimeModule`]. A `runtime_fn` declared to live in that module must be a
/// `pub` symbol defined in one of these files.
///
/// `Web` is the `web` feature-module (`web/*`, including `web::pubsub`).
/// `Server` is the server feature-module set (`server` + `server_stream` +
/// `http_stream`). `Cache` is the `cache` feature-module (`cache.rs`). `Random`
/// is the `random` feature-module (`random.rs`).
fn module_source_files(module: RuntimeModule) -> Vec<PathBuf> {
    let root = runtime_src_root();
    let rel: &[&str] = match module {
        RuntimeModule::Web => &["web/pubsub.rs", "web/mod.rs"],
        RuntimeModule::Server => &["server.rs", "server_stream.rs", "http_stream.rs"],
        RuntimeModule::Cache => &["cache.rs"],
        RuntimeModule::Random => &["random.rs"],
    };
    rel.iter().map(|r| root.join(r)).collect()
}

/// Whether `src` defines a bare-`pub` item named `symbol` (fn, struct, enum,
/// const, static, type alias, or trait). A source-symbol scan, not a build.
///
/// Only `pub` without a visibility restriction qualifies — `pub(crate)`,
/// `pub(super)`, and similar restricted forms are rejected so a symbol that is
/// not truly public cannot satisfy a caller that expects a crate-external item.
/// `pub async fn` and `pub unsafe fn` are accepted alongside plain `pub fn`.
fn defines_pub_symbol(src: &str, symbol: &str) -> bool {
    // Item-kind prefixes that may follow `pub` (with an optional `async`/`unsafe`
    // modifier before `fn`).
    const KINDS: &[&str] = &[
        "fn ",
        "async fn ",
        "unsafe fn ",
        "struct ",
        "enum ",
        "const ",
        "static ",
        "type ",
        "trait ",
    ];
    src.lines().any(|line| {
        let trimmed = line.trim_start();
        let Some(after_pub) = trimmed.strip_prefix("pub") else {
            return false;
        };
        // A restricted visibility (`pub(crate)`, `pub(super)`, …) starts with `(`.
        // Reject it: only bare `pub` (followed by whitespace or an item kind) counts.
        if after_pub.starts_with('(') {
            return false;
        }
        let rest = after_pub.trim_start();
        KINDS.iter().any(|kind| {
            rest.strip_prefix(kind).is_some_and(|after| {
                // The item name is the leading identifier; it must be exactly
                // `symbol` (terminated by a non-identifier character).
                after.strip_prefix(symbol).is_some_and(|tail| {
                    tail.chars()
                        .next()
                        .is_none_or(|c| !c.is_alphanumeric() && c != '_')
                })
            })
        })
    })
}

/// Every kernel that declares a `runtime_module` must emit a symbol that the
/// vendored runtime source actually defines in that module. A `runtime_fn` with
/// no defining `pub` symbol fails here, before the emitted crate would fail
/// `cargo build` — the fast tripwire for the module-set SEAL breach class.
#[test]
fn every_declared_runtime_symbol_is_defined_in_its_module() {
    let mut undefined: Vec<String> = Vec::new();
    for &k in StdlibKernel::ALL {
        let def = k.def();
        let Some(module) = def.runtime_module else {
            continue;
        };
        let files = module_source_files(module);
        let found = files.iter().any(|path| {
            std::fs::read_to_string(path).is_ok_and(|src| defines_pub_symbol(&src, def.runtime_fn))
        });
        if !found {
            undefined.push(format!(
                "{k:?}: runtime_fn `{}` declared in {module:?} but no `pub` symbol defines it",
                def.runtime_fn
            ));
        }
    }
    assert!(
        undefined.is_empty(),
        "kernels with an undefined runtime symbol in their declared module:\n{}",
        undefined.join("\n")
    );
}

/// `source_display_name` is the SSOT for the user-facing qualified source name
/// used in diagnostics and IR pretty-printing. The default formula is
/// `"{qualifier}.{name}"` from `def()`; the exception cases here are the
/// kernels whose display path differs from the canon-resolution qualifier (e.g.
/// kernels relocated into `Unsafe` sub-modules after the canon entry was
/// registered). Pin them so a rename of the exception match in `lib.rs` does
/// not silently change what a user sees in a diagnostic.
#[test]
fn source_display_name_matches_known_exceptions() {
    use StdlibKernel::*;
    let cases: &[(StdlibKernel, &str)] = &[
        (ResultOkDefault, "Result.Ok"),
        (DbExecRaw, "Db.Unsafe.unsafeExecRaw"),
        (DbQuery, "Db.Unsafe.unsafeQuery"),
        (DbGetString, "Db.Unsafe.unsafeGetString"),
        (DbGetInt, "Db.Unsafe.unsafeGetInt"),
        (DbGetBool, "Db.Unsafe.unsafeGetBool"),
        (DbGetField, "Db.Unsafe.unsafeGetField"),
        (SqlUnsafeFragment, "Db.Unsafe.unsafeFragment"),
        (HtmlScriptNode, "Html.Unsafe.unsafeScript"),
        // `Cache.*` kernels bind the `*Raw` source functions; `def().name` is
        // the pure Ipê wrapper, so the display name names the kernel node.
        (CacheGet, "Cache.getRaw"),
        (CachePut, "Cache.putRaw"),
        (CacheRemove, "Cache.removeRaw"),
        (CacheClear, "Cache.clearRaw"),
        (CacheSize, "Cache.sizeRaw"),
        (CacheStats, "Cache.statsRaw"),
        (CacheDestroyRaw, "Cache.destroyRaw"),
    ];
    for &(k, expected) in cases {
        assert_eq!(
            k.source_display_name(),
            expected,
            "{k:?}: source_display_name mismatch"
        );
    }
}

/// For every kernel NOT in the exception set, `source_display_name` equals
/// `"{qualifier}.{name}"` derived from `def()`. This guards the default arm
/// of the match in `source_display_name`.
#[test]
fn source_display_name_default_is_qualifier_dot_name() {
    use StdlibKernel::*;
    let exceptions = [
        ResultOkDefault,
        Interpolate,
        DbExecRaw,
        DbQuery,
        DbGetString,
        DbGetInt,
        DbGetBool,
        DbGetField,
        SqlUnsafeFragment,
        HtmlScriptNode,
        CacheGet,
        CachePut,
        CacheRemove,
        CacheClear,
        CacheSize,
        CacheStats,
        CacheDestroyRaw,
    ];
    for &k in StdlibKernel::ALL {
        if exceptions.contains(&k) {
            continue;
        }
        let def = k.def();
        let expected = format!("{}.{}", def.qualifier, def.name);
        assert_eq!(
            k.source_display_name(),
            expected,
            "{k:?}: source_display_name should be qualifier.name for non-exception kernels"
        );
    }
}
