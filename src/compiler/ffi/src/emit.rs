//! The `.ipei` and `kernel.json` emitters — two of the three artifacts.
//!
//! Both iterate the same validated [`PkgInfo`] and key every entry off
//! [`FnInfo::wrapper_ref_name`], so the `.ipei` binding name and the
//! `kernel.json` `"name"` are byte-equal by construction. The Ipê-visible
//! signature is built ONCE per function ([`wrapper_ipe_signature`]) from the
//! single stored [`Fallibility`] bit, so the two artifacts cannot disagree on
//! getter fallibility.

use std::collections::BTreeSet;

use crate::pkginfo::{Effect, Fallibility, FeatureName, FnInfo, Param, PkgInfo};
use crate::transparency::{ForeignVariantPayload, TransparentType};

/// Map a foreign Rust type string to its Ipê type, used only when the
/// inspector supplied no `ipeType` override.
///
/// Integer widths carry as `Int`, floats as `Float`; `Option`/`Vec`/`Result`
/// map to their Ipê containers; anything else is a nominal opaque name
/// (module path stripped). There is deliberately NO `any` arm.
#[must_use]
pub fn foreign_to_ipe(t: &str) -> String {
    let t = t.trim();
    let t = t.strip_prefix('&').unwrap_or(t).trim();
    let t = t.strip_prefix("mut ").unwrap_or(t).trim();
    if let Some(inner) = strip_container(t, "Option") {
        return format!("Maybe {}", paren_multi(&foreign_to_ipe(inner)));
    }
    if let Some(inner) = strip_container(t, "Vec") {
        return format!("List {}", paren_multi(&foreign_to_ipe(inner)));
    }
    // Unqualified `Result<T, E>`: only the 2-arg standard form maps to
    // `Result Error T`. A crate-local newtype with a different arity falls
    // through to the nominal opaque arm.
    // Only the 2-arg form maps to `Result Error T`; wrong arity falls through
    // to the nominal opaque arm so extra type arguments are not silently dropped.
    if let Some(inner) = strip_container(t, "Result")
        && let [ok, _err] = split_top_level_args(inner).as_slice()
    {
        // The foreign error arm folds into the typed Ipê `Error` at the
        // boundary — never a type param, never a `String` error.
        return format!("Result Error {}", paren_multi(&foreign_to_ipe(ok.trim())));
    }
    // Qualified Result alias: restrict to the known standard library paths
    // (`std|core::result::Result`, `std|core::fmt::Result`,
    // `std|core::io::Result`). A crate-local `mycrate::Result<A, B, C>`
    // whose module prefix is not a std path falls through to the generic
    // nominal-opaque arm so its extra type arguments are not silently dropped.
    if let Some((prefix, last_seg)) = t.rsplit_once("::") {
        let last_base = last_seg.split('<').next().unwrap_or(last_seg).trim();
        if last_base == "Result" && is_std_result_module(prefix) {
            if let Some(inner) = strip_container(last_seg, "Result") {
                // `io::Result<T>` / `result::Result<T, E>`: Ok payload is
                // the first comma-delimited argument.
                let ok = inner.split(',').next().unwrap_or(inner).trim();
                return format!("Result Error {}", paren_multi(&foreign_to_ipe(ok)));
            }
            // `fmt::Result` — bare alias for `Result<(), fmt::Error>`.
            return "Result Error ()".to_owned();
        }
    }
    match t {
        "str" | "String" | "OsStr" | "OsString" | "Path" | "PathBuf" | "CStr" | "CString" => {
            "String".to_owned()
        }
        "bool" => "Bool".to_owned(),
        "char" => "Char".to_owned(),
        "()" => "()".to_owned(),
        "i8" | "i16" | "i32" | "i64" | "i128" | "u8" | "u16" | "u32" | "u64" | "u128" | "isize"
        | "usize" => "Int".to_owned(),
        "f32" | "f64" => "Float".to_owned(),
        other => {
            // Nominal opaque: strip the module path and any generic args.
            let base = other.rsplit_once("::").map_or(other, |(_, l)| l);
            let base = base.split('<').next().unwrap_or(base).trim();
            if base.is_empty() {
                "()".to_owned()
            } else {
                base.to_owned()
            }
        }
    }
}

/// Strip `Ctor<inner>` down to `inner` when `t` is that container.
fn strip_container<'a>(t: &'a str, ctor: &str) -> Option<&'a str> {
    t.strip_prefix(ctor)
        .and_then(|rest| rest.trim().strip_prefix('<'))
        .and_then(|rest| rest.strip_suffix('>'))
}

/// True when `module` is one of the known standard-library module paths that
/// define a `Result` alias: `result`, `fmt`, `io` (with optional `std::` or
/// `core::` prefix). Unknown module paths are rejected so a crate-local
/// `mycrate::Result` is never coerced into the std mapping.
fn is_std_result_module(module: &str) -> bool {
    // Strip one optional leading `std::` or `core::` qualifier, then check the
    // leaf module name.
    let leaf = module
        .strip_prefix("std::")
        .or_else(|| module.strip_prefix("core::"))
        .unwrap_or(module);
    matches!(leaf, "result" | "fmt" | "io")
}

/// Split the comma-separated arguments of a generic parameter list at the
/// TOP level only — commas inside nested `<…>` groups do not split.
///
/// Returns the argument strings in declaration order. The caller receives an
/// empty `Vec` for an empty string (i.e. a bare `Result` with no angle
/// brackets).
fn split_top_level_args(inner: &str) -> Vec<&str> {
    let mut args = Vec::new();
    let mut depth: u32 = 0;
    let mut start = 0;
    for (i, b) in inner.bytes().enumerate() {
        match b {
            b'<' => depth = depth.saturating_add(1),
            b'>' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                args.push(inner[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail = inner[start..].trim();
    if !tail.is_empty() {
        args.push(tail);
    }
    args
}

/// Parenthesise a multi-word type when it nests under another constructor.
fn paren_multi(s: &str) -> String {
    if s.contains(' ') && !s.starts_with('(') {
        format!("({s})")
    } else {
        s.to_owned()
    }
}

/// The Ipê type of one foreign param/result: the inspector's override when
/// present, else the [`foreign_to_ipe`] fallback.
#[must_use]
pub fn param_ipe_type(p: &Param) -> String {
    if p.ipe_type.is_empty() {
        foreign_to_ipe(&p.foreign_ty)
    } else {
        p.ipe_type.clone()
    }
}

/// Build the full Ipê-visible signature for one binding.
///
/// The result wrapper is decided by the single stored [`Fallibility`] bit
/// plus the effect class: an infallible accessor is bare (`Version -> Int`),
/// an effectful wrapper lifts to `Task Error a`, everything else is
/// `Result Error a`. Constructed directly from parts — there is no
/// wrap-then-strip step for the two emitters to disagree over.
#[must_use]
pub fn wrapper_ipe_signature(f: &FnInfo) -> String {
    let param_sig = if f.params().is_empty() {
        "()".to_owned()
    } else {
        let parts: Vec<String> = f.params().iter().map(param_ipe_type).collect();
        parts.join(" -> ")
    };
    format!("{param_sig} -> {}", wrapper_ipe_result(f))
}

/// The Ipê result type of one binding — the part of
/// [`wrapper_ipe_signature`] after its parameters.
#[must_use]
pub fn wrapper_ipe_result(f: &FnInfo) -> String {
    let non_err: Vec<&Param> = f
        .results()
        .iter()
        .filter(|r| r.foreign_ty != "error")
        .collect();
    // A by-borrow reader threads its receiver back beside the result, so the Ok
    // payload gains a trailing receiver component: `R` becomes `(R, T)`, `()`
    // becomes `T`. The caller destructures it and flows the handle on without a
    // clone or the `IPE-L0130` linearity gate.
    let thread_recv = f.is_borrow_reader();
    let inner_ok = match (non_err.as_slice(), thread_recv) {
        ([], false) => "()".to_owned(),
        ([single], false) => param_ipe_type(single),
        (multi, false) => {
            let parts: Vec<String> = multi.iter().map(|p| param_ipe_type(p)).collect();
            format!("({})", parts.join(", "))
        }
        // Borrow-reader: append the receiver as the last tuple component.
        ([], true) => paren_multi(f.recv_type()),
        (results, true) => {
            let mut parts: Vec<String> = results.iter().map(|p| param_ipe_type(p)).collect();
            parts.push(f.recv_type().to_owned());
            format!("({})", parts.join(", "))
        }
    };
    match f.fallibility() {
        Fallibility::Infallible => inner_ok,
        Fallibility::TaskError => {
            // An inspector-rendered `Result e a` already carries the fallible
            // layer; peel it to the Ok payload before re-wrapping. The peel is
            // error-name-agnostic: the wrapper ALWAYS folds the foreign error
            // through the redaction funnel into the carrier's `Error` slot, so
            // whatever the foreign error rendered as (`Error`,
            // `ErrorsFirestoreError`, `String`) must not survive into the
            // surface — a surface re-stating it would disagree with the
            // wrapper's own type.
            let ok = peel_result_layer(&inner_ok).trim().to_owned();
            let carrier = if f.effect() == Effect::Effectful {
                "Task Error"
            } else {
                "Result Error"
            };
            format!("{carrier} {}", paren_multi(&ok))
        }
    }
}

/// Drop ONE leading `Result <err>` layer off a rendered Ipê type, returning
/// the Ok component (with any surrounding parens of the whole intact).
/// A rendering that is not a two-arg `Result` application returns unchanged.
fn peel_result_layer(s: &str) -> &str {
    let Some(rest) = s.strip_prefix("Result ") else {
        return s;
    };
    let rest = rest.trim_start();
    // Skip the error component: a balanced `(...)` group or a single word.
    let after_err = if rest.starts_with('(') {
        let mut depth = 0_u32;
        let mut end = None;
        for (i, c) in rest.char_indices() {
            match c {
                '(' => depth = depth.saturating_add(1),
                ')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        end = Some(i + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        end.and_then(|i| rest.get(i..))
    } else {
        rest.find(' ').and_then(|i| rest.get(i..))
    };
    match after_err.map(str::trim_start) {
        Some(ok) if !ok.is_empty() => ok,
        _ => s,
    }
}

/// The Ipê builtin heads that never need an opaque-type declaration.
///
/// Shared with the interface emitter's shadow-detection gate and the
/// transparency classification's shadow gate; defined leaf-side in `naming`.
#[must_use]
pub const fn ipe_builtin_heads() -> &'static [&'static str] {
    crate::naming::IPE_BUILTIN_HEADS
}

/// Every opaque foreign type name referenced by a signature: capitalised
/// identifier tokens that are not Ipê builtins.
pub fn opaque_names_in(sig: &str, out: &mut BTreeSet<String>) {
    for token in sig.split(|c: char| !c.is_alphanumeric() && c != '_') {
        let starts_upper = token.chars().next().is_some_and(char::is_uppercase);
        if starts_upper && !crate::naming::IPE_BUILTIN_HEADS.contains(&token) {
            out.insert(token.to_owned());
        }
    }
}

/// Render one transparent foreign type's Ipê declaration — the record /
/// closed-union vocabulary of the representation axis.
///
/// A transparent struct declares a record alias over its members' carrier
/// surfaces; a transparent enum declares a closed union whose constructors
/// take their payload carriers positionally (a struct-variant's member NAMES
/// stay in the catalog for the conversion glue — the Ipê constructor surface
/// is positional, mirroring how Ipê union constructors apply).
///
/// Consumed by [`emit_ipei`] and the interface emitter for the SAME admitted
/// set ([`crate::interface::CrateInterface::transparent_types`]), so no
/// artifact ever declares a record the wrappers still treat as an opaque
/// handle.
#[must_use]
pub fn transparent_type_decl(t: &TransparentType) -> String {
    match t {
        TransparentType::Struct { name, fields, .. } => {
            let parts: Vec<String> = fields
                .iter()
                .map(|f| format!("{} : {}", f.name, f.carrier.ipe_surface()))
                .collect();
            format!("type alias {name} = {{ {} }}", parts.join(", "))
        }
        TransparentType::Enum { name, variants, .. } => {
            let arms: Vec<String> = variants
                .iter()
                .map(|v| {
                    let args: Vec<&str> = match &v.payload {
                        ForeignVariantPayload::Unit => Vec::new(),
                        ForeignVariantPayload::Tuple(carriers) => {
                            carriers.iter().map(|c| c.ipe_surface()).collect()
                        }
                        ForeignVariantPayload::Struct(members) => {
                            members.iter().map(|m| m.carrier.ipe_surface()).collect()
                        }
                    };
                    if args.is_empty() {
                        v.name.as_str().to_owned()
                    } else {
                        format!("{} {}", v.name, args.join(" "))
                    }
                })
                .collect();
            format!("type {name} = {}", arms.join(" | "))
        }
    }
}

/// Emit the `.ipei` type-environment seed.
///
/// Contains the module header, one declaration per referenced foreign type
/// (so the seed is complete — a `Ty::Con` no module declares would dangle),
/// and one HM signature per binding. A name in `transparent` (the interface's
/// admitted set, so the two projections cannot disagree) declares its real
/// record/union shape; every other foreign name stays a nominal opaque.
#[must_use]
pub fn emit_ipei(
    pkg: &PkgInfo,
    transparent: &std::collections::BTreeMap<String, TransparentType>,
) -> String {
    use std::fmt::Write;
    let module = crate::naming::rust_module_name(pkg.pkg_path());
    let mut out = format!("module {module} exposing (..)\n\n");
    let sigs: Vec<(String, String)> = pkg
        .fns()
        .iter()
        .map(|f| (f.wrapper_ref_name(), wrapper_ipe_signature(f)))
        .collect();
    let mut opaque = BTreeSet::new();
    for (_, sig) in &sigs {
        opaque_names_in(sig, &mut opaque);
    }
    for name in &opaque {
        // Writing into a String is infallible.
        if let Some(t) = transparent.get(name) {
            let _ = writeln!(out, "{}", transparent_type_decl(t));
        } else {
            let _ = writeln!(out, "type {name}");
        }
    }
    if !opaque.is_empty() {
        out.push('\n');
    }
    for (name, sig) in &sigs {
        let _ = writeln!(out, "{name} : {sig}");
    }
    out
}

/// The `kernel.json` / `consumer.json` wire form of the per-type decision.
///
/// Every transparent type with its full member vocabulary, and every
/// reported-but-opaque type with its reason. `None` when the inspection
/// reported no types at all, so a package without a `types` section keeps
/// byte-identical artifacts.
#[must_use]
pub fn foreign_types_json(
    catalog: &crate::transparency::ForeignTypeCatalog,
) -> Option<serde_json::Value> {
    if catalog.transparent().is_empty() && catalog.opaque_reasons().is_empty() {
        return None;
    }
    let transparent: Vec<serde_json::Value> = catalog
        .transparent()
        .values()
        .map(transparent_type_json)
        .collect();
    let opaque: Vec<serde_json::Value> = catalog
        .opaque_reasons()
        .iter()
        .map(|r| serde_json::json!({ "name": r.name, "reason": r.reason }))
        .collect();
    Some(serde_json::json!({ "transparent": transparent, "opaque": opaque }))
}

/// One transparent type's wire form.
///
/// Members carry their Ipê carrier surface (`Int`, `Float`, …) — the
/// identity-pair rule means the Rust spelling is recoverable from it, so one
/// spelling is stored, never two to drift.
#[must_use]
pub fn transparent_type_json(t: &TransparentType) -> serde_json::Value {
    let member = |m: &crate::transparency::ForeignMember| serde_json::json!({ "name": m.name.as_str(), "carrier": m.carrier.ipe_surface() });
    match t {
        TransparentType::Struct {
            name,
            rust_path,
            fields,
        } => serde_json::json!({
            "name": name.as_str(),
            "kind": "struct",
            "rustPath": rust_path.as_str(),
            "fields": fields.iter().map(member).collect::<Vec<_>>(),
        }),
        TransparentType::Enum {
            name,
            rust_path,
            variants,
        } => {
            let vs: Vec<serde_json::Value> = variants
                .iter()
                .map(|v| match &v.payload {
                    ForeignVariantPayload::Unit => {
                        serde_json::json!({ "name": v.name.as_str(), "kind": "unit" })
                    }
                    ForeignVariantPayload::Tuple(carriers) => serde_json::json!({
                        "name": v.name.as_str(),
                        "kind": "tuple",
                        "carriers": carriers
                            .iter()
                            .map(|c| c.ipe_surface())
                            .collect::<Vec<_>>(),
                    }),
                    ForeignVariantPayload::Struct(members) => serde_json::json!({
                        "name": v.name.as_str(),
                        "kind": "struct",
                        "members": members.iter().map(member).collect::<Vec<_>>(),
                    }),
                })
                .collect();
            serde_json::json!({
                "name": name.as_str(),
                "kind": "enum",
                "rustPath": rust_path.as_str(),
                "variants": vs,
            })
        }
    }
}

/// Emit `kernel.json`.
///
/// One entry per binding keyed by the same `wrapper_ref_name`, the shared
/// signature string, and — for a parametric binding — the generic block
/// whose call AST is the RE-SERIALIZATION of the validated domain
/// [`crate::call::Call`] (a warm build re-runs the identical decode gate on
/// read).
#[must_use]
pub fn emit_kernel_json(pkg: &PkgInfo) -> String {
    let module = crate::naming::rust_module_name(pkg.pkg_path());
    let kernel = crate::naming::rust_kernel_name(pkg.pkg_path());
    let functions: Vec<serde_json::Value> = pkg
        .fns()
        .iter()
        .map(|f| {
            let mut o = serde_json::Map::new();
            o.insert("name".into(), f.wrapper_ref_name().into());
            o.insert("arity".into(), f.params().len().max(1).into());
            o.insert("ipeType".into(), wrapper_ipe_signature(f).into());
            if let Some(g) = f.generic() {
                o.insert(
                    "generic".into(),
                    serde_json::json!({
                        "params": g.params,
                        "bounds": g.bounds,
                        "call": g.call.to_wire_json(),
                    }),
                );
            }
            serde_json::Value::Object(o)
        })
        .collect();
    let mut doc = serde_json::Map::new();
    doc.insert("moduleName".into(), module.into());
    doc.insert("kernelName".into(), kernel.into());
    doc.insert("package".into(), pkg.pkg_path().into());
    doc.insert("functions".into(), functions.into());
    if !pkg.transitive_deps().is_empty() {
        let deps: Vec<serde_json::Value> = pkg
            .transitive_deps()
            .iter()
            .map(|d| {
                serde_json::json!({
                    "ident": d.ident.as_str(),
                    "name": d.name.as_str(),
                    "version": d.version.as_str(),
                })
            })
            .collect();
        doc.insert("transitiveDeps".into(), deps.into());
    }
    if !pkg.features().is_empty() {
        let features: Vec<&str> = pkg.features().iter().map(FeatureName::as_str).collect();
        doc.insert("features".into(), serde_json::json!(features));
    }
    // The per-type representation decision, verbatim from the decode-time
    // classification: every transparent shape and every reported-but-opaque
    // type with its reason. Absent when the inspection reported no types.
    if let Some(types) = foreign_types_json(pkg.foreign_types()) {
        doc.insert("types".into(), types);
    }
    let mut text = serde_json::to_string_pretty(&serde_json::Value::Object(doc))
        .unwrap_or_else(|_| "{}".to_owned());
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn semver_pkg() -> PkgInfo {
        let doc = serde_json::json!({
            "pkg": "semver",
            "name": "semver",
            "version": "1.0.26",
            "functions": [
                {
                    "name": "parse",
                    "params": [{"name": "text", "type": "&str", "ipeType": "String"}],
                    "results": [{"name": "", "type": "Result<Version, Error>"}],
                    "effect": "fallible"
                },
                {
                    "name": "major_field",
                    "params": [{"name": "self", "type": "&Version", "ipeType": "Version"}],
                    "results": [{"name": "", "type": "u64"}],
                    "effect": "pure",
                    "recvType": "Version",
                    "isField": true
                },
                {
                    "name": "to_string",
                    "params": [{"name": "self", "type": "&Version", "ipeType": "Version"}],
                    "results": [{"name": "", "type": "String"}],
                    "effect": "effectful",
                    "recvType": "Version"
                }
            ],
            "errors": [],
            "transitiveDeps": [
                {"ident": "semver", "name": "semver", "version": "1.0.26"}
            ],
            "features": ["std"]
        });
        PkgInfo::decode_json(&doc.to_string()).expect("decodes")
    }

    #[test]
    fn foreign_fallback_mapping_covers_the_closed_table() {
        assert_eq!(foreign_to_ipe("u64"), "Int");
        assert_eq!(foreign_to_ipe("f32"), "Float");
        assert_eq!(foreign_to_ipe("&str"), "String");
        assert_eq!(foreign_to_ipe("bool"), "Bool");
        assert_eq!(foreign_to_ipe("()"), "()");
        assert_eq!(foreign_to_ipe("Option<u8>"), "Maybe Int");
        assert_eq!(foreign_to_ipe("Vec<String>"), "List String");
        assert_eq!(
            foreign_to_ipe("Result<Version, Error>"),
            "Result Error Version"
        );
        assert_eq!(foreign_to_ipe("semver::Version"), "Version");
        assert_eq!(foreign_to_ipe("Vec<Option<i32>>"), "List (Maybe Int)");
    }

    #[test]
    fn qualified_result_aliases_map_correctly() {
        // `fmt::Result` is `Result<(), fmt::Error>` — Ok payload is `()`.
        assert_eq!(foreign_to_ipe("fmt::Result"), "Result Error ()");
        assert_eq!(foreign_to_ipe("std::fmt::Result"), "Result Error ()");
        // `io::Result<T>` carries an explicit Ok type arg; error is absorbed.
        assert_eq!(foreign_to_ipe("io::Result<()>"), "Result Error ()");
        assert_eq!(
            foreign_to_ipe("std::io::Result<String>"),
            "Result Error String"
        );
        assert_eq!(foreign_to_ipe("std::io::Result<usize>"), "Result Error Int");
    }

    #[test]
    fn signatures_read_the_single_fallibility_bit() {
        let pkg = semver_pkg();
        let sigs: Vec<String> = pkg.fns().iter().map(wrapper_ipe_signature).collect();
        assert_eq!(
            sigs,
            vec![
                // Fallible plain fn: Result-wrapped once, never doubled.
                "String -> Result Error Version".to_owned(),
                // Field getter: bare (the infallible bit).
                "Version -> Int".to_owned(),
                // Effectful plain fn: Task-lifted.
                "Version -> Task Error String".to_owned(),
            ]
        );
    }

    #[test]
    fn fallible_setter_signature_carries_the_result_layer() {
        // A checked (narrowing-integer) setter renders a `Result`-returning
        // wrapper; the surface signature must carry the SAME layer, or the
        // interface and the wrapper disagree at cargo time.
        let pkg = crate::pkginfo::PkgInfo::decode_json(
            &serde_json::json!({
                "pkg": "semver",
                "name": "semver",
                "version": "1.0.26",
                "functions": [{
                    "name": "patch_set_field",
                    "params": [
                        {"name": "value", "type": "Int", "ipeType": "Int", "rustType": "u32"},
                        {"name": "self", "type": "Version", "ipeType": "Version", "rustType": "semver::Version"}
                    ],
                    "results": [{"name": "", "type": "Version", "rustType": "semver::Version"}],
                    "effect": "fallible",
                    "recvType": "Version",
                    "recvRustType": "semver::Version",
                    "methodName": "patch",
                    "isFieldSet": true
                }],
                "errors": []
            })
            .to_string(),
        )
        .expect("decodes");
        let f = pkg.fns().first().expect("one binding");
        assert_eq!(
            wrapper_ipe_signature(f),
            "Int -> Version -> Result Error Version"
        );
    }

    #[test]
    fn borrow_reader_threads_the_receiver_into_the_result_tuple() {
        // A `&self` reader (receiver `rustType` begins with `&`) that returns a
        // non-`Self` value threads the receiver back: the Ok payload gains a
        // trailing receiver component, `Int` becomes `(Int, Widget)`.
        let pkg = crate::pkginfo::PkgInfo::decode_json(
            &serde_json::json!({
                "pkg": "handle_demo",
                "name": "handle_demo",
                "version": "0.1.0",
                "functions": [{
                    "name": "slot_count",
                    "params": [
                        {"name": "self", "type": "Widget", "ipeType": "Widget", "rustType": "&handle_demo::Widget"}
                    ],
                    "results": [{"name": "", "type": "Int", "rustType": "usize"}],
                    "effect": "pure",
                    "recvType": "Widget",
                    "recvRustType": "handle_demo::Widget",
                    "methodName": "slot_count"
                }],
                "errors": []
            })
            .to_string(),
        )
        .expect("decodes");
        let f = pkg.fns().first().expect("one binding");
        assert!(f.is_borrow_reader());
        assert_eq!(
            wrapper_ipe_signature(f),
            "Widget -> Result Error (Int, Widget)"
        );
    }

    #[test]
    fn transparent_type_decls_render_the_record_and_union_vocabulary() {
        let pkg = PkgInfo::decode_json(
            &serde_json::json!({
                "pkg": "tm",
                "name": "tm",
                "version": "0.1.0",
                "functions": [],
                "errors": [],
                "types": [
                    {"name": "Point", "rustPath": "tm::Point", "kind": "struct",
                     "fields": [
                        {"name": "x", "type": "Int", "rustType": "i64"},
                        {"name": "y", "type": "Float", "rustType": "f64"}
                     ]},
                    {"name": "Shade", "rustPath": "tm::Shade", "kind": "enum",
                     "variants": [
                        {"name": "On", "kind": "unit"},
                        {"name": "Level", "kind": "tuple",
                         "members": [{"name": "0", "type": "Int", "rustType": "i64"}]},
                        {"name": "Mix", "kind": "struct",
                         "members": [
                            {"name": "amount", "type": "Int", "rustType": "i64"},
                            {"name": "label", "type": "String", "rustType": "String"}
                         ]}
                     ]}
                ]
            })
            .to_string(),
        )
        .expect("decodes");
        let decls: Vec<String> = pkg
            .foreign_types()
            .transparent()
            .values()
            .map(transparent_type_decl)
            .collect();
        assert_eq!(
            decls,
            vec![
                "type alias Point = { x : Int, y : Float }".to_owned(),
                // A struct-variant's payload surfaces positionally, in
                // declaration order; the member names stay in the catalog for
                // the conversion glue.
                "type Shade = On | Level Int | Mix Int String".to_owned(),
            ]
        );
    }

    #[test]
    fn ipei_seed_declares_every_opaque_type_and_every_binding() {
        let pkg = semver_pkg();
        let ipei = emit_ipei(&pkg, &std::collections::BTreeMap::new());
        let expected = "module Rust.Semver exposing (..)\n\n\
                        type Version\n\n\
                        parse : String -> Result Error Version\n\
                        major_field_from_version : Version -> Int\n\
                        to_string_from_version : Version -> Task Error String\n";
        assert_eq!(ipei, expected);
    }

    #[test]
    fn kernel_json_keys_off_the_same_wrapper_ref_names() {
        let pkg = semver_pkg();
        let text = emit_kernel_json(&pkg);
        let doc: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(doc.pointer("/moduleName"), Some(&"Rust.Semver".into()));
        assert_eq!(doc.pointer("/kernelName"), Some(&"Rust_Semver".into()));
        let functions = doc
            .pointer("/functions")
            .and_then(serde_json::Value::as_array)
            .expect("functions array");
        let names: Vec<&str> = functions
            .iter()
            .map(|f| {
                f.pointer("/name")
                    .and_then(serde_json::Value::as_str)
                    .expect("name")
            })
            .collect();
        assert_eq!(
            names,
            vec![
                "parse",
                "major_field_from_version",
                "to_string_from_version"
            ]
        );
        // The .ipei and kernel.json signatures are the SAME string per fn.
        let ipei = emit_ipei(&pkg, &std::collections::BTreeMap::new());
        for f in functions {
            let name = f
                .pointer("/name")
                .and_then(serde_json::Value::as_str)
                .expect("name");
            let sig = f
                .pointer("/ipeType")
                .and_then(serde_json::Value::as_str)
                .expect("ipeType");
            assert!(
                ipei.contains(&format!("{name} : {sig}")),
                "{name} signature must match the .ipei seed"
            );
        }
        assert_eq!(
            doc.pointer("/transitiveDeps/0/ident"),
            Some(&"semver".into())
        );
        assert_eq!(doc.pointer("/features/0"), Some(&"std".into()));
    }

    #[test]
    fn kernel_json_carries_the_per_type_decision() {
        let pkg = PkgInfo::decode_json(
            &serde_json::json!({
                "pkg": "tm", "name": "tm", "version": "0.1.0",
                "functions": [],
                "errors": [],
                "types": [
                    {"name": "Point", "rustPath": "tm::Point", "kind": "struct",
                     "fields": [{"name": "x", "type": "Int", "rustType": "i64"}]},
                    {"name": "Sealed", "rustPath": "tm::Sealed", "kind": "struct",
                     "hiddenMembers": true}
                ]
            })
            .to_string(),
        )
        .expect("decodes");
        let doc: serde_json::Value =
            serde_json::from_str(&emit_kernel_json(&pkg)).expect("valid JSON");
        assert_eq!(
            doc.pointer("/types/transparent/0/name"),
            Some(&"Point".into())
        );
        assert_eq!(
            doc.pointer("/types/transparent/0/rustPath"),
            Some(&"tm::Point".into())
        );
        assert_eq!(doc.pointer("/types/opaque/0/name"), Some(&"Sealed".into()));
        assert!(
            doc.pointer("/types/opaque/0/reason")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|r| r.contains("hidden")),
            "{doc}"
        );
        // A package reporting no types keeps a byte-stable artifact (no key).
        let bare: serde_json::Value =
            serde_json::from_str(&emit_kernel_json(&semver_pkg())).expect("valid JSON");
        assert!(bare.get("types").is_none());
    }

    #[test]
    fn transparent_type_json_writes_every_variant_kind() {
        let pkg = PkgInfo::decode_json(
            &serde_json::json!({
                "pkg": "tm", "name": "tm", "version": "0.1.0",
                "functions": [],
                "errors": [],
                "types": [
                    {"name": "Shade", "rustPath": "tm::Shade", "kind": "enum",
                     "variants": [
                        {"name": "On", "kind": "unit"},
                        {"name": "Level", "kind": "tuple",
                         "members": [{"name": "0", "type": "Int", "rustType": "i64"}]},
                        {"name": "Mix", "kind": "struct",
                         "members": [{"name": "amount", "type": "Int", "rustType": "i64"}]}
                     ]}
                ]
            })
            .to_string(),
        )
        .expect("decodes");
        let original = pkg
            .foreign_types()
            .transparent()
            .get("Shade")
            .expect("transparent");
        assert_eq!(
            transparent_type_json(original),
            serde_json::json!({
                "name": "Shade", "kind": "enum", "rustPath": "tm::Shade",
                "variants": [
                    {"name": "On", "kind": "unit"},
                    {"name": "Level", "kind": "tuple", "carriers": ["Int"]},
                    {"name": "Mix", "kind": "struct",
                     "members": [{"name": "amount", "carrier": "Int"}]}
                ]
            })
        );
    }

    #[test]
    fn ipei_seed_declares_transparent_shapes() {
        let pkg = PkgInfo::decode_json(
            &serde_json::json!({
                "pkg": "tm", "name": "tm", "version": "0.1.0",
                "functions": [
                    {"name": "shift",
                     "params": [{"name": "p", "type": "Point", "ipeType": "Point",
                                 "rustType": "tm::Point"}],
                     "results": [{"name": "", "type": "Point", "rustType": "tm::Point"}],
                     "effect": "pure"}
                ],
                "errors": [],
                "types": [
                    {"name": "Point", "rustPath": "tm::Point", "kind": "struct",
                     "fields": [{"name": "x", "type": "Int", "rustType": "i64"}]}
                ]
            })
            .to_string(),
        )
        .expect("decodes");
        let ipei = emit_ipei(&pkg, pkg.foreign_types().transparent());
        assert!(ipei.contains("type alias Point = { x : Int }"), "{ipei}");
        assert!(!ipei.contains("type Point\n"), "{ipei}");
    }

    #[test]
    fn generic_block_round_trips_through_the_validated_call() {
        let doc = serde_json::json!({
            "pkg": "box1",
            "name": "box1",
            "functions": [{
                "name": "make",
                "params": [{"name": "value", "type": "T"}],
                "results": [{"name": "", "type": "Box1<T>"}],
                "effect": "pure",
                "generic": {
                    "params": ["a"],
                    "bounds": {"a": ["Clone"]},
                    "call": {
                        "kind": "function",
                        "path": ["::box1", "Box1"],
                        "typeArgs": [{"param": 0}],
                        "method": "make",
                        "args": [0],
                        "argTypes": [{"param": 0}],
                        "ret": {"ctor": "::box1::Box1", "args": [{"param": 0}]}
                    }
                }
            }],
            "errors": []
        });
        let pkg = PkgInfo::decode_json(&doc.to_string()).expect("decodes");
        let text = emit_kernel_json(&pkg);
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        let call = parsed
            .pointer("/functions/0/generic/call")
            .expect("generic call present");
        // The re-serialized call decodes through the same gate it came from.
        let redecoded = crate::call::Call::decode(1, call.clone(), "make").expect("re-decodes");
        assert_eq!(
            redecoded.render_body(&["a".to_owned()]),
            "::box1::Box1::<A>::make(arg0)"
        );
    }

    // --- Result alias restriction tests ---

    #[test]
    fn crate_local_result_with_three_args_maps_by_generic_ctor_not_std_result() {
        // A crate-local `mycrate::Result<A, B, C>` has an unknown module prefix
        // and 3 type args — neither criterion matches std Result. The mapping
        // must fall through to the nominal opaque arm, not emit `Result Error A`
        // (which would silently drop B and C).
        let mapped = foreign_to_ipe("mycrate::Result<A, B, C>");
        // The nominal opaque arm strips the module path and generic args,
        // yielding the bare constructor name.
        assert_eq!(mapped, "Result");
        // Critically, the extra type args B and C are not silently dropped.
        assert!(
            !mapped.contains("Error"),
            "must not be coerced to Result Error"
        );
    }

    #[test]
    fn unqualified_result_with_wrong_arity_falls_through_to_nominal_opaque() {
        // An unqualified `Result<A, B, C>` has 3 args — not the 2-arg standard
        // form; it must not be mapped as `Result Error A`.
        let three = foreign_to_ipe("Result<A, B, C>");
        assert!(
            !three.contains("Error"),
            "3-arg Result must not be std-mapped"
        );

        // A 1-arg `Result<T>` is equally non-standard.
        let one = foreign_to_ipe("Result<T>");
        assert!(
            !one.contains("Error"),
            "1-arg Result must not be std-mapped"
        );
    }

    #[test]
    fn std_result_aliases_still_map_correctly_after_restriction() {
        // The known std aliases must be unaffected by the restriction.
        assert_eq!(
            foreign_to_ipe("std::result::Result<T, E>"),
            "Result Error T"
        );
        assert_eq!(
            foreign_to_ipe("core::result::Result<T, E>"),
            "Result Error T"
        );
        assert_eq!(foreign_to_ipe("std::fmt::Result"), "Result Error ()");
        assert_eq!(foreign_to_ipe("core::fmt::Result"), "Result Error ()");
        assert_eq!(
            foreign_to_ipe("std::io::Result<String>"),
            "Result Error String"
        );
        assert_eq!(
            foreign_to_ipe("core::io::Result<usize>"),
            "Result Error Int"
        );
        assert_eq!(foreign_to_ipe("io::Result<()>"), "Result Error ()");
        assert_eq!(foreign_to_ipe("fmt::Result"), "Result Error ()");
        // Standard 2-arg unqualified Result still maps.
        assert_eq!(
            foreign_to_ipe("Result<Version, Error>"),
            "Result Error Version"
        );
    }
}
