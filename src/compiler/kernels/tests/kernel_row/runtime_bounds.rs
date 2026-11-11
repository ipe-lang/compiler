//! Drift gate: [`StdlibKernel::runtime_bounds`] equals the bounds the runtime's signatures put on each kernel.
//!
//! The lowerer proves a kernel's runtime bounds at every concrete instance
//! from the table alone, so a runtime `Clone`/`PartialEq`/`Sync` bound the
//! table misses lets `ipe` accept a program whose emitted crate fails
//! `cargo build` with E0277. This test parses every `.rs` file under the
//! runtime source root with `syn` and, for each kernel, reads every bare
//! `pub fn` named its `runtime_fn` — every `cfg` variant (the native and the
//! `wasm` pub/sub, say), taking the union of their bounds so one target's
//! refusal is every target's.
//!
//! * **Forward** — each `Clone`/`PartialEq`/`Eq`/`Sync` bound on a runtime
//!   generic is declared. A generic the runtime also bounds `Ord`,
//!   `PartialOrd` or `Hash` is a `comparable` scheme variable, which the type
//!   checker proves before lowering (every comparable carrier copies,
//!   compares and is shared), so it is skipped; a closure-bound generic
//!   (`F: Fn(..)`) is a function argument, not a value. A `Sync` bound on an
//!   argument listed in [`StdlibKernel::sync_captured_args`] is declared there.
//! * **Positional** — when the runtime function takes exactly the kernel's
//!   arity of parameters, a parameter typed as a bare generic at a scheme
//!   argument that is the variable `v` must find its bounds on `v`'s row. Any
//!   other parameter shape (`Vec<T>`, `Element<M>`, a record expanded into
//!   several parameters) is checked at the set level only; the per-family
//!   refusal tests in `ipe-cli`'s `golden_list_repeat_clone_seal` cover it end
//!   to end.
//! * **Reverse** — each declared bound is carried by some runtime generic, so
//!   a stale row fails. A kernel whose `runtime_fn` names no bare `pub fn` (a
//!   template-emitted or intercepted kernel; the runtime crate's
//!   `tests/symbol_resolution.rs` owns that list) must declare no row.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ipe_kernels::{ArgOrder, RuntimeBounds, StdlibKernel, TyShape, spine_arg};
use syn::{
    FnArg, GenericParam, Item, PathArguments, Type, TypeParamBound, Visibility, WherePredicate,
};

/// The deepest runtime module directory the walk descends into.
const MAX_DEPTH: usize = 8;

/// One type parameter of a runtime function.
#[derive(Default)]
struct Generic {
    /// The row bounds it carries.
    bounds: RuntimeBounds,
    /// Whether it is also bound `Ord`/`PartialOrd`/`Hash` (a `comparable` variable).
    comparable: bool,
    /// Whether it is bound by a closure trait (`Fn`/`FnMut`/`FnOnce`).
    closure: bool,
}

/// The parts of one runtime `pub fn` signature the scan reads.
struct Signature {
    /// Every type parameter, by name.
    generics: BTreeMap<String, Generic>,
    /// For each parameter, the type parameter it is typed as when bare.
    params: Vec<Option<String>>,
}

/// The vendored runtime source root, relative to this crate's manifest.
fn runtime_src_root() -> PathBuf {
    e2e_support::manifest_dir!().join("../../runtime/rust/src")
}

/// Folds one trait bound named `name` (closure-shaped when `parenthesized`) into `generic`.
fn absorb(generic: &mut Generic, name: &str, parenthesized: bool) {
    match name {
        "Clone" => generic.bounds = generic.bounds.with(RuntimeBounds::CLONE),
        "PartialEq" | "Eq" => generic.bounds = generic.bounds.with(RuntimeBounds::PARTIAL_EQ),
        "Sync" => generic.bounds = generic.bounds.with(RuntimeBounds::SYNC),
        "Ord" | "PartialOrd" | "Hash" => generic.comparable = true,
        "Fn" | "FnMut" | "FnOnce" => generic.closure = true,
        _ => {}
    }
    if parenthesized {
        generic.closure = true;
    }
}

/// Folds every trait bound of `bounds` into `generic`.
fn absorb_all<'a>(generic: &mut Generic, bounds: impl IntoIterator<Item = &'a TypeParamBound>) {
    for bound in bounds {
        if let TypeParamBound::Trait(trait_bound) = bound
            && let Some(last) = trait_bound.path.segments.last()
        {
            let parenthesized = matches!(last.arguments, PathArguments::Parenthesized(_));
            absorb(generic, &last.ident.to_string(), parenthesized);
        }
    }
}

/// The single identifier `ty` names when it is a bare path with no arguments.
fn bare_ident(ty: &Type) -> Option<String> {
    let Type::Path(path) = ty else {
        return None;
    };
    if path.qself.is_some() || path.path.segments.len() != 1 {
        return None;
    }
    let segment = path.path.segments.first()?;
    matches!(segment.arguments, PathArguments::None).then(|| segment.ident.to_string())
}

/// The scan's reading of one function signature.
fn signature(sig: &syn::Signature) -> Signature {
    let mut generics: BTreeMap<String, Generic> = BTreeMap::new();
    for param in &sig.generics.params {
        if let GenericParam::Type(ty) = param {
            let generic = generics.entry(ty.ident.to_string()).or_default();
            absorb_all(generic, &ty.bounds);
        }
    }
    if let Some(clause) = &sig.generics.where_clause {
        for predicate in &clause.predicates {
            if let WherePredicate::Type(pred) = predicate
                && let Some(name) = bare_ident(&pred.bounded_ty)
                && let Some(generic) = generics.get_mut(&name)
            {
                absorb_all(generic, &pred.bounds);
            }
        }
    }
    let params = sig
        .inputs
        .iter()
        .map(|input| match input {
            FnArg::Typed(typed) => bare_ident(&typed.ty).filter(|n| generics.contains_key(n)),
            FnArg::Receiver(_) => None,
        })
        .collect();
    Signature { generics, params }
}

/// Records every bare `pub fn` of `items`, inline modules included.
fn collect_items(items: &[Item], out: &mut BTreeMap<String, Vec<Signature>>) {
    for item in items {
        match item {
            Item::Fn(func) if matches!(func.vis, Visibility::Public(_)) => {
                out.entry(func.sig.ident.to_string())
                    .or_default()
                    .push(signature(&func.sig));
            }
            Item::Mod(module) => {
                if let Some((_, inner)) = &module.content {
                    collect_items(inner, out);
                }
            }
            _ => {}
        }
    }
}

/// Parses every `.rs` file under `dir` into `out`, refusing an unreadable or unparsable file.
fn collect_dir(dir: &Path, depth: usize, out: &mut Scan) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("{}: deeper than {MAX_DEPTH} levels", dir.display()));
    }
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut paths: Vec<PathBuf> = entries
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect_dir(&path, depth.saturating_add(1), out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let source =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let file = syn::parse_file(&source).map_err(|e| format!("{}: {e}", path.display()))?;
            collect_items(&file.items, &mut out.signatures);
            out.sources.push(source);
        }
    }
    Ok(())
}

/// The runtime source as the scan read it.
#[derive(Default)]
struct Scan {
    /// Every bare runtime `pub fn`, by name, with each `cfg` variant's signature.
    signatures: BTreeMap<String, Vec<Signature>>,
    /// The text of every runtime source file.
    sources: Vec<String>,
}

/// Parses the whole runtime source tree.
fn runtime_scan() -> Result<Scan, String> {
    let mut out = Scan::default();
    collect_dir(&runtime_src_root(), 0, &mut out)?;
    Ok(out)
}

/// Every bare runtime `pub fn`, by name, with each `cfg` variant's signature.
fn runtime_signatures() -> Result<BTreeMap<String, Vec<Signature>>, String> {
    runtime_scan().map(|scan| scan.signatures)
}

/// The union of every row of `kernel`'s table.
fn declared_union(kernel: StdlibKernel) -> RuntimeBounds {
    kernel
        .runtime_bounds()
        .iter()
        .fold(RuntimeBounds::NONE, |acc, (_, bounds)| acc.with(*bounds))
}

/// The bounds `kernel` declares on scheme variable `var`.
fn declared_on(kernel: StdlibKernel, var: u8) -> RuntimeBounds {
    kernel
        .runtime_bounds()
        .iter()
        .find(|(v, _)| *v == var)
        .map_or(RuntimeBounds::NONE, |(_, bounds)| *bounds)
}

/// The Ipê argument index of runtime parameter `param` of a kernel with `arity` and `order`.
fn ipe_index(order: ArgOrder, arity: usize, param: usize) -> Option<usize> {
    match order {
        ArgOrder::IpeOrder => Some(param),
        ArgOrder::ContainerFirst => arity.checked_sub(1)?.checked_sub(param),
    }
}

/// Kernels the type checker refuses at every reference (IPE-L0108), so no program reaches their runtime function.
///
/// `Web.appRouted` is unschemed until its lowering lands (the type checker's
/// `REACHABLE_BUT_UNLOWERED` bucket pins it so); without a scheme shape it
/// cannot carry a row. The exemption holds only while the kernel has no
/// shape: once it gains one, the forward check reads it like every other
/// kernel and its rows must be declared.
const REFUSED_BEFORE_LOWERING: [StdlibKernel; 1] = [StdlibKernel::WebAppRouted];

/// Whether the forward check passes over `kernel`: refused before lowering and still shapeless.
fn refused_before_lowering(kernel: StdlibKernel) -> bool {
    REFUSED_BEFORE_LOWERING.contains(&kernel) && kernel.scheme_shape().is_none()
}

#[test]
fn every_refused_kernel_is_shapeless_and_rowless() {
    for kernel in REFUSED_BEFORE_LOWERING {
        assert!(
            refused_before_lowering(kernel),
            "{kernel:?} has a scheme shape"
        );
        assert!(
            kernel.runtime_bounds().is_empty(),
            "{kernel:?} declares a row"
        );
    }
    assert!(!refused_before_lowering(StdlibKernel::WebApp));
}

#[test]
fn every_runtime_bound_is_declared() {
    let scanned = runtime_signatures().expect("the runtime source must parse");
    let mut failures = Vec::new();
    for &kernel in StdlibKernel::ALL {
        if refused_before_lowering(kernel) {
            continue;
        }
        let def = kernel.def();
        let Some(signatures) = scanned.get(def.runtime_fn) else {
            continue;
        };
        let captured = kernel.sync_captured_args();
        let set_level = if captured.is_empty() {
            declared_union(kernel)
        } else {
            declared_union(kernel).with(RuntimeBounds::SYNC)
        };
        let arity = usize::from(def.arity);
        for signature in signatures {
            for (name, generic) in &signature.generics {
                if generic.closure || generic.comparable {
                    continue;
                }
                if !set_level.contains(generic.bounds) {
                    failures.push(format!(
                        "{kernel:?}: `{}` bounds `{name}` {:?}, but the kernel declares only {set_level:?}",
                        def.runtime_fn, generic.bounds
                    ));
                }
            }
            if signature.params.len() != arity {
                continue;
            }
            let Some(shape) = kernel.scheme_shape() else {
                continue;
            };
            for (param, bare) in signature.params.iter().enumerate() {
                let Some(name) = bare else { continue };
                let Some(generic) = signature.generics.get(name) else {
                    continue;
                };
                if generic.closure || generic.comparable {
                    continue;
                }
                let Some(index) = ipe_index(def.arg_order, arity, param) else {
                    continue;
                };
                let Some(TyShape::Var(var)) = spine_arg(shape, index) else {
                    continue;
                };
                let declared = if captured.contains(&index) {
                    declared_on(kernel, *var).with(RuntimeBounds::SYNC)
                } else {
                    declared_on(kernel, *var)
                };
                if !declared.contains(generic.bounds) {
                    failures.push(format!(
                        "{kernel:?}: `{}` parameter {param} is `{name}`, bounded {:?}, at scheme \
                         variable {var}, which declares only {declared:?}",
                        def.runtime_fn, generic.bounds
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "a runtime bound is missing from `StdlibKernel::runtime_bounds`:\n{}",
        failures.join("\n")
    );
}

#[test]
fn every_declared_bound_has_a_runtime_generic() {
    let scanned = runtime_signatures().expect("the runtime source must parse");
    let mut failures = Vec::new();
    for &kernel in StdlibKernel::ALL {
        let declared = declared_union(kernel);
        if declared.is_empty() {
            continue;
        }
        let def = kernel.def();
        let Some(signatures) = scanned.get(def.runtime_fn) else {
            failures.push(format!(
                "{kernel:?}: declares {declared:?}, but `{}` is no runtime `pub fn`",
                def.runtime_fn
            ));
            continue;
        };
        let carried = signatures
            .iter()
            .flat_map(|signature| signature.generics.values())
            .filter(|generic| !generic.closure)
            .fold(RuntimeBounds::NONE, |acc, generic| acc.with(generic.bounds));
        for bound in RuntimeBounds::ALL {
            if declared.contains(bound) && !carried.contains(bound) {
                failures.push(format!(
                    "{kernel:?}: declares {bound:?}, but no generic of `{}` carries it",
                    def.runtime_fn
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "a `StdlibKernel::runtime_bounds` row is stale:\n{}",
        failures.join("\n")
    );
}

/// A kernel whose runtime function the scan cannot read has no generic definition there.
///
/// The forward check passes over a kernel whose `runtime_fn` is no bare
/// `pub fn` (a method, a function a macro body defines). Such a function
/// spelled with type parameters anywhere in the runtime source carries bounds
/// the scan never reads, so it is refused here.
#[test]
fn no_unscanned_runtime_fn_is_generic() {
    let scan = runtime_scan().expect("the runtime source must parse");
    let unread: Vec<&str> = StdlibKernel::ALL
        .iter()
        .map(|kernel| kernel.def().runtime_fn)
        .filter(|name| !scan.signatures.contains_key(*name))
        .filter(|name| {
            scan.sources
                .iter()
                .any(|source| spells_generic_fn(source, name))
        })
        .collect();
    assert!(
        unread.is_empty(),
        "a generic runtime function the bound scan cannot read: {unread:?}"
    );
}

/// Whether `source` defines `fn name` with a type parameter or an `impl Trait` argument.
///
/// Reads the text from `fn name` to the body's opening brace, so a generic
/// spelled as `fn name<T>` or as `fn name(x: impl Clone)` is found alike.
fn spells_generic_fn(source: &str, name: &str) -> bool {
    let needle = format!("fn {name}");
    source.match_indices(&needle).any(|(at, _)| {
        let rest = source.get(at.saturating_add(needle.len())..).unwrap_or("");
        let header = rest.split('{').next().unwrap_or("");
        header.starts_with('<') || (header.starts_with('(') && header.contains("impl "))
    })
}

#[test]
fn the_generic_spelling_check_reads_both_forms() {
    assert!(spells_generic_fn("pub fn f<T: Clone>(x: T) {}", "f"));
    assert!(spells_generic_fn("pub fn f(x: impl Clone) {}", "f"));
    assert!(!spells_generic_fn("pub fn f(x: i64) {}", "f"));
    assert!(!spells_generic_fn("pub fn fg<T>(x: T) {}", "f"));
}

/// The scan reads real signatures: `list_repeat` is found and its element generic copies.
#[test]
fn the_scan_reads_list_repeat() {
    let scanned = runtime_signatures().expect("the runtime source must parse");
    let repeat = scanned.get(StdlibKernel::ListRepeat.def().runtime_fn);
    assert!(
        repeat.is_some_and(|signatures| {
            signatures.iter().any(|signature| {
                signature
                    .generics
                    .values()
                    .any(|generic| generic.bounds.contains(RuntimeBounds::CLONE))
            })
        }),
        "the scan must find `list_repeat` with a `Clone` element"
    );
    assert!(
        declared_on(StdlibKernel::ListRepeat, 0).contains(RuntimeBounds::CLONE),
        "`List.repeat` copies its element"
    );
}

/// A variable only a record argument carries is reached, not positionally aligned.
#[test]
fn a_record_only_variable_is_reached() {
    let shape = StdlibKernel::TerminalAppScreen
        .scheme_shape()
        .expect("`Terminal.app.screen` has a scheme shape");
    assert!(!ipe_kernels::shape_aligns_var(shape, 0));
    assert!(ipe_kernels::shape_reaches_var(shape, 0));
    assert!(!ipe_kernels::shape_reaches_var(shape, 9));
}
