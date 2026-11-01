//! Demand-driven generic FFI: per-instance bindability gate + ONE generic
//! wrapper per generic foreign function.
//!
//! The Rust FFI call path has no call-site-rewrite seam: every instantiation
//! of a generic foreign fn resolves to the SAME base wrapper name, and rustc
//! monomorphises through its own generics. So this module emits ONE
//! `<T: bounds>` generic wrapper per generic fn, and gates every REACHED
//! instantiation before any Rust is emitted:
//!
//! 1. closed-set check — each concrete type-arg must lie in the closed
//!    Ipê↔Rust set (primitive / `List` / `Maybe`, recursive);
//! 2. trait-bound check — each declared bound must be in [`MODELLABLE_5`]
//!    AND satisfied by the concrete arg via the static trait table.
//!
//! A violation is a first-class `IPE-F4400` [`Diagnostic`] at the call site —
//! never a silent drop (the call site references the base name, so a skip
//! would be a downstream E0425) and never emit-and-cargo-fail.
//!
//! The consumer wiring (M4) converts the lowering's solved concrete `Ty` per
//! call region into [`InstanceTy`]; this crate stays registry-independent.

use std::collections::BTreeSet;

use crate::call::{ByKind, Call};
use crate::diag::{ClosedSetViolation, Diagnostic, GenericBindDefect};
use crate::naming::{RustTypeExpr, mangle_tvar, wrapper_fn_ident};
use crate::num_coerce::{NumWidth, num_widen_scalar};
use crate::pkginfo::{FnInfo, GenericFn};
use crate::typeref::{ArgTypeRef, ClosureKind, InnerTypeRef};

/// The exact set of trait bounds the parametric-stub monomorphiser models.
///
/// MUST stay byte-identical to the inspector's `MODELLABLE_5`
/// (`tools/ipe-ffi-inspector/src/main.rs`) — the two-way drift fence test
/// reads the inspector source and fails if either side changes alone.
pub const MODELLABLE_5: [&str; 5] = ["Hash", "Eq", "Ord", "Clone", "Default"];

/// Whether a declared bound is modellable by the static trait table.
#[must_use]
pub fn modellable_trait(t: &str) -> bool {
    MODELLABLE_5.contains(&t)
}

// ── the concrete-instantiation input shape ──────────────────────────────────

/// A concrete Ipê type instantiating one generic FFI type-param.
///
/// The consumer wiring hands this over; it mirrors the canonical `Ty`
/// closely enough for the closed-set gate, and the conversion is the
/// consumer's one mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstanceTy {
    /// A named type constructor with its (possibly empty) arguments —
    /// `Int`, `String`, `List Int`, `Maybe (List Float)`, opaque `Version`.
    Con {
        /// The constructor name.
        name: String,
        /// The type arguments.
        args: Vec<Self>,
    },
    /// A bare type variable that survived monomorphisation.
    Var(String),
    /// The unit type.
    Unit,
    /// A record type (outside the closed set).
    Record,
    /// A tuple type (outside the closed set).
    Tuple(Vec<Self>),
    /// A function type (outside the closed set).
    Function,
    /// An unexpanded type alias (outside the closed set).
    Alias(String),
}

impl InstanceTy {
    /// A no-argument constructor.
    #[must_use]
    pub fn con(name: &str) -> Self {
        Self::Con {
            name: name.to_owned(),
            args: Vec::new(),
        }
    }

    /// Render as an Ipê-source-shaped string for diagnostics.
    #[must_use]
    pub fn render(&self) -> String {
        fn paren_if(t: &InstanceTy) -> String {
            match t {
                InstanceTy::Con { args, .. } if !args.is_empty() => format!("({})", t.render()),
                _ => t.render(),
            }
        }
        match self {
            Self::Con { name, args } => {
                if args.is_empty() {
                    name.clone()
                } else {
                    let rendered: Vec<String> = args.iter().map(paren_if).collect();
                    format!("{name} {}", rendered.join(" "))
                }
            }
            Self::Var(n) | Self::Alias(n) => n.clone(),
            Self::Unit => "()".to_owned(),
            Self::Record => "{ … }".to_owned(),
            Self::Tuple(parts) => {
                let rendered: Vec<String> = parts.iter().map(Self::render).collect();
                format!("({})", rendered.join(", "))
            }
            Self::Function => "<function>".to_owned(),
        }
    }
}

/// Map a concrete Ipê type to its Rust type, restricted to the CLOSED set.
///
/// Anything else — records, tuples, functions, opaque foreign types, bare
/// type variables — is a [`ClosedSetViolation`]: outside the set, synthesis
/// would be unsound.
///
/// Opaque `Clone`-deriving foreign types are admissible in principle but
/// require derive-scan metadata; admitting one on faith would be unsound, so
/// they are rejected here (the conservative default).
///
/// # Errors
///
/// The violation naming why the type is outside the closed set.
pub fn ipe_type_to_rust_closed(ty: &InstanceTy) -> Result<String, ClosedSetViolation> {
    match ty {
        InstanceTy::Con { name, args } => match (name.as_str(), args.as_slice()) {
            ("Int", []) => Ok("i64".to_owned()),
            ("Float", []) => Ok("f64".to_owned()),
            ("Bool", []) => Ok("bool".to_owned()),
            ("Char", []) => Ok("char".to_owned()),
            ("String", []) => Ok("String".to_owned()),
            ("List", [el]) => Ok(format!("Vec<{}>", ipe_type_to_rust_closed(el)?)),
            ("Maybe", [el]) => Ok(format!("IpeMaybe<{}>", ipe_type_to_rust_closed(el)?)),
            _ => Err(ClosedSetViolation::NonClosedConstructor(name.clone())),
        },
        InstanceTy::Unit => Ok("()".to_owned()),
        InstanceTy::Var(n) => Err(ClosedSetViolation::UnresolvedTypeVariable(n.clone())),
        InstanceTy::Record => Err(ClosedSetViolation::RecordType),
        InstanceTy::Tuple(_) => Err(ClosedSetViolation::TupleType),
        InstanceTy::Function => Err(ClosedSetViolation::FunctionType),
        InstanceTy::Alias(n) => Err(ClosedSetViolation::TypeAlias(n.clone())),
    }
}

// ── static trait table ──────────────────────────────────────────────────────

/// The subset of [`MODELLABLE_5`] a closed Rust type satisfies.
///
/// Cells verified against the runtime + std, not ported on faith:
///
/// * `i64` / `String` / `bool` / `char` / `()` — all five.
/// * `f64` / `f32` — Clone + Default only; IEEE-754 has no `Eq`/`Ord`/`Hash`
///   in Rust (the security-critical cell).
/// * `Vec<T>` (std) — Default always (empty vec); Hash/Eq/Ord/Clone iff `T`
///   has them.
/// * `IpeMaybe<T>` — the runtime enum derives `Clone, Debug, PartialEq,
///   Serialize` only (`src/runtime/rust/src/core.rs`): Clone iff `T: Clone`,
///   nothing else. It is NOT std `Option` — no Default/Hash/Eq/Ord.
///
/// An unrecognised type conservatively satisfies nothing.
#[must_use]
pub fn traits_of_rust_type(rust_ty: &str) -> BTreeSet<&'static str> {
    match rust_ty {
        "i64" | "String" | "bool" | "char" | "()" => return MODELLABLE_5.into_iter().collect(),
        "f64" | "f32" => return ["Clone", "Default"].into_iter().collect(),
        _ => {}
    }
    if let Some(inner) = strip_wrap("Vec<", rust_ty) {
        // Conditional traits carry from the element; Default is unconditional
        // (the empty vec).
        let mut out = traits_of_rust_type(inner);
        out.retain(|t| matches!(*t, "Hash" | "Eq" | "Ord" | "Clone"));
        out.insert("Default");
        return out;
    }
    if let Some(inner) = strip_wrap("IpeMaybe<", rust_ty) {
        let mut out = traits_of_rust_type(inner);
        out.retain(|t| *t == "Clone");
        return out;
    }
    BTreeSet::new()
}

fn strip_wrap<'a>(prefix: &str, s: &'a str) -> Option<&'a str> {
    s.strip_prefix(prefix).and_then(|r| r.strip_suffix('>'))
}

/// Does the (already-closed) Rust type satisfy the named modellable trait?
#[must_use]
pub fn rust_type_has_trait(rust_ty: &str, bound: &str) -> bool {
    traits_of_rust_type(rust_ty).contains(bound)
}

/// A capture is admissible into a multi-call `Fn`/`FnMut` slot ONLY when its
/// Rust type is positively Clone (an allowlist, never a denylist).
#[must_use]
pub fn rust_type_is_clone(rust_ty: &str) -> bool {
    rust_type_has_trait(rust_ty, "Clone")
}

/// True iff the Ipê type maps to a closed Rust type that is positively
/// Clone. A type outside the closed set is conservatively rejected — Clone
/// cannot be proven on faith.
#[must_use]
pub fn capture_is_clone(ty: &InstanceTy) -> bool {
    ipe_type_to_rust_closed(ty).is_ok_and(|rust_ty| rust_type_is_clone(&rust_ty))
}

/// Map a modellable trait name to its fully-qualified Rust path for the
/// `<T: …>` bound rendering.
#[must_use]
pub fn trait_to_rust_path(t: &str) -> Option<&'static str> {
    match t {
        "Hash" => Some("::std::hash::Hash"),
        "Eq" => Some("::std::cmp::Eq"),
        "Ord" => Some("::std::cmp::Ord"),
        "Clone" => Some(CLONE_PATH),
        "Default" => Some("::core::default::Default"),
        _ => None,
    }
}

const CLONE_PATH: &str = "::core::clone::Clone";

// ── per-instance bindability check ──────────────────────────────────────────

/// One reachable generic FFI call instance: the qualified callee, the
/// concrete type-args (positional with the generic block's params), and the
/// binding's generic block.
#[derive(Debug)]
pub struct FfiInstance<'a> {
    /// The qualified Ipê callee (`Rust.Box1.make`).
    pub callee: &'a str,
    /// The concrete type-args, positional with `generic.params`.
    pub types: &'a [InstanceTy],
    /// The binding's validated generic block.
    pub generic: &'a GenericFn,
}

/// Check every reachable generic FFI instance; the caller fails the build
/// when the result is non-empty, BEFORE generating any Rust.
#[must_use]
pub fn check_instances(instances: &[FfiInstance<'_>]) -> Vec<Diagnostic> {
    instances.iter().flat_map(check_instance).collect()
}

/// All bindability violations for one instance.
///
/// The closed-set check runs first (a non-mappable arg has no Rust type to
/// check bounds against), then the per-param trait-bound check on the args
/// that ARE closed. Positional alignment truncates to the shorter list — a
/// length mismatch is a malformed stub, never an out-of-range access.
#[must_use]
pub fn check_instance(inst: &FfiInstance<'_>) -> Vec<Diagnostic> {
    let not_bindable = |defect: GenericBindDefect| Diagnostic::GenericNotBindable {
        callee: inst.callee.to_owned(),
        defect,
    };
    let mut out = Vec::new();
    for (pname, ty) in inst.generic.params.iter().zip(inst.types) {
        match ipe_type_to_rust_closed(ty) {
            Err(violation) => out.push(not_bindable(GenericBindDefect::OutsideClosedSet {
                param: pname.clone(),
                ty: ty.render(),
                violation,
            })),
            Ok(rust_ty) => {
                for bound in inst.generic.bounds.get(pname).into_iter().flatten() {
                    if !modellable_trait(bound) {
                        out.push(not_bindable(GenericBindDefect::UnmodellableBound {
                            param: pname.clone(),
                            bound: bound.clone(),
                        }));
                    } else if !rust_type_has_trait(&rust_ty, bound) {
                        out.push(not_bindable(GenericBindDefect::BoundUnsatisfied {
                            param: pname.clone(),
                            ty: ty.render(),
                            rust_ty: rust_ty.clone(),
                            bound: bound.clone(),
                        }));
                    }
                }
            }
        }
    }
    out
}

// ── closure-capture gate ────────────────────────────────────────────────────

/// The first capture that is not provably Clone, as
/// `(name, rendered type)` — or `None` when the lambda may be lowered as-is.
///
/// * `FnOnce` — the host calls the closure at most once, so a non-Clone
///   capture is MOVED in soundly; never gated.
/// * `Fn` / `FnMut` — the owned-clone bridge re-clones every capture per
///   call, so ALL captures must be positively Clone.
#[must_use]
pub fn first_non_clone_capture(
    kind: ClosureKind,
    captures: &[(String, InstanceTy)],
) -> Option<(&str, String)> {
    if kind == ClosureKind::FnOnce {
        return None;
    }
    captures
        .iter()
        .find(|(_, ty)| !capture_is_clone(ty))
        .map(|(name, ty)| (name.as_str(), ty.render()))
}

/// The full capture gate over one closure FFI argument.
///
/// # Errors
///
/// An `IPE-F4400` [`Diagnostic`] naming the first non-Clone capture flowing
/// into a multi-call (`Fn`/`FnMut`) slot — never a cargo failure.
pub fn gate_closure_arg(
    callee: &str,
    kind: ClosureKind,
    captures: &[(String, InstanceTy)],
) -> Result<(), Diagnostic> {
    match first_non_clone_capture(kind, captures) {
        None => Ok(()),
        Some((name, ty)) => Err(Diagnostic::GenericNotBindable {
            callee: callee.to_owned(),
            defect: GenericBindDefect::CaptureNotClone {
                capture: name.to_owned(),
                ty,
            },
        }),
    }
}

// ── unsound closure shapes: drop + record ───────────────────────────────────

/// Why a closure-carrying binding is DROPPED (silently not bound, reason
/// recorded for coverage — its call site is itself tree-shaken away, so this
/// is never a hard failure).
///
/// The higher-order-return shape (a closure returning a closure) has no
/// variant: [`Call::decode`] already rejects any nested closure as
/// `ClosureNestedOrNonDirect`, so it is unrepresentable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosureDropReason {
    /// An `FnMut`/`FnOnce` closure passed BY REF: the owned-clone bridge
    /// clones the borrow, so mutations to the clone never propagate back —
    /// binding it would silently lose writes.
    MutByRefSlot,
    /// A by-ref closure whose borrowed arg is a CONCRETE type the backend
    /// cannot prove Clone: the bridge's `.clone()` would be ill-typed. A
    /// generic (`param`) borrowed arg is NOT flagged — the forced `+ Clone`
    /// bound enforces Clone at instantiation.
    ByRefNonCloneConcrete,
}

impl std::fmt::Display for ClosureDropReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MutByRefSlot => f.write_str("closure-mut-slot"),
            Self::ByRefNonCloneConcrete => f.write_str("closure-by-ref-noclone"),
        }
    }
}

/// Classify one wrapper-arg slot as an unsound closure shape to drop, or
/// `None` for a bindable shape (including every non-closure slot).
#[must_use]
pub fn closure_drop_reason(at: &ArgTypeRef) -> Option<ClosureDropReason> {
    let ArgTypeRef::Closure {
        kind,
        by_ref,
        arg_types,
        ..
    } = at
    else {
        return None;
    };
    if *by_ref && *kind != ClosureKind::Fn {
        return Some(ClosureDropReason::MutByRefSlot);
    }
    if *by_ref && arg_types.iter().any(concrete_not_clone) {
        return Some(ClosureDropReason::ByRefNonCloneConcrete);
    }
    None
}

/// A concrete (non-generic) borrowed closure-arg leaf the backend cannot
/// prove Clone. A `param` ref is generic — its Clone-ness is enforced by the
/// closure's forced `+ Clone` bound, so it is never a drop here.
fn concrete_not_clone(t: &InnerTypeRef) -> bool {
    match t {
        InnerTypeRef::Param(_) => false,
        other => !rust_type_is_clone(&other.render(&[])),
    }
}

// ── per-function generic-wrapper synthesis ──────────────────────────────────

/// One synthesised generic wrapper, keyed for the DCE tree-shake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittedWrapper {
    /// The owning kernel name (`Rust_Box1`).
    pub kernel_name: String,
    /// The tree-shake reference name (the `kernel.json` `"name"`).
    pub ref_name: String,
    /// The synthesised `pub fn` source.
    pub source: String,
}

/// Outcome of synthesising one generic FFI function's wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapperResult {
    /// The wrapper was synthesised.
    Emitted(EmittedWrapper),
    /// An unmodellable declared bound — a first-class rejection.
    Rejected(Diagnostic),
    /// An unsound closure shape — silently not bound, reason recorded.
    Dropped {
        /// The tree-shake reference name of the dropped binding.
        ref_name: String,
        /// Why the shape is unsound.
        reason: ClosureDropReason,
    },
}

/// Synthesise wrappers for every generic function in a package's binding
/// list; emitted sources and rejection diagnostics are collected separately
/// (a [`WrapperResult::Dropped`] is neither).
#[must_use]
pub fn synthesise_generic_wrappers(
    kernel_name: &str,
    fns: &[FnInfo],
) -> (Vec<EmittedWrapper>, Vec<Diagnostic>) {
    let mut emitted = Vec::new();
    let mut rejected = Vec::new();
    for f in fns {
        match synthesise_generic_wrapper(kernel_name, f) {
            Some(WrapperResult::Emitted(w)) => emitted.push(w),
            Some(WrapperResult::Rejected(d)) => rejected.push(d),
            Some(WrapperResult::Dropped { .. }) | None => {}
        }
    }
    (emitted, rejected)
}

/// Synthesise ONE generic wrapper from a binding's validated call AST.
///
/// `None` for a non-generic binding. The AST *is* the structure — there is
/// no string template, so an ill-placed hole is unrepresentable and the
/// only rejection left is an unmodellable declared bound.
#[must_use]
pub fn synthesise_generic_wrapper(kernel_name: &str, f: &FnInfo) -> Option<WrapperResult> {
    let g = f.generic()?;
    let ref_name = f.wrapper_ref_name();
    // An unsound closure shape is dropped before any bound-modellability
    // pass (it is not worth one).
    if let Some(reason) = g.call.arg_types().iter().find_map(closure_drop_reason) {
        return Some(WrapperResult::Dropped { ref_name, reason });
    }
    // Any declared bound outside the modellable table → reject loudly.
    for p in &g.params {
        for bound in g.bounds.get(p).into_iter().flatten() {
            if !modellable_trait(bound) {
                return Some(WrapperResult::Rejected(Diagnostic::GenericNotBindable {
                    callee: ref_name,
                    defect: GenericBindDefect::UnmodellableBound {
                        param: p.clone(),
                        bound: bound.clone(),
                    },
                }));
            }
        }
    }
    let base_name = wrapper_fn_ident(kernel_name, &ref_name);
    let source = render_generic_wrapper(&base_name, g);
    Some(WrapperResult::Emitted(EmittedWrapper {
        kernel_name: kernel_name.to_owned(),
        ref_name,
        source,
    }))
}

/// Whether a slot is a serde-reduced value (owned or `&T` input) — both take
/// the same wrapper shape: an Ipê `String` param plus a `from_str` prelude
/// binding the owned `sv_j` local (they diverge only at the call site).
const fn is_serde_slot(at: &ArgTypeRef) -> bool {
    matches!(
        at,
        ArgTypeRef::Inner(InnerTypeRef::SerdeValue | InnerTypeRef::SerdeValueRef)
    )
}

fn is_result_ctor(t: &InnerTypeRef) -> bool {
    matches!(
        t,
        InnerTypeRef::Ctor(nm, args)
            if args.len() == 2
                && (nm.as_str() == "::core::result::Result"
                    || nm.as_str() == "::std::result::Result"
                    || nm.as_str() == "Result")
    )
}

/// The element type of a host `Option<T>` node, or `None`. The inspector maps
/// an Ipê `Maybe` slot to an `Option` ctor (bare or fully-qualified); the Ipê
/// carrier `IpeMaybe` is what the backend forwarder actually passes/expects, so
/// this drives the boundary coercion at both param and return positions —
/// mirroring the flat tier (`bindings.rs`). A path-qualified inner keeps its
/// nesting (`Option<Vec<String>>` → `T = Vec<String>`).
fn option_inner(t: &InnerTypeRef) -> Option<&InnerTypeRef> {
    match t {
        InnerTypeRef::Ctor(nm, args)
            if args.len() == 1
                && (nm.as_str() == "::core::option::Option"
                    || nm.as_str() == "::std::option::Option"
                    || nm.as_str() == "Option") =>
        {
            args.first()
        }
        _ => None,
    }
}

fn vec_inner(t: &InnerTypeRef) -> Option<&InnerTypeRef> {
    match t {
        InnerTypeRef::Ctor(nm, args)
            if args.len() == 1
                && (nm.as_str() == "::std::vec::Vec"
                    || nm.as_str() == "::alloc::vec::Vec"
                    || nm.as_str() == "Vec") =>
        {
            args.first()
        }
        _ => None,
    }
}

/// Lift the host OK shape (bound to `val`) into its Ipê-facing carrier,
/// COMPOSITIONALLY: serde re-serialises to JSON text (total — Value's
/// `Serialize` never errs), numerics widen saturating, `Option` folds into
/// `IpeMaybe`, `Vec` maps element-wise, everything else passes through. The
/// recursion is what keeps a container-nested serde/numeric OK
/// (`Option<serde_json::Value>`, `Vec<serde_json::Value>`) in agreement with
/// the `.ipei` surface — a raw inner `serde_json::Value` here would be
/// exit-0-then-cargo-fail against the forwarder. Returns the declared Rust
/// carrier and the lift expression.
fn ok_ref_lift(ok: &InnerTypeRef, params: &[String], val: &str) -> (String, String) {
    if matches!(ok, InnerTypeRef::SerdeValue | InnerTypeRef::SerdeValueRef) {
        return (
            "String".to_owned(),
            format!("serde_json::to_string(&({val})).unwrap_or_default()"),
        );
    }
    if let InnerTypeRef::Prim(w) = ok
        && let Some(nw) = NumWidth::parse(w.as_str()).filter(|n| !n.is_carrier())
    {
        let widen = num_widen_scalar(nw, val);
        return (widen.carrier.to_owned(), widen.expr);
    }
    if let Some(inner) = option_inner(ok) {
        let (decl, expr) = ok_ref_lift(inner, params, "x");
        return (
            format!("IpeMaybe<{decl}>"),
            format!(
                "match {val} {{ Some(x) => IpeMaybe::Just({expr}), None => IpeMaybe::Nothing }}"
            ),
        );
    }
    if let Some(inner) = vec_inner(ok) {
        let (decl, expr) = ok_ref_lift(inner, params, "x");
        if expr == "x" {
            return (format!("Vec<{decl}>"), val.to_owned());
        }
        return (
            format!("Vec<{decl}>"),
            format!("{val}.into_iter().map(|x| {expr}).collect::<Vec<_>>()"),
        );
    }
    (ok.render(params), val.to_owned())
}

/// The generic-param indices that appear as a BORROWED argument inside a
/// by-ref closure slot. Each reaches the owned-clone bridge's `.clone()` on
/// a `&A`, so the wrapper must FORCE `+ Clone` onto that param even when the
/// host fn declares no such bound — the bridge author owns the Clone
/// obligation. Sound and complete: every concrete type reaching a call site
/// maps to a closed Rust type that IS Clone (the capture allowlist), so
/// forcing Clone never rejects a real call.
fn borrowed_closure_param_idxs(call: &Call) -> BTreeSet<usize> {
    call.arg_types()
        .iter()
        .filter_map(|at| match at {
            ArgTypeRef::Closure {
                by_ref: true,
                arg_types,
                ..
            } => Some(arg_types),
            _ => None,
        })
        .flatten()
        .filter_map(|t| match t {
            InnerTypeRef::Param(i) => Some(*i),
            _ => None,
        })
        .collect()
}

#[allow(clippy::too_many_lines)] // one linear render mirroring the ported synthesiser; splitting would scatter the body-shape decision table
fn render_generic_wrapper(base_name: &str, g: &GenericFn) -> String {
    let call = &g.call;
    let params = &g.params;
    let arity = call.arity();
    let is_async = call.is_async();
    let has_closure_arg = call
        .arg_types()
        .iter()
        .any(|at| matches!(at, ArgTypeRef::Closure { .. }));
    // Serde slots get the deserialise prelude — except the RECEIVER slot:
    // Ipê passes the Value HANDLE there (the call site uses the raw argN), so
    // a prelude would be both ill-typed and unused.
    let recv_arg_idx = call.receiver().map(|r| r.arg);
    let serde_arg_idxs: Vec<usize> = call
        .arg_types()
        .iter()
        .enumerate()
        .filter(|&(j, at)| is_serde_slot(at) && Some(j) != recv_arg_idx)
        .map(|(j, _)| j)
        .collect();
    // Slots whose host type is `Option<T>`: the wrapper declares the Ipê
    // carrier `IpeMaybe<T>` and a prelude shadows the binding to the host
    // `Option<T>` before the call — the param-side mirror of the flat tier.
    let maybe_arg_idxs: Vec<usize> = call
        .arg_types()
        .iter()
        .enumerate()
        .filter(|&(j, at)| {
            Some(j) != recv_arg_idx
                && matches!(at, ArgTypeRef::Inner(t) if option_inner(t).is_some())
        })
        .map(|(j, _)| j)
        .collect();
    // The host return shape: a `Result<Ok, Err>` ctor means a fallible host;
    // the OK arm carries the value the Ipê surface returns.
    let ret_is_result = is_result_ctor(call.ret());
    let ok_ref = match call.ret() {
        InnerTypeRef::Ctor(_, args) if ret_is_result => args
            .first()
            .cloned()
            .unwrap_or_else(|| InnerTypeRef::Prim(RustTypeExpr::unit())),
        other => other.clone(),
    };
    let (ret_inner, ok_lift) = ok_ref_lift(&ok_ref, params, "v");
    let body_call = call.render_body(params);
    // <T: bound + …> per param; bare param when unbounded. A param borrowed
    // inside a by-ref closure slot gets `+ Clone` forced (deduped against a
    // source-declared Clone).
    let forced_clone = borrowed_closure_param_idxs(call);
    let mut decls: Vec<String> = params
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let mut paths: Vec<&'static str> = g
                .bounds
                .get(p)
                .into_iter()
                .flatten()
                .filter_map(|b| trait_to_rust_path(b))
                .collect();
            if forced_clone.contains(&i) && !paths.contains(&CLONE_PATH) {
                paths.push(CLONE_PATH);
            }
            if paths.is_empty() {
                mangle_tvar(p)
            } else {
                format!("{}: {}", mangle_tvar(p), paths.join(" + "))
            }
        })
        .collect();
    decls.extend(call.closure_bounds(params));
    let generics = if decls.is_empty() {
        String::new()
    } else {
        format!("<{}>", decls.join(", "))
    };
    // A `&mut self` receiver threads through UFCS as `&mut argJ`, which
    // needs the binding declared `mut`.
    let mut_arg_idx = call
        .receiver()
        .filter(|r| r.by == ByKind::RefMut)
        .map(|r| r.arg);
    let param_decl = if arity == 0 {
        "_: ()".to_owned()
    } else {
        let parts: Vec<String> = (0..arity)
            .map(|j| {
                // A serde value-arg's wrapper param is the Ipê-facing String
                // (JSON text); the prelude binds the deserialised local. A
                // `Maybe` slot declares the Ipê carrier `IpeMaybe<T>`; its
                // prelude adapts to the host `Option<T>`.
                let ty = if serde_arg_idxs.contains(&j) {
                    "String".to_owned()
                } else if maybe_arg_idxs.contains(&j) {
                    let inner = match call.arg_types().get(j) {
                        Some(ArgTypeRef::Inner(t)) => option_inner(t),
                        _ => None,
                    };
                    inner.map_or_else(
                        || call.render_arg_type_at(params, j),
                        |el| format!("IpeMaybe<{}>", el.render(params)),
                    )
                } else {
                    call.render_arg_type_at(params, j)
                };
                let binder = if Some(j) == mut_arg_idx {
                    format!("mut arg{j}")
                } else {
                    format!("arg{j}")
                };
                format!("{binder}: {ty}")
            })
            .collect();
        parts.join(", ")
    };
    let serde_prelude: Vec<String> = serde_arg_idxs
        .iter()
        .map(|j| {
            format!(
                "let sv_{j}: serde_json::Value = match \
                 serde_json::from_str::<serde_json::Value>(&arg{j}) \
                 {{ Ok(v) => v, Err(e) => return IpeResult::Err(ipe_error_from_foreign(e)), }};"
            )
        })
        .collect();
    // Shadow each `Maybe` arg with its host `Option`, using the single-SSOT
    // runtime helper (the flat tier's param bridge). `render_body` then names
    // the shadowed binding, so it needs no change.
    let maybe_prelude: Vec<String> = maybe_arg_idxs
        .iter()
        .map(|j| format!("let arg{j} = ipe_maybe_to_option(arg{j});"))
        .collect();
    let wrapper_ret = if is_async {
        format!("IpeTask<{ret_inner}>")
    } else {
        format!("IpeResult<IpeError, {ret_inner}>")
    };
    // A closure-carrying wrapper's panic most likely originated in the Ipê
    // closure the host invoked — say so.
    let panic_msg = if has_closure_arg {
        "an Ipê closure passed to FFI panicked"
    } else {
        "foreign call panicked"
    };
    let body: Vec<String> = if is_async {
        // The async panic boundary is the spawned task's JoinError; the
        // serde prelude lives INSIDE the async block so its early `return`
        // exits the future, not the IpeTask-returning fn.
        let mut lines = vec!["    Box::pin(async move {".to_owned()];
        lines.extend(serde_prelude.iter().map(|p| format!("        {p}")));
        // The Maybe→Option shadow runs before the spawn so the spawned
        // `async move` captures the host `Option`, not the Ipê carrier.
        lines.extend(maybe_prelude.iter().map(|p| format!("        {p}")));
        // The spawn + cancel-guard + join-error funnel is `ffi_spawn_guarded` —
        // arming the `AbortOnDrop` and folding a poll-time panic to the redacted
        // funnel are its indivisible job, so this shape cannot spawn unguarded.
        // A non-panic `JoinError` is already the funnelled `Err`; only the
        // success value needs the shape's own lift.
        if ret_is_result {
            lines.push(format!(
                "        match ffi_spawn_guarded(async move {{ {body_call}.await }}).await \
                 {{ Ok(Ok(v)) => ok_res({ok_lift}), Ok(Err(e)) => \
                 IpeResult::Err(ipe_error_from_foreign(e)), Err(e) => \
                 IpeResult::Err(e) }}"
            ));
        } else {
            lines.push(format!(
                "        match ffi_spawn_guarded(async move {{ {body_call}.await }}).await \
                 {{ Ok(v) => ok_res({ok_lift}), Err(e) => \
                 IpeResult::Err(e) }}"
            ));
        }
        lines.push("    })".to_owned());
        lines
    } else {
        // Sync: the foreign call runs inside catch_unwind so a foreign (or
        // Ipê-closure) panic becomes a typed Err, never a process unwind
        // across the boundary.
        let mut lines: Vec<String> = serde_prelude.iter().map(|p| format!("    {p}")).collect();
        lines.extend(maybe_prelude.iter().map(|p| format!("    {p}")));
        if ret_is_result {
            lines.push(format!(
                "    match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(move || \
                 {body_call})) {{ Ok(Ok(v)) => ok_res({ok_lift}), Ok(Err(e)) => \
                 IpeResult::Err(ipe_error_from_foreign(e)), Err(__p) => \
                 IpeResult::Err(ipe_error_from_panic(\"{panic_msg}\", __p)) }}"
            ));
        } else {
            lines.push(format!(
                "    match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(move || \
                 {body_call})) {{ Ok(v) => ok_res({ok_lift}), Err(__p) => \
                 IpeResult::Err(ipe_error_from_panic(\"{panic_msg}\", __p)) }}"
            ));
        }
        lines
    };
    let mut lines = vec![
        format!("// [ffi-generic] {base_name} <{}>", params.join(", ")),
        format!("pub fn {base_name}{generics}({param_decl}) -> {wrapper_ret} {{"),
    ];
    lines.extend(body);
    lines.push("}".to_owned());
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ty_int() -> InstanceTy {
        InstanceTy::con("Int")
    }

    fn ty_list(el: InstanceTy) -> InstanceTy {
        InstanceTy::Con {
            name: "List".into(),
            args: vec![el],
        }
    }

    fn ty_maybe(el: InstanceTy) -> InstanceTy {
        InstanceTy::Con {
            name: "Maybe".into(),
            args: vec![el],
        }
    }

    /// The emitted wrapper, or a test failure for any other outcome.
    fn emitted(r: Option<WrapperResult>) -> EmittedWrapper {
        match r {
            Some(WrapperResult::Emitted(w)) => Some(w),
            _ => None,
        }
        .expect("expected an emitted wrapper")
    }

    /// A generic binding decoded through the real `PkgInfo` gate.
    fn generic_fn_of(fn_json: &serde_json::Value) -> FnInfo {
        let pkg = crate::pkginfo::PkgInfo::decode_json(
            &json!({
                "pkg": "box1",
                "name": "box1",
                "functions": [fn_json],
                "errors": []
            })
            .to_string(),
        )
        .expect("decodes");
        pkg.fns().first().expect("one binding").clone()
    }

    // ── MODELLABLE_5 two-way drift fence ────────────────────────────────

    /// If the inspector's `MODELLABLE_5` and this module's set ever diverge,
    /// this test fails — either side changing alone breaks CI, never a
    /// user's cargo build. Reads the inspector source directly (it is a
    /// separate de-workspaced crate, so a code-level import is impossible).
    #[test]
    fn modellable_5_matches_the_inspector_declaration() {
        let inspector_src = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tools/ipe-ffi-inspector/src/model.rs"
        );
        let src = std::fs::read_to_string(inspector_src)
            .expect("inspector source must exist for the drift fence");
        let decl_line = src
            .lines()
            .find(|l| l.contains("const MODELLABLE_5:"))
            .expect("inspector must declare MODELLABLE_5");
        let inspector_set: Vec<&str> = decl_line.split('"').skip(1).step_by(2).collect();
        assert_eq!(
            inspector_set,
            MODELLABLE_5.to_vec(),
            "inspector MODELLABLE_5 and ipe_ffi::instance::MODELLABLE_5 diverged"
        );
    }

    #[test]
    fn modellable_trait_is_exactly_the_five() {
        for t in MODELLABLE_5 {
            assert!(modellable_trait(t), "{t} must be modellable");
        }
        for t in ["Serialize", "Debug", "Send", "Sync", "PartialEq", ""] {
            assert!(!modellable_trait(t), "{t} must not be modellable");
        }
    }

    // ── closed-set mapper ───────────────────────────────────────────────

    #[test]
    fn closed_set_maps_primitives_and_recursive_containers() {
        assert_eq!(ipe_type_to_rust_closed(&ty_int()), Ok("i64".to_owned()));
        assert_eq!(
            ipe_type_to_rust_closed(&InstanceTy::con("String")),
            Ok("String".to_owned())
        );
        assert_eq!(
            ipe_type_to_rust_closed(&InstanceTy::Unit),
            Ok("()".to_owned())
        );
        assert_eq!(
            ipe_type_to_rust_closed(&ty_list(ty_maybe(InstanceTy::con("Float")))),
            Ok("Vec<IpeMaybe<f64>>".to_owned())
        );
    }

    #[test]
    fn closed_set_rejects_everything_else_with_a_named_violation() {
        assert_eq!(
            ipe_type_to_rust_closed(&InstanceTy::Var("a".into())),
            Err(ClosedSetViolation::UnresolvedTypeVariable("a".into()))
        );
        assert_eq!(
            ipe_type_to_rust_closed(&InstanceTy::con("Version")),
            Err(ClosedSetViolation::NonClosedConstructor("Version".into()))
        );
        assert_eq!(
            ipe_type_to_rust_closed(&InstanceTy::Record),
            Err(ClosedSetViolation::RecordType)
        );
        assert_eq!(
            ipe_type_to_rust_closed(&InstanceTy::Function),
            Err(ClosedSetViolation::FunctionType)
        );
        // A List of a non-closed element is itself non-closed.
        assert_eq!(
            ipe_type_to_rust_closed(&ty_list(InstanceTy::con("Version"))),
            Err(ClosedSetViolation::NonClosedConstructor("Version".into()))
        );
    }

    // ── static trait table ──────────────────────────────────────────────

    #[test]
    fn trait_table_cells_match_runtime_and_std_derives() {
        let all: BTreeSet<&str> = MODELLABLE_5.into_iter().collect();
        for t in ["i64", "String", "bool", "char", "()"] {
            assert_eq!(traits_of_rust_type(t), all, "{t}");
        }
        // IEEE-754: floats are Clone + Default only — the security cell.
        let floats: BTreeSet<&str> = ["Clone", "Default"].into_iter().collect();
        assert_eq!(traits_of_rust_type("f64"), floats);
        assert_eq!(traits_of_rust_type("f32"), floats);
        // Vec<T>: Default always; the rest conditional on T.
        assert_eq!(traits_of_rust_type("Vec<i64>"), all);
        assert_eq!(traits_of_rust_type("Vec<f64>"), floats);
        // IpeMaybe<T>: Clone iff T: Clone, nothing else (runtime derive).
        let clone_only = BTreeSet::from(["Clone"]);
        assert_eq!(traits_of_rust_type("IpeMaybe<String>"), clone_only);
        assert_eq!(traits_of_rust_type("IpeMaybe<f64>"), clone_only);
        // Vec<IpeMaybe<T>>: Default from Vec + Clone from the element.
        let clone_default: BTreeSet<&str> = ["Clone", "Default"].into_iter().collect();
        assert_eq!(traits_of_rust_type("Vec<IpeMaybe<i64>>"), clone_default);
        // Unknown types satisfy nothing.
        assert!(traits_of_rust_type("Version").is_empty());
    }

    // ── per-instance bindability check ──────────────────────────────────

    fn hash_eq_generic() -> GenericFn {
        generic_fn_of(&json!({
            "name": "make",
            "effect": "pure",
            "generic": {
                "params": ["a"],
                "bounds": {"a": ["Hash", "Eq"]},
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
        }))
        .generic()
        .expect("generic block")
        .clone()
    }

    #[test]
    fn instance_check_passes_a_hashable_arg_and_rejects_a_float() {
        let g = hash_eq_generic();
        let ok = FfiInstance {
            callee: "Rust.Box1.make",
            types: &[ty_int()],
            generic: &g,
        };
        assert!(check_instance(&ok).is_empty());

        let float = [InstanceTy::con("Float")];
        let bad = FfiInstance {
            callee: "Rust.Box1.make",
            types: &float,
            generic: &g,
        };
        let diags = check_instance(&bad);
        // Float fails BOTH declared bounds (Hash and Eq) — one each.
        assert_eq!(diags.len(), 2, "{diags:?}");
        assert!(matches!(
            diags.first(),
            Some(Diagnostic::GenericNotBindable {
                callee,
                defect: GenericBindDefect::BoundUnsatisfied { param, rust_ty, bound, .. },
            }) if callee == "Rust.Box1.make" && param == "a" && rust_ty == "f64" && bound == "Hash"
        ));
    }

    #[test]
    fn instance_check_rejects_a_non_closed_arg_without_double_reporting() {
        let g = hash_eq_generic();
        let opaque = [InstanceTy::con("Version")];
        let inst = FfiInstance {
            callee: "Rust.Box1.make",
            types: &opaque,
            generic: &g,
        };
        let diags = check_instance(&inst);
        // Closed-set violation only — bounds are not re-checked on a
        // non-mappable arg.
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert!(matches!(
            diags.first(),
            Some(Diagnostic::GenericNotBindable {
                defect: GenericBindDefect::OutsideClosedSet { violation, .. },
                ..
            }) if *violation == ClosedSetViolation::NonClosedConstructor("Version".into())
        ));
    }

    #[test]
    fn instance_check_rejects_an_unmodellable_declared_bound() {
        let f = generic_fn_of(&json!({
            "name": "store",
            "effect": "pure",
            "generic": {
                "params": ["a"],
                "bounds": {"a": ["Serialize"]},
                "call": {
                    "kind": "function",
                    "path": ["::box1"],
                    "method": "store",
                    "args": [0],
                    "argTypes": [{"param": 0}],
                    "ret": {"ctor": "()"},
                    "assocOnType": false
                }
            }
        }));
        let g = f.generic().expect("generic").clone();
        let strings = [InstanceTy::con("String")];
        let inst = FfiInstance {
            callee: "Rust.Box1.store",
            types: &strings,
            generic: &g,
        };
        let diags = check_instance(&inst);
        // Names the BOUND (String may well satisfy Serialize — the real
        // cause is the modelling limit).
        assert!(matches!(
            diags.first(),
            Some(Diagnostic::GenericNotBindable {
                defect: GenericBindDefect::UnmodellableBound { param, bound },
                ..
            }) if param == "a" && bound == "Serialize"
        ));
    }

    // ── capture gate ────────────────────────────────────────────────────

    #[test]
    fn fn_once_slots_admit_non_clone_captures_multi_call_slots_gate_them() {
        let captures = vec![("db".to_owned(), InstanceTy::con("Db"))];
        assert_eq!(
            first_non_clone_capture(ClosureKind::FnOnce, &captures),
            None
        );
        assert_eq!(
            first_non_clone_capture(ClosureKind::Fn, &captures),
            Some(("db", "Db".to_owned()))
        );
        assert_eq!(
            first_non_clone_capture(ClosureKind::FnMut, &captures),
            Some(("db", "Db".to_owned()))
        );
        let clonable = vec![
            ("n".to_owned(), ty_int()),
            ("xs".to_owned(), ty_list(InstanceTy::con("String"))),
            ("m".to_owned(), ty_maybe(InstanceTy::con("Float"))),
        ];
        assert_eq!(first_non_clone_capture(ClosureKind::Fn, &clonable), None);
        assert!(gate_closure_arg("Rust.Clo.keep", ClosureKind::Fn, &clonable).is_ok());
        let gated = gate_closure_arg("Rust.Clo.keep", ClosureKind::Fn, &captures);
        assert!(matches!(
            gated,
            Err(Diagnostic::GenericNotBindable {
                defect: GenericBindDefect::CaptureNotClone { capture, ty },
                ..
            }) if capture == "db" && ty == "Db"
        ));
    }

    // ── closure drop reasons ────────────────────────────────────────────

    fn closure_slot(kind: &str, by_ref: bool, arg: &serde_json::Value) -> ArgTypeRef {
        let f = generic_fn_of(&json!({
            "name": "each",
            "effect": "pure",
            "generic": {
                "params": ["a"],
                "call": {
                    "kind": "function",
                    "path": ["::clo"],
                    "method": "each",
                    "args": [0],
                    "argTypes": [
                        {"closure": {"kind": kind, "byRef": by_ref,
                                      "argTypes": [arg], "ret": {"prim": "bool"}}}
                    ],
                    "ret": {"ctor": "()"},
                    "assocOnType": false
                }
            }
        }));
        f.generic()
            .expect("generic")
            .call
            .arg_types()
            .first()
            .expect("slot")
            .clone()
    }

    #[test]
    fn unsound_closure_shapes_are_classified_for_drop() {
        // A by-ref FnMut slot loses writes through the owned-clone bridge.
        assert_eq!(
            closure_drop_reason(&closure_slot("FnMut", true, &json!({"param": 0}))),
            Some(ClosureDropReason::MutByRefSlot)
        );
        // A by-ref Fn slot borrowing a generic param is fine (forced Clone).
        assert_eq!(
            closure_drop_reason(&closure_slot("Fn", true, &json!({"param": 0}))),
            None
        );
        // A by-ref Fn slot borrowing a concrete non-Clone type is dropped.
        assert_eq!(
            closure_drop_reason(&closure_slot("Fn", true, &json!({"ctor": "::db::Db"}))),
            Some(ClosureDropReason::ByRefNonCloneConcrete)
        );
        // A by-ref Fn slot borrowing a provably-Clone concrete is kept.
        assert_eq!(
            closure_drop_reason(&closure_slot("Fn", true, &json!({"prim": "i64"}))),
            None
        );
        // A by-value FnOnce moves its arg — never a drop.
        assert_eq!(
            closure_drop_reason(&closure_slot("FnOnce", false, &json!({"ctor": "::db::Db"}))),
            None
        );
        // A non-closure slot is never a closure drop.
        assert_eq!(
            closure_drop_reason(&ArgTypeRef::Inner(InnerTypeRef::Prim(
                RustTypeExpr::for_test("i64")
            ))),
            None
        );
    }

    // ── wrapper synthesis ───────────────────────────────────────────────

    #[test]
    fn synthesises_the_one_generic_wrapper_with_qualified_bounds() {
        let f = generic_fn_of(&json!({
            "name": "make",
            "effect": "pure",
            "generic": {
                "params": ["a"],
                "bounds": {"a": ["Hash", "Eq"]},
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
        }));
        let w = emitted(synthesise_generic_wrapper("Rust_Box1", &f));
        assert_eq!(w.kernel_name, "Rust_Box1");
        assert_eq!(w.ref_name, "make");
        let expected = "\
// [ffi-generic] box1_make <a>\n\
pub fn box1_make<A: ::std::hash::Hash + ::std::cmp::Eq>(arg0: A) -> IpeResult<IpeError, ::box1::Box1<A>> {\n    \
match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(move || ::box1::Box1::<A>::make(arg0))) { Ok(v) => ok_res(v), Err(__p) => IpeResult::Err(ipe_error_from_panic(\"foreign call panicked\", __p)) }\n\
}\n";
        assert_eq!(w.source, expected);
    }

    #[test]
    fn non_generic_bindings_synthesise_nothing() {
        let f = generic_fn_of(&json!({"name": "plain", "effect": "pure"}));
        assert_eq!(synthesise_generic_wrapper("Rust_Box1", &f), None);
    }

    #[test]
    fn by_ref_closure_forces_clone_on_the_borrowed_param() {
        let f = generic_fn_of(&json!({
            "name": "keep",
            "effect": "pure",
            "generic": {
                "params": ["a"],
                "call": {
                    "kind": "function",
                    "path": ["::clo"],
                    "method": "keep",
                    "args": [0, 1],
                    "argTypes": [
                        {"ctor": "Vec", "args": [{"param": 0}]},
                        {"closure": {"kind": "Fn", "byRef": true,
                                      "argTypes": [{"param": 0}], "ret": {"prim": "bool"}}}
                    ],
                    "ret": {"ctor": "Vec", "args": [{"param": 0}]},
                    "assocOnType": false
                }
            }
        }));
        let w = emitted(synthesise_generic_wrapper("Rust_Clo", &f));
        // The host declares no `A: Clone`, but the owned-clone bridge needs
        // it — the wrapper forces the bound.
        assert!(
            w.source.contains(
                "pub fn clo_keep<A: ::core::clone::Clone, F1: Fn(A) -> bool + ::core::clone::Clone>"
            ),
            "{}",
            w.source
        );
        // The closure-carrying body names the likely panic origin.
        assert!(
            w.source
                .contains("ipe_error_from_panic(\"an Ipê closure passed to FFI panicked\", __p)"),
            "{}",
            w.source
        );
        assert!(
            w.source.contains("(arg0: Vec<A>, arg1: F1)"),
            "{}",
            w.source
        );
    }

    #[test]
    fn unmodellable_declared_bound_rejects_the_wrapper() {
        let f = generic_fn_of(&json!({
            "name": "store",
            "effect": "pure",
            "generic": {
                "params": ["a"],
                "bounds": {"a": ["Serialize"]},
                "call": {
                    "kind": "function",
                    "path": ["::box1"],
                    "method": "store",
                    "args": [0],
                    "argTypes": [{"param": 0}],
                    "ret": {"ctor": "()"},
                    "assocOnType": false
                }
            }
        }));
        assert!(matches!(
            synthesise_generic_wrapper("Rust_Box1", &f),
            Some(WrapperResult::Rejected(Diagnostic::GenericNotBindable {
                defect: GenericBindDefect::UnmodellableBound { .. },
                ..
            }))
        ));
    }

    #[test]
    fn unsound_closure_shape_drops_the_wrapper_with_its_reason() {
        let f = generic_fn_of(&json!({
            "name": "each_mut",
            "effect": "pure",
            "generic": {
                "params": ["a"],
                "call": {
                    "kind": "function",
                    "path": ["::clo"],
                    "method": "each_mut",
                    "args": [0],
                    "argTypes": [
                        {"closure": {"kind": "FnMut", "byRef": true,
                                      "argTypes": [{"param": 0}], "ret": {"ctor": "()"}}}
                    ],
                    "ret": {"ctor": "()"},
                    "assocOnType": false
                }
            }
        }));
        assert_eq!(
            synthesise_generic_wrapper("Rust_Clo", &f),
            Some(WrapperResult::Dropped {
                ref_name: "each_mut".into(),
                reason: ClosureDropReason::MutByRefSlot
            })
        );
        // Collected sources exclude the drop; no diagnostic either.
        let (emitted, rejected) = synthesise_generic_wrappers("Rust_Clo", std::slice::from_ref(&f));
        assert!(emitted.is_empty());
        assert!(rejected.is_empty());
    }

    #[test]
    fn async_serde_trait_method_spawns_and_reserialises() {
        let f = generic_fn_of(&json!({
            "name": "get_obj",
            "effect": "effectful",
            "recvType": "Db",
            "methodName": "get_obj",
            "generic": {
                "params": [],
                "call": {
                    "kind": "method",
                    "path": ["::db", "Db"],
                    "method": "get_obj",
                    "receiver": {"arg": 0, "by": "ref"},
                    "args": [1],
                    "argTypes": [{"ctor": "::db::Db"}, {"serdeValue": true}],
                    "ret": {"ctor": "::core::result::Result",
                            "args": [{"serdeValue": true}, {"ctor": "::std::string::String"}]},
                    "traitQualifier": ["::db::Db", "::db::Repo"],
                    "methodTurbofish": [{"serdeValue": true}],
                    "isAsync": true
                }
            }
        }));
        let w = emitted(synthesise_generic_wrapper("Rust_Db", &f));
        // The serde value-arg surfaces as an Ipê String; the receiver keeps
        // its handle type.
        assert!(
            w.source
                .contains("(arg0: ::db::Db, arg1: String) -> IpeTask<String>"),
            "{}",
            w.source
        );
        // The prelude lives INSIDE the async block.
        assert!(
            w.source
                .contains("    Box::pin(async move {\n        let sv_1:"),
            "{}",
            w.source
        );
        // Spawned through the guarded choke-point (spawn + abort-on-drop +
        // join-error funnel are its indivisible job), three-arm fallible match
        // (the funnelled JoinError rides the trailing `Err(e)` arm), serde OK
        // re-serialised.
        assert!(
            w.source.contains(
                "match ffi_spawn_guarded(async move { <::db::Db as ::db::Repo>::get_obj::<serde_json::Value>(&arg0, sv_1).await }).await { Ok(Ok(v)) => ok_res(serde_json::to_string(&(v)).unwrap_or_default()), Ok(Err(e)) => IpeResult::Err(ipe_error_from_foreign(e)), Err(e) => IpeResult::Err(e) }"
            ),
            "{}",
            w.source
        );
    }

    #[test]
    fn maybe_slot_param_takes_ipe_maybe_and_adapts_to_option() {
        // A synthesised closed-instance wrapper whose host takes `Option<…>`
        // params and returns `Option<…>` must speak the Ipê carrier `IpeMaybe`
        // at BOTH boundaries — the backend forwarder passes `IpeMaybe`, so a
        // raw `Option` sig is exit-0-then-cargo-fail (E0308). Mirrors the
        // `update_obj…` shape (`Maybe (List String)` arg) that reaches this
        // renderer once skyshop calls it.
        let f = generic_fn_of(&json!({
            "name": "update_obj",
            "effect": "effectful",
            "recvType": "Db",
            "methodName": "update_obj",
            "generic": {
                "params": [],
                "call": {
                    "kind": "method",
                    "path": ["::db", "Db"],
                    "method": "update_obj",
                    "receiver": {"arg": 0, "by": "ref"},
                    "args": [1, 2],
                    "argTypes": [
                        {"ctor": "::db::Db"},
                        {"ctor": "Option", "args": [{"ctor": "String"}]},
                        {"ctor": "Option", "args": [{"ctor": "Vec", "args": [{"ctor": "String"}]}]}
                    ],
                    "ret": {"ctor": "::core::result::Result",
                            "args": [{"ctor": "Option", "args": [{"ctor": "String"}]},
                                     {"ctor": "::std::string::String"}]},
                    "traitQualifier": ["::db::Db", "::db::Repo"],
                    "isAsync": true
                }
            }
        }));
        let w = emitted(synthesise_generic_wrapper("Rust_Db", &f));
        // Param sig carries the Ipê carrier at both slots (nested container
        // preserved: `IpeMaybe<Vec<String>>`).
        assert!(
            w.source
                .contains("(arg0: ::db::Db, arg1: IpeMaybe<String>, arg2: IpeMaybe<Vec<String>>)"),
            "{}",
            w.source
        );
        // Return type lifts to the carrier.
        assert!(
            w.source.contains("-> IpeTask<IpeMaybe<String>>"),
            "{}",
            w.source
        );
        // Adapt prelude shadows each Maybe arg to the host `Option` via the
        // single-SSOT runtime helper, BEFORE the spawned call.
        assert!(
            w.source.contains("let arg1 = ipe_maybe_to_option(arg1);"),
            "{}",
            w.source
        );
        assert!(
            w.source.contains("let arg2 = ipe_maybe_to_option(arg2);"),
            "{}",
            w.source
        );
        // The OK lift wraps the host `Option` back into `IpeMaybe`.
        assert!(
            w.source.contains(
                "Ok(Ok(v)) => ok_res(match v { Some(x) => IpeMaybe::Just(x), None => IpeMaybe::Nothing })"
            ),
            "{}",
            w.source
        );
    }

    #[test]
    fn ref_mut_receiver_binds_the_arg_mut_and_numeric_ok_widens() {
        let f = generic_fn_of(&json!({
            "name": "bump",
            "effect": "pure",
            "recvType": "Counter",
            "methodName": "bump",
            "generic": {
                "params": [],
                "call": {
                    "kind": "method",
                    "path": ["::ctr", "Counter"],
                    "method": "bump",
                    "receiver": {"arg": 0, "by": "refmut"},
                    "args": [],
                    "argTypes": [{"ctor": "::ctr::Counter"}],
                    "ret": {"prim": "u32"}
                }
            }
        }));
        let w = emitted(synthesise_generic_wrapper("Rust_Ctr", &f));
        assert!(
            w.source
                .contains("(mut arg0: ::ctr::Counter) -> IpeResult<IpeError, i64>"),
            "{}",
            w.source
        );
        // The u32 OK value widens to the carrier inside the match arm.
        assert!(w.source.contains("ok_res((v) as i64)"), "{}", w.source);
    }
}
