//! Capture-clone classification and rewrite subsystem.
//!
//! Classifies every [`IrType`] as `CopyLeaf`, `CloneOk`, or `NonClone` for the
//! two capture-clone rewrites that make closures `Fn` (not `FnOnce`):
//!
//! * T3 — `rewrite_captured_clones`: inserts `.clone()` at closure-capture
//!   boundaries.
//! * T5 — `rewrite_multiuse_clones`: inserts `.clone()` on all but the last
//!   consuming occurrence of a `CloneOk`/`Generic` binding.
//!
//! Entry point from [`super::Lowerer`]: [`super::Lowerer::clone_env`] builds the
//! [`CloneEnv`] context; the rewrite fns are called with it.

use std::collections::BTreeSet;

use ipe_diagnostics::{DResult, Feature, Span};
use ipe_intern::{Interner, Symbol};
use ipe_ir::{EnumPayloadTable, Expr, IrType, ModPath, Pat, enum_payload_holds};

use super::capture_rewrite::force_shared_capture_clones;

// ── Capture-clone classification ──────────────────────────────────────
//
// Classifies an `IrType` for the capture-clone rewrite that makes closures
// `Fn` (not `FnOnce`). Rules:
//   CopyLeaf  — scalar types that are `Copy`; reads are bare moves (copies).
//   CloneOk   — types that derive `Clone` in the runtime; reads inside closures
//               must use `{name}.clone()` so the closure is re-callable.
//   NonClone  — types that do NOT implement `Clone` (functions, tasks, decoders,
//               server opaques, …); capturing one in a non-callee position is
//               a IPE-L0125 diagnostic.
//
// This is conservative: when unsure → `NonClone` (fail-closed, never a
// silent cargo failure).

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum CloneClass {
    CopyLeaf,
    CloneOk,
    NonClone,
}

/// Is `home` an FFI foreign-interface module (`Rust.*`)? An [`IrType::Enum`]
/// under such a home is an opaque handle onto the real foreign Rust type, whose
/// `Clone`-ness is the foreign crate's decision — not Ipe's — so it is treated
/// as non-`Clone` for the multi-use clone rewrite. Mirrors the backend's
/// `is_foreign_interface_home` (`ipe_backend_rust` `lib.rs`).
pub(super) fn enum_home_is_ffi_foreign(interner: &Interner, home: &ModPath) -> bool {
    home.0
        .first()
        .and_then(|s| interner.resolve(*s))
        .is_some_and(|s| s == "Rust")
}

/// The clone-classification context.
///
/// Carries the interner, the `Rust.*`-home unions that are TRANSPARENT FFI
/// imports, and the program's enum payload table. A transparent union lowers
/// to a real app enum (deriving `Clone` like any user enum); only the
/// REMAINING `Rust.*`-home enums are opaque handles onto real foreign types.
/// The payload table lets a user enum's class see the value types its
/// variants hold — the same table the backend's enum-`Clone` fixpoint reads.
#[derive(Clone, Copy)]
pub(super) struct CloneEnv<'a> {
    pub(super) interner: &'a Interner,
    pub(super) transparent_ffi: &'a BTreeSet<(ModPath, Symbol)>,
    pub(super) payloads: &'a EnumPayloadTable,
}

/// Is `(home, name)` an OPAQUE FFI foreign handle — a `Rust.*`-home enum that
/// is not a transparent import?
pub(super) fn enum_is_opaque_ffi_handle(env: CloneEnv<'_>, home: &ModPath, name: Symbol) -> bool {
    enum_home_is_ffi_foreign(env.interner, home)
        && !env.transparent_ffi.contains(&(home.clone(), name))
}

/// Is `t` a leaf whose presence in an enum payload makes the enum non-`Clone`?
///
/// Leaves defer to [`ipe_ir::payload_leaf_is_clone`] — the one leaf rule the
/// backend's enum-`Clone` fixpoint applies to payload fields — plus opaque FFI
/// handles. Transparent carriers answer `false` because the payload walk
/// descends into them itself.
fn payload_leaf_is_nonclone(env: CloneEnv<'_>, t: &IrType) -> bool {
    match t {
        IrType::Enum { home, name, .. } => enum_is_opaque_ffi_handle(env, home, *name),
        IrType::Maybe(_)
        | IrType::List(_)
        | IrType::Set(_)
        | IrType::Result(_, _)
        | IrType::Dict(_, _)
        | IrType::Tuple(_)
        | IrType::Record(_)
        | IrType::Ui { .. }
        | IrType::WebRoute(_) => false,
        other => !ipe_ir::payload_leaf_is_clone(other),
    }
}

pub(super) fn clone_class(env: CloneEnv<'_>, t: &IrType) -> CloneClass {
    match t {
        // Scalars — primitive Copy types.
        // `Decimal` is `#[derive(Copy)]` — treat as CopyLeaf.
        // StreamWriter is `#[derive(Clone, Copy)]` — an i64 id wrapper
        // (server_stream.rs:38). Bare capture is sound.
        // `WsHandle` is `#[derive(Clone, Copy)]` — an i64 id wrapper.
        IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Char
        | IrType::Unit
        | IrType::BackoffStrategy
        | IrType::Order
        | IrType::HttpMethod
        | IrType::Decimal
        | IrType::ErrorKind
        | IrType::StreamWriter
        | IrType::WebSocketServer => CloneClass::CopyLeaf,
        // Runtime-verified Clone types.
        // Str(String), Bytes(Vec<u8>), Json(serde_json::Value), Db(Arc-backed),
        // UiPlain (element.rs derives Clone), WebReq (req.rs derives Clone).
        // Error: IpeError derives Clone (not Copy — carries a heap `String`).
        // ErrorDetails: IpeErrorDetails derives Clone (not Copy — carries
        // heap-allocated `String`/`Vec<String>` payloads).
        // `SqlFragment` is `#[derive(Clone, PartialEq)]` (no Copy — carries a
        // heap-allocated `String` + `Vec<SqlParam>`).
        // `Secret` is `#[derive(Clone)]` (no Copy — carries a heap-allocated
        // `String`; hand-written `PartialEq`, not derived — see its own doc).
        // `Path` is `#[derive(Clone)]` (no Copy — carries a heap-allocated
        // cleaned `String`; `PartialEq`/`Eq` derived — a path is not a secret).
        // The nominal error-payload types derive Clone (not Copy — each
        // carries heap-allocated `String`s; SEAL fix).
        // Runtime-verified Clone server/http opaques (audited):
        // ServerRequest/ServerResponse/ServerCookie (server.rs:33/50/59),
        // ServerRoute (server.rs:136), HttpRequest (http_client.rs:64) all
        // `#[derive(Clone, …)]`.
        // `WsServerCfg` holds Arc<dyn Fn> callbacks — Clone via Arc.
        IrType::Str
        | IrType::Bytes
        | IrType::Json
        | IrType::Db
        | IrType::UiPlain(_)
        | IrType::WebReq
        | IrType::SessionHandle
        // The widget handle carries only a `String` tag — `#[derive(Clone)]`,
        // its Clone-ness independent of the (unstored) seal args.
        | IrType::CustomElement { .. }
        | IrType::Error
        | IrType::ErrorDetails
        | IrType::ErrorInfo
        | IrType::PanicInfo
        | IrType::TypeInfo
        | IrType::SqlFragment
        | IrType::Secret
        | IrType::Path
        // `Url` is `#[derive(Clone)]` (no Copy — a newtype over `url::Url`,
        // itself a heap-`String`-backed type; `PartialEq`/`Eq` derived).
        | IrType::Url
        // `Relative` is `#[derive(Clone)]` (validated `String` projection fields).
        | IrType::UrlRelative
        | IrType::Dsn
        | IrType::Connection
        | IrType::ConnReadOnly
        | IrType::ConnReadWrite
        | IrType::Setting
        | IrType::ShapeWeb
        | IrType::ShapeWebView
        | IrType::ShapeTerminal
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        | IrType::HttpRequest
        // `Regex` is `#[derive(Clone)]` (no Copy — wraps an `Arc<regex::Regex>`).
        | IrType::Regex
        | IrType::WebSocketServerCfg
        // Process-run-with cfg + Cache config / stats + Csv document runtime
        // structs are `Clone` (no `Copy`).
        | IrType::ProcessRunWithCfg
        | IrType::ProcessRunInPtyCfg
        | IrType::CacheCfg
        | IrType::WebSocketClientCfg
        | IrType::CacheStats
        | IrType::CsvDoc
        // Ipe.Email runtime structs + provider enum are `Clone` (no `Copy`).
        | IrType::EmailMessage
        | IrType::EmailAttachment
        | IrType::EmailSesConfig
        | IrType::EmailSmtpConfig
        | IrType::EmailProvider
        // Typed-key newtypes are `Clone` (no `Copy` — carry heap-allocated Strings).
        | IrType::CryptoKey
        | IrType::CryptoMac
        | IrType::EmailAddress
        // `Locale` wraps a `String` — `Clone` but not `Copy`.
        | IrType::Locale
        // `Principal` wraps a `String` — `Clone` but not `Copy`.
        | IrType::Principal
        // `AuthConfig` / `TokenSource` derive `Clone` — `CloneOk`.
        | IrType::AuthConfig
        | IrType::TokenSource
        // The promoted `Arc<dyn Fn>` carrier is `Clone` (a refcount bump), so a
        // `SharedFun` slot is `CloneOk` — this is what lets a composite carrying
        // it become clonable and so reusable.
        | IrType::SharedFun(_, _)
        // The runtime `Decoder<E, T>` carries `run : Arc<dyn Fn + Send + Sync>`
        // with a hand-written unconditional `Clone`, so a `Decoder` slot is
        // `CloneOk` and never poisons its enclosing composite.
        | IrType::Decoder(_) => CloneClass::CloneOk,
        // Non-Clone: function-typed, task, Cmd, Sub.
        // Also Generic(_) until T5 (which injects `T: Clone`).
        IrType::Fun(_, _)
        // A curried `FnOnce` chain is the same boxed-closure family as `Fun` —
        // and doubly so here: it is LITERALLY consume-once by construction.
        | IrType::FnOnceChain(_, _)
        | IrType::Task(_)
        | IrType::Cmd(_)
        | IrType::Sub(_)
        | IrType::Generic(_)
        // A row variable, like a bare generic, is floored to `NonClone` here:
        // its `Clone` rides the emitted `R: … + Clone` witness bound, and every
        // field read off it emits an explicit `.clone()`, so no bare capture of
        // the whole row value relies on a `CloneOk` classification.
        | IrType::RowGeneric(_)
        // Opaque shape-app handles wrap active event loops — not Clone.
        | IrType::WebApp
        | IrType::TuiApp
        | IrType::CliApp
        | IrType::WorkerApp => CloneClass::NonClone,
        // Composite: CloneOk iff all components CloneOk (no NonClone part).
        // `Maybe`, `List`, `Set`, `Result`, `Dict` are NAMED Rust types
        // (`IpeMaybe<T>`, `Vec<T>`, `BTreeSet<T>`, `IpeResult<E,A>`,
        // `HashMap<K,V>`) — they never implement `Copy` even when every element
        // is `Copy`. Use `clone_class_named_composite` to floor `CopyLeaf` → `CloneOk`
        // so T5 inserts `.clone()` for multi-use bindings (e.g. `Vec<i64>`).
        IrType::Maybe(elem) | IrType::List(elem) | IrType::Set(elem) => {
            clone_class_named_composite(env, std::iter::once(elem.as_ref()))
        }
        IrType::Result(e, a) | IrType::Dict(e, a) => {
            clone_class_named_composite(env, [e.as_ref(), a.as_ref()].into_iter())
        }
        IrType::Tuple(elems) => clone_class_composite(env, elems.iter()),
        // Named types: emitted Rust struct/enum derives `Clone` but NOT `Copy`.
        // A CopyLeaf payload (e.g. all-Int record, no-arg enum) does NOT make the
        // wrapper `Copy` — bare capture would move it on first closure call → E0525.
        // Floor to CloneOk so the rewrite inserts `.clone()` per call.
        IrType::Record(fields) => clone_class_named_composite(env, fields.values()),
        IrType::Enum { home, name, args } => enum_clone_class(env, home, *name, args),
        // Ui{msg} / WebRoute(page) — recurse on the message/page type-param.
        // Both emit named runtime structs (`Html<M>`, `Route<P>`, …) that derive
        // `Clone` but never `Copy`, so a `Copy` parameter floors to `CloneOk`.
        IrType::Ui { msg, .. } => clone_class_named_composite(env, std::iter::once(msg.as_ref())),
        IrType::WebRoute(page) => {
            clone_class_named_composite(env, std::iter::once(page.as_ref()))
        }
    }
}

/// T5 multi-use-clone eligibility for a by-value fn/def PARAMETER.
///
/// A `CloneOk` param clones per the general multi-use rule. A bare
/// [`IrType::Generic`] param is ALSO eligible even though [`clone_class`] floors
/// it to `NonClone`: `render_fn_generics` (`ipe_backend_rust` `emit_expr.rs`,
/// `bounds.with_clone()`) stamps `T: Clone` on EVERY emitted generic fn
/// type-param UNCONDITIONALLY, so an inserted `x.clone()` on a reused generic
/// param always type-checks. That `T: Clone` bound is the soundness gate — a
/// non-`Clone` instantiation (e.g. `Box<dyn Fn>`) fails the bound at the CALLER
/// before the inserted `.clone()` is ever reached, so inserting the clone is
/// sound (over-cloning is the only downside, never unsoundness). SINGLE SOURCE
/// OF TRUTH: this predicate and `render_fn_generics`' unconditional
/// `with_clone()` must agree — if one changes, the other must change with it,
/// else a reused generic either moves twice (E0382) or clones a non-`Clone`
/// value (E0599).
///
/// Scope: only a BARE `Generic` leaf. Composites carrying a generic
/// (`List (Generic)`, `Tuple(.., Generic)`, …) still floor to `NonClone` via the
/// generic leaf and are intentionally out of scope here — the wider blast radius
/// of flipping `clone_class(Generic)` itself is a separate design decision.
/// A bare `Generic` param already makes [`reject_fn_value_reuse`] a
/// no-op (`ir_contains_fun(Generic) == false`), so admitting it here loses no
/// diagnostic — it only closes the silent double-move.
pub(super) fn param_is_multiuse_clonable(env: CloneEnv<'_>, ir_ty: &IrType) -> bool {
    matches!(clone_class(env, ir_ty), CloneClass::CloneOk) || matches!(ir_ty, IrType::Generic(_))
}

/// The `Clone`-treatment a captured symbol of type `ir_ty` receives inside a
/// closure body: `Some(true)` clones at the boundary (`.clone()` / `CloneVar`),
/// `Some(false)` is a genuinely non-`Clone` capture (bare only in depth-0 callee
/// position, else IPE-L0126), `None` is a `CopyLeaf` capture left bare.
///
/// A bare [`IrType::Generic`] capture clones, exactly as a bare `Generic` PARAM
/// does under [`param_is_multiuse_clonable`]: `render_fn_generics` stamps
/// `T: Clone` on every emitted generic type-param unconditionally, so the
/// inserted `.clone()` type-checks, and a non-`Clone` instantiation is rejected
/// at the CALLER by that bound before the clone is reached. SINGLE SOURCE OF
/// TRUTH with `param_is_multiuse_clonable` — both admit a bare `Generic` on the
/// same emitted `with_clone` bound; if one changes the other must.
pub(super) fn classify_capture_clone(env: CloneEnv<'_>, ir_ty: &IrType) -> Option<bool> {
    if matches!(ir_ty, IrType::Generic(_)) {
        return Some(true);
    }
    match clone_class(env, ir_ty) {
        CloneClass::CloneOk => Some(true),
        CloneClass::NonClone => Some(false),
        CloneClass::CopyLeaf => None,
    }
}

/// How a free local of a capture-cloned kernel handler survives the emitted `.clone()`.
///
/// The backend shadows every such capture with `let v = v.clone();` inside a
/// fresh wrapper closure (`KernelFn::capture_cloned_handler_arg`), so only a
/// capture proven `Clone` (or `Copy`) is sound there. `NonClone` and
/// `Unresolved` are the refused classes: absent a resolved type there is no
/// proof the emitted clone type-checks, so the gate fails closed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum HandlerCapture {
    /// A `Copy` leaf.
    CopyLeaf,
    /// A `Clone` value carrier.
    CloneOk,
    /// A pure-`Fun` binder its binder site promotes to the `Clone` `Arc` carrier.
    ArcCarrier,
    /// A non-`Clone` value (`Box<dyn Fn>`, task, decoder): refused.
    NonClone,
    /// A capture whose type did not resolve to an `IrType`: refused.
    Unresolved,
}

impl HandlerCapture {
    /// Whether the emitted per-call `.clone()` of this capture is proven to type-check.
    pub(super) const fn admitted(self) -> bool {
        match self {
            Self::CopyLeaf | Self::CloneOk | Self::ArcCarrier => true,
            Self::NonClone | Self::Unresolved => false,
        }
    }
}

/// Classify one handler capture of type `ir_ty` for the capture-clone prologue.
///
/// `promotable_binder` is whether the capture's binder runs the `Arc<dyn Fn>`
/// carrier promotion (a `let` name, a def/lambda param, a match-arm binder):
/// such a pure-`Fun` binder flowing into a `requires_sync_capture` kernel is
/// promoted there, so its capture is an `Arc` clone. Every other `Fun` (a
/// destructure-bound one) stays a non-`Clone` `Box`. A `None` type is
/// `Unresolved`, never defaulted to a bare `Copy` read.
pub(super) fn classify_handler_capture(
    env: CloneEnv<'_>,
    ir_ty: Option<&IrType>,
    promotable_binder: bool,
) -> HandlerCapture {
    let Some(ty) = ir_ty else {
        return HandlerCapture::Unresolved;
    };
    if promotable_binder && ipe_ir::fun_value_arc_promotable(ty) {
        return HandlerCapture::ArcCarrier;
    }
    match classify_capture_clone(env, ty) {
        Some(true) => HandlerCapture::CloneOk,
        Some(false) => HandlerCapture::NonClone,
        None => HandlerCapture::CopyLeaf,
    }
}

/// The clone class of one COMPOSITE PART.
///
/// A bare [`IrType::Generic`] part is `CloneOk`, not `NonClone`: every emitted
/// generic fn stamps `T: Clone` unconditionally (`render_fn_generics`), so a
/// composite carrying the tvar (`Vec<(T, String)>` for an `enum`'s pairs,
/// `Vec<Variant<T>>` for a `taggedUnion`'s variants) is `Clone` whenever the
/// composite's own shape is, and a `.clone()` inserted on it type-checks — a
/// non-`Clone` instantiation is rejected at the CALLER by that same `T: Clone`
/// bound before the clone is reached. This is the composite analogue of the
/// bare-`Generic` special-cases in [`classify_capture_clone`] and
/// [`param_is_multiuse_clonable`]; without it a composite move-captured by two
/// sibling closures (a `Codec`'s `enc` + `mkDec`, both reading the same pairs /
/// variants) is left un-cloned and the emitted Rust fails `cargo` with E0382 /
/// E0507 — an `ipe`-accept-then-`cargo`-fail SEAL break. SINGLE SOURCE OF TRUTH
/// with those two predicates: all three admit a bare `Generic` on the identical
/// `with_clone` bound; if one changes the others must.
fn clone_class_part(env: CloneEnv<'_>, p: &IrType) -> CloneClass {
    match p {
        IrType::Generic(_) => CloneClass::CloneOk,
        other => clone_class(env, other),
    }
}

fn clone_class_composite<'a>(
    env: CloneEnv<'_>,
    parts: impl Iterator<Item = &'a IrType>,
) -> CloneClass {
    let mut any_clone_ok = false;
    for p in parts {
        match clone_class_part(env, p) {
            CloneClass::NonClone => return CloneClass::NonClone,
            CloneClass::CloneOk => any_clone_ok = true,
            CloneClass::CopyLeaf => {}
        }
    }
    if any_clone_ok {
        CloneClass::CloneOk
    } else {
        CloneClass::CopyLeaf
    }
}

/// Like [`clone_class_composite`] but floors `CopyLeaf` to `CloneOk`.
///
/// Use for **named Rust types** (emitted `struct` / `enum`) that derive `Clone`
/// but **not** `Copy`.  A payload of all-scalar fields makes
/// `clone_class_composite` return `CopyLeaf`, falsely claiming the wrapper is
/// `Copy`.  Bare capture of such a type inside a `move` closure moves the value
/// on first call, causing E0525 on any subsequent call.  Flooring to `CloneOk`
/// ensures the rewrite inserts `.clone()` per call — safe because the wrapper
/// derives `Clone`.
/// Clone class of a named user enum.
///
/// `NonClone` when the enum is an FFI foreign-interface opaque handle (a
/// `Rust.*` home with no transparent import: the real foreign Rust type, whose
/// `Clone`-ness is the foreign crate's decision), or when a variant payload
/// holds a non-`Clone` value (a `Task`, a boxed fn, an opaque FFI handle), so
/// the backend's enum-`Clone` fixpoint gives it no `Clone` impl. Either way a
/// duplicating `.clone()` would be cargo E0599 after `ipe` exit 0 (a SEAL
/// break). Otherwise its type arguments decide, floored to `CloneOk` like any
/// named composite; a TRANSPARENT FFI import lowers to a real app enum and
/// lands here too.
fn enum_clone_class(
    env: CloneEnv<'_>,
    home: &ModPath,
    name: Symbol,
    args: &[IrType],
) -> CloneClass {
    if enum_is_opaque_ffi_handle(env, home, name)
        || enum_payload_holds(home, name, env.payloads, &|p| {
            payload_leaf_is_nonclone(env, p)
        })
    {
        CloneClass::NonClone
    } else {
        clone_class_named_composite(env, args.iter())
    }
}

fn clone_class_named_composite<'a>(
    env: CloneEnv<'_>,
    parts: impl Iterator<Item = &'a IrType>,
) -> CloneClass {
    match clone_class_composite(env, parts) {
        CloneClass::NonClone => CloneClass::NonClone,
        // CopyLeaf is only valid for Rust primitive types that implement `Copy`.
        // Named structs and enums never derive `Copy` (derive macro doesn't emit it),
        // so the weakest safe class here is `CloneOk`.
        CloneClass::CloneOk | CloneClass::CopyLeaf => CloneClass::CloneOk,
    }
}

/// Does `pat` bind ANY symbol in `a` OR `b`? One walk of `pat` tests each bound
/// name against both sets at once — a bound name is caught iff it is in either
/// set, so this is the `pat`-binds-any-in-the-union predicate the clone/non-clone
/// capture split needs, in a single traversal rather than one walk per set.
fn pat_binds_any_in_either(pat: &Pat, a: &BTreeSet<Symbol>, b: &BTreeSet<Symbol>) -> bool {
    let in_either = |s: &Symbol| a.contains(s) || b.contains(s);
    match pat {
        Pat::Var(s) => in_either(s),
        Pat::Wildcard | Pat::Int(_) | Pat::Bool(_) | Pat::Char(_) | Pat::Str(_) => false,
        Pat::Alias(inner, s) => in_either(s) || pat_binds_any_in_either(inner, a, b),
        Pat::Ctor { args, .. } => args.iter().any(|p| pat_binds_any_in_either(p, a, b)),
        Pat::Tuple(elems) => elems.iter().any(|p| pat_binds_any_in_either(p, a, b)),
        Pat::Record(fields) => fields.iter().any(|(_, p)| pat_binds_any_in_either(p, a, b)),
        Pat::Slice { prefix, rest } => {
            prefix.iter().any(|p| pat_binds_any_in_either(p, a, b))
                || rest
                    .as_deref()
                    .is_some_and(|p| pat_binds_any_in_either(p, a, b))
        }
        Pat::Or(alts) => alts.iter().any(|p| pat_binds_any_in_either(p, a, b)),
    }
}

/// Rewrite a lowered IR expression — the body of a `move` closure — to make
/// the closure `Fn` (not `FnOnce`) by inserting `.clone()` calls on captures
/// that are not `Copy`:
///
/// * `Var(s)` where `s ∈ clone_set` → `CloneVar(s)` (runtime `.clone()`)
/// * `Var(s)` where `s ∈ noncl_set` AND `s` is the DIRECT callee of an
///   `Apply` → kept bare (`Fn::call` borrows the receiver — verified green)
/// * `Var(s)` where `s ∈ noncl_set` elsewhere → `Err(IPE-L0125)`
/// * all others → unchanged (not captured, or `CopyLeaf`)
///
/// Shadow discipline mirrors [`rewrite_var_free_occurrences`]: `Let` /
/// `Destructure` / `Lambda` / `Match`-arm patterns rebind and remove the symbol
/// from the active sets inside the shadowed sub-expression.
#[allow(clippy::too_many_lines)]
// `depth`: closure-nesting depth relative to the outermost lambda being
// processed.  Used to gate the NonClone callee-position exemption: at depth 0
// a `Var(f)` in direct `Apply.func` position is allowed bare (Rust borrows
// `&self` for `Fn::call`).  At depth > 0 the symbol is captured by an inner
// `move` closure which steals it from the outer env on the first call →
// outer closure becomes `FnOnce` (E0525).  The exemption is therefore only
// sound at depth 0.
pub(super) fn rewrite_captured_clones(
    clone_set: &BTreeSet<Symbol>,
    noncl_set: &BTreeSet<Symbol>,
    lambda_span: Span,
    expr: Expr,
    depth: u32,
) -> DResult<Expr> {
    if clone_set.is_empty() && noncl_set.is_empty() {
        return Ok(expr);
    }
    match expr {
        Expr::Var(s) => {
            if clone_set.contains(&s) {
                Ok(Expr::CloneVar(s))
            } else if noncl_set.contains(&s) {
                Err(super::unsupported(lambda_span, Feature::NonCloneCapture))
            } else {
                Ok(Expr::Var(s))
            }
        }
        // Leaves that are never local captures.
        Expr::CloneVar(_)
        | Expr::Int(_)
        | Expr::Float(_)
        | Expr::Bool(_)
        | Expr::Str(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::FuncValue { .. } => Ok(expr),
        // Apply: a `Var(s)` in DIRECT func position where `s ∈ noncl_set`
        // is allowed bare ONLY at depth 0.  At depth 0, Rust's `Fn::call`
        // borrows `&self`, so re-calling the closure is safe.
        // At depth > 0 the symbol lives inside an inner `move` closure: the
        // inner closure would move it out of the outer env on the first call,
        // making the outer closure `FnOnce` (E0525).
        //
        // Args discipline: a lambda that appears as a CALLBACK ARGUMENT
        // (e.g. `task_and_then(task, \ts -> insertRow db ts)`) has already been
        // fully processed by its own `lower_lambda` pass at depth 0, including
        // the callee-position exemption for NonClone symbols.  Propagating
        // `noncl_set` into arg-position lambdas here would re-examine already-
        // handled callee sites at depth+1, where the exemption does NOT fire,
        // spuriously emitting L0126.
        //
        // Lambdas in FUNC position (immediately-invoked pattern
        // `(\x -> f x) p`) are NOT cleared: the inner lambda creation moves a
        // NonClone value out of the outer env on every call → outer closure
        // becomes FnOnce against a `Box<dyn Fn>` return annotation → Rust E0277.
        // Those still propagate `noncl_set` via the normal
        // `other` path into the `Lambda` arm.
        Expr::Apply { func, args } => {
            let new_func = Box::new(match *func {
                Expr::Var(s) if noncl_set.contains(&s) && depth == 0 => Expr::Var(s),
                other => rewrite_captured_clones(clone_set, noncl_set, lambda_span, other, depth)?,
            });
            let new_args = args
                .into_iter()
                .map(|a| {
                    // Clear `noncl_set` for lambda arguments — they are
                    // already self-consistent from their own `lower_lambda`
                    // pass.  Non-lambda expressions keep the full `noncl_set`
                    // so forwarding a NonClone value in arg position (e.g.
                    // `applyTwice f x` where `f` is non-callee) still fires
                    // L0126 as expected.
                    if matches!(&a, Expr::Lambda { .. }) {
                        let empty = BTreeSet::new();
                        rewrite_captured_clones(clone_set, &empty, lambda_span, a, depth)
                    } else {
                        rewrite_captured_clones(clone_set, noncl_set, lambda_span, a, depth)
                    }
                })
                .collect::<DResult<Vec<_>>>()?;
            Ok(Expr::Apply {
                func: new_func,
                args: new_args,
            })
        }
        Expr::BinOp { op, lhs, rhs } => Ok(Expr::BinOp {
            op,
            lhs: Box::new(rewrite_captured_clones(
                clone_set,
                noncl_set,
                lambda_span,
                *lhs,
                depth,
            )?),
            rhs: Box::new(rewrite_captured_clones(
                clone_set,
                noncl_set,
                lambda_span,
                *rhs,
                depth,
            )?),
        }),
        Expr::Let { name, value, body } => {
            let new_value = Box::new(rewrite_captured_clones(
                clone_set,
                noncl_set,
                lambda_span,
                *value,
                depth,
            )?);
            if clone_set.contains(&name) || noncl_set.contains(&name) {
                let inner_clone: BTreeSet<Symbol> =
                    clone_set.iter().copied().filter(|&s| s != name).collect();
                let inner_noncl: BTreeSet<Symbol> =
                    noncl_set.iter().copied().filter(|&s| s != name).collect();
                Ok(Expr::Let {
                    name,
                    value: new_value,
                    body: Box::new(rewrite_captured_clones(
                        &inner_clone,
                        &inner_noncl,
                        lambda_span,
                        *body,
                        depth,
                    )?),
                })
            } else {
                Ok(Expr::Let {
                    name,
                    value: new_value,
                    body: Box::new(rewrite_captured_clones(
                        clone_set,
                        noncl_set,
                        lambda_span,
                        *body,
                        depth,
                    )?),
                })
            }
        }
        Expr::Destructure {
            binder,
            value,
            body,
        } => {
            let new_value = Box::new(rewrite_captured_clones(
                clone_set,
                noncl_set,
                lambda_span,
                *value,
                depth,
            )?);
            if pat_binds_any_in_either(&binder, clone_set, noncl_set) {
                let inner_clone: BTreeSet<Symbol> = clone_set
                    .iter()
                    .copied()
                    .filter(|&s| !super::pat_binds_symbol(&binder, s))
                    .collect();
                let inner_noncl: BTreeSet<Symbol> = noncl_set
                    .iter()
                    .copied()
                    .filter(|&s| !super::pat_binds_symbol(&binder, s))
                    .collect();
                Ok(Expr::Destructure {
                    binder,
                    value: new_value,
                    body: Box::new(rewrite_captured_clones(
                        &inner_clone,
                        &inner_noncl,
                        lambda_span,
                        *body,
                        depth,
                    )?),
                })
            } else {
                Ok(Expr::Destructure {
                    binder,
                    value: new_value,
                    body: Box::new(rewrite_captured_clones(
                        clone_set,
                        noncl_set,
                        lambda_span,
                        *body,
                        depth,
                    )?),
                })
            }
        }
        // Lambda: its own params shadow for the body.
        //
        // `noncl_set` IS propagated into inner lambda bodies (at depth+1) so
        // that the depth > 0 gate can fire for the immediately-invoked pattern
        // `(\x -> f x) p`: that inner `\x -> f x` is in `Apply.func`
        // position and reaches this arm via the normal `other` path.  At depth 1
        // the callee-position exemption (`depth == 0`) does NOT fire, so
        // `Var(f)` inside the inner body triggers L0126 — correctly preventing
        // a `FnOnce` closure from being boxed as `Box<dyn Fn>`.
        //
        // The companion case — lambdas in ARGUMENT position such as
        // `task_and_then(task, \ts -> insertRow db ts)` — is handled one level
        // up in the `Apply` arm: arg-position lambdas receive an empty
        // `noncl_set` before entering this arm, so `inner_noncl` below is
        // already empty and no spurious L0126 is emitted.
        Expr::Lambda { params, ret, body } => {
            let param_names: BTreeSet<Symbol> = params.iter().map(|(s, _)| *s).collect();
            let inner_clone: BTreeSet<Symbol> = clone_set
                .iter()
                .copied()
                .filter(|s| !param_names.contains(s))
                .collect();
            let inner_noncl: BTreeSet<Symbol> = noncl_set
                .iter()
                .copied()
                .filter(|s| !param_names.contains(s))
                .collect();
            Ok(Expr::Lambda {
                params,
                ret,
                body: Box::new(rewrite_captured_clones(
                    &inner_clone,
                    &inner_noncl,
                    lambda_span,
                    *body,
                    depth + 1,
                )?),
            })
        }
        // `Expr::SharedLambda` is produced by `lower_let` strictly
        // AFTER every `rewrite_captured_clones` call for its scope has
        // already run, so this arm is never actually reached in practice —
        // kept total (mirroring the `Lambda` arm exactly) so a future
        // producer change fails loudly via a type error, not silently via
        // an unhandled-variant panic.
        Expr::SharedLambda { params, ret, body } => {
            let param_names: BTreeSet<Symbol> = params.iter().map(|(s, _)| *s).collect();
            let inner_clone: BTreeSet<Symbol> = clone_set
                .iter()
                .copied()
                .filter(|s| !param_names.contains(s))
                .collect();
            let inner_noncl: BTreeSet<Symbol> = noncl_set
                .iter()
                .copied()
                .filter(|s| !param_names.contains(s))
                .collect();
            Ok(Expr::SharedLambda {
                params,
                ret,
                body: Box::new(rewrite_captured_clones(
                    &inner_clone,
                    &inner_noncl,
                    lambda_span,
                    *body,
                    depth + 1,
                )?),
            })
        }
        Expr::Match(m) => Ok(Expr::Match(m.try_map_bodies(
            |scrutinee| {
                rewrite_captured_clones(clone_set, noncl_set, lambda_span, scrutinee, depth)
            },
            |pat, body, guard| {
                let new_body = if pat_binds_any_in_either(pat, clone_set, noncl_set) {
                    let inner_clone: BTreeSet<Symbol> = clone_set
                        .iter()
                        .copied()
                        .filter(|&s| !super::pat_binds_symbol(pat, s))
                        .collect();
                    let inner_noncl: BTreeSet<Symbol> = noncl_set
                        .iter()
                        .copied()
                        .filter(|&s| !super::pat_binds_symbol(pat, s))
                        .collect();
                    rewrite_captured_clones(&inner_clone, &inner_noncl, lambda_span, body, depth)?
                } else {
                    rewrite_captured_clones(clone_set, noncl_set, lambda_span, body, depth)?
                };
                Ok((new_body, guard))
            },
        )?)),
        Expr::If { cond, then_, else_ } => Ok(Expr::If {
            cond: Box::new(rewrite_captured_clones(
                clone_set,
                noncl_set,
                lambda_span,
                *cond,
                depth,
            )?),
            then_: Box::new(rewrite_captured_clones(
                clone_set,
                noncl_set,
                lambda_span,
                *then_,
                depth,
            )?),
            else_: Box::new(rewrite_captured_clones(
                clone_set,
                noncl_set,
                lambda_span,
                *else_,
                depth,
            )?),
        }),
        // Call: kernel / top-level function application.
        //
        // Same Lambda-in-args discipline as `Expr::Apply`: a lambda
        // passed as a callback to a kernel (e.g. `List.map (\m -> f m) xs` or
        // `task_and_then(task, \ts -> insertRow db ts)`) is already fully
        // processed by its own `lower_lambda` pass at depth 0.  Propagating
        // `noncl_set` into it here would fire spurious L0126 at depth+1.
        //
        // Non-lambda args keep the full `noncl_set` so forwarding a NonClone
        // value in arg position (e.g. `applyTwice f x` where `f` is non-callee)
        // is still rejected.
        Expr::Call {
            callee,
            args,
            pin,
            on_form,
        } => Ok(Expr::Call {
            callee,
            args: args
                .into_iter()
                .map(|a| {
                    if matches!(&a, Expr::Lambda { .. }) {
                        let empty = BTreeSet::new();
                        rewrite_captured_clones(clone_set, &empty, lambda_span, a, depth)
                    } else {
                        rewrite_captured_clones(clone_set, noncl_set, lambda_span, a, depth)
                    }
                })
                .collect::<DResult<Vec<_>>>()?,
            pin,
            on_form,
        }),
        Expr::Tuple(items) => Ok(Expr::Tuple(
            items
                .into_iter()
                .map(|e| rewrite_captured_clones(clone_set, noncl_set, lambda_span, e, depth))
                .collect::<DResult<Vec<_>>>()?,
        )),
        Expr::List { elem, items } => Ok(Expr::List {
            elem,
            items: items
                .into_iter()
                .map(|e| rewrite_captured_clones(clone_set, noncl_set, lambda_span, e, depth))
                .collect::<DResult<Vec<_>>>()?,
        }),
        Expr::Cons { head, tail } => Ok(Expr::Cons {
            head: Box::new(rewrite_captured_clones(
                clone_set,
                noncl_set,
                lambda_span,
                *head,
                depth,
            )?),
            tail: Box::new(rewrite_captured_clones(
                clone_set,
                noncl_set,
                lambda_span,
                *tail,
                depth,
            )?),
        }),
        Expr::ListIndexClone { list, index } => Ok(Expr::ListIndexClone {
            list: Box::new(rewrite_captured_clones(
                clone_set,
                noncl_set,
                lambda_span,
                *list,
                depth,
            )?),
            index,
        }),
        Expr::ListLenCheck { list, len, exact } => Ok(Expr::ListLenCheck {
            list: Box::new(rewrite_captured_clones(
                clone_set,
                noncl_set,
                lambda_span,
                *list,
                depth,
            )?),
            len,
            exact,
        }),
        Expr::Record { fields, ty } => Ok(Expr::Record {
            fields: fields
                .into_iter()
                .map(|(sym, e)| {
                    rewrite_captured_clones(clone_set, noncl_set, lambda_span, e, depth)
                        .map(|e| (sym, e))
                })
                .collect::<DResult<Vec<_>>>()?,
            ty,
        }),
        Expr::Access {
            record,
            field,
            field_ty,
        } => Ok(Expr::Access {
            record: Box::new(rewrite_captured_clones(
                clone_set,
                noncl_set,
                lambda_span,
                *record,
                depth,
            )?),
            field,
            field_ty,
        }),
        Expr::Update { record, fields } => Ok(Expr::Update {
            record: Box::new(rewrite_captured_clones(
                clone_set,
                noncl_set,
                lambda_span,
                *record,
                depth,
            )?),
            fields: fields
                .into_iter()
                .map(|(sym, e)| {
                    rewrite_captured_clones(clone_set, noncl_set, lambda_span, e, depth)
                        .map(|e| (sym, e))
                })
                .collect::<DResult<Vec<_>>>()?,
        }),
        Expr::TaskSeq { effect, rest } => Ok(Expr::TaskSeq {
            effect: Box::new(rewrite_captured_clones(
                clone_set,
                noncl_set,
                lambda_span,
                *effect,
                depth,
            )?),
            rest: Box::new(rewrite_captured_clones(
                clone_set,
                noncl_set,
                lambda_span,
                *rest,
                depth,
            )?),
        }),
        Expr::Ctor {
            home,
            ty,
            variant,
            args,
        } => Ok(Expr::Ctor {
            home,
            ty,
            variant,
            args: args
                .into_iter()
                .map(|a| rewrite_captured_clones(clone_set, noncl_set, lambda_span, a, depth))
                .collect::<DResult<Vec<_>>>()?,
        }),
        // TailLoop/TailRecur are produced by a post-lower TCO pass that runs
        // AFTER lower_lambda — they cannot appear inside a lambda body at this
        // point. Handle defensively: TailLoop params shadow; TailRecur recurse.
        // TailLoop is NOT a new closure scope — do NOT increment depth here.
        Expr::TailLoop { params, body } => {
            let param_names: BTreeSet<Symbol> = params.iter().map(|(s, _)| *s).collect();
            let inner_clone: BTreeSet<Symbol> = clone_set
                .iter()
                .copied()
                .filter(|s| !param_names.contains(s))
                .collect();
            let inner_noncl: BTreeSet<Symbol> = noncl_set
                .iter()
                .copied()
                .filter(|s| !param_names.contains(s))
                .collect();
            Ok(Expr::TailLoop {
                params,
                body: Box::new(rewrite_captured_clones(
                    &inner_clone,
                    &inner_noncl,
                    lambda_span,
                    *body,
                    depth,
                )?),
            })
        }
        Expr::TailRecur { args } => Ok(Expr::TailRecur {
            args: args
                .into_iter()
                .map(|a| rewrite_captured_clones(clone_set, noncl_set, lambda_span, a, depth))
                .collect::<DResult<Vec<_>>>()?,
        }),
    }
}

/// Refuse (IPE-L0135) a reuse of a non-`Clone` effect-carrier binding `sym`.
///
/// Reached only through the lowerer's single move-ownership entry point, so
/// every used binder of every form (parameter, arm binder, `let`, destructured
/// component) runs it. The binder's type comes from the lowerer's fail-closed
/// binder-type resolver: a used binder whose type does not resolve is refused
/// there, never skipped past this check.
pub(super) fn reject_nonclone_value_reuse(
    env: CloneEnv<'_>,
    sym: Symbol,
    ir_ty: &IrType,
    body: &Expr,
    span: Span,
) -> DResult<()> {
    if !super::ir_type_has_effect_carrier(ir_ty, env.payloads)
        || !matches!(clone_class(env, ir_ty), CloneClass::NonClone)
    {
        return Ok(());
    }
    // A sequenced task or argument-reversed kernel whose first-evaluated operand
    // the emitter must rewrite to `sym.clone()` (so the continuation can still
    // capture `sym`) has no `Clone` impl to call.
    if ipe_ir::seq_clone::seq_rewrite_clones_symbol(sym, body, env.payloads) {
        return Err(super::unsupported(span, Feature::NonCloneValueReuse));
    }
    // A by-value pattern binder of a `Copy` record field copies it, so a
    // pattern that moves no part does not consume `sym`.
    let copy_fields = super::copy_record_fields(env, ir_ty);
    let consumes = super::count_value_consumes(sym, &copy_fields, body);
    if consumes > 1 {
        return Err(super::unsupported(span, Feature::NonCloneValueReuse));
    }
    // A borrowing read (`sym.field`, a length probe) that the emitted order
    // evaluates AFTER a move of `sym` observes a moved value (E0382), even
    // though the borrow itself is not a consume. A by-value pattern match
    // (`match sym`, `let <pat> = sym`) moves the parts its binders bind, so a
    // later read of a moved part is the same hazard.
    if super::nonclone_read_after_move(env, sym, ir_ty, body) {
        return Err(super::unsupported(span, Feature::NonCloneValueReuse));
    }
    // A single consume that is a bare `Var` update base, combined with any use
    // of `sym` OUTSIDE that update expression (in the let-body or a peer
    // expression), is a use-after-move: the emitted `let mut __ipe_rec = sym;`
    // moves sym, so a read of sym anywhere after that block is E0382 in Rust.
    // Uses of sym INSIDE the update's own field values (e.g. `{ m | f = m.x }`)
    // are NOT reuse: `emit_update` binds each field value to a temporary BEFORE
    // moving the base, so the in-field read observes sym while it is still owned.
    // `count_var_uses_update_aware` therefore counts only uses outside the
    // update; more than one total (the base move plus an outside read) rejects.
    if consumes == 1
        && super::sym_is_bare_update_base(sym, body)
        && super::count_var_uses_update_aware(sym, body) > 1
    {
        return Err(super::unsupported(span, Feature::NonCloneValueReuse));
    }
    Ok(())
}

/// The MAX use-count across all non-shadowing arms of a (post-scrutinee-rewrite)
/// `Match` node, for restoring the shared `remaining` counter after the per-arm
/// snapshot pass in `rewrite_multiuse_clones`.
///
/// Returns 0 when there are no arms or every arm pattern shadows `sym`.
fn match_arm_peak_uses(sym: Symbol, m: &ipe_ir::Match) -> usize {
    m.arms()
        .iter()
        .map(|arm| {
            if super::pat_binds_symbol(&arm.pat, sym) {
                0
            } else {
                super::count_var_uses(sym, &arm.body)
            }
        })
        .max()
        .unwrap_or(0)
}

/// Rewrite `Var(sym)` / `Lambda`-captures of `sym` in evaluation order so that
/// all but the last-evaluated occurrence are `.clone()`d. Evaluation order is
/// DFS left-to-right, except that a call whose callee evaluates its arguments
/// reversed ([`ipe_ir::Callee::evaluates_args_reversed`]) is visited
/// last-argument-first.
///
/// `remaining` starts at `count_var_uses(sym, expr)`.  Each consuming
/// occurrence decrements it; when `remaining > 1` the occurrence is non-last
/// and is rewritten:
/// * bare `Var(sym)` → `CloneVar(sym)`;
/// * Lambda whose body refs sym → `Let { name: sym, value: CloneVar(sym), body: Lambda }`.
///   The pre-clone rebinding captures the CLONE into the closure while the
///   OUTER `sym` remains alive for subsequent uses.
///
/// When `remaining == 1` (the last occurrence), the node is kept bare.
///
/// Shadow discipline and Lambda-body descent mirror `count_var_uses`.
#[allow(clippy::too_many_lines)]
pub(super) fn rewrite_multiuse_clones(sym: Symbol, remaining: &mut usize, expr: Expr) -> Expr {
    if *remaining == 0 {
        return expr;
    }
    match expr {
        Expr::Var(s) if s == sym => {
            if *remaining > 1 {
                *remaining -= 1;
                Expr::CloneVar(s)
            } else {
                *remaining -= 1;
                Expr::Var(s)
            }
        }
        // Pre-existing CloneVar at the outer scope: treat like Var — always
        // leave as CloneVar (it already borrows; no further action needed).
        Expr::CloneVar(s) if s == sym => {
            *remaining -= 1;
            Expr::CloneVar(s)
        }
        // Lambda: if it move-captures `sym`, consume one `remaining` slot.
        // When NOT the last use, wrap in a pre-clone Let so the closure
        // captures the clone and the outer `sym` stays alive.
        Expr::Lambda { params, ret, body } => {
            if super::lambda_body_refs_sym(sym, &body) {
                // a FURTHER-nested `move` closure inside this lambda's
                // body that ALSO captures `sym` would move `sym` out of THIS
                // closure's captured environment on the first call, turning a
                // `Box<dyn Fn>` into a de-facto `FnOnce` (E0507). This arm only
                // ever gave THIS lambda a pre-clone wrap and never descended
                // into its body, so the inner closure was left un-wrapped
                // (07-todo-cli's `todoTitle` / `conn` / `idStr`: captured into a
                // `task_map`/`task_and_then` closure nested inside the pipeline
                // eta-lambda AND consumed by-value in the outer `db_exec` arg).
                // `force_shared_capture_clones` walks the body and gives every
                // directly-capturing nested lambda its OWN `let sym = sym.clone()`
                // wrap, sourced from the fresh owned `sym` this lambda captures.
                // It is a no-op when there is no nested capturing lambda, so the
                // steady-state single-closure case stays byte-identical. Applied
                // in BOTH branches because the nested-capture wrap is independent
                // of whether THIS lambda is the last use of `sym`.
                let body = Box::new(force_shared_capture_clones(sym, *body));
                if *remaining > 1 {
                    *remaining -= 1;
                    // Pre-clone: `let sym = sym.clone() in Lambda { … }`.
                    // The inner rebinding `sym` shadows the outer; the `move`
                    // closure inside captures the inner sym (the clone).
                    Expr::Let {
                        name: sym,
                        value: Box::new(Expr::CloneVar(sym)),
                        body: Box::new(Expr::Lambda { params, ret, body }),
                    }
                } else {
                    *remaining -= 1;
                    Expr::Lambda { params, ret, body }
                }
            } else {
                Expr::Lambda { params, ret, body }
            }
        }
        // `Expr::SharedLambda` mirrors `Expr::Lambda` here — it is
        // ALSO a `move` closure literal that may capture `sym`, so it needs
        // the same pre-clone treatment when it is not the last use.
        Expr::SharedLambda { params, ret, body } => {
            if super::lambda_body_refs_sym(sym, &body) {
                // same nested-capture descent as the `Lambda` arm above.
                let body = Box::new(force_shared_capture_clones(sym, *body));
                if *remaining > 1 {
                    *remaining -= 1;
                    Expr::Let {
                        name: sym,
                        value: Box::new(Expr::CloneVar(sym)),
                        body: Box::new(Expr::SharedLambda { params, ret, body }),
                    }
                } else {
                    *remaining -= 1;
                    Expr::SharedLambda { params, ret, body }
                }
            } else {
                Expr::SharedLambda { params, ret, body }
            }
        }
        // Non-`sym` Var / CloneVar and all atomic leaves — pass through.
        Expr::Var(_)
        | Expr::CloneVar(_)
        | Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::FuncValue { .. } => expr,
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op,
            lhs: Box::new(rewrite_multiuse_clones(sym, remaining, *lhs)),
            rhs: Box::new(rewrite_multiuse_clones(sym, remaining, *rhs)),
        },
        // `If` branches are mutually exclusive.  Each branch gets its own
        // per-arm counter seeded from its own use-count plus a phantom +1 when
        // the value escapes the `If` (v3 C1: post-if liveness = after_cond - max > 0).
        // The shared counter is restored by subtracting the MAX branch use-count.
        Expr::If { cond, then_, else_ } => {
            let new_cond = Box::new(rewrite_multiuse_clones(sym, remaining, *cond));
            let after_cond = *remaining;
            let then_count = super::count_var_uses(sym, &then_);
            let else_count = super::count_var_uses(sym, &else_);
            let peak = then_count.max(else_count);
            // phantom +1 when sym is live after the If (post-branch tail uses)
            let tail_live = after_cond.saturating_sub(peak) > 0;
            let phantom = usize::from(tail_live);
            let mut then_rem = then_count + phantom;
            let mut else_rem = else_count + phantom;
            let new_then = Box::new(rewrite_multiuse_clones(sym, &mut then_rem, *then_));
            let new_else = Box::new(rewrite_multiuse_clones(sym, &mut else_rem, *else_));
            *remaining = after_cond.saturating_sub(peak);
            Expr::If {
                cond: new_cond,
                then_: new_then,
                else_: new_else,
            }
        }
        // `value` is in the outer scope; `body` is shadowed if `name == sym`.
        Expr::Let { name, value, body } => {
            let new_value = Box::new(rewrite_multiuse_clones(sym, remaining, *value));
            let new_body = if name == sym {
                body
            } else {
                Box::new(rewrite_multiuse_clones(sym, remaining, *body))
            };
            Expr::Let {
                name,
                value: new_value,
                body: new_body,
            }
        }
        Expr::Destructure {
            binder,
            value,
            body,
        } => {
            let new_value = Box::new(rewrite_multiuse_clones(sym, remaining, *value));
            let new_body = if super::pat_binds_symbol(&binder, sym) {
                body
            } else {
                Box::new(rewrite_multiuse_clones(sym, remaining, *body))
            };
            Expr::Destructure {
                binder,
                value: new_value,
                body: new_body,
            }
        }
        // Match arms are mutually exclusive.  Rewrite the scrutinee with
        // the shared counter (it runs unconditionally), then give each arm body
        // its OWN counter — per-arm snapshot/restore (v3 C1).
        //
        // Per-arm seed = arm's own use-count + phantom +1 when `sym` is live
        // after the match (post-match tail uses exist).  The phantom +1 biases
        // the arm's real last use to `.clone()` so the tail's move stays sound.
        // Shared counter is restored to `after_scrut - peak` (REAL peak, no
        // phantom), so downstream tail uses see the correct residual.
        Expr::Match(m) => {
            // Step 1: rewrite scrutinee (unconditional — threads shared counter).
            let m = m.map_scrutinee(|scrutinee| rewrite_multiuse_clones(sym, remaining, scrutinee));
            let after_scrut = *remaining;

            // Step 2: compute per-arm seeds before we move `m`.
            // peak = MAX real use-count over non-shadowing arms.
            let peak = match_arm_peak_uses(sym, &m);
            // phantom +1 when sym survives past the match
            let tail_live = after_scrut.saturating_sub(peak) > 0;
            let phantom = usize::from(tail_live);

            // Step 3: rewrite each arm body with its own independent counter.
            let m = m.map_bodies(
                |scrutinee| scrutinee,
                |pat, body, guard| {
                    if super::pat_binds_symbol(pat, sym) {
                        (body, guard)
                    } else {
                        let arm_count = super::count_var_uses(sym, &body);
                        let mut arm_remaining = arm_count + phantom;
                        let new_body = rewrite_multiuse_clones(sym, &mut arm_remaining, body);
                        (new_body, guard)
                    }
                },
            );

            // Step 4: restore shared counter using the REAL peak (no phantom).
            *remaining = after_scrut.saturating_sub(peak);
            Expr::Match(m)
        }
        // Arguments are visited in EVALUATION order, so the last-evaluated
        // occurrence is the one left bare. A kernel whose runtime takes its
        // arguments reversed evaluates the container before the function, so a
        // capture by the function is the later use and the container's read the
        // one cloned.
        Expr::Call {
            callee,
            args,
            pin,
            on_form,
        } => {
            let args =
                callee.map_args_in_eval_order(args, |a| rewrite_multiuse_clones(sym, remaining, a));
            Expr::Call {
                callee,
                args,
                pin,
                on_form,
            }
        }
        Expr::Apply { func, args } => {
            let new_func = Box::new(rewrite_multiuse_clones(sym, remaining, *func));
            let new_args = args
                .into_iter()
                .map(|a| rewrite_multiuse_clones(sym, remaining, a))
                .collect();
            Expr::Apply {
                func: new_func,
                args: new_args,
            }
        }
        Expr::Tuple(items) => Expr::Tuple(
            items
                .into_iter()
                .map(|e| rewrite_multiuse_clones(sym, remaining, e))
                .collect(),
        ),
        Expr::List { elem, items } => Expr::List {
            elem,
            items: items
                .into_iter()
                .map(|e| rewrite_multiuse_clones(sym, remaining, e))
                .collect(),
        },
        Expr::Cons { head, tail } => Expr::Cons {
            head: Box::new(rewrite_multiuse_clones(sym, remaining, *head)),
            tail: Box::new(rewrite_multiuse_clones(sym, remaining, *tail)),
        },
        Expr::ListIndexClone { list, index } => Expr::ListIndexClone {
            list: Box::new(rewrite_multiuse_clones(sym, remaining, *list)),
            index,
        },
        Expr::ListLenCheck { list, len, exact } => Expr::ListLenCheck {
            list: Box::new(rewrite_multiuse_clones(sym, remaining, *list)),
            len,
            exact,
        },
        Expr::Record { fields, ty } => Expr::Record {
            fields: fields
                .into_iter()
                .map(|(k, v)| (k, rewrite_multiuse_clones(sym, remaining, v)))
                .collect(),
            ty,
        },
        // `Access.record` emits as `(record).field.clone()` — the record is
        // BORROWED by the method call, not moved.  We still recurse so that
        // the `remaining` counter advances correctly (count_var_uses counts
        // Access-under-record uses).  A VarLocal found here becomes CloneVar
        // unless it is the last overall use, in which case it stays bare (the
        // borrow keeps the original value alive for subsequent uses).
        Expr::Access {
            record,
            field,
            field_ty,
        } => Expr::Access {
            record: Box::new(rewrite_multiuse_clones(sym, remaining, *record)),
            field,
            field_ty,
        },
        // `Update.record` — `emit_update` binds each field value to a temporary
        // FIRST, then moves (or clones, for `CloneVar`) the base into
        // `__ipe_rec`.  We recurse so `remaining` advances through every
        // occurrence, keeping last-counted == last-textual.
        //
        // NOTE ordering: the field values are the first-emitted subexpressions
        // (`let __ipe_upd_i = <value>;` precedes `let mut __ipe_rec = <base>;`),
        // so they must be rewritten BEFORE the record base to match emit order —
        // the last-emitted occurrence is the one left bare.
        Expr::Update { record, fields } => {
            let fields = fields
                .into_iter()
                .map(|(k, v)| (k, rewrite_multiuse_clones(sym, remaining, v)))
                .collect();
            let record = Box::new(rewrite_multiuse_clones(sym, remaining, *record));
            Expr::Update { record, fields }
        }
        Expr::Ctor {
            home,
            ty,
            variant,
            args,
        } => Expr::Ctor {
            home,
            ty,
            variant,
            args: args
                .into_iter()
                .map(|a| rewrite_multiuse_clones(sym, remaining, a))
                .collect(),
        },
        Expr::TaskSeq { effect, rest } => Expr::TaskSeq {
            effect: Box::new(rewrite_multiuse_clones(sym, remaining, *effect)),
            rest: Box::new(rewrite_multiuse_clones(sym, remaining, *rest)),
        },
        Expr::TailLoop { params, body } => {
            if params.iter().any(|(s, _)| *s == sym) {
                Expr::TailLoop { params, body } // sym shadowed by loop var
            } else {
                Expr::TailLoop {
                    params,
                    body: Box::new(rewrite_multiuse_clones(sym, remaining, *body)),
                }
            }
        }
        Expr::TailRecur { args } => Expr::TailRecur {
            args: args
                .into_iter()
                .map(|a| rewrite_multiuse_clones(sym, remaining, a))
                .collect(),
        },
    }
}

#[cfg(test)]
mod handler_capture_tests {
    use std::collections::BTreeSet;

    use ipe_intern::Interner;
    use ipe_ir::{EnumPayloadTable, IrType};

    use super::{CloneEnv, HandlerCapture, classify_handler_capture};

    fn fun_ty() -> IrType {
        IrType::Fun(vec![IrType::Str], Box::new(IrType::Str))
    }

    /// An unresolved capture type is refused even on a promotable binder.
    #[test]
    fn unresolved_capture_is_refused() {
        let interner = Interner::new();
        let ffi = BTreeSet::new();
        let payloads = EnumPayloadTable::new();
        let env = CloneEnv {
            interner: &interner,
            transparent_ffi: &ffi,
            payloads: &payloads,
        };
        for promotable in [false, true] {
            let class = classify_handler_capture(env, None, promotable);
            assert_eq!(class, HandlerCapture::Unresolved);
            assert!(!class.admitted());
        }
    }

    /// A pure-`Fun` capture is admitted only through a promotable binder.
    #[test]
    fn fun_capture_needs_promotable_binder() {
        let interner = Interner::new();
        let ffi = BTreeSet::new();
        let payloads = EnumPayloadTable::new();
        let env = CloneEnv {
            interner: &interner,
            transparent_ffi: &ffi,
            payloads: &payloads,
        };
        let ty = fun_ty();
        assert_eq!(
            classify_handler_capture(env, Some(&ty), true),
            HandlerCapture::ArcCarrier
        );
        let bare = classify_handler_capture(env, Some(&ty), false);
        assert_eq!(bare, HandlerCapture::NonClone);
        assert!(!bare.admitted());
    }

    /// `Copy` and `Clone` captures are admitted.
    #[test]
    fn copy_and_clone_captures_are_admitted() {
        let interner = Interner::new();
        let ffi = BTreeSet::new();
        let payloads = EnumPayloadTable::new();
        let env = CloneEnv {
            interner: &interner,
            transparent_ffi: &ffi,
            payloads: &payloads,
        };
        assert!(classify_handler_capture(env, Some(&IrType::Int), false).admitted());
        assert!(classify_handler_capture(env, Some(&IrType::Str), false).admitted());
    }
}

#[cfg(test)]
mod tests {
    use ipe_intern::Symbol;
    use ipe_ir::{CallPin, Callee, Expr, IrType, KernelFn, OnFormKind};

    use super::rewrite_multiuse_clones;

    const SYM: Symbol = Symbol::from_raw(1);
    const PARAM: Symbol = Symbol::from_raw(2);

    /// `kernel (\param -> sym) sym`: the function captures `sym` and the container reads it.
    fn capture_then_read(kernel: KernelFn) -> Expr {
        Expr::Call {
            callee: Callee::Kernel(kernel),
            args: vec![
                Expr::Lambda {
                    params: vec![(PARAM, IrType::Int)],
                    ret: IrType::Str,
                    body: Box::new(Expr::Var(SYM)),
                },
                Expr::Var(SYM),
            ],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }
    }

    fn rewrite(expr: Expr) -> Vec<Expr> {
        let mut remaining = super::super::count_var_uses(SYM, &expr);
        assert_eq!(remaining, 2, "fixture must use `sym` twice");
        let Expr::Call { args, .. } = rewrite_multiuse_clones(SYM, &mut remaining, expr) else {
            return Vec::new();
        };
        assert_eq!(remaining, 0, "every use must be consumed");
        args
    }

    #[test]
    fn container_first_kernel_clones_the_container_read_and_moves_the_capture() {
        let args = rewrite(capture_then_read(KernelFn::MaybeMap));
        assert!(
            matches!(
                args.as_slice(),
                [Expr::Lambda { .. }, Expr::CloneVar(s)] if *s == SYM
            ),
            "the runtime evaluates the container first, so its read is the non-last use: {args:?}"
        );
    }

    #[test]
    fn ipe_order_kernel_pre_clones_the_capture_and_moves_the_container() {
        let args = rewrite(capture_then_read(KernelFn::ListMap));
        assert!(
            matches!(
                args.as_slice(),
                [Expr::Let { name, value, .. }, Expr::Var(s)]
                    if *name == SYM && matches!(**value, Expr::CloneVar(v) if v == SYM) && *s == SYM
            ),
            "the capture is the non-last use in Ipê order: {args:?}"
        );
    }
}
