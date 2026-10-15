//! Model-admissibility gate for `Ipe.Web` / `Ipe.Tui` / `Ipe.WebView`
//! app-entry kernels.
//!
//! The app entry threads a **Model** state type through `init` / `update` /
//! `view`. Each runtime entry bounds that Model:
//!
//! * `web_app` — `Model: serde::Serialize + serde::de::DeserializeOwned +
//!   Clone + PartialEq + Send + Sync + 'static` (the Model is persisted to the
//!   session store), so a non-serde Model is inadmissible.
//! * `tui_app` / `webview_app` — `Model: Clone + Send + 'static`, so a
//!   non-`Clone` (i.e. non-derivable) Model is inadmissible.
//!
//! Without this gate a well-typed program storing a `Cmd` / `Sub` / `Task` /
//! `Decoder` / `Db` / function — or, for `Ipe.Web`, an `Html` / `Element` /
//! `Color` — in its Model `ipe`-succeeds and then `cargo`-fails on the missing
//! trait bound. This module extracts the Model type from the app cfg's `view`
//! function and, if it fails the required predicate, returns a fail-closed
//! `IPE-L0120` diagnostic naming the offending field — converting the
//! `cargo`-fail into a clean `ipe` error (MAKE INVALID STATES UNREPRESENTABLE).

use ipe_diagnostics::{AppShape, DResult, Diagnostic, LowerError, ModelLeaf, Span};
use ipe_ir::{Expr, IrType, ir_type_is_derivable, ir_type_is_serde};

use crate::EmitCtx;

/// The `idx`-th parameter type of a function-valued app-cfg field, whether
/// that field is a named function reference ([`Expr::FuncValue`]) or an inline
/// lambda ([`Expr::Lambda`]).
///
/// Both shapes carry **concrete, solved** parameter [`IrType`]s: a `FuncValue`
/// stores its full `IrType::Fun(params, ret)`, and `lower_lambda` reads each
/// lambda parameter's type from the solver's region map (`lower.rs`), so
/// `params[idx].1` is the settled type, not a placeholder.
///
/// Returns `None` for any other expression shape (a `Var` referencing a
/// let-bound local, a partial application, …) — the documented fail-open
/// residual of the admissibility gates. Callers treat `None` as "cannot prove
/// inadmissible" and skip; see `docs/adr/0002-codegen-soundness-and-the-seal.md` §3.3.
///
/// This is the SHARED recovery primitive for (a) the Model gate, (b) the
/// lambda-`view` path (a lambda `view` returns its Model here rather than
/// `None`, so it is not silently skipped), and (c) the routed-vs-non-routed
/// emit branch (`emit_web::routed_page_field`), keeping the type-tier
/// `RoutedWebCheck` and the emit-tier detection in agreement on lambda-shaped
/// cfg fields.
#[must_use]
pub fn fn_param_ty(e: &Expr, idx: usize) -> Option<&IrType> {
    match e {
        Expr::FuncValue {
            ty: IrType::Fun(params, _),
            ..
        } => params.get(idx),
        Expr::Lambda { params, .. } => params.get(idx).map(|(_, ty)| ty),
        _ => None,
    }
}

/// Extract the Model type from an app cfg's `view` field expression.
///
/// `view : Model -> Html Msg` (Web/WebView) / `Model -> Element Msg` (Tui) is
/// either a named function reference ([`Expr::FuncValue`]) or an inline lambda
/// ([`Expr::Lambda`]); the Model is the first parameter type in both shapes
/// (see [`fn_param_ty`], which is Lambda-aware).
///
/// Returns `None` when the Model type cannot be recovered structurally (the
/// field is neither a function reference nor a lambda). Callers treat `None`
/// as "cannot prove inadmissible" and skip the gate — this never
/// *false-blocks* a well-formed program; an inadmissible Model behind an
/// unrecoverable `view` shape simply falls back to the prior behaviour rather
/// than regressing.
#[must_use]
pub fn model_ty_of_view(view_e: &Expr) -> Option<&IrType> {
    fn_param_ty(view_e, 0)
}

/// Extract the Msg type from an app cfg's `update` field expression.
///
/// `update : Msg -> Model -> (Model, Cmd Msg)` is either a named function
/// reference ([`Expr::FuncValue`]) or an inline lambda ([`Expr::Lambda`]);
/// the Msg is the **first** parameter type in both shapes (see [`fn_param_ty`]).
///
/// Returns `None` when the Msg type cannot be recovered structurally (the
/// field is neither a function reference nor a lambda). Callers treat `None`
/// as "cannot prove inadmissible" and skip the gate — fail-open residual, same
/// as [`model_ty_of_view`].
#[must_use]
pub fn msg_ty_of_update(update_e: &Expr) -> Option<&IrType> {
    fn_param_ty(update_e, 0)
}

/// Gate the Msg type of an app entry against the runtime's derivable bound.
///
/// All three app shapes (`Web`, `Tui`, `Webview`) require their Msg to be
/// clonable and sendable. The compiler derives `Clone + Debug + PartialEq` for
/// any "derivable" type, which covers the `Send + Sync + Debug + 'static`
/// required by `web_app` and `Clone + Send + 'static` required by `tui_app` /
/// `webview_app`. The predicate used is always [`ir_type_is_derivable`] (NOT
/// serde) — Msg is never persisted, so `Html`-carrying Msg variants are
/// **accepted** (Html derives Clone+Debug+PartialEq) while Cmd/Sub/Task/
/// Decoder/function-carrying variants are rejected.
///
/// On failure returns [`Diagnostic::Lower`] carrying [`LowerError::
/// InadmissibleAppMsg`] (`IPE-L0125`) with the offending variant/field and leaf
/// kind. The IR carries no spans at emit, so the span is [`Span::DUMMY`] and
/// the message is self-contained.
pub fn check_admissible_msg(ctx: &EmitCtx, msg_ty: &IrType, app: AppShape) -> DResult<()> {
    // Msg admissibility is always derivable (Clone + Debug + PartialEq),
    // regardless of the app shape. Web needs Send+Sync+Debug+'static;
    // Tui/Webview need Clone+Send+'static. The derivable predicate is strictly
    // stronger than "Clone only" and covers both. Crucially, this is NOT serde,
    // so Html-carrying Msg (derivable but not serde) is accepted here.
    let ok = ir_type_is_derivable(msg_ty, &|home, name| ctx.enum_is_derivable(home, name));
    if ok {
        return Ok(());
    }

    // Inadmissible: traverse with Tui shape (uses derivable, correct for Msg).
    let (field, leaf) = blame(ctx, msg_ty, AppShape::Tui);
    Err(Diagnostic::Lower {
        span: Span::DUMMY,
        msg: LowerError::InadmissibleAppMsg {
            app,
            field: field.into_boxed_str(),
            leaf,
        },
    })
}

/// Gate the Model type of an app entry against the runtime bound `app` requires.
///
/// * [`AppShape::Web`] → the Model must satisfy [`ir_type_is_serde`] (which
///   structurally implies `Clone + PartialEq`, so the full `web_app` bound is
///   covered by this one predicate).
/// * [`AppShape::Tui`] / [`AppShape::WebView`] → the Model must satisfy
///   [`ir_type_is_derivable`] (the backend derives `Clone` iff a type is
///   derivable, and Tui/Webview need only `Clone`).
///
/// On failure returns [`Diagnostic::Lower`] carrying [`LowerError::
/// InadmissibleAppModel`] (`IPE-L0120`) with the offending field and leaf kind.
/// The IR carries no spans at emit, so the span is [`Span::DUMMY`] and the
/// message is self-contained (precedent: the backend's `Span::DUMMY` `Name`
/// diagnostics). Normal plain-data Models pass unchanged.
pub fn check_admissible_model(ctx: &EmitCtx, model_ty: &IrType, app: AppShape) -> DResult<()> {
    let ok = match app {
        AppShape::Web => ir_type_is_serde(model_ty, &|home, name| ctx.enum_is_serde(home, name)),
        AppShape::Tui | AppShape::WebView | AppShape::Cli => {
            ir_type_is_derivable(model_ty, &|home, name| ctx.enum_is_derivable(home, name))
        }
    };
    if ok {
        return Ok(());
    }

    // Inadmissible: locate the offending field + leaf for a precise message.
    let (field, leaf) = blame(ctx, model_ty, app);
    Err(Diagnostic::Lower {
        span: Span::DUMMY,
        msg: LowerError::InadmissibleAppModel {
            app,
            field: field.into_boxed_str(),
            leaf,
        },
    })
}

/// Return whether `ty` satisfies the admissibility predicate for `app`.
fn admissible(ctx: &EmitCtx, ty: &IrType, app: AppShape) -> bool {
    match app {
        AppShape::Web => ir_type_is_serde(ty, &|home, name| ctx.enum_is_serde(home, name)),
        AppShape::Tui | AppShape::WebView | AppShape::Cli => {
            ir_type_is_derivable(ty, &|home, name| ctx.enum_is_derivable(home, name))
        }
    }
}

/// Identify the offending Model field name (empty when the Model is not a
/// record) and the leaf category of the first non-admissible payload.
///
/// Only ever called on a `model_ty` already known to be inadmissible, so a leaf
/// is always found; the `ModelLeaf::Handle` fallback is a defensive default that
/// never fires for a genuinely inadmissible type.
fn blame(ctx: &EmitCtx, model_ty: &IrType, app: AppShape) -> (String, ModelLeaf) {
    if let IrType::Record(fields) = model_ty {
        for (sym, field_ty) in fields {
            if !admissible(ctx, field_ty, app) {
                let name = ctx.resolve_ident(*sym).unwrap_or("").to_owned();
                return (name, leaf_of(ctx, field_ty, app));
            }
        }
    }
    (String::new(), leaf_of(ctx, model_ty, app))
}

/// The leaf category of the first non-admissible leaf reachable from `ty`.
///
/// Recurses through transparent carriers and (via the whole-program variant
/// table) through non-admissible user enums. A depth bound guards against a
/// pathological self-referential enum cycle (the type checker forbids infinite
/// value types, so this is belt-and-braces, never reached in practice).
fn leaf_of(ctx: &EmitCtx, ty: &IrType, app: AppShape) -> ModelLeaf {
    leaf_of_bounded(ctx, ty, app, 64)
}

#[allow(clippy::too_many_lines)] // one arm per IrType variant, deliberately exhaustive
fn leaf_of_bounded(ctx: &EmitCtx, ty: &IrType, app: AppShape, fuel: u32) -> ModelLeaf {
    if fuel == 0 {
        return ModelLeaf::Handle;
    }
    let next = fuel - 1;
    match ty {
        IrType::Fun(_, _) | IrType::SharedFun(_, _) | IrType::FnOnceChain(_, _) => {
            ModelLeaf::Function
        }
        IrType::Cmd(_) => ModelLeaf::Command,
        IrType::Sub(_) => ModelLeaf::Subscription,
        IrType::Task(_) => ModelLeaf::Task,
        IrType::Decoder(_) => ModelLeaf::Decoder,
        IrType::Ui { .. } | IrType::UiPlain(_) => ModelLeaf::ViewValue,
        // Transparent carriers: descend into the first non-admissible child.
        IrType::Maybe(e) | IrType::List(e) | IrType::Set(e) => leaf_of_bounded(ctx, e, app, next),
        IrType::Result(a, b) | IrType::Dict(a, b) => {
            if admissible(ctx, a, app) {
                leaf_of_bounded(ctx, b, app, next)
            } else {
                leaf_of_bounded(ctx, a, app, next)
            }
        }
        IrType::Tuple(es) => es
            .iter()
            .find(|e| !admissible(ctx, e, app))
            .map_or(ModelLeaf::Handle, |e| leaf_of_bounded(ctx, e, app, next)),
        IrType::Record(fields) => fields
            .values()
            .find(|f| !admissible(ctx, f, app))
            .map_or(ModelLeaf::Handle, |f| leaf_of_bounded(ctx, f, app, next)),
        IrType::Enum { home, name, .. } => {
            // A non-admissible user enum: descend into its variant payloads to
            // find the concrete offending leaf.
            for (_, payloads) in ctx.enum_variant_payloads(home, *name) {
                for field_ty in payloads {
                    if !admissible(ctx, field_ty, app) {
                        return leaf_of_bounded(ctx, field_ty, app, next);
                    }
                }
            }
            ModelLeaf::Handle
        }
        // The opaque `Db`/server/live handles are `Handle`. The primitive /
        // `Generic` leaves are admissible so `leaf_of` is never called on them
        // as the sole content of an inadmissible type — they share the same
        // defensive `Handle` fallback rather than a panic.
        IrType::Db
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        // `StreamWriter` is an opaque handle — not a valid Model leaf.
        | IrType::StreamWriter
        // `HttpRequest` is an opaque handle — not a valid Model leaf.
        | IrType::HttpRequest
        // `Regex` is an opaque compiled-pattern handle (not serde) — not a
        // valid Model leaf.
        | IrType::Regex
        // `WsHandle` / `WsServerCfg` are opaque handles — not valid Model leaves.
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
        | IrType::WebReq
        | IrType::WebRoute(_)
        // The `CustomElement.node` custom-element handle is an opaque, non-serde value —
        // it must never live in a Model (session state), exactly like a function
        // value. `admissible()` (via `ir_type_is_serde` = `false`) rejects a
        // Model field of this type; this arm names it in the resulting IPE-L0120.
        | IrType::CustomElement { .. }
        // Cache config / stats + Csv document are kernel-boundary data records,
        // not serde, never persisted to a session store — not valid Model
        // leaves.
        | IrType::CacheCfg
        | IrType::WebSocketClientCfg
        | IrType::CacheStats
        | IrType::CsvDoc
        // Ipe.Email records + provider ADT are kernel-boundary values, not
        // serde, never persisted to a session store — not valid Model leaves.
        | IrType::EmailMessage
        | IrType::EmailAttachment
        | IrType::EmailSesConfig
        | IrType::EmailSmtpConfig
        | IrType::EmailProvider
        // `ProcessRunWithCfg` / `ProcessRunInPtyCfg` are kernel-boundary non-serde
        // input records — not valid Model leaves, same classification as the
        // Email/Cache cfg types.
        | IrType::ProcessRunWithCfg
        | IrType::ProcessRunInPtyCfg
        // Typed-key newtypes are not serde — a `Key`/`Mac`/`EmailAddress` in a
        // Web Model would be a compile-time IPE-L0120.
        | IrType::CryptoKey
        | IrType::CryptoMac
        | IrType::EmailAddress
        // `Locale` is not serde — a transient runtime value, not a session datum.
        | IrType::Locale
        // `SqlFragment` is a query-building value, never
        // persisted to a Web session store — not a valid Model leaf.
        | IrType::SqlFragment
        // `Secret` must never round-trip through a Web session
        // store — not a valid Model leaf. This is the `blame()` classification
        // consulted ONLY after `admissible()` (which uses `ir_type_is_serde`,
        // `false` for `Secret`) has already rejected a Web Model containing
        // one, so a `Secret` Model field is a compile-time IPE-L0120 naming
        // this leaf, never a session-store leak.
        | IrType::Secret
        // `Principal` must never round-trip through a Web session store — a
        // client-hydrated `Principal` would be a forged authenticated identity.
        // Not serde, so `admissible()` rejects it; this arm names it in the
        // resulting IPE-L0120, same classification as `Secret`.
        | IrType::Principal
        // `Path` is a filesystem-boundary value, not serde — same
        // classification as `Secret`: a Web Model field of type `Path` is
        // rejected by `admissible()` (via `ir_type_is_serde` = `false`) and
        // this arm names it in the resulting IPE-L0120.
        | IrType::Path
        // `Url` is a request-boundary value, not serde — same classification as
        // `Path`: a Web Model field of type `Url` is rejected by `admissible()`
        // (via `ir_type_is_serde` = `false`) and this arm names it in the
        // resulting IPE-L0120.
        | IrType::Url
        // `Relative` is a same-origin href projection, not serde — same
        // classification as `Url`: a Web Model field of type `Relative` is
        // rejected by `admissible()` and named in the resulting IPE-L0120.
        | IrType::UrlRelative
        // `Dsn` is a connection-descriptor value carrying a `Secret`, not serde —
        // same classification as `Url`/`Secret`: a Web Model field of type `Dsn`
        // is rejected by `admissible()` and this arm names it in the IPE-L0120.
        | IrType::Dsn
        | IrType::DbLocation
        // An external `Connection` is a live pool handle, never serde — a Model
        // field of this type is rejected by `admissible()`; these arms name it in
        // the IPE-L0120. The phantom markers cannot appear in a Model field but
        // stay listed for exhaustiveness.
        | IrType::Connection
        | IrType::ConnReadOnly
        | IrType::ConnReadWrite
        // A runtime-config `Setting` is a transient carrier (may hold a
        // `Secret`), never serde — a Model field of this type is rejected by
        // `admissible()`; these arms name it in the IPE-L0120. The phantom shape
        // markers cannot appear in a Model field but stay listed for exhaustiveness.
        | IrType::Setting
        | IrType::ShapeWeb
        | IrType::ShapeWebView
        | IrType::ShapeTerminal
        // `AuthConfig`/`TokenSource` are transient authed-route descriptors,
        // never serde — a Model field of either is rejected by `admissible()`;
        // these arms name it in the IPE-L0120.
        | IrType::AuthConfig
        | IrType::TokenSource
        // Shape opaque app leaves — not serde, never a Model field.
        | IrType::WebApp
        | IrType::TuiApp
        | IrType::CliApp
        | IrType::WorkerApp
        // `Order` is a plain three-variant data enum — an admissible leaf.
        // `Decimal` is a Copy newtype — an admissible leaf.
        // `ErrorKind`/`Error`/`ErrorDetails` and the nominal error-payload
        // leaves (`ErrorInfo`/`PanicInfo`/`TypeInfo`, SEAL fix)
        // derive serde — admissible leaves (e.g. a Model's `historyError :
        // Maybe Error` field).
        | IrType::BackoffStrategy
        | IrType::Order
        | IrType::HttpMethod
        | IrType::Decimal
        | IrType::ErrorKind
        | IrType::Error
        | IrType::ErrorDetails
        | IrType::ErrorInfo
        | IrType::PanicInfo
        | IrType::TypeInfo
        | IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes
        | IrType::Json
        | IrType::Generic(_)
        // A row variable never types a concrete Model field (a Model is a
        // closed record); classified with the other opaque leaves for totality.
        | IrType::RowGeneric(_)
        // `SessionHandle` is admissible (serde `i64`), so it never reaches this
        // classifier; present for totality.
        | IrType::SessionHandle => ModelLeaf::Handle,
    }
}
