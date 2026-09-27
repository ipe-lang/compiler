//! Feature-detection walks over lowered `IrType` / `Expr` /
//! `Func` / `Program`: whether a lowered type structurally mentions a given
//! feature-gated runtime type (server, http, csv, cache, secret, decimal,
//! email, locale, json, url, …) or embeds a function.

use ipe_intern::{Interner, Symbol};
use ipe_ir::{Expr, Func, IrType, TypeDef};

/// Total structural walk over an [`IrType`], returning `true` when `leaf`
/// matches the type itself or any type it transitively carries.
///
/// This is the ONE recursion the whole runtime-feature-mention family shares:
/// each per-feature guard (`ir_type_mentions_server` / `_http` / `_csv` /
/// `_secret` / `_json`) is a thin wrapper supplying only its LEAF predicate —
/// the set of nominal `IrType` variants whose emitted Rust form lives in that
/// feature's runtime module. The wrapper never re-implements the recursion, so
/// the family cannot drift into per-feature recursion asymmetry (a carrier one
/// guard descends into but another skips).
///
/// The match is deliberately EXHAUSTIVE with no wildcard arm: a future
/// [`IrType`] variant that introduces a new type-carrying position is a compile
/// error here rather than a silently-missed mention. A guard scanning a subset
/// of carriers under-selects a runtime feature, and the emitted crate then
/// references a type with no definition in scope (E0412/E0425/E0433 — a breach
/// of the ipe-exit-0-then-cargo-build SEAL). Every carrier — including the
/// reference-counted `SharedFun`, the `Set`/`WebRoute`/`Ui` carriers, and the
/// curried `FnOnceChain` — descends uniformly; every non-carrier leaf that is
/// not itself matched by `leaf` terminates the walk. Detection is thereby a
/// SUPERSET of every position the emitter can spell a feature-gated type.
pub(super) fn ir_type_mentions(ty: &IrType, leaf: &impl Fn(&IrType) -> bool) -> bool {
    if leaf(ty) {
        return true;
    }
    match ty {
        // Non-carrier leaves: no nested `IrType`. A leaf that `leaf` did not
        // already accept above cannot mention the feature type.
        IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes
        | IrType::Json
        | IrType::Db
        | IrType::Generic(_)
        | IrType::RowGeneric(_)
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
        | IrType::SqlFragment
        | IrType::Secret
        | IrType::Path
        | IrType::Url
        | IrType::UrlRelative
        | IrType::Dsn
        | IrType::Connection
        | IrType::ConnReadOnly
        | IrType::ConnReadWrite
        | IrType::Setting
        | IrType::ShapeWeb
        | IrType::ShapeWebView
        | IrType::ShapeTerminal
        | IrType::Locale
        | IrType::Principal
        | IrType::ProcessRunWithCfg
        | IrType::ProcessRunInPtyCfg
        | IrType::CacheCfg
        | IrType::CacheStats
        | IrType::WebSocketClientCfg
        | IrType::CsvDoc
        | IrType::CryptoKey
        | IrType::CryptoMac
        | IrType::EmailMessage
        | IrType::EmailAttachment
        | IrType::EmailSesConfig
        | IrType::EmailSmtpConfig
        | IrType::EmailProvider
        | IrType::EmailAddress
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        | IrType::AuthConfig
        | IrType::TokenSource
        | IrType::StreamWriter
        | IrType::HttpRequest
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
        | IrType::WebReq
        | IrType::SessionHandle
        | IrType::Regex
        | IrType::WebApp
        | IrType::TuiApp
        | IrType::CliApp
        | IrType::WorkerApp
        | IrType::UiPlain(_) => false,
        // Single-payload carriers.
        IrType::Task(inner)
        | IrType::Cmd(inner)
        | IrType::Sub(inner)
        | IrType::Decoder(inner)
        | IrType::Maybe(inner)
        | IrType::Set(inner)
        | IrType::WebRoute(inner)
        | IrType::Ui { msg: inner, .. }
        | IrType::List(inner) => ir_type_mentions(inner, leaf),
        // Two-payload carriers.
        IrType::Result(a, b) | IrType::Dict(a, b) | IrType::CustomElement { down: a, up: b } => {
            ir_type_mentions(a, leaf) || ir_type_mentions(b, leaf)
        }
        // Function carriers, all three boxing families.
        IrType::Fun(params, ret)
        | IrType::SharedFun(params, ret)
        | IrType::FnOnceChain(params, ret) => {
            params.iter().any(|p| ir_type_mentions(p, leaf)) || ir_type_mentions(ret, leaf)
        }
        IrType::Tuple(elems) => elems.iter().any(|e| ir_type_mentions(e, leaf)),
        IrType::Record(fields) => fields.values().any(|f| ir_type_mentions(f, leaf)),
        IrType::Enum { args, .. } => args.iter().any(|a| ir_type_mentions(a, leaf)),
    }
}

/// Does `ty` mention any opaque `Ipe.Http.Server` runtime type
/// (`ServerRequest` / `ServerResponse` / `ServerRoute` / `ServerCookie`)?
///
/// `Ipe.Http.Server.Response` is a record alias that folds to
/// `IrType::ServerResponse`, so a program can *use* the server types — build a
/// `Response` record literal, annotate `Request -> Task Error Response` — WITHOUT
/// ever calling a server kernel. The `server` runtime module (which defines
/// these structs) is only appended to the emitted crate when it is used, so the
/// used-check must include the TYPES, not just the kernels; otherwise
/// `ServerResponse` is referenced but undefined (E0412 — a SEAL breach).
pub(super) fn ir_type_mentions_server(ty: &IrType) -> bool {
    // The `server`-gated opaque handles all map to `RuntimeFeatureId::Server` in
    // the SSOT; routing through it keeps this view total and drift-free (a new
    // `server`-gated leaf is detected here the day its requirement is declared).
    ir_type_mentions(ty, &|t| {
        ipe_ir::ir_type_feature_requirement(t) == Some(ipe_ir::RuntimeFeatureId::Server)
    })
}

/// `true` when `ty` mentions one of the synthesized Prelude `enums`.
///
/// Each is an `IrType::Enum` with empty home and the interned builtin name
/// (`SqlValue`, `SqlField`, `ProjectionTerm`, …). A surviving emitted type can
/// reference one in a field — e.g. `Ipe.Db.Store`'s query `Cond` carries a
/// `SqlValue` — without any function constructing the value, so the
/// synthetic-enum injection must follow type mentions as well as value
/// construction, or the backend has no Rust name for the enum (ICE). Mirrors
/// [`ir_type_mentions_server`] for the SQL value surface.
pub(super) fn ir_type_mentions_sqlvalue(ty: &IrType, enums: &[Symbol]) -> bool {
    ir_type_mentions(ty, &|t| match t {
        IrType::Enum { home, name, .. } => home.0.is_empty() && enums.contains(name),
        _ => false,
    })
}

/// `true` when `ty` mentions an `Ipe.Http`-client opaque type — `HttpRequest`
/// or `HttpMethod`, both defined in the `http_client` runtime module. A
/// function that merely passes such a value through (without itself calling a
/// client kernel) still references the type in emitted code, so the module and
/// its `reqwest` dependency must be present. Mirrors [`ir_type_mentions_server`]
/// for the client surface.
pub(super) fn ir_type_mentions_http(ty: &IrType) -> bool {
    ir_type_mentions(ty, &|t| {
        ipe_ir::ir_type_feature_requirement(t) == Some(ipe_ir::RuntimeFeatureId::HttpClient)
    })
}

/// `true` when `ty` mentions the `Ipe.Csv` opaque type `CsvDoc`, defined in the
/// `csv` runtime module. A bare `{ header : List String, rows : List (List
/// String) }` record shape folds to `IrType::CsvDoc` and emits a bare `CsvDoc`
/// reference resolved through the module's `pub use csv::*` glob, so a function
/// that merely names such a value — WITHOUT itself calling a `Csv` kernel —
/// still references the type in emitted code, and the module (and its `csv`
/// dependency) must be present. Mirrors [`ir_type_mentions_http`].
pub(super) fn ir_type_mentions_csv(ty: &IrType) -> bool {
    ir_type_mentions(ty, &|t| {
        ipe_ir::ir_type_feature_requirement(t) == Some(ipe_ir::RuntimeFeatureId::Csv)
    })
}

/// `true` when `ty` mentions the `Ipe.Cache` config record `CacheCfg`
/// (`IrType::CacheCfg`, rendered `ipe_runtime::cache::CacheCfg`) or the stats
/// record `CacheStats` (`IrType::CacheStats`), both defined in the `cache`
/// runtime module. `Cache.defaultCfg` and the `withMaxEntries` / `withTTL` /
/// `withMaxBytes` builders are pure Ipê source that construct a `CacheCfg`
/// record literal with NO kernel call, so a program that only builds a config
/// (never calling `Cache.new`) still emits a `CacheCfg` reference resolved
/// through the module's `pub use cache::*` glob — omitting this guard would
/// leave that reference undefined (E0433 — a SEAL breach). This guard covers
/// the folded config/stats records; the opaque handle enum is covered
/// separately by [`ir_type_mentions_cache_handle`] (which needs the interner to
/// resolve its `Ipe.Cache.Cache` identity). Mirrors [`ir_type_mentions_csv`].
pub(super) fn ir_type_mentions_cache(ty: &IrType) -> bool {
    ir_type_mentions(ty, &|t| {
        ipe_ir::ir_type_feature_requirement(t) == Some(ipe_ir::RuntimeFeatureId::CacheKernel)
    })
}

/// `true` when `ty` mentions the opaque `Ipe.Cache` handle enum — an
/// `IrType::Enum` whose `home` resolves to `["Ipe", "Cache"]` and whose `name`
/// resolves to `"Cache"` (the same identity [`Lowerer::is_cache_handle_con`]
/// encodes). The stdlib declares `type Cache k v = Cache Int` with a public
/// constructor whose `EnumDef` is suppressed (it is backed by the runtime
/// `IpeCacheHandle`), so user code can NAME the handle in a signature,
/// CONSTRUCT it (`Cache 7`), or PATTERN-MATCH it (`case c of Cache raw -> …`)
/// WITHOUT calling any `Cache.*` kernel and WITHOUT mentioning `CacheCfg` /
/// `CacheStats`. Every such position emits an `IpeCacheHandle` reference resolved
/// through the module's `pub use cache::*` glob, so — like
/// [`ir_type_mentions_cache`] for the config record — the guard must include the
/// handle type, or the emitted crate references `IpeCacheHandle` with no
/// definition in scope (E0425/E0433 — a SEAL breach). Symbol resolution is
/// required to match the interned `home` / `name`, so the interner is threaded
/// in rather than a bare `matches!`. Stays a TOTAL walk via
/// [`ir_type_mentions`].
pub(super) fn ir_type_mentions_cache_handle(ty: &IrType, interner: &Interner) -> bool {
    ir_type_mentions(ty, &|t| match t {
        IrType::Enum { home, name, .. } => {
            interner.resolve(*name) == Some("Cache")
                && matches!(
                    home.0.as_slice(),
                    [a, b]
                        if interner.resolve(*a) == Some("Ipe")
                            && interner.resolve(*b) == Some("Cache")
                )
        }
        _ => false,
    })
}

/// `true` when `ty` mentions a builtin `Ipe.Http.Stream` opaque type — the
/// `ChunkEvent` chunk-event enum (backed by
/// `ipe_runtime::http_stream::ChunkEvent`) or the `StreamId` handle (backed by
/// `ipe_runtime::http_stream::IpeStreamId`). Both lower to `IrType::Enum` with an
/// empty `home` and a `name` resolving to the source identifier (no synthetic
/// `EnumDef`, so no `home` path to match — the empty home is the identity).
///
/// `HttpStream.chunks` produces a `ChunkEvent`-payloaded message and takes a
/// `StreamId`, so a program that names either type in a signature, record field,
/// or enum payload — while the `HttpStream.chunks` kernel itself sits behind an
/// unreachable binding, so the kernel scan never records it — still emits a
/// `ChunkEvent<…>` / `IpeStreamId` reference resolved through the module's
/// `pub use http_stream::*` glob. The `http_stream` module is declared only by
/// the `server` append ([`RuntimeModule::Server`]), so this mention must set
/// `uses_server`, or the emitted crate references the type with no definition in
/// scope (E0425 `ChunkEvent` / E0412 `IpeStreamId` — a SEAL breach). Symbol
/// resolution is required to match the interned `name`, so the interner is
/// threaded in. Mirrors [`ir_type_mentions_cache_handle`].
pub(super) fn ir_type_mentions_http_stream(ty: &IrType, interner: &Interner) -> bool {
    ir_type_mentions(ty, &|t| match t {
        IrType::Enum { home, name, .. } => {
            home.0.is_empty() && matches!(interner.resolve(*name), Some("ChunkEvent" | "StreamId"))
        }
        _ => false,
    })
}

/// `true` when `ty` mentions the `Ipe.Secret` opaque type `Secret`, defined in
/// the `secret` runtime module (backed by `ipe_runtime::secret::Secret`). A
/// function that only forwards a `Secret` parameter — e.g. an `Ipe.Auth` token
/// wrapper whose signature names `Secret` but calls no `Secret.*` kernel — still
/// emits a `Secret` reference resolved through the module's `pub use secret::*`
/// glob, so the module (and its `zeroize` dependency) must be present.
/// `Algorithm` also folds to `IrType::Secret` (see the JWT `Algorithm` alias),
/// so this guard covers it too. Mirrors [`ir_type_mentions_csv`].
pub(super) fn ir_type_mentions_secret(ty: &IrType) -> bool {
    ir_type_mentions(ty, &|t| {
        ipe_ir::ir_type_feature_requirement(t) == Some(ipe_ir::RuntimeFeatureId::Secret)
    })
}

/// `true` when `ty` mentions the `Ipe.Decimal` opaque type `Decimal`, defined in
/// the `decimal` runtime module (backed by `ipe_runtime::decimal::Decimal`). The
/// `Ipe.Money` ADT carries a `Decimal` amount field, so a program that names a
/// `Money` (or a bare `Decimal`) value in ANY emittable type position — a
/// signature, a record field, or an enum-variant payload — emits a
/// `ipe_runtime::decimal::Decimal` reference resolved through the module's
/// `pub use decimal::*` glob, WITHOUT necessarily calling a `Decimal.*`/`Money.*`
/// kernel (the `Money.parseCurrency` / `currencyCode` surface is pure Ipê source
/// over the ADT). Dropping `decimal.rs` and `rust_decimal` on the call-site flag
/// alone would emit that reference with no module in scope (E0433 — a SEAL
/// breach). Mirrors [`ir_type_mentions_secret`].
pub(super) fn ir_type_mentions_decimal(ty: &IrType) -> bool {
    ir_type_mentions(ty, &|t| {
        ipe_ir::ir_type_feature_requirement(t) == Some(ipe_ir::RuntimeFeatureId::Decimal)
    })
}

/// `true` when `ty` mentions any `Ipe.Email` runtime type (`EmailAddress`,
/// `EmailMessage`, `EmailAttachment`, `EmailSesConfig`, `EmailSmtpConfig`, or
/// `EmailProvider`) anywhere in its structure. These types are defined in
/// `email.rs`, which the emitter appends to `ipe_runtime/mod.rs` only when
/// `uses_email` is set. A program that names any of them in a signature, record
/// field, or enum payload — without calling `Email.send` or any `EmailAddress`
/// kernel — still emits a reference the module's `pub use email::*` glob must
/// satisfy. Mirrors [`ir_type_mentions_secret`].
pub(super) fn ir_type_mentions_email(ty: &IrType) -> bool {
    ir_type_mentions(ty, &|t| {
        matches!(
            t,
            IrType::EmailAddress
                | IrType::EmailMessage
                | IrType::EmailAttachment
                | IrType::EmailSesConfig
                | IrType::EmailSmtpConfig
                | IrType::EmailProvider
        )
    })
}

/// `true` when `ty` mentions the `Ipe.Locale` opaque type (`IrType::Locale`,
/// rendered `ipe_runtime::locale::Locale`). The `locale.rs` module is not
/// declared in the base `mod.rs` template; a program that names `Locale` in
/// any emittable type position emits a reference resolved only when the module
/// is declared and the `locale` Cargo feature is enabled. Mirrors
/// [`ir_type_mentions_secret`].
pub(super) fn ir_type_mentions_locale(ty: &IrType) -> bool {
    ir_type_mentions(ty, &|t| matches!(t, IrType::Locale))
}

/// `true` when `ty` mentions `Json` (`IrType::Json`, rendered `JsonVal`) or a
/// `Decoder<T>` (`IrType::Decoder`, rendered `Decoder<…>`) anywhere in its
/// structure — the two types the fixed prelude aliases against the `json` runtime
/// module. A `Decoder` node is itself a mention (the `Decoder<T>` alias must
/// exist) AND its inner type is scanned by the shared walk. Used at the
/// module-assembly site to keep the two prelude aliases + the `json` feature for a
/// program that NAMES either type in a signature, record field, or enum payload
/// even when it calls no `Json.*` kernel (a decoder forwarded as a parameter) —
/// the type-mention guard the fail-closed `uses_json` requires.
pub(super) fn ir_type_mentions_json(ty: &IrType) -> bool {
    ir_type_mentions(ty, &|t| {
        ipe_ir::ir_type_feature_requirement(t) == Some(ipe_ir::RuntimeFeatureId::Json)
    })
}

/// `true` when `ty` mentions the `Ipe.Url` opaque type `Url`, rendered
/// `ipe_runtime::url::Url` (feature-gated on `url`). A stdlib type can EMBED a
/// `Url` field (`{ src : Url }`) and be brought into a program by a plain import
/// with no `Url` KERNEL call, so a program that only NAMES a `Url` value in a
/// signature, record field, or enum-variant payload still emits a
/// `ipe_runtime::url::Url` reference resolved through the gated module — dropping
/// `url` on the call-site flag alone leaves that reference dangling (E0433 — the
/// breach this closes). Routed through the [`ipe_ir::ir_type_feature_requirement`]
/// SSOT so the leaf can never again be silently un-gated. Mirrors
/// [`ir_type_mentions_secret`].
pub(super) fn ir_type_mentions_url(ty: &IrType) -> bool {
    ir_type_mentions(ty, &|t| {
        ipe_ir::ir_type_feature_requirement(t) == Some(ipe_ir::RuntimeFeatureId::Url)
    })
}

/// Does any [`IrType`] occurring ANYWHERE in `expr` satisfy `pred`?
///
/// A runtime-feature guard (`uses_json` / `uses_server` / `uses_http`) must be a
/// SUPERSET of the emitter's type rendering: whenever [`crate::emit_types`] will
/// spell a feature-gated type (`JsonVal`, `ServerResponse`, `HttpRequest`), the
/// corresponding feature must be selected, or the emitted crate references a type
/// with no definition in scope (E0412/E0425/E0433 — a SEAL breach). The emitter
/// renders types not only from a function's SIGNATURE but from every type carried
/// inside its BODY — a local lambda's parameter/return types, a `let`-bound
/// closure's, an empty list's element type, a record-field read's field type, a
/// reified function value's type, a tail-loop's parameter types. A guard scanning
/// signatures alone under-approximates and drops a feature the body still spells.
///
/// This walker closes that gap: it visits every type-carrying position of the
/// expression tree and applies `pred` (an `ir_type_mentions_*` predicate, itself
/// fully recursive over a type's structure). Enumerated exhaustively (no `_`
/// catch-all) so a future [`Expr`] variant that introduces a new type position is
/// a compile error here — never a silently-missed render (SEAL discipline).
pub(super) fn expr_type_mentions(expr: &Expr, pred: &impl Fn(&IrType) -> bool) -> bool {
    // Types carried directly at this node.
    let here = match expr {
        Expr::List { elem, .. } => pred(elem),
        Expr::Access { field_ty, .. } => pred(field_ty),
        Expr::Lambda { params, ret, .. } | Expr::SharedLambda { params, ret, .. } => {
            params.iter().any(|(_, t)| pred(t)) || pred(ret)
        }
        Expr::FuncValue { ty, .. } => pred(ty),
        Expr::TailLoop { params, .. } => params.iter().any(|(_, t)| pred(t)),
        Expr::Record { ty, .. } => matches!(ty, Some(t) if pred(t)),
        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::PathLit(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::Var(_)
        | Expr::CloneVar(_)
        | Expr::Ctor { .. }
        | Expr::BinOp { .. }
        | Expr::Let { .. }
        | Expr::Destructure { .. }
        | Expr::If { .. }
        | Expr::Match(_)
        | Expr::Call { .. }
        | Expr::Tuple(_)
        | Expr::Cons { .. }
        | Expr::ListIndexClone { .. }
        | Expr::ListLenCheck { .. }
        | Expr::Update { .. }
        | Expr::Apply { .. }
        | Expr::TaskSeq { .. }
        | Expr::TailRecur { .. } => false,
    };
    if here {
        return true;
    }
    // Recurse into every child expression.
    match expr {
        Expr::BinOp { lhs, rhs, .. } => {
            expr_type_mentions(lhs, pred) || expr_type_mentions(rhs, pred)
        }
        Expr::Let { value, body, .. } | Expr::Destructure { value, body, .. } => {
            expr_type_mentions(value, pred) || expr_type_mentions(body, pred)
        }
        Expr::If { cond, then_, else_ } => {
            expr_type_mentions(cond, pred)
                || expr_type_mentions(then_, pred)
                || expr_type_mentions(else_, pred)
        }
        Expr::Match(m) => {
            expr_type_mentions(m.scrutinee(), pred)
                || m.arms().iter().any(|arm| {
                    expr_type_mentions(&arm.body, pred)
                        || arm
                            .guard
                            .as_ref()
                            .is_some_and(|g| expr_type_mentions(g, pred))
                })
        }
        Expr::Call { args, .. }
        | Expr::Tuple(args)
        | Expr::Ctor { args, .. }
        | Expr::TailRecur { args } => args.iter().any(|a| expr_type_mentions(a, pred)),
        Expr::List { items, .. } => items.iter().any(|e| expr_type_mentions(e, pred)),
        Expr::Cons { head, tail } => {
            expr_type_mentions(head, pred) || expr_type_mentions(tail, pred)
        }
        Expr::ListIndexClone { list, .. } | Expr::ListLenCheck { list, .. } => {
            expr_type_mentions(list, pred)
        }
        Expr::Record { fields, .. } => fields.iter().any(|(_, e)| expr_type_mentions(e, pred)),
        Expr::Update { record, fields } => {
            expr_type_mentions(record, pred)
                || fields.iter().any(|(_, e)| expr_type_mentions(e, pred))
        }
        Expr::Lambda { body, .. }
        | Expr::SharedLambda { body, .. }
        | Expr::TailLoop { body, .. } => expr_type_mentions(body, pred),
        Expr::Apply { func, args } => {
            expr_type_mentions(func, pred) || args.iter().any(|a| expr_type_mentions(a, pred))
        }
        Expr::TaskSeq { effect, rest } => {
            expr_type_mentions(effect, pred) || expr_type_mentions(rest, pred)
        }
        Expr::Access { record, .. } => expr_type_mentions(record, pred),
        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::PathLit(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::Var(_)
        | Expr::CloneVar(_)
        | Expr::FuncValue { .. } => false,
    }
}

/// Does any type-carrying position of a whole [`Func`] satisfy `pred`? The
/// SINGLE per-function type scan every runtime-feature guard shares, so no guard
/// can under-approximate by forgetting a position. It covers, exhaustively:
///
/// * the return type,
/// * every value-level parameter type,
/// * every type carried inside the body ([`expr_type_mentions`]),
/// * every field type of every row-generic parameter ([`Func::row_params`]).
///
/// The row-field arm is what makes detection ⊇ emission for a row-polymorphic
/// parameter: a row field typed `Json` / `Secret` / … is emitted as the witness
/// trait's associated type (`R1: IpeHasPayload<Payload = Json>`) even when the
/// body never reads it, so a guard that scanned only params / ret / body would
/// drop the feature the witness impl still spells (the emitted crate would then
/// reference a type with no definition in scope — E0412). The row's field types
/// live ONLY in `row_params` — the parameter itself is the opaque `RowGeneric` —
/// so this is the sole position that reaches them.
pub(super) fn func_type_mentions(f: &Func, pred: &impl Fn(&IrType) -> bool) -> bool {
    pred(&f.ret)
        || f.params.iter().any(|(_, t)| pred(t))
        || expr_type_mentions(&f.body, pred)
        || f.row_params
            .iter()
            .any(|r| r.fields.iter().any(|(_, t)| pred(t)))
}

/// Does `pred` match any type position the WHOLE program can emit? The single
/// per-feature program scan every runtime-feature guard shares, so no feature's
/// `uses_*` flag can under-approximate by scanning a subset of the emittable
/// surface. It covers, exhaustively, every place the emitter renders a type:
///
/// * every function's signature + body + row-generic fields
///   ([`func_type_mentions`]),
/// * every synthesised / collected closed record type (a record standing alone
///   in a Model or a bare literal, reached by no function mention),
/// * every user enum-def variant payload (a feature type sitting only in a
///   variant field, reached by no function mention).
///
/// The record and enum-def arms are what make detection ⊇ emission for an
/// opaque feature type embedded ONLY in a data declaration — a `CsvDoc` record
/// field, a `Secret` enum payload — with no function ever naming it. A guard
/// scanning only `funcs` would drop the feature the emitted struct/enum still
/// spells (the crate would reference a type with no definition in scope —
/// E0412/E0433). Every runtime-feature guard runs this identical surface, so
/// the family cannot drift into per-feature scan asymmetry.
pub(super) fn program_type_mentions(
    funcs: &[Func],
    records: &[IrType],
    types_ir: &[TypeDef],
    pred: &impl Fn(&IrType) -> bool,
) -> bool {
    funcs.iter().any(|f| func_type_mentions(f, pred))
        || records.iter().any(pred)
        || types_ir.iter().any(|td| match td {
            TypeDef::Enum(e) => e.variants.iter().any(|v| v.fields.iter().any(pred)),
        })
}

/// Push every closed record shape the expression tree's type-carrying slots
/// hold (a record literal's own `ty`, a field-access `field_ty`, a lambda's
/// param/return types, …) into `out`, deduping through `seen`.
///
/// The purpose is to surface a GENERIC record that lives only in a function
/// body — one appearing in no signature, which [`Lowerer::collect_record_types`]
/// deliberately skips (a var-bearing region record has no live poly context to
/// name it). Its shape is already fully formed here, each field carrying its
/// solved [`IrType::Generic`], so it feeds the backend's record-shape prepass
/// directly; the backend recurses into each pushed shape to synthesise (and
/// alpha-reconcile) the generic struct.
///
/// A record whose IR embeds a function type is NOT surfaced — the same G-b gate
/// [`Lowerer::collect_records_in_ty`] applies: the `Web.tea` cfg record's
/// `Box<dyn Fn>` fields cannot back a derivable struct, and it is consumed
/// structurally rather than materialised.
///
/// Enumerated exhaustively (no `_` catch-all in the type-position arm) so a new
/// type-carrying [`Expr`] variant is a compile error here, never a silently
/// missed shape (SEAL discipline, matching [`expr_type_mentions`]).
#[allow(clippy::too_many_lines)] // two exhaustive per-variant `Expr` matches (types-here + recurse) push it past 100
pub(super) fn collect_body_record_shapes(
    expr: &Expr,
    out: &mut Vec<IrType>,
    seen: &mut std::collections::HashSet<IrType>,
) {
    let mut consider = |ty: &IrType| {
        if matches!(ty, IrType::Record(_)) && !ir_contains_fun(ty) && seen.insert(ty.clone()) {
            out.push(ty.clone());
        }
    };
    // Types carried directly at this node — the same positions `expr_type_mentions`
    // visits.
    match expr {
        Expr::List { elem, .. } => consider(elem),
        Expr::Access { field_ty, .. } => consider(field_ty),
        Expr::Lambda { params, ret, .. } | Expr::SharedLambda { params, ret, .. } => {
            for (_, t) in params {
                consider(t);
            }
            consider(ret);
        }
        Expr::FuncValue { ty, .. } => consider(ty),
        Expr::TailLoop { params, .. } => {
            for (_, t) in params {
                consider(t);
            }
        }
        Expr::Record { ty, .. } => {
            if let Some(t) = ty {
                consider(t);
            }
        }
        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::PathLit(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::Var(_)
        | Expr::CloneVar(_)
        | Expr::Ctor { .. }
        | Expr::BinOp { .. }
        | Expr::Let { .. }
        | Expr::Destructure { .. }
        | Expr::If { .. }
        | Expr::Match(_)
        | Expr::Call { .. }
        | Expr::Tuple(_)
        | Expr::Cons { .. }
        | Expr::ListIndexClone { .. }
        | Expr::ListLenCheck { .. }
        | Expr::Update { .. }
        | Expr::Apply { .. }
        | Expr::TaskSeq { .. }
        | Expr::TailRecur { .. } => {}
    }
    // Recurse into every child expression.
    match expr {
        Expr::BinOp { lhs, rhs, .. } => {
            collect_body_record_shapes(lhs, out, seen);
            collect_body_record_shapes(rhs, out, seen);
        }
        Expr::Let { value, body, .. } | Expr::Destructure { value, body, .. } => {
            collect_body_record_shapes(value, out, seen);
            collect_body_record_shapes(body, out, seen);
        }
        Expr::If { cond, then_, else_ } => {
            collect_body_record_shapes(cond, out, seen);
            collect_body_record_shapes(then_, out, seen);
            collect_body_record_shapes(else_, out, seen);
        }
        Expr::Match(m) => {
            collect_body_record_shapes(m.scrutinee(), out, seen);
            for arm in m.arms() {
                collect_body_record_shapes(&arm.body, out, seen);
                if let Some(g) = arm.guard.as_ref() {
                    collect_body_record_shapes(g, out, seen);
                }
            }
        }
        Expr::Call { args, .. }
        | Expr::Tuple(args)
        | Expr::Ctor { args, .. }
        | Expr::TailRecur { args } => {
            for a in args {
                collect_body_record_shapes(a, out, seen);
            }
        }
        Expr::List { items, .. } => {
            for e in items {
                collect_body_record_shapes(e, out, seen);
            }
        }
        Expr::Cons { head, tail } => {
            collect_body_record_shapes(head, out, seen);
            collect_body_record_shapes(tail, out, seen);
        }
        Expr::ListIndexClone { list, .. } | Expr::ListLenCheck { list, .. } => {
            collect_body_record_shapes(list, out, seen);
        }
        Expr::Record { fields, .. } => {
            for (_, e) in fields {
                collect_body_record_shapes(e, out, seen);
            }
        }
        Expr::Update { record, fields } => {
            collect_body_record_shapes(record, out, seen);
            for (_, e) in fields {
                collect_body_record_shapes(e, out, seen);
            }
        }
        Expr::Lambda { body, .. }
        | Expr::SharedLambda { body, .. }
        | Expr::TailLoop { body, .. } => collect_body_record_shapes(body, out, seen),
        Expr::Apply { func, args } => {
            collect_body_record_shapes(func, out, seen);
            for a in args {
                collect_body_record_shapes(a, out, seen);
            }
        }
        Expr::TaskSeq { effect, rest } => {
            collect_body_record_shapes(effect, out, seen);
            collect_body_record_shapes(rest, out, seen);
        }
        Expr::Access { record, .. } => collect_body_record_shapes(record, out, seen),
        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::PathLit(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::Var(_)
        | Expr::CloneVar(_)
        | Expr::FuncValue { .. } => {}
    }
}

pub(super) fn ir_contains_fun(ty: &IrType) -> bool {
    match ty {
        // A curried `FnOnce` chain is the same boxed-closure family as `Fun`; the
        // promoted `Arc<dyn Fn>` (`SharedFun`) is still a function value, so the
        // reuse gate must keep seeing it as fn-bearing.
        IrType::Fun(_, _) | IrType::SharedFun(_, _) | IrType::FnOnceChain(_, _) => true,
        // `IpeTask<E,A>`, `IpeCmd<M>`, `IpeSub<M>` are opaque runtime types; the
        // inner type parameter might itself embed a function, so recurse.
        IrType::Task(inner) | IrType::Cmd(inner) | IrType::Sub(inner) => ir_contains_fun(inner),
        IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes
        | IrType::Json
        // `Decoder<T>` is an opaque struct, not a function type.
        | IrType::Decoder(_)
        // `Db` is an opaque connection pool handle, not a function type.
        | IrType::Db
        // Opaque server types are opaque handles, not function types.
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        // `StreamWriter` is an opaque stream handle — not a function type.
        | IrType::StreamWriter
        // `HttpRequest` is an opaque handle — not a function type.
        | IrType::HttpRequest
        // `Regex` is an opaque compiled-pattern handle — not a function type.
        | IrType::Regex
        // `WsHandle` / `WsServerCfg` are opaque handles — not function types.
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
        | IrType::Generic(_)
        // A row variable erases to a witness-bounded generic; it embeds no
        // function type of its own.
        | IrType::RowGeneric(_)
        // nullary plain types (`Length`, `Color`, etc.) trivially contain no
        // functions.  `WebReq` is an opaque handle with no `Fn` fields.
        | IrType::UiPlain(_)
        | IrType::WebReq
        | IrType::SessionHandle
        // `Order` (LT/EQ/GT) is a primitive leaf — no embedded function.
        // `HttpMethod` is a closed 7-variant unit ADT — no embedded function.
        // `Decimal` is a Copy newtype — no embedded function.
        // `ErrorKind`/`Error`/`ErrorDetails` and the nominal error-payload
        // leaves (`ErrorInfo`/`PanicInfo`/`TypeInfo`, SEAL fix)
        // are leaves — no embedded function.
        // `BackoffStrategy` is a Copy leaf — no embedded function.
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
        // `SqlFragment` is an opaque query-building value — no embedded function.
        // `Secret` is an opaque sealed string wrapper — no embedded function.
        // `Path` is an opaque validated string wrapper — no embedded function.
        // `Url` is an opaque validated URL wrapper — no embedded function.
        | IrType::SqlFragment
        | IrType::Secret
        | IrType::Path
        | IrType::Url
        | IrType::UrlRelative
        | IrType::Dsn
        | IrType::Connection
        | IrType::ConnReadOnly
        | IrType::ConnReadWrite
        | IrType::Setting
        | IrType::ShapeWeb
        | IrType::ShapeWebView
        | IrType::ShapeTerminal
        // Process-run-with cfg + Cache config / stats + Csv document are plain
        // data records — no function.
        | IrType::ProcessRunWithCfg
        | IrType::ProcessRunInPtyCfg
        | IrType::CacheCfg
        | IrType::WebSocketClientCfg
        | IrType::CacheStats
        | IrType::CsvDoc
        // Ipe.Email records + provider ADT — plain data, no function.
        | IrType::EmailMessage
        | IrType::EmailAttachment
        | IrType::EmailSesConfig
        | IrType::EmailSmtpConfig
        | IrType::EmailProvider
        // Typed-key newtypes — opaque scalar wrappers, no embedded function.
        | IrType::CryptoKey
        | IrType::CryptoMac
        | IrType::EmailAddress
        | IrType::Locale
        | IrType::Principal
        // `AuthConfig` / `TokenSource` are opaque descriptors — no embedded
        // function.
        | IrType::AuthConfig
        | IrType::TokenSource
        // Shape app leaves — opaque handles wrapping runtime event loops,
        // no embedded Ipê function.
        | IrType::WebApp
        | IrType::TuiApp
        | IrType::CliApp
        | IrType::WorkerApp => false,
        // `WebRoute page` carries the page type it builds — recurse (the
        // route's own builder closure is runtime-internal, not a Ipê `Fn`).
        IrType::WebRoute(page) => ir_contains_fun(page),
        // The widget handle carries no function; its seal types are canon-proven
        // function-free, but recurse for structural faithfulness.
        IrType::CustomElement { down, up } => ir_contains_fun(down) || ir_contains_fun(up),
        IrType::Enum { args, .. } => args.iter().any(ir_contains_fun),
        IrType::Maybe(elem) | IrType::List(elem) => ir_contains_fun(elem),
        IrType::Result(err, ok) => ir_contains_fun(err) || ir_contains_fun(ok),
        IrType::Dict(k, v) => ir_contains_fun(k) || ir_contains_fun(v),
        IrType::Set(a) => ir_contains_fun(a),
        IrType::Tuple(elems) => elems.iter().any(ir_contains_fun),
        IrType::Record(fields) => fields.values().any(ir_contains_fun),
        // `Element<M>` / `Html<M>` carry a msg type parameter — recurse.
        IrType::Ui { msg, .. } => ir_contains_fun(msg),
    }
}
