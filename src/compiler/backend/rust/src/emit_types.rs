//! Type emission: user enums and their `IpeStringify` impls, plus
//! IR-type → Rust-type rendering.
//!
//! Ports the relevant arms of `Ipê/Generate/Rust/Builder/TypeEmitter.hs`
//! (`unionToRustTypeDef`) and `Emitter.hs` (`typeDefToString` / the enum
//! `ipeStringifyEnumImpl`). The byte target is golden `main.rs` lines 31–43.

use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::{Symbol, rust_fmt_str_lit, rust_str_lit};
use ipe_ir::{EnumDef, IrType, UiCtor, UiPlain, refused_marker};

use std::collections::BTreeSet;

use ipe_ir::Program;

use crate::doc::Doc;
use crate::items::{Items, braced};
use crate::naming::{
    field_witness_assoc_type_name, field_witness_getter_name, field_witness_trait_name,
    mangle_reserved,
};
use crate::render::{RenderConfig, render_seeded};
use crate::{EmitCtx, RecordStruct};

/// SSOT tripwire pinning every unified-colour carrier string this module emits
/// (`ipe_runtime::color::{Color, ColorError, TermProfile, AnsiColor}`) to a live
/// type in the runtime colour module: a rename or removal in `ipe_runtime::color`
/// makes the test target fail to compile, so the emitted carrier can never point
/// at a missing type (the SEAL). The runtime crate is a `dev-dependency` of the
/// backend, so the pin lives in the test target — matching the existing
/// registry-parity tripwires (`canon_equals_registry`).
#[cfg(test)]
const _COLOR_CARRIER_SSOT: fn() = || {
    let _: Option<ipe_runtime_rust::color::Color> = None;
    let _: Option<ipe_runtime_rust::color::ColorError> = None;
    let _: Option<ipe_runtime_rust::color::TermProfile> = None;
    let _: Option<ipe_runtime_rust::color::AnsiColor> = None;
};

/// Render a `format!(<fmt>, <arg>, …)` `IpeStringify` body natively, laid out
/// exactly as `rustfmt --edition 2024 --style-edition 2024` would — the record
/// `ipe_show` body and the payload-variant enum arm.
///
/// `rustfmt` keeps the whole call on one line when its argument text (the span
/// between `format!(` and the closing `)`) fits `fn_call_width` (60) AND the full
/// line fits `max_width` (100); otherwise it breaks one argument per line
/// (WITHOUT a trailing comma, as it does for every macro call), each argument at
/// one block-indent step past `block_indent`, the `)` dedented back to
/// `block_indent`. This is precisely a [`Doc::CallArgs`] with
/// `trailing_comma == false`, so the shared renderer reproduces the decision by
/// construction.
///
/// `open_col` is the column the `format!` token lands on — used only for the
/// single-line fit test — and `block_indent` is the indent a broken line nests
/// from: for the record body both are 8 (two block-indent levels deep in
/// `ipe_show`); for an enum arm `open_col` is the column after the `… => ` arm
/// head while `block_indent` is the arm's own indent (12). The returned string
/// carries no leading spaces for `open_col` — the caller has already written the
/// prefix on that line — and every broken line carries its own absolute indent.
fn render_stringify_format(
    fmt_literal: &str,
    args: &[String],
    open_col: usize,
    block_indent: usize,
) -> String {
    let elems: Vec<Doc> = std::iter::once(Doc::owned(fmt_literal.to_owned()))
        .chain(args.iter().map(|a| Doc::owned(a.clone())))
        .collect();
    let call = Doc::call_args(
        Doc::text("format!("),
        elems,
        Doc::text(")"),
        // A macro argument list breaks without a trailing comma.
        false,
    );
    render_seeded(&call, RenderConfig::default(), block_indent, open_col)
}

/// `rustfmt`'s `max_width` (default 100): the widest line the formatter leaves
/// unbroken.
const MAX_WIDTH: usize = 100;

/// `rustfmt`'s `fn_call_width` (default 60): the widest a call's argument text may
/// be and still lay out flat between its delimiters.
const FN_CALL_WIDTH: usize = 60;

/// Render a payload-variant enum arm's `Pat => format!(…)` tail exactly as
/// `rustfmt` lays it out, returning the whole arm line(s) including the arm head
/// and the trailing `,`.
///
/// `rustfmt` decides in three tiers, in order:
///
///   * INLINE — the whole `arm_head format!(…),` fits `max_width` and the
///     argument text fits `fn_call_width`: one line.
///   * BLOCK-WRAP — the call's argument text fits `fn_call_width` (so the call
///     itself does not want to break its delimiters) but the inline arm overflows
///     `max_width`: `rustfmt` wraps the body in a synthesized brace block —
///     `Pat => {\n    format!(…)\n}` (no trailing comma) — with the `format!` on
///     its own line at the arm indent + 4, where it fits.
///   * DELIMITER-BREAK — the argument text itself exceeds `fn_call_width`: the
///     `format!` breaks one argument per line in place after the `=> `, the `)`
///     dedented to the arm indent, and the arm keeps its trailing `,`.
///
/// `arm_head` is the `            {Enum}::{Variant}(binders) => ` prefix at block
/// indent 12; `fmt_literal` and `args` are the `format!` operands.
fn render_stringify_enum_arm(arm_head: &str, fmt_literal: &str, args: &[String]) -> String {
    const ARM_INDENT: usize = 12;
    let open_col = arm_head.chars().count();

    // The argument text between `format!(` and `)` — `rustfmt`'s `fn_call_width`
    // span — and the full inline arm line width.
    let inline_args = args.join(", ");
    let args_text = if args.is_empty() {
        fmt_literal.to_owned()
    } else {
        format!("{fmt_literal}, {inline_args}")
    };
    let args_width = args_text.chars().count();
    let inline_call = format!("format!({args_text})");
    let inline_arm_width = open_col + inline_call.chars().count() + 1; // +1 for the `,`

    if args_width <= FN_CALL_WIDTH && inline_arm_width <= MAX_WIDTH {
        // INLINE.
        format!("{arm_head}{inline_call},")
    } else if args_width <= FN_CALL_WIDTH {
        // BLOCK-WRAP: the call fits `fn_call_width` but the inline arm overflows,
        // so `rustfmt` brace-wraps the body. The `format!` lands at arm indent + 4.
        let body_indent = " ".repeat(ARM_INDENT + 4);
        let close_indent = " ".repeat(ARM_INDENT);
        format!("{arm_head}{{\n{body_indent}{inline_call}\n{close_indent}}}")
    } else {
        // DELIMITER-BREAK: the argument text exceeds `fn_call_width`, so the
        // `format!` breaks one argument per line after `=> `; the arm keeps `,`.
        let call = render_stringify_format(fmt_literal, args, open_col, ARM_INDENT);
        format!("{arm_head}{call},")
    }
}

/// The generic-type-parameter scope in effect while emitting one function's
/// signature and body.
///
/// Maps a Ipê type-variable [`Symbol`] to its deterministic Rust generic name
/// (`T1`, `T2`, …) by the variable's *position* in the function's quantification
/// order — never by the symbol's spelling — so a function quantifying `[a, b]`
/// renders `a` → `T1` and `b` → `T2` regardless of source naming. Empty for
/// monomorphic functions and for program-level emission (enums, record structs),
/// where no generic is in scope.
///
/// For `UiLayout`/`UiLayoutWith`, M is inferred bottom-up from the concrete
/// element/attrs types sourced from `SolvedTypes.regions`, not threaded down
/// from the enclosing function's `Html<M>` return type.
///
/// The type is [`Copy`], so it is threaded by value through the emitters.
#[derive(Clone, Copy)]
pub struct GenericScope<'a> {
    params: &'a [Symbol],
    /// The row variables quantified by the enclosing function, in order
    /// (`rows[i]` → `R{i+1}`). Empty for every scope that is not a
    /// row-polymorphic function signature (structs, enums, monomorphic funcs).
    /// Kept disjoint from [`Self::params`]: `T`-prefixed vs `R`-prefixed names
    /// can never collide.
    rows: &'a [Symbol],
    /// The PARAMETER BINDER symbols whose type is an [`ipe_ir::IrType::RowGeneric`]
    /// — the names a body field read must route through a witness getter. A row
    /// variable (`rows`) names the open tail in type position; a row binder
    /// (`row_binders`) is the value-level parameter carrying that type (e.g.
    /// `rec` in `greet rec = rec.name`). Access emission keys on the binder.
    row_binders: &'a [Symbol],
}

impl<'a> GenericScope<'a> {
    /// A scope quantifying `params`, in order (`params[i]` → `T{i+1}`), with no
    /// row variables. Used by every non-row emission site (structs, enums,
    /// monomorphic and ordinary-generic functions).
    #[must_use]
    pub const fn new(params: &'a [Symbol]) -> Self {
        Self {
            params,
            rows: &[],
            row_binders: &[],
        }
    }

    /// A scope quantifying `params` (`T{i+1}`) and `rows` (`R{i+1}`). Used by a
    /// row-polymorphic function signature so an [`IrType::RowGeneric`] renders
    /// to its positional `R{n}` name. `row_binders` lists the value-level
    /// parameter names carrying a row-generic type, so a body field read on one
    /// routes through the witness getter.
    #[must_use]
    pub const fn with_rows(
        params: &'a [Symbol],
        rows: &'a [Symbol],
        row_binders: &'a [Symbol],
    ) -> Self {
        Self {
            params,
            rows,
            row_binders,
        }
    }

    /// The deterministic Rust generic name for a row variable `sym` (`R1`,
    /// `R2`, … by position in the enclosing function's row params).
    ///
    /// # Errors
    ///
    /// Returns [`Diagnostic::CompilerBug`] when `sym` is not in this scope's row
    /// list — the lowerer is contracted to list every row variable it erased to
    /// an [`IrType::RowGeneric`] in [`ipe_ir::Func::row_params`], so a row
    /// generic outside the row scope is an internal invariant violation.
    fn row_name(&self, sym: Symbol) -> DResult<String> {
        self.rows.iter().position(|p| *p == sym).map_or_else(
            || {
                Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::GenericScope::row_name",
                    detail: format!(
                        "row variable symbol {} is not in the enclosing function's row scope; \
                         the lowerer must list every row variable in Func::row_params",
                        sym.as_raw()
                    ),
                })
            },
            |i| Ok(format!("R{}", i.saturating_add(1))),
        )
    }

    /// `true` iff `sym` is a parameter binder whose type is a row generic — the
    /// predicate the Access emitter uses to decide whether a field read routes
    /// through a witness getter rather than a struct field.
    #[must_use]
    pub fn is_row(&self, sym: Symbol) -> bool {
        self.row_binders.contains(&sym)
    }

    /// The deterministic Rust generic name for `sym` (`T1`, `T2`, … by position).
    ///
    /// # Errors
    ///
    /// Returns [`Diagnostic::CompilerBug`] when `sym` is not in this scope — the
    /// lowerer is contracted to list every structurally-used type variable in
    /// [`ipe_ir::Func::type_params`], so an [`IrType::Generic`] outside the
    /// quantification scope is an internal invariant violation, surfaced rather
    /// than emitted as an undefined Rust identifier.
    fn rust_name(&self, sym: Symbol) -> DResult<String> {
        self.params.iter().position(|p| *p == sym).map_or_else(
            || {
                Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::GenericScope::rust_name",
                    detail: format!(
                        "generic type variable symbol {} is not in the enclosing function's \
                         quantification scope; the lowerer must list every structurally-used \
                         type variable in Func::type_params",
                        sym.as_raw()
                    ),
                })
            },
            |i| Ok(format!("T{}", i.saturating_add(1))),
        )
    }
}

/// Render an IR type to its Rust spelling. `generics` is the enclosing
/// function's generic scope (empty at program level), used to render
/// [`IrType::Generic`] as its deterministic Rust generic name.
#[allow(clippy::too_many_lines)]
pub fn render_type(ctx: &EmitCtx, ty: &IrType, generics: GenericScope) -> DResult<String> {
    Ok(match ty {
        IrType::BackoffStrategy => "ipe_runtime::task::BackoffStrategy".to_owned(),
        IrType::Order => "ipe_runtime::basics::IpeOrder".to_owned(),
        IrType::HttpMethod => "ipe_runtime::HttpMethod".to_owned(),
        IrType::Decimal => "ipe_runtime::decimal::Decimal".to_owned(),
        IrType::Principal => "ipe_runtime::principal::Principal".to_owned(),
        IrType::AuthConfig => "ipe_runtime::server::AuthConfig".to_owned(),
        IrType::TokenSource => "ipe_runtime::server::TokenSource".to_owned(),
        IrType::ErrorKind => "ipe_runtime::error::IpeErrorKind".to_owned(),
        IrType::Error => "ipe_runtime::error::IpeError".to_owned(),
        IrType::ErrorDetails => "ipe_runtime::error::IpeErrorDetails".to_owned(),
        // The NOMINAL error-payload types (SEAL fix): rendered as
        // the runtime's concrete structs, so a pattern-bound payload and any
        // position naming these types agree on ONE Rust type — never a
        // project-local synthesized record struct.
        IrType::ErrorInfo => "ipe_runtime::error::IpeErrorInfo".to_owned(),
        IrType::PanicInfo => "ipe_runtime::error::IpePanicInfo".to_owned(),
        IrType::TypeInfo => "ipe_runtime::error::IpeTypeInfo".to_owned(),
        IrType::SqlFragment => "ipe_runtime::db::SqlFragment".to_owned(),
        IrType::Secret => "ipe_runtime::secret::Secret".to_owned(),
        IrType::Path => "ipe_runtime::path::Path".to_owned(),
        IrType::Regex => "ipe_runtime::regex_kernel::Regex".to_owned(),
        // `SessionHandle` IS the runtime session-registry key: a plain `i64`. It
        // renders identically to `Int` (zero-cost, seal-simple); its opacity is
        // enforced at the Ipê type level (no constructor, obtained only from
        // `Js.openSession`), not by a distinct Rust newtype.
        IrType::Int | IrType::SessionHandle => "i64".to_owned(),
        IrType::Float => "f64".to_owned(),
        IrType::Bool => "bool".to_owned(),
        IrType::Str => "String".to_owned(),
        IrType::Char => "char".to_owned(),
        IrType::Unit => "()".to_owned(),
        IrType::Task(inner) => format!("IpeTask<{}>", render_type(ctx, inner, generics)?),
        IrType::Enum { home, name, args } => {
            // A foreign OPAQUE FFI type renders as its REAL Rust path — its
            // placeholder union is never emitted as an enum ([`ipe_lower`]
            // skips opaque `Rust.*`-home unions), so the bare enum name would
            // dangle. A TRANSPARENT import HAS a registered `EnumDef` (the
            // lowerer emitted its declaration) and renders as that app enum
            // through the ordinary path below — its values are native, and
            // the wrapper seam converts them.
            // Opaque foreign types are non-generic by construction.
            if ctx.is_foreign_interface_home(home) && !ctx.has_enum_def(home, *name) {
                if !args.is_empty() {
                    return Err(Diagnostic::CompilerBug {
                        where_: "ipe_backend_rust::render_type",
                        detail: "foreign opaque FFI type rendered with type arguments".to_owned(),
                    });
                }
                return ctx.foreign_type_path(home, *name);
            }
            // Special-case builtin Http.Stream ADTs that are NOT registered as
            // synthetic `EnumDef`s but appear in user type annotations.
            //
            // `ChunkEvent` is generic over the error type (`E` = always
            // `IpeError` in practice) — we bake the concrete type arg in here
            // rather than propagating it through the IrType layer (the Ipê
            // user sees `ChunkEvent` as a non-generic type; the `E` channel is
            // invisible to user code).
            //
            // `StreamId` is handled by the `enum_name` override in `EmitCtx`
            // (returns `"IpeStreamId"`), so it falls through to the normal
            // non-generic path below.
            if home.0.is_empty() && args.is_empty() && ctx.resolve_ident(*name) == Ok("ChunkEvent")
            {
                return Ok("ChunkEvent<IpeError>".to_owned());
            }
            // `Ipe.Cache.Cache k v` is backed by the NON-generic runtime
            // enum `IpeCacheHandle` — drop the phantom `k`/`v` args (they live
            // only on the kernel calls), else the render would emit an invalid
            // `IpeCacheHandle<T1, T2>` (E0107). `enum_name` returns the runtime
            // name; here we skip appending the arg list.
            if ctx.is_cache_handle_type(home, *name) {
                return Ok("IpeCacheHandle".to_owned());
            }
            let base = ctx.enum_name(home, *name)?.to_owned();
            if args.is_empty() {
                // A non-generic enum renders as the bare Rust type name.
                base
            } else {
                let mut parts = Vec::with_capacity(args.len());
                for arg in args {
                    parts.push(render_type(ctx, arg, generics)?);
                }
                format!("{base}<{}>", parts.join(", "))
            }
        }
        // The built-in `Maybe a` / `Result e a` render to the runtime's shared
        // representations, brought into scope by the emitted crate's
        // `pub use ipe_runtime::*`.
        IrType::Maybe(elem) => format!("IpeMaybe<{}>", render_type(ctx, elem, generics)?),
        IrType::Result(err, ok) => format!(
            "IpeResult<{}, {}>",
            render_type(ctx, err, generics)?,
            render_type(ctx, ok, generics)?
        ),
        // The built-in `List a` is the runtime's `Vec<T>`.
        IrType::List(elem) => format!("Vec<{}>", render_type(ctx, elem, generics)?),
        // `Dict k v` is the runtime's `HashMap<K, V>`.
        IrType::Dict(k, v) => format!(
            "HashMap<{}, {}>",
            render_type(ctx, k, generics)?,
            render_type(ctx, v, generics)?
        ),
        // `Set a` is the runtime's `BTreeSet<A>`.
        IrType::Set(a) => format!("BTreeSet<{}>", render_type(ctx, a, generics)?),
        // `Bytes` is an arbitrary byte buffer — `Vec<u8>`. Divergence from
        // Ipê: Ipê aliases Bytes = String; Rust's String is UTF-8 constrained,
        // so Bytes maps to Vec<u8> for lossless arbitrary binary.
        IrType::Bytes => "Vec<u8>".to_owned(),
        // `Json` is the opaque JSON value type, `serde_json::Value`, exposed
        // from the runtime as `JsonVal` (re-exported via `pub use ipe_runtime::*`
        // in the emitted crate).
        IrType::Json => "JsonVal".to_owned(),
        // `Decoder<T>` is the JSON decoder type, aliased in the emitted project's
        // preamble as `pub type Decoder<T> = ipe_runtime::json::Decoder<IpeError, T>`.
        //
        // when the DECODED VALUE is itself a function (`Decoder (a -> b)` —
        // e.g. the accumulator of a `succeed Ctor |> required …` pipeline, or a
        // `succeed (partiallyApplied x)` payload), the runtime represents that
        // payload as an owned/linear curry chain, `Box<dyn FnOnce(a) -> b + Send>`
        // (what `curryN` builds and `decode_succeed`'s `A` is inferred to). A bare
        // `render_type` would render the `IrType::Fun` payload as the SHARED
        // callback form `Box<dyn Fn(a) -> b + Send + Sync>` — the wrong trait
        // (`Fn` vs `FnOnce`) AND an over-constrained `+ Sync` the curry chain does
        // not satisfy → ipe-0-then-cargo-fail (E0308/E0277). A decoder payload
        // never flows into an `Arc<dyn Fn + Send + Sync>` slot, so it is always the
        // Send-only owned shape. Render it as the `FnOnceChain` the runtime uses.
        IrType::Decoder(inner) => {
            let inner_s = match inner.as_ref() {
                IrType::Fun(params, ret) => render_fn_once_chain(ctx, params, ret, generics)?,
                other => render_type(ctx, other, generics)?,
            };
            format!("Decoder<{inner_s}>")
        }
        // `Db` is the opaque database connection pool type, re-exported from the
        // runtime as `pub use ipe_runtime::Db;` in the emitted crate preamble.
        IrType::Db => "Db".to_owned(),
        // `IpeCmd<M>` / `IpeSub<M>` are the opaque TEA command and subscription
        // types, aliased in the emitted project's preamble as
        // `pub type IpeCmd<M> = ipe_runtime::tea::IpeCmd<M>` and
        // `pub type IpeSub<M> = ipe_runtime::tea::IpeSub<M>`.
        IrType::Cmd(inner) => format!("IpeCmd<{}>", render_type(ctx, inner, generics)?),
        IrType::Sub(inner) => format!("IpeSub<{}>", render_type(ctx, inner, generics)?),
        // Opaque server types — render to their ipe_runtime names directly.
        IrType::ServerRequest => "ServerRequest".to_owned(),
        IrType::ServerResponse => "ServerResponse".to_owned(),
        IrType::ServerRoute => "ServerRoute".to_owned(),
        IrType::ServerCookie => "ServerCookie".to_owned(),
        // stream writer handle — re-exported from ipe_runtime::server_stream.
        IrType::StreamWriter => "StreamWriter".to_owned(),
        // HTTP request handle — re-exported from ipe_runtime::http.
        IrType::HttpRequest => "HttpRequest".to_owned(),
        // Ipe.Http.Server.WebSocket opaque handles.
        IrType::WebSocketServer => "WsHandle".to_owned(),
        IrType::WebSocketServerCfg => "WsServerCfg<IpeError>".to_owned(),
        // Ipe.Cache config / stats records — re-exported (ungated) from
        // ipe_runtime::cache, so the bare name resolves via the crate glob use.
        // `ProcessRunWithCfg` — re-exported from ipe_runtime::system, bare via
        // the glob use.
        IrType::ProcessRunWithCfg => "ProcessRunWithCfg".to_owned(),
        IrType::ProcessRunInPtyCfg => "ProcessRunInPtyCfg".to_owned(),
        IrType::CacheCfg => "CacheCfg".to_owned(),
        IrType::CacheStats => "CacheStats".to_owned(),
        // Ipe.WebSocket connect-config record — re-exported (feature-gated
        // on `websocket_client`) from ipe_runtime::ws_client, bare via the glob.
        IrType::WebSocketClientCfg => "WsClientCfg".to_owned(),
        // Ipe.Csv document record — re-exported (ungated) from ipe_runtime::csv,
        // so the bare name resolves via the crate glob use.
        IrType::CsvDoc => "CsvDoc".to_owned(),
        // Ipe.Email records + provider ADT — re-exported from ipe_runtime::email
        // (`pub use email::*` appended when the program uses `Email.send`), so
        // the bare names resolve via the crate glob use. `Attachment` maps to the
        // runtime `EmailAttachment` (the Ipê alias name differs from the runtime
        // struct name).
        IrType::EmailMessage => "EmailMessage".to_owned(),
        IrType::EmailAttachment => "EmailAttachment".to_owned(),
        IrType::EmailSesConfig => "SesConfig".to_owned(),
        IrType::EmailSmtpConfig => "SmtpConfig".to_owned(),
        IrType::EmailProvider => "EmailProvider".to_owned(),
        // Typed-key newtypes — fully-qualified to avoid ambiguity with any
        // user-defined `Key`/`Mac`/`EmailAddress` types.
        IrType::CryptoKey => "ipe_runtime::crypto_core::Key".to_owned(),
        IrType::CryptoMac => "ipe_runtime::crypto_core::Mac".to_owned(),
        IrType::EmailAddress => "ipe_runtime::email::EmailAddress".to_owned(),
        // `Ipe.Url`'s opaque validated URL — fully-qualified to avoid ambiguity
        // with any user-defined `Url` type.
        IrType::Url => "ipe_runtime::url::Url".to_owned(),
        // `Ipe.Url`'s opaque same-origin relative reference — fully-qualified.
        IrType::UrlRelative => "ipe_runtime::url::UrlRelative".to_owned(),
        // `Ipe.Db.Dsn`'s opaque validated connection descriptor — fully-qualified
        // to avoid ambiguity with any user-defined `Dsn` type.
        IrType::Dsn => "ipe_runtime::dsn::Dsn".to_owned(),
        // `Ipe.Db`'s external-connection handle — the phantom access mode is
        // already erased at lowering, so every `Connection ReadOnly` /
        // `Connection ReadWrite` position renders to the one concrete pool type.
        // The bare markers describe only that erased mode; they never stand as a
        // value type, so rendering them names the same handle (a fail-safe, never
        // a panic).
        IrType::Connection | IrType::ConnReadOnly | IrType::ConnReadWrite => {
            "ipe_runtime::external_conn::ExternalConnection".to_owned()
        }
        // `Ipe.App`'s runtime-config carrier — the phantom shape marker is
        // already erased at lowering, so every `Setting Web` / `Setting
        // Terminal` position renders to the one concrete carrier. The bare
        // markers describe only that erased shape; they never stand as a value
        // type, so rendering them names the same carrier (fail-safe, never a panic).
        IrType::Setting | IrType::ShapeWeb | IrType::ShapeWebView | IrType::ShapeTerminal => {
            "ipe_runtime::app_config::Setting".to_owned()
        }
        // `Locale` is fully-qualified to avoid ambiguity with any user-defined
        // `Locale` type; the runtime module is always compiled (the struct is a
        // plain newtype; ICU4X parse/case bodies activate under `--features locale`).
        IrType::Locale => "ipe_runtime::locale::Locale".to_owned(),
        // Ipe.Ui / Ipe.Html parametric types.  Use fully-qualified Rust paths
        // (T2 soundness: `Attribute` exists in BOTH Ipe.Ui and Ipe.Html namespaces;
        // qualified paths keep them unambiguous and prevent glob-import shadowing).
        IrType::Ui { ctor, msg } => {
            let m = render_type(ctx, msg, generics)?;
            match ctor {
                UiCtor::Html => format!("ipe_runtime::html::Html<{m}>"),
                UiCtor::Element => format!("ipe_runtime::ui::element::Element<{m}>"),
                UiCtor::Cells => format!("ipe_runtime::tui::CellsView<{m}>"),
                UiCtor::UiAttribute => format!("ipe_runtime::ui::element::Attribute<{m}>"),
                UiCtor::TuiAttribute => format!("ipe_runtime::tui::TuiAttr<{m}>"),
                UiCtor::CliLines => format!("ipe_runtime::tui::LinesView<{m}>"),
                UiCtor::CliAttribute => format!("ipe_runtime::tui::CliAttr<{m}>"),
                UiCtor::HtmlAttribute => format!("ipe_runtime::html::Attribute<{m}>"),
                UiCtor::HtmlEvent => format!("ipe_runtime::html::Event<{m}>"),
                UiCtor::Label => format!("ipe_runtime::ui::input::Label<{m}>"),
                UiCtor::Placeholder => format!("ipe_runtime::ui::input::Placeholder<{m}>"),
                UiCtor::RadioOption => format!("ipe_runtime::ui::input::RadioOption<{m}>"),
            }
        }
        IrType::UiPlain(plain) => match plain {
            UiPlain::Length => "ipe_runtime::ui::element::Length".to_owned(),
            UiPlain::Color => "ipe_runtime::color::Color".to_owned(),
            UiPlain::HAlign => "ipe_runtime::ui::element::HAlign".to_owned(),
            UiPlain::VAlign => "ipe_runtime::ui::element::VAlign".to_owned(),
            UiPlain::Location => "ipe_runtime::ui::element::Location".to_owned(),
            UiPlain::PseudoClass => "ipe_runtime::ui::element::PseudoClass".to_owned(),
            UiPlain::Description => "ipe_runtime::ui::element::Description".to_owned(),
            UiPlain::LayoutContext => "ipe_runtime::ui::element::LayoutContext".to_owned(),
            // Ipe.Color companion value types — each renders to its
            // always-vendored `ipe_runtime::color::*` runtime type (re-exported at
            // the crate root, so the bare-path shim call also resolves).
            UiPlain::ColorError => "ipe_runtime::color::ColorError".to_owned(),
            UiPlain::TermProfile => "ipe_runtime::color::TermProfile".to_owned(),
            // The terminal-colour type: the palette constructors build it and
            // `Color.toAnsi` yields it.
            UiPlain::AnsiColor => "ipe_runtime::color::AnsiColor".to_owned(),
            UiPlain::WcagLevel => "ipe_runtime::color::WcagLevel".to_owned(),
            UiPlain::TextSize => "ipe_runtime::color::TextSize".to_owned(),
            UiPlain::Deficiency => "ipe_runtime::color::Deficiency".to_owned(),
        },
        // Web types — render to qualified runtime paths.
        // `WebReq` is defined in `dom::req` (target-neutral, always compiled);
        // `web::req` re-exports it only under the full `web` feature.  Emitting
        // the canonical `dom::req` path makes the generated crate compile on
        // every target including `wasm32` + `wasm-client` (where the lean `web`
        // shell does not include `req`).
        IrType::WebReq => "ipe_runtime::dom::req::WebReq".to_owned(),
        // (`SessionHandle` renders to `i64` — see the `Int | SessionHandle` arm above.)
        // Shape opaque app leaves — render to qualified runtime paths.
        // On the browser target `Web.tea` lowers to `wasm::wasm_app(...)` (see
        // `emit_web`), which returns an `IpeTask` the wasm epilogue drives via
        // `run_start(ipe_main())` — so the leaf renders as that task type, not the
        // native-only `WebApp` handle (absent on wasm32).
        IrType::WebApp if ctx.target == ipe_ir::Target::WasmClient => "IpeTask<()>".to_owned(),
        // A `Web.tea` handle renders to the served `WebApp` unless the delivery
        // host is webview-native (`web desktop`): then the same DOM app is driven
        // by `WebViewApp`, whose `run_blocking` runs the event loop on the process
        // main thread (tao/Cocoa requirement). One shape, two host executors.
        IrType::WebApp if ctx.uses_webview => "ipe_runtime::tea::WebViewApp".to_owned(),
        IrType::WebApp => "ipe_runtime::tea::WebApp".to_owned(),
        IrType::TuiApp => "ipe_runtime::tea::TuiApp".to_owned(),
        IrType::CliApp => "ipe_runtime::tea::CliApp".to_owned(),
        IrType::WorkerApp => "ipe_runtime::tea::WorkerApp".to_owned(),
        // `Route<Page>` has NO default type parameter in the runtime
        // (`web/route.rs`), so the page argument MUST be rendered: a bare
        // `Route` is an E0107 cargo failure in every rendered position — the
        // empty `routes = []` literal's `Vec::<…>::new()` turbofish and any
        // let-bound route table's fn signature.
        IrType::WebRoute(page) => format!(
            "ipe_runtime::web::route::Route<{}>",
            render_type(ctx, page, generics)?
        ),
        // The widget handle carries only its generated tag string; the seal
        // types are phantom (they drive the down-encode / up-decode codegen at
        // the `CustomElement.node` call site, not the handle's own representation), so
        // the rendered type takes no parameters.
        IrType::CustomElement { .. } => "ipe_runtime::ui::widget::IpeCustomElement".to_owned(),
        IrType::Tuple(elems) => {
            let mut parts = Vec::with_capacity(elems.len());
            for elem in elems {
                parts.push(render_type(ctx, elem, generics)?);
            }
            format!("({})", parts.join(", "))
        }
        IrType::Record(fields) => ctx.render_record_use(fields, generics)?,
        // Handler-arrow special case: `Request -> Task Error Response` must
        // render as `ServerHandler<IpeError>` (an Arc<dyn Fn> alias defined in
        // the runtime), not as a generic `Box<dyn Fn + Send + 'static>`.  This
        // arm MUST appear before the generic `Fun` arm so it takes priority.
        IrType::Fun(params, ret)
            if matches!(params.as_slice(), [IrType::ServerRequest])
                && matches!(ret.as_ref(), IrType::Task(inner) if matches!(inner.as_ref(), IrType::ServerResponse)) =>
        {
            "ServerHandler<IpeError>".to_owned()
        }
        // WsServerCfg callback fields store Arc<dyn Fn + Send + Sync>; emit the
        // matching type so the WS adapter functions compile.  The three shapes are:
        //   onConnect / onClose  →  Fn(WsHandle) -> IpeTask<()>
        //   onMessage            →  Fn(WsHandle, String) -> IpeTask<()>
        //   onError              →  Fn(WsHandle, Error)  -> IpeTask<()>
        // `onError`'s second param is the error type, NOT String — its runtime
        // setter `ws_server_with_on_error` takes `Arc<dyn Fn(WsHandle, E) -> …>`,
        // so it MUST render as `Arc<…>` here (and box with `Arc::new` in
        // `wants_arc_ctor`, whose pattern is kept in lock-step). Omitting the
        // `[WebSocketServer, Error]` shape rendered it as the generic `Box<dyn Fn>`
        // below and passed a `Box` into that `Arc` param → ipe-0-then-cargo-fail
        // E0308 for any `onError` callback.
        // This arm MUST appear before the generic `Fun` arm so it takes priority.
        IrType::Fun(params, ret)
            if matches!(
                params.as_slice(),
                [IrType::WebSocketServer] | [IrType::WebSocketServer, IrType::Str | IrType::Error]
            ) && matches!(ret.as_ref(), IrType::Task(inner) if matches!(inner.as_ref(), IrType::Unit)) =>
        {
            let mut parts = Vec::with_capacity(params.len());
            for param in params {
                parts.push(render_type(ctx, param, generics)?);
            }
            let ret_ty = render_type(ctx, ret, generics)?;
            format!(
                "Arc<dyn Fn({}) -> {ret_ty} + Send + Sync + 'static>",
                parts.join(", ")
            )
        }
        // The promoted reference-counted fn carrier: `Arc<dyn Fn(..) -> R + Send
        // + Sync + 'static>`. `Arc` is `Clone` (a refcount bump), so a composite
        // holding this slot is itself `Clone` and can be duplicated for reuse.
        // Same trait-object bound as the `Box` carrier below — the ONLY
        // difference is the smart pointer — so the swap is capture-transparent
        // (every capture the `Box` form admits, the `Arc` form admits too).
        IrType::SharedFun(params, ret) => {
            let mut parts = Vec::with_capacity(params.len());
            for param in params {
                parts.push(render_type(ctx, param, generics)?);
            }
            let ret = render_type(ctx, ret, generics)?;
            format!(
                "::std::sync::Arc<dyn Fn({}) -> {ret} + Send + Sync + 'static>",
                parts.join(", ")
            )
        }
        IrType::Fun(params, ret) => {
            // A first-class function value is a boxed trait object
            // `Box<dyn Fn(T0, ...) -> R + Send + Sync + 'static>`. The
            // `Send + Sync + 'static` bounds are required so closures can be
            // passed to Task combinators (`task_map`, `task_and_then`, etc.)
            // AND — crucially — so a callback-typed PARAMETER can be forwarded
            // into the runtime's UI/Web event-callback slots, whose fields are
            // `Arc<dyn Fn(_) -> _ + Send + Sync + 'static>` (see
            // `ipe_runtime::ui::element::Event`). Without `Sync` on this boxed
            // param, an emitted user fn generic over its Msg type
            // (`fn f<T1: Clone>(onEdit: Box<dyn Fn(String) -> T1 + Send>) …`)
            // that arc-wraps `onEdit` (via `arc_callback_wrap`) and passes it to
            // `input_multiline_`/`input_text_`/… fails E0277 (`… cannot be
            // shared between threads safely`) — the seal break that
            // `26-ui-showcase`'s `regression_gates_input_multiline_fill`
            // surfaced. `Send + Sync` is strictly stronger than the previous
            // `Send`, so every `Send + 'static` consumer (the Task combinators)
            // still accepts it; all closures emitted by this backend are `move`
            // closures capturing only `Send + Sync + 'static` values, so this is
            // sound. A nullary function type renders as
            // `Box<dyn Fn() -> R + Send + Sync + 'static>`. The boxed-closure
            // optimisation (a concrete, non-boxed generic closure type) is deferred.
            let mut parts = Vec::with_capacity(params.len());
            for param in params {
                parts.push(render_type(ctx, param, generics)?);
            }
            let ret = render_type(ctx, ret, generics)?;
            format!(
                "Box<dyn Fn({}) -> {ret} + Send + Sync + 'static>",
                parts.join(", ")
            )
        }
        // `f7_succeed_curried`: a curried chain of ONE-SHOT closures,
        // one `Box<dyn FnOnce>` level per parameter — distinct from `Fun`'s
        // flattened, re-callable `Box<dyn Fn(T0, T1, ...) -> R>`. Rendered
        // from the INSIDE out: the last parameter's box wraps the bare
        // return type; every earlier parameter's box wraps the box built
        // for the levels after it. Matches exactly the nesting the
        // `curryN` runtime helpers construct (`curry2` → `Box<dyn
        // FnOnce(A1) -> Box<dyn FnOnce(A2) -> R + Send> + Send>`), which is
        // what the `next_decoder` parameter of `decode_pipeline_required` /
        // `decode_pipeline_optional` / `decode_pipeline_required_at` /
        // `db_decode_required` / `db_decode_optional` actually requires.
        IrType::FnOnceChain(params, ret) => render_fn_once_chain(ctx, params, ret, generics)?,
        // A generic type variable renders as the function's corresponding Rust
        // generic (`T1`, `T2`, …), resolved by position in the quantification
        // scope. No trait bound is emitted — only parametric pass-through is
        // supported here; constrained variables are rejected upstream.
        IrType::Generic(sym) => generics.rust_name(*sym)?,
        // A row variable renders as the function's corresponding row generic
        // (`R1`, `R2`, …), resolved by position in the row scope. Its field
        // obligations are carried as witness bounds in the generic clause; the
        // type name itself is the bare `R{n}`.
        IrType::RowGeneric(sym) => generics.row_name(*sym)?,
    })
}

/// Render a curried chain of ONE-SHOT closures — one `Box<dyn FnOnce(..) -> _ +
/// Send + 'static>` level per parameter, nested from the INSIDE out. This is the
/// exact shape the `curryN` runtime helpers construct (`curry2` → `Box<dyn
/// FnOnce(A1) -> Box<dyn FnOnce(A2) -> R + Send> + Send>`) and that the
/// `next_decoder` / factory parameters of the decode/db-decode combinators
/// require. It is Send-ONLY (never `+ Sync`): a `FnOnce` curry chain is an
/// owned/linear value that flows into the runtime's `Box<dyn Fn(..) + Send>`
/// decoder slots, never into a shared `Arc<dyn Fn + Send + Sync>` callback slot —
/// so forcing `+ Sync` on it is over-constrained and unsatisfiable.
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] on an empty parameter list — a function
/// type with no parameters is not a `FnOnce` chain (see the [`IrType::FnOnceChain`]
/// variant's doc comment: its sole producer never constructs a zero-param chain).
fn render_fn_once_chain(
    ctx: &EmitCtx,
    params: &[IrType],
    ret: &IrType,
    generics: GenericScope,
) -> DResult<String> {
    let Some((last, init)) = params.split_last() else {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::emit_types::render_fn_once_chain",
            detail: "function-value curry chain with an empty parameter list".to_owned(),
        });
    };
    let mut acc = render_type(ctx, ret, generics)?;
    acc = format!(
        "Box<dyn FnOnce({}) -> {acc} + Send + 'static>",
        render_type(ctx, last, generics)?
    );
    for param in init.iter().rev() {
        acc = format!(
            "Box<dyn FnOnce({}) -> {acc} + Send + 'static>",
            render_type(ctx, param, generics)?
        );
    }
    Ok(acc)
}

/// Emit an enum and its derived `IpeStringify` impl, including the trailing
/// newline.
///
/// A nullary-only, non-generic enum emits byte-identically to the
/// golden:
/// ```text
/// #[derive(Clone, Debug, PartialEq)]
/// pub enum MainMsg {
///     Increment,
///     Decrement,
/// }
///
/// impl IpeStringify for MainMsg {
///     fn ipe_show(&self) -> String {
///         match self {
///             MainMsg::Increment => "Increment".to_string(),
///             MainMsg::Decrement => "Decrement".to_string(),
///         }
///     }
/// }
/// ```
///
/// A payload-carrying and/or generic enum gains tuple-variant payloads, a
/// `<T1, …>` clause on the enum and its impl, and `IpeStringify` arms that bind
/// each payload field and render it through its own `IpeStringify` impl:
/// ```text
/// #[derive(Clone, Debug, PartialEq)]
/// pub enum MainMaybe<T1> {
///     Just(T1),
///     Nothing,
/// }
///
/// impl<T1: IpeStringify> IpeStringify for MainMaybe<T1> {
///     fn ipe_show(&self) -> String {
///         match self {
///             MainMaybe::Just(p0) => format!("Just {}", IpeStringify::ipe_show(p0)),
///             MainMaybe::Nothing => "Nothing".to_string(),
///         }
///     }
/// }
/// ```
///
/// A payload field that sits on a type-size cycle back to its own enum —
/// directly (`Node Tree Int Tree`) or indirectly (mutual recursion, or a
/// self-edge routed through a tuple / record / another generic's type argument)
/// — is wrapped in `Box<…>` so the Rust enum stays finite-sized (E0072); the
/// construction and pattern emitters balance that boxing. See
/// [`crate::EmitCtx::is_cyclic_self_field`].
pub fn emit_enum(ctx: &EmitCtx, def: &EnumDef) -> DResult<String> {
    // A `Ipe.WebSocket` ADT bridged to a runtime enum
    // (`WebSocketMessage` → `WsClientMessage`, `CloseCode` → `WsCloseCode`) has
    // NO user-emitted decl — its definition lives in `ipe_runtime::ws_client`,
    // and emitting a second enum with the same name would trip E0428. The
    // `enum_name` override in `EmitCtx::build` already routes every reference to
    // the runtime type. Suppress the body here.
    if ctx.is_websocket_bridged_enum(&def.home, def.name)? {
        return Ok(String::new());
    }
    // `ProjectionTerm` / `ProjectionOperand` are Prelude built-ins whose
    // definition lives in `ipe_runtime::db`.  Instead of re-emitting a full
    // enum body (which would clash or drift from the runtime type the
    // `db_find_projection` signature names), emit a type alias so the
    // generated crate and the runtime share ONE nominal type.
    let resolved_name = ctx.interner.resolve(def.name);
    if def.home.0.is_empty()
        && matches!(
            resolved_name,
            Some("ProjectionTerm" | "ProjectionOperand" | "ArithOp")
        )
    {
        let alias_name = ctx.enum_name(&def.home, def.name)?.to_owned();
        let runtime_name = resolved_name.unwrap_or("");
        return Ok(format!(
            "pub type {alias_name} = ipe_runtime::db::{runtime_name};\n"
        ));
    }
    let name = ctx.enum_name(&def.home, def.name)?.to_owned();
    // The enum's own generic scope: each type parameter → `T1`, `T2`, … by
    // position. Empty for a non-generic enum.
    let scope = GenericScope::new(&def.type_params);

    let (variants, arms) = emit_enum_variant_lines_and_arms(ctx, def, &name, scope)?;

    let self_clone = ctx.enum_is_clone(&def.home, def.name);
    // seal: an enum storing a function payload carries it on the `Arc<dyn Fn(..)
    // -> Tn + Send + Sync + 'static>` (`SharedFun`) carrier; a trait object with
    // a type-parameter in its param/return positions requires that parameter to
    // outlive `'static`. Add `T: 'static` to every type parameter of such an
    // enum (its decl clause AND the emitted impls' `for`-type clause) so the
    // generic form type-checks; a monomorphic use (`Handler Int`, `T = i64`)
    // satisfies it trivially. An enum with NO stored function (fully derivable)
    // is unaffected — no `'static` bound, byte-identical to before.
    let params_need_static = enum_stores_shared_fun(ctx, def);

    // Generic clauses: `<T1, T2>` on the enum, `<T1: IpeStringify, …>` on
    // the impl, `<T1, T2>` on the impl's `for` type. All empty when the enum is
    // non-generic, so that path emits no generic clause.
    let params: Vec<String> = (1..=def.type_params.len())
        .map(|i| format!("T{i}"))
        .collect();
    // `: 'static` closes a BARE type parameter (`T1: 'static`); `+ 'static`
    // extends an existing trait-bound list (`T1: IpeStringify + … + 'static`).
    let decl_static = if params_need_static { ": 'static" } else { "" };
    let bound_static = if params_need_static { " + 'static" } else { "" };
    let (decl_clause, impl_bounds, use_clause) = if params.is_empty() {
        (String::new(), String::new(), String::new())
    } else {
        let bounds: Vec<String> = params
            .iter()
            .map(|p| format!("{p}: IpeStringify{bound_static}"))
            .collect();
        let decl_params: Vec<String> = params.iter().map(|p| format!("{p}{decl_static}")).collect();
        (
            format!("<{}>", decl_params.join(", ")),
            format!("<{}>", bounds.join(", ")),
            format!("<{}>", params.join(", ")),
        )
    };

    // seal: only a fully-derivable enum takes the unconditional
    // `#[derive(Clone, Debug, PartialEq)]`. An enum whose payload reaches a
    // first-class function / opaque wrapper (directly or through a carrier /
    // another non-derivable enum) cannot derive those traits — emit no auto
    // derives (the hand-written `IpeStringify` impl below still gives it a total
    // string form).
    let self_derivable = ctx.enum_is_derivable(&def.home, def.name);
    // seal: the serde derive is gated on the SERDE predicate, not the CDPeq
    // one. serde-support ⊊ CDPeq-support: a `Clone + Debug + PartialEq` enum whose
    // payload reaches a `Html` / `Element` / `Color` / `UiPlain` value (serde-less
    // but derivable) must NOT be forced to `serde::Serialize` / `Deserialize` —
    // doing so under `uses_web` is an exit-0-then-cargo-fail (E0277). Such an enum
    // still gets its `#[derive(Clone, Debug, PartialEq)]` (self_derivable), just
    // without serde, so it stays cargo-buildable. `enum_is_serde ⇒ enum_is_derivable`
    // (the serde fixpoint is a demotion of the derivable one), so serde is never
    // added without CDPeq. The app-entry Model gate independently rejects a
    // NON-serde type used AS a Web/Tui/WebView Model; this gate covers every OTHER
    // (non-Model) emitted type in a Web program.
    let self_serde = ctx.enum_is_serde(&def.home, def.name);
    // Both browser shapes force the runtime `json` feature and route seal types
    // through serde: Ipe.Web serialises the Model in its session store
    // (`Model: serde::Serialize + serde::de::DeserializeOwned`), and BOTH Web and
    // Ipe.WebView carry a `CustomElement.node`'s down/up seal types through `ui_widget_`
    // (`Down: Serialize`, `Up: DeserializeOwned`). WebView's own Model bound is
    // only `Clone + Send`, so without unioning `uses_webview` here a serde-legal
    // widget seal type in a WebView program ipe-accepts but cargo-fails E0277 —
    // the SEAL breach. Emitting the derive on a serde-legal type is always
    // cargo-buildable (the `is_serde` fixpoint guarantees every leaf derivable),
    // so widening the gate to either browser shape stays fail-closed.
    let serde_derives = if self_serde && ctx.derives_serde() {
        ", serde::Serialize, serde::Deserialize"
    } else {
        ""
    };
    let derive_prefix = if self_derivable {
        format!("#[derive(Clone, Debug, PartialEq{serde_derives})]\n")
    } else {
        String::new()
    };
    let clone_impl = if self_clone && !self_derivable {
        emit_enum_clone_impl(ctx, def, &name, &params, bound_static, &use_clause)?
    } else {
        String::new()
    };
    let ipe_impl_head = impl_header(&impl_bounds, "IpeStringify", &format!("{name}{use_clause}"));
    let mut items = Items::new();
    items.push(&braced(
        &format!("{derive_prefix}pub enum {name}{decl_clause}"),
        &variants,
    ));
    items.push(&clone_impl);
    items.push(&format!(
        "{ipe_impl_head}
    fn ipe_show(&self) -> String {{
        match self {{
{arms}
        }}
    }}
}}"
    ));
    Ok(items.render())
}

/// Emit an enum's variant declaration lines and its `ipe_show` match arms.
///
/// A nullary variant renders a bare ident and a `Name::V => "V".to_string()`
/// arm; a payload variant renders `V(field types…)` (boxing a direct self-edge)
/// and a `format!`-based arm binding `p0..pN`. A field whose every component
/// has a show row renders through its `IpeStringify` impl; a field holding a
/// component with no rendering (a function, an opaque `Rust.*` handle) is bound
/// `_` and renders as that component's fixed marker ([`refused_marker`]).
fn emit_enum_variant_lines_and_arms(
    ctx: &EmitCtx,
    def: &EnumDef,
    name: &str,
    scope: GenericScope,
) -> DResult<(String, String)> {
    let mut variant_lines = Vec::with_capacity(def.variants.len());
    let mut show_arms = Vec::with_capacity(def.variants.len());
    for variant in &def.variants {
        // The Rust variant ident is keyword-mangled; the `ipe_show` string keeps
        // the original Ipê name so a variant like `Type` still displays as
        // "Type", not "Type_". For non-keyword variants the two coincide, so the
        // golden stays byte-identical.
        let vn = ctx.emit_ident(variant.name)?;
        let display = ctx.resolve_ident(variant.name)?.to_owned();
        if variant.fields.is_empty() {
            variant_lines.push(format!("    {vn},"));
            show_arms.push(format!(
                "            {name}::{vn} => {}.to_string(),",
                rust_str_lit(&display)
            ));
        } else {
            // Payload variant: render each field type (boxing a direct self-edge),
            // and bind a `pN` per field in the stringify arm.
            let mut field_types = Vec::with_capacity(variant.fields.len());
            let mut binders = Vec::with_capacity(variant.fields.len());
            let mut show_args = Vec::with_capacity(variant.fields.len());
            for (i, field_ty) in variant.fields.iter().enumerate() {
                let rendered = render_type(ctx, field_ty, scope)?;
                let rendered = if ctx.is_cyclic_self_field(field_ty, &def.home, def.name) {
                    format!("Box<{rendered}>")
                } else {
                    rendered
                };
                field_types.push(rendered);
                // seal: a field holding a component with no show row has no
                // `IpeStringify` impl, so it binds `_` and renders as its fixed
                // marker; every other field has one (the `ipe-cli` show-table
                // assertion pins each leaf to a runtime row). `binder` is a
                // `match self` binder, already a `&FieldType`.
                match refused_marker(field_ty, &ctx.enum_variants, ctx.interner) {
                    None => {
                        let binder = format!("p{i}");
                        show_args.push(format!("IpeStringify::ipe_show({binder})"));
                        binders.push(binder);
                    }
                    Some(marker) => {
                        binders.push("_".to_owned());
                        show_args.push(rust_str_lit(&marker));
                    }
                }
            }
            variant_lines.push(format!("    {vn}({}),", field_types.join(", ")));
            let placeholders = vec!["{}"; variant.fields.len()].join(" ");
            // `Vname <f0> <f1> …` (variant name, then space-
            // separated fields). Matches `ipeStringifyEnumImpl`.
            // The arm head `            {name}::{vn}(binders) => ` sits at block
            // indent 12; `render_stringify_enum_arm` lays the `format!` tail out in
            // `rustfmt`'s inline / block-wrap / delimiter-break tiers.
            let arm_head = format!("            {name}::{vn}({}) => ", binders.join(", "));
            // The display text renders through the format-string renderer (its
            // braces doubled); the `{}` placeholders then go in before the
            // closing quote the renderer always ends with.
            let mut fmt_literal = rust_fmt_str_lit(&format!("{display} "));
            let closing_quote = fmt_literal.len().saturating_sub(1);
            fmt_literal.insert_str(closing_quote, &placeholders);
            show_arms.push(render_stringify_enum_arm(
                &arm_head,
                &fmt_literal,
                &show_args,
            ));
        }
    }
    Ok((variant_lines.join("\n"), show_arms.join("\n")))
}

/// Emit the HAND-WRITTEN `impl Clone` for an enum that is `Clone` but NOT fully
/// `CDPeq`-derivable — a payload on the `Arc<dyn Fn>` (`SharedFun`) carrier,
/// which is `Clone` yet neither `Debug` nor `PartialEq`. The Phase-2 companion of
/// the record `is_clone` tier.
///
/// Each arm reconstructs the variant, `.clone()`-ing every bound field (a nullary
/// variant clones with no binders; a payload variant binds `p0..pN` and clones
/// each — an `Arc::clone` refcount bump on every fn slot, a value clone on the
/// rest). Without it, a function-carrying enum used in ANY `.clone()` position (a
/// `Msg`, a duplicated binding) would be an `ipe`-0-then-cargo-fail `E0599`. A
/// fully-derivable enum takes the auto derive instead, so the two Clone paths
/// never both emit.
fn emit_enum_clone_impl(
    ctx: &EmitCtx,
    def: &EnumDef,
    name: &str,
    params: &[String],
    bound_static: &str,
    use_clause: &str,
) -> DResult<String> {
    let clone_bounds = if params.is_empty() {
        String::new()
    } else {
        let bounds: Vec<String> = params
            .iter()
            .map(|p| format!("{p}: Clone{bound_static}"))
            .collect();
        format!("<{}>", bounds.join(", "))
    };
    let mut clone_arms = Vec::with_capacity(def.variants.len());
    for variant in &def.variants {
        let vn = ctx.emit_ident(variant.name)?;
        if variant.fields.is_empty() {
            clone_arms.push(format!("            {name}::{vn} => {name}::{vn},"));
        } else {
            let binders: Vec<String> = (0..variant.fields.len()).map(|i| format!("p{i}")).collect();
            let clones: Vec<String> = binders.iter().map(|b| format!("{b}.clone()")).collect();
            clone_arms.push(format!(
                "            {name}::{vn}({}) => {name}::{vn}({}),",
                binders.join(", "),
                clones.join(", ")
            ));
        }
    }
    let clone_head = impl_header(&clone_bounds, "Clone", &format!("{name}{use_clause}"));
    Ok(format!(
        "{clone_head}
    fn clone(&self) -> Self {{
        match self {{
{}
        }}
    }}
}}
",
        clone_arms.join("\n")
    ))
}

/// Does this enum store a function on the `Arc<dyn Fn(..) -> Tn + … + 'static>`
/// (`SharedFun`) carrier — the one tier whose type parameters need a `'static`
/// bound (a trait object with a type parameter in its param/return positions
/// requires it)?
///
/// Recognised as "`Clone` but not derivable": a fully-derivable enum has no
/// function payload, and a non-`Clone` enum stores a `Box<dyn Fn>` / opaque
/// handle (still gated). Every enum outside that tier returns `false`, so its
/// emitted decl clause is byte-identical to before.
fn enum_stores_shared_fun(ctx: &EmitCtx, def: &EnumDef) -> bool {
    ctx.enum_is_clone(&def.home, def.name) && !ctx.enum_is_derivable(&def.home, def.name)
}

/// A trait-impl header wrapped exactly as `rustfmt` would.
///
/// `impl<..> Trait for Type {` stays on one line while it fits the 100-column
/// max width. When it overflows, the trait stays on the first line, `for Type`
/// drops to a continuation line indented four columns, and the opening brace
/// moves to its own line. These impls are emitted at module scope (column
/// zero), so the width test needs no indent offset.
fn impl_header(bounds: &str, trait_name: &str, ty: &str) -> String {
    let one_line = format!("impl{bounds} {trait_name} for {ty} {{");
    if one_line.len() <= 100 {
        one_line
    } else {
        format!("impl{bounds} {trait_name}\n    for {ty}\n{{")
    }
}

/// Emit a synthesised record struct and its derived `IpeStringify` impl,
/// including the trailing newline.
///
/// Shape (for `{ x : Int, y : Int }`):
/// ```text
/// #[derive(Clone, Debug, PartialEq)]
/// pub struct RecXY {
///     x: i64,
///     y: i64,
/// }
///
/// impl IpeStringify for RecXY {
///     fn ipe_show(&self) -> String {
///         format!("{{{} {}}}", IpeStringify::ipe_show(&self.x), IpeStringify::ipe_show(&self.y))
///     }
/// }
/// ```
///
/// The `ipe_show` body mirrors the reference's `%v` rendering of a struct
/// (`{f0 f1 ...}`, fields space-separated in declared order, no field names) so
/// stringifying a record reads identically across the two backends. Each field
/// renders through its `IpeStringify` impl, or as a fixed marker when it holds
/// a component with no rendering ([`refused_marker`]).
///
/// A GENERIC record shape (a field typed by a type variable) gains a
/// generic clause on both the struct and its impl. Shape (for `{ value : a }`):
/// ```text
/// #[derive(Clone, Debug, PartialEq)]
/// pub struct RecValue<T1> {
///     value: T1,
/// }
///
/// impl<T1: IpeStringify> IpeStringify for RecValue<T1> {
///     ...
/// }
/// ```
/// The impl bounds each parameter `IpeStringify`, so a field typed by it
/// renders at the generic frame. A monomorphic record emits an empty clause.
pub fn emit_record_struct(ctx: &EmitCtx, rec: &RecordStruct) -> DResult<String> {
    let name = &rec.name;
    // The struct's own generic scope: each parameter symbol → `T1`, `T2`, … by
    // position. Empty for a monomorphic record.
    let scope = GenericScope::new(&rec.type_params);
    let mut field_lines = Vec::with_capacity(rec.fields.len());
    let mut show_args = Vec::with_capacity(rec.fields.len());
    for (field_name, field_ty) in &rec.fields {
        let ident = mangle_reserved(field_name.clone());
        let rust_ty = render_type(ctx, field_ty, scope)?;
        field_lines.push(format!("    {ident}: {rust_ty},"));
        // seal: a field holding a component with no show row has no
        // `IpeStringify` impl, so it renders as its fixed marker.
        match refused_marker(field_ty, &ctx.enum_variants, ctx.interner) {
            None => show_args.push(format!("IpeStringify::ipe_show(&self.{ident})")),
            Some(marker) => show_args.push(rust_str_lit(&marker)),
        }
    }
    let fields_block = field_lines.join("\n");

    // seal: a record that stores a function on the `Arc<dyn Fn(..) -> Tn + Send
    // + Sync + 'static>` (`SharedFun`) carrier — directly, or through a generic
    // instantiation of a carrier enum such as `IpeCodecCodec<Tn>` (whose own decl
    // is `IpeCodecCodec<Tn: 'static>`) held in a field — needs `Tn: 'static` on
    // every type parameter of the struct AND its hand-written `Clone` impl. A
    // trait object with a type parameter in its param/return positions requires
    // that parameter to outlive `'static`; without the bound the generic struct
    // is well-typed to `ipe` but E0310s at `cargo` (a SEAL break). Recognised by
    // the same `is_clone`-but-not-derivable proxy the sibling carrier enum uses
    // (`enum_stores_shared_fun`): a fully-derivable record has no function
    // payload, so it is unaffected — no `'static` bound, byte-identical to before.
    let params_need_static = rec.is_clone && !rec.is_derivable;
    let decl_static = if params_need_static { ": 'static" } else { "" };
    let bound_static = if params_need_static { " + 'static" } else { "" };

    // Generic clauses: `<T1, T2>` on the struct, `<T1: IpeStringify, …>`
    // on the impl, `<T1, T2>` on the impl's `for` type. All empty when the record
    // is monomorphic.
    let params: Vec<String> = (1..=rec.type_params.len())
        .map(|i| format!("T{i}"))
        .collect();
    let (decl_clause, impl_bounds, use_clause) = if params.is_empty() {
        (String::new(), String::new(), String::new())
    } else {
        let bounds: Vec<String> = params
            .iter()
            .map(|p| format!("{p}: IpeStringify{bound_static}"))
            .collect();
        let decl_params: Vec<String> = params.iter().map(|p| format!("{p}{decl_static}")).collect();
        (
            format!("<{}>", decl_params.join(", ")),
            format!("<{}>", bounds.join(", ")),
            format!("<{}>", params.join(", ")),
        )
    };

    // Stringify of a struct: `{v0 v1 ...}` — N space-separated `{}` placeholders
    // wrapped in literal braces. With zero fields the rendering is just `{}`.
    //
    // The `format!` body is laid out natively (not hand-inlined then handed to
    // `rustfmt`): it lands at column 8 — `fn ipe_show`'s body, two block-indent
    // levels deep — and breaks one argument per line there when its argument text
    // exceeds `fn_call_width`, matching `rustfmt` by construction.
    let body = if rec.fields.is_empty() {
        "\"{}\".to_string()".to_owned()
    } else {
        let placeholders = vec!["{}"; rec.fields.len()].join(" ");
        let fmt_literal = format!("\"{{{{{placeholders}}}}}\"");
        render_stringify_format(&fmt_literal, &show_args, 8, 8)
    };

    // seal: only a fully-derivable record takes the unconditional
    // `#[derive(Clone, Debug, PartialEq)]`. A record holding a first-class
    // function / opaque wrapper field (directly or through a carrier / a
    // non-derivable enum) cannot derive those traits — emit no auto derives (the
    // hand-written `IpeStringify` impl below still gives it a total string form).
    //
    // seal: the serde derive is gated on `rec.is_serde` (the per-record serde
    // fixpoint), NOT `rec.is_derivable`. A CDPeq-but-not-serde record — e.g. a
    // view-helper `{ title : String, body : Html Msg }` in a Ipe.Web program —
    // keeps its `#[derive(Clone, Debug, PartialEq)]` but is NOT forced to
    // `serde::Serialize` / `Deserialize`, which would be an exit-0-then-cargo-fail
    // (E0277: `Html<Msg>: Serialize` unsatisfied). `is_serde ⇒ is_derivable`
    // (serde-OK leaves ⊂ derivable leaves), so serde is never added without CDPeq.
    // The app-entry Model gate independently rejects a non-serde type used AS a
    // Web/Tui/WebView Model; this gate covers every OTHER (non-Model) record.
    //
    // Both browser shapes force serde on seal types: WebView (like Web) carries a
    // `CustomElement.node`'s down/up records through `ui_widget_` (`Down: Serialize`,
    // `Up: DeserializeOwned`), yet its Model bound is only `Clone + Send`. Gating
    // solely on `uses_web` therefore ipe-accepts a serde-legal down record in a
    // WebView program but cargo-fails E0277 — the SEAL breach. `is_serde`
    // guarantees the derive always compiles, so unioning `uses_webview` is
    // fail-closed.
    let serde_derives = if rec.is_serde && ctx.derives_serde() {
        ", serde::Serialize, serde::Deserialize"
    } else {
        ""
    };
    let derive_prefix = if rec.is_derivable {
        format!("#[derive(Clone, Debug, PartialEq{serde_derives})]\n")
    } else {
        String::new()
    };
    // seal: a record that is `Clone` but NOT fully `CDPeq`-derivable — the
    // fn-value-reuse promotion's record-of-functions, whose `Arc<dyn Fn>`
    // (`SharedFun`) fields are `Clone` yet neither `Debug` nor `PartialEq` — gets
    // a HAND-WRITTEN `impl Clone` (cloning every field, an `Arc::clone` refcount
    // bump on each fn slot). Without it, a reused promoted record's `.clone()`
    // would be an `ipe`-0-then-cargo-fail `E0599`. A fully-derivable record takes
    // the derive above instead, so the two paths never both emit a `Clone` impl.
    let clone_impl = if rec.is_clone && !rec.is_derivable {
        emit_record_clone_impl(rec, &params, bound_static, &format!("{name}{use_clause}"))
    } else {
        String::new()
    };
    let ipe_impl_head = impl_header(&impl_bounds, "IpeStringify", &format!("{name}{use_clause}"));
    let mut items = Items::new();
    items.push(&braced(
        &format!("{derive_prefix}pub struct {name}{decl_clause}"),
        &fields_block,
    ));
    items.push(&clone_impl);
    items.push(&format!(
        "{ipe_impl_head}
    fn ipe_show(&self) -> String {{
        {body}
    }}
}}"
    ));
    Ok(items.render())
}

/// The hand-written `impl Clone` of a record that is `Clone` but not derivable,
/// cloning every field. `params` are the struct's `T1..Tn` names and
/// `for_type` is the impl's `for` type (`Name<T1, ..>`).
///
/// Every type parameter carries a `Clone` bound: the bare-variable admission in
/// the `is_clone` fixpoint (`field_is_clone`) is sound only under it — a record
/// may carry a bare-`Tn` field (or a `SharedFun` slot keyed on `Tn`) whose
/// per-`Tn` clone rides this bound, exactly as the sibling function-carrier
/// enum's hand-written `impl<Tn: Clone> Clone`.
fn emit_record_clone_impl(
    rec: &RecordStruct,
    params: &[String],
    bound_static: &str,
    for_type: &str,
) -> String {
    let field_clones: Vec<String> = rec
        .fields
        .iter()
        .map(|(field_name, _)| {
            let ident = mangle_reserved(field_name.clone());
            format!("            {ident}: self.{ident}.clone(),")
        })
        .collect();
    let impl_clone_bounds = if params.is_empty() {
        String::new()
    } else {
        let bounds: Vec<String> = params
            .iter()
            .map(|p| format!("{p}: Clone{bound_static}"))
            .collect();
        format!("<{}>", bounds.join(", "))
    };
    let clone_head = impl_header(&impl_clone_bounds, "Clone", for_type);
    format!(
        "{clone_head}
    fn clone(&self) -> Self {{
        Self {{
{}
        }}
    }}
}}
",
        field_clones.join("\n"),
    )
}

/// Every distinct field name required by any row-polymorphic function's
/// [`ipe_ir::Func::row_params`] across the whole program, in sorted order.
///
/// One field-witness trait is synthesised per such name; the empty set (a
/// program with no row-polymorphic annotation) emits no witness substrate at
/// all, so the common case is untouched.
pub fn row_witness_field_names(program: &Program) -> BTreeSet<Symbol> {
    let mut names = BTreeSet::new();
    for module in &program.modules {
        for func in &module.funcs {
            for row in &func.row_params {
                names.extend(row.fields.keys().copied());
            }
        }
    }
    names
}

/// Every distinct field name that appears in `updated_fields` of any row
/// parameter across the whole program. These are the fields for which an
/// `IpeWithF` setter-witness trait and per-struct impl must be synthesised
/// (G2: update-through-row).
pub fn row_updated_field_names(program: &Program) -> BTreeSet<Symbol> {
    let mut names = BTreeSet::new();
    for module in &program.modules {
        for func in &module.funcs {
            for row in &func.row_params {
                names.extend(row.updated_fields.iter().copied());
            }
        }
    }
    names
}

/// Synthesise the per-field witness traits and their per-struct impls that let a
/// row-polymorphic function read (and optionally update) a field off a
/// rustc-generic record parameter.
///
/// For each field name `f` required by any row bound in the program, one getter
/// trait `IpeHasF { type F; fn ipe_f(&self) -> &Self::F; }` is emitted, plus
/// one impl for EVERY registry struct that carries `f`. The impl's associated
/// type is the struct's own field type (rendered in the struct's generic scope),
/// so the row bound `R: IpeHasF<F = T>` type-checks against exactly the shapes
/// the solver already proved carry `f : T`. Static dispatch only — rustc
/// monomorphises each getter call to the concrete struct; no `dyn`, no
/// reflection.
///
/// For each field name `f` that also appears in `updated_fields` of any row
/// parameter (G2: update-through-row), a setter trait `IpeWithF: IpeHasF { fn
/// ipe_with_f(self, v: Self::F) -> Self; }` is also emitted, plus one impl per
/// registry struct carrying `f`. The `..self` functional-update in each impl
/// preserves all untouched fields. The supertrait relationship
/// (`IpeWithF: IpeHasF`) makes "updatable implies readable" a structural
/// invariant — the bound `R: IpeWithF` implies `R: IpeHasF`, so both reads and
/// updates on the same field are always available together.
///
/// Returns the empty string when the program has no row-polymorphic annotation.
pub fn emit_row_witnesses(ctx: &EmitCtx, program: &Program) -> DResult<String> {
    let field_names = row_witness_field_names(program);
    if field_names.is_empty() {
        return Ok(String::new());
    }
    let updated_field_names = row_updated_field_names(program);
    let mut items = Items::new();
    for field_sym in &field_names {
        let field_name = ctx.resolve_ident(*field_sym)?.to_owned();
        let trait_name = field_witness_trait_name(&field_name);
        let assoc = field_witness_assoc_type_name(&field_name);
        let getter = field_witness_getter_name(&field_name);
        // Getter trait: one associated type (the field's type) and one
        // borrowing getter. The associated type keeps the trait type-agnostic
        // so a single trait serves the field at every type it occurs at across
        // structs.
        items.push(&format!(
            "pub trait {trait_name} {{\n    type {assoc};\n    fn {getter}(&self) -> &Self::{assoc};\n}}"
        ));
        // Setter trait for fields that are updated in some row-poly body (G2).
        // Supertraits the getter: `IpeWithF: IpeHasF`. The setter consumes
        // `self` and returns `Self` so the `..self` rebuild in each struct impl
        // preserves the residual fields without naming the struct at the call
        // site.
        let needs_setter = updated_field_names.contains(field_sym);
        if needs_setter {
            let setter_trait = crate::naming::field_setter_witness_trait_name(&field_name);
            let setter_method = crate::naming::field_setter_witness_method_name(&field_name);
            items.push(&format!(
                "pub trait {setter_trait}: {trait_name} {{\n    fn {setter_method}(self, v: Self::{assoc}) -> Self;\n}}"
            ));
        }
        // One getter impl per registry struct carrying this field — total over
        // the struct namespace, no reachability analysis (correctness needs
        // none).
        for rec in ctx.record_structs() {
            let Some((field_ipe_name, field_ty)) =
                rec.fields.iter().find(|(fname, _)| *fname == field_name)
            else {
                continue;
            };
            let ident = mangle_reserved(field_ipe_name.clone());
            // The struct's own generic scope: a generic struct's field type may
            // be a `T{n}`, resolved by position exactly as in `emit_record_struct`.
            let scope = GenericScope::new(&rec.type_params);
            let assoc_ty = render_type(ctx, field_ty, scope)?;
            let params: Vec<String> = (1..=rec.type_params.len())
                .map(|i| format!("T{i}"))
                .collect();
            let (decl_clause, use_clause) = if params.is_empty() {
                (String::new(), String::new())
            } else {
                (
                    format!("<{}>", params.join(", ")),
                    format!("<{}>", params.join(", ")),
                )
            };
            let struct_ty = format!("{}{use_clause}", rec.name);
            let head = impl_header(&decl_clause, &trait_name, &struct_ty);
            items.push(&format!(
                "{head}\n    type {assoc} = {assoc_ty};\n    fn {getter}(&self) -> &{assoc_ty} {{ &self.{ident} }}\n}}"
            ));
            // Setter impl for this (field, struct) pair when needed.
            if needs_setter {
                let setter_trait = crate::naming::field_setter_witness_trait_name(&field_name);
                let setter_method = crate::naming::field_setter_witness_method_name(&field_name);
                let setter_head = impl_header(&decl_clause, &setter_trait, &struct_ty);
                // The `..self` functional update preserves all fields NOT
                // being updated. The struct name IS known here (inside the
                // per-struct impl loop), so the update is a concrete struct
                // rebuild: `StructName { field: v, ..self }`. This is the
                // only place in the whole emission that needs the concrete
                // struct name — it is the entire point of the impl
                // separation.
                let struct_name = &rec.name;
                items.push(&format!(
                    "{setter_head}\n    fn {setter_method}(self, v: {assoc_ty}) -> Self {{ {struct_name}{use_clause} {{ {ident}: v, ..self }} }}\n}}"
                ));
            }
        }
    }
    Ok(items.render())
}

#[cfg(test)]
mod show_pin_agreement {
    use super::{GenericScope, render_type};
    use crate::RustBackend;
    use ipe_intern::Interner;
    use ipe_ir::{
        IrType, ModPath, Program, RuntimeBridgedEnum, SHOWN_LEAVES, ShowLeaf, ShowPolicy,
        ShowShape, UiCtor, UiPlain,
    };

    /// The runtime's show-row pins: each leaf with the Rust type that renders it.
    const SHOW_ROWS: &str = include_str!("../../../../runtime/rust/tests/show_rows.rs");

    /// Every `"Leaf" => Policy: Type;` line of `text`.
    fn parse_pins(text: &str) -> Vec<(&str, &str)> {
        text.lines()
            .filter_map(|line| {
                let (leaf, rest) = line.trim().strip_prefix('"')?.split_once('"')?;
                let (_, ty) = rest.trim().strip_prefix("=>")?.split_once(':')?;
                Some((leaf, ty.trim().strip_suffix(';')?.trim()))
            })
            .collect()
    }

    /// A Rust type's own name: its last path segment, type arguments dropped.
    fn type_name(spelled: &str) -> &str {
        let head = spelled.split_once('<').map_or(spelled, |(head, _)| head);
        head.rsplit_once("::").map_or(head, |(_, name)| name).trim()
    }

    fn leaf_of(ty: &IrType) -> Option<ShowLeaf> {
        match ty.show_shape() {
            ShowShape::Leaf(leaf) => Some(leaf),
            ShowShape::Carrier(_)
            | ShowShape::Param
            | ShowShape::Named { .. }
            | ShowShape::TooWide => None,
        }
    }

    /// One sample type per shown leaf the backend renders without a program.
    fn leaf_samples() -> Vec<IrType> {
        let unit = || Box::new(IrType::Unit);
        let ui = |ctor| IrType::Ui { ctor, msg: unit() };
        vec![
            IrType::Int,
            IrType::SessionHandle,
            IrType::Float,
            IrType::Bool,
            IrType::Str,
            IrType::Char,
            IrType::Unit,
            IrType::Task(unit()),
            IrType::Bytes,
            IrType::Json,
            IrType::Decoder(unit()),
            IrType::Db,
            IrType::Cmd(unit()),
            IrType::Sub(unit()),
            IrType::ServerRequest,
            IrType::ServerResponse,
            IrType::ServerRoute,
            IrType::ServerCookie,
            IrType::StreamWriter,
            IrType::HttpRequest,
            IrType::WebSocketServer,
            IrType::WebSocketServerCfg,
            ui(UiCtor::Html),
            ui(UiCtor::Element),
            ui(UiCtor::Cells),
            ui(UiCtor::UiAttribute),
            ui(UiCtor::TuiAttribute),
            ui(UiCtor::CliLines),
            ui(UiCtor::CliAttribute),
            ui(UiCtor::HtmlAttribute),
            ui(UiCtor::HtmlEvent),
            ui(UiCtor::Label),
            ui(UiCtor::Placeholder),
            ui(UiCtor::RadioOption),
            IrType::UiPlain(UiPlain::Length),
            IrType::UiPlain(UiPlain::Color),
            IrType::UiPlain(UiPlain::HAlign),
            IrType::UiPlain(UiPlain::VAlign),
            IrType::UiPlain(UiPlain::Location),
            IrType::UiPlain(UiPlain::PseudoClass),
            IrType::UiPlain(UiPlain::Description),
            IrType::UiPlain(UiPlain::LayoutContext),
            IrType::UiPlain(UiPlain::ColorError),
            IrType::UiPlain(UiPlain::TermProfile),
            IrType::UiPlain(UiPlain::AnsiColor),
            IrType::UiPlain(UiPlain::WcagLevel),
            IrType::UiPlain(UiPlain::TextSize),
            IrType::UiPlain(UiPlain::Deficiency),
            IrType::WebReq,
            IrType::WebRoute(unit()),
            IrType::CustomElement {
                down: unit(),
                up: unit(),
            },
            IrType::Order,
            IrType::BackoffStrategy,
            IrType::HttpMethod,
            IrType::Decimal,
            IrType::Principal,
            IrType::AuthConfig,
            IrType::TokenSource,
            IrType::ErrorKind,
            IrType::Error,
            IrType::ErrorDetails,
            IrType::ErrorInfo,
            IrType::PanicInfo,
            IrType::TypeInfo,
            IrType::SqlFragment,
            IrType::Secret,
            IrType::Path,
            IrType::Regex,
            IrType::ProcessRunWithCfg,
            IrType::ProcessRunInPtyCfg,
            IrType::CacheCfg,
            IrType::CacheStats,
            IrType::WebSocketClientCfg,
            IrType::CsvDoc,
            IrType::EmailMessage,
            IrType::EmailAttachment,
            IrType::EmailSesConfig,
            IrType::EmailSmtpConfig,
            IrType::EmailProvider,
            IrType::CryptoKey,
            IrType::CryptoMac,
            IrType::EmailAddress,
            IrType::Url,
            IrType::UrlRelative,
            IrType::Dsn,
            IrType::Connection,
            IrType::Setting,
            IrType::Locale,
            IrType::WebApp,
            IrType::TuiApp,
            IrType::CliApp,
            IrType::WorkerApp,
        ]
    }

    /// The runtime-bridged enums `render_type` names without a registered
    /// definition, as `(leaf, type)` samples.
    fn bridged_samples(interner: &mut Interner) -> Vec<(ShowLeaf, IrType)> {
        [
            RuntimeBridgedEnum::CacheHandle,
            RuntimeBridgedEnum::ChunkEvent,
            RuntimeBridgedEnum::StreamId,
            RuntimeBridgedEnum::RedirectPolicy,
        ]
        .into_iter()
        .map(|bridged| {
            let home = bridged
                .home()
                .iter()
                .map(|seg| interner.intern(seg).expect("intern a home segment"))
                .collect();
            let name = interner.intern(bridged.name()).expect("intern a name");
            let ty = IrType::Enum {
                home: ModPath(home),
                name,
                args: Vec::new(),
            };
            (bridged.show_leaf(), ty)
        })
        .collect()
    }

    /// The Rust type `render_type` spells for each shown leaf is a type the
    /// runtime's `show_rows.rs` pins to that leaf, and every shown leaf has a
    /// sample here, so a renamed render or a moved pin breaks this test.
    #[test]
    fn every_rendered_leaf_type_is_its_pinned_row_type() {
        let mut interner = Interner::new();
        let bridged = bridged_samples(&mut interner);
        let program = Program {
            modules: vec![],
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
        };
        let backend = RustBackend::new(&interner);
        let ctx = backend.emit_ctx_for_tests(&program).expect("build EmitCtx");
        let pins = parse_pins(SHOW_ROWS);
        let samples: Vec<(ShowLeaf, IrType)> = leaf_samples()
            .into_iter()
            .map(|ty| {
                let leaf = leaf_of(&ty).expect("a leaf sample classifies as a leaf");
                (leaf, ty)
            })
            .chain(bridged)
            .collect();
        for (leaf, ty) in &samples {
            let rendered = render_type(&ctx, ty, GenericScope::new(&[])).expect("render");
            let pinned: Vec<&str> = pins
                .iter()
                .filter(|(name, _)| *name == leaf.name())
                .map(|(_, pin)| type_name(pin))
                .collect();
            assert!(
                pinned.contains(&type_name(&rendered)),
                "leaf {} renders as `{rendered}`, but show_rows.rs pins it to {pinned:?}",
                leaf.name()
            );
        }
        for (name, policy) in SHOWN_LEAVES {
            if policy.tag() == ShowPolicy::Refused.tag() {
                continue;
            }
            assert!(
                samples.iter().any(|(leaf, _)| leaf.name() == name),
                "shown leaf {name} has no render sample"
            );
        }
    }

    #[test]
    fn the_pin_parser_reads_a_row_and_skips_the_rest() {
        let text = "pins! {\n    \"Int\" => Value: i64;\n    #[cfg(feature = \"x\")]\n    \"Task\" => Internals: a::IpeTask<b::E, ()>;\n}\n";
        assert_eq!(
            parse_pins(text),
            vec![("Int", "i64"), ("Task", "a::IpeTask<b::E, ()>")]
        );
        assert_eq!(type_name("a::IpeTask<b::E, ()>"), "IpeTask");
        assert_eq!(type_name("()"), "()");
        assert_ne!(
            type_name("ipe_runtime::url::Url"),
            type_name("x::UrlRelative")
        );
    }
}
