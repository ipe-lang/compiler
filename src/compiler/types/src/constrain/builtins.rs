use super::{
    BTreeSet, BuiltinTag, CtorKey, CtorScheme, DResult, Diagnostic, FieldTag, Interner, Symbol, Ty,
    TyBounds,
};

/// Generates [`FieldSymbols`] from one `(FieldTag, field)` row per tag.
///
/// A row's interned text and its `get` arm come from the same row, so a tag
/// can never pair with another tag's text; a tag with no row fails the
/// exhaustive `get` match and a duplicate row is a duplicate field.
macro_rules! field_symbols {
    ($(($tag:ident, $field:ident)),+ $(,)?) => {
        /// Interned record field names the type checker keys on, one per [`FieldTag`].
        ///
        /// Each name is spelled once, in [`FieldTag::text`]; rows are listed in
        /// intern order, which fixes the `Symbol` order of record keys.
        pub struct FieldSymbols {
            $(
                #[doc = concat!("The [`FieldTag::", stringify!($tag), "`] field name.")]
                pub $field: Symbol,
            )+
        }

        impl FieldSymbols {
            /// Interns every row's [`FieldTag::text`].
            ///
            /// # Errors
            /// Propagates the interner-capacity diagnostic.
            pub fn new(interner: &mut Interner) -> DResult<Self> {
                Ok(Self {
                    $($field: interner.intern(FieldTag::$tag.text())?,)+
                })
            }

            /// The interned field name of `tag`.
            #[must_use]
            pub const fn get(&self, tag: FieldTag) -> Symbol {
                match tag {
                    $(FieldTag::$tag => self.$field,)+
                }
            }
        }
    };
}

field_symbols! {
    (HttpBody, http_f_body),
    (HttpHeaders, http_f_headers),
    (HttpStatus, http_f_status),
    (ServerContentType, server_f_content_type),
    (MigrationName, migration_f_name),
    (MigrationSql, migration_f_sql),
    (HttpMethod, http_f_method),
    (HttpUrl, http_f_url),
    (HttpTimeout, http_f_timeout),
    (HttpRedirects, http_f_redirects),
    (LayoutWrapperAttrs, lw_wrapper_attrs),
    (LayoutRootAttrs, lw_root_attrs),
    (AppInit, live_f_init),
    (AppUpdate, live_f_update),
    (AppView, live_f_view),
    (AppSubscriptions, live_f_subscriptions),
    (AppRoutes, live_f_routes),
    (AppNotFound, live_f_not_found),
    (TerminalKeyKind, tui_f_key_kind),
    (TerminalKeyValue, tui_f_key_value),
    (ButtonOnPress, btn_f_on_press),
    (Label, btn_f_label),
    (InputOnChange, input_f_on_change),
    (InputText, input_f_text),
    (InputPlaceholder, input_f_placeholder),
    (InputChecked, input_f_checked),
    (InputIcon, input_f_icon),
    (InputSpellcheck, input_f_spellcheck),
    (InputValue, input_f_value),
    (InputMin, input_f_min),
    (InputMax, input_f_max),
    (InputStep, input_f_step),
    (InputOptions, input_f_options),
    (InputSelected, input_f_selected),
    (CsvHeader, csv_f_header),
    (CsvRows, csv_f_rows),
    (CacheMaxEntries, cache_f_max_entries),
    (CacheTtlMs, cache_f_ttl_ms),
    (CacheMaxBytes, cache_f_max_bytes),
    (CacheHits, cache_f_hits),
    (CacheMisses, cache_f_misses),
    (CacheEvictions, cache_f_evictions),
    (WsUrl, ws_f_url),
    (WsHeaders, ws_f_headers),
    (WsTimeout, ws_f_timeout),
    (WsPingInterval, ws_f_ping_interval),
    (EmailFrom, email_f_from),
    (EmailTo, email_f_to),
    (EmailCc, email_f_cc),
    (EmailBcc, email_f_bcc),
    (EmailSubject, email_f_subject),
    (EmailTextBody, email_f_text_body),
    (EmailHtmlBody, email_f_html_body),
    (EmailAttachments, email_f_attachments),
    (EmailReplyTo, email_f_reply_to),
    (EmailFilename, email_f_filename),
    (EmailMimeType, email_f_mime_type),
    (EmailContent, email_f_content),
    (RetryBaseMs, retry_f_base_ms),
    (RetryMaxAttempts, retry_f_max_attempts),
    (RetryShouldRetry, retry_f_should_retry),
    (RetryStrategy, retry_f_strategy),
    (EdgeTop, edge_f_top),
    (EdgeRight, edge_f_right),
    (EdgeBottom, edge_f_bottom),
    (EdgeLeft, edge_f_left),
    (ShadowOffsetX, shadow_f_offset_x),
    (ShadowOffsetY, shadow_f_offset_y),
    (ShadowBlur, shadow_f_blur),
    (ShadowSpread, shadow_f_spread),
    (ShadowColor, shadow_f_color),
    (ImageSrc, img_f_src),
    (ImageDescription, img_f_description),
    (ProcessCommand, process_f_command),
    (ProcessArgs, process_f_args),
    (ProcessCwd, process_f_cwd),
    (ProcessEnv, process_f_env),
    (ProcessExitCode, process_f_exit_code),
    (ProcessStdout, process_f_stdout),
    (ProcessStderr, process_f_stderr),
    (ProcessCols, process_f_cols),
    (ProcessRows, process_f_rows),
    (ProcessOutput, process_f_output),
}

/// Interned symbols of every built-in type, constructor, and field name.
pub struct Builtins {
    pub int: Symbol,
    pub float: Symbol,
    pub bool: Symbol,
    pub string: Symbol,
    pub char: Symbol,
    pub task: Symbol,
    pub maybe: Symbol,
    pub result: Symbol,
    pub list: Symbol,
    /// Interned `Just` / `Nothing` / `Ok` / `Err` / `True` / `False` — the
    /// Prelude-exposed built-in constructor names.
    pub just: Symbol,
    pub nothing: Symbol,
    pub ok: Symbol,
    pub err: Symbol,
    pub true_: Symbol,
    pub false_: Symbol,
    /// `Ipe.Dict` type constructor symbol.
    pub dict: Symbol,
    /// `Ipe.Set` type constructor symbol.
    pub set: Symbol,
    /// `Ipe.Bytes` type constructor symbol.
    /// Divergence from Ipê: Bytes is a distinct primitive in Ipê-Rust (Vec<u8>),
    /// not a String alias as in the the reference.
    pub bytes: Symbol,
    /// The interned `Error` symbol, used to validate the error channel in
    /// `Task Error a` annotations (normalised to unary `Task a`) and to pin the
    /// handler parameter type in `mapError` / `onError` so a bare lambda `\e ->
    /// ...` infers `e : Error` without leaving a free variable.
    pub error: Symbol,
    /// `ErrorKind` — the classification carried by `Error`'s first field. Its
    /// constructors are canon's `BUILTIN_UNIONS` row, read by
    /// [`Self::ctor_schemes`] and by `ipe_lower`'s seeded unions; no symbol of
    /// one is held here.
    pub errorkind: Symbol,
    /// `ErrorDetails` — the 6-variant enrichment union carried on
    /// `ErrorInfo.details`. Registered as a Prelude
    /// built-in exactly like `ErrorKind` — see `ipe_lower`'s
    /// `enum_variants`/`ctor_arity` seeding.
    pub errordetails: Symbol,
    /// `BackoffStrategy` — the 4-constructor retry-backoff strategy ADT
    /// (`Linear | LinearWithJitter | Exponential | ExponentialWithJitter`).
    /// Registered as a Prelude built-in; seeded by `ipe_lower`'s
    /// `enum_variants`/`ctor_arity` (via `BuiltinTag::BackoffStrategy`).
    pub backoffstrategy: Symbol,
    /// The 6 `ErrorDetails` constructor symbols, in canon's registered index
    /// order (`crates/ipe_canon/src/env.rs`) — do not reorder.
    pub ed_ffi_panic: Symbol,
    pub ed_type_mismatch: Symbol,
    pub ed_http_status: Symbol,
    pub ed_json_decode: Symbol,
    pub ed_custom: Symbol,
    pub ed_database: Symbol,
    /// `DbFailure` — the closed database-failure-cause union carried by
    /// `ErrorDetails.Database`.
    pub db_failure: Symbol,
    /// `AuthError` — the closed, payload-free refusal union of
    /// `Auth.verifyToken`.
    pub auth_error: Symbol,
    /// `PanicInfo` / `TypeInfo` / `ErrorInfo` — NOMINAL type-constructor
    /// symbols (SEAL fix, see
    /// `docs/adr/0001-language-semantics-and-types.md`). The three payload
    /// record types are opaque nominal Cons (like the server `Request`), NOT
    /// structural records: a bare record literal must not unify with them —
    /// the runtime backs them with concrete structs (`IpePanicInfo` /
    /// `IpeTypeInfo` / `IpeErrorInfo`), so a structural lowering
    /// (project-local synthesized struct) would fail `cargo build` after a
    /// clean `ipe` exit. Field ACCESS on them stays available through
    /// `resolve_deferred`'s builtin-record field tables.
    pub panicinfo: Symbol,
    pub typeinfo: Symbol,
    pub errorinfo: Symbol,
    /// Two distinct scheme type-variable symbols (`a`, `e`) used to build the
    /// built-in constructor schemes. Their identity links a constructor's
    /// payload to its result type, exactly like a user union's declared vars;
    /// each use site instantiates them fresh through one shared map.
    pub tv_a: Symbol,
    pub tv_e: Symbol,
    /// Interned record field names, one per [`FieldTag`].
    pub fields: FieldSymbols,
    // ── Http type symbols ────────────────────────────────────────────────────
    /// `"HttpMethod"` — the `Ipe.Http.HttpMethod` ADT type constructor.
    pub http_method: Symbol,
    /// `"RedirectPolicy"` — the `Ipe.Http.RedirectPolicy` ADT type constructor.
    pub redirect_policy: Symbol,
    /// `"Duration"` — the `Ipe.Duration.Duration` opaque ADT type constructor.
    /// Consumed by the `Http.withTimeout` kernel (its typed timeout argument);
    /// homed via [`Self::duration_home`] so a point-free reference lowers to the
    /// compiled-module enum, mirroring `EmailProvider` / [`Self::email_home`].
    pub duration: Symbol,
    /// `"NoRedirects"` — nullary `RedirectPolicy` constructor.
    pub no_redirects: Symbol,
    /// `"FollowRedirects"` — `Int -> RedirectPolicy` constructor.
    pub follow_redirects: Symbol,
    // ── Db type symbols ──────────────────────────────────────────────────────
    /// `"Db"` — the opaque database connection pool type constructor.
    pub db: Symbol,
    /// `"SqlValue"` — the sum type for typed SQL parameter values.
    pub sqlvalue: Symbol,
    /// `"SqlField"` — the sum type for PATCH-style field-set / field-omit SQL params.
    pub sqlfield: Symbol,
    /// `"SqlFragment"` — `Ipe.Db.Sql`'s opaque, parameterized WHERE-fragment
    /// type.
    pub sqlfragment: Symbol,
    /// `"Secret"` — `Ipe.Secret`'s opaque, sealed secret-string wrapper
    /// type.
    pub secret: Symbol,
    /// `"Path"` — `Ipe.Path`'s opaque, validated filesystem-path type.
    pub path: Symbol,
    /// `"Regex"` — `Ipe.Regex`'s opaque compiled-pattern handle. Built ONLY by
    /// `Regex.compile : String -> Result Error Regex`. Zero type arguments.
    /// Lowered to `IrType::Regex`.
    pub regex: Symbol,
    // ── SqlValue constructor name symbols ─────────────────────────────────────
    pub sql_string: Symbol,
    pub sql_int: Symbol,
    pub sql_float: Symbol,
    pub sql_bool: Symbol,
    pub sql_bytes: Symbol,
    pub sql_time: Symbol,
    /// `"SqlDecimal"` — carries a native `Decimal`, bound as lossless TEXT.
    pub sql_decimal: Symbol,
    /// `"SqlMoney"` — wraps a `String` in `"ISO_CODE AMOUNT"` format (TEXT).
    pub sql_money: Symbol,
    pub sql_null: Symbol,
    // ── SqlField constructor name symbols ─────────────────────────────────────
    pub set_field: Symbol,
    pub omit_field: Symbol,
    // ── Shared row-decoder type (JSON) ────────────────────────────────────────
    /// `"Decoder"` — the opaque decoder type constructor shared by `Ipe.Json.Decode`
    /// and `Ipe.Db.Decode`. Represented in the IR as `IrType::Decoder(Box<IrType>)`.
    pub decoder: Symbol,
    // ── TEA Cmd / Sub type constructor symbols ────────────────────────────────
    /// `"Cmd"` — the opaque command type constructor `Cmd msg`.
    /// Represented in the IR as `IrType::Cmd(Box<IrType>)`.
    pub cmd: Symbol,
    /// `"Sub"` — the opaque subscription type constructor `Sub msg`.
    /// Represented in the IR as `IrType::Sub(Box<IrType>)`.
    pub sub: Symbol,
    // ── Ipe.Http.Server opaque type constructor symbols ───────────────────────
    /// `"Request"` — the opaque server request type.
    pub server_request: Symbol,
    /// `"Response"` — the opaque server response type.
    pub server_response: Symbol,
    /// `"Route"` — the opaque server route type.
    pub server_route: Symbol,
    /// `"Cookie"` — the opaque server cookie type.
    pub server_cookie: Symbol,
    /// `"AuthConfig"` — the opaque authed-route configuration type
    /// (`ipe_runtime::server::AuthConfig`). Built only through `Server.authConfig`;
    /// the sole value the authed-route kernels accept. Lowered to
    /// `IrType::AuthConfig`.
    pub auth_config: Symbol,
    /// `"TokenSource"` — the opaque descriptor of where the authed middleware
    /// reads the session token (`ipe_runtime::server::TokenSource`). Built only
    /// through the `Server` token-source kernels. Lowered to
    /// `IrType::TokenSource`.
    pub token_source: Symbol,
    /// `"Handler"` — the `Request -> Task Error Response` alias from
    /// `Ipe.Http.Server`. Pre-interned so `constrain_def` can detect a
    /// `handler : Handler` annotation and expand it to the full arrow type
    /// before the parameter-loop runs (fixes IPE-T0004 for handler bindings).
    pub handler: Symbol,
    // ── Ipe.Http.Server.Stream opaque type constructor symbol ───────────
    /// `"StreamWriter"` — the opaque stream writer handle passed to the
    /// `Stream.stream` callback and consumed by `Stream.emit` /
    /// `Stream.finish` / `Stream.withContentType`.
    pub stream_writer: Symbol,
    // ── Ipe.Http.Server.WebSocket opaque type constructor symbols ────────
    /// `"WebSocketServer"` — the opaque per-peer WebSocket handle (`WsHandle`).
    pub ws_server: Symbol,
    /// `"WebSocketServerCfg"` — the opaque WebSocket server configuration
    /// (`WsServerCfg<IpeError>`).
    pub ws_server_cfg: Symbol,
    // ── Ipe.Ui / Ipe.Html parametric type constructor symbols ─────────────────
    /// `"Attribute"` — Ipe.Ui attribute type constructor `Attribute msg`.
    ///
    /// Used to build Ui kernel type schemes so the HM solver constrains
    /// `List (Attribute msg)` arguments (e.g. `layout [] child`) to a concrete
    /// element type rather than leaving them as free variables.  Without these
    /// entries the empty-attrs list `[]` keeps `List (Ty::Var)` as its region
    /// type, `list_elem_ir` returns `IrType::Json`, and `emit_list` emits the
    /// bare `Vec::new()` that Rust rejects with E0283 when M cannot be inferred
    /// from elsewhere in the expression.
    pub attribute: Symbol,
    /// `"View"` — the engine-tagged view carrier `View engine msg`. The SSOT
    /// surface every engine's view collapses into: `View Web msg` IS `Element
    /// msg`, `View Tui msg` IS `Screen msg`, `View Cli msg` IS `Lines msg`.
    pub view: Symbol,
    /// `"Element"` — Ipe.Ui element type constructor `Element msg`. Retained as
    /// the canon alias `View Web msg`.
    pub element: Symbol,
    /// `"Screen"` — Tui-only view type constructor `Screen msg`. Distinct from
    /// `Element msg`; produced by `Ipe.Ui.Tui.*` builders.
    pub cells: Symbol,
    /// `"TuiAttr"` — the cell-native attribute type constructor
    /// `Ipe.Ui.Tui.Attribute msg`. Distinct from the DOM `Attribute msg`
    /// (`attribute`): only terminal-honorable attributes (spacing/padding/
    /// align/bold/underline/color/bg) inhabit it, so a DOM attribute
    /// (`Ui.onClick`, `Ui.scrollbars`, …) is unnameable in a `Screen` view —
    /// a type error, never a silent render-time drop.
    pub tui_attr: Symbol,
    /// `"Lines"` — the Cli-only line-oriented view type constructor `Lines msg`.
    /// Distinct from both `Element msg` and `Screen msg`; produced by
    /// `Ipe.Ui.Cli.*` builders. Line-scoped, so 2D cell and DOM builders are
    /// unnameable in it.
    pub cli_lines: Symbol,
    /// `"CliAttr"` — the line-native attribute type constructor
    /// `Ipe.Ui.Cli.Attribute msg`. Only line-scoped styles
    /// (bold/underline/dim/reverse/color/bg) inhabit it, so a 2D cell attribute
    /// or a DOM attribute is unnameable in a `Lines` view.
    pub cli_attr: Symbol,
    /// `"ColorError"` — the typed parse-error channel of the string-input colour
    /// constructors (`fromHex` / `fromName`). Backs `ipe_runtime::color::ColorError`.
    pub color_error: Symbol,
    /// `"TermProfile"` — the terminal capability profile `Color.toAnsi` targets.
    /// Backs `ipe_runtime::color::TermProfile`.
    pub term_profile: Symbol,
    /// `"AnsiColor"` — the terminal colour type: the palette `Ipe.Color`
    /// constructors (`black`…`brightWhite`, `default`, `rgb`) build it, and
    /// `Color.toAnsi` down-samples an sRGB `Color` to it. Backs
    /// `ipe_runtime::color::AnsiColor`.
    pub ansi_color: Symbol,
    /// `"WcagLevel"` — the WCAG conformance level `Color.meetsWcag` checks
    /// against. Backs `ipe_runtime::color::WcagLevel`.
    pub wcag_level: Symbol,
    /// `"TextSize"` — the text-size band a WCAG threshold applies to. Backs
    /// `ipe_runtime::color::TextSize`.
    pub text_size: Symbol,
    /// `"Deficiency"` — the colour-vision deficiency `Color.simulate` previews.
    /// Backs `ipe_runtime::color::Deficiency`.
    pub deficiency: Symbol,
    /// `"CustomElement"` — the JS-widget boundary type constructor
    /// `CustomElement down up`. Empty-module opaque handle; consumed only by the
    /// `CustomElement.node` kernel scheme.
    pub custom_element: Symbol,
    /// `"Html"` — Html type constructor `Html msg` (shared by Ipe.Html and
    /// Ipe.Ui render entry points).
    pub html_con: Symbol,
    /// `"Length"` — Ipe.Ui nullary length type produced by `Ui.px` / `Ui.fill`
    /// / `Ui.minimum` / …. Lowered to `IrType::UiPlain(UiPlain::Length)` via the
    /// `"Length"` arm in `ipe_lower::ir_type_from_ty`.
    pub length: Symbol,
    /// `"Color"` — Ipe.Ui nullary colour type produced by `Ui.rgb` / `Ui.rgba`
    /// / `Ui.white` / …. Lowered to `IrType::UiPlain(UiPlain::Color)`.
    pub color: Symbol,
    /// `"Description"` — Ipe.Ui semantic description type produced by `Ui.descMain`
    /// / `Ui.descNavigation` / …. Lowered to `IrType::UiPlain(UiPlain::Description)`
    /// via the `"Description"` arm in `ipe_lower::ir_type_from_ty`.
    pub description: Symbol,
    /// `"PseudoClass"` — Ipe.Ui nullary pseudo-class-selector type produced by
    /// `Ui.hover` / `Ui.focus` / `Ui.focusVisible` / `Ui.active` / `Ui.disabled`
    /// and consumed by `Ui.onPseudo`. Lowered to
    /// `IrType::UiPlain(UiPlain::PseudoClass)` via the
    /// `"PseudoClass"` arm in `ipe_lower::ir_type_from_ty`.
    pub pseudo_class: Symbol,
    /// `"Value"` — the opaque JSON value type (`Value = any` in Ipê) produced /
    /// consumed by the `JsonEnc.*` encoders. Lowered to `IrType::Json`
    /// (`serde_json::Value`, re-exported as `JsonVal`) via the `"Value"` arm in
    /// `ipe_lower::ir_type_from_ty`. A distinct interned symbol so the `JsonEnc`
    /// scheme can produce a *concrete* `Value` region type (closing the former
    /// `Ty::Var(u32::MAX)` exit-0 hole) rather than leaning on the lowerer's
    /// free-`Ty::Var` → `Json` fallback.
    pub json_value: Symbol,
    // ── Ipe.Web / Ipe.Web opaque type constructor symbols ───────────────────
    /// `"WebReq"` — opaque request threaded through `Web.tea`'s `init`.
    pub web_req: Symbol,
    /// `"SessionHandle"` — the opaque `Ipe.Ffi.Js` session-stream handle,
    /// obtained only from `Js.openSession`. Backed by the runtime session id.
    pub session_handle: Symbol,
    /// `"WebRoute"` — opaque route descriptor returned by `Web.route`.
    pub live_route_con: Symbol,
    // ── Ipe.Ui.Input type constructor symbols ─────────────────────────
    /// `"Label"` — the `Label msg` type constructor from `Ipe.Ui.Input`.
    /// Lowered to `IrType::Ui { ctor: UiCtor::Label, msg }`.
    pub input_label_con: Symbol,
    /// `"Placeholder"` — the `Placeholder msg` type constructor from `Ipe.Ui.Input`.
    /// Lowered to `IrType::Ui { ctor: UiCtor::Placeholder, msg }`.
    pub input_placeholder_con: Symbol,
    /// `"RadioOption"` — the `RadioOption msg` type constructor from `Ipe.Ui.Input`.
    /// Lowered to `IrType::Ui { ctor: UiCtor::RadioOption, msg }`.
    pub input_radio_option_con: Symbol,
    // ── Ipe.Http.Stream opaque StreamId type constructor ─────────────────
    /// `"StreamId"` — the opaque stream identifier type constructor from
    /// `Ipe.Http.Stream`. Backed by `ipe_runtime::http_stream::IpeStreamId`.
    /// No synthetic `EnumDef` is injected; the backend handles it via a special
    /// case in `enum_name` that maps the symbol to the runtime struct.
    pub stream_id: Symbol,
    // ── Order ADT ─────────────────────────────────────────────────────
    /// `"Order"` — the type constructor for three-way comparison results.
    pub order: Symbol,
    /// `"LT"` — the LT constructor of the Order ADT (less-than).
    pub lt: Symbol,
    /// `"EQ"` — the EQ constructor of the Order ADT (equal).
    pub eq: Symbol,
    /// `"GT"` — the GT constructor of the Order ADT (greater-than).
    pub gt: Symbol,
    // ── JWT builder opaque type constructor symbols (D-00) ────────────────────
    /// `"Claims"` — opaque JWT claims builder object.  Backed at runtime by
    /// `serde_json::Value` (a JSON object accumulator).  Used as the input /
    /// output of the `Jwt.subject`, `Jwt.issuer`, … builder chain functions
    /// and the final `Jwt.encode` call.
    pub jwt_claims: Symbol,
    /// `"Algorithm"` — JWT signing algorithm descriptor.  Backed at runtime by
    /// a sealed `Ipe.Secret` wrapping the string `"HS256:<secret>"` or
    /// `"RS256:<pem>"`.  Built by `Jwt.hs256` / `Jwt.rs256` and consumed by
    /// `Jwt.encode` / `Jwt.decode`.
    pub jwt_algorithm: Symbol,
    // ── Ipe.Decimal opaque type constructor symbol ────────────────────────────
    /// `"Decimal"` — the opaque arbitrary-precision decimal type constructor
    /// from `Ipe.Decimal`.  Backed by `ipe_runtime::decimal::Decimal` (wrapping
    /// `rust_decimal::Decimal`).  Zero type arguments.  Lowered to
    /// `IrType::Decimal` by `ir_type_from_ty` / `ir_type_from_canon`.
    pub decimal: Symbol,
    // ── Ipe.Email type symbols ───────────────────────────────────────────
    /// `"EmailProvider"` — the opaque `Ipe.Email.EmailProvider` ADT constructor
    /// (`Resend`/`Ses`/`SendGrid`/`Smtp`).  Backed by
    /// `ipe_runtime::email::EmailProvider`; lowered to `IrType::EmailProvider`.
    pub email_provider: Symbol,
    // ── Ipe.Crypto typed-key newtypes ──────────────────────────────────────
    /// `"Key"` — opaque role-typed crypto key (`ipe_runtime::crypto::Key`).
    /// The ONLY constructor is `Key.fromString`/`Key.fromBytes`; no implicit
    /// `String` coercion. Lowered to `IrType::CryptoKey`.
    pub crypto_key: Symbol,
    /// `"Mac"` — opaque role-typed MAC output (`ipe_runtime::crypto::Mac`).
    /// Produced by `hmacSha256WithKey`/`hmacSha512WithKey` or parsed by
    /// `Mac.fromHex`; extracted via `Mac.toHex`.  Lowered to `IrType::CryptoMac`.
    pub crypto_mac: Symbol,
    // ── Ipe.Email.EmailAddress ──────────────────────────────────────────────
    /// `"EmailAddress"` — opaque validated email address
    /// (`ipe_runtime::email::EmailAddress`).  The ONLY constructor is
    /// `EmailAddress.parse : String -> Maybe EmailAddress`; extracted via
    /// `EmailAddress.toString`.  Lowered to `IrType::EmailAddress`.
    pub email_address: Symbol,
    // ── Ipe.Auth.Principal ────────────────────────────────────────────────────
    /// `"Principal"` — the opaque authenticated subject (`ipe_runtime::
    /// principal::Principal`). NO Ipê constructor: a value only ever comes from
    /// the server auth middleware's mint. Read via `Ipe.Auth.subject :
    /// Principal -> String`. Zero type arguments. Lowered to `IrType::Principal`.
    pub principal: Symbol,
    // ── Ipe.Url ─────────────────────────────────────────────────────────────
    /// `"Url"` — `Ipe.Url`'s opaque validated URL type (`ipe_runtime::url::Url`).
    /// The ONLY constructor is `Url.fromString : String -> Result Error Url`;
    /// extracted via `Url.toString`. Zero type arguments. Lowered to
    /// `IrType::Url`.
    pub url: Symbol,
    /// `"Relative"` — `Ipe.Url`'s opaque validated same-origin relative
    /// reference (`ipe_runtime::url::UrlRelative`). The ONLY constructor is
    /// `Url.relative : String -> Result Error Relative`; zero type arguments.
    /// Lowered to `IrType::UrlRelative`.
    pub url_relative: Symbol,
    // ── Ipe.Db.Dsn ──────────────────────────────────────────────────────────
    /// `"Dsn"` — `Ipe.Db.Dsn`'s opaque validated connection descriptor
    /// (`ipe_runtime::dsn::Dsn`). Constructed only by `Db.Dsn.parse` /
    /// `Db.Dsn.build`; zero type arguments. Lowered to `IrType::Dsn`.
    pub dsn: Symbol,
    /// `"DbLocation"` — `Ipe.Db.Location`'s opaque typed database location
    /// (`ipe_runtime::db::DbLocation`); zero type arguments. Lowered to
    /// `IrType::DbLocation`.
    pub db_location: Symbol,
    // ── Ipe.Db external Connection ──────────────────────────────────────────
    /// `"Connection"` — the external-DB connection handle constructor
    /// `Connection mode` (`ipe_runtime::external_conn::ExternalConnection`).
    /// Minted only by `Db.Dsn.open`. The phantom
    /// `mode` distinguishes `ReadOnly` from `ReadWrite` at inference and is
    /// erased at emit. Lowered to `IrType::Connection`.
    pub connection: Symbol,
    /// `"ReadOnly"` — the phantom read-only access-mode marker. Appears only as
    /// `Connection`'s argument; never a standalone value. Lowered to
    /// `IrType::ConnReadOnly`.
    pub conn_read_only: Symbol,
    /// `"ReadWrite"` — the phantom mutable access-mode marker. Appears only as
    /// `Connection`'s argument; never a standalone value. Lowered to
    /// `IrType::ConnReadWrite`.
    pub conn_read_write: Symbol,
    // ── Ipe.App runtime-config Setting ──────────────────────────────────────
    /// `"Setting"` — the runtime-config carrier constructor `Setting shape`
    /// (`ipe_runtime::app_config::Setting`). Built only by the setting kernels
    /// (`Host.bind` / `Log.level` / `Db.url` / `Web.csrf` / …). The phantom
    /// `shape` marker keeps a `Web`-only setting from unifying into a
    /// `Terminal` app's settings list; erased at emit. Lowered to
    /// `IrType::Setting`.
    pub setting: Symbol,
    /// `"Web"` — the phantom shape marker pinning a setting to the web shape.
    /// Appears only as `Setting`'s argument; never a standalone value. Lowered
    /// to `IrType::ShapeWeb`.
    pub shape_web: Symbol,
    /// `"WebView"` — the phantom shape marker pinning a setting to the webview
    /// shape. Appears only as `Setting`'s argument. Lowered to
    /// `IrType::ShapeWebView`.
    pub shape_webview: Symbol,
    /// `"Terminal"` — the phantom shape marker pinning a setting to the terminal
    /// shape. Appears only as `Setting`'s argument. Lowered to
    /// `IrType::ShapeTerminal`.
    pub shape_terminal: Symbol,
    /// `"Program"` — the shape-carrier constructor `Program shape msg`, the
    /// uniform result of every TEA entry (`Web.tea`/`Tui.tea`/`Cli.tea`). Arity 2;
    /// the phantom `shape` tag and `msg` both erase at lower, so a `Program`
    /// lowers to the shape's existing app leaf (`WebApp`/`TuiApp`/`CliApp`).
    pub program: Symbol,
    /// `"Web"` — the phantom program-shape tag for the web shape. Appears only as
    /// `Program`'s first argument; erased at lower. Shares the interned name `Web`
    /// with [`Self::shape_web`] but is a distinct carrier tag.
    pub program_shape_web: Symbol,
    /// `"Tui"` — the phantom program-shape tag for the terminal-cells shape.
    /// Appears only as `Program`'s first argument; erased at lower.
    pub program_shape_tui: Symbol,
    /// `"Cli"` — the phantom program-shape tag for the terminal-lines shape.
    /// Appears only as `Program`'s first argument; erased at lower.
    pub program_shape_cli: Symbol,
    /// `"Worker"` — the phantom program-shape tag for the view-less co-located
    /// worker shape. Appears only as `Program`'s first argument; erased at lower.
    pub program_shape_worker: Symbol,
    /// `"HostMode"` — the closed host-bind ADT, the argument type of
    /// `Host.bind`. Built only by its constructor kernels; each projects to the
    /// raw `Int` host-bind tag at emit, so `HostMode` erases to `Int`.
    pub host_mode: Symbol,
    /// `"LogLevel"` — the closed log-severity ADT, the argument type of
    /// `Log.level`. Built only by its constructor kernels; erases to `Int`.
    pub log_level: Symbol,
    /// `"CsrfMode"` — the closed CSRF-policy ADT, the argument type of
    /// `Web.csrf`. Built only by its constructor kernels; carries no disabling
    /// variant, and erases to `Int`.
    pub csrf_mode: Symbol,
    /// `"RevocationMode"` — the closed revocation-gate ADT (`Off` / `Store`),
    /// the argument type of `Web.withRevocation` / `Server.withRevocation`.
    /// Stricter-only monotonic; erases to `Int`.
    pub revocation_mode: Symbol,
    // ── Ipe.Locale ─────────────────────────────────────────────────────────
    /// `"Locale"` — opaque BCP-47 locale handle (`ipe_runtime::locale::Locale`).
    /// The ONLY constructor is `Locale.fromTag : String -> Maybe Locale`;
    /// extracted via `Locale.toTag : Locale -> String`.  Lowered to
    /// `IrType::Locale`.
    pub locale: Symbol,
    // ── Ipe.PubSub.Topic ───────────────────────────────────────────────────
    /// `"Topic"` — the phantom topic-handle type constructor `Topic a`.
    /// Erases to `String` at runtime (`ir_type_from_ty` maps `Topic a → Str`).
    /// Used only in kernel type schemes (`CmdPublish`/`SubSubscribeTopic`/
    /// `PubSubPublish`/`PubSubPublishNoEcho`/`PubSubTopic`) to share the
    /// payload type variable `a` between publisher and subscriber.
    pub topic_con: Symbol,
    // ── Ipe.Db.Store.Cond ──────────────────────────────────────────────────
    /// `"Cond"` — the typed `WHERE`-predicate ADT built by the accessor-typed
    /// query leaves. Used as the result type of the `StoreEqCol` kernel scheme;
    /// its constructors (`Compare` / …) lower normally as an emitted enum.
    pub cond_con: Symbol,
    /// `"Pred"` — the `Ipe.Db.Store.Pred row` row-security predicate algebra ADT.
    /// The `row` argument is phantom (the runtime `Pred` carries only data). It is
    /// the result of the `StoreCorrelate` kernel scheme and the lambda result the
    /// `StoreExistsIn` kernel scheme requires, so a correlated-subquery predicate's
    /// share and outer row types stay pinned to their stores.
    pub pred_con: Symbol,
    /// `"Secured"` — the `Ipe.Db.Store.Secured row` classified, policy-attached
    /// table ADT. The first argument of the `StoreExistsIn` kernel scheme: the
    /// referenced share store whose own read policy composes into the `EXISTS`
    /// subquery. Its `row` argument ties the share store's row type to the
    /// correlation the `existsIn` lambda names.
    pub secured_con: Symbol,
    /// `"Codec"` — the `Ipe.Codec` codec ADT. Used as the first parameter of the
    /// `StoreEqBy` kernel scheme (`Codec t -> …`), so an enum/newtype column's
    /// comparison value is projected to a bound `SqlValue` through its own codec.
    pub codec_con: Symbol,
    /// `"Remote"` — the `Ipe.Remote.Remote req resp` server-endpoint ADT, homed
    /// via [`Self::remote_home`].
    pub remote_con: Symbol,
    /// `"RemoteAuth"` — the `Ipe.Remote.RemoteAuth` session signing key ADT,
    /// homed via [`Self::remote_home`].
    pub remote_auth_con: Symbol,
    /// `"Step"` — the `Ipe.Task.Step` loop-step ADT (`Continue s | Done a`).
    /// Consumed by the `Task.loop` kernel scheme; homed via
    /// [`Self::task_home`] so the scheme's `Step` is the compiled-module enum.
    pub task_step: Symbol,
    /// `"Store"` — the `Ipe.Db.Store.Store a` ADT, the classified, queryable
    /// table. Reads and writes accept a `Store a`; it is reachable only via
    /// `public` / `secured` applied to a `Draft a` (deny-by-default).
    pub store_con: Symbol,
    /// `"Draft"` — the `Ipe.Db.Store.Draft a` ADT, the unclassified table
    /// `fromCodec` returns. Used as the parameter and result of the accessor-typed
    /// schema-shaping builder kernel schemes (`StorePrimaryKey` / `StoreSerial` /
    /// … / `StoreDefaultInt`): they refine a `Draft`, before classification. No
    /// read or write kernel accepts a `Draft`, so an unclassified table is
    /// unqueryable by construction.
    pub draft_con: Symbol,
    /// `"Joined"` — the `Ipe.Db.Store.Joined a b` two-store inner-join ADT, the
    /// result of the `StoreJoin` kernel scheme
    /// (`Store a -> (a -> k) -> Store b -> (b -> k) -> Joined a b`). It carries
    /// both stores' row types so `toList` decodes each side through its own
    /// codec.
    pub joined_con: Symbol,
    /// `"Select"` — the `Ipe.Db.Store.Select row` column-projection ADT, the
    /// result of the `StoreSelect` kernel scheme
    /// (`(( Cols a, Cols b ) -> row) -> Joined a b -> Select row`). Its `row`
    /// argument is the projected shape the lambda returns.
    pub select_con: Symbol,
    /// `"Policy"` — the `Ipe.Db.Store.Policy row` operation-scoped row-security
    /// ADT. The `row` argument is phantom (the runtime `Policy` carries per-
    /// operation `Pred` data and validated column names, no `row` value), but it
    /// ties the accessor's record type to the store's row type in the
    /// `StoreOwnerColumn` / `StoreImmutable` kernel schemes, so `secured`
    /// (`Policy row -> Store row -> …`) pins the policy's columns to the store.
    pub policy_con: Symbol,
    /// `"Order"` — the `Ipe.Db.Store.Order` nullary ADT (`Asc | Desc`), the
    /// sort-direction argument of `orderByLeft` / `orderByRight`. It has no
    /// type parameters; the scheme just names the ADT so inference pins the
    /// second argument of each kernel to `Order`.
    pub order_con: Symbol,
    // ── Ipe.Db.Store.ProjectionTerm / ProjectionOperand ─────────────────────────
    /// `"ProjectionTerm"` — typed representation of a single named-select
    /// projection, backing `selectNamed`. Defined in `ipe_runtime::db` and
    /// exported via a type alias from the Spine. Zero type arguments.
    pub projection_term: Symbol,
    /// `"ColumnTerm"` — `ColumnTerm String String` constructor of `ProjectionTerm`
    /// (left-table column, right-table column).
    pub column_term: Symbol,
    /// `"LiteralTerm"` — `LiteralTerm` nullary constructor of `ProjectionTerm`
    /// (a `?` literal placeholder).
    pub literal_term: Symbol,
    /// `"UpperTerm"` — `UpperTerm String` constructor of `ProjectionTerm`
    /// (upper-cased column reference).
    pub upper_term: Symbol,
    /// `"LowerTerm"` — `LowerTerm String` constructor of `ProjectionTerm`
    /// (lower-cased column reference).
    pub lower_term: Symbol,
    /// `"CoalesceTerm"` — `CoalesceTerm ProjectionOperand ProjectionOperand`
    /// constructor of `ProjectionTerm` (SQL COALESCE of two operands).
    pub coalesce_term: Symbol,
    /// `"ProjectionOperand"` — companion type for the two operands of `CoalesceTerm`.
    /// Defined in `ipe_runtime::db` alongside `ProjectionTerm`.
    pub projection_operand: Symbol,
    /// `"OperandColumn"` — `OperandColumn String` constructor of `ProjectionOperand`
    /// (a dotted column reference).
    pub operand_column: Symbol,
    /// `"OperandLiteral"` — `OperandLiteral` nullary constructor of `ProjectionOperand`
    /// (a `?` literal placeholder).
    pub operand_literal: Symbol,
    /// `"ArithTerm"` — `ArithTerm ArithOp ProjectionOperand ProjectionOperand`
    /// constructor of `ProjectionTerm` (SQL arithmetic over two operands).
    pub arith_term: Symbol,
    /// `"ArithOp"` — the closed operator tag of `ArithTerm`. Zero type arguments.
    pub arith_op: Symbol,
    /// `"ArithAdd"` — nullary `ArithOp` constructor (SQL `+`).
    pub arith_add: Symbol,
    /// `"ArithSub"` — nullary `ArithOp` constructor (SQL `-`).
    pub arith_sub: Symbol,
    /// `"ArithMul"` — nullary `ArithOp` constructor (SQL `*`).
    pub arith_mul: Symbol,
    // ── Shape opaque app-leaf type constructor symbols ────────────────────────
    /// `"WebApp"` — opaque app handle returned by `Web.tea` / `Web.appRouted` /
    /// `Web.appWith`. Nullary; backed by `ipe_runtime::tea::WebApp`.
    pub web_app: Symbol,
    /// `"TuiApp"` — opaque app handle returned by `Tui.tea`. Nullary;
    /// backed by `ipe_runtime::tea::TuiApp`.
    pub tui_app: Symbol,
    /// `"CliApp"` — opaque app handle returned by `Cli.tea`. Nullary;
    /// backed by `ipe_runtime::tea::CliApp`.
    pub cli_app: Symbol,
    /// The interned module segments `["Ipe", "Db", "Store"]` — the real home of
    /// the `Cond` / `Store` / `Draft` / `Joined` / `Select` / `Policy` / `Order`
    /// ADTs. A kernel scheme returning one of these carries this home so the
    /// lowerer's home-keyed variant lookup finds its emitted enum instead of
    /// treating an unhomed name as an unknown builtin.
    pub db_store_home: Vec<Symbol>,
    /// The interned module segments `["Ipe", "Codec"]` — the real home of the
    /// `Codec` ADT.
    pub codec_home: Vec<Symbol>,
    /// The interned module segments `["Ipe", "Email"]` — the real home of the
    /// `EmailProvider` ADT. The `send` kernel scheme carries this home so a
    /// point-free reference lowers to the emitted enum instead of dropping
    /// through the lowerer's home-keyed variant lookup into the unknown-builtin
    /// internal-compiler-error arm.
    pub email_home: Vec<Symbol>,
    /// The interned module segments `["Ipe", "Duration"]` — the real home of the
    /// `Duration` ADT. The `Http.withTimeout` kernel scheme carries this home so a
    /// point-free reference lowers to the compiled-module enum instead of dropping
    /// through the lowerer's home-keyed variant lookup into the unknown-builtin
    /// internal-compiler-error arm (mirrors [`Self::email_home`]).
    pub duration_home: Vec<Symbol>,
    /// The interned module segments `["Ipe", "Task"]` — the real home of the
    /// `Step` ADT. The `Task.loop` kernel scheme carries this home so its `Step`
    /// is the same nominal type `Ipe.Task` declares, and a point-free reference
    /// lowers to that emitted enum (mirrors [`Self::duration_home`]).
    pub task_home: Vec<Symbol>,
    /// The interned module segments `["Ipe", "Remote"]` — the real home of the
    /// `Remote` and `RemoteAuth` ADTs, so a type naming either is the type
    /// `Ipe.Remote` declares (mirrors [`Self::duration_home`]).
    pub remote_home: Vec<Symbol>,
    /// Each module scheme home a [`BuiltinTag::scheme_home`] names, keyed by its
    /// dotted path, as interned segments.
    pub scheme_homes: std::collections::BTreeMap<&'static str, Vec<Symbol>>,
}

/// Intern the segments of every module scheme home a builtin tag names.
///
/// # Errors
///
/// Fails when the interner refuses a segment.
fn scheme_homes(
    interner: &mut Interner,
) -> DResult<std::collections::BTreeMap<&'static str, Vec<Symbol>>> {
    let mut homes = std::collections::BTreeMap::new();
    for row in ipe_kernels::BUILTIN_TYPES {
        let Some(tag) = row.tag() else { continue };
        let ipe_kernels::KernelHome::Module(path) = tag.scheme_home() else {
            continue;
        };
        if homes.contains_key(path) {
            continue;
        }
        let mut segments = Vec::new();
        for segment in path.split('.') {
            segments.push(interner.intern(segment)?);
        }
        homes.insert(path, segments);
    }
    Ok(homes)
}

impl Builtins {
    /// Interns every built-in name into `interner`; re-interning is idempotent.
    ///
    /// # Errors
    ///
    /// Fails when the interner refuses a name (its symbol space is exhausted).
    #[allow(clippy::too_many_lines)] // declarative intern table — each field listed explicitly for exhaustiveness
    pub fn new(interner: &mut Interner) -> DResult<Self> {
        Ok(Self {
            int: interner.intern("Int")?,
            float: interner.intern("Float")?,
            bool: interner.intern("Bool")?,
            string: interner.intern("String")?,
            char: interner.intern("Char")?,
            task: interner.intern("Task")?,
            maybe: interner.intern("Maybe")?,
            result: interner.intern("Result")?,
            list: interner.intern("List")?,
            dict: interner.intern("Dict")?,
            set: interner.intern("Set")?,
            bytes: interner.intern("Bytes")?,
            just: interner.intern("Just")?,
            nothing: interner.intern("Nothing")?,
            ok: interner.intern("Ok")?,
            err: interner.intern("Err")?,
            true_: interner.intern("True")?,
            false_: interner.intern("False")?,
            error: interner.intern("Error")?,
            errorkind: interner.intern("ErrorKind")?,
            errordetails: interner.intern("ErrorDetails")?,
            backoffstrategy: interner.intern("BackoffStrategy")?,
            ed_ffi_panic: interner.intern("FfiPanic")?,
            ed_type_mismatch: interner.intern("TypeMismatch")?,
            ed_http_status: interner.intern("HttpStatus")?,
            ed_json_decode: interner.intern("JsonDecode")?,
            ed_custom: interner.intern("Custom")?,
            ed_database: interner.intern("Database")?,
            db_failure: interner.intern("DbFailure")?,
            auth_error: interner.intern("AuthError")?,
            panicinfo: interner.intern("PanicInfo")?,
            typeinfo: interner.intern("TypeInfo")?,
            errorinfo: interner.intern("ErrorInfo")?,
            tv_a: interner.intern("a")?,
            tv_e: interner.intern("e")?,
            fields: FieldSymbols::new(interner)?,
            // Http type symbols.
            http_method: interner.intern("HttpMethod")?,
            redirect_policy: interner.intern("RedirectPolicy")?,
            duration: interner.intern("Duration")?,
            no_redirects: interner.intern("NoRedirects")?,
            follow_redirects: interner.intern("FollowRedirects")?,
            // Db symbols.
            db: interner.intern("Db")?,
            sqlvalue: interner.intern("SqlValue")?,
            sqlfield: interner.intern("SqlField")?,
            sqlfragment: interner.intern("SqlFragment")?,
            secret: interner.intern("Secret")?,
            path: interner.intern("Path")?,
            regex: interner.intern("Regex")?,
            sql_string: interner.intern("SqlString")?,
            sql_int: interner.intern("SqlInt")?,
            sql_float: interner.intern("SqlFloat")?,
            sql_bool: interner.intern("SqlBool")?,
            sql_bytes: interner.intern("SqlBytes")?,
            sql_time: interner.intern("SqlTime")?,
            sql_decimal: interner.intern("SqlDecimal")?,
            sql_money: interner.intern("SqlMoney")?,
            sql_null: interner.intern("SqlNull")?,
            set_field: interner.intern("SetField")?,
            omit_field: interner.intern("OmitField")?,
            decoder: interner.intern("Decoder")?,
            // TEA Cmd / Sub type constructors.
            cmd: interner.intern("Cmd")?,
            sub: interner.intern("Sub")?,
            // Ipe.Http.Server opaque types.
            server_request: interner.intern("Request")?,
            server_response: interner.intern("Response")?,
            server_route: interner.intern("Route")?,
            server_cookie: interner.intern("Cookie")?,
            auth_config: interner.intern("AuthConfig")?,
            token_source: interner.intern("TokenSource")?,
            handler: interner.intern("Handler")?,
            // Ipe.Http.Server.Stream opaque handle.
            stream_writer: interner.intern("StreamWriter")?,
            // Ipe.Http.Server.WebSocket opaque handles.
            ws_server: interner.intern("WebSocketServer")?,
            ws_server_cfg: interner.intern("WebSocketServerCfg")?,
            // Ipe.Ui / Ipe.Html parametric type constructor symbols.
            attribute: interner.intern("Attribute")?,
            view: interner.intern("View")?,
            element: interner.intern("Element")?,
            cells: interner.intern("Screen")?,
            tui_attr: interner.intern("TuiAttr")?,
            cli_lines: interner.intern("Lines")?,
            cli_attr: interner.intern("CliAttr")?,
            color_error: interner.intern("ColorError")?,
            term_profile: interner.intern("TermProfile")?,
            ansi_color: interner.intern("AnsiColor")?,
            wcag_level: interner.intern("WcagLevel")?,
            text_size: interner.intern("TextSize")?,
            deficiency: interner.intern("Deficiency")?,
            custom_element: interner.intern("CustomElement")?,
            html_con: interner.intern("Html")?,
            length: interner.intern("Length")?,
            color: interner.intern("Color")?,
            description: interner.intern("Description")?,
            pseudo_class: interner.intern("PseudoClass")?,
            json_value: interner.intern("Value")?,
            // Ipe.Web opaque types.
            web_req: interner.intern("WebReq")?,
            session_handle: interner.intern("SessionHandle")?,
            live_route_con: interner.intern("WebRoute")?,
            // Ipe.Ui.Input type constructors.
            input_label_con: interner.intern("Label")?,
            input_placeholder_con: interner.intern("Placeholder")?,
            input_radio_option_con: interner.intern("RadioOption")?,
            // Ipe.Http.Stream: StreamId opaque handle type.
            stream_id: interner.intern("StreamId")?,
            // ── Ipe.Email type symbols ───────────────────
            email_provider: interner.intern("EmailProvider")?,
            // ── Order ADT ─────────────────────────────────────────────
            order: interner.intern("Order")?,
            lt: interner.intern("LT")?,
            eq: interner.intern("EQ")?,
            gt: interner.intern("GT")?,
            // ── JWT builder opaque type constructor symbols (D-00) ──────────────
            jwt_claims: interner.intern("Claims")?,
            jwt_algorithm: interner.intern("Algorithm")?,
            // ── Ipe.Decimal opaque type constructor ──────────────────────────────
            decimal: interner.intern("Decimal")?,
            // ── Ipe.Crypto typed-key newtypes ────────────────────────────────────
            crypto_key: interner.intern("Key")?,
            crypto_mac: interner.intern("Mac")?,
            // ── Ipe.Email.EmailAddress ────────────────────────────────────────────
            email_address: interner.intern("EmailAddress")?,
            // ── Ipe.Auth.Principal ────────────────────────────────────────────────
            principal: interner.intern("Principal")?,
            // ── Ipe.Url ───────────────────────────────────────────────────────────
            url: interner.intern("Url")?,
            url_relative: interner.intern("Relative")?,
            // ── Ipe.Db.Dsn ────────────────────────────────────────────────────────
            dsn: interner.intern("Dsn")?,
            db_location: interner.intern("DbLocation")?,
            connection: interner.intern("Connection")?,
            conn_read_only: interner.intern("ReadOnly")?,
            conn_read_write: interner.intern("ReadWrite")?,
            setting: interner.intern("Setting")?,
            shape_web: interner.intern("Web")?,
            shape_webview: interner.intern("WebView")?,
            shape_terminal: interner.intern("Terminal")?,
            program: interner.intern("Program")?,
            program_shape_web: interner.intern("Web")?,
            program_shape_tui: interner.intern("Tui")?,
            program_shape_cli: interner.intern("Cli")?,
            program_shape_worker: interner.intern("Worker")?,
            host_mode: interner.intern("HostMode")?,
            log_level: interner.intern("LogLevel")?,
            csrf_mode: interner.intern("CsrfMode")?,
            revocation_mode: interner.intern("RevocationMode")?,
            // ── Ipe.Locale ───────────────────────────────────────────────────────
            locale: interner.intern("Locale")?,
            // ── Ipe.PubSub.Topic ────────────────────────────────────────────────
            topic_con: interner.intern("Topic")?,
            cond_con: interner.intern("Cond")?,
            pred_con: interner.intern("Pred")?,
            secured_con: interner.intern("Secured")?,
            store_con: interner.intern("Store")?,
            draft_con: interner.intern("Draft")?,
            joined_con: interner.intern("Joined")?,
            select_con: interner.intern("Select")?,
            policy_con: interner.intern("Policy")?,
            order_con: interner.intern("Order")?,
            codec_con: interner.intern("Codec")?,
            remote_con: interner.intern("Remote")?,
            remote_auth_con: interner.intern("RemoteAuth")?,
            task_step: interner.intern("Step")?,
            // ── ProjectionTerm / ProjectionOperand ──────────────────────────────
            projection_term: interner.intern("ProjectionTerm")?,
            column_term: interner.intern("ColumnTerm")?,
            literal_term: interner.intern("LiteralTerm")?,
            upper_term: interner.intern("UpperTerm")?,
            lower_term: interner.intern("LowerTerm")?,
            coalesce_term: interner.intern("CoalesceTerm")?,
            projection_operand: interner.intern("ProjectionOperand")?,
            operand_column: interner.intern("OperandColumn")?,
            operand_literal: interner.intern("OperandLiteral")?,
            arith_term: interner.intern("ArithTerm")?,
            arith_op: interner.intern("ArithOp")?,
            arith_add: interner.intern("ArithAdd")?,
            arith_sub: interner.intern("ArithSub")?,
            arith_mul: interner.intern("ArithMul")?,
            // ── Shape opaque app-leaf type constructor symbols ─────────────
            web_app: interner.intern("WebApp")?,
            tui_app: interner.intern("TuiApp")?,
            cli_app: interner.intern("CliApp")?,
            db_store_home: vec![
                interner.intern("Ipe")?,
                interner.intern("Db")?,
                interner.intern("Store")?,
            ],
            codec_home: vec![interner.intern("Ipe")?, interner.intern("Codec")?],
            email_home: vec![interner.intern("Ipe")?, interner.intern("Email")?],
            duration_home: vec![interner.intern("Ipe")?, interner.intern("Duration")?],
            task_home: vec![interner.intern("Ipe")?, interner.intern("Task")?],
            remote_home: vec![interner.intern("Ipe")?, interner.intern("Remote")?],
            scheme_homes: scheme_homes(interner)?,
        })
    }

    /// The built-in constructor table, derived from canon's `BUILTIN_UNIONS`.
    ///
    /// Every constructor canon registers maps to exactly one entry: a scheme
    /// (constructible and matchable from source) or a sealed key (a runtime-only
    /// capability handle such as `StreamId`). A union or constructor this walk
    /// does not know, or a payload whose arity disagrees with canon's, is a
    /// `CompilerBug` — the table can never drift into an unconstrained miss.
    ///
    /// # Errors
    /// `CompilerBug` (`constrain.builtin_ctor_payload`) on a canon entry with no
    /// payload arm, an arity mismatch, or a tag whose symbol disagrees.
    pub fn ctor_schemes(&self, interner: &mut Interner) -> DResult<BuiltinCtors> {
        let mut schemes = Vec::new();
        let mut sealed = BTreeSet::new();
        for union in ipe_canon::builtins::BUILTIN_UNIONS {
            let (tag, params) = self.builtin_union_head(union.type_name)?;
            let type_sym = interner.intern(union.type_name)?;
            if let Some(t) = tag
                && self.builtin_symbol(t) != type_sym
            {
                return Err(payload_bug(union.type_name, "<tag symbol>"));
            }
            let module = tag.map_or_else(Vec::new, |t| self.builtin_con_module(t).to_vec());
            let result = Ty::Con {
                module,
                name: type_sym,
                args: params,
            };
            for (ctor, _index, arity) in union.ctors.iter().copied() {
                let ctor_sym = interner.intern(ctor)?;
                let key: CtorKey = (Vec::new(), type_sym, ctor_sym);
                match self.builtin_ctor_payload(union.type_name, ctor)? {
                    CtorPayload::Scheme(arg_tys) if arg_tys.len() == arity => {
                        schemes.push((
                            key,
                            CtorScheme {
                                arg_tys,
                                result: result.clone(),
                            },
                        ));
                    }
                    CtorPayload::Scheme(_) => return Err(payload_bug(union.type_name, ctor)),
                    CtorPayload::Sealed => {
                        sealed.insert(key);
                    }
                }
            }
        }
        Ok(BuiltinCtors { schemes, sealed })
    }

    /// The tag and result type parameters of the canon builtin union `type_name`.
    ///
    /// `ChunkEvent` and `ArithOp` have no [`BuiltinTag`]; their result `Con`
    /// carries the empty module every builtin `Con` without a tag carries.
    fn builtin_union_head(&self, type_name: &str) -> DResult<(Option<BuiltinTag>, Vec<Ty>)> {
        let a = Ty::Var(self.tv_a.as_raw());
        let e = Ty::Var(self.tv_e.as_raw());
        let tag = match type_name {
            "Maybe" => return Ok((Some(BuiltinTag::Maybe), vec![a])),
            "Result" => return Ok((Some(BuiltinTag::Result), vec![e, a])),
            "ChunkEvent" | "ArithOp" => return Ok((None, Vec::new())),
            "Bool" => BuiltinTag::Bool,
            "Order" => BuiltinTag::Order,
            "SqlValue" => BuiltinTag::SqlValue,
            "SqlField" => BuiltinTag::SqlField,
            "ProjectionTerm" => BuiltinTag::ProjectionTerm,
            "ProjectionOperand" => BuiltinTag::ProjectionOperand,
            "StreamId" => BuiltinTag::StreamId,
            "HttpMethod" => BuiltinTag::HttpMethod,
            "RedirectPolicy" => BuiltinTag::RedirectPolicy,
            "Error" => BuiltinTag::Error,
            "ErrorKind" => BuiltinTag::ErrorKind,
            "ErrorDetails" => BuiltinTag::ErrorDetails,
            "DbFailure" => BuiltinTag::DbFailure,
            "AuthError" => BuiltinTag::AuthError,
            _ => return Err(payload_bug(type_name, "<union>")),
        };
        Ok((Some(tag), Vec::new()))
    }

    /// The payload of canon builtin constructor `ctor` of union `type_name`.
    ///
    /// One arm per canon constructor; the final arm refuses an unknown pair so a
    /// constructor added to canon without a payload here breaks every build.
    fn builtin_ctor_payload(&self, type_name: &str, ctor: &str) -> DResult<CtorPayload> {
        let a = || Ty::Var(self.tv_a.as_raw());
        let e = || Ty::Var(self.tv_e.as_raw());
        let tagged = |tag: BuiltinTag| Ty::Con {
            module: self.builtin_con_module(tag).to_vec(),
            name: self.builtin_symbol(tag),
            args: Vec::new(),
        };
        let untagged = |name: Symbol| Ty::Con {
            module: Vec::new(),
            name,
            args: Vec::new(),
        };
        let string = || tagged(BuiltinTag::String);
        let int = || tagged(BuiltinTag::Int);
        let operand = || tagged(BuiltinTag::ProjectionOperand);
        let args = match (type_name, ctor) {
            ("Bool", "True" | "False")
            | ("Maybe", "Nothing")
            | ("Order", "LT" | "EQ" | "GT")
            | ("SqlField", "OmitField")
            | ("ProjectionTerm", "LiteralTerm")
            | ("ProjectionOperand", "OperandLiteral")
            | ("ArithOp", "ArithAdd" | "ArithSub" | "ArithMul")
            | ("ChunkEvent", "Done")
            | ("HttpMethod", "Get" | "Post" | "Put" | "Delete" | "Patch" | "Head" | "Options")
            | ("RedirectPolicy", "NoRedirects")
            | (
                "ErrorKind",
                "Io" | "Network" | "Ffi" | "Decode" | "Timeout" | "NotFound" | "PermissionDenied"
                | "InvalidInput" | "Conflict" | "Unavailable" | "Unexpected" | "LimitExceeded"
                | "UpdateRequired",
            )
            | (
                "DbFailure",
                "UniqueViolation"
                | "ForeignKeyViolation"
                | "NotNullViolation"
                | "CheckViolation"
                | "TriggerRaised"
                | "OtherConstraint"
                | "Busy"
                | "ReadOnlyDatabase"
                | "AccessDenied"
                | "CannotOpen"
                | "NotADatabase"
                | "InvalidStatement"
                | "Unreachable"
                | "OtherFailure",
            )
            | (
                "AuthError",
                "Malformed"
                | "BadSignature"
                | "Expired"
                | "NotYetValid"
                | "MissingClaim"
                | "Revoked"
                | "RevocationUnavailable"
                | "TooManyCredentials"
                | "SecretTooShort",
            ) => Vec::new(),
            ("Maybe", "Just") | ("Result", "Ok") => vec![a()],
            ("Result", "Err") => vec![e()],
            ("SqlValue", "SqlString" | "SqlMoney")
            | ("ProjectionTerm", "UpperTerm" | "LowerTerm")
            | ("ProjectionOperand", "OperandColumn")
            | ("ChunkEvent", "Chunk")
            | ("ErrorDetails", "JsonDecode" | "Custom") => vec![string()],
            ("SqlValue", "SqlInt" | "SqlTime")
            | ("RedirectPolicy", "FollowRedirects")
            | ("ErrorDetails", "HttpStatus") => vec![int()],
            ("SqlValue", "SqlFloat") => vec![tagged(BuiltinTag::Float)],
            ("SqlValue", "SqlBool") => vec![tagged(BuiltinTag::Bool)],
            ("SqlValue", "SqlBytes") => vec![tagged(BuiltinTag::Bytes)],
            ("SqlValue", "SqlDecimal") => vec![tagged(BuiltinTag::Decimal)],
            ("SqlValue", "SqlNull") | ("SqlField", "SetField") => {
                vec![tagged(BuiltinTag::SqlValue)]
            }
            ("ProjectionTerm", "ColumnTerm") => vec![string(), string()],
            ("ProjectionTerm", "CoalesceTerm") => vec![operand(), operand()],
            ("ProjectionTerm", "ArithTerm") => {
                vec![untagged(self.arith_op), operand(), operand()]
            }
            ("ChunkEvent", "Errored") => vec![tagged(BuiltinTag::Error)],
            // `PanicInfo` / `TypeInfo` / `ErrorInfo` are NOMINAL opaque Cons,
            // not structural records: a bare record literal fails to unify at
            // ipe time instead of lowering to a struct the runtime rejects.
            // Source builds them only through the `Error` smart constructors.
            ("Error", "Error") => vec![tagged(BuiltinTag::ErrorKind), untagged(self.errorinfo)],
            ("ErrorDetails", "FfiPanic") => vec![untagged(self.panicinfo)],
            ("ErrorDetails", "TypeMismatch") => vec![untagged(self.typeinfo)],
            ("ErrorDetails", "Database") => vec![tagged(BuiltinTag::DbFailure)],
            // A stream handle is minted only by the runtime; source never names it.
            ("StreamId", "StreamId") => return Ok(CtorPayload::Sealed),
            _ => return Err(payload_bug(type_name, ctor)),
        };
        Ok(CtorPayload::Scheme(args))
    }
}

/// How one canon builtin constructor enters the type checker.
pub enum CtorPayload {
    /// Constructible and matchable from source, with these payload types.
    Scheme(Vec<Ty>),
    /// A runtime-only capability handle: naming it from source is refused.
    Sealed,
}

/// The builtin constructor table derived from canon's `BUILTIN_UNIONS`.
pub struct BuiltinCtors {
    /// Source-visible constructors, keyed by canon's `(home, type, ctor)`.
    pub schemes: Vec<(CtorKey, CtorScheme)>,
    /// Capability-handle constructors source may never name.
    pub sealed: BTreeSet<CtorKey>,
}

/// The `CompilerBug` for a canon builtin entry this table cannot derive.
fn payload_bug(type_name: &str, ctor: &str) -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: "constrain.builtin_ctor_payload",
        detail: format!("canon builtin `{type_name}.{ctor}` has no matching constructor payload"),
    }
}

/// The type discipline a binary operator imposes. Classified once from the
/// resolved kernel name so the constraint walk doesn't re-borrow the interner.
#[derive(Clone, Copy)]
pub enum BinopClass {
    /// `//`: integer division `Int -> Int -> Int`.
    IntDiv,
    /// `/`: `Float -> Float -> Float` (matches the the backend's float division).
    FloatDiv,
    /// `+ - *`: `Number a => a -> a -> a`. The operands and the result share one
    /// numeric variable carrying the named obligation, so the operation stays
    /// generic over `Int` / `Float` until a concrete operand pins it.
    Num(TyBounds),
    /// `< > <= >=`: `Comparable a => a -> a -> Bool` — operands share one
    /// ordered type; the result is `Bool`.
    Order,
    /// `== /=`: `Equatable a => a -> a -> Bool` — operands share one equatable
    /// type (structural equality is total over every non-function type); the
    /// result is `Bool`. The shared variable carries the equality obligation, so
    /// a generalised use emits a Rust `PartialEq` bound.
    Equality,
    /// `&& ||`: `Bool -> Bool -> Bool`.
    Boolean,
    /// `++`: `String -> String -> String`. The general `Appendable` super-type
    /// (which would also cover `List a -> List a -> List a`) is a later batch;
    /// for now both operands and the result are pinned to `String`, so applying
    /// `++` to any other type (a would-be `List`) is a fail-closed type error
    /// rather than a mis-typed pass-through.
    Append,
    /// Any other operator (`::`, …): `a -> a -> a`. The numeric/ordering
    /// super-types do not cover list cons, so it stays a plain pass-through here
    /// and is gated at lowering rather than mis-typed.
    Poly,
}

/// Classify a resolved operator kernel name (`add`, `eq`, `and`, …).
pub const fn classify_binop(func: &str) -> BinopClass {
    match func.as_bytes() {
        b"add" => BinopClass::Num(TyBounds::add()),
        b"sub" => BinopClass::Num(TyBounds::sub()),
        b"mul" => BinopClass::Num(TyBounds::mul()),
        b"idiv" => BinopClass::IntDiv,
        b"fdiv" => BinopClass::FloatDiv,
        b"lt" | b"gt" | b"le" | b"ge" => BinopClass::Order,
        b"eq" | b"neq" => BinopClass::Equality,
        b"and" | b"or" => BinopClass::Boolean,
        b"append" => BinopClass::Append,
        _ => BinopClass::Poly,
    }
}
