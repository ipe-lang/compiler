//! Structural record-shape detectors: recognise the built-in
//! HTTP / email / process / CSV / cache / websocket record shapes (over both
//! solved `Ty` and canonical `Type`) so lowering can map them to their
//! dedicated runtime representations.

use ipe_canon::ast as canon;
use ipe_intern::Interner;
use ipe_types::Ty;

use super::ty_contains_var;

/// The expected TYPE shape of one field of the canonical `HttpRequest`
/// record — `String` / `Bool` / `Int` / `List (String, String)` (the
/// header-pair list). Ground truth mirrors
/// `ipe_types::constrain::Builder`'s `http_request()` closure
/// (`crates/ipe_types/src/constrain.rs` ~L3583) and its
/// `normalize_annotation_ty` twin (~L2264) — the ONLY two places in the
/// compiler that actually construct an `HttpRequest`'s field types.
#[derive(Clone, Copy)]
pub(super) enum HttpFieldTy {
    Str,
    Int,
    /// `List (String, String)`.
    StrPairList,
    /// `Dict String String`.
    StrStrDict,
    /// The `HttpMethod` ADT (`Get | Post | Put | Delete | Patch | Head | Options`).
    /// Matched as a zero-argument `Ty::Con` whose name resolves to `"HttpMethod"` —
    /// analogous to `Bool`/`Int` builtins, with no module path (empty `module`).
    HttpMethodAdt,
    /// The `RedirectPolicy` ADT (`NoRedirects | FollowRedirects Int`).
    /// Matched as a zero-argument `Ty::Con` whose name resolves to `"RedirectPolicy"` —
    /// same convention as `HttpMethodAdt`.
    RedirectPolicyAdt,
}

/// Does the NAME column of a `(name, type)` pair table equal the shared
/// name-only SSOT slice, element-for-element? A `const fn` so a name+type table
/// can bind its names to `ipe_ir::record_shapes` with a `const _: () =
/// assert!(pair_names_match(TABLE, X));` — a name drift then fails `cargo build`
/// (const-eval), un-skippable. Byte-for-byte `&str` equality is delegated to
/// [`ipe_ir::record_shapes::names_match`] on the extracted names; the walk uses
/// slice-pattern destructuring (`[head, tail @ ..]`), never `[_]` indexing, so
/// the `indexing_slicing` restriction holds.
const fn pair_names_match(pairs: &[(&str, HttpFieldTy)], names: &[&str]) -> bool {
    match (pairs, names) {
        ([], []) => true,
        ([(name, _), pairs_rest @ ..], [shared, names_rest @ ..]) => {
            // A one-element slice reuses the shared byte comparator so the
            // `&str`-equality logic lives in exactly one place (`ipe_ir`).
            ipe_ir::record_shapes::names_match(&[*name], &[*shared])
                && pair_names_match(pairs_rest, names_rest)
        }
        _ => false,
    }
}

/// The canonical `HttpRequest` record shape as `(field name, expected field
/// TYPE)` pairs, alphabetically sorted by name: `body`, `headers`, `method`,
/// `redirects`, `timeout`, `url`.
///
/// Shared by [`Lowerer::ir_type_from_ty`]'s structural fold (solved/inferred
/// `Ty::Record` regions — e.g. a `Http.defaultRequest |> withMethod |> …`
/// builder chain) AND [`Lowerer::ir_type_from_canon`]'s record arm
/// (user-written anonymous-record annotations — e.g.
/// `printReq : { body : String, ... } -> String`). Both paths MUST apply the
/// identical test so a genuinely `HttpRequest`-shaped value resolves to the
/// same `IrType::HttpRequest` / `ipe_runtime::HttpRequest` regardless of
/// which path its type reached emission through. Without the shared test a
/// value built via the former and consumed via the latter (or vice versa)
/// would diverge (IPE-I0001), one side folding to the opaque runtime type, the
/// other falling back to a backend-synthesised struct with a different name.
///
/// Checking field TYPES here (not just names) is
/// load-bearing: Ipê's row-polymorphic record types are purely structural —
/// the `HttpRequest` alias is expanded to a plain structural record at
/// annotation-normalisation time (`normalize_annotation_ty`), so NO nominal
/// alias identity survives into either `Ty` (post-solve) or `canon::Type`
/// (pre-solve annotation) for the lowerer to key off. A genuinely nominal
/// check is therefore not reachable at this layer without threading alias
/// identity through canonicalisation + solving — a much larger change that
/// no alias in this compiler currently receives. Field-TYPE-plus-NAME
/// matching is the strongest test achievable here: an unrelated record that
/// merely shares the 7 field NAMES with unrelated field TYPES (e.g. all-
/// `Int`) no longer folds to `IrType::HttpRequest` (the false-positive this
/// row exists to close), while a record that is structurally IDENTICAL to
/// `HttpRequest` (same names AND same types) still folds — arguably the
/// sound answer under a purely structural type system.
pub(super) const HTTP_REQUEST_FIELD_TYPES: &[(&str, HttpFieldTy)] = &[
    ("body", HttpFieldTy::Str),
    ("headers", HttpFieldTy::StrPairList),
    ("method", HttpFieldTy::HttpMethodAdt),
    ("redirects", HttpFieldTy::RedirectPolicyAdt),
    ("timeout", HttpFieldTy::Int),
    ("url", HttpFieldTy::Str),
];

// The NAME column of this local name+type table is bound to the shared SSOT so
// a rename in `ipe_ir::record_shapes` (or here) that drifts the two apart fails
// `cargo build` in this crate — the backend's name-only fallback keys off the
// same SSOT, so drift can no longer silently break THE SEAL.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if this table's NAME column drifts from the `ipe_ir` SSOT, the field-name SEAL invariant [ledger #boundary]
const _: () = assert!(pair_names_match(
    HTTP_REQUEST_FIELD_TYPES,
    ipe_ir::record_shapes::HTTP_REQUEST_FIELDS
));

/// The canonical `Ipe.Http.Server.Response` record shape as `(field name,
/// expected field TYPE)` pairs, alphabetically sorted by name: `body`,
/// `contentType`, `headers`, `status`. Matches the reference
/// `Ipê/Http/Server.ipe:66` record alias. A `Ty::Record` (or `canon::Type`)
/// of this exact shape folds to [`IrType::ServerResponse`] so a handler-built
/// record literal emits the runtime `ipe_runtime::ServerResponse` struct
/// (which the server kernels produce/consume) rather than a backend-synthesised
/// `Rec…` struct — the same anti-drift discipline as `HttpRequest`.
pub(super) const SERVER_RESPONSE_FIELD_TYPES: &[(&str, HttpFieldTy)] = &[
    ("body", HttpFieldTy::Str),
    ("contentType", HttpFieldTy::Str),
    ("headers", HttpFieldTy::StrStrDict),
    ("status", HttpFieldTy::Int),
];

// NAME column bound to the shared SSOT — see the note at HTTP_REQUEST_FIELD_TYPES.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if this table's NAME column drifts from the `ipe_ir` SSOT, the field-name SEAL invariant [ledger #boundary]
const _: () = assert!(pair_names_match(
    SERVER_RESPONSE_FIELD_TYPES,
    ipe_ir::record_shapes::SERVER_RESPONSE_FIELDS
));

/// Does `fields` match the canonical `Response` record shape — same NAMES *and*
/// TYPES as [`SERVER_RESPONSE_FIELD_TYPES`]? Sorts `fields` by name in place
/// (see [`is_http_request_shape`]).
pub(super) fn is_server_response_shape(fields: &mut [(&str, &Ty)], interner: &Interner) -> bool {
    if fields.len() != SERVER_RESPONSE_FIELD_TYPES.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    fields.iter().zip(SERVER_RESPONSE_FIELD_TYPES.iter()).all(
        |((name, ty), (expected_name, expected_ty))| {
            *name == *expected_name && ty_matches_http_field(ty, *expected_ty, interner)
        },
    )
}

/// The [`canon::Type`] twin of [`is_server_response_shape`].
pub(super) fn is_server_response_canon_shape(
    fields: &mut [(&str, &canon::Type)],
    interner: &Interner,
) -> bool {
    if fields.len() != SERVER_RESPONSE_FIELD_TYPES.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    fields.iter().zip(SERVER_RESPONSE_FIELD_TYPES.iter()).all(
        |((name, ty), (expected_name, expected_ty))| {
            *name == *expected_name && canon_ty_matches_http_field(ty, *expected_ty, interner)
        },
    )
}

/// Does this solved [`Ty`] match `expected` — one leaf of
/// [`HTTP_REQUEST_FIELD_TYPES`]? Built-in leaf types (`String` / `Bool` /
/// `Int` / `List`) are `Ty::Con` with an empty `module` (built-ins have no
/// user-defined home) — checked defensively alongside the name, though
/// IPE-N0026 (see `ipe_canon::resolve`) already forbids a user type from
/// shadowing these reserved names, so the module check can never fire in
/// practice.
pub(super) fn ty_matches_http_field(ty: &Ty, expected: HttpFieldTy, interner: &Interner) -> bool {
    match (expected, ty) {
        (HttpFieldTy::Str, Ty::Con { module, name, args }) => {
            module.is_empty() && args.is_empty() && interner.resolve(*name) == Some("String")
        }
        (HttpFieldTy::Int, Ty::Con { module, name, args }) => {
            module.is_empty() && args.is_empty() && interner.resolve(*name) == Some("Int")
        }
        (HttpFieldTy::StrPairList, Ty::Con { module, name, args }) => {
            module.is_empty()
                && interner.resolve(*name) == Some("List")
                && matches!(
                    args.as_slice(),
                    [Ty::Tuple(elems)] if matches!(
                        elems.as_slice(),
                        [a, b]
                            if ty_matches_http_field(a, HttpFieldTy::Str, interner)
                                && ty_matches_http_field(b, HttpFieldTy::Str, interner)
                    )
                )
        }
        (HttpFieldTy::StrStrDict, Ty::Con { module, name, args }) => {
            module.is_empty()
                && interner.resolve(*name) == Some("Dict")
                && matches!(
                    args.as_slice(),
                    [k, v]
                        if ty_matches_http_field(k, HttpFieldTy::Str, interner)
                            && ty_matches_http_field(v, HttpFieldTy::Str, interner)
                )
        }
        (HttpFieldTy::HttpMethodAdt, Ty::Con { module, name, args }) => {
            module.is_empty() && args.is_empty() && interner.resolve(*name) == Some("HttpMethod")
        }
        (HttpFieldTy::RedirectPolicyAdt, Ty::Con { module, name, args }) => {
            module.is_empty()
                && args.is_empty()
                && interner.resolve(*name) == Some("RedirectPolicy")
        }
        _ => false,
    }
}

/// The [`canon::Type`] twin of [`ty_matches_http_field`] — same test, applied
/// to a pre-solve user-written annotation rather than a post-solve `Ty`. Kept
/// as a structurally parallel (not shared/generic) function because
/// `canon::Type::Con`'s field is named `home` where `Ty::Con`'s is `module`;
/// unifying them behind a trait would obscure more than it would save for
/// two four-case matches.
pub(super) fn canon_ty_matches_http_field(
    ty: &canon::Type,
    expected: HttpFieldTy,
    interner: &Interner,
) -> bool {
    match (expected, ty) {
        (HttpFieldTy::Str, canon::Type::Con { home, name, args }) => {
            home.is_empty() && args.is_empty() && interner.resolve(*name) == Some("String")
        }
        (HttpFieldTy::Int, canon::Type::Con { home, name, args }) => {
            home.is_empty() && args.is_empty() && interner.resolve(*name) == Some("Int")
        }
        (HttpFieldTy::StrPairList, canon::Type::Con { home, name, args }) => {
            home.is_empty()
                && interner.resolve(*name) == Some("List")
                && matches!(
                    args.as_slice(),
                    [canon::Type::Tuple(elems)] if matches!(
                        elems.as_slice(),
                        [a, b]
                            if canon_ty_matches_http_field(a, HttpFieldTy::Str, interner)
                                && canon_ty_matches_http_field(b, HttpFieldTy::Str, interner)
                    )
                )
        }
        (HttpFieldTy::StrStrDict, canon::Type::Con { home, name, args }) => {
            home.is_empty()
                && interner.resolve(*name) == Some("Dict")
                && matches!(
                    args.as_slice(),
                    [k, v]
                        if canon_ty_matches_http_field(k, HttpFieldTy::Str, interner)
                            && canon_ty_matches_http_field(v, HttpFieldTy::Str, interner)
                )
        }
        (HttpFieldTy::HttpMethodAdt, canon::Type::Con { home, name, args }) => {
            home.is_empty() && args.is_empty() && interner.resolve(*name) == Some("HttpMethod")
        }
        (HttpFieldTy::RedirectPolicyAdt, canon::Type::Con { home, name, args }) => {
            home.is_empty() && args.is_empty() && interner.resolve(*name) == Some("RedirectPolicy")
        }
        _ => false,
    }
}

/// Does `fields` (collected as `(resolved name, &Ty)` pairs, one per record
/// field) match the canonical `HttpRequest` shape — same field NAMES *and*
/// same field TYPES as [`HTTP_REQUEST_FIELD_TYPES`]? Sorts `fields` by name
/// in place: the `BTreeMap<Symbol, _>` callers iterate over sorts by
/// Symbol-integer intern order, NOT alphabetical order, so the caller cannot
/// pre-sort before resolving names.
pub(super) fn is_http_request_shape(fields: &mut [(&str, &Ty)], interner: &Interner) -> bool {
    if fields.len() != HTTP_REQUEST_FIELD_TYPES.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    fields.iter().zip(HTTP_REQUEST_FIELD_TYPES.iter()).all(
        |((name, ty), (expected_name, expected_ty))| {
            *name == *expected_name && ty_matches_http_field(ty, *expected_ty, interner)
        },
    )
}

/// The [`canon::Type`] twin of [`is_http_request_shape`] — see that
/// function's doc comment.
pub(super) fn is_http_request_canon_shape(
    fields: &mut [(&str, &canon::Type)],
    interner: &Interner,
) -> bool {
    if fields.len() != HTTP_REQUEST_FIELD_TYPES.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    fields.iter().zip(HTTP_REQUEST_FIELD_TYPES.iter()).all(
        |((name, ty), (expected_name, expected_ty))| {
            *name == *expected_name && canon_ty_matches_http_field(ty, *expected_ty, interner)
        },
    )
}

/// the canonical `Ipe.Cache.CacheCfg` field-name set, alphabetically
/// sorted: `maxBytes`, `maxEntries`, `ttlMs` — all `Int`. Folded to the nominal
/// `IrType::CacheCfg` (`ipe_runtime::cache::CacheCfg`) so a `Cache.defaultCfg`
/// record literal constructs the runtime struct the `cache_new_raw` kernel
/// takes (same mechanism as the `HttpRequest` fold above). Re-exported from the
/// shared SSOT so lower and backend read one definition.
pub(super) use ipe_ir::record_shapes::CACHE_CFG_FIELDS;

/// The canonical `Ipe.WebSocket.WebSocketCfg` field NAMES *and* TYPES,
/// alphabetically sorted by name — `headers : List (String, String)`,
/// `pingInterval : Int`, `timeout : Int`, `url : String`. A record of exactly
/// this shape folds to the nominal `IrType::WebSocketClientCfg`
/// (`ipe_runtime::ws_client::WsClientCfg`) so a `WebSocket.defaultCfg`-built
/// record literal constructs the runtime struct the `web_socket_connect_with`
/// kernel takes (same mixed-type mechanism as the `HttpRequest` fold above,
/// reusing the shared [`HttpFieldTy`] leaf matcher).
pub(super) const WEBSOCKET_CFG_FIELD_TYPES: &[(&str, HttpFieldTy)] = &[
    ("headers", HttpFieldTy::StrPairList),
    ("pingInterval", HttpFieldTy::Int),
    ("timeout", HttpFieldTy::Int),
    ("url", HttpFieldTy::Str),
];

// NAME column bound to the shared SSOT — see the note at HTTP_REQUEST_FIELD_TYPES.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if this table's NAME column drifts from the `ipe_ir` SSOT, the field-name SEAL invariant [ledger #boundary]
const _: () = assert!(pair_names_match(
    WEBSOCKET_CFG_FIELD_TYPES,
    ipe_ir::record_shapes::WEBSOCKET_CFG_FIELDS
));

/// Does `fields` (as `(resolved name, &Ty)` pairs) match the canonical
/// `WebSocketCfg` shape — same field NAMES *and* TYPES as
/// [`WEBSOCKET_CFG_FIELD_TYPES`]? Sorts `fields` by name in place.
pub(super) fn is_websocket_cfg_shape(fields: &mut [(&str, &Ty)], interner: &Interner) -> bool {
    if fields.len() != WEBSOCKET_CFG_FIELD_TYPES.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    fields.iter().zip(WEBSOCKET_CFG_FIELD_TYPES.iter()).all(
        |((name, ty), (expected_name, expected_ty))| {
            *name == *expected_name && ty_matches_http_field(ty, *expected_ty, interner)
        },
    )
}

/// The [`canon::Type`] twin of [`is_websocket_cfg_shape`].
pub(super) fn is_websocket_cfg_canon_shape(
    fields: &mut [(&str, &canon::Type)],
    interner: &Interner,
) -> bool {
    if fields.len() != WEBSOCKET_CFG_FIELD_TYPES.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    fields.iter().zip(WEBSOCKET_CFG_FIELD_TYPES.iter()).all(
        |((name, ty), (expected_name, expected_ty))| {
            *name == *expected_name && canon_ty_matches_http_field(ty, *expected_ty, interner)
        },
    )
}

/// the canonical `Ipe.Cache.stats` return field-name set, alphabetically
/// sorted: `evictions`, `hits`, `misses` — all `Int`. Folded to the nominal
/// `IrType::CacheStats` (`ipe_runtime::cache::CacheStats`).
pub(super) const CACHE_STATS_FIELDS: &[&str] = &["evictions", "hits", "misses"];

/// Is `ty` the built-in `Int` — an empty-module, arg-less `Con` named `Int`?
/// Shared by the two all-`Int` Cache-record shape tests. `IPE-N0026` forbids a
/// user type shadowing `Int`, so the module check can never fire in practice
/// but is asserted defensively (mirrors [`ty_matches_http_field`]).
pub(super) fn ty_is_int(ty: &Ty, interner: &Interner) -> bool {
    matches!(ty, Ty::Con { module, name, args }
        if module.is_empty() && args.is_empty() && interner.resolve(*name) == Some("Int"))
}

/// Is `ty` the built-in `BackoffStrategy` — an empty-module, arg-less `Con`
/// named `BackoffStrategy`? Used by the `RetryPolicy` shape check for the
/// `strategy` field, or a free `Ty::Var` (solver left the field unsolved).
pub(super) fn is_backoff_strategy_ty(interner: &Interner, ty: &Ty) -> bool {
    if ty_contains_var(ty) {
        return true;
    }
    matches!(ty, Ty::Con { module, name, args }
        if module.is_empty() && args.is_empty()
            && interner.resolve(*name) == Some("BackoffStrategy"))
}

/// The [`canon::Type`] twin of [`ty_is_int`].
pub(super) fn canon_ty_is_int(ty: &canon::Type, interner: &Interner) -> bool {
    matches!(ty, canon::Type::Con { home, name, args }
        if home.is_empty() && args.is_empty() && interner.resolve(*name) == Some("Int"))
}

/// Does `fields` (as `(resolved name, &Ty)` pairs) match an all-`Int` record
/// whose sorted field NAMES equal `expected`? Sorts `fields` in place. Used for
/// both Cache record shapes — the field TYPES are checked (all `Int`) alongside
/// the NAMES so an unrelated 3-field record with different types does not fold.
pub(super) fn is_all_int_record_shape(
    fields: &mut [(&str, &Ty)],
    expected: &[&str],
    interner: &Interner,
) -> bool {
    if fields.len() != expected.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    fields
        .iter()
        .zip(expected.iter())
        .all(|((name, ty), expected_name)| *name == *expected_name && ty_is_int(ty, interner))
}

/// The [`canon::Type`] twin of [`is_all_int_record_shape`].
pub(super) fn is_all_int_canon_record_shape(
    fields: &mut [(&str, &canon::Type)],
    expected: &[&str],
    interner: &Interner,
) -> bool {
    if fields.len() != expected.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    fields
        .iter()
        .zip(expected.iter())
        .all(|((name, ty), expected_name)| *name == *expected_name && canon_ty_is_int(ty, interner))
}

/// The canonical `Ipe.Csv.Csv` record field-name set, alphabetically sorted:
/// `header`, `rows`. A record of exactly this shape (NAMES *and* the field
/// TYPES `header : List String`, `rows : List (List String)`) folds to the
/// nominal `IrType::CsvDoc` (`ipe_runtime::csv::CsvDoc`) so a record literal fed
/// to `Csv.encode` constructs the runtime struct the `csv_encode` kernel takes,
/// and a `csv_parse` result is field-accessed on that struct's pub fields (same
/// mechanism as the `HttpRequest` / `CacheCfg` folds above). The `ipe_types`
/// `csv_rec` type scheme mirrors this shape. Re-exported from the shared SSOT
/// so lower and backend read one definition.
pub(super) use ipe_ir::record_shapes::CSV_DOC_FIELDS;

/// Is `ty` the built-in `List String` — a `List` `Con` whose single arg is the
/// built-in `String`? The inner-element depth is selected by `list_depth`
/// (1 = `List String`, 2 = `List (List String)`).
pub(super) fn ty_is_list_of_string(ty: &Ty, list_depth: u8, interner: &Interner) -> bool {
    match ty {
        Ty::Con { module, name, args }
            if module.is_empty() && interner.resolve(*name) == Some("List") =>
        {
            match args.as_slice() {
                [inner] if list_depth > 1 => ty_is_list_of_string(inner, list_depth - 1, interner),
                [inner] => matches!(inner, Ty::Con { module: m, name: n, args: a }
                    if m.is_empty() && a.is_empty() && interner.resolve(*n) == Some("String")),
                _ => false,
            }
        }
        _ => false,
    }
}

/// The [`canon::Type`] twin of [`ty_is_list_of_string`].
pub(super) fn canon_ty_is_list_of_string(
    ty: &canon::Type,
    list_depth: u8,
    interner: &Interner,
) -> bool {
    match ty {
        canon::Type::Con { home, name, args }
            if home.is_empty() && interner.resolve(*name) == Some("List") =>
        {
            match args.as_slice() {
                [inner] if list_depth > 1 => {
                    canon_ty_is_list_of_string(inner, list_depth - 1, interner)
                }
                [inner] => matches!(inner, canon::Type::Con { home: h, name: n, args: a }
                    if h.is_empty() && a.is_empty() && interner.resolve(*n) == Some("String")),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Does `fields` match the canonical `Csv` shape — field NAMES `header`/`rows`
/// AND field TYPES `List String` / `List (List String)`? Sorts `fields` in
/// place (`BTreeMap` callers iterate in Symbol-intern order, not alphabetical).
/// The field TYPES are checked alongside the NAMES so an unrelated 2-field
/// `{ header, rows }` record with different types does not fold to `CsvDoc`.
pub(super) fn is_csv_doc_shape(fields: &mut [(&str, &Ty)], interner: &Interner) -> bool {
    if fields.len() != CSV_DOC_FIELDS.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    matches!(fields, [(h, hty), (r, rty)]
        if *h == "header" && *r == "rows"
            && ty_is_list_of_string(hty, 1, interner)
            && ty_is_list_of_string(rty, 2, interner))
}

/// The [`canon::Type`] twin of [`is_csv_doc_shape`].
pub(super) fn is_csv_doc_canon_shape(
    fields: &mut [(&str, &canon::Type)],
    interner: &Interner,
) -> bool {
    if fields.len() != CSV_DOC_FIELDS.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    matches!(fields, [(h, hty), (r, rty)]
        if *h == "header" && *r == "rows"
            && canon_ty_is_list_of_string(hty, 1, interner)
            && canon_ty_is_list_of_string(rty, 2, interner))
}

// ── #210 Ipe.Email record shapes ────────────────────────────────────────────
// The four `Ipe.Email` record shapes fold to their nominal runtime structs
// (`ipe_runtime::email::{EmailMessage, EmailAttachment, SesConfig, SmtpConfig}`)
// so a `defaultMessage`/`defaultAttachment`/… built record literal constructs
// the exact struct the `email_send` kernel + the `EmailProvider` variant fields
// take (mirror of the `CsvDoc` / `CacheCfg` folds). Each shape is matched on
// field NAMES *and* field TYPES so an unrelated same-arity record does not fold.

/// The four `Ipe.Email` field-name sets, re-exported from the shared SSOT so
/// lower and backend read one definition:
/// - `EMAIL_ATTACHMENT_FIELDS` — `{ content, filename, mimeType }` (`content :
///   Bytes`, `filename`/`mimeType : String`); folds to `IrType::EmailAttachment`.
/// - `EMAIL_SES_FIELDS` — `{ key, region, secret }` (`key`/`region : String`,
///   `secret : Secret`); folds to `IrType::EmailSesConfig`.
/// - `EMAIL_SMTP_FIELDS` — `{ host, pass, port, user }` (`port : Int`, `pass :
///   Secret`, `host`/`user : String`); folds to `IrType::EmailSmtpConfig`.
/// - `EMAIL_MESSAGE_FIELDS` — `{ attachments, bcc, cc, from, htmlBody, replyTo,
///   subject, textBody, to }`; folds to `IrType::EmailMessage`.
pub(super) use ipe_ir::record_shapes::{
    EMAIL_ATTACHMENT_FIELDS, EMAIL_MESSAGE_FIELDS, EMAIL_SES_FIELDS, EMAIL_SMTP_FIELDS,
};

/// Is `ty` the built-in `String`?
pub(super) fn ty_is_string(ty: &Ty, interner: &Interner) -> bool {
    matches!(ty, Ty::Con { module, name, args }
        if module.is_empty() && args.is_empty() && interner.resolve(*name) == Some("String"))
}

/// The [`canon::Type`] twin of [`ty_is_string`].
pub(super) fn canon_ty_is_string(ty: &canon::Type, interner: &Interner) -> bool {
    matches!(ty, canon::Type::Con { home, name, args }
        if home.is_empty() && args.is_empty() && interner.resolve(*name) == Some("String"))
}

/// Is `ty` the `Ipe.Bytes` primitive (`Vec<u8>` on Rust)?
///
/// `Bytes` is imported from `Ipe.Bytes` (non-empty module path), so this
/// predicate does NOT require an empty module — it matches any `Con` whose
/// name is `"Bytes"` with no type arguments.  This mirrors the lowerer's
/// `ir_type_from_ty` arm that maps `"Bytes" => IrType::Bytes` regardless of
/// module.
pub(super) fn ty_is_bytes(ty: &Ty, interner: &Interner) -> bool {
    matches!(ty, Ty::Con { name, args, .. }
        if args.is_empty() && interner.resolve(*name) == Some("Bytes"))
}

/// The [`canon::Type`] twin of [`ty_is_bytes`].
pub(super) fn canon_ty_is_bytes(ty: &canon::Type, interner: &Interner) -> bool {
    matches!(ty, canon::Type::Con { name, args, .. }
        if args.is_empty() && interner.resolve(*name) == Some("Bytes"))
}

/// Is `ty` the `Ipe.Secret` sealed secret type?  Matched by NAME only
/// (module-agnostic), mirroring `ir_type_from_ty`'s `"Secret" => IrType::Secret`
/// arm — the type is imported from `Ipe.Secret` (a non-empty module path), so
/// this predicate does not require an empty module.  Used by the `SesConfig` /
/// `SmtpConfig` folds, whose credential fields are `Secret`, not `String`.
pub(super) fn ty_is_secret(ty: &Ty, interner: &Interner) -> bool {
    matches!(ty, Ty::Con { name, args, .. }
        if args.is_empty() && interner.resolve(*name) == Some("Secret"))
}

/// The [`canon::Type`] twin of [`ty_is_secret`].
pub(super) fn canon_ty_is_secret(ty: &canon::Type, interner: &Interner) -> bool {
    matches!(ty, canon::Type::Con { name, args, .. }
        if args.is_empty() && interner.resolve(*name) == Some("Secret"))
}

/// Is `ty` the `Ipe.Email.EmailAddress` opaque type?  Matched by NAME only
/// (module-agnostic), mirroring `ir_type_from_ty`'s `"EmailAddress" => IrType::EmailAddress`.
pub(super) fn ty_is_email_address(ty: &Ty, interner: &Interner) -> bool {
    matches!(ty, Ty::Con { name, args, .. }
        if args.is_empty() && interner.resolve(*name) == Some("EmailAddress"))
}

/// The [`canon::Type`] twin of [`ty_is_email_address`].
pub(super) fn canon_ty_is_email_address(ty: &canon::Type, interner: &Interner) -> bool {
    matches!(ty, canon::Type::Con { name, args, .. }
        if args.is_empty() && interner.resolve(*name) == Some("EmailAddress"))
}

/// Is `ty` a `List EmailAddress`?
pub(super) fn ty_is_list_of_email_address(ty: &Ty, interner: &Interner) -> bool {
    matches!(ty, Ty::Con { name, args, .. }
        if interner.resolve(*name) == Some("List")
            && matches!(args.as_slice(), [inner] if ty_is_email_address(inner, interner)))
}

/// The [`canon::Type`] twin of [`ty_is_list_of_email_address`].
pub(super) fn canon_ty_is_list_of_email_address(ty: &canon::Type, interner: &Interner) -> bool {
    matches!(ty, canon::Type::Con { name, args, .. }
        if interner.resolve(*name) == Some("List")
            && matches!(args.as_slice(), [inner] if canon_ty_is_email_address(inner, interner)))
}

/// Does `fields` match the `SmtpConfig` shape — `{ host, pass, port, user }`
/// with `port : Int`, `pass : Secret` (sealed), and `host`/`user` `String`?
/// Sorts `fields` in place.
pub(super) fn is_email_smtp_shape(fields: &mut [(&str, &Ty)], interner: &Interner) -> bool {
    if fields.len() != EMAIL_SMTP_FIELDS.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    matches!(fields, [(host_n, host_ty), (pass_n, pass_ty), (port_n, port_ty), (user_n, user_ty)]
        if *host_n == "host" && *pass_n == "pass" && *port_n == "port" && *user_n == "user"
            && ty_is_string(host_ty, interner)
            && ty_is_secret(pass_ty, interner)
            && ty_is_int(port_ty, interner)
            && ty_is_string(user_ty, interner))
}

/// The [`canon::Type`] twin of [`is_email_smtp_shape`].
pub(super) fn is_email_smtp_canon_shape(
    fields: &mut [(&str, &canon::Type)],
    interner: &Interner,
) -> bool {
    if fields.len() != EMAIL_SMTP_FIELDS.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    matches!(fields, [(host_n, host_ty), (pass_n, pass_ty), (port_n, port_ty), (user_n, user_ty)]
        if *host_n == "host" && *pass_n == "pass" && *port_n == "port" && *user_n == "user"
            && canon_ty_is_string(host_ty, interner)
            && canon_ty_is_secret(pass_ty, interner)
            && canon_ty_is_int(port_ty, interner)
            && canon_ty_is_string(user_ty, interner))
}

/// Does `fields` match the `SesConfig` shape — `{ key, region, secret }` with
/// `key`/`region` `String` and `secret : Secret` (sealed)? Sorts `fields` in
/// place. Sorted order: key, region, secret.
pub(super) fn is_email_ses_shape(fields: &mut [(&str, &Ty)], interner: &Interner) -> bool {
    if fields.len() != EMAIL_SES_FIELDS.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    matches!(fields, [(key_n, key_ty), (region_n, region_ty), (secret_n, secret_ty)]
        if *key_n == "key" && *region_n == "region" && *secret_n == "secret"
            && ty_is_string(key_ty, interner)
            && ty_is_string(region_ty, interner)
            && ty_is_secret(secret_ty, interner))
}

/// The [`canon::Type`] twin of [`is_email_ses_shape`].
pub(super) fn is_email_ses_canon_shape(
    fields: &mut [(&str, &canon::Type)],
    interner: &Interner,
) -> bool {
    if fields.len() != EMAIL_SES_FIELDS.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    matches!(fields, [(key_n, key_ty), (region_n, region_ty), (secret_n, secret_ty)]
        if *key_n == "key" && *region_n == "region" && *secret_n == "secret"
            && canon_ty_is_string(key_ty, interner)
            && canon_ty_is_string(region_ty, interner)
            && canon_ty_is_secret(secret_ty, interner))
}

/// Does `fields` match the 9-field `EmailMessage` shape (NAMES + TYPES)? Sorts
/// `fields` in place. The `attachments` element is checked to be a `List` of a
/// record whose own shape is the `Attachment` shape (`{ content : Bytes,
/// filename : String, mimeType : String }`); `to`/`cc`/`bcc` are `List
/// EmailAddress`; `from`/`replyTo` are `EmailAddress`; `htmlBody`/`subject`/
/// `textBody` are `String`.
pub(super) fn is_email_message_shape(fields: &mut [(&str, &Ty)], interner: &Interner) -> bool {
    if fields.len() != EMAIL_MESSAGE_FIELDS.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    let names_match = fields
        .iter()
        .zip(EMAIL_MESSAGE_FIELDS.iter())
        .all(|((name, _), exp)| *name == *exp);
    if !names_match {
        return false;
    }
    fields.iter().all(|(name, ty)| match *name {
        "to" | "cc" | "bcc" => ty_is_list_of_email_address(ty, interner),
        "from" | "replyTo" => ty_is_email_address(ty, interner),
        "attachments" => ty_is_list_of_attachment(ty, interner),
        _ => ty_is_string(ty, interner),
    })
}

/// The [`canon::Type`] twin of [`is_email_message_shape`].
pub(super) fn is_email_message_canon_shape(
    fields: &mut [(&str, &canon::Type)],
    interner: &Interner,
) -> bool {
    if fields.len() != EMAIL_MESSAGE_FIELDS.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    let names_match = fields
        .iter()
        .zip(EMAIL_MESSAGE_FIELDS.iter())
        .all(|((name, _), exp)| *name == *exp);
    if !names_match {
        return false;
    }
    fields.iter().all(|(name, ty)| match *name {
        "to" | "cc" | "bcc" => canon_ty_is_list_of_email_address(ty, interner),
        "from" | "replyTo" => canon_ty_is_email_address(ty, interner),
        "attachments" => canon_ty_is_list_of_attachment(ty, interner),
        _ => canon_ty_is_string(ty, interner),
    })
}

/// Does `fields` match the `Attachment` shape — `{ content : Bytes, filename :
/// String, mimeType : String }` (sorted: content, filename, mimeType)?
///
/// `content` is `Bytes` (`Vec<u8>`); the other two are `String`. Sorts `fields`
/// in place. Used by `ty_is_list_of_attachment`.
pub(super) fn is_email_attachment_shape(fields: &mut [(&str, &Ty)], interner: &Interner) -> bool {
    if fields.len() != EMAIL_ATTACHMENT_FIELDS.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    // Sorted order: content, filename, mimeType.
    matches!(
        fields,
        [(cn, ct), (fn_, ft), (mn, mt)]
            if *cn == "content"
                && *fn_ == "filename"
                && *mn == "mimeType"
                && ty_is_bytes(ct, interner)
                && ty_is_string(ft, interner)
                && ty_is_string(mt, interner)
    )
}

/// The [`canon::Type`] twin of [`is_email_attachment_shape`].
pub(super) fn is_email_attachment_canon_shape(
    fields: &mut [(&str, &canon::Type)],
    interner: &Interner,
) -> bool {
    if fields.len() != EMAIL_ATTACHMENT_FIELDS.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    matches!(
        fields,
        [(cn, ct), (fn_, ft), (mn, mt)]
            if *cn == "content"
                && *fn_ == "filename"
                && *mn == "mimeType"
                && canon_ty_is_bytes(ct, interner)
                && canon_ty_is_string(ft, interner)
                && canon_ty_is_string(mt, interner)
    )
}

/// Is `ty` a `List <Attachment-shaped record>`?
pub(super) fn ty_is_list_of_attachment(ty: &Ty, interner: &Interner) -> bool {
    match ty {
        Ty::Con { module, name, args }
            if module.is_empty() && interner.resolve(*name) == Some("List") =>
        {
            match args.as_slice() {
                [Ty::Record(fields, _)] => {
                    let mut fs: Vec<(&str, &Ty)> = fields
                        .iter()
                        .filter_map(|(s, t)| interner.resolve(*s).map(|n| (n, t)))
                        .collect();
                    is_email_attachment_shape(&mut fs, interner)
                }
                _ => false,
            }
        }
        _ => false,
    }
}

/// The [`canon::Type`] twin of [`ty_is_list_of_attachment`].
pub(super) fn canon_ty_is_list_of_attachment(ty: &canon::Type, interner: &Interner) -> bool {
    match ty {
        canon::Type::Con { home, name, args }
            if home.is_empty() && interner.resolve(*name) == Some("List") =>
        {
            match args.as_slice() {
                [canon::Type::Record(fields)] => {
                    let mut fs: Vec<(&str, &canon::Type)> = fields
                        .iter()
                        .filter_map(|(s, t)| interner.resolve(*s).map(|n| (n, t)))
                        .collect();
                    is_email_attachment_canon_shape(&mut fs, interner)
                }
                _ => false,
            }
        }
        _ => false,
    }
}

// ── Ipe.Process.runWith record shape ────────────────────────────────────────
// The `ProcessRunWithCfg` input record folds to `IrType::ProcessRunWithCfg`
// (`ipe_runtime::system::ProcessRunWithCfg`) so a `Process.runWith`-call
// record literal constructs the runtime struct directly (same discipline as
// `CacheCfg` / `CsvDoc` / `EmailMessage`). Sorted field names: args < command
// < cwd < env.

/// The two `Ipe.Process` config field-name sets, re-exported from the shared
/// SSOT so lower and backend read one definition:
/// - `PROCESS_RUN_WITH_CFG_FIELDS` — `{ args, command, cwd, env }`; folds to
///   `IrType::ProcessRunWithCfg`.
/// - `PROCESS_RUN_IN_PTY_CFG_FIELDS` — `{ args, cols, command, cwd, env, rows }`;
///   folds to `IrType::ProcessRunInPtyCfg`.
pub(super) use ipe_ir::record_shapes::{
    PROCESS_RUN_IN_PTY_CFG_FIELDS, PROCESS_RUN_WITH_CFG_FIELDS,
};

/// Is `ty` the built-in `Path` — an empty-module, arg-less `Con` named `Path`?
pub(super) fn ty_is_path(ty: &Ty, interner: &Interner) -> bool {
    matches!(ty, Ty::Con { module, name, args }
        if module.is_empty() && args.is_empty() && interner.resolve(*name) == Some("Path"))
}

/// Is `ty` `Maybe Path`?
pub(super) fn ty_is_maybe_path(ty: &Ty, interner: &Interner) -> bool {
    matches!(ty, Ty::Con { module, name, args }
        if module.is_empty()
            && interner.resolve(*name) == Some("Maybe")
            && matches!(args.as_slice(), [inner] if ty_is_path(inner, interner)))
}

/// Does `fields` match the `ProcessRunWithCfg` shape — `{ args : List String,
/// command : String, cwd : Maybe Path, env : List (String, String) }`?
/// Sorts `fields` in place. Sorted order: args, command, cwd, env.
#[allow(clippy::similar_names)] // `cmd_n`/`cwd_n` differ by one char — unavoidable given field names
pub(super) fn is_process_run_with_cfg_shape(
    fields: &mut [(&str, &Ty)],
    interner: &Interner,
) -> bool {
    if fields.len() != PROCESS_RUN_WITH_CFG_FIELDS.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    matches!(
        fields,
        [(args_n, args_ty), (cmd_n, cmd_ty), (cwd_n, cwd_ty), (env_n, env_ty)]
            if *args_n == "args"
                && *cmd_n == "command"
                && *cwd_n == "cwd"
                && *env_n == "env"
                && ty_is_list_of_string(args_ty, 1, interner)
                && ty_is_string(cmd_ty, interner)
                && ty_is_maybe_path(cwd_ty, interner)
                && ty_matches_http_field(env_ty, HttpFieldTy::StrPairList, interner)
    )
}

/// The [`canon::Type`] twin of [`ty_is_path`].
pub(super) fn canon_ty_is_path(ty: &canon::Type, interner: &Interner) -> bool {
    matches!(ty, canon::Type::Con { home, name, args }
        if home.is_empty() && args.is_empty() && interner.resolve(*name) == Some("Path"))
}

/// The [`canon::Type`] twin of [`ty_is_maybe_path`].
pub(super) fn canon_ty_is_maybe_path(ty: &canon::Type, interner: &Interner) -> bool {
    matches!(ty, canon::Type::Con { home, name, args }
        if home.is_empty()
            && interner.resolve(*name) == Some("Maybe")
            && matches!(args.as_slice(), [inner] if canon_ty_is_path(inner, interner)))
}

/// The [`canon::Type`] twin of [`is_process_run_with_cfg_shape`].
#[allow(clippy::similar_names)] // `cmd_n`/`cwd_n` differ by one char — unavoidable given field names
pub(super) fn is_process_run_with_cfg_canon_shape(
    fields: &mut [(&str, &canon::Type)],
    interner: &Interner,
) -> bool {
    if fields.len() != PROCESS_RUN_WITH_CFG_FIELDS.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    matches!(
        fields,
        [(args_n, args_ty), (cmd_n, cmd_ty), (cwd_n, cwd_ty), (env_n, env_ty)]
            if *args_n == "args"
                && *cmd_n == "command"
                && *cwd_n == "cwd"
                && *env_n == "env"
                && canon_ty_is_list_of_string(args_ty, 1, interner)
                && canon_ty_is_string(cmd_ty, interner)
                && canon_ty_is_maybe_path(cwd_ty, interner)
                && canon_ty_matches_http_field(env_ty, HttpFieldTy::StrPairList, interner)
    )
}

/// Does `fields` match the `ProcessRunInPtyCfg` shape — `{ args : List String,
/// cols : Int, command : String, cwd : Maybe Path, env : List (String, String),
/// rows : Int }`? Sorts `fields` in place. Sorted order: args, cols, command,
/// cwd, env, rows.
#[allow(clippy::similar_names)] // `cmd_n`/`cwd_n`/`cols_n` differ by one char — unavoidable given field names
pub(super) fn is_process_run_in_pty_cfg_shape(
    fields: &mut [(&str, &Ty)],
    interner: &Interner,
) -> bool {
    if fields.len() != PROCESS_RUN_IN_PTY_CFG_FIELDS.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    matches!(
        fields,
        [(args_n, args_ty), (cols_n, cols_ty), (cmd_n, cmd_ty), (cwd_n, cwd_ty), (env_n, env_ty), (rows_n, rows_ty)]
            if *args_n == "args"
                && *cols_n == "cols"
                && *cmd_n == "command"
                && *cwd_n == "cwd"
                && *env_n == "env"
                && *rows_n == "rows"
                && ty_is_list_of_string(args_ty, 1, interner)
                && ty_is_int(cols_ty, interner)
                && ty_is_string(cmd_ty, interner)
                && ty_is_maybe_path(cwd_ty, interner)
                && ty_matches_http_field(env_ty, HttpFieldTy::StrPairList, interner)
                && ty_is_int(rows_ty, interner)
    )
}

/// The [`canon::Type`] twin of [`is_process_run_in_pty_cfg_shape`].
#[allow(clippy::similar_names)] // `cmd_n`/`cwd_n`/`cols_n` differ by one char — unavoidable given field names
pub(super) fn is_process_run_in_pty_cfg_canon_shape(
    fields: &mut [(&str, &canon::Type)],
    interner: &Interner,
) -> bool {
    if fields.len() != PROCESS_RUN_IN_PTY_CFG_FIELDS.len() {
        return false;
    }
    fields.sort_unstable_by_key(|(name, _)| *name);
    matches!(
        fields,
        [(args_n, args_ty), (cols_n, cols_ty), (cmd_n, cmd_ty), (cwd_n, cwd_ty), (env_n, env_ty), (rows_n, rows_ty)]
            if *args_n == "args"
                && *cols_n == "cols"
                && *cmd_n == "command"
                && *cwd_n == "cwd"
                && *env_n == "env"
                && *rows_n == "rows"
                && canon_ty_is_list_of_string(args_ty, 1, interner)
                && canon_ty_is_int(cols_ty, interner)
                && canon_ty_is_string(cmd_ty, interner)
                && canon_ty_is_maybe_path(cwd_ty, interner)
                && canon_ty_matches_http_field(env_ty, HttpFieldTy::StrPairList, interner)
                && canon_ty_is_int(rows_ty, interner)
    )
}
