//! Structural fingerprint of a Ipe.Web Model type (H24).
//!
//! `model_schema_tag` computes a SHA-256 hash of the Model type's structural
//! shape, folded with a hand-maintained wire-format epoch constant. The
//! session store compares a persisted blob's tag against the live process's
//! BEFORE deserializing it, so a structurally different (but syntactically
//! decodable) checkpoint is REJECTED — never silently decoded into the wrong
//! shape. A rejected tag falls through the store's existing fail-soft path
//! (drop the session, fresh `init`), never a panic.
//!
//! The same fingerprint keys a `--debugger` cli/worker session log
//! ([`session_codec_arg`]): `ipe dev run --replay` refuses a log whose `Msg` tag
//! differs from the running program's, never decoding it into the wrong shape.
//!
//! Canonicalisation rules (each with a regression test below):
//!
//! * Record fields hash sorted by RESOLVED NAME, never by raw [`Symbol`] —
//!   `IrType::Record`'s `BTreeMap<Symbol, _>` iterates in intern order, which
//!   depends on parse order, not on the Model's shape. The name-sorted order
//!   is the SAME canonicalisation the emitted `RecordStruct` field layout
//!   already uses, so the tag and the actual wire order share one source of
//!   truth.
//! * Enums fold in their NOMINAL identity (home module + type name) — Ipê
//!   ADTs are nominal, and a same-shaped but differently-named enum decodes
//!   with the wrong semantic meaning attached.
//! * Enum VARIANTS hash in DECLARATION order (never sorted), each with its
//!   NAME folded in at its position: the serialized discriminant is assigned
//!   by declaration index, so BOTH a rename (same position, new name) AND a
//!   reorder (same name set, new positions) are wire-format-relevant. This
//!   asymmetry with record fields is deliberate and load-bearing — records
//!   are emitted name-sorted; enum variants are emitted in declaration order.
//! * The match over [`IrType`] is EXHAUSTIVE (no `_ =>`), mirroring
//!   `emit_web::ir_type_display_name`, so a future variant is a compile
//!   error here too. Non-serde-admissible variants still get total, panic-free
//!   arms — they can never reach this function on a well-typed program (the
//!   Model-admissibility gate runs first), but a total match is cheaper to
//!   keep correct than a partial one.
//! * Fuel-bounded recursion (the same belt-and-braces `64` the
//!   `emit_model_gate` walk uses) — the type checker forbids infinite value
//!   types, so the bound only guards a compiler bug in THAT invariant.

use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::Symbol;
use ipe_ir::{IrType, ModPath, ir_type_is_serde};
use sha2::{Digest, Sha256};

use crate::EmitCtx;

/// Wire-format epoch. Must equal the runtime's
/// `ipe_runtime::web::store::WEB_MODEL_SCHEMA_WIRE_VERSION`; bumped ONLY
/// when the tag framing / blob encoding itself changes shape (the
/// `KEY_TAG`-style domain-separation convention), never for a Model change —
/// the Model's own shape is covered by the structural hash.
///
/// `v2` carries a self-describing (field-keyed JSON) checkpoint body so a
/// returning session can be spliced across a purely-additive Model change;
/// `v1`'s positional body could not be. Folding the epoch into every tag means
/// a `v1` checkpoint can never tag-match a `v2` binary, so an old-format blob
/// is refused before deserialize rather than mis-decoded.
const WIRE_EPOCH: &str = "ipe-live-model-schema-v2";

/// SHA-256 structural fingerprint of `model_ty`, folded with the wire-format
/// epoch constant. Two Models with the same field names, same field order
/// (by name — see the module doc), same field types (recursively), the same
/// nominal identity for every reachable user enum, and the same variant name
/// at each declared enum position hash IDENTICALLY, independent of `Symbol`
/// intern order and of which module was parsed first.
///
/// # Errors
/// Propagates a [`Diagnostic::CompilerBug`] if `ctx.resolve_ident` fails for
/// any field/variant symbol reachable from `model_ty` — an internal invariant
/// violation (the lowerer is contracted to hand the backend only resolvable
/// symbols), never silently defaulted: a hash computed over incomplete input
/// would undermine the reject-on-mismatch property this tag exists for.
pub fn model_schema_tag(ctx: &EmitCtx, model_ty: &IrType) -> DResult<[u8; 32]> {
    let mut h = Sha256::new();
    update_str(&mut h, WIRE_EPOCH);
    hash_ty(ctx, model_ty, &mut h, FUEL)?;
    Ok(h.finalize().into())
}

/// The runtime module holding the cli/worker session codecs.
const SESSION_LOG_PATH: &str = "ipe_runtime::debugger::session_log";

/// The session codec a `--debugger` cli/worker app entry passes the runtime.
///
/// Picked from what the app's types can encode, so the runtime's codec bounds
/// hold by construction (the serde derive lands on exactly the types
/// [`ir_type_is_serde`] accepts, see `EmitCtx::derives_serde`):
///
/// * `Msg` and `Model` both serde → `Full` (an overflowed session carries its
///   base and replays from it);
/// * only `Msg` serde → `MsgsOnly` (an overflowed session is refused at replay);
/// * `Msg` not serde (a `Secret`, a handle, …) → `TraceOnly`, recorded as a
///   trace and refused at replay with the reason;
/// * either type unrecoverable from the cfg → `TraceOnly` as well — without a
///   fingerprint no log can be proved to match the program, so none is written.
///
/// # Errors
/// Propagates [`model_schema_tag`]'s resolution failures.
pub fn session_codec_arg(
    ctx: &EmitCtx,
    msg_ty: Option<&IrType>,
    model_ty: Option<&IrType>,
) -> DResult<String> {
    let (Some(msg_ty), Some(model_ty)) = (msg_ty, model_ty) else {
        return Ok(format!(
            "{SESSION_LOG_PATH}::TraceOnly({SESSION_LOG_PATH}::Unreplayable::TypeUnknown)"
        ));
    };
    let is_serde = |ty: &IrType| ir_type_is_serde(ty, &|home, name| ctx.enum_is_serde(home, name));
    if !is_serde(msg_ty) {
        return Ok(format!(
            "{SESSION_LOG_PATH}::TraceOnly({SESSION_LOG_PATH}::Unreplayable::MsgNotEncodable)"
        ));
    }
    let codec = if is_serde(model_ty) {
        "Full"
    } else {
        "MsgsOnly"
    };
    let msg_tag = tag_literal(&model_schema_tag(ctx, msg_ty)?);
    let model_tag = tag_literal(&model_schema_tag(ctx, model_ty)?);
    Ok(format!(
        "{SESSION_LOG_PATH}::{codec}::new({msg_tag}, {model_tag})"
    ))
}

/// A schema tag as a Rust `[u8; 32]` array literal.
fn tag_literal(tag: &[u8; 32]) -> String {
    let bytes: Vec<String> = tag.iter().map(|b| format!("0x{b:02x}")).collect();
    format!("[{}]", bytes.join(", "))
}

/// Recursion budget — the same belt-and-braces bound
/// `emit_model_gate::leaf_of_bounded` uses; unreachable on well-typed input
/// (the type checker forbids infinite value types).
const FUEL: u32 = 64;

/// Hash `bytes` with an explicit little-endian length prefix so two distinct
/// inputs can never concatenate into the same byte stream (the classic
/// delimiter-collision hazard) — the same framing `ipe`'s build-cache key
/// already established.
fn update_len_prefixed(h: &mut Sha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    h.update(len.to_le_bytes());
    h.update(bytes);
}

fn update_str(h: &mut Sha256, s: &str) {
    update_len_prefixed(h, s.as_bytes());
}

fn update_count(h: &mut Sha256, n: usize) {
    h.update((u64::try_from(n).unwrap_or(u64::MAX)).to_le_bytes());
}

// One fixed domain tag per `IrType` variant, hashed before the variant's own
// payload. The VALUES are arbitrary but frozen: changing one is a wire-format
// change (every deployed session tag rotates), so treat this table like
// `WIRE_EPOCH` — append for new variants, never renumber.
const TAG_INT: u8 = 1;
const TAG_FLOAT: u8 = 2;
const TAG_STR: u8 = 3;
const TAG_BOOL: u8 = 4;
const TAG_CHAR: u8 = 5;
const TAG_UNIT: u8 = 6;
const TAG_MAYBE: u8 = 7;
const TAG_LIST: u8 = 8;
const TAG_RESULT: u8 = 9;
const TAG_DICT: u8 = 10;
const TAG_SET: u8 = 11;
const TAG_TUPLE: u8 = 12;
const TAG_RECORD: u8 = 13;
const TAG_ENUM: u8 = 14;
const TAG_FUN: u8 = 15;
const TAG_FN_ONCE_CHAIN: u8 = 16;
const TAG_GENERIC: u8 = 17;
const TAG_TASK: u8 = 18;
const TAG_BYTES: u8 = 19;
const TAG_JSON: u8 = 20;
const TAG_DECODER: u8 = 21;
const TAG_DB: u8 = 22;
const TAG_CMD: u8 = 23;
const TAG_SUB: u8 = 24;
const TAG_SERVER_REQUEST: u8 = 25;
const TAG_SERVER_RESPONSE: u8 = 26;
const TAG_SERVER_ROUTE: u8 = 27;
const TAG_SERVER_COOKIE: u8 = 28;
const TAG_STREAM_WRITER: u8 = 29;
const TAG_HTTP_REQUEST: u8 = 30;
const TAG_WEBSOCKET_SERVER: u8 = 31;
const TAG_WEBSOCKET_SERVER_CFG: u8 = 32;
const TAG_UI: u8 = 33;
const TAG_UI_PLAIN: u8 = 34;
const TAG_LIVE_REQ: u8 = 35;
const TAG_LIVE_ROUTE: u8 = 36;
const TAG_ORDER: u8 = 37;
const TAG_DECIMAL: u8 = 38;
const TAG_ERROR_KIND: u8 = 39;
const TAG_ERROR: u8 = 40;
const TAG_ERROR_DETAILS: u8 = 41;
const TAG_ERROR_INFO: u8 = 42;
const TAG_PANIC_INFO: u8 = 43;
const TAG_TYPE_INFO: u8 = 44;
const TAG_SQL_FRAGMENT: u8 = 45;
const TAG_SECRET: u8 = 46;
const TAG_CACHE_CFG: u8 = 47;
const TAG_CACHE_STATS: u8 = 48;
const TAG_CSV_DOC: u8 = 49;
const TAG_EMAIL_MESSAGE: u8 = 50;
const TAG_EMAIL_ATTACHMENT: u8 = 51;
const TAG_EMAIL_SES_CONFIG: u8 = 52;
const TAG_EMAIL_SMTP_CONFIG: u8 = 53;
const TAG_EMAIL_PROVIDER: u8 = 54;
const TAG_SHARED_FUN: u8 = 55;
const TAG_PATH: u8 = 56;
const TAG_REGEX: u8 = 57;
const TAG_HTTP_METHOD: u8 = 58;
const TAG_CRYPTO_KEY: u8 = 59;
const TAG_CRYPTO_MAC: u8 = 60;
const TAG_EMAIL_ADDRESS: u8 = 61;
const TAG_URL: u8 = 62;
const TAG_LOCALE: u8 = 63;
const TAG_ROW_GENERIC: u8 = 64;
const TAG_DSN: u8 = 65;
const TAG_CONNECTION: u8 = 66;
const TAG_CONN_READONLY: u8 = 67;
const TAG_CONN_READWRITE: u8 = 68;
const TAG_PRINCIPAL: u8 = 69;
const TAG_AUTH_CONFIG: u8 = 70;
const TAG_TOKEN_SOURCE: u8 = 71;
const TAG_SETTING: u8 = 72;
const TAG_SHAPE_WEB: u8 = 73;
const TAG_SHAPE_WEBVIEW: u8 = 74;
const TAG_SHAPE_TERMINAL: u8 = 75;
const TAG_CUSTOM_ELEMENT: u8 = 76;
// `ProcessRunWithCfg` — kernel-boundary non-serde input record for `Ipe.Process.runWith`.
const TAG_PROCESS_RUN_WITH_CFG: u8 = 77;
const TAG_BACKOFF_STRATEGY: u8 = 78;
// Shape opaque app leaves — non-serde, never a Model field; present for exhaustiveness.
const TAG_WEB_APP: u8 = 79;
// Tag 80 is unassigned: a webview build renders a `Web.tea` (`WebApp`) handle,
// so there is no distinct webview-app leaf to tag.
const TAG_TUI_APP: u8 = 81;
const TAG_CLI_APP: u8 = 82;
// The view-less worker app leaf — non-serde, never a Model field; present for
// exhaustiveness. Tag 87 is the next free structural tag.
const TAG_WORKER_APP: u8 = 87;
// `ProcessRunInPtyCfg` — kernel-boundary non-serde input record for `Ipe.Process.runInPty`.
const TAG_PROCESS_RUN_IN_PTY_CFG: u8 = 83;
const TAG_WEBSOCKET_CLIENT_CFG: u8 = 84;
// `SessionHandle` — opaque `Ipe.Ffi.Js` session handle. Renders to a bare `i64`
// (the session-registry key), which IS serde, so it may be a Model field; it gets
// its own structural tag so a Model shape carrying it hashes distinctly.
const TAG_SESSION_HANDLE: u8 = 85;
// `Url.Relative` — non-serde opaque same-origin reference, never a Model field;
// present for exhaustiveness.
const TAG_URL_RELATIVE: u8 = 86;
/// Fuel exhaustion marker — distinct from every variant tag.
const TAG_FUEL_EXHAUSTED: u8 = 0xFF;

/// Fold `ty`'s structural shape into `h`. See the module doc for the
/// canonicalisation rules; exhaustive over every [`IrType`] variant.
///
/// # Errors
/// Propagates `ctx.resolve_ident` failures (see [`model_schema_tag`]).
#[allow(clippy::too_many_lines)] // one arm per IrType variant, deliberately exhaustive
fn hash_ty(ctx: &EmitCtx, ty: &IrType, h: &mut Sha256, fuel: u32) -> DResult<()> {
    if fuel == 0 {
        // Belt-and-braces only; unreachable on well-typed input.
        h.update([TAG_FUEL_EXHAUSTED]);
        return Ok(());
    }
    let next = fuel - 1;
    match ty {
        IrType::Int => h.update([TAG_INT]),
        IrType::Float => h.update([TAG_FLOAT]),
        IrType::Str => h.update([TAG_STR]),
        IrType::Bool => h.update([TAG_BOOL]),
        IrType::Char => h.update([TAG_CHAR]),
        IrType::Unit => h.update([TAG_UNIT]),
        IrType::Bytes => h.update([TAG_BYTES]),
        IrType::Json => h.update([TAG_JSON]),
        IrType::Db => h.update([TAG_DB]),
        IrType::ServerRequest => h.update([TAG_SERVER_REQUEST]),
        IrType::ServerResponse => h.update([TAG_SERVER_RESPONSE]),
        IrType::ServerRoute => h.update([TAG_SERVER_ROUTE]),
        IrType::ServerCookie => h.update([TAG_SERVER_COOKIE]),
        IrType::StreamWriter => h.update([TAG_STREAM_WRITER]),
        IrType::HttpRequest => h.update([TAG_HTTP_REQUEST]),
        IrType::WebSocketServer => h.update([TAG_WEBSOCKET_SERVER]),
        IrType::WebSocketServerCfg => h.update([TAG_WEBSOCKET_SERVER_CFG]),
        IrType::WebReq => h.update([TAG_LIVE_REQ]),
        IrType::SessionHandle => h.update([TAG_SESSION_HANDLE]),
        IrType::BackoffStrategy => h.update([TAG_BACKOFF_STRATEGY]),
        IrType::Order => h.update([TAG_ORDER]),
        IrType::HttpMethod => h.update([TAG_HTTP_METHOD]),
        IrType::Decimal => h.update([TAG_DECIMAL]),
        IrType::ErrorKind => h.update([TAG_ERROR_KIND]),
        IrType::Error => h.update([TAG_ERROR]),
        IrType::ErrorDetails => h.update([TAG_ERROR_DETAILS]),
        IrType::ErrorInfo => h.update([TAG_ERROR_INFO]),
        IrType::PanicInfo => h.update([TAG_PANIC_INFO]),
        IrType::TypeInfo => h.update([TAG_TYPE_INFO]),
        IrType::SqlFragment => h.update([TAG_SQL_FRAGMENT]),
        IrType::Secret => h.update([TAG_SECRET]),
        IrType::Path => h.update([TAG_PATH]),
        IrType::Regex => h.update([TAG_REGEX]),
        IrType::CacheCfg => h.update([TAG_CACHE_CFG]),
        IrType::CacheStats => h.update([TAG_CACHE_STATS]),
        IrType::CsvDoc => h.update([TAG_CSV_DOC]),
        IrType::WebSocketClientCfg => h.update([TAG_WEBSOCKET_CLIENT_CFG]),
        IrType::EmailMessage => h.update([TAG_EMAIL_MESSAGE]),
        IrType::EmailAttachment => h.update([TAG_EMAIL_ATTACHMENT]),
        IrType::EmailSesConfig => h.update([TAG_EMAIL_SES_CONFIG]),
        IrType::EmailSmtpConfig => h.update([TAG_EMAIL_SMTP_CONFIG]),
        IrType::EmailProvider => h.update([TAG_EMAIL_PROVIDER]),
        // `ProcessRunWithCfg` — kernel-boundary non-serde input record; present for exhaustiveness.
        IrType::ProcessRunWithCfg => h.update([TAG_PROCESS_RUN_WITH_CFG]),
        // `ProcessRunInPtyCfg` — kernel-boundary non-serde input record; present for exhaustiveness.
        IrType::ProcessRunInPtyCfg => h.update([TAG_PROCESS_RUN_IN_PTY_CFG]),
        // Typed-key newtypes — non-serde but present for exhaustiveness.
        IrType::CryptoKey => h.update([TAG_CRYPTO_KEY]),
        IrType::CryptoMac => h.update([TAG_CRYPTO_MAC]),
        IrType::EmailAddress => h.update([TAG_EMAIL_ADDRESS]),
        IrType::Url => h.update([TAG_URL]),
        // `Url.Relative` — non-serde opaque reference; present for exhaustiveness.
        IrType::UrlRelative => h.update([TAG_URL_RELATIVE]),
        // `Dsn` — non-serde opaque descriptor; present for exhaustiveness.
        IrType::Dsn => h.update([TAG_DSN]),
        // External `Connection` + phantom access-mode markers — non-serde opaque
        // handles; present for exhaustiveness.
        IrType::Connection => h.update([TAG_CONNECTION]),
        IrType::ConnReadOnly => h.update([TAG_CONN_READONLY]),
        IrType::ConnReadWrite => h.update([TAG_CONN_READWRITE]),
        // Runtime-config `Setting` + phantom shape markers — non-serde opaque
        // carrier; present for exhaustiveness.
        IrType::Setting => h.update([TAG_SETTING]),
        IrType::ShapeWeb => h.update([TAG_SHAPE_WEB]),
        IrType::ShapeWebView => h.update([TAG_SHAPE_WEBVIEW]),
        IrType::ShapeTerminal => h.update([TAG_SHAPE_TERMINAL]),
        // `Locale` — non-serde opaque handle; present for exhaustiveness.
        IrType::Locale => h.update([TAG_LOCALE]),
        // `Principal` — non-serde opaque identity; present for exhaustiveness.
        IrType::Principal => h.update([TAG_PRINCIPAL]),
        // `AuthConfig`/`TokenSource` — non-serde authed-route descriptors;
        // present for exhaustiveness.
        IrType::AuthConfig => h.update([TAG_AUTH_CONFIG]),
        IrType::TokenSource => h.update([TAG_TOKEN_SOURCE]),
        // Shape opaque app leaves — non-serde, never a Model field; present for exhaustiveness.
        IrType::WebApp => h.update([TAG_WEB_APP]),
        IrType::TuiApp => h.update([TAG_TUI_APP]),
        IrType::CliApp => h.update([TAG_CLI_APP]),
        IrType::WorkerApp => h.update([TAG_WORKER_APP]),

        IrType::Task(inner) => {
            h.update([TAG_TASK]);
            hash_ty(ctx, inner, h, next)?;
        }
        IrType::Maybe(inner) => {
            h.update([TAG_MAYBE]);
            hash_ty(ctx, inner, h, next)?;
        }
        IrType::List(inner) => {
            h.update([TAG_LIST]);
            hash_ty(ctx, inner, h, next)?;
        }
        IrType::Set(inner) => {
            h.update([TAG_SET]);
            hash_ty(ctx, inner, h, next)?;
        }
        IrType::Decoder(inner) => {
            h.update([TAG_DECODER]);
            hash_ty(ctx, inner, h, next)?;
        }
        IrType::Cmd(inner) => {
            h.update([TAG_CMD]);
            hash_ty(ctx, inner, h, next)?;
        }
        IrType::Sub(inner) => {
            h.update([TAG_SUB]);
            hash_ty(ctx, inner, h, next)?;
        }
        IrType::WebRoute(page) => {
            h.update([TAG_LIVE_ROUTE]);
            hash_ty(ctx, page, h, next)?;
        }
        IrType::CustomElement { down, up } => {
            h.update([TAG_CUSTOM_ELEMENT]);
            hash_ty(ctx, down, h, next)?;
            hash_ty(ctx, up, h, next)?;
        }
        IrType::Result(err, ok) => {
            h.update([TAG_RESULT]);
            hash_ty(ctx, err, h, next)?;
            hash_ty(ctx, ok, h, next)?;
        }
        IrType::Dict(k, v) => {
            h.update([TAG_DICT]);
            hash_ty(ctx, k, h, next)?;
            hash_ty(ctx, v, h, next)?;
        }
        IrType::Tuple(elems) => {
            h.update([TAG_TUPLE]);
            update_count(h, elems.len());
            for e in elems {
                hash_ty(ctx, e, h, next)?;
            }
        }
        IrType::Record(fields) => {
            h.update([TAG_RECORD]);
            // Canonical order: resolved NAME, never raw Symbol — the
            // BTreeMap's native order is intern-order-dependent (see the
            // module doc and the intern-order regression test).
            let mut named: Vec<(&str, &IrType)> = fields
                .iter()
                .map(|(s, t)| Ok::<_, Diagnostic>((ctx.resolve_ident(*s)?, t)))
                .collect::<DResult<Vec<_>>>()?;
            named.sort_by_key(|(n, _)| *n);
            update_count(h, named.len());
            for (name, field_ty) in named {
                update_str(h, name);
                hash_ty(ctx, field_ty, h, next)?;
            }
        }
        IrType::Enum { home, name, args } => {
            h.update([TAG_ENUM]);
            hash_enum(ctx, home, *name, args, h, next)?;
        }
        IrType::Fun(params, ret) => {
            // Never serde-admissible — unreachable behind the Model gate,
            // but kept total (a panic-free arm is cheaper than an
            // "unreachable" one, and needs no change if the gate loosens).
            h.update([TAG_FUN]);
            update_count(h, params.len());
            for p in params {
                hash_ty(ctx, p, h, next)?;
            }
            hash_ty(ctx, ret, h, next)?;
        }
        IrType::SharedFun(params, ret) => {
            // A distinct Rust type from `Fun` (`Arc<dyn Fn>` vs `Box<dyn Fn>`),
            // so a distinct schema tag. Never serde-admissible — unreachable
            // behind the Model gate, kept total.
            h.update([TAG_SHARED_FUN]);
            update_count(h, params.len());
            for p in params {
                hash_ty(ctx, p, h, next)?;
            }
            hash_ty(ctx, ret, h, next)?;
        }
        IrType::FnOnceChain(params, ret) => {
            h.update([TAG_FN_ONCE_CHAIN]);
            update_count(h, params.len());
            for p in params {
                hash_ty(ctx, p, h, next)?;
            }
            hash_ty(ctx, ret, h, next)?;
        }
        IrType::Generic(sym) => {
            h.update([TAG_GENERIC]);
            update_str(h, ctx.resolve_ident(*sym)?);
        }
        // A row variable hashes by its source name under a distinct tag. Not
        // serde-admissible (a row-poly type never types a serde-gated Model
        // field); the arm keeps the hash total.
        IrType::RowGeneric(sym) => {
            h.update([TAG_ROW_GENERIC]);
            update_str(h, ctx.resolve_ident(*sym)?);
        }
        IrType::Ui { ctor, msg } => {
            // Not serde-admissible (unreachable behind the gate); the Debug
            // rendering of the small closed `UiCtor` set is a stable-enough
            // discriminant for a total arm — a hypothetical rename only
            // over-invalidates (fail-soft), never mis-accepts.
            h.update([TAG_UI]);
            update_str(h, &format!("{ctor:?}"));
            hash_ty(ctx, msg, h, next)?;
        }
        IrType::UiPlain(plain) => {
            h.update([TAG_UI_PLAIN]);
            update_str(h, &format!("{plain:?}"));
        }
    }
    Ok(())
}

/// Fold one user enum into the hash. See the module doc: nominal identity
/// (home + name) + type arguments + each variant's payload shapes, in
/// declaration order.
fn hash_enum(
    ctx: &EmitCtx,
    home: &ModPath,
    name: Symbol,
    args: &[IrType],
    h: &mut Sha256,
    fuel: u32,
) -> DResult<()> {
    // Nominal identity: Ipê ADTs are nominal, so the type name AND its home
    // module path fold in — a same-shaped enum from another module is a
    // DIFFERENT wire format.
    update_str(h, ctx.resolve_ident(name)?);
    update_count(h, home.0.len());
    for seg in &home.0 {
        update_str(h, ctx.resolve_ident(*seg)?);
    }
    // Type arguments are part of the wire shape: `Box Int` and `Box String`
    // share the definition's payload template but serialize differently.
    update_count(h, args.len());
    for a in args {
        hash_ty(ctx, a, h, fuel)?;
    }
    let variants = ctx.enum_variant_payloads(home, name);
    update_count(h, variants.len());
    for (variant_sym, payload) in variants {
        // Declaration order preserved (never sorted, unlike record fields)
        // and each variant's NAME folded in at its own position: the
        // serialized discriminant is assigned by DECLARATION INDEX, so both
        // a rename (name changes, index fixed) and a reorder (index changes,
        // name set fixed) are wire-format-relevant and must both change the
        // hash.
        update_str(h, ctx.resolve_ident(*variant_sym)?);
        update_count(h, payload.len());
        for field_ty in payload {
            hash_ty(ctx, field_ty, h, fuel)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ipe_diagnostics::DResult;
    use ipe_intern::Interner;
    use ipe_ir::{IrType, Program};

    use super::model_schema_tag;
    use crate::{DbDriver, EmitCtx};

    /// An `EmitCtx` over an empty program — enough for hashing types whose
    /// leaves are builtins (no user enums to resolve).
    fn empty_program() -> Program {
        Program {
            modules: vec![],
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
        }
    }

    fn hash_record(
        interner: &Interner,
        program: &Program,
        fields: BTreeMap<ipe_intern::Symbol, IrType>,
    ) -> DResult<[u8; 32]> {
        let ctx = EmitCtx::build(
            interner,
            program,
            DbDriver::Sqlite,
            None,
            ipe_ir::Target::Native,
            Vec::new(),
            crate::MountBase::root(),
            false,
            None,
            false,
            crate::BuildIntent::Release,
            String::new(),
            false,
            false,
            None,
        )?;
        model_schema_tag(&ctx, &IrType::Record(fields))
    }

    #[test]
    fn record_field_rename_changes_the_hash() -> DResult<()> {
        let mut interner = Interner::new();
        let x = interner.intern("x")?;
        let y = interner.intern("y")?;
        let z = interner.intern("z")?;
        let program = empty_program();

        let tag_before = hash_record(
            &interner,
            &program,
            BTreeMap::from([(x, IrType::Int), (y, IrType::Int)]),
        )?;
        let tag_renamed = hash_record(
            &interner,
            &program,
            BTreeMap::from([(x, IrType::Int), (z, IrType::Int)]),
        )?;
        assert_ne!(
            tag_before, tag_renamed,
            "renaming a Model field (y -> z) must change the schema tag"
        );
        Ok(())
    }

    /// Regression proof for the `BTreeMap<Symbol, _>` intern-order hazard:
    /// the SAME `{x: Int, y: Str}` shape built from two interners that
    /// intern `"x"`/`"y"` in OPPOSITE orders (so the raw `Symbol` ids — and
    /// therefore the map's native iteration order — differ) must hash
    /// IDENTICALLY. A hash walking the map directly instead of
    /// resolving-then-sorting-by-name fails this.
    #[test]
    fn record_field_reorder_by_intern_order_is_hash_stable() -> DResult<()> {
        let program = empty_program();

        let mut interner_xy = Interner::new();
        let x1 = interner_xy.intern("x")?;
        let y1 = interner_xy.intern("y")?;
        let a = hash_record(
            &interner_xy,
            &program,
            BTreeMap::from([(x1, IrType::Int), (y1, IrType::Str)]),
        )?;

        let mut interner_yx = Interner::new();
        let y2 = interner_yx.intern("y")?; // interned FIRST — lower raw id
        let x2 = interner_yx.intern("x")?;
        let b = hash_record(
            &interner_yx,
            &program,
            BTreeMap::from([(x2, IrType::Int), (y2, IrType::Str)]),
        )?;

        assert_eq!(
            a, b,
            "the schema tag must be independent of Symbol intern order \
             (parse order), depending only on the Model's shape"
        );
        Ok(())
    }

    /// A minimal single-module program carrying `types` (helper for the
    /// enum-identity tests below).
    fn program_with_types(name: ipe_ir::ModPath, types: Vec<ipe_ir::TypeDef>) -> Program {
        Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![ipe_ir::Module {
                name,
                types,
                funcs: vec![],
                entry: None,
                records: vec![],
                uses_tea: false,
                uses_server: false,
                uses_http: false,
                uses_config: false,
                uses_compression: false,
                uses_csv: false,
                uses_cache: false,
                uses_encoding: false,
                uses_regex: false,
                uses_uuid: false,
                uses_random: false,
                uses_log: false,
                uses_decimal: false,
                uses_char_category: false,
                uses_crypto_core: false,
                uses_secret: false,
                uses_json: false,
                uses_crypto: false,
                uses_jwt: false,
                uses_url: false,
                uses_ui: false,
                uses_web: false,
                uses_tui: false,
                uses_console: false,
                uses_webview: false,
                uses_css: false,
                uses_auth: false,
                uses_principal: false,
                uses_websocket: false,
                uses_email: false,
                uses_locale: false,
                uses_time: false,
                uses_env_public: false,
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        }
    }

    fn enum_def(
        home: ipe_ir::ModPath,
        name: ipe_intern::Symbol,
        variants: Vec<ipe_ir::Variant>,
    ) -> ipe_ir::TypeDef {
        ipe_ir::TypeDef::Enum(ipe_ir::EnumDef {
            name,
            home,
            type_params: vec![],
            variants,
        })
    }

    /// Two structurally-identical but differently-NAMED enums must hash
    /// DIFFERENTLY — Ipê ADTs are nominal, and a same-shaped enum from a
    /// different module decodes with the wrong semantic meaning attached
    /// (the "restore passes the gate with nonsense" H24 hazard).
    #[test]
    fn identical_shape_different_enum_name_differs() -> DResult<()> {
        let mut interner = Interner::new();
        let mod_a = interner.intern("ModA")?;
        let mod_b = interner.intern("ModB")?;
        let wrapper = interner.intern("Wrapper")?;
        let boxed = interner.intern("Box")?;
        let wrap = interner.intern("Wrap")?;
        let field = interner.intern("v")?;
        let main_mod = interner.intern("Main")?;

        let home_a = ipe_ir::ModPath(vec![mod_a]);
        let home_b = ipe_ir::ModPath(vec![mod_b]);
        // SAME variant name, SAME single-Int payload — only the nominal
        // identity (home + type name) differs.
        let variant = ipe_ir::Variant {
            name: wrap,
            fields: vec![IrType::Int],
        };
        let program = program_with_types(
            ipe_ir::ModPath(vec![main_mod]),
            vec![
                enum_def(home_a.clone(), wrapper, vec![variant.clone()]),
                enum_def(home_b.clone(), boxed, vec![variant]),
            ],
        );
        let ctx = EmitCtx::build(
            &interner,
            &program,
            DbDriver::Sqlite,
            None,
            ipe_ir::Target::Native,
            Vec::new(),
            crate::MountBase::root(),
            false,
            None,
            false,
            crate::BuildIntent::Release,
            String::new(),
            false,
            false,
            None,
        )?;

        let model_a = IrType::Record(BTreeMap::from([(
            field,
            IrType::Enum {
                home: home_a,
                name: wrapper,
                args: vec![],
            },
        )]));
        let model_b = IrType::Record(BTreeMap::from([(
            field,
            IrType::Enum {
                home: home_b,
                name: boxed,
                args: vec![],
            },
        )]));
        let a = model_schema_tag(&ctx, &model_a)?;
        let b = model_schema_tag(&ctx, &model_b)?;
        assert_ne!(
            a, b,
            "two same-shaped but differently-named enums must produce \
             different schema tags (nominal identity)"
        );
        Ok(())
    }

    /// Reordering two SAME-SHAPE (zero-payload) variants must change the
    /// hash: the serialized discriminant is assigned by DECLARATION INDEX,
    /// so `Pending | Active | Done` and `Active | Pending | Done` are
    /// different wire formats even though the name SET and shape set are
    /// identical. A shape-only hash — or one that sorts variants by name the
    /// way record fields are sorted — hashes these identically and leaves
    /// the H24 reorder hazard open.
    #[test]
    fn enum_variant_reorder_among_same_shape_variants_changes_the_hash() -> DResult<()> {
        let mut interner = Interner::new();
        let mod_a = interner.intern("ModA")?;
        let status = interner.intern("Status")?;
        let pending = interner.intern("Pending")?;
        let active = interner.intern("Active")?;
        let done = interner.intern("Done")?;
        let field = interner.intern("status")?;
        let main_mod = interner.intern("Main")?;
        let home = ipe_ir::ModPath(vec![mod_a]);
        let nullary = |name| ipe_ir::Variant {
            name,
            fields: vec![],
        };

        let program_1 = program_with_types(
            ipe_ir::ModPath(vec![main_mod]),
            vec![enum_def(
                home.clone(),
                status,
                vec![nullary(pending), nullary(active), nullary(done)],
            )],
        );
        let program_2 = program_with_types(
            ipe_ir::ModPath(vec![main_mod]),
            vec![enum_def(
                home.clone(),
                status,
                // First two variants swapped — same name set, same shapes.
                vec![nullary(active), nullary(pending), nullary(done)],
            )],
        );

        let model = IrType::Record(BTreeMap::from([(
            field,
            IrType::Enum {
                home,
                name: status,
                args: vec![],
            },
        )]));

        let ctx_1 = EmitCtx::build(
            &interner,
            &program_1,
            DbDriver::Sqlite,
            None,
            ipe_ir::Target::Native,
            Vec::new(),
            crate::MountBase::root(),
            false,
            None,
            false,
            crate::BuildIntent::Release,
            String::new(),
            false,
            false,
            None,
        )?;
        let a = model_schema_tag(&ctx_1, &model)?;
        let ctx_2 = EmitCtx::build(
            &interner,
            &program_2,
            DbDriver::Sqlite,
            None,
            ipe_ir::Target::Native,
            Vec::new(),
            crate::MountBase::root(),
            false,
            None,
            false,
            crate::BuildIntent::Release,
            String::new(),
            false,
            false,
            None,
        )?;
        let b = model_schema_tag(&ctx_2, &model)?;
        assert_ne!(
            a, b,
            "swapping two zero-payload variants changes the serialized \
             discriminant assignment and must change the schema tag"
        );
        Ok(())
    }

    /// Epoch drift tripwire (the `crate_specs_match_manifests` convention):
    /// the runtime's `WEB_MODEL_SCHEMA_WIRE_VERSION` declaration must carry
    /// the SAME epoch string as this module's `WIRE_EPOCH` — the two crates
    /// share no dependency edge, so this source-level check is what keeps
    /// the pairing honest.
    #[test]
    fn wire_epoch_matches_runtime_constant() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../runtime/rust/src/web/store.rs");
        let text = std::fs::read_to_string(&path)
            .expect("wire-epoch drift guard: cannot read runtime web/store.rs");
        let needle = format!(
            "pub const WEB_MODEL_SCHEMA_WIRE_VERSION: &str = \"{}\";",
            super::WIRE_EPOCH
        );
        assert!(
            text.contains(&needle),
            "runtime WEB_MODEL_SCHEMA_WIRE_VERSION must equal the backend's \
             WIRE_EPOCH ({:?}) — bump BOTH or neither",
            super::WIRE_EPOCH
        );
    }

    /// Termination proof for the fuel bound: a type nested far past the
    /// 64-level budget still RETURNS (Ok or a propagated Err — the property
    /// under test is termination, not success). The fuel bound guarantees
    /// O(64) work, so completion within the harness's own timeout IS the
    /// assertion.
    #[test]
    fn deeply_nested_type_never_hangs() -> DResult<()> {
        let mut interner = Interner::new();
        let field = interner.intern("deep")?;
        let program = empty_program();

        let mut ty = IrType::Int;
        for _ in 0..200 {
            ty = IrType::Maybe(Box::new(ty));
        }
        let result = hash_record(&interner, &program, BTreeMap::from([(field, ty)]));
        assert!(
            result.is_ok(),
            "a fuel-exhausted walk degrades to the exhaustion marker, never \
             an error or a hang: {result:?}"
        );
        Ok(())
    }

    /// Every domain tag (including the fuel-exhaustion marker) must be
    /// pairwise-distinct: a shared value would let two `IrType` kinds fold
    /// identically into the structural hash, collapsing the reject-on-mismatch
    /// property this tag table exists for. Any future duplicate fails here.
    #[test]
    #[allow(clippy::too_many_lines)] // one row per tag, deliberately exhaustive
    fn every_domain_tag_is_pairwise_distinct() {
        use super::{
            TAG_AUTH_CONFIG, TAG_BACKOFF_STRATEGY, TAG_BOOL, TAG_BYTES, TAG_CACHE_CFG,
            TAG_CACHE_STATS, TAG_CHAR, TAG_CLI_APP, TAG_CMD, TAG_CONN_READONLY, TAG_CONN_READWRITE,
            TAG_CONNECTION, TAG_CRYPTO_KEY, TAG_CRYPTO_MAC, TAG_CSV_DOC, TAG_CUSTOM_ELEMENT,
            TAG_DB, TAG_DECIMAL, TAG_DECODER, TAG_DICT, TAG_DSN, TAG_EMAIL_ADDRESS,
            TAG_EMAIL_ATTACHMENT, TAG_EMAIL_MESSAGE, TAG_EMAIL_PROVIDER, TAG_EMAIL_SES_CONFIG,
            TAG_EMAIL_SMTP_CONFIG, TAG_ENUM, TAG_ERROR, TAG_ERROR_DETAILS, TAG_ERROR_INFO,
            TAG_ERROR_KIND, TAG_FLOAT, TAG_FN_ONCE_CHAIN, TAG_FUEL_EXHAUSTED, TAG_FUN, TAG_GENERIC,
            TAG_HTTP_METHOD, TAG_HTTP_REQUEST, TAG_INT, TAG_JSON, TAG_LIST, TAG_LIVE_REQ,
            TAG_LIVE_ROUTE, TAG_LOCALE, TAG_MAYBE, TAG_ORDER, TAG_PANIC_INFO, TAG_PATH,
            TAG_PRINCIPAL, TAG_PROCESS_RUN_IN_PTY_CFG, TAG_PROCESS_RUN_WITH_CFG, TAG_RECORD,
            TAG_REGEX, TAG_RESULT, TAG_ROW_GENERIC, TAG_SECRET, TAG_SERVER_COOKIE,
            TAG_SERVER_REQUEST, TAG_SERVER_RESPONSE, TAG_SERVER_ROUTE, TAG_SET, TAG_SETTING,
            TAG_SHAPE_TERMINAL, TAG_SHAPE_WEB, TAG_SHAPE_WEBVIEW, TAG_SHARED_FUN, TAG_SQL_FRAGMENT,
            TAG_STR, TAG_STREAM_WRITER, TAG_SUB, TAG_TASK, TAG_TOKEN_SOURCE, TAG_TUI_APP,
            TAG_TUPLE, TAG_TYPE_INFO, TAG_UI, TAG_UI_PLAIN, TAG_UNIT, TAG_URL, TAG_URL_RELATIVE,
            TAG_WEB_APP, TAG_WEBSOCKET_CLIENT_CFG, TAG_WEBSOCKET_SERVER, TAG_WEBSOCKET_SERVER_CFG,
        };

        let tags: &[(&str, u8)] = &[
            ("TAG_INT", TAG_INT),
            ("TAG_FLOAT", TAG_FLOAT),
            ("TAG_STR", TAG_STR),
            ("TAG_BOOL", TAG_BOOL),
            ("TAG_CHAR", TAG_CHAR),
            ("TAG_UNIT", TAG_UNIT),
            ("TAG_MAYBE", TAG_MAYBE),
            ("TAG_LIST", TAG_LIST),
            ("TAG_RESULT", TAG_RESULT),
            ("TAG_DICT", TAG_DICT),
            ("TAG_SET", TAG_SET),
            ("TAG_TUPLE", TAG_TUPLE),
            ("TAG_RECORD", TAG_RECORD),
            ("TAG_ENUM", TAG_ENUM),
            ("TAG_FUN", TAG_FUN),
            ("TAG_FN_ONCE_CHAIN", TAG_FN_ONCE_CHAIN),
            ("TAG_GENERIC", TAG_GENERIC),
            ("TAG_TASK", TAG_TASK),
            ("TAG_BYTES", TAG_BYTES),
            ("TAG_JSON", TAG_JSON),
            ("TAG_DECODER", TAG_DECODER),
            ("TAG_DB", TAG_DB),
            ("TAG_CMD", TAG_CMD),
            ("TAG_SUB", TAG_SUB),
            ("TAG_SERVER_REQUEST", TAG_SERVER_REQUEST),
            ("TAG_SERVER_RESPONSE", TAG_SERVER_RESPONSE),
            ("TAG_SERVER_ROUTE", TAG_SERVER_ROUTE),
            ("TAG_SERVER_COOKIE", TAG_SERVER_COOKIE),
            ("TAG_STREAM_WRITER", TAG_STREAM_WRITER),
            ("TAG_HTTP_REQUEST", TAG_HTTP_REQUEST),
            ("TAG_WEBSOCKET_SERVER", TAG_WEBSOCKET_SERVER),
            ("TAG_WEBSOCKET_SERVER_CFG", TAG_WEBSOCKET_SERVER_CFG),
            ("TAG_UI", TAG_UI),
            ("TAG_UI_PLAIN", TAG_UI_PLAIN),
            ("TAG_LIVE_REQ", TAG_LIVE_REQ),
            ("TAG_LIVE_ROUTE", TAG_LIVE_ROUTE),
            ("TAG_ORDER", TAG_ORDER),
            ("TAG_DECIMAL", TAG_DECIMAL),
            ("TAG_ERROR_KIND", TAG_ERROR_KIND),
            ("TAG_ERROR", TAG_ERROR),
            ("TAG_ERROR_DETAILS", TAG_ERROR_DETAILS),
            ("TAG_ERROR_INFO", TAG_ERROR_INFO),
            ("TAG_PANIC_INFO", TAG_PANIC_INFO),
            ("TAG_TYPE_INFO", TAG_TYPE_INFO),
            ("TAG_SQL_FRAGMENT", TAG_SQL_FRAGMENT),
            ("TAG_SECRET", TAG_SECRET),
            ("TAG_CACHE_CFG", TAG_CACHE_CFG),
            ("TAG_CACHE_STATS", TAG_CACHE_STATS),
            ("TAG_CSV_DOC", TAG_CSV_DOC),
            ("TAG_EMAIL_MESSAGE", TAG_EMAIL_MESSAGE),
            ("TAG_EMAIL_ATTACHMENT", TAG_EMAIL_ATTACHMENT),
            ("TAG_EMAIL_SES_CONFIG", TAG_EMAIL_SES_CONFIG),
            ("TAG_EMAIL_SMTP_CONFIG", TAG_EMAIL_SMTP_CONFIG),
            ("TAG_EMAIL_PROVIDER", TAG_EMAIL_PROVIDER),
            ("TAG_SHARED_FUN", TAG_SHARED_FUN),
            ("TAG_PATH", TAG_PATH),
            ("TAG_REGEX", TAG_REGEX),
            ("TAG_HTTP_METHOD", TAG_HTTP_METHOD),
            ("TAG_CRYPTO_KEY", TAG_CRYPTO_KEY),
            ("TAG_CRYPTO_MAC", TAG_CRYPTO_MAC),
            ("TAG_EMAIL_ADDRESS", TAG_EMAIL_ADDRESS),
            ("TAG_URL", TAG_URL),
            ("TAG_URL_RELATIVE", TAG_URL_RELATIVE),
            ("TAG_LOCALE", TAG_LOCALE),
            ("TAG_ROW_GENERIC", TAG_ROW_GENERIC),
            ("TAG_DSN", TAG_DSN),
            ("TAG_CONNECTION", TAG_CONNECTION),
            ("TAG_CONN_READONLY", TAG_CONN_READONLY),
            ("TAG_CONN_READWRITE", TAG_CONN_READWRITE),
            ("TAG_PRINCIPAL", TAG_PRINCIPAL),
            ("TAG_AUTH_CONFIG", TAG_AUTH_CONFIG),
            ("TAG_TOKEN_SOURCE", TAG_TOKEN_SOURCE),
            ("TAG_SETTING", TAG_SETTING),
            ("TAG_SHAPE_WEB", TAG_SHAPE_WEB),
            ("TAG_SHAPE_WEBVIEW", TAG_SHAPE_WEBVIEW),
            ("TAG_SHAPE_TERMINAL", TAG_SHAPE_TERMINAL),
            ("TAG_CUSTOM_ELEMENT", TAG_CUSTOM_ELEMENT),
            ("TAG_PROCESS_RUN_WITH_CFG", TAG_PROCESS_RUN_WITH_CFG),
            ("TAG_BACKOFF_STRATEGY", TAG_BACKOFF_STRATEGY),
            ("TAG_WEB_APP", TAG_WEB_APP),
            ("TAG_TUI_APP", TAG_TUI_APP),
            ("TAG_CLI_APP", TAG_CLI_APP),
            ("TAG_PROCESS_RUN_IN_PTY_CFG", TAG_PROCESS_RUN_IN_PTY_CFG),
            ("TAG_WEBSOCKET_CLIENT_CFG", TAG_WEBSOCKET_CLIENT_CFG),
            ("TAG_FUEL_EXHAUSTED", TAG_FUEL_EXHAUSTED),
        ];

        for (i, &(name_a, val_a)) in tags.iter().enumerate() {
            for &(name_b, val_b) in tags.iter().skip(i + 1) {
                assert_ne!(
                    val_a, val_b,
                    "domain tags {name_a} and {name_b} share value {val_a}; \
                     every TAG_* constant must be distinct so two IrType kinds \
                     can never fold identically into the structural hash"
                );
            }
        }
    }

    /// An `EmitCtx` over an empty program, for the session-codec choice.
    fn session_ctx<'a>(interner: &'a Interner, program: &'a Program) -> DResult<EmitCtx<'a>> {
        EmitCtx::build(
            interner,
            program,
            DbDriver::Sqlite,
            None,
            ipe_ir::Target::Native,
            Vec::new(),
            crate::MountBase::root(),
            false,
            None,
            false,
            crate::BuildIntent::Release,
            String::new(),
            false,
            false,
            None,
        )
    }

    /// Serde `Msg` and `Model` get the `Full` codec, keyed by both tags.
    #[test]
    fn session_codec_full_when_both_types_encode() -> DResult<()> {
        let interner = Interner::new();
        let program = empty_program();
        let ctx = session_ctx(&interner, &program)?;
        let codec = super::session_codec_arg(&ctx, Some(&IrType::Str), Some(&IrType::Int))?;
        assert!(
            codec.starts_with("ipe_runtime::debugger::session_log::Full::new([0x"),
            "{codec}"
        );
        Ok(())
    }

    /// A non-serde `Model` gets `MsgsOnly`: an overflowed session is refused.
    #[test]
    fn session_codec_msgs_only_when_model_does_not_encode() -> DResult<()> {
        let interner = Interner::new();
        let program = empty_program();
        let ctx = session_ctx(&interner, &program)?;
        let codec = super::session_codec_arg(&ctx, Some(&IrType::Int), Some(&IrType::Secret))?;
        assert!(
            codec.starts_with("ipe_runtime::debugger::session_log::MsgsOnly::new("),
            "{codec}"
        );
        Ok(())
    }

    /// A `Secret`-bearing `Msg` is trace-only; replay refuses with the reason.
    #[test]
    fn session_codec_trace_only_for_secret_msg() -> DResult<()> {
        let interner = Interner::new();
        let program = empty_program();
        let ctx = session_ctx(&interner, &program)?;
        let secret_msg = IrType::Maybe(Box::new(IrType::Secret));
        let codec = super::session_codec_arg(&ctx, Some(&secret_msg), Some(&IrType::Int))?;
        assert_eq!(
            codec,
            "ipe_runtime::debugger::session_log::TraceOnly(\
             ipe_runtime::debugger::session_log::Unreplayable::MsgNotEncodable)"
        );
        Ok(())
    }

    /// An unrecoverable type writes no typed log: nothing proves a log matches.
    #[test]
    fn session_codec_trace_only_for_unknown_type() -> DResult<()> {
        let interner = Interner::new();
        let program = empty_program();
        let ctx = session_ctx(&interner, &program)?;
        let codec = super::session_codec_arg(&ctx, None, Some(&IrType::Int))?;
        assert_eq!(
            codec,
            "ipe_runtime::debugger::session_log::TraceOnly(\
             ipe_runtime::debugger::session_log::Unreplayable::TypeUnknown)"
        );
        Ok(())
    }
}
