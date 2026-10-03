//! Name resolution: `ipe_syntax` source tree → canonical AST. Port of the
//! supported subset of `Ipe.Canonicalise.{Module,Expression,Pattern,Type}`.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::rc::Rc;
use std::sync::OnceLock;

use ipe_diagnostics::{
    AliasExpansionKind, Candidates, CmdSubShapeMismatch, CodecAutoRejection, DResult, Diagnostic,
    EditTarget, Located, ModulePlacementReason, ModulePlacementRejection, NameError, ParseError,
    SealRejection, SortedNames, Span, TypeError,
};
use ipe_intern::{Interner, Symbol};
use ipe_kernels::{AppSurface, StdlibKernel, WebCapability};
use ipe_syntax as src;
use ipe_syntax::fixity::{Assoc, Fixity, fixity};

use crate::ast as canon;
use crate::env::{CtorHome, CtorIdentity, Env, VarHome};
use crate::scope::{
    AliasBody, Clash, ExprTarget, Identity, ModuleScope, Origin, Resolved, Tier,
    TypeTarget as ScopeType, ValueIdentity,
};

/// The maximum number of `did you mean` suggestions attached to an unresolved
/// name. Keeping it small prevents a wall of near-misses drowning the actual
/// error; the list is `(Levenshtein, name)`-sorted so the closest comes first.
const MAX_SUGGESTIONS: usize = 3;

/// The inclusive edit-distance ceiling for a suggestion. Mirrors the reference compiler
/// reference (`Ipe.Canonicalise.Module.suggestQualifier`): beyond two edits a
/// "did you mean" is more misleading than helpful, so silence wins.
const SUGGESTION_MAX_DISTANCE: usize = 2;

/// Recursion-depth cap for [`canonicalise_type`].
///
/// Every recursive call to [`canonicalise_type`] — including alias-body
/// expansion — adds one native stack frame. A long straight chain of distinct
/// aliases (`type alias A1 = A0`, `type alias A2 = A1`, …) composes their
/// individually-parser-capped-at-256 bodies into a single call depth that
/// grows with the chain length, independent of the total node count (the chain
/// produces only O(n) nodes). Empirically, a debug-profile build overflows the
/// default 2 MiB thread stack as low as depth ~256 — and exactly where depends
/// on the compiled frame layout, which shifts with unrelated edits elsewhere in
/// the crate. The cap is therefore set with comfortable headroom below that
/// cliff (rather than at it), so the `IPE-N0032` guard fires deterministically
/// in every build profile, thread-stack configuration, and code layout — never
/// a native stack overflow. A chain this deep is already pathological; the
/// margin buys stack safety at no real expressiveness cost.
///
/// Checked first inside [`canonicalise_type`] because it is the cheap,
/// profile-independent stack-safety guard.
const TYPE_EXPANSION_DEPTH_LIMIT: u32 = 128;

/// Per-annotation node budget for [`canonicalise_type`]'s alias expansion.
///
/// `visited` (the `Vec<Symbol>` threaded through the call stack) only blocks a
/// directly CYCLIC alias — it is popped once a branch finishes, so it tracks
/// the current expansion PATH, not every alias ever expanded. A diamond of
/// aliases (`type alias A1 = (A0, A0)`, `type alias A2 = (A1, A1)`, …,
/// `type alias A30 = (A29, A29)`) is acyclic and re-expands the same subtree
/// at every sibling position, doubling the work per level. `visited` alone
/// lets that compose to billions of nodes despite the diamond's call depth
/// staying at most ~30. This budget ticks once per [`canonicalise_type`] call
/// and is never restored, so it bounds the total number of nodes one
/// annotation's expansion can produce regardless of tree shape.
///
/// Deliberately much larger than [`TYPE_EXPANSION_DEPTH_LIMIT`] — a wide
/// annotation (a record with hundreds of fields, none of them nested) burns
/// through this quickly without ever growing the call stack, so it alone must
/// not be relied on for stack safety.
const TYPE_EXPANSION_NODE_LIMIT: u32 = 100_000;

/// The reserved member spelling of the JS-widget boundary constructor, reached as
/// `CustomElement.fromFile "<js-path>"` through `import Ipe.Ffi.Js.CustomElement
/// as CustomElement`. Legal only as the whole body of a `CustomElement`-annotated
/// binding, applied to a single string literal (see
/// [`detect_custom_element_constructor`]); any other appearance is IPE-N0044.
const CUSTOM_ELEMENT_CTOR: &str = "fromFile";

/// The reserved boundary type-constructor spelling paired with
/// [`CUSTOM_ELEMENT_CTOR`]: only a binding annotated `CustomElement down up` may
/// carry the constructor as its body. Doubles as the qualifier spelling of the
/// `Ipe.Ffi.Js.CustomElement` module the constructor is reached through.
const CUSTOM_ELEMENT_TYPE: &str = "CustomElement";

/// Type-constructor names the compiler reserves for built-ins. A user `type` /
/// `type alias` whose name is one of these is rejected at declaration
/// ([`NameError::ReservedBuiltinType`], IPE-N0026).
///
/// This is the exact set that `ipe_lower`'s `ir_type_from_ty` matches *ahead of*
/// its user-enum lookup (`enum_variants` guard). Because that match keys on the
/// type name alone, a user declaration of any of these names would be silently
/// overridden by the built-in IR mapping and miscompile with **no diagnostic** —
/// so the shadow must be rejected here, at the parse/canon boundary, rather than
/// validated downstream (parse-don't-validate; make-invalid-states-
/// unrepresentable).
///
/// Every entry is cited to its `crates/ipe_lower/src/lower.rs::ir_type_from_ty`
/// arm (HEAD line numbers):
///
/// ```text
/// Int 2069, Float 2070, Bool 2071, String/Error 2077, Char 2078, Bytes 2081,
/// Task 2084, Maybe 2103, Result 2108, List 2114, Dict 2119, Set 2133,
/// Decoder 2148, Db 2162, Cmd 2167, Sub 2179, SqlValue/SqlField 2195,
/// Request 2203, Response 2204, Route 2205, Cookie 2206, Html 2221,
/// Element 2236, Attribute 2254, Event 2279, Length 2295, HAlign 2297,
/// VAlign 2298, Location 2299, PseudoClass 2300, Description 2301,
/// LayoutContext 2302, WebReq 2304.
/// ```
///
/// `SqlFragment` is not in this citation list; see its own arm in
/// `ir_type_from_ty` / `ir_type_from_canon`.
///
/// Several names that `ir_type_from_ty` also matches are deliberately EXCLUDED,
/// because they sit BELOW the `enum_variants` guard in BOTH lowering
/// paths (ty + canon), so a program union of that name wins by its
/// `(home, name)` identity and only a genuine opaque builtin (no union entry)
/// reaches the fallback arm:
///   * `Value` — matched *after* the `enum_variants` guard, so a user
///     `type Value` already wins; it is not a silent-override hole.
///   * `Color`, `Length`, `HAlign`, `VAlign`, `Location`, `PseudoClass`,
///     `Description`, `LayoutContext`, `WebReq` — the nullary Ipe.Ui / Ipe.Web
///     opaque names. Leaving them UNRESERVED is what lets a user ADT — and,
///     crucially, a compiled-source `Ipe.Css` type (`Color` / `Length` / …) —
///     declare them; the home-aware guard keeps the genuine Ipe.Ui
///     builtin resolving to `UiPlain`. Multiple shipped `.ipe` fixtures
///     (`dict_adt_gate`, `set_adt_fn_gate`, `mm_local_pkg`, …) already
///     declare `type Color` as a benign sample ADT and now lower correctly.
pub const RESERVED_BUILTIN_TYPES: &[&str] = &[
    "Int",
    "Float",
    "Bool",
    "String",
    "Error",
    "Char",
    "Bytes",
    "Task",
    "Maybe",
    "Result",
    "List",
    "Dict",
    "Set",
    "Decoder",
    "Db",
    "Cmd",
    "Sub",
    "SqlValue",
    "SqlField",
    // `Ipe.Db.Store`'s typed projection-descriptor ADTs.  Reserved so user code
    // cannot declare a same-named union and silently override the synthetic
    // `EnumDef` the lowerer injects (same precedent as `SqlValue`/`SqlField`).
    "ProjectionTerm",
    "ProjectionOperand",
    "ArithOp",
    // `Ipe.Db.Sql`'s opaque WHERE-fragment type — reserved (not
    // `EXTRA_BUILTIN_TYPE_NAMES`) so user shadowing of this security-tier type
    // is a hard canon error, matching the `SqlValue`/`SqlField` precedent.
    "SqlFragment",
    // `Ipe.Secret`'s opaque sealed secret-string type —
    // reserved for the same reason as `SqlFragment`: a security-tier type
    // must not be shadowable by user code.
    "Secret",
    // `Ipe.Jwt`'s opaque signing-algorithm descriptor — shares the `Secret`
    // runtime representation (sealed, no Debug/Display surface on key material).
    // Reserved because its lowerer arm sits above the `enum_variants` guard
    // in both `ir_type_from_canon` and `ir_type_from_ty`, fixing a silent
    // SEAL break where a user `type Algorithm` would be mis-lowered.
    "Algorithm",
    // `Ipe.Path`'s opaque validated filesystem-path type — reserved for the
    // same reason: a security-tier type (the traversal/NUL-rejection boundary)
    // must not be shadowable by user code.
    "Path",
    // `Ipe.Regex`'s opaque compiled-pattern type — reserved so `Regex.compile`'s
    // typed-`Err`-on-invalid-pattern guarantee cannot be defeated by a user
    // `type Regex` shadowing the built-in handle.
    "Regex",
    // `Ipe.Url`'s opaque validated URL type — reserved for the same reason: a
    // security-tier type (the scheme/SSRF parse boundary) must not be
    // shadowable by user code defeating `Url.fromString`'s parse guarantee.
    "Url",
    // `Ipe.Url`'s opaque same-origin relative reference — reserved for the same
    // reason: a security-tier type (the browser-href SSRF boundary) must not be
    // shadowable by user code defeating `Url.relative`'s parse guarantee.
    "Relative",
    // `Ipe.Db.Dsn`'s opaque validated connection descriptor — reserved for the
    // same reason: a security-tier type (the DSN parse boundary, carrying a
    // `Secret` password and a fail-closed TLS posture) must not be shadowable by
    // user code, or a forged look-alike `Dsn` could smuggle a host/credential
    // past the parser once a connect step consumes it.
    "Dsn",
    // `Ipe.Crypto`'s opaque role-typed crypto key — reserved because a user
    // `type Key` would be silently mis-lowered to `IrType::CryptoKey` (the
    // lowerer arm sits above the `enum_variants` guard), causing SEAL breaks
    // wherever the user's ADT constructors are used.
    "Key",
    // `Ipe.Crypto`'s opaque HMAC output — reserved for the same reason as `Key`.
    "Mac",
    // `Ipe.Email`'s opaque validated email address — reserved because its lowerer
    // arm sits above the `enum_variants` guard; a user `type EmailAddress` would
    // be silently mis-lowered to `IrType::EmailAddress`, breaking the SEAL.
    "EmailAddress",
    // `Ipe.Locale`'s opaque BCP-47 locale handle — reserved for the same reason:
    // its lowerer arm sits above the `enum_variants` guard and a user
    // `type Locale` would be mis-lowered.
    "Locale",
    // `Ipe.Auth`'s opaque authenticated subject — reserved because it is a
    // security-tier type: a user `type Principal` could forge a look-alike that
    // an `…As` row-security op would trust as an authenticated caller. It has no
    // Ipê constructor, so the type name being unshadowable keeps the mint the
    // sole origin.
    "Principal",
    // `Ipe.Db`'s external-connection handle `Connection mode` and its two phantom
    // access-mode markers. Reserved because the read-only-by-type guarantee is the
    // load-bearing security property: a user `type Connection …` or a shadowed
    // `ReadOnly`/`ReadWrite` could forge a read-write handle to a foreign DB from a
    // read-only one, defeating the compile-time write barrier. The markers appear
    // only as `Connection`'s argument (phantom), never as a standalone value.
    "Connection",
    "ReadOnly",
    "ReadWrite",
    // The JS-interop visual-widget boundary type. A binding typed
    // `CustomElement down up` names, in its two concrete type parameters, the
    // sealed down-state and up-event that cross the Ipê↔JS seam — every value
    // is decoded on the way in / encoded on the way out, never an untyped blob.
    // Reserved so user code cannot declare its own `type CustomElement …` and
    // smuggle an untyped widget past the seal: the reservation is what makes the
    // typed boundary the ONLY spelling of the boundary (Security #1, fail-closed
    // by construction). A USE of the name in an annotation resolves in
    // `canonicalise_type` only through two fail-closed gates — exactly two type
    // parameters (arity, IPE-N0031) and a plain-value SEAL on each (IPE-N0039).
    // `CustomElement down up` is the shipped typed JS-widget boundary.
    // Its two type parameters name the sealed down-state and up-event.
    "CustomElement",
    // `Ipe.PubSub`'s phantom topic handle type — reserved so user code cannot
    // define `type Topic` and silently bypass the lowerer's `Topic a → Str` arm.
    // `PubSub.ipe` (EmbeddedStdlib) may declare it without penalty.
    "Topic",
    "StreamId",
    "ChunkEvent",
    // `Ipe.Http`'s closed HTTP-verb ADT. Reserved because it drives
    // exhaustiveness (`exhaust_union`) and lowers to a fixed
    // `IrType::HttpMethod` enum; a user `type HttpMethod` would be hijacked by
    // the bare-name lowerer arm and mis-lower.
    "HttpMethod",
    "Request",
    "Response",
    "Route",
    "Cookie",
    // `Ipe.Server`'s opaque authed-route descriptors. Reserved because they are
    // security-tier: `AuthConfig` carries the token-verification `Secret`, and a
    // user look-alike `type AuthConfig …`/`type TokenSource …` could smuggle a
    // forged configuration into an authed route and defeat the fail-closed auth
    // gate. Built only through the `Server` auth kernels, never an Ipê term.
    "AuthConfig",
    "TokenSource",
    // `Ipe.App`'s runtime-config carrier `Setting shape`. Reserved because it is
    // security-tier: a setting may carry a `Secret` (a `Db.url` credential), and
    // the phantom `shape` marker is the load-bearing guarantee that a `Web`-only
    // setting cannot be smuggled into another shape's settings list. A user
    // `type Setting …` could forge a look-alike and defeat that shape barrier.
    // Built only through the setting kernels, never an Ipê term.
    "Setting",
    // `Program shape msg` — the TEA shape carrier, the uniform result of every
    // `<Shape>.app` entry. Reserved so a user `type Program …` cannot forge a
    // look-alike carrier and cross a `main`'s shape barrier; built only by the
    // app-entry kernels, never an Ipê term. The phantom `shape` tag and `msg`
    // both erase at lower.
    "Program",
    // The closed config-tag ADTs — the argument types of `Host.bind` /
    // `Log.level` / `Web.csrf`. Reserved so a user `type HostMode …` cannot forge
    // a look-alike with an out-of-range or CSRF-disabling variant that the setting
    // builders would then accept; each is built only through its constructor
    // kernels, never an Ipê term. `CsrfMode` in particular has no disabling
    // variant, so a setting cannot express turning CSRF off.
    "HostMode",
    "LogLevel",
    "CsrfMode",
    // `RevocationMode` — nullary closed revocation-gate ADT (`Off` / `Store`).
    // Reserved so a user `type RevocationMode …` cannot forge a look-alike with an
    // out-of-range or enabling variant; built only through `Web.revocationOff` /
    // `Web.revocationStore` constructor kernels.
    "RevocationMode",
    "Html",
    // `View engine msg` — the engine-tagged view carrier and SSOT surface.
    // Reserved so a user `type View …` cannot shadow the builtin and forge a
    // view over an out-of-set engine tag, defeating the closed `{Web, Tui, Cli}`
    // engine gate.
    "View",
    "Element",
    // `Ipe.Ui.Tui`'s Tui-only view type `Screen msg`. Reserved so a user
    // `type Screen …` cannot shadow the builtin and defeat the shape-gate that
    // prevents Web/Cli builders from appearing in a `view : M -> Screen Msg`
    // function. Built only through `Ipe.Ui.Tui.*` kernels. `Cells` is
    // reserved alongside it — the internal rendering-model spelling.
    "Screen",
    "Cells",
    // `Ipe.Ui.Tui`'s cell-native attribute type `Attribute msg` (interned
    // `TuiAttr`). Reserved so a user `type TuiAttr …` cannot forge a look-alike
    // that would admit a DOM attribute into a `Screen` view.
    "TuiAttr",
    // `Ipe.Ui.Cli`'s line-oriented view type `Lines msg` and its line-native
    // attribute type `Attribute msg` (interned `CliAttr`). Reserved so a user
    // `type Lines …` / `type CliAttr …` cannot shadow the builtins and defeat the
    // shape-gate that keeps DOM and 2D cell builders out of a `Lines` view. Built
    // only through `Ipe.Ui.Cli.*` kernels.
    "Lines",
    "CliAttr",
    // `Ipe.Color`'s opaque companion types. The unified colour value type `Color`
    // is user-shadowable via the empty-home `Ui.Color` name (its lowerer arm sits
    // below the `enum_variants` guard); these companions instead carry a fixed
    // `ipe_runtime::color::*` identity and are built ONLY through `Ipe.Color`
    // kernels — the typed parse-error channel (`ColorError`), the terminal
    // capability profile and down-sampled result (`TermProfile` / `AnsiColor`),
    // and the accessibility bands (`WcagLevel` / `TextSize` / `Deficiency`).
    // Reserved so a user type of the same name cannot forge a look-alike over the
    // opaque runtime carrier.
    "ColorError",
    "TermProfile",
    "AnsiColor",
    "WcagLevel",
    "TextSize",
    "Deficiency",
    "Attribute",
    "Event",
    "Length",
    "HAlign",
    "VAlign",
    "Location",
    "PseudoClass",
    "Description",
    "LayoutContext",
    "WebReq",
    // `Ipe.Ffi.Js`'s opaque session-stream handle — reserved for the same reason as
    // the other security-tier opaque handles (`Principal` / `Connection`): the
    // handle is the SOLE address of a bounded session, obtained only from
    // `Js.openSession`, and a user `type SessionHandle …` could forge a look-alike
    // to address a session it never opened, defeating the fail-closed cross-handle
    // routing. It has no Ipê constructor, so reserving the name keeps the mint the
    // sole origin. Its lowerer arm sits ABOVE the `enum_variants` guard.
    "SessionHandle",
];

/// Extra built-in type names that are handled by the lowerer's explicit arms
/// (`ipe_lower::ir_type_from_canon`) but are NOT listed in
/// [`RESERVED_BUILTIN_TYPES`] (and therefore may NOT be user-defined).
///
/// These names must receive the empty-home sentinel (`Vec::new()`) from
/// `canonicalise_type` just like the reserved builtins — omitting them would
/// cause `canonicalise_type` to emit [`NameError::TypeNotFound`] for a
/// legitimate builtin annotation such as `relay : Order` or `ws : WebSocketServer`.
///
/// The names below are absent from `RESERVED_BUILTIN_TYPES` because they are
/// either:
/// * Nullary Ipe.Ui/Ipe.Web opaque names whose lowerer arm sits BELOW the
///   `enum_variants` guard (so a user `type Color` wins by its real home) — and
///   therefore can never be shadowed in a user annotation either; OR
/// * Additional opaque kernel types added after the original reservation list
///   was drawn up.
///
/// Keeping this list in sync with `ir_type_from_canon`'s explicit arms is the
/// only invariant. Any name handled by an explicit arm with `home = []` that
/// is NOT in `RESERVED_BUILTIN_TYPES` belongs here.
const EXTRA_BUILTIN_TYPE_NAMES: &[&str] = &[
    // Three-way comparison result (`lt`/`eq`/`gt`).
    "Order",
    // Ipe.Ui plain types — lowerer guard is BELOW `enum_variants` so user ADTs
    // of the same name win via their real home; but annotations that name them
    // without a program-level definition still need the empty-home sentinel.
    "Color",
    "Length",
    "HAlign",
    "VAlign",
    "Location",
    "PseudoClass",
    "Description",
    "LayoutContext",
    "WebReq",
    // Ipe.Web / Ipe.Http.Server / Ipe.Http.Server.WebSocket opaque types.
    "WebRoute",
    "StreamWriter",
    "HttpRequest",
    "WebSocketServer",
    "WebSocketServerCfg",
    // Ipe.Ui.Input parametric label/placeholder types.
    "Label",
    "Placeholder",
    // Ipe.Decimal opaque arbitrary-precision decimal type.
    // Lowerer arm: `ir_type_from_canon` `"Decimal" => IrType::Decimal`.
    "Decimal",
    // `Ipe.Db.Migration` record alias `{ name : String, sql : String }`
    // (reference `Ipe/Db.ipe:237`). Structural record — `normalize_annotation_ty`
    // expands the name to the record; the lowerer keeps it a synthesised struct
    // (no opaque arm), so it is user-shadowable-safe like `HttpRequest`.
    "Migration",
    // `Ipe.Error`'s `ErrorKind` / `ErrorDetails` unions. Both have an
    // `ir_type_from_canon` arm (`"ErrorKind" => IrType::ErrorKind` /
    // `"ErrorDetails" => IrType::ErrorDetails`) and are declared in the shared
    // built-in table (`crate::builtins::BUILTIN_UNIONS`), so an annotation such
    // as `classify : ErrorKind -> String` must resolve to the empty-home
    // sentinel rather than IPE-N0002.
    "ErrorKind",
    "ErrorDetails",
    // `Ipe.Error`'s NOMINAL payload types (see
    // `docs/adr/0001-language-semantics-and-types.md`).
    // Opaque nominal Cons backed
    // by `ipe_runtime::error::{IpePanicInfo, IpeTypeInfo, IpeErrorInfo}`, so
    // annotations such as `describePanic : PanicInfo -> String` must resolve.
    // Lowerer arms: `ir_type_from_canon` / `ir_type_from_ty`
    // `"PanicInfo" => IrType::PanicInfo` (etc.).
    "PanicInfo",
    "TypeInfo",
    "ErrorInfo",
    // `CustomElement down up` — the JS-widget boundary type (reserved in
    // `RESERVED_BUILTIN_TYPES`). Registered here too so a bare annotation
    // `codeEditor : CustomElement EditorState EditorEvent` resolves to the
    // empty-home sentinel rather than IPE-N0002; `canonicalise_type` then gates
    // it fail-closed on arity (IPE-N0031) and the plain-value SEAL (IPE-N0039),
    // and the typed seam is fully emittable.
    "CustomElement",
];

/// Kernel-implicit built-in type names that are globally in scope in
/// every Ipê program but are NOT declared by any compiled `.ipe` source file —
/// they are resolved by the runtime as opaque handles.
///
/// Without these entries, bare annotations
/// like `handleHome : Handler` fail with `TypeNotFound` / IPE-N0002 even
/// though they are legitimate kernel builtins. Each entry receives the
/// empty-home sentinel (`Vec::new()`) just like `RESERVED_BUILTIN_TYPES` and
/// `EXTRA_BUILTIN_TYPE_NAMES`.
///
/// Note: not all of these have explicit arms in `ipe_lower::ir_type_from_canon`
/// yet (`Handler` / `Middleware` / `Session` / `Store` /
/// `VNode`). Registering them here is the canon-level fix; lowerer arms complete
/// the end-to-end path.
///
/// **User-shadowable**: every name here may be declared by a user `.ipe` module
/// without a canon error. The lowerer arm for each sits BELOW the
/// `enum_variants` guard, so a user ADT wins via its real home — the same
/// `Color`/`Length` precedent used by [`EXTRA_BUILTIN_TYPE_NAMES`]. Names
/// whose lowerer arm sits ABOVE the guard with a fixed `IrType` mapping
/// (`HttpMethod`, `Connection`, …) live in [`RESERVED_BUILTIN_TYPES`] instead.
const KERNEL_IMPLICIT_BUILTIN_TYPE_NAMES: &[&str] = &[
    // `Request -> Task Error Response` alias from Ipe.Http.Server.
    "Handler",
    // `Html msg` — the top-level rendered HTML node type from Ipe.Html / Ipe.Ui.
    // Needed so `viewFoo : Model -> Html Msg` annotations typecheck without
    // `import Ipe.Html exposing (Html)`.
    "Html",
    // Opaque JSON value type (`Value = any` in Ipê). The lowerer handles this
    // via an explicit arm placed after the `enum_variants` guard — so a user
    // `type Value` still wins, but a bare annotation compiles.
    "Value",
    // `Handler -> Handler` middleware alias from Ipe.Http.Middleware.
    "Middleware",
    // Ipe.Web session object.
    "Session",
    // Ipe.Web session store.
    "Store",
    // Virtual DOM node (Ipe.Web diff engine).
    "VNode",
];

/// `true` when `name` is any known Ipê built-in type name.
///
/// Covers the union of the reserved set, the lowerer's extra explicit-arm
/// names, and the kernel-implicit names. Answers "is this a known built-in
/// at all?".
///
/// Used for annotation resolution (the empty-home sentinel in
/// `resolve_unqualified_type_home`) and for re-export tracking in stdlib
/// modules. NOT the right predicate for "may a user declare this name?" —
/// use [`is_user_type_declaration_forbidden`] for that gate.
#[must_use]
pub fn is_reserved_builtin_type_name(name: &str) -> bool {
    builtin_type_name_set().contains(name)
}

/// The union of every built-in type-name table, as an O(1)-membership set built
/// once. The three source slices stay the single source of truth; this only
/// caches their union so per-node membership tests avoid three linear scans.
fn builtin_type_name_set() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        RESERVED_BUILTIN_TYPES
            .iter()
            .chain(EXTRA_BUILTIN_TYPE_NAMES)
            .chain(KERNEL_IMPLICIT_BUILTIN_TYPE_NAMES)
            .copied()
            .collect()
    })
}

/// `true` when a user `.ipe` module (or an FFI-generated shadow module) may
/// NOT soundly declare a type with this name.
///
/// Only [`RESERVED_BUILTIN_TYPES`] names are forbidden: those are types whose
/// lowerer arm in `ir_type_from_ty` / `ir_type_from_canon` sits ABOVE the
/// `enum_variants` guard with a fixed `IrType` mapping. A competing user ADT
/// would be silently overridden and mis-lower — IPE-N0026 blocks it.
///
/// [`EXTRA_BUILTIN_TYPE_NAMES`] and [`KERNEL_IMPLICIT_BUILTIN_TYPE_NAMES`]
/// names are explicitly NOT forbidden: their lowerer arms sit below the guard
/// (the user ADT wins via its own home). A user `type Handler a`, `type Store`,
/// or `type Color` is valid and lowers correctly. An FFI interface wrapping a
/// foreign `struct Handler` or `struct Store` is equally sound.
///
/// Both [`reject_reserved_builtin_type`] (the canon resolve gate, IPE-N0026)
/// and the FFI shadow gate call this predicate — it is the SSOT for "is this
/// user-declaration forbidden?".
#[must_use]
pub fn is_user_type_declaration_forbidden(name: &str) -> bool {
    RESERVED_BUILTIN_TYPES.contains(&name)
}

/// Fixed type-argument arity for empty-home builtins, or `None`.
///
/// Drives the IPE-N0031 canon gate: a mis-arity application would otherwise
/// fall through to the lowerer's empty-home ICE catch-all (IPE-I0001). This
/// is the single source of truth for the fixed-arity gate; the lower-side
/// and seal-side tables derive from it so any future addition closes the gate
/// at all sites at once.
///
/// Members:
/// * closed containers (`List`/`Maybe`/`Set`, `Dict`/`Result`);
/// * `Connection mode` — `Ipe.Db`'s external-connection handle (arity 1);
/// * `Setting shape` — `Ipe.App`'s runtime-config carrier (arity 1);
/// * `ReadOnly`/`ReadWrite` — nullary phantom access-mode markers;
/// * `HostMode`/`LogLevel`/`CsrfMode`/`RevocationMode` — nullary closed config-tag ADTs (the
///   argument types of `Host.bind`/`Log.level`/`Web.csrf`/`Web.withRevocation`).
/// * `ColorError`/`TermProfile`/`AnsiColor`/`WcagLevel`/`TextSize`/`Deficiency` —
///   the nullary opaque `Ipe.Color` companion types, each carrying an
///   `ipe_runtime::color::*` identity.
///
/// `Task`/`Cmd`/`Sub` are absent (their gate is in `ipe_types::constrain`).
/// `CustomElement` is absent (name-based gate, fused with its boundary SEAL).
#[must_use]
pub fn builtin_empty_home_arity(name: Option<&str>) -> Option<usize> {
    match name? {
        "List" | "Maybe" | "Set" | "Connection" | "Setting" => Some(1),
        // `Program shape msg` — the TEA shape carrier (arity 2); the phantom
        // `shape` tag and `msg` both erase at lower. Widened here FIRST so a
        // `Program`-carrier application resolves through the IPE-N0031 arity gate
        // instead of falling into the lowerer's empty-home ICE (IPE-I0001).
        // `View engine msg` — the engine-tagged view carrier (arity 2); the
        // phantom `engine` tag erases at lower to the per-engine `IrType::Ui`
        // ctor. Gated here so a mis-arity `View` application resolves through
        // IPE-N0031 rather than the lowerer's empty-home ICE.
        "Dict" | "Result" | "Program" | "View" => Some(2),
        "ReadOnly" | "ReadWrite" | "HostMode" | "LogLevel" | "CsrfMode" | "RevocationMode"
        | "ProjectionTerm" | "ProjectionOperand" | "ArithOp" | "ColorError" | "TermProfile"
        | "AnsiColor" | "WcagLevel" | "TextSize" | "Deficiency" => Some(0),
        _ => None,
    }
}

/// Built-in primitive value types that ARE plain, closed, and serialisable —
/// the leaves the boundary seal (§2.1) accepts directly. Every crossing value is
/// encoded/decoded as canonical JSON, so this is exactly the set of primitives
/// with a total JSON denotation.
const SEAL_PLAIN_PRIMITIVES: &[&str] = &["Int", "Float", "Bool", "String", "Char", "Bytes"];

/// All value containers the boundary seal recurses into, listed once.
///
/// `Connection` is deliberately absent even though it appears in
/// [`builtin_empty_home_arity`]: it is an opaque DB handle, not a value
/// container the seal should recurse into. The test
/// `seal_container_arity_derives_from_builtin_arity` asserts this split.
const SEAL_VALUE_CONTAINERS: &[&str] = &["List", "Set", "Maybe", "Dict", "Result"];

/// The arity a value-container name contributes to the boundary seal recursion.
///
/// Returns the expected argument count for names in [`SEAL_VALUE_CONTAINERS`].
/// Returns `None` for anything outside that set (including `Connection`, which
/// has an entry in [`builtin_empty_home_arity`] but is intentionally excluded
/// from seal recursion as an opaque handle).
///
/// Derived from [`builtin_empty_home_arity`] to keep the two tables in sync:
/// any arity added there for a value container must be mirrored here, and the
/// test `seal_container_arity_derives_from_builtin_arity` will red if they diverge.
fn seal_container_arity(name: &str) -> Option<usize> {
    if SEAL_VALUE_CONTAINERS.contains(&name) {
        builtin_empty_home_arity(Some(name))
    } else {
        None
    }
}

/// Built-in effect carriers — never a boundary DATA value.
const SEAL_EFFECT_CARRIERS: &[&str] = &["Cmd", "Sub", "Task"];

/// Built-in view / `Ipe.Ui` value types — clonable but not a boundary
/// serialisable data value.
const SEAL_VIEW_TYPES: &[&str] = &[
    "Html",
    "View",
    "Element",
    "Attribute",
    "Event",
    "Color",
    "Length",
    "HAlign",
    "VAlign",
    "Location",
    "PseudoClass",
    "Description",
    "LayoutContext",
];

/// Built-in `Secret` / reserved-sink / opaque security-boundary handle types.
/// A secret- or sink-privileged value, or an opaque validated handle, must never
/// be serialised across the JS seam — these mirror the non-serde leaves of the
/// `HydrationState` plain-value gate
/// (`ipe_backend_rust::project::ir_type_contains_non_serde`), extended with the
/// explicit `Secret` / sink exclusion the boundary seal adds.
const SEAL_SECRET_OR_SINK: &[&str] = &[
    "Secret",
    "SqlFragment",
    "SqlValue",
    "SqlField",
    "Regex",
    "Path",
    "Url",
    "Relative",
    "Dsn",
    "Key",
    "Mac",
    "EmailAddress",
    "Locale",
];

/// The boundary-seal legality check over a canonicalised type (§2.1). Returns
/// `Some(reason)` when `ty` may NOT cross the Ipê↔JS seam, `None` when it is a
/// plain, closed, concrete value type.
///
/// FAIL-CLOSED by construction: only shapes PROVEN plain-and-safe return `None`.
/// Primitives, `Unit`, tuples, closed records, and the value containers
/// (`List` / `Set` / `Maybe` / `Dict` / `Result`) are accepted by recursing into
/// their element types. Type variables and open rows are rejected (the seal is
/// monomorphic and concrete). Functions, effect carriers, view values, and
/// `Secret` / sink / opaque-handle builtins are rejected by category.
///
/// A reference to a user-declared ADT (a `Con` whose name is neither a known
/// plain nor a known non-plain builtin) is accepted at THIS layer: its
/// transitive payload types are not visible in the canonicaliser's type context
/// (only alias BODIES are, and those are already expanded before reaching here).
/// The generated per-type seal codec re-derives and re-verifies each concrete
/// field, so an ADT that would carry a non-plain field is caught here and can
/// never reach codegen with an untyped seam.
fn boundary_seal_rejection(ty: &canon::Type, interner: &Interner) -> Option<SealRejection> {
    match ty {
        // The seal is monomorphic and concrete: a type variable has no single
        // codec, and an open row is not a closed value type.
        canon::Type::Var(_) | canon::Type::RecordOpen(_, _) => Some(SealRejection::NonConcrete),
        // A function is not a plain value and is not serialisable.
        canon::Type::Lambda(_, _) => Some(SealRejection::Function),
        // Unit, tuples, and closed records are plain when every element is.
        canon::Type::Unit => None,
        canon::Type::Tuple(elems) => elems
            .iter()
            .find_map(|e| boundary_seal_rejection(e, interner)),
        canon::Type::Record(fields) => fields
            .iter()
            .find_map(|(_, t)| boundary_seal_rejection(t, interner)),
        canon::Type::Con { home, name, args } => {
            let Some(text) = interner.resolve(*name) else {
                // A name not backed by the interner is an impossible invariant;
                // fail closed rather than treat it as plain.
                return Some(SealRejection::NotProvenPlain);
            };
            if SEAL_PLAIN_PRIMITIVES.contains(&text) {
                return None;
            }
            if SEAL_EFFECT_CARRIERS.contains(&text) {
                return Some(SealRejection::EffectCarrier);
            }
            if SEAL_VIEW_TYPES.contains(&text) {
                return Some(SealRejection::ViewValue);
            }
            if SEAL_SECRET_OR_SINK.contains(&text) {
                return Some(SealRejection::SecretOrSink);
            }
            if seal_container_arity(text).is_some() {
                return args
                    .iter()
                    .find_map(|a| boundary_seal_rejection(a, interner));
            }
            // A user-declared ADT reference: accepted at this layer (its payloads
            // are re-verified by the generated codec later). Distinguished from an
            // unknown/opaque builtin by having a real defining home OR by not
            // being any known builtin type name. An empty-home name that IS a
            // known builtin but reached none of the arms above (an opaque handle
            // such as `Db`, `Decoder`, a server type, or `CustomElement` itself)
            // is NOT proven plain — fail closed.
            if home.is_empty() && is_reserved_builtin_type_name(text) {
                return Some(SealRejection::NotProvenPlain);
            }
            None
        }
    }
}

/// Render a canonicalised type for a boundary-seal diagnostic. Deliberately
/// terse (constructor name with `…` for its arguments) — the diagnostic's job is
/// to name WHICH parameter is illegal and WHY, not to pretty-print the full type.
fn canon_type_display(ty: &canon::Type, interner: &Interner) -> Box<str> {
    match ty {
        canon::Type::Var(v) => interner.resolve(*v).unwrap_or("_").into(),
        canon::Type::Lambda(_, _) => "a function type".into(),
        canon::Type::Unit => "()".into(),
        canon::Type::Tuple(_) => "a tuple type".into(),
        canon::Type::Record(_) => "a record type".into(),
        canon::Type::RecordOpen(_, _) => "an open record type".into(),
        canon::Type::Con { name, args, .. } => {
            let base = interner.resolve(*name).unwrap_or("_");
            if args.is_empty() {
                base.into()
            } else {
                format!("{base} …").into()
            }
        }
    }
}

/// The subset of [`RESERVED_BUILTIN_TYPES`] that a trusted
/// [`ModuleOrigin::EmbeddedStdlib`] module is permitted to DEFINE, while a
/// [`ModuleOrigin::User`] module stays rejected (IPE-N0026).
///
/// These are exactly the nullary Ipe.Ui / Ipe.Web opaque names that sit
/// BELOW the home-aware `enum_variants` guard in the lowerer
/// (`ipe_lower::ir_type_from_ty` + `ir_type_from_canon`). Because the lowerer
/// keys a program-defined `type Length` under its real `(home, name)`
/// and resolves it to its OWN enum, a compiled-source stdlib module
/// (`Ipe.Css` / the `Ipe.Palette` spike) can canonically DEFINE these types
/// without a `UiPlain` hijack — so canon reservation is not
/// load-bearing for lowering-soundness on this exact set.
///
/// The reservation is retained for [`ModuleOrigin::User`] as a defence-in-depth
/// *user-facing guarantee* ("you cannot shadow `Length`" → a clean IPE-N0026
/// rather than a confusing dual-`Length` type-boundary error against the
/// built-in `UiPlain::Length`). The carve-out is keyed on the UNFORGEABLE typed
/// [`ModuleOrigin`], never on module text: a hostile user file named
/// `Ipe.Css` is discovered as User source and gets NEITHER this exemption NOR
/// the IPE-N0025 namespace exemption.
///
/// NOTE: the load-bearing built-in names whose lowerer arms sit ABOVE the
/// `enum_variants` guard (`Html` / `Attribute` / `Event` / `Element`, plus every
/// primitive like `Int` / `Task` / `List`) are deliberately EXCLUDED — even the
/// trusted stdlib must not redefine them, since a same-named union would be
/// hijacked by the bare-name arm and mis-lower. This set is precisely the
/// below-guard nullary opaque names, and nothing else.
const STDLIB_DEFINABLE_UI_TYPES: &[&str] = &[
    "Length",
    "HAlign",
    "VAlign",
    "Location",
    "PseudoClass",
    "Description",
    "LayoutContext",
    "WebReq",
];

/// The subset of [`RESERVED_BUILTIN_TYPES`] that a trusted
/// [`ModuleOrigin::EmbeddedStdlib`] module may DEFINE as the source-level
/// re-declaration of a shared opaque BOXED-WRAPPER carrier — as opposed to the
/// nullary Ipe.Ui plain names in [`STDLIB_DEFINABLE_UI_TYPES`].
///
/// `Decoder` is the shared row-decoder carrier (`IrType::Decoder`, runtime
/// `ipe_runtime::json::Decoder<E, T>`). `Ipe.Json.Decode` names it as a
/// bare reserved builtin (no source declaration — it is a qualifier-only kernel
/// module). `Ipe.Config` is a compiled-source module that `exposing (Decoder)`
/// and re-declares `type Decoder a = Decoder` to put the name in its export set,
/// exactly — Config's decoders and JSON's share
/// one carrier, differing only in the parse front-end.
///
/// Unlike [`STDLIB_DEFINABLE_UI_TYPES`] (below-guard nullary names that must
/// lower to the module's OWN enum), this re-declaration is SOUND precisely
/// because `Decoder`'s lowerer arm sits ABOVE the `enum_variants` guard AND
/// `ipe_lower::is_opaque_boxed_wrapper` recognises it: every `Decoder a`
/// annotation lowers to the shared `IrType::Decoder(a)` carrier and the
/// `type Decoder a = Decoder` declaration injects no competing enum. A
/// [`ModuleOrigin::User`] module stays rejected (IPE-N0026), so the shared
/// security-tier carrier cannot be shadowed by user code.
const STDLIB_DEFINABLE_CARRIER_TYPES: &[&str] = &[
    "Decoder",
    // `Ipe.PubSub.Topic a` — phantom topic-handle type. Lowers to `Str` at
    // runtime; EmbeddedStdlib (`Ipe.PubSub`) must declare it to put the name
    // in its export set. User modules cannot shadow it (IPE-N0026 still
    // applies to `ModuleOrigin::User`).
    "Topic",
    // Opaque crypto primitives (`Ipe.Crypto`). Each arm sits above the
    // `enum_variants` guard, so the stdlib module must re-declare the name to
    // export it. User modules cannot shadow these (IPE-N0026).
    "Key",
    "Mac",
    // Opaque validated e-mail address (`Ipe.Email`). Same pattern as `Key`.
    "EmailAddress",
    // Opaque BCP-47 locale handle (`Ipe.Locale`). Same pattern as `Key`.
    "Locale",
];

/// Reject a `type` / `type alias` whose name shadows a reserved built-in type
/// constructor. See [`RESERVED_BUILTIN_TYPES`] and
/// [`is_user_type_declaration_forbidden`].
///
/// A [`ModuleOrigin::EmbeddedStdlib`] module is exempt for the
/// [`STDLIB_DEFINABLE_UI_TYPES`] subset (nullary Ipe.Ui plain names — `Ipe.Css`)
/// and the [`STDLIB_DEFINABLE_CARRIER_TYPES`] subset (shared opaque boxed-wrapper
/// carriers — `Ipe.Config`'s `Decoder`). A [`ModuleOrigin::User`] module is gated
/// against the full reserved set, so the default user-facing behaviour is
/// byte-identical.
///
/// The forbidden predicate is [`is_user_type_declaration_forbidden`] — both
/// this function and the FFI shadow gate call it as their single SSOT.
fn reject_reserved_builtin_type(
    name: Symbol,
    span: Span,
    origin: ModuleOrigin,
    interner: &Interner,
) -> DResult<()> {
    // An unresolvable type name is an interner-invariant break; fail closed
    // (CompilerBug) rather than the `_ => Ok(())` wildcard passing the gate on a
    // `None` resolve.
    let resolved = resolve_or_bug(interner, name, "ipe_canon::reject_reserved_builtin_type")?;
    if is_user_type_declaration_forbidden(resolved)
        && !(origin == ModuleOrigin::EmbeddedStdlib
            && (STDLIB_DEFINABLE_UI_TYPES.contains(&resolved)
                || STDLIB_DEFINABLE_CARRIER_TYPES.contains(&resolved)))
    {
        return Err(Diagnostic::Name {
            span,
            msg: NameError::ReservedBuiltinType {
                name: Box::<str>::from(resolved),
            },
        });
    }
    Ok(())
}

/// Trust provenance of a module entering [`canonicalise_module_with_origin`].
///
/// This is the *unforgeable* answer to upstream's "a user file named `Ipe.Auth`
/// silently shadows the audited stdlib" supply-chain hazard. The tag is a value
/// the build **driver** constructs — set to [`Self::EmbeddedStdlib`] *only* for a
/// module whose source came from `ipe`'s compile-time embed table, and never
/// derivable from module text. A hostile user file literally named `Ipe.Palette`
/// is discovered as ordinary user source, tagged [`Self::User`], and stays
/// rejected by the reserved-namespace gate (IPE-N0025).
///
/// MAKE INVALID STATES UNREPRESENTABLE: "this module is trusted stdlib" is a
/// typed value, not a string check on the module name.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ModuleOrigin {
    /// Ordinary user-authored source. Subject to every reserved-namespace and
    /// reserved-builtin-type gate.
    #[default]
    User,
    /// A compiled-source stdlib module injected from `ipe`'s embed table. Exempt
    /// from IPE-N0025 (it legitimately declares `module Ipe.…`) and required to
    /// be fully annotated (fail-closed gate below).
    EmbeddedStdlib,
    /// A driver-generated FFI interface module (`module Rust.<Crate> …`),
    /// derived at build time from a bound crate's validated `kernel.json`.
    /// The ONLY origin whose bodies may use `Ffi.binding "<wrapper>" …`, and
    /// the only legitimate definer of a `Rust.…` home; required to be fully
    /// annotated (the annotation IS the trusted FFI signature seed).
    FfiInterface,
}

/// The aliases a dependency exports, keyed by their qualified spelling.
///
/// Each key is the interned `"Q.Name"` for an import qualifier `Q` and an alias
/// `Name` its module exports, so `Q.Name` expands in place. A bare alias name
/// is never keyed here: it resolves through the type namespace of
/// [`ModuleScope`].
type QualifiedAliases = BTreeMap<Symbol, crate::ExportedAlias>;

/// The immutable context threaded through [`canonicalise_type`]. Bundling the
/// read-only references keeps the recursive call under clippy's argument-count
/// ceiling while leaving the per-call mutable state (`free_vars`, `visited`,
/// `subst`) explicit at each call site.
struct TypeCtx<'a> {
    /// The module environment; a bare type name resolves through its
    /// [`ModuleScope`] type namespace.
    env: &'a Env,
    /// Maps each import qualifier (the short name used in `Q.TypeName` type
    /// annotations) to the full dep-module path.  Built from the module's
    /// `import` declarations in [`canonicalise_module_with_origin`].
    ///
    /// When a `TType(qualifier, segments, args)` node has a non-empty qualifier,
    /// this map is consulted FIRST.  On a hit, the dep path becomes the `home`
    /// for the resulting `Con` node — so `Counter.Msg` correctly gets
    /// `home = ["Counter"]` regardless of whether the current module also
    /// defines a local `type Msg`.  On a miss (kernel / stdlib qualifier) the
    /// lookup falls back to the bare type namespace.
    qualifier_paths: &'a BTreeMap<Symbol, Vec<Symbol>>,
    /// The dependency aliases reachable as `Q.Name`.
    qualified_aliases: &'a QualifiedAliases,
    interner: &'a Interner,
    /// The interned `"any"` wildcard type-variable symbol. A bare builtin
    /// parametric UI annotation (`view : Html`, `attr : Attribute`) is
    /// arity-filled to `Html any` / `Attribute any` at the [`src::TypeAnnotation::TType`]
    /// arm using this symbol, so its lone message parameter is inferred rather
    /// than reaching the lowerer as a zero-arg `Html` (IPE-I0001). Pre-interned
    /// by the module entry point (where the interner is mutable); the `TType` arm
    /// runs under an immutable interner and cannot mint it.
    ui_wildcard_msg: Symbol,
    /// Span of the enclosing value annotation, used as the location for an
    /// alias-arity error (the type AST itself carries no inner spans).
    ann_span: Span,
}

/// Canonicalise a parsed module into its name-resolved form.
///
/// # Errors
/// Returns [`Diagnostic::Name`] for any name that resolves to neither a
/// constructor, a bound variable, a top-level binding, nor a kernel function
/// ([`NameError::ValueNotFound`] / [`NameError::ConstructorNotFound`] /
/// [`NameError::UnknownModule`] / [`NameError::NoSuchMember`], each with a
/// deterministic did-you-mean), or for a duplicated value/constructor/type name
/// ([`NameError::DuplicateValue`] / [`NameError::DuplicateConstructor`] /
/// [`NameError::DuplicateType`]). [`Diagnostic::CompilerBug`] if the interner's
/// symbol table is exhausted or a name symbol is not interned.
pub fn canonicalise(m: &src::Module, interner: &mut Interner) -> DResult<canon::Module> {
    let home = m.name.value.clone();
    let mut env = Env::initial(home, interner)?;
    // Register `import Ipê.… as Alias` / `import Ipe.… as Alias` qualifiers.
    // The single-module path does no dep injection, but stdlib qualifier
    // aliases must still resolve (`import Ipe.Json.Encode as Encode` →
    // `Encode.string`), so run the same registration the multi-module path uses.
    register_stdlib_import_aliases(&m.imports, &mut env, interner)?;
    // The single-module path has no deps, so only stdlib kernel imports bind
    // bare names, in source order, before any local declaration.
    for import in &m.imports {
        bind_stdlib_kernel_import(import, &mut env, interner)?;
    }
    // Single-module has no deps, so no user qualifiers to map — but a Html-family
    // STDLIB import qualifier (`import Ipe.Html.Attributes as Attr`) still needs
    // its `["Html"]` type home folded so a qualified `Attr.Attribute` lowers to
    // `html::Attribute`.
    let mut qualifier_paths: BTreeMap<Symbol, Vec<Symbol>> = BTreeMap::new();
    fold_html_stdlib_qualifier_homes(&m.imports, &mut qualifier_paths, interner)?;
    // The bare single-module entry is always ordinary USER source: the trust tag
    // can only be raised via `canonicalise_module_with_origin`.
    // The single-module entry does not build a `ModuleExports`, so the kernel-
    // alias map is discarded — registration + def-skip already happened in `env`.
    canonicalise_with_env(
        m,
        &mut env,
        &qualifier_paths,
        &QualifiedAliases::new(),
        ModuleOrigin::User,
        interner,
    )
    .map(|(canon_mod, _kernel_aliases, _own_aliases)| canon_mod)
}

/// Canonicalise a module in a multi-module project context.
///
/// Called by [`crate::canonicalise_module`].
///
/// # Errors
/// [`NameError::ModulePathMismatch`] — declared module name does not match
/// `expected_path`.
/// [`NameError::ReservedNamespace`] — first path segment is `Ipê` or `Std`.
/// [`NameError::ModuleNotFound`] — an `import` names a module absent from
/// `deps`.
/// [`NameError::NameNotExposed`] — an unqualified `exposing (name)` imports a
/// name the dep module does not export.
/// [`NameError::AmbiguousImport`] — two different dep modules both expose the
/// same unqualified name.
/// Any error that [`canonicalise`] can return.
pub fn canonicalise_module(
    m: &src::Module,
    expected_path: &[Symbol],
    deps: &BTreeMap<Vec<Symbol>, crate::ModuleExports>,
    interner: &mut Interner,
) -> DResult<(canon::Module, crate::ModuleExports)> {
    // Thin wrapper: an unqualified call is ordinary USER source. The trust tag
    // can only be raised by a driver that explicitly reaches for
    // [`canonicalise_module_with_origin`] with the compiled-stdlib source it
    // embedded — never inferable from module text.
    canonicalise_module_with_origin(m, expected_path, deps, ModuleOrigin::User, interner)
}

/// Canonicalise a module carrying an explicit trust [`ModuleOrigin`].
///
/// Identical to [`canonicalise_module`] except that an [`ModuleOrigin::EmbeddedStdlib`]
/// module is (a) exempt from the IPE-N0025 reserved-namespace gate — it
/// legitimately declares `module Ipe.…` — and (b) required to carry a type
/// annotation on every top-level binding (fail-closed; see the gate at the end
/// of this function). A [`ModuleOrigin::User`] module is treated exactly as
/// before, so no user-facing behaviour changes on the default path.
///
/// # Errors
/// Same set as [`canonicalise_module`], plus a fail-closed
/// [`Diagnostic::CompilerBug`] when an [`ModuleOrigin::EmbeddedStdlib`] module has
/// an un-annotated top-level binding.
pub fn canonicalise_module_with_origin(
    m: &src::Module,
    expected_path: &[Symbol],
    deps: &BTreeMap<Vec<Symbol>, crate::ModuleExports>,
    origin: ModuleOrigin,
    interner: &mut Interner,
) -> DResult<(canon::Module, crate::ModuleExports)> {
    // Legacy entry point: dep exports arrive as an owned map and the
    // importable-module catalog is that map's key set plus the kernel paths.
    let dep_refs: BTreeMap<Vec<Symbol>, &crate::ModuleExports> =
        deps.iter().map(|(k, v)| (k.clone(), v)).collect();
    let catalog = crate::ModuleCatalog::new(deps.keys().map(|p| path_to_dot_string(interner, p)));
    canonicalise_module_in_project(m, expected_path, &dep_refs, &catalog, origin, interner)
}

/// Canonicalise a module against per-dep export references plus an explicit
/// known-module universe (the incremental driver's entry point).
///
/// Identical semantics to [`canonicalise_module_with_origin`] except:
/// * `deps` holds *references* to the importers' dep interfaces (the salsa
///   `module_interface` query memos) rather than owned clones, and is expected
///   to contain exactly this module's resolved imports — the only entries the
///   pre-incremental accumulated map ever observably consulted;
/// * `known_modules` (dot-joined module paths) supplies the IPE-N0020
///   did-you-mean candidate list, decoupling the *suggestion universe* (all
///   modules in the project) from the *injection map* (this module's imports).
///   Strings only — suggestion building must never intern (interning here
///   would perturb build-wide symbol numbering).
///
/// # Errors
/// Same set as [`canonicalise_module_with_origin`].
/// Whether `origin` is the single unforgeable compile-time provenance permitted
/// to define a module under reserved namespace `prefix`.
///
/// Each reserved prefix has exactly one legitimate definer: `Ipe.*` is the
/// bundled stdlib, injected only under [`ModuleOrigin::EmbeddedStdlib`]; `Rust.*`
/// is a driver-generated FFI interface, minted only under
/// [`ModuleOrigin::FfiInterface`]. Every other origin — including
/// [`ModuleOrigin::User`], the tag every local file and every third-party
/// dependency module carries — is refused, fail-closed. An unrecognised reserved
/// prefix has no owning origin, so it too is refused (default-deny).
fn origin_owns_reserved_prefix(origin: ModuleOrigin, prefix: &str) -> bool {
    match prefix {
        "Ipe" => origin == ModuleOrigin::EmbeddedStdlib,
        "Rust" => origin == ModuleOrigin::FfiInterface,
        _ => false,
    }
}

#[allow(clippy::too_many_lines)] // one linear resolution pass over a module's declarations
pub fn canonicalise_module_in_project(
    m: &src::Module,
    expected_path: &[Symbol],
    deps: &BTreeMap<Vec<Symbol>, &crate::ModuleExports>,
    catalog: &crate::ModuleCatalog,
    origin: ModuleOrigin,
    interner: &mut Interner,
) -> DResult<(canon::Module, crate::ModuleExports)> {
    let home = m.name.value.clone();

    // IPE-N0023: declared module name must match the path the build driver
    // computed from the file's location.
    if home.as_slice() != expected_path {
        let declared = path_to_dot_string(interner, &home);
        let expected = path_to_dot_string(interner, expected_path);
        return Err(Diagnostic::Name {
            span: m.name.span,
            msg: NameError::ModulePathMismatch { declared, expected },
        });
    }

    // IPE-N0025: a module whose first path segment is a reserved namespace prefix
    // (`Ipe` for the stdlib, `Rust` for driver-generated FFI interfaces — the
    // closed [`ipe_kernels::RESERVED_MODULE_PREFIXES`] set) is refused unless it
    // carries the ONE unforgeable compile-time origin that legitimately defines
    // that namespace. Downstream stages treat a reserved home specially (stdlib
    // symbol resolution; opaque foreign-crate interfaces never emitted as Rust
    // enums), so a user file — or a third-party dependency, which is likewise
    // `ModuleOrigin::User` — squatting there would shadow a stdlib symbol or
    // silently vanish from emission. The exemption is granted only by the
    // driver-vouched origin tag, never because the module text says `module Ipe.…`.
    if let Some(first) = home.first().copied() {
        // An unresolvable first segment is an interner-invariant break; fail
        // closed (CompilerBug) rather than default to `""`, which would silently
        // skip the reserved-namespace supply-chain gate below.
        let first_name = resolve_or_bug(interner, first, "ipe_canon::reserved_namespace_gate")?;
        if let Some(prefix) = ipe_kernels::reserved_prefix_of(&[first_name])
            && !origin_owns_reserved_prefix(origin, prefix)
        {
            let name = path_to_dot_string(interner, &home);
            return Err(Diagnostic::Name {
                span: m.name.span,
                msg: NameError::ReservedNamespace { name },
            });
        }
    }

    let mut env = Env::initial(home.clone(), interner)?;
    env.origin = origin;
    env.module_catalog = catalog.clone();
    let mut import_aliases: BTreeMap<Box<str>, BTreeSet<Box<str>>> = BTreeMap::new();
    for import in &m.imports {
        if let Some(alias) = import.alias {
            import_aliases
                .entry(path_to_dot_string(interner, &import.name.value))
                .or_default()
                .insert(name_str(interner, alias)?);
        }
    }
    env.import_aliases = Rc::new(import_aliases);
    // Fail closed at the boundary on an `Ipe.*` import that names neither a
    // kernel stdlib module nor a compiled-source dep (a typo such as
    // `Ipe.Strng`), before alias registration and the dep loop silently skip it.
    // Runs first so the did-you-mean can rank over the importable-module catalog.
    reject_unknown_ipe_import_with_candidates(
        &m.imports,
        |p| deps.contains_key(p),
        catalog,
        interner,
    )?;
    // Register user import aliases for stdlib (`Ipê.*` / `Ipe.*`) modules BEFORE
    // the dep-injection loop below. The loop bare-`continue`s for stdlib imports
    // (they need no dep injection), so alias registration is a separate,
    // self-contained pass keyed off the same authoritative path table.
    register_stdlib_import_aliases(&m.imports, &mut env, interner)?;
    // The dependency aliases reachable as `Q.Name`, filled by the qualifier
    // loop below.
    let mut qualified_aliases = QualifiedAliases::new();

    // Process each import declaration in source order, binding the names it
    // brings into scope in the module scope. Every import binds before any
    // local declaration does.
    // The `Ipe` root symbol, used below to discriminate a stdlib-kernel import
    // (absent from `deps`, qualifier-resolved) from a compiled-source stdlib dep.
    let ipe_sym = interner.intern("Ipe")?;
    for import in &m.imports {
        let dep_path = &import.name.value;
        // A stdlib kernel module binds from its pre-installed qualifier tables.
        bind_stdlib_kernel_import(import, &mut env, interner)?;
        // IPE-kernel vs compiled-source discrimination (fail-closed).
        //
        // A `Ipê.*` / `Ipe.*` import is EITHER a kernel module whose qualifiers
        // are pre-installed by `Env::initial` (absent from the user `deps` map —
        // a `deps.get` on it would spuriously IPE-N0020 every importer of
        // `Ipe.String`) OR a compiled-source stdlib module the build driver
        // injected into `deps` (e.g. `Ipe.Palette` / `Ipe.Css`). The former stays
        // on the qualifier-only `continue` path; the latter falls through to the
        // ordinary `deps.get` + `inject_dep_exports`, resolving byte-identically
        // to a user dependency. Presence in `deps` is the single discriminator:
        // a genuine kernel is never in `deps`, a compiled-source module always is.
        if dep_path.first().copied().is_some_and(|s| s == ipe_sym) && !deps.contains_key(dep_path) {
            // A kernel path needs no dep injection — its qualifiers are
            // pre-installed. A non-kernel `Ipe.*` path absent from `deps` was
            // already rejected by `reject_unknown_ipe_import_with_candidates`
            // above, so anything reaching here is a genuine kernel module.
            continue;
        }
        // IPE-N0020: dep module must have been discovered + canonicalised before
        // this module in topological order.
        let dep = *deps.get(dep_path).ok_or_else(|| {
            let name = path_to_dot_string(interner, dep_path);
            // Did-you-mean over the caller-supplied known-module universe, ranked
            // and capped through the SAME helper every other site uses (strings
            // only — never intern on this path). An unrelated import
            // (`Rust.Firestore` against the project's own modules) is beyond the
            // edit-distance ceiling, so it yields none rather than the whole list.
            let sugg = rank_suggestions(&name, catalog.paths());
            Diagnostic::Name {
                span: import.name.span,
                msg: NameError::ModuleNotFound {
                    suggestions: Candidates::at(EditTarget::whole(import.name.span, &name), sugg),
                    name,
                },
            }
        })?;

        inject_dep_exports(import, dep, &mut env, interner)?;
    }

    // Auto-inject the driver-generated `Rust.Ffi` forwarder module when a
    // module imports `Ipe.Ffi.Rust [as X]` without an explicit `import
    // Rust.Ffi`. This removes the redundant double-import requirement: a module
    // that binds `Rust.fn "<crate>" "<path>"` already declared its intent
    // through `import Ipe.Ffi.Rust`; the resolver rewrite in
    // `canonicalise_asserted_call` targets the `Ffi` qualifier, so that
    // qualifier must be in scope. When the user omitted `import Rust.Ffi` and
    // the driver-generated module is available in `deps`, inject it
    // automatically under the `Ffi` qualifier — identical to what an explicit
    // `import Rust.Ffi` (unaliased) would do. The security gate is unaffected:
    // `canonicalise_asserted_call` still calls `resolve_qual_var`, which checks
    // that the SPECIFIC mangled symbol exists as a member of `Ffi`; an
    // uninstalled crate produces no forwarder, so the member is absent and the
    // same IPE-N0038 refusal fires.
    {
        let rust_sym = interner.intern("Rust")?;
        let ffi_sym = interner.intern("Ffi")?;
        let ipe_ffi_rust: [Symbol; 3] = [ipe_sym, ffi_sym, rust_sym];
        let imports_ipe_ffi_rust = m
            .imports
            .iter()
            .any(|imp| imp.name.value.as_slice() == ipe_ffi_rust);
        if imports_ipe_ffi_rust {
            let rust_ffi_path = vec![rust_sym, ffi_sym];
            // Only inject when the driver generated the module AND the user did
            // not already import it explicitly (idempotent, but skip the work).
            if let Some(rust_ffi_dep) = deps.get(&rust_ffi_path)
                && !env.qual_vars.contains_key(&ffi_sym)
            {
                let synthetic_import = src::Import {
                    span: ipe_diagnostics::Span::DUMMY,
                    import_kw: ipe_diagnostics::Span::DUMMY,
                    name: ipe_diagnostics::Located::new(
                        ipe_diagnostics::Span::DUMMY,
                        rust_ffi_path,
                    ),
                    alias: None,
                    exposing: ipe_diagnostics::Located::new(
                        ipe_diagnostics::Span::DUMMY,
                        src::Exposing::List(vec![]),
                    ),
                };
                inject_dep_exports(&synthetic_import, rust_ffi_dep, &mut env, interner)?;
            }
        }
    }

    // Build qualifier → dep-path map so `TType(qualifier, …)` annotations in
    // type sigs resolve `home` from the dep path, not from the bare type
    // namespace.  Example: `import Counter` with no `exposing` clause
    // binds no bare type, so without this map `Counter.Msg`
    // would look up "Msg" and find the LOCAL `type Msg` instead of Counter's.
    //
    // Qualifier = explicit `as Alias` if present, else last segment of the
    // module path — mirrors `inject_dep_exports`'s `env.qual_vars` logic.
    let mut qualifier_paths: BTreeMap<Symbol, Vec<Symbol>> = BTreeMap::new();
    // Each qualifier's first-seen import span, so a clash (below) points back
    // to it like `DuplicateValue`/`DuplicateType`'s `first` field.
    let mut qualifier_first_span: BTreeMap<Symbol, Span> = BTreeMap::new();
    for import in &m.imports {
        let dep_path = &import.name.value;
        // Skip stdlib kernel imports (not in `deps`).
        if dep_path.first().copied().is_some_and(|s| s == ipe_sym) && !deps.contains_key(dep_path) {
            continue;
        }
        // Qualifiers this import is reachable under (see `import_qualifiers`).
        let reachable_qualifiers = import_qualifiers(import.alias, dep_path, interner)?;
        for qualifier in reachable_qualifiers {
            // `import App.Utils` + `import Lib.Utils` (both default to the
            // qualifier `Utils`), or one `as` alias over two distinct dep
            // modules, is a clash: a qualified `Utils.format` would otherwise
            // name whichever import came last. Re-importing the SAME dep module
            // under the same qualifier (a diamond dependency) is a no-op,
            // matching the module scope's rule for one definition bound twice.
            if let Some(existing_path) = qualifier_paths.get(&qualifier) {
                if existing_path != dep_path {
                    let qualifier_s = name_str(interner, qualifier)?;
                    let first = qualifier_first_span
                        .get(&qualifier)
                        .copied()
                        .unwrap_or(import.name.span);
                    return Err(Diagnostic::Name {
                        span: import.name.span,
                        msg: NameError::DuplicateQualifier {
                            qualifier: qualifier_s,
                            first,
                        },
                    });
                }
                continue;
            }
            qualifier_paths.insert(qualifier, dep_path.clone());
            qualifier_first_span.insert(qualifier, import.name.span);

            // Register every exported alias of the dep under a synthetic
            // `Qualifier.Name` key so a QUALIFIED annotation (`Money.Price`)
            // expands the alias exactly as an `exposing`-injected one would —
            // qualified access needs no exposure, and the qualified key can never
            // collide with a bare local name (bare symbols carry no dot).
            if let Some(dep) = deps.get(dep_path) {
                let qualifier_s = name_str(interner, qualifier)?;
                for (&alias_name, ea) in &dep.aliases {
                    let alias_s = name_str(interner, alias_name)?;
                    let key = interner.intern(&format!("{qualifier_s}.{alias_s}"))?;
                    qualified_aliases.entry(key).or_insert_with(|| ea.clone());
                }
            }
        }
    }

    // Fold Html-family STDLIB import qualifiers into `qualifier_paths` (→
    // `["Html"]`) so a qualified `Attr.Attribute` (`import Ipe.Html.Attributes as
    // Attr`) resolves to the `html::Attribute` home. Runs AFTER the
    // user-dep loop so a user qualifier that also names a Html dep keeps its real
    // dep path (`entry(..).or_insert` inside the helper is a no-op on a hit).
    fold_html_stdlib_qualifier_homes(&m.imports, &mut qualifier_paths, interner)?;

    let (mut canon_mod, kernel_aliases, own_aliases) = canonicalise_with_env(
        m,
        &mut env,
        &qualifier_paths,
        &qualified_aliases,
        origin,
        interner,
    )?;
    // The record-alias auto-constructors that were actually synthesized:
    // exactly the defs whose name is an alias name. A function-field alias is
    // gated out of synthesis, so it is absent here and must NOT be exported as a
    // value — deriving the set from the real defs keeps exports and synthesis in
    // lockstep (no re-derivation that could drift).
    let own_alias_names: BTreeSet<Symbol> = m.aliases.iter().map(|a| a.value.name.value).collect();
    let synth_ctor_names: BTreeSet<Symbol> = canon_mod
        .defs
        .iter()
        .map(|d| d.name().value)
        .filter(|n| own_alias_names.contains(n))
        .collect();
    // Fail-closed stdlib annotation gate (design §3). Whole-program rank-based
    // let-generalisation is NOT implemented: an UN-annotated top-level binding
    // used at two distinct concrete types would unify under one mono var and
    // could mis-infer deep inside the stdlib. For an EmbeddedStdlib module we
    // therefore make the fully-annotated precondition a MACHINE-CHECKED contract
    // rather than an assumption — any `Def::Untyped` top-level is a
    // compiler-internal error at THIS boundary, turning a would-be confusing
    // deep-stdlib unification failure (or exit-0-then-cargo-fail) into an explicit
    // build-time invariant. It can never fire for user code (User origin skips
    // this block); synthesised record-alias ctors are `Def::Typed`, so they pass.
    if matches!(
        origin,
        ModuleOrigin::EmbeddedStdlib | ModuleOrigin::FfiInterface
    ) {
        for d in &canon_mod.defs {
            if let canon::Def::Untyped { name, .. } = d {
                let binding = name_str(interner, name.value)?;
                let module = path_to_dot_string(interner, &home);
                return Err(Diagnostic::CompilerBug {
                    where_: "canon.stdlib_unannotated",
                    detail: format!(
                        "compiled-source stdlib module `{module}` binding `{binding}` \
                         must carry a type annotation (annotation-driven generalisation \
                         is required for stdlib modules)"
                    ),
                });
            }
        }
    }

    // Build the export surface from the module's own `exposing (…)` clause.
    let exports = build_module_exports(
        &home,
        m,
        &env,
        &synth_ctor_names,
        &kernel_aliases,
        &own_aliases,
        interner,
    );

    // IPE-N0033 (ADR 0005): a Program importing any `Ipe.Tea.*` shape is a
    // contradiction. Skip stdlib origins — the embedded `Ipe.Web.Head` /
    // `Ipe.Web.Console` helpers are static and never import a shape, and only
    // USER modules are subject to the Program/TEA distinction.
    if origin == ModuleOrigin::User {
        check_main_not_runtime_branched(&canon_mod, interner)?;
        check_program_tea_import_gate(m, &canon_mod, interner)?;
        check_cross_shape_cmd_sub_gate(m, &canon_mod, interner)?;
        check_input_fields_are_subscriptions(&canon_mod, interner)?;
        check_library_ssot_import_gate(m, interner)?;
        // Thread a sibling top-level `config` binding into the app entry
        // (`main = Web.tea { … }` becomes `Web.appWith config { … }`), or reject
        // a `config` binding that no app entry consumes (IPE-N0043).
        thread_config_binding(&mut canon_mod, interner)?;
    }

    Ok((canon_mod, exports))
}

/// The reserved name of the app's cross-cutting settings binding — a top-level
/// `config : List (Setting shape)`. Recognised by name (mirroring `main` /
/// `package`), threaded into the app entry so the whole app's wiring reads from
/// one place.
const CONFIG_BINDING: &str = "config";

/// Thread a sibling top-level `config` binding into the module's `Web` app entry,
/// and reject a `config` binding no entry consumes (IPE-N0043).
///
/// When a module declares both a top-level `config` binding and a `main` whose
/// head is a settings-less `Web` entry (`Web.tea` / `Web.appRouted`), rewrite the
/// entry to `Web.appWith config <cfg>`: the `config` value becomes the settings
/// argument the runtime installs.
///
/// A `config` binding that reaches no app entry is rejected (IPE-N0043). This
/// includes: `main` being a Program (non-`Web` shape, or absent), and `main`
/// already being an inline `Web.appWith [ … ] { … }` — in the latter case the
/// inline settings take effect and the sibling `config` would be silently dropped,
/// so the compiler rejects the combination rather than producing an app that
/// ignores its own `config` binding.
///
/// # Errors
/// [`Diagnostic::Name`] (IPE-N0043) when a `config` binding is declared but never
/// threaded into an app entry.
fn thread_config_binding(canon_mod: &mut canon::Module, interner: &mut Interner) -> DResult<()> {
    let Some(config_sym) = interner.lookup(CONFIG_BINDING) else {
        return Ok(()); // `config` never interned → this module cannot name one.
    };
    // A top-level `config` binding, and its declaration span (for IPE-N0043 blame).
    let config_span = canon_mod
        .defs
        .iter()
        .find(|d| d.name().value == config_sym)
        .map(|d| d.name().span);
    let Some(config_span) = config_span else {
        return Ok(()); // no `config` binding — nothing to thread or lint.
    };

    let Some(main_sym) = interner.lookup("main") else {
        // `config` present but no `main` can be named → it is never threaded.
        return Err(discarded_config(config_span));
    };
    // Pre-intern the canonical qualifier + settings-carrying entry name so the
    // walker can re-target the kernel without a live `&mut Interner` borrow held
    // across the `&mut defs` walk. `interner.intern` is idempotent (returns the
    // existing symbol when already interned), so this never perturbs numbering
    // for a module that already names `Web` / `appWith`.
    let web_sym = interner.intern("Web").ok();
    let app_with_sym = interner.intern("appWith").ok();
    let tea_sym = interner.intern("tea").ok();
    let app_routed_sym = interner.intern("appRouted").ok();
    let (Some(web_sym), Some(app_with_sym), Some(tea_sym), Some(app_routed_sym)) =
        (web_sym, app_with_sym, tea_sym, app_routed_sym)
    else {
        // Interner exhausted (unreachable in practice) → fail closed rather than
        // silently drop the config.
        return Err(discarded_config(config_span));
    };

    let Some(main_def) = canon_mod
        .defs
        .iter_mut()
        .find(|d| d.name().value == main_sym)
    else {
        return Err(discarded_config(config_span));
    };

    let home = main_def.home().to_vec();
    let body = match main_def {
        canon::Def::Untyped { body, .. } | canon::Def::Typed { body, .. } => body,
    };
    let names = ConfigThreadNames {
        config: config_sym,
        web: web_sym,
        app_with: app_with_sym,
        tea: tea_sym,
        app_routed: app_routed_sym,
    };
    if thread_config_into_entry(body, &names, &home) {
        return Ok(());
    }
    // A `config` binding exists but `main` neither is a settings-less `Web` entry
    // to thread it into nor already carries its own settings — it is discarded.
    Err(discarded_config(config_span))
}

/// The pre-interned symbols [`thread_config_into_entry`] needs to recognise a
/// `Web` app entry and re-target it, resolved before the `&mut defs` walk so no
/// `&mut Interner` borrow is held across it.
struct ConfigThreadNames {
    /// The `config` binding's symbol (threaded as the settings reference).
    config: Symbol,
    /// The `Web` qualifier symbol.
    web: Symbol,
    /// The settings-carrying `appWith` entry name symbol.
    app_with: Symbol,
    /// The settings-less `Web.tea` entry name symbol.
    tea: Symbol,
    /// The settings-less `Web.appRouted` entry name symbol.
    app_routed: Symbol,
}

/// Build the IPE-N0043 discarded-`config` diagnostic at the binding's span.
const fn discarded_config(span: Span) -> Diagnostic {
    Diagnostic::Name {
        span,
        msg: NameError::DiscardedConfig,
    }
}

/// Rewrite a settings-less `Web` entry at the head of `body` to thread `config`,
/// returning whether the `config` binding was threaded into an app entry.
///
/// Returns `true` when the head is `Web.tea` / `Web.appRouted` applied to its
/// single cfg record — rewritten in place to `Web.appWith config <cfg>`.
///
/// Returns `false` when:
/// * the head is already `Web.appWith` — the entry carries its own inline
///   settings list, so a sibling `config` binding has nowhere to go and is
///   discarded (caller emits IPE-N0043); or
/// * the head is not a `Web` app entry at all (a Program, a non-`Web` shape,
///   or an unrecognised form).
fn thread_config_into_entry(
    body: &mut canon::Expr,
    names: &ConfigThreadNames,
    home: &[Symbol],
) -> bool {
    // Peel `\… -> …` / `let … in …` wrappers to the head call, matching the TEA
    // entry classification (`main_head_is_tea_entry`). Only a `main` whose head
    // is a `Web` entry `Call` is threadable; a bare kernel reference with no cfg
    // argument is not a valid entry and is left for the type-checker.
    match &mut body.value {
        canon::Expr_::Lambda(_, inner) | canon::Expr_::Let(_, inner) => {
            thread_config_into_entry(inner, names, home)
        }
        canon::Expr_::Call(callee, args) => {
            let canon::Expr_::VarKernel { module, name, .. } = &callee.value else {
                return false;
            };
            if *module != names.web {
                return false; // a non-`Web` shape entry does not thread `config`.
            }
            // Inline `Web.appWith` already carries its own settings list.
            // A sibling `config` binding would be silently dropped — reject it
            // (caller emits IPE-N0043) rather than letting settings go missing.
            if *name == names.app_with {
                return false;
            }
            // Settings-less `Web` entry with exactly its cfg record: rewrite the
            // callee to `Web.appWith` and prepend the `config` reference.
            if (*name == names.tea || *name == names.app_routed) && args.len() == 1 {
                let module = *module;
                // Re-target the kernel to `Web.appWith`. Both the type-checker
                // (`resolve_scheme(SchemeKey(id))`) and the emit path key off the
                // pre-resolved `id`, so it MUST carry the settings-carrying
                // `WebAppWith` variant — a `None` id would fail closed as
                // IPE-L0108 (Unsupported kernel) at type-check.
                callee.value = canon::Expr_::VarKernel {
                    id: Some(StdlibKernel::WebAppWith),
                    module,
                    name: names.app_with,
                };
                let config_ref = Located::new(
                    callee.span,
                    canon::Expr_::VarTopLevel {
                        module: home.to_vec(),
                        name: names.config,
                    },
                );
                args.insert(0, config_ref);
                return true;
            }
            false
        }
        _ => false,
    }
}

/// The TEA app-entry kernels, keyed `(qualifier, entry name)`. A module whose
/// `main` head-calls one of these is a TEA app; any other `main` (a plain
/// `Task`) is a Program. Kept in lockstep with the app-entry rows of
/// `env::QUALIFIERS` (`Web.tea`/`appRouted`, `Tui.tea`, `Cli.tea`).
///
/// Keyed on the kernel `(module, name)` a resolved `VarKernel` carries. `Tui.tea`
/// and `Cli.tea` are the two terminal drive-axis entries; each owns its own
/// `Cmd` / `Sub` surface (see [`AppSurface::admits_cmd_sub_of`]).
const TEA_APP_ENTRIES: &[(&str, &str)] = &[
    ("Web", "tea"),
    ("Web", "appRouted"),
    ("Web", "appWith"),
    ("Tui", "tea"),
    ("Cli", "tea"),
    // `Worker.tea` — the view-less co-located worker app-entry. A worker is a TEA
    // app (its `main` head-calls the entry) with its own `Cmd` / `Sub` scope
    // (`Ipe.Tea.Worker.{Cmd,Sub}`).
    ("Worker", "tea"),
];

/// `true` iff a [`crate::shape_source::SHAPE_ENTRIES`] row lives in the `Ipe.Tea.*`
/// namespace — the structural discriminator between a TEA app-entry (which has a
/// [`TEA_APP_ENTRIES`] counterpart) and the sole non-TEA `Ipe.Http.Server`
/// `listen` shape entry (which does not).
#[allow(clippy::indexing_slicing)] // indices guarded by `len >= 2` then `== "Ipe"/"Tea"`
const fn shape_entry_is_tea(path: &[&str]) -> bool {
    path.len() >= 2
        && crate::env::const_str_eq(path[0], "Ipe")
        && crate::env::const_str_eq(path[1], "Tea")
}

/// `true` iff some [`TEA_APP_ENTRIES`] row is `(qualifier, name)`.
#[allow(clippy::indexing_slicing)] // index guarded by `i < len`
const fn tea_app_entries_has(qualifier: &str, name: &str) -> bool {
    let mut i = 0;
    while i < TEA_APP_ENTRIES.len() {
        let (q, n) = TEA_APP_ENTRIES[i];
        if crate::env::const_str_eq(q, qualifier) && crate::env::const_str_eq(n, name) {
            return true;
        }
        i += 1;
    }
    false
}

/// `true` iff some `Ipe.Tea.*` [`crate::shape_source::SHAPE_ENTRIES`] row keys
/// `(last-path-segment, name)` — the TEA-app view of that table, as
/// [`TEA_APP_ENTRIES`] keys it.
#[allow(clippy::indexing_slicing)] // indices guarded by `i < len` / non-empty path in SHAPE_ENTRIES
const fn shape_entries_tea_has(qualifier: &str, name: &str) -> bool {
    let entries = crate::shape_source::SHAPE_ENTRIES;
    let mut i = 0;
    while i < entries.len() {
        let (path, n, _) = entries[i];
        if shape_entry_is_tea(path)
            && !path.is_empty()
            && crate::env::const_str_eq(path[path.len() - 1], qualifier)
            && crate::env::const_str_eq(n, name)
        {
            return true;
        }
        i += 1;
    }
    false
}

/// **Compile-time bijection tripwire (fail-closed).** The resolver's
/// [`TEA_APP_ENTRIES`] (keyed by short qualifier) and the classifier's
/// `Ipe.Tea.*` [`crate::shape_source::SHAPE_ENTRIES`] rows (keyed by canonical path)
/// name the same TEA app-entries — the former's `(qualifier, name)` is exactly
/// the latter's `(last-path-segment, name)`. Both peel the same `main` head to
/// classify a program's shape; a one-sided edit would let `ipe` classify a
/// program one way at the resolver and another at the shape gate.
///
/// This asserts the two-way agreement during const-eval, so the *build* breaks
/// the instant the tables drift — never a test that can be skipped, nor a
/// downstream shape misclassification. The `Ipe.Http.Server` `listen` row is not
/// under `Ipe.Tea.*`, so it is (correctly) excluded from both directions: it is
/// the one shape entry that is not a TEA app.
///
/// The `long_running_const_eval` allow covers the bounded
/// `TEA_APP_ENTRIES.len() × SHAPE_ENTRIES.len()` cross-scan — deterministic and
/// finite, just larger than the lint's default step budget.
#[allow(long_running_const_eval)]
#[allow(clippy::indexing_slicing)] // indices guarded by `i < len`
const _: () = {
    // Forward: every TEA app-entry the resolver recognises must be a
    // `Ipe.Tea.*` shape entry the classifier recognises.
    let mut i = 0;
    while i < TEA_APP_ENTRIES.len() {
        let (q, n) = TEA_APP_ENTRIES[i];
        // IPE-RUST-AUDIT:ACCEPTED — runs during const-eval of this `const`, so it
        // fails the build on table drift and can never panic at runtime.
        assert!(
            shape_entries_tea_has(q, n),
            "shape-table drift: TEA_APP_ENTRIES has an entry with no matching \
             `Ipe.Tea.*` SHAPE_ENTRIES row (by last-path-segment + name). Add the \
             row to crate::shape_source::SHAPE_ENTRIES, or remove the stale TEA_APP_ENTRIES \
             entry.",
        );
        i += 1;
    }
    // Backward: every `Ipe.Tea.*` shape entry must be a TEA app-entry the
    // resolver recognises (non-`Ipe.Tea` rows, e.g. `Ipe.Http.Server`, are
    // excluded by construction — they are not TEA apps).
    let entries = crate::shape_source::SHAPE_ENTRIES;
    let mut j = 0;
    while j < entries.len() {
        let (path, n, _) = entries[j];
        if shape_entry_is_tea(path) && !path.is_empty() {
            let qualifier = path[path.len() - 1];
            // IPE-RUST-AUDIT:ACCEPTED — const-eval build-time proof, never a runtime abort.
            assert!(
                tea_app_entries_has(qualifier, n),
                "shape-table drift: an `Ipe.Tea.*` SHAPE_ENTRIES row has no matching \
                 TEA_APP_ENTRIES entry (by last-path-segment + name). Add the entry \
                 to TEA_APP_ENTRIES, or remove the stale SHAPE_ENTRIES row.",
            );
        }
        j += 1;
    }
};

/// IPE-N0045: reject a `main` that selects its shape at run time.
///
/// A program's shape is pinned by the head of `main` at compile time (§ static
/// pinning): `main = Web.tea …` is a web app, `main = Tui.tea …` a
/// terminal app, a `Task Error ()` `main` a script. It is never chosen from a
/// value, so a `main` whose head — after peeling application / `let` / `\… ->`,
/// exactly as the shape classifier peels it — is an `if` or `case` with a branch
/// that reaches an app entry is a run-time shape choice, refused here.
///
/// Only a branch that reaches a shape entry trips this. A plain program whose
/// `main` is a `Task` computed through an `if` / `case` (no branch heads on an
/// app entry) is a normal script and passes — the branch selects a *value*, not
/// a *shape*. This runs before [`check_program_tea_import_gate`] so a
/// shape-branching `main` gets this precise diagnostic rather than the coarser
/// Program-imports-a-shape one.
///
/// # Errors
/// [`Diagnostic::Name`] (IPE-N0045) at the branching head when `main` selects a
/// shape at run time.
fn check_main_not_runtime_branched(canon_mod: &canon::Module, interner: &Interner) -> DResult<()> {
    let Some(main_sym) = interner.lookup("main") else {
        return Ok(()); // `main` never interned → this module cannot name one.
    };
    let Some(main_def) = canon_mod.defs.iter().find(|d| d.name().value == main_sym) else {
        return Ok(()); // helper module with no `main` — not an entry.
    };
    let body = match main_def {
        canon::Def::Untyped { body, .. } | canon::Def::Typed { body, .. } => body,
    };
    // Peel to the head the shape classifier reads, keeping the located node so a
    // rejection blames the branching head itself.
    let mut node = body;
    loop {
        match &node.value {
            canon::Expr_::Call(callee, _) => node = callee,
            canon::Expr_::Lambda(_, inner) | canon::Expr_::Let(_, inner) => node = inner,
            canon::Expr_::If(arms, else_) => {
                let any_shape = arms
                    .iter()
                    .map(|(_, branch)| branch)
                    .chain(std::iter::once(else_.as_ref()))
                    .any(|branch| branch_head_reaches_tea_entry(branch, interner));
                return if any_shape {
                    Err(Diagnostic::Name {
                        span: node.span,
                        msg: NameError::RuntimeBranchedMain,
                    })
                } else {
                    Ok(())
                };
            }
            canon::Expr_::Case(_, branches) => {
                let any_shape = branches
                    .iter()
                    .any(|b| branch_head_reaches_tea_entry(&b.body, interner));
                return if any_shape {
                    Err(Diagnostic::Name {
                        span: node.span,
                        msg: NameError::RuntimeBranchedMain,
                    })
                } else {
                    Ok(())
                };
            }
            _ => return Ok(()),
        }
    }
}

/// Does a branch of `main`'s `if` / `case` head-reach a TEA app entry?
///
/// Peels the same forms as the shape classifier (application / `let` / `\… ->`)
/// and, for a nested `if` / `case`, recurses into every sub-branch — so
/// `if a then Web.tea c else if b then Cli … else …` is caught at any depth. A
/// branch whose head is a plain expression (a `Task`, a value) reaches no entry
/// and does not, on its own, mark the `main` a shape choice.
fn branch_head_reaches_tea_entry(branch: &canon::Expr, interner: &Interner) -> bool {
    let mut node = branch;
    loop {
        match &node.value {
            canon::Expr_::Call(callee, _) => node = callee,
            canon::Expr_::Lambda(_, inner) | canon::Expr_::Let(_, inner) => node = inner,
            canon::Expr_::If(arms, else_) => {
                return arms
                    .iter()
                    .map(|(_, inner)| inner)
                    .chain(std::iter::once(else_.as_ref()))
                    .any(|inner| branch_head_reaches_tea_entry(inner, interner));
            }
            canon::Expr_::Case(_, sub) => {
                return sub
                    .iter()
                    .any(|b| branch_head_reaches_tea_entry(&b.body, interner));
            }
            canon::Expr_::VarKernel { module, name, .. } => {
                let (Some(m), Some(n)) = (interner.resolve(*module), interner.resolve(*name))
                else {
                    return false;
                };
                return TEA_APP_ENTRIES.contains(&(m, n));
            }
            _ => return false,
        }
    }
}

/// IPE-N0033: reject a Program (plain-`main` module) that imports any
/// `Ipe.Tea.*` shape module.
///
/// The rule is exactly ADR 0005's structural marker: importing anything under
/// `Ipe.Tea.*` marks a module a TEA app. A module is a TEA app iff its `main`
/// head-calls one of [`TEA_APP_ENTRIES`]; every other `main` is a Program. So a
/// module that imports a `Ipe.Tea.*` shape but whose `main` is not a shape entry
/// is a Program-importing-a-shape contradiction, reported at the offending
/// import span. The `Ipe.Ui` / `Ipe.Html` / `Ipe.Css` data + static-render
/// modules are deliberately top-level, so a Program that builds a `Ui` tree and
/// renders it with a `Task` never trips this gate.
///
/// # Errors
/// [`Diagnostic::Name`] (IPE-N0033) when a plain-`main` module imports a
/// `Ipe.Tea.*` shape.
fn check_program_tea_import_gate(
    m: &src::Module,
    canon_mod: &canon::Module,
    interner: &Interner,
) -> DResult<()> {
    // A `Ipe.Tea.*` import: path length ≥ 3 with first two segments Ipe, Tea.
    let (Some(ipe_sym), Some(tea_sym)) = (interner.lookup("Ipe"), interner.lookup("Tea")) else {
        // No `Ipe.Tea` segment interned in this build → no shape can be
        // imported; nothing to gate.
        return Ok(());
    };
    let tea_import = m.imports.iter().find(|imp| {
        // `Ipe.Tea.<Shape>`: at least three segments whose first two are Ipe, Tea.
        matches!(
            imp.name.value.as_slice(),
            [first, second, _, ..]
                if *first == ipe_sym && *second == tea_sym
        )
    });
    let Some(tea_import) = tea_import else {
        return Ok(());
    };

    // The Program/TEA distinction only applies to an ENTRY module — one that
    // defines `main`. A helper submodule with no `main` (e.g. an `Update`
    // module that imports `Ipe.Tea.Web.Cmd` solely to name `Cmd` in `update`'s
    // signature and build `Cmd.none` / `Cmd.batch` effects) is neither a
    // Program nor an app entry, so it is exempt from this gate.
    let main_sym = interner.lookup("main");
    let main_def =
        main_sym.and_then(|main_sym| canon_mod.defs.iter().find(|d| d.name().value == main_sym));
    let Some(main_def) = main_def else {
        return Ok(());
    };

    // The module is a TEA app iff its `main` head-calls a shape entry.
    let main_is_app_entry = {
        let body = match main_def {
            canon::Def::Untyped { body, .. } | canon::Def::Typed { body, .. } => body,
        };
        main_head_is_tea_entry(body, interner)
    };

    if main_is_app_entry {
        return Ok(());
    }

    // A declarative `Ipe.Http.Server` program (`main = Server.listen …`) may
    // legitimately import `Ipe.Tea.Web` to build a mountable web app with
    // `Web.embed` and mount it via `Server.mountApp` on the shared server port
    // (shape-model §9). Such a `main` head-calls `Server.listen`, not a TEA
    // shape entry, so it would otherwise trip this gate; exempt it. The embedded
    // app is a VALUE consumed by the Server, not the module's own app shape.
    if main_head_is_server_listen(
        match main_def {
            canon::Def::Untyped { body, .. } | canon::Def::Typed { body, .. } => body,
        },
        interner,
    ) {
        return Ok(());
    }

    Err(Diagnostic::Name {
        span: tea_import.name.span,
        msg: NameError::ProgramImportsTeaShape {
            module: path_to_dot_string(interner, &tea_import.name.value),
        },
    })
}

/// Does this `main` body head-call `Server.listen` — the declarative
/// `Ipe.Http.Server` entry? Same head-peeling as [`main_head_is_tea_entry`]. A
/// Server program that embeds a web app (`Web.embed` + `Server.mountApp`) is a
/// Program at the module level, not a TEA app, so it is exempt from the
/// `Ipe.Tea.*`-import gate (IPE-N0033).
fn main_head_is_server_listen(body: &canon::Expr, interner: &Interner) -> bool {
    let mut node = body;
    loop {
        match &node.value {
            canon::Expr_::Call(callee, _) => node = callee,
            canon::Expr_::Lambda(_, inner) | canon::Expr_::Let(_, inner) => node = inner,
            canon::Expr_::VarKernel { module, name, .. } => {
                let (Some(m), Some(n)) = (interner.resolve(*module), interner.resolve(*name))
                else {
                    return false;
                };
                return m == "Server" && n == "listen";
            }
            _ => return false,
        }
    }
}

/// Does this `main` body head-call a TEA shape entry ([`TEA_APP_ENTRIES`])?
///
/// Peels the forms a TEA `main` takes — an application `entry { … }`, a
/// point-free `main = \… -> entry …` lambda, and a `let cfg = { … } in entry
/// cfg` — down to the head expression, then checks whether it is a shape-entry
/// `VarKernel`. Only the head matters: a Program's `main` never reduces to a
/// shape-entry kernel at its head. Peeling `let` keeps a let-bound-config app
/// classified as a TEA app so its malformed config reaches the precise
/// `IPE-L0119` lowering diagnostic instead of the coarser IPE-N0033 gate.
fn main_head_is_tea_entry(body: &canon::Expr, interner: &Interner) -> bool {
    let mut node = body;
    loop {
        match &node.value {
            // `entry { cfg }` / `entry a b` — the callee is the head.
            canon::Expr_::Call(callee, _) => node = callee,
            // `main = \req -> entry { cfg }` — the lambda body is the head.
            canon::Expr_::Lambda(_, inner) => node = inner,
            // `main = let cfg = { … } in entry cfg` — the `in` body is the head.
            // A let-bound config is still a TEA-app entry (the head-called shape
            // kernel is under the `in`), so a malformed one reaches its precise
            // `IPE-L0119` lowering diagnostic rather than being misread as a
            // Program under IPE-N0033.
            canon::Expr_::Let(_, body) => node = body,
            canon::Expr_::VarKernel { module, name, .. } => {
                let (Some(m), Some(n)) = (interner.resolve(*module), interner.resolve(*name))
                else {
                    return false;
                };
                return TEA_APP_ENTRIES.contains(&(m, n));
            }
            _ => return false,
        }
    }
}

/// The TEA app surface a `main` proves from its entry kernel.
///
/// A user's `Ipe.Tea.<Shape>.{Cmd,Sub}` import is checked against it by
/// [`AppSurface::admits_cmd_sub_of`]. Returns `None` when `main` is not a
/// shape-entry app — the cross-shape gate then does not apply (a plain-`main`
/// Program importing `Ipe.Tea.*` is already rejected by IPE-N0033).
fn app_shape_name(body: &canon::Expr, interner: &Interner) -> Option<AppSurface> {
    let mut node = body;
    loop {
        match &node.value {
            canon::Expr_::Call(callee, _) => node = callee,
            canon::Expr_::Lambda(_, inner) | canon::Expr_::Let(_, inner) => node = inner,
            canon::Expr_::VarKernel { module, name, .. } => {
                let (m, n) = (interner.resolve(*module)?, interner.resolve(*name)?);
                return TEA_APP_ENTRIES
                    .iter()
                    .find(|(em, en)| *em == m && *en == n)
                    .and_then(|(shape, _member)| AppSurface::from_segment(shape));
            }
            _ => return None,
        }
    }
}

/// IPE-N0035: reject a TEA app that imports another shape's `Cmd` / `Sub`.
///
/// `Cmd` / `Sub` are shape-specific and re-exported per shape under
/// `Ipe.Tea.<Shape>.{Cmd,Sub}`. The app's shape is proven from its entry kernel
/// (`Web.tea` / `Tui.tea` / `Cli.tea`); an imported
/// `Ipe.Tea.<OtherShape>.{Cmd,Sub}` has no denotation in this app and fails
/// closed here, naming the correct import path for the app's own shape.
///
/// Applies only to TEA apps (a proven shape entry). A plain-`main` Program that
/// imports any `Ipe.Tea.*` path — a shape-scoped `Cmd` / `Sub` included — is
/// already the IPE-N0033 contradiction, so this gate never needs to fire there.
///
/// # Errors
/// [`Diagnostic::Name`] (IPE-N0035) at the offending import span.
fn check_cross_shape_cmd_sub_gate(
    m: &src::Module,
    canon_mod: &canon::Module,
    interner: &Interner,
) -> DResult<()> {
    let (Some(ipe_sym), Some(tea_sym)) = (interner.lookup("Ipe"), interner.lookup("Tea")) else {
        return Ok(());
    };
    let (Some(cmd_sym), Some(sub_sym)) = (interner.lookup("Cmd"), interner.lookup("Sub")) else {
        // Neither `Cmd` nor `Sub` interned → no shape-scoped module can be named.
        return Ok(());
    };

    // The app's shape, proven from `main`'s entry kernel. A non-app `main` (no
    // shape entry) leaves this `None`; the gate then does not apply.
    let main_sym = interner.lookup("main");
    let app_shape = main_sym.and_then(|main_sym| {
        canon_mod
            .defs
            .iter()
            .find(|d| d.name().value == main_sym)
            .and_then(|d| {
                let body = match d {
                    canon::Def::Untyped { body, .. } | canon::Def::Typed { body, .. } => body,
                };
                app_shape_name(body, interner)
            })
    });
    let Some(app_shape) = app_shape else {
        return Ok(());
    };

    // The gate compares app SURFACES: `Tui` and `Cli` each own their `Sub`
    // (input subscriptions live there), so neither admits the other's; only the
    // shared `Ipe.Tea.Terminal.{Cmd,Sub}` serves both terminal surfaces.
    for imp in &m.imports {
        // `Ipe.Tea.<Shape>.{Cmd,Sub}`: exactly four segments,
        // `Ipe . Tea . Shape . Cmd|Sub`.
        let [first, second, shape, leaf] = imp.name.value.as_slice() else {
            continue;
        };
        if *first != ipe_sym || *second != tea_sym {
            continue;
        }
        if *leaf != cmd_sym && *leaf != sub_sym {
            continue;
        }
        let Some(imported_shape) = interner.resolve(*shape) else {
            continue;
        };
        if app_shape.admits_cmd_sub_of(imported_shape) {
            continue;
        }
        let leaf_name = if *leaf == cmd_sym { "Cmd" } else { "Sub" };
        let app_name = app_shape.name();
        return Err(Diagnostic::Name {
            span: imp.name.span,
            msg: NameError::WrongShapeCmdSub(Box::new(CmdSubShapeMismatch {
                imported: format!("Ipe.Tea.{imported_shape}.{leaf_name}").into_boxed_str(),
                imported_shape: imported_shape.into(),
                app_shape: app_name.into(),
                expected: format!("Ipe.Tea.{app_name}.{leaf_name}").into_boxed_str(),
            })),
        });
    }
    Ok(())
}

/// The dotted import path a kernel's qualifier is reached through.
///
/// For example `TeaTuiSub` → `Ipe.Tea.Tui.Sub`, from
/// [`crate::env::STDLIB_MODULE_QUALIFIERS`].
fn kernel_module_path(kernel: StdlibKernel) -> Option<String> {
    let qualifier = kernel.decl().qualifier;
    crate::env::STDLIB_MODULE_QUALIFIERS
        .iter()
        .find(|(_, q)| *q == qualifier)
        .map(|(path, _)| path.join("."))
}

/// IPE-N0052: reject terminal input passed as a `Tui.tea` / `Cli.tea` config field.
///
/// The stray field is `onKey` / `onLine`. The entry configs are the canonical four TEA fields (`init` / `update` /
/// `view` / `subscriptions`); input is a subscription (`Tui.Sub.onKey` /
/// `Cli.Sub.onLine`). The closed config row already refuses any extra field at
/// type-check, so this gate is not what keeps the program sound — it turns the
/// generic record mismatch into a diagnostic naming the `Sub` constructor to
/// use. Checks the entry's inline record literal and a same-module top-level
/// binding the entry is applied to.
///
/// # Errors
/// [`Diagnostic::Name`] (IPE-N0052) at the offending field's value.
fn check_input_fields_are_subscriptions(
    canon_mod: &canon::Module,
    interner: &Interner,
) -> DResult<()> {
    let Some(main_sym) = interner.lookup("main") else {
        return Ok(());
    };
    let Some(main_def) = canon_mod.defs.iter().find(|d| d.name().value == main_sym) else {
        return Ok(());
    };
    let body = match main_def {
        canon::Def::Untyped { body, .. } | canon::Def::Typed { body, .. } => body,
    };
    // Peel to the entry call the shape classifier reads.
    let mut node = body;
    let (entry, surface, cfg) = loop {
        match &node.value {
            canon::Expr_::Call(callee, args) => {
                if let canon::Expr_::VarKernel { id: Some(k), .. } = &callee.value
                    && let Some(surface) = k.app_entry_surface()
                    && let [cfg] = args.as_slice()
                {
                    break (*k, surface, cfg);
                }
                node = callee;
            }
            canon::Expr_::Lambda(_, inner) | canon::Expr_::Let(_, inner) => node = inner,
            _ => return Ok(()),
        }
    };
    // The config record: inline, or a same-module top-level binding.
    let fields = match &cfg.value {
        canon::Expr_::Record(fields) => fields,
        canon::Expr_::VarTopLevel { module, name } if *module == canon_mod.name => {
            let Some(def) = canon_mod.defs.iter().find(|d| d.name().value == *name) else {
                return Ok(());
            };
            let def_body = match def {
                canon::Def::Untyped { body, .. } | canon::Def::Typed { body, .. } => body,
            };
            let canon::Expr_::Record(fields) = &def_body.value else {
                return Ok(());
            };
            fields
        }
        _ => return Ok(()),
    };
    // Only this entry's own input subscription names its input field (the other
    // surface's name falls to the closed config row). Every input subscription
    // and its module come from the kernel registry.
    for (field_sym, value) in fields {
        let Some(field) = interner.resolve(*field_sym) else {
            continue;
        };
        let own_input = StdlibKernel::ALL
            .iter()
            .find(|k| k.input_surface() == Some(surface) && k.decl().name == field);
        if let Some(input) = own_input {
            let entry_decl = entry.decl();
            return Err(Diagnostic::Name {
                span: value.span,
                msg: NameError::InputFieldIsSubscription {
                    entry: format!("{}.{}", entry_decl.qualifier, entry_decl.name).into_boxed_str(),
                    field: field.into(),
                    sub_module: kernel_module_path(*input)
                        .unwrap_or_else(|| input.decl().qualifier.to_owned())
                        .into_boxed_str(),
                },
            });
        }
    }
    Ok(())
}

/// IPE-N0047: reject a stdlib import the library single-source-of-truth table
/// does not admit for this module's shape (spec § 5).
///
/// The program's shape is pinned by the head of `main`
/// ([`crate::shape_source::classify_main_shape`]); the placement's runtime is a
/// delivery-time choice not known at resolve for the Web shape. So this gate
/// enforces exactly the SHAPE-FIXED deny rows — a rejection that holds
/// regardless of runtime. The one runtime-specific row (a native effect denied
/// only in the sandboxed `spa` runtime) is enforced downstream by the wasm
/// target gate (IPE-N0029), which knows the resolved runtime; both consult the
/// same [`crate::shape_runtime::allowed_in`] table, so there is one source of
/// truth and no per-site duplication.
///
/// A module is refused here only when [`crate::shape_runtime::allowed_in`] denies
/// it in EVERY runtime the shape can carry (both `live` and `spa` for Web, the
/// sole co-located runtime for every other shape). A denial that holds in one
/// runtime but not the other is left to the runtime-aware gate, so a delivery
/// that would be valid is never rejected at resolve.
///
/// Only USER modules with a `main`-pinned shape are gated; a helper submodule
/// (no `main`) is a `Script` placement by default and carries no shape-render
/// constraint of its own — its imports are gated when the entry that reaches it
/// is resolved.
///
/// # Errors
/// [`Diagnostic::Name`] (IPE-N0047) at the offending import span.
fn check_library_ssot_import_gate(m: &src::Module, interner: &Interner) -> DResult<()> {
    use crate::shape_runtime::{Admissibility, Placement, Runtime, Shape};

    // Only an ENTRY module — one that defines `main` — has a placement to gate.
    // A helper submodule (no `main`) carries no shape/runtime of its own: its
    // shape is not `main`-pinned, and a shape-render or browser-host module it
    // imports is legitimate when the entry that transitively reaches it renders
    // that surface. Gating a helper as a default `script` placement would reject
    // a `Ipe.Browser.*` widget helper reused by a web entry. The entry's own
    // gate — plus the runtime-aware wasm link gate over the whole linked program
    // — cover a helper's imports transitively; here we gate only the entry.
    let Some(main_sym) = interner.lookup("main") else {
        return Ok(()); // `main` never interned → this module defines no entry.
    };
    if !m.values.iter().any(|v| v.value.name.value == main_sym) {
        return Ok(()); // a helper module with no `main` — not an entry.
    }

    let shape = Shape::from_main(crate::shape_source::classify_main_shape(m, interner));

    // The runtimes this shape can carry: Web admits both served and solo, every
    // other shape has its one co-located runtime. A row is enforced here only
    // when it denies in ALL of them (a shape-fixed rejection).
    let runtimes: &[Runtime] = match shape {
        Shape::Web => &[Runtime::Served, Runtime::Solo],
        _ => &[Runtime::Served],
    };

    for import in &m.imports {
        let dot = path_to_dot_string(interner, &import.name.value);
        let class = crate::shape_runtime::classify(&dot);

        // Collect the deny reasons across every runtime this shape can carry.
        // A shape-fixed rejection denies in all of them; the reason is the same
        // in each, so the first suffices for the message.
        let mut denies_everywhere = true;
        let mut first_reason = None;
        for &runtime in runtimes {
            match crate::shape_runtime::allowed_in(class, Placement { shape, runtime }) {
                Admissibility::Allow => {
                    denies_everywhere = false;
                    break;
                }
                Admissibility::Deny(reason) => {
                    first_reason.get_or_insert(reason);
                }
            }
        }

        if !denies_everywhere {
            continue;
        }
        let Some(reason) = first_reason else {
            continue;
        };

        return Err(Diagnostic::Name {
            span: import.name.span,
            msg: NameError::ModuleNotAllowedInPlacement(Box::new(ModulePlacementRejection {
                module: dot,
                placement: placement_phrase(shape, runtimes).into(),
                reason: map_placement_reason(&reason),
            })),
        });
    }
    Ok(())
}

/// The human placement phrase to name in an IPE-N0047 message. For a non-Web
/// shape the phrase is unambiguous (`script` / `terminal` / `worker`; a server
/// is a `script`). For the Web shape a shape-fixed rejection holds in both
/// runtimes, so the bare `web` word names the shape without over-committing to
/// `live` or `spa`.
const fn placement_phrase(
    shape: crate::shape_runtime::Shape,
    _runtimes: &[crate::shape_runtime::Runtime],
) -> &'static str {
    use crate::shape_runtime::Shape;
    match shape {
        Shape::Script => "script",
        Shape::Tui | Shape::Cli => "terminal",
        Shape::Worker => "worker",
        Shape::Web => "web",
    }
}

/// Map a [`crate::shape_runtime::DenyReason`] onto the diagnostic-layer
/// [`ModulePlacementReason`]. The two enums are kept distinct so the placement
/// model (canon) and the message set (diagnostics) each own their vocabulary;
/// this total mapping is the one bridge between them.
const fn map_placement_reason(reason: &crate::shape_runtime::DenyReason) -> ModulePlacementReason {
    use crate::shape_runtime::DenyReason;
    match reason {
        DenyReason::NativeEffectInSandbox => ModulePlacementReason::NativeEffectInSandbox,
        DenyReason::BrowserOutsideBrowserHost { .. } => {
            ModulePlacementReason::BrowserOutsideBrowserHost
        }
    }
}

/// Reject any `Ipe.*` import that names no importable module, at the import
/// span, with IPE-N0020 (`ModuleNotFound`) and a did-you-mean.
///
/// An `Ipe.*` import is importable when it is a kernel stdlib module
/// ([`crate::env::is_kernel_stdlib_module`]) or a compiled-source module the
/// build driver supplied as a dep (`is_known_dep`). Anything else is a typo
/// (`Ipe.Strng`) that must fail closed at the boundary rather than being
/// silently dropped. Suggestions are ranked over the importable-module
/// `catalog` (kernel, compiled-source, and project dot-paths), strings only —
/// never interning.
///
/// Only the project entry (which carries the resolved `deps` universe) can
/// classify a compiled-source `Ipe.*` module, so this runs there. The bare
/// single-module entry injects no deps and cannot distinguish a compiled-source
/// module from a typo, so it does not gate imports.
///
/// # Errors
/// [`NameError::ModuleNotFound`] for an unknown `Ipe.*` import; or
/// [`Diagnostic::CompilerBug`] if interning `Ipe` exhausts the interner.
fn reject_unknown_ipe_import_with_candidates(
    imports: &[src::Import],
    is_known_dep: impl Fn(&[Symbol]) -> bool,
    catalog: &crate::ModuleCatalog,
    interner: &mut Interner,
) -> DResult<()> {
    let ipe_sym = interner.intern("Ipe")?;
    for import in imports {
        let dep_path = &import.name.value;
        if dep_path.first().copied().is_none_or(|s| s != ipe_sym) {
            continue;
        }
        if is_known_dep(dep_path) || crate::env::is_kernel_stdlib_module(dep_path, interner) {
            continue;
        }
        let name = path_to_dot_string(interner, dep_path);
        let sugg = rank_suggestions(&name, catalog.paths());
        return Err(Diagnostic::Name {
            span: import.name.span,
            msg: NameError::ModuleNotFound {
                suggestions: Candidates::at(EditTarget::whole(import.name.span, &name), sugg),
                name,
            },
        });
    }
    Ok(())
}

/// Register user import aliases for stdlib (`Ipê.*` / `Ipe.*`) modules.
///
/// For every stdlib import, resolve its full path to the canonical qualifier
/// (via [`Env::canonical_stdlib_qualifier`]) and register the user's *effective*
/// qualifier — the explicit `as Alias`, else the Elm last-segment default —
/// against the canonical qualifier's kernel members. This is what makes
/// `import Ipe.Json.Encode as Encode` register `Encode` → the `JsonEnc`
/// members, and `import Ipe.Ui as U` register `U` → the `Ui` members.
///
/// Idempotent when the effective qualifier already equals the canonical name
/// (the common `import Ipe.Log as Log` case — `Log` is already registered).
///
/// A path that names no known stdlib module is left unregistered (fail-closed,
/// per [`Env::canonical_stdlib_qualifier`]): any later `Alias.member` reference
/// surfaces the ordinary `UnknownModule` diagnostic at its use site rather than
/// resolving against an invented qualifier. This preserves the pre-existing
/// behaviour for as-yet-unported stdlib modules (e.g. `Ipe.Css`).
///
/// # Errors
/// [`Diagnostic::CompilerBug`] if interning `Ipe` or a canonical name
/// exhausts the interner.
fn register_stdlib_import_aliases(
    imports: &[src::Import],
    env: &mut Env,
    interner: &mut Interner,
) -> DResult<()> {
    let ipe_sym = interner.intern("Ipe")?;
    // Which canonical qualifier each EXPLICIT `as Alias` was registered against,
    // plus the span of the import that first claimed it. Two stdlib imports
    // aliased to one name (`… as J` twice) would otherwise extend-merge member
    // tables last-wins with no diagnostic; this rejects the second with the same
    // DuplicateQualifier the user-dep path raises. Bare imports are absent — a
    // bare import is spoken under its CANONICAL qualifier, so two bare imports
    // that merely share a last path segment (`Ipe.Json.Decode` + `Ipe.Db.Decode`,
    // both segment `Decode`) do not collide and stay legitimate.
    let mut explicit_alias_canonical: BTreeMap<Symbol, (Symbol, Span)> = BTreeMap::new();
    for import in imports {
        let dep_path = &import.name.value;
        // Only `Ipe.*` imports name compiler stdlib modules.
        if dep_path.first().copied().is_none_or(|s| s != ipe_sym) {
            continue;
        }
        let Some(canonical) = env.canonical_stdlib_qualifier(dep_path, interner)? else {
            // Unknown stdlib path: register nothing (fail-closed).
            continue;
        };
        // Elm convention: an explicit `as Alias` names the qualifier, otherwise
        // the module is exposed under the LAST path segment.
        let alias = import
            .alias
            .unwrap_or_else(|| dep_path.last().copied().unwrap_or_else(name_zero));
        if let Some(explicit) = import.alias {
            // Reject an explicit alias already claimed by a prior explicit alias
            // for a DIFFERENT module (`import … as J` twice), or one that names a
            // DIFFERENT stdlib module's canonical qualifier
            // (`import Ipe.Json.Encode as Crypto`). Either way a silent
            // extend-merge would resolve `Alias.member` last-wins across modules
            // with no diagnostic, and aliasing onto a gated canonical would also
            // unlock that canonical's must-import gate. Re-aliasing the same
            // module under the same name stays a no-op.
            if let Some(&(prev_canonical, first)) = explicit_alias_canonical.get(&explicit) {
                if prev_canonical != canonical {
                    return Err(Diagnostic::Name {
                        span: import.name.span,
                        msg: NameError::DuplicateQualifier {
                            qualifier: name_str(interner, explicit)?,
                            first,
                        },
                    });
                }
            } else if explicit != canonical
                && crate::env::is_stdlib_canonical_qualifier(interner, explicit)
            {
                return Err(Diagnostic::Name {
                    span: import.name.span,
                    msg: NameError::DuplicateQualifier {
                        qualifier: name_str(interner, explicit)?,
                        first: import.name.span,
                    },
                });
            }
            explicit_alias_canonical.insert(explicit, (canonical, import.name.span));
        }
        // Tier-C import gate (ADR 0001): this `import Ipe.X [as Alias]` brings the
        // qualifier into scope under the name the user will type. Mark that name
        // (the alias, or — via the fall-through below — the canonical) so a later
        // `Alias.member` / `X.member` resolves instead of raising N0034. An
        // explicit alias that collides with a gated canonical was rejected above,
        // so marking an explicit alias here can never unlock an unrelated gate.
        //
        // A BARE import exposes the module under its last path segment. When that
        // segment equals a DIFFERENT module's gated canonical qualifier
        // (`import Ipe.Http.Stream` → segment `Stream` = server `Stream`'s
        // canonical; `import Ipe.Server.Http` → segment `Http` = client `Http`'s
        // canonical), marking it would unlock the foreign module's privileged
        // kernels with no import of that module — a capability smuggle. Fail
        // closed: skip the mark for that foreign-canonical case. The member-clone
        // below still runs, so the bare import's own members resolve, and its
        // canonical is still marked via the `import.alias.is_none()` branch.
        let alias_is_foreign_gated_canonical = import.alias.is_none()
            && alias != canonical
            && crate::env::is_stdlib_canonical_qualifier(interner, alias);
        if !alias_is_foreign_gated_canonical {
            env.mark_stdlib_qualifier_imported(alias);
        }
        // A bare `import Ipe.X.Y` (no explicit `as`) also names the module under
        // its CANONICAL qualifier — for a dotted-canonical module such as
        // `Ipe.Db.Decode` (canonical `Db.Decode`) that is the multi-segment form
        // the parser produces from `Db.Decode.member`, which no `as` alias can
        // spell. Marking the canonical too keeps `X.Y.member` resolving without an
        // alias. An explicit `as Alias` names a single qualifier on purpose, so it
        // does not pull the canonical into scope.
        if import.alias.is_none() {
            env.mark_stdlib_qualifier_imported(canonical);
        }
        if alias == canonical {
            // Already registered under its canonical name — nothing to clone.
            continue;
        }
        // Clone the canonical qualifier's members under the alias key. The cloned
        // `VarHome::Kernel` entries carry the CANONICAL module + name symbols, so
        // a later `Alias.member` resolves to the same `VarKernel` a canonical
        // reference would (the lowerer's kernel match arms are unaffected).
        if let Some(members) = env.qual_vars.get(&canonical).cloned() {
            std::rc::Rc::make_mut(&mut env.qual_vars)
                .entry(alias)
                .or_default()
                .extend(members);
        }
    }
    Ok(())
}

/// Bind the bare names a stdlib kernel-module import brings into scope.
///
/// A kernel module (`Ipe.List`, `Ipe.Html`, …) has no `deps` entry: its members
/// live in the canonical qualifier's tables [`Env::qual_vars`] and
/// [`Env::qual_ctors`], installed by [`Env::initial`]. This is the kernel
/// counterpart of [`inject_dep_exports`] and binds at the same tiers:
///
/// * `exposing (..)` binds every value member at [`Tier::Open`].
/// * `exposing (name, …)` binds each named value at [`Tier::Explicit`]. A
///   lowercase name that is not a value member of the module is
///   [`NameError::NameNotExposed`], never an invented binding.
/// * `exposing (Type(..))` or `Type(A, …)` binds the constructors the filter
///   admits of a built-in union with a qualified home (`HttpMethod`'s
///   `Get`/`Post`) at [`Tier::Explicit`]. Those constructors are otherwise
///   reachable only qualified (`Http.Post`), so a bare `Post` with no import
///   never shadows a user constructor.
///
/// Each binding is cloned verbatim from the qualified table, so a bare use
/// lowers exactly as the qualified `M.member` does. A capitalised type exposure
/// names a kernel-implicit built-in type and binds no value. A path naming no
/// kernel module binds nothing: a compiled-source stdlib module is bound by
/// [`inject_dep_exports`], and an unknown `Ipe.*` path was already refused.
///
/// # Errors
/// [`NameError::NameNotExposed`]; [`NameError::AmbiguousImport`] for an explicit
/// name another explicit import already binds to a different definition; or
/// [`Diagnostic::CompilerBug`] if interning exhausts the interner.
fn bind_stdlib_kernel_import(
    import: &src::Import,
    env: &mut Env,
    interner: &mut Interner,
) -> DResult<()> {
    let dep_path = &import.name.value;
    let ipe_sym = interner.intern("Ipe")?;
    // Only `Ipê.*` / `Ipe.*` imports name compiler stdlib modules.
    if dep_path.first().copied().is_none_or(|s| s != ipe_sym) {
        return Ok(());
    }
    let Some(canonical) = env.canonical_stdlib_qualifier(dep_path, interner)? else {
        return Ok(());
    };
    let members: Vec<(Symbol, VarHome)> = env
        .qual_vars
        .get(&canonical)
        .map(|members| members.iter().map(|(&n, h)| (n, h.clone())).collect())
        .unwrap_or_default();
    match &import.exposing.value {
        src::Exposing::All => {
            for (name, home) in members {
                let identity = value_identity(&home, name)?;
                let origin = imported(
                    ExprTarget::Value(home),
                    identity,
                    dep_path,
                    import.name.span,
                );
                bind_expr(env, name, Tier::Open, origin, interner)?;
            }
        }
        src::Exposing::List(items) => {
            for item in items {
                match &item.value {
                    src::Exposed::Value(name) => {
                        let name = *name;
                        let Some(home) = members
                            .iter()
                            .find(|(n, _)| *n == name)
                            .map(|(_, h)| h.clone())
                        else {
                            let name_s = name_str(interner, name)?;
                            return Err(Diagnostic::Name {
                                span: item.span,
                                msg: NameError::NameNotExposed {
                                    module: path_to_dot_string(interner, dep_path),
                                    name: name_s.clone(),
                                    suggestions: Candidates::at(
                                        EditTarget::whole(item.span, &name_s),
                                        suggestions(
                                            name,
                                            members.iter().map(|(n, _)| *n),
                                            interner,
                                        ),
                                    ),
                                },
                            });
                        };
                        let identity = value_identity(&home, name)?;
                        let origin =
                            imported(ExprTarget::Value(home), identity, dep_path, item.span);
                        bind_expr(env, name, Tier::Explicit, origin, interner)?;
                    }
                    src::Exposed::Type(type_name, privacy) => {
                        let filter = exposed_ctor_filter(privacy);
                        let ctors: Vec<CtorHome> = env
                            .qual_ctors
                            .get(&canonical)
                            .map(|ctors| {
                                ctors
                                    .values()
                                    .filter(|c| c.type_name == *type_name && filter.admits(c.name))
                                    .cloned()
                                    .collect()
                            })
                            .unwrap_or_default();
                        for ctor in ctors {
                            let name = ctor.name;
                            let origin = imported(
                                ExprTarget::Ctor(ctor.clone()),
                                ctor_identity(&ctor),
                                dep_path,
                                item.span,
                            );
                            bind_expr(env, name, Tier::Explicit, origin, interner)?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// The module-level identity of a value bound at `home`.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] for a lexical home, which never binds at module level.
fn value_identity(home: &VarHome, name: Symbol) -> DResult<Identity> {
    ValueIdentity::of(home, name)
        .map(Identity::Value)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_canon::value_identity",
            detail: "a module-level value carries a lexical home".into(),
        })
}

/// The defining identity of a constructor: its type's home and name.
fn ctor_identity(ctor: &CtorHome) -> Identity {
    Identity::Ctor(CtorIdentity {
        home: ctor.home.clone(),
        type_name: ctor.type_name,
    })
}

/// An import binding reached through `importer`, introduced at `span`.
fn imported<T>(target: T, identity: Identity, importer: &[Symbol], span: Span) -> Origin<T> {
    Origin {
        target,
        identity,
        importers: BTreeSet::from([importer.to_vec()]),
        span,
    }
}

/// A binding declared in the module being canonicalised, at `span`.
const fn declared<T>(target: T, identity: Identity, span: Span) -> Origin<T> {
    Origin {
        target,
        identity,
        importers: BTreeSet::new(),
        span,
    }
}

/// The importing module paths, rendered for a diagnostic.
fn importer_names(importers: &BTreeSet<Vec<Symbol>>, interner: &Interner) -> SortedNames {
    SortedNames::new(importers.iter().map(|p| path_to_dot_string(interner, p)))
}

/// The duplicate-declaration error for an expression-namespace name.
const fn duplicate_expr(is_ctor: bool, name: Box<str>, first: Span) -> NameError {
    if is_ctor {
        NameError::DuplicateConstructor { name, first }
    } else {
        NameError::DuplicateValue { name, first }
    }
}

/// Bind a bare value or constructor name at `tier`, refusing a clash.
///
/// - Two explicit imports of different definitions are IPE-N0024 at the later
///   import, naming every importing module.
/// - Two local declarations are IPE-N0010 (value) or IPE-N0011 (constructor)
///   at the later one.
/// - A local declaration spelling an explicitly imported name is refused at the
///   declaration with the same code, `first` pointing at the import item.
///
/// # Errors
/// The clash's [`Diagnostic::Name`]; [`Diagnostic::CompilerBug`] if a name
/// symbol is not interned.
fn bind_expr(
    env: &mut Env,
    name: Symbol,
    tier: Tier,
    origin: Origin<ExprTarget>,
    interner: &Interner,
) -> DResult<()> {
    let span = origin.span;
    let is_ctor = matches!(origin.target, ExprTarget::Ctor(_));
    let mut importers = origin.importers.clone();
    let Err(clash) = Rc::make_mut(&mut env.module_scope)
        .expr
        .bind(name, tier, origin)
    else {
        return Ok(());
    };
    let name_s = name_str(interner, name)?;
    let (span, msg) = match clash {
        Clash::SameTier { .. } if tier == Tier::Explicit => {
            if let Resolved::Found(prior, _) = env.module_scope.expr.resolve(name) {
                importers.extend(prior.importers.iter().cloned());
            }
            let modules = importer_names(&importers, interner);
            (
                span,
                NameError::AmbiguousImport {
                    name: name_s,
                    modules,
                },
            )
        }
        Clash::SameTier { first } => (span, duplicate_expr(is_ctor, name_s, first)),
        Clash::LocalOverExplicit { local, import } => {
            (local, duplicate_expr(is_ctor, name_s, import))
        }
    };
    Err(Diagnostic::Name { span, msg })
}

/// Bind a bare union or alias name at `tier`, refusing a clash.
///
/// Two explicit imports of different definitions, two local declarations, and
/// a local declaration spelling an explicitly imported type are each IPE-N0012:
/// at the later binding, or at the local declaration with `first` pointing at
/// the import item.
///
/// # Errors
/// [`NameError::DuplicateType`]; [`Diagnostic::CompilerBug`] if a name symbol
/// is not interned.
fn bind_type(
    env: &mut Env,
    name: Symbol,
    tier: Tier,
    origin: Origin<ScopeType>,
    interner: &Interner,
) -> DResult<()> {
    let span = origin.span;
    let Err(clash) = Rc::make_mut(&mut env.module_scope)
        .ty
        .bind(name, tier, origin)
    else {
        return Ok(());
    };
    let (span, first) = match clash {
        Clash::SameTier { first } => (span, first),
        Clash::LocalOverExplicit { local, import } => (local, import),
    };
    Err(Diagnostic::Name {
        span,
        msg: NameError::DuplicateType {
            name: name_str(interner, name)?,
            first,
        },
    })
}

/// Which of a type's constructors an `exposing` clause opens into unqualified
/// scope. Derived once from a [`src::Privacy`] by [`exposed_ctor_filter`] so both
/// the built-in and user-dep injectors select the same set by construction: a
/// `Type(A, B)` subset opens exactly `A`/`B`, never a withheld sibling.
enum CtorFilter {
    /// `Type(..)` — every constructor of the type.
    All,
    /// `Type(A, B)` — only the named constructors.
    Only(BTreeSet<Symbol>),
    /// `Type` (opaque) — no constructors.
    None,
}

impl CtorFilter {
    /// Whether the constructor named `ctor` is opened by this filter.
    fn admits(&self, ctor: Symbol) -> bool {
        match self {
            Self::All => true,
            Self::Only(set) => set.contains(&ctor),
            Self::None => false,
        }
    }
}

/// The constructor filter an `exposing` privacy opens. Fail-closed: an opaque
/// exposure admits nothing; a subset admits only the named constructors.
fn exposed_ctor_filter(privacy: &src::Privacy) -> CtorFilter {
    match privacy {
        src::Privacy::Public => CtorFilter::All,
        src::Privacy::Private => CtorFilter::None,
        src::Privacy::PublicCtors(names) => CtorFilter::Only(names.iter().copied().collect()),
    }
}

/// Builtin type names whose lowering (`ipe_lower::ir_type_from_{ty,canon}`)
/// disambiguates by the `home` path — `Attribute` exists in BOTH `Ipe.Ui`
/// (→ `ipe_runtime::ui::element::Attribute`) and `Ipe.Html.Attributes`
/// (→ `ipe_runtime::html::Attribute`), and the lowerer's `is_html = home
/// contains "Html"` check drives the choice. `Event` is listed for the same
/// home-driven precedent (currently single-ctor `html::Event`, so harmless).
/// Every OTHER builtin type is home-insensitive at lowering (its named arm fires
/// on the name string regardless of `home`).
const HOME_SENSITIVE_BUILTIN_TYPES: &[&str] = &["Attribute", "Event"];

/// Record the canonical `["Html"]` `home` for a home-sensitive builtin TYPE
/// (`Attribute` / `Event`) brought UNQUALIFIED into scope via an explicit
/// `import <Html-family> exposing (Attribute, …)` list — the TYPE
/// counterpart of [`bind_stdlib_kernel_import`] (which binds only kernel
/// values and constructors).
///
/// ## Why
///
/// `Attribute` exists in BOTH `Ipe.Ui` (→ `ui::element::Attribute`) and
/// `Ipe.Html.Attributes` (→ `html::Attribute`); the lowerer disambiguates by
/// `is_html = home contains "Html"`. Without this fold, a bare `Attribute`
/// exposed from a stdlib Html module reaches the empty-home sentinel (stdlib
/// imports are skipped by the dep-injection loop), so `is_html` fails and the
/// `Ipe.Web.Head.pairToAttr : (String,String) -> Attribute msg` shape
/// mis-lowers to `ui::element::Attribute` while its `Attr.attribute` body
/// produces `html::Attribute` — an exit-0-then-cargo-fail E0308 SEAL violation.
/// Binding the bare name at the explicit tier with the `["Html"]` home
/// disambiguates it.
///
/// ## Why `["Html"]` and not the full dep path
///
/// The HM constrainer builds the Ipe.Html attribute type as `Ty::Con { module:
/// ["Html"], name: Attribute }` (`constrain.rs` `html_attr`). Recording the full
/// `["Ipe","Html","Attributes"]` would mint a NOMINALLY-DISTINCT `Attribute` that
/// fails to unify with `Html.node`'s parameter (`expected Html.Attribute, found
/// Ipe.Html.Attributes.Attribute`). `["Html"]` matches the constrainer AND
/// satisfies the lowerer's `is_html` check.
///
/// ## Scope and soundness
///
/// * Only names in [`HOME_SENSITIVE_BUILTIN_TYPES`] are touched — a no-op for
///   every home-insensitive builtin.
/// * The QUALIFIED `Attr.Attribute` / `Ui.Attribute` case is handled separately
///   by [`fold_html_stdlib_qualifier_homes`] (keyed on the QUALIFIER, so the two
///   stay distinct); this pass must touch ONLY names exposed UNQUALIFIED, or it
///   would also hijack a qualified `Ui.Attribute` in the same module (whose
///   fallback also reads the bare type namespace) — the exact regression in
///   `26-ui-showcase/RegressionGates.testId : Ui.Attribute msg`.
/// * **Conflict guard.** If the SAME module ALSO brings the Ui `Attribute` type
///   into UNQUALIFIED scope (`import Ipe.Ui … exposing (Attribute)` or `exposing
///   (..)`), a bare `Attribute` is genuinely ambiguous, so we record NOTHING and
///   leave the sentinel rather than silently pinning one home.
/// * Runs BEFORE any value body is canonicalised.
/// * A LOCAL `type Attribute` is already rejected by
///   `reject_reserved_builtin_type` (IPE-N0026). A name a local declaration or
///   an explicit import already binds is left as it is, and binding the same
///   `["Html"]` home twice is one binding.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] if interning `Html` exhausts the interner.
fn inject_stdlib_exposed_type_homes(
    m: &src::Module,
    env: &mut Env,
    interner: &mut Interner,
) -> DResult<()> {
    let html_sym = interner.intern("Html")?;

    // Does this module bring the Ui `Attribute` TYPE into UNQUALIFIED scope?
    let ui_exposes_attribute = m.imports.iter().any(|import| {
        let dep = &import.name.value;
        // Exactly `Ipe.Ui` (owner of the Ui `Attribute`), not a `Ipe.Ui.*`
        // sub-module (which does not re-export it).
        let is_std_ui = dep.len() == 2
            && dep
                .first()
                .copied()
                .is_some_and(|s| interner.resolve(s) == Some("Ipe"))
            && dep
                .get(1)
                .copied()
                .is_some_and(|s| interner.resolve(s) == Some("Ui"));
        if !is_std_ui {
            return false;
        }
        match &import.exposing.value {
            src::Exposing::All => true,
            src::Exposing::List(items) => items.iter().any(|item| {
                matches!(&item.value, src::Exposed::Type(n, _)
                    if interner.resolve(*n) == Some("Attribute"))
            }),
        }
    });
    if ui_exposes_attribute {
        return Ok(());
    }

    // The module's OWN home-sensitive builtin type exposure. A compiled-source
    // Html-family module (`Ipe.Html.Attributes`) writes its builders'
    // signatures over the bare `Attribute` it defines; without recording the
    // `["Html"]` home here, that bare `Attribute` reaches the empty-home
    // sentinel and mis-lowers to `ui::element::Attribute` while the body
    // produces `html::Attribute` — a cargo-fail E0308. Keyed on the module's own
    // Html-family name + its `module … exposing` list, mirroring the import case.
    let self_is_html_family = m
        .name
        .value
        .iter()
        .any(|s| interner.resolve(*s) == Some("Html"));
    if self_is_html_family && let src::Exposing::List(items) = &m.exposing.value {
        for item in items {
            let src::Exposed::Type(type_name, _privacy) = &item.value else {
                continue;
            };
            let Some(resolved) = interner.resolve(*type_name) else {
                continue;
            };
            if !HOME_SENSITIVE_BUILTIN_TYPES.contains(&resolved) {
                continue;
            }
            bind_html_type_home(env, *type_name, html_sym, &[], item.span, interner)?;
        }
    }

    for import in &m.imports {
        let src::Exposing::List(items) = &import.exposing.value else {
            continue;
        };
        let is_html_family = import
            .name
            .value
            .iter()
            .any(|s| interner.resolve(*s) == Some("Html"));
        if !is_html_family {
            continue;
        }
        for item in items {
            let src::Exposed::Type(type_name, _privacy) = &item.value else {
                continue;
            };
            let Some(resolved) = interner.resolve(*type_name) else {
                continue;
            };
            if !HOME_SENSITIVE_BUILTIN_TYPES.contains(&resolved) {
                continue;
            }
            bind_html_type_home(
                env,
                *type_name,
                html_sym,
                &import.name.value,
                item.span,
                interner,
            )?;
        }
    }
    Ok(())
}

/// Bind a home-sensitive builtin type at the explicit tier under the `["Html"]`
/// home, unless a local declaration or an explicit import already binds it.
///
/// An empty `importer` is the module's own `exposing` list.
///
/// # Errors
/// [`NameError::DuplicateType`] is unreachable past the guard;
/// [`Diagnostic::CompilerBug`] if a name symbol is not interned.
fn bind_html_type_home(
    env: &mut Env,
    name: Symbol,
    html_sym: Symbol,
    importer: &[Symbol],
    span: Span,
    interner: &Interner,
) -> DResult<()> {
    if env.module_scope.ty.eager_bound(name) {
        return Ok(());
    }
    let home = vec![html_sym];
    let importers = if importer.is_empty() {
        BTreeSet::new()
    } else {
        BTreeSet::from([importer.to_vec()])
    };
    let origin = Origin {
        target: ScopeType::Union(home.clone()),
        identity: Identity::Type(home),
        importers,
        span,
    };
    bind_type(env, name, Tier::Explicit, origin, interner)
}

/// Fold each Html-family STDLIB import qualifier into `qualifier_paths`, mapping
/// it to the canonical `["Html"]` type home.
///
/// Stdlib kernel imports are skipped by the ordinary `qualifier_paths`
/// construction (they carry no `deps` entry), so a QUALIFIED `Attr.Attribute`
/// (from `import Ipe.Html.Attributes as Attr`) would fall through to the
/// bare `Attribute` type binding — a single binding that cannot tell
/// `Attr.Attribute` (Html) from `Ui.Attribute` (Ui), so both mis-lowered to the
/// same newtype. Registering the qualifier here — `Attr` (and the canonical
/// `Html`) → `["Html"]` — makes the `TType` arm resolve `Attr.Attribute` to the
/// `html::Attribute` home directly, while `Ui.Attribute` (Ui-family qualifier,
/// deliberately NOT folded) keeps falling through to the empty Ui sentinel.
///
/// The `["Html"]` value is the SAME single-segment home the HM constrainer uses
/// for the Ipe.Html attribute type (`constrain.rs` `html_attr`), so the emitted
/// type unifies with `Html.node`'s parameter rather than minting a distinct
/// `Ipe.Html.Attributes.Attribute`.
///
/// An Html-family qualifier resolves to `["Html"]` even when the same qualifier
/// was already bound to the compiled-source `Ipe.Html.Attributes` dep path: a
/// qualified `Attr.Attribute` type ref must lower to the `html::Attribute` home
/// the HM constrainer and the lowerer's `is_html` check both expect. Forcing
/// `["Html"]` here (over the just-inserted `["Ipe","Html","Attributes"]` dep
/// path) is the qualified-type counterpart of the `["Html"]` builtin home
/// recorded in `build_module_exports`.
///
/// The force-home is a per-qualifier sentinel, but its authority is name-scoped
/// at the `TType` consumer: it homes only the reserved builtin view-type NAMES
/// (`Attribute`/`Html`). A compiled-source ADT declared in `Ipe.Html.Attributes`
/// (e.g. `Attr.LinkTarget`) is not a reserved builtin, so the consumer keeps its
/// real `["Ipe","Html","Attributes"]` home rather than this
/// `["Html"]` sentinel. Value members are likewise unaffected — they resolve
/// through the compiled-source module, not `qualifier_paths`.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] if interning `Html` exhausts the interner.
fn fold_html_stdlib_qualifier_homes(
    imports: &[src::Import],
    qualifier_paths: &mut BTreeMap<Symbol, Vec<Symbol>>,
    interner: &mut Interner,
) -> DResult<()> {
    let html_sym = interner.intern("Html")?;
    for import in imports {
        let dep_path = &import.name.value;
        let is_html_family = dep_path
            .iter()
            .any(|s| interner.resolve(*s) == Some("Html"));
        if !is_html_family {
            continue;
        }
        // Effective qualifier: explicit `as Alias`, else the Elm last-segment
        // default (`import Ipe.Html.Attributes` → `Attributes`).
        let qualifier = import
            .alias
            .unwrap_or_else(|| dep_path.last().copied().unwrap_or_else(name_zero));
        // Register the qualifier's REAL dep path (or the bare `["Html"]` builtin
        // home for a builtin-only module such as `Ipe.Html` that carries no
        // compiled source). The `TType` consumer force-homes the builtin
        // view-type NAMES (`Attribute`/`Html`) to `["Html"]` when the qualifier
        // is Html-family, so `Attr.Attribute` lowers to `html::Attribute` while a
        // compiled-source ADT (`Attr.LinkTarget`) keeps this real module home. A
        // stdlib kernel import carries no user-dep `qualifier_paths` entry, so
        // this fill is what makes an Html-family qualifier resolvable at all.
        let is_stdlib_html = matches!(
            dep_path.first().and_then(|s| interner.resolve(*s)),
            Some("Ipe")
        );
        let home = if dep_path.len() > 1 {
            dep_path.clone()
        } else {
            vec![html_sym]
        };
        if is_stdlib_html {
            qualifier_paths.insert(qualifier, home);
        } else {
            qualifier_paths.entry(qualifier).or_insert(home);
        }
    }
    Ok(())
}

/// The canonical module, its kernel aliases, and its own aliases resolved in its scope.
type CanonicalisedModule = (
    canon::Module,
    BTreeMap<Symbol, KernelAlias>,
    BTreeMap<Symbol, crate::ExportedAlias>,
);

/// Shared resolution body used by both [`canonicalise`] and
/// [`canonicalise_module`].
///
/// Both callers provide a pre-initialised `env` whose module scope already
/// binds every imported name, and the dependency aliases reachable as `Q.Name`.
/// This function:
///
/// 1. Binds this module's own union types and constructors at the local tier.
/// 2. Binds this module's own `type alias` declarations at the local tier and
///    resolves each own alias body once, in this module's scope.
/// 3. Canonicalises constructor payload field types (second union pass).
/// 4. Binds top-level value names at the local tier.
/// 5. Canonicalises each value declaration body.
///
/// A local declaration spelling a name an explicit import already binds, in the
/// same namespace, is refused at the declaration.
///
/// # Errors
/// Same set as [`canonicalise`].
// A linear resolution pipeline (register types → collect aliases → synthesize
// record-alias ctors → register values → canonicalise bodies); splitting the
// stages into separate functions would thread the same resolution context
// through each and obscure the ordering the stages depend on.
#[allow(clippy::too_many_lines)]
fn canonicalise_with_env(
    m: &src::Module,
    env: &mut Env,
    qualifier_paths: &BTreeMap<Symbol, Vec<Symbol>>,
    qualified_aliases: &QualifiedAliases,
    origin: ModuleOrigin,
    interner: &mut Interner,
) -> DResult<CanonicalisedModule> {
    let home = env.home.clone();

    // Import-derived `unsafe` disclosure: does this module reach for a trust-escape
    // hatch by importing an `Ipe.<M>.Unsafe` submodule? Computed here, where the
    // source import list is still present (it is dropped from the canonical module),
    // and carried on the canonical module so the lowerer can thread it to the
    // whole-program capability scan.
    let imports_unsafe_submodule = imports_an_unsafe_submodule(&m.imports, interner);

    // Import-derived web-capability disclosure: which reserved `Ipe.Browser.<Api>`
    // submodules did this module import? The same reviewable-import discipline as
    // the `unsafe` fact above, computed here where the source import list survives.
    let imported_web_capabilities = imported_web_capabilities_of(&m.imports, interner);

    // The `"any"` wildcard symbol used to arity-fill a bare builtin parametric
    // UI annotation (`view : Html` → `view : Html any`). Interned once here where
    // the interner is mutable; the deeper `canonicalise_type` TType arm runs under
    // an immutable `&Interner` and threads this symbol via `TypeCtx`.
    let ui_wildcard_msg = interner.intern("any")?;

    // Bind this module's own unions and their constructors at the local tier,
    // rejecting a duplicate type or constructor name, and a name an explicit
    // import already binds. The canonical `canon::Union` records (with their
    // canonicalised payload field types) are built in a second pass below, once
    // type aliases are bound — a field type may reference an alias.
    for u in &m.unions {
        let type_name = u.value.name.value;
        let type_span = u.value.name.span;
        // IPE-N0026: reject a user type whose name shadows a reserved built-in
        // before it can silently override the lowerer's builtin-name mapping.
        reject_reserved_builtin_type(type_name, type_span, origin, interner)?;
        let origin = declared(
            ScopeType::Union(home.clone()),
            Identity::Type(home.clone()),
            type_span,
        );
        bind_type(env, type_name, Tier::Local, origin, interner)?;
        register_union(&u.value, &home, env, interner)?;
    }

    // Bind type aliases. Both the non-parametric form (`type alias Count =
    // Int`) and the parametric form (`type alias Pair a = ( a, a )`) are
    // supported: a parametric alias records its declared parameters and is
    // expanded by substituting each use site's type arguments for the parameters
    // in the body. An alias name that collides with a union (or another
    // alias) is a duplicate type name. A local alias body is kept as a source
    // annotation and expanded in place at every use site by `canonicalise_type`;
    // an imported one arrives canonical from its defining module. Either way no
    // later stage ever sees an alias.
    for a in &m.aliases {
        let alias_name = a.value.name.value;
        let alias_span = a.value.name.span;
        // IPE-N0026: `type alias` names are gated the same as `type` names — an
        // alias shadowing a built-in would be silently overridden too.
        reject_reserved_builtin_type(alias_name, alias_span, origin, interner)?;
        let body = AliasBody::Local {
            params: a.value.vars.iter().map(|v| v.value).collect(),
            body: a.value.body.value.clone(),
        };
        let origin = declared(
            ScopeType::Alias(body),
            Identity::Type(home.clone()),
            alias_span,
        );
        bind_type(env, alias_name, Tier::Local, origin, interner)?;
    }

    // Each own alias body resolved once, in this module's scope: the form an
    // importer receives through `ModuleExports::aliases`.
    let own_aliases = resolve_own_aliases(
        m,
        env,
        qualifier_paths,
        qualified_aliases,
        interner,
        ui_wildcard_msg,
    )?;

    // Second union pass: now that aliases are collected, canonicalise every
    // constructor's payload field types (a field may reference an alias or
    // another local union) and build the canonical union records.
    let mut unions = Vec::with_capacity(m.unions.len());
    for u in &m.unions {
        unions.push(canonicalise_union(
            &u.value,
            env,
            qualifier_paths,
            qualified_aliases,
            interner,
            ui_wildcard_msg,
        )?);
    }

    // Synthesize a value-level auto-constructor for every local record type
    // alias (IPE-N0001). Built here — the single site where each alias's
    // source-order fields are known — as an ordinary typed `Def`, so no later
    // stage special-cases it.
    //
    // A user-written top-level value of the same name IS the constructor: an
    // explicit `Profile name age active = { … }` binding SUPPRESSES synthesis of
    // the auto-ctor for `type alias Profile = { … }`, exactly as the upstream
    // Rust emitter's `existingNames` guard skips a synthesized ctor whose name a
    // user function already occupies. The two do NOT collide — the explicit def
    // provides the implementation, the auto-ctor is redundant. Computed here
    // (the sole point over `m.values`) and threaded into synthesis.
    let user_value_names: BTreeSet<Symbol> = m.values.iter().map(|v| v.value.name.value).collect();
    let synth_ctor_defs = synthesize_record_alias_ctors(
        m,
        &home,
        env,
        qualifier_paths,
        qualified_aliases,
        &user_value_names,
        interner,
        ui_wildcard_msg,
    )?;

    // Bind every top-level value name at the local tier so bindings can be
    // referenced before their definition (mutual / forward references),
    // rejecting duplicates. The synthesized record-alias constructors bind
    // first so their names are reserved in the value namespace.
    for d in &synth_ctor_defs {
        let name = d.name();
        let target = VarHome::TopLevel(home.clone());
        let identity = value_identity(&target, name.value)?;
        let origin = declared(ExprTarget::Value(target), identity, name.span);
        bind_expr(env, name.value, Tier::Local, origin, interner)?;
    }
    // Bind the `["Html"]` origin home for a home-sensitive builtin TYPE
    // brought UNQUALIFIED via `import <Html-family> exposing (Attribute)`, so the
    // bare `Attribute msg` annotation lowers to the SAME newtype (`html::Attribute`
    // vs `ui::element::Attribute`) its body produces. Runs before any value body
    // is canonicalised so `resolve_unqualified_type_name` sees the bound home
    // rather than the empty-home sentinel that always mis-selects `UiAttribute`.
    inject_stdlib_exposed_type_homes(m, env, interner)?;
    // Stage-4 kernel aliases discovered in this module: `f = Kernel.kernel "K_n"`.
    // Each is bound as a `VarHome::Kernel` (so every reference — in-module
    // `f` or cross-module `Alias.f` — routes straight to the kernel) and its
    // body is NOT canonicalised into a top-level def (the alias emits no runtime
    // function; it IS the kernel). The map is returned so the project entry can
    // record it on `ModuleExports.kernel_aliases`.
    let mut kernel_aliases: BTreeMap<Symbol, KernelAlias> = BTreeMap::new();
    for v in &m.values {
        let name = v.value.name.value;
        let name_span = v.value.name.span;
        // FAIL-CLOSED (THE SEAL): `detect_kernel_alias` errors when the binding
        // is a kernel alias naming an unregistered kernel — never a silent
        // TopLevel fall-through that would emit a dangling call.
        let alias = detect_kernel_alias(&v.value, env, interner)?;
        let target = alias.as_ref().map_or_else(
            || VarHome::TopLevel(home.clone()),
            |alias| VarHome::Kernel(alias.id, alias.module, alias.function),
        );
        let identity = value_identity(&target, name)?;
        let origin = declared(ExprTarget::Value(target), identity, name_span);
        bind_expr(env, name, Tier::Local, origin, interner)?;
        if let Some(alias) = alias {
            kernel_aliases.insert(name, alias);
        }
    }

    // Build the `Ipe.Codec.auto` derive context (the qualifiers naming the
    // imported `Ipe.Codec` module + the record shape of every annotated witness
    // value), so the derive can recognise `Codec.auto witness` and read the
    // witness's fields at its call site by lookup alone. Built here — the single
    // point where the module's values, aliases, imports, and type context all
    // coexist — and stored on the env, which every value body's resolution clones.
    let codec_auto = build_codec_auto_context(
        m,
        env,
        qualifier_paths,
        qualified_aliases,
        interner,
        ui_wildcard_msg,
    )?;
    env.codec_auto = Rc::new(codec_auto);

    // Canonicalise each value declaration. A kernel alias has no runtime body —
    // it lowers as its kernel at every call site — so it is skipped here, exactly
    // as a kernel-qualifier member is never a compiled def.
    let mut defs = Vec::with_capacity(m.values.len() + synth_ctor_defs.len());
    for v in &m.values {
        if kernel_aliases.contains_key(&v.value.name.value) {
            continue;
        }
        defs.push(canonicalise_value(
            &v.value,
            env,
            qualifier_paths,
            qualified_aliases,
            interner,
            ui_wildcard_msg,
        )?);
    }
    // The synthesized constructor defs are already fully canonical.
    defs.extend(synth_ctor_defs);

    Ok((
        canon::Module {
            name: home,
            unions,
            defs,
            imports_unsafe_submodule,
            imported_web_capabilities,
        },
        kernel_aliases,
        own_aliases,
    ))
}

/// Resolve each of this module's own `type alias` bodies once, in this module's scope.
///
/// The result is what an importer receives: a canonical body whose declared
/// parameters are replaced by [`alias_param_slots`] variables, so expanding it
/// in another module is a substitution over canonical types and never a fresh
/// resolution of source names against the importer's imports. An alias whose
/// body names something this module cannot see is refused here, at its
/// declaration, whether or not any module uses it.
#[allow(clippy::too_many_arguments)] // the resolution context `canonicalise_type` reads
fn resolve_own_aliases(
    m: &src::Module,
    env: &Env,
    qualifier_paths: &BTreeMap<Symbol, Vec<Symbol>>,
    qualified_aliases: &QualifiedAliases,
    interner: &mut Interner,
    ui_wildcard_msg: Symbol,
) -> DResult<BTreeMap<Symbol, crate::ExportedAlias>> {
    let max_params = m
        .aliases
        .iter()
        .map(|a| a.value.vars.len())
        .max()
        .unwrap_or(0);
    let slots = alias_param_slots(max_params, interner)?;
    let interner: &Interner = interner;
    let mut resolved = BTreeMap::new();
    for a in &m.aliases {
        let decl = &a.value;
        let ctx = TypeCtx {
            env,
            qualifier_paths,
            qualified_aliases,
            interner,
            ui_wildcard_msg,
            ann_span: decl.body.span,
        };
        let param_slots: Vec<Symbol> = slots.iter().copied().take(decl.vars.len()).collect();
        let subst: BTreeMap<Symbol, canon::Type> = decl
            .vars
            .iter()
            .map(|v| v.value)
            .zip(param_slots.iter().copied().map(canon::Type::Var))
            .collect();
        let mut free_vars = BTreeSet::new();
        // Seeded with the alias itself, exactly as a use-site expansion pushes
        // it, so a self-reference stops rather than recursing.
        let mut visited = vec![decl.name.value];
        let mut budget = TYPE_EXPANSION_NODE_LIMIT;
        let body = canonicalise_type(
            &decl.body.value,
            &ctx,
            &subst,
            &mut free_vars,
            &mut visited,
            &mut budget,
            0,
        )?;
        resolved.insert(
            decl.name.value,
            crate::ExportedAlias {
                home: env.home.clone(),
                param_slots,
                body,
                free_vars,
                literal_record: matches!(decl.body.value, src::TypeAnnotation::TRecord(_)),
            },
        );
    }
    Ok(resolved)
}

/// The placeholder variables standing for an exported alias's parameters, by position.
///
/// Each name contains spaces, which no source type variable can spell, so a
/// slot never collides with a variable an alias body leaves free.
fn alias_param_slots(count: usize, interner: &mut Interner) -> DResult<Vec<Symbol>> {
    let mut slots = Vec::with_capacity(count);
    for index in 0..count {
        slots.push(interner.intern(&format!("alias param {index}"))?);
    }
    Ok(slots)
}

/// Expand an imported alias at a use site by substituting `args` for its parameter slots.
///
/// The body is already canonical in its defining module, so this is a pure
/// structural substitution: no name is resolved against the importer's scope.
/// Every node spends from the same `budget` and `depth` ceilings as a source
/// expansion, so a body that grows across a chain of modules stays bounded.
///
/// # Errors
/// [`NameError::TypeExpansionTooDeep`] when the expansion exceeds the depth or
/// node ceiling.
fn instantiate_imported_alias(
    body: &canon::Type,
    slots: &BTreeMap<Symbol, canon::Type>,
    ctx: &TypeCtx,
    budget: &mut u32,
    depth: u32,
) -> DResult<canon::Type> {
    spend_expansion_node(ctx, budget, depth)?;
    let next = depth.saturating_add(1);
    Ok(match body {
        canon::Type::Var(v) => match slots.get(v) {
            Some(arg) => copy_substituted_arg(arg, ctx, budget)?,
            None => canon::Type::Var(*v),
        },
        canon::Type::Unit => canon::Type::Unit,
        canon::Type::Lambda(a, b) => canon::Type::Lambda(
            Box::new(instantiate_imported_alias(a, slots, ctx, budget, next)?),
            Box::new(instantiate_imported_alias(b, slots, ctx, budget, next)?),
        ),
        canon::Type::Con { home, name, args } => {
            let mut can_args = Vec::with_capacity(args.len());
            for a in args {
                can_args.push(instantiate_imported_alias(a, slots, ctx, budget, next)?);
            }
            canon::Type::Con {
                home: home.clone(),
                name: *name,
                args: can_args,
            }
        }
        canon::Type::Tuple(elems) => {
            let mut can_elems = Vec::with_capacity(elems.len());
            for e in elems {
                can_elems.push(instantiate_imported_alias(e, slots, ctx, budget, next)?);
            }
            canon::Type::Tuple(can_elems)
        }
        canon::Type::Record(fields) => {
            canon::Type::Record(instantiate_fields(fields, slots, ctx, budget, next)?)
        }
        // The row variable is kept as declared, matching a source expansion,
        // which never substitutes an open record's row variable.
        canon::Type::RecordOpen(row, fields) => {
            canon::Type::RecordOpen(*row, instantiate_fields(fields, slots, ctx, budget, next)?)
        }
    })
}

/// Substitute parameter slots through each field type of a record body.
fn instantiate_fields(
    fields: &[(Symbol, canon::Type)],
    slots: &BTreeMap<Symbol, canon::Type>,
    ctx: &TypeCtx,
    budget: &mut u32,
    depth: u32,
) -> DResult<Vec<(Symbol, canon::Type)>> {
    let mut out = Vec::with_capacity(fields.len());
    for (name, ty) in fields {
        out.push((
            *name,
            instantiate_imported_alias(ty, slots, ctx, budget, depth)?,
        ));
    }
    Ok(out)
}

/// Does any `import` name an `Ipe.<M>.Unsafe` submodule?
///
/// The signal for the `unsafe` capability: a dotted import whose FIRST segment is
/// `Ipe` and whose LAST segment is `Unsafe`, with a module segment between them
/// (path length ≥ 3, e.g. `Ipe.Html.Unsafe`, `Ipe.Db.Unsafe`). A user file
/// literally named `Ipe.Db.Unsafe` cannot be imported — it is rejected at
/// discovery as `User` origin (IPE-N0025) — so a matching import can only name a
/// vouched `EmbeddedStdlib` submodule. Mirrors the `Ipe.Tea.*` import-shape
/// check: a segment-slice pattern, no string allocation on the hot path.
/// The web capabilities disclosed by a module's reserved `Ipe.Browser.<Api>`
/// imports.
///
/// Walks the same import list `imports_an_unsafe_submodule` walks, resolving each
/// import's canonical path segments and looking them up in the closed
/// [`WebCapability::for_browser_module`] table. Keyed on the canonical path, so a
/// local alias never changes the disclosure, and the reserved `Ipe.Browser.*`
/// namespace cannot be forged by a user file (rejected at discovery as `User`
/// origin), exactly as the `unsafe` submodule rule relies on.
fn imported_web_capabilities_of(
    imports: &[src::Import],
    interner: &Interner,
) -> BTreeSet<WebCapability> {
    let mut set = BTreeSet::new();
    for imp in imports {
        let segments: Vec<&str> = imp
            .name
            .value
            .iter()
            .filter_map(|sym| interner.resolve(*sym))
            .collect();
        // A segment that failed to resolve shortens the slice, so a partial path
        // simply fails to match — fail-closed to "no disclosure from this import",
        // never a mis-attributed one.
        if segments.len() == imp.name.value.len()
            && let Some(w) = WebCapability::for_browser_module(&segments)
        {
            set.insert(w);
        }
    }
    set
}

fn imports_an_unsafe_submodule(imports: &[src::Import], interner: &Interner) -> bool {
    let Some((ipe_sym, unsafe_sym)) = interner.lookup("Ipe").zip(interner.lookup("Unsafe")) else {
        // Neither segment interned in this build → no such import can exist.
        return false;
    };
    imports.iter().any(|imp| {
        matches!(
            imp.name.value.as_slice(),
            [first, _, .., last] if *first == ipe_sym && *last == unsafe_sym
        )
    })
}

/// Synthesize the value-level auto-constructor for every LOCAL `type alias`
/// whose declaration body is a *literal* record (IPE-N0001).
///
/// For `type alias T p0..pk = { f0 : A0, …, fN : AN }` this produces the
/// ordinary typed binding
///
/// ```text
/// T : ∀ (used-of p0..pk). A0 -> … -> AN -> { f0:A0, …, fN:AN }
/// T f0 … fN = { f0 = f0, …, fN = fN }
/// ```
///
/// materialised as a [`canon::Def::Typed`] indistinguishable from a hand-written
/// function — every downstream stage (HM, lowering, backend) needs no
/// special-casing and no new IR node. Field order is captured **once** from the
/// source `TRecord` vec and projected into the parameter patterns, the body
/// record literal, and the arrow argument types from a **single** iteration, so
/// positional argument `i` provably binds field `f_i` (there is no structure in
/// which the two orders can disagree).
///
/// Gating (PARSE, DON'T VALIDATE):
/// * Only a **literal** `TRecord` body qualifies. A head alias to a record
///   alias (`type alias U = T`) gets **no** constructor — matching Elm — because
///   its source body is a `TType`, not a `TRecord`.
/// * A non-record alias (`type alias Count = Int`) gets no binding, so using it
///   as a value stays an ordinary `IPE-N0001` name error.
///
/// The result is a **closed** record: this compiler has no row variable, so a
/// missing / extra / mis-typed field is a compile error, never silent
/// acceptance — the constructor opens no row-poly surface.
///
/// # Errors
/// [`NameError::DuplicateValue`] when the alias name already names a data
/// constructor in scope (the value-namespace usage of that name is already
/// taken — rejecting the silent constructor-wins shadow, Elm-faithful).
/// [`Diagnostic::Name`] ([`NameError::AliasArity`] / [`NameError::UnknownModule`])
/// propagated from canonicalising a field type; [`Diagnostic::CompilerBug`] on
/// an un-interned symbol.
/// Built-in opaque boxed-wrapper type constructors — `Decoder` / `Task` / `Cmd`
/// / `Sub`. Each lowers to a runtime type that boxes its payload behind a trait
/// object and derives nothing over that payload, so a function in its type
/// arguments is a legitimate value rather than a non-derivable-derive carrier.
///
/// Mirrors `ipe_lower`'s `is_opaque_boxed_wrapper`
/// (`crates/ipe_lower/src/lower.rs` L151) EXACTLY — the set MUST stay identical
/// so this canon-side synthesis gate and the lowerer's
/// `embeds_nonderivable_function` agree on which record-alias fields carry a
/// buildable constructor. Matched by name only, sound because these are
/// kernel-implicit built-in type constructors a user program cannot redefine.
fn is_opaque_boxed_wrapper_canon(interner: &Interner, name: Symbol) -> bool {
    matches!(
        interner.resolve(name),
        Some("Decoder" | "Task" | "Cmd" | "Sub")
    )
}

/// Could this canonical field type NOT be a field of a
/// `#[derive(Clone, Debug, PartialEq)]` + `impl IpeStringify` struct — i.e. is it
/// non-derivable-as-a-struct-field?
///
/// A synthesised record-alias constructor's body is a record literal, so the
/// backend emits a `#[derive(Clone, Debug, PartialEq)]` struct (plus an
/// `impl IpeStringify`) over the field types. A field whose type satisfies none
/// of those obligations makes the emitted Rust fail to compile. Two disjoint
/// shapes are non-derivable-as-a-struct-field:
///
/// 1. A raw function (`Lambda`) — lowers to `Box<dyn Fn(...) + Send>`, which
///    is `!Clone`, `!Debug`, `!PartialEq`, `!IpeStringify`.
/// 2. An OPAQUE boxed-wrapper VALUE ([`is_opaque_boxed_wrapper_canon`] —
///    `Decoder` / `Task` / `Cmd` / `Sub`). Its runtime representation is a
///    `Box<dyn Fn>` (`Decoder`), a boxed-thunk enum (`IpeCmd` / `IpeSub`), or a
///    `Pin<Box<dyn Future>>` (`IpeTask`) — none of which impl `Clone` / `Debug` /
///    `PartialEq` / `IpeStringify` over their payload.
///
/// # Why this predicate is NOT the lowerer's function-embedding one
///
/// This is deliberately DISTINCT from `ipe_lower`'s `embeds_nonderivable_function`
/// (`crates/ipe_lower/src/lower.rs` L183) — and from this crate's round-1 port
/// `canon_type_embeds_function`, now deleted. That predicate answers a
/// different question: "does a RAW FUNCTION appear anywhere inside this type",
/// and it EXEMPTS an opaque wrapper HEAD (returns `false` and does NOT recurse)
/// because a function nested inside a `Decoder` payload is boxed away — the
/// L0107 concern is a bare function reaching the derive, not a wrapper doing its
/// job.
///
/// That exemption is CORRECT for the lowerer's payload-scan but WRONG for the
/// struct-synthesis decision: an opaque wrapper in FIELD position is ITSELF the
/// non-derivable value, regardless of its payload. `{ dec : Decoder Int }`,
/// `{ cmd : Cmd Msg }` carry no raw function at all, yet the emitted
/// `#[derive(…)]` struct over `Decoder` / `IpeCmd` does not build (ipe accepts
/// it but cargo rejects it — an exit-0-then-cargo-fail seal hole). So here the
/// opaque head SHORT-CIRCUITS to `true` (the flip): the wrapper is non-derivable
/// as a struct field, so the alias must DECLINE synthesis and stay a plain type
/// (no positional constructor). It loses zero capability — such
/// a record is unbuildable-as-a-struct at every real construction/use site
/// regardless — and turns the un-buildable constructor UNREPRESENTABLE at canon
/// rather than emitted-then-cargo-rejected.
///
/// [`is_opaque_boxed_wrapper_canon`]'s SET stays byte-identical to
/// `lower.rs` L151 (`Decoder` / `Task` / `Cmd` / `Sub`); only its ROLE here is
/// flipped (field-position opaque head ⇒ non-derivable, not exempt).
fn field_type_nonderivable(interner: &Interner, t: &canon::Type) -> bool {
    match t {
        canon::Type::Lambda(_, _) => true,
        canon::Type::Con { name, args, .. } => {
            // FLIP vs the lowerer's function-embedding predicate: an opaque
            // boxed-wrapper HEAD in field position is ITSELF non-derivable —
            // short-circuit to `true`, do NOT recurse-into-and-exempt its
            // payload. Otherwise recurse: a carrier (`List`/`Maybe`/`Result`/…)
            // is non-derivable exactly when one of its arguments is.
            is_opaque_boxed_wrapper_canon(interner, *name)
                || args.iter().any(|a| field_type_nonderivable(interner, a))
        }
        canon::Type::Tuple(elems) => elems.iter().any(|e| field_type_nonderivable(interner, e)),
        canon::Type::Record(fields) | canon::Type::RecordOpen(_, fields) => fields
            .iter()
            .any(|(_, f)| field_type_nonderivable(interner, f)),
        canon::Type::Var(_) | canon::Type::Unit => false,
    }
}

// ─── `Ipe.Codec.auto` derive ───────────────────────────────────────
//
// `Codec.auto witness` derives a record codec at compile time by rewriting the
// call into the field-by-field `Codec { enc, mkDec }` a developer could have
// written by hand (the direct form, not the applicative `object`/`field`
// builder, whose generic constructor slot is not `Clone` in emitted Rust —
// IPE-L0107). The rewrite re-enters the ordinary inference → lower → emit path,
// so THE SEAL holds by construction: the derive emits no bespoke Rust, only an
// expression the hand-written direct-form codec already exercises. A witness
// with a non-derivable field is rejected fail-closed (IPE-N0041) at ipe time —
// never an accept-then-cargo-fail.

/// Build the per-module [`CodecAutoContext`] the `auto` recogniser reads: the
/// qualifiers that name the imported `Ipe.Codec` module, and the record shape of
/// every top-level value annotated with a record type.
#[allow(clippy::too_many_arguments)]
fn build_codec_auto_context(
    m: &src::Module,
    env: &Env,
    qualifier_paths: &BTreeMap<Symbol, Vec<Symbol>>,
    qualified_aliases: &QualifiedAliases,
    interner: &mut Interner,
    ui_wildcard_msg: Symbol,
) -> DResult<crate::env::CodecAutoContext> {
    // Qualifiers bound to `Ipe.Codec`: any import qualifier whose resolved path
    // is exactly `["Ipe", "Codec"]`. A compiled-source stdlib module is a build
    // dep, so its import registers in `qualifier_paths` like a user module.
    let ipe_seg = interner.intern("Ipe")?;
    let codec_seg = interner.intern("Codec")?;
    let codec_path = [ipe_seg, codec_seg];
    let mut qualifiers: BTreeSet<Symbol> = BTreeSet::new();
    for (&qual, path) in qualifier_paths {
        if path.as_slice() == codec_path {
            qualifiers.insert(qual);
        }
    }
    // The record shape of every value whose annotation is a record type (an
    // inline `{ … }` or a `type alias` naming one). Fields are canonicalised
    // ONCE here, in declared order, exactly as `synthesize_record_alias_ctors`
    // canonicalises an alias's fields — so the derived codec sees the same
    // expanded field types a hand-written codec's annotation would.
    let mut witness_records: BTreeMap<Symbol, Vec<(Symbol, canon::Type)>> = BTreeMap::new();
    for v in &m.values {
        let Some(ann) = &v.value.type_annotation else {
            continue;
        };
        if let Some(fields) = witness_record_fields(
            &ann.value,
            env,
            qualifier_paths,
            qualified_aliases,
            interner,
            ui_wildcard_msg,
            ann.span,
        )? {
            witness_records.insert(v.value.name.value, fields);
        }
    }

    Ok(crate::env::CodecAutoContext {
        qualifiers,
        witness_records,
    })
}

/// Resolve an annotation to a closed record's canonical fields, when it names
/// one. An inline `TRecord` or a `TType` naming a record `type alias` both
/// qualify; anything else is `None` (not a witness the derive can read). A
/// parametric or open record is declined (`None`) — the derive needs concrete,
/// closed field types.
#[allow(clippy::too_many_arguments)]
fn witness_record_fields(
    ann: &src::TypeAnnotation,
    env: &Env,
    qualifier_paths: &BTreeMap<Symbol, Vec<Symbol>>,
    qualified_aliases: &QualifiedAliases,
    interner: &Interner,
    ui_wildcard_msg: Symbol,
    ann_span: Span,
) -> DResult<Option<Vec<(Symbol, canon::Type)>>> {
    let ctx = TypeCtx {
        env,
        qualifier_paths,
        qualified_aliases,
        interner,
        ui_wildcard_msg,
        ann_span,
    };
    // The source-level fields to canonicalise, and the alias name (if any) to
    // seed `visited` for a self-referential field — mirroring the alias-ctor
    // synthesis, so the two expand a record annotation identically.
    let (src_fields, seed): (&Vec<(Located<Symbol>, src::TypeAnnotation)>, Vec<Symbol>) = match ann
    {
        src::TypeAnnotation::TRecord(fields) => (fields, Vec::new()),
        src::TypeAnnotation::TType(qualifier, segments, args) if args.is_empty() => {
            let Some(name) = segments.last().copied() else {
                return Ok(None);
            };
            // The same resolution `canonicalise_type` expands through: a bare
            // witness takes the one precedence ladder, and a qualified witness
            // reads the qualifier's alias, never a same-named local one.
            let qualifier =
                resolve_or_bug(interner, *qualifier, "ipe_canon::witness_record_fields")?;
            let alias = if qualifier.is_empty() {
                match resolve_unqualified_type_name(name, &ctx, &[])? {
                    TypeName::Alias(alias) => Some((name, alias)),
                    TypeName::Union(_)
                    | TypeName::Ambiguous { .. }
                    | TypeName::Builtin
                    | TypeName::Missing => None,
                }
            } else {
                alias_lookup_key(qualifier, name, qualified_aliases, interner)?.and_then(|key| {
                    qualified_aliases
                        .get(&key)
                        .map(|exported| (key, ResolvedAlias::Imported(exported)))
                })
            };
            match alias {
                Some((
                    alias_key,
                    ResolvedAlias::Local {
                        params: [],
                        body: src::TypeAnnotation::TRecord(fields),
                    },
                )) => (fields, vec![alias_key]),
                // An imported record alias is already canonical in its
                // defining module's scope; its fields are the witness as-is.
                Some((_, ResolvedAlias::Imported(exported)))
                    if exported.param_slots.is_empty() && exported.literal_record =>
                {
                    let canon::Type::Record(fields) = &exported.body else {
                        return Ok(None);
                    };
                    return Ok(Some(fields.clone()));
                }
                Some((_, ResolvedAlias::Local { .. } | ResolvedAlias::Imported(_))) | None => {
                    return Ok(None);
                }
            }
        }
        _ => return Ok(None),
    };
    let subst = BTreeMap::new();
    let mut free_set = BTreeSet::new();
    let mut visited = seed;
    let mut can_fields = Vec::with_capacity(src_fields.len());
    for (fname, fty) in src_fields {
        let mut budget = TYPE_EXPANSION_NODE_LIMIT;
        let cty = canonicalise_type(
            fty,
            &ctx,
            &subst,
            &mut free_set,
            &mut visited,
            &mut budget,
            0,
        )?;
        can_fields.push((fname.value, cty));
    }
    Ok(Some(can_fields))
}

/// Recognise `<Codec>.auto witness` at a call site and rewrite it into the
/// derived codec. `Ok(None)` when the call is not a codec derive, so ordinary
/// resolution proceeds unchanged.
fn canonicalise_codec_auto(
    callee: &src::Expr,
    args: &[src::Expr],
    span: Span,
    env: &Env,
    interner: &mut Interner,
) -> DResult<Option<canon::Expr_>> {
    let src::Expr_::VarQual(qualifier, member) = &callee.value else {
        return Ok(None);
    };
    if env.codec_auto.qualifiers.is_empty() || !env.codec_auto.qualifiers.contains(qualifier) {
        return Ok(None);
    }
    if interner.resolve(*member) != Some("auto") {
        return Ok(None);
    }

    let reject = |reason: CodecAutoRejection, field: &str| Diagnostic::Name {
        span,
        msg: NameError::CodecAutoUnderivable {
            reason,
            field: field.into(),
        },
    };

    // Exactly one witness argument, a bare reference to a top-level value.
    let [witness] = args else {
        return Err(reject(CodecAutoRejection::ArityMismatch, ""));
    };
    let witness_name = match &witness.value {
        src::Expr_::VarLocal(name) | src::Expr_::VarQual(_, name) => *name,
        _ => return Err(reject(CodecAutoRejection::WitnessNotRecordValue, "")),
    };
    let Some(fields) = env.codec_auto.witness_records.get(&witness_name) else {
        return Err(reject(CodecAutoRejection::WitnessNotRecordValue, ""));
    };

    // Inference records one type per node span; lower reads it back the same way.
    // Every synthesised node therefore needs its OWN span — sharing the call span
    // across the many nodes the derive mints would collapse them to one region
    // entry and mislower. `SynSpan` hands out fresh, unique spans in a high byte
    // range that no real source offset reaches, seeded from the call site so two
    // `auto` calls in one module never overlap.
    let mut sg = SynSpan::seeded(span);
    derive_record_codec(fields, &mut sg, env, interner).map(Some)
}

/// A generator of unique synthetic spans for the nodes a canon rewrite mints.
///
/// Inference keys `SolvedTypes::regions` by `(module, node.span)`, so two
/// synthesised nodes sharing a span collide (only one type survives) and lower
/// then reads the wrong arrow shape. Each fresh span is a distinct, zero-content
/// byte range placed above `SYN_SPAN_BASE` — beyond any real file's length — so
/// it cannot alias a source span. A per-call seed keeps distinct `auto` sites in
/// disjoint ranges.
struct SynSpan {
    next: u32,
    /// The real call-site span, used only as the location of a fail-closed
    /// diagnostic (synthetic node spans are content-free and point at nothing).
    diag: Span,
}

/// The floor for synthetic spans — above any plausible source-file byte length,
/// so a synthetic span never collides with a real source offset.
const SYN_SPAN_BASE: u32 = 0xF000_0000;

impl SynSpan {
    const fn seeded(call: Span) -> Self {
        // Offset each call site into its own sub-range (bounded stride, saturating
        // so it can never wrap below the base) to keep multiple derives disjoint.
        let seed = SYN_SPAN_BASE.saturating_add((call.lo & 0x000F_FFFF).saturating_mul(64));
        Self {
            next: seed,
            diag: call,
        }
    }

    /// A fresh unique span. Content-free (`[n, n]`); its only role is to be a
    /// distinct region key.
    const fn fresh(&mut self) -> Span {
        let n = self.next;
        // Saturating: an exhausted generator reuses the ceiling rather than
        // wrapping into the source range — a pathological many-node module would
        // mislower, but that is unreachable in practice and stays above the base.
        self.next = self.next.saturating_add(1);
        Span::new(n, n)
    }
}

/// A reference to a stdlib kernel by its registry variant, byte-identical to a
/// normally-resolved `Qualifier.member` reference (same `module`/`name` symbols
/// `kernel_home` stores).
fn kernel_ref(k: StdlibKernel, span: Span, interner: &mut Interner) -> DResult<canon::Expr> {
    let decl = k.decl();
    let module = interner.intern(decl.qualifier)?;
    let name = interner.intern(decl.name)?;
    Ok(Located::new(
        span,
        canon::Expr_::VarKernel {
            id: Some(k),
            module,
            name,
        },
    ))
}

/// The `snake_case` column/key for a camelCase field name (`priceMinor` →
/// `price_minor`).
///
/// A pure compile-time transform: an underscore-boundary is inserted before each
/// uppercase letter, which is then lowercased; runs of uppercase and existing
/// underscores are preserved as single boundaries.
///
/// This is the single source of truth for the field→column/key transform:
/// `Codec.auto` derives its column names through it, and the accessor-column
/// query and spec lowering call it (re-exported from the crate root) so a
/// `.recordedAt` accessor names the same `recorded_at` column the codec does.
#[must_use]
pub fn to_snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    let mut prev_lower_or_digit = false;
    for c in name.chars() {
        if c.is_ascii_uppercase() {
            if prev_lower_or_digit {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
            prev_lower_or_digit = false;
        } else {
            out.push(c);
            prev_lower_or_digit = c.is_ascii_lowercase() || c.is_ascii_digit();
        }
    }
    out
}

/// The leaf encoder + decoder expressions for one field type — the codec the
/// field's type selects, inlined as the raw `Json.Encode`/`Json.Decode`
/// expressions a hand-written codec uses (never routed through `Codec.string`
/// etc.), so the derived emit is byte-identical to the hand-written direct form.
///
/// `enc` is a bare `value -> Value` function expression; `dec` is a bare
/// `Decoder field` expression. Returns the offending `(reason, field)` when the
/// field type has no derivable leaf.
fn field_leaf_codecs(
    field: Symbol,
    ty: &canon::Type,
    sg: &mut SynSpan,
    env: &Env,
    interner: &mut Interner,
) -> DResult<(canon::Expr, canon::Expr)> {
    let field_name = resolve_or_bug(interner, field, "ipe_canon::field_leaf_codecs")?.to_owned();
    let diag_span = sg.diag;
    let bad = |reason: CodecAutoRejection, name: &str| Diagnostic::Name {
        span: diag_span,
        msg: NameError::CodecAutoUnderivable {
            reason,
            field: name.into(),
        },
    };

    // A `Secret` / reserved-sink field is unencodable by construction (Security).
    if let canon::Type::Con { name, args, .. } = ty
        && args.is_empty()
        && let Some(text) = interner.resolve(*name)
        && SEAL_SECRET_OR_SINK.contains(&text)
    {
        return Err(bad(CodecAutoRejection::SecretField, &field_name));
    }
    // A function field is not a serialisable value.
    if matches!(ty, canon::Type::Lambda(_, _)) {
        return Err(bad(CodecAutoRejection::FunctionField, &field_name));
    }

    match ty {
        canon::Type::Con { name, args, .. } if args.is_empty() => {
            let leaf = match interner.resolve(*name) {
                Some("String") => Some((StdlibKernel::JsonEncString, StdlibKernel::JsonDecString)),
                Some("Int") => Some((StdlibKernel::JsonEncInt, StdlibKernel::JsonDecInt)),
                Some("Bool") => Some((StdlibKernel::JsonEncBool, StdlibKernel::JsonDecBool)),
                Some("Float") => Some((StdlibKernel::JsonEncFloat, StdlibKernel::JsonDecFloat)),
                _ => None,
            };
            match leaf {
                Some((enc_k, dec_k)) => Ok((
                    kernel_ref(enc_k, sg.fresh(), interner)?,
                    kernel_ref(dec_k, sg.fresh(), interner)?,
                )),
                None => Err(bad(CodecAutoRejection::UnsupportedField, &field_name)),
            }
        }
        // `List t` — `Encode.list <encElem>` / `Decode.list <decElem>`, recursing
        // on the element type. `Encode.list` takes the element encoder + the list;
        // partially applied to the encoder it is the `List t -> Value` encoder.
        canon::Type::Con { name, args, .. }
            if interner.resolve(*name) == Some("List") && args.len() == 1 =>
        {
            let Some(elem) = args.first() else {
                return Err(bad(CodecAutoRejection::UnsupportedField, &field_name));
            };
            let (enc_elem, dec_elem) = field_leaf_codecs(field, elem, sg, env, interner)?;
            let enc = call_expr(
                kernel_ref(StdlibKernel::JsonEncList, sg.fresh(), interner)?,
                vec![enc_elem],
                sg.fresh(),
            );
            let dec = call_expr(
                kernel_ref(StdlibKernel::JsonDecList, sg.fresh(), interner)?,
                vec![dec_elem],
                sg.fresh(),
            );
            Ok((enc, dec))
        }
        // A nested closed record — derive its codec inline and project the enc/dec
        // out of the `Codec { enc, mkDec }` it produces.
        canon::Type::Record(fields) => {
            let codec = derive_record_codec(fields, sg, env, interner)?;
            project_codec_enc_dec(&codec, sg, env, interner)
        }
        _ => Err(bad(CodecAutoRejection::UnsupportedField, &field_name)),
    }
}

/// Build the direct-form record codec `Codec { enc, mkDec }` for a closed
/// record's fields. The encoder is an `Encode.object` over the field encoders;
/// the decoder factory a `Decode.succeed <ctorLambda> |> Pipeline.required key
/// leafDec |> …` chain — each field appearing once on each side.
fn derive_record_codec(
    fields: &[(Symbol, canon::Type)],
    sg: &mut SynSpan,
    env: &Env,
    interner: &mut Interner,
) -> DResult<canon::Expr_> {
    // Per-field leaf codecs (rejects a non-derivable field fail-closed).
    let mut leaves: Vec<(Symbol, canon::Expr, canon::Expr)> = Vec::with_capacity(fields.len());
    for (fname, fty) in fields {
        let (enc, dec) = field_leaf_codecs(*fname, fty, sg, env, interner)?;
        leaves.push((*fname, enc, dec));
    }

    // The record parameter of the encoder lambda, a fresh name that cannot alias
    // a field or a user binding. Its span seeds a unique name per record.
    let name_span = sg.fresh();
    let rec_param = interner.intern(&format!("codec_rec_{}", name_span.lo))?;

    // enc = \rec -> Encode.object [ (key, leafEnc rec.field), … ]
    let mut pairs = Vec::with_capacity(leaves.len());
    for (fname, enc, _) in &leaves {
        let key = to_snake_case(resolve_or_bug(
            interner,
            *fname,
            "ipe_canon::derive_record_codec::encoder",
        )?);
        let access = Located::new(
            sg.fresh(),
            canon::Expr_::Access(
                Box::new(Located::new(sg.fresh(), canon::Expr_::VarLocal(rec_param))),
                *fname,
            ),
        );
        let encoded = call_expr(enc.clone(), vec![access], sg.fresh());
        pairs.push(Located::new(
            sg.fresh(),
            canon::Expr_::Tuple(vec![
                Located::new(sg.fresh(), canon::Expr_::Str(key)),
                encoded,
            ]),
        ));
    }
    let obj = call_expr(
        kernel_ref(StdlibKernel::JsonEncObject, sg.fresh(), interner)?,
        vec![Located::new(sg.fresh(), canon::Expr_::List(pairs))],
        sg.fresh(),
    );
    let enc_lambda = Located::new(
        sg.fresh(),
        canon::Expr_::Lambda(
            vec![Located::new(sg.fresh(), canon::Pattern_::PVar(rec_param))],
            Box::new(obj),
        ),
    );

    // The record-builder lambda `\f0 … fN -> { f0 = f0, … }` — the sanctioned
    // direct constructor (a monomorphic record literal, not a bare constructor in
    // a generic slot).
    let ctor_patterns: Vec<canon::Pattern> = leaves
        .iter()
        .map(|(fname, _, _)| Located::new(sg.fresh(), canon::Pattern_::PVar(*fname)))
        .collect();
    let ctor_body_fields: Vec<(Symbol, canon::Expr)> = leaves
        .iter()
        .map(|(fname, _, _)| {
            (
                *fname,
                Located::new(sg.fresh(), canon::Expr_::VarLocal(*fname)),
            )
        })
        .collect();
    let ctor_lambda = Located::new(
        sg.fresh(),
        canon::Expr_::Lambda(
            ctor_patterns,
            Box::new(Located::new(
                sg.fresh(),
                canon::Expr_::Record(ctor_body_fields),
            )),
        ),
    );

    // mkDec = \_ -> Decode.succeed ctor |> Pipeline.required key leafDec |> …
    // `|>` desugars to `Call(rhs, [lhs])`; fold left over the fields, seeding with
    // `Decode.succeed ctor`.
    let mut decoder = call_expr(
        kernel_ref(StdlibKernel::JsonDecSucceed, sg.fresh(), interner)?,
        vec![ctor_lambda],
        sg.fresh(),
    );
    for (fname, _, dec) in &leaves {
        let key = to_snake_case(resolve_or_bug(
            interner,
            *fname,
            "ipe_canon::derive_record_codec::decoder",
        )?);
        let required = call_expr(
            kernel_ref(StdlibKernel::JsonDecPRequired, sg.fresh(), interner)?,
            vec![
                Located::new(sg.fresh(), canon::Expr_::Str(key)),
                dec.clone(),
            ],
            sg.fresh(),
        );
        decoder = call_expr(required, vec![decoder], sg.fresh());
    }
    let mkdec_lambda = Located::new(
        sg.fresh(),
        canon::Expr_::Lambda(
            vec![Located::new(sg.fresh(), canon::Pattern_::PAnything)],
            Box::new(decoder),
        ),
    );

    // shp = SRecord [ (key, colType), … ] — the DB column list, keyed by the same
    // snake_case keys the encoder/decoder use.
    let shp = derive_record_shape(fields, sg, env, interner)?;

    codec_record_expr(enc_lambda, mkdec_lambda, shp, sg, env, interner)
}

/// Resolve one of the derive's own building-block constructors (`Codec`,
/// `Shape`'s `SRecord`, `ColType`'s `CText`/…), all defined in `Ipe.Codec`.
///
/// Recognising `Codec.auto` at the call site proves the module imports
/// `Ipe.Codec` under some qualifier, but that import need not
/// `exposing (Codec(..), Shape(..), ColType(..))` — a plain `import Ipe.Codec as
/// Codec` leaves those constructors out of the bare expression namespace
/// entirely. They are always present QUALIFIED, though: `inject_dep_exports`
/// registers every dep constructor under its qualifier in `qual_ctors`
/// regardless of the `exposing` clause. So resolve through the recognised codec
/// qualifier first, and only then fall back to the bare name — the derive
/// works from the qualifier alone, never demanding the user expose the codec
/// internals, and behaves identically whether it runs in the entry module or any
/// dependency module of a multi-module program.
fn lookup_codec_ctor(env: &Env, ctor: Symbol) -> Option<&CtorHome> {
    env.codec_auto
        .qualifiers
        .iter()
        .find_map(|q| env.qual_ctors.get(q).and_then(|m| m.get(&ctor)))
        .or_else(|| match env.module_scope.expr.resolve(ctor) {
            Resolved::Found(
                Origin {
                    target: ExprTarget::Ctor(found),
                    ..
                },
                _,
            ) => Some(found),
            // An ambiguous bare name is no building block: the derive fails
            // closed with its underivable diagnostic, never picking one origin.
            Resolved::Found(..) | Resolved::Ambiguous { .. } | Resolved::Missing => None,
        })
}

/// A reference to the named constructor `ctor` resolved against the env — the
/// module must import the module that owns it (`Ipe.Codec` for `Codec`/`Shape`/
/// `ColType`). Fails fail-closed with the same underivable diagnostic the codec
/// derive uses when the constructor is not in scope.
fn ctor_ref_named(
    ctor: &str,
    sg: &mut SynSpan,
    env: &Env,
    interner: &mut Interner,
) -> DResult<canon::Expr> {
    let sym = interner.intern(ctor)?;
    let Some(found) = lookup_codec_ctor(env, sym) else {
        return Err(Diagnostic::Name {
            span: sg.diag,
            msg: NameError::CodecAutoUnderivable {
                reason: CodecAutoRejection::WitnessNotRecordValue,
                field: String::new().into(),
            },
        });
    };
    Ok(Located::new(
        sg.fresh(),
        canon::Expr_::VarCtor {
            home: found.home.clone(),
            type_name: found.type_name,
            name: found.name,
            index: found.index,
        },
    ))
}

/// The `ColType` a derived record FIELD contributes to its `SRecord` shape. A
/// scalar field maps to its scalar column type (`CText`/`CInt`/`CReal`/`CBool`);
/// a `List` field or a nested record maps to one JSON-in-TEXT column (`CBlob`).
/// The field types reaching here have already passed `field_leaf_codecs`, so an
/// unsupported type never arrives — the exhaustive fallthrough is the blob
/// column the derive's own container/record leaves produce.
fn field_col_type_expr(
    ty: &canon::Type,
    sg: &mut SynSpan,
    env: &Env,
    interner: &mut Interner,
) -> DResult<canon::Expr> {
    let scalar = match ty {
        canon::Type::Con { name, args, .. } if args.is_empty() => match interner.resolve(*name) {
            Some("String") => Some("CText"),
            Some("Int") => Some("CInt"),
            Some("Bool") => Some("CBool"),
            Some("Float") => Some("CReal"),
            _ => None,
        },
        _ => None,
    };
    ctor_ref_named(scalar.unwrap_or("CBlob"), sg, env, interner)
}

/// The `Shape` expression for a derived record: `SRecord [ (key, colType), … ]`
/// over the fields, keyed by the same `snake_case` keys the encoder/decoder use
/// so the column list, the wire keys, and the round-trip stay one source of truth.
fn derive_record_shape(
    fields: &[(Symbol, canon::Type)],
    sg: &mut SynSpan,
    env: &Env,
    interner: &mut Interner,
) -> DResult<canon::Expr> {
    let mut pairs = Vec::with_capacity(fields.len());
    for (fname, fty) in fields {
        let key = to_snake_case(resolve_or_bug(
            interner,
            *fname,
            "ipe_canon::derive_record_shape",
        )?);
        let col = field_col_type_expr(fty, sg, env, interner)?;
        pairs.push(Located::new(
            sg.fresh(),
            canon::Expr_::Tuple(vec![Located::new(sg.fresh(), canon::Expr_::Str(key)), col]),
        ));
    }
    let cols = Located::new(sg.fresh(), canon::Expr_::List(pairs));
    let srecord = ctor_ref_named("SRecord", sg, env, interner)?;
    Ok(call_expr(srecord, vec![cols], sg.fresh()))
}

/// Wrap the encoder, decoder-factory, and shape into the
/// `Codec { enc = …, mkDec = …, shp = … }` value — the single-constructor
/// `Ipe.Codec.Codec` applied to its record. The constructor resolves against the
/// env (the module must import `Ipe.Codec`).
fn codec_record_expr(
    enc: canon::Expr,
    mkdec: canon::Expr,
    shp: canon::Expr,
    sg: &mut SynSpan,
    env: &Env,
    interner: &mut Interner,
) -> DResult<canon::Expr_> {
    let codec_ctor_sym = interner.intern("Codec")?;
    let enc_field = interner.intern("enc")?;
    let mkdec_field = interner.intern("mkDec")?;
    let shp_field = interner.intern("shp")?;
    let Some(ctor) = lookup_codec_ctor(env, codec_ctor_sym) else {
        return Err(Diagnostic::Name {
            span: sg.diag,
            msg: NameError::CodecAutoUnderivable {
                reason: CodecAutoRejection::WitnessNotRecordValue,
                field: String::new().into(),
            },
        });
    };
    let record = Located::new(
        sg.fresh(),
        canon::Expr_::Record(vec![
            (enc_field, enc),
            (mkdec_field, mkdec),
            (shp_field, shp),
        ]),
    );
    let ctor_ref = Located::new(
        sg.fresh(),
        canon::Expr_::VarCtor {
            home: ctor.home.clone(),
            type_name: ctor.type_name,
            name: ctor.name,
            index: ctor.index,
        },
    );
    Ok(canon::Expr_::Call(Box::new(ctor_ref), vec![record]))
}

/// Project the `enc` and `mkDec {}` out of a derived nested-record codec, so a
/// nested record field can be encoded/decoded inline. `enc` becomes a bare
/// `value -> Value`; the decoder is `mkDec {}` (the factory run once), a bare
/// `Decoder value`.
fn project_codec_enc_dec(
    codec: &canon::Expr_,
    sg: &mut SynSpan,
    env: &Env,
    interner: &mut Interner,
) -> DResult<(canon::Expr, canon::Expr)> {
    // `case <codec> of Codec r -> r.enc` and `… -> r.mkDec {}`. Each projection
    // holds its OWN `case` over a fresh copy of the codec and its own binder, so
    // no node span is shared between the two.
    let codec_ctor_sym = interner.intern("Codec")?;
    let enc_field = interner.intern("enc")?;
    let mkdec_field = interner.intern("mkDec")?;
    let Some(ctor) = lookup_codec_ctor(env, codec_ctor_sym) else {
        return Err(Diagnostic::Name {
            span: sg.diag,
            msg: NameError::CodecAutoUnderivable {
                reason: CodecAutoRejection::UnsupportedField,
                field: String::new().into(),
            },
        });
    };
    let home = ctor.home.clone();
    let type_name = ctor.type_name;
    let ctor_name = ctor.name;
    let ctor_index = ctor.index;

    let mut make_projection = |proj_field: Symbol, run_unit: bool| -> canon::Expr {
        let binder = interner
            .intern(&format!("codec_r_{}", sg.fresh().lo))
            .unwrap_or(proj_field);
        let access = Located::new(
            sg.fresh(),
            canon::Expr_::Access(
                Box::new(Located::new(sg.fresh(), canon::Expr_::VarLocal(binder))),
                proj_field,
            ),
        );
        let body = if run_unit {
            // The decoder factory is `{} -> Decoder a` — run it with the empty
            // record `{}`, not unit.
            call_expr(
                access,
                vec![Located::new(sg.fresh(), canon::Expr_::Record(Vec::new()))],
                sg.fresh(),
            )
        } else {
            access
        };
        let pat = Located::new(
            sg.fresh(),
            canon::Pattern_::PCtor {
                home: home.clone(),
                type_name,
                name: ctor_name,
                index: ctor_index,
                args: vec![Located::new(sg.fresh(), canon::Pattern_::PVar(binder))],
            },
        );
        Located::new(
            sg.fresh(),
            canon::Expr_::Case(
                Box::new(Located::new(sg.fresh(), codec.clone())),
                vec![canon::CaseBranch { pat, body }],
            ),
        )
    };

    let enc = make_projection(enc_field, false);
    let dec = make_projection(mkdec_field, true);
    Ok((enc, dec))
}

/// Every constructor this module declares.
fn local_ctors(env: &Env) -> impl Iterator<Item = &CtorHome> {
    env.module_scope
        .expr
        .locals()
        .filter_map(|(_, origin)| match &origin.target {
            ExprTarget::Ctor(ctor) => Some(ctor),
            ExprTarget::Value(_) => None,
        })
}

/// Whether `name` is a constructor this module declares.
fn is_local_ctor(scope: &ModuleScope, name: Symbol) -> bool {
    matches!(
        scope.expr.resolve(name),
        Resolved::Found(origin, Tier::Local) if matches!(origin.target, ExprTarget::Ctor(_))
    )
}

/// A canonical function application node `f a0 a1 …`.
fn call_expr(f: canon::Expr, args: Vec<canon::Expr>, span: Span) -> canon::Expr {
    Located::new(span, canon::Expr_::Call(Box::new(f), args))
}

#[allow(clippy::too_many_arguments)] // qualifier paths threaded through the resolution context
fn synthesize_record_alias_ctors(
    m: &src::Module,
    home: &[Symbol],
    env: &Env,
    qualifier_paths: &BTreeMap<Symbol, Vec<Symbol>>,
    qualified_aliases: &QualifiedAliases,
    user_value_names: &BTreeSet<Symbol>,
    interner: &Interner,
    ui_wildcard_msg: Symbol,
) -> DResult<Vec<canon::Def>> {
    let mut synth = Vec::new();
    for a in &m.aliases {
        // Strict-literal gate: only a `{ … }` body carries a constructor.
        let src::TypeAnnotation::TRecord(fields) = &a.value.body.value else {
            continue;
        };
        let alias_name = a.value.name.value;
        let alias_span = a.value.name.span;

        // An explicit user top-level value of the same name IS the constructor
        // (`Profile name age active = { … }` alongside `type alias Profile`).
        // Decline synthesis — the user's def is the implementation, and letting
        // both through would double-emit the value. Mirrors the upstream Rust
        // emitter's `existingNames` guard (`Ipe.Generate.Rust.Builder.ModuleEmitter`,
        // `synCtor … if Set.member ctorName existingNames then []`).
        if user_value_names.contains(&alias_name) {
            continue;
        }

        // Canonicalise every field type ONCE, in declared (source) order. The
        // alias's own params fall through to `Type::Var` (empty `subst`), so a
        // param used in a field generalises and a phantom param drops out. The
        // alias name is pre-seeded into `visited` so a self-referential field
        // (`{ next : List T }`) expands exactly as `x : T` would — the ctor's
        // return record is byte-identical to the annotation expansion.
        let ctx = TypeCtx {
            env,
            qualifier_paths,
            qualified_aliases,
            interner,
            ui_wildcard_msg,
            ann_span: a.value.body.span,
        };
        let subst = BTreeMap::new();
        let mut free_set = BTreeSet::new();
        let mut visited = vec![alias_name];
        let mut can_fields: Vec<(Symbol, canon::Type)> = Vec::with_capacity(fields.len());
        for (fname, fty) in fields {
            let mut budget = TYPE_EXPANSION_NODE_LIMIT;
            let cty = canonicalise_type(
                fty,
                &ctx,
                &subst,
                &mut free_set,
                &mut visited,
                &mut budget,
                0,
            )?;
            can_fields.push((fname.value, cty));
        }

        // Data-record gate. DECLINE synthesis when ANY field type is
        // non-derivable-as-a-struct-field ([`field_type_nonderivable`]). The
        // synthesised constructor's body is a record literal that lowers to a
        // `#[derive(Clone, Debug, PartialEq)]` + `impl IpeStringify` struct over
        // the field types; a field that satisfies none of those obligations makes
        // the emitted Rust fail to build. Two disjoint non-derivable shapes:
        //
        //   * a raw function — directly (`{ handler : Int -> Msg }`, config-record
        //     aliases like `Web.tea`'s cfg) OR nested inside a derive carrier
        //     (`{ xs : List (Int -> Int) }`, `{ f : Maybe (Int -> Int) }`,
        //     `{ p : (Int -> Int, Bool) }`, `{ g : Result e (Int -> Int) }`, a
        //     nested record). For a DIRECT arrow the lowerer's own
        //     `embeds_nonderivable_function` region gate would reject the (unused,
        //     un-DCE'd) ctor body at IPE-L0107; a head-only gate over the nested
        //     shape would emit Rust that cargo then rejects.
        //   * an OPAQUE boxed-wrapper field (`{ dec : Decoder Int }`,
        //     `{ cmd : Cmd Msg }`, `Sub`, `Task`) — ipe accepts it but cargo
        //     rejects (E0277 Clone/Debug, E0369 ==, E0599 IpeStringify), because
        //     the wrapper VALUE is itself non-derivable; nesting one under a
        //     carrier (`List (Decoder Int)`, `Maybe (Cmd Msg)`) is equally
        //     non-derivable (the predicate recurses).
        //
        // There is no whole-program DCE to prune an *unused* such ctor, so
        // synthesizing it would turn a module that merely *names* the alias into a
        // build failure. Declining keeps the alias a plain type (no positional
        // constructor) and makes the un-buildable constructor UNREPRESENTABLE at
        // canon rather than emitted-then-rejected. See [`field_type_nonderivable`]
        // for why the synthesis predicate is NOT the lowerer's function-embedding
        // one (opaque head in field position ⇒ non-derivable, a deliberate flip).
        if can_fields
            .iter()
            .any(|(_, t)| field_type_nonderivable(interner, t))
        {
            continue;
        }

        // A record alias whose name coincides with a data constructor is valid
        // per the upstream Elm / Ipe rules: the TYPE namespace (`type alias`) and
        // the CONSTRUCTOR namespace (`type … = Ctor | …`) are distinct.
        //
        // The upstream the compiler (`Ipe.Canonicalise.Module.registerAliases`) inserts
        // the alias name into `_vars` via `Map.insert` without ANY check against
        // `_ctors` — the two occupy separate namespaces and coexist peacefully.
        //
        // A constructor and a value share one expression-namespace ladder, so
        // the local constructor and the auto-constructor would be two local
        // bindings of one name. Skipping synthesis keeps the ADT constructor the
        // sole local binding, which every expression and pattern reads.
        //
        // The old code emitted IPE-N0010 (DuplicateValue) here, which was wrong
        // and broke the `type Tab = Overview | …` + `type alias Overview = { … }`
        // pattern found in examples/25-ipe-console/src/State.ipe.
        //
        // Ref: `Ipe.Canonicalise.Module.registerAliases` upstream, lines 1759–1775.
        if is_local_ctor(&env.module_scope, alias_name) {
            continue;
        }

        // Quantified vars, ordered by resolved NAME (stable wire order — intern
        // ids are allocation-dependent), matching `canonicalise_value`.
        let mut free_vars: Vec<Symbol> = free_set.into_iter().collect();
        free_vars.sort_by(|x, y| interner.resolve(*x).cmp(&interner.resolve(*y)));

        // Three co-constructed views from the one ordered `can_fields` vec:
        // parameter patterns, the body record literal, and the arrow arg types.
        let patterns: Vec<canon::Pattern> = can_fields
            .iter()
            .map(|(fname, _)| Located::new(alias_span, canon::Pattern_::PVar(*fname)))
            .collect();
        let body_fields: Vec<(Symbol, canon::Expr)> = can_fields
            .iter()
            .map(|(fname, _)| {
                (
                    *fname,
                    Located::new(alias_span, canon::Expr_::VarLocal(*fname)),
                )
            })
            .collect();
        let body = Located::new(alias_span, canon::Expr_::Record(body_fields));
        let mut ty = canon::Type::Record(can_fields.clone());
        for (_, fty) in can_fields.iter().rev() {
            ty = canon::Type::Lambda(Box::new(fty.clone()), Box::new(ty));
        }

        synth.push(canon::Def::Typed {
            home: home.to_vec(),
            name: a.value.name,
            free_vars,
            patterns,
            body,
            ty,
        });
    }
    Ok(synth)
}

/// The home a dependency's exported value `name` resolves to.
///
/// A value that is a kernel alias in the dependency resolves as its kernel, the
/// same bare as qualified — never a `TopLevel` def the alias module never emits.
fn dep_value_home(dep: &crate::ModuleExports, name: Symbol) -> VarHome {
    dep.kernel_aliases.get(&name).map_or_else(
        || VarHome::TopLevel(dep.path.clone()),
        |a| VarHome::Kernel(a.id, a.module, a.function),
    )
}

/// Bind a dependency's exported value `name` at `tier`.
///
/// # Errors
/// The clash [`bind_expr`] reports.
fn bind_dep_value(
    dep: &crate::ModuleExports,
    name: Symbol,
    tier: Tier,
    span: Span,
    env: &mut Env,
    interner: &Interner,
) -> DResult<()> {
    let home = dep_value_home(dep, name);
    let identity = value_identity(&home, name)?;
    let origin = imported(ExprTarget::Value(home), identity, &dep.path, span);
    bind_expr(env, name, tier, origin, interner)
}

/// Bind a dependency's union `type_name` and the constructors `filter` admits at
/// `tier`.
///
/// # Errors
/// The clash [`bind_type`] or [`bind_expr`] reports.
#[allow(clippy::too_many_arguments)] // each argument is one independent fact of the binding
fn bind_dep_union(
    dep: &crate::ModuleExports,
    type_name: Symbol,
    home: &[Symbol],
    filter: &CtorFilter,
    tier: Tier,
    span: Span,
    env: &mut Env,
    interner: &Interner,
) -> DResult<()> {
    let origin = imported(
        ScopeType::Union(home.to_vec()),
        Identity::Type(home.to_vec()),
        &dep.path,
        span,
    );
    bind_type(env, type_name, tier, origin, interner)?;
    for ctor in dep.ctors.values() {
        if ctor.type_name == type_name && filter.admits(ctor.name) {
            let origin = imported(
                ExprTarget::Ctor(ctor.clone()),
                ctor_identity(ctor),
                &dep.path,
                span,
            );
            bind_expr(env, ctor.name, tier, origin, interner)?;
        }
    }
    Ok(())
}

/// Bind a dependency's alias `alias_name` at `tier`. The alias arrives
/// canonical in the dependency's own scope, so a body naming a type only the
/// dependency imports needs no import here.
///
/// # Errors
/// The clash [`bind_type`] reports.
fn bind_dep_alias(
    dep: &crate::ModuleExports,
    alias_name: Symbol,
    ea: &crate::ExportedAlias,
    tier: Tier,
    span: Span,
    env: &mut Env,
    interner: &Interner,
) -> DResult<()> {
    let origin = imported(
        ScopeType::Alias(AliasBody::Imported(ea.clone())),
        Identity::Type(ea.home.clone()),
        &dep.path,
        span,
    );
    bind_type(env, alias_name, tier, origin, interner)
}

/// Bind a dep module's exports in the resolving module's scope.
///
/// Called once per `import` declaration, in source order. Handles:
///
/// * `exposing (..)`: every exported value, union, constructor and alias binds
///   at the open tier, where two definitions under one name are IPE-N0024 only
///   at a bare use no higher tier answers.
/// * An explicit `exposing (name, Type(..))` list: each item binds at the
///   explicit tier, where a second definition under one name is refused at the
///   import (IPE-N0024 for a value or constructor, IPE-N0012 for a type).
/// * IPE-N0022 (`NameNotExposed`) when the exposing list names a value or type
///   the dep does not export.
/// * Qualifier registration (`import M as Q` or auto-qualifier = last segment).
///
/// # Errors
/// [`NameError::NameNotExposed`] / [`NameError::AmbiguousImport`] /
/// [`NameError::DuplicateType`]; or [`Diagnostic::CompilerBug`] on an
/// unresolvable symbol.
#[allow(clippy::too_many_lines)] // declarative injection table — splitting would obscure flow
fn inject_dep_exports(
    import: &src::Import,
    dep: &crate::ModuleExports,
    env: &mut Env,
    interner: &mut Interner,
) -> DResult<()> {
    let dep_path = &dep.path;

    match &import.exposing.value {
        src::Exposing::All => {
            let span = import.name.span;
            for &name in &dep.values {
                bind_dep_value(dep, name, Tier::Open, span, env, interner)?;
            }
            for (&type_name, home) in &dep.types {
                bind_dep_union(
                    dep,
                    type_name,
                    home,
                    &CtorFilter::All,
                    Tier::Open,
                    span,
                    env,
                    interner,
                )?;
            }
            for (&alias_name, ea) in &dep.aliases {
                bind_dep_alias(dep, alias_name, ea, Tier::Open, span, env, interner)?;
            }
        }
        src::Exposing::List(items) => {
            for item in items {
                match &item.value {
                    src::Exposed::Value(name) => {
                        if !dep.values.contains(name) {
                            let name_s = name_str(interner, *name)?;
                            let module_s = path_to_dot_string(interner, dep_path);
                            let sugg = suggestions(*name, dep.values.iter().copied(), interner);
                            return Err(Diagnostic::Name {
                                span: item.span,
                                msg: NameError::NameNotExposed {
                                    module: module_s,
                                    suggestions: Candidates::at(
                                        EditTarget::whole(item.span, &name_s),
                                        sugg,
                                    ),
                                    name: name_s,
                                },
                            });
                        }
                        bind_dep_value(dep, *name, Tier::Explicit, item.span, env, interner)?;
                    }
                    src::Exposed::Type(type_name, privacy) => {
                        let union_home = dep.types.get(type_name);
                        let alias = dep.aliases.get(type_name);
                        if union_home.is_none() && alias.is_none() {
                            let name_s = name_str(interner, *type_name)?;
                            let module_s = path_to_dot_string(interner, dep_path);
                            let all_names = dep.types.keys().chain(dep.aliases.keys()).copied();
                            let sugg = suggestions(*type_name, all_names, interner);
                            return Err(Diagnostic::Name {
                                span: item.span,
                                msg: NameError::NameNotExposed {
                                    module: module_s,
                                    suggestions: Candidates::at(
                                        EditTarget::prefix(item.span, &name_s),
                                        sugg,
                                    ),
                                    name: name_s,
                                },
                            });
                        }
                        if let Some(home) = union_home {
                            bind_dep_union(
                                dep,
                                *type_name,
                                home,
                                &exposed_ctor_filter(privacy),
                                Tier::Explicit,
                                item.span,
                                env,
                                interner,
                            )?;
                        }
                        if let Some(ea) = alias {
                            bind_dep_alias(
                                dep,
                                *type_name,
                                ea,
                                Tier::Explicit,
                                item.span,
                                env,
                                interner,
                            )?;
                            // A record alias also exports a value-level
                            // auto-constructor under the same name; when the
                            // dep exposed it (present in `dep.values`), bring it
                            // into the expression namespace too so `exposing
                            // (Account)` makes `Account` usable as a constructor.
                            if dep.values.contains(type_name) {
                                bind_dep_value(
                                    dep,
                                    *type_name,
                                    Tier::Explicit,
                                    item.span,
                                    env,
                                    interner,
                                )?;
                            }
                        }
                    }
                }
            }
        }
    }

    // Qualifiers this import is reachable under (see `import_qualifiers`).
    let reachable_qualifiers = import_qualifiers(import.alias, dep_path, interner)?;
    for &qualifier in &reachable_qualifiers {
        // A user dep module whose qualifier collides with a gated stdlib short-name
        // (e.g. a project-local `import Auth` over the stdlib `Auth`) shadows the
        // Tier-C import gate: its members now live in `qual_vars` under that
        // qualifier, so `Qualifier.member` must resolve against the imported local
        // module rather than raise IPE-N0034 for the un-imported stdlib module of
        // the same name. Marking the qualifier imported makes the gate defer here.
        env.mark_stdlib_qualifier_imported(qualifier);
        let qual_map = std::rc::Rc::make_mut(&mut env.qual_vars)
            .entry(qualifier)
            .or_default();
        for &v in &dep.values {
            // A dep value that is a Stage-4 kernel alias resolves as its kernel, so a
            // qualified `Alias.f` routes straight to the kernel dispatch — never a
            // `TopLevel(dep_path)` reference to a def the alias module never emits.
            if let Some(alias) = dep.kernel_aliases.get(&v) {
                qual_map.insert(v, VarHome::Kernel(alias.id, alias.module, alias.function));
            } else {
                qual_map.insert(v, VarHome::TopLevel(dep_path.clone()));
            }
        }
        // Register qualified constructors so `Alias.CtorName` resolves correctly.
        // Needed for compiled-source ADTs (e.g. `Money.USD` from `import Ipe.Money
        // as Money`) where constructors are not stdlib kernels and never enter
        // `qual_vars`.  We register ALL ctors from this dep regardless of the
        // user's `exposing (...)` clause — qualified access does not require the
        // name to be in the exposing list (only unqualified access does).
        if !dep.ctors.is_empty() {
            let qual_ctor_map = std::rc::Rc::make_mut(&mut env.qual_ctors)
                .entry(qualifier)
                .or_default();
            for (ctor_sym, ctor_home) in &dep.ctors {
                qual_ctor_map
                    .entry(*ctor_sym)
                    .or_insert_with(|| ctor_home.clone());
            }
        }
    }

    Ok(())
}

/// The type home a compiled-source stdlib module records for a
/// reserved builtin TYPE it re-exports (`Ipe.Ui exposing (Attribute)`,
/// `Ipe.Html exposing (Attribute)`, `Ipe.Path exposing (Path)`).
///
/// A HOME-SENSITIVE builtin (`Attribute` / `Event`) has TWO distinct carriers:
/// the Html one (`ipe_runtime::html::Attribute`, home `["Html"]`) and the Ui one
/// (`ipe_runtime::ui::element::Attribute`, the empty-home sentinel the lowerer's
/// `is_html` check reads as `UiAttribute`). The EXPORTING module picks the
/// carrier: an Html-family module (`Ipe.Html`, `Ipe.Html.Attributes`) re-exports
/// the Html one under `["Html"]`; the Ui module (`Ipe.Ui`) re-exports the Ui one
/// under the empty home. Homing the Ui carrier to `["Html"]` would lower every
/// `Ipe.Ui.Grid`/`Transition`/`Animation` builder's `Attribute` return type to
/// `html::Attribute` while its `Ui.gridTracks`/`Ui.transition`/`Ui.animate` body
/// produces `ui::Attribute` — an exit-0-then-cargo-fail E0308. `["Html"]` is also
/// the home the HM constrainer uses for the Html carrier, so the emitted type
/// unifies with `Html.node`'s parameter rather than minting a nominally-distinct
/// `Attribute`. A terminal engine (`Ipe.Ui.Tui`, `Ipe.Ui.Cells`, `Ipe.Ui.Cli`)
/// re-exports its own `Attribute` under its own path, which canonicalises to
/// that engine's builtin carrier. A home-INsensitive builtin (`Path`, …) keeps
/// the exporting module's own path.
fn reexported_builtin_type_home(
    resolved: &str,
    home: &[Symbol],
    interner: &Interner,
) -> Vec<Symbol> {
    if !HOME_SENSITIVE_BUILTIN_TYPES.contains(&resolved)
        || terminal_attribute_builtin(home, resolved, interner).is_some()
    {
        return home.to_owned();
    }
    let module_is_html = home.iter().any(|s| interner.resolve(*s) == Some("Html"));
    if module_is_html {
        interner
            .lookup("Html")
            .map_or_else(|| home.to_owned(), |html| vec![html])
    } else {
        // Ui carrier — the empty-home sentinel that lowers to `UiAttribute`.
        Vec::new()
    }
}

/// Build a [`crate::ModuleExports`] from the module's own declarations filtered
/// by its `exposing (…)` clause.
///
/// Only names declared in THIS module are considered as exportable; re-exporting
/// an imported name is not yet supported (and would require a separate pass after
/// imports are resolved, which the current design defers to a later milestone).
fn build_module_exports(
    home: &[Symbol],
    m: &src::Module,
    env: &Env,
    synth_ctor_names: &BTreeSet<Symbol>,
    kernel_aliases: &BTreeMap<Symbol, KernelAlias>,
    own_aliases: &BTreeMap<Symbol, crate::ExportedAlias>,
    interner: &Interner,
) -> crate::ModuleExports {
    let mut exports = crate::ModuleExports {
        path: home.to_owned(),
        ..crate::ModuleExports::default()
    };

    // Sets of names defined by THIS module (not imported from deps).
    let own_values: BTreeSet<Symbol> = m.values.iter().map(|v| v.value.name.value).collect();
    let own_types: BTreeSet<Symbol> = m.unions.iter().map(|u| u.value.name.value).collect();

    match &m.exposing.value {
        src::Exposing::All => {
            exports.values = own_values;
            for &type_name in &own_types {
                exports.types.insert(type_name, home.to_owned());
                for ctor_home in local_ctors(env) {
                    if ctor_home.type_name == type_name {
                        exports.ctors.insert(ctor_home.name, ctor_home.clone());
                    }
                }
            }
            for a in &m.aliases {
                if let Some(resolved) = own_aliases.get(&a.value.name.value) {
                    exports.aliases.insert(a.value.name.value, resolved.clone());
                }
                // A record alias also exports its value-level auto-constructor
                // — but ONLY when one was actually synthesized (a
                // function-field alias is gated out). The synthesized `Def` lives
                // in this module's `defs`, so the importer binds the name as
                // `TopLevel(dep_path)` with no re-synthesis.
                if synth_ctor_names.contains(&a.value.name.value) {
                    exports.values.insert(a.value.name.value);
                }
            }
        }
        src::Exposing::List(items) => {
            for item in items {
                match &item.value {
                    src::Exposed::Value(name) => {
                        if own_values.contains(name) {
                            exports.values.insert(*name);
                        }
                    }
                    src::Exposed::Type(type_name, privacy) => {
                        if own_types.contains(type_name) {
                            exports.types.insert(*type_name, home.to_owned());
                            let filter = exposed_ctor_filter(privacy);
                            if !matches!(filter, CtorFilter::None) {
                                for ctor_home in local_ctors(env) {
                                    if ctor_home.type_name == *type_name
                                        && filter.admits(ctor_home.name)
                                    {
                                        exports.ctors.insert(ctor_home.name, ctor_home.clone());
                                    }
                                }
                            }
                        } else if let Some(resolved) = interner
                            .resolve(*type_name)
                            .filter(|n| is_reserved_builtin_type_name(n))
                        {
                            // A compiled-source stdlib module re-exports a reserved
                            // builtin TYPE it does not (and, for `Attribute` et al.,
                            // may not) declare as a source ADT — e.g. `Ipe.Path
                            // exposing (Path)`, `Ipe.Html.Attributes exposing
                            // (Attribute)`. Record it so an importer's `exposing
                            // (T)` resolves instead of failing `NameNotExposed`; no
                            // constructors (a builtin carrier has none at source).
                            let builtin_home =
                                reexported_builtin_type_home(resolved, home, interner);
                            exports.types.insert(*type_name, builtin_home);
                        } else if let Some(resolved) = own_aliases.get(type_name) {
                            exports.aliases.insert(*type_name, resolved.clone());
                            // Exposing a record alias also exposes its
                            // value-level auto-constructor, when one was
                            // synthesized (function-field aliases are gated out).
                            if synth_ctor_names.contains(type_name) {
                                exports.values.insert(*type_name);
                            }
                        }
                    }
                }
            }
        }
    }

    // Record every EXPORTED kernel alias so importers register `Alias.f` as the
    // kernel rather than a `TopLevel` reference. A kernel alias is an ordinary
    // value as far as `exposing` is concerned, so it is already in
    // `exports.values`; we only add the ones actually exported (an un-exposed
    // alias is module-private and needs no cross-module entry).
    for (&name, alias) in kernel_aliases {
        if exports.values.contains(&name) {
            exports.kernel_aliases.insert(
                name,
                crate::ExportedKernelAlias {
                    id: alias.id,
                    module: alias.module,
                    function: alias.function,
                },
            );
        }
    }

    exports
}

/// Build a dot-joined module path string from interned symbols for use in
/// diagnostic payloads. Segments that are not backed by the interner are
/// rendered as `?` (lossy) — this is acceptable because the result is only
/// used in `Box<str>` diagnostic fields, never as a key.
fn path_to_dot_string(interner: &Interner, path: &[Symbol]) -> Box<str> {
    path.iter()
        .map(|&s| interner.resolve(s).unwrap_or("?"))
        .collect::<Vec<_>>()
        .join(".")
        .into()
}

/// The qualifier symbols under which a dep import becomes reachable.
///
/// An explicit `as Alias` names exactly one, on purpose. A BARE `import Rls.Owner` names TWO:
/// the last path segment (`Owner` — Elm convention, `import Lib.Utils` makes
/// `Utils.foo` available) AND the full dotted path (`Rls.Owner`), the qualifier
/// the parser produces from `Rls.Owner.member` / `Rls.Owner.Doc` which no
/// single-segment `as` alias can spell. Registering both keeps a fully-qualified
/// reference resolving IDENTICALLY in expression and type-annotation position —
/// both consult the qualifier maps — mirroring the dotted-canonical stdlib
/// handling (`Ipe.Db.Decode` → `Db.Decode`).
///
/// # Errors
/// Propagates the interner's error when the dotted qualifier cannot be interned.
pub fn import_qualifiers(
    alias: Option<Symbol>,
    dep_path: &[Symbol],
    interner: &mut Interner,
) -> DResult<Vec<Symbol>> {
    let forms = import_qualifier_forms(alias.is_some(), dep_path.len());
    let mut qualifiers = Vec::with_capacity(forms.len());
    for form in forms {
        let qualifier = match form {
            QualifierForm::Alias => alias.unwrap_or_else(name_zero),
            QualifierForm::LastSegment => dep_path.last().copied().unwrap_or_else(name_zero),
            QualifierForm::DottedPath => {
                interner.intern(&path_to_dot_string(interner, dep_path))?
            }
        };
        qualifiers.push(qualifier);
    }
    Ok(qualifiers)
}

/// One spelling under which a dep import is reachable as a qualifier.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QualifierForm {
    /// The explicit `as Alias` name.
    Alias,
    /// The last segment of the imported module path (`Utils` for `Lib.Utils`).
    LastSegment,
    /// The full dotted module path (`Lib.Utils`).
    DottedPath,
}

/// The qualifier forms a dep import registers, in registration order.
///
/// The single rule behind [`import_qualifiers`]: an explicit alias names exactly
/// one qualifier; a bare import names its last segment and, when the path has
/// more than one segment, its dotted path as well. Consumers working on text
/// (a lint over the parse tree) spell the same forms without an interner.
#[must_use]
pub const fn import_qualifier_forms(has_alias: bool, path_len: usize) -> &'static [QualifierForm] {
    if has_alias {
        &[QualifierForm::Alias]
    } else if path_len > 1 {
        &[QualifierForm::LastSegment, QualifierForm::DottedPath]
    } else {
        &[QualifierForm::LastSegment]
    }
}

/// Bind a union's constructors at the local tier.
///
/// This is the *name-resolution* half: each constructor's home / type / index /
/// arity is bound in the expression namespace so a `VarCtor` reference or a
/// constructor pattern can resolve before any value body is canonicalised. The
/// payload field *types* are canonicalised separately in [`canonicalise_union`]
/// (after type aliases are collected, so a field type may itself reference an
/// alias).
///
/// # Errors
/// [`NameError::DuplicateConstructor`] on a constructor name the module already
/// declares, or one an explicit import already binds;
/// [`Diagnostic::CompilerBug`] if a constructor symbol is not interned.
fn register_union(
    u: &src::Union,
    home: &[Symbol],
    env: &mut Env,
    interner: &Interner,
) -> DResult<()> {
    let type_name = u.name.value;
    for (index, c) in u.ctors.iter().enumerate() {
        let name = c.value.name;
        let ctor = CtorHome {
            home: home.to_vec(),
            type_name,
            name,
            index,
            arity: c.value.args.len(),
        };
        let identity = ctor_identity(&ctor);
        let origin = declared(ExprTarget::Ctor(ctor), identity, c.span);
        bind_expr(env, name, Tier::Local, origin, interner)?;
    }
    Ok(())
}

/// Build the canonical [`canon::Union`] record for a source union, canonicalising
/// every constructor's payload field types under the union's type-variable scope.
///
/// Each field type variable (`a` in `Just a`) is a free variable of the type
/// annotation and resolves to a [`canon::Type::Var`]; a field that names the
/// union itself (`Tree` in `Node Tree Int Tree`) resolves to a local
/// [`canon::Type::Con`]. The union's declared `vars` are carried through in
/// declaration order — the lowerer's IR `type_params` order depends on it.
///
/// # Errors
/// [`NameError::AliasArity`] when a field type applies an alias with the wrong
/// argument count; [`Diagnostic::CompilerBug`] on a forged symbol.
fn canonicalise_union(
    u: &src::Union,
    env: &Env,
    qualifier_paths: &BTreeMap<Symbol, Vec<Symbol>>,
    qualified_aliases: &QualifiedAliases,
    interner: &Interner,
    ui_wildcard_msg: Symbol,
) -> DResult<canon::Union> {
    let type_name = u.name.value;
    let vars: Vec<Symbol> = u.vars.iter().map(|v| v.value).collect();
    let mut ctors = Vec::with_capacity(u.ctors.len());
    for (index, c) in u.ctors.iter().enumerate() {
        let name = c.value.name;
        let arity = c.value.args.len();
        let ctx = TypeCtx {
            env,
            qualifier_paths,
            qualified_aliases,
            interner,
            ui_wildcard_msg,
            ann_span: c.span,
        };
        let mut args = Vec::with_capacity(c.value.args.len());
        for a in &c.value.args {
            // A constructor field type is canonicalised under an empty
            // substitution: each free type variable it mentions is one of the
            // union's `vars` and resolves to a `Type::Var`. The `free_vars` set is
            // local (the union's quantification, not a binding's), so it is
            // discarded — the declared `vars` are the authoritative parameter list.
            let mut free_vars = BTreeSet::new();
            let mut visited = Vec::new();
            let subst = BTreeMap::new();
            let mut budget = TYPE_EXPANSION_NODE_LIMIT;
            args.push(canonicalise_type(
                a,
                &ctx,
                &subst,
                &mut free_vars,
                &mut visited,
                &mut budget,
                0,
            )?);
        }
        ctors.push(canon::Ctor {
            name,
            index,
            arity,
            args,
            span: c.span,
        });
    }
    Ok(canon::Union {
        home: env.home.clone(),
        name: type_name,
        name_span: u.name.span,
        vars,
        ctors,
    })
}

/// Canonicalise a single top-level value declaration.
fn canonicalise_value(
    val: &src::Value,
    env: &Env,
    qualifier_paths: &BTreeMap<Symbol, Vec<Symbol>>,
    qualified_aliases: &QualifiedAliases,
    interner: &mut Interner,
    ui_wildcard_msg: Symbol,
) -> DResult<canon::Def> {
    // The reserved `CustomElement.fromFile "<js-path>"` constructor is recognised BEFORE
    // the body is canonicalised: its qualified head is otherwise an unknown member,
    // and only this position (the whole body of a `CustomElement`-annotated
    // binding) is legal. A malformed use fails closed here (IPE-N0044); any other
    // appearance of the qualified name is rejected downstream by `resolve_qual_var`.
    if let Some(def) = detect_custom_element_constructor(
        val,
        env,
        qualifier_paths,
        qualified_aliases,
        interner,
        ui_wildcard_msg,
    )? {
        return Ok(def);
    }

    // Add parameter-bound names to a body-local environment.
    let mut body_env = env.clone();
    for p in &val.patterns {
        bind_pattern_names(&p.value, &mut body_env);
    }

    let mut patterns = Vec::with_capacity(val.patterns.len());
    for p in &val.patterns {
        reject_duplicate_pattern_binders(p, interner)?;
        patterns.push(canonicalise_pattern(p, env, interner)?);
    }
    let body = canonicalise_expr(&val.body, &body_env, interner)?;

    match &val.type_annotation {
        None => Ok(canon::Def::Untyped {
            home: env.home.clone(),
            name: val.name,
            patterns,
            body,
        }),
        Some(ann) => {
            let mut free_vars = BTreeSet::new();
            let mut visited = Vec::new();
            let ctx = TypeCtx {
                env,
                qualifier_paths,
                qualified_aliases,
                interner,
                ui_wildcard_msg,
                ann_span: ann.span,
            };
            let subst = BTreeMap::new();
            let mut budget = TYPE_EXPANSION_NODE_LIMIT;
            let ty = canonicalise_type(
                &ann.value,
                &ctx,
                &subst,
                &mut free_vars,
                &mut visited,
                &mut budget,
                0,
            )?;
            // Order the quantified type variables by their resolved NAME, not by
            // `Symbol` id (intern order is allocation-dependent, hence not a
            // stable wire order). Determinism gate: a multi-tyvar annotation
            // must yield the same `free_vars` regardless of how the interner
            // happened to number the names.
            let mut free_vars: Vec<Symbol> = free_vars.into_iter().collect();
            free_vars.sort_by(|a, b| interner.resolve(*a).cmp(&interner.resolve(*b)));
            Ok(canon::Def::Typed {
                home: env.home.clone(),
                name: val.name,
                free_vars,
                patterns,
                body,
                ty,
            })
        }
    }
}

/// Bind every variable a pattern introduces as a local in the environment.
fn bind_pattern_names(p: &src::Pattern_, env: &mut Env) {
    match p {
        // The wildcard, the dev-only `Debug._` catch-all, the unit pattern, and
        // the literal leaves all bind nothing.
        src::Pattern_::PAnything
        | src::Pattern_::PDebugAnything
        | src::Pattern_::PUnit
        | src::Pattern_::PInt(_)
        | src::Pattern_::PBool(_)
        | src::Pattern_::PChar(_)
        | src::Pattern_::PStr(_) => {}
        src::Pattern_::PVar(name) => env.add_local(*name),
        src::Pattern_::PCtor(_, _, args) => {
            for a in args {
                bind_pattern_names(&a.value, env);
            }
        }
        // A tuple and a list pattern both bind every element's names.
        src::Pattern_::PTuple(elems) | src::Pattern_::PList(elems) => {
            for e in elems {
                bind_pattern_names(&e.value, env);
            }
        }
        src::Pattern_::PRecord(fields) => {
            // Field-pun: each field name binds a local of the same name.
            for f in fields {
                env.add_local(f.value);
            }
        }
        src::Pattern_::PAlias(inner, name) => {
            // The alias binds its name AND every name its inner pattern binds.
            bind_pattern_names(&inner.value, env);
            env.add_local(name.value);
        }
        src::Pattern_::PCons(head, tail) => {
            bind_pattern_names(&head.value, env);
            bind_pattern_names(&tail.value, env);
        }
        src::Pattern_::POr(alts) => {
            // Every alternative binds the identical name set (proved in
            // `canonicalise_pattern`), so binding the FIRST alternative's names
            // introduces the whole or-pattern's common binder set exactly once.
            if let Some(first) = alts.first() {
                bind_pattern_names(&first.value, env);
            }
        }
    }
}

/// The set of variable names a source pattern binds. Wildcards and literals bind
/// nothing; a nested or-pattern contributes its (already-consistent) common set,
/// taken from its first alternative. Used to prove or-pattern binder-set
/// equality fail-fast in canon (IPE-T0019).
fn bound_name_set(p: &src::Pattern_) -> std::collections::BTreeSet<Symbol> {
    let mut names = std::collections::BTreeSet::new();
    collect_bound_names(p, &mut names);
    names
}

fn collect_bound_names(p: &src::Pattern_, names: &mut std::collections::BTreeSet<Symbol>) {
    match p {
        src::Pattern_::PAnything
        | src::Pattern_::PDebugAnything
        | src::Pattern_::PUnit
        | src::Pattern_::PInt(_)
        | src::Pattern_::PBool(_)
        | src::Pattern_::PChar(_)
        | src::Pattern_::PStr(_) => {}
        src::Pattern_::PVar(name) => {
            names.insert(*name);
        }
        src::Pattern_::PCtor(_, _, args) => {
            for a in args {
                collect_bound_names(&a.value, names);
            }
        }
        src::Pattern_::PTuple(elems) | src::Pattern_::PList(elems) => {
            for e in elems {
                collect_bound_names(&e.value, names);
            }
        }
        src::Pattern_::PRecord(fields) => {
            for f in fields {
                names.insert(f.value);
            }
        }
        src::Pattern_::PAlias(inner, name) => {
            collect_bound_names(&inner.value, names);
            names.insert(name.value);
        }
        src::Pattern_::PCons(head, tail) => {
            collect_bound_names(&head.value, names);
            collect_bound_names(&tail.value, names);
        }
        src::Pattern_::POr(alts) => {
            // A nested or-pattern's alternatives are already proved equal in
            // `canonicalise_pattern`; contribute the first alternative's set.
            if let Some(first) = alts.first() {
                collect_bound_names(&first.value, names);
            }
        }
    }
}

/// Reject a pattern that binds the same variable name more than once.
///
/// A pattern's binders each introduce a distinct local, so two binders of one
/// name in the same pattern (`( x, x )`, `x :: x`, `{ a, a }`) are ambiguous —
/// a later use could mean either, and the two need not be equal. Rather than
/// silently shadow one with the other, canon rejects it here, before the local
/// scope is built. The alternatives of an or-pattern are DISJOINT scopes (only
/// one ever matches), so a name reused ACROSS alternatives is not a duplicate;
/// each alternative is checked on its own.
fn reject_duplicate_pattern_binders(p: &src::Pattern, interner: &Interner) -> DResult<()> {
    let mut seen: BTreeMap<Symbol, Span> = BTreeMap::new();
    collect_binders_no_dup(p, &mut seen, interner)?;
    Ok(())
}

fn collect_binders_no_dup(
    p: &src::Pattern,
    seen: &mut BTreeMap<Symbol, Span>,
    interner: &Interner,
) -> DResult<()> {
    let note = |name: Symbol, span: Span, seen: &mut BTreeMap<Symbol, Span>| -> DResult<()> {
        if let Some(&first) = seen.get(&name) {
            return Err(Diagnostic::Name {
                span,
                msg: NameError::DuplicatePatternBinder {
                    name: name_str(interner, name)?,
                    first,
                },
            });
        }
        seen.insert(name, span);
        Ok(())
    };
    match &p.value {
        src::Pattern_::PAnything
        | src::Pattern_::PDebugAnything
        | src::Pattern_::PUnit
        | src::Pattern_::PInt(_)
        | src::Pattern_::PBool(_)
        | src::Pattern_::PChar(_)
        | src::Pattern_::PStr(_) => {}
        src::Pattern_::PVar(name) => note(*name, p.span, seen)?,
        src::Pattern_::PCtor(_, _, args) => {
            for a in args {
                collect_binders_no_dup(a, seen, interner)?;
            }
        }
        src::Pattern_::PTuple(elems) | src::Pattern_::PList(elems) => {
            for e in elems {
                collect_binders_no_dup(e, seen, interner)?;
            }
        }
        src::Pattern_::PRecord(fields) => {
            for f in fields {
                note(f.value, f.span, seen)?;
            }
        }
        src::Pattern_::PAlias(inner, name) => {
            collect_binders_no_dup(inner, seen, interner)?;
            note(name.value, name.span, seen)?;
        }
        src::Pattern_::PCons(head, tail) => {
            collect_binders_no_dup(head, seen, interner)?;
            collect_binders_no_dup(tail, seen, interner)?;
        }
        src::Pattern_::POr(alts) => {
            // Each alternative is a disjoint scope: a name reused across
            // alternatives is legal, so each alternative is checked against a
            // fresh set rather than the shared one.
            for alt in alts {
                let mut alt_seen: BTreeMap<Symbol, Span> = BTreeMap::new();
                collect_binders_no_dup(alt, &mut alt_seen, interner)?;
            }
        }
    }
    Ok(())
}

/// Resolve a constructor pattern's bare name. A pattern reads the expression
/// namespace's one ladder: a value its first answering tier binds (a record
/// alias's auto-constructor) shadows any lower-tier constructor, and is no
/// constructor to match on. `unqualified` is whether the pattern's source token
/// is the bare name, so a did-you-mean may edit it.
fn resolve_pattern_ctor<'e>(
    name: Symbol,
    unqualified: bool,
    span: Span,
    env: &'e Env,
    interner: &Interner,
) -> DResult<&'e CtorHome> {
    match env.module_scope.expr.resolve(name) {
        Resolved::Found(
            Origin {
                target: ExprTarget::Ctor(ctor),
                ..
            },
            _,
        ) => Ok(ctor),
        Resolved::Ambiguous { importers } => {
            let modules = importer_names(&importers, interner);
            Err(ambiguous_import(name, span, modules, interner)?)
        }
        Resolved::Found(..) | Resolved::Missing => Err(ctor_pattern_not_found(
            name,
            unqualified,
            span,
            env,
            interner,
        )?),
    }
}

/// Canonicalise a pattern. Supports wildcard, var, and constructor patterns.
fn canonicalise_pattern(
    p: &src::Pattern,
    env: &Env,
    interner: &Interner,
) -> DResult<canon::Pattern> {
    let span = p.span;
    let node = match &p.value {
        src::Pattern_::PAnything => canon::Pattern_::PAnything,
        src::Pattern_::PDebugAnything => canon::Pattern_::PDebugAnything,
        src::Pattern_::PUnit => canon::Pattern_::PUnit,
        src::Pattern_::PVar(name) => canon::Pattern_::PVar(*name),
        src::Pattern_::PCtor(name, segments, args) => {
            let ctor = resolve_pattern_ctor(*name, segments.is_empty(), span, env, interner)?;
            let home = ctor.home.clone();
            let type_name = ctor.type_name;
            let index = ctor.index;
            let mut can_args = Vec::with_capacity(args.len());
            for a in args {
                can_args.push(canonicalise_pattern(a, env, interner)?);
            }
            canon::Pattern_::PCtor {
                home,
                type_name,
                name: *name,
                index,
                args: can_args,
            }
        }
        src::Pattern_::PTuple(elems) => {
            let mut can_elems = Vec::with_capacity(elems.len());
            for e in elems {
                can_elems.push(canonicalise_pattern(e, env, interner)?);
            }
            canon::Pattern_::PTuple(can_elems)
        }
        src::Pattern_::PRecord(fields) => {
            // Field-pun record pattern: the field names carry through verbatim
            // (the binding of each as a local happens in `bind_pattern_names`).
            canon::Pattern_::PRecord(fields.clone())
        }
        src::Pattern_::PInt(n) => canon::Pattern_::PInt(*n),
        src::Pattern_::PBool(b) => canon::Pattern_::PBool(*b),
        src::Pattern_::PChar(c) => canon::Pattern_::PChar(c.clone()),
        src::Pattern_::PStr(s) => canon::Pattern_::PStr(s.clone()),
        src::Pattern_::PAlias(inner, name) => {
            let can_inner = canonicalise_pattern(inner, env, interner)?;
            canon::Pattern_::PAlias(Box::new(can_inner), *name)
        }
        src::Pattern_::PList(elems) => {
            let mut can_elems = Vec::with_capacity(elems.len());
            for e in elems {
                can_elems.push(canonicalise_pattern(e, env, interner)?);
            }
            canon::Pattern_::PList(can_elems)
        }
        src::Pattern_::PCons(head, tail) => {
            let can_head = canonicalise_pattern(head, env, interner)?;
            let can_tail = canonicalise_pattern(tail, env, interner)?;
            canon::Pattern_::PCons(Box::new(can_head), Box::new(can_tail))
        }
        src::Pattern_::POr(alts) => {
            // Fail-fast binder-set equality (IPE-T0019): every alternative must
            // bind the identical set of names. The set-equality half is purely
            // syntactic and checked here, before the solver; the same-type half
            // rides the post-solve type-mismatch path. The parser guarantees
            // `≥ 2` alternatives, so `split_first` always yields a reference.
            let Some((first, rest)) = alts.split_first() else {
                return Err(Diagnostic::CompilerBug {
                    where_: "canon::canonicalise_pattern",
                    detail: "an or-pattern reached canon with no alternatives".to_owned(),
                });
            };
            let reference = bound_name_set(&first.value);
            for alt in rest {
                let this = bound_name_set(&alt.value);
                if this != reference {
                    // The offending names are those bound by some alternative but
                    // not all — the symmetric difference from the reference set.
                    // Resolve each to its interner string, then let the diagnostic
                    // newtype impose the canonical (string) order.
                    let names = SortedNames::try_new(
                        reference
                            .symmetric_difference(&this)
                            .copied()
                            .map(|sym| name_str(interner, sym)),
                    )?;
                    return Err(Diagnostic::Type {
                        span: alt.span,
                        msg: TypeError::OrPatternBindingMismatch { names },
                    });
                }
            }
            let mut can_alts = Vec::with_capacity(alts.len());
            for alt in alts {
                can_alts.push(canonicalise_pattern(alt, env, interner)?);
            }
            canon::Pattern_::POr(can_alts)
        }
    };
    Ok(Located::new(span, node))
}

/// Canonicalise an expression, resolving every name.
#[allow(clippy::too_many_lines)] // one arm per source expression form
fn canonicalise_expr(e: &src::Expr, env: &Env, interner: &mut Interner) -> DResult<canon::Expr> {
    let span = e.span;
    let node = match &e.value {
        src::Expr_::Int(n) => canon::Expr_::Int(*n),
        src::Expr_::Float(f) => canon::Expr_::Float(*f),
        src::Expr_::Str(s) => canon::Expr_::Str(s.clone()),
        // Triple-quoted strings: desugar `{{expr}}` interpolation into a `++`
        // chain at canonicalise time. Mirrors `Ipe.Canonicalise.Expression.hs`
        // line 42 (`Src.MultilineStr s -> desugarMultiline env s`).
        src::Expr_::MultilineStr { raw, anchor } => {
            desugar_multiline(raw, *anchor, span, env, interner)?
        }
        src::Expr_::Char(c) => canon::Expr_::Char(c.clone()),
        src::Expr_::Unit => canon::Expr_::Unit,
        src::Expr_::VarLocal(name) => resolve_var(*name, span, env, interner)?,
        src::Expr_::VarQual(qual, name) => resolve_qual_var(*qual, *name, span, env, interner)?,
        src::Expr_::Call(f, args) => {
            if let Some(node) = canonicalise_foreign_call(f, args, span, env, interner)? {
                node
            } else if let Some(node) = canonicalise_asserted_call(f, args, span, env, interner)? {
                node
            } else if let Some(node) = canonicalise_codec_auto(f, args, span, env, interner)? {
                node
            } else {
                let callee = canonicalise_expr(f, env, interner)?;
                let mut can_args = Vec::with_capacity(args.len());
                for a in args {
                    can_args.push(canonicalise_expr(a, env, interner)?);
                }
                canon::Expr_::Call(Box::new(callee), can_args)
            }
        }
        src::Expr_::Case(scrut, arms) => {
            let can_scrut = canonicalise_expr(scrut, env, interner)?;
            let mut branches = Vec::with_capacity(arms.len());
            for (pat, body) in arms {
                // Pattern-bound names are local in the arm body.
                let mut arm_env = env.clone();
                bind_pattern_names(&pat.value, &mut arm_env);
                reject_duplicate_pattern_binders(pat, interner)?;
                let can_pat = canonicalise_pattern(pat, env, interner)?;
                let can_body = canonicalise_expr(body, &arm_env, interner)?;
                branches.push(canon::CaseBranch {
                    pat: can_pat,
                    body: can_body,
                });
            }
            canon::Expr_::Case(Box::new(can_scrut), branches)
        }
        src::Expr_::Lambda(params, body) => {
            // The lambda's parameters become locals in its body; every other
            // free name resolves against the enclosing scope (an outer local,
            // a top-level binding, or a kernel) exactly as a bare reference
            // would — that is the capture. The parameter patterns themselves
            // are resolved against the *enclosing* env (a constructor pattern
            // must resolve there), matching how `case` arms are handled.
            let mut body_env = env.clone();
            let mut can_params = Vec::with_capacity(params.len());
            for p in params {
                reject_duplicate_pattern_binders(p, interner)?;
                bind_pattern_names(&p.value, &mut body_env);
                can_params.push(canonicalise_pattern(p, env, interner)?);
            }
            let can_body = canonicalise_expr(body, &body_env, interner)?;
            canon::Expr_::Lambda(can_params, Box::new(can_body))
        }
        src::Expr_::Binops(pairs, final_) => canonicalise_binops(pairs, final_, env, interner)?,
        src::Expr_::Let(bindings, body) => {
            // Sequential (`let*`) scoping: each binding's value is resolved
            // against the enclosing scope plus the bindings before it, then its
            // name becomes a local for the bindings that follow and for the
            // `in` body. This matches the non-recursive nested-`Let` the lowerer
            // emits, so a self- or forward-reference resolves to an outer name or
            // fails cleanly (`ValueNotFound`) rather than miscompiling.
            let mut let_env = env.clone();
            let mut can_bindings = Vec::with_capacity(bindings.len());
            for b in bindings {
                let can_body = canonicalise_expr(&b.body, &let_env, interner)?;
                // The binder's value is resolved against the scope so far; then
                // every variable it introduces (a plain name, or each leaf of a
                // tuple / record destructure) becomes a local for the bindings
                // that follow and the `in` body. The binder pattern itself is
                // canonicalised against the enclosing env (consistent with how
                // `case` arms and lambda parameters resolve their patterns).
                reject_duplicate_pattern_binders(&b.pat, interner)?;
                let can_pat = canonicalise_pattern(&b.pat, &let_env, interner)?;
                bind_pattern_names(&b.pat.value, &mut let_env);
                can_bindings.push(canon::LetBinding {
                    pat: can_pat,
                    body: can_body,
                });
            }
            let can_in = canonicalise_expr(body, &let_env, interner)?;
            canon::Expr_::Let(can_bindings, Box::new(can_in))
        }
        src::Expr_::If(branches, else_expr) => {
            // `if` introduces no bindings: every condition and branch resolves
            // against the same enclosing scope.
            let mut can_branches = Vec::with_capacity(branches.len());
            for (cond, body) in branches {
                let can_cond = canonicalise_expr(cond, env, interner)?;
                let can_body = canonicalise_expr(body, env, interner)?;
                can_branches.push((can_cond, can_body));
            }
            let can_else = canonicalise_expr(else_expr, env, interner)?;
            canon::Expr_::If(can_branches, Box::new(can_else))
        }
        src::Expr_::Tuple(elems) => {
            // A tuple introduces no bindings: every element resolves against the
            // same enclosing scope.
            let mut can_elems = Vec::with_capacity(elems.len());
            for elem in elems {
                can_elems.push(canonicalise_expr(elem, env, interner)?);
            }
            canon::Expr_::Tuple(can_elems)
        }
        src::Expr_::List(elems) => {
            // A list literal introduces no bindings: every element resolves
            // against the same enclosing scope.
            let mut can_elems = Vec::with_capacity(elems.len());
            for elem in elems {
                can_elems.push(canonicalise_expr(elem, env, interner)?);
            }
            canon::Expr_::List(can_elems)
        }
        src::Expr_::Record(fields) => {
            // A record introduces no bindings: every field value resolves against
            // the same enclosing scope. The field names are labels, carried
            // unresolved; a duplicate is rejected (see `canonicalise_fields`).
            canon::Expr_::Record(canonicalise_fields(fields, env, interner)?)
        }
        src::Expr_::Access(record, field) => {
            // `record.field`: the record sub-expression resolves against the
            // enclosing scope; the field is a label carried through unresolved.
            let can_record = canonicalise_expr(record, env, interner)?;
            canon::Expr_::Access(Box::new(can_record), field.value)
        }
        src::Expr_::Update(base, fields) => {
            // `{ base | field = value, ... }`: the base names a record variable,
            // resolved against the enclosing scope exactly as a bare reference
            // would be (an unknown name is the usual `ValueNotFound`). The updated
            // fields resolve the same way as a literal's, with the same
            // duplicate-field rejection.
            let base_node = resolve_var(base.value, base.span, env, interner)?;
            let can_base = Located::new(base.span, base_node);
            let can_fields = canonicalise_fields(fields, env, interner)?;
            canon::Expr_::Update(Box::new(can_base), can_fields)
        }
    };
    Ok(Located::new(span, node))
}

/// Canonicalise a record field list (shared by the literal `{ f = v, ... }` and
/// the update `{ r | f = v, ... }` forms).
///
/// Each field value resolves against the enclosing scope; the field name is a
/// label carried through unresolved. A field name written twice would otherwise
/// silently collapse to one struct field, so a duplicate is rejected here — a
/// field is, in effect, a value defined more than once in the record.
fn canonicalise_fields(
    fields: &[(Located<Symbol>, src::Expr)],
    env: &Env,
    interner: &mut Interner,
) -> DResult<Vec<(Symbol, canon::Expr)>> {
    let mut seen: BTreeMap<Symbol, Span> = BTreeMap::new();
    let mut can_fields = Vec::with_capacity(fields.len());
    for (name, value) in fields {
        if let Some(first) = seen.get(&name.value) {
            return Err(Diagnostic::Name {
                span: name.span,
                msg: NameError::DuplicateValue {
                    name: name_str(interner, name.value)?,
                    first: *first,
                },
            });
        }
        seen.insert(name.value, name.span);
        let can_value = canonicalise_expr(value, env, interner)?;
        can_fields.push((name.value, can_value));
    }
    Ok(can_fields)
}

/// Resolve a bare name: a lexical binder first, then the expression
/// namespace's one ladder (local, explicit, open, ambient), where a constructor
/// and a value of one spelling compete as equals. Unknown → error.
///
/// # Errors
/// [`NameError::AmbiguousImport`] for two open-import definitions no higher
/// tier shadows; [`NameError::ValueNotFound`] when no tier binds the name.
fn resolve_var(name: Symbol, span: Span, env: &Env, interner: &Interner) -> DResult<canon::Expr_> {
    if let Some(home) = env.lookup_var(name) {
        // A lexical binder shadows every module-level binding of its spelling.
        return Ok(var_home_to_expr(name, home));
    }
    match env.module_scope.expr.resolve(name) {
        Resolved::Found(origin, _) => Ok(match &origin.target {
            ExprTarget::Ctor(ctor) => ctor_expr(ctor),
            ExprTarget::Value(home) => var_home_to_expr(name, home),
        }),
        Resolved::Ambiguous { importers } => {
            let modules = importer_names(&importers, interner);
            Err(ambiguous_import(name, span, modules, interner)?)
        }
        Resolved::Missing => Err(value_not_found(name, span, env, interner)?),
    }
}

/// The canonical reference to a resolved constructor.
fn ctor_expr(ctor: &CtorHome) -> canon::Expr_ {
    canon::Expr_::VarCtor {
        home: ctor.home.clone(),
        type_name: ctor.type_name,
        name: ctor.name,
        index: ctor.index,
    }
}

/// Map a resolved [`VarHome`] to its canonical [`canon::Expr_`] form, total over
/// every variant so a lexical binder and every ladder tier share one lowering
/// rule.
fn var_home_to_expr(name: Symbol, home: &VarHome) -> canon::Expr_ {
    match home {
        VarHome::Local => canon::Expr_::VarLocal(name),
        VarHome::TopLevel(module) => canon::Expr_::VarTopLevel {
            module: module.clone(),
            name,
        },
        VarHome::Kernel(id, m, f) => canon::Expr_::VarKernel {
            id: Some(*id),
            module: *m,
            name: *f,
        },
        // A reachable-but-unbacked member: no registry id, so the type stage
        // fails closed with IPE-L0108 rather than resolving to a scheme.
        VarHome::ReservedKernel { module, name } => canon::Expr_::VarKernel {
            id: None,
            module: *module,
            name: *name,
        },
    }
}

/// Build the ordinary `IPE-N0001` [`NameError::ValueNotFound`] for a bare name.
///
/// A bare value name can resolve to either a value binding or a constructor used
/// as a value, so the suggestion pool spans the lexical binders and every
/// module-level value and constructor name.
fn value_not_found(
    name: Symbol,
    span: Span,
    env: &Env,
    interner: &Interner,
) -> DResult<Diagnostic> {
    let name_s = name_str(interner, name)?;
    Ok(Diagnostic::Name {
        span,
        msg: NameError::ValueNotFound {
            suggestions: Candidates::at(
                EditTarget::whole(span, &name_s),
                suggestions(
                    name,
                    env.vars
                        .keys()
                        .copied()
                        .chain(env.module_scope.expr.names()),
                    interner,
                ),
            ),
            name: name_s,
        },
    })
}

/// Reject a bare reference to a reserved literal-only constructor.
///
/// `Rust.Ffi.call` and `CustomElement.fromFile` are legal ONLY fully applied in
/// their sanctioned positions (a `Rust.Ffi` interface call, the whole body of a
/// `CustomElement`-annotated binding). The applied forms are rewritten before
/// their callee resolves, so reaching qualified-name resolution means the name
/// was referenced bare, nested, or applied outside that position — each a
/// malformed use. Returns the precise teachable diagnostic, or `None` when the
/// name is not a reserved constructor.
fn reject_bare_reserved_constructor(
    qualifier: Symbol,
    name: Symbol,
    span: Span,
    env: &Env,
    interner: &Interner,
) -> Option<Diagnostic> {
    if env.origin == ModuleOrigin::User
        && interner.resolve(qualifier) == Some(crate::asserted::ASSERTED_MODULE)
        && interner.resolve(name) == Some("call")
    {
        return Some(Diagnostic::Name {
            span,
            msg: NameError::AssertedCallMalformed {
                detail: "`Rust.Ffi.call` is not a value — it must be applied directly \
                         to a string-literal Rust path"
                    .into(),
            },
        });
    }
    if interner.resolve(qualifier) == Some(CUSTOM_ELEMENT_TYPE)
        && interner.resolve(name) == Some(CUSTOM_ELEMENT_CTOR)
    {
        return Some(Diagnostic::Name {
            span,
            msg: NameError::CustomElementCtorMalformed {
                detail: Box::<str>::from(
                    "`CustomElement.fromFile` is legal only as the whole body of a \
                     `CustomElement`-annotated binding, applied to a single string literal",
                ),
            },
        });
    }
    None
}

/// The diagnostic for a constructor pattern naming no constructor in scope.
///
/// An unqualified constructor pattern starts with its name, so a sole
/// did-you-mean may overwrite that prefix; a qualified one starts with the
/// module, so it has no edit region.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] if `name` is not interned.
fn ctor_pattern_not_found(
    name: Symbol,
    unqualified: bool,
    span: Span,
    env: &Env,
    interner: &Interner,
) -> DResult<Diagnostic> {
    let name_s = name_str(interner, name)?;
    let region = if unqualified {
        EditTarget::prefix(span, &name_s)
    } else {
        None
    };
    let ctor_names = env
        .module_scope
        .expr
        .names_where(|target| matches!(target, ExprTarget::Ctor(_)));
    Ok(Diagnostic::Name {
        span,
        msg: NameError::ConstructorNotFound {
            suggestions: Candidates::at(region, suggestions(name, ctor_names, interner)),
            name: name_s,
        },
    })
}

/// `span` when it is exactly the source token `qualifier.member`.
///
/// A reference the parser synthesised (an operator desugared to a qualified
/// name) carries a span of a different width; it gets no edit region.
fn qualified_token(span: Span, qualifier: Option<&str>, member: Option<&str>) -> Option<Span> {
    let width = qualifier?
        .len()
        .checked_add(1)?
        .checked_add(member?.len())?;
    (usize::try_from(span.hi.checked_sub(span.lo)?).ok()? == width).then_some(span)
}

/// The diagnostic for a qualifier no import or ambient table binds.
///
/// A qualifier a bare `import` of some catalog module would bind is IPE-N0034
/// naming every such module; anything else is IPE-N0004 ranked over the
/// qualifiers this module can actually use. `token` is the `qualifier.member`
/// source token when one exists (value position), giving the did-you-mean its
/// edit region; a type annotation has none.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] if `qualifier` is not interned.
fn unbound_qualifier(
    qualifier: Symbol,
    span: Span,
    token: Option<Span>,
    env: &Env,
    interner: &Interner,
) -> DResult<Diagnostic> {
    let qualifier_s = name_str(interner, qualifier)?;
    let home = path_to_dot_string(interner, &env.home);
    let modules = env.module_catalog.modules_bound_by(&qualifier_s, &home);
    if !modules.is_empty() {
        return Ok(import_required(qualifier_s, modules, span, token, env));
    }
    Ok(Diagnostic::Name {
        span,
        msg: NameError::UnknownModule {
            suggestions: Candidates::at(
                token.and_then(|t| EditTarget::prefix(t, &qualifier_s)),
                suggestions(qualifier, env.usable_qualifiers(), interner),
            ),
            qualifier: qualifier_s,
        },
    })
}

/// The verdict for `qualifier`, which a bare `import` of each of `modules`
/// (non-empty, sorted) would bind but no import in this module binds.
///
/// A module already imported under an `as` alias is not missing an import: the
/// use site spelled the module's name instead of its alias, so the verdict is
/// IPE-N0004 offering the alias (an applicable edit only when exactly one
/// module and one alias answer). Otherwise it is IPE-N0034 naming `modules`.
fn import_required(
    qualifier: Box<str>,
    modules: Box<[Box<str>]>,
    span: Span,
    token: Option<Span>,
    env: &Env,
) -> Diagnostic {
    let aliases: BTreeSet<&Box<str>> = modules
        .iter()
        .filter_map(|module| env.import_aliases.get(module))
        .flatten()
        .collect();
    if aliases.is_empty() {
        return Diagnostic::Name {
            span,
            msg: NameError::ImportRequired {
                qualifier,
                candidates: modules,
            },
        };
    }
    let region = if modules.len() == 1 && aliases.len() == 1 {
        token.and_then(|t| EditTarget::prefix(t, &qualifier))
    } else {
        None
    };
    Diagnostic::Name {
        span,
        msg: NameError::UnknownModule {
            suggestions: Candidates::at(region, aliases.into_iter().cloned().collect()),
            qualifier,
        },
    }
}

/// Resolve a qualified name `Qualifier.name`. Distinguishes an unknown
/// qualifier ([`NameError::UnknownModule`]) from a known qualifier missing the
/// member ([`NameError::NoSuchMember`]).
fn resolve_qual_var(
    qualifier: Symbol,
    name: Symbol,
    span: Span,
    env: &Env,
    interner: &Interner,
) -> DResult<canon::Expr_> {
    // A bare reference to a reserved literal-only constructor (`Rust.Ffi.call`,
    // `CustomElement.fromFile`) has no value to denote — each is legal only fully
    // applied in a sanctioned position, so refuse it with a teachable diagnostic
    // rather than a no-such-member miss.
    if let Some(diag) = reject_bare_reserved_constructor(qualifier, name, span, env, interner) {
        return Err(diag);
    }
    // Resolve the qualifier and member text once and reuse across the
    // removed-surface and negate gates below — the interner lookup is a Vec
    // index plus a content compare, and both symbols are consulted twice.
    let qualifier_text = interner.resolve(qualifier);
    let name_text = interner.resolve(name);
    // Removed-surface gate (IPE-N0036): bindings intentionally dropped from
    // the Ipê surface are intercepted here before any catalog lookup, so the
    // user gets a clear migration diagnostic rather than "no such member".
    // Checked ahead of the import gate since the surface binding is gone
    // regardless of whether the module was imported.
    if qualifier_text == Some("Task") {
        match name_text {
            Some("run") => {
                return Err(Diagnostic::Name {
                    span,
                    msg: NameError::RemovedSurface {
                        qualifier: "Task".into(),
                        name: "run".into(),
                        // The entry boundary auto-runs a Task-typed `main`;
                        // mid-flow forcing can use `Task.andThen` chains.
                        replacement: "".into(),
                    },
                });
            }
            Some("perform") => {
                return Err(Diagnostic::Name {
                    span,
                    msg: NameError::RemovedSurface {
                        qualifier: "Task".into(),
                        name: "perform".into(),
                        replacement: "Task.attempt".into(),
                    },
                });
            }
            _ => {}
        }
    }
    // Unary minus desugars (in the parser) to a `Basics.negate` reference. Its
    // qualified form resolves DIRECTLY to the negate kernel here, bypassing the
    // scope chain, so a user binding named `negate` cannot capture the operator:
    // `-x` always means arithmetic negation. `Basics` is the ambient prelude
    // (Tier A) and is not otherwise a resolvable qualifier, so this is the sole
    // `Basics.member` spelling — no member table to consult.
    if qualifier_text == Some("Basics") && name_text == Some("negate") {
        return Ok(canon::Expr_::VarKernel {
            id: Some(StdlibKernel::BasicsNegate),
            module: qualifier,
            name,
        });
    }
    // Tier-C import gate (ADR 0001): a known stdlib qualifier used WITHOUT its
    // import is the teachable must-import diagnostic (IPE-N0034), naming the exact
    // `Ipe.*` module to add — NOT a silent resolve against the pre-installed
    // catalog, and NOT the generic "unknown module" (the module is known; the
    // import is missing). Checked before the member lookup, since the catalog
    // members are present regardless of import.
    let token = qualified_token(span, qualifier_text, name_text);
    if let Some(import_path) = env.stdlib_import_required(qualifier) {
        return Err(import_required(
            name_str(interner, qualifier)?,
            Box::new([path_to_dot_string(interner, import_path)]),
            span,
            token,
            env,
        ));
    }
    let Some(members) = env.qual_members(qualifier) else {
        return Err(unbound_qualifier(qualifier, span, token, env, interner)?);
    };
    match members.get(&name) {
        Some(VarHome::Kernel(id, m, f)) => Ok(canon::Expr_::VarKernel {
            id: Some(*id),
            module: *m,
            name: *f,
        }),
        // Reachable-but-unbacked member: no registry id, IPE-L0108 at type-check.
        Some(VarHome::ReservedKernel { module, name }) => Ok(canon::Expr_::VarKernel {
            id: None,
            module: *module,
            name: *name,
        }),
        Some(VarHome::TopLevel(module)) => Ok(canon::Expr_::VarTopLevel {
            module: module.clone(),
            name,
        }),
        Some(VarHome::Local) => Ok(canon::Expr_::VarLocal(name)),
        // The qualifier resolves via qual_vars but the member is not a value.
        // Check qual_ctors — needed for compiled-source ADT constructors accessed
        // as `Alias.CtorName` (e.g. `Money.USD`, `Money.EUR`).
        None => {
            if let Some(ctor_map) = env.qual_ctors.get(&qualifier)
                && let Some(ch) = ctor_map.get(&name)
            {
                return Ok(canon::Expr_::VarCtor {
                    home: ch.home.clone(),
                    type_name: ch.type_name,
                    name: ch.name,
                    index: ch.index,
                });
            }
            let member = name_str(interner, name)?;
            Err(Diagnostic::Name {
                span,
                msg: NameError::NoSuchMember {
                    module: name_str(interner, qualifier)?,
                    suggestions: Candidates::at(
                        token.and_then(|t| EditTarget::suffix(t, &member)),
                        suggestions(
                            name,
                            members
                                .keys()
                                .chain(env.qual_ctors.get(&qualifier).iter().flat_map(|m| m.keys()))
                                .copied(),
                            interner,
                        ),
                    ),
                    member,
                },
            })
        }
    }
}

/// Canonicalise a binary-operator chain into a precedence-correct tree.
///
/// The parser records a chain `e0 op0 e1 op1 … opN-1 eN` as a *flat* list of
/// `(operand, operator)` pairs plus a trailing operand, without consulting
/// precedence. Here we re-associate it via precedence climbing (port of
/// `Ipe.Canonicalise.Expression.canonicaliseBinops`), reading each operator's
/// precedence + associativity from [`fixity`].
///
/// Unlike the reference compiler parser — which nests `Src.Binops` pairwise and so needs a
/// flattening pre-pass — the Rust parser already emits one flat chain per
/// syntactic level. A `Binop` *operand* therefore only ever arises from an
/// explicit parenthesised group, which must stay atomic; we never re-flatten
/// it, so the user's grouping is preserved.
fn canonicalise_binops(
    pairs: &[(src::Expr, Located<Symbol>)],
    final_: &src::Expr,
    env: &Env,
    interner: &mut Interner,
) -> DResult<canon::Expr_> {
    // No operators: just the final operand.
    if pairs.is_empty() {
        return Ok(canonicalise_expr(final_, env, interner)?.value);
    }

    let basics = interner.intern("Basics")?;

    // Canonicalise every operand once, left to right, into a front-poppable
    // queue; pair each operator with its precedence + associativity.
    let mut operands: VecDeque<canon::Expr> = VecDeque::with_capacity(pairs.len() + 1);
    let mut ops: VecDeque<(Located<Symbol>, Fixity)> = VecDeque::with_capacity(pairs.len());
    for (operand, op) in pairs {
        operands.push_back(canonicalise_expr(operand, env, interner)?);
        let op_fixity = fixity(resolve_or_bug(
            interner,
            op.value,
            "ipe_canon::canonicalise_binops",
        )?);
        ops.push_back((*op, op_fixity));
    }
    operands.push_back(canonicalise_expr(final_, env, interner)?);

    let left = operands
        .pop_front()
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_canon::canonicalise_binops",
            detail: "binop chain with operators but no operands".to_owned(),
        })?;
    let tree = climb_binops(left, &mut operands, &mut ops, basics, interner)?;
    Ok(tree.value)
}

/// Precedence-climbing core. Consumes all operators from `ops`, pairing each
/// with the next operand from `operands`, and folds them into `left` according
/// to precedence and associativity.
///
/// Call-stack depth is O(1) in chain length: a `pending` heap-stack holds
/// reduce-deferred `(left, op, prec)` frames so no native frame is opened per
/// operator. Shares the heap-work-stack discipline of
/// `module_classify::walk_expr`.
///
/// Reduce predicate (reproduces the recursive semantics byte-for-byte):
/// - Left/non-assoc: reduce when a pending op is at least as tight as the
///   incoming one (`top_prec >= prec`), restricting its right subtree to
///   strictly-higher precedence.
/// - Right-assoc: reduce only when the pending op is strictly tighter
///   (`top_prec > prec`), leaving equal-precedence ops on the stack so they
///   nest rightward.
fn climb_binops(
    left0: canon::Expr,
    operands: &mut VecDeque<canon::Expr>,
    ops: &mut VecDeque<(Located<Symbol>, Fixity)>,
    basics: Symbol,
    interner: &mut Interner,
) -> DResult<canon::Expr> {
    // Pending frames: left operand + operator + its precedence, awaiting their
    // right subtree once higher-precedence operators to the right are reduced.
    let mut pending: Vec<(canon::Expr, Located<Symbol>, u8)> = Vec::new();
    let mut left = left0;
    while let Some(&(op, op_fixity)) = ops.front() {
        let prec = op_fixity.prec();
        // Reduce any pending frame whose operator binds at least as tightly as
        // the incoming `op` (left/non-assoc) or strictly tighter (right-assoc).
        while let Some(&(_, _, top_prec)) = pending.last() {
            let should_reduce = match op_fixity.assoc() {
                Assoc::Left | Assoc::None => top_prec >= prec,
                Assoc::Right => top_prec > prec,
            };
            if !should_reduce {
                break;
            }
            let (l, top_op, _) = pending.pop().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_canon::climb_binops",
                detail: "pending stack empty after last() confirmed non-empty".to_owned(),
            })?;
            left = combine_binop(l, top_op, left, basics, interner)?;
        }
        ops.pop_front();
        let next = operands
            .pop_front()
            .ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_canon::climb_binops",
                detail: "operator without a right operand".to_owned(),
            })?;
        pending.push((left, op, prec));
        left = next;
    }
    // Drain remaining pending frames right-to-left (rightmost operator was
    // pushed last; LIFO pop folds left correctly).
    while let Some((l, op, _)) = pending.pop() {
        left = combine_binop(l, op, left, basics, interner)?;
    }
    Ok(left)
}

/// Resolve an interned `Symbol` to its text, or fail closed with a
/// [`Diagnostic::CompilerBug`] naming `where_`.
///
/// A `Symbol` that the interner cannot resolve is a broken internal invariant,
/// not a user error: every `Symbol` reaching resolution was minted by the same
/// interner. Fail-open handling (an empty string flowing on) turns that
/// invariant break into a silently-wrong result downstream — a mis-precedenced
/// operator, an empty record key, a `TypeNotFound { name: "" }`. Routing it to
/// the compiler-bug channel keeps invalid states unrepresentable.
fn resolve_or_bug<'a>(
    interner: &'a Interner,
    sym: Symbol,
    where_: &'static str,
) -> DResult<&'a str> {
    interner
        .resolve(sym)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_,
            detail: "interned symbol did not resolve".to_owned(),
        })
}

/// Build a single resolved binary-operation node.
fn combine_binop(
    lhs: canon::Expr,
    op: Located<Symbol>,
    rhs: canon::Expr,
    basics: Symbol,
    interner: &mut Interner,
) -> DResult<canon::Expr> {
    let span = Span::new(lhs.span.lo, rhs.span.hi);
    // The cons operator `::` is not a kernel binop — it builds a list node so
    // the type checker can give it the proper `a -> List a -> List a` discipline
    // and the backend can lower it to the runtime list prepend.
    if interner.resolve(op.value) == Some("::") {
        return Ok(Located::new(
            span,
            canon::Expr_::Cons(Box::new(lhs), Box::new(rhs)),
        ));
    }
    // Parser-pipeline operators desugar to calls into `Ipe.Parser`.
    // `a |= b`  keeps b's result:  `Ipe.Parser.ignore a b`
    // `a |. b`  keeps a's result:  `Ipe.Parser.keep   a b`
    //
    // Argument order matches the combinators: `ignore dropped kept` and
    // `keep kept dropped`, so passing (lhs, rhs) in source order is correct —
    // lhs is the left operand, rhs the right, and each combinator runs them
    // left-to-right internally via `map2`.
    {
        // Resolve the operator text to an owned string first so the immutable
        // borrow on `interner` ends before the `intern` calls below.
        let pipe_kind: Option<&'static str> = match interner.resolve(op.value) {
            Some("|=") => Some("ignore"),
            Some("|.") => Some("keep"),
            _ => None,
        };
        if let Some(fn_name) = pipe_kind {
            let mod_ipe = interner.intern("Ipe")?;
            let mod_parser = interner.intern("Parser")?;
            let fn_sym = interner.intern(fn_name)?;
            let callee = Located::new(
                span,
                canon::Expr_::VarTopLevel {
                    module: vec![mod_ipe, mod_parser],
                    name: fn_sym,
                },
            );
            return Ok(Located::new(
                span,
                canon::Expr_::Call(Box::new(callee), vec![lhs, rhs]),
            ));
        }
    }
    // Pipe operators desugar to function application — no new AST node needed.
    // `x |> f`  ≡  `f x`  ⇒  Call(rhs, [lhs])
    // `f <| x`  ≡  `f x`  ⇒  Call(lhs, [rhs])
    // Correct in a curried language: `(g a) x ≡ g a x`, so a chain
    // `[1,2,3] |> List.map inc` becomes Call(Call(List.map,[inc]),[[1,2,3]]),
    // a shape already handled by the existing Call lowering path.
    if interner.resolve(op.value) == Some("|>") {
        return Ok(Located::new(
            span,
            canon::Expr_::Call(Box::new(rhs), vec![lhs]),
        ));
    }
    if interner.resolve(op.value) == Some("<|") {
        return Ok(Located::new(
            span,
            canon::Expr_::Call(Box::new(lhs), vec![rhs]),
        ));
    }
    // Composition operators eta-expand to a lambda over one fresh parameter:
    //   `f >> g`  ≡  `\x -> g (f x)`   (left-to-right composition)
    //   `f << g`  ≡  `\x -> f (g x)`   (right-to-left composition)
    // The parameter name is derived from the operator's source span, so it is
    // unique per occurrence. Its `compose_` prefix is distinct from every fresh
    // pool the lowerer mints (`eta_`/`cap_`/`arg_`/…), so it cannot alias an
    // eta-expansion name; a user binding the same name would be harmlessly
    // shadowed, since this lambda's body references only the (already-resolved)
    // `f`/`g` operands and its own parameter.
    let op_text = interner.resolve(op.value);
    if op_text == Some(">>") || op_text == Some("<<") {
        let forward = op_text == Some(">>");
        let param = interner.intern(&format!("compose_{}_{}", span.lo, span.hi))?;
        // `>>` applies `f` (lhs) first then `g` (rhs); `<<` applies `g` (rhs)
        // first then `f` (lhs). `inner` is the first application, `outer` wraps it.
        let (first, second) = if forward { (lhs, rhs) } else { (rhs, lhs) };
        let arg = Located::new(span, canon::Expr_::VarLocal(param));
        let inner = Located::new(span, canon::Expr_::Call(Box::new(first), vec![arg]));
        let outer = Located::new(span, canon::Expr_::Call(Box::new(second), vec![inner]));
        let pat = Located::new(span, canon::Pattern_::PVar(param));
        return Ok(Located::new(
            span,
            canon::Expr_::Lambda(vec![pat], Box::new(outer)),
        ));
    }
    let func = resolve_op_func(op.value, interner)?;
    Ok(Located::new(
        span,
        canon::Expr_::Binop {
            op: op.value,
            op_span: op.span,
            home: basics,
            func,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        },
    ))
}

/// Map an operator symbol to its kernel function name. Supported subset of
/// `Expression.resolveOpName`.
fn resolve_op_func(op: Symbol, interner: &mut Interner) -> DResult<Symbol> {
    let func: Option<&'static str> = match interner.resolve(op) {
        Some("+") => Some("add"),
        Some("-") => Some("sub"),
        Some("*") => Some("mul"),
        Some("/") => Some("fdiv"),
        Some("//") => Some("idiv"),
        Some("==") => Some("eq"),
        Some("/=") => Some("neq"),
        Some("<") => Some("lt"),
        Some(">") => Some("gt"),
        Some("<=") => Some("le"),
        Some(">=") => Some("ge"),
        Some("&&") => Some("and"),
        Some("||") => Some("or"),
        Some("++") => Some("append"),
        // Unknown operators map to their own name under Basics, matching the
        // the compiler fall-through (`_ -> Can.VarKernel "Basics" op`).
        _ => None,
    };
    // The immutable borrow above ends here, so interning is now permitted.
    func.map_or(Ok(op), |name| interner.intern(name))
}

/// An alias a bare or qualified type reference expands through.
#[derive(Clone, Copy)]
enum ResolvedAlias<'a> {
    /// Declared in this module: its source body expands in this module's scope.
    Local {
        params: &'a [Symbol],
        body: &'a src::TypeAnnotation,
    },
    /// Exported by a dependency, its body already canonical.
    Imported(&'a crate::ExportedAlias),
}

/// What a bare type name resolves to, by one precedence: local, explicit
/// import, open (`exposing (..)`) import, reserved builtin.
enum TypeName<'a> {
    /// The alias the ladder's first answering tier binds.
    Alias(ResolvedAlias<'a>),
    /// The union the ladder's first answering tier binds, with its home.
    Union(Vec<Symbol>),
    /// Two open imports bring in the name from distinct homes.
    Ambiguous { modules: SortedNames },
    /// A reserved builtin type name (the empty-home sentinel).
    Builtin,
    /// No tier binds the name.
    Missing,
}

/// Resolve a bare type name to the alias or union it names.
///
/// One ladder covers aliases and unions alike ([`crate::scope::Scope::resolve`]),
/// so a lower tier can never beat a higher one; then a reserved builtin. A name
/// in `visited` is a local alias mid-expansion: its recursive use skips the
/// ladder, whose local tier that alias occupies.
fn resolve_unqualified_type_name<'a>(
    name: Symbol,
    ctx: &TypeCtx<'a>,
    visited: &[Symbol],
) -> DResult<TypeName<'a>> {
    if !visited.contains(&name) {
        match ctx.env.module_scope.ty.resolve(name) {
            Resolved::Found(origin, _) => {
                return Ok(match &origin.target {
                    ScopeType::Union(home) => TypeName::Union(home.clone()),
                    ScopeType::Alias(AliasBody::Local { params, body }) => {
                        TypeName::Alias(ResolvedAlias::Local { params, body })
                    }
                    ScopeType::Alias(AliasBody::Imported(exported)) => {
                        TypeName::Alias(ResolvedAlias::Imported(exported))
                    }
                });
            }
            Resolved::Ambiguous { importers } => {
                return Ok(TypeName::Ambiguous {
                    modules: importer_names(&importers, ctx.interner),
                });
            }
            Resolved::Missing => {}
        }
    }
    let name_s = resolve_or_bug(
        ctx.interner,
        name,
        "ipe_canon::resolve_unqualified_type_name",
    )?;
    if is_reserved_builtin_type_name(name_s) {
        // Empty-home sentinel: the lowerer's per-name explicit arm resolves it.
        return Ok(TypeName::Builtin);
    }
    Ok(TypeName::Missing)
}

/// The IPE-N0002 for a bare type name no tier binds, ranked over every type
/// name in scope.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] if `name` is not interned.
fn type_not_found(name: Symbol, ctx: &TypeCtx) -> DResult<Diagnostic> {
    let name_s = resolve_or_bug(ctx.interner, name, "ipe_canon::type_not_found")?;
    let candidates = ctx.env.module_scope.ty.names();
    Ok(Diagnostic::Name {
        span: ctx.ann_span,
        msg: NameError::TypeNotFound {
            name: name_s.into(),
            suggestions: Candidates::hints(suggestions(name, candidates, ctx.interner)),
        },
    })
}

/// What a type reference resolved to: an alias to expand (with the `aliases`
/// key a recursive use is tracked under), or a union's home.
enum TypeTarget<'a> {
    Alias(Symbol, ResolvedAlias<'a>),
    Home(Vec<Symbol>),
}

/// The IPE-N0024 for a bare name two imports bring in from distinct homes.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] if `name` is not interned.
fn ambiguous_import(
    name: Symbol,
    span: Span,
    modules: SortedNames,
    interner: &Interner,
) -> DResult<Diagnostic> {
    Ok(Diagnostic::Name {
        span,
        msg: NameError::AmbiguousImport {
            name: name_str(interner, name)?,
            modules,
        },
    })
}

/// The home of a qualified union reference `qualifier.name` that names no alias.
///
/// A dep qualifier gives the dep's path. Any other qualifier (a stdlib kernel
/// module) falls back to the union home the bare name's ladder answers with,
/// else the empty-home sentinel. Two open-import homes for the name are
/// IPE-N0024, never a silent pick.
///
/// Html-family builtin force-home: `fold_html_stdlib_qualifier_homes` registers
/// an Html-family stdlib qualifier's real dep path, but the reserved builtin
/// VIEW-TYPE names (`Attribute`/`Html`) must lower to the `["Html"]` carrier the
/// HM constrainer and the lowerer's `is_html` check both expect. So a
/// reserved-builtin name under an Html-family qualifier force-homes to
/// `["Html"]`. A compiled-source ADT declared in `Ipe.Html.Attributes` (e.g.
/// `Attr.LinkTarget`) is NOT a reserved builtin, so it keeps its real module
/// home; homing it to `["Html"]` would mint a phantom `html::LinkTarget` the
/// runtime has no type for. `Ui.Attribute` (a non-Html qualifier) is untouched
/// — it falls through to the empty Ui sentinel.
///
/// # Errors
/// [`NameError::AmbiguousImport`] for two open-import homes;
/// [`Diagnostic::CompilerBug`] if `name` is not interned.
fn qualified_type_home(qualifier: Symbol, name: Symbol, ctx: &TypeCtx) -> DResult<Vec<Symbol>> {
    let qualifier_home = if let Some(path) = ctx.qualifier_paths.get(&qualifier) {
        path.clone()
    } else {
        match ctx.env.module_scope.ty.resolve(name) {
            Resolved::Found(
                Origin {
                    target: ScopeType::Union(home),
                    ..
                },
                _,
            ) => home.clone(),
            Resolved::Ambiguous { importers } => {
                let modules = importer_names(&importers, ctx.interner);
                return Err(ambiguous_import(name, ctx.ann_span, modules, ctx.interner)?);
            }
            Resolved::Found(..) | Resolved::Missing => Vec::new(),
        }
    };
    let qualifier_is_html_family = qualifier_home
        .iter()
        .any(|s| ctx.interner.resolve(*s) == Some("Html"));
    let name_is_reserved_builtin = ctx
        .interner
        .resolve(name)
        .is_some_and(is_reserved_builtin_type_name);
    if qualifier_is_html_family && name_is_reserved_builtin {
        // `Html` is interned by `fold_html_stdlib_qualifier_homes` whenever any
        // Html-family import exists, so a hit here is the norm; the qualifier's
        // own home is the fail-closed fallback.
        return Ok(ctx
            .interner
            .lookup("Html")
            .map_or(qualifier_home, |html| vec![html]));
    }
    Ok(qualifier_home)
}

/// Spend one node of a type expansion against its depth and node ceilings.
///
/// Depth is passed BY VALUE and incremented at every recursive call site, so it
/// mirrors the true native call-stack depth (each invocation gets its own copy;
/// sibling iterations in a loop do not compound). It is checked first because it
/// is cheap and profile-independent; the node budget alone cannot guard stack
/// depth (a long straight alias chain produces O(n) nodes but O(n) stack frames).
/// The budget is ticked before any recursion, so a deeper call can only happen
/// once this node has already spent from it — bounding total work regardless of
/// tree shape. A diamond alias re-expands the same subtree at each sibling
/// position; the path-based `visited` guard does not catch it because the
/// diamond is acyclic. This budget does.
///
/// # Errors
/// [`NameError::TypeExpansionTooDeep`] when either ceiling is exceeded.
fn spend_expansion_node(ctx: &TypeCtx, budget: &mut u32, depth: u32) -> DResult<()> {
    if depth > TYPE_EXPANSION_DEPTH_LIMIT {
        return Err(Diagnostic::Name {
            span: ctx.ann_span,
            msg: NameError::TypeExpansionTooDeep {
                kind: AliasExpansionKind::Depth,
                limit: TYPE_EXPANSION_DEPTH_LIMIT,
            },
        });
    }
    spend_budget_node(ctx, budget)
}

/// Spend one node of the expansion's node ceiling.
///
/// # Errors
/// [`NameError::TypeExpansionTooDeep`] when the ceiling is exhausted.
fn spend_budget_node(ctx: &TypeCtx, budget: &mut u32) -> DResult<()> {
    *budget = budget.checked_sub(1).ok_or(Diagnostic::Name {
        span: ctx.ann_span,
        msg: NameError::TypeExpansionTooDeep {
            kind: AliasExpansionKind::Nodes,
            limit: TYPE_EXPANSION_NODE_LIMIT,
        },
    })?;
    Ok(())
}

/// Copy an alias argument into a parameter position, spending one node per node copied.
///
/// A parameter used `k` times copies its argument `k` times, so nesting such an
/// alias multiplies the output: `T (T (T Int))` over a ten-slot `T` is a
/// thousand nodes from a handful of calls. Charging every copied node keeps the
/// expansion's output, not just its call count, under the node ceiling. The
/// walk uses an explicit stack, so a deep argument cannot grow the native one.
///
/// # Errors
/// [`NameError::TypeExpansionTooDeep`] when the copy exhausts the node ceiling.
fn copy_substituted_arg(
    arg: &canon::Type,
    ctx: &TypeCtx,
    budget: &mut u32,
) -> DResult<canon::Type> {
    let mut pending = vec![arg];
    while let Some(node) = pending.pop() {
        spend_budget_node(ctx, budget)?;
        match node {
            canon::Type::Var(_) | canon::Type::Unit => {}
            canon::Type::Lambda(a, b) => {
                pending.push(a);
                pending.push(b);
            }
            canon::Type::Con { args, .. } | canon::Type::Tuple(args) => pending.extend(args),
            canon::Type::Record(fields) | canon::Type::RecordOpen(_, fields) => {
                pending.extend(fields.iter().map(|(_, ty)| ty));
            }
        }
    }
    Ok(arg.clone())
}

/// The `qualified_aliases` key a type reference `qualifier.name` expands
/// through, if any.
///
/// A bare reference looks up its own name. A QUALIFIED reference (`Money.Price`)
/// expands the dep's exported alias through its synthetic `Qualifier.Name` key
/// even when the name was never `exposing`-injected — qualified access needs no
/// exposure. A qualified reference with no such key (a union of the dep, a
/// stdlib kernel type) names no alias at all, so `None`: it never expands a
/// same-named alias of the referencing module, which the qualifier does not name.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] when `name` is not interned.
fn alias_lookup_key(
    qualifier: &str,
    name: Symbol,
    aliases: &QualifiedAliases,
    interner: &Interner,
) -> DResult<Option<Symbol>> {
    if qualifier.is_empty() {
        return Ok(Some(name));
    }
    let name_s = resolve_or_bug(interner, name, "ipe_canon::alias_lookup_key")?;
    Ok(interner
        .lookup(&format!("{qualifier}.{name_s}"))
        .filter(|sym| aliases.contains_key(sym)))
}

/// Canonicalise a type annotation. Supported subset of `Canonicalise.Type`, extended
/// with `type alias` expansion (non-parametric and parametric): a `TType`
/// whose unqualified name registers as an alias is replaced in place by its
/// body, with the use site's type arguments substituted for the alias's declared
/// parameters, so no later stage observes the alias name.
///
/// `subst` maps an in-scope alias parameter to the (already canonicalised) type
/// argument bound to it; a `TVar` found in `subst` resolves to that type instead
/// of remaining free. `visited` carries the chain of aliases currently being
/// expanded along this path — a name already in the chain is a recursive alias,
/// whose expansion stops (the name is left as an opaque constructor) rather than
/// recursing forever (soundness over completeness: a cyclic alias is exotic, but
/// must never hang or crash the compiler).
///
/// # Errors
/// [`Diagnostic::Name`] ([`NameError::AliasArity`]) when an alias is applied to a
/// number of type arguments that differs from its declared parameter count; the
/// span is the enclosing annotation (the type AST carries no inner spans).
/// [`Diagnostic::CompilerBug`] if a name symbol is not interned.
#[allow(clippy::too_many_lines)] // exhaustive type-annotation walker
fn canonicalise_type(
    t: &src::TypeAnnotation,
    ctx: &TypeCtx,
    subst: &BTreeMap<Symbol, canon::Type>,
    free_vars: &mut BTreeSet<Symbol>,
    visited: &mut Vec<Symbol>,
    budget: &mut u32,
    depth: u32,
) -> DResult<canon::Type> {
    spend_expansion_node(ctx, budget, depth)?;
    match t {
        src::TypeAnnotation::TLambda(a, b) => Ok(canon::Type::Lambda(
            Box::new(canonicalise_type(
                a,
                ctx,
                subst,
                free_vars,
                visited,
                budget,
                depth.saturating_add(1),
            )?),
            Box::new(canonicalise_type(
                b,
                ctx,
                subst,
                free_vars,
                visited,
                budget,
                depth.saturating_add(1),
            )?),
        )),
        src::TypeAnnotation::TVar(v) => {
            // A variable bound to an alias argument resolves to that argument; its
            // own free variables were recorded when the argument was canonicalised
            // at the use site, so it does not re-enter `free_vars` here. An unbound
            // variable is genuinely free and is quantified by the binding.
            subst.get(v).map_or_else(
                || {
                    free_vars.insert(*v);
                    Ok(canon::Type::Var(*v))
                },
                |arg| copy_substituted_arg(arg, ctx, budget),
            )
        }
        src::TypeAnnotation::TUnit => Ok(canon::Type::Unit),
        src::TypeAnnotation::TTuple(elems) => {
            let mut can_elems = Vec::with_capacity(elems.len());
            for e in elems {
                can_elems.push(canonicalise_type(
                    e,
                    ctx,
                    subst,
                    free_vars,
                    visited,
                    budget,
                    depth.saturating_add(1),
                )?);
            }
            Ok(canon::Type::Tuple(can_elems))
        }
        src::TypeAnnotation::TRecord(fields) => {
            // Each field type is canonicalised under the current substitution, so
            // a field variable bound by an enclosing alias argument resolves to it
            // and an unbound one is collected into `free_vars` (quantified by the
            // binding) — exactly the [`TVar`] handling above, applied per field.
            let mut can_fields = Vec::with_capacity(fields.len());
            for (name, fty) in fields {
                can_fields.push((
                    name.value,
                    canonicalise_type(
                        fty,
                        ctx,
                        subst,
                        free_vars,
                        visited,
                        budget,
                        depth.saturating_add(1),
                    )?,
                ));
            }
            Ok(canon::Type::Record(can_fields))
        }
        src::TypeAnnotation::TRecordOpen(row_var, fields) => {
            // The row variable names the open tail; like any unbound annotation
            // variable it is quantified by the binding, so it is collected into
            // `free_vars` (unless an enclosing alias argument already bound it,
            // in which case the substitution resolves it). Each constrained
            // field type is canonicalised exactly as in the closed `TRecord`
            // arm above.
            if !subst.contains_key(row_var) {
                free_vars.insert(*row_var);
            }
            let mut can_fields = Vec::with_capacity(fields.len());
            for (name, fty) in fields {
                can_fields.push((
                    name.value,
                    canonicalise_type(
                        fty,
                        ctx,
                        subst,
                        free_vars,
                        visited,
                        budget,
                        depth.saturating_add(1),
                    )?,
                ));
            }
            Ok(canon::Type::RecordOpen(*row_var, can_fields))
        }
        src::TypeAnnotation::TType(qualifier, segments, args) => {
            let name = segments.last().copied().unwrap_or_else(|| {
                // An unnamed type cannot occur in the grammar; fall back to
                // the home module's name so the node is still well-formed.
                ctx.env.home.last().copied().unwrap_or_else(name_zero)
            });
            // Tier-1 qualified-type validation: when the parser produced a
            // non-empty qualifier (e.g. `JsonDec.Decoder`), verify it names a
            // known module qualifier in `env.qual_vars`. Tier-2 (resolving the
            // actual type name via a `qual_types` map) is a follow-up once the
            // multi-module import layer builds that map; for now, a valid
            // qualifier is sufficient to accept the annotation and look the type
            // up in the bare type namespace as usual.
            // An unqualified type carries a genuinely-interned empty-string
            // qualifier, so `""` is a valid result here; only an unresolvable
            // symbol is the compiler-bug case.
            let qualifier_str = resolve_or_bug(
                ctx.interner,
                *qualifier,
                "ipe_canon::canonicalise_type::qualifier",
            )?;
            if !qualifier_str.is_empty() {
                // Tier-C import gate (ADR 0001): a KNOWN stdlib module qualifier on
                // a type (`Dict.Dict`, `JsonDec.Decoder`) used without importing it
                // is the teachable IPE-N0034, naming the module to add — checked
                // before the unknown-qualifier fallback, since the catalog
                // qualifier is present in `qual_vars` regardless of import.
                if let Some(import_path) = ctx.env.stdlib_import_required(*qualifier) {
                    return Err(import_required(
                        qualifier_str.into(),
                        Box::new([path_to_dot_string(ctx.interner, import_path)]),
                        ctx.ann_span,
                        None,
                        ctx.env,
                    ));
                }
                if !ctx.env.qual_vars.contains_key(qualifier) {
                    return Err(unbound_qualifier(
                        *qualifier,
                        ctx.ann_span,
                        None,
                        ctx.env,
                        ctx.interner,
                    )?);
                }
            }
            // `View engine msg` — the engine-tagged view carrier and SSOT view
            // surface. It canonicalises to a real 2-argument `Con(View, [engine
            // tag, msg])` that survives into inference: the engine tag is a
            // nullary `Con` drawn from the CLOSED `{Web, Tui, Cli}` set, and the
            // whole carrier is what every DOM/Tui/Cli combinator's scheme now
            // yields (`View Web msg` IS `Element msg`, `View Tui msg` IS `Screen
            // msg`, `View Cli msg` IS `Lines msg`). Because the tag is a distinct
            // nullary constructor, a cross-engine node (`View Tui msg` where
            // `View Web msg` is expected) fails unification, and an unconstrained
            // engine variable is left unsolved and rejected — never defaulted.
            // The engine tag is read syntactically here (never routed through
            // type-home resolution); any tag outside the closed set has no view
            // denotation and is rejected fail-closed as an unresolved type name.
            // Only the `msg` argument is a real type, canonicalised under the
            // current substitution.
            if qualifier_str.is_empty()
                && ctx.interner.resolve(name) == Some("View")
                && args.len() == 2
                && let Some(src::TypeAnnotation::TType(engine_qual, engine_segs, engine_args)) =
                    args.first()
                && let Some(msg_ann) = args.get(1)
                && engine_args.is_empty()
                && ctx
                    .interner
                    .resolve(*engine_qual)
                    .is_some_and(str::is_empty)
                && let Some(engine) = engine_segs.last().copied()
            {
                // Fail closed: the engine tag MUST be one of the closed view
                // engines `{Web, Tui, Cli}`. Any other tag (a flexible variable
                // included) has no view denotation and is rejected as an
                // unresolved type name, never left as a deferred flexible var.
                match ctx.interner.resolve(engine) {
                    Some("Web" | "Tui" | "Cli") => {}
                    _ => {
                        return Err(Diagnostic::Name {
                            span: ctx.ann_span,
                            msg: NameError::TypeNotFound {
                                name: name_str(ctx.interner, engine)?,
                                suggestions: Candidates::default(),
                            },
                        });
                    }
                }
                // The message argument is canonicalised under the current
                // substitution exactly as any use-site argument; the engine tag
                // becomes a nullary `Con` carrying the interned engine name.
                let msg = canonicalise_type(
                    msg_ann,
                    ctx,
                    subst,
                    free_vars,
                    visited,
                    budget,
                    depth.saturating_add(1),
                )?;
                return Ok(canon::Type::Con {
                    home: Vec::new(),
                    name,
                    args: vec![
                        canon::Type::Con {
                            home: Vec::new(),
                            name: engine,
                            args: Vec::new(),
                        },
                        msg,
                    ],
                });
            }
            // `Element` / `Screen` / `Lines` — the per-engine aliases of the
            // engine-tagged view carrier. Each is exactly `View <engine> msg`
            // (`Element` = `View Web`, `Screen` = `View Tui`, `Lines` = `View
            // Cli`), so it canonicalises to the SAME `Con(View, [engine, msg])`
            // as the carrier. This keeps every existing `: Element msg`
            // annotation and DOM combinator unifying with the SSOT view type the
            // combinator schemes yield, with no parallel surface: the alias and
            // the carrier are one canonical type. The public module-qualified
            // spellings a user writes (`Ui.Element`, the terminal `Screen` /
            // `Lines` equivalents) alias identically: each name is a RESERVED
            // builtin no user module can declare, so the qualifier cannot name a
            // different type, and an unknown qualifier is already turned away by
            // the qualifier gate above. The bare arity-0 form (`view : Element`)
            // is an alias too: its implicit message parameter arity-fills with
            // the `any` wildcard right here, so it canonicalises to the same
            // `View <engine> any` carrier the arity-1 form yields — never a
            // stray `Element any` con that no longer unifies with the View the
            // combinators produce. Only the arity-0 and arity-1 forms are
            // aliases; a mis-arity use falls through.
            if args.len() <= 1
                && let Some(engine_name) = match ctx.interner.resolve(name) {
                    Some("Element") => Some("Web"),
                    Some("Screen") => Some("Tui"),
                    Some("Lines") => Some("Cli"),
                    _ => None,
                }
            {
                // `View` and the engine tags are pre-interned at env init, so a
                // miss here is a compiler bug, never user input.
                let view_sym =
                    ctx.interner
                        .lookup("View")
                        .ok_or_else(|| Diagnostic::CompilerBug {
                            where_: "ipe_canon::canonicalise_type::view_alias",
                            detail: "the `View` carrier name is not interned".into(),
                        })?;
                let engine_sym =
                    ctx.interner
                        .lookup(engine_name)
                        .ok_or_else(|| Diagnostic::CompilerBug {
                            where_: "ipe_canon::canonicalise_type::view_alias",
                            detail: "a view-engine tag name is not interned".into(),
                        })?;
                let msg = match args.first() {
                    Some(msg_ann) => canonicalise_type(
                        msg_ann,
                        ctx,
                        subst,
                        free_vars,
                        visited,
                        budget,
                        depth.saturating_add(1),
                    )?,
                    None => canon::Type::Var(ctx.ui_wildcard_msg),
                };
                return Ok(canon::Type::Con {
                    home: Vec::new(),
                    name: view_sym,
                    args: vec![
                        canon::Type::Con {
                            home: Vec::new(),
                            name: engine_sym,
                            args: Vec::new(),
                        },
                        msg,
                    ],
                });
            }
            // Type arguments are canonicalised under the current substitution
            // (they appear at the use site) regardless of whether `name` is an
            // alias or an ordinary constructor.
            let mut can_args = Vec::with_capacity(args.len());
            for a in args {
                can_args.push(canonicalise_type(
                    a,
                    ctx,
                    subst,
                    free_vars,
                    visited,
                    budget,
                    depth.saturating_add(1),
                )?);
            }
            // Resolve the reference once: an alias expands in place, a union
            // yields its home. A bare name goes through the one precedence
            // ladder (`resolve_unqualified_type_name`); a QUALIFIED reference
            // (`Money.Price`) expands the qualifier's alias through its
            // synthetic key, and otherwise names a union of the qualifier.
            let target = if qualifier_str.is_empty() {
                match resolve_unqualified_type_name(name, ctx, visited)? {
                    TypeName::Alias(alias) => TypeTarget::Alias(name, alias),
                    TypeName::Union(home) => TypeTarget::Home(home),
                    TypeName::Builtin => TypeTarget::Home(Vec::new()),
                    TypeName::Ambiguous { modules } => {
                        return Err(ambiguous_import(name, ctx.ann_span, modules, ctx.interner)?);
                    }
                    TypeName::Missing => return Err(type_not_found(name, ctx)?),
                }
            } else if let Some(alias_key) =
                alias_lookup_key(qualifier_str, name, ctx.qualified_aliases, ctx.interner)?
                && !visited.contains(&alias_key)
                && let Some(exported) = ctx.qualified_aliases.get(&alias_key)
            {
                TypeTarget::Alias(alias_key, ResolvedAlias::Imported(exported))
            } else {
                TypeTarget::Home(qualified_type_home(*qualifier, name, ctx)?)
            };
            let home = match target {
                TypeTarget::Home(home) => home,
                // An alias not already mid-expansion (cycle) is expanded. Arity
                // must match exactly — a type alias has to be fully applied.
                TypeTarget::Alias(alias_key, alias) => {
                    let check_arity = |expected: usize| -> DResult<()> {
                        if can_args.len() == expected {
                            return Ok(());
                        }
                        Err(Diagnostic::Name {
                            span: ctx.ann_span,
                            msg: NameError::AliasArity {
                                name: name_str(ctx.interner, name)?,
                                expected,
                                found: can_args.len(),
                            },
                        })
                    };
                    return match alias {
                        // A local alias: its declared parameters are bound to the
                        // canonicalised arguments and the source body is
                        // canonicalised under that fresh substitution, in this
                        // module's own scope.
                        ResolvedAlias::Local { params, body } => {
                            check_arity(params.len())?;
                            let body_subst: BTreeMap<Symbol, canon::Type> =
                                params.iter().copied().zip(can_args).collect();
                            visited.push(alias_key);
                            let expanded = canonicalise_type(
                                body,
                                ctx,
                                &body_subst,
                                free_vars,
                                visited,
                                budget,
                                depth.saturating_add(1),
                            );
                            visited.pop();
                            expanded
                        }
                        // An imported alias: its body is already canonical in the
                        // defining module's scope, so the arguments are
                        // substituted for its parameter slots and nothing is
                        // re-resolved here.
                        ResolvedAlias::Imported(exported) => {
                            check_arity(exported.param_slots.len())?;
                            free_vars.extend(exported.free_vars.iter().copied());
                            let slots: BTreeMap<Symbol, canon::Type> =
                                exported.param_slots.iter().copied().zip(can_args).collect();
                            instantiate_imported_alias(
                                &exported.body,
                                &slots,
                                ctx,
                                budget,
                                depth.saturating_add(1),
                            )
                        }
                    };
                }
            };
            // `Ipe.Ui.Tui.Attribute` / `Ipe.Ui.Cli.Attribute` — the terminal
            // engines' attribute types, which their kernels mint as the reserved
            // builtins `TuiAttr` / `CliAttr`. The public spelling a user writes
            // (`Tui.Attribute msg`, or `Attribute msg` exposed from either module)
            // canonicalises to that same builtin, so the documented type is
            // nameable. The bare form arity-fills its message parameter exactly
            // as the DOM `Attribute` does.
            if let Some(builtin) = ctx
                .interner
                .resolve(name)
                .and_then(|n| terminal_attribute_builtin(&home, n, ctx.interner))
                && can_args.len() <= 1
            {
                let name = ctx
                    .interner
                    .lookup(builtin)
                    .ok_or_else(|| Diagnostic::CompilerBug {
                        where_: "ipe_canon::canonicalise_type::terminal_attribute",
                        detail: "a terminal attribute builtin name is not interned".into(),
                    })?;
                let args = if can_args.is_empty() {
                    vec![canon::Type::Var(ctx.ui_wildcard_msg)]
                } else {
                    can_args
                };
                return Ok(canon::Type::Con {
                    home: Vec::new(),
                    name,
                    args,
                });
            }
            // A fixed-arity built-in that resolves to the empty-home sentinel
            // (a closed container, or `Ipe.Db`'s `Connection mode` handle and
            // its nullary `ReadOnly`/`ReadWrite` markers) has an exact-`args.len()`
            // lowerer arm: a mis-application (`Maybe List String` parsed as
            // `Maybe` over two args, a bare `List`, `Dict String`, `Connection`,
            // `Connection a b`) would otherwise reach the lowerer's
            // `ir_type_from_canon` empty-home catch-all and ICE (IPE-I0001).
            // Fail closed here with a clean IPE-N0031, the sibling of
            // `AliasArity` for the closed table. Gating on the empty home keeps a
            // user `type List a b` (which wins by its real home) unaffected.
            if home.is_empty()
                && let Some(expected) = builtin_empty_home_arity(ctx.interner.resolve(name))
                && can_args.len() != expected
            {
                return Err(Diagnostic::Name {
                    span: ctx.ann_span,
                    msg: NameError::BuiltinTypeArity {
                        name: name_str(ctx.interner, name)?,
                        expected,
                        found: can_args.len(),
                    },
                });
            }
            // The `CustomElement down up` JS-widget boundary type RESOLVES to a
            // two-parameter opaque builtin — but only after two fail-closed gates,
            // checked on the NAME regardless of home. The name is reserved against
            // every origin (no module — not even trusted stdlib — may define or
            // export it, see the exemption sets), so a qualified spelling
            // (`Dep.CustomElement`) is checked identically to the bare one; user
            // DEFINITION of the name is already rejected earlier (IPE-N0026).
            //
            //   (a) ARITY: exactly two type arguments — the sealed down-state and
            //       the up-event. A mis-arity is a clean IPE-N0031, the same code
            //       the closed builtin containers use; a dedicated NAME-based check
            //       (not `builtin_container_arity`, which gates on the empty-home
            //       sentinel) so the qualified spelling is gated too.
            //   (b) SEAL: each of the two parameters must be a plain, closed,
            //       concrete value type (§2.1). A function, an effect carrier, a
            //       view value, a `Secret`/reserved-sink type, an open row, or a
            //       type variable is rejected fail-closed (IPE-N0039) — such a
            //       value must never be serialised across the Ipê↔JS seam.
            //
            // On passing both, the type resolves to a `Con` with the empty-home
            // sentinel and lowers to the opaque widget handle.
            if ctx.interner.resolve(name) == Some("CustomElement") {
                if can_args.len() != 2 {
                    return Err(Diagnostic::Name {
                        span: ctx.ann_span,
                        msg: NameError::BuiltinTypeArity {
                            name: name_str(ctx.interner, name)?,
                            expected: 2,
                            found: can_args.len(),
                        },
                    });
                }
                for arg in &can_args {
                    if let Some(reason) = boundary_seal_rejection(arg, ctx.interner) {
                        return Err(Diagnostic::Name {
                            span: ctx.ann_span,
                            msg: NameError::BoundarySealIllegal {
                                seal_type: canon_type_display(arg, ctx.interner),
                                reason,
                            },
                        });
                    }
                }
                return Ok(canon::Type::Con {
                    home: Vec::new(),
                    name,
                    args: can_args,
                });
            }
            // A bare builtin parametric UI constructor (`Html` / `Attribute`)
            // carries one implicit message parameter — `view : Html`
            // means `view : Html any`, with the message type inferred from the
            // body's `Ui.layout …`. Arity-fill the missing parameter here, at the
            // single canon source of truth, so BOTH the type checker (via
            // `from_canon`, whose `any`-wildcard machinery gives each occurrence a
            // fresh flex variable) AND the lowerer see `Html any` rather than a
            // zero-arg `Html` that reaches the lowerer's empty-home catch-all ICE
            // (IPE-I0001). The fill is gated on the empty-home sentinel, so a user
            // `type Html a` (real home) is never touched; the synthetic `any` var
            // is NOT collected into `free_vars`, keeping it a per-occurrence
            // wildcard the solver resolves rather than a quantified type parameter.
            // The view aliases (`Element` / `Screen` / `Lines`) are NOT filled
            // here — their bare form already canonicalised to the `View <engine>
            // any` carrier above, so a fill here would forge a stray `Element any`.
            let can_args = if home.is_empty()
                && can_args.is_empty()
                && matches!(ctx.interner.resolve(name), Some("Html" | "Attribute"))
            {
                vec![canon::Type::Var(ctx.ui_wildcard_msg)]
            } else {
                can_args
            };
            Ok(canon::Type::Con {
                home,
                name,
                args: can_args,
            })
        }
    }
}

/// The reserved builtin a terminal engine's `Attribute` resolves to:
/// `Ipe.Ui.Tui.Attribute` (re-exposed by `Ipe.Ui.Cells`) is `TuiAttr`,
/// `Ipe.Ui.Cli.Attribute` is `CliAttr`.
fn terminal_attribute_builtin(
    home: &[Symbol],
    name: &str,
    interner: &Interner,
) -> Option<&'static str> {
    if name != "Attribute" {
        return None;
    }
    let segments: Vec<&str> = home.iter().filter_map(|s| interner.resolve(*s)).collect();
    match segments.as_slice() {
        ["Ipe", "Ui", "Tui" | "Cells"] => Some("TuiAttr"),
        ["Ipe", "Ui", "Cli"] => Some("CliAttr"),
        _ => None,
    }
}

/// Resolve a symbol to an owned name for a diagnostic payload.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] (`IPE-I0010`) when the symbol is not backed by
/// the interner — every name here came from the parser via this interner, so a
/// miss is an impossible-invariant violation, surfaced rather than swallowed as
/// an empty identifier.
fn name_str(interner: &Interner, sym: Symbol) -> DResult<Box<str>> {
    interner
        .resolve(sym)
        .map(Box::<str>::from)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "intern.resolve",
            detail: "canonicaliser: name symbol not backed by the interner".to_owned(),
        })
}

/// A resolved Stage-4 kernel alias — the target of a standard-library binding
/// of the shape `f = Kernel.kernel "Module_function"`.
///
/// The binding routes every reference of `f` straight to the built-in kernel
/// `id`, so it lowers identically to a qualified `Module.function` call. The
/// `module` / `function` symbols are the first-`_` split of the kernel string,
/// retained so the alias registers a [`VarHome::Kernel`] carrying the same
/// canonical `(module, function)` pair a direct qualified reference produces.
#[derive(Clone, Copy)]
pub struct KernelAlias {
    pub id: StdlibKernel,
    pub module: Symbol,
    pub function: Symbol,
}

/// Recognise the `Ffi.binding "<wrapper_fn_ident>" arg0 …` body shape of a
/// driver-generated FFI interface module and produce the typed
/// [`canon::Expr_::ForeignCall`] node.
///
/// Returns `Ok(None)` for every module whose origin is not
/// [`ModuleOrigin::FfiInterface`] — the call then falls through to ordinary
/// qualified-name resolution, where `Ffi` is not an importable module and the
/// reference fails with the ordinary unknown-name diagnostic. This is the
/// trust gate: user source can never mint a `ForeignCall`, so an arbitrary
/// wrapper identifier (or a mistyped annotation over one) is unrepresentable
/// outside driver-vouched interface modules.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] when an `FfiInterface` module carries a
/// malformed `Ffi.binding` shape (non-literal or non-identifier wrapper name)
/// — the driver generated it, so malformation is an internal invariant
/// violation, never user error.
fn canonicalise_foreign_call(
    callee: &src::Expr,
    args: &[src::Expr],
    span: Span,
    env: &Env,
    interner: &mut Interner,
) -> DResult<Option<canon::Expr_>> {
    if env.origin != ModuleOrigin::FfiInterface {
        return Ok(None);
    }
    let src::Expr_::VarQual(qualifier, member) = &callee.value else {
        return Ok(None);
    };
    let ffi_sym = interner.intern("Ffi")?;
    // The `asserted` spelling is matched by RESOLVE, not intern: interning a
    // symbol the module never spells would shift the deterministic interning
    // sequence (and with it, golden byte identity) for every pre-existing
    // FFI program. A module that does spell `Ffi.asserted` interned the word
    // at parse, so resolve finds it.
    let binding_sym = interner.intern("binding")?;
    let member_is_binding = *member == binding_sym;
    let asserted = interner.resolve(*member) == Some("asserted");
    if *qualifier != ffi_sym || (!member_is_binding && !asserted) {
        return Ok(None);
    }
    let malformed = |detail: String| Diagnostic::CompilerBug {
        where_: "canon.foreign_binding",
        detail,
    };
    let Some((ident_expr, value_args)) = args.split_first() else {
        return Err(malformed(format!(
            "Ffi.binding without a wrapper-identifier argument at {span:?}"
        )));
    };
    let src::Expr_::Str(ident) = &ident_expr.value else {
        return Err(malformed(format!(
            "Ffi.binding wrapper identifier must be a string literal at {span:?}"
        )));
    };
    let mut chars = ident.chars();
    let well_formed = chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !well_formed {
        return Err(malformed(format!(
            "Ffi.binding wrapper identifier {ident:?} is not a Rust fn identifier"
        )));
    }
    let mut can_args = Vec::with_capacity(value_args.len());
    for a in value_args {
        can_args.push(canonicalise_expr(a, env, interner)?);
    }
    Ok(Some(canon::Expr_::ForeignCall {
        ident: interner.intern(ident)?,
        args: can_args,
        asserted,
    }))
}

/// Recognise a USER-module `Rust.Ffi.call "<crate>::<fn>"` application and
/// rewrite it to a reference to the driver-generated definition in the
/// `Rust.Ffi` interface module (see [`crate::asserted`]).
///
/// The rewrite never mints a [`canon::Expr_::ForeignCall`] — that stays
/// exclusive to [`ModuleOrigin::FfiInterface`] bodies. It only re-points the
/// call at the generated forwarder, which ordinary qualified-name resolution
/// (import gate included) then resolves; the forwarder's annotation is the
/// author's asserted signature, so type checking proceeds normally.
///
/// Returns `Ok(None)` when the callee is not `Rust.Ffi.call` in a
/// [`ModuleOrigin::User`] module.
///
/// # Errors
/// [`NameError::AssertedCallMalformed`] (IPE-N0038) for a non-literal path
/// argument, an invalid path, or a path the build driver generated no
/// forwarder for (the site the driver's scan refused, or a compile path with
/// no FFI preparation).
fn canonicalise_asserted_call(
    callee: &src::Expr,
    args: &[src::Expr],
    span: Span,
    env: &Env,
    interner: &mut Interner,
) -> DResult<Option<canon::Expr_>> {
    if env.origin != ModuleOrigin::User {
        return Ok(None);
    }
    // Matched by RESOLVE, never intern: this runs for every call expression
    // in every user module, and interning a symbol the module never spells
    // would shift the deterministic interning sequence (golden byte identity).
    // A module that does spell `Rust.Ffi.call` / `Rust.fn` interned the
    // symbols at parse.
    let Some(which) = crate::asserted::classify_asserted_callee(callee, interner) else {
        return Ok(None);
    };
    let malformed = |detail: String| Diagnostic::Name {
        span,
        msg: NameError::AssertedCallMalformed {
            detail: detail.into_boxed_str(),
        },
    };
    // Each spelling consumes its own leading string literals as the path; any
    // remaining arguments are value arguments applied to the forwarder.
    let path_arity = crate::asserted::path_arg_count(which);
    if args.len() < path_arity {
        return Err(malformed(match which {
            crate::asserted::AssertedCallee::Call => {
                "it is applied to no arguments — the first argument must be the \
                 string-literal Rust path"
                    .to_owned()
            }
            crate::asserted::AssertedCallee::RustFn => {
                "`Rust.fn` takes exactly two string literals: the crate and the item \
                 path (`Rust.fn \"sha2\" \"Sha256::digest\"`)"
                    .to_owned()
            }
            crate::asserted::AssertedCallee::RustConst => {
                "`Rust.const` takes exactly two string literals: the crate and the item \
                 path (`Rust.const \"std\" \"f64::consts::PI\"`)"
                    .to_owned()
            }
        }));
    }
    let (path_args, value_args) = args.split_at(path_arity);
    let path = crate::asserted::read_asserted_path(which, callee.span, path_args)
        .map_err(|(_, detail)| malformed(detail))?;
    // A native constant reads through its own generated definition (a bare
    // value), distinct from the `Rust.fn` forwarder even at an identical path.
    let def_name = match which {
        crate::asserted::AssertedCallee::RustConst => path.const_def_name(),
        _ => path.def_name(),
    };
    let def_sym = interner.intern(&def_name)?;
    // The generated module is imported as `import Rust.Ffi` (unaliased), which
    // registers it under its LAST path segment like every dep import — so the
    // rewritten reference resolves through the `Ffi` qualifier even though the
    // surface spelling is the full `Rust.Ffi.call`.
    let ffi_qualifier = interner.intern("Ffi")?;
    let raw_path = path.as_str().to_owned();
    let target = resolve_qual_var(ffi_qualifier, def_sym, span, env, interner).map_err(|_| {
        malformed(format!(
            "no asserted binding exists for `{raw_path}` — a native binding needs \
             `import Rust.Ffi` (unaliased), the target crate installed via `ipe rust \
             add`, and a top-level annotated definition whose whole body is this call"
        ))
    })?;
    if value_args.is_empty() {
        return Ok(Some(target));
    }
    // A native constant is a bare value read — it is never applied to
    // arguments, so any trailing value argument is a misuse, refused here.
    if matches!(which, crate::asserted::AssertedCallee::RustConst) {
        return Err(malformed(
            "`Rust.const` reads a bare native constant and takes no value arguments — \
             it is applied to none"
                .to_owned(),
        ));
    }
    let mut can_args = Vec::with_capacity(value_args.len());
    for a in value_args {
        can_args.push(canonicalise_expr(a, env, interner)?);
    }
    Ok(Some(canon::Expr_::Call(
        Box::new(ipe_diagnostics::Located::new(callee.span, target)),
        can_args,
    )))
}

/// The offending-argument shape a `CustomElement.fromFile` body rejects, each naming the
/// specific rule broken for the IPE-N0044 diagnostic detail.
fn custom_element_ctor_error(span: Span, detail: &'static str) -> Diagnostic {
    Diagnostic::Name {
        span,
        msg: NameError::CustomElementCtorMalformed {
            detail: Box::<str>::from(detail),
        },
    }
}

/// Is `raw` an ABSOLUTE / rooted path under EITHER target's separator regime?
///
/// A widget-hook literal must be project-root-relative: it is joined against the
/// project root at the build gate, and `Path::join` discards the base when its
/// argument is absolute, so a rooted literal escapes the project. The compiler
/// does not know the final target OS, so — like the shared traversal seal — this
/// rejects a literal rooted under Unix OR Windows rules, never relying on the
/// host's own `Path::is_absolute` (which is host-OS-specific: on Linux `C:\x`
/// would read as relative). Rooted shapes caught, all before any cleaning:
/// * a leading `/` — a Unix (and Windows) absolute root;
/// * a leading `\` — a Windows root or the first byte of a `\\` UNC prefix;
/// * a `C:` drive designator (an ASCII letter then `:`), rooted or drive-relative
///   alike (`C:\x` and `C:x` both anchor to a volume, never the project root).
///
/// A bare leading `.` or an ordinary `js/x.js` is relative and passes.
fn is_rooted_widget_path(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    // Leading separator under either regime (`/` always; `\` on Windows), which
    // also covers the first byte of a `\\server\share` / `\\?\…` UNC prefix.
    if matches!(bytes.first(), Some(b'/' | b'\\')) {
        return true;
    }
    // A `C:`-style drive designator: an ASCII letter followed by a colon.
    matches!((bytes.first(), bytes.get(1)), (Some(c), Some(b':')) if c.is_ascii_alphabetic())
}

/// The last name segment of a syntactic type annotation's head constructor, or
/// `None` when the annotation is not a bare/qualified type-constructor application
/// (an arrow, a tuple, a record, a variable). Used to recognise a
/// `CustomElement …` annotation by NAME regardless of any leading qualifier.
fn annotation_head_name<'a>(ann: &src::TypeAnnotation, interner: &'a Interner) -> Option<&'a str> {
    let src::TypeAnnotation::TType(_, segments, _) = ann else {
        return None;
    };
    interner.resolve(*segments.last()?)
}

/// Recognise the reserved `CustomElement.fromFile "<js-path>"` constructor binding and
/// resolve it to a typed [`canon::Def`] carrying a [`canon::Expr_::CustomElementCtor`].
///
/// The constructor is the JS-widget analogue of the `Kernel.kernel "…"` literal
/// gate: legal ONLY as the entire body of a binding annotated `CustomElement
/// down up`, applied to a SINGLE STRING LITERAL naming the author's widget-hook
/// JS file. The two type parameters are the seal (down-state / up-event) only;
/// the JS source is a value argument, never a type parameter. The literal is
/// cleaned and traversal-checked at build time here (reusing the same
/// `ipe_path_core` seal); its existence inside the
/// project root is verified later, at the build stage that owns the root.
///
/// Returns:
/// * `Ok(None)` — the binding does not mention `CustomElement.fromFile` at all (an ordinary
///   value / function); the caller canonicalises it normally.
/// * `Ok(Some(def))` — a well-formed constructor binding.
/// * `Err(IPE-N0044)` — the binding IS a `CustomElement.fromFile` use but is malformed: a
///   non-literal argument, a bare (unapplied) reference, a wrong argument count, a
///   traversing path, a missing / non-`CustomElement` annotation, or the binding
///   carrying parameters. Fail-closed: absent proof the widget path is a safe,
///   in-project, build-readable literal, the binding is refused (Security #5).
///
/// # Errors
/// [`NameError::CustomElementCtorMalformed`] (IPE-N0044) on any malformed use.
/// A path that fails the traversal seal surfaces as [`ParseError::InvalidPathLiteral`]
/// (IPE-P0063), through `ipe_diagnostics::path_check::PathLitText::seal`.
fn detect_custom_element_constructor(
    val: &src::Value,
    env: &Env,
    qualifier_paths: &BTreeMap<Symbol, Vec<Symbol>>,
    qualified_aliases: &QualifiedAliases,
    interner: &Interner,
    ui_wildcard_msg: Symbol,
) -> DResult<Option<canon::Def>> {
    // Peel the outermost application head. The constructor head is the qualified
    // `CustomElement.fromFile` member (reached through `import
    // Ipe.Ffi.Js.CustomElement as CustomElement`), whether applied
    // (`CustomElement.fromFile "x"`) or bare (`CustomElement.fromFile`).
    let (head, args): (&src::Expr, &[src::Expr]) = match &val.body.value {
        src::Expr_::Call(callee, args) => (callee, args.as_slice()),
        // A bare reference (`codeEditor = CustomElement.fromFile`) — the head is
        // the body itself with no arguments, so the shared validation reports the
        // unapplied case.
        src::Expr_::VarQual(..) => (&val.body, &[]),
        _ => return Ok(None),
    };
    let src::Expr_::VarQual(qualifier, member) = &head.value else {
        return Ok(None);
    };
    if interner.resolve(*qualifier) != Some(CUSTOM_ELEMENT_TYPE)
        || interner.resolve(*member) != Some(CUSTOM_ELEMENT_CTOR)
    {
        return Ok(None);
    }

    // From here the binding IS claiming the constructor: every failure is a
    // fail-closed IPE-N0044, never a fall-through to ordinary resolution.

    // The binding must be a bare value, not a function — the constructor has no
    // curried surface.
    if !val.patterns.is_empty() {
        return Err(custom_element_ctor_error(
            val.body.span,
            "`CustomElement.fromFile` is a value constructor and takes no binding parameters",
        ));
    }

    // The annotation must be present and name the reserved `CustomElement`
    // boundary type. Checked by NAME (the type is reserved + un-shadowable), so a
    // qualified spelling is gated identically; a missing or other annotation is
    // the wrong-position case.
    let Some(ann) = &val.type_annotation else {
        return Err(custom_element_ctor_error(
            val.body.span,
            "`CustomElement.fromFile` is legal only as the body of a binding annotated \
             `CustomElement down up`; this binding has no such annotation",
        ));
    };
    if annotation_head_name(&ann.value, interner) != Some(CUSTOM_ELEMENT_TYPE) {
        return Err(custom_element_ctor_error(
            val.body.span,
            "`CustomElement.fromFile` is legal only as the body of a binding annotated \
             `CustomElement down up`",
        ));
    }

    // The single string-literal argument, sealed to a cleaned, project-relative,
    // traversal-free widget path.
    let cleaned = custom_element_widget_path(args, val.body.span)?;

    // Resolve the annotation to its canonical type — this re-runs the arity + SEAL
    // gates on `CustomElement down up`, so a mis-arity (IPE-N0031) or seal-illegal
    // parameter (IPE-N0039) is still rejected here exactly as for any other
    // `CustomElement` annotation.
    let mut free_vars = BTreeSet::new();
    let mut visited = Vec::new();
    let ctx = TypeCtx {
        env,
        qualifier_paths,
        qualified_aliases,
        interner,
        ui_wildcard_msg,
        ann_span: ann.span,
    };
    let subst = BTreeMap::new();
    let mut budget = TYPE_EXPANSION_NODE_LIMIT;
    let ty = canonicalise_type(
        &ann.value,
        &ctx,
        &subst,
        &mut free_vars,
        &mut visited,
        &mut budget,
        0,
    )?;
    let mut free_vars: Vec<Symbol> = free_vars.into_iter().collect();
    free_vars.sort_by(|a, b| interner.resolve(*a).cmp(&interner.resolve(*b)));

    let body =
        ipe_diagnostics::Located::new(val.body.span, canon::Expr_::CustomElementCtor(cleaned));
    Ok(Some(canon::Def::Typed {
        home: env.home.clone(),
        name: val.name,
        free_vars,
        patterns: Vec::new(),
        body,
        ty,
    }))
}

/// Seal a `CustomElement.fromFile` argument list to a cleaned widget path.
///
/// Enforces exactly one string-literal argument, cleans it through the shared
/// `ipe_path_core` seal, and tightens to a project-root-relative
/// path. Every failure is the fail-closed IPE-N0044 (or the path-literal
/// IPE-P0063 for a `..` escape); the caller is already committed to the
/// constructor, so there is no fall-through.
fn custom_element_widget_path(args: &[src::Expr], body_span: Span) -> DResult<String> {
    // Exactly one argument, and it must be a string literal — a non-literal
    // (a variable / an expression) cannot be resolved to a file path at build time.
    let [arg] = args else {
        return Err(custom_element_ctor_error(
            body_span,
            "`CustomElement.fromFile` takes exactly one argument — a single string literal \
             naming the widget-hook JS file",
        ));
    };
    let src::Expr_::Str(raw) = &arg.value else {
        return Err(custom_element_ctor_error(
            arg.span,
            "the `CustomElement.fromFile` argument must be a single string literal, not a \
             variable or expression (the path is read at build time)",
        ));
    };

    // Path seal: the all-regimes gate, the SAME `ipe_path_core` source of truth
    // the runtime `Path.fromString` seal uses. The build host that later joins this path may
    // run either regime, so a literal any regime refuses (a `..` escape, a
    // Windows `..\` or disguised `..`) is refused with IPE-P0063 — no arbitrary
    // out-of-project file is read at build. The carried form is the Unix one:
    // widget paths are `/`-separated project-relative text.
    let cleaned = match ipe_diagnostics::path_check::PathLitText::seal(raw) {
        Ok(lit) => lit
            .sealed(ipe_diagnostics::path_check::Regime::Unix)
            .to_owned(),
        Err(refusal) => {
            return Err(Diagnostic::Parse {
                span: arg.span,
                msg: ParseError::InvalidPathLiteral {
                    literal: raw.as_str().into(),
                    refusal,
                },
            });
        }
    };

    // constructor-specific tightening (Security #1, defence-in-depth): the widget
    // path MUST be project-root-relative. The shared `ipe_path_core` seal accepts an
    // absolute path by design (a `path` value may legitimately be absolute), but a
    // widget path is joined against the project root at the build gate — and
    // `Path::join` DISCARDS the base when its argument is absolute, so an absolute
    // literal would resolve OUTSIDE the project and read/stat an arbitrary file.
    // Reject any rooted literal here under EITHER target's separator regime (a Unix
    // `/…`, a Windows leading `\`, a `C:` drive designator, or a `\\server\share`
    // / `\\?\…` UNC/verbatim prefix), independent of the compiling host's OS — the
    // same all-targets discipline the traversal seal uses. Checked on the ORIGINAL
    // literal so a rooted spelling cannot be normalised into a relative-looking
    // form. Fail-closed at CANON: the verdict never depends on whether the
    // out-of-project file exists.
    if is_rooted_widget_path(raw.as_str()) {
        return Err(custom_element_ctor_error(
            arg.span,
            "the `CustomElement.fromFile` widget path must be project-root-relative — an \
             absolute path (a leading `/` or `\\`, a `C:` drive, or a UNC \
             `\\\\server\\share` prefix) would resolve outside the project and is refused",
        ));
    }
    Ok(cleaned)
}

/// Recognise a Stage-4 kernel-alias binding and resolve it against the kernel
/// registry — the compiled-source counterpart of the reference compiler's
/// `collectKernelAliases` (`Ipe.Build.Compile`).
///
/// A binding qualifies when it takes NO parameters and its body is exactly
/// `Kernel.kernel "Module_function"`. The string is split at the FIRST `_` into
/// a `(module, function)` pair (the `KernelMod_funcName` convention) and looked
/// up in `env.stdlib_index`.
///
/// ORIGIN GATE (capability-model integrity): minting a kernel is the exclusive
/// privilege of driver-vouched [`ModuleOrigin::EmbeddedStdlib`] /
/// [`ModuleOrigin::FfiInterface`] modules — the standard library and the
/// generated FFI interface. A binding of this shape in a [`ModuleOrigin::User`]
/// module is REJECTED (IPE-N0042), mirroring the `Ffi.binding` origin gate in
/// [`canonicalise_foreign_call`]: user source could otherwise bind a name
/// directly to any kernel — including an unsafe-tier kernel (a raw-`<script>`
/// sink, a secret reveal, a raw SQL exec) — reaching the effect with no
/// `unsafe` capability disclosed and no `.Unsafe` import to acknowledge. The
/// only sanctioned path to an unsafe kernel is its `Ipe.<M>.Unsafe` module,
/// which flips the `unsafe` capability. Make-invalid-states-unrepresentable:
/// `Kernel.kernel` in user text is unrepresentable, not merely discouraged.
///
/// Returns:
/// * `Ok(None)` — the binding is an ordinary value/function, not a kernel alias.
/// * `Ok(Some(alias))` — a kernel alias whose target is a registered kernel.
/// * `Err(IPE-N0042)` — the binding IS a kernel alias but the module origin is
///   `User`, so it may not mint a kernel (the capability-model gate).
/// * `Err(IPE-N0028)` — the binding IS a kernel alias but its string names no
///   registered kernel. This is the FAIL-CLOSED gate demanded by THE SEAL:
///   accepting it would let `ipe` emit a call to a non-existent kernel that
///   type-checks here yet fails the downstream `cargo build`. A kernel the
///   resolver would recognise but the registry does not cover is a
///   representable-but-illegal state, rejected at compile time.
///
/// # Errors
/// [`NameError::KernelAliasInUserSource`] (IPE-N0042) when a kernel-alias shape
/// appears in a `User`-origin module.
/// [`NameError::UnknownKernelAlias`] (IPE-N0028) when the split `(module,
/// function)` pair is absent from the kernel registry.
pub fn detect_kernel_alias(
    value: &src::Value,
    env: &Env,
    interner: &mut Interner,
) -> DResult<Option<KernelAlias>> {
    // A kernel alias binds a bare value — a binding with parameters is an
    // ordinary function, never the point-free Layer-3 alias shape.
    if !value.patterns.is_empty() {
        return Ok(None);
    }
    // Body must be `Kernel.kernel "<raw>"`, i.e. a call of the qualified
    // `Kernel.kernel` to a single string literal.
    let src::Expr_::Call(callee, args) = &value.body.value else {
        return Ok(None);
    };
    let src::Expr_::VarQual(qualifier, member) = &callee.value else {
        return Ok(None);
    };
    // Compare against the reserved `Kernel.kernel` spelling (the last segment of
    // `import Ipe.Ffi.Kernel as Kernel`). These interns are idempotent (the
    // strings almost always already exist), and only run for the narrow
    // `VarQual`-applied-to-one-arg shape, so the cost is negligible.
    let kernel_qualifier_sym = interner.intern("Kernel")?;
    let kernel_sym = interner.intern("kernel")?;
    if *qualifier != kernel_qualifier_sym || *member != kernel_sym {
        return Ok(None);
    }
    let [arg] = args.as_slice() else {
        return Ok(None);
    };
    let src::Expr_::Str(raw) = &arg.value else {
        return Ok(None);
    };

    // ORIGIN GATE: the binding is a genuine `Kernel.kernel "<raw>"` kernel alias.
    // Only a driver-vouched EmbeddedStdlib / FfiInterface module may mint a
    // kernel; the SAME shape in User source is rejected (IPE-N0042). Placed
    // AFTER full shape confirmation so an ordinary user value is never touched,
    // and BEFORE the registry lookup so the rejection does not depend on whether
    // the named kernel happens to be registered. Mirrors the `Ffi.binding`
    // origin gate in `canonicalise_foreign_call`; fail-closed for any origin
    // that is not one of the two vouched kinds.
    if !matches!(
        env.origin,
        ModuleOrigin::EmbeddedStdlib | ModuleOrigin::FfiInterface
    ) {
        return Err(Diagnostic::Name {
            span: value.body.span,
            msg: NameError::KernelAliasInUserSource {
                alias: Box::<str>::from(raw.as_str()),
            },
        });
    }

    // Split at the FIRST `_` — `"PubSub_publish"` → `("PubSub", "publish")`,
    // matching the runtime's `KernelMod_funcName` convention. A string with no
    // `_`, or an empty module/function half, is a malformed alias and fails
    // closed the same way an unknown kernel does.
    let split = raw
        .split_once('_')
        .filter(|(m, f)| !m.is_empty() && !f.is_empty());
    // A `IPE-N0028` for the alias — its `module` / `function` are the split
    // halves (empty when the string is malformed, so the message still renders).
    let unknown_alias = |module: Box<str>, function: Box<str>| Diagnostic::Name {
        span: value.body.span,
        msg: NameError::UnknownKernelAlias {
            alias: Box::<str>::from(raw.as_str()),
            module,
            function,
        },
    };
    let Some((module_str, function_str)) = split else {
        return Err(unknown_alias(Box::<str>::from(""), Box::<str>::from("")));
    };
    let module = interner.intern(module_str)?;
    let function = interner.intern(function_str)?;
    // FAIL-CLOSED: only a kernel the registry actually covers resolves. An
    // unregistered pair is rejected here, never emitted as a dangling call.
    env.stdlib_index
        .get(&(module, function))
        .copied()
        .map_or_else(
            || {
                Err(unknown_alias(
                    Box::<str>::from(module_str),
                    Box::<str>::from(function_str),
                ))
            },
            |id| {
                Ok(Some(KernelAlias {
                    id,
                    module,
                    function,
                }))
            },
        )
}

/// Build the deterministic `did you mean` suggestion list for an unresolved
/// `typo`, drawn from `candidates`.
///
/// Candidates within [`SUGGESTION_MAX_DISTANCE`] edits (and not identical) are
/// kept, sorted by `(Levenshtein distance, name)` — a total, allocation-order-
/// independent ordering — and truncated to [`MAX_SUGGESTIONS`]. A candidate the
/// interner cannot resolve is skipped (it cannot be rendered) rather than
/// faulting the whole diagnostic.
fn suggestions(
    typo: Symbol,
    candidates: impl Iterator<Item = Symbol>,
    interner: &Interner,
) -> Box<[Box<str>]> {
    let Some(typo_str) = interner.resolve(typo) else {
        return Box::new([]);
    };
    rank_suggestions(typo_str, candidates.filter_map(|c| interner.resolve(c)))
}

/// The `(Levenshtein, name)`-ranked, edit-distance-capped, `MAX_SUGGESTIONS`-capped
/// "did you mean" list over string candidates — the single ranking every
/// suggestion site shares.
///
/// Symbol-keyed sites reach it through [`suggestions`]; the IPE-N0020
/// module-not-found site (whose candidate universe is dot-joined module-path
/// strings that must never be interned) calls it directly. Sharing this keeps an
/// unrelated name (`Rust.Firestore` against a project's modules) yielding few or
/// none everywhere, rather than one site dumping the whole universe unranked.
fn rank_suggestions<'a>(typo: &str, candidates: impl Iterator<Item = &'a str>) -> Box<[Box<str>]> {
    let mut scored: Vec<(usize, Box<str>)> = candidates
        .map(|name| (levenshtein(typo, name), Box::<str>::from(name)))
        .filter(|(d, _)| *d > 0 && *d <= SUGGESTION_MAX_DISTANCE)
        .collect();
    // (distance, name) is a total order; `Box<str>` compares lexicographically.
    scored.sort();
    scored.dedup();
    scored
        .into_iter()
        .take(MAX_SUGGESTIONS)
        .map(|(_, name)| name)
        .collect()
}

/// Iterative Levenshtein edit distance over Unicode scalar values, computed
/// with two rolling rows and no indexing (the `indexing_slicing` lint is
/// denied workspace-wide). Ipê identifiers are short ASCII names, so the
/// O(n·m) cost is negligible. Mirrors the reference compiler's `levenshtein`.
fn levenshtein(a: &str, b: &str) -> usize {
    let b_chars: Vec<char> = b.chars().collect();
    // Row 0: cost of deleting every prefix of `b` (i.e. inserting into empty a).
    let mut prev: Vec<usize> = (0..=b_chars.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        // `curr[0]` = cost of deleting the first `i + 1` chars of `a`.
        let mut curr: Vec<usize> = Vec::with_capacity(b_chars.len() + 1);
        curr.push(i + 1);
        // `diag` tracks `prev[j - 1]`; for the first column that is `prev[0]`,
        // which always equals the row index `i`.
        let mut diag = i;
        for (cb, &up) in b_chars.iter().zip(prev.iter().skip(1)) {
            let cost = usize::from(ca != *cb);
            let left = curr.last().copied().unwrap_or(i + 1);
            let cell = (up + 1).min(left + 1).min(diag + cost);
            curr.push(cell);
            diag = up;
        }
        prev = curr;
    }
    prev.last().copied().unwrap_or(0)
}

/// The interned symbol for the empty string (symbol id 0 is never guaranteed,
/// so we cannot hardcode it). Used only on the unreachable unnamed-type path.
const fn name_zero() -> Symbol {
    Symbol::from_raw(0)
}

// ── Triple-quoted string interpolation desugar ────────────────────────────────
//
// Faithful Rust port of `Ipe.Canonicalise.Expression.desugarMultiline` /
// `splitInterpolation` / `chunkToExpr` / `resolveInterpolationRef`.
//
// Entry point: `desugar_multiline(raw, span, env, interner)` — called from
// `canonicalise_expr` when it sees `src::Expr_::MultilineStr`.
//
// The raw string is split into alternating `Lit` / `Interp` chunks, each
// expression chunk is wrapped in the internal `Interpolate` renderer, and the
// whole list is folded left into a `++` (String.append) binop chain.
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed chunk from a triple-quoted string.
enum Chunk {
    /// A literal string segment (no interpolation).
    Lit(String),
    /// An interpolation body — the raw text between `{{` and `}}`.
    Interp(String),
}

/// Split a raw triple-quoted string body into alternating literal / expression
/// chunks. Direct Rust port of `Ipe.Canonicalise.Expression.splitInterpolation`.
///
/// Escape grammar (spec from upstream `splitInterpolation` comments):
///   `\{{`  → literal `{{`  (no interpolation consumed)
///   `\\`   → literal `\`
///   `\X`   → literal `\X` for any other `X` (verbatim pass-through)
/// An unclosed `{{` (no matching `}}`) is treated as literal content.
fn split_interpolation(raw: &str) -> Vec<Chunk> {
    let chars: Vec<char> = raw.chars().collect();
    let mut result: Vec<Chunk> = Vec::new();
    let mut acc = String::new();
    let mut i = 0;
    while let Some(&c0) = chars.get(i) {
        let c1 = chars.get(i + 1).copied();
        let c2 = chars.get(i + 2).copied();
        match (c0, c1, c2) {
            // `\{{` → emit literal `{{`, skip 3 chars.
            ('\\', Some('{'), Some('{')) => {
                acc.push_str("{{");
                i += 3;
            }
            // `\\` → emit literal `\`, skip 2 chars.
            ('\\', Some('\\'), _) => {
                acc.push('\\');
                i += 2;
            }
            // `{{` → start an interpolation. Flush accumulated literal first.
            ('{', Some('{'), _) => {
                if !acc.is_empty() {
                    result.push(Chunk::Lit(std::mem::take(&mut acc)));
                }
                i += 2;
                // Collect the body up to the matching `}}`.
                let mut body = String::new();
                let mut closed = false;
                while let Some(&bc) = chars.get(i) {
                    if bc == '}' && chars.get(i + 1).copied() == Some('}') {
                        i += 2;
                        closed = true;
                        break;
                    }
                    body.push(bc);
                    i += 1;
                }
                if closed {
                    result.push(Chunk::Interp(body));
                } else {
                    // Unclosed `{{` — treat entire `{{body` as literal content.
                    acc.push_str("{{");
                    acc.push_str(&body);
                }
            }
            // Any other character — copy verbatim.
            _ => {
                acc.push(c0);
                i += 1;
            }
        }
    }
    if !acc.is_empty() {
        result.push(Chunk::Lit(acc));
    }
    result
}

/// Convert a `Chunk` to a canonical expression.
/// Port of `Ipe.Canonicalise.Expression.chunkToExpr`.
///
/// `Lit` → `Expr_::Str`.
/// `Interp` → resolve the body as a simple ref, then wrap in the internal
/// `Interpolate` renderer (no surface binding — only `{{…}}` reaches it).
fn chunk_to_expr(
    chunk: Chunk,
    span: Span,
    env: &Env,
    interner: &mut Interner,
) -> DResult<canon::Expr> {
    match chunk {
        Chunk::Lit(s) => Ok(Located::new(span, canon::Expr_::Str(s))),
        Chunk::Interp(body) => {
            // Trim leading/trailing whitespace, matching the reference compiler
            // `dropWhile (== ' ') (reverse (dropWhile …))`.
            let trimmed = body.trim();
            let resolved = resolve_interp_ref(trimmed, span, env, interner)?;
            let mod_sym = interner.intern("_internal_")?;
            let fn_sym = interner.intern("interpolate")?;
            let stringify = Located::new(
                span,
                canon::Expr_::VarKernel {
                    id: Some(StdlibKernel::Interpolate),
                    module: mod_sym,
                    name: fn_sym,
                },
            );
            Ok(Located::new(
                span,
                canon::Expr_::Call(Box::new(stringify), vec![resolved]),
            ))
        }
    }
}

/// Resolve a simple interpolation reference.
/// Port of `Ipe.Canonicalise.Expression.resolveInterpolationRef`.
///
/// Handles four shapes:
///   `foo`          — bare identifier → local var (or kernel if in scope)
///   `record.field` — field access → `Access(VarLocal(record), field)`
///   `Module.func`  — qualified name → `VarKernel` (if known) or literal fallback
///   `func arg`     — single function call → `Call(resolve(func), [resolve(arg)])`
/// Anything more complex falls back to a literal `{{...}}` string (clear signal
/// to the developer that only simple expressions are interpolable).
fn resolve_interp_ref(
    s: &str,
    span: Span,
    env: &Env,
    interner: &mut Interner,
) -> DResult<canon::Expr> {
    // Check for `func arg` (a single space separates them).
    if let Some(space_pos) = s.find(' ') {
        let func_str = &s[..space_pos];
        let arg_str = s[space_pos + 1..].trim();
        if !func_str.is_empty() && !arg_str.is_empty() {
            let func_expr = resolve_interp_ref(func_str, span, env, interner)?;
            let arg_expr = resolve_interp_ref(arg_str, span, env, interner)?;
            return Ok(Located::new(
                span,
                canon::Expr_::Call(Box::new(func_expr), vec![arg_expr]),
            ));
        }
    }
    resolve_simple_interp_ref(s, span, env, interner)
}

/// Inner resolver for an interpolation reference without a space (no call form).
/// Port of `resolveSimpleRef` inside `resolveInterpolationRef`.
fn resolve_simple_interp_ref(
    s: &str,
    span: Span,
    env: &Env,
    interner: &mut Interner,
) -> DResult<canon::Expr> {
    // Numeric literal. A body that begins with an ASCII digit can never be an
    // identifier (Ipê identifiers never start with a digit), so it is an
    // integer or float literal — NOT a local reference. Emitting `VarLocal`
    // here (the fall-through below) would leak an unbound name past
    // canonicalisation and fire the IPE-I0001 "unbound local `<n>`" ICE in
    // `constrain`, which treats an unresolved local as a violated invariant
    // (the resolver is supposed to have resolved every local). Recognise the
    // literal instead, so e.g. `{{String.fromInt 54}}` lowers to
    // `String.fromInt 54` and prints "54". This must precede the `.`-split
    // below, else a float like `1.5` is mis-parsed as `Access(1, 5)`.
    //
    // Interpolation segments that start with an ASCII digit cannot be
    // identifiers (Ipê identifiers never start with a digit), so they must be
    // integer or float literals — NOT local references. Emitting `VarLocal`
    // for a digit-leading string would leave an unbound name past
    // canonicalisation, which fires an ICE in `constrain`. Recognising the
    // literal here prevents that path.
    if s.starts_with(|c: char| c.is_ascii_digit()) {
        if let Ok(n) = s.parse::<i64>() {
            return Ok(Located::new(span, canon::Expr_::Int(n)));
        }
        if let Ok(f) = s.parse::<f64>()
            && f.is_finite()
        {
            return Ok(Located::new(span, canon::Expr_::Float(f)));
        }
        // Leading digit but not a valid `Int`/`Float` (e.g. `1e400`, `0xFF`,
        // `9z`): fall back to the literal `{{...}}` string rather than emit a
        // `VarLocal` that would ICE. Mirrors the "too complex → literal" policy.
        return Ok(Located::new(
            span,
            canon::Expr_::Str(format!("{{{{{s}}}}}")),
        ));
    }
    if let Some(dot_pos) = s.find('.') {
        let first = &s[..dot_pos];
        let rest = &s[dot_pos + 1..];
        if first.is_empty() || rest.is_empty() {
            // Degenerate `.foo` or `foo.` — literal fallback.
            return Ok(Located::new(
                span,
                canon::Expr_::Str(format!("{{{{{s}}}}}")),
            ));
        }
        let first_char = first.chars().next().unwrap_or('_');
        if first_char.is_uppercase() {
            // Qualified reference `Module.func`.
            let qual_sym = interner.intern(first)?;
            // Look up the qualifier in the current environment.
            if let Some(members) = env.qual_vars.get(&qual_sym) {
                let name_sym = interner.intern(rest)?;
                if let Some(home) = members.get(&name_sym) {
                    return Ok(Located::new(span, var_home_to_expr(name_sym, home)));
                }
            }
            // Unknown module or member — literal fallback (clear signal to dev).
            return Ok(Located::new(
                span,
                canon::Expr_::Str(format!("{{{{{s}}}}}")),
            ));
        }
        // Lowercase `record.field` → `Access(VarLocal(record), field)`.
        let rec_sym = interner.intern(first)?;
        let field_sym = interner.intern(rest)?;
        return Ok(Located::new(
            span,
            canon::Expr_::Access(
                Box::new(Located::new(span, canon::Expr_::VarLocal(rec_sym))),
                field_sym,
            ),
        ));
    }
    // Bare identifier — resolve through the one canonical bare-name path
    // (`resolve_var`): constructor first, then variable, then the wildcard
    // tier, and an unknown name fails closed with the ordinary IPE-N0001
    // `ValueNotFound` diagnostic. A bare nullary constructor (`{{Nothing}}`)
    // thus references its constructor value exactly as it would outside an
    // interpolation. Emitting `VarLocal` for an unbound/unknown name would
    // leak it past canonicalisation and fire the `constrain` unbound-local
    // ICE, so every name this path emits as `VarLocal` is provably bound.
    let sym = interner.intern(s)?;
    Ok(Located::new(span, resolve_var(sym, span, env, interner)?))
}

/// Desugar a triple-quoted string into a `++`-chained canonical expression.
/// Entry point from `canonicalise_expr`. Port of
/// `Ipe.Canonicalise.Expression.desugarMultiline`.
fn desugar_multiline(
    raw: &str,
    anchor: u32,
    span: Span,
    env: &Env,
    interner: &mut Interner,
) -> DResult<canon::Expr_> {
    // Strip the source indentation margin before splitting, so the runtime
    // value drops the leading whitespace the author used to lay the block out.
    // The strip removes only leading whitespace (never a `{{`/`}}` marker or its
    // body), so every interpolation expression is extracted from the same text
    // it would have been without a margin — sub-spans and the node span are
    // unchanged.
    let stripped = src::strip_anchor_margin(raw, anchor);
    let chunks = split_interpolation(&stripped);
    // Build one canonical expression per chunk.
    let mut parts: Vec<canon::Expr> = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        parts.push(chunk_to_expr(chunk, span, env, interner)?);
    }
    match parts.len() {
        0 => Ok(canon::Expr_::Str(String::new())),
        1 => Ok(parts.remove(0).value),
        _ => {
            // Left-fold into a `++` chain: ((a ++ b) ++ c) ++ …
            let mut iter = parts.into_iter();
            let Some(first) = iter.next() else {
                // Unreachable: the match arm guards len >= 2.
                return Ok(canon::Expr_::Str(String::new()));
            };
            let op_sym = interner.intern("++")?;
            let home_sym = interner.intern("Basics")?;
            let func_sym = interner.intern("append")?;
            let mut acc = first;
            for part in iter {
                let merged_span = Span::new(acc.span.lo, part.span.hi);
                // Synthetic desugared `++`: no real operator glyph in source.
                // Zero-width span at the join point — the token walker drops it.
                let synthetic_op_span = Span::new(acc.span.hi, acc.span.hi);
                acc = Located::new(
                    merged_span,
                    canon::Expr_::Binop {
                        op: op_sym,
                        op_span: synthetic_op_span,
                        home: home_sym,
                        func: func_sym,
                        lhs: Box::new(acc),
                        rhs: Box::new(part),
                    },
                );
            }
            Ok(acc.value)
        }
    }
}

#[cfg(test)]
mod alias_ctor_gate_tests {
    //! Unit coverage for [`field_type_nonderivable`] — the STRUCT-derivability
    //! gate that decides whether a record `type alias` gets a synthesised
    //! auto-constructor (IPE-N0001). It returns `true` (DECLINE synthesis)
    //! when a field type could NOT be a field of a
    //! `#[derive(Clone, Debug, PartialEq)]` + `impl IpeStringify` struct — a raw
    //! function at ANY depth inside a derive carrier (the round-1 seal fix) OR an
    //! OPAQUE boxed-wrapper (`Decoder` / `Task` / `Cmd` / `Sub`) in field
    //! position (the round-2 flip: the wrapper VALUE is itself non-derivable).
    //! It returns `false` only for genuinely derivable data (plain records,
    //! non-opaque parametric containers of derivable payloads, vars, unit).

    use super::*;

    fn sym(i: &mut Interner, s: &str) -> Symbol {
        i.intern(s).expect("intern must succeed")
    }

    /// A bare arrow `() -> ()` — the minimal `Lambda`; only its shape matters to
    /// the predicate.
    fn arrow() -> canon::Type {
        canon::Type::Lambda(Box::new(canon::Type::Unit), Box::new(canon::Type::Unit))
    }

    fn con(i: &mut Interner, name: &str, args: Vec<canon::Type>) -> canon::Type {
        let n = sym(i, name);
        canon::Type::Con {
            home: Vec::new(),
            name: n,
            args,
        }
    }

    #[test]
    fn direct_arrow_field_is_nonderivable() {
        let i = Interner::new();
        // `{ handler : () -> () }` — a raw function lowers to `Box<dyn Fn>`.
        assert!(field_type_nonderivable(&i, &arrow()));
    }

    #[test]
    fn snake_case_maps_camel_to_snake_for_codec_auto_keys() {
        // The DB/column key convention `Codec.auto` emits.
        assert_eq!(to_snake_case("priceMinor"), "price_minor");
        assert_eq!(to_snake_case("id"), "id");
        assert_eq!(to_snake_case("createdAt"), "created_at");
        // An all-lowercase name and an existing underscore pass through.
        assert_eq!(to_snake_case("name"), "name");
        assert_eq!(to_snake_case("already_snake"), "already_snake");
        // A run of capitals is one boundary, not one per letter.
        assert_eq!(to_snake_case("httpURL"), "http_url");
        // A trailing digit is a lowercase-like boundary source.
        assert_eq!(to_snake_case("line1Item"), "line1_item");
    }

    #[test]
    fn syn_span_hands_out_unique_high_spans() {
        // Every synthesised node must get its OWN region key; two calls never
        // collide, and every span sits above the source range.
        let mut sg = SynSpan::seeded(Span::new(10, 20));
        let a = sg.fresh();
        let b = sg.fresh();
        assert_ne!(a, b, "fresh spans must be distinct");
        assert!(
            a.lo >= SYN_SPAN_BASE,
            "synthetic spans clear the source range"
        );
        assert!(b.lo > a.lo, "spans advance monotonically");
        // The diagnostic span is the real call site, not a synthetic one.
        assert_eq!(sg.diag, Span::new(10, 20));
    }

    #[test]
    fn function_nested_in_derive_carriers_is_nonderivable() {
        let mut i = Interner::new();

        // `List (a -> b)` — the round-1 seal break.
        let list_arrow = con(&mut i, "List", vec![arrow()]);
        assert!(
            field_type_nonderivable(&i, &list_arrow),
            "List (arrow) must be gated"
        );

        // `Maybe (a -> b)`.
        let maybe_arrow = con(&mut i, "Maybe", vec![arrow()]);
        assert!(
            field_type_nonderivable(&i, &maybe_arrow),
            "Maybe (arrow) must be gated"
        );

        // `(a -> b, Bool)` — arrow in a tuple element.
        let bool_con = con(&mut i, "Bool", vec![]);
        let tuple_arrow = canon::Type::Tuple(vec![arrow(), bool_con]);
        assert!(
            field_type_nonderivable(&i, &tuple_arrow),
            "tuple carrying an arrow must be gated"
        );

        // `Result Error (a -> b)` — arrow in the second type argument.
        let err_con = con(&mut i, "Error", vec![]);
        let result_arrow = con(&mut i, "Result", vec![err_con, arrow()]);
        assert!(
            field_type_nonderivable(&i, &result_arrow),
            "Result e (arrow) must be gated"
        );

        // Nested record: `{ inner : { f : a -> b } }`.
        let f = sym(&mut i, "f");
        let inner = sym(&mut i, "inner");
        let inner_rec = canon::Type::Record(vec![(f, arrow())]);
        let nested_rec = canon::Type::Record(vec![(inner, inner_rec)]);
        assert!(
            field_type_nonderivable(&i, &nested_rec),
            "a nested record carrying an arrow must be gated"
        );
    }

    #[test]
    fn opaque_wrapper_field_is_nonderivable() {
        // ROUND-2 FLIP. An opaque boxed-wrapper in FIELD position is ITSELF
        // non-derivable as a struct field — its runtime rep (`Box<dyn Fn>` /
        // boxed-thunk enum / `Pin<Box<dyn Future>>`) impls no
        // `Clone`/`Debug`/`PartialEq`/`IpeStringify`. So the head SHORT-CIRCUITS
        // to `true`, DECLINING synthesis (round-1 asserted the opposite — the
        // seal hole: ipe-0 then cargo-101).
        let mut i = Interner::new();

        // `Decoder Int` — opaque head, no raw arrow anywhere, yet non-derivable.
        let int_con = con(&mut i, "Int", vec![]);
        let decoder_int = con(&mut i, "Decoder", vec![int_con]);
        assert!(
            field_type_nonderivable(&i, &decoder_int),
            "Decoder Int is a non-derivable struct field → must be gated"
        );

        // `Cmd Msg` — boxed-thunk enum, non-derivable.
        let msg_con = con(&mut i, "Msg", vec![]);
        let cmd_msg = con(&mut i, "Cmd", vec![msg_con]);
        assert!(
            field_type_nonderivable(&i, &cmd_msg),
            "Cmd Msg is a non-derivable struct field → must be gated"
        );

        // `Sub Msg`.
        let msg2 = con(&mut i, "Msg", vec![]);
        let sub_msg = con(&mut i, "Sub", vec![msg2]);
        assert!(
            field_type_nonderivable(&i, &sub_msg),
            "Sub Msg is a non-derivable struct field → must be gated"
        );

        // `Task Error a` — `Pin<Box<dyn Future>>`, non-derivable regardless of
        // its (here function) payload.
        let err_con = con(&mut i, "Error", vec![]);
        let task_arrow = con(&mut i, "Task", vec![err_con, arrow()]);
        assert!(
            field_type_nonderivable(&i, &task_arrow),
            "Task Error a is a non-derivable struct field → must be gated"
        );
    }

    #[test]
    fn opaque_wrapper_nested_under_carrier_is_nonderivable() {
        // The predicate RECURSES into non-opaque carriers, so an opaque wrapper
        // nested one level down is still caught.
        let mut i = Interner::new();

        // `List (Decoder Int)`.
        let int_con = con(&mut i, "Int", vec![]);
        let decoder_int = con(&mut i, "Decoder", vec![int_con]);
        let list_decoder = con(&mut i, "List", vec![decoder_int]);
        assert!(
            field_type_nonderivable(&i, &list_decoder),
            "List (Decoder Int) must be gated"
        );

        // `Maybe (Cmd Msg)`.
        let msg_con = con(&mut i, "Msg", vec![]);
        let cmd_msg = con(&mut i, "Cmd", vec![msg_con]);
        let maybe_cmd = con(&mut i, "Maybe", vec![cmd_msg]);
        assert!(
            field_type_nonderivable(&i, &maybe_cmd),
            "Maybe (Cmd Msg) must be gated"
        );
    }

    #[test]
    fn plain_data_types_are_derivable() {
        let mut i = Interner::new();

        // `{ x : Int }` — a plain record field.
        let int_con = con(&mut i, "Int", vec![]);
        assert!(!field_type_nonderivable(&i, &int_con));

        // `List Int` — a non-opaque container of a derivable payload.
        let int_arg = con(&mut i, "Int", vec![]);
        let list_int = con(&mut i, "List", vec![int_arg]);
        assert!(!field_type_nonderivable(&i, &list_int));

        // `Maybe (List String)` — nested derivable data.
        let str_con = con(&mut i, "String", vec![]);
        let list_str = con(&mut i, "List", vec![str_con]);
        let maybe_list_str = con(&mut i, "Maybe", vec![list_str]);
        assert!(!field_type_nonderivable(&i, &maybe_list_str));

        // Type variables and unit are derivable.
        let a = sym(&mut i, "a");
        assert!(!field_type_nonderivable(&i, &canon::Type::Var(a)));
        assert!(!field_type_nonderivable(&i, &canon::Type::Unit));
    }

    #[test]
    fn resolve_or_bug_fails_closed_on_unresolvable_symbol() {
        let i = Interner::new();
        // A raw symbol the interner never handed out resolves to `None`; the
        // fail-closed path must be `CompilerBug`, never a fabricated empty name.
        let forged = Symbol::from_raw(u32::MAX);
        let err = resolve_or_bug(&i, forged, "test_site")
            .expect_err("an unresolvable symbol must not resolve to a name");
        assert!(
            matches!(err, Diagnostic::CompilerBug { where_, .. } if where_ == "test_site"),
            "fail-closed path must be CompilerBug at the given site"
        );
    }

    #[test]
    fn resolve_or_bug_returns_text_for_interned_symbol() {
        let mut i = Interner::new();
        let s = i.intern("Widget").expect("intern");
        assert_eq!(
            resolve_or_bug(&i, s, "test_site").expect("resolves"),
            "Widget"
        );
    }

    #[test]
    fn reject_reserved_builtin_type_fails_closed_on_unresolvable_name() {
        // A type name symbol the interner never handed out must not pass the
        // reserved-builtin-type gate on a `None` resolve; it fails closed with a
        // CompilerBug rather than the old `_ => Ok(())` wildcard.
        let i = Interner::new();
        let forged = Symbol::from_raw(u32::MAX);
        let err = reject_reserved_builtin_type(forged, Span::DUMMY, ModuleOrigin::User, &i)
            .expect_err("an unresolvable type name must not silently pass the gate");
        assert!(
            matches!(err, Diagnostic::CompilerBug { .. }),
            "unresolvable name must fail closed as CompilerBug"
        );
    }

    #[test]
    fn reject_reserved_builtin_type_still_gates_correctly() {
        // The fail-closed change must not weaken the ordinary gate: an ordinary
        // name passes, a reserved built-in name is still rejected for a user
        // module.
        let mut i = Interner::new();
        let widget = i.intern("Widget").expect("intern");
        assert!(
            reject_reserved_builtin_type(widget, Span::DUMMY, ModuleOrigin::User, &i).is_ok(),
            "an ordinary user type name is allowed"
        );
        let reserved = i.intern("Int").expect("intern");
        let err = reject_reserved_builtin_type(reserved, Span::DUMMY, ModuleOrigin::User, &i)
            .expect_err("a reserved built-in name must still be rejected");
        assert!(
            matches!(
                err,
                Diagnostic::Name {
                    msg: NameError::ReservedBuiltinType { .. },
                    ..
                }
            ),
            "reserved name rejection must be ReservedBuiltinType"
        );
    }
}

#[cfg(test)]
mod suggestion_ranking_tests {
    //! [`rank_suggestions`] — the single ranking every did-you-mean site shares,
    //! including the IPE-N0020 module-not-found candidate universe (which is why
    //! an unrelated import cannot dump every project module as a "did you mean").

    use super::{MAX_SUGGESTIONS, rank_suggestions};

    #[test]
    fn unrelated_name_yields_none() {
        // A project's own modules against a wholly unrelated import: every
        // candidate is beyond the edit-distance ceiling, so none is offered —
        // never the whole unranked module list.
        let modules = [
            "Lib.Auth",
            "Lib.Cart",
            "Lib.Db",
            "Page.Home",
            "Page.Product",
            "State",
            "Ui.Layout",
        ];
        let got = rank_suggestions("Rust.Firestore", modules.into_iter());
        assert!(
            got.is_empty(),
            "an unrelated name must yield no suggestions, got: {got:?}"
        );
    }

    #[test]
    fn near_misses_are_ranked_and_capped_at_max() {
        // More close candidates than the cap: the list is capped at
        // `MAX_SUGGESTIONS`, closest-first.
        let modules = ["Foo", "Food", "Fool", "Foot", "Fond"];
        let got = rank_suggestions("Foo", modules.into_iter());
        assert!(
            got.len() <= MAX_SUGGESTIONS,
            "must cap at MAX_SUGGESTIONS ({MAX_SUGGESTIONS}), got {}: {got:?}",
            got.len()
        );
        assert!(!got.is_empty(), "genuine near-misses must be offered");
        // The exact-match candidate (`Foo`, distance 0) is excluded — a
        // suggestion identical to the typed name is noise.
        assert!(
            !got.iter().any(|s| s.as_ref() == "Foo"),
            "distance-0 self must not be suggested, got: {got:?}"
        );
    }
}

#[cfg(test)]
mod exposed_ctor_subset_tests {
    //! `exposing (Type(subset))` opens ONLY the named constructors unqualified.
    //! Both constructor binders ([`bind_dep_union`], the user-dep path, and
    //! [`bind_stdlib_kernel_import`], the built-in path) route their
    //! selection through [`exposed_ctor_filter`], so a withheld sibling stays
    //! out of unqualified scope by construction — it remains reachable only
    //! through its qualifier.

    use super::*;

    fn sym(i: &mut Interner, s: &str) -> Symbol {
        i.intern(s).expect("intern must succeed")
    }

    fn ctor(i: &mut Interner, ty: &str, name: &str, index: usize) -> CtorHome {
        CtorHome {
            home: vec![sym(i, "Dep")],
            type_name: sym(i, ty),
            name: sym(i, name),
            index,
            arity: 0,
        }
    }

    #[test]
    fn filter_all_admits_every_ctor() {
        let mut i = Interner::new();
        let a = ctor(&mut i, "T", "A", 0);
        let b = ctor(&mut i, "T", "B", 1);
        let filter = exposed_ctor_filter(&src::Privacy::Public);
        assert!(filter.admits(a.name), "Type(..) opens A");
        assert!(filter.admits(b.name), "Type(..) opens B");
    }

    #[test]
    fn filter_subset_admits_only_named_ctors() {
        let mut i = Interner::new();
        let a = ctor(&mut i, "T", "A", 0);
        let b = ctor(&mut i, "T", "B", 1);
        let filter = exposed_ctor_filter(&src::Privacy::PublicCtors(vec![a.name]));
        assert!(filter.admits(a.name), "Type(A) opens A");
        assert!(
            !filter.admits(b.name),
            "Type(A) must NOT open the withheld sibling B"
        );
    }

    #[test]
    fn filter_opaque_admits_nothing() {
        let mut i = Interner::new();
        let a = ctor(&mut i, "T", "A", 0);
        let filter = exposed_ctor_filter(&src::Privacy::Private);
        assert!(
            matches!(filter, CtorFilter::None),
            "opaque is the None filter"
        );
        assert!(!filter.admits(a.name), "opaque Type opens no constructor");
    }

    /// Canonicalise a producer then an importer against it, returning the
    /// importer's result. The producer exposes BOTH constructors so `dep.ctors`
    /// carries A and B; the importer's `exposing` clause is the sole selector.
    fn import_against_producer(importer_src: &str) -> (DResult<canon::Module>, Interner) {
        let mut i = Interner::new();
        let producer_src = "module Dep exposing (T(..))\n\ntype T = A | B\n";
        let dep_path = vec![sym(&mut i, "Dep")];
        let main_path = vec![sym(&mut i, "Main")];
        let mut deps: BTreeMap<Vec<Symbol>, crate::ModuleExports> = BTreeMap::new();

        let setup_err = |detail: &'static str| Diagnostic::CompilerBug {
            where_: "exposed_ctor_subset_tests",
            detail: detail.into(),
        };
        let Ok(parsed_dep) = ipe_parse::parse_module(producer_src, &mut i) else {
            return (Err(setup_err("producer parse")), i);
        };
        let Ok((_, exports)) = canonicalise_module(&parsed_dep, &dep_path, &deps, &mut i) else {
            return (Err(setup_err("producer canon")), i);
        };
        deps.insert(dep_path, exports);

        let Ok(parsed_main) = ipe_parse::parse_module(importer_src, &mut i) else {
            return (Err(setup_err("importer parse")), i);
        };
        let result = canonicalise_module(&parsed_main, &main_path, &deps, &mut i)
            .map(|(module, _exports)| module);
        (result, i)
    }

    #[test]
    fn subset_exposes_named_ctor_unqualified() {
        // `exposing (T(A))` — bare `A` resolves; bare `B` (a withheld sibling)
        // does NOT; the qualified `Dep.B` still does.
        let (ok_a, _) = import_against_producer(
            "module Main exposing (x)\n\n\
             import Dep exposing (T(A))\n\n\
             x =\n    A\n",
        );
        assert!(
            ok_a.is_ok(),
            "bare A must resolve under exposing (T(A)): {ok_a:?}"
        );

        let (err_b, _) = import_against_producer(
            "module Main exposing (x)\n\n\
             import Dep exposing (T(A))\n\n\
             x =\n    B\n",
        );
        assert!(
            matches!(err_b, Err(Diagnostic::Name { .. })),
            "bare B must NOT resolve under exposing (T(A)) — over-exposure regression: {err_b:?}"
        );

        let (ok_qual_b, _) = import_against_producer(
            "module Main exposing (x)\n\n\
             import Dep exposing (T(A))\n\n\
             x =\n    Dep.B\n",
        );
        assert!(
            ok_qual_b.is_ok(),
            "qualified Dep.B stays reachable regardless of the exposing subset: {ok_qual_b:?}"
        );
    }

    #[test]
    fn all_ctors_exposed_under_double_dot() {
        // `exposing (T(..))` — both A and B resolve unqualified.
        let (ok_a, _) = import_against_producer(
            "module Main exposing (x)\n\n\
             import Dep exposing (T(..))\n\n\
             x =\n    A\n",
        );
        let (ok_b, _) = import_against_producer(
            "module Main exposing (x)\n\n\
             import Dep exposing (T(..))\n\n\
             x =\n    B\n",
        );
        assert!(ok_a.is_ok() && ok_b.is_ok(), "T(..) opens both A and B");
    }

    #[test]
    fn opaque_type_exposes_no_ctor_unqualified() {
        // `exposing (T)` — neither A nor B is unqualified; only `Dep.A` works.
        let (err_a, _) = import_against_producer(
            "module Main exposing (x)\n\n\
             import Dep exposing (T)\n\n\
             x =\n    A\n",
        );
        assert!(
            matches!(err_a, Err(Diagnostic::Name { .. })),
            "opaque exposing (T) must NOT open bare A: {err_a:?}"
        );
        let (ok_qual, _) = import_against_producer(
            "module Main exposing (x)\n\n\
             import Dep exposing (T)\n\n\
             x =\n    Dep.A\n",
        );
        assert!(
            ok_qual.is_ok(),
            "qualified Dep.A stays reachable under opaque T"
        );
    }
}

#[cfg(test)]
mod seal_container_arity_tests {
    use super::{SEAL_VALUE_CONTAINERS, builtin_empty_home_arity, seal_container_arity};

    /// Every name in `SEAL_VALUE_CONTAINERS` has a matching entry in
    /// `builtin_empty_home_arity`. This test reds if an arity changes in the
    /// gate but the seal list is not updated, or vice versa.
    #[test]
    fn seal_container_arity_derives_from_builtin_arity() {
        for name in SEAL_VALUE_CONTAINERS {
            let gate_arity = builtin_empty_home_arity(Some(name));
            let seal_arity = seal_container_arity(name);
            assert_eq!(
                gate_arity, seal_arity,
                "`{name}`: gate arity {gate_arity:?} != seal arity {seal_arity:?}"
            );
            assert!(
                gate_arity.is_some(),
                "`{name}` is in SEAL_VALUE_CONTAINERS but has no gate arity"
            );
        }
    }

    /// `Connection` has a gate arity entry (it is a builtin container) but must
    /// NOT appear in `SEAL_VALUE_CONTAINERS` — it is an opaque DB handle, not
    /// a value container the seal recurses into.
    #[test]
    fn connection_excluded_from_seal_value_containers() {
        assert!(
            builtin_empty_home_arity(Some("Connection")).is_some(),
            "Connection must have a gate arity (arity=1)"
        );
        assert!(
            !SEAL_VALUE_CONTAINERS.contains(&"Connection"),
            "Connection must NOT be in SEAL_VALUE_CONTAINERS"
        );
        assert!(
            seal_container_arity("Connection").is_none(),
            "seal_container_arity(Connection) must return None"
        );
    }
}

#[cfg(test)]
mod config_threading_tests {
    //! Unit coverage for [`thread_config_binding`] — the item-1 recognition site
    //! that threads a sibling top-level `config` binding into a `Web` app entry
    //! and rejects a `config` binding no entry consumes (IPE-N0043).

    use super::*;
    use ipe_diagnostics::Located;

    fn sym(i: &mut Interner, s: &str) -> Symbol {
        i.intern(s).expect("intern must succeed")
    }

    /// A `VarKernel` head for `Web.<name>` (e.g. `Web.tea`).
    fn web_entry(i: &mut Interner, name: &str) -> canon::Expr {
        let module = sym(i, "Web");
        let name = sym(i, name);
        Located::new(
            Span::DUMMY,
            canon::Expr_::VarKernel {
                id: None,
                module,
                name,
            },
        )
    }

    /// `<entry> {cfg}` — an app entry applied to a single (opaque) cfg argument.
    fn entry_call(entry: canon::Expr) -> canon::Expr {
        let cfg = Located::new(Span::DUMMY, canon::Expr_::Unit);
        Located::new(Span::DUMMY, canon::Expr_::Call(Box::new(entry), vec![cfg]))
    }

    /// A module with the given `main` body and an optional top-level `config`
    /// binding (a `Unit` body stand-in — only its NAME matters here).
    fn module_with(i: &mut Interner, main_body: canon::Expr, with_config: bool) -> canon::Module {
        let home = vec![sym(i, "Main")];
        let main_name = sym(i, "main");
        let mut defs = vec![canon::Def::Untyped {
            home: home.clone(),
            name: Located::new(Span::DUMMY, main_name),
            patterns: Vec::new(),
            body: main_body,
        }];
        if with_config {
            let config_name = sym(i, "config");
            defs.push(canon::Def::Untyped {
                home: home.clone(),
                name: Located::new(Span::DUMMY, config_name),
                patterns: Vec::new(),
                body: Located::new(Span::DUMMY, canon::Expr_::Unit),
            });
        }
        canon::Module {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            name: home,
            unions: Vec::new(),
            defs,
        }
    }

    /// The `main` binding's body from a module (post-threading inspection).
    fn main_body<'a>(m: &'a canon::Module, i: &Interner) -> Option<&'a canon::Expr> {
        m.defs
            .iter()
            .find(|d| i.resolve(d.name().value) == Some("main"))
            .map(|d| match d {
                canon::Def::Untyped { body, .. } | canon::Def::Typed { body, .. } => body,
            })
    }

    #[test]
    fn config_is_threaded_into_web_app_entry() {
        let mut i = Interner::new();
        let main_body_expr = entry_call(web_entry(&mut i, "tea"));
        let mut m = module_with(&mut i, main_body_expr, true);
        thread_config_binding(&mut m, &mut i).expect("config must thread into Web.tea");

        // `main` is now `Web.appWith config <cfg>`: callee re-targeted to
        // `appWith`, `config` prepended as the settings argument.
        let threaded = main_body(&m, &i).is_some_and(|body| {
            let canon::Expr_::Call(callee, args) = &body.value else {
                return false;
            };
            let canon::Expr_::VarKernel { name, .. } = &callee.value else {
                return false;
            };
            let re_targeted = i.resolve(*name) == Some("appWith");
            let config_first = matches!(
                args.first().map(|a| &a.value),
                Some(canon::Expr_::VarTopLevel { name, .. }) if i.resolve(*name) == Some("config")
            );
            re_targeted && args.len() == 2 && config_first
        });
        assert!(
            threaded,
            "main must become `Web.appWith config <cfg>` after threading"
        );
    }

    #[test]
    fn inline_app_with_with_sibling_config_is_rejected() {
        // `main = Web.appWith [ … ] { … }` already carries its own settings list.
        // A sibling `config` binding has nowhere to be threaded — its settings
        // would be silently dropped. IPE-N0043 must fire.
        let mut i = Interner::new();
        let entry = web_entry(&mut i, "appWith");
        let settings = Located::new(Span::DUMMY, canon::Expr_::Unit);
        let cfg = Located::new(Span::DUMMY, canon::Expr_::Unit);
        let main_body = Located::new(
            Span::DUMMY,
            canon::Expr_::Call(Box::new(entry), vec![settings, cfg]),
        );
        let mut m = module_with(&mut i, main_body, true);
        let err = thread_config_binding(&mut m, &mut i)
            .expect_err("a config binding beside inline appWith must be rejected (IPE-N0043)");
        assert!(
            matches!(
                err,
                Diagnostic::Name {
                    msg: NameError::DiscardedConfig,
                    ..
                }
            ),
            "expected IPE-N0043 DiscardedConfig, got {err:?}"
        );
    }

    #[test]
    fn discarded_config_in_a_program_is_rejected() {
        // `config` present but `main` is a plain Program (Unit body) — no entry
        // consumes the config, so IPE-N0043 fires.
        let mut i = Interner::new();
        let main_body = Located::new(Span::DUMMY, canon::Expr_::Unit);
        let mut m = module_with(&mut i, main_body, true);
        let err =
            thread_config_binding(&mut m, &mut i).expect_err("a discarded config must be rejected");
        assert!(
            matches!(
                err,
                Diagnostic::Name {
                    msg: NameError::DiscardedConfig,
                    ..
                }
            ),
            "expected IPE-N0043 DiscardedConfig, got {err:?}"
        );
    }

    #[test]
    fn no_config_binding_is_a_noop() {
        // A module with no `config` binding is untouched (no rewrite, no error).
        let mut i = Interner::new();
        let main_body_expr = entry_call(web_entry(&mut i, "tea"));
        let mut m = module_with(&mut i, main_body_expr, false);
        thread_config_binding(&mut m, &mut i).expect("no config → no-op");
        let untouched = main_body(&m, &i).is_some_and(
            |body| matches!(&body.value, canon::Expr_::Call(_, args) if args.len() == 1),
        );
        assert!(
            untouched,
            "no config threaded when none is declared (single cfg arg stands)"
        );
    }
}

#[cfg(test)]
mod rust_ffi_auto_inject_tests {
    //! Unit coverage for the ergonomic papercut fix (#1762): a module that
    //! imports `Ipe.Ffi.Rust as Rust` and uses `Rust.fn` does NOT need a
    //! separate `import Rust.Ffi`; the resolver auto-injects the forwarder
    //! qualifier. The security gate is verified: an uninstalled crate (no
    //! forwarder generated → symbol absent from `Rust.Ffi` exports) still fires
    //! the IPE-N0038 refusal.
    #![allow(clippy::panic, clippy::expect_used)] // test setup: a failed parse/intern IS the failure

    use super::*;

    fn sym(i: &mut Interner, s: &str) -> Symbol {
        i.intern(s).expect("intern must succeed")
    }

    /// Build a minimal `Rust.Ffi` `ModuleExports` carrying exactly the given
    /// forwarder value name (e.g. `asserted_tm_shift__<hash>`).
    fn rust_ffi_exports(i: &mut Interner, forwarder: &str) -> crate::ModuleExports {
        let rust = sym(i, "Rust");
        let ffi = sym(i, "Ffi");
        let path = vec![rust, ffi];
        let v = sym(i, forwarder);
        let mut values = std::collections::BTreeSet::new();
        values.insert(v);
        crate::ModuleExports {
            path,
            values,
            types: BTreeMap::default(),
            ctors: BTreeMap::default(),
            aliases: BTreeMap::default(),
            kernel_aliases: BTreeMap::default(),
        }
    }

    /// Canonicalise a module that uses `Rust.fn` WITH `import Ipe.Ffi.Rust as
    /// Rust` but WITHOUT `import Rust.Ffi`, against a `Rust.Ffi` dep that
    /// carries the expected forwarder. Must resolve successfully.
    #[test]
    fn rust_fn_resolves_without_explicit_rust_ffi_import() {
        // The forwarder name for `Rust.fn "tm" "shift"` — derived deterministically
        // by `AssertedPath::from_crate_and_path("tm", "shift").def_name()`.
        let forwarder = crate::asserted::AssertedPath::from_crate_and_path("tm", "shift")
            .expect("valid path")
            .def_name();

        let mut i = Interner::new();
        let rust_sym = sym(&mut i, "Rust");
        let ffi_sym = sym(&mut i, "Ffi");
        let rust_ffi_path = vec![rust_sym, ffi_sym];

        let rust_ffi_dep = rust_ffi_exports(&mut i, &forwarder);
        let mut deps: BTreeMap<Vec<Symbol>, crate::ModuleExports> = BTreeMap::new();
        deps.insert(rust_ffi_path, rust_ffi_dep);

        // Module uses `Rust.fn` WITHOUT `import Rust.Ffi` — the papercut case.
        let src = "module Main exposing (shifted)\n\
             import Ipe.Ffi.Rust as Rust\n\n\
             shifted : Int -> Result Error Int\n\
             shifted =\n    Rust.fn \"tm\" \"shift\"\n";

        let main_path = vec![sym(&mut i, "Main")];
        let Ok(parsed) = ipe_parse::parse_module(src, &mut i) else {
            panic!("parse failed");
        };
        let result = canonicalise_module(&parsed, &main_path, &deps, &mut i);
        assert!(
            result.is_ok(),
            "Rust.fn must resolve with only `import Ipe.Ffi.Rust as Rust` (no `import Rust.Ffi`): {result:?}"
        );
    }

    /// An uninstalled crate (no forwarder in `Rust.Ffi`) still fires IPE-N0038
    /// even when `Rust.Ffi` is auto-injected.
    #[test]
    fn rust_fn_on_uninstalled_crate_still_fails() {
        // Forwarder for `tm::shift` is seeded in the dep, but the module binds
        // `nope::phantom` — no forwarder for that → must fail.
        let forwarder = crate::asserted::AssertedPath::from_crate_and_path("tm", "shift")
            .expect("valid path")
            .def_name();

        let mut i = Interner::new();
        let rust_sym = sym(&mut i, "Rust");
        let ffi_sym = sym(&mut i, "Ffi");
        let rust_ffi_path = vec![rust_sym, ffi_sym];

        let rust_ffi_dep = rust_ffi_exports(&mut i, &forwarder);
        let mut deps: BTreeMap<Vec<Symbol>, crate::ModuleExports> = BTreeMap::new();
        deps.insert(rust_ffi_path, rust_ffi_dep);

        // `nope::phantom` has no forwarder → should fail.
        let src = "module Main exposing (ghost)\n\
                   import Ipe.Ffi.Rust as Rust\n\n\
                   ghost : Int -> Result Error Int\n\
                   ghost =\n    Rust.fn \"nope\" \"phantom\"\n";

        let main_path = vec![sym(&mut i, "Main")];
        let Ok(parsed) = ipe_parse::parse_module(src, &mut i) else {
            panic!("parse failed");
        };
        let result = canonicalise_module(&parsed, &main_path, &deps, &mut i);
        assert!(
            result.is_err(),
            "Rust.fn on an uninstalled crate must fail even with auto-inject: {result:?}"
        );
    }
}

#[cfg(test)]
mod unary_minus_hygiene_tests {
    //! Unary minus on a non-literal desugars to a QUALIFIED `Basics.negate`
    //! reference, which resolves through the module catalog to the
    //! `Basics_negate` kernel. A user binding named `negate` — top-level or
    //! `let`-local — therefore cannot capture the operator: `-x` always means
    //! arithmetic negation.
    #![allow(clippy::panic, clippy::expect_used)] // test setup: a failed parse/canon IS the failure

    use super::*;

    fn sym(i: &mut Interner, s: &str) -> Symbol {
        i.intern(s).expect("intern must succeed")
    }

    /// The canonicalised body of the named top-level def.
    fn def_body<'m>(module: &'m canon::Module, i: &Interner, name: &str) -> &'m canon::Expr {
        module
            .defs
            .iter()
            .find(|d| i.resolve(d.name().value) == Some(name))
            .map(|d| match d {
                canon::Def::Untyped { body, .. } | canon::Def::Typed { body, .. } => body,
            })
            .expect("named def must exist")
    }

    /// The callee of a `Call` body must be the `Basics.negate` kernel.
    fn assert_negate_kernel_callee(body: &canon::Expr, i: &Interner) {
        let canon::Expr_::Call(callee, _) = &body.value else {
            panic!("body must be a Call, got {:?}", body.value);
        };
        match &callee.value {
            canon::Expr_::VarKernel { module, name, .. } => {
                assert_eq!(i.resolve(*module), Some("Basics"), "kernel module");
                assert_eq!(i.resolve(*name), Some("negate"), "kernel name");
            }
            other => panic!("unary-minus callee must be the Basics.negate kernel, got {other:?}"),
        }
    }

    /// `-x` resolves to the `Basics.negate` kernel with no shadowing binding.
    #[test]
    fn unary_minus_resolves_to_basics_negate_kernel() {
        let mut i = Interner::new();
        let src = "module Main exposing (v)\n\nv x =\n    -x\n";
        let main_path = vec![sym(&mut i, "Main")];
        let deps: BTreeMap<Vec<Symbol>, crate::ModuleExports> = BTreeMap::new();
        let Ok(parsed) = ipe_parse::parse_module(src, &mut i) else {
            panic!("parse failed");
        };
        let (module, _) = canonicalise_module(&parsed, &main_path, &deps, &mut i)
            .expect("module must canonicalise");
        assert_negate_kernel_callee(def_body(&module, &i, "v"), &i);
    }

    /// A top-level `negate` binding does NOT capture the unary-minus operator:
    /// `-x` still resolves to the `Basics.negate` kernel.
    #[test]
    fn top_level_negate_does_not_capture_unary_minus() {
        let mut i = Interner::new();
        let src = "module Main exposing (v)\n\n\
                   negate n =\n    n\n\n\
                   v x =\n    -x\n";
        let main_path = vec![sym(&mut i, "Main")];
        let deps: BTreeMap<Vec<Symbol>, crate::ModuleExports> = BTreeMap::new();
        let Ok(parsed) = ipe_parse::parse_module(src, &mut i) else {
            panic!("parse failed");
        };
        let (module, _) = canonicalise_module(&parsed, &main_path, &deps, &mut i)
            .expect("module must canonicalise");
        assert_negate_kernel_callee(def_body(&module, &i, "v"), &i);
    }

    /// A `let`-local `negate` binding does NOT capture the unary-minus operator
    /// in its `in` body.
    #[test]
    fn let_local_negate_does_not_capture_unary_minus() {
        let mut i = Interner::new();
        let src = "module Main exposing (v)\n\n\
                   v x =\n    let\n        negate = x\n    in\n    -x\n";
        let main_path = vec![sym(&mut i, "Main")];
        let deps: BTreeMap<Vec<Symbol>, crate::ModuleExports> = BTreeMap::new();
        let Ok(parsed) = ipe_parse::parse_module(src, &mut i) else {
            panic!("parse failed");
        };
        let (module, _) = canonicalise_module(&parsed, &main_path, &deps, &mut i)
            .expect("module must canonicalise");
        let canon::Expr_::Let(_, in_body) = &def_body(&module, &i, "v").value else {
            panic!("v body must be a Let");
        };
        assert_negate_kernel_callee(in_body, &i);
    }
}

#[cfg(test)]
mod html_qualifier_type_home_tests {
    //! An Html-family stdlib qualifier (`import Ipe.Html.Attributes as Attr`)
    //! force-homes the reserved builtin VIEW-TYPE names (`Attribute`/`Html`) to
    //! `["Html"]`, so `Attr.Attribute` lowers to `html::Attribute`. A
    //! compiled-source ADT declared in the same module (`Attr.LinkTarget`) is NOT
    //! a reserved builtin, so it keeps its real `["Ipe","Html","Attributes"]`
    //! home — not the builtin `["Html"]`.
    #![allow(clippy::panic, clippy::expect_used)] // test setup: a failed parse/canon IS the failure

    use super::*;

    fn sym(i: &mut Interner, s: &str) -> Symbol {
        i.intern(s).expect("intern must succeed")
    }

    /// A hand-built `Ipe.Html.Attributes` export view: the compiled-source ADT
    /// `LinkTarget` (home = the module's own path) plus the re-exported builtin
    /// `Attribute` (home = `["Html"]`, matching `reexported_builtin_type_home`).
    /// Built directly rather than by canonicalising a `module Ipe.Html.Attributes`
    /// source, which the resolver rejects as a reserved namespace.
    fn html_attributes_exports(i: &mut Interner, dep_path: &[Symbol]) -> crate::ModuleExports {
        let link_target = sym(i, "LinkTarget");
        let absolute = sym(i, "Absolute");
        let attribute = sym(i, "Attribute");
        let html_home = vec![sym(i, "Html")];

        let mut types: BTreeMap<Symbol, Vec<Symbol>> = BTreeMap::new();
        types.insert(link_target, dep_path.to_vec());
        types.insert(attribute, html_home);

        let mut ctors: BTreeMap<Symbol, CtorHome> = BTreeMap::new();
        ctors.insert(
            absolute,
            CtorHome {
                home: dep_path.to_vec(),
                type_name: link_target,
                name: absolute,
                index: 0,
                arity: 0,
            },
        );

        crate::ModuleExports {
            path: dep_path.to_vec(),
            types,
            ctors,
            ..crate::ModuleExports::default()
        }
    }

    /// Canonicalise an importer against the hand-built `Ipe.Html.Attributes`
    /// export view, returning the importer's canonical module.
    fn import_against_html_attributes(importer_src: &str) -> (canon::Module, Interner) {
        let mut i = Interner::new();
        let dep_path = vec![
            sym(&mut i, "Ipe"),
            sym(&mut i, "Html"),
            sym(&mut i, "Attributes"),
        ];
        let main_path = vec![sym(&mut i, "Main")];
        let mut deps: BTreeMap<Vec<Symbol>, crate::ModuleExports> = BTreeMap::new();
        let exports = html_attributes_exports(&mut i, &dep_path);
        deps.insert(dep_path, exports);

        let Ok(parsed_main) = ipe_parse::parse_module(importer_src, &mut i) else {
            panic!("importer parse failed");
        };
        let (module, _) = canonicalise_module(&parsed_main, &main_path, &deps, &mut i)
            .expect("importer must canonicalise");
        (module, i)
    }

    /// The declared home of the named typed def's annotation, which must be a
    /// nullary `Con`.
    fn annotation_con_home<'m>(
        module: &'m canon::Module,
        i: &Interner,
        def_name: &str,
    ) -> &'m [Symbol] {
        let ty = module
            .defs
            .iter()
            .find(|d| i.resolve(d.name().value) == Some(def_name))
            .and_then(|d| match d {
                canon::Def::Typed { ty, .. } => Some(ty),
                canon::Def::Untyped { .. } => None,
            })
            .expect("named typed def must exist");
        match ty {
            canon::Type::Con { home, .. } => home,
            other => panic!("annotation must be a Con, got {other:?}"),
        }
    }

    /// `Attr.LinkTarget` — a compiled-source ADT — homes at its REAL module
    /// `["Ipe","Html","Attributes"]`, NOT the builtin `["Html"]`. This is the
    /// annotation-resolution bug: the force-home must not swallow a source ADT.
    #[test]
    fn compiled_source_html_adt_keeps_real_module_home() {
        let (module, i) = import_against_html_attributes(
            "module Main exposing (x)\n\n\
             import Ipe.Html.Attributes as Attr\n\n\
             x : Attr.LinkTarget\n\
             x =\n    Attr.Absolute\n",
        );
        let home = annotation_con_home(&module, &i, "x");
        let dotted: Vec<_> = home.iter().map(|s| i.resolve(*s)).collect();
        assert_eq!(
            dotted,
            vec![Some("Ipe"), Some("Html"), Some("Attributes")],
            "Attr.LinkTarget (a compiled-source ADT) must home at its real module, \
             not the builtin [\"Html\"]"
        );
    }

    /// The builtin view type `Attr.Attribute` still force-homes to `["Html"]` so
    /// it lowers to `html::Attribute` — the behaviour the fold exists to give.
    #[test]
    fn builtin_view_type_still_force_homes_to_html() {
        let (module, i) = import_against_html_attributes(
            "module Main exposing (x)\n\n\
             import Ipe.Html.Attributes as Attr\n\n\
             x : Attr.Attribute msg\n\
             x =\n    Attr.Absolute\n",
        );
        let home = annotation_con_home(&module, &i, "x");
        let dotted: Vec<_> = home.iter().map(|s| i.resolve(*s)).collect();
        assert_eq!(
            dotted,
            vec![Some("Html")],
            "the reserved builtin Attr.Attribute must keep the [\"Html\"] force-home"
        );
    }
}

#[cfg(test)]
mod duplicate_pattern_binder_tests {
    //! IPE-N0049 — a single pattern may not bind one name twice. Or-pattern
    //! alternatives are disjoint scopes, so a name reused across them is legal.

    use super::{reject_duplicate_pattern_binders, src};
    use ipe_diagnostics::{Diagnostic, IPE_N0049, Located, NameError, Span};
    use ipe_intern::Interner;

    fn sym(i: &mut Interner, name: &str) -> ipe_intern::Symbol {
        i.intern(name).expect("intern must succeed")
    }

    fn pvar(i: &mut Interner, name: &str, lo: u32) -> src::Pattern {
        Located::new(Span::new(lo, lo + 1), src::Pattern_::PVar(sym(i, name)))
    }

    #[test]
    fn tuple_binding_the_same_name_twice_is_rejected() {
        let mut i = Interner::new();
        let x1 = pvar(&mut i, "x", 0);
        let x2 = pvar(&mut i, "x", 5);
        let pat = Located::new(Span::new(0, 6), src::Pattern_::PTuple(vec![x1, x2]));
        let err = reject_duplicate_pattern_binders(&pat, &i)
            .expect_err("`( x, x )` binds `x` twice — must be rejected");
        assert!(
            matches!(
                err,
                Diagnostic::Name {
                    msg: NameError::DuplicatePatternBinder { .. },
                    ..
                }
            ),
            "expected DuplicatePatternBinder"
        );
        assert_eq!(
            err.code(),
            IPE_N0049,
            "duplicate pattern binder is IPE-N0049"
        );
    }

    #[test]
    fn cons_binding_the_same_name_twice_is_rejected() {
        let mut i = Interner::new();
        let head = Box::new(pvar(&mut i, "x", 0));
        let tail = Box::new(pvar(&mut i, "x", 4));
        let pat = Located::new(Span::new(0, 5), src::Pattern_::PCons(head, tail));
        assert!(
            reject_duplicate_pattern_binders(&pat, &i).is_err(),
            "`x :: x` binds `x` twice — must be rejected"
        );
    }

    #[test]
    fn distinct_names_in_a_tuple_are_accepted() {
        let mut i = Interner::new();
        let a = pvar(&mut i, "a", 0);
        let b = pvar(&mut i, "b", 5);
        let pat = Located::new(Span::new(0, 6), src::Pattern_::PTuple(vec![a, b]));
        assert!(
            reject_duplicate_pattern_binders(&pat, &i).is_ok(),
            "`( a, b )` binds two distinct names — must be accepted"
        );
    }

    #[test]
    fn or_pattern_reusing_a_name_across_alternatives_is_accepted() {
        // `x | x` — each alternative is a disjoint scope; the reuse is legal.
        let mut i = Interner::new();
        let alt1 = pvar(&mut i, "x", 0);
        let alt2 = pvar(&mut i, "x", 4);
        let pat = Located::new(Span::new(0, 5), src::Pattern_::POr(vec![alt1, alt2]));
        assert!(
            reject_duplicate_pattern_binders(&pat, &i).is_ok(),
            "a name reused across or-pattern alternatives is not a duplicate"
        );
    }

    #[test]
    fn duplicate_within_one_or_alternative_is_rejected() {
        // `( x, x ) | y` — the duplicate lives inside the first alternative.
        let mut i = Interner::new();
        let x1 = pvar(&mut i, "x", 0);
        let x2 = pvar(&mut i, "x", 3);
        let inner = Located::new(Span::new(0, 4), src::Pattern_::PTuple(vec![x1, x2]));
        let y = pvar(&mut i, "y", 8);
        let pat = Located::new(Span::new(0, 9), src::Pattern_::POr(vec![inner, y]));
        assert!(
            reject_duplicate_pattern_binders(&pat, &i).is_err(),
            "a duplicate inside one alternative must still be rejected"
        );
    }

    #[test]
    fn wildcards_may_repeat() {
        let i = Interner::new();
        let w1 = Located::new(Span::new(0, 1), src::Pattern_::PAnything);
        let w2 = Located::new(Span::new(3, 4), src::Pattern_::PAnything);
        let pat = Located::new(Span::new(0, 5), src::Pattern_::PTuple(vec![w1, w2]));
        assert!(
            reject_duplicate_pattern_binders(&pat, &i).is_ok(),
            "`_` binds nothing, so `( _, _ )` is fine"
        );
    }
}
