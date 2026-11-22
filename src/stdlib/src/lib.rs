//! The embedded Ipê standard-library source (`Ipe.*`).
//!
//! `ipe` is self-contained: the foundational `Ipe` modules are the `.ipe`
//! sources under `src/stdlib/Ipe/`, `include_str!`-embedded into the binary
//! at compile time. These sources ARE the standard library — there is no
//! out-of-repo original they mirror; embedding them keeps the build portable
//! and the toolchain hermetic.
//!
//! `Ipe.Basics` is the canonical implicit module (ADR 0001): its Tier-A surface
//! is auto-imported into every module. There is no `Ipe.Prelude` module — the
//! old value-flooding alias is removed, so `import Ipe.Prelude` does not resolve.
//! The source is ordinary Ipê: the same parser that reads user code reads it (the
//! `parses` test proves it), so it is the substrate the import resolver compiles.
#![forbid(unsafe_code)]

/// One embedded standard-library module: its dotted name and its Ipê source.
pub struct StdModule {
    /// The dotted module name as written in an `import`, e.g. `Ipe.Maybe`.
    pub name: &'static str,
    /// The module's Ipê source, embedded at compile time.
    pub source: &'static str,
}

/// How the toolchain reads one registered stdlib module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// A kernel qualifier of the resolver; `veneer` is its parse-fixture
    /// source, when it has one.
    Kernel {
        /// The kernel veneer's Ipê source, embedded at compile time.
        veneer: Option<&'static str>,
    },
    /// A kernel qualifier the resolver still accepts and `ipe doc` never presents.
    Retired,
    /// A module compiled from its Ipê source.
    Compiled {
        /// The module's Ipê source, embedded at compile time.
        source: &'static str,
        /// How `ipe doc` and the stdlib reference present this module.
        tier: StdTier,
    },
    /// A module compiled from its Ipê source, which is also a kernel veneer
    /// parse fixture.
    CompiledVeneer {
        /// The module's Ipê source, embedded at compile time.
        source: &'static str,
        /// How `ipe doc` and the stdlib reference present this module.
        tier: StdTier,
    },
    /// A module documented from its Ipê source and never compiled or injected.
    DocOnly {
        /// The module's Ipê source, embedded at compile time.
        source: &'static str,
    },
}

/// One row of the [`STDLIB`] registry: a dotted module name and its [`Role`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StdlibModule {
    /// The dotted module name as written in an `import`, e.g. `Ipe.Maybe`.
    pub dotted: &'static str,
    /// How the toolchain reads the module.
    pub role: Role,
}

impl StdlibModule {
    /// The module's embedded Ipê source, when the row carries one.
    #[must_use]
    pub const fn source(&self) -> Option<&'static str> {
        match self.role {
            Role::Kernel { veneer } => veneer,
            Role::Retired => None,
            Role::Compiled { source, .. }
            | Role::CompiledVeneer { source, .. }
            | Role::DocOnly { source } => Some(source),
        }
    }

    /// Whether `ipe doc` and the stdlib reference present the module.
    #[must_use]
    pub const fn is_documented(&self) -> bool {
        !matches!(self.role, Role::Retired)
    }
}

/// The [`MODULES`] view of a row: a kernel veneer parse fixture.
const fn veneer_view(row: &StdlibModule) -> Option<StdModule> {
    match row.role {
        Role::Kernel {
            veneer: Some(source),
        }
        | Role::CompiledVeneer { source, .. } => Some(StdModule {
            name: row.dotted,
            source,
        }),
        Role::Kernel { veneer: None }
        | Role::Retired
        | Role::Compiled { .. }
        | Role::DocOnly { .. } => None,
    }
}

/// The [`COMPILED_STD_MODULES`] view of a row: a compiled-source module.
const fn compiled_view(row: &StdlibModule) -> Option<CompiledStdModule> {
    match row.role {
        Role::Compiled { source, tier } | Role::CompiledVeneer { source, tier } => {
            Some(CompiledStdModule {
                dotted: row.dotted,
                source,
                tier,
            })
        }
        Role::Kernel { .. } | Role::Retired | Role::DocOnly { .. } => None,
    }
}

/// The [`DOC_ONLY_MODULES`] view of a row: a documentation-only module.
const fn doc_only_view(row: &StdlibModule) -> Option<DocOnlyModule> {
    match row.role {
        Role::DocOnly { source } => Some(DocOnlyModule {
            dotted: row.dotted,
            source,
        }),
        Role::Kernel { .. }
        | Role::Retired
        | Role::Compiled { .. }
        | Role::CompiledVeneer { .. } => None,
    }
}

/// Define a `const` projection of [`STDLIB`]: a count of the rows `$view`
/// keeps, and the array of those views in registry order.
macro_rules! projection {
    ($count:ident, $fill:ident, $ty:ty, $view:ident, $blank:ident) => {
        /// How many registry rows the view keeps.
        const fn $count(rows: &[StdlibModule]) -> usize {
            let mut kept = 0usize;
            let mut rest = rows;
            while let Some((row, tail)) = rest.split_first() {
                if $view(row).is_some() {
                    kept += 1;
                }
                rest = tail;
            }
            kept
        }

        /// The views the registry rows keep, in registry order; `N` is their count.
        const fn $fill<const N: usize>(rows: &[StdlibModule]) -> [$ty; N] {
            let mut out = [$blank; N];
            let mut slots: &mut [$ty] = &mut out;
            let mut rest = rows;
            while let Some((row, tail)) = rest.split_first() {
                if let Some(view) = $view(row)
                    && let Some((slot, more)) = slots.split_first_mut()
                {
                    *slot = view;
                    slots = more;
                }
                rest = tail;
            }
            out
        }
    };
}

/// The placeholder a projection array starts from; every slot is overwritten.
const BLANK_VENEER: StdModule = StdModule {
    name: "",
    source: "",
};
/// The placeholder a projection array starts from; every slot is overwritten.
const BLANK_COMPILED: CompiledStdModule = CompiledStdModule {
    dotted: "",
    source: "",
    tier: StdTier::Public,
};
/// The placeholder a projection array starts from; every slot is overwritten.
const BLANK_DOC_ONLY: DocOnlyModule = DocOnlyModule {
    dotted: "",
    source: "",
};

projection!(
    veneer_count,
    veneer_rows,
    StdModule,
    veneer_view,
    BLANK_VENEER
);
projection!(
    compiled_count,
    compiled_rows,
    CompiledStdModule,
    compiled_view,
    BLANK_COMPILED
);
projection!(
    doc_only_count,
    doc_only_rows,
    DocOnlyModule,
    doc_only_view,
    BLANK_DOC_ONLY
);

/// The [`MODULES`] projection of [`STDLIB`].
const VENEER_ROWS: [StdModule; veneer_count(STDLIB)] = veneer_rows(STDLIB);
/// The [`COMPILED_STD_MODULES`] projection of [`STDLIB`].
const COMPILED_ROWS: [CompiledStdModule; compiled_count(STDLIB)] = compiled_rows(STDLIB);
/// The [`DOC_ONLY_MODULES`] projection of [`STDLIB`].
const DOC_ONLY_ROWS: [DocOnlyModule; doc_only_count(STDLIB)] = doc_only_rows(STDLIB);

/// `Ipe.Basics` —`identity` / `always` / `not` / `fst` / `snd` / `clamp`.
const BASICS: &str = include_str!("../Ipe/Basics.ipe");
/// `Ipe.Maybe` — combinators over the `Maybe` ADT.
const MAYBE: &str = include_str!("../Ipe/Maybe.ipe");
/// `Ipe.Result` — combinators over the `Result` ADT.
const RESULT: &str = include_str!("../Ipe/Result.ipe");
/// `Ipe.List` — list combinators, compiled-source Layer-3.
///
/// Pure members (`map`/`filter`/`foldl`/… and the reverse-accumulator helpers)
/// are implemented directly in Ipê.  The eleven kernel-backed members
/// (`sort`/`singleton`/`repeat`/`product`/`intersperse`/`partition`/`unzip`/
/// `map2`–`map5`) are point-free `Kernel.kernel "List_*"` aliases resolved by
/// `ipe_canon::resolve::detect_kernel_alias` to the registered `List*`
/// `StdlibKernel` variants (`ipe_runtime::list::*`).  Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`,
/// so the disjointness invariant holds.
const LIST: &str = include_str!("../Ipe/List.ipe");
/// `Ipe.String` — string combinators, compiled-source Layer-3.
///
/// Every member is a point-free `Kernel.kernel "String_*"` alias resolved by
/// `ipe_canon::resolve::detect_kernel_alias` to a registered `String*`
/// `StdlibKernel` variant. Registered in [`COMPILED_STD_MODULES`] (NOT
/// `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`, so the disjointness invariant
/// holds. The module also re-exports the `String` builtin type via the
/// `build_module_exports` reserved-builtin-type path.
const STRING: &str = include_str!("../Ipe/String.ipe");
/// `Ipe.Char` — single-character helpers, compiled-source Layer-3.
///
/// Every member is a point-free `Kernel.kernel "Char_*"` alias resolved by
/// `ipe_canon::resolve::detect_kernel_alias` to a registered `Char*`
/// `StdlibKernel` variant (`ipe_runtime::char::*`). Registered in
/// [`COMPILED_STD_MODULES`] and also in `MODULES`, so the module resolves for
/// consumers that read either table.
const CHAR: &str = include_str!("../Ipe/Char.ipe");
/// `Ipe.Dict` — string-keyed associative map, compiled-source Layer-3.
///
/// Every member is a point-free `Kernel.kernel "Dict_*"` alias resolved by
/// `ipe_canon::resolve::detect_kernel_alias` to a registered `Dict*`
/// `StdlibKernel` variant. Registered in [`COMPILED_STD_MODULES`] (NOT
/// `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`, so the disjointness
/// invariant holds.
const DICT: &str = include_str!("../Ipe/Dict.ipe");
/// `Ipe.Set` — unordered set of unique elements, compiled-source Layer-3.
///
/// Every member is a point-free `Kernel.kernel "Set_*"` alias resolved by
/// `ipe_canon::resolve::detect_kernel_alias` to a registered `Set*`
/// `StdlibKernel` variant (`ipe_runtime::set::*`). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`,
/// so the disjointness invariant holds.
const SET: &str = include_str!("../Ipe/Set.ipe");
/// `Ipe.Bytes` — arbitrary byte buffer, distinct from `String`.
///
/// `Bytes` is a distinct primitive lowering to `Vec<u8>` (lossless for
/// non-UTF-8 binary), not a `String` alias.
const BYTES: &str = include_str!("../Ipe/Bytes.ipe");
/// `Ipe.Crypto` — hashes / HMAC / RSA / AEAD / key-derivation / random.
const CRYPTO: &str = include_str!("../Ipe/Crypto.ipe");
/// `Ipe.Bitwise` — Int-only bitwise operations, compiled-source Layer-3.
///
/// Every member is a point-free `Kernel.kernel "Bitwise_*"` alias resolved by
/// `ipe_canon::resolve::detect_kernel_alias` to a registered `Bitwise*`
/// `StdlibKernel` variant (`ipe_runtime::bitwise::*`). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`,
/// so the disjointness invariant holds.
const BITWISE: &str = include_str!("../Ipe/Bitwise.ipe");
/// `Ipe.Task` — Task combinator surface, compiled-source Layer-3.
///
/// Members are either point-free `Kernel.kernel "Task_*"` aliases resolved by
/// `ipe_canon::resolve::detect_kernel_alias` to registered `Task*`
/// `StdlibKernel` variants (`ipe_runtime::task::*`), or pure Ipê over those
/// aliases (`BackoffStrategy` type definition, `RetryPolicy` type alias).
/// Registered in [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in
/// `STDLIB_MODULE_QUALIFIERS`, so the disjointness invariant holds.
const TASK: &str = include_str!("../Ipe/Task.ipe");
/// `Ipe.Io` — standard-I/O effect kernels, compiled-source Layer-3.
///
/// Every member is a point-free `Kernel.kernel "Io_*"` alias resolved by
/// `ipe_canon::resolve::detect_kernel_alias` to a registered `Io*`
/// `StdlibKernel` variant (`ipe_runtime::io::*`). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`,
/// so the disjointness invariant holds.
const IO: &str = include_str!("../Ipe/Io.ipe");
/// `Ipe.Debug` — development-only escape hatch, compiled-source Layer-3.
///
/// Every member is a point-free `Kernel.kernel "Debug_*"` alias resolved by
/// `ipe_canon::resolve::detect_kernel_alias` to a registered `Debug*`
/// `StdlibKernel` variant. Registered in [`COMPILED_STD_MODULES`] (NOT
/// `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`, so the disjointness
/// invariant holds.
const DEBUG: &str = include_str!("../Ipe/Debug.ipe");
/// `Ipe.Uuid` — UUID generation and parsing, compiled-source Layer-3.
///
/// `v4` and `v7` are point-free `Kernel.kernel "Uuid_v4"` / `"Uuid_v7"` aliases
/// resolved by `ipe_canon::resolve::detect_kernel_alias` to the registered
/// `UuidV4` / `UuidV7` `StdlibKernel` variants (`ipe_runtime::uuid_kernel::*`).
/// `parse` resolves to `UuidParse` likewise. Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`,
/// so the disjointness invariant holds.
const UUID: &str = include_str!("../Ipe/Uuid.ipe");
/// `Ipe.Time` — clock + formatting + calendar helpers, compiled-source Layer-3.
///
/// Every member is a point-free `Kernel.kernel "Time_*"` alias resolved by
/// `ipe_canon::resolve::detect_kernel_alias` to a registered `Time*`
/// `StdlibKernel` variant. Registered in [`COMPILED_STD_MODULES`] (NOT
/// `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`, so the disjointness
/// invariant holds.
const TIME: &str = include_str!("../Ipe/Time.ipe");
/// `Ipe.Decimal` — arbitrary-precision decimal arithmetic, compiled-source Layer-3.
///
/// Every member is a point-free `Kernel.kernel "Decimal_*"` alias resolved by
/// `ipe_canon::resolve::detect_kernel_alias` to a registered `Decimal*`
/// `StdlibKernel` variant (`ipe_runtime::decimal::*`). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`,
/// so the disjointness invariant holds.
const DECIMAL: &str = include_str!("../Ipe/Decimal.ipe");
/// `Ipe.System` — process / environment effect kernels.
const SYSTEM: &str = include_str!("../Ipe/System.ipe");
/// `Ipe.Random` — entropy-backed and seeded randomness, compiled-source Layer-3.
///
/// Every member is either a point-free `Kernel.kernel "Random_*"` alias resolved by
/// `ipe_canon::resolve::detect_kernel_alias` to a registered `Random*`
/// `StdlibKernel` variant (`ipe_runtime::random::*`), or pure Ipê over those
/// aliases (`range`, the seeded wrappers, the opaque `Seed` ADT). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`,
/// so the disjointness invariant holds.
const RANDOM: &str = include_str!("../Ipe/Random.ipe");
/// `Ipe.Encoding` — text encoding helpers (base64 / URL / hex), compiled-source Layer-3.
///
/// Every member is a point-free `Kernel.kernel "Encoding_*"` alias resolved by
/// `ipe_canon::resolve::detect_kernel_alias` to a registered `Encoding*`
/// `StdlibKernel` variant (`ipe_runtime::encoding::*`). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`,
/// so the disjointness invariant holds.
const ENCODING: &str = include_str!("../Ipe/Encoding.ipe");
/// `Ipe.File` — file-system effects, compiled-source Layer-3.
///
/// Every member but `readFileLimit` is a point-free `Kernel.kernel "File_*"`
/// alias; `readFileLimit` is pure Ipê that unwraps its typed `ByteSize` ceiling
/// into the private raw-`Int` kernel alias, so the documented `ByteSize`
/// contract is the one the compiler enforces. Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`,
/// so the disjointness invariant holds.
const FILE: &str = include_str!("../Ipe/File.ipe");
/// `Ipe.Http` — outbound HTTP client kernels + pure builders.
const HTTP: &str = include_str!("../Ipe/Http.ipe");
/// `Ipe.Process` — subprocess execution (no shell) effect kernels.
const PROCESS: &str = include_str!("../Ipe/Process.ipe");

/// `Ipe.Path` — filesystem-path helpers, compiled-source Layer-3.
///
/// The members are point-free `Kernel.kernel "Path_*"` aliases resolved by the
/// kernel-alias mechanism (`ipe_canon::resolve::detect_kernel_alias`) to
/// the `PathFromString`/`PathToString`/`PathBase`/`PathDir`/`PathExt`/
/// `PathIsAbsolute`/`PathUnder`/`PathAbsolute` `StdlibKernel` variants. Registered in [`COMPILED_STD_MODULES`] (NOT `MODULES`) so its body
/// is actually compiled; NOT in `STDLIB_MODULE_QUALIFIERS`, so the disjointness
/// invariant holds.
const PATH: &str = include_str!("../Ipe/Path.ipe");
/// `Ipe.Html.Attributes` — HTML attribute builders, compiled-source Layer-3.
///
/// Every fixed-key builder (`class`/`id`/`checked`/…) is pure Ipê over the
/// three retained primitives `attribute`/`boolAttribute`/`noAttr`, which are
/// point-free `Kernel.kernel "Attr_attribute"`/`"Attr_boolAttribute"`/`"Attr_noAttr"`
/// aliases resolved by `ipe_canon::resolve::detect_kernel_alias` to the
/// `HtmlAttribute`/`HtmlBoolAttribute`/`HtmlNoAttr` kernels (runtime:
/// `ipe_runtime::html::html_named_attr_`/`html_bool_named_attr_`/`html_no_attr_`).
/// Registered in [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in
/// `STDLIB_MODULE_QUALIFIERS`, so the disjointness invariant holds.
const HTML_ATTRIBUTES: &str = include_str!("../Ipe/Html/Attributes.ipe");
/// `Ipe.Html.Unsafe` — the un-escaped raw-HTML escape hatch, compiled-source
/// Layer-3.
///
/// Its members `unsafeRaw` and `unsafeScript` are point-free
/// `Kernel.kernel "Html_unsafeRaw"` / `"Html_unsafeScript"` aliases resolved by
/// `ipe_canon::resolve::detect_kernel_alias` to the `HtmlRawNode` /
/// `HtmlScriptNode` kernels (runtime: `ipe_runtime::ui::helpers::html_raw_node_`,
/// the `HRaw` verbatim sink, and the inline-`<script>` sink). Only the surface
/// home moved here from `Ipe.Html`; the kernels, their registry keys, and the
/// render-sink behaviour are unchanged. Importing this dotted `Ipe.<M>.Unsafe` submodule
/// discloses the `unsafe` capability. Registered in [`COMPILED_STD_MODULES`]
/// (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`, so the disjointness
/// invariant holds.
const HTML_UNSAFE: &str = include_str!("../Ipe/Html/Unsafe.ipe");
/// `Ipe.Db.Unsafe` — the raw-SQL / untyped-column-read escape hatches for
/// `Ipe.Db`, compiled-source Layer-3.
///
/// Every member is a point-free `Kernel.kernel "Db_*"` / `"Sql_unsafeFragment"`
/// alias resolved by `ipe_canon::resolve::detect_kernel_alias` to a retained
/// kernel: `unsafeExecRaw`/`unsafeQuery`/`unsafeGet*` to the unchanged `Db*`
/// kernels (runtime: `ipe_runtime::db::db_exec_raw`/`db_query_params`/
/// `db_get_*`), and the new `unsafeFragment` to the `SqlUnsafeFragment` kernel
/// (runtime: `ipe_runtime::db::sql_unsafe_fragment`, the un-validated
/// counterpart to `sql_column`). Only the surface home moved here from
/// `Ipe.Db` / `Ipe.Db.Sql`; the kernels, their registry keys, and their
/// runtime behaviour are unchanged. Importing this dotted `Ipe.<M>.Unsafe`
/// submodule discloses the `unsafe` capability. Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`,
/// so the disjointness invariant holds.
const DB_UNSAFE: &str = include_str!("../Ipe/Db/Unsafe.ipe");
/// `Ipe.Db.Dsn` — the typed, opaque connection descriptor (parse-don't-validate),
/// compiled-source Layer-3.
///
/// Defines the `Driver` / `TlsMode` ADTs and wraps the `Db.Dsn_*` parse-surface
/// kernels (`parse` / `build` / accessors / `redacted`), resolved by
/// `ipe_canon::resolve::detect_kernel_alias` to the retained `Dsn*` kernels
/// (runtime: `ipe_runtime::dsn::*`). The descriptor's password is a `Secret`;
/// there is no plain-`String` password accessor. Pure — constructing a `Dsn`
/// discloses no capability. Registered in [`COMPILED_STD_MODULES`] (NOT
/// `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`, so the disjointness invariant
/// holds.
const DB_DSN: &str = include_str!("../Ipe/Db/Dsn.ipe");
/// `Ipe.Db.Location` — the typed location `Db.open` opens, compiled-source
/// Layer-3.
///
/// Defines the `Mode` ADT and wraps the `Db.Location_*` constructor kernels,
/// marshalling `Mode` to a small-integer tag. A file location is parsed once
/// into a sealed SQLite file name, so no caller text reaches a URL parser.
/// Pure — constructing a location discloses no capability. Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in
/// `STDLIB_MODULE_QUALIFIERS`, so the disjointness invariant holds.
const DB_LOCATION: &str = include_str!("../Ipe/Db/Location.ipe");
/// `Ipe.Secret.Unsafe` — the raw secret-reveal escape hatch for `Ipe.Secret`,
/// compiled-source Layer-3.
///
/// The single member `unsafeReveal` is a point-free `Kernel.kernel "Secret_reveal"`
/// alias resolved by `ipe_canon::resolve::detect_kernel_alias` to the retained
/// `SecretReveal` kernel (runtime: `ipe_runtime::secret::secret_reveal`, the
/// single greppable un-parse). Only the surface home moved here from
/// `Ipe.Secret`; the kernel, its registry key, and the sealed-newtype barrier
/// are unchanged. The scoped `Secret.use` stays on the native `Ipe.Secret`
/// surface. Importing this dotted `Ipe.<M>.Unsafe` submodule discloses the
/// `unsafe` capability. Registered in [`COMPILED_STD_MODULES`] (NOT `MODULES`);
/// NOT in `STDLIB_MODULE_QUALIFIERS`, so the disjointness invariant holds.
const SECRET_UNSAFE: &str = include_str!("../Ipe/Secret/Unsafe.ipe");
/// `Ipe.Html` — HTML element builders, compiled-source Layer-3.
///
/// Every element builder (`div`/`nav`/`br`/…) is pure Ipê over two retained
/// primitives — `node`/`voidNode` — which, with `text`/`doctype`/
/// `titleNode`/`styleNode`, are point-free `Kernel.kernel "Html_*"` aliases
/// resolved by `ipe_canon::resolve::detect_kernel_alias` to the retained
/// `HtmlNode`/`HtmlVoidNode`/… kernels (runtime: `ipe_runtime::ui::helpers::*`).
/// The serialiser (`render`/`toString`/`escapeHtml`/`escapeAttr`/`attrToString`)
/// and `renderStatic` stay native — the XSS barrier — and are re-aliased here so
/// `Html.render` keeps resolving. Event attributes stay in `Ipe.Html.Events`.
/// Registered in [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in
/// `STDLIB_MODULE_QUALIFIERS`, so the disjointness invariant holds.
const HTML: &str = include_str!("../Ipe/Html.ipe");
/// `Ipe.Ui` — element / attribute / colour / layout surface, compiled-source
/// Layer-3.
///
/// The layout builders (`el`/`row`/`column`/`wrappedRow`/`grid`/`paragraph`/
/// `textColumn`/`form`/`input`) are pure Ipê over two retained primitives —
/// `node`/`taggedNode` — point-free `Kernel.kernel "Ui_*"` aliases resolved by
/// `ipe_canon::resolve::detect_kernel_alias` to the retained `UiNode`/
/// `UiTaggedNode` kernels (runtime: `ipe_runtime::ui::helpers::*`). Every other
/// member (`layout`/`spacing`/`button`/`link`/`image`/the `on*` events/the
/// security-gated `mediaQuery`/`breakpoint`/`onPseudo`/the `desc*` roles/…)
/// stays native and is re-aliased here through the same mechanism, so its
/// bespoke emit arm is unchanged. The
/// `Ipe.Ui.*` sub-modules (Background/Border/Font/Region/Input/Lazy/Keyed)
/// stay native kernel qualifiers. Registered in [`COMPILED_STD_MODULES`] (NOT
/// `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`, so the disjointness invariant
/// holds.
const UI: &str = include_str!("../Ipe/Ui.ipe");
/// `Ipe.Regex` — RE2 regex helpers, compiled-source Layer-3.
///
/// The members are point-free `Kernel.kernel "Regex_*"` aliases resolved by the
/// kernel-alias mechanism (`ipe_canon::resolve::detect_kernel_alias`) to
/// the pure `RegexMatch`/`RegexFind`/… `StdlibKernel` variants. Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`) so its body is actually compiled;
/// NOT in `STDLIB_MODULE_QUALIFIERS`, so the disjointness invariant holds.
const REGEX: &str = include_str!("../Ipe/Regex.ipe");
/// `Ipe.Url` — typed, validated URLs, compiled-source Layer-3.
///
/// The members are point-free `Kernel.kernel "Url_*"` aliases resolved by the
/// kernel-alias mechanism (`ipe_canon::resolve::detect_kernel_alias`) to the
/// pure `UrlFromString`/`UrlScheme`/… `StdlibKernel` variants (runtime:
/// `ipe_runtime::url::*`). Registered in [`COMPILED_STD_MODULES`] (NOT
/// `MODULES`) so its body is actually compiled; NOT in
/// `STDLIB_MODULE_QUALIFIERS`, so the disjointness invariant holds.
const URL: &str = include_str!("../Ipe/Url.ipe");

/// `Ipe.Url.Parser` — typed routing patterns over a parsed `Url`,
/// compiled-source Layer-3.
///
/// Pure Ipê source; no `Kernel.kernel` calls and no stored function values. A
/// `Pattern` is pure data (segment matchers plus query keys); `parse` matches it
/// against the shipped `Ipe.Url` accessors (`path`/`query`) — splitting path
/// segments and query pairs once over the already-parsed `Url`, no re-parse — and
/// yields the ordered `Captures`. Registered in [`COMPILED_STD_MODULES`] (NOT
/// `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`, so the disjointness invariant
/// holds.
const URL_PARSER: &str = include_str!("../Ipe/Url/Parser.ipe");

/// `Ipe.Markdown` — markdown → `Ipe.Ui` Element renderer, compiled-source
/// Layer-3.
///
/// Pure Ipê source; no `Kernel.kernel` calls. The entire renderer (block
/// parser + inline span parser + `Ui.*` tree builder) is expressed in Ipê.
/// Output routes exclusively through typed `Ipe.Ui` constructors so no raw
/// HTML, scripts, or event handlers can reach the DOM — safe to feed
/// untrusted markdown without an extra sanitisation step.
///
/// NOT in `STDLIB_MODULE_QUALIFIERS`, so the disjointness invariant holds.
const STD_MARKDOWN: &str = include_str!("../Ipe/Markdown.ipe");

/// Every kernel veneer parse fixture, keyed by its dotted import name: the
/// [`STDLIB`] rows a [`Role::Kernel`] veneer or a [`Role::CompiledVeneer`] carries.
pub const MODULES: &[StdModule] = &VENEER_ROWS;

/// The embedded Ipê source for a dotted `Ipe` module name, or `None` when
/// the name is not one of the embedded modules.
#[must_use]
pub fn source(module_name: &str) -> Option<&'static str> {
    MODULES
        .iter()
        .find(|m| m.name == module_name)
        .map(|m| m.source)
}

// ===========================================================================
// Compiled-source stdlib modules — DISJOINT from `MODULES` above.
// ===========================================================================
//
// `MODULES` above is a PARSE-TEST fixture: those `Ipe.*` files are shadow
// copies whose real implementations are Rust kernels resolved by qualifier.
// `COMPILED_STD_MODULES` is the opposite: modules that are ACTUALLY compiled
// from Ipê source through the ordinary parse → canon → infer → lower → emit
// pipeline (a Std-source module that defines AND pattern-matches its own data
// type — the exact thing a kernel cannot express).
//
// A module is EITHER kernel-qualified (a member of `STDLIB_MODULE_QUALIFIERS`)
// OR compiled-source (here) — never both. `compiled_vs_kernel_qualifier_disjoint`
// enforces that invariant; a name in both would be pre-installed as a kernel
// qualifier AND injected as a source dep, giving ambiguous resolution.

/// A stdlib module's presentation tier: how `ipe doc` and the stdlib
/// reference group and label it.
///
/// This is a typed fact on the registry row, never read off the dotted
/// name's spelling: a consumer renders from `tier`, and the `.Internals`
/// suffix carries no meaning of its own (see the `tiers_agree_with_names`
/// build-time proof below, which ties the two together exactly once).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdTier {
    /// Part of the public, documented API surface.
    Public,
    /// A low-level port layer backing the public module named `of`; importable
    /// (canon places no restriction on it) but presented as internal.
    PortLayer {
        /// The dotted name of the public module this port layer backs.
        of: &'static str,
    },
}

/// One compiled-from-source standard-library module: its dotted name, its
/// embedded Ipê source, and its presentation tier.
pub struct CompiledStdModule {
    /// The dotted module name as written in an `import`, e.g. `Ipe.Palette`.
    pub dotted: &'static str,
    /// The module's Ipê source, embedded at compile time.
    pub source: &'static str,
    /// How `ipe doc` and the stdlib reference present this module.
    pub tier: StdTier,
}

/// `Ipe.Palette` — a Std-namespace spike module that defines `Shade` / `Spacing`
/// and pattern-matches their constructors in `toHex` / `spacingPx`. Neither
/// type name collides with the `Length` / `Color` vocabulary that `Ipe.Css`
/// owns; `Spacing` / `Sp` are unique to this module.
const PALETTE: &str = include_str!("../Ipe/Palette.ipe");

/// `Ipe.Color` — Layer-3 source; every member is a point-free
/// `Kernel.kernel "Color_*"` alias resolved by `detect_kernel_alias` to the
/// registered `Color*` kernels (`ipe_runtime::color::*`). Also re-exports the
/// `Color` builtin type via the reserved-builtin-type path in
/// `build_module_exports`. Disjoint from `STDLIB_MODULE_QUALIFIERS` (no
/// `"Color"` entry there).
const COLOR: &str = include_str!("../Ipe/Color.ipe");

/// `Ipe.Tuple` — pure pair helpers (elm/core `Tuple` parity).
///
/// Pure Ipê source; no `Kernel.kernel` calls — every helper pattern-matches or
/// builds a 2-tuple.  Not in `STDLIB_MODULE_QUALIFIERS` so the disjointness
/// invariant holds.
const TUPLE: &str = include_str!("../Ipe/Tuple.ipe");

/// `Ipe.Parser` — pure parser-combinator library (elm/parser parity).
///
/// Pure Ipê source: defines AND pattern-matches its own `Parser` / `Problem` /
/// `Step` / internal `State` / `Step_` data types, expressing every combinator
/// over `Ipe.String` / `Ipe.Char` primitives with no `Kernel.kernel` calls. A
/// `Parser a` wraps a `State -> Step_ a` function in a single-constructor union
/// (a storable value carrier). Disjoint from `STDLIB_MODULE_QUALIFIERS` (no
/// `"Parser"` entry there), so the invariant holds.
const PARSER: &str = include_str!("../Ipe/Parser.ipe");

/// `Ipe.Random.Generator` — composable, seeded, reproducible random
/// generators (elm/random `Generator` parity).
///
/// Pure Ipê source: defines the `Seed` union + a `Generator` type alias and
/// builds every combinator over the seeded primitives it draws through
/// `Kernel.kernel "Random_seededIntRaw"` / `"Random_seededFloatRaw"` (the pure
/// `RandomSeededInt`/`RandomSeededFloat` kernels, `ipe_runtime::random::*`).
/// The `Ipe.Random` KERNEL qualifier owns those primitives; this
/// compiled-source module is the DISTINCT `Ipe.Random.Generator` path, so the
/// disjointness invariant holds.
const RANDOM_GENERATOR: &str = include_str!("../Ipe/Random/Generator.ipe");

/// `Ipe.Css` — the typed stylesheet DSL, compiled pure Ipê source: it
/// defines AND pattern-matches its own `CssProp` / `CssRule` / `Length` /
/// `Color` / keyword-enum ADTs and folds them to a CSS string.  Its only Rust
/// surface is the leaf security kernels under the `Ipe.CssSafety`
/// kernel qualifier (NOT under `Ipe.Css`, so the disjointness invariant holds).
const CSS: &str = include_str!("../Ipe/Css.ipe");

/// `Ipe.Test` — lightweight in-process test framework.
///
/// Compiled pure-Ipê source that defines the `Test` / `TestResult` ADTs and
/// all assertion helpers.  `kindName` re-exports `Ipe.Error.kindName`; `summarise`
/// is pure (no IO).
/// Disjoint from `STDLIB_MODULE_QUALIFIERS` (no `"Test"` entry exists there).
const IPE_TEST: &str = include_str!("../Ipe/Test.ipe");

/// `Ipe.Web.Head` — typed `<head>` helpers for Ipe.Web per-page injection.
///
/// Helpers delegate to the `Html` kernel qualifier and the compiled-source
/// `Ipe.Html.Attributes` builders — no new kernel variants required.
/// `Ipe.Web.Head` is NOT in `STDLIB_MODULE_QUALIFIERS` (that table only has
/// `Ipe.Web` → `"Web"`), so the disjointness invariant holds.
const STD_LIVE_HEAD: &str = include_str!("../Ipe/Web/Head.ipe");

/// `Ipe.Web.Head.Unsafe` — the verbatim JSON-LD `<script>` injection hatch,
/// compiled-source Layer-3.
///
/// The single member `unsafeJsonLd` is a pure-Ipê definition over the `Html`
/// kernel qualifier (`Html.script` over an `Ipe.Html.Unsafe.unsafeRaw` body, as
/// the safe surface refuses a text-bodied `<script>`), homed here so the
/// raw-script sink never resolves off a plain `Ipe.Web.Head` import. Importing
/// this dotted `Ipe.<M>.Unsafe` submodule discloses the `unsafe` capability.
/// `Ipe.Web.Head.Unsafe` is NOT in
/// `STDLIB_MODULE_QUALIFIERS` (no kernel qualifier), so the disjointness
/// invariant holds.
const STD_LIVE_HEAD_UNSAFE: &str = include_str!("../Ipe/Web/Head/Unsafe.ipe");

/// `Ipe.Ui.Responsive` — device-class helpers for responsive layout branching.
///
/// Pure Ipê source; no kernel calls.  Ported verbatim from
/// `../ipe/ipe-stdlib/Std/Ui/Responsive.ipe`.
/// Not in `STDLIB_MODULE_QUALIFIERS` so disjointness invariant holds.
/// Unblocks `37-composite-live-shop` (N0004: Ipe.Ui.Responsive).
const STD_UI_RESPONSIVE: &str = include_str!("../Ipe/Ui/Responsive.ipe");

/// `Ipe.Ui.Chart` — pure-Ipê charting helpers (line, area, bar, sparkline, heatmap).
///
/// Depends on `Ui.colorCss` (kernel `UiColorCss`) to convert `Color` values to
/// CSS strings inside SVG attributes.  Ported verbatim from
/// `../ipe/ipe-stdlib/Std/Ui/Chart.ipe`.
/// Not in `STDLIB_MODULE_QUALIFIERS` so disjointness invariant holds.
/// Unblocks `38-composite-ui-multibackend` (N0004: Ipe.Ui.Chart).
const STD_UI_CHART: &str = include_str!("../Ipe/Ui/Chart.ipe");

/// `Ipe.Ui.Grid` — typed CSS-grid track ADT + `columns`/`rows`/`tracks` builders.
///
/// Pure-Ipê; uses the native `Ui.gridTracks` kernel (`KernelFn::UiGridTracksRaw`)
/// that constructs `AttrGridTracks(cols, rows)`, rendered as `grid-template-columns`/
/// `grid-template-rows` by the web renderer and parsed by `tui/layout.rs`.
/// Not in `STDLIB_MODULE_QUALIFIERS` so disjointness invariant holds.
const STD_UI_GRID: &str = include_str!("../Ipe/Ui/Grid.ipe");

/// `Ipe.Ui.Transition` — typed CSS transition `Step`/`Easing` ADTs +
/// `attribute`/`attributeUnsafe` builders.
///
/// Pure-Ipê; the `transition` primitive is a native `Ipe.Ui` kernel
/// (`KernelFn::UiTransitionRaw`) that constructs `AttrTransition shorthand
/// respect`, rendered by `src/runtime/rust/src/ui/render.rs`.
/// Not in `STDLIB_MODULE_QUALIFIERS` so disjointness invariant holds.
const STD_UI_TRANSITION: &str = include_str!("../Ipe/Ui/Transition.ipe");

/// `Ipe.Ui.Transform` — typed CSS transform / opacity helpers for `Ui.animate`
/// keyframes. Pure Ipê; uses only `Ipe.*` internals — no
/// native primitive needed. Not in `STDLIB_MODULE_QUALIFIERS` so disjointness
/// invariant holds. Unblocks `26-ui-showcase` (IPE-N0004: Ipe.Ui.Transform).
const STD_UI_TRANSFORM: &str = include_str!("../Ipe/Ui/Transform.ipe");

/// `Ipe.Ui.Animation` — typed CSS keyframe-animation `Iterations`/`FillMode`
/// ADTs + `Spec` record + `attribute`/`defaultSpec`/`with*` builders.
///
/// Pure-Ipê; the `animate` primitive is a native `Ipe.Ui` kernel
/// (`KernelFn::UiAnimateRaw`, `String -> String -> String -> Bool -> Attribute`)
/// that constructs `AttrAnimation name shorthand keyframes respect`, rendered
/// by `src/runtime/rust/src/ui/render.rs` (inline `animation:` property) and
/// injected as an `@keyframes` block by `web::style_inject::build_anim`.
/// Depends on the sibling `Ipe.Ui.Transition` (`Easing`) and `Ipe.Ui.Transform`
/// (`Prop`/`propsToCss`).
/// Not in `STDLIB_MODULE_QUALIFIERS` so disjointness invariant holds.
/// Unblocks `26-ui-showcase` (IPE-N0004: Ipe.Ui.Animation — Animation.attribute).
const STD_UI_ANIMATION: &str = include_str!("../Ipe/Ui/Animation.ipe");

/// `Ipe.Ui.Cells` — retained alias re-exposing the `Ipe.Ui.Tui` builders
/// under their historical path.
///
/// The Tui view type is `Screen msg` (a newtype distinct from `Element msg`),
/// produced exclusively by the builders here (`none` / `text` / `cells` /
/// `el` / `row` / `column`) and consumed only by `Tui.tea`'s `view` field.
/// Using these builders inside a Web/Cli shape is a compile-time type error
/// because the type checker sees `Screen msg` where `Element msg` is expected.
///
/// Not in `STDLIB_MODULE_QUALIFIERS` so disjointness invariant holds.
const STD_UI_CELLS: &str = include_str!("../Ipe/Ui/Cells.ipe");

/// `Ipe.Ui.Tui` — the Tui shape's view surface: the `Screen msg` view type,
/// its builders, and its OWN cell-native `Attribute msg` (spacing/padding/align/
/// bold/underline/colour). A terminal author imports this instead of `Ipe.Ui`,
/// so DOM attributes are unnameable in a `Screen` view (a type error, never a
/// silent render-time drop).
const STD_UI_TUI: &str = include_str!("../Ipe/Ui/Tui.ipe");

/// `Ipe.Ui.Cli` — the Cli shape's line-oriented view surface: the
/// `Lines msg` view type, its builders, and its OWN line-native `Attribute msg`
/// (bold/underline/dim/reverse/colour). A line author imports this instead of
/// `Ipe.Ui` or `Ipe.Ui.Tui`, so DOM and 2D cell-grid attributes are
/// unnameable in a `Lines` view (a type error, never a silent render-time drop).
const STD_UI_CLI: &str = include_str!("../Ipe/Ui/Cli.ipe");

/// `Ipe.Color.Ansi` — the first-class terminal colour palette: the sixteen named
/// ANSI colours plus `default` and a truecolour path, each typed `AnsiColor`
/// (the shared `ipe_runtime::color::AnsiColor` carrier). Both the Tui and Cli
/// view surfaces accept it in their `color` / `bg` builders.
const STD_COLOR_ANSI: &str = include_str!("../Ipe/Color/Ansi.ipe");

/// `Ipe.Codec` — one invariant codec that drives the JSON direction.
///
/// Pure Ipê source: defines the `Codec a` nominal union (an encoder plus a
/// decode-runner, both stored on the clonable shared-function carrier) and the
/// `map` bijection over the existing `Ipe.Json.Encode` / `Ipe.Json.Decode`
/// kernels — no new kernel, no `Kernel.kernel` call. The decode side is stored as
/// `String -> Result Error a` (a runner) rather than a bare `Decoder a` because
/// the runtime JSON decoder is a single-shot non-clonable carrier that cannot be
/// held in a reusable value. Not in `STDLIB_MODULE_QUALIFIERS` so the
/// disjointness invariant holds.
const STD_CODEC: &str = include_str!("../Ipe/Codec.ipe");

/// `Ipe.Db.Codec` — the codec↔SQL row seam. Turns one `Ipe.Codec.Codec a` into
/// a row's `(column, SqlValue)` binds (`codecToBinds`) and decodes a store `Row`
/// back to `a` (`codecFromRow`), reusing the codec's own JSON encoder/decoder
/// over an in-memory `Value` (via the `Json.Decode.decodeValue`/`value` seam) —
/// no second decoder, no string round-trip. Every produced value is a BOUND
/// `SqlValue` parameter; the bridge constructs no SQL text, so it adds no
/// injection surface over `Ipe.Db.Sql`. Pure Ipê. Not in
/// `STDLIB_MODULE_QUALIFIERS` so the disjointness invariant holds.
const STD_DB_CODEC: &str = include_str!("../Ipe/Db/Codec.ipe");

/// `Ipe.Analytics` — typed, consent-gated product analytics.
///
/// Pure Ipê source: defines the `Pii` opaque type (no `ToString`/`toJson`
/// instance — serialises only as `"[redacted]"`), `ConsentState`, `Sink`,
/// `PropValue`, `Props`, `Config`, and `AnalyticsEvent` ADTs. Routes I/O
/// through `Ipe.Io` (`Stderr` sink), `Ipe.File` (`Jsonl` sink), and
/// `Ipe.Db` / `Ipe.Db.Store` / `Ipe.Db.Sql` (store-backed persistence).
/// Consent gating is fail-closed in pure Ipê: `track` / `trackEvent` /
/// `persist` / `persistEvent` drop the event and return `Task.succeed ()`
/// on `Pending` or `Denied`. Money values encode losslessly as
/// `{"amount":"<decimal>","currency":"<code>"}`. PII is redacted before
/// any string reaches the database — `PPii` serialises to `"[redacted]"`
/// in the `props_json` column. No new kernel; all I/O routes through
/// existing `Io_eprintln`, `File_append`, and `Db_*` / `Sql_*` kernels.
/// Not in `STDLIB_MODULE_QUALIFIERS` so the disjointness invariant holds.
const STD_ANALYTICS: &str = include_str!("../Ipe/Analytics.ipe");

/// `Ipe.Db.Store` — codec-driven typed persistence.
///
/// Pure Ipê source: defines the `Store` / `ColType` / `ColumnSpec`
/// ADTs and pattern-matches them, driving reads and writes through the audited
/// `Ipe.Db` / `Ipe.Db.Sql` kernel surface — no new kernel, no `Kernel.kernel` call.
/// Injection-safe by construction: `validSqlIdent` is the only gate through which
/// a table/column identifier reaches SQL (mirroring the `valid_sql_ident` kernel
/// gate), and every value binds as a `SqlValue`/`SqlField` parameter through
/// `Db.insertFields`/`Db.updateFields`/`Db.findWhere`/`Db.deleteWhere`. The
/// raw-SQL escape stays on `Ipe.Db.Unsafe`. Not in `STDLIB_MODULE_QUALIFIERS`
/// (the `Ipe.Db` / `Ipe.Db.Sql` kernel qualifiers are the DISTINCT `["Ipe","Db"]`
/// / `["Ipe","Db","Sql"]` paths), so the disjointness invariant holds.
const STD_DB_STORE: &str = include_str!("../Ipe/Db/Store.ipe");

/// `Ipe.Db.Store.Unsafe` — the raw, string-named query leaves for `Ipe.Db.Store`.
///
/// Pure Ipê source: the `eq` / `neq` / `gt` / … leaves that name a column by a
/// bare `String` (for a `fromColumns` raw store that has no row type to check an
/// accessor against). Importing it discloses the `unsafe` capability. Not an
/// injection hatch — each column is still validated against the store's columns
/// at query build time through the same audited `Cond`→`SqlFragment` path. Not
/// in `STDLIB_MODULE_QUALIFIERS` so the disjointness invariant holds.
const STD_DB_STORE_UNSAFE: &str = include_str!("../Ipe/Db/Store/Unsafe.ipe");

/// `Ipe.Money` — currency-typed Money on `Ipe.Decimal` + ISO 4217 enum.
///
/// Compiled pure-Ipê source: defines the `Money` / `Currency` ADTs and
/// pattern-matches their own constructors.  All `Ffi.callPure` calls from
/// the original `Ffi.callPure` calls have been replaced with pure Ipe
/// case-expressions / recursions.  The FX rate registry is stubbed.
/// Not in `STDLIB_MODULE_QUALIFIERS` so disjointness invariant holds.
/// Unblocks `00-standard-libs` (N0004: Ipe.Money).
const STD_MONEY: &str = include_str!("../Ipe/Money.ipe");

/// `Ipe.WebSocket` — outbound WebSocket client (compiled source).
///
/// Defines 3 ADTs (`WebSocket`, `WebSocketMessage`, `CloseCode`) and routes its
/// I/O through `Kernel.kernel "WebSocket_*"` / `"Sub_subscribeWebSocket"` aliases.
/// RESOLVES (ipe-0 AND cargo-0): the six Task-tier `WebSocket_*` kernels plus
/// `Sub_subscribeWebSocket` are registered (`ipe_runtime::ws_client::*`). The
/// Sub-tier kernel is `any`-typed; the backend peephole splits it on the literal
/// `kind` into the four typed `sub_subscribe_ws_*` runtime fns. `connectWith`'s
/// `WebSocketCfg` record folds to the runtime `WsClientCfg` struct (mirrors the
/// `CacheCfg` fold). The `ws_client` runtime module + `tokio-tungstenite` dep are
/// gated behind the `websocket_client` feature the backend adds via
/// `uses_websocket`. Resolved via the `Kernel.kernel` alias fast-path, so the
/// `WebSocket` qualifier stays out of `STDLIB_MODULE_QUALIFIERS`.
const IPE_CORE_WEBSOCKET: &str = include_str!("../Ipe/WebSocket.ipe");

/// `Ipe.Ffi.Js` — the raw typed transport across the Ipê↔JS seam, ports (compiled
/// source).
///
/// Exposes `send : a -> Cmd msg` (outbound) and
/// `subscribe : Decoder a -> (a -> msg) -> Sub msg` (inbound), routed through the
/// `Kernel.kernel "Js_send"` / `"Js_subscribe"` aliases to the registered `JsSend` /
/// `JsSubscribe` kernels. The crossing value is seal-checked fail-closed on its
/// CONCRETE type (IPE-N0039, the same predicate the `CustomElement down up`
/// boundary uses), so a `Secret`/reserved-sink payload and a `Decoder Value`
/// subscription are both rejected at compile time — the untyped channel cannot be
/// spelled. Reachable use discloses the `js-port` capability. Resolved via the
/// `Kernel.kernel` alias fast-path, so the `Js` qualifier stays out of
/// `STDLIB_MODULE_QUALIFIERS`.
const IPE_CORE_JS: &str = include_str!("../Ipe/Ffi/Js.ipe");

/// `Ipe.Ffi.Js.CustomElement` — the typed JS custom-element boundary (compiled
/// source).
///
/// Exposes `node : CustomElement down up -> down -> (up -> msg) -> Element msg`,
/// routed through the `Kernel.kernel "CustomElement_node"` alias to the
/// registered custom-element view-node kernel, and the reserved literal-only `fromFile "<js-path>"`
/// constructor (recognised structurally by the resolver, not a value binding).
/// The crossing seals its down-state / up-event on the CONCRETE type
/// (IPE-N0039). The widget transport is shipped; the binding lowers to the
/// opaque handle. Resolved via the `Kernel.kernel` alias
/// fast-path, so the qualifier stays out of `STDLIB_MODULE_QUALIFIERS`.
const IPE_CORE_JS_CUSTOM_ELEMENT: &str = include_str!("../Ipe/Ffi/Js/CustomElement.ipe");

/// `Ipe.Ffi.Kernel` — the documentation veneer for the point-free kernel-alias
/// primitive `Kernel.kernel "<Name>"`.
///
/// A DOC-ONLY surface (registered in [`DOC_ONLY_MODULES`], NOT
/// `COMPILED_STD_MODULES`): `Ipe.Ffi.Kernel` is a reserved compiler-internal
/// qualifier — accepted at the import boundary and resolved by
/// `detect_kernel_alias` only in a driver-vouched embedded-stdlib / FFI-interface
/// module — never a member-bearing importable module. Keeping it out of
/// `COMPILED_STD_MODULES` is load-bearing: were it injectable, the many stdlib
/// modules that `import Ipe.Ffi.Kernel as Kernel` would pull in this
/// body-less veneer as a compiled dep. The embedded source carries only the
/// module-header and the `kernel : String -> a` signature + doc so the surface is
/// discoverable through `ipe doc`.
const IPE_FFI_KERNEL: &str = include_str!("../Ipe/Ffi/Kernel.ipe");

/// `Ipe.Ffi.Rust` — the documentation veneer for the taxonomy-native native-call
/// surface (`Rust.fn` / `Rust.const`) and the companion `foreign` declaration.
///
/// A DOC-ONLY surface (registered in [`DOC_ONLY_MODULES`], NOT
/// `COMPILED_STD_MODULES`): `Ipe.Ffi.Rust` is a reserved compiler-internal
/// qualifier — accepted at the import boundary, its `Rust.fn`/`Rust.const` calls
/// rewritten onto the driver-generated forwarder by `canonicalise_asserted_call`
/// — never a member-bearing importable module. The embedded source carries the
/// module-header and the `fn` / `const` signatures + docs so the surface is
/// discoverable through `ipe doc`.
const IPE_FFI_RUST: &str = include_str!("../Ipe/Ffi/Rust.ipe");

/// `Ipe.Package` — the schema of a `package.ipe` manifest. Documentation only:
/// the manifest reader checks a manifest against it, and nothing compiles it.
const IPE_PACKAGE: &str = include_str!("../Ipe/Package.ipe");

/// `Ipe.Browser.Clipboard` — write text to the system clipboard over `Ipe.Ffi.Js`
/// ports (compiled source).
///
/// The thin first-party proof of the per-capability web mechanism: importing this
/// reserved `Ipe.Browser.<Api>` module discloses `js-port:clipboard`
/// (import-derived, keyed on the canonical path via
/// `WebCapability::for_browser_module`), which the app-boundary consent gate then
/// requires the top-level app to grant. Registered in [`COMPILED_STD_MODULES`]
/// (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`, so the disjointness
/// invariant holds. The served wasm-sink JS handler reaches
/// `navigator.clipboard.writeText`, trapping a host denial to a typed `Err`.
const IPE_BROWSER_CLIPBOARD: &str = include_str!("../Ipe/Browser/Clipboard.ipe");

/// `Ipe.Browser.Clipboard.Internals` — the low-level clipboard port surface: the
/// closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring behind the high-level
/// `write` / `read`. Importing it discloses the same `js-port:clipboard` axis (the
/// prefix key covers the submodule). Registered in [`COMPILED_STD_MODULES`] (NOT
/// `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_CLIPBOARD_INTERNALS: &str =
    include_str!("../Ipe/Browser/Clipboard/Internals.ipe");

/// `Ipe.Browser.Geolocation` — read the device location over `Ipe.Ffi.Js` ports
/// (compiled source), spanning BOTH port directions: an outbound `JsCmd` request
/// (`current` one-shot / `watch` continuous) and an inbound `JsMsg` reply folded
/// exhaustively into `Result Error Coords`. Importing it discloses
/// `js-port:geolocation` (import-derived, keyed on the canonical
/// `Ipe.Browser.Geolocation` path prefix via `WebCapability::for_browser_module`).
/// The served wasm-sink JS handler reaches `navigator.geolocation.getCurrentPosition`
/// / `watchPosition`, trapping a denial / unavailability / timeout to the matching
/// typed inbound variant. Registered in [`COMPILED_STD_MODULES`] (NOT `MODULES`);
/// NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_GEOLOCATION: &str = include_str!("../Ipe/Browser/Geolocation.ipe");

/// `Ipe.Browser.Geolocation.Internals` — the low-level geolocation port surface:
/// the closed outbound/inbound ADTs, the full `Options` knob set, and the raw
/// `Ipe.Ffi.Js` wiring the high-level layer wraps. Importing it discloses the same
/// `js-port:geolocation` axis (the prefix key covers the submodule), so the full
/// option surface cannot be reached undisclosed. Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_GEOLOCATION_INTERNALS: &str =
    include_str!("../Ipe/Browser/Geolocation/Internals.ipe");

/// `Ipe.Browser.Notification` — show system notifications over `Ipe.Ffi.Js` ports
/// (compiled source), spanning BOTH port directions: an outbound `JsCmd` request
/// (`requestPermission` / `notify` / `notifyWith`) and an inbound `JsMsg` reply
/// folded exhaustively into `Result Error ()`. Importing it discloses
/// `js-port:notification` (import-derived, keyed on the canonical
/// `Ipe.Browser.Notification` path prefix via `WebCapability::for_browser_module`).
/// The served wasm-sink JS handler reaches `Notification.requestPermission` /
/// `new Notification`, trapping a denial / absence to the matching typed inbound
/// variant. Registered in [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in
/// `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_NOTIFICATION: &str = include_str!("../Ipe/Browser/Notification.ipe");

/// `Ipe.Browser.Notification.Internals` — the low-level notification port surface:
/// the closed outbound/inbound ADTs, the full `Options` knob set, and the raw
/// `Ipe.Ffi.Js` wiring the high-level layer wraps. Importing it discloses the same
/// `js-port:notification` axis (the prefix key covers the submodule). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_NOTIFICATION_INTERNALS: &str =
    include_str!("../Ipe/Browser/Notification/Internals.ipe");

/// `Ipe.Browser.Push` — subscribe the device to sealed push over `Ipe.Ffi.Js` ports
/// (compiled source): the opaque `ApplicationKey` and `Subscription`, and the
/// correlated `subscribe` / `current` / `unsubscribe` requests. Importing it
/// discloses `js-port:push` (import-derived, keyed on the canonical
/// `Ipe.Browser.Push` path prefix via `WebCapability::for_browser_module`).
/// Registered in [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in
/// `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_PUSH: &str = include_str!("../Ipe/Browser/Push.ipe");

/// `Ipe.Browser.Push.Internals` — the low-level push port surface: the one parser
/// and one encoder of the canonical subscription text and the reply decoders the
/// port runs. Importing it discloses the same `js-port:push` axis (the prefix key
/// covers the submodule). Registered in [`COMPILED_STD_MODULES`] (NOT `MODULES`);
/// NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_PUSH_INTERNALS: &str = include_str!("../Ipe/Browser/Push/Internals.ipe");

/// `Ipe.Browser.Storage` — read from and write to Web Storage (`localStorage`)
/// over `Ipe.Ffi.Js` ports (compiled source), spanning BOTH port directions: an
/// outbound `JsCmd` request (`get` / `set` / `remove` / `clear`) and an inbound
/// `JsMsg` reply folded exhaustively into `Result Error (Maybe String)`. Importing
/// it discloses `js-port:storage` (import-derived, keyed on the canonical
/// `Ipe.Browser.Storage` path prefix via `WebCapability::for_browser_module`). The
/// served wasm-sink JS handler reaches `localStorage.getItem` / `setItem` /
/// `removeItem` / `clear`, trapping a private-mode / absent-store throw to the
/// typed `Unavailable` inbound variant. Registered in [`COMPILED_STD_MODULES`]
/// (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_STORAGE: &str = include_str!("../Ipe/Browser/Storage.ipe");

/// `Ipe.Browser.Storage.Internals` — the low-level Web Storage port surface: the
/// closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring the high-level
/// layer wraps. Importing it discloses the same `js-port:storage` axis (the prefix
/// key covers the submodule). Registered in [`COMPILED_STD_MODULES`] (NOT
/// `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_STORAGE_INTERNALS: &str = include_str!("../Ipe/Browser/Storage/Internals.ipe");

/// `Ipe.Browser.Vibration` — drive the device vibration actuator over `Ipe.Ffi.Js`
/// ports (compiled source), spanning BOTH port directions: an outbound `JsCmd`
/// request (`vibrate` / `pattern` / `cancel`) and an inbound `JsMsg` reply folded
/// exhaustively into `Result Error ()`. Importing it discloses `js-port:vibration`
/// (import-derived, keyed on the canonical `Ipe.Browser.Vibration` path prefix via
/// `WebCapability::for_browser_module`). The served wasm-sink JS handler reaches
/// `navigator.vibrate`, trapping an absent actuator to the typed `Unavailable`
/// inbound variant. Registered in [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in
/// `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_VIBRATION: &str = include_str!("../Ipe/Browser/Vibration.ipe");

/// `Ipe.Browser.Vibration.Internals` — the low-level Vibration port surface: the
/// closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring the high-level
/// layer wraps. Importing it discloses the same `js-port:vibration` axis (the
/// prefix key covers the submodule). Registered in [`COMPILED_STD_MODULES`] (NOT
/// `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_VIBRATION_INTERNALS: &str =
    include_str!("../Ipe/Browser/Vibration/Internals.ipe");

/// `Ipe.Browser.Share` — invoke the platform share sheet over `Ipe.Ffi.Js` ports
/// (compiled source), spanning BOTH port directions: an outbound `JsCmd` request
/// (`share`) and an inbound `JsMsg` reply folded exhaustively into
/// `Result Error ()`. Importing it discloses `js-port:share` (import-derived, keyed
/// on the canonical `Ipe.Browser.Share` path prefix via
/// `WebCapability::for_browser_module`). The served wasm-sink JS handler reaches
/// `navigator.share`, trapping a user cancellation (`AbortError`) to `Cancelled`
/// and an absent API to `Unavailable`. Registered in [`COMPILED_STD_MODULES`] (NOT
/// `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_SHARE: &str = include_str!("../Ipe/Browser/Share.ipe");

/// `Ipe.Browser.Share.Internals` — the low-level Web Share port surface: the closed
/// outbound/inbound ADTs, the full `Payload` surface, and the raw `Ipe.Ffi.Js`
/// wiring the high-level layer wraps. Importing it discloses the same
/// `js-port:share` axis (the prefix key covers the submodule). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_SHARE_INTERNALS: &str = include_str!("../Ipe/Browser/Share/Internals.ipe");

/// `Ipe.Browser.Battery` — read the device battery status over `Ipe.Ffi.Js` ports
/// (compiled source), spanning BOTH port directions: an outbound `JsCmd` request
/// (`status` one-shot / `watch` continuous) and an inbound `JsMsg` reply folded
/// exhaustively into `Result Error Status`. Importing it discloses
/// `js-port:battery` (import-derived, keyed on the canonical `Ipe.Browser.Battery`
/// path prefix via `WebCapability::for_browser_module`). The served wasm-sink JS
/// handler reaches `navigator.getBattery`, trapping an absent API to the typed
/// `Unavailable` inbound variant. Registered in [`COMPILED_STD_MODULES`] (NOT
/// `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_BATTERY: &str = include_str!("../Ipe/Browser/Battery.ipe");

/// `Ipe.Browser.Battery.Internals` — the low-level Battery Status port surface: the
/// closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring the high-level
/// layer wraps. Importing it discloses the same `js-port:battery` axis (the prefix
/// key covers the submodule). Registered in [`COMPILED_STD_MODULES`] (NOT
/// `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_BATTERY_INTERNALS: &str = include_str!("../Ipe/Browser/Battery/Internals.ipe");

/// `Ipe.Browser.NetworkInfo` — read network-information hints over `Ipe.Ffi.Js`
/// ports (compiled source), spanning BOTH port directions: an outbound `JsCmd`
/// request (`info` one-shot / `watch` continuous) and an inbound `JsMsg` reply
/// folded exhaustively into `Result Error Info`. Importing it discloses
/// `js-port:network-info` (import-derived, keyed on the canonical
/// `Ipe.Browser.NetworkInfo` path prefix via `WebCapability::for_browser_module`).
/// The served wasm-sink JS handler reaches `navigator.connection`, trapping an
/// absent API to the typed `Unavailable` inbound variant. Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_NETWORK_INFO: &str = include_str!("../Ipe/Browser/NetworkInfo.ipe");

/// `Ipe.Browser.NetworkInfo.Internals` — the low-level Network Information port
/// surface: the closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring the
/// high-level layer wraps. Importing it discloses the same `js-port:network-info`
/// axis (the prefix key covers the submodule). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_NETWORK_INFO_INTERNALS: &str =
    include_str!("../Ipe/Browser/NetworkInfo/Internals.ipe");

/// `Ipe.Browser.FilePicker` — open a native file picker and read the chosen
/// file as a `data:` URL, over `Ipe.Ffi.Js` ports. Importing discloses
/// `js-port:file` (keyed on the `Ipe.Browser.FilePicker` path prefix via
/// `WebCapability::for_browser_module`). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_FILE_PICKER: &str = include_str!("../Ipe/Browser/FilePicker.ipe");

/// `Ipe.Browser.FilePicker.Internals` — the low-level file-picker port
/// surface: the closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring
/// the high-level layer wraps. Importing it discloses the same `js-port:file`
/// axis (the prefix key covers the submodule). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_FILE_PICKER_INTERNALS: &str =
    include_str!("../Ipe/Browser/FilePicker/Internals.ipe");

/// `Ipe.Browser.Camera` — capture a photo from the device camera (or an
/// image file-input fallback on desktop) as a `data:` URL, over `Ipe.Ffi.Js`
/// ports. Importing discloses `js-port:camera` (keyed on the
/// `Ipe.Browser.Camera` path prefix via `WebCapability::for_browser_module`).
/// Registered in [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in
/// `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_CAMERA: &str = include_str!("../Ipe/Browser/Camera.ipe");

/// `Ipe.Browser.Camera.Internals` — the low-level camera capture port
/// surface: the closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring
/// the high-level layer wraps. Importing it discloses the same `js-port:camera`
/// axis (the prefix key covers the submodule). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_CAMERA_INTERNALS: &str = include_str!("../Ipe/Browser/Camera/Internals.ipe");

/// `Ipe.Browser.Microphone` — capture a bounded audio clip from the device
/// microphone as a base-64 `data:` URL, over `Ipe.Ffi.Js` ports. Importing
/// discloses `js-port:microphone` (keyed on the `Ipe.Browser.Microphone` path
/// prefix via `WebCapability::for_browser_module`). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_MICROPHONE: &str = include_str!("../Ipe/Browser/Microphone.ipe");

/// `Ipe.Browser.Microphone.Internals` — the low-level microphone capture port
/// surface: the closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring
/// the high-level layer wraps. Importing it discloses the same
/// `js-port:microphone` axis (the prefix key covers the submodule). Registered
/// in [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in
/// `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_MICROPHONE_INTERNALS: &str =
    include_str!("../Ipe/Browser/Microphone/Internals.ipe");

/// `Ipe.Browser.Speech` — one-shot text-to-speech synthesis and queue control
/// via the browser `speechSynthesis` API, over `Ipe.Ffi.Js` ports. Importing
/// discloses `js-port:speech` (keyed on the `Ipe.Browser.Speech` path prefix
/// via `WebCapability::for_browser_module`). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_SPEECH: &str = include_str!("../Ipe/Browser/Speech.ipe");

/// `Ipe.Browser.Speech.Internals` — the low-level speech synthesis port
/// surface: the closed outbound/inbound ADTs, the `Options` record, and the raw
/// `Ipe.Ffi.Js` wiring the high-level layer wraps. Importing it discloses the
/// same `js-port:speech` axis (the prefix key covers the submodule). Registered
/// in [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in
/// `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_SPEECH_INTERNALS: &str = include_str!("../Ipe/Browser/Speech/Internals.ipe");

/// `Ipe.Browser.Permission` — one-shot query and continuous state-change stream
/// over `navigator.permissions.query({ name })` (compiled source). Importing it
/// discloses `js-port:permission`; only the top-level app's `[capabilities]
/// accepts` set can grant it. Registered in [`COMPILED_STD_MODULES`] (NOT
/// `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_PERMISSION: &str = include_str!("../Ipe/Browser/Permission.ipe");

/// `Ipe.Browser.Permission.Internals` — the low-level Permissions API port
/// surface: the closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring
/// the high-level layer wraps. Importing it discloses the same
/// `js-port:permission` axis (the prefix key covers the submodule). Registered
/// in [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in
/// `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_PERMISSION_INTERNALS: &str =
    include_str!("../Ipe/Browser/Permission/Internals.ipe");

/// `Ipe.Browser.Gamepad` — a session-stream delivering gamepad connect/disconnect
/// events and polled button/axis state frames, over `Ipe.Ffi.Js` ports. Importing
/// discloses `js-port:gamepad` (keyed on the `Ipe.Browser.Gamepad` path prefix via
/// `WebCapability::for_browser_module`). Registered in [`COMPILED_STD_MODULES`]
/// (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_GAMEPAD: &str = include_str!("../Ipe/Browser/Gamepad.ipe");

/// `Ipe.Browser.Gamepad.Internals` — the low-level Gamepad port surface: the
/// closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring the high-level
/// layer wraps. Importing it discloses the same `js-port:gamepad` axis (the prefix
/// key covers the submodule). Registered in [`COMPILED_STD_MODULES`] (NOT
/// `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_GAMEPAD_INTERNALS: &str = include_str!("../Ipe/Browser/Gamepad/Internals.ipe");

/// `Ipe.Browser.Recorder` — record a bounded audio (or audio + video) stream from
/// the device via `getUserMedia` + `MediaRecorder`, delivered as a session-stream
/// of typed data chunks over `Ipe.Ffi.Js` ports. `startAudio` / `startVideo` open
/// the session (returning a typed `Recording` handle), `stop` closes it, and
/// `chunks` folds the inbound frames exhaustively into a typed `Frame`. Importing
/// discloses `js-port:recorder` (keyed on the `Ipe.Browser.Recorder` path prefix
/// via `WebCapability::for_browser_module`). Registered in [`COMPILED_STD_MODULES`]
/// (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_RECORDER: &str = include_str!("../Ipe/Browser/Recorder.ipe");

/// `Ipe.Browser.Recorder.Internals` — the low-level media-recording port surface:
/// the closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring the high-level
/// layer wraps. Importing it discloses the same `js-port:recorder` axis (the prefix
/// key covers the submodule). Registered in [`COMPILED_STD_MODULES`] (NOT
/// `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_RECORDER_INTERNALS: &str = include_str!("../Ipe/Browser/Recorder/Internals.ipe");

/// `Ipe.Browser.WebAuthn` — register and authenticate a public-key credential (a
/// passkey) via the Web Authentication API (`navigator.credentials.create` /
/// `.get`) over `Ipe.Ffi.Js` ports. `register` / `authenticate` return a
/// `Task Error PublicKeyCredential`; `results` folds inbound frames exhaustively
/// into a typed `Outcome`. Credential material is opaque base64url — never raw
/// key bytes. Importing discloses `js-port:web-authn` (keyed on the
/// `Ipe.Browser.WebAuthn` path prefix via `WebCapability::for_browser_module`).
/// Registered in [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in
/// `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_WEB_AUTHN: &str = include_str!("../Ipe/Browser/WebAuthn.ipe");

/// `Ipe.Browser.WebAuthn.Internals` — the low-level Web Authentication port
/// surface: the closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring the
/// high-level layer wraps. Importing it discloses the same `js-port:web-authn`
/// axis (the prefix key covers the submodule). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_WEB_AUTHN_INTERNALS: &str = include_str!("../Ipe/Browser/WebAuthn/Internals.ipe");

/// `Ipe.Browser.Visibility` — read the document visibility state over
/// `Ipe.Ffi.Js` ports (compiled source), spanning BOTH port directions: an
/// outbound `JsCmd` request (`state` one-shot / `watch` continuous) and an
/// inbound `JsMsg` reply folded exhaustively into `Result Error State`. Importing
/// it discloses `js-port:visibility` (import-derived, keyed on the canonical
/// `Ipe.Browser.Visibility` path prefix via `WebCapability::for_browser_module`).
/// The served JS sink reads `document.visibilityState`, trapping an absent API to
/// the typed `Unavailable` inbound variant. Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_VISIBILITY: &str = include_str!("../Ipe/Browser/Visibility.ipe");

/// `Ipe.Browser.Visibility.Internals` — the low-level Visibility port surface:
/// the closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring the
/// high-level layer wraps. Importing it discloses the same `js-port:visibility`
/// axis (the prefix key covers the submodule). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_VISIBILITY_INTERNALS: &str =
    include_str!("../Ipe/Browser/Visibility/Internals.ipe");

/// `Ipe.Browser.MediaQuery` — evaluate CSS media queries over `Ipe.Ffi.Js` ports
/// (compiled source), spanning BOTH port directions: an outbound `JsCmd` request
/// (`match_` one-shot / `watch` continuous) and an inbound `JsMsg` reply folded
/// exhaustively into `Result Error Bool`. Importing it discloses
/// `js-port:media-query` (import-derived, keyed on the canonical
/// `Ipe.Browser.MediaQuery` path prefix via `WebCapability::for_browser_module`).
/// The served JS sink reaches `window.matchMedia`, trapping an absent API to the
/// typed `Unavailable` inbound variant. Registered in [`COMPILED_STD_MODULES`]
/// (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_MEDIA_QUERY: &str = include_str!("../Ipe/Browser/MediaQuery.ipe");

/// `Ipe.Browser.MediaQuery.Internals` — the low-level `MediaQuery` port surface:
/// the closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring the
/// high-level layer wraps. Importing it discloses the same `js-port:media-query`
/// axis (the prefix key covers the submodule). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_MEDIA_QUERY_INTERNALS: &str =
    include_str!("../Ipe/Browser/MediaQuery/Internals.ipe");

/// `Ipe.Browser.Connectivity` — read the browser online/offline state over
/// `Ipe.Ffi.Js` ports (compiled source), spanning BOTH port directions: an
/// outbound `JsCmd` request (`connected` one-shot / `watch` continuous) and an
/// inbound `JsMsg` reply folded exhaustively into `Result Error Bool`. Importing
/// it discloses `js-port:connectivity` (import-derived, keyed on the canonical
/// `Ipe.Browser.Connectivity` path prefix via `WebCapability::for_browser_module`).
/// The served JS sink reads `navigator.onLine` and attaches `online`/`offline`
/// event listeners, trapping an absent API to the typed `Unavailable` inbound
/// variant. Registered in [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in
/// `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_CONNECTIVITY: &str = include_str!("../Ipe/Browser/Connectivity.ipe");

/// `Ipe.Browser.Connectivity.Internals` — the low-level Connectivity port
/// surface: the closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring the
/// high-level layer wraps. Importing it discloses the same `js-port:connectivity`
/// axis (the prefix key covers the submodule). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_CONNECTIVITY_INTERNALS: &str =
    include_str!("../Ipe/Browser/Connectivity/Internals.ipe");

/// `Ipe.Browser.Orientation` — a session-stream delivering `deviceorientation`
/// events as typed alpha/beta/gamma readings, over `Ipe.Ffi.Js` ports. Importing
/// discloses `js-port:orientation` (keyed on the `Ipe.Browser.Orientation` path
/// prefix via `WebCapability::for_browser_module`). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_ORIENTATION: &str = include_str!("../Ipe/Browser/Orientation.ipe");

/// `Ipe.Browser.Orientation.Internals` — the low-level Orientation port surface:
/// the closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring the high-level
/// layer wraps. Importing it discloses the same `js-port:orientation` axis (the
/// prefix key covers the submodule). Registered in [`COMPILED_STD_MODULES`]
/// (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_ORIENTATION_INTERNALS: &str =
    include_str!("../Ipe/Browser/Orientation/Internals.ipe");

/// `Ipe.Browser.Motion` — a session-stream delivering `devicemotion` events as
/// typed acceleration and rotation-rate readings, over `Ipe.Ffi.Js` ports.
/// Importing discloses `js-port:motion` (keyed on the `Ipe.Browser.Motion` path
/// prefix via `WebCapability::for_browser_module`). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_MOTION: &str = include_str!("../Ipe/Browser/Motion.ipe");

/// `Ipe.Browser.Motion.Internals` — the low-level Motion port surface: the closed
/// outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring the high-level layer
/// wraps. Importing it discloses the same `js-port:motion` axis (the prefix key
/// covers the submodule). Registered in [`COMPILED_STD_MODULES`] (NOT `MODULES`);
/// NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_MOTION_INTERNALS: &str = include_str!("../Ipe/Browser/Motion/Internals.ipe");

/// `Ipe.Browser.Channel` — a session-stream for cross-tab message exchange over
/// the `BroadcastChannel` API, via `Ipe.Ffi.Js` ports. Importing discloses
/// `js-port:channel` (keyed on the `Ipe.Browser.Channel` path prefix via
/// `WebCapability::for_browser_module`). Registered in [`COMPILED_STD_MODULES`]
/// (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_CHANNEL: &str = include_str!("../Ipe/Browser/Channel.ipe");

/// `Ipe.Browser.Channel.Internals` — the low-level `BroadcastChannel` port surface:
/// the closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring the high-level
/// layer wraps. Importing it discloses the same `js-port:channel` axis (the prefix
/// key covers the submodule). Registered in [`COMPILED_STD_MODULES`]
/// (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_CHANNEL_INTERNALS: &str = include_str!("../Ipe/Browser/Channel/Internals.ipe");

/// `Ipe.Browser.Fullscreen` — request/exit fullscreen and receive
/// `fullscreenchange` notifications, over `Ipe.Ffi.Js` ports. Importing discloses
/// `js-port:fullscreen` (keyed on the `Ipe.Browser.Fullscreen` path prefix via
/// `WebCapability::for_browser_module`). Registered in [`COMPILED_STD_MODULES`]
/// (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_FULLSCREEN: &str = include_str!("../Ipe/Browser/Fullscreen.ipe");

/// `Ipe.Browser.Fullscreen.Internals` — the low-level Fullscreen port surface: the
/// closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring the high-level
/// layer wraps. Importing it discloses the same `js-port:fullscreen` axis (the
/// prefix key covers the submodule). Registered in [`COMPILED_STD_MODULES`]
/// (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_FULLSCREEN_INTERNALS: &str =
    include_str!("../Ipe/Browser/Fullscreen/Internals.ipe");

/// `Ipe.Browser.ScreenOrientation` — lock/unlock the screen orientation and read
/// the current orientation type, over `Ipe.Ffi.Js` ports. Importing discloses
/// `js-port:screen-orientation` (keyed on the `Ipe.Browser.ScreenOrientation`
/// path prefix via `WebCapability::for_browser_module`). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_SCREEN_ORIENTATION: &str = include_str!("../Ipe/Browser/ScreenOrientation.ipe");

/// `Ipe.Browser.ScreenOrientation.Internals` — the low-level Screen Orientation
/// port surface: the closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring
/// the high-level layer wraps. Importing it discloses the same
/// `js-port:screen-orientation` axis (the prefix key covers the submodule).
/// Registered in [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in
/// `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_SCREEN_ORIENTATION_INTERNALS: &str =
    include_str!("../Ipe/Browser/ScreenOrientation/Internals.ipe");

/// `Ipe.Browser.WakeLock` — acquire a screen wake lock and release it, over
/// `Ipe.Ffi.Js` ports. Importing discloses `js-port:wake-lock` (keyed on the
/// `Ipe.Browser.WakeLock` path prefix via `WebCapability::for_browser_module`).
/// Registered in [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in
/// `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_WAKE_LOCK: &str = include_str!("../Ipe/Browser/WakeLock.ipe");

/// `Ipe.Browser.WakeLock.Internals` — the low-level Wake Lock port surface: the
/// closed outbound/inbound ADTs and the raw `Ipe.Ffi.Js` wiring the high-level
/// layer wraps. Importing it discloses the same `js-port:wake-lock` axis (the
/// prefix key covers the submodule). Registered in [`COMPILED_STD_MODULES`]
/// (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`.
const IPE_BROWSER_WAKE_LOCK_INTERNALS: &str = include_str!("../Ipe/Browser/WakeLock/Internals.ipe");

/// `Ipe.Env` — build-time-embedded public config (compiled source).
///
/// Defines `public : String -> Maybe String`, routed through the
/// `Kernel.kernel "Env_public"` alias to the registered `EnvPublic` kernel. The
/// generated `env_public.rs` (per-project, keyed on `package.ipe`'s `[wasm]
/// publicEnv` allowlist) is what actually backs it — see
/// `ipe_backend_rust::project::render_env_public_rs`. Resolved via the
/// `Kernel.kernel` alias fast-path, so the `Env` qualifier stays out of
/// `STDLIB_MODULE_QUALIFIERS`.
const IPE_CORE_ENV: &str = include_str!("../Ipe/Env.ipe");

/// `Ipe.Cache` — in-memory LRU + TTL cache (compiled source).
///
/// Defines `type Cache k v = Cache Int` ADT.  RESOLVES (ipe-0 AND
/// cargo-0): the seven `Cache_*` kernels are registered
/// (`ipe_runtime::cache::*`).  The opaque `Cache k v` is backed by the non-generic
/// runtime `IpeCacheHandle` (the phantom `k`/`v` are dropped); `CacheCfg` / the
/// `stats` return record fold to the runtime `CacheCfg` / `CacheStats` structs.
/// Not in `STDLIB_MODULE_QUALIFIERS` so disjointness invariant holds.
const STD_CACHE: &str = include_str!("../Ipe/Cache.ipe");

/// `Ipe.Compression` — gzip + zstd compression (compiled source).
///
/// Members are point-free `Kernel.kernel "Compression_*"` aliases backed by the
/// registered `Compression*` kernels (`ipe_runtime::compression::*`); the
/// `kernel_backed_qualifiers_match_registry` test locks that this stays true.
/// Not in `STDLIB_MODULE_QUALIFIERS` so disjointness invariant holds.
const STD_COMPRESSION: &str = include_str!("../Ipe/Compression.ipe");

/// `Ipe.Config` — typed TOML/YAML/JSON decoders (compiled source).
///
/// Defines `type Decoder a` — the SHARED opaque decoder carrier
/// (`IrType::Decoder`, runtime `ipe_runtime::json::Decoder<E, T>`), the same one
/// `Ipe.Json.Decode` names as a bare reserved builtin. RESOLVES (ipe-0
/// AND cargo-0): (a) `Ipe.Config`'s `Decoder` re-declaration is exempted
/// from IPE-N0026 via `ipe_canon`'s `STDLIB_DEFINABLE_CARRIER_TYPES` (trusted
/// `EmbeddedStdlib` origin only — user shadowing stays rejected); the ABOVE-guard
/// `Decoder` lowerer arm + `is_opaque_boxed_wrapper` make the re-declaration
/// lower to the shared carrier with no competing enum. (b) The 16 `Config_*`
/// kernels are registered across every anti-drift site; the 11 combinator/
/// primitive kernels emit the shared JSON `decode_*` runtime fns, the 5 format/
/// nullable/load kernels emit `ipe_runtime::config_decode::*` (vendored
/// unconditionally, same posture as Csv/Cache/Compression).
/// Not in `STDLIB_MODULE_QUALIFIERS`.
const STD_CONFIG: &str = include_str!("../Ipe/Config.ipe");

/// `Ipe.Csv` — CSV encode + decode (compiled source).
///
/// Defines `type alias Csv` + pure Ipê builders.  The kernel-backed members are
/// point-free `Kernel.kernel "Csv_*"` aliases backed by the registered `Csv*`
/// kernels; the `kernel_backed_qualifiers_match_registry` test locks that this
/// stays true.
/// Not in `STDLIB_MODULE_QUALIFIERS` so disjointness invariant holds.
const STD_CSV: &str = include_str!("../Ipe/Csv.ipe");

/// `Ipe.Email` — provider-abstract email send (compiled source).
///
/// Defines `type EmailProvider` + `type alias EmailMessage` ADTs.  `Email.send`
/// is a point-free `Kernel.kernel "Email_send"` alias backed by the registered
/// `EmailSend` kernel; the `kernel_backed_qualifiers_match_registry` test locks
/// that this stays true.
/// Not in `STDLIB_MODULE_QUALIFIERS` so disjointness invariant holds.
const STD_EMAIL: &str = include_str!("../Ipe/Email.ipe");

/// `Ipe.Web.Console` — typed console identity + builder helpers (compiled source).
///
/// Pure Ipê; no Kernel.kernel calls.
/// Not in `STDLIB_MODULE_QUALIFIERS` so disjointness invariant holds.
const STD_LIVE_CONSOLE: &str = include_str!("../Ipe/Web/Console.ipe");

/// `Ipe.PubSub` — Task-shaped publish, callable from any context (compiled source).
///
/// Routes through `Kernel.kernel "PubSub_publish"` / `"PubSub_publishNoEcho"`.
/// RESOLVES (ipe-0 AND cargo-0): `PubSubPublish`/`PubSubPublishNoEcho` have a
/// type scheme (`String -> a -> Task Error Int`) and a dedicated emit arm
/// (`pubsub_publish::<_, IpeError>(topic, payload)`).  A member use exits ipe-0
/// AND cargo-0.  The payload `a` is a genuine monomorphized type var (concrete-
/// over-generic), never erased.  Sanctioned divergence §B-FfiKernelAliasSealed: closed completeness gap.
/// Not in `STDLIB_MODULE_QUALIFIERS` so disjointness invariant holds.
const STD_PUBSUB: &str = include_str!("../Ipe/PubSub.ipe");

/// `Ipe.Remote` — typed endpoints between a split program's client and server
/// (compiled source).
///
/// Routes through `Kernel.kernel "Remote_*"`. REFUSED (ipe non-zero): the six
/// `Remote` kernels are unschemed, so every member use, and every annotation
/// naming `Remote` / `RemoteAuth`, fails closed with IPE-L0108; importing the
/// module without a use compiles. Not in `STDLIB_MODULE_QUALIFIERS` so the
/// disjointness invariant holds.
const STD_REMOTE: &str = include_str!("../Ipe/Remote.ipe");

/// `Ipe.Trace` — opt-in distributed-tracing spans (compiled source).
///
/// Members are point-free `Kernel.kernel "Trace_*"` aliases backed by the
/// registered `Trace*` kernels; the `kernel_backed_qualifiers_match_registry`
/// test locks that this stays true.
/// Not in `STDLIB_MODULE_QUALIFIERS` so disjointness invariant holds.
const STD_TRACE: &str = include_str!("../Ipe/Trace.ipe");

/// `Ipe.Locale` — opaque BCP-47 locale handle + locale-aware case mapping.
///
/// `Locale.fromTag`/`Locale.toTag` route through `Kernel.kernel "Locale_*"` aliases
/// resolved by the kernel-alias mechanism to the registered
/// `LocaleFromTag`/`LocaleToTag` `StdlibKernel` variants
/// (`ipe_runtime::locale::*`).  `String.toUpperIn`/`toLowerIn` route to the
/// registered `StringToUpperIn`/`StringToLowerIn` variants likewise.
/// Registered in [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in
/// `STDLIB_MODULE_QUALIFIERS`, so the disjointness invariant holds.
/// The runtime `locale` feature is required; programs that never import this
/// module pay no ICU4X dependency cost.
const LOCALE: &str = include_str!("../Ipe/Locale.ipe");

/// `Ipe.Math` — numeric helpers, compiled-source Layer-3.
///
/// Every member is a point-free `Kernel.kernel "Math_*"` alias resolved by
/// `ipe_canon::resolve::detect_kernel_alias` to a registered `Math*`
/// `StdlibKernel` variant (`ipe_runtime::math::*`). Registered in
/// [`COMPILED_STD_MODULES`] (NOT `MODULES`); NOT in `STDLIB_MODULE_QUALIFIERS`,
/// so the disjointness invariant holds.
const MATH: &str = include_str!("../Ipe/Math.ipe");
const LOG: &str = include_str!("../Ipe/Log.ipe");
const LEVEL: &str = include_str!("../Ipe/Level.ipe");
const ERROR: &str = include_str!("../Ipe/Error.ipe");

/// `Ipe.Ui.Events` — pure Ipê re-exports of `Ipe.Ui` event helpers (compiled source).
///
/// Pure Ipê; no Kernel.kernel calls.  RESOLVES (ipe-0 AND cargo-0): the
/// `onSubmit`/`onInput` re-exports are typed to the Rust kernels'
/// function-arg schemes (`(a -> msg) -> Attribute msg` /
/// `(String -> msg) -> Attribute msg`) — sanctioned divergence §B-UiEventsFnArg.
/// Not in `STDLIB_MODULE_QUALIFIERS` so disjointness invariant holds.
const STD_UI_EVENTS: &str = include_str!("../Ipe/Ui/Events.ipe");

/// `Ipe.Net` — the opaque, range-validated `Port` newtype (compiled source).
///
/// Pure Ipê: defines `type Port = Port Int` and pattern-matches it in `toInt`;
/// the constructor is unexported, so `fromInt` (the `1..65535` parse boundary,
/// building its `Err` through `Ipe.Error.invalidInput`) is the only way in.
/// No `Kernel.kernel` call. Not in `STDLIB_MODULE_QUALIFIERS`, so the disjointness
/// invariant holds.
const STD_NET: &str = include_str!("../Ipe/Net.ipe");

/// `Ipe.Duration` — the opaque, unit-explicit `Duration` newtype (compiled source).
///
/// Pure Ipê: defines `type Duration = Duration Int` (whole milliseconds) and
/// pattern-matches it in `toMillis`; the constructor is unexported, so the
/// unit-named constructors (`millis`/`seconds`/`minutes`, each clamping a
/// negative to zero) are the only way in. No `Kernel.kernel` call. Not in
/// `STDLIB_MODULE_QUALIFIERS`, so the disjointness invariant holds.
const STD_DURATION: &str = include_str!("../Ipe/Duration.ipe");

/// `Ipe.Time.Timestamp` — the opaque instant-in-time newtype (compiled source).
///
/// Pure Ipê: defines `type Timestamp = Timestamp Int` (milliseconds since the
/// Unix epoch) and pattern-matches it in `toUnixMillis`; the constructor is
/// NOT exported, so `fromUnixMillis` is the only way in. Arithmetic composes
/// with `Ipe.Duration`: `add : Duration -> Timestamp -> Timestamp` and
/// `diff : Timestamp -> Timestamp -> Duration`. The `Time_*` runtime kernels
/// keep their `Int` signatures; the `Ipe.Time` wrapper maps `Timestamp`
/// to/from the raw integer at the boundary. Not in `STDLIB_MODULE_QUALIFIERS`,
/// so the disjointness invariant holds.
const STD_TIME_TIMESTAMP: &str = include_str!("../Ipe/Time/Timestamp.ipe");

/// `Ipe.ByteSize` — the opaque, unit-explicit `ByteSize` newtype (compiled source).
///
/// Pure Ipê: defines `type ByteSize = ByteSize Int` (bytes) and pattern-matches
/// it in `toBytes`; the constructor is unexported, so the unit-named
/// constructors (`bytes`/`kib`/`mib`, each clamping a negative to zero) are the
/// only way in. No `Kernel.kernel` call. Not in `STDLIB_MODULE_QUALIFIERS`, so the
/// disjointness invariant holds.
const STD_BYTESIZE: &str = include_str!("../Ipe/ByteSize.ipe");

/// `Ipe.Length` -- the shared CSS length-unit spelling SSOT (compiled source).
///
/// Pure Ipe: defines `type Unit = Px | Vh | Vw` and folds it in `toCss`, the
/// one Ipe-side place a shared `<n><unit>` length is spelled. `Ipe.Css`
/// delegates its shared `Px`/`Vh`/`Vw` arms here; the language-level mirror of
/// the runtime carrier `ipe_runtime::length::CssUnit`, held byte-equal to it by
/// the `css_length_color_ssot` gate. No `Kernel.kernel` call. Not in
/// `STDLIB_MODULE_QUALIFIERS`, so the disjointness invariant holds.
const STD_LENGTH: &str = include_str!("../Ipe/Length.ipe");

/// `Ipe.Http.StatusCode` — typed HTTP response status code (compiled source).
///
/// Pure Ipê: defines `type StatusCode = StatusCode Int` (unexported ctor) with
/// `fromInt` (total, any `Int` is valid), `code` (raw integer recovery), and
/// the four classifiers `isSuccess` / `isRedirect` / `isClientError` /
/// `isServerError`.  `Ipe.Http.statusCode` wraps `HttpResponse.status` into
/// this type at the API boundary — no runtime struct change required.  No
/// `Kernel.kernel` call.  Not in `STDLIB_MODULE_QUALIFIERS`, so the disjointness
/// invariant holds.
const STD_HTTP_STATUS_CODE: &str = include_str!("../Ipe/Http/StatusCode.ipe");

/// Every registered standard-library module, one row per module.
///
/// The single registry: [`MODULES`], [`COMPILED_STD_MODULES`] and
/// [`DOC_ONLY_MODULES`] are `const` projections of it, so a module is declared
/// once and every view reads the same row. Each `Ipe/**/*.ipe` file is the
/// source of exactly one row (`every_stdlib_file_registered_once`), and the
/// kernel and retired rows are exactly `ipe_canon`'s `STDLIB_MODULE_QUALIFIERS`
/// (`canon_qualifiers_equal_stdlib_projection`).
pub const STDLIB: &[StdlibModule] = &[
    // ── Kernel qualifiers: the resolver's `STDLIB_MODULE_QUALIFIERS` ─────────
    StdlibModule {
        dotted: "Ipe.Crypto",
        role: Role::Kernel {
            veneer: Some(CRYPTO),
        },
    },
    StdlibModule {
        dotted: "Ipe.Secret",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.CssSafety",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Jwt",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Json.Encode",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Json.Decode",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Json.Decode.Pipeline",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.System",
        role: Role::Kernel {
            veneer: Some(SYSTEM),
        },
    },
    StdlibModule {
        dotted: "Ipe.Process",
        role: Role::Kernel {
            veneer: Some(PROCESS),
        },
    },
    StdlibModule {
        dotted: "Ipe.Http",
        role: Role::Kernel { veneer: Some(HTTP) },
    },
    StdlibModule {
        dotted: "Ipe.Http.Server",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Http.Middleware",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Http.RateLimit",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Db",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.App",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Host",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Console",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Db.Decode",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Db.Sql",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Ui.Background",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Ui.Border",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Ui.Font",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Ui.Region",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Ui.Input",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Ui.Lazy",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Ui.Keyed",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Html.Events",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Tea.Web",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Tea.Tui",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Tea.Cli",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Tea.Worker",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Tea.Web.PubSub",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Tea.Web.Cmd",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Tea.Web.Sub",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Tea.Terminal.Cmd",
        role: Role::Retired,
    },
    StdlibModule {
        dotted: "Ipe.Tea.Terminal.Sub",
        role: Role::Retired,
    },
    StdlibModule {
        dotted: "Ipe.Tea.Tui.Cmd",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Tea.Tui.Sub",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Tea.Cli.Cmd",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Tea.Cli.Sub",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Tea.Worker.Cmd",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Tea.Worker.Sub",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Auth",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Auth.Revocation",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Http.Server.Stream",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Http.Stream",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Http.Server.WebSocket",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Server",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Server.Http",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Server.Middleware",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Server.RateLimit",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Server.Stream",
        role: Role::Kernel { veneer: None },
    },
    StdlibModule {
        dotted: "Ipe.Server.WebSocket",
        role: Role::Kernel { veneer: None },
    },
    // ── Compiled-source modules ──────────────────────────────────────────────
    StdlibModule {
        dotted: "Ipe.Palette",
        role: Role::Compiled {
            source: PALETTE,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Net",
        role: Role::Compiled {
            source: STD_NET,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Duration",
        role: Role::Compiled {
            source: STD_DURATION,
            tier: StdTier::Public,
        },
    },
    // Ipe.Time.Timestamp — opaque instant newtype; pure Ipê over a raw `Int`
    // epoch-millis carrier. Composes with `Ipe.Duration` for typed arithmetic.
    // The `Time_*` runtime kernels keep their `Int` signatures.
    StdlibModule {
        dotted: "Ipe.Time.Timestamp",
        role: Role::Compiled {
            source: STD_TIME_TIMESTAMP,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.ByteSize",
        role: Role::Compiled {
            source: STD_BYTESIZE,
            tier: StdTier::Public,
        },
    },
    // Ipe.Length -- pure-Ipe SSOT for the shared CSS length-unit spelling
    // (`Px`/`Vh`/`Vw`); `Ipe.Css` folds its shared arms through it. No kernel
    // calls; the language-level mirror of `ipe_runtime::length::CssUnit`.
    StdlibModule {
        dotted: "Ipe.Length",
        role: Role::Compiled {
            source: STD_LENGTH,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Tuple",
        role: Role::Compiled {
            source: TUPLE,
            tier: StdTier::Public,
        },
    },
    // Ipe.Parser — pure-Ipê parser combinators (elm/parser parity); no kernel
    // calls. Defines and pattern-matches its own `Parser`/`Problem`/`Step` data.
    StdlibModule {
        dotted: "Ipe.Parser",
        role: Role::Compiled {
            source: PARSER,
            tier: StdTier::Public,
        },
    },
    // Ipe.Bitwise — Layer-3 source; every member is a point-free
    // `Kernel.kernel "Bitwise_*"` alias resolved by `detect_kernel_alias` to the
    // registered `Bitwise*` kernels (`ipe_runtime::bitwise::*`). Disjoint from
    // `STDLIB_MODULE_QUALIFIERS` (no `"Bitwise"` entry there).
    StdlibModule {
        dotted: "Ipe.Bitwise",
        role: Role::Compiled {
            source: BITWISE,
            tier: StdTier::Public,
        },
    },
    // Ipe.Color — Layer-3 source; every member is a point-free
    // `Kernel.kernel "Color_*"` alias resolved by `detect_kernel_alias` to the
    // registered `Color*` kernels (`ipe_runtime::color::*`). Also re-exports the
    // `Color` builtin type. Disjoint from `STDLIB_MODULE_QUALIFIERS` (no
    // `"Color"` entry there).
    StdlibModule {
        dotted: "Ipe.Color",
        role: Role::Compiled {
            source: COLOR,
            tier: StdTier::Public,
        },
    },
    // Ipe.Color.Ansi — the terminal colour palette (`black`…`brightWhite`,
    // `default`, `rgb`), each a point-free `Kernel.kernel "TermColor_*"` alias
    // typed `AnsiColor`. Imports `Ipe.Color` for the `AnsiColor` type.
    StdlibModule {
        dotted: "Ipe.Color.Ansi",
        role: Role::Compiled {
            source: STD_COLOR_ANSI,
            tier: StdTier::Public,
        },
    },
    // Ipe.String — Layer-3 source; every member is a point-free
    // `Kernel.kernel "String_*"` alias resolved by `detect_kernel_alias` to the
    // registered `String*` kernels. Also re-exports the `String` builtin type
    // via the reserved-builtin-type path in `build_module_exports`. Disjoint
    // from `STDLIB_MODULE_QUALIFIERS` (no `"String"` entry there).
    StdlibModule {
        dotted: "Ipe.String",
        role: Role::Compiled {
            source: STRING,
            tier: StdTier::Public,
        },
    },
    // Ipe.Encoding — Layer-3 source; every member is a point-free
    // `Kernel.kernel "Encoding_*"` alias resolved by `detect_kernel_alias` to the
    // registered `Encoding*` kernels (`ipe_runtime::encoding::*`). Disjoint from
    // `STDLIB_MODULE_QUALIFIERS` (no `"Encoding"` entry there).
    StdlibModule {
        dotted: "Ipe.Encoding",
        role: Role::Compiled {
            source: ENCODING,
            tier: StdTier::Public,
        },
    },
    // Ipe.Debug — Layer-3 source; every member is a point-free
    // `Kernel.kernel "Debug_*"` alias resolved by `detect_kernel_alias` to the
    // registered `Debug*` kernels (`ipe_runtime::debug::*`). Disjoint from
    // `STDLIB_MODULE_QUALIFIERS` (no `"Debug"` entry there).
    StdlibModule {
        dotted: "Ipe.Debug",
        role: Role::Compiled {
            source: DEBUG,
            tier: StdTier::Public,
        },
    },
    // Ipe.Uuid — Layer-3 source; `v4`/`v7`/`parse` are point-free
    // `Kernel.kernel "Uuid_*"` aliases resolved by `detect_kernel_alias` to the
    // registered `UuidV4`/`UuidV7`/`UuidParse` kernels
    // (`ipe_runtime::uuid_kernel::*`). Disjoint from `STDLIB_MODULE_QUALIFIERS`
    // (no `"Uuid"` entry there).
    StdlibModule {
        dotted: "Ipe.Uuid",
        role: Role::Compiled {
            source: UUID,
            tier: StdTier::Public,
        },
    },
    // Ipe.Time — Layer-3 source; every member is a point-free
    // `Kernel.kernel "Time_*"` alias resolved by `detect_kernel_alias` to the
    // registered `Time*` kernels. Disjoint from `STDLIB_MODULE_QUALIFIERS`
    // (no `"Time"` entry there).
    StdlibModule {
        dotted: "Ipe.Time",
        role: Role::Compiled {
            source: TIME,
            tier: StdTier::Public,
        },
    },
    // Ipe.Set — Layer-3 source; every member is a point-free
    // `Kernel.kernel "Set_*"` alias resolved by `detect_kernel_alias` to the
    // registered `Set*` kernels (`ipe_runtime::set::*`). Disjoint from
    // `STDLIB_MODULE_QUALIFIERS` (no `"Set"` entry there).
    StdlibModule {
        dotted: "Ipe.Set",
        role: Role::Compiled {
            source: SET,
            tier: StdTier::Public,
        },
    },
    // Ipe.Bytes — Layer-3 source; every member is a point-free
    // `Kernel.kernel "Bytes_*"` alias resolved by `detect_kernel_alias` to the
    // registered `Bytes*` kernels (`ipe_runtime::bytes::*`). Disjoint from
    // `STDLIB_MODULE_QUALIFIERS` (no `"Bytes"` entry there).
    StdlibModule {
        dotted: "Ipe.Bytes",
        role: Role::Compiled {
            source: BYTES,
            tier: StdTier::Public,
        },
    },
    // Ipe.Char — Layer-3 source; every member is a point-free
    // `Kernel.kernel "Char_*"` alias resolved by `detect_kernel_alias` to the
    // registered `Char*` kernels (`ipe_runtime::char::*`). Disjoint from
    // `STDLIB_MODULE_QUALIFIERS` (no `"Char"` entry there).
    StdlibModule {
        dotted: "Ipe.Char",
        role: Role::CompiledVeneer {
            source: CHAR,
            tier: StdTier::Public,
        },
    },
    // Ipe.Io — Layer-3 source; every member is a point-free
    // `Kernel.kernel "Io_*"` alias resolved by `detect_kernel_alias` to the
    // registered `Io*` kernels (`ipe_runtime::io::*`). Disjoint from
    // `STDLIB_MODULE_QUALIFIERS` (no `"Io"` entry there).
    StdlibModule {
        dotted: "Ipe.Io",
        role: Role::Compiled {
            source: IO,
            tier: StdTier::Public,
        },
    },
    // Ipe.Dict — Layer-3 source; every member is a point-free
    // `Kernel.kernel "Dict_*"` alias resolved by `detect_kernel_alias` to the
    // registered `Dict*` kernels (`ipe_runtime::dict::*`). Disjoint from
    // `STDLIB_MODULE_QUALIFIERS` (no `"Dict"` entry there).
    StdlibModule {
        dotted: "Ipe.Dict",
        role: Role::Compiled {
            source: DICT,
            tier: StdTier::Public,
        },
    },
    // Ipe.List — Layer-3 source; pure members compile from Ipê; the eleven
    // kernel-backed members (`sort`/`singleton`/`repeat`/`product`/
    // `intersperse`/`partition`/`unzip`/`map2`–`map5`) are point-free
    // `Kernel.kernel "List_*"` aliases resolved by `detect_kernel_alias` to the
    // registered `List*` kernels (`ipe_runtime::list::*`). Disjoint from
    // `STDLIB_MODULE_QUALIFIERS` (no `"List"` entry there).
    StdlibModule {
        dotted: "Ipe.List",
        role: Role::Compiled {
            source: LIST,
            tier: StdTier::Public,
        },
    },
    // Ipe.Task — Layer-3 source; members are either point-free
    // `Kernel.kernel "Task_*"` aliases resolved by `detect_kernel_alias` to the
    // registered `Task*` kernels (`ipe_runtime::task::*`), or pure Ipê over
    // those aliases (`BackoffStrategy` / `RetryPolicy`). Disjoint from
    // `STDLIB_MODULE_QUALIFIERS` (no `"Task"` entry there).
    StdlibModule {
        dotted: "Ipe.Task",
        role: Role::Compiled {
            source: TASK,
            tier: StdTier::Public,
        },
    },
    // Ipe.Decimal — Layer-3 source; every member is a point-free
    // `Kernel.kernel "Decimal_*"` alias resolved by `detect_kernel_alias` to the
    // registered `Decimal*` kernels (`ipe_runtime::decimal::*`). Disjoint from
    // `STDLIB_MODULE_QUALIFIERS` (no `"Decimal"` entry there after migration).
    StdlibModule {
        dotted: "Ipe.Decimal",
        role: Role::Compiled {
            source: DECIMAL,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Random",
        role: Role::Compiled {
            source: RANDOM,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Random.Generator",
        role: Role::Compiled {
            source: RANDOM_GENERATOR,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Css",
        role: Role::Compiled {
            source: CSS,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Test",
        role: Role::Compiled {
            source: IPE_TEST,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Web.Head",
        role: Role::Compiled {
            source: STD_LIVE_HEAD,
            tier: StdTier::Public,
        },
    },
    // Ipe.Web.Head.Unsafe — Layer-3 source; the single `unsafeJsonLd` verbatim
    // JSON-LD `<script>` hatch. Its body is pure Ipê over the `Html` kernel
    // qualifier and `Ipe.Html.Unsafe.unsafeRaw` — no new kernel. Importing it
    // discloses the `unsafe` capability.
    StdlibModule {
        dotted: "Ipe.Web.Head.Unsafe",
        role: Role::Compiled {
            source: STD_LIVE_HEAD_UNSAFE,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Ui.Responsive",
        role: Role::Compiled {
            source: STD_UI_RESPONSIVE,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Ui.Chart",
        role: Role::Compiled {
            source: STD_UI_CHART,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Ui.Grid",
        role: Role::Compiled {
            source: STD_UI_GRID,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Ui.Transition",
        role: Role::Compiled {
            source: STD_UI_TRANSITION,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Ui.Transform",
        role: Role::Compiled {
            source: STD_UI_TRANSFORM,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Ui.Animation",
        role: Role::Compiled {
            source: STD_UI_ANIMATION,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Ui.Cells",
        role: Role::Compiled {
            source: STD_UI_CELLS,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Ui.Tui",
        role: Role::Compiled {
            source: STD_UI_TUI,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Ui.Cli",
        role: Role::Compiled {
            source: STD_UI_CLI,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Codec",
        role: Role::Compiled {
            source: STD_CODEC,
            tier: StdTier::Public,
        },
    },
    // Ipe.Analytics — consent-gated typed analytics. `Pii` is opaque with no
    // reveal path; `PPii` always serialises as `"[redacted]"`. Consent is
    // fail-closed in pure Ipê (drop on Pending/Denied). Two concrete sinks:
    // `Stderr` (via `Io_eprintln`) and `Jsonl Path` (via `File_append`).
    StdlibModule {
        dotted: "Ipe.Analytics",
        role: Role::Compiled {
            source: STD_ANALYTICS,
            tier: StdTier::Public,
        },
    },
    // Ipe.Db.Store — Layer-3 source; codec-driven typed persistence over the
    // audited `Ipe.Db` / `Ipe.Db.Sql` kernels. Pure Ipê, no new kernel.
    // Injection-safe by construction (`validSqlIdent` gate + parameterised
    // binds). The raw-SQL escape stays on `Ipe.Db.Unsafe`.
    StdlibModule {
        dotted: "Ipe.Db.Store",
        role: Role::Compiled {
            source: STD_DB_STORE,
            tier: StdTier::Public,
        },
    },
    // Ipe.Db.Store.Unsafe — Layer-3 source; the raw string-named query leaves for
    // a `fromColumns` raw store. Imports `Ipe.Db.Store` for the `Cond`
    // constructors. Importing it discloses the `unsafe` capability. Still
    // injection-safe (each column is validated against the store at query build).
    StdlibModule {
        dotted: "Ipe.Db.Store.Unsafe",
        role: Role::Compiled {
            source: STD_DB_STORE_UNSAFE,
            tier: StdTier::Public,
        },
    },
    // Ipe.Db.Codec — the codec↔SQL row seam (`codecToBinds` / `codecFromRow`).
    // Pure Ipê over `Ipe.Codec` + the reserved `SqlValue`; reuses the codec's
    // own JSON encoder/decoder via the in-memory `Value` seam. No new kernel is
    // registered here (the two Json `Value` seams live in `Ipe.Json.Decode`).
    // Injection-safe: every value is a bound `SqlValue`, no SQL text is built.
    StdlibModule {
        dotted: "Ipe.Db.Codec",
        role: Role::Compiled {
            source: STD_DB_CODEC,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Money",
        role: Role::Compiled {
            source: STD_MONEY,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.WebSocket",
        role: Role::Compiled {
            source: IPE_CORE_WEBSOCKET,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Ffi.Js",
        role: Role::Compiled {
            source: IPE_CORE_JS,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Ffi.Js.CustomElement",
        role: Role::Compiled {
            source: IPE_CORE_JS_CUSTOM_ELEMENT,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Clipboard",
        role: Role::Compiled {
            source: IPE_BROWSER_CLIPBOARD,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Clipboard.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_CLIPBOARD_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Clipboard",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Geolocation",
        role: Role::Compiled {
            source: IPE_BROWSER_GEOLOCATION,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Geolocation.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_GEOLOCATION_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Geolocation",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Notification",
        role: Role::Compiled {
            source: IPE_BROWSER_NOTIFICATION,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Notification.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_NOTIFICATION_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Notification",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Push",
        role: Role::Compiled {
            source: IPE_BROWSER_PUSH,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Push.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_PUSH_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Push",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Storage",
        role: Role::Compiled {
            source: IPE_BROWSER_STORAGE,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Storage.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_STORAGE_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Storage",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Vibration",
        role: Role::Compiled {
            source: IPE_BROWSER_VIBRATION,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Vibration.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_VIBRATION_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Vibration",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Share",
        role: Role::Compiled {
            source: IPE_BROWSER_SHARE,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Share.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_SHARE_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Share",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Battery",
        role: Role::Compiled {
            source: IPE_BROWSER_BATTERY,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Battery.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_BATTERY_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Battery",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.NetworkInfo",
        role: Role::Compiled {
            source: IPE_BROWSER_NETWORK_INFO,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.NetworkInfo.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_NETWORK_INFO_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.NetworkInfo",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.FilePicker",
        role: Role::Compiled {
            source: IPE_BROWSER_FILE_PICKER,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.FilePicker.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_FILE_PICKER_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.FilePicker",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Camera",
        role: Role::Compiled {
            source: IPE_BROWSER_CAMERA,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Camera.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_CAMERA_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Camera",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Microphone",
        role: Role::Compiled {
            source: IPE_BROWSER_MICROPHONE,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Microphone.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_MICROPHONE_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Microphone",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Speech",
        role: Role::Compiled {
            source: IPE_BROWSER_SPEECH,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Speech.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_SPEECH_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Speech",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Permission",
        role: Role::Compiled {
            source: IPE_BROWSER_PERMISSION,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Permission.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_PERMISSION_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Permission",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Gamepad",
        role: Role::Compiled {
            source: IPE_BROWSER_GAMEPAD,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Gamepad.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_GAMEPAD_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Gamepad",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Recorder",
        role: Role::Compiled {
            source: IPE_BROWSER_RECORDER,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Recorder.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_RECORDER_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Recorder",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.WebAuthn",
        role: Role::Compiled {
            source: IPE_BROWSER_WEB_AUTHN,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.WebAuthn.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_WEB_AUTHN_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.WebAuthn",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Visibility",
        role: Role::Compiled {
            source: IPE_BROWSER_VISIBILITY,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Visibility.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_VISIBILITY_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Visibility",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.MediaQuery",
        role: Role::Compiled {
            source: IPE_BROWSER_MEDIA_QUERY,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.MediaQuery.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_MEDIA_QUERY_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.MediaQuery",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Connectivity",
        role: Role::Compiled {
            source: IPE_BROWSER_CONNECTIVITY,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Connectivity.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_CONNECTIVITY_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Connectivity",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Orientation",
        role: Role::Compiled {
            source: IPE_BROWSER_ORIENTATION,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Orientation.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_ORIENTATION_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Orientation",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Motion",
        role: Role::Compiled {
            source: IPE_BROWSER_MOTION,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Motion.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_MOTION_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Motion",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Channel",
        role: Role::Compiled {
            source: IPE_BROWSER_CHANNEL,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Channel.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_CHANNEL_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Channel",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Fullscreen",
        role: Role::Compiled {
            source: IPE_BROWSER_FULLSCREEN,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.Fullscreen.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_FULLSCREEN_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.Fullscreen",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.ScreenOrientation",
        role: Role::Compiled {
            source: IPE_BROWSER_SCREEN_ORIENTATION,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.ScreenOrientation.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_SCREEN_ORIENTATION_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.ScreenOrientation",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.WakeLock",
        role: Role::Compiled {
            source: IPE_BROWSER_WAKE_LOCK,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Browser.WakeLock.Internals",
        role: Role::Compiled {
            source: IPE_BROWSER_WAKE_LOCK_INTERNALS,
            tier: StdTier::PortLayer {
                of: "Ipe.Browser.WakeLock",
            },
        },
    },
    StdlibModule {
        dotted: "Ipe.Env",
        role: Role::Compiled {
            source: IPE_CORE_ENV,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Cache",
        role: Role::Compiled {
            source: STD_CACHE,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Compression",
        role: Role::Compiled {
            source: STD_COMPRESSION,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Config",
        role: Role::Compiled {
            source: STD_CONFIG,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Csv",
        role: Role::Compiled {
            source: STD_CSV,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Email",
        role: Role::Compiled {
            source: STD_EMAIL,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Web.Console",
        role: Role::Compiled {
            source: STD_LIVE_CONSOLE,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.PubSub",
        role: Role::Compiled {
            source: STD_PUBSUB,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Remote",
        role: Role::Compiled {
            source: STD_REMOTE,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Trace",
        role: Role::Compiled {
            source: STD_TRACE,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Ui.Events",
        role: Role::Compiled {
            source: STD_UI_EVENTS,
            tier: StdTier::Public,
        },
    },
    // Ipe.Http.StatusCode — typed HTTP status code over Int (opaque ctor,
    // `fromInt` / `code` / `isSuccess` / `isRedirect` / `isClientError` /
    // `isServerError`).  Pure Ipê; no Kernel.kernel calls.
    StdlibModule {
        dotted: "Ipe.Http.StatusCode",
        role: Role::Compiled {
            source: STD_HTTP_STATUS_CODE,
            tier: StdTier::Public,
        },
    },
    // Ipe.Regex — Layer-3 source, `Kernel.kernel "Regex_*"` aliases route
    // to the registered pure `Regex*` kernels (`ipe_runtime::regex_kernel::*`).
    StdlibModule {
        dotted: "Ipe.Regex",
        role: Role::Compiled {
            source: REGEX,
            tier: StdTier::Public,
        },
    },
    // Ipe.Path — Layer-3 source, `Kernel.kernel "Path_*"` aliases route
    // to the registered pure `Path*` kernels (`ipe_runtime::path::*`).
    StdlibModule {
        dotted: "Ipe.Path",
        role: Role::Compiled {
            source: PATH,
            tier: StdTier::Public,
        },
    },
    // Ipe.File — Layer-3 source over the `File_*` effect kernels
    // (`ipe_runtime::file::*`); `readFileLimit` unwraps its `ByteSize` ceiling.
    StdlibModule {
        dotted: "Ipe.File",
        role: Role::Compiled {
            source: FILE,
            tier: StdTier::Public,
        },
    },
    // Ipe.Html.Attributes — Layer-3 source; fixed-key builders are pure Ipê over
    // the retained `Kernel.kernel "Attr_*"` primitives (`ipe_runtime::html::*`).
    StdlibModule {
        dotted: "Ipe.Html.Attributes",
        role: Role::Compiled {
            source: HTML_ATTRIBUTES,
            tier: StdTier::Public,
        },
    },
    // Ipe.Html.Unsafe — Layer-3 source; the single `unsafeRaw` escape hatch is a
    // `Kernel.kernel "Html_unsafeRaw"` alias to the unchanged `HtmlRawNode` kernel.
    // Importing it discloses the `unsafe` capability.
    StdlibModule {
        dotted: "Ipe.Html.Unsafe",
        role: Role::Compiled {
            source: HTML_UNSAFE,
            tier: StdTier::Public,
        },
    },
    // Ipe.Db.Unsafe — Layer-3 source; the raw-SQL / untyped-read escape hatches
    // are `Kernel.kernel "Db_*"` / `"Sql_unsafeFragment"` aliases to unchanged (and
    // one new) kernels. Importing it discloses the `unsafe` capability.
    StdlibModule {
        dotted: "Ipe.Db.Unsafe",
        role: Role::Compiled {
            source: DB_UNSAFE,
            tier: StdTier::Public,
        },
    },
    // Ipe.Db.Dsn — Layer-3 source; the typed, opaque connection descriptor
    // (parse-don't-validate). Defines the `Driver` / `TlsMode` ADTs and wraps the
    // `Db.Dsn_*` parse-surface kernels, marshalling the ADTs to/from small-integer
    // tags. Pure: constructing a `Dsn` performs no I/O and discloses no
    // capability. NOT an `.Unsafe` submodule.
    StdlibModule {
        dotted: "Ipe.Db.Dsn",
        role: Role::Compiled {
            source: DB_DSN,
            tier: StdTier::Public,
        },
    },
    // Ipe.Db.Location — Layer-3 source; the typed location `Db.open` opens.
    // Defines the `Mode` ADT and wraps the `Db.Location_*` constructor kernels.
    // Pure: constructing a location performs no I/O and discloses no capability.
    StdlibModule {
        dotted: "Ipe.Db.Location",
        role: Role::Compiled {
            source: DB_LOCATION,
            tier: StdTier::Public,
        },
    },
    // Ipe.Secret.Unsafe — Layer-3 source; the single `unsafeReveal` escape hatch
    // is a `Kernel.kernel "Secret_reveal"` alias to the unchanged `SecretReveal`
    // kernel. Importing it discloses the `unsafe` capability. The scoped
    // `Secret.use` stays on the native `Ipe.Secret` surface (capability-neutral).
    StdlibModule {
        dotted: "Ipe.Secret.Unsafe",
        role: Role::Compiled {
            source: SECRET_UNSAFE,
            tier: StdTier::Public,
        },
    },
    // Ipe.Html — Layer-3 source; element builders are pure Ipê over the retained
    // `Kernel.kernel "Html_node"` / `"Html_voidNode"` primitives, with the native
    // serialiser (`render`/`escape*`) re-aliased (`ipe_runtime::ui::helpers::*`).
    StdlibModule {
        dotted: "Ipe.Html",
        role: Role::Compiled {
            source: HTML,
            tier: StdTier::Public,
        },
    },
    // Ipe.Ui — Layer-3 source; the layout builders are pure Ipê over the retained
    // `Kernel.kernel "Ui_node"` / `"Ui_taggedNode"` primitives, with every other
    // member re-aliased to its unchanged native kernel (`ipe_runtime::ui::*`).
    StdlibModule {
        dotted: "Ipe.Ui",
        role: Role::Compiled {
            source: UI,
            tier: StdTier::Public,
        },
    },
    // Ipe.Markdown — pure Ipê markdown→Ui renderer; no kernel calls.
    StdlibModule {
        dotted: "Ipe.Markdown",
        role: Role::Compiled {
            source: STD_MARKDOWN,
            tier: StdTier::Public,
        },
    },
    // Ipe.Url — Layer-3 source, `Kernel.kernel "Url_*"` aliases route to the
    // registered pure `Url*` kernels (`ipe_runtime::url::*`).
    StdlibModule {
        dotted: "Ipe.Url",
        role: Role::Compiled {
            source: URL,
            tier: StdTier::Public,
        },
    },
    // Ipe.Url.Parser — pure-Ipê routing combinators over the shipped `Ipe.Url`
    // accessors; no kernel calls.
    StdlibModule {
        dotted: "Ipe.Url.Parser",
        role: Role::Compiled {
            source: URL_PARSER,
            tier: StdTier::Public,
        },
    },
    // Ipe.Locale — opaque BCP-47 locale handle + locale-aware case mapping.
    // `Locale.fromTag`/`Locale.toTag` resolve via `Kernel.kernel "Locale_*"`;
    // `String.toUpperIn`/`toLowerIn` resolve via `Kernel.kernel "String_toUpperIn"`
    // / `"String_toLowerIn"`.  The runtime module is `ipe_runtime::locale::*`
    // (feature `locale`).  Disjoint from `STDLIB_MODULE_QUALIFIERS` (no
    // `"Locale"` entry there), so the invariant holds.
    StdlibModule {
        dotted: "Ipe.Locale",
        role: Role::Compiled {
            source: LOCALE,
            tier: StdTier::Public,
        },
    },
    // Ipe.Math — Layer-3 source; every member is a point-free
    // `Kernel.kernel "Math_*"` alias resolved by `detect_kernel_alias` to the
    // registered `Math*` kernels (`ipe_runtime::math::*`). Disjoint from
    // `STDLIB_MODULE_QUALIFIERS` (no `"Math"` entry there), so the invariant
    // holds.
    StdlibModule {
        dotted: "Ipe.Math",
        role: Role::Compiled {
            source: MATH,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Basics",
        role: Role::Compiled {
            source: BASICS,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Maybe",
        role: Role::Compiled {
            source: MAYBE,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Result",
        role: Role::Compiled {
            source: RESULT,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Log",
        role: Role::Compiled {
            source: LOG,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Level",
        role: Role::Compiled {
            source: LEVEL,
            tier: StdTier::Public,
        },
    },
    StdlibModule {
        dotted: "Ipe.Error",
        role: Role::Compiled {
            source: ERROR,
            tier: StdTier::Public,
        },
    },
    // ── Documentation-only modules ───────────────────────────────────────────
    StdlibModule {
        dotted: "Ipe.Ffi.Kernel",
        role: Role::DocOnly {
            source: IPE_FFI_KERNEL,
        },
    },
    StdlibModule {
        dotted: "Ipe.Ffi.Rust",
        role: Role::DocOnly {
            source: IPE_FFI_RUST,
        },
    },
    StdlibModule {
        dotted: "Ipe.Package",
        role: Role::DocOnly {
            source: IPE_PACKAGE,
        },
    },
];

/// Every compiled-source stdlib module, keyed by its dotted import name: the
/// [`STDLIB`] rows a [`Role::Compiled`] or [`Role::CompiledVeneer`] carries.
///
/// Disjoint from `ipe_canon`'s `STDLIB_MODULE_QUALIFIERS` (kernel qualifiers) —
/// see the module comment.
pub const COMPILED_STD_MODULES: &[CompiledStdModule] = &COMPILED_ROWS;

/// Byte-wise equality; `split_first` keeps the walk free of slice indexing in
/// a `const fn`.
const fn bytes_eq(mut a: &[u8], mut b: &[u8]) -> bool {
    loop {
        match (a.split_first(), b.split_first()) {
            (None, None) => return true,
            (Some((&ha, ta)), Some((&hb, tb))) if ha == hb => (a, b) = (ta, tb),
            _ => return false,
        }
    }
}

/// Whether `dotted` ends in the literal suffix `.Internals`.
const fn ends_with_dot_internals(dotted: &str) -> bool {
    const SUFFIX: &[u8] = b".Internals";
    let bytes = dotted.as_bytes();
    if bytes.len() < SUFFIX.len() {
        return false;
    }
    let (_, tail) = bytes.split_at(bytes.len() - SUFFIX.len());
    bytes_eq(tail, SUFFIX)
}

/// Whether `dotted` is exactly `of` followed by the literal suffix
/// `.Internals`, byte for byte, with no allocation.
const fn names_internals_of(dotted: &str, of: &str) -> bool {
    const SUFFIX: &[u8] = b".Internals";
    let dotted_bytes = dotted.as_bytes();
    let of_bytes = of.as_bytes();
    if dotted_bytes.len() != of_bytes.len() + SUFFIX.len() {
        return false;
    }
    let (head, tail) = dotted_bytes.split_at(of_bytes.len());
    bytes_eq(head, of_bytes) && bytes_eq(tail, SUFFIX)
}

/// Whether `rows` holds a `StdTier::Public` row named `dotted`.
///
/// Searches `rows` itself, not the global `COMPILED_STD_MODULES` — so the
/// proof below is self-contained and exercisable on a fixture slice, not only
/// on the real table.
const fn has_public_row_named(rows: &[CompiledStdModule], dotted: &str) -> bool {
    let mut remaining = rows;
    while let Some((row, tail)) = remaining.split_first() {
        if matches!(row.tier, StdTier::Public) && bytes_eq(row.dotted.as_bytes(), dotted.as_bytes())
        {
            return true;
        }
        remaining = tail;
    }
    false
}

/// Whether every row's `tier` agrees with its `dotted` name: a `.Internals`
/// row must be a `PortLayer` naming a `Public` row at its own prefix
/// (`dotted == of ++ ".Internals"`, checked both ways), and no `Public` row
/// may be spelled `.Internals`. Consumers then render the tier field alone —
/// never the spelling.
const fn tiers_agree_with_names(rows: &[CompiledStdModule]) -> bool {
    let mut remaining = rows;
    while let Some((row, tail)) = remaining.split_first() {
        match row.tier {
            StdTier::Public => {
                if ends_with_dot_internals(row.dotted) {
                    return false;
                }
            }
            StdTier::PortLayer { of } => {
                if !names_internals_of(row.dotted, of) || !has_public_row_named(rows, of) {
                    return false;
                }
            }
        }
        remaining = tail;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a `.Internals` row is typed `Public`, or a `PortLayer`'s `of` names no `Public` row, or the `.Internals` suffix and `of` disagree [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    tiers_agree_with_names(COMPILED_STD_MODULES),
    "every `.Internals` row must be a StdTier::PortLayer naming a Public row at its own prefix, and no Public row may be spelled `.Internals`",
);

// ===========================================================================
// Documentation-only modules — reserved compiler-internal qualifiers.
// ===========================================================================
//
// These name reserved FFI qualifiers (`Ipe.Ffi.Kernel`, `Ipe.Ffi.Rust`) that
// the compiler recognises structurally, not as importable member-bearing
// modules: `Kernel.kernel "…"` is rewritten by `detect_kernel_alias` and
// `Rust.fn`/`Rust.const` by `canonicalise_asserted_call`, each only in a
// driver-vouched origin. They carry doc-comments + signatures purely so the
// surface is discoverable through `ipe doc` and the generated stdlib reference.
//
// They are DISJOINT from both `MODULES` and `COMPILED_STD_MODULES` on purpose:
// the doc-enumeration paths read this table, but the build-driver injection
// path (`is_compiled_source_segments`) does NOT, so a stdlib module that does
// `import Ipe.Ffi.Kernel as Kernel` never pulls a body-less veneer in as a
// compiled dependency.

/// One documentation-only stdlib module: its dotted name and its embedded Ipê
/// source.
///
/// Shares the shape of [`CompiledStdModule`] but is never compiled or injected
/// — it feeds `ipe doc` and the stdlib reference only.
pub struct DocOnlyModule {
    /// The dotted module name as written in an `import`, e.g. `Ipe.Ffi.Kernel`.
    pub dotted: &'static str,
    /// The module's Ipê source, embedded at compile time.
    pub source: &'static str,
}

/// The modules surfaced for documentation only: the [`STDLIB`] rows a
/// [`Role::DocOnly`] carries. Enumerated by the `ipe doc` module list and the
/// stdlib-reference generator; never compiled or injected.
pub const DOC_ONLY_MODULES: &[DocOnlyModule] = &DOC_ONLY_ROWS;

/// Prose for the members of one kernel registry qualifier.
///
/// The source is doc-only Ipê: `ipe doc` joins each exposed binding's comment
/// to the kernel member of the same name, and shows the module comment on the
/// pages of that qualifier. It never adds a member; which members a page lists
/// is the resolver's export table.
pub struct KernelDocSource {
    /// The kernel registry qualifier the prose annotates, e.g. `Cmd` or `TeaTuiSub`.
    pub qualifier: &'static str,
    /// The doc-only Ipê source, embedded at compile time.
    pub source: &'static str,
}

/// Prose for kernel members that no stdlib veneer documents.
///
/// `Cmd` and `Sub` annotate the member set every `Ipe.Tea.<Shape>.Cmd` and
/// `Ipe.Tea.<Shape>.Sub` module re-exports; `TeaTuiSub` and `TeaCliSub` annotate
/// the input subscriptions only one shape exposes.
pub const KERNEL_DOC_SOURCES: &[KernelDocSource] = &[
    KernelDocSource {
        qualifier: "Cmd",
        source: include_str!("../kernel-docs/Cmd.ipe"),
    },
    KernelDocSource {
        qualifier: "Sub",
        source: include_str!("../kernel-docs/Sub.ipe"),
    },
    KernelDocSource {
        qualifier: "TeaTuiSub",
        source: include_str!("../kernel-docs/TuiSub.ipe"),
    },
    KernelDocSource {
        qualifier: "TeaCliSub",
        source: include_str!("../kernel-docs/CliSub.ipe"),
    },
];

/// The embedded Ipê source for a compiled-source stdlib module named by its path
/// SEGMENTS (e.g. `["Std", "Palette"]`), or `None` when the segments name no
/// compiled-source module.
///
/// Segment-based (rather than `Symbol`-based) so it composes directly with the
/// build driver's `Vec<String>` module paths without an interner round-trip.
#[must_use]
pub fn compiled_std_source_segments(segments: &[String]) -> Option<&'static str> {
    let dotted = segments.join(".");
    COMPILED_STD_MODULES
        .iter()
        .find(|m| m.dotted == dotted)
        .map(|m| m.source)
}

/// Whether `segments` name a compiled-source stdlib module.
#[must_use]
pub fn is_compiled_source_segments(segments: &[String]) -> bool {
    compiled_std_source_segments(segments).is_some()
}

/// Transitively inject the embedded compiled-source stdlib modules the graph imports.
///
/// Every embedded module reachable from `sources` is injected into it, and the set
/// of module paths actually injected from the embed table is returned — the caller's
/// unforgeable record of which modules earn `EmbeddedStdlib` trust.
///
/// This is the single source of truth for the injection algorithm and its
/// **squat-guard**: a module path already present in `sources` (a user file
/// squatting on an `Ipe.*` name, or an already-injected node) is never
/// re-inserted and never tagged trusted, so a hostile `src/Ipe/Palette.ipe`
/// stays `ModuleOrigin::User` and remains IPE-N0025-rejected. Both frontends —
/// the native CLI driver and the WebAssembly injector — call this one closure so
/// the trust set can never drift between them.
///
/// `extract_imports` is supplied by the caller (the compiler's token-level
/// import scan) so this leaf crate stays dependency-free — it takes no compiler
/// crate in its runtime graph. `on_injected` is invoked once per newly-injected
/// module with its path and its synthetic on-disk-looking path, letting the
/// native caller record a `DiscoveredModule` while the wasm caller ignores it.
///
/// Efficiency: the worklist is seeded only from imports that match a
/// compiled-source module, so a build importing none does zero work.
/// The compiled-source stdlib modules a kernel-veneer module `import` induces —
/// compiled types named in the veneer's exposed surface that it cannot pull as
/// source itself (its own `import`s are inert because it is kernel-resolved).
///
/// `Ipe.Http` exposes `withTimeout : Ipe.Duration.Duration -> …`, so importing
/// `Ipe.Http` induces `Ipe.Duration`. Empty for every other veneer.
fn veneer_induced_compiled_deps(import_segments: &[String]) -> &'static [&'static [&'static str]] {
    // Normalise to the dotted form (segments may arrive split or joined),
    // mirroring `compiled_std_source_segments`.
    match import_segments.join(".").as_str() {
        "Ipe.Http" => &[&["Ipe", "Duration"]],
        _ => &[],
    }
}

pub fn inject_compiled_std_closure(
    sources: &mut std::collections::BTreeMap<Vec<String>, (std::path::PathBuf, String)>,
    extract_imports: impl Fn(&str) -> Vec<Vec<String>>,
    mut on_injected: impl FnMut(&[String], &std::path::Path),
) -> std::collections::BTreeSet<Vec<String>> {
    let mut injected: std::collections::BTreeSet<Vec<String>> = std::collections::BTreeSet::new();

    // Seed the worklist from every compiled-source import across current sources.
    // Short-circuit: an unused-stdlib build enqueues nothing and returns empty.
    // User sources are fresh every call, so they are lexed here — only the
    // compile-time-constant embedded sources are memoized (below).
    let mut work: std::collections::VecDeque<Vec<String>> = std::collections::VecDeque::new();
    for (_, src) in sources.values() {
        for imp in extract_imports(src) {
            if is_compiled_source_segments(&imp) {
                work.push_back(imp.clone());
            }
            // A kernel-veneer module can expose a member whose TYPE is a
            // compiled-source stdlib type it does not itself pull as source
            // (its own `import`s are inert — the veneer is kernel-resolved).
            // `Ipe.Http.withTimeout : Ipe.Duration.Duration -> …` is such a
            // member: a program that imports `Ipe.Http` and names `withTimeout`
            // must have `Ipe.Duration`'s compiled enum in scope for the type to
            // lower, even without an explicit `import Ipe.Duration`. Seed those
            // induced compiled deps here so the closure pulls them.
            for induced in veneer_induced_compiled_deps(&imp) {
                work.push_back(induced.iter().map(|s| (*s).to_owned()).collect());
            }
        }
    }

    while let Some(path) = work.pop_front() {
        // Already present — a user file OR an already-injected node. Skip; do NOT
        // tag trusted (BTreeMap key = free dedup; a user squat stays User origin).
        if sources.contains_key(&path) {
            continue;
        }
        let Some(embedded) = compiled_std_source_segments(&path) else {
            // Not a compiled-source module (e.g. a kernel import like `Ipe.String`
            // inside an embedded source): leave it kernel-resolved.
            continue;
        };

        // Synthetic on-disk-looking path, for diagnostics only — never read from
        // disk: `sources` already carries the embedded text.
        let synth_path = std::path::PathBuf::from("<embedded-stdlib>").join(path.join("."));
        sources.insert(path.clone(), (synth_path.clone(), embedded.to_owned()));
        on_injected(&path, &synth_path);
        injected.insert(path.clone());

        // Std -> Std closure: enqueue the embedded module's OWN compiled-source
        // imports. The embedded text is a compile-time constant, so its
        // compiled-source import edges are a pure function of it and are memoized
        // once per module — the fixpoint then walks precomputed edges instead of
        // re-lexing the same `&'static str` on every call. Fixpoint via the
        // `sources.contains_key` guard above.
        let edges = embedded_compiled_std_imports(embedded, &extract_imports);
        for imp in &*edges {
            if !sources.contains_key(imp) {
                work.push_back(imp.clone());
            }
        }
    }

    injected
}

/// A memoized, shareable list of one embedded module's compiled-source import
/// edges (path segments per edge).
type ImportEdges = std::sync::Arc<Vec<Vec<String>>>;

/// The compiled-source import edges of one embedded stdlib module, memoized by
/// the module's `&'static str` identity.
///
/// The embedded sources are compile-time constants, so their compiled-source
/// import lists never change; lexing each once and caching the result removes
/// the per-call re-lex of every embedded module the closure walks. The cache is
/// keyed by the source's pointer identity (unique per embedded `&'static str`),
/// and the stored list is already filtered to compiled-source modules so the
/// caller iterates it directly. Correctness is unaffected: the memoized value is
/// exactly what `extract_imports` would return for that constant text.
fn embedded_compiled_std_imports(
    embedded: &'static str,
    extract_imports: &impl Fn(&str) -> Vec<Vec<String>>,
) -> ImportEdges {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};

    static CACHE: OnceLock<Mutex<HashMap<usize, ImportEdges>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = embedded.as_ptr() as usize;

    if let Ok(guard) = cache.lock()
        && let Some(hit) = guard.get(&key)
    {
        return Arc::clone(hit);
    }

    let edges: Vec<Vec<String>> = extract_imports(embedded)
        .into_iter()
        .filter(|imp| is_compiled_source_segments(imp))
        .collect();
    let edges = Arc::new(edges);

    if let Ok(mut guard) = cache.lock() {
        return Arc::clone(guard.entry(key).or_insert(edges));
    }
    edges
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipe_intern::Interner;

    /// A minimal `import` extractor for the closure tests: one dotted module path
    /// per `import <Path>` line, split into segments. Sufficient for the fixed
    /// single-line fixtures here; the production closure uses
    /// `ipe_db::extract_imports_from_source`.
    fn extract_test_imports(src: &str) -> Vec<Vec<String>> {
        src.lines()
            .filter_map(|line| line.trim().strip_prefix("import "))
            .map(|rest| {
                let dotted = rest.split_whitespace().next().unwrap_or("");
                dotted.split('.').map(str::to_owned).collect()
            })
            .collect()
    }

    /// `COMPILED_STD_MODULES` groups into the `Public` rows and the
    /// `PortLayer` rows by `tier` alone, never by matching `.Internals`
    /// against the name — the typed field is what a renderer (`ipe doc`'s
    /// `--list`) must read to group its listing by tier.
    #[test]
    fn list_groups_port_layers_by_tier() {
        let (port_layers, public): (Vec<_>, Vec<_>) = COMPILED_STD_MODULES
            .iter()
            .partition(|m| matches!(m.tier, StdTier::PortLayer { .. }));

        assert!(!port_layers.is_empty(), "no PortLayer row found");
        assert!(!public.is_empty(), "no Public row found");
        for m in &port_layers {
            assert!(
                ends_with_dot_internals(m.dotted),
                "{} is tiered PortLayer but is not spelled `.Internals`",
                m.dotted
            );
        }
        for m in &public {
            assert!(
                !ends_with_dot_internals(m.dotted),
                "{} is tiered Public but is spelled `.Internals`",
                m.dotted
            );
        }
    }

    /// The build-time proof (`tiers_agree_with_names`, asserted over
    /// `COMPILED_STD_MODULES` below) refuses a `.Internals` row typed
    /// `Public` and a `PortLayer` whose `of` names no `Public` row —
    /// exercised here at runtime on fixture slices so the refusal is pinned
    /// without needing a build failure to observe it.
    #[test]
    fn a_public_row_named_internals_is_refused() {
        const BAD_PUBLIC_INTERNALS: &[CompiledStdModule] = &[CompiledStdModule {
            dotted: "Ipe.Example.Internals",
            source: "",
            tier: StdTier::Public,
        }];
        const BAD_ORPHAN_PORT_LAYER: &[CompiledStdModule] = &[CompiledStdModule {
            dotted: "Ipe.Example.Internals",
            source: "",
            tier: StdTier::PortLayer { of: "Ipe.Example" },
        }];
        const GOOD: &[CompiledStdModule] = &[
            CompiledStdModule {
                dotted: "Ipe.Example",
                source: "",
                tier: StdTier::Public,
            },
            CompiledStdModule {
                dotted: "Ipe.Example.Internals",
                source: "",
                tier: StdTier::PortLayer { of: "Ipe.Example" },
            },
        ];
        assert!(
            !tiers_agree_with_names(BAD_PUBLIC_INTERNALS),
            "a `.Internals` row typed `Public` must be refused"
        );

        assert!(
            !tiers_agree_with_names(BAD_ORPHAN_PORT_LAYER),
            "a `PortLayer` naming no `Public` row must be refused"
        );

        assert!(
            tiers_agree_with_names(GOOD),
            "a `PortLayer` naming its own `Public` row must be accepted"
        );
    }

    /// The module `|=` / `|.` desugar into is an embedded module under exactly
    /// the name the syntax crate declares.
    #[test]
    fn the_parser_operator_module_is_embedded_under_its_declared_name() {
        let declared = ipe_syntax::fixity::PARSER_OPERATOR_MODULE.dotted();
        assert!(
            COMPILED_STD_MODULES.iter().any(|m| m.dotted == declared),
            "no embedded module is named {declared}"
        );
    }

    /// Every embedded `Ipe` module must PARSE with the same front end that
    /// reads user code — the proof that the compiler can read its own embedded
    /// standard library (the foundation the import resolver builds on).
    #[test]
    fn every_embedded_module_parses() {
        for m in MODULES {
            let mut interner = Interner::new();
            let parsed = ipe_parse::parse_module(m.source, &mut interner);
            assert!(
                parsed.is_ok(),
                "embedded module {} must parse: {:?}",
                m.name,
                parsed.err()
            );
        }
    }

    /// `Ipe.Basics` resolves to its embedded source; the removed `Ipe.Prelude`
    /// alias does not resolve to anything (no backward-compatible mapping).
    #[test]
    fn basics_resolves_and_prelude_is_gone() {
        // `Ipe.Basics` migrated to compiled-source: no longer a `MODULES`
        // parse-fixture, so `source` returns `None`; its text is reached through
        // the compiled-source table.
        assert_eq!(source("Ipe.Basics"), None);
        assert!(is_compiled_source_segments(&[
            "Ipe".to_owned(),
            "Basics".to_owned()
        ]));
        assert_eq!(source("Ipe.Prelude"), None);
    }

    /// An unknown `Ipe` module is not embedded.
    #[test]
    fn unknown_module_is_absent() {
        assert_eq!(source("Ipe.Nope"), None);
    }

    /// Importing the `Ipe.Http` kernel veneer induces the compiled-source
    /// `Ipe.Duration` module: `Http.withTimeout : Duration -> …` names a
    /// compiled type the veneer cannot pull as source itself, so the closure
    /// must inject `Ipe.Duration` even without an explicit `import`. A program
    /// that never touches `Ipe.Http` induces nothing.
    #[test]
    fn http_veneer_induces_duration_dep() {
        let mut sources: std::collections::BTreeMap<Vec<String>, (std::path::PathBuf, String)> =
            std::collections::BTreeMap::new();
        sources.insert(
            vec!["Main".to_owned()],
            (
                std::path::PathBuf::from("Main.ipe"),
                "import Ipe.Http as M\n".to_owned(),
            ),
        );
        let injected = inject_compiled_std_closure(&mut sources, extract_test_imports, |_, _| {});
        assert!(
            injected.contains(&vec!["Ipe".to_owned(), "Duration".to_owned()]),
            "importing Ipe.Http must inject the compiled Ipe.Duration dep, got {injected:?}"
        );

        let mut no_http: std::collections::BTreeMap<Vec<String>, (std::path::PathBuf, String)> =
            std::collections::BTreeMap::new();
        no_http.insert(
            vec!["Main".to_owned()],
            (
                std::path::PathBuf::from("Main.ipe"),
                "import Ipe.Io as Io\n".to_owned(),
            ),
        );
        let none = inject_compiled_std_closure(&mut no_http, extract_test_imports, |_, _| {});
        assert!(
            !none.contains(&vec!["Ipe".to_owned(), "Duration".to_owned()]),
            "a program without Ipe.Http must not induce Ipe.Duration, got {none:?}"
        );
    }

    /// Every compiled-source module must PARSE with the real front end — the
    /// PARSE-DON'T-VALIDATE floor: a module cannot enter any build graph until it
    /// is proven to parse with the same parser that reads user code.
    #[test]
    fn every_compiled_source_module_parses() {
        for m in COMPILED_STD_MODULES {
            let mut interner = Interner::new();
            let parsed = ipe_parse::parse_module(m.source, &mut interner);
            assert!(
                parsed.is_ok(),
                "compiled-source module {} must parse: {:?}",
                m.dotted,
                parsed.err()
            );
        }
    }

    /// Anti-drift guard for the per-module availability prose above (issue
    /// #1975): the `KernelDef` registry is the single source of truth for which
    /// members are backed, and hand-written "KERNEL-BLOCKED" / "OMITTED pending a
    /// kernel" doc claims silently drifted from it in both directions. Every
    /// qualifier whose compiled-source module routes members through
    /// `Kernel.kernel "<Qualifier>_*"` MUST have at least one registered kernel;
    /// this asserts the ground truth those doc comments describe so a future edit
    /// that (a) deletes a kernel or (b) re-introduces a false "no kernel exists"
    /// claim is caught against the registry rather than trusted prose.
    #[test]
    fn kernel_backed_qualifiers_match_registry() {
        let registered: std::collections::BTreeSet<&'static str> = ipe_kernels::StdlibKernel::ALL
            .iter()
            .map(|k| k.def().qualifier)
            .collect();

        // The qualifiers whose module docs previously claimed no kernel existed;
        // the registry now backs each, so the claim was drift.
        for qualifier in ["Compression", "Csv", "Email", "Trace", "Time"] {
            assert!(
                registered.contains(qualifier),
                "module doc treats `{qualifier}` as kernel-backed, but the \
                 KernelDef registry has no `{qualifier}_*` kernel — the doc \
                 prose and the registry SSOT have drifted",
            );
        }
    }

    /// Every documentation-only veneer must PARSE with the real front end — it is
    /// relayed to `ipe doc` from raw source, so ill-formed source would surface a
    /// broken signature line rather than fail closed.
    #[test]
    fn every_doc_only_module_parses() {
        for m in DOC_ONLY_MODULES {
            let mut interner = Interner::new();
            let parsed = ipe_parse::parse_module(m.source, &mut interner);
            assert!(
                parsed.is_ok(),
                "doc-only module {} must parse: {:?}",
                m.dotted,
                parsed.err()
            );
        }
    }

    /// Every kernel prose source parses with the front end that reads user code.
    #[test]
    fn every_kernel_doc_source_parses() {
        for m in KERNEL_DOC_SOURCES {
            let mut interner = Interner::new();
            let parsed = ipe_parse::parse_module(m.source, &mut interner);
            assert!(
                parsed.is_ok(),
                "kernel doc source {} must parse: {:?}",
                m.qualifier,
                parsed.err()
            );
        }
    }

    /// Every `.ipe` file under `dir`, recursively, as `(path, source)`, sorted by path.
    fn ipe_files(dir: &std::path::Path) -> Vec<(String, String)> {
        let mut found = Vec::new();
        let mut pending = vec![dir.to_path_buf()];
        while let Some(at) = pending.pop() {
            for entry in std::fs::read_dir(&at).expect("the stdlib tree reads") {
                let path = entry.expect("a stdlib tree entry reads").path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|ext| ext == "ipe") {
                    let source = std::fs::read_to_string(&path).expect("a stdlib file reads");
                    found.push((path.display().to_string(), source));
                }
            }
        }
        found.sort();
        found
    }

    /// The files of `files` that are not the source of exactly one row of
    /// `rows`, each with how many rows carry it.
    fn misregistered<'a>(
        files: &'a [(String, String)],
        rows: &[StdlibModule],
    ) -> Vec<(&'a str, usize)> {
        files
            .iter()
            .filter_map(|(path, source)| {
                let carriers = rows
                    .iter()
                    .filter(|row| row.source() == Some(source.as_str()))
                    .count();
                (carriers != 1).then_some((path.as_str(), carriers))
            })
            .collect()
    }

    /// Every `Ipe/**/*.ipe` file is the source of exactly one [`STDLIB`] row: a
    /// file no row registers is a module `ipe doc` and the compiler never see.
    #[test]
    fn every_stdlib_file_registered_once() {
        let files = ipe_files(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Ipe"));
        assert!(!files.is_empty(), "the stdlib tree holds no `.ipe` file");
        assert_eq!(misregistered(&files, STDLIB), Vec::<(&str, usize)>::new());
    }

    /// A planted file no row registers, and a file two rows register, are both
    /// reported: the registration check is not vacuous.
    #[test]
    fn a_planted_unregistered_file_is_reported() {
        let files = vec![
            (
                "Ipe/Planted.ipe".to_owned(),
                "module Ipe.Planted exposing (x)".to_owned(),
            ),
            (
                "Ipe/Twice.ipe".to_owned(),
                "module Ipe.Twice exposing (y)".to_owned(),
            ),
        ];
        let rows = [
            StdlibModule {
                dotted: "Ipe.Twice",
                role: Role::DocOnly {
                    source: "module Ipe.Twice exposing (y)",
                },
            },
            StdlibModule {
                dotted: "Ipe.TwiceAgain",
                role: Role::Compiled {
                    source: "module Ipe.Twice exposing (y)",
                    tier: StdTier::Public,
                },
            },
        ];
        assert_eq!(
            misregistered(&files, &rows),
            vec![("Ipe/Planted.ipe", 0), ("Ipe/Twice.ipe", 2)]
        );
    }

    /// The kernel and retired rows of [`STDLIB`] are exactly the resolver's
    /// `STDLIB_MODULE_QUALIFIERS`, so the two registries cannot drift across the
    /// crate boundary (the compiled rows are disjoint from it:
    /// `compiled_vs_kernel_qualifier_disjoint`).
    #[test]
    fn canon_qualifiers_equal_stdlib_projection() {
        let canon: std::collections::BTreeSet<String> = ipe_canon::STDLIB_MODULE_QUALIFIERS
            .iter()
            .map(|(segments, _)| segments.join("."))
            .collect();
        let kernel: std::collections::BTreeSet<String> = STDLIB
            .iter()
            .filter(|row| matches!(row.role, Role::Kernel { .. } | Role::Retired))
            .map(|row| row.dotted.to_owned())
            .collect();
        assert_eq!(kernel, canon);
    }

    /// Each dotted name is registered once.
    #[test]
    fn stdlib_rows_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for row in STDLIB {
            assert!(
                seen.insert(row.dotted),
                "{} is registered twice",
                row.dotted
            );
        }
    }

    /// Each kernel registry qualifier has at most one prose source.
    #[test]
    fn kernel_doc_source_qualifiers_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for m in KERNEL_DOC_SOURCES {
            assert!(
                seen.insert(m.qualifier),
                "kernel doc qualifier {} has two sources",
                m.qualifier
            );
        }
    }

    /// Load-bearing invariant: a documentation-only veneer is NEVER a compiled or
    /// injectable module. Were a `DOC_ONLY_MODULES` name also in
    /// `COMPILED_STD_MODULES` (or the `MODULES` parse fixtures), the many stdlib
    /// modules that `import Ipe.Ffi.Kernel as Kernel` would pull the body-less
    /// veneer in as a compiled dependency — the exact breakage this table avoids.
    #[test]
    fn doc_only_disjoint_from_compiled_and_parse_fixtures() {
        for d in DOC_ONLY_MODULES {
            assert!(
                !COMPILED_STD_MODULES.iter().any(|m| m.dotted == d.dotted),
                "{} is BOTH doc-only and compiled-source — it must never be injectable",
                d.dotted
            );
            assert!(
                !MODULES.iter().any(|m| m.name == d.dotted),
                "{} is BOTH doc-only and a `MODULES` parse fixture",
                d.dotted
            );
            let segments: Vec<String> = d.dotted.split('.').map(str::to_owned).collect();
            assert!(
                !is_compiled_source_segments(&segments),
                "{} must not be seen as a compiled-source module by the injector",
                d.dotted
            );
        }
    }

    /// Load-bearing invariant (design §2.1): a module is EITHER a kernel
    /// qualifier OR a compiled-source module, never both. A name in both would be
    /// pre-installed as a kernel qualifier AND injected as a source dep — an
    /// ambiguous resolution / silent miscompile.
    #[test]
    fn compiled_vs_kernel_qualifier_disjoint() {
        for m in COMPILED_STD_MODULES {
            let segments: Vec<&str> = m.dotted.split('.').collect();
            let clash = ipe_canon::STDLIB_MODULE_QUALIFIERS
                .iter()
                .any(|(path, _)| *path == segments.as_slice());
            assert!(
                !clash,
                "{} is BOTH a compiled-source module and a kernel qualifier — \
                 the two tables must be disjoint",
                m.dotted
            );
        }
    }

    /// Anti-drift (parse-level floor): every EXPORTED VALUE of a compiled-source
    /// stdlib module has a source home — either a local top-level binding (a pure
    /// body OR an `Kernel.kernel "…"` alias) OR a name pulled in by an `import …
    /// exposing (name)` re-export. An exported value that is neither is the
    /// source-vs-kernel drift class: a member declared in `exposing (...)` with no
    /// body, which fails name-resolution at every call site. Catching it here makes
    /// a declared-but-homeless export a build-time (CI) failure, pre-cargo.
    ///
    /// An uppercase item names a type: a local union or alias, an import's
    /// re-export, or a reserved builtin (e.g. `Ipe.Path`'s `Path`, a
    /// kernel-provided opaque with no source declaration). An uppercase item that
    /// is none of these — a constructor or an uppercase value spelled bare —
    /// exports nothing, so it is refused here. The deeper
    /// "every export — types included — resolves through the real pipeline" guard
    /// is `compiled_source_modules_resolve_all_exports` in the `ipe` crate, which
    /// canonicalises each module against the kernel env. `exposing (..)` (export
    /// all) has nothing to cross-check and is skipped.
    #[test]
    fn every_exported_value_has_a_home() {
        use ipe_syntax::{Exposed, Exposing};

        for m in COMPILED_STD_MODULES {
            let mut interner = Interner::new();
            let parsed = ipe_parse::parse_module(m.source, &mut interner);
            assert!(
                parsed.is_ok(),
                "compiled-source module {} must parse before its exports \
                 can be checked: {:?}",
                m.dotted,
                parsed.err(),
            );
            let Ok(parsed) = parsed else { continue };

            let exposed = match &parsed.exposing.value {
                Exposing::All => continue,
                Exposing::List(items) => items,
            };

            // A name re-exported from an `import … exposing (name)` (or from an
            // export-all import, which surfaces every name of the imported module)
            // is a resolvable home even without a local declaration.
            let imported = |name| {
                parsed.imports.iter().any(|imp| match &imp.exposing.value {
                    Exposing::All => true,
                    Exposing::List(items) => items.iter().any(|e| match &e.value {
                        Exposed::Value(n) | Exposed::Type(n, _) => *n == name,
                    }),
                })
            };

            for item in exposed {
                match &item.value {
                    Exposed::Value(name) => {
                        let local = parsed.values.iter().any(|v| v.value.name.value == *name);
                        let rendered = interner.resolve(*name).unwrap_or("<?>");
                        assert!(
                            local || imported(*name),
                            "{}: exports value `{rendered}` but the module neither \
                             defines a top-level binding for it nor re-exports it \
                             from an import — a declared-but-homeless export \
                             (source-vs-kernel drift)",
                            m.dotted,
                        );
                    }
                    Exposed::Type(name, _) => {
                        let rendered = interner.resolve(*name).unwrap_or("<?>");
                        let local = parsed.unions.iter().any(|u| u.value.name.value == *name)
                            || parsed.aliases.iter().any(|a| a.value.name.value == *name);
                        assert!(
                            local
                                || imported(*name)
                                || ipe_canon::is_reserved_builtin_type_name(rendered),
                            "{}: exposes `{rendered}` but declares no type or alias \
                             of that name, re-exports none, and it is no reserved \
                             builtin — the item exports nothing",
                            m.dotted,
                        );
                    }
                }
            }
        }
    }

    /// Segment lookup resolves a compiled-source module and rejects a non-member.
    #[test]
    fn compiled_source_segment_lookup() {
        let palette = vec!["Ipe".to_owned(), "Palette".to_owned()];
        assert!(is_compiled_source_segments(&palette));
        assert!(compiled_std_source_segments(&palette).is_some());

        let log = vec!["Ipe".to_owned(), "Log".to_owned()];
        assert!(
            is_compiled_source_segments(&log),
            "Ipe.Log is compiled-source"
        );

        let nope = vec!["Ipe".to_owned(), "Nope".to_owned()];
        assert!(!is_compiled_source_segments(&nope));
    }

    /// The forbidden-term list is read from the same shared file the shell gate
    /// uses (`tools/scripts/reference-impl-forbidden-terms.txt`). The test asserts
    /// that none of the embedded `.ipe` sources match any forbidden term, covering both
    /// `MODULES` (parse-fixture modules) and `COMPILED_STD_MODULES`.
    #[test]
    fn no_reference_impl_leak_in_embedded_stdlib() {
        // Embedded at compile time from the shared SSOT term file.
        const TERMS_RAW: &str =
            include_str!("../../../tools/scripts/reference-impl-forbidden-terms.txt");

        // Parse terms: skip blank lines, comment lines, and lines starting with
        // `\b` (word-bounded src-only terms — the shell gate handles those via a
        // separate rg invocation; for the Rust test we include them as plain
        // substrings, which is conservative and sufficient for the .ipe sources).
        let terms: Vec<&str> = TERMS_RAW
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.trim_start_matches("\\b").trim_end_matches("\\b"))
            .collect();

        assert!(!terms.is_empty(), "term list must not be empty");

        // Collect all embedded .ipe sources from both tables.
        let all_sources: Vec<(&str, &str)> = MODULES
            .iter()
            .map(|m| (m.name, m.source))
            .chain(COMPILED_STD_MODULES.iter().map(|m| (m.dotted, m.source)))
            .collect();

        let mut violations: Vec<String> = Vec::new();
        for (name, source) in &all_sources {
            for term in &terms {
                let term_lower = term.to_lowercase();
                // Find every offending line (case-insensitive substring search).
                for (lineno, line) in source.lines().enumerate() {
                    if !line.to_lowercase().contains(&term_lower) {
                        continue;
                    }
                    // Mirror the shell gate's allowance: a line whose match
                    // is only inside a doc-link path to our own divergence
                    // ledger is not a private-impl citation.
                    if line.to_lowercase().contains("divergences-from-") {
                        continue;
                    }
                    violations.push(format!(
                        "{} line {}: {:?} matches forbidden term {:?}",
                        name,
                        lineno + 1,
                        line.trim(),
                        term
                    ));
                }
            }
        }

        assert!(
            violations.is_empty(),
            "reference-implementation leak(s) found in embedded stdlib sources:\n{}",
            violations.join("\n")
        );
    }

    /// Anti-drift tripwire: every registered `StdlibKernel` whose qualifier is
    /// user-visible must be reachable through at least one of two paths —
    ///
    /// 1. **Catalog reachability**: its `(qualifier, name)` appears as a
    ///    `VarHome::Kernel` in a freshly-built `Env`'s `qual_vars`.
    /// 2. **Compiled-source reachability**: a compiled-source `.ipe` module
    ///    contains a point-free `Kernel.kernel "Qualifier_name"` alias whose raw
    ///    string, split at the first `_`, matches `(qualifier, name)`.
    ///
    /// A kernel reachable through neither resolves to IPE-N0005 (`X doesn't have
    /// anything called Y`) — a silently dead feature.  This test closes that class
    /// for every future kernel without a hand-maintained allow-list.
    ///
    /// The inverse direction (catalog entry → registry) is guarded by the
    /// `stdlib_catalog_matches_kernel_registry` tripwire in `ipe_canon`.
    #[test]
    fn every_kernel_is_reachable() {
        use ipe_canon::Env;
        use ipe_intern::Interner;
        use ipe_kernels::StdlibKernel;
        use ipe_syntax::Expr_;

        // ── Step 1: catalog-reachable set ────────────────────────────────────
        // Collect every StdlibKernel carried by a VarHome::Kernel entry across
        // all qualifier maps.  Aliases and shape-scoped copies may yield the
        // same kernel more than once; Vec + contains() is sufficient.
        let mut interner = Interner::new();
        let env = Env::initial(vec![], &mut interner).expect("Env::initial must not fail");
        let catalog_reachable: Vec<StdlibKernel> = env.kernel_homes().collect();

        // ── Step 2: compiled-source-reachable set ────────────────────────────
        // Scan every compiled-source module for the exact `Kernel.kernel "<raw>"`
        // call shape (point-free binding whose body is a qualified call
        // `Kernel.kernel` applied to a single string literal).  Split the raw
        // string at the first `_` to recover `(qualifier, name)`.
        //
        // The parsed AST walk mirrors `detect_kernel_alias` in `ipe_canon` and
        // is immune to false positives from comments or string content: only
        // value bodies that parse as `VarQual("Kernel", "kernel")` applied to one
        // string literal are counted.
        let mut compiled_reachable: Vec<(String, String)> = Vec::new();

        // Reachability evidence comes ONLY from sources that actually compile
        // into a user program. The `MODULES` veneers are never injected
        // (`inject_compiled_std_closure` consults `COMPILED_STD_MODULES` alone),
        // so a `Kernel.kernel` alias in a veneer is no proof a kernel is reachable
        // — crediting one masks a dead feature (a member `ipe doc` advertises but
        // a real call resolves to IPE-N0005).
        let all_sources = COMPILED_STD_MODULES.iter().map(|m| m.source);

        for source in all_sources {
            let mut local_interner = Interner::new();
            let Ok(parsed) = ipe_parse::parse_module(source, &mut local_interner) else {
                continue; // parse failures are caught by other tests
            };
            // Re-intern the reserved `Kernel` / `kernel` tokens in this module's
            // interner so symbol comparisons are valid within the same interner.
            let Ok(local_kernel_qualifier) = local_interner.intern("Kernel") else {
                continue;
            };
            let Ok(local_kernel) = local_interner.intern("kernel") else {
                continue;
            };
            for value in &parsed.values {
                // Only bare (point-free) bindings are Kernel.kernel aliases.
                if !value.value.patterns.is_empty() {
                    continue;
                }
                let Expr_::Call(callee, args) = &value.value.body.value else {
                    continue;
                };
                let Expr_::VarQual(q_sym, m_sym) = &callee.value else {
                    continue;
                };
                if *q_sym != local_kernel_qualifier || *m_sym != local_kernel {
                    continue;
                }
                let [arg] = args.as_slice() else {
                    continue;
                };
                let Expr_::Str(raw) = &arg.value else {
                    continue;
                };
                // Split at the first `_`: `"File_walk"` → `("File", "walk")`.
                if let Some((q, n)) = raw.split_once('_')
                    && !q.is_empty()
                    && !n.is_empty()
                {
                    compiled_reachable.push((q.to_owned(), n.to_owned()));
                }
            }
        }

        // ── Step 3: cross-check every registered kernel ───────────────────────
        let mut failures: Vec<String> = Vec::new();
        for sk in StdlibKernel::ALL {
            let d = sk.decl();
            // Internal kernels (qualifier starts with `_`) are not user-visible.
            if d.qualifier.starts_with('_') {
                continue;
            }
            let catalog_ok = catalog_reachable.contains(sk);
            let compiled_ok = compiled_reachable
                .iter()
                .any(|(q, n)| q == d.qualifier && n == d.name);
            if !catalog_ok && !compiled_ok {
                failures.push(format!(
                    "StdlibKernel::{sk:?} — `{q}.{n}` is registered but UNREACHABLE: \
                     not in the env.rs QUALIFIERS member catalog and not via a \
                     `Kernel.kernel \"{q}_{n}\"` alias in any compiled-source module. \
                     It resolves to IPE-N0005 (dead feature). Add its catalog line \
                     to `install_prelude_qualifiers` OR its `Kernel.kernel` alias to \
                     the owning `.ipe` module.",
                    sk = sk,
                    q = d.qualifier,
                    n = d.name,
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "kernel reachability tripwire: {} dead feature(s) found:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// The Browser-capability family maps an inbound permission `Denied` to the
    /// distinct `Error.permissionDenied` kind, never to the generic
    /// `Error.unavailable`. `Fullscreen` folds a `Denied` reply in both
    /// `foldOutcome` (a `Task Error ()`) and `toResult` (a `Result Error Bool`);
    /// a caller matching on the error kind must be able to tell a permission
    /// refusal from a genuinely-absent API, so both arms carry
    /// `Error.permissionDenied`, matching every sibling module in the cluster
    /// (`Camera`, `FilePicker`, `Geolocation`, `Microphone`).
    #[test]
    fn fullscreen_denial_is_permission_denied_not_unavailable() {
        let src = IPE_BROWSER_FULLSCREEN;
        // Both folds must route `Denied` to the distinct permission kind: one
        // occurrence in `foldOutcome`, one in `toResult`.
        let denied_arms = src.match_indices("Denied ->").count();
        assert_eq!(
            denied_arms, 2,
            "Fullscreen should fold `Denied` in exactly two places (foldOutcome + toResult), \
             found {denied_arms}"
        );
        assert_eq!(
            src.match_indices("Task.fail Error.permissionDenied")
                .count(),
            1,
            "foldOutcome's `Denied` arm must fail with the distinct `Error.permissionDenied` kind"
        );
        assert_eq!(
            src.match_indices("Err Error.permissionDenied").count(),
            1,
            "toResult's `Denied` arm must yield the distinct `Error.permissionDenied` kind"
        );
        // A denial must NOT be downgraded to the generic `unavailable` kind, the
        // regression this pins: `unavailable` may only describe an absent API.
        assert!(
            !src.contains("Error.unavailable \"fullscreen request denied\""),
            "a fullscreen permission denial must not fold to `Error.unavailable` \
             (it is indistinguishable from an absent API)"
        );
    }

    /// Fail-closed second boundary (issue #2651): `ScreenOrientation.foldOutcome`
    /// folds the correlated reply to `lock`/`unlock`. The shared inbound `JsMsg`
    /// spans all three commands' replies, so a `Query`'s `Orientation` frame can
    /// arrive on a lock/unlock correlation id. Only the genuine `Ok_` (a lock or
    /// unlock completed) may fold to success; an `Orientation` reply — a query
    /// answer — must fold to a typed failure, mirroring `foldOrientation`, which
    /// rejects `Ok_` as "query returned no type". A regression that maps
    /// `Orientation _` back to `Task.succeed ()` fails open: a query answer would
    /// be reported as a lock success though no lock was ever confirmed.
    #[test]
    fn screen_orientation_lock_fold_rejects_query_reply() {
        use ipe_syntax::{Expr_, Pattern_};

        let mut interner = Interner::new();
        let parsed = ipe_parse::parse_module(IPE_BROWSER_SCREEN_ORIENTATION, &mut interner)
            .expect("ScreenOrientation must parse");

        let orientation_ctor = interner
            .intern("Orientation")
            .expect("intern `Orientation`");
        let ok_ctor = interner.intern("Ok_").expect("intern `Ok_`");
        let task_qual = interner.intern("Task").expect("intern `Task`");
        let fail_name = interner.intern("fail").expect("intern `fail`");
        let succeed_name = interner.intern("succeed").expect("intern `succeed`");

        // The RHS of a `case` arm is a `Task.fail (...)` call.
        let calls_task = |body: &ipe_syntax::Expr, member| -> bool {
            let Expr_::Call(callee, _) = &body.value else {
                return false;
            };
            matches!(
                &callee.value,
                Expr_::VarQual(q, m) if *q == task_qual && *m == member
            )
        };

        // Find the single arm of `fold`'s `case` whose head constructor is `ctor`.
        // Returns `None` if the binding, its `case` shape, or the arm is absent;
        // the call sites `expect` it so a missing arm fails the test loudly
        // without the `panic!` macro (banned repo-wide, tests included).
        let mut arm_rhs = |fold_name: &str, ctor| -> Option<ipe_syntax::Expr> {
            let sym = interner.intern(fold_name).ok()?;
            let value = parsed.values.iter().find(|v| v.value.name.value == sym)?;
            let Expr_::Case(_, arms) = &value.value.body.value else {
                return None;
            };
            arms.iter().find_map(|(pat, rhs)| match &pat.value {
                Pattern_::PCtor(name, _, _) if *name == ctor => Some(rhs.clone()),
                _ => None,
            })
        };

        // The lock/unlock fold rejects a query (`Orientation`) reply: fail, not succeed.
        let lock_orientation = arm_rhs("foldOutcome", orientation_ctor)
            .expect("foldOutcome must have an `Orientation` case arm");
        assert!(
            calls_task(&lock_orientation, fail_name),
            "foldOutcome's `Orientation _` arm must fold to `Task.fail` — a query \
             reply is not a lock/unlock success (fail-closed second boundary)",
        );
        assert!(
            !calls_task(&lock_orientation, succeed_name),
            "foldOutcome's `Orientation _` arm must NOT fold to `Task.succeed` — \
             that is the fail-open boundary of issue #2651",
        );

        // Defend-in-depth mirror: the query fold rejects a lock/unlock (`Ok_`) reply.
        let query_ok = arm_rhs("foldOrientation", ok_ctor)
            .expect("foldOrientation must have an `Ok_` case arm");
        assert!(
            calls_task(&query_ok, fail_name),
            "foldOrientation's `Ok_` arm must fold to `Task.fail` — a lock/unlock \
             completion is not a query answer",
        );
    }

    /// Fail-closed axis decode (issue #2692, sibling of #2650): the
    /// `DeviceOrientation` reading decoder must read each axis with
    /// `Decode.nullable`, which distinguishes JSON null (→ `Nothing`) from a
    /// wrong-type value (→ decode error, whole frame dropped). The regression
    /// this pins is `Decode.oneOf [ Decode.map Just Decode.float, Decode.succeed
    /// Nothing ]`: its `succeed Nothing` fallback swallows a present-but-wrong-type
    /// axis into `Nothing`, fabricating a plausible reading (fail-open).
    #[test]
    fn device_orientation_axes_decode_fail_closed_on_wrong_type() {
        let src = IPE_BROWSER_ORIENTATION_INTERNALS;
        assert_eq!(
            src.matches("Decode.nullable Decode.float").count(),
            3,
            "each of the three axes (alpha/beta/gamma) must decode with `Decode.nullable`",
        );
        assert!(
            !src.contains("Decode.succeed Nothing"),
            "no axis may fall back to `Decode.succeed Nothing` — it swallows a \
             wrong-type value into `Nothing`, the fail-open boundary of #2692",
        );
    }

    /// Canonicalise `src` as the project module `Main` over `catalog`.
    fn canon_main(
        src: &str,
        catalog: &ipe_canon::ModuleCatalog,
    ) -> Result<(), ipe_diagnostics::Diagnostic> {
        let mut interner = Interner::new();
        let parsed = ipe_parse::parse_module(src, &mut interner)?;
        let expected = parsed.name.value.clone();
        ipe_canon::canonicalise_module_in_project(
            &parsed,
            &expected,
            &std::collections::BTreeMap::new(),
            catalog,
            ipe_canon::ModuleOrigin::User,
            &mut interner,
        )
        .map(drop)
    }

    /// The candidate modules of an IPE-N0034, or `None` for any other outcome.
    fn import_candidates(result: &Result<(), ipe_diagnostics::Diagnostic>) -> Option<Vec<&str>> {
        match result {
            Err(ipe_diagnostics::Diagnostic::Name {
                msg: ipe_diagnostics::NameError::ImportRequired { candidates, .. },
                ..
            }) => Some(candidates.iter().map(|m| &**m).collect()),
            _ => None,
        }
    }

    /// Every qualifier a catalog module's bare import binds, used unimported,
    /// is the must-import diagnostic listing EXACTLY the catalog modules whose
    /// bare import binds it — over a catalog built the way the build driver
    /// builds it (kernel paths + compiled-source modules + the project).
    ///
    /// Iterates the whole catalog, so a module added later that shares a
    /// qualifier with another (the kernel `Ipe.Tea.Tui` and the compiled
    /// `Ipe.Ui.Tui` both bind `Tui`) is checked by construction: a candidate
    /// set built from one table, a first match, or a last-segment-keyed map
    /// drops one and goes red here.
    #[test]
    fn compiled_std_modules_are_in_the_catalog() {
        let catalog = ipe_canon::ModuleCatalog::new(
            std::iter::once(Box::<str>::from("Main")).chain(
                COMPILED_STD_MODULES
                    .iter()
                    .map(|module| Box::<str>::from(module.dotted)),
            ),
        );
        let qualifiers: std::collections::BTreeSet<&str> = catalog
            .paths()
            .flat_map(|module| {
                let segments: Vec<&str> = module.split('.').collect();
                let canonical = ipe_canon::stdlib_canonical_qualifier(&segments);
                module.rsplit('.').next().into_iter().chain(canonical)
            })
            .filter(|qualifier| *qualifier != "Main")
            .collect();
        let mut shared = 0usize;
        for qualifier in qualifiers {
            // `Cmd` / `Sub` belong to the shape modules: an unimported use names
            // the four shapes to import, not every module whose bare import
            // happens to end in `Cmd` / `Sub`.
            let expected: Vec<&str> = if matches!(qualifier, "Cmd" | "Sub") {
                vec![
                    "Ipe.Tea.Cli",
                    "Ipe.Tea.Tui",
                    "Ipe.Tea.Web",
                    "Ipe.Tea.Worker",
                ]
            } else {
                catalog
                    .paths()
                    .filter(|module| *module != "Main")
                    .filter(|module| ipe_canon::bare_import_binds(module, qualifier))
                    .collect()
            };
            if expected.is_empty() {
                continue;
            }
            let src = format!("module Main exposing (main)\n\nmain =\n    {qualifier}.x\n");
            let result = canon_main(&src, &catalog);
            // An ambient qualifier resolves with no import, so it never raises
            // IPE-N0034 and builds no candidate list.
            if matches!(
                &result,
                Ok(())
                    | Err(ipe_diagnostics::Diagnostic::Name {
                        msg: ipe_diagnostics::NameError::NoSuchMember { .. },
                        ..
                    })
            ) {
                continue;
            }
            if expected.len() > 1 {
                shared += 1;
            }
            assert_eq!(
                import_candidates(&result).as_deref(),
                Some(&expected[..]),
                "{qualifier}.x unimported must be IPE-N0034 naming every binding \
                 module, sorted: {result:?}"
            );
        }
        assert!(
            shared > 0,
            "the catalog has a qualifier two modules bind (`Tui`); the check above \
             must exercise it"
        );
        let tui = canon_main(
            "module Main exposing (main)\n\nmain =\n    Tui.x\n",
            &catalog,
        );
        assert_eq!(
            import_candidates(&tui).as_deref(),
            Some(&["Ipe.Tea.Tui", "Ipe.Ui.Tui"][..]),
            "{tui:?}"
        );
        for module in COMPILED_STD_MODULES {
            let qualifier = module.dotted.rsplit('.').next().unwrap_or(module.dotted);
            assert!(
                ipe_canon::bare_import_binds(module.dotted, qualifier),
                "a compiled-source module binds its last segment: {}",
                module.dotted
            );
        }
    }
}
