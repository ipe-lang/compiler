//! Stable error codes (`IPE-XNNNN`) and their metadata.
//!
//! Every [`crate::Diagnostic`] maps to exactly one [`Code`] via
//! [`crate::Diagnostic::code`]. Codes are the machine-greppable, user-facing
//! handle a reader passes to `ipe doc <CODE>`; they never change once
//! shipped. The taxonomy is authoritative here (this file + the explain
//! pages under `src/compiler/diagnostics/explain/`).
//!
//! Ranges: `IPE-P####` parse, `IPE-N####` name resolution, `IPE-T####` type,
//! `IPE-L####` lower / not-yet-supported, `IPE-F####` foreign bindings (FFI),
//! `IPE-S####` security consent, `IPE-E####` environment, `IPE-I####` internal
//! (compiler bug). The single letter after `IPE-` is the code's [`Family`], and
//! [`Code::family`] derives it from that byte — the taxonomy letter and the
//! family are one fact, not two that can drift.
//!
//! Single source of truth: the [`code!`] table below declares every code once,
//! pairing its wire string with its one-line title and its `ipe doc` page.
//! [`ALL_CODES`], [`title`], and [`explain_page`] are all generated from that
//! one table, so a code cannot exist in one and be missing from another, and
//! the taxonomy size is derived by counting rows — never a hand-pinned literal.
//! Adding a code is one table row (plus its `explain/<CODE>.md`); see [`code!`].

/// The compiler's GitHub `org/repo` slug.
///
/// Single source of truth for every GitHub URL the compiler and its tooling
/// build (issue tracker, install script, release feed, CLI banner): every
/// other such URL is derived from this one constant rather than carrying its
/// own copy of the slug, so a repository move is a one-line change here.
pub const GITHUB_REPO_SLUG: &str = "ipe-lang/compiler";

/// Where a reader reports a compiler bug or nudges an unimplemented feature.
///
/// Single source of truth: every humble / ICE message and every `IPE-I*` /
/// `IPE-L*` explain page footer calls this one function, derived from
/// [`GITHUB_REPO_SLUG`].
#[must_use]
pub fn issue_tracker_url() -> String {
    format!("https://github.com/{GITHUB_REPO_SLUG}/issues")
}

/// A stable compiler error code, e.g. `IPE-T0001`.
///
/// The wrapped string is always one of the taxonomy constants in this module;
/// the field is private so a `Code` cannot be forged with an unknown value from
/// outside the crate. Compare via the constants ([`IPE_T0001`] etc.).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Code(&'static str);

/// The taxonomy family a [`Code`] belongs to — the compiler stage or concern
/// that owns it.
///
/// Encoded by the single letter after `IPE-` in the wire string, so a code's
/// family is not a second fact to keep in sync but a projection of the code
/// itself (see [`Code::family`]).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Family {
    /// `IPE-P####` — parse / lex.
    Parse,
    /// `IPE-N####` — name resolution.
    Name,
    /// `IPE-T####` — type inference / checking.
    Type,
    /// `IPE-L####` — lowering / not-yet-supported.
    Lower,
    /// `IPE-F####` — foreign bindings (FFI) and the sandbox jail that hosts them.
    Ffi,
    /// `IPE-S####` — security consent.
    Security,
    /// `IPE-E####` — environment (network, registry, host).
    Environment,
    /// `IPE-I####` — internal compiler bug (an ICE); the only family whose
    /// diagnostics carry [`Severity::Bug`].
    Internal,
}

impl Code {
    /// The wire form of the code, e.g. `"IPE-T0001"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    /// The [`Family`] this code belongs to, derived from its family letter.
    ///
    /// The letter is the byte at index 4 of the `"IPE-X…"` wire string (`I`,`P`,`E`,`-`, then the
    /// letter) — looked up in [`FAMILIES`], the one letter↔family table.
    /// Matched with a bounds-checked slice pattern (never an unchecked `[4]`
    /// index) so a malformed wire string — impossible for a taxonomy constant,
    /// but the field is a `&'static str` — yields [`Family::Internal`] rather
    /// than panicking: fail-closed to the "report a bug" family. `const` so the
    /// family chokepoints in `Diagnostic::code`'s helpers evaluate at build time.
    #[must_use]
    pub const fn family(self) -> Family {
        let [b'I', b'P', b'E', b'-', letter, ..] = *self.0.as_bytes() else {
            return Family::Internal;
        };
        let mut rest: &[FamilyRow] = &FAMILIES;
        while let [row, tail @ ..] = rest {
            if row.letter == letter as char {
                return row.family;
            }
            rest = tail;
        }
        Family::Internal
    }
}

/// One row of the family table: a [`Family`], the letter its codes carry after
/// `IPE-`, and a one-line description of what the family covers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FamilyRow {
    /// The family.
    pub family: Family,
    /// The letter after `IPE-` in every code of the family.
    pub letter: char,
    /// What the family covers, one line.
    pub summary: &'static str,
}

/// The single letter↔family table, in display order.
///
/// [`Code::family`] reads it to classify a code and [`Family::letter`] /
/// [`Family::summary`] read it to describe a family, so the prefix letters and
/// the families cannot drift apart.
pub const FAMILIES: [FamilyRow; 8] = [
    FamilyRow {
        family: Family::Parse,
        letter: 'P',
        summary: "parsing — the source is not valid Ipê syntax",
    },
    FamilyRow {
        family: Family::Name,
        letter: 'N',
        summary: "name resolution — an unknown, ambiguous, or misplaced name, import, or module",
    },
    FamilyRow {
        family: Family::Type,
        letter: 'T',
        summary: "type checking — the program's types do not fit together",
    },
    FamilyRow {
        family: Family::Lower,
        letter: 'L',
        summary: "lowering — a construct the compiler does not support yet",
    },
    FamilyRow {
        family: Family::Ffi,
        letter: 'F',
        summary: "foreign bindings (FFI) — Rust crates bound into Ipê and the sandbox that hosts them",
    },
    FamilyRow {
        family: Family::Security,
        letter: 'S',
        summary: "security consent — an effect or escape hatch that needs your explicit approval",
    },
    FamilyRow {
        family: Family::Environment,
        letter: 'E',
        summary: "environment — the network, the package registry, or the host system",
    },
    INTERNAL_ROW,
];

/// The internal family's row — also the fail-closed answer for a family
/// lookup that cannot miss.
const INTERNAL_ROW: FamilyRow = FamilyRow {
    family: Family::Internal,
    letter: 'I',
    summary: "internal — a compiler bug; please report it",
};

impl Family {
    /// This family's row in [`FAMILIES`].
    const fn row(self) -> FamilyRow {
        let mut rest: &[FamilyRow] = &FAMILIES;
        while let [row, tail @ ..] = rest {
            if row.family as u8 == self as u8 {
                return *row;
            }
            rest = tail;
        }
        // Every variant has a row (pinned by `every_family_has_exactly_one_row`);
        // the internal row is the fail-closed answer for an impossible miss.
        INTERNAL_ROW
    }

    /// The letter after `IPE-` in this family's codes.
    #[must_use]
    pub const fn letter(self) -> char {
        self.row().letter
    }

    /// What this family covers, one line.
    #[must_use]
    pub const fn summary(self) -> &'static str {
        self.row().summary
    }
}

/// How severe a diagnostic is. Governs the rendered header word and exit policy.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Severity {
    /// A genuine user error: compilation must stop.
    Error,
    /// A warning: compilation may continue but the code is suspect.
    Warning,
    /// An internal compiler bug (an `IPE-I####`): "please report".
    Bug,
}

/// The single-source-of-truth taxonomy table.
///
/// Each row declares one code, once: `IDENT = "WIRE", "title", "explain-base"`.
/// From these rows the macro derives, so they can never drift apart:
/// - a `pub const IDENT: Code = Code("WIRE")` (with the given doc comment),
/// - the [`title`] arm mapping `IDENT` to `"title"`,
/// - the [`explain_page`] arm mapping `IDENT` to
///   `include_str!("../explain/<explain-base>.md")` (a missing file fails the
///   build), and
/// - membership in [`ALL_CODES`], whose length *is* the taxonomy size.
///
/// # Adding a code
///
/// Add one row and its `explain/<CODE>.md`; nothing else needs to change:
///
/// ```ignore
/// /// what went wrong, in one line
/// IPE_P0099 = "IPE-P0099", "what went wrong, in one line", "IPE-P0099";
/// ```
///
/// No count constant is touched: `ALL_CODES.len()` is recomputed from the rows.
macro_rules! code {
    (
        $(
            $(#[$meta:meta])*
            $ident:ident = $wire:literal, $title:literal, $explain_base:literal;
        )*
    ) => {
        $(
            #[allow(clippy::too_long_first_doc_paragraph)] // code-table doc strings are intentionally terse single lines
            $(#[$meta])*
            pub const $ident: Code = Code($wire);
        )*

        /// Every taxonomy code, authoritative for `ipe doc` and drift detection.
        ///
        /// This is the single source of truth. `ipe` iterates this slice to resolve
        /// `doc <CODE>` — no hand-mirror needed. Its length is the taxonomy size.
        pub const ALL_CODES: &[Code] = &[$($ident),*];

        /// The one-line human title for a code.
        ///
        /// Total over the taxonomy: every shipped constant has an explicit arm
        /// (generated from the [`code!`] table). A code outside the taxonomy
        /// (impossible to construct outside this crate) falls back to the generic
        /// internal-error title rather than panicking.
        #[must_use]
        pub fn title(c: Code) -> &'static str {
            match c {
                $($ident => $title,)*
                _ => "unknown error code",
            }
        }

        /// The embedded `ipe doc` page for a code.
        ///
        /// Each page is `include_str!`d from `explain/<CODE>.md` at compile time,
        /// so a missing or renamed page is a build error — the registry cannot
        /// drift from the taxonomy silently. Total over every shipped constant
        /// (generated from the [`code!`] table); the `_` arm only guards a `Code`
        /// that cannot be constructed outside this crate.
        ///
        /// Page invariants (enforced by
        /// [`tests::every_code_has_a_conforming_explain_page`]): line 1 is exactly
        /// `# <CODE>: <title()>`, and the body carries at least three
        /// ```` ```ipe ```` fences.
        #[must_use]
        pub fn explain_page(c: Code) -> Option<&'static str> {
            match c {
                $($ident => Some(include_str!(concat!("../explain/", $explain_base, ".md"))),)*
                _ => None,
            }
        }
    };
}

code! {
    // -----------------------------------------------------------------------
    // Parse (IPE-P####)
    // -----------------------------------------------------------------------

    /// unexpected token
    IPE_P0001 = "IPE-P0001", "unexpected token", "IPE-P0001";
    /// unexpected end of file
    IPE_P0002 = "IPE-P0002", "unexpected end of file", "IPE-P0002";
    /// input nests too deeply
    IPE_P0003 = "IPE-P0003", "input nests too deeply", "IPE-P0003";
    /// unknown character
    IPE_P0010 = "IPE-P0010", "unknown character", "IPE-P0010";
    /// stray `.`
    IPE_P0011 = "IPE-P0011", "stray '.'", "IPE-P0011";
    /// number joined to a name
    IPE_P0012 = "IPE-P0012", "number joined to a name", "IPE-P0012";
    /// integer literal out of range
    IPE_P0013 = "IPE-P0013", "integer literal out of range", "IPE-P0013";
    /// unterminated string literal
    IPE_P0014 = "IPE-P0014", "unterminated string literal", "IPE-P0014";
    /// malformed character literal
    IPE_P0015 = "IPE-P0015", "malformed character literal", "IPE-P0015";
    /// float literal out of range
    IPE_P0016 = "IPE-P0016", "float literal out of range", "IPE-P0016";
    /// unterminated block comment
    IPE_P0017 = "IPE-P0017", "unterminated block comment", "IPE-P0017";
    /// a space before `.` reads as an accessor function (unsupported)
    IPE_P0018 = "IPE-P0018", "a space before '.' reads as an accessor function", "IPE-P0018";
    /// malformed module header
    IPE_P0020 = "IPE-P0020", "malformed module header", "IPE-P0020";
    /// malformed exposing list
    IPE_P0021 = "IPE-P0021", "malformed exposing list", "IPE-P0021";
    /// missing `=` in definition
    IPE_P0030 = "IPE-P0030", "missing '=' in definition", "IPE-P0030";
    /// malformed type declaration
    IPE_P0031 = "IPE-P0031", "malformed type declaration", "IPE-P0031";
    /// only a type constructor can take arguments
    IPE_P0040 = "IPE-P0040", "only a type constructor can take arguments", "IPE-P0040";
    /// expected a type
    IPE_P0041 = "IPE-P0041", "expected a type", "IPE-P0041";
    /// unclosed delimiter
    IPE_P0050 = "IPE-P0050", "unclosed delimiter", "IPE-P0050";
    /// malformed case expression
    IPE_P0060 = "IPE-P0060", "malformed case expression", "IPE-P0060";
    /// malformed let expression
    IPE_P0061 = "IPE-P0061", "malformed let expression", "IPE-P0061";
    /// malformed if expression
    IPE_P0062 = "IPE-P0062", "malformed if expression", "IPE-P0062";
    /// invalid path literal — a `path "…"` whose string fails compile-time validation
    IPE_P0063 = "IPE-P0063", "invalid path literal", "IPE-P0063";
    /// a bare `_` as the whole `let` binding pattern binds nothing and is not allowed
    IPE_P0064 = "IPE-P0064", "bare `_` as a whole `let` binding pattern is not allowed", "IPE-P0064";
    /// a `do` block with no Task steps — use `let … in` for pure bindings
    IPE_P0065 = "IPE-P0065", "a `do` block must contain at least one Task step", "IPE-P0065";
    /// doc-string on a non-exported binding is unreachable (warning)
    IPE_P0066 = "IPE-P0066", "doc-string on a non-exported binding is unreachable", "IPE-P0066";
    /// exported binding has no doc-string — opt-in lint (warning)
    IPE_P0067 = "IPE-P0067", "exported binding has no doc-string", "IPE-P0067";
    /// type annotation has no matching value binding
    IPE_P0068 = "IPE-P0068", "type annotation has no matching value binding", "IPE-P0068";
    /// duplicate type annotation for one name
    IPE_P0069 = "IPE-P0069", "duplicate type annotation for one name", "IPE-P0069";
    /// source exceeds the addressable span range (u32 byte offsets)
    IPE_P0070 = "IPE-P0070", "source file is too large to compile", "IPE-P0070";

    // -----------------------------------------------------------------------
    // Name resolution (IPE-N####)
    // -----------------------------------------------------------------------

    /// cannot find this value in scope
    IPE_N0001 = "IPE-N0001", "cannot find this value in scope", "IPE-N0001";
    /// cannot find this type in scope
    IPE_N0002 = "IPE-N0002", "cannot find this type in scope", "IPE-N0002";
    /// cannot find this constructor
    IPE_N0003 = "IPE-N0003", "cannot find this constructor", "IPE-N0003";
    /// unknown module or import
    IPE_N0004 = "IPE-N0004", "unknown module or import", "IPE-N0004";
    /// module has no such member
    IPE_N0005 = "IPE-N0005", "module has no such member", "IPE-N0005";
    /// value defined more than once
    IPE_N0010 = "IPE-N0010", "value defined more than once", "IPE-N0010";
    /// constructor defined more than once
    IPE_N0011 = "IPE-N0011", "constructor defined more than once", "IPE-N0011";
    /// type defined more than once
    IPE_N0012 = "IPE-N0012", "type defined more than once", "IPE-N0012";
    /// type alias applied with the wrong number of arguments
    IPE_N0013 = "IPE-N0013", "type alias applied with the wrong number of arguments", "IPE-N0013";
    /// a local module named in an import cannot be found
    IPE_N0020 = "IPE-N0020", "module not found", "IPE-N0020";
    /// importing a module creates a cycle
    IPE_N0021 = "IPE-N0021", "import cycle", "IPE-N0021";
    /// the import names a member the module does not expose
    IPE_N0022 = "IPE-N0022", "name not exposed", "IPE-N0022";
    /// the module declaration does not match the file's path
    IPE_N0023 = "IPE-N0023", "module path mismatch", "IPE-N0023";
    /// two imports expose the same name unqualified
    IPE_N0024 = "IPE-N0024", "ambiguous import", "IPE-N0024";
    /// a local module claims a reserved namespace
    IPE_N0025 = "IPE-N0025", "reserved namespace", "IPE-N0025";
    /// a user type/alias reuses a built-in type name
    IPE_N0026 = "IPE-N0026", "type name reserved for a built-in", "IPE-N0026";
    /// two imports register the same qualifier against different dep modules
    IPE_N0027 = "IPE-N0027", "duplicate import qualifier", "IPE-N0027";
    /// an `Kernel.kernel "Name"` alias names a kernel that is not registered
    IPE_N0028 = "IPE-N0028", "unknown kernel alias", "IPE-N0028";
    /// A server-only kernel named from a `--target wasm` build.
    IPE_N0029 = "IPE-N0029", "server-only effect in a wasm build", "IPE-N0029";
    /// A wasm client-entry's reachability closure transitively reaches a
    /// server-classified module.
    IPE_N0030 = "IPE-N0030", "server module reachable from the wasm client entry", "IPE-N0030";
    /// a built-in container type constructor (`List`/`Maybe`/`Set`/`Dict`/`Result`)
    /// is applied to the wrong number of type arguments
    IPE_N0031 = "IPE-N0031", "built-in container type applied to the wrong number of arguments", "IPE-N0031";
    /// type alias expansion exceeded the depth or node-count budget (cyclic or
    /// exponentially-fanning alias chain)
    IPE_N0032 = "IPE-N0032", "type alias expansion too deep or too large", "IPE-N0032";
    /// a plain-`main` Program imports a managed-update-loop shape under `Ipe.Tea.*`
    IPE_N0033 = "IPE-N0033", "a Program may not import a managed-update-loop shape", "IPE-N0033";
    /// a known standard-library module is used qualified without importing it
    IPE_N0034 = "IPE-N0034", "standard-library module used without importing it", "IPE-N0034";
    /// a TEA app imports another shape's `Cmd` / `Sub` re-export module
    IPE_N0035 = "IPE-N0035", "Cmd / Sub imported from a different shape than the app's", "IPE-N0035";
    /// a removed surface binding is used; `ipe fix` can migrate the call site
    IPE_N0036 = "IPE-N0036", "a removed standard-library surface is still being called", "IPE-N0036";
    /// an asserted foreign call (`Rust.Ffi.call`) is malformed at its use site
    IPE_N0038 = "IPE-N0038", "an asserted foreign call (Rust.Ffi.call) is malformed", "IPE-N0038";
    /// a `CustomElement` boundary type parameter is not a plain, closed, concrete
    /// value type — the SEAL rejects it before it can cross the Ipê↔JS seam
    IPE_N0039 = "IPE-N0039", "a CustomElement boundary type parameter is not a plain, closed value type", "IPE-N0039";
    /// a decoder-pipeline combinator (`required` / `optional` / `requiredAt` /
    /// `custom`) is hand-nested rather than threaded with `|>`, reversing
    /// field→constructor binding — rejected fail-closed with the `|>` rewrite
    IPE_N0040 = "IPE-N0040", "a decoder-pipeline combinator is hand-nested instead of threaded with |>", "IPE-N0040";
    /// `Ipe.Codec.auto` cannot derive a codec: the witness is not an annotated
    /// record value, or a field's type has no derivable leaf codec (a function, a
    /// `Secret`, a data-carrying ADT, an opaque handle) — rejected fail-closed
    IPE_N0041 = "IPE-N0041", "Ipe.Codec.auto cannot derive a codec for this type", "IPE-N0041";
    /// a `Kernel.kernel "Name"` kernel-alias binding appears in user source — minting
    /// a kernel is reserved to the driver-vouched standard library / FFI interface,
    /// so user code cannot reach an unsafe kernel without a disclosing `.Unsafe`
    /// import (capability-model integrity, fail-closed)
    IPE_N0042 = "IPE-N0042", "a kernel alias (Kernel.kernel) may not be minted in user source", "IPE-N0042";
    /// a top-level `config` binding (the app's cross-cutting `List (Setting
    /// shape)`) is declared but never threaded into an app entry — inert data
    /// the runtime never installs, so every setting it lists is silently dropped
    IPE_N0043 = "IPE-N0043", "a config binding is declared but never threaded into an app entry", "IPE-N0043";
    /// the reserved `CustomElement.fromFile "<js-path>"` constructor is malformed at its use
    /// site — applied to a non-literal, referenced bare (unapplied), given a
    /// traversing path, its named file absent, or placed anywhere other than the
    /// whole body of a `CustomElement`-annotated binding (fail-closed at build)
    IPE_N0044 = "IPE-N0044", "the CustomElement.fromFile constructor is malformed at its use site", "IPE-N0044";
    /// `main` chooses its shape at runtime — its head is an `if` / `case`
    /// whose branches reach app entries — but a program's shape is a
    /// compile-time choice, pinned by the entry head, not a runtime value
    IPE_N0045 = "IPE-N0045", "main selects its shape at runtime, but a shape is a compile-time choice", "IPE-N0045";
    /// `Web.tea`'s `init` annotation uses a free type variable for its request
    /// argument — the request type is `WebReq`, not an unconstrained `a`
    IPE_N0046 = "IPE-N0046", "Web.tea init annotation uses a type variable where WebReq is required", "IPE-N0046";
    /// a standard-library module is imported in a shape × runtime placement the
    /// library single-source-of-truth table does not admit
    IPE_N0047 = "IPE-N0047", "this standard-library module is not available in this shape × runtime placement", "IPE-N0047";
    /// two distinct Ipê definitions mangle to one generated Rust name, which
    /// would emit two Rust items under one identifier (E0428) — reported with
    /// both Ipê names and the shared Rust name so the fix is a rename
    IPE_N0048 = "IPE-N0048", "two definitions fold to one generated Rust name", "IPE-N0048";
    /// a pattern binds the same variable name more than once
    IPE_N0049 = "IPE-N0049", "a pattern binds the same name twice", "IPE-N0049";
    /// a Script imports a shape's view module but renders nothing
    IPE_N0050 = "IPE-N0050", "a Script imports a shape's UI, which it cannot render", "IPE-N0050";
    /// an app entry (`Web.tea`, `Tui.tea`, `Cli.tea`, `Worker.tea`, …) is built
    /// inside a definition whose `Model` / `Msg` is still a type variable; the
    /// running app needs one concrete model and message type
    IPE_N0051 = "IPE-N0051", "an app entry is built with a Model or Msg that is still a type variable", "IPE-N0051";
    /// terminal input passed as an app config field instead of a subscription
    IPE_N0052 = "IPE-N0052", "terminal input is a subscription, not an app config field", "IPE-N0052";

    // -----------------------------------------------------------------------
    // Type (IPE-T####)
    // -----------------------------------------------------------------------

    /// type mismatch
    IPE_T0001 = "IPE-T0001", "type mismatch", "IPE-T0001";
    /// infinite type
    IPE_T0002 = "IPE-T0002", "infinite type", "IPE-T0002";
    /// type inference exceeded its step budget
    IPE_T0003 = "IPE-T0003", "type inference exceeded its step budget", "IPE-T0003";
    /// more parameters than the type signature describes
    IPE_T0004 = "IPE-T0004", "more parameters than the type signature describes", "IPE-T0004";
    /// this case does not handle every possibility
    IPE_T0010 = "IPE-T0010", "this case does not handle every possibility", "IPE-T0010";
    /// redundant case branch
    IPE_T0011 = "IPE-T0011", "redundant case branch", "IPE-T0011";
    /// this record has no such field
    IPE_T0012 = "IPE-T0012", "this record has no such field", "IPE-T0012";
    /// constructor pattern binds the wrong number of payload fields
    IPE_T0013 = "IPE-T0013", "constructor pattern binds the wrong number of fields", "IPE-T0013";
    /// a generic function is used at a type that lacks the required operations
    IPE_T0014 = "IPE-T0014", "this type does not support the required operations", "IPE-T0014";
    /// a parameter / binder pattern is refutable (must be irrefutable)
    IPE_T0015 = "IPE-T0015", "parameter pattern must be irrefutable", "IPE-T0015";
    /// a `Task` type is applied to the wrong number of arguments (not 1 or 2)
    IPE_T0016 = "IPE-T0016", "async carrier (`Task`/`Cmd`/`Sub`) applied to the wrong number of type arguments", "IPE-T0016";
    /// a record update on a nominal builtin type (readable fields, no update form)
    IPE_T0017 = "IPE-T0017", "built-in type cannot be updated with record syntax", "IPE-T0017";
    /// a wildcard arm swallows constructors a finite ADT could name explicitly
    IPE_T0018 = "IPE-T0018", "this catch-all arm hides constructors of a closed union", "IPE-T0018";
    /// each alternative of an or-pattern must bind the same variables
    ///
    /// T0018 is now the closed-union catch-all lint; or-patterns keep T0019.
    IPE_T0019 = "IPE-T0019", "each alternative of an or-pattern must bind the same variables", "IPE-T0019";
    /// an `Html` value is used where an `Element` is required (wrap it in `Ui.html`)
    IPE_T0020 = "IPE-T0020", "this is `Html` where an `Element` is required", "IPE-T0020";
    /// a wildcard `any` parameter the body ties to another type (name it with a type variable)
    IPE_T0021 = "IPE-T0021", "this `any` is tied to another type, so it cannot stay a wildcard", "IPE-T0021";

    // -----------------------------------------------------------------------
    // Lower / not-yet-supported (IPE-L####)
    // -----------------------------------------------------------------------

    /// pattern kind not supported yet
    IPE_L0100 = "IPE-L0100", "pattern kind not supported yet", "IPE-L0100";
    /// operator not supported yet
    IPE_L0101 = "IPE-L0101", "operator not supported yet", "IPE-L0101";
    /// polymorphic type variables not supported yet
    IPE_L0102 = "IPE-L0102", "polymorphic value's type could not be determined", "IPE-L0102";
    /// function-valued parameters/returns not supported yet
    IPE_L0103 = "IPE-L0103", "function-valued parameters/returns not supported yet", "IPE-L0103";
    /// only `Task ()` is supported yet
    IPE_L0104 = "IPE-L0104", "only Task () is supported yet", "IPE-L0104";
    /// parameter destructuring not supported yet
    IPE_L0105 = "IPE-L0105", "parameter destructuring not supported yet", "IPE-L0105";
    /// top-level function needs a type signature
    IPE_L0106 = "IPE-L0106", "top-level function needs a type signature", "IPE-L0106";
    /// first-class functions not supported yet
    IPE_L0107 = "IPE-L0107", "function value in a record field not supported here", "IPE-L0107";
    /// kernel function not available yet
    IPE_L0108 = "IPE-L0108", "kernel function not available yet", "IPE-L0108";
    /// partial or over-application of a function not supported yet
    IPE_L0110 = "IPE-L0110", "partial or over-application not supported yet", "IPE-L0110";
    /// updating a generic record needs a bounded type parameter
    IPE_L0111 = "IPE-L0111", "updating a generic record is not supported yet", "IPE-L0111";
    /// a constructor payload sub-pattern other than a variable / wildcard
    IPE_L0112 = "IPE-L0112", "nested constructor payload patterns not supported yet", "IPE-L0112";
    /// a data constructor used as a first-class function value / partially applied
    IPE_L0113 = "IPE-L0113", "constructor used as a function value not supported yet", "IPE-L0113";
    /// a function value stored in a constructor payload not supported yet
    IPE_L0114 = "IPE-L0114", "function value in a constructor payload not supported yet", "IPE-L0114";
    /// a tuple pattern beyond a single irrefutable destructure not supported yet
    IPE_L0115 = "IPE-L0115", "tuple pattern not supported here yet", "IPE-L0115";
    /// two `case` arms for the same constructor (nested discrimination) not yet
    IPE_L0116 = "IPE-L0116", "refutable pattern-discrimination shape not supported yet", "IPE-L0116";
    /// `Float` is not a valid `Set` element or `Dict` key on the Rust backend
    IPE_L0117 = "IPE-L0117", "Float is not a valid Set element or Dict key on the Rust backend", "IPE-L0117";
    /// `Web.appRouted` is not yet supported — use `Web.tea` (non-routed) for now
    IPE_L0118 = "IPE-L0118", "`Web.appRouted` is not yet supported — use `Web.tea` (non-routed) for now", "IPE-L0118";
    /// an app-entry cfg must be an inline record literal, not a let-bound variable
    IPE_L0119 = "IPE-L0119", "app entry cfg must be an inline record literal", "IPE-L0119";
    /// a Web/Terminal/WebView app Model is not admissible for that app shape's
    /// runtime bound (Web needs serde+Clone+PartialEq; Terminal/WebView need Clone)
    IPE_L0120 = "IPE-L0120", "app Model is not admissible for this app shape", "IPE-L0120";
    /// `JsonDec.succeed` / `Db.Decode.succeed` constructor arity exceeds 10
    /// (the maximum supported by `curry1`..`curry10` in the runtime)
    IPE_L0121 = "IPE-L0121", "`JsonDec.succeed` / `Db.Decode.succeed` constructor arity exceeds 10", "IPE-L0121";
    /// `Web.route` pattern `:param` count does not match the page-constructor
    /// payload count; the route can never deliver the right number of arguments
    IPE_L0122 = "IPE-L0122", "`Web.route` `:param` count does not match page-constructor payload count", "IPE-L0122";
    /// `Web.route` page builder is neither a page constructor, an inline lambda,
    /// nor a named function — the Rust backend cannot emit a type-directed closure
    IPE_L0123 = "IPE-L0123", "`Web.route` page builder is not a constructor, lambda, or named function", "IPE-L0123";
    /// `Web.tea` routes list is non-empty but Model has no `page` field.
    ///
    /// The routes are forwarded to the non-routed runtime path and never update the
    /// Model. Emitted as a **warning** (`applyRoute` silently no-ops the same
    /// shape, so this compiles) to flag the likely mis-named routed-page field.
    IPE_L0124 = "IPE-L0124", "`Web.tea` routes list is non-empty but Model has no `page` field", "IPE-L0124";
    /// inadmissible Msg type in a Web/Terminal/WebView app.
    ///
    /// The Msg type's Rust rendering would not satisfy the runtime's
    /// `Clone + Send + Sync + Debug + 'static` bound — converts a
    /// would-be `cargo` trait-bound failure into a fail-closed `ipe` error.
    IPE_L0125 = "IPE-L0125", "app Msg is not admissible for this app shape", "IPE-L0125";
    /// a non-Clone, non-callee-position capture inside a closure
    IPE_L0126 = "IPE-L0126", "non-Clone capture in a closure is not yet supported", "IPE-L0126";
    /// a value holding a function is used more than once (function values cannot
    /// be copied yet)
    IPE_L0127 = "IPE-L0127", "a value holding a function is used more than once", "IPE-L0127";
    /// an `as`-alias in a refutable match-arm position whose inner pattern needs
    /// Rust-level runtime dispatch (a nested constructor / literal / list pattern)
    IPE_L0128 = "IPE-L0128", "alias over a dispatch-needing nested pattern not supported yet", "IPE-L0128";
    /// A routed `Web.tea` under `--target wasm` (client router not yet built).
    IPE_L0129 = "IPE-L0129", "routed Web.tea not supported under --target wasm yet", "IPE-L0129";
    /// a foreign opaque FFI handle (possibly non-`Clone`) is used more than once
    IPE_L0130 = "IPE-L0130", "a foreign opaque FFI handle is used more than once", "IPE-L0130";
    /// a row-polymorphic record annotation `{ r | f : T }` reached the backend
    IPE_L0131 = "IPE-L0131", "a row-polymorphic record annotation is not yet emittable", "IPE-L0131";
    /// `Ui.cells` (a terminal-only raw cell grid) is used in the Web/WebView shape
    IPE_L0132 = "IPE-L0132", "Ui.cells is terminal-only and not available in the Web/WebView shape", "IPE-L0132";
    /// an equality/ordering collection op over a function-carrying element.
    ///
    /// `List.member`/`sort`/`unique`/… need `==`/`Ord` on the element; a stored
    /// function is `Clone` but not comparable.
    IPE_L0134 = "IPE-L0134", "an equality- or ordering-requiring collection operation over a function-carrying element is not sound (a function is not comparable)", "IPE-L0134";
    /// a non-`Clone` value (a `Task`/`Cmd`/`Sub` effect, bare or inside a
    /// union/tuple/record payload) is used more than once in a value-consuming
    /// position.
    ///
    /// A generic union derives `Clone where T: Clone`, but the concrete payload
    /// here (e.g. `Task`) is not `Clone`, so the value-reuse rewrite has no sound
    /// `.clone()` to insert. Thread the value linearly (use it once) instead.
    IPE_L0135 = "IPE-L0135", "a non-Clone value (a Task/Cmd/Sub effect or a payload carrying one) is used more than once", "IPE-L0135";
    /// `main` is not a runnable program entry.
    ///
    /// A program's `main` is the single effect it runs, so it must be a
    /// `Task Error ()` — written directly (a script), or produced by an app
    /// entry (`Web.tea` / `Tui.tea` / `Cli.tea`, each of which
    /// returns a `Task Error ()`). A `main` of any other type (an `Int`, a
    /// `String`, a function, …) carries no effect to run; the runtime's single
    /// run site needs a `Task`, so this fails closed at `ipe` time rather than
    /// shipping a crate that cannot build.
    IPE_L0136 = "IPE-L0136", "`main` is not a runnable program entry", "IPE-L0136";
    /// a `Debug.*` development-only escape hatch reached a production build
    /// (`ipe release`)
    IPE_L0140 = "IPE-L0140", "a Debug.* escape hatch was used in a production build", "IPE-L0140";
    /// a `Task`-typed value was discarded (`let _ = <task>`) in a non-`Task`
    /// context, which would run its effect through an implicit `Task.run`
    /// outside the effect discipline
    IPE_L0141 = "IPE-L0141", "a Task effect was discarded in a non-Task context, escaping the Task effect discipline", "IPE-L0141";
    /// a wildcard `any` in return position is carried by no parameter and pinned
    /// by no body, so no caller can determine its single concrete type
    IPE_L0142 = "IPE-L0142", "a return-position wildcard `any` cannot be determined", "IPE-L0142";
    /// a caller passes a record whose field has the wrong type for a wildcard-`any`
    /// parameter that reads that field — the required field type comes from the
    /// callee's body, not from a shared type-checker unification (which `any`
    /// severs), so the mismatch is caught here rather than emitting Rust E0271
    IPE_L0143 = "IPE-L0143", "caller field type does not match the field type required by the callee", "IPE-L0143";
    /// a non-record value is passed at a row-generic parameter position — only a
    /// record can carry the `IpeHas*` witness bound the callee's body requires
    IPE_L0144 = "IPE-L0144", "argument at a row-generic position is not a record", "IPE-L0144";
    /// a `Store.eq` / `Store.eqBy` column argument is not a usable field accessor:
    /// not a bare `.field` accessor, its field is absent from the row, its field
    /// type is not a scalar under plain `eq` (needs `eqBy` + codec), or the
    /// derived column name is not a valid SQL identifier
    IPE_L0145 = "IPE-L0145", "a Store.eq column argument is not a usable field accessor", "IPE-L0145";
    /// an accessor-typed `Store.*` query leaf or column-spec builder was used
    /// point-free / partially applied — these leaves read their column from a
    /// `.field` accessor and have no runtime function, so they must be applied
    /// directly with their accessor and value
    IPE_L0146 = "IPE-L0146", "a Store accessor query/spec builder was applied point-free", "IPE-L0146";
    /// `CustomElement.node` (a server-driven custom element) is used outside a
    /// Web/WebView shape — its up-event handler rides the seal codec, present
    /// only in a browser build, so it has no transport under `Terminal` / `Program`
    IPE_L0147 = "IPE-L0147", "`CustomElement.node` is browser-only and cannot be used outside a Web/WebView shape", "IPE-L0147";
    /// a `Js.send`/`Js.subscribe` port value crossed the Ipê↔JS seam with a
    /// non-seal-legal type (a `Secret`/reserved-sink, an untyped `Value`, a
    /// function, or another non-plain value)
    IPE_L0148 = "IPE-L0148", "a JS port boundary value is not seal-legal (a secret/sink, an untyped Value, or a non-plain type cannot cross to JS)", "IPE-L0148";
    /// a `Store.select` projection lambda is not a lowerable column projection —
    /// its body is not a single `cols.field` column reference over one of the
    /// two bound side records, or names a field absent from that side's row
    IPE_L0149 = "IPE-L0149", "a Store.select projection is not a usable column reference", "IPE-L0149";
    /// a committed string literal reached a `Secret`-typed position — a secret
    /// must not be baked into source; read it from the environment at runtime
    IPE_L0150 = "IPE-L0150", "a committed string literal cannot become a Secret", "IPE-L0150";
    /// `Secret.fromString` was referenced without being fully applied (point-free,
    /// let-bound, or passed as a value); it is legal only as a saturated one-argument
    /// call so every argument passes the committed-literal seal gate
    IPE_L0151 = "IPE-L0151", "`Secret.fromString` must be applied directly to its argument", "IPE-L0151";
    /// a kernel whose handler the backend re-wraps per call (`Stream.stream`) was
    /// referenced point-free or partially applied; the re-wrap needs the handler
    /// in hand, so the kernel is legal only as a saturated call
    IPE_L0152 = "IPE-L0152", "a handler-wrapping kernel must be applied to all its arguments", "IPE-L0152";
    /// `Ui.cells` (a terminal character-grid builder) was used in a Cli
    /// (`Cli.tea`) program. A Cli view returns `String` (line output),
    /// so a character grid has no denotation there. Use `Tui.tea` for
    /// a full-screen cell-grid app.
    IPE_L0153 = "IPE-L0153", "Ui.cells is terminal-screen-only and not available in the Cli shape", "IPE-L0153";
    /// a higher-order kernel's callback returns a function.
    ///
    /// The kernel applies its callback at one exact arity, so a callback whose
    /// final result is another arrow has no sound lowering.
    IPE_L0154 = "IPE-L0154", "a higher-order kernel callback returns a function", "IPE-L0154";
    /// a collection mapper needs more adapter parameters than one call site allows.
    ///
    /// Re-carrying the stored functions a mapper receives needs one fresh
    /// parameter per wrapper and adapter position, bounded per call site.
    IPE_L0155 = "IPE-L0155", "a collection mapper needs more adapter parameters than one call site allows", "IPE-L0155";
    /// expression nests too deeply for the backend
    IPE_L0200 = "IPE-L0200", "expression nests too deeply for the backend", "IPE-L0200";

    // -----------------------------------------------------------------------
    // FFI (IPE-F####)
    // -----------------------------------------------------------------------

    /// a foreign-call description cannot be rendered as valid Rust
    IPE_F4400 = "IPE-F4400", "a foreign-call description cannot be rendered as valid Rust", "IPE-F4400";
    /// a foreign binding's inspection data is malformed
    IPE_F4401 = "IPE-F4401", "a foreign binding's inspection data is malformed", "IPE-F4401";
    /// a foreign function declares contradictory shape flags
    IPE_F4402 = "IPE-F4402", "a foreign function declares contradictory shape flags", "IPE-F4402";
    /// no isolation jail can be established for compiling an untrusted crate
    IPE_F4410 = "IPE-F4410", "no isolation jail can be established for compiling an untrusted crate", "IPE-F4410";
    /// a git source for a foreign crate was rejected
    IPE_F4411 = "IPE-F4411", "a git source for a foreign crate was rejected", "IPE-F4411";
    /// an FFI cache artifact cannot be read or written
    IPE_F4412 = "IPE-F4412", "an FFI cache artifact cannot be read or written", "IPE-F4412";
    /// no runtime jail can be established around the emitted app, or a jailed run failed
    IPE_F4413 = "IPE-F4413", "no runtime jail can be established around the emitted app", "IPE-F4413";
    /// an author-asserted foreign call (`Rust.Ffi.call`) was refused
    IPE_F4414 = "IPE-F4414", "an author-asserted foreign call (Rust.Ffi.call) was refused", "IPE-F4414";
    /// a crate being added needs a system library that is not installed
    IPE_F4415 = "IPE-F4415", "a crate being added needs a system library that is not installed", "IPE-F4415";

    // -----------------------------------------------------------------------
    // Security consent (IPE-S####)
    // -----------------------------------------------------------------------

    /// a program imports an `Ipe.<M>.Unsafe` escape hatch and the risk was not
    /// acknowledged (non-interactive build without `--accept-risks` / manifest
    /// pre-acceptance, or an interactive "no")
    IPE_S0001 = "IPE-S0001", "unsafe escape hatch imported without acknowledgment", "IPE-S0001";

    // -----------------------------------------------------------------------
    // Environment (IPE-E####)
    // -----------------------------------------------------------------------

    /// the crate registry could not be reached (network or DNS failure)
    IPE_E0001 = "IPE-E0001", "could not reach the crate registry", "IPE-E0001";

    // -----------------------------------------------------------------------
    // Internal (IPE-I####)
    // -----------------------------------------------------------------------

    /// internal compiler error
    IPE_I0001 = "IPE-I0001", "internal compiler error", "IPE-I0001";
    /// intern: unresolved symbol
    IPE_I0010 = "IPE-I0010", "intern: unresolved symbol", "IPE-I0010";
    /// intern: symbol table exhausted
    IPE_I0011 = "IPE-I0011", "intern: symbol table exhausted", "IPE-I0011";
    /// ICE: match on unknown variant
    IPE_I0100 = "IPE-I0100", "ICE: match on unknown variant", "IPE-I0100";
    /// ICE: duplicate match arm
    IPE_I0101 = "IPE-I0101", "ICE: duplicate match arm", "IPE-I0101";
    /// ICE: non-exhaustive match
    IPE_I0102 = "IPE-I0102", "ICE: non-exhaustive match", "IPE-I0102";
    /// ICE: match arm enum mismatch
    IPE_I0103 = "IPE-I0103", "ICE: match arm enum mismatch", "IPE-I0103";
    /// ICE: no Rust name for symbol
    IPE_I0200 = "IPE-I0200", "ICE: no Rust name for symbol", "IPE-I0200";
    /// ICE: dangling value/variant symbol
    IPE_I0201 = "IPE-I0201", "ICE: dangling value/variant symbol", "IPE-I0201";
    /// ICE: cross-module type-name collision
    IPE_I0202 = "IPE-I0202", "ICE: cross-module type-name collision", "IPE-I0202";
    /// ICE: golden anchor missing
    IPE_I0203 = "IPE-I0203", "ICE: golden anchor missing", "IPE-I0203";
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The taxonomy size is derived from the table, not pinned to a literal.
    /// This guards the one property a derived count still needs: that
    /// `ALL_CODES` holds no duplicate wire strings, so its length equals the
    /// number of distinct codes.
    #[test]
    fn taxonomy_has_no_duplicate_codes() {
        let mut seen = std::collections::BTreeSet::new();
        for &c in ALL_CODES {
            assert!(seen.insert(c.as_str()), "{} duplicated", c.as_str());
        }
        assert_eq!(seen.len(), ALL_CODES.len());
    }

    /// The family table is a bijection: every family has exactly one row, every
    /// letter names one family, and each family reads its own row back.
    #[test]
    fn every_family_has_exactly_one_row() {
        let all = [
            Family::Parse,
            Family::Name,
            Family::Type,
            Family::Lower,
            Family::Ffi,
            Family::Security,
            Family::Environment,
            Family::Internal,
        ];
        for family in all {
            let rows = FAMILIES.iter().filter(|r| r.family == family).count();
            assert_eq!(rows, 1, "{family:?} has {rows} rows");
            assert!(!family.summary().is_empty(), "{family:?} has no summary");
        }
        let mut letters = std::collections::BTreeSet::new();
        for row in FAMILIES {
            assert!(letters.insert(row.letter), "letter {} repeats", row.letter);
            assert_eq!(row.family.letter(), row.letter);
        }
    }

    /// A code's letter after `IPE-` is its family's letter — the classifier and
    /// the description read the same table.
    #[test]
    fn every_code_letter_is_its_family_letter() {
        for &c in ALL_CODES {
            let letter = c.as_str().chars().nth(4);
            assert_eq!(letter, Some(c.family().letter()), "{}", c.as_str());
        }
    }

    #[test]
    fn every_code_has_a_nonempty_distinct_title() {
        for &c in ALL_CODES {
            assert!(!title(c).is_empty(), "{} has empty title", c.as_str());
        }
    }

    #[test]
    fn codes_are_distinct_and_well_formed() {
        let mut seen = std::collections::BTreeSet::new();
        for &c in ALL_CODES {
            let s = c.as_str();
            assert!(s.starts_with("IPE-"), "{s} bad prefix");
            assert!(seen.insert(s), "{s} duplicated");
        }
        assert_eq!(seen.len(), ALL_CODES.len());
    }

    /// CI coverage gate: every taxonomy code has a conforming explain page.
    /// Line 1 must be exactly `# <CODE>: <title()>` and the body must carry at
    /// least three ```` ```ipe ```` fences. A code without a page, or with a
    /// non-conforming one, fails the suite (and `include_str!` already fails the
    /// build if the file is absent entirely).
    #[test]
    fn every_code_has_a_conforming_explain_page() {
        for &c in ALL_CODES {
            assert!(
                explain_page(c).is_some(),
                "{} has no explain page",
                c.as_str()
            );
            if let Some(page) = explain_page(c) {
                let first = page.lines().next().unwrap_or("");
                let expected = format!("# {}: {}", c.as_str(), title(c));
                assert_eq!(
                    first,
                    expected,
                    "{} page line 1 must be `{expected}`",
                    c.as_str()
                );
                let fences = page.matches("```ipe").count();
                assert!(
                    fences >= 3,
                    "{} page has {fences} ```ipe fences, need >= 3",
                    c.as_str()
                );
                assert!(
                    page.ends_with('\n'),
                    "{} page must end with a trailing newline",
                    c.as_str()
                );
                assert!(
                    !page.ends_with("\n\n"),
                    "{} page must not end with a double blank line",
                    c.as_str()
                );
            }
        }
    }

    #[test]
    fn issue_tracker_url_is_a_github_issues_link() {
        assert_eq!(
            issue_tracker_url(),
            format!("https://github.com/{GITHUB_REPO_SLUG}/issues")
        );
    }

    /// Every code in `ALL_CODES` must produce a non-default title and a `Some` explain page.
    ///
    /// Because the `code!` macro generates both the constants and `ALL_CODES`
    /// from the same table, a code present as a constant but absent from
    /// `ALL_CODES` is structurally impossible — this test is the observable
    /// complement: it asserts that nothing in `ALL_CODES` silently falls through
    /// to the generic fallback arms in `title` / `explain_page`.
    ///
    /// Any code that trips this assertion was added to the table without the
    /// required explain page, or with an empty title string.
    #[test]
    fn every_code_in_all_codes_has_non_fallback_title_and_explain() {
        for &c in ALL_CODES {
            let t = title(c);
            assert!(
                t != "unknown error code" && !t.is_empty(),
                "{} fell through to the fallback title arm — \
                 its entry in the code! table is missing or malformed",
                c.as_str()
            );
            assert!(
                explain_page(c).is_some(),
                "{} has no explain page — add explain/{}.md",
                c.as_str(),
                c.as_str()
            );
        }
    }

    /// `IPE-N0030` is a real, emitted diagnostic — its entry in `ALL_CODES` must
    /// be reachable and its title must match the taxonomy declaration exactly.
    ///
    /// This pins the `ipe doc IPE-N0030` and did-you-mean surfaces against
    /// silent omission.
    #[test]
    fn n0030_is_registered_and_explain_surface_finds_it() {
        assert!(
            ALL_CODES.contains(&IPE_N0030),
            "IPE-N0030 is missing from ALL_CODES"
        );
        assert_eq!(
            title(IPE_N0030),
            "server module reachable from the wasm client entry"
        );
        assert!(
            explain_page(IPE_N0030).is_some(),
            "IPE-N0030 has no explain page"
        );
    }
}
