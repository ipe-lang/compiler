//! The `PkgInfo` decode boundary — where inspector output enters the typed
//! world.
//!
//! The permissive WIRE layer (byte-mirroring the `ipe-ffi-inspector` JSON)
//! lives in the [`wire`] submodule. The DOMAIN layer here is constructed only
//! through the validating conversion: identifiers become [`RustIdent`]s, the
//! accessor-flag soup collapses into the closed [`FnShape`] sum, the effect
//! string becomes the closed [`Effect`] enum, and each parametric `generic`
//! block's call AST passes the [`Call`] gate. A defective FUNCTION is
//! over-dropped (recorded, package kept); a defective PACKAGE header fails the
//! decode.

mod wire;

use std::collections::BTreeMap;

use wire::{WireConstant, WireFunction, WireParam, WirePkgInfo, WireTransitiveDep};

use crate::call::Call;
use crate::carrier::{Carrier, ClosureSig, EnumDef, StructDef};
use crate::diag::{Diagnostic, WireDefect};
use crate::naming::{FieldSelector, RustIdent, RustPattern, RustTypeExpr, wrapper_ref_name};

// ── domain layer ────────────────────────────────────────────────────────────

/// How a foreign function's effect is classified by the inspector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// No observable side effect.
    Pure,
    /// Pure but may fail (`Result`-returning).
    Fallible,
    /// Performs I/O or other observable effects.
    Effectful,
}

/// Whether the binding's Ipê-visible type is wrapped in the fallible carrier.
///
/// Decoded ONCE here; both the `.ipei` and `kernel.json` emitters read this
/// same bit, so the two artifacts cannot disagree on getter fallibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fallibility {
    /// Projection/match/construct body — never fails; no `Result` wrapper.
    Infallible,
    /// Every other wrapper: the result is `Result Error a` / `Task Error a`.
    TaskError,
}

/// The kind of an enum accessor's target variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumVariantKind {
    /// A payload-free variant.
    Unit,
    /// Positional payload fields.
    Tuple,
    /// Named payload fields.
    Struct,
}

/// One arm of an enum tag accessor's generated `match`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumArm {
    /// The validated Rust pattern (`A`, `B(..)`, `C{..}`) — a variant head
    /// with an optional `(..)`/`{..}` suffix, so it renders inside the `match`
    /// without escaping.
    pub pattern: RustPattern,
    /// The tag string the arm returns (rendered as a Rust string LITERAL, so
    /// it stays plain data).
    pub tag: String,
}

/// The closed sum the mutually-exclusive accessor flags collapse into.
///
/// Two flags set at once is [`Diagnostic::ShapeContradiction`] — that one
/// binding is dropped, the package survives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FnShape {
    /// An ordinary free function or method.
    Plain,
    /// A synthetic struct-field getter.
    FieldGet,
    /// A synthetic struct-field setter.
    FieldSet,
    /// A synthetic package-level var/const getter.
    PkgVar,
    /// An enum-variant constructor (`E::Variant(args)`).
    EnumCtor {
        /// The Rust variant identifier.
        variant: RustIdent,
        /// The variant's payload kind.
        kind: EnumVariantKind,
        /// Struct-variant field names in declaration order (each a validated
        /// identifier, rendered verbatim as a field name).
        struct_fields: Vec<RustIdent>,
    },
    /// An enum tag accessor (exhaustive `match` returning the variant name).
    EnumTag {
        /// The generated match arms.
        arms: Vec<EnumArm>,
        /// Whether the match needs a trailing `_ =>` wildcard arm.
        wildcard: bool,
    },
    /// A single-field payload extractor (`E -> Maybe T`).
    EnumExtract {
        /// The Rust variant identifier.
        variant: RustIdent,
        /// The variant's payload kind.
        kind: EnumVariantKind,
        /// The selected binder: a validated field NAME (struct variant) or a
        /// decimal positional index (tuple variant).
        selector: FieldSelector,
        /// The variant's total field arity (tuple extractors bind every
        /// position before returning the selected one).
        field_count: u64,
        /// Whether the match needs a trailing `_ =>` wildcard arm.
        wildcard: bool,
    },
    /// A `[rust.define.closure]` adapter: the wrapper takes an Ipê function
    /// value and returns a boxed Rust closure of the exact author-declared
    /// signature. Author-declared native code that flows through the same
    /// `FfiInterface` trust gate as every other wrapper — the driver merges the
    /// manifest entry into the inspection document, so user `.ipe` source can
    /// never mint it.
    ClosureAdapter {
        /// The parsed, validated target signature. The emitter renders from
        /// this alone — no raw manifest string reaches generated Rust.
        sig: ClosureSig,
    },
    /// A `[rust.define.struct]` definition + constructor: Ipê DEFINES a nominal
    /// Rust type (a record of owned, Ipê-coercible carrier fields, with an
    /// allowlisted `#[derive]` set) plus a constructor wrapper that builds it
    /// from decode-validated inbound values — the exact `EnumCtor`/`FieldSet`
    /// inbound path generalised to a struct literal. Author-declared native code
    /// that flows through the same `FfiInterface` trust gate as every other
    /// wrapper; user `.ipe` source can never mint it.
    StructCtor {
        /// The parsed, validated struct definition. The emitter renders the
        /// `#[derive]`ed definition + the constructor body from this alone — no
        /// raw manifest string reaches generated Rust.
        def: StructDef,
    },
    /// A `[rust.define.enum]` definition + per-variant constructors: Ipê DEFINES
    /// a nominal Rust `enum` (a sum of unit / tuple-payload variants over owned
    /// carriers, with an allowlisted `#[derive]` set) plus one constructor
    /// wrapper per variant — the `StructCtor` path generalised to a sum, and the
    /// `EnumCtor` inbound coercion generalised to an author-defined enum. This is
    /// the shape an Iced/TEA `Message` needs. Author-declared native code that
    /// flows through the same `FfiInterface` trust gate as every other wrapper;
    /// user `.ipe` source can never mint it.
    EnumDefCtor {
        /// The parsed, validated enum definition. The emitter renders the
        /// `#[derive]`ed definition + each variant constructor from this alone —
        /// no raw manifest string reaches generated Rust.
        def: EnumDef,
    },
}

/// One foreign parameter or result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    /// The parameter name (may be empty). Ipê-facing data, never rendered as
    /// Rust code.
    pub name: String,
    /// The foreign Rust type string, verbatim from the inspector. Ipê-facing
    /// data: it drives `foreign_to_ipe` and the opaque-path map, never renders
    /// as Rust code.
    pub foreign_ty: String,
    /// The inspector's Ipê-side type override (empty ⇒ derive from
    /// `foreign_ty`). Ipê-facing data, never rendered as Rust code.
    pub ipe_type: String,
    /// The inspector's Rust-side type override for wrapper emission — a
    /// validated type expression when present, so it renders verbatim without
    /// opening a statement. `None` ⇒ no override.
    pub rust_type: Option<RustTypeExpr>,
}

impl Param {
    /// The Rust-type override as a string, or `""` when absent — the shape the
    /// wrapper emitter's string-level helpers consume.
    #[must_use]
    pub fn rust_type_str(&self) -> &str {
        self.rust_type.as_ref().map_or("", RustTypeExpr::as_str)
    }
}

/// A parametric generic block: type-param names, per-param trait bounds, and
/// the validated call AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericFn {
    /// Type-param names in Ipê-source order (positional with call param refs).
    pub params: Vec<String>,
    /// Per-param trait bound names.
    pub bounds: BTreeMap<String, Vec<String>>,
    /// The validated call AST.
    pub call: Call,
}

/// One bindable foreign function, fully validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FnInfo {
    name: RustIdent,
    params: Vec<Param>,
    results: Vec<Param>,
    variadic: bool,
    effect: Effect,
    recv_type: String,
    recv_rust_type: Option<RustTypeExpr>,
    method_name: String,
    shape: FnShape,
    fallibility: Fallibility,
    self_returning: bool,
    generic: Option<GenericFn>,
    call_path: String,
}

impl FnInfo {
    /// The inspector-assigned function name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// The disambiguated wrapper-reference name (the tri-artifact key).
    #[must_use]
    pub fn wrapper_ref_name(&self) -> String {
        wrapper_ref_name(self.name.as_str(), &self.recv_type)
    }

    /// The receiver type name (empty for a free function).
    #[must_use]
    pub fn recv_type(&self) -> &str {
        &self.recv_type
    }

    /// The receiver's Rust type override (empty when unknown).
    #[must_use]
    pub fn recv_rust_type(&self) -> &str {
        self.recv_rust_type
            .as_ref()
            .map_or("", RustTypeExpr::as_str)
    }

    /// The host method name (empty for a free function).
    #[must_use]
    pub fn method_name(&self) -> &str {
        &self.method_name
    }

    /// The foreign parameters.
    #[must_use]
    pub fn params(&self) -> &[Param] {
        &self.params
    }

    /// The foreign results.
    #[must_use]
    pub fn results(&self) -> &[Param] {
        &self.results
    }

    /// Whether the last foreign param is variadic.
    #[must_use]
    pub const fn variadic(&self) -> bool {
        self.variadic
    }

    /// The inspector's effect classification.
    #[must_use]
    pub const fn effect(&self) -> Effect {
        self.effect
    }

    /// The collapsed accessor shape.
    #[must_use]
    pub const fn shape(&self) -> &FnShape {
        &self.shape
    }

    /// The single stored fallibility bit (both emitters read this).
    #[must_use]
    pub const fn fallibility(&self) -> Fallibility {
        self.fallibility
    }

    /// Whether the method is an owned-threading setter (`&mut self` receiver
    /// whose wrapper moves, mutates, and returns the receiver).
    #[must_use]
    pub const fn self_returning(&self) -> bool {
        self.self_returning
    }

    /// Whether the method is a by-borrow reader whose receiver must be threaded
    /// back out beside the result.
    ///
    /// True for an ordinary ([`FnShape::Plain`]) instance method whose receiver
    /// is taken by borrow (`&self`/`&mut self` — the `self` param's Rust type
    /// begins with `&`) and does NOT already return the receiver
    /// ([`Self::self_returning`]). For such a method the wrapper appends the
    /// receiver to its result, so the Ipê surface binds `T -> Result Error
    /// (R, T)` and the caller can flow a non-`Clone` foreign handle on without a
    /// clone or the `IPE-L0130` linearity gate.
    ///
    /// A method that itself returns the receiver type (a `Self`-returning
    /// builder) is excluded — threading the receiver back would duplicate it.
    #[must_use]
    pub fn is_borrow_reader(&self) -> bool {
        if !matches!(self.shape, FnShape::Plain) || self.self_returning {
            return false;
        }
        let Some(recv) = self.params.first() else {
            return false;
        };
        let is_instance =
            !self.recv_type.is_empty() && !self.method_name.is_empty() && recv.name == "self";
        if !is_instance || !recv.rust_type_str().trim_start().starts_with('&') {
            return false;
        }
        // The `to_string` Display bridge takes `impl Display`, not the receiver
        // handle — it is a value conversion, not a handle reader, so it never
        // threads a receiver back.
        if self.method_name == "to_string" {
            return false;
        }
        // Exclude a `Self`-returning reader: the sole non-error result already
        // IS the receiver, so there is nothing extra to thread back.
        let sole_result_is_self = match self
            .results
            .iter()
            .filter(|r| r.foreign_ty != "error")
            .collect::<Vec<_>>()
            .as_slice()
        {
            [r] => {
                r.ipe_type == self.recv_type
                    || (r.ipe_type.is_empty() && r.foreign_ty == self.recv_type)
            }
            _ => false,
        };
        !sole_result_is_self
    }

    /// The parametric generic block, when present.
    #[must_use]
    pub const fn generic(&self) -> Option<&GenericFn> {
        self.generic.as_ref()
    }

    /// Crate-relative call path for a submodule free fn (empty otherwise).
    #[must_use]
    pub fn call_path(&self) -> &str {
        &self.call_path
    }
}

/// One resolved crate from the introspection probe's `cargo metadata`.
///
/// Maps the lib identifier to the canonical package name + exact locked
/// version. The manifest emitter reads this so it never guesses `_`→`-` or
/// emits `"*"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitiveDep {
    /// The Rust lib-target identifier (the `::<ident>::…` path segment).
    pub ident: RustIdent,
    /// The canonical package name (the Cargo `[dependencies]` key). Validated
    /// at decode so it cannot break out of the TOML key position when the
    /// manifest emitter renders `<name> = "=<version>"`.
    pub name: PackageName,
    /// The exact resolved version, validated at decode so it cannot break out
    /// of its TOML string when the manifest emitter pins it.
    pub version: CrateVersion,
}

/// A validated cargo PACKAGE name: `[A-Za-z0-9_-]+`. Distinct from
/// [`RustIdent`] — a package name legitimately carries dashes
/// (`async-stripe`); its LIB identifier is the underscored form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageName(String);

impl PackageName {
    /// Validate and wrap a Cargo package name.
    ///
    /// # Errors
    ///
    /// [`crate::diag::WireDefect::InvalidIdent`] when the string is empty, does
    /// not start with an ASCII letter, or contains anything outside
    /// `[A-Za-z0-9_-]`.
    pub fn parse(s: &str) -> Result<Self, crate::diag::WireDefect> {
        let legal = !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
        if legal {
            Ok(Self(s.to_owned()))
        } else {
            Err(crate::diag::WireDefect::InvalidIdent { got: s.to_owned() })
        }
    }

    /// The validated package name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated resolved crate version.
///
/// The version is the ONLY path by which a resolved-dependency string reaches
/// a TOML value position of the emitted `Cargo.toml`: the manifest emitter
/// renders `<name> = "=<version>"` (and the `version = "=<version>"` features
/// branch) from it. A raw, unvalidated version could carry a `"`-and-newline
/// payload that closes the TOML string and splices arbitrary manifest content
/// (`[dependencies.evil]`, a path override) into the generated file. Gating
/// here at the decode boundary — the same surface [`PackageName`] and
/// [`PkgPath`] are gated on — makes an injection-bearing version
/// unrepresentable past decode.
///
/// The value is parsed as a `SemVer` version, `MAJOR.MINOR.PATCH[-PRE][+BUILD]`,
/// never as requirement text: the emitter prefixes `=`, and `=` followed by a
/// `SemVer` version is always a requirement Cargo accepts, while requirement
/// text (`*`, `=1`, `>=1, <2`) after that `=` is one Cargo refuses.
///
/// An EMPTY version is legal here — the inspector reports an empty version on a
/// probe failure, and the manifest emitter's own downstream check refuses to
/// pin an empty version loudly ([`crate::driver::cargo_dep_lines`]); rejecting
/// it at decode would turn that precise "unpinned dependency" diagnostic into a
/// blunt whole-package decode failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateVersion(String);

/// Whether `c` may appear in a crate-version requirement value.
///
/// The requirement charset `[0-9A-Za-z.*=<>~^,+ -]` of
/// [`crate::driver::VersionPin`] (the CLI `name@version` boundary). A
/// requirement is spliced into a TOML value position of the inspector's probe
/// manifest; every character outside this set (quote, bracket, brace,
/// backslash, control, …) is excluded so a value can never close its string
/// and inject manifest content.
pub(crate) const fn version_char_is_legal(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '.' | '-' | '+' | '*' | '=' | '>' | '<' | '~' | '^' | ',' | ' '
        )
}

impl CrateVersion {
    /// Parse a crate version: a `SemVer` version, or empty.
    ///
    /// # Errors
    ///
    /// [`crate::diag::WireDefect::InvalidVersion`] when non-empty text is not a
    /// `SemVer` version `MAJOR.MINOR.PATCH[-PRE][+BUILD]`.
    pub fn parse(s: &str) -> Result<Self, crate::diag::WireDefect> {
        if s.is_empty() || is_semver_version(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(crate::diag::WireDefect::InvalidVersion { got: s.to_owned() })
        }
    }

    /// The validated version text (may be empty on inspector probe failure).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the version is empty (an unresolved probe).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Whether `s` is a `SemVer` version `MAJOR.MINOR.PATCH[-PRE][+BUILD]`.
///
/// The grammar is the one Cargo's `semver` crate reads after `=`: three
/// `u64` numeric identifiers without leading zeros, then optional dot-separated
/// pre-release and build identifiers over `[0-9A-Za-z-]`, where a numeric
/// pre-release identifier carries no leading zero.
fn is_semver_version(s: &str) -> bool {
    let (rest, build) = s.split_once('+').map_or((s, None), |(r, b)| (r, Some(b)));
    let (core, pre) = rest
        .split_once('-')
        .map_or((rest, None), |(c, p)| (c, Some(p)));
    let mut parts = core.split('.');
    let core_legal = matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(major), Some(minor), Some(patch), None)
            if [major, minor, patch].into_iter().all(is_numeric_identifier)
    );
    core_legal
        && pre.is_none_or(|p| p.split('.').all(is_prerelease_identifier))
        && build.is_none_or(|b| b.split('.').all(is_build_identifier))
}

/// Whether `s` is a `SemVer` numeric identifier: a `u64` with no leading zero.
fn is_numeric_identifier(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'))
        && s.parse::<u64>().is_ok()
}

/// Whether `s` is a `SemVer` pre-release identifier.
///
/// A non-empty `[0-9A-Za-z-]` run; an all-digit one is a numeric identifier.
fn is_prerelease_identifier(s: &str) -> bool {
    if s.bytes().all(|b| b.is_ascii_digit()) {
        is_numeric_identifier(s)
    } else {
        is_build_identifier(s)
    }
}

/// Whether `s` is a `SemVer` build identifier: a non-empty `[0-9A-Za-z-]` run.
fn is_build_identifier(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A validated inspector-reported package path.
///
/// The crate name or `--manifest` path the inspector was invoked with,
/// echoed back on the wire. Free-form text (it may carry `/`, `.`, `@`,
/// spaces — a manifest path is not a bare identifier), but never a control
/// character.
///
/// This is the only path by which `pkg` reaches emitted code: it is
/// interpolated verbatim into two `//` comment lines of the unsandboxed
/// `_bindings.rs` written into the user's crate
/// ([`crate::bindings::emit_bindings`]). A raw, unvalidated string there
/// would let an embedded `\n` close the comment and splice compilable Rust
/// source into it. Every other consumer of `pkg_path` (`rust_module_name`,
/// `rust_kernel_name`, `pkg_to_crate_import`) already maps non-alphanumerics
/// to `_`; gating here at the decode boundary keeps the invariant enforced
/// once, consistent with the rest of this module's parse-don't-validate
/// newtypes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkgPath(String);

impl PkgPath {
    fn parse(s: &str) -> Result<Self, crate::diag::WireDefect> {
        if s.chars().any(char::is_control) {
            Err(crate::diag::WireDefect::InvalidPkgPath { got: s.to_owned() })
        } else {
            Ok(Self(s.to_owned()))
        }
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// A decode-validated filesystem path to an author-supplied wrapper crate.
///
/// Never empty: a package with no wrapper is [`PkgSource::Registry`], not an
/// empty path. A control character is refused (no path the inspector reports
/// carries one), and a `..` component (split on `/` or `\`) is refused
/// outright, so no lexical traversal survives decode. Every other character a
/// real directory name can hold (`+`, a quote, non-ASCII letters) is admitted:
/// the `path` dependency value is rendered as an escaped TOML basic string, so
/// no character here reaches the emitted manifest raw. The path is NOT yet
/// proven to sit inside the project: only [`WrapperCratePath::jail`] yields the
/// [`JailedWrapperDir`] a `path` dependency line is rendered from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapperCratePath(String);

/// The read ceiling for a wrapper crate's `Cargo.toml`, in bytes.
pub const WRAPPER_MANIFEST_LIMIT: u64 = 1024 * 1024;

impl WrapperCratePath {
    /// Validate and wrap a wrapper-crate path.
    ///
    /// # Errors
    ///
    /// [`WireDefect::InvalidPkgPath`] when the path is empty or carries a
    /// control character; [`WireDefect::WrapperPathTraversal`] when a
    /// component is `..`.
    pub fn parse(s: &str) -> Result<Self, WireDefect> {
        if s.is_empty() || s.chars().any(char::is_control) {
            return Err(WireDefect::InvalidPkgPath { got: s.to_owned() });
        }
        if s.split(['/', '\\']).any(|seg| seg == "..") {
            return Err(WireDefect::WrapperPathTraversal { got: s.to_owned() });
        }
        Ok(Self(s.to_owned()))
    }

    /// The decode-validated (not yet root-jailed) wrapper-crate path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Prove the wrapper crate sits inside `project_root` and is the crate cargo builds.
    ///
    /// The proof is taken at load time, when the installed crate is read back
    /// for a build: both sides are canonicalized, so a symlink (at any
    /// component) that leads out of the project, an absolute path elsewhere,
    /// and a stale absolute path left by a moved or copied project are all
    /// refused. A relative path resolves against the project root. The
    /// canonical form must be UTF-8 without control characters; on Windows its
    /// verbatim drive prefix (`\\?\C:`) is converted to the plain drive form
    /// only when the plain form canonicalizes back to the same directory. The
    /// directory's `Cargo.toml` is then read (a regular file, never followed
    /// through a symlink, at most [`WRAPPER_MANIFEST_LIMIT`] bytes) and its
    /// `[package] name` parsed into the [`PackageName`] the dependency key is
    /// rendered from.
    ///
    /// # Errors
    ///
    /// [`WireDefect::WrapperPathUnresolvable`] when the root or the wrapper
    /// directory does not resolve to an existing directory;
    /// [`WireDefect::WrapperPathOutsideRoot`] when the resolved directory
    /// leaves the root; [`WireDefect::WrapperPathUnrenderable`] when the
    /// canonical directory has no plain UTF-8 form;
    /// [`WireDefect::WrapperManifest`] when its `Cargo.toml` is missing,
    /// unreadable, not a regular file, oversized, or lacks a legal
    /// `[package] name`.
    pub fn jail(&self, project_root: &std::path::Path) -> Result<JailedWrapperDir, WireDefect> {
        let unresolvable = |detail: String| WireDefect::WrapperPathUnresolvable {
            got: self.0.clone(),
            detail,
        };
        let root = std::fs::canonicalize(project_root).map_err(|e| unresolvable(e.to_string()))?;
        let resolved =
            std::fs::canonicalize(root.join(&self.0)).map_err(|e| unresolvable(e.to_string()))?;
        if !resolved.starts_with(&root) {
            return Err(WireDefect::WrapperPathOutsideRoot {
                got: self.0.clone(),
                root: root.to_string_lossy().into_owned(),
            });
        }
        let metadata = std::fs::metadata(&resolved).map_err(|e| unresolvable(e.to_string()))?;
        if !metadata.is_dir() {
            return Err(unresolvable("not a directory".to_owned()));
        }
        let path =
            plain_path_text(&resolved).ok_or_else(|| WireDefect::WrapperPathUnrenderable {
                got: self.0.clone(),
                canonical: resolved.to_string_lossy().into_owned(),
            })?;
        let package =
            read_wrapper_package(&resolved).map_err(|defect| WireDefect::WrapperManifest {
                got: self.0.clone(),
                defect,
            })?;
        Ok(JailedWrapperDir { path, package })
    }
}

/// The plain UTF-8 text of a canonical directory, if it has one.
///
/// A path with no prefix is taken as is. A Windows verbatim drive prefix
/// (`\\?\C:`) becomes the plain drive form, accepted only when that plain
/// form canonicalizes back to the same directory (a component a plain path
/// cannot name, such as a trailing dot, fails the proof). Every other prefix
/// (a UNC share, a device namespace), a non-UTF-8 path, and a path carrying a
/// control character yield `None`.
fn plain_path_text(resolved: &std::path::Path) -> Option<String> {
    use std::path::{Component, Prefix};
    let mut components = resolved.components();
    let plain = match components.clone().next() {
        Some(Component::Prefix(prefix)) => {
            let Prefix::VerbatimDisk(letter) = prefix.kind() else {
                return None;
            };
            components.next();
            let mut plain = std::path::PathBuf::from(format!("{}:\\", char::from(letter)));
            plain.extend(components.filter(|c| !matches!(c, Component::RootDir)));
            let same = std::fs::canonicalize(&plain).is_ok_and(|back| back == resolved);
            if !same {
                return None;
            }
            plain
        }
        _ => resolved.to_path_buf(),
    };
    let text = plain.to_str()?;
    if text.chars().any(char::is_control) {
        return None;
    }
    Some(text.to_owned())
}

/// The `[package]` table of a wrapper crate's `Cargo.toml`, as far as the jail reads it.
#[derive(serde::Deserialize)]
struct WrapperCargoManifest {
    package: WrapperCargoPackage,
}

/// The `[package] name` of a wrapper crate's `Cargo.toml`.
#[derive(serde::Deserialize)]
struct WrapperCargoPackage {
    name: String,
}

/// Read and parse the `[package] name` of the `Cargo.toml` in `dir`.
///
/// The manifest is opened without following a symlink at its final
/// component, must be a regular file, and is read up to
/// [`WRAPPER_MANIFEST_LIMIT`] bytes; one byte more is refused as oversized.
fn read_wrapper_package(
    dir: &std::path::Path,
) -> Result<PackageName, crate::diag::WrapperManifestDefect> {
    use crate::diag::WrapperManifestDefect as Defect;
    use std::io::Read as _;
    let unreadable = |e: std::io::Error| Defect::Unreadable {
        detail: e.to_string(),
    };
    let file = open_manifest_no_follow(&dir.join("Cargo.toml"))?;
    let metadata = file.metadata().map_err(unreadable)?;
    if !metadata.is_file() {
        return Err(Defect::NotRegularFile);
    }
    let oversized = Defect::Oversized {
        limit: WRAPPER_MANIFEST_LIMIT,
    };
    if metadata.len() > WRAPPER_MANIFEST_LIMIT {
        return Err(oversized);
    }
    let mut bytes = Vec::new();
    file.take(WRAPPER_MANIFEST_LIMIT.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if !u64::try_from(bytes.len()).is_ok_and(|n| n <= WRAPPER_MANIFEST_LIMIT) {
        return Err(oversized);
    }
    let text = String::from_utf8(bytes).map_err(|e| Defect::Invalid {
        detail: e.to_string(),
    })?;
    let manifest: WrapperCargoManifest = toml::from_str(&text).map_err(|e| Defect::Invalid {
        detail: e.message().to_owned(),
    })?;
    let found = manifest.package.name;
    PackageName::parse(&found).map_err(|_| Defect::PackageNameIllegal { found })
}

/// Open `path` read-only without following a symlink at its final component.
///
/// `O_NONBLOCK` keeps a FIFO planted in place of the manifest from blocking
/// the open; the caller's regular-file check then refuses it.
#[cfg(unix)]
fn open_manifest_no_follow(
    path: &std::path::Path,
) -> Result<std::fs::File, crate::diag::WrapperManifestDefect> {
    use crate::diag::WrapperManifestDefect as Defect;
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    rustix::fs::open(path, flags, Mode::empty())
        .map(std::fs::File::from)
        .map_err(|errno| {
            let is_link = std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink());
            if is_link {
                Defect::NotRegularFile
            } else {
                Defect::Unreadable {
                    detail: std::io::Error::from(errno).to_string(),
                }
            }
        })
}

/// Open `path` read-only, refusing a reparse point at its final component.
#[cfg(windows)]
fn open_manifest_no_follow(
    path: &std::path::Path,
) -> Result<std::fs::File, crate::diag::WrapperManifestDefect> {
    use crate::diag::WrapperManifestDefect as Defect;
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    /// `FILE_FLAG_OPEN_REPARSE_POINT`: opens a reparse point itself, never its target.
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    /// `FILE_ATTRIBUTE_REPARSE_POINT`.
    const ATTR_REPARSE_POINT: u32 = 0x400;
    let unreadable = |e: std::io::Error| Defect::Unreadable {
        detail: e.to_string(),
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_REPARSE_POINT)
        .open(path)
        .map_err(unreadable)?;
    let attributes = file.metadata().map_err(unreadable)?.file_attributes();
    if attributes & ATTR_REPARSE_POINT == 0 {
        Ok(file)
    } else {
        Err(Defect::NotRegularFile)
    }
}

/// Refuse: this platform has no symlink-refusing open.
#[cfg(not(any(unix, windows)))]
fn open_manifest_no_follow(
    _path: &std::path::Path,
) -> Result<std::fs::File, crate::diag::WrapperManifestDefect> {
    Err(crate::diag::WrapperManifestDefect::Unreadable {
        detail: "this platform has no symlink-refusing open".to_owned(),
    })
}

/// A wrapper-crate directory proven, at load, to be the crate cargo builds.
///
/// The only value a `path = "…"` dependency line is rendered from. It holds
/// the plain canonical absolute path (inside the project root) and the
/// `[package] name` its `Cargo.toml` declares, so the dependency key and the
/// crate cargo finds at the path cannot disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JailedWrapperDir {
    path: String,
    package: PackageName,
}

impl JailedWrapperDir {
    /// The plain canonical absolute wrapper directory.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.path
    }

    /// The `[package] name` the wrapper's `Cargo.toml` declares.
    #[must_use]
    pub const fn package(&self) -> &PackageName {
        &self.package
    }
}

/// Where an inspected package's Rust code comes from.
///
/// Decided once at decode, so every consumer matches exhaustively: no empty
/// path can be mistaken for a registry pin, and no registry package can carry
/// a local path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PkgSource {
    /// An ordinary crates.io / git inspection, pinned by exact version.
    Registry,
    /// An author-supplied local wrapper crate, bound by `path`.
    Wrapper(WrapperCratePath),
}

/// A validated Cargo feature name.
///
/// Each effective feature is spliced into a `features = [ … ]` array (a TOML
/// string position) of the emitted `Cargo.toml` by
/// [`crate::driver::cargo_dep_lines`]. A raw, unvalidated feature could carry a
/// `"`-and-newline (or `]`/`}`) payload that closes the array + inline table
/// and injects arbitrary manifest content (`[dependencies.evil]`, a `path`
/// override). Gating here at the decode boundary — the same surface
/// [`PackageName`], [`PkgPath`] and [`CrateVersion`] are gated on — makes an
/// injection-bearing feature unrepresentable past decode. The charset admits
/// Cargo's dependency-feature syntax (`dep:foo`, `foo/bar`, `dep?/feat`) while
/// excluding every TOML-breaking character (quote, bracket, brace, backslash,
/// control), so a name can never escape its string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FeatureName(String);

impl FeatureName {
    /// Validate and wrap a Cargo feature name.
    ///
    /// The one gate for every path a feature reaches the emitted manifest by:
    /// the wire-decode boundary ([`PkgInfo`]'s effective feature set) and the
    /// `ipe add --features` CLI argument both route through it.
    ///
    /// # Errors
    ///
    /// [`crate::diag::WireDefect::InvalidFeature`] when the name is empty or
    /// carries a character outside `[A-Za-z0-9_+./?:-]` (every TOML-breaking
    /// character — quote, bracket, brace, backslash, control — is excluded).
    pub fn parse(s: &str) -> Result<Self, crate::diag::WireDefect> {
        let legal = !s.is_empty()
            && s.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '.' | '/' | '?' | ':')
            });
        if legal {
            Ok(Self(s.to_owned()))
        } else {
            Err(crate::diag::WireDefect::InvalidFeature { got: s.to_owned() })
        }
    }

    /// The validated feature name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One inspected public constant, validated at the decode boundary.
///
/// A crate-relative Rust path whose every segment is a legal identifier, and
/// the constant's verbatim Rust type. The `Rust.const` surface reads this to
/// confirm an author's asserted scalar type against the real constant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstInfo {
    path: String,
    ty: String,
}

impl ConstInfo {
    /// The constant's crate-relative path (`f64::consts::PI`).
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The constant's Rust type, verbatim from the inspection (`f64`).
    #[must_use]
    pub fn rust_type(&self) -> &str {
        &self.ty
    }
}

/// A fully-validated package inspection result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkgInfo {
    pkg_path: PkgPath,
    name: PackageName,
    version: CrateVersion,
    fns: Vec<FnInfo>,
    consts: Vec<ConstInfo>,
    modules: Vec<String>,
    errors: Vec<String>,
    notes: Vec<String>,
    transitive_deps: Vec<TransitiveDep>,
    features: Vec<FeatureName>,
    /// Rendered foreign-nominal path (`::`-prefixed) -> the type's canonical
    /// DEFINING path (the rustdoc `paths` identity, identical in every crate
    /// that can see the type). The catalog unification keys cross-crate
    /// nominal identity on the value. Entries failing the path-shape
    /// validation are dropped at decode (no identity claim survives
    /// unvalidated; absence only disables unification, never soundness).
    foreign_type_ids: std::collections::BTreeMap<String, String>,
    /// The decoded transparent-or-opaque representation axis: which reported
    /// foreign types surface structurally (record / closed union) and why each
    /// remaining reported type stays an opaque handle. Classified ONCE here at
    /// the decode boundary; every emitter reads this same decision.
    foreign_types: crate::transparency::ForeignTypeCatalog,
    /// Author-declared opaque handles: Ipê handle nominal → absolute Rust path
    /// (`::crate::Type`). Each names a reported crate type the author minted a
    /// handle over via `foreign X = { kind = Opaque "Type" }`; the interface
    /// unions these into the crate's opaque map so the nominal exists even when
    /// no binding references it yet. Every path passed the `::seg::…::Seg`
    /// shape gate at decode (a malformed entry is dropped, never emitted raw).
    declared_opaques: std::collections::BTreeMap<String, String>,
    /// Where the package's Rust code comes from: a registry pin, or an
    /// author-supplied wrapper crate the emitted app crate depends on by `path`
    /// (see [`crate::driver::cargo_dep_lines`]).
    source: PkgSource,
    dropped: Vec<Diagnostic>,
}

impl PkgInfo {
    /// Decode one `PkgInfo` JSON document (the inspector's single-crate
    /// output) through the validating domain conversion.
    ///
    /// # Errors
    ///
    /// A package-level defect (JSON shape, illegal crate name) fails the
    /// decode. A function-level defect drops that one binding into
    /// [`PkgInfo::dropped`] — over-drop, never under-bind.
    pub fn decode_json(text: &str) -> Result<Self, Diagnostic> {
        let wire: WirePkgInfo =
            serde_json::from_str(text).map_err(|e| Diagnostic::WireMalformed {
                context: "package inspection document".to_owned(),
                defect: WireDefect::Json {
                    detail: e.to_string(),
                },
            })?;
        Self::try_from(wire)
    }

    /// The crate path as given to the inspector.
    #[must_use]
    pub fn pkg_path(&self) -> &str {
        self.pkg_path.as_str()
    }

    /// The validated crate name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// The validated crate name as the charset-gated newtype — the only value
    /// permitted to reach the manifest emitter's TOML dependency-KEY position
    /// (`<name> = "=<version>"`). Deriving the key from anything but this typed
    /// name (e.g. the weakly gated [`Self::pkg_path`]) would let an
    /// attacker-influenced string reach the key position; the type forbids it.
    #[must_use]
    pub const fn name_pkg(&self) -> &PackageName {
        &self.name
    }

    /// The exact resolved crate version (may be empty on inspector failure).
    #[must_use]
    pub fn version(&self) -> &str {
        self.version.as_str()
    }

    /// The validated resolved crate version — the only value that can reach the
    /// manifest emitter's TOML-value position.
    #[must_use]
    pub const fn crate_version(&self) -> &CrateVersion {
        &self.version
    }

    /// The validated bindable functions.
    #[must_use]
    pub fn fns(&self) -> &[FnInfo] {
        &self.fns
    }

    /// The validated inspected public constants (the `Rust.const` cross-check).
    #[must_use]
    pub fn consts(&self) -> &[ConstInfo] {
        &self.consts
    }

    /// Public module paths to glob-import in generated wrappers.
    #[must_use]
    pub fn modules(&self) -> &[String] {
        &self.modules
    }

    /// The inspector's fail-closed error channel. Non-empty means the
    /// inspection is unusable; the driver refuses to emit from it.
    #[must_use]
    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    /// Diagnostic notes for the `ipe add` user.
    #[must_use]
    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// Every crate resolved by the introspection probe.
    #[must_use]
    pub fn transitive_deps(&self) -> &[TransitiveDep] {
        &self.transitive_deps
    }

    /// The effective feature set the introspection succeeded with.
    #[must_use]
    pub fn features(&self) -> &[FeatureName] {
        &self.features
    }

    /// Rendered foreign-nominal path (`::`-prefixed) -> defining-path identity.
    #[must_use]
    pub const fn foreign_type_ids(&self) -> &std::collections::BTreeMap<String, String> {
        &self.foreign_type_ids
    }

    /// The decoded transparent-or-opaque representation axis for this
    /// package's reported foreign types.
    #[must_use]
    pub const fn foreign_types(&self) -> &crate::transparency::ForeignTypeCatalog {
        &self.foreign_types
    }

    /// Author-declared opaque handles: Ipê handle nominal → absolute Rust path.
    /// The interface unions these into the crate's opaque map so a declared
    /// handle exists as a nominal even before any binding references it.
    #[must_use]
    pub const fn declared_opaques(&self) -> &std::collections::BTreeMap<String, String> {
        &self.declared_opaques
    }

    /// Where the package's Rust code comes from.
    #[must_use]
    pub const fn source(&self) -> &PkgSource {
        &self.source
    }

    /// The bindings dropped by the validating conversion, with the reason
    /// each was refused — the over-drop keystone made visible.
    #[must_use]
    pub fn dropped(&self) -> &[Diagnostic] {
        &self.dropped
    }
}

/// Decode the wire `declaredOpaques` map (Ipê handle nominal → Rust path).
///
/// A declared opaque path reaches the wrapper emitter verbatim (as a `type X =
/// <path>` alias body), so a malformed or injection-bearing path fails the WHOLE
/// package here rather than reaching the emitter. Unlike `foreignTypeIds`
/// (metadata whose absence only disables unification), a declared opaque is
/// load-bearing — a dropped entry would silently leave a referenced handle
/// unresolved, so an ill-shaped path refuses instead of dropping.
fn decode_declared_opaques(
    raw: std::collections::BTreeMap<String, String>,
    crate_name: &str,
) -> Result<std::collections::BTreeMap<String, String>, Diagnostic> {
    let mut out = std::collections::BTreeMap::new();
    for (name, path) in raw {
        if !path.strip_prefix("::").is_some_and(is_rust_path_shaped) {
            return Err(Diagnostic::WireMalformed {
                context: format!("crate `{crate_name}` declared opaque `{name}`"),
                defect: WireDefect::Json {
                    detail: format!("`{path}` is not an absolute `::seg::…::Seg` Rust path"),
                },
            });
        }
        out.insert(name, path);
    }
    Ok(out)
}

/// `true` when `s` is `seg::…::Seg` with every segment a legal Rust
/// identifier (ASCII letter/underscore head, alphanumeric/underscore tail).
fn is_rust_path_shaped(s: &str) -> bool {
    !s.is_empty()
        && s.split("::").all(|seg| {
            let mut chars = seg.chars();
            chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

fn decode_effect(function: &str, s: &str) -> Result<Effect, Diagnostic> {
    match s {
        "pure" => Ok(Effect::Pure),
        "fallible" => Ok(Effect::Fallible),
        "effectful" => Ok(Effect::Effectful),
        _ => Err(Diagnostic::WireMalformed {
            context: format!("function `{function}`"),
            defect: WireDefect::UnknownEffect { got: s.to_owned() },
        }),
    }
}

fn decode_variant_kind(function: &str, s: &str) -> Result<EnumVariantKind, Diagnostic> {
    match s {
        "unit" => Ok(EnumVariantKind::Unit),
        "tuple" => Ok(EnumVariantKind::Tuple),
        "struct" => Ok(EnumVariantKind::Struct),
        _ => Err(Diagnostic::WireMalformed {
            context: format!("function `{function}`"),
            defect: WireDefect::Json {
                detail: format!(
                    "unknown enum variant kind {s:?} (expected \"unit\", \"tuple\", or \"struct\")"
                ),
            },
        }),
    }
}

fn decode_arms(function: &str, arms: Vec<String>) -> Result<Vec<EnumArm>, Diagnostic> {
    let context = |defect: WireDefect| Diagnostic::WireMalformed {
        context: format!("function `{function}`"),
        defect,
    };
    arms.into_iter()
        .map(|raw| {
            let (pattern, tag) = raw.split_once('\t').ok_or_else(|| {
                context(WireDefect::Json {
                    detail: format!("enum tag arm {raw:?} is not \"<pattern>\\t<tag>\"-shaped"),
                })
            })?;
            // The pattern renders as code inside the match; validate it.
            let pattern = RustPattern::parse(pattern).map_err(context)?;
            Ok(EnumArm {
                pattern,
                tag: tag.to_owned(),
            })
        })
        .collect()
}

/// Collapse the seven mutually-exclusive accessor flags into the closed shape.
fn decode_shape(w: &WireFunction) -> Result<FnShape, Diagnostic> {
    let flags: [(&'static str, bool); 9] = [
        ("isField", w.is_field),
        ("isFieldSet", w.is_field_set),
        ("isPkgVar", w.is_pkg_var),
        ("isEnumCtor", w.is_enum_ctor),
        ("isEnumTag", w.is_enum_tag),
        ("isEnumExtract", w.is_enum_extract),
        ("isClosureAdapter", w.is_closure_adapter),
        ("isStructCtor", w.is_struct_ctor),
        ("isEnumDef", w.is_enum_def),
    ];
    let set: Vec<&'static str> = flags.iter().filter(|(_, b)| *b).map(|(n, _)| *n).collect();
    if set.len() > 1 {
        return Err(Diagnostic::ShapeContradiction {
            function: w.name.clone(),
            flags: set,
        });
    }
    let wire_err = |defect: WireDefect| Diagnostic::WireMalformed {
        context: format!("function `{}`", w.name),
        defect,
    };
    let ident_field =
        |s: &str| -> Result<RustIdent, Diagnostic> { RustIdent::parse(s).map_err(wire_err) };
    Ok(match set.first().copied() {
        Some("isField") => FnShape::FieldGet,
        Some("isFieldSet") => FnShape::FieldSet,
        Some("isPkgVar") => FnShape::PkgVar,
        Some("isEnumCtor") => {
            // Struct-variant field names render verbatim as Rust field idents.
            let struct_fields: Vec<RustIdent> = w
                .enum_struct_fields
                .iter()
                .map(|f| RustIdent::parse(f))
                .collect::<Result<_, _>>()
                .map_err(wire_err)?;
            FnShape::EnumCtor {
                variant: ident_field(&w.enum_variant)?,
                kind: decode_variant_kind(&w.name, &w.enum_kind)?,
                struct_fields,
            }
        }
        Some("isEnumTag") => FnShape::EnumTag {
            arms: decode_arms(&w.name, w.enum_arms.clone())?,
            wildcard: w.enum_wildcard,
        },
        Some("isEnumExtract") => {
            let selector =
                FieldSelector::parse(w.enum_struct_fields.first().map_or("", String::as_str))
                    .map_err(wire_err)?;
            FnShape::EnumExtract {
                variant: ident_field(&w.enum_variant)?,
                kind: decode_variant_kind(&w.name, &w.enum_kind)?,
                selector,
                field_count: w.enum_field_count,
                wildcard: w.enum_wildcard,
            }
        }
        Some("isClosureAdapter") => {
            // The parsed signature is the SOLE input the emitter renders from;
            // an ill-formed one (a carrier outside the closed set, a bound
            // outside {Send, Sync, 'static}, a non-total return, trailing text)
            // over-drops the whole define entry here, never emit-and-cargo-fail.
            let sig = ClosureSig::parse(&w.closure_sig).map_err(wire_err)?;
            FnShape::ClosureAdapter { sig }
        }
        Some("isStructCtor") => {
            // The parsed definition is the SOLE input the emitter renders from;
            // an ill-formed one (a bad struct/field name, a field type outside
            // the carrier set, a derive outside the allowlist, or a total-Eq
            // derive on a Float field) over-drops the whole define entry here,
            // never emit-and-cargo-fail.
            let raw_fields: Vec<(String, String)> = w
                .struct_ctor_fields
                .iter()
                .map(|f| (f.name.clone(), f.ty.clone()))
                .collect();
            let def = StructDef::parse(&w.struct_name, &raw_fields, &w.struct_derives)
                .map_err(wire_err)?;
            // An opaque field resolves to a crate path only at emit time (the
            // decode boundary has no crate opaque-map). A bare/parameterised
            // handle the crate cannot name over-drops in the emitter (empty
            // wrapper region ⇒ the interface skips the forwarder), so the SEAL
            // holds without a decode-time refusal here.
            FnShape::StructCtor { def }
        }
        Some("isEnumDef") => {
            // The parsed definition is the SOLE input the emitter renders from;
            // an ill-formed one (a bad enum/variant name, a payload type outside
            // the carrier set, a derive outside the allowlist, a total-Eq derive
            // on a Float payload, or a variantless enum) over-drops the whole
            // define entry here, never emit-and-cargo-fail.
            let raw_variants: Vec<(String, Vec<String>)> = w
                .enum_def_variants
                .iter()
                .map(|v| (v.name.clone(), v.payload.clone()))
                .collect();
            let def = EnumDef::parse(&w.enum_def_name, &raw_variants, &w.enum_def_derives)
                .map_err(wire_err)?;
            // An opaque payload resolves to a crate path only at emit time (the
            // decode boundary has no crate opaque-map). A bare/parameterised
            // handle the crate cannot name over-drops in the emitter (empty
            // wrapper region ⇒ the interface skips the forwarders), so the SEAL
            // holds without a decode-time refusal here.
            FnShape::EnumDefCtor { def }
        }
        // No flag set is an ordinary function; every named flag has an explicit
        // arm above, and the filter that produced `set` draws only from those
        // names, so any other `Some` is unreachable — fall back to `Plain`
        // rather than panic.
        None | Some(_) => FnShape::Plain,
    })
}

const fn shape_fallibility(shape: &FnShape, effect: Effect) -> Fallibility {
    match shape {
        // A CHECKED setter (narrowing integer field, wire `effect: fallible`)
        // renders a `Result`-returning wrapper; the surface signature must
        // carry the same layer or the interface and the wrapper disagree at
        // cargo time.
        FnShape::FieldSet if matches!(effect, Effect::Fallible) => Fallibility::TaskError,
        // For `ClosureAdapter`, Infallible names CONSTRUCTION: building the
        // boxed adapter cannot fail, so the wrapper's own return is the bare
        // boxed closure (no `Result` wrapper). This is NOT a claim that CALLING
        // the closure cannot fail — a per-call panic in a `Total` return
        // aborts, and a `Result`/`Option` return folds the failure in-band (see
        // the `ClosureAdapter` emit arm).
        FnShape::FieldGet
        | FnShape::FieldSet
        | FnShape::EnumCtor { .. }
        | FnShape::EnumTag { .. }
        | FnShape::EnumExtract { .. }
        | FnShape::ClosureAdapter { .. }
        // A struct constructor is a total struct literal over decode-validated
        // inbound values — building it cannot fail, so the wrapper's own return
        // is the bare struct (no `Result` wrapper).
        | FnShape::StructCtor { .. }
        // Each enum-variant constructor is a total variant literal over
        // decode-validated inbound values — building it cannot fail either.
        | FnShape::EnumDefCtor { .. } => Fallibility::Infallible,
        FnShape::Plain | FnShape::PkgVar => Fallibility::TaskError,
    }
}

fn param_from_wire(function: &str, w: WireParam) -> Result<Param, Diagnostic> {
    // `rustType` renders verbatim into the wrapper; validate it at decode so an
    // injection-bearing override is unrepresentable past this point. Empty ⇒
    // no override.
    let rust_type = if w.rust_type.is_empty() {
        None
    } else {
        Some(
            RustTypeExpr::parse(&w.rust_type).map_err(|defect| Diagnostic::WireMalformed {
                context: format!("function `{function}`"),
                defect,
            })?,
        )
    };
    Ok(Param {
        name: w.name,
        foreign_ty: w.ty,
        ipe_type: w.ipe_type,
        rust_type,
    })
}

impl TryFrom<WireFunction> for FnInfo {
    type Error = Diagnostic;

    fn try_from(w: WireFunction) -> Result<Self, Diagnostic> {
        let context = |defect: WireDefect| Diagnostic::WireMalformed {
            context: format!("function `{}`", w.name),
            defect,
        };
        let name = RustIdent::parse(&w.name).map_err(&context)?;
        if !w.method_name.is_empty() {
            RustIdent::parse(&w.method_name).map_err(&context)?;
        }
        if !w.call_path.is_empty() {
            crate::naming::IdentPath::parse(&w.call_path).map_err(&context)?;
        }
        let effect = decode_effect(&w.name, &w.effect)?;
        let shape = decode_shape(&w)?;
        let fallibility = shape_fallibility(&shape, effect);
        let generic = match &w.generic {
            None => None,
            Some(g) => {
                let refname = wrapper_ref_name(&w.name, &w.recv_type);
                let call = Call::decode(g.params.len(), g.call.clone(), &refname)?;
                Some(GenericFn {
                    params: g.params.clone(),
                    bounds: g.bounds.clone(),
                    call,
                })
            }
        };
        // The receiver's Rust-type override renders verbatim — validate it.
        let recv_rust_type = if w.recv_rust_type.is_empty() {
            None
        } else {
            Some(RustTypeExpr::parse(&w.recv_rust_type).map_err(&context)?)
        };
        let params = w
            .params
            .into_iter()
            .map(|p| param_from_wire(&w.name, p))
            .collect::<Result<_, _>>()?;
        let results = w
            .results
            .into_iter()
            .map(|p| param_from_wire(&w.name, p))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            name,
            params,
            results,
            variadic: w.variadic,
            effect,
            recv_type: w.recv_type,
            recv_rust_type,
            method_name: w.method_name,
            shape,
            fallibility,
            self_returning: w.self_returning,
            generic,
            call_path: w.call_path,
        })
    }
}

/// The define-type names one def references through its opaque fields/payloads
/// — the outgoing edges of the define-type reference graph. A scalar carrier
/// carries no edge; an opaque carrier names a bare handle that MAY be another
/// define type (resolved by membership in the caller's name set).
fn define_def_edges(shape: &FnShape) -> Vec<&RustIdent> {
    match shape {
        FnShape::StructCtor { def } => def
            .fields
            .iter()
            .filter_map(|(_, c)| match c {
                Carrier::Opaque(id) => Some(id),
                _ => None,
            })
            .collect(),
        FnShape::EnumDefCtor { def } => def
            .variants
            .iter()
            .flat_map(|v| {
                v.payload.iter().filter_map(|c| match c {
                    Carrier::Opaque(id) => Some(id),
                    _ => None,
                })
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// The def name a define-type binding defines, or [`None`] for a non-defining
/// shape.
const fn define_def_name(shape: &FnShape) -> Option<&RustIdent> {
    match shape {
        FnShape::StructCtor { def } => Some(&def.name),
        FnShape::EnumDefCtor { def } => Some(&def.name),
        _ => None,
    }
}

/// The set of define-type names that lie on a cycle in the define-type
/// reference graph (a def whose fields/payloads reach, directly or through
/// other define types, back to itself).
///
/// Edges to names that are NOT define-defined (crate opaques, unresolvable
/// handles) leave the graph and cannot close a cycle, so they are ignored: a
/// name is on a cycle iff it can reach itself through define-defined names
/// only. Computed as the fixed point of "keep only names that both are reached
/// by a live name and reach a live name" — a node survives iff it has an
/// in-edge and an out-edge within the surviving set, which for a finite graph
/// leaves exactly the union of its cycles.
fn recursive_define_names(
    defs: &BTreeMap<String, std::collections::BTreeSet<String>>,
) -> std::collections::BTreeSet<String> {
    // Restrict every edge target to a defined name — an edge leaving the graph
    // can never be part of a cycle.
    let mut out: BTreeMap<String, std::collections::BTreeSet<String>> = defs
        .iter()
        .map(|(name, edges)| {
            (
                name.clone(),
                edges
                    .iter()
                    .filter(|e| defs.contains_key(*e))
                    .cloned()
                    .collect(),
            )
        })
        .collect();
    loop {
        // A node with no out-edge (within the graph) sinks — it ends no cycle.
        // A node no live node points at is a source — it starts no cycle.
        let with_out: std::collections::BTreeSet<String> = out
            .iter()
            .filter(|(_, edges)| !edges.is_empty())
            .map(|(name, _)| name.clone())
            .collect();
        let with_in: std::collections::BTreeSet<String> = out.values().flatten().cloned().collect();
        let live: std::collections::BTreeSet<String> =
            with_out.intersection(&with_in).cloned().collect();
        if live.len() == out.len() {
            return live;
        }
        out = out
            .into_iter()
            .filter(|(name, _)| live.contains(name))
            .map(|(name, edges)| {
                (
                    name,
                    edges.into_iter().filter(|e| live.contains(e)).collect(),
                )
            })
            .collect();
    }
}

/// One representative cycle chain through `start`, for the diagnostic — the
/// first path a depth-first walk closes back onto `start` (every edge target
/// restricted to a recursive name, so the walk stays on the cycle set).
fn cycle_chain_from(
    start: &str,
    edges: &BTreeMap<String, std::collections::BTreeSet<String>>,
    recursive: &std::collections::BTreeSet<String>,
) -> Vec<String> {
    let mut path = vec![start.to_owned()];
    let mut node = start.to_owned();
    let mut guard = recursive.len().saturating_add(1);
    while guard > 0 {
        guard -= 1;
        let Some(next) = edges
            .get(&node)
            .and_then(|es| es.iter().find(|e| recursive.contains(*e)).cloned())
        else {
            break;
        };
        if next == start {
            path.push(next);
            return path;
        }
        if path.contains(&next) {
            path.push(next);
            return path;
        }
        path.push(next.clone());
        node = next;
    }
    path
}

/// Drop every define-type binding whose def lies on a cycle in the define-type
/// reference graph, recording one [`Diagnostic`] per refused def. A non-defining
/// binding (a getter/plain call) is never touched here — the emitter's survivor
/// fixpoint fans the over-drop out to references of a dropped type.
fn drop_recursive_define_defs(fns: &mut Vec<FnInfo>, dropped: &mut Vec<Diagnostic>) {
    let mut edges: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
    for f in fns.iter() {
        if let Some(name) = define_def_name(f.shape()) {
            let deps = define_def_edges(f.shape())
                .into_iter()
                .map(|id| id.as_str().to_owned())
                .collect();
            edges.insert(name.as_str().to_owned(), deps);
        }
    }
    let recursive = recursive_define_names(&edges);
    if recursive.is_empty() {
        return;
    }
    for name in &recursive {
        let cycle = cycle_chain_from(name, &edges, &recursive);
        dropped.push(Diagnostic::WireMalformed {
            context: format!("define type `{name}`"),
            defect: WireDefect::RecursiveDefineType {
                name: name.clone(),
                cycle,
            },
        });
    }
    fns.retain(|f| define_def_name(f.shape()).is_none_or(|n| !recursive.contains(n.as_str())));
}

/// Parse `w`'s three identity fields (package path, crate name, declared
/// version), tagging every failure with the same `WireMalformed` context.
fn decode_identity(w: &WirePkgInfo) -> Result<(PkgPath, PackageName, CrateVersion), Diagnostic> {
    let pkg_path = PkgPath::parse(&w.pkg).map_err(|defect| Diagnostic::WireMalformed {
        context: "package inspection document".to_owned(),
        defect,
    })?;
    let name = PackageName::parse(&w.name).map_err(|defect| Diagnostic::WireMalformed {
        context: format!("crate `{}`", w.name),
        defect,
    })?;
    let version = CrateVersion::parse(&w.version).map_err(|defect| Diagnostic::WireMalformed {
        context: format!("crate `{}`", w.name),
        defect,
    })?;
    Ok((pkg_path, name, version))
}

/// Decode every wire function, collapse duplicate wrapper-reference names,
/// and drop any def caught in a recursive define-type cycle. A defective or
/// over-dropped binding is recorded in the returned diagnostics rather than
/// failing the whole package.
fn decode_functions(functions: Vec<WireFunction>) -> (Vec<FnInfo>, Vec<Diagnostic>) {
    let mut fns = Vec::with_capacity(functions.len());
    let mut dropped = Vec::new();
    for wf in functions {
        match FnInfo::try_from(wf) {
            Ok(f) => fns.push(f),
            // Over-drop: the one defective binding is refused and
            // recorded; every other binding in the package survives.
            Err(d) => dropped.push(d),
        }
    }
    // Collapse duplicate wrapper-reference names at the decode boundary
    // (first wins) so all three emitters see the same deduped list by
    // construction — a real `to_string` colliding with the synthetic
    // Display bridge is one entry, never a duplicate Rust item.
    let mut seen_refs = std::collections::BTreeSet::new();
    fns.retain(|f| seen_refs.insert(f.wrapper_ref_name()));
    // A directly- or mutually-recursive define type has no boxed
    // indirection in the closed carrier set, so emitting it would be an
    // infinitely-sized Rust type (`error[E0072]`). Refuse every def on a
    // cycle here — the def-bearing binding is dropped, and the emitter's
    // survivor fixpoint fans the over-drop out to every reference of it.
    drop_recursive_define_defs(&mut fns, &mut dropped);
    (fns, dropped)
}

/// Decode the reported transitive dependencies, dropping the inspector's own
/// synthetic probe scaffold (never a real registry dependency).
fn decode_transitive_deps(deps: Vec<WireTransitiveDep>) -> Result<Vec<TransitiveDep>, Diagnostic> {
    let mut transitive_deps = Vec::with_capacity(deps.len());
    for dep in deps {
        // The inspector's own probe scaffold registers as a workspace
        // member during introspection; it is a synthetic non-registry
        // package, not a real dependency, so it never becomes a typed
        // `TransitiveDep` (its `_ipe_ffi_probe_…` name is not even a legal
        // `PackageName`). Dropping it here keeps a non-dependency
        // unrepresentable past decode.
        if dep.name.starts_with("_ipe_ffi_probe") {
            continue;
        }
        let ident = RustIdent::parse(&dep.ident).map_err(|defect| Diagnostic::WireMalformed {
            context: format!("transitive dep `{}`", dep.name),
            defect,
        })?;
        let name = PackageName::parse(&dep.name).map_err(|defect| Diagnostic::WireMalformed {
            context: format!("transitive dep `{}`", dep.name),
            defect,
        })?;
        let version =
            CrateVersion::parse(&dep.version).map_err(|defect| Diagnostic::WireMalformed {
                context: format!("transitive dep `{}`", dep.name),
                defect,
            })?;
        transitive_deps.push(TransitiveDep {
            ident,
            name,
            version,
        });
    }
    Ok(transitive_deps)
}

/// Foreign-type identity entries: keep only well-shaped `::seg::…::Seg` keys
/// and `seg::…::Seg` values (every segment a legal Rust ident). A malformed
/// entry is dropped — identity metadata only ever ENABLES nominal
/// unification, so absence is the safe default.
fn decode_foreign_type_ids(
    ids: std::collections::BTreeMap<String, String>,
) -> std::collections::BTreeMap<String, String> {
    ids.into_iter()
        .filter(|(k, v)| {
            k.strip_prefix("::").is_some_and(is_rust_path_shaped) && is_rust_path_shaped(v)
        })
        .collect()
}

/// Each feature is spliced into a `features = [ … ]` array of the emitted
/// `Cargo.toml`; gate it at the boundary so an injection-bearing feature
/// fails the WHOLE package here rather than reaching the emitter.
fn decode_features(
    features: Vec<String>,
    crate_name: &str,
) -> Result<Vec<FeatureName>, Diagnostic> {
    let mut out = Vec::with_capacity(features.len());
    for f in features {
        out.push(
            FeatureName::parse(&f).map_err(|defect| Diagnostic::WireMalformed {
                context: format!("crate `{crate_name}`"),
                defect,
            })?,
        );
    }
    Ok(out)
}

/// The wrapper path is spliced into a `path = "…"` TOML value of the emitted
/// manifest; gate it at the boundary so an injection-bearing path fails the
/// WHOLE package here rather than reaching the emitter.
fn decode_source(wrapper_path: &str, crate_name: &str) -> Result<PkgSource, Diagnostic> {
    if wrapper_path.is_empty() {
        Ok(PkgSource::Registry)
    } else {
        Ok(PkgSource::Wrapper(
            WrapperCratePath::parse(wrapper_path).map_err(|defect| Diagnostic::WireMalformed {
                context: format!("crate `{crate_name}`"),
                defect,
            })?,
        ))
    }
}

/// Inspected constants: keep only a well-shaped crate-relative path
/// (`seg::…::SEG`, every segment a legal Rust ident) with a non-empty
/// recorded type. A malformed entry is dropped — absence only disables a
/// `.const` cross-check (fail-closed), never admits an unverified read.
fn decode_consts(constants: Vec<WireConstant>) -> Vec<ConstInfo> {
    constants
        .into_iter()
        .filter(|c| !c.path.is_empty() && !c.ty.is_empty() && is_rust_path_shaped(&c.path))
        .map(|c| ConstInfo {
            path: c.path,
            ty: c.ty,
        })
        .collect()
}

impl TryFrom<WirePkgInfo> for PkgInfo {
    type Error = Diagnostic;

    fn try_from(w: WirePkgInfo) -> Result<Self, Diagnostic> {
        let (pkg_path, name, version) = decode_identity(&w)?;
        let (fns, dropped) = decode_functions(w.functions);
        let transitive_deps = decode_transitive_deps(w.transitive_deps)?;
        let foreign_type_ids = decode_foreign_type_ids(w.foreign_type_ids);
        let declared_opaques = decode_declared_opaques(w.declared_opaques, &w.name)?;
        let features = decode_features(w.features, &w.name)?;
        let source = decode_source(&w.wrapper_path, &w.name)?;
        // The representation axis: classification failure of one entry is an
        // opaque fallback recorded in the catalog, never a package failure.
        let foreign_types = crate::transparency::ForeignTypeCatalog::classify(&w.types);
        let consts = decode_consts(w.constants);
        Ok(Self {
            pkg_path,
            name,
            version,
            fns,
            consts,
            modules: w.modules,
            errors: w.errors,
            notes: w.notes,
            transitive_deps,
            features,
            foreign_type_ids,
            foreign_types,
            declared_opaques,
            source,
            dropped,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diag::CallDefect;
    use serde_json::json;

    fn decode(v: &serde_json::Value) -> Result<PkgInfo, Diagnostic> {
        PkgInfo::decode_json(&v.to_string())
    }

    fn fn_at(pkg: &PkgInfo, i: usize) -> &FnInfo {
        pkg.fns().get(i).expect("function present")
    }

    fn base_pkg(functions: &serde_json::Value) -> serde_json::Value {
        json!({
            "pkg": "semver",
            "name": "semver",
            "version": "1.0.26",
            "functions": functions,
            "errors": []
        })
    }

    /// A `base_pkg` document carrying a `declaredOpaques` map.
    fn pkg_with_declared_opaques(declared: &serde_json::Value) -> serde_json::Value {
        json!({
            "pkg": "semver",
            "name": "semver",
            "version": "1.0.26",
            "functions": [],
            "errors": [],
            "declaredOpaques": declared
        })
    }

    #[test]
    fn declared_opaques_decode_with_a_valid_absolute_path() {
        let doc = pkg_with_declared_opaques(&json!({ "Connection": "::postgres::Client" }));
        let pkg = decode(&doc).expect("decodes");
        assert_eq!(
            pkg.declared_opaques().get("Connection").map(String::as_str),
            Some("::postgres::Client")
        );
    }

    #[test]
    fn a_declared_opaque_with_a_non_absolute_path_fails_the_package() {
        // A bare (non-`::`-prefixed) path is refused — the whole package fails
        // rather than emit an un-renderable alias body.
        let doc = pkg_with_declared_opaques(&json!({ "Connection": "postgres::Client" }));
        assert!(matches!(
            decode(&doc),
            Err(Diagnostic::WireMalformed { .. })
        ));
    }

    #[test]
    fn a_declared_opaque_with_an_injection_bearing_path_fails_the_package() {
        let doc = pkg_with_declared_opaques(
            &json!({ "Connection": "::postgres::Client; use std::process::Command" }),
        );
        assert!(matches!(
            decode(&doc),
            Err(Diagnostic::WireMalformed { .. })
        ));
    }

    #[test]
    fn types_wire_key_decodes_the_representation_axis() {
        let pkg = decode(&json!({
            "pkg": "tm",
            "name": "tm",
            "version": "0.1.0",
            "functions": [],
            "errors": [],
            "types": [
                {"name": "Point", "rustPath": "tm::Point", "kind": "struct",
                 "fields": [{"name": "x", "type": "Int", "rustType": "i64"}]},
                {"name": "Sealed", "rustPath": "tm::Sealed", "kind": "struct",
                 "hiddenMembers": true}
            ]
        }))
        .expect("decodes");
        assert!(
            pkg.foreign_types().transparent().contains_key("Point"),
            "a fully-qualifying reported struct decodes transparent"
        );
        assert_eq!(
            pkg.foreign_types()
                .opaque_reasons()
                .iter()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Sealed"],
            "a hidden-members type stays opaque with its reason recorded"
        );
        // A document with no `types` key (every existing cache) decodes to an
        // empty catalog — nothing surfaces transparently by default.
        let bare = decode(&base_pkg(&json!([]))).expect("decodes");
        assert!(bare.foreign_types().transparent().is_empty());
        assert!(bare.foreign_types().opaque_reasons().is_empty());
    }

    #[test]
    fn decodes_a_minimal_plain_function() {
        let pkg = decode(&base_pkg(&json!([{
            "name": "parse",
            "params": [{"name": "text", "type": "&str", "ipeType": "string", "rustType": "&str"}],
            "results": [{"name": "", "type": "Result<Version, Error>"}],
            "variadic": false,
            "effect": "fallible",
            "exported": true
        }])))
        .expect("decodes");
        assert_eq!(pkg.name(), "semver");
        assert_eq!(pkg.version(), "1.0.26");
        let f = fn_at(&pkg, 0);
        assert_eq!(f.name(), "parse");
        assert_eq!(f.wrapper_ref_name(), "parse");
        assert_eq!(f.effect(), Effect::Fallible);
        assert_eq!(*f.shape(), FnShape::Plain);
        assert_eq!(f.fallibility(), Fallibility::TaskError);
        assert!(pkg.dropped().is_empty());
    }

    #[test]
    fn field_getter_shape_carries_the_infallible_bit() {
        let pkg = decode(&base_pkg(&json!([{
            "name": "major_field",
            "params": [],
            "results": [{"name": "", "type": "u64"}],
            "effect": "pure",
            "recvType": "Version",
            "isField": true
        }])))
        .expect("decodes");
        let f = fn_at(&pkg, 0);
        assert_eq!(*f.shape(), FnShape::FieldGet);
        assert_eq!(f.fallibility(), Fallibility::Infallible);
        assert_eq!(f.wrapper_ref_name(), "major_field_from_version");
    }

    #[test]
    fn enum_shapes_decode_their_payloads() {
        let pkg = decode(&base_pkg(&json!([
            {
                "name": "new_prerelease",
                "effect": "pure",
                "isEnumCtor": true,
                "enumVariant": "Prerelease",
                "enumKind": "tuple"
            },
            {
                "name": "tag_of_op",
                "effect": "pure",
                "isEnumTag": true,
                "enumArms": ["Exact\tExact", "Greater(..)\tGreater"],
                "enumWildcard": true
            },
            {
                "name": "value_as_greater",
                "effect": "pure",
                "isEnumExtract": true,
                "enumVariant": "Greater",
                "enumKind": "tuple",
                "enumStructFields": ["0"],
                "enumFieldCount": 2
            }
        ])))
        .expect("decodes");
        assert_eq!(pkg.fns().len(), 3);
        assert!(matches!(
            fn_at(&pkg, 0).shape(),
            FnShape::EnumCtor {
                kind: EnumVariantKind::Tuple,
                ..
            }
        ));
        let tag = match fn_at(&pkg, 1).shape() {
            FnShape::EnumTag { arms, wildcard } => Some((arms.clone(), *wildcard)),
            _ => None,
        };
        let (arms, wildcard) = tag.expect("decoded as EnumTag");
        assert!(wildcard);
        let first_arm = arms.first().expect("arm present");
        assert_eq!(first_arm.pattern.as_str(), "Exact");
        assert_eq!(first_arm.tag, "Exact");
        let extract = match fn_at(&pkg, 2).shape() {
            FnShape::EnumExtract {
                selector,
                field_count,
                ..
            } => Some((selector.clone(), *field_count)),
            _ => None,
        };
        let (selector, field_count) = extract.expect("decoded as EnumExtract");
        assert_eq!(selector.as_str(), "0");
        assert_eq!(field_count, 2);
        // Every accessor shape is infallible — the single stored bit.
        for f in pkg.fns() {
            assert_eq!(f.fallibility(), Fallibility::Infallible);
        }
    }

    #[test]
    fn a_define_closure_decodes_into_a_closure_adapter_shape() {
        let pkg = decode(&base_pkg(&json!([{
            "name": "update_fn",
            "effect": "pure",
            "isClosureAdapter": true,
            "closureSig": "Fn(Int, Bool) -> Int + Send + Sync + 'static"
        }])))
        .expect("decodes");
        let f = fn_at(&pkg, 0);
        let rendered = match f.shape() {
            FnShape::ClosureAdapter { sig } => sig.rust_dyn_fn(),
            other => format!("not a closure adapter: {other:?}"),
        };
        assert_eq!(rendered, "dyn Fn(i64, bool) -> i64 + Send + Sync + 'static");
        // Construction is infallible; per-call failure is handled in-band.
        assert_eq!(f.fallibility(), Fallibility::Infallible);
        assert!(pkg.dropped().is_empty());
    }

    #[test]
    fn an_ill_formed_closure_signature_over_drops_the_entry() {
        // A return outside the carrier set (a total opaque) refuses at decode —
        // the whole define entry over-drops, never emit-and-cargo-fail.
        let pkg = decode(&base_pkg(&json!([{
            "name": "bad_fn",
            "effect": "pure",
            "isClosureAdapter": true,
            "closureSig": "Fn(Int) -> Widget + Send + Sync + 'static"
        }])))
        .expect("package survives");
        assert!(pkg.fns().is_empty());
        assert!(matches!(
            pkg.dropped().first().expect("dropped diagnostic"),
            Diagnostic::WireMalformed {
                defect: WireDefect::InvalidClosureSig { .. },
                ..
            }
        ));
    }

    #[test]
    fn a_define_struct_decodes_into_a_struct_ctor_shape() {
        let pkg = decode(&base_pkg(&json!([{
            "name": "counter_new",
            "effect": "pure",
            "isStructCtor": true,
            "structName": "Counter",
            "structFields": [{ "name": "value", "type": "i64" }],
            "structDerives": ["Default", "Clone"]
        }])))
        .expect("decodes");
        let f = fn_at(&pkg, 0);
        let (name, derives, arity) = match f.shape() {
            FnShape::StructCtor { def } => (
                def.name.as_str().to_owned(),
                def.derives.rust_list(),
                def.fields.len(),
            ),
            other => (format!("not a struct ctor: {other:?}"), String::new(), 0),
        };
        assert_eq!(name, "Counter");
        assert_eq!(derives, "Clone, Default");
        assert_eq!(arity, 1);
        // Construction is infallible — a total struct literal.
        assert_eq!(f.fallibility(), Fallibility::Infallible);
        assert!(pkg.dropped().is_empty());
    }

    #[test]
    fn an_ill_formed_define_struct_over_drops_the_entry() {
        // A derive outside the allowlist refuses the whole entry at decode.
        let pkg = decode(&base_pkg(&json!([{
            "name": "bad_new",
            "effect": "pure",
            "isStructCtor": true,
            "structName": "Bad",
            "structFields": [{ "name": "x", "type": "f64" }],
            "structDerives": ["Eq"]
        }])))
        .expect("package survives");
        assert!(pkg.fns().is_empty());
        assert!(matches!(
            pkg.dropped().first().expect("dropped diagnostic"),
            Diagnostic::WireMalformed {
                defect: WireDefect::InvalidType { .. },
                ..
            }
        ));
    }

    #[test]
    fn a_define_enum_decodes_into_an_enum_def_shape() {
        let pkg = decode(&base_pkg(&json!([{
            "name": "message",
            "effect": "pure",
            "isEnumDef": true,
            "enumName": "Message",
            "enumVariants": [
                { "name": "Increment", "payload": [] },
                { "name": "SetValue", "payload": ["i64"] }
            ],
            "enumDerives": ["Clone"]
        }])))
        .expect("decodes");
        let f = fn_at(&pkg, 0);
        let (name, derives, variants) = match f.shape() {
            FnShape::EnumDefCtor { def } => (
                def.name.as_str().to_owned(),
                def.derives.rust_list(),
                def.variants.len(),
            ),
            other => (format!("not an enum def: {other:?}"), String::new(), 0),
        };
        assert_eq!(name, "Message");
        assert_eq!(derives, "Clone");
        assert_eq!(variants, 2);
        // Construction is infallible — a total variant literal.
        assert_eq!(f.fallibility(), Fallibility::Infallible);
        assert!(pkg.dropped().is_empty());
    }

    #[test]
    fn an_ill_formed_define_enum_over_drops_the_entry() {
        // A variantless enum is uninhabited — refused at decode.
        let pkg = decode(&base_pkg(&json!([{
            "name": "bad",
            "effect": "pure",
            "isEnumDef": true,
            "enumName": "Void",
            "enumVariants": [],
            "enumDerives": []
        }])))
        .expect("package survives");
        assert!(pkg.fns().is_empty());
        assert!(matches!(
            pkg.dropped().first().expect("dropped diagnostic"),
            Diagnostic::WireMalformed {
                defect: WireDefect::InvalidType { .. },
                ..
            }
        ));
    }

    #[test]
    fn a_self_recursive_define_struct_is_refused_at_decode() {
        // `Tree { child: Tree }` has no boxed indirection in the closed carrier
        // set, so emitting it would be an infinitely-sized Rust type (E0072).
        let pkg = decode(&base_pkg(&json!([{
            "name": "tree_new",
            "effect": "pure",
            "isStructCtor": true,
            "structName": "Tree",
            "structFields": [{ "name": "child", "type": "Tree" }],
            "structDerives": ["Clone"]
        }])))
        .expect("package survives");
        assert!(pkg.fns().is_empty(), "the recursive def emits nothing");
        assert!(matches!(
            pkg.dropped().first().expect("dropped diagnostic"),
            Diagnostic::WireMalformed {
                defect: WireDefect::RecursiveDefineType { name, .. },
                ..
            } if name == "Tree"
        ));
    }

    #[test]
    fn a_mutually_recursive_define_pair_is_refused_at_decode() {
        // `A { inner: B }` + `B { inner: A }` close a cycle through each other.
        let pkg = decode(&base_pkg(&json!([
            {
                "name": "a_new",
                "effect": "pure",
                "isStructCtor": true,
                "structName": "A",
                "structFields": [{ "name": "inner", "type": "B" }],
                "structDerives": ["Clone"]
            },
            {
                "name": "b_new",
                "effect": "pure",
                "isStructCtor": true,
                "structName": "B",
                "structFields": [{ "name": "inner", "type": "A" }],
                "structDerives": ["Clone"]
            }
        ])))
        .expect("package survives");
        assert!(pkg.fns().is_empty(), "both cyclic defs emit nothing");
        let refused: std::collections::BTreeSet<&str> = pkg
            .dropped()
            .iter()
            .filter_map(|d| match d {
                Diagnostic::WireMalformed {
                    defect: WireDefect::RecursiveDefineType { name, .. },
                    ..
                } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            refused,
            ["A", "B"]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
        );
    }

    #[test]
    fn a_self_recursive_define_enum_is_refused_at_decode() {
        // `List::Cons(List)` recurses through its own variant payload.
        let pkg = decode(&base_pkg(&json!([{
            "name": "list",
            "effect": "pure",
            "isEnumDef": true,
            "enumName": "List",
            "enumVariants": [
                { "name": "Nil", "payload": [] },
                { "name": "Cons", "payload": ["List"] }
            ],
            "enumDerives": ["Clone"]
        }])))
        .expect("package survives");
        assert!(pkg.fns().is_empty());
        assert!(matches!(
            pkg.dropped().first().expect("dropped diagnostic"),
            Diagnostic::WireMalformed {
                defect: WireDefect::RecursiveDefineType { name, .. },
                ..
            } if name == "List"
        ));
    }

    #[test]
    fn a_non_recursive_define_chain_survives_decode() {
        // `A { b: B }`, `B { c: i64 }` is an acyclic chain — both survive.
        let pkg = decode(&base_pkg(&json!([
            {
                "name": "a_new",
                "effect": "pure",
                "isStructCtor": true,
                "structName": "A",
                "structFields": [{ "name": "b", "type": "B" }],
                "structDerives": ["Clone"]
            },
            {
                "name": "b_new",
                "effect": "pure",
                "isStructCtor": true,
                "structName": "B",
                "structFields": [{ "name": "c", "type": "i64" }],
                "structDerives": ["Clone"]
            }
        ])))
        .expect("decodes");
        assert_eq!(pkg.fns().len(), 2, "the acyclic chain survives whole");
        assert!(pkg.dropped().is_empty());
    }

    #[test]
    fn a_define_type_referencing_a_crate_opaque_is_not_a_cycle() {
        // `Wrap { inner: Regex }` names a crate opaque, not a define type —
        // the edge leaves the graph and closes no cycle.
        let pkg = decode(&base_pkg(&json!([{
            "name": "wrap_new",
            "effect": "pure",
            "isStructCtor": true,
            "structName": "Wrap",
            "structFields": [{ "name": "inner", "type": "Regex" }],
            "structDerives": ["Clone"]
        }])))
        .expect("decodes");
        assert_eq!(pkg.fns().len(), 1);
        assert!(pkg.dropped().is_empty());
    }

    #[test]
    fn an_enum_def_flag_clashing_with_an_accessor_flag_drops_the_binding() {
        let pkg = decode(&base_pkg(&json!([{
            "name": "confused",
            "effect": "pure",
            "isEnumDef": true,
            "isField": true,
            "enumName": "X"
        }])))
        .expect("package survives");
        assert!(pkg.fns().is_empty());
        assert!(matches!(
            pkg.dropped().first().expect("dropped diagnostic"),
            Diagnostic::ShapeContradiction { .. }
        ));
    }

    #[test]
    fn a_struct_ctor_flag_clashing_with_an_accessor_flag_drops_the_binding() {
        let pkg = decode(&base_pkg(&json!([{
            "name": "confused",
            "effect": "pure",
            "isStructCtor": true,
            "isField": true,
            "structName": "X"
        }])))
        .expect("package survives");
        assert!(pkg.fns().is_empty());
        assert!(matches!(
            pkg.dropped().first().expect("dropped diagnostic"),
            Diagnostic::ShapeContradiction { .. }
        ));
    }

    #[test]
    fn a_closure_adapter_flag_clashing_with_an_accessor_flag_drops_the_binding() {
        let pkg = decode(&base_pkg(&json!([{
            "name": "confused",
            "effect": "pure",
            "isClosureAdapter": true,
            "isField": true,
            "closureSig": "Fn(Int) -> Int"
        }])))
        .expect("package survives");
        assert!(pkg.fns().is_empty());
        assert!(matches!(
            pkg.dropped().first().expect("dropped diagnostic"),
            Diagnostic::ShapeContradiction { .. }
        ));
    }

    #[test]
    fn contradictory_shape_flags_drop_the_one_binding_and_keep_the_package() {
        let pkg = decode(&base_pkg(&json!([
            {
                "name": "good",
                "effect": "pure"
            },
            {
                "name": "confused",
                "effect": "pure",
                "isField": true,
                "isEnumCtor": true,
                "enumVariant": "V",
                "enumKind": "unit"
            }
        ])))
        .expect("package survives");
        assert_eq!(pkg.fns().len(), 1);
        assert_eq!(fn_at(&pkg, 0).name(), "good");
        assert_eq!(pkg.dropped().len(), 1);
        assert!(matches!(
            pkg.dropped().first().expect("dropped diagnostic"),
            Diagnostic::ShapeContradiction { function, flags }
                if function == "confused" && flags == &vec!["isField", "isEnumCtor"]
        ));
    }

    #[test]
    fn unknown_effect_drops_the_binding() {
        let pkg = decode(&base_pkg(&json!([{
            "name": "weird",
            "effect": "spooky"
        }])))
        .expect("package survives");
        assert!(pkg.fns().is_empty());
        assert!(matches!(
            pkg.dropped().first().expect("dropped diagnostic"),
            Diagnostic::WireMalformed {
                defect: WireDefect::UnknownEffect { got },
                ..
            } if got == "spooky"
        ));
    }

    #[test]
    fn an_injection_shaped_function_name_is_refused() {
        let pkg = decode(&base_pkg(&json!([{
            "name": "evil; std::process::exit(1)",
            "effect": "pure"
        }])))
        .expect("package survives");
        assert!(pkg.fns().is_empty());
        assert!(matches!(
            pkg.dropped().first().expect("dropped diagnostic"),
            Diagnostic::WireMalformed {
                defect: WireDefect::InvalidIdent { .. },
                ..
            }
        ));
    }

    #[test]
    fn an_injection_bearing_rust_type_drops_the_binding() {
        let pkg = decode(&base_pkg(&json!([{
            "name": "evil",
            "params": [{"name": "x", "type": "u64", "rustType": "u64; std::process::exit(1)"}],
            "results": [{"name": "", "type": "u64"}],
            "effect": "pure"
        }])))
        .expect("package survives");
        assert!(pkg.fns().is_empty());
        assert!(matches!(
            pkg.dropped().first().expect("dropped diagnostic"),
            Diagnostic::WireMalformed {
                defect: WireDefect::InvalidType { .. },
                ..
            }
        ));
    }

    #[test]
    fn an_injection_bearing_recv_rust_type_drops_the_binding() {
        let pkg = decode(&base_pkg(&json!([{
            "name": "major_field",
            "params": [],
            "results": [{"name": "", "type": "u64"}],
            "effect": "pure",
            "recvType": "Version",
            "recvRustType": "Version { } fn e(){}",
            "isField": true
        }])))
        .expect("package survives");
        assert!(pkg.fns().is_empty());
        assert!(matches!(
            pkg.dropped().first().expect("dropped diagnostic"),
            Diagnostic::WireMalformed {
                defect: WireDefect::InvalidType { .. },
                ..
            }
        ));
    }

    #[test]
    fn an_injection_bearing_enum_struct_field_drops_the_binding() {
        let pkg = decode(&base_pkg(&json!([{
            "name": "make_point",
            "effect": "pure",
            "isEnumCtor": true,
            "enumVariant": "Point",
            "enumKind": "struct",
            "enumStructFields": ["x: i32, } std::process::exit(1); struct P { y"]
        }])))
        .expect("package survives");
        assert!(pkg.fns().is_empty());
        assert!(matches!(
            pkg.dropped().first().expect("dropped diagnostic"),
            Diagnostic::WireMalformed {
                defect: WireDefect::InvalidIdent { .. },
                ..
            }
        ));
    }

    #[test]
    fn an_injection_bearing_selector_drops_the_binding() {
        let pkg = decode(&base_pkg(&json!([{
            "name": "value_of",
            "effect": "pure",
            "isEnumExtract": true,
            "enumVariant": "V",
            "enumKind": "struct",
            "enumStructFields": ["field, .. } => evil(); if let V { real"],
            "enumFieldCount": 1
        }])))
        .expect("package survives");
        assert!(pkg.fns().is_empty());
        assert!(matches!(
            pkg.dropped().first().expect("dropped diagnostic"),
            Diagnostic::WireMalformed {
                defect: WireDefect::InvalidSelector { .. },
                ..
            }
        ));
    }

    #[test]
    fn an_injection_bearing_enum_tag_pattern_drops_the_binding() {
        let pkg = decode(&base_pkg(&json!([{
            "name": "tag_of",
            "effect": "pure",
            "isEnumTag": true,
            "enumArms": ["A => 1, _ if evil()\tA"],
            "enumWildcard": false
        }])))
        .expect("package survives");
        assert!(pkg.fns().is_empty());
        assert!(matches!(
            pkg.dropped().first().expect("dropped diagnostic"),
            Diagnostic::WireMalformed {
                defect: WireDefect::InvalidPattern { .. },
                ..
            }
        ));
    }

    #[test]
    fn an_illegal_crate_name_fails_the_whole_package() {
        let v = json!({
            "pkg": "x",
            "name": "bad-crate!",
            "functions": [],
            "errors": []
        });
        assert!(matches!(
            decode(&v),
            Err(Diagnostic::WireMalformed {
                defect: WireDefect::InvalidIdent { .. },
                ..
            })
        ));
    }

    // `pkg_path` is emitted verbatim into two `//` comment lines of the
    // unsandboxed `_bindings.rs` (`crate::bindings::emit_bindings`). A `pkg`
    // carrying a newline could close the comment and splice compilable Rust
    // source into it. Assert decode refuses the WHOLE package (like the
    // illegal-crate-name case above) rather than passing the raw string
    // through.
    #[test]
    fn a_newline_bearing_pkg_path_fails_the_whole_package() {
        let v = json!({
            "pkg": "semver\n} fn evil() { std::process::exit(1)",
            "name": "semver",
            "functions": [],
            "errors": []
        });
        assert!(matches!(
            decode(&v),
            Err(Diagnostic::WireMalformed {
                defect: WireDefect::InvalidPkgPath { .. },
                ..
            })
        ));
    }

    // `pkg` legitimately carries `/` for a `--manifest`-path invocation
    // (unlike the crate `name`, which is a bare identifier) — the control-
    // character gate must not reject ordinary path shapes.
    #[test]
    fn a_manifest_path_shaped_pkg_path_decodes() {
        let v = json!({
            "pkg": "crates/semver-tool/Cargo.toml",
            "name": "semver",
            "functions": [],
            "errors": []
        });
        let pkg = decode(&v).expect("manifest-path-shaped pkg decodes");
        assert_eq!(pkg.pkg_path(), "crates/semver-tool/Cargo.toml");
    }

    // The resolved `version` is spliced into a TOML value position of the
    // emitted `Cargo.toml` (`<name> = "=<version>"`). A version carrying a
    // `"`-and-newline payload could close the string and inject a rogue
    // `[dependencies.evil]` table. Assert decode refuses the WHOLE package
    // (like the newline-bearing-pkg-path case) rather than passing the raw
    // string through to the manifest emitter.
    #[test]
    fn an_injection_bearing_version_fails_the_whole_package() {
        let evil = "1.0\", features=[\"net\"] }\n[dependencies.evil]\npath = \"/etc";
        let v = json!({
            "pkg": "semver",
            "name": "semver",
            "version": evil,
            "functions": [],
            "errors": []
        });
        assert!(matches!(
            decode(&v),
            Err(Diagnostic::WireMalformed {
                defect: WireDefect::InvalidVersion { .. },
                ..
            })
        ));
    }

    // The same gate guards a TRANSITIVE dependency's version — the transitive
    // path is the one `CargoDep::render` reaches for every non-primary crate.
    #[test]
    fn an_injection_bearing_transitive_version_fails_the_whole_package() {
        let v = json!({
            "pkg": "semver",
            "name": "semver",
            "version": "1.0.26",
            "functions": [],
            "errors": [],
            "transitiveDeps": [
                {"ident": "serde_json", "name": "serde-json",
                 "version": "1.0\" }\n[dependencies.evil]\npath = \"/etc"}
            ]
        });
        assert!(matches!(
            decode(&v),
            Err(Diagnostic::WireMalformed {
                defect: WireDefect::InvalidVersion { .. },
                ..
            })
        ));
    }

    // Every `SemVer` version (pre-release and build metadata included) and the
    // empty unresolved-probe version decode.
    #[test]
    fn legal_versions_decode() {
        for ok in [
            "1.0.26",
            "0.0.0",
            "1.0.0-rc.6",
            "1.0.0-alpha-1.0.x",
            "1.2.3+build.5",
            "1.2.3+001",
            "1.0.0-rc.1+exp.sha.5114f85",
            "",
        ] {
            let v = json!({
                "pkg": "semver",
                "name": "semver",
                "version": ok,
                "functions": [],
                "errors": []
            });
            assert!(decode(&v).is_ok(), "{ok:?} must decode");
        }
    }

    // Requirement text and malformed versions are refused at decode: the
    // emitter renders `"=<version>"`, and each of these after `=` is a
    // requirement Cargo rejects.
    #[test]
    fn requirement_text_and_malformed_versions_are_refused() {
        for bad in [
            "==1",
            "=*",
            "*",
            "=1.0.0",
            ">=1, <2",
            "^1.2.3",
            "1",
            "1.0",
            "1.0.0.0",
            "01.0.0",
            "1.00.0",
            "1..0",
            " 1.0.0",
            "1.0.0 ",
            "1.0.0-",
            "1.0.0+",
            "1.0.0-rc..1",
            "1.0.0-01",
            "1.0.0+a+b",
            "18446744073709551616.0.0",
        ] {
            assert!(
                matches!(
                    CrateVersion::parse(bad),
                    Err(WireDefect::InvalidVersion { .. })
                ),
                "{bad:?} must be refused"
            );
            let transitive = json!({
                "pkg": "semver",
                "name": "semver",
                "version": "1.0.26",
                "functions": [],
                "errors": [],
                "transitiveDeps": [{"ident": "serde", "name": "serde", "version": bad}]
            });
            assert!(
                matches!(
                    decode(&transitive),
                    Err(Diagnostic::WireMalformed {
                        defect: WireDefect::InvalidVersion { .. },
                        ..
                    })
                ),
                "{bad:?} as a transitive version must fail the whole package"
            );
        }
    }

    // A feature string is spliced into the `features = [ … ]` array of the
    // emitted `Cargo.toml`. A feature carrying `"`, `]`, `}` and a newline
    // could close the array + inline table and inject a rogue
    // `[dependencies.evil]` table. Assert decode refuses the WHOLE package
    // rather than passing the raw string through to the manifest emitter.
    #[test]
    fn an_injection_bearing_feature_fails_the_whole_package() {
        let evil = "std\"]}\n[dependencies.evil]\npath = \"/tmp/evil\nx = [\"";
        let v = json!({
            "pkg": "semver",
            "name": "semver",
            "version": "1.0.26",
            "functions": [],
            "errors": [],
            "features": [evil]
        });
        assert!(matches!(
            decode(&v),
            Err(Diagnostic::WireMalformed {
                defect: WireDefect::InvalidFeature { .. },
                ..
            })
        ));
    }

    // The transitive `name` becomes the `[dependencies]` key of the emitted
    // manifest. Only `ident` went through a gate before; `name` was raw. A
    // name carrying a TOML breakout must fail the whole package at decode.
    #[test]
    fn an_injection_bearing_transitive_name_fails_the_whole_package() {
        let v = json!({
            "pkg": "semver",
            "name": "semver",
            "version": "1.0.26",
            "functions": [],
            "errors": [],
            "transitiveDeps": [
                {"ident": "serde_json",
                 "name": "serde\"]}\n[dependencies.evil]\npath = \"/tmp/evil\nx=[\"",
                 "version": "1.0.145"}
            ]
        });
        assert!(matches!(
            decode(&v),
            Err(Diagnostic::WireMalformed {
                defect: WireDefect::InvalidIdent { .. },
                ..
            })
        ));
    }

    // Legal Cargo feature syntax (plain names, dashed, `dep:`, `crate/feat`,
    // optional `dep?/feat`) must still decode — the gate rejects only the
    // TOML-breaking charset, never ordinary feature syntax.
    #[test]
    fn legal_features_decode() {
        let v = json!({
            "pkg": "tokio",
            "name": "tokio",
            "version": "1.0.0",
            "functions": [],
            "errors": [],
            "features": ["rt-multi-thread", "dep:foo", "serde/std", "dep?/feat", "v1.2"]
        });
        let pkg = decode(&v).expect("legal features decode");
        assert_eq!(
            pkg.features()
                .iter()
                .map(FeatureName::as_str)
                .collect::<Vec<_>>(),
            [
                "rt-multi-thread",
                "dep:foo",
                "serde/std",
                "dep?/feat",
                "v1.2"
            ]
        );
    }

    // The inspector's own probe scaffold registers as a workspace member of
    // the introspection project and appears in `transitiveDeps`. It is a
    // synthetic non-registry package (its `_ipe_ffi_probe_…` name is not a
    // legal `PackageName`), so decode must DROP it rather than fail — every
    // surviving `TransitiveDep` is then a real dependency.
    #[test]
    fn the_probe_scaffold_is_dropped_at_decode() {
        let v = json!({
            "pkg": "semver",
            "name": "semver",
            "version": "1.0.26",
            "functions": [],
            "errors": [],
            "transitiveDeps": [
                {"ident": "_ipe_ffi_probe_semver", "name": "_ipe_ffi_probe_semver",
                 "version": "0.0.0"},
                {"ident": "serde_json", "name": "serde-json", "version": "1.0.145"}
            ]
        });
        let pkg = decode(&v).expect("probe scaffold is dropped, not rejected");
        let names: Vec<&str> = pkg
            .transitive_deps()
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert_eq!(names, ["serde-json"]);
    }

    #[test]
    fn a_generic_block_routes_through_the_call_gate() {
        let good = decode(&base_pkg(&json!([{
            "name": "make",
            "effect": "pure",
            "generic": {
                "params": ["a"],
                "bounds": {"a": ["Clone"]},
                "call": {
                    "kind": "function",
                    "path": ["::box1", "Box1"],
                    "typeArgs": [{"param": 0}],
                    "method": "make",
                    "args": [0],
                    "argTypes": [{"param": 0}],
                    "ret": {"ctor": "::box1::Box1", "args": [{"param": 0}]}
                }
            }
        }])))
        .expect("decodes");
        let g = fn_at(&good, 0).generic().expect("generic present");
        assert_eq!(g.params, vec!["a".to_owned()]);
        assert_eq!(
            g.call.render_body(&g.params),
            "::box1::Box1::<A>::make(arg0)"
        );

        // An out-of-range param ref inside the call drops the binding with
        // the F4400 defect attached.
        let bad = decode(&base_pkg(&json!([{
            "name": "make",
            "effect": "pure",
            "generic": {
                "params": ["a"],
                "call": {
                    "kind": "function",
                    "path": ["::box1", "Box1"],
                    "method": "make",
                    "args": [0],
                    "argTypes": [{"param": 0}],
                    "ret": {"param": 7}
                }
            }
        }])))
        .expect("package survives");
        assert!(bad.fns().is_empty());
        assert!(matches!(
            bad.dropped().first().expect("dropped diagnostic"),
            Diagnostic::CallUnrenderable {
                defect: CallDefect::ParamRefOutOfRange {
                    index: 7,
                    n_params: 1
                },
                ..
            }
        ));
    }

    #[test]
    fn inspector_error_channel_and_metadata_survive_the_conversion() {
        let v = json!({
            "pkg": "semver",
            "name": "semver",
            "functions": [],
            "modules": ["semver"],
            "errors": ["rustdoc failed"],
            "notes": ["facade guidance"],
            "transitiveDeps": [
                {"ident": "serde_json", "name": "serde-json", "version": "1.0.145"}
            ],
            "features": ["std"]
        });
        let pkg = decode(&v).expect("decodes");
        assert_eq!(pkg.errors(), ["rustdoc failed".to_owned()]);
        assert_eq!(pkg.notes(), ["facade guidance".to_owned()]);
        assert_eq!(
            pkg.features()
                .iter()
                .map(FeatureName::as_str)
                .collect::<Vec<_>>(),
            ["std"]
        );
        assert_eq!(
            pkg.transitive_deps().first().expect("dep").ident.as_str(),
            "serde_json"
        );
        assert_eq!(
            pkg.transitive_deps().first().expect("dep").name.as_str(),
            "serde-json"
        );
        assert_eq!(pkg.modules(), ["semver".to_owned()]);
    }
}
