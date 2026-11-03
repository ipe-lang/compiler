//! The shared coverage-matrix contract: one exported stdlib symbol, the surface
//! and aspect traits, and a cell verdict.
//!
//! The stdlib surface is otherwise an implicit concept, re-derived by three
//! partial enumerations that drift apart; a member present in one but forgotten
//! in another falls through the seam between their gates. This contract fixes one
//! reconciled symbol type and one `surface × aspect` grid so a new aspect is a
//! single column applied to every symbol, and a hole is named at its coordinate
//! rather than lost between checks.
//!
//! A [`Surface`] is any enumerable registry; [`StdlibSymbol`] is the item of the
//! stdlib surface. An [`AspectCheck`] renders one column, returning a [`Cell`]
//! per symbol. A [`Cell::Hole`] fails the gate; a [`Cell::Warn`] is advisory
//! debt; [`Cell::Ok`] and [`Cell::NotApplicable`] pass.
//!
//! [`Surface::all`] is fallible: a probe that cannot enumerate its registry
//! (a module that fails to parse, a table that fails to materialize) must
//! refuse with a [`crate::coverage::error::CoverageError`] rather than return
//! an empty or partial `Vec` that the runner would read as "nothing here."

/// Which namespace of the exported surface a symbol belongs to.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum SymbolKind {
    /// A value binding (a function or a constant).
    Value,
    /// A type constructor (a union or an opaque type name).
    Type,
    /// A data constructor of a union.
    Ctor,
}

/// One exported stdlib symbol, reconciled from every enumeration of the surface.
///
/// Each facet answers "does this enumeration know the symbol?" so a symbol
/// present in one registry but absent from another is visible at a glance, and
/// the aspect columns read the facets rather than re-deriving them.
// The four facet bools are independent registry answers (kernel / compiled-source
// / exported / higher-order), each read by a distinct column; collapsing them
// into an enum would fabricate mutual exclusions that do not hold (a symbol is
// commonly both kernel-backed and compiled-source-aliased).
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct StdlibSymbol {
    /// The dot-free module segments the symbol lives in (`["Ipe", "List"]`).
    pub module: Vec<String>,
    /// The symbol's own name (`"map"`).
    pub name: String,
    /// Whether the symbol names a value, a type, or a constructor.
    pub kind: SymbolKind,
    /// Registered in the kernel registry.
    pub has_kernel: bool,
    /// Defined in a compiled-source stdlib module.
    pub has_compiled_source: bool,
    /// Listed in its module's `exposing (...)` — reachable by an importer.
    pub exported: bool,
    /// The symbol's α-canonical typed scheme, or the explicit absence a
    /// kernel the registry declares unschemed carries.
    pub scheme: SchemeState,
    /// The scheme takes or returns a function — drives the composition column.
    pub is_higher_order: bool,
}

/// Whether a stdlib symbol's α-canonical typed scheme is known.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum SchemeState {
    /// The rendered α-canonical scheme string.
    Rendered(String),
    /// No scheme applies or resolves — a type/constructor symbol, a
    /// compiled-source value whose projected interface carries no signature,
    /// or a kernel the registry declares unschemed (a routed/unlowered
    /// bucket `IPE-L0108` refuses at its call sites).
    Unschemed,
}

/// An enumerable registry of items.
///
/// The stdlib surface is the first implementor; env-var, CLI, diagnostic,
/// foreign, and package registries are siblings that drift the same way, so the
/// runner iterates any `Surface × AspectCheck` and each surface declares which
/// aspects apply (an inapplicable aspect returns [`Cell::NotApplicable`]).
pub trait Surface: Sync {
    /// The kind of item this surface enumerates.
    type Item;
    /// A human name for the surface, used in the rendered matrix header.
    fn name(&self) -> &'static str;
    /// Every item of the surface, in a deterministic, sorted order.
    ///
    /// # Errors
    /// A [`crate::coverage::error::CoverageError`] when the surface cannot be
    /// fully enumerated — never a partial or empty `Vec` standing in for the
    /// failure.
    fn all(&self) -> Result<Vec<Self::Item>, crate::coverage::error::CoverageError>;
    /// The display label of an item, naming its row in a hole coordinate (a
    /// dotted symbol path for the stdlib surface, a variable name for the
    /// env-var surface).
    fn label(item: &Self::Item) -> String;
}

/// One aspect column of the matrix, over a surface's item type.
///
/// Applied to every item of a surface; the returned [`Cell`] is that
/// `(item, aspect)` coordinate's verdict. The item type is a parameter so a
/// second surface (env-var, CLI, …) plugs its own item into the same runner —
/// the stdlib columns are `AspectCheck<StdlibSymbol>`, an env-var column is
/// `AspectCheck<EnvItem>`.
pub trait AspectCheck<Item>: Sync {
    /// A human name for the column, used in the rendered matrix header and in a
    /// hole's failure message.
    fn name(&self) -> &'static str;
    /// The verdict for one item on this aspect.
    fn check(&self, item: &Item) -> Cell;
}

/// One `(symbol, aspect)` verdict.
///
/// The [`Cell::Hole`]-versus-[`Cell::Warn`] split is the severity axis: a
/// forgotten binding is a correctness gap that fails the gate, an advisory (an
/// untested helper, a review-staleness note) is debt that is reported without
/// failing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Cell {
    /// The aspect holds for this symbol.
    Ok,
    /// A real gap, carrying a human message — fails the gate at this coordinate.
    Hole(String),
    /// An advisory the aspect flags without failing the gate.
    Warn(String),
    /// The aspect does not apply to this symbol, carrying a one-line reason
    /// DERIVED from a real property (composition for a first-order value, `wasm`
    /// for a native-only kernel, a browser web axis a standalone build+run cannot
    /// run). A first-class, justified pass verdict — distinct from [`Self::Ok`] (a
    /// proven-holding aspect) so an inapplicability is never a silent
    /// [`Self::Hole`]→pass, and its reason is surfaced in the rendered report.
    NotApplicable {
        /// Why the aspect does not apply, named from the deriving property.
        reason: String,
    },
}

impl Cell {
    /// A [`Self::NotApplicable`] with a static reason — the ergonomic constructor
    /// for the common case a column knows the inapplicability reason as a literal.
    #[must_use]
    pub fn not_applicable(reason: impl Into<String>) -> Self {
        Self::NotApplicable {
            reason: reason.into(),
        }
    }
}
