//! The coverage-matrix runner: iterate `surface × aspects`, render the grid, and
//! fail naming every hole.
//!
//! One runner applies every registered [`AspectCheck`] to every symbol of a
//! [`Surface`], producing a `(symbol, aspect)` grid. A [`Cell::Hole`] fails the
//! run at its named coordinate; a [`Cell::Warn`] is reported as advisory debt
//! without failing; [`Cell::Ok`] and [`Cell::NotApplicable`] pass. This
//! concentrates every per-aspect check into one loop so no symbol is judged on a
//! subset of the aspects.

use std::path::PathBuf;

use ipe_diagnostics::Code;

use crate::coverage::cli_surface::CliItem;
use crate::coverage::compiler_surface::CompilerCrate;
use crate::coverage::contract::{AspectCheck, Cell, StdlibSymbol, Surface};
use crate::coverage::env_surface::EnvItem;
use crate::coverage::error::CoverageError;
use crate::coverage::foreign_surface::ForeignItem;
use crate::coverage::package_surface::PackageItem;

/// The registered static aspect columns of the stdlib surface.
///
/// These read only registries and typed interfaces — no program build — so they
/// run in the fast (non-E2E) path.
///
/// # Errors
/// A typed [`CoverageError`] if a column's own construction (which reads the
/// stdlib registries) fails — never a silently truncated column set.
pub fn static_columns() -> Result<Vec<Box<dyn AspectCheck<StdlibSymbol>>>, CoverageError> {
    Ok(vec![
        Box::new(crate::coverage::columns_static::HomeColumn),
        Box::new(crate::coverage::columns_static::ResolvesColumn::new()),
        Box::new(crate::coverage::columns_static::ClosedSchemeColumn::new()),
        Box::new(crate::coverage::columns_static::LayerAgreementColumn::new()?),
        // LANE B: register your columns here
        Box::new(crate::coverage::columns_doc::DocumentedColumn::new()),
        Box::new(crate::coverage::columns_doc::DocExampleColumn::new()),
    ])
}

/// The registered dynamic aspect columns of the stdlib surface.
///
/// These generate a minimal program per symbol and emit/build/run it (or lower
/// it), so they are gated behind the E2E path — the heavy sweep runs only when
/// the caller asks for it. The `documented` and `doc-example` columns stay in
/// [`static_columns`] because a doc-string type-check is cheap enough for the
/// fast path.
///
/// # Errors
/// A typed [`CoverageError`] if a column's scratch directory cannot be created.
pub fn dynamic_columns() -> Result<Vec<Box<dyn AspectCheck<StdlibSymbol>>>, CoverageError> {
    Ok(vec![
        Box::new(crate::coverage::columns_runtime::LowersColumn::new()?),
        Box::new(crate::coverage::columns_runtime::ComposesColumn::new()?),
        Box::new(crate::coverage::columns_runtime::BuildRunColumn::new()?),
        Box::new(crate::coverage::columns_runtime::RuntimeFnExistsColumn::new()),
        Box::new(crate::coverage::columns_runtime::WasmColumn),
    ])
}

/// One hole found in the grid, at a named `(symbol, aspect)` coordinate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Hole {
    /// The dotted symbol path, e.g. `Ipe.List.map`.
    pub symbol: String,
    /// The aspect column that reported the hole.
    pub aspect: &'static str,
    /// The column's human message.
    pub message: String,
}

/// One advisory found in the grid, at a named `(symbol, aspect)` coordinate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Advisory {
    /// The dotted symbol path.
    pub symbol: String,
    /// The aspect column that reported the advisory.
    pub aspect: &'static str,
    /// The column's human message.
    pub message: String,
}

/// One justified `NotApplicable` verdict, at a named `(symbol, aspect)`
/// coordinate.
///
/// The aspect does not apply, with the deriving reason recorded so the pass is
/// auditable and never a silent [`Cell::Hole`]→pass.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NotApplicableEntry {
    /// The dotted symbol path.
    pub symbol: String,
    /// The aspect column that judged the symbol inapplicable.
    pub aspect: &'static str,
    /// Why the aspect does not apply, derived from a real property of the symbol.
    pub reason: String,
}

/// The outcome of a matrix run: every hole and every advisory, in the
/// deterministic order the surface enumerates its symbols and the columns are
/// registered.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct MatrixReport {
    /// Every failing coordinate.
    pub holes: Vec<Hole>,
    /// Every advisory coordinate.
    pub advisories: Vec<Advisory>,
    /// Every justified `NotApplicable` coordinate, with its deriving reason.
    pub not_applicable: Vec<NotApplicableEntry>,
    /// The number of symbols enumerated.
    pub symbols: usize,
    /// The number of aspect columns applied.
    pub columns: usize,
}

impl MatrixReport {
    /// Whether the run passed: no holes (advisories do not fail the gate).
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.holes.is_empty()
    }

    /// A rendered, human-readable failure report naming every hole coordinate,
    /// followed by any advisories.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;

        let mut out = format!(
            "coverage matrix: {} symbols × {} columns\n",
            self.symbols, self.columns
        );
        if self.holes.is_empty() {
            out.push_str("no holes\n");
        } else {
            let _ = writeln!(out, "{} hole(s):", self.holes.len());
            for h in &self.holes {
                let _ = writeln!(out, "  HOLE [{}] {}: {}", h.aspect, h.symbol, h.message);
            }
        }
        for a in &self.advisories {
            let _ = writeln!(out, "  WARN [{}] {}: {}", a.aspect, a.symbol, a.message);
        }
        for n in &self.not_applicable {
            let _ = writeln!(out, "  N/A  [{}] {}: {}", n.aspect, n.symbol, n.reason);
        }
        out
    }
}

/// Run the matrix over one surface and one column set, collecting every hole and
/// advisory coordinate.
///
/// # Errors
/// The typed [`CoverageError`] the surface's own enumeration refused with — a
/// surface that cannot enumerate its items never silently reports zero holes
/// over a grid it never actually judged.
pub fn run<S>(
    surface: &S,
    columns: &[Box<dyn AspectCheck<S::Item>>],
) -> Result<MatrixReport, CoverageError>
where
    S: Surface,
{
    let items = surface.all()?;
    let mut report = MatrixReport {
        symbols: items.len(),
        columns: columns.len(),
        ..MatrixReport::default()
    };
    for item in &items {
        let path = S::label(item);
        for column in columns {
            match column.check(item) {
                Cell::Ok => {}
                Cell::NotApplicable { reason } => {
                    report.not_applicable.push(NotApplicableEntry {
                        symbol: path.clone(),
                        aspect: column.name(),
                        reason,
                    });
                }
                Cell::Hole(message) => report.holes.push(Hole {
                    symbol: path.clone(),
                    aspect: column.name(),
                    message,
                }),
                Cell::Warn(message) => report.advisories.push(Advisory {
                    symbol: path.clone(),
                    aspect: column.name(),
                    message,
                }),
            }
        }
    }
    Ok(report)
}

/// Run the stdlib surface against its registered static columns.
///
/// # Errors
/// A typed [`CoverageError`] from column construction or surface enumeration.
pub fn run_static() -> Result<MatrixReport, CoverageError> {
    run(&crate::coverage::surface::StdlibSurface, &static_columns()?)
}

/// Run the stdlib surface against its registered dynamic (emit/build/run)
/// columns. Heavy — the caller gates this behind the E2E path.
///
/// # Errors
/// A typed [`CoverageError`] from column construction or surface enumeration.
pub fn run_dynamic() -> Result<MatrixReport, CoverageError> {
    run(&crate::coverage::surface::StdlibSurface, &dynamic_columns()?)
}

/// The registered aspect columns of the env-var surface.
///
/// These read only the env-var registry and a one-time scan of the source tree
/// for `IPE_*` reads — no program build — so they run in the fast path.
#[must_use]
pub fn env_columns() -> Vec<Box<dyn AspectCheck<EnvItem>>> {
    let scan = crate::coverage::env_surface::SourceReads::scan();
    vec![
        Box::new(crate::coverage::columns_env::RegisteredColumn),
        Box::new(crate::coverage::columns_env::ReadInCodeColumn::new(
            scan.clone(),
        )),
        Box::new(crate::coverage::columns_env::DocumentedColumn::new()),
        Box::new(crate::coverage::columns_env::TruthyParseColumn::new(&scan)),
        Box::new(crate::coverage::columns_env::ProdSafetyColumn),
    ]
}

/// Run the env-var surface against its registered columns.
///
/// # Errors
/// The typed [`CoverageError`] the source-tree scan refused with.
pub fn run_env() -> Result<MatrixReport, CoverageError> {
    run(&crate::coverage::env_surface::EnvVarSurface, &env_columns())
}

/// The registered aspect columns of the diagnostic surface.
///
/// These read only the taxonomy constants and a one-time scan of the source tree
/// for refusal-test assertions — no program build — so they run in the fast path.
#[must_use]
pub fn diagnostic_columns() -> Vec<Box<dyn AspectCheck<Code>>> {
    vec![
        Box::new(crate::coverage::diagnostic_surface::ExplainPageColumn),
        Box::new(crate::coverage::diagnostic_surface::DocumentedColumn),
        Box::new(crate::coverage::diagnostic_surface::RefusalTestedColumn::new()),
    ]
}

/// Run the diagnostic surface against its registered columns.
///
/// # Errors
/// The typed [`CoverageError`] the surface's own enumeration refused with.
pub fn run_diagnostic() -> Result<MatrixReport, CoverageError> {
    run(
        &crate::coverage::diagnostic_surface::DiagnosticSurface,
        &diagnostic_columns(),
    )
}

/// The registered aspect columns of the CLI surface.
///
/// These read the help table and scan source/test trees — no program build —
/// so they run in the fast path alongside the env-var columns.
#[must_use]
pub fn cli_columns() -> Vec<Box<dyn AspectCheck<CliItem>>> {
    vec![
        Box::new(crate::coverage::columns_cli::DocumentedColumn),
        Box::new(crate::coverage::columns_cli::TestedColumn::new()),
        Box::new(crate::coverage::columns_cli::NotAdvertisedUnimplementedColumn::new()),
    ]
}

/// Run the CLI surface against its registered columns.
///
/// # Errors
/// The typed [`CoverageError`] the surface's own enumeration refused with.
pub fn run_cli_surface() -> Result<MatrixReport, CoverageError> {
    run(&crate::coverage::cli_surface::CliSurface, &cli_columns())
}

/// The registered aspect columns of the compiler-crate surface.
///
/// These inspect `src/compiler/<crate>/src/` trees directly — no build — so
/// they run in the fast (non-E2E) path.
#[must_use]
pub fn compiler_columns() -> Vec<Box<dyn AspectCheck<CompilerCrate>>> {
    vec![
        Box::new(crate::coverage::columns_compiler::TestedColumn),
        Box::new(crate::coverage::columns_compiler::NoPanicColumn),
        Box::new(crate::coverage::columns_compiler::DocumentedColumn),
    ]
}

/// Run the compiler-crate surface against its registered columns.
///
/// # Errors
/// The typed [`CoverageError`] the surface's own enumeration refused with.
pub fn run_compiler() -> Result<MatrixReport, CoverageError> {
    run(
        &crate::coverage::compiler_surface::CompilerSurface,
        &compiler_columns(),
    )
}

/// The registered aspect columns of the foreign-binding surface.
///
/// All five columns read only the closed [`ipe_kernels::Capability::ALL`]
/// constant and scan the source tree — no program build — so they run in the
/// fast path.
#[must_use]
pub fn foreign_columns() -> Vec<Box<dyn AspectCheck<ForeignItem>>> {
    crate::coverage::foreign_surface::foreign_columns()
}

/// Run the foreign-binding surface against its registered columns.
///
/// # Errors
/// The typed [`CoverageError`] the surface's own enumeration refused with.
pub fn run_foreign() -> Result<MatrixReport, CoverageError> {
    run(
        &crate::coverage::foreign_surface::ForeignSurface,
        &foreign_columns(),
    )
}

/// The registered aspect columns of the package surface for one project root.
///
/// These read only the project's manifest and lockfile — no program build — so
/// they run in the fast path alongside the env-var columns.
///
/// # Errors
/// A typed [`CoverageError`] if the lockfile exists but fails to parse.
pub fn package_columns(
    project_root: PathBuf,
) -> Result<Vec<Box<dyn AspectCheck<PackageItem>>>, CoverageError> {
    crate::coverage::package_surface::package_columns(project_root)
}

/// Run the package surface for `project_root` against its registered columns.
///
/// # Errors
/// A typed [`CoverageError`] from column construction or surface enumeration
/// (a malformed manifest or lockfile, named rather than reported as a clean,
/// empty surface).
pub fn run_package(project_root: PathBuf) -> Result<MatrixReport, CoverageError> {
    let surface = crate::coverage::package_surface::PackageSurface::new(project_root.clone());
    run(&surface, &package_columns(project_root)?)
}
