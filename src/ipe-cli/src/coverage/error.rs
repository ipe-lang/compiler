//! The typed error channel for the coverage-matrix tool.
//!
//! Every fallible step of a [`crate::coverage::contract::Surface::all`] or
//! [`crate::coverage::contract::AspectCheck`] probe returns one of these
//! variants rather than folding the failure into an empty result or an
//! advisory [`crate::coverage::contract::Cell::Warn`]. A coverage row or
//! column the tool could not compute must never be read as "nothing to
//! report here" — it must be a named, typed refusal that reaches the caller.
//!
//! Exhaustive by construction: there is no `Other(String)` arm, so a new
//! fallible step requires a new variant here rather than a silent stringly
//! fallback.

use std::fmt;
use std::sync::Arc;

use ipe_diagnostics::{Diagnostic, plain_message};
use ipe_kernels::StdlibKernel;

use crate::api_surface::{DiffError, ModulePath};
use crate::coverage::source_tree::TreeRefusal;

/// Every way a coverage probe can fail to produce a row, a cell, or an
/// `ipe doc` kernel page.
#[derive(Debug)]
pub enum CoverageError {
    /// A compiled-source stdlib module's source failed to parse.
    Parse {
        /// The module that failed to parse.
        module: ModulePath,
        /// The parse diagnostic.
        diagnostic: Diagnostic,
    },
    /// A compiled-source stdlib module's typed interface failed to extract.
    Extract {
        /// The module whose typed interface failed to extract.
        module: ModulePath,
        /// The underlying extraction failure.
        source: DiffError,
    },
    /// The kernel type-scheme table failed to materialize.
    KernelTable(Diagnostic),
    /// A kernel's scheme resolved but failed to render to a [`ipe_diagnostics::TyDoc`].
    RenderScheme {
        /// The kernel whose scheme failed to render.
        kernel: StdlibKernel,
        /// The render failure.
        source: Diagnostic,
    },
    /// An interned symbol in a module's `exposing (...)` list did not resolve.
    UnresolvedSymbol {
        /// The module whose `exposing` list named the symbol.
        module: ModulePath,
    },
    /// A kernel qualifier has no entry in the stdlib module list.
    UnknownQualifier {
        /// The unresolvable qualifier.
        qualifier: &'static str,
    },
    /// The project manifest failed to load.
    Manifest(Box<crate::CliError>),
    /// The lockfile failed to load.
    Lockfile(Box<crate::CliError>),
    /// The environment-variable source scan was refused.
    EnvScan(Arc<TreeRefusal>),
    /// A scratch directory for a runtime probe could not be created.
    Scratch(std::io::Error),
    /// The runtime crate's source tree could not be probed.
    RuntimeSrc(std::io::Error),
}

impl fmt::Display for CoverageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse { module, diagnostic } => write!(
                f,
                "module `{}` failed to parse: {}",
                module.join("."),
                plain_message(diagnostic, "")
            ),
            Self::Extract { module, source } => write!(
                f,
                "module `{}` failed to extract its typed interface: {source}",
                module.join(".")
            ),
            Self::KernelTable(d) => write!(
                f,
                "the kernel type-scheme table failed to materialize: {}",
                plain_message(d, "")
            ),
            Self::RenderScheme { kernel, source } => write!(
                f,
                "kernel `{kernel:?}`'s scheme failed to render: {}",
                plain_message(source, "")
            ),
            Self::UnresolvedSymbol { module } => write!(
                f,
                "module `{}` exposes a symbol that failed to resolve from the interner",
                module.join(".")
            ),
            Self::UnknownQualifier { qualifier } => write!(
                f,
                "kernel qualifier `{qualifier}` has no entry in the stdlib module list"
            ),
            Self::Manifest(e) => write!(f, "project manifest: {e}"),
            Self::Lockfile(e) => write!(f, "lockfile: {e}"),
            Self::EnvScan(e) => write!(f, "environment-variable source scan refused: {e}"),
            Self::Scratch(e) => write!(f, "scratch directory for a runtime probe: {e}"),
            Self::RuntimeSrc(e) => write!(f, "runtime crate source tree probe: {e}"),
        }
    }
}

impl std::error::Error for CoverageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Manifest(e) | Self::Lockfile(e) => Some(&**e),
            Self::Scratch(e) | Self::RuntimeSrc(e) => Some(e),
            Self::EnvScan(e) => Some(&**e),
            Self::Extract { source, .. } => Some(source),
            Self::Parse { .. }
            | Self::KernelTable(_)
            | Self::RenderScheme { .. }
            | Self::UnresolvedSymbol { .. }
            | Self::UnknownQualifier { .. } => None,
        }
    }
}
