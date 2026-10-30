//! Every stdlib kernel joined against its HM type scheme.
//!
//! The join is cross-checked against [`ipe_kernels::KernelDef::shape`] so a
//! kernel the registry declares schemed but the scheme table omits — or
//! declares unschemed but the table still carries — is a named drift, never
//! a silent flexible-type fallback.
//!
//! This is the defend-in-depth layer, not the structural fix: the true
//! source-of-truth join belongs in [`ipe_types::kernel_type_table`] itself
//! (returning this same reconciled shape for every kernel), which needs a
//! change to `src/compiler/types` out of scope here. This helper checks the
//! one drift the table's own construction cannot catch of itself — a filter
//! condition added to `kernel_type_table` that silently diverges from
//! `KernelDef::shape` would otherwise pass unnoticed.
//!
//! [`kernel_schemes`] is read by both the coverage surface (`coverage::surface`)
//! and `ipe doc`'s kernel-module renderer (`doc`), replacing each site's own
//! independent, drift-prone join.

use std::collections::BTreeMap;

use ipe_diagnostics::Diagnostic;
use ipe_intern::Interner;
use ipe_kernels::StdlibKernel;
use ipe_types::{Ty, kernel_type_table};

/// A kernel's HM type scheme, or the explicit absence a routed/unlowered
/// bucket carries.
#[derive(Clone, Debug)]
pub enum KernelScheme {
    /// The kernel's resolved type scheme.
    Schemed(Ty),
    /// The kernel is genuinely unschemed (a routed/unlowered bucket, not
    /// callable from well-typed Ipê — `IPE-L0108` refuses it at its call
    /// sites).
    Unschemed,
}

/// Why [`kernel_schemes`] could not join the registry against the scheme
/// table.
#[derive(Debug)]
pub enum KernelSchemeError {
    /// The scheme table itself failed to materialize.
    Table(Diagnostic),
    /// A kernel's declared shape and its presence in the table disagree.
    Drift {
        /// The kernel whose shape and table presence disagree.
        kernel: StdlibKernel,
        /// Whether [`ipe_kernels::KernelDef::shape`] is declared for this kernel.
        shape_declared: bool,
        /// Whether the kernel appeared in the scheme table's output.
        in_table: bool,
    },
    /// The scheme table carries the same kernel more than once — which entry
    /// is the scheme is undetermined.
    Duplicate {
        /// The kernel the table lists twice.
        kernel: StdlibKernel,
    },
}

impl std::fmt::Display for KernelSchemeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Table(d) => write!(
                f,
                "the kernel type-scheme table failed to materialize: {}",
                ipe_diagnostics::plain_message(d, "")
            ),
            Self::Drift {
                kernel,
                shape_declared,
                in_table,
            } => write!(
                f,
                "kernel `{kernel:?}` disagrees between its declared shape \
                 (shape_declared={shape_declared}) and its presence in the \
                 type-scheme table (in_table={in_table}) — the kernel registry \
                 and the scheme table have drifted apart"
            ),
            Self::Duplicate { kernel } => write!(
                f,
                "kernel `{kernel:?}` appears more than once in the type-scheme table"
            ),
        }
    }
}

impl std::error::Error for KernelSchemeError {}

/// The parametrized core of [`kernel_schemes`]: joins `all` against `table`
/// using `shape` to answer "does the registry declare this kernel schemed?",
/// independent of the live interner/table so a test can inject a failing or
/// drifted table without a real typecheck.
fn join(
    all: &[StdlibKernel],
    table: Result<Vec<(StdlibKernel, Ty)>, Diagnostic>,
    shape: impl Fn(StdlibKernel) -> bool,
) -> Result<Vec<(StdlibKernel, KernelScheme)>, KernelSchemeError> {
    let table = table.map_err(KernelSchemeError::Table)?;
    let mut by_kernel: BTreeMap<usize, Ty> = BTreeMap::new();
    for (kernel, ty) in table {
        if by_kernel.insert(kernel as usize, ty).is_some() {
            return Err(KernelSchemeError::Duplicate { kernel });
        }
    }

    all.iter()
        .map(|&kernel| {
            let shape_declared = shape(kernel);
            let ty = by_kernel.remove(&(kernel as usize));
            match (shape_declared, ty) {
                (true, Some(ty)) => Ok((kernel, KernelScheme::Schemed(ty))),
                (false, None) => Ok((kernel, KernelScheme::Unschemed)),
                (shape_declared, ty) => Err(KernelSchemeError::Drift {
                    kernel,
                    shape_declared,
                    in_table: ty.is_some(),
                }),
            }
        })
        .collect()
}

/// Every [`StdlibKernel`] joined against its HM type scheme.
///
/// # Errors
/// [`KernelSchemeError::Table`] if the scheme table fails to materialize;
/// [`KernelSchemeError::Drift`] if a kernel's declared shape and its table
/// presence disagree.
pub fn kernel_schemes(
    interner: &mut Interner,
) -> Result<Vec<(StdlibKernel, KernelScheme)>, KernelSchemeError> {
    join(StdlibKernel::ALL, kernel_type_table(interner), |k| {
        k.def().shape.is_some()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_diagnostic() -> Diagnostic {
        Diagnostic::CompilerBug {
            where_: "kernel_schemes.test",
            detail: "injected failure".to_owned(),
        }
    }

    fn dummy_ty() -> Ty {
        Ty::Unit
    }

    #[test]
    fn a_failing_table_is_a_typed_table_error() {
        let all = [StdlibKernel::LogInfo];
        let result = join(&all, Err(dummy_diagnostic()), |_| true);
        assert!(matches!(result, Err(KernelSchemeError::Table(_))));
    }

    #[test]
    fn a_schemed_kernel_absent_from_the_table_is_drift() {
        let all = [StdlibKernel::LogInfo];
        let result = join(&all, Ok(Vec::new()), |_| true);
        assert!(matches!(
            result,
            Err(KernelSchemeError::Drift {
                shape_declared: true,
                in_table: false,
                ..
            })
        ));
    }

    #[test]
    fn an_unschemed_kernel_present_in_the_table_is_drift() {
        let all = [StdlibKernel::LogInfo];
        let table = vec![(StdlibKernel::LogInfo, dummy_ty())];
        let result = join(&all, Ok(table), |_| false);
        assert!(matches!(
            result,
            Err(KernelSchemeError::Drift {
                shape_declared: false,
                in_table: true,
                ..
            })
        ));
    }

    #[test]
    fn a_kernel_the_table_lists_twice_is_a_duplicate_not_last_wins() {
        let all = [StdlibKernel::LogInfo];
        let table = vec![
            (StdlibKernel::LogInfo, dummy_ty()),
            (StdlibKernel::LogInfo, dummy_ty()),
        ];
        let result = join(&all, Ok(table), |_| true);
        assert!(matches!(
            result,
            Err(KernelSchemeError::Duplicate {
                kernel: StdlibKernel::LogInfo
            })
        ));
    }

    #[test]
    fn an_unschemed_kernel_absent_from_the_table_is_unschemed() {
        let all = [StdlibKernel::LogInfo];
        let result = join(&all, Ok(Vec::new()), |_| false);
        let rows = result.expect("no drift when shape and table presence agree");
        assert!(matches!(
            rows.as_slice(),
            [(StdlibKernel::LogInfo, KernelScheme::Unschemed)]
        ));
    }

    #[test]
    fn every_stdlib_kernel_resolves_against_the_live_table_exactly_once() {
        let mut interner = Interner::new();
        let rows = kernel_schemes(&mut interner)
            .expect("the live kernel registry and scheme table must agree");
        assert_eq!(rows.len(), StdlibKernel::ALL.len());
        let mut seen: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
        for (kernel, _) in &rows {
            assert!(
                seen.insert(*kernel as usize),
                "kernel {kernel:?} appeared twice"
            );
        }
    }
}
