//! The constraint solver, ported from the relevant core of
//! `Ipe.Type.Solve` (derivative of elm/compiler's `Type.Solve`,
//! BSD-3-Clause).
//!
//! The reference solver threads ranks / marks / generalisation for full
//! let-polymorphism. The supported subset has no nested `let`-generalisation
//! to model, so solving reduces to: run every generated equality
//! [`Constraint`] through
//! the unifier, in order, sharing one [`Budget`]. The defensive solver-step
//! bound (`IPE_SOLVER_BUDGET`) carries over verbatim in spirit.

use ipe_diagnostics::{DResult, Diagnostic, Span, TypeError};
use ipe_intern::Interner;

use crate::homed::{InferError, ModuleHome};
use crate::ty::Content;
use crate::unify::unify_at;
use crate::unionfind::{UnionFind, VarId};

/// Default cap on solver steps before bailing.
///
/// Ordinary programs consume well under a thousand steps; the cap exists purely
/// to bound adversarial blow-up.
pub const DEFAULT_SOLVER_BUDGET: u64 = 5_000_000;

/// Environment variable that overrides [`DEFAULT_SOLVER_BUDGET`].
pub const BUDGET_ENV: &str = "IPE_SOLVER_BUDGET";

/// A single constraint: the types of two solver variables must unify.
///
/// The [`Span`] is the source region blamed in any resulting [`TypeError`],
/// and `home` is the module owning the expression that emitted it: a span is
/// byte offsets with no file, so the home is the only key to its file.
#[derive(Clone, Debug)]
pub struct Constraint {
    pub span: Span,
    pub lhs: VarId,
    pub rhs: VarId,
    /// The module that owns the constrained expression.
    pub home: ModuleHome,
}

/// A decrementing solver-step budget.
///
/// Each unify/occurs/zonk step ticks it; reaching zero raises
/// [`TypeError::StepBudgetExceeded`] carrying the original `limit` (so the help
/// line can name the value to raise). A budget of `None` is disabled (the
/// `IPE_SOLVER_BUDGET=0` escape hatch).
pub struct Budget {
    remaining: Option<u64>,
    /// The step cap this budget was created with, reported in the diagnostic.
    /// `0` for an unbounded budget (never surfaced — it cannot be exhausted).
    limit: u64,
}

impl Budget {
    /// A budget with an explicit step cap.
    #[must_use]
    pub const fn new(steps: u64) -> Self {
        Self {
            remaining: Some(steps),
            limit: steps,
        }
    }

    /// A disabled (unbounded) budget.
    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            remaining: None,
            limit: 0,
        }
    }

    /// Resolve the budget from the environment, mirroring the reference compiler
    /// three-mode resolution (unset → default; `0` → disabled; `N` → absolute).
    /// A malformed value falls back to the default rather than failing the
    /// build — the budget is a guard rail, not a feature.
    #[must_use]
    pub fn from_env() -> Self {
        ipe_env::var(BUDGET_ENV).map_or_else(
            |_| Self::new(DEFAULT_SOLVER_BUDGET),
            |raw| match raw.trim().parse::<u64>() {
                Ok(0) => Self::unbounded(),
                Ok(n) => Self::new(n),
                Err(_) => Self::new(DEFAULT_SOLVER_BUDGET),
            },
        )
    }

    /// Consume one step.
    ///
    /// # Errors
    /// [`TypeError::StepBudgetExceeded`] when the budget is exhausted, carrying
    /// the configured `limit`.
    pub const fn tick(&mut self) -> DResult<()> {
        if let Some(remaining) = self.remaining.as_mut() {
            match remaining.checked_sub(1) {
                Some(next) => *remaining = next,
                None => {
                    return Err(Diagnostic::Type {
                        span: Span::DUMMY,
                        msg: TypeError::StepBudgetExceeded { budget: self.limit },
                    });
                }
            }
        }
        Ok(())
    }
}

/// Solve every constraint in order, unifying in place.
///
/// A failing constraint is sited at the module owning the constrained
/// expression, so the driver frames it against exactly that module's file.
///
/// # Errors
/// [`InferError::Sited`] at the failing constraint's home for a mismatch or
/// an infinite type; [`InferError::Program`] for a step-budget exhaustion or a
/// union-find invariant violation.
pub fn solve_attributed(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    constraints: &[Constraint],
) -> Result<(), InferError> {
    for c in constraints {
        unify_at(uf, budget, interner, &c.home, c.span, c.lhs, c.rhs)?;
    }
    Ok(())
}
