//! The constraint solver, ported from the relevant core of
//! `Ipe.Type.Solve` (derivative of elm/compiler's `Type.Solve`,
//! BSD-3-Clause).
//!
//! The reference solver threads ranks / marks / generalisation for full
//! let-polymorphism. The supported subset has no nested `let`-generalisation
//! to model, so solving reduces to: run every generated equality
//! [`Constraint`] through
//! the unifier, in order, sharing one [`Budget`]. The defensive solver-step
//! bound (`IPE_SOLVER_BUDGET`) carries over in spirit, always as a positive
//! ceiling.

use std::num::NonZeroU64;

use ipe_diagnostics::{DResult, Diagnostic, Span, TypeError};
use ipe_intern::{Interner, Symbol};

use crate::homed::{InferError, ModuleHome};
use crate::ty::Content;
use crate::unify::unify_constraint;
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
    /// What the equality checks, so a failure can name its cause.
    pub origin: ConstraintOrigin,
}

/// What a [`Constraint`] checks beyond the bare equality of its two sides.
///
/// The solver reads it only when the constraint fails: a call's arity fault
/// shows as a shape mismatch, and the origin is what lets the one solve point
/// report it as the arity fault it is.
#[derive(Clone, Copy, Debug)]
pub enum ConstraintOrigin {
    /// An equality with no further meaning.
    Plain,
    /// A callee's type against the arrow its call's arguments shape.
    CallShape(CallSite),
    /// A call's result against the type its context expects of it.
    CallResult(CallSite),
}

/// One call, as an arity diagnostic names it.
#[derive(Clone, Copy, Debug)]
pub struct CallSite {
    /// The callee's type variable.
    pub callee: VarId,
    /// The callee's name, when the call names it directly.
    pub name: Option<CalleeName>,
    /// How many arguments the call gives.
    pub given: usize,
}

/// A directly named callee: `greet`, or `List.sum` with its module qualifier.
#[derive(Clone, Copy, Debug)]
pub struct CalleeName {
    /// The module a kernel callee is read through.
    pub qualifier: Option<Symbol>,
    /// The callee's own name.
    pub name: Symbol,
}

/// A solver step ceiling: a positive number of steps, never "no limit".
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SolverSteps(NonZeroU64);

/// Why a solver budget setting names no step ceiling.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SolverStepsError {
    /// The setting is `0`, which admits no step at all.
    Zero,
}

impl SolverStepsError {
    /// The typed refusal a program meets under this setting.
    ///
    /// A zero setting is a ceiling of no steps, so it is the step-budget
    /// refusal (IPE-T0003) for a budget of `0`, raised before any solving.
    #[must_use]
    pub const fn into_diagnostic(self) -> Diagnostic {
        match self {
            Self::Zero => Diagnostic::Type {
                span: Span::DUMMY,
                msg: TypeError::StepBudgetExceeded { budget: 0 },
            },
        }
    }
}

impl SolverSteps {
    /// The [`DEFAULT_SOLVER_BUDGET`] ceiling.
    pub const DEFAULT: Self = match NonZeroU64::new(DEFAULT_SOLVER_BUDGET) {
        Some(steps) => Self(steps),
        // A zero default would admit no step: the least ceiling refuses closed.
        None => Self(NonZeroU64::MIN),
    };

    /// The largest ceiling.
    pub const MAX: Self = Self(NonZeroU64::MAX);

    /// A ceiling of `steps`, or `None` for zero.
    #[must_use]
    pub const fn new(steps: u64) -> Option<Self> {
        match NonZeroU64::new(steps) {
            Some(steps) => Some(Self(steps)),
            None => None,
        }
    }

    /// The step count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// The ceiling the solver budget variable ([`BUDGET_ENV`]) names.
    ///
    /// # Errors
    /// [`SolverStepsError::Zero`] when the variable is `0`.
    pub fn from_env() -> Result<Self, SolverStepsError> {
        Self::from_setting(ipe_env::var(BUDGET_ENV).ok().as_deref())
    }

    /// The ceiling a raw setting names: unset is the default, `0` is refused.
    ///
    /// A malformed value falls back to the default.
    ///
    /// # Errors
    /// [`SolverStepsError::Zero`] when the trimmed setting parses to `0`.
    pub fn from_setting(raw: Option<&str>) -> Result<Self, SolverStepsError> {
        match raw.map(|raw| raw.trim().parse::<u64>()) {
            None | Some(Err(_)) => Ok(Self::DEFAULT),
            Some(Ok(steps)) => Self::new(steps).ok_or(SolverStepsError::Zero),
        }
    }
}

/// A decrementing solver-step budget under a [`SolverSteps`] ceiling.
///
/// Each unify/occurs/zonk step ticks it; the step past the ceiling raises
/// [`TypeError::StepBudgetExceeded`] carrying the ceiling (so the help line
/// can name the value to raise).
pub struct Budget {
    remaining: u64,
    /// The step ceiling this budget was created with, reported in the diagnostic.
    limit: SolverSteps,
}

impl Budget {
    /// A budget of `steps` steps.
    #[must_use]
    pub const fn new(steps: SolverSteps) -> Self {
        Self {
            remaining: steps.get(),
            limit: steps,
        }
    }

    /// A budget of [`SolverSteps::MAX`] steps, which no test reaches.
    #[cfg(test)]
    #[must_use]
    pub const fn unbounded() -> Self {
        Self::new(SolverSteps::MAX)
    }

    /// The steps consumed so far.
    ///
    /// Equals the ceiling once a tick has been refused.
    #[must_use]
    pub const fn spent(&self) -> u64 {
        self.limit.get().saturating_sub(self.remaining)
    }

    /// Consume `steps` steps at once, all or none.
    ///
    /// A refused charge leaves the budget exhausted, as a refused tick does.
    ///
    /// # Errors
    /// [`TypeError::StepBudgetExceeded`] when fewer than `steps` remain,
    /// carrying the configured `limit`.
    pub const fn charge(&mut self, steps: u64) -> DResult<()> {
        if let Some(next) = self.remaining.checked_sub(steps) {
            self.remaining = next;
            Ok(())
        } else {
            self.remaining = 0;
            Err(Diagnostic::Type {
                span: Span::DUMMY,
                msg: TypeError::StepBudgetExceeded {
                    budget: self.limit.get(),
                },
            })
        }
    }

    /// Consume one step.
    ///
    /// # Errors
    /// [`TypeError::StepBudgetExceeded`] when the budget is exhausted, carrying
    /// the configured `limit`.
    pub const fn tick(&mut self) -> DResult<()> {
        match self.remaining.checked_sub(1) {
            Some(next) => {
                self.remaining = next;
                Ok(())
            }
            None => Err(Diagnostic::Type {
                span: Span::DUMMY,
                msg: TypeError::StepBudgetExceeded {
                    budget: self.limit.get(),
                },
            }),
        }
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
        unify_constraint(uf, budget, interner, c)?;
    }
    Ok(())
}
