//! Diagnostics paired with the module that owns them.
//!
//! Spans in a linked multi-module program are byte offsets that every module
//! shares, so a span alone cannot name its file: the owning module path (the
//! "home") is the only exact key. Every source-attributed error and warning
//! the type checker returns therefore carries its home from the point of
//! construction, typed as a [`ModuleHome`] that cannot be empty.

use ipe_diagnostics::{Diagnostic, Severity, TypeError};
use ipe_intern::Symbol;

/// A non-empty module path naming the module that owns a span.
///
/// Built only through [`ModuleHome::new`], so a value of this type is proof
/// that the path names exactly one module and a span paired with it frames
/// against that module's file.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ModuleHome(Vec<Symbol>);

impl ModuleHome {
    /// The home named by `path`, or `None` when `path` is empty.
    #[must_use]
    pub fn new(path: Vec<Symbol>) -> Option<Self> {
        if path.is_empty() {
            None
        } else {
            Some(Self(path))
        }
    }

    /// The module path; never empty.
    #[must_use]
    pub const fn path(&self) -> &[Symbol] {
        self.0.as_slice()
    }

    /// The owned module path; never empty.
    #[must_use]
    pub fn into_path(self) -> Vec<Symbol> {
        self.0
    }
}

/// A diagnostic that belongs to the whole program rather than to one module.
///
/// Built only through [`InferError::unsited`] and [`InferError::sited`], so it
/// holds a [`Diagnostic::CompilerBug`] or a step-budget exhaustion and never a
/// source error that would need a file to frame against.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProgramDiag(Diagnostic);

impl ProgramDiag {
    /// The whole-program diagnostic.
    #[must_use]
    pub const fn diagnostic(&self) -> &Diagnostic {
        &self.0
    }

    /// The owned whole-program diagnostic.
    #[must_use]
    pub fn into_diagnostic(self) -> Diagnostic {
        self.0
    }
}

/// The one error type the type checker returns.
///
/// A source error always names the module owning its span; only an internal
/// or whole-program diagnostic has no home.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum InferError {
    /// A source error and the module whose file its span belongs to.
    Sited {
        /// The source error.
        diag: Diagnostic,
        /// The module owning the error's span.
        home: ModuleHome,
    },
    /// An internal or whole-program diagnostic with no owning module.
    Program(ProgramDiag),
}

/// Whether `diag` belongs to the whole program instead of one module.
const fn is_program_wide(diag: &Diagnostic) -> bool {
    matches!(
        diag,
        Diagnostic::CompilerBug { .. }
            | Diagnostic::Type {
                msg: TypeError::StepBudgetExceeded { .. },
                ..
            }
    )
}

impl InferError {
    /// Classify a diagnostic produced with no owning module.
    ///
    /// A [`Diagnostic::CompilerBug`] or step-budget exhaustion passes through.
    /// Any other diagnostic is a source error that lost its home, so it is
    /// refused as a [`Diagnostic::CompilerBug`] carrying its code and is never
    /// framed against a guessed file.
    #[must_use]
    pub fn unsited(diag: Diagnostic) -> Self {
        if is_program_wide(&diag) {
            return Self::Program(ProgramDiag(diag));
        }
        Self::Program(ProgramDiag(Diagnostic::CompilerBug {
            where_: "types.unsited_error",
            detail: format!(
                "source error {} reached the type checker's output without an owning module",
                diag.code().as_str()
            ),
        }))
    }

    /// Pair a diagnostic with the module `home` owning its span.
    ///
    /// A whole-program diagnostic stays unsited: it has no span to frame.
    #[must_use]
    pub fn sited(diag: Diagnostic, home: &ModuleHome) -> Self {
        if is_program_wide(&diag) {
            return Self::Program(ProgramDiag(diag));
        }
        Self::Sited {
            diag,
            home: home.clone(),
        }
    }

    /// Pair a diagnostic with the module `path`, failing closed on an empty one.
    ///
    /// An empty `path` names no file, so the diagnostic goes through
    /// [`InferError::unsited`].
    #[must_use]
    pub fn sited_at_path(diag: Diagnostic, path: &[Symbol]) -> Self {
        match ModuleHome::new(path.to_vec()) {
            Some(home) => Self::sited(diag, &home),
            None => Self::unsited(diag),
        }
    }

    /// The diagnostic, sited or not.
    #[must_use]
    pub const fn diagnostic(&self) -> &Diagnostic {
        match self {
            Self::Sited { diag, .. } => diag,
            Self::Program(program) => program.diagnostic(),
        }
    }

    /// The owning module, or `None` for a whole-program diagnostic.
    #[must_use]
    pub const fn home(&self) -> Option<&ModuleHome> {
        match self {
            Self::Sited { home, .. } => Some(home),
            Self::Program(_) => None,
        }
    }

    /// The owned diagnostic, sited or not.
    #[must_use]
    pub fn into_diagnostic(self) -> Diagnostic {
        match self {
            Self::Sited { diag, .. } => diag,
            Self::Program(program) => program.into_diagnostic(),
        }
    }
}

/// A Warning-severity diagnostic paired with its owning module.
///
/// Built only through [`HomedWarning::new`], so a value of this type is proof
/// that the diagnostic is a warning (it cannot fail compilation) and that its
/// home names exactly one module (its span frames against that module's file).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HomedWarning {
    diagnostic: Diagnostic,
    home: ModuleHome,
}

impl HomedWarning {
    /// Pair a Warning-severity `diagnostic` with the module `home` owning it.
    ///
    /// # Errors
    /// * The diagnostic itself, sited at `home`, when its severity is not
    ///   [`Severity::Warning`]: a finding that must fail compilation is
    ///   refused as a warning and returned as the compilation error instead.
    /// * [`Diagnostic::CompilerBug`] when `home` is empty: a warning with no
    ///   owning module has no file to render against.
    pub fn new(diagnostic: Diagnostic, home: &[Symbol]) -> Result<Self, InferError> {
        if diagnostic.severity() != Severity::Warning {
            return Err(InferError::sited_at_path(diagnostic, home));
        }
        let Some(home) = ModuleHome::new(home.to_vec()) else {
            return Err(InferError::Program(ProgramDiag(Diagnostic::CompilerBug {
                where_: "types.homed_warning",
                detail: "a warning reached the type checker's output without an owning module"
                    .to_owned(),
            })));
        };
        Ok(Self { diagnostic, home })
    }

    /// The warning diagnostic.
    #[must_use]
    pub const fn diagnostic(&self) -> &Diagnostic {
        &self.diagnostic
    }

    /// The module path owning the warning; never empty.
    #[must_use]
    pub const fn home(&self) -> &[Symbol] {
        self.home.path()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipe_diagnostics::Span;

    fn redundant_branch() -> Diagnostic {
        Diagnostic::Type {
            span: Span::DUMMY,
            msg: TypeError::RedundantCaseBranch {
                constructor: "Red".into(),
            },
        }
    }

    fn mismatch() -> Diagnostic {
        Diagnostic::Type {
            span: Span::DUMMY,
            msg: TypeError::Mismatch,
        }
    }

    #[test]
    fn warning_with_home_is_accepted() {
        let home = vec![Symbol::from_raw(0)];
        let homed = HomedWarning::new(redundant_branch(), &home);
        assert!(homed.is_ok(), "a homed warning must be accepted");
        let Ok(homed) = homed else { return };
        assert_eq!(homed.home(), home.as_slice());
        assert_eq!(homed.diagnostic(), &redundant_branch());
    }

    #[test]
    fn empty_home_is_refused_as_compiler_bug() {
        let refused = HomedWarning::new(redundant_branch(), &[]);
        assert!(
            matches!(
                refused.as_ref().map_err(InferError::diagnostic),
                Err(Diagnostic::CompilerBug {
                    where_: "types.homed_warning",
                    ..
                })
            ),
            "a warning without a home must be refused, got {refused:?}"
        );
        assert!(matches!(refused, Err(InferError::Program(_))));
    }

    #[test]
    fn error_severity_is_refused_and_returned_sited() {
        let path = vec![Symbol::from_raw(0)];
        let refused = HomedWarning::new(mismatch(), &path);
        assert_eq!(
            refused,
            Err(InferError::Sited {
                diag: mismatch(),
                home: ModuleHome(path),
            })
        );
    }

    #[test]
    fn unsited_refuses_a_source_error() {
        let refused = InferError::unsited(mismatch());
        assert!(
            matches!(
                refused.diagnostic(),
                Diagnostic::CompilerBug {
                    where_: "types.unsited_error",
                    ..
                }
            ),
            "a homeless source error must become a compiler bug, got {refused:?}"
        );
        assert!(refused.home().is_none());
        let Diagnostic::CompilerBug { detail, .. } = refused.diagnostic() else {
            return;
        };
        assert!(
            detail.contains(mismatch().code().as_str()),
            "the refusal must carry the lost error's code, got {detail:?}"
        );
    }

    #[test]
    fn unsited_keeps_whole_program_diagnostics() {
        let bug = Diagnostic::CompilerBug {
            where_: "types.test",
            detail: String::new(),
        };
        assert_eq!(
            InferError::unsited(bug.clone()),
            InferError::Program(ProgramDiag(bug))
        );
        let budget = Diagnostic::Type {
            span: Span::DUMMY,
            msg: TypeError::StepBudgetExceeded { budget: 7 },
        };
        assert_eq!(
            InferError::unsited(budget.clone()),
            InferError::Program(ProgramDiag(budget))
        );
    }

    #[test]
    fn empty_module_home_is_unrepresentable() {
        assert_eq!(ModuleHome::new(Vec::new()), None);
        let path = vec![Symbol::from_raw(0)];
        assert_eq!(
            ModuleHome::new(path.clone()).map(ModuleHome::into_path),
            Some(path)
        );
    }

    #[test]
    fn sited_at_empty_path_fails_closed() {
        let refused = InferError::sited_at_path(mismatch(), &[]);
        assert!(
            matches!(
                refused.diagnostic(),
                Diagnostic::CompilerBug {
                    where_: "types.unsited_error",
                    ..
                }
            ),
            "an empty path must not site a source error, got {refused:?}"
        );
    }
}
