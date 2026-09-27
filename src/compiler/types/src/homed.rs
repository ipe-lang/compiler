//! Diagnostics paired with the module that owns them.
//!
//! Spans in a linked multi-module program are byte offsets local to each
//! source file, so a span alone cannot name its file: the owning module path
//! (the "home") is the only exact key. Every type-checker warning therefore
//! carries its home from the point of construction.

use ipe_diagnostics::{Diagnostic, Severity};
use ipe_intern::Symbol;

/// A diagnostic paired with the `home` module path of the definition owning it.
///
/// The path is empty when the diagnostic belongs to no single definition.
pub type HomedDiagnostic = (Diagnostic, Vec<Symbol>);

/// A Warning-severity diagnostic paired with its non-empty owning module path.
///
/// Built only through [`HomedWarning::new`], so a value of this type is proof
/// that the diagnostic is a warning (it cannot fail compilation) and that its
/// home names exactly one module (its span frames against that module's file).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HomedWarning {
    diagnostic: Diagnostic,
    home: Vec<Symbol>,
}

impl HomedWarning {
    /// Pair a Warning-severity `diagnostic` with the module `home` owning it.
    ///
    /// # Errors
    /// * The diagnostic itself, homed, when its severity is not
    ///   [`Severity::Warning`]: a finding that must fail compilation is
    ///   refused as a warning and returned as the compilation error instead.
    /// * [`Diagnostic::CompilerBug`] when `home` is empty: a warning with no
    ///   owning module has no file to render against.
    pub fn new(diagnostic: Diagnostic, home: &[Symbol]) -> Result<Self, HomedDiagnostic> {
        if diagnostic.severity() != Severity::Warning {
            return Err((diagnostic, home.to_vec()));
        }
        if home.is_empty() {
            return Err((
                Diagnostic::CompilerBug {
                    where_: "types.homed_warning",
                    detail: "a warning reached the type checker's output without an owning module"
                        .to_owned(),
                },
                Vec::new(),
            ));
        }
        Ok(Self {
            diagnostic,
            home: home.to_vec(),
        })
    }

    /// The warning diagnostic.
    #[must_use]
    pub const fn diagnostic(&self) -> &Diagnostic {
        &self.diagnostic
    }

    /// The module path owning the warning; never empty.
    #[must_use]
    pub const fn home(&self) -> &[Symbol] {
        self.home.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipe_diagnostics::{Span, TypeError};

    fn redundant_branch() -> Diagnostic {
        Diagnostic::Type {
            span: Span::DUMMY,
            msg: TypeError::RedundantCaseBranch {
                constructor: "Red".into(),
            },
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
                refused,
                Err((
                    Diagnostic::CompilerBug {
                        where_: "types.homed_warning",
                        ..
                    },
                    _
                ))
            ),
            "a warning without a home must be refused, got {refused:?}"
        );
    }

    #[test]
    fn error_severity_is_refused_and_returned_homed() {
        let home = vec![Symbol::from_raw(0)];
        let error = Diagnostic::CompilerBug {
            where_: "types.test",
            detail: String::new(),
        };
        assert_ne!(error.severity(), Severity::Warning);
        let refused = HomedWarning::new(error.clone(), &home);
        assert_eq!(refused, Err((error, home)));
    }
}
