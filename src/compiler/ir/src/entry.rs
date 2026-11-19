//! How the emitted `fn main` runs the program's entry.
//!
//! The one classification of `main`'s lowered return type. The lowerer admits a
//! `main` exactly when [`EntryRun::of`] names a form, and the backend picks the
//! emitted entry line from the same form in every layout, so the admitted set
//! and the emitted set cannot drift apart.

use crate::{IrType, Program};

/// The run form of an entry function.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntryRun {
    /// A task the runtime drives to completion: `block_on_entry(ipe_main)`.
    Task,
    /// A shape-app handle that owns its event loop:
    /// `run_blocking_entry(ipe_main)`.
    ShapeApp,
}

impl EntryRun {
    /// The run form of an entry returning `ret`, or `None` when no emitted entry
    /// can run it (an `Int`, a `String`, a function, …).
    ///
    /// * `Task(_)` — a `Task Error a`; the run site discards the produced value.
    /// * `Result(Error, _)` — `main = someTask |> Task.run`; the backend re-wraps
    ///   the settled `Result` into a task.
    /// * `Unit` — a synchronous body; the backend wraps it as `task_succeed(())`.
    /// * `WebApp` / `TuiApp` / `CliApp` / `WorkerApp` — shape-app leaves.
    #[must_use]
    pub fn of(ret: &IrType) -> Option<Self> {
        match ret {
            IrType::Task(_) | IrType::Unit => Some(Self::Task),
            IrType::Result(err, _) if matches!(**err, IrType::Error) => Some(Self::Task),
            IrType::WebApp | IrType::TuiApp | IrType::CliApp | IrType::WorkerApp => {
                Some(Self::ShapeApp)
            }
            _ => None,
        }
    }

    /// Whether some module of `program` names an entry function whose run form
    /// is `self`.
    #[must_use]
    pub fn is_entry_of(self, program: &Program) -> bool {
        program.modules.iter().any(|m| {
            m.entry.is_some_and(|eid| {
                m.funcs
                    .iter()
                    .any(|f| f.id == eid && Self::of(&f.ret) == Some(self))
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::EntryRun;
    use crate::IrType;

    #[test]
    fn every_shape_leaf_runs_as_a_shape_app() {
        for leaf in [
            IrType::WebApp,
            IrType::TuiApp,
            IrType::CliApp,
            IrType::WorkerApp,
        ] {
            assert_eq!(EntryRun::of(&leaf), Some(EntryRun::ShapeApp), "{leaf:?}");
        }
    }

    #[test]
    fn task_shapes_run_as_a_task() {
        for ret in [
            IrType::Task(Box::new(IrType::Unit)),
            IrType::Unit,
            IrType::Result(Box::new(IrType::Error), Box::new(IrType::Int)),
        ] {
            assert_eq!(EntryRun::of(&ret), Some(EntryRun::Task), "{ret:?}");
        }
    }

    #[test]
    fn a_value_with_no_effect_has_no_run_form() {
        for ret in [
            IrType::Int,
            IrType::Str,
            IrType::Result(Box::new(IrType::Int), Box::new(IrType::Int)),
        ] {
            assert_eq!(EntryRun::of(&ret), None, "{ret:?}");
        }
    }
}
