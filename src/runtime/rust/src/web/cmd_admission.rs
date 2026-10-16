//! The one point where a web session's `Perform` Cmd is started or refused.
//!
//! [`admit`] draws one [`CmdPermit`] from the session's [`SessionCmds`] before
//! it starts the body; without one it turns the body into its failure Msg
//! unstarted. An [`AdmittedCmd`] pairs the started future with its permit and
//! has no other constructor, so a started web Cmd always holds a unit and the
//! unit returns when the Cmd's result is handed to the session queue, or when
//! the task is dropped.

use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::error::SendError;

use super::budget::{CmdPermit, OverBudget, SESSION_CMD_CEILING, SessionCmds};
use crate::LimitRefusal;
use crate::tea::{PerformBody, PerformFuture};

/// What [`admit`] made of one `Perform` body.
pub(crate) enum Admit<M> {
    /// The body started under a held permit.
    Run(AdmittedCmd<M>),
    /// The body's failure Msg; the effect never started.
    Refused(M),
}

/// A started `Perform` body and the permit it holds until its Msg is handed over.
pub(crate) struct AdmittedCmd<M> {
    fut: PerformFuture<M>,
    permit: CmdPermit,
}

/// Start `body` under one of the session's Cmd units, or refuse it unstarted.
pub(crate) fn admit<M>(body: Box<dyn PerformBody<M>>, cmds: &SessionCmds) -> Admit<M> {
    match cmds.try_permit() {
        Ok(permit) => Admit::Run(AdmittedCmd {
            fut: body.run(),
            permit,
        }),
        Err(why) => {
            if cmds.first_refusal(why) {
                crate::system::emit_runtime_log("live", refusal_log(why));
            }
            Admit::Refused(body.refuse(refusal(why)))
        }
    }
}

/// The program-facing refusal for the bound `why` names.
fn refusal(why: OverBudget) -> LimitRefusal {
    let text = match why {
        OverBudget::Session => format!(
            "this session already has {} commands running; this command was not started",
            SESSION_CMD_CEILING.get()
        ),
        OverBudget::Process => "the server already has the maximum number of commands running; \
                                this command was not started"
            .to_owned(),
    };
    LimitRefusal::new(text).context("web session commands")
}

/// The operator log line for the first refusal by the bound `why` names.
const fn refusal_log(why: OverBudget) -> &'static str {
    match why {
        OverBudget::Session => {
            "run_cmd: a session reached its in-flight command ceiling; its further commands are refused until one finishes"
        }
        OverBudget::Process => {
            "run_cmd: the server reached its in-flight command budget; further commands are refused until one finishes"
        }
    }
}

impl<M: Send> AdmittedCmd<M> {
    /// Run the Cmd to its Msg and hand the Msg to `tx`, then return the unit.
    ///
    /// # Errors
    ///
    /// The Msg back when the session queue is closed; the unit returns then too.
    pub(crate) async fn finish(self, tx: &Sender<M>) -> Result<(), SendError<M>> {
        let Self { fut, permit } = self;
        let msg = fut.await;
        let sent = tx.send(msg).await;
        drop(permit);
        sent
    }
}

/// Hand a refused Cmd's failure Msg to the session queue without waiting.
///
/// A full or closed queue drops the Msg: awaiting room would stall the driver
/// on its own queue, and a sender task per refusal would make refusals an
/// unbounded task count. The effect was never started either way.
pub(crate) fn deliver_refusal<M>(msg: M, tx: &Sender<M>, cmds: &SessionCmds) {
    if let Ok(slot) = tx.try_reserve() {
        slot.send(msg);
    } else if cmds.first_dropped_refusal() {
        crate::system::emit_runtime_log(
            "live",
            "run_cmd: session msg queue full or closed; dropping a refused command's failure",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tea::{IpeCmd, cmd_perform};
    use crate::web::budget::{Budget, Cmds, PROCESS_CMD_BUDGET};
    use crate::{
        IpeError, IpeResult, IpeTask, ipe_error_kind, ipe_error_kind_name, ipe_error_message,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::{Semaphore, mpsc};

    #[derive(Debug, PartialEq, Eq)]
    enum Msg {
        Done(i64),
        Failed { kind: String, message: String },
    }

    fn decode(result: IpeResult<IpeError, i64>) -> Msg {
        match result {
            IpeResult::Ok(n) => Msg::Done(n),
            IpeResult::Err(e) => Msg::Failed {
                kind: ipe_error_kind_name(ipe_error_kind(e.clone())),
                message: ipe_error_message(e),
            },
        }
    }

    fn perform(cmd: IpeCmd<Msg>) -> Option<Box<dyn PerformBody<Msg>>> {
        match cmd {
            IpeCmd::Perform(body) => Some(body),
            IpeCmd::None | IpeCmd::Batch(_) | IpeCmd::Publish(_) => None,
        }
    }

    /// A body that counts its start, then waits for a pass from `gate`.
    fn gated(
        started: &Arc<AtomicUsize>,
        gate: &Arc<Semaphore>,
    ) -> Option<Box<dyn PerformBody<Msg>>> {
        let (started, gate) = (Arc::clone(started), Arc::clone(gate));
        let task: IpeTask<IpeError, i64> = Box::pin(async move {
            started.fetch_add(1, Ordering::SeqCst);
            drop(gate.acquire().await);
            IpeResult::Ok(1)
        });
        perform(cmd_perform(task, decode))
    }

    /// A body that finishes at once with `n`.
    fn ready(n: i64) -> Option<Box<dyn PerformBody<Msg>>> {
        let task: IpeTask<IpeError, i64> = Box::pin(async move { IpeResult::Ok(n) });
        perform(cmd_perform(task, decode))
    }

    /// Yield until `started` reaches `want`, within a bounded number of turns.
    async fn until_started(started: &AtomicUsize, want: usize) {
        for _ in 0..10_000 {
            if started.load(Ordering::SeqCst) >= want {
                return;
            }
            tokio::task::yield_now().await;
        }
    }

    fn count(n: usize) -> u64 {
        u64::try_from(n).unwrap_or(u64::MAX)
    }

    /// Of 65 pending Performs exactly 64 start and the 65th is refused with a
    /// `LimitExceeded` naming the ceiling; 64 alone are all admitted.
    #[tokio::test]
    async fn sixty_fifth_refused() {
        let ceiling = SESSION_CMD_CEILING.get();
        let cmds = SessionCmds::new();
        let started = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(0));
        let (tx, mut rx) = mpsc::channel::<Msg>(256);
        let bodies: Vec<_> = (0..=ceiling)
            .filter_map(|_| gated(&started, &gate))
            .collect();
        assert_eq!(count(bodies.len()), ceiling + 1);
        let mut refused = Vec::new();
        let mut tasks = Vec::new();
        for body in bodies {
            match admit(body, &cmds) {
                Admit::Run(cmd) => {
                    let tx = tx.clone();
                    tasks.push(tokio::spawn(async move { cmd.finish(&tx).await.is_ok() }));
                }
                Admit::Refused(msg) => refused.push(msg),
            }
        }
        until_started(&started, tasks.len()).await;
        assert_eq!(
            count(started.load(Ordering::SeqCst)),
            ceiling,
            "exactly the ceiling starts"
        );
        assert_eq!(cmds.used(), SESSION_CMD_CEILING);
        assert_eq!(refused.len(), 1, "exactly one Cmd is refused");
        let running = format!("{ceiling} commands running");
        assert!(
            refused.iter().all(|m| matches!(
                m,
                Msg::Failed { kind, message } if kind == "LimitExceeded" && message.contains(&running)
            )),
            "the refusal is a LimitExceeded naming the ceiling: {refused:?}"
        );

        gate.add_permits(tasks.len());
        for task in tasks {
            assert!(
                matches!(task.await, Ok(true)),
                "an admitted Cmd delivers its Msg"
            );
        }
        for _ in 0..ceiling {
            assert_eq!(rx.recv().await, Some(Msg::Done(1)));
        }
        assert_eq!(
            cmds.used(),
            Cmds::new(0),
            "every finished Cmd returns its unit"
        );

        // Control: the ceiling alone is admitted whole.
        let control = SessionCmds::new();
        let held: Vec<_> = (0..ceiling)
            .filter_map(|_| ready(0))
            .map(|body| admit(body, &control))
            .collect();
        assert_eq!(count(held.len()), ceiling);
        assert!(
            held.iter().all(|a| matches!(a, Admit::Run(_))),
            "a Cmd under the ceiling is never refused"
        );
    }

    /// Finishing one admitted Cmd lets the next one admit.
    #[tokio::test]
    async fn finished_cmd_frees_slot() {
        let process = Budget::process(Cmds::new(8));
        let cmds = SessionCmds::with_limits(&process, Cmds::new(1));
        let (tx, mut rx) = mpsc::channel::<Msg>(4);
        let first = ready(2).map(|body| admit(body, &cmds));
        assert!(matches!(first, Some(Admit::Run(_))));
        let Some(Admit::Run(first)) = first else {
            return;
        };
        let blocked = ready(3).map(|body| admit(body, &cmds));
        assert!(
            matches!(blocked, Some(Admit::Refused(Msg::Failed { .. }))),
            "a full session refuses"
        );
        assert!(first.finish(&tx).await.is_ok());
        assert_eq!(rx.recv().await, Some(Msg::Done(2)));
        assert_eq!(cmds.used(), Cmds::new(0));
        let next = ready(4).map(|body| admit(body, &cmds));
        assert!(
            matches!(next, Some(Admit::Run(_))),
            "a returned unit admits the next Cmd"
        );
    }

    /// Permits return when the session queue is closed, and when the runtime
    /// holding unfinished Cmds is dropped.
    #[test]
    fn closed_session_returns_permits() {
        let process = Budget::process(Cmds::new(8));
        let cmds = SessionCmds::with_limits(&process, Cmds::new(4));
        let started = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(0));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let (tx, rx) = mpsc::channel::<Msg>(4);
            let tasks: Vec<_> = (0..4)
                .filter_map(|_| gated(&started, &gate))
                .filter_map(|body| match admit(body, &cmds) {
                    Admit::Run(cmd) => Some(cmd),
                    Admit::Refused(_) => None,
                })
                .map(|cmd| {
                    let tx = tx.clone();
                    tokio::spawn(async move { cmd.finish(&tx).await.is_err() })
                })
                .collect();
            assert_eq!(tasks.len(), 4);
            until_started(&started, 4).await;
            assert_eq!(cmds.used(), Cmds::new(4));
            drop(rx);
            gate.add_permits(4);
            for task in tasks {
                assert!(
                    matches!(task.await, Ok(true)),
                    "a closed queue fails the send"
                );
            }
        });
        assert_eq!((cmds.used(), process.used()), (Cmds::new(0), Cmds::new(0)));

        // A runtime dropped with Cmds still running returns their units.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let never = Arc::new(Semaphore::new(0));
        let restarted = Arc::new(AtomicUsize::new(0));
        let (tx, _rx) = mpsc::channel::<Msg>(4);
        rt.block_on(async {
            for body in (0..4).filter_map(|_| gated(&restarted, &never)) {
                if let Admit::Run(cmd) = admit(body, &cmds) {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        let _ = cmd.finish(&tx).await;
                    });
                }
            }
            until_started(&restarted, 4).await;
        });
        assert_eq!(
            cmds.used(),
            Cmds::new(4),
            "the parked Cmds hold their units"
        );
        drop(rt);
        assert_eq!((cmds.used(), process.used()), (Cmds::new(0), Cmds::new(0)));
    }

    /// A storm of refusals spawns no task and holds no unit; a full queue
    /// drops the refusal, and a free slot delivers it.
    #[tokio::test]
    async fn refusal_storm_bounded() {
        let ceiling = SESSION_CMD_CEILING.get();
        let process = Budget::process(PROCESS_CMD_BUDGET);
        let cmds = SessionCmds::with_limits(&process, SESSION_CMD_CEILING);
        let held: Vec<_> = (0..ceiling)
            .filter_map(|_| ready(0))
            .filter_map(|body| match admit(body, &cmds) {
                Admit::Run(cmd) => Some(cmd),
                Admit::Refused(_) => None,
            })
            .collect();
        assert_eq!(count(held.len()), ceiling);
        let (tx, mut rx) = mpsc::channel::<Msg>(1);
        let tasks = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        let refusals = (0..10_000)
            .filter_map(|_| ready(1))
            .filter_map(|body| match admit(body, &cmds) {
                Admit::Refused(msg) => {
                    deliver_refusal(msg, &tx, &cmds);
                    Some(())
                }
                Admit::Run(_) => None,
            })
            .count();
        assert_eq!(refusals, 10_000, "every Cmd past the ceiling is refused");
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            tasks,
            "a refusal spawns no task"
        );
        assert_eq!(cmds.used(), SESSION_CMD_CEILING, "a refusal holds no unit");
        assert!(
            matches!(rx.try_recv(), Ok(Msg::Failed { .. })),
            "the first refusal took the free slot"
        );
        assert!(rx.try_recv().is_err(), "a full queue dropped the rest");

        // Control: with a free slot the refusal is delivered.
        let last = ready(1).map(|body| admit(body, &cmds));
        assert!(matches!(last, Some(Admit::Refused(_))));
        if let Some(Admit::Refused(msg)) = last {
            deliver_refusal(msg, &tx, &cmds);
        }
        assert!(matches!(rx.try_recv(), Ok(Msg::Failed { .. })));
        drop(held);
        assert_eq!(cmds.used(), Cmds::new(0));
    }
}
