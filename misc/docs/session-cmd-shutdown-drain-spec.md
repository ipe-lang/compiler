# Session work is cancelled before the shutdown closes the pools it uses

Designed by: security-soundness-guardian
Reviewed by: security-soundness-guardian (re-checked on `origin/main` `a95c1c1af`)

Status on `origin/main` `a95c1c1af`: the Cmd, request and `Task.parallel`
part (sections 3.1 to 3.4, tests T1 to T9) merged as #3789 (`737fbe473`). Open:
section 3.5, the session driver, the TTL sweep, the page-mint commit task and
`dispatch_cmd`'s `Delivery` match, with test T10 and the T11 to T13 unit tests
below. Current anchors: `dispatch_cmd` `web/mod.rs:2632` (still
`cmd.finish(...).await.is_err()` at :2651), `drive_session` :2850, the
page-mint `commit` spawn :5257 (`store.set` :5259, the driver spawn :5263), the
unguarded sweep loop :7076 to :7081, the spawn-shape scan near :19202;
`shutdown::work()` `server/shutdown.rs:539`, `WorkGuard::cancelled` :595,
`Phase::Closing` :96, `cmd_admission::Delivery` `web/cmd_admission.rs:44`.

Finding: S-08 (`misc/code-review-issues/PROBE-2026-10-18.md`). Builds on
`misc/docs/graceful-shutdown-spec.md`; its confirmed decisions hold unchanged
(inherited `SIG_IGN` stays ignored, a second signal exits `128 + signo`, the one
grace is `IPE_WEB_SHUTDOWN_GRACE_MS`, no rename). No new CLI command or flag, no
syntax, no stdlib surface, no `unsafe`.

## 1. Premise: it holds on current main

Verified on `origin/main` `44ac247f2`.

- `server.rs` `serve_app` (around line 2781) stops accepting, waits in
  `armed.settle_live()`, flushes the exporters, then calls
  `shutdown::close_owned_pools`.
- `settle_live` (`server/shutdown.rs:310`) waits only for the `Live` count. Only
  `Drain::hold` guards add to that count: the serve site itself, SSE bodies,
  WebSocket loops and stream bodies.
- A web `Perform` Cmd starts in `web/mod.rs:2569` `dispatch_cmd` as a bare
  `tokio::spawn(scope.clone().scoped(..))`. It holds a `CmdPermit` but no drain
  guard, and it never selects on the drain. So the close does not wait for it
  and does not stop it.
- Three more kinds of work are not counted either:
  - the session driver (`drive_session`, `web/mod.rs:2771`), which writes a
    checkpoint to the session-store pool for every Msg;
  - the TTL sweep task (`web/mod.rs:6990`);
  - a request handler still running after the grace. `axum::serve` spawns one
    task per connection, and dropping the serve future does not stop those
    tasks.
- The tokio runtime outlives `close_owned_pools`: `web_app` returns, then
  `main` returns. Between the close and the runtime's drop, a pending Cmd's
  `acquire` gets `sqlx::Error::PoolClosed`. `db.rs:1499` maps that to
  `IpeDbFailure::Unreachable`, which reaches the program as `Unavailable`, and
  `db.rs:146` gives it the text "connection pool closed".
  `tools/code-review/src/Lib/App.ipe:210/610` wrap the queue load in
  `ServerLog.logged "queue load failed"`, so the WARN is written inside the Cmd
  itself, once per session whose queue load was still running.
- The earlier graceful-shutdown change ordered the drain before the close only
  for long-lived streams. It did not cover Cmds.

A second gap is in the same class. When a `Task.parallel` future is dropped
(`task.rs:844` `task_parallel`), its children keep running. The handles sit in a
`VecDeque<JoinHandle>`, and a `JoinHandle` that is only dropped detaches its
task (the module's own comment at `task.rs:810` says so). Only the
first-failure path aborts the survivors. So cancelling a Cmd that runs
`Task.parallel` would leave its children running into the closed pool.

## 2. Class property

**Every unit of work that can touch an owned pool, started while the app
serves, is counted by the one shutdown owner. Once the grace is spent, that
owner cancels it and waits for it to drop before any owned pool closes.
`close_owned_pools` cannot be called without the owner's proof that the work
count reached zero, or that its bounded wait expired.**

The order lives in ONE place: `server/shutdown.rs`. The type system enforces it.
`close_owned_pools(&Armed, WorkSettled)` takes a `WorkSettled`, and only
`Armed::cancel_work` mints one. `PoolsClosed` and then `Stopped` follow from it,
as they already do.

A dropped parent Task must also drop the tasks it spawned: a cancel must never
leave detached children.

## 3. Design

### 3.1 `server/shutdown.rs`: the one owner

- `Phase` gains `Closing`, after `Draining`. `Draining` still starts at the
  first signal, and streams still end on it. `Closing` starts when the grace is
  spent or every counted unit has ended, whichever comes first.
- A second counter, `work: Arc<Live>`, sits beside `live`, with its own
  `WORK_CEILING` (`1 << 20`, `pub(crate)`). The two counts stay apart because a
  stream ends at `Draining` while work runs until `Closing`.
- `pub fn work() -> Result<WorkGuard, WorkFull>` uses the process owner, like
  `drain()`. The cases:
  - No armed owner: a guard that is never cancelled. Unit tests and CLI TEA get
    this.
  - Phase `Serving` or `Draining`: a counted guard.
  - Phase `Closing`: an uncounted guard whose `cancelled()` is already ready.
  - Count at `WORK_CEILING`: `Err(WorkFull)`.

  The guard increments the count before it reads the phase, so a unit that
  races the flip is either counted and cancelled, or born cancelled.
- `WorkGuard::cancelled(&mut self)` is cancel-safe and resolves at `Closing`.
  `Drop` decrements the count and wakes the idle waiter when the count reaches
  zero (the same shape as `LiveGuard`).
- `Armed::settle_live` waits until both `live` and `work` are zero, for at most
  the grace that is left. Within the grace the work is drained, not cut, so a
  decision save that finishes in time commits.
- `Armed::cancel_work(&self) -> WorkSettled`:
  1. It flips the phase to `Closing`.
  2. If the count is above zero, it writes one stderr line through
     `emit_runtime_log(tag, ..)`: `shutting down: cancelled N tasks still running after the <grace> ms grace (IPE_WEB_SHUTDOWN_GRACE_MS)`.
  3. It waits for `work == 0`, for at most `WORK_CANCEL_DEADLINE` (500 ms).
  4. If units are still left, it writes `M tasks did not stop within 500 ms; closing the pools anyway`.
  5. It returns `WorkSettled`.
- `close_owned_pools(armed, _: WorkSettled)` adds the proof parameter. A test
  build may still mint `WorkSettled` only through `cancel_work`.
- `POOLS_CLOSE_BOUND` and the e2e exit bound each grow by
  `WORK_CANCEL_DEADLINE`.

### 3.2 `server.rs` `serve_app`: the order, and request work

- The order becomes: `settle_live` → `cancel_work` → `flush_exporters` →
  `close_owned_pools(&armed, settled)`.
- A `WorkLayer` (a private tower layer in `server.rs`) wraps the router inside
  the Host admission, so a refused request holds nothing:
  `HostAdmissionLayer.layer(WorkLayer.layer(CanonicalUrl::new(router)))`.
- Each request future takes `shutdown::work()`. `WorkFull` and `cancelled()`
  both answer 503 with `Connection: close`. The guard is held only until the
  response head exists. An SSE or WebSocket body after that is a `LiveGuard`
  unit, as it is today.
- This covers the page handler's `charge_up`/`store.set`, the event POST, and
  every `Server.listen` handler on the same serve site.

### 3.3 `web/cmd_admission.rs`: every web Cmd is work

- `admit` takes `shutdown::work()` alongside the `CmdPermit`, and
  `AdmittedCmd { fut, permit, work }` keeps its single constructor.
  `WorkFull` gives the body's refusal Msg, the same path as
  `OverBudget::Process` (a `LimitRefusal`, context `web session commands`).
- A compile-time `const` assertion keeps
  `PROCESS_CMD_BUDGET.get() < WORK_CEILING` true, so the process Cmd budget,
  not the work ceiling, is the bound a well-behaved load reaches.
- `finish(self, tx) -> Result<Delivery, SendError<M>>` uses
  `Delivery::{Delivered, Cancelled}`. It runs
  `select! { biased; () = work.cancelled() => Ok(Cancelled), sent = run_then_send => sent }`.
  The body future and the queue send are both inside the cancelled arm's race.
  The bias means a Cmd admitted at `Closing` never polls its body. Task kernels
  are lazy, so `body.run()` starts nothing.
- The mod.rs caller's `.is_err()` still compiles: `Ok(Cancelled)` writes nothing.
  So the Cmd and request part stays clear of `web/mod.rs`.

### 3.4 `task.rs` `task_parallel`: a dropped parent aborts its children

- Each spawned handle is paired with an `AbortOnDrop` guard on its
  `abort_handle()`.
- An awaited `Ok` defuses its own guard. The first-failure path keeps aborting
  the survivors explicitly.
- Dropping the parallel future drops the deque, which aborts every unfinished
  child.
- This is the existing choke-point pattern (`ffi_spawn_guarded`), so no new
  primitive is added.

### 3.5 `web/mod.rs`: the session driver and the sweep (open)

- `drive_session` takes a `WorkGuard` for each turn, next to the existing
  `budget::Turn`, from the input take to the end of the iteration. The
  checkpoint write therefore finishes before the close.
- Every input the driver takes (Msg, event, entry, revocation close) first
  takes its unit; one taken after `Closing` is born cancelled and ends the
  driver, so no `update` and no store call runs after it. The gate sits on the
  path to every effect, so a parked driver that wakes late is safe without a
  racing arm.
- The driver is not counted while it is parked. Counting it would make every
  shutdown wait out the whole grace for idle sessions.
- The TTL sweep task selects on `Closing` and holds a guard while it runs
  `store.sweep()`.
- The page-mint `commit` task moves in a `WorkGuard` taken by the request
  before the spawn, and holds it across `store.set` and the seed `run_cmd`.
- `dispatch_cmd` matches `Delivery` explicitly, with no `is_err()`.

## 4. Decisions (decided by PRINCIPLES.md)

- **DP-1 Drain, then cancel; not cancel at the first signal.** A Cmd that
  finishes within the grace must commit its write and deliver its Msg
  (correctness beats speed). After the grace, cancelling is the bounded
  outcome that principle 3 requires.
  - A dropped sqlx transaction rolls back, so DB atomicity holds.
  - A non-DB remote effect, such as an outbound POST, is left indeterminate,
    the same as a process kill today.
- **DP-2 A cancelled Cmd's result is dropped without a per-Cmd line.** It has
  no result: the future is dropped, no Msg exists, and `update` never sees it.
  - A per-session WARN is the defect itself.
  - A debug level does not exist in `emit_runtime_log`, and adding an
    operator-facing level switch would be new surface.
  - One aggregate stderr line, written only when N > 0 and bounded to two lines
    for each shutdown, keeps the cut observable and tells the operator which
    variable to raise. It writes no sid, no Msg and no payload (no leakage).
- **DP-3 A Cmd admitted at `Closing` gets no refusal Msg.** A refusal would
  run `update` and could log through the program, which is S-08 again. The
  session is ending, so nothing waits for the Msg.
- **DP-4 Request work is in scope.** A handler that runs past the grace into
  the closed pool is the same class on the `Server.listen` surface. Leaving it
  out would fix one symptom and leave the class open.

## 5. Interactions

- **Per-session Cmd ceiling (64) and `PROCESS_CMD_BUDGET`.** The permit is
  unchanged and is still drawn first. A cancelled Cmd drops its `CmdPermit`
  with the `AdmittedCmd`, so both budgets get their unit back. A Cmd admitted at
  `Closing` draws and returns at once. The work guard is a separate count and is
  never charged against the Cmd budget. Orphaned Cmds of evicted sessions
  (`ipe-session-cmd-ceiling` LIMIT, DP-4 there) are counted as work too, so
  shutdown now cancels them as well.
- **`Unavailable` mapping.** Unchanged. `PoolClosed` → `Unreachable` →
  `Unavailable` stays right for a pool that really is closed. After this fix no
  counted unit can observe it from an owned pool. The one exception is the
  residual in §8.
- **`exit_process` / second signal (8be).** Unchanged. A forced exit skips
  `cancel_work` the way it skips the close.
- **Two serve sites sharing one owner (8bd).** The first site to finish
  waits in `settle_live` for the sibling's serving hold, so `Closing` never
  flips while a sibling still accepts.

## 6. Files, sequencing, stop conditions

Merged (#3789): `server/shutdown.rs`, `server.rs`, `web/cmd_admission.rs`,
`task.rs`, `src/ipe-cli/tests/server_shutdown_e2e.rs` (T9),
BUG-CLASSES 8ds and 8dt.

Open, one commit, off a freshly fetched `origin/main` (the autofocus change
it had to follow merged as #3793):
- `src/runtime/rust/src/web/mod.rs` — `drive_session`, the sweep spawn, the
  page `commit` task, `dispatch_cmd`'s `Delivery` match, the native tests
  T11 to T14, and the spawn-shape scan near line 19202 if a spawn changes
  shape.
- `src/ipe-cli/tests/server_shutdown_e2e.rs` — T10.
- `misc/plugins/ipe/skills/lane-brief/BUG-CLASSES.md` — the 8ds example list
  gains the driver turn, the sweep and the page mint.

Disjoint from the frame-sandbox change (`frame-content-sandbox-spec.md`,
which does not touch `web/mod.rs`) and from every code-review change. The
413 reply marking of `code-review-bounded-refuse-draft-spec.md` edits
`web/mod.rs` and runs after this merges.

Stop conditions (exit with `LIMIT:`):
- Counting the driver needs it counted while parked (an idle session would
  hold the whole grace): stop; the design counts a turn, never the park.
- `store.sweep()` cannot be raced against `cancelled()` without leaving a
  half-pruned checkpoint table (a sweep that is not one transaction): stop;
  the store's sweep is re-planned in `web/store.rs`, a file this change does
  not own.
- A spawn outside the four named sites needs a guard: stop and list it; it is
  a further member of 8ds, re-planned rather than patched.
- T10 cannot be made red by removing the driver guard (the checkpoint write
  always ends inside the grace on the test machine): lower the grace in the
  test, never drop the test.

## 7. Refusal tests

Each one goes red without its fix.

| id | file | proves | CI job |
|----|------|--------|--------|
| T1 | `server/shutdown.rs` | a counted `WorkGuard` holds `settle_live` until it drops; with grace 0, `cancel_work` flips `Closing`, `cancelled()` resolves, and the wait ends when the guard drops | `runtime-full-features` |
| T2 | `server/shutdown.rs` | a guard that never drops: `cancel_work` returns within `WORK_CANCEL_DEADLINE` + slack and logs the "did not stop" line (a bounded wait, not a hang) | `runtime-full-features` |
| T3 | `server/shutdown.rs` | `work()` after `Closing` is uncounted and already cancelled; `work()` at `WORK_CEILING` is `Err(WorkFull)` | `runtime-full-features` |
| T4 | `web/cmd_admission.rs` | an admitted Cmd whose body is pending forever, cancelled: `finish` → `Ok(Cancelled)`, the body is dropped (drop flag), `cmds.used() == 0`, and the queue gets nothing | `runtime-full-features` |
| T5 | `web/cmd_admission.rs` | a Cmd admitted at `Closing`: the body's poll counter is 0, there is no Msg, and the permit is returned | `runtime-full-features` |
| T6 | `web/cmd_admission.rs` | a Cmd that ends inside the grace delivers its Msg (`Ok(Delivered)`); this test goes red if the cancel is moved to `Draining` | `runtime-full-features` |
| T7 | `server.rs` | `serve_app` with a registered recording pool and a handler that sleeps past a 0 ms grace and then marks a flag: the pool's close starts after the handler's future dropped, the flag never sets, and the client reads 503 | `runtime-feature-combos` clippy rows + `runtime-full-features` |
| T8 | `task.rs` | dropping a `task_parallel` future after its children start: a child that would set a flag after a sleep never sets it (paused time) | `runtime-full-features` |
| T9 | `src/ipe-cli/tests/server_shutdown_e2e.rs` (new E-test) | a `Web.tea` app whose `init` Cmd sleeps 3 s and then queries `Db.open`, logging on error; grace 300 ms; SIGTERM → exit 0, one `SHUTDOWN_LINE`, **0** stderr lines containing `connection pool closed`, exactly 1 `cancelled 1 tasks` line, no sidecars | `IPE_E2E=1` e2e shards in `ci.yml` (the `nextest-archive` shard matrix) |
| T11 | `web/mod.rs` native | a driver mid-turn at `Closing`: the turn's checkpoint write completes, then the driver ends; no `update` runs after `Closing` (a Msg queued after it is never applied) | `runtime-full-features` |
| T12 | `web/mod.rs` native | the sweep loop at `Closing` ends without starting a sweep; a sweep running at `Closing` holds the settle until it returns | `runtime-full-features` |
| T13 | `web/mod.rs` native | a page-mint `commit` admitted after `Closing` never calls `store.set` nor runs the seed Cmd | `runtime-full-features` |
| T14 | `web/mod.rs` native | `dispatch_cmd` logs the dropped-result line only for a closed queue, never for `Ok(Cancelled)` (the explicit `Delivery` match) | `runtime-full-features` |
| T10 | same e2e file | a `Web.tea` app with a 50 ms `Sub.every` on the SQLite session store, grace 0: SIGTERM → exit 0, no `did not stop` line (red if the parked driver were counted), no sidecars. The persistent stores swallow write errors, so a cut checkpoint is invisible here; T11 is the turn guard's proof | `IPE_E2E=1` e2e shards |

- T7 also pins that the `cancel_work` call cannot be removed: drop the call and
  the flag sets.
- The type-level ordering (`close_owned_pools` requires `WorkSettled`) is a
  build error, not a test.
- Mutation checklist for the reviewer: remove the `biased` (T5 goes red),
  remove the work guard from `admit` (T4 and T9 go red), and drop the
  `AbortOnDrop` pairing (T8 goes red).

## 8. Residuals (bounded, stated)

- **A Cmd that never yields** (a long synchronous compute inside one poll)
  cannot be pre-empted without threads or `unsafe`. `cancel_work` waits at most
  `WORK_CANCEL_DEADLINE`, reports it, and closes anyway. Such a Cmd may then log
  `PoolClosed`. The exit is still bounded.
- **Transient or user-held pools** that are not registered as owned stay out of
  scope, as in the graceful-shutdown spec. `close_all` never closes them, so
  they cannot produce `PoolClosed`.
- **Durability gap.** A Cmd cancelled at shutdown is not persisted for replay
  after a restart. This is unchanged: today it is killed the same way. Making
  Cmds durable is a separate design.
- **Silent store writes.** `SqliteStore`/`PostgresStore` `set`, `delete` and
  `sweep` discard their query result (`let _ =`), so a checkpoint that fails
  (a closed pool, a full disk) is lost with no line and no typed outcome. The
  driver cannot tell a stored checkpoint from a dropped one, and no e2e test
  can observe a cut turn. Root cause: `SessionStore::set` returns `Installed`
  only; it needs a typed write outcome (`Stored | Displaced | Failed(kind)`)
  that `checkpoint` maps, logged once per failure run. Owned by `web/store.rs`,
  outside this change.
- **A revoked session left in a persistent store at `Closing`.** A revocation
  the driver sees after the close ends it without `store.delete` (the pool is
  closing). Not a hole: a cold row is re-proved at rejoin (`prove_persisted`),
  so a revoked credential's row is refused there.

## 9. BUG-CLASSES touched

- **8bd** (shared resource closed by the first of several consumers): extend
  its check. Spawned work started on user code's behalf is a consumer. Name
  every `tokio::spawn` or `spawn_in_current_scope` that can reach an owned pool,
  and show that each one is counted.
- **New 8ds: work started on user code's behalf outside the shutdown's work
  count.** A Cmd, driver turn, sweep or past-grace handler that is not counted
  keeps running after the pools it uses close.
  - Rule: every such start takes `shutdown::work()`, and the close requires
    `WorkSettled`.
  - Check: for each new spawn in `web/` or `server`, either the guard is held,
    or the spawn never reaches a pool and the reason is written down.
  - e.g. S-08.
- **New 8dt: a dropped combinator that detaches its spawned children.** A
  future that owns `JoinHandle`s must abort them on drop (`AbortOnDrop`), not
  only on its own failure path.
  - Check: every `JoinHandle` collection in `task.rs`/`tea.rs` is paired with an
    abort guard.
  - e.g. `task_parallel`.
- **8a** (owned resource lost at a timeout) is reviewed. The permit and the
  guard drop together with `AdmittedCmd` on every path, cancel included.
