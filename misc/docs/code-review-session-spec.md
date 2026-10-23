# code-review: the session step as a pure module, effects as data

Designed by: security-soundness-guardian
Base: origin/main 43629ce94 (`tools/code-review`)
Depends on: `misc/docs/code-review-key-mode-spec.md` (KeyMode) lands FIRST. This spec does not redesign key handling. The `KeyDown` arm, `KeyOffers`, `keyOffers` and whatever drawn key-mode state KeyMode adds to `Model` move into `Lib.Session` verbatim, in the shape KeyMode leaves them.
Proof run: `cd tools/code-review && ipe test` (local only; there is no CI job for this tool and none is added).

Vocabulary: module, interface, implementation, depth, seam, adapter, leverage, locality. One adapter is a hypothetical seam; two adapters make a real seam.

## 1. Premise on the base

`Lib.App` (749 lines) is two things in one module:

1. the session transition: `step`, the page entry, the five slot steps, the `shownPanel` normalization and the drawn-offer queries; and
2. the effect interpreter: five `Cmd.perform` sites (`queueStep`, `historyStep`, `loadViewCmd`, `standingStep`, `saveDecision`), the callbacks (`queueLoaded`, `historyLoaded`, `viewLoaded`, `standingLoaded`, `decisionSaved`) and `decisionTask`, which re-reads the `Model` inside the task builder.

Three facts follow from that, and each is a defect, not a style point.

- **Effects are not observable.** `SingleFlightTests.after` folds `App.update` and drops every `Cmd`. "Started nothing" is proved only by proxy: the slot stayed taken. "Started exactly one" is proved by `everyTaskStartsAtItsSlot`, which is syntactic: it shows a `perform` sits in a named function, not that a transition emits it once. No test can say "this `Msg` on this `Model` starts no task".
- **The completion ownership rule is not one rule.** `DecisionSaved`, `SelectedViewLoaded` and `StandingLoaded` carry their `Epoch`. `PendingLoaded` and `HistoryPageLoaded` carry only a `LoadTicket`, and `Queue.loadArrived` compares the slot owner against `settings.epoch` at arrival. Five slots, two ownership checks.
- **`DecisionSaved Ok` drains unconditionally.** `step` requests `QueueDrain attested written cursor` before asking whether the decision slot is `DecisionSaving` for that uid and this epoch. Under the debugger import (`misc/docs/code-review-debugger-import-spec.md`) a forged `DecisionSaved` reaches that drain. The import spec closes the forged pair at the sink (`drainThenLoad` re-proves against the signed log). The step itself still lacks the rule "a completion the slot does not own changes nothing".

`Lib.Queue` (2315 lines) holds the queue page state and producers. It also holds four unrelated slot state machines: `LoadSlot`/`LoadTicket`, `SelectedView`, `StandingRead` and `DecisionSlot`/`DecidableRow`/`RefusalPanel`, plus the History page types, producer and text. `View` reaches 31 distinct `Queue.` names. All of them are types, read queries or text, and none is a transition.

## 2. Deletion tests

**Session (`Lib.Session` holding `step`).** Delete it, and its content goes back into `Lib.App` beside the `Cmd` construction. Gating, ownership and effect issuance are interleaved again in one function per slot. The leverage is real only with two adapters on the seam `Session.step : AppSettings -> Msg -> Model -> ( Model, List Effect )`:

- the `Cmd` interpreter (`Lib.App`, production), and
- the test recorder (`TestSupport.record`, which keeps the `List Effect` per step).

With one adapter this would be a hypothetical seam, and the split would be churn. With two, every single-flight property becomes a value assertion on a transition. **Keep.**

**Splitting `Queue`.**

- `Lib.Slot` (the generic `LoadSlot`, `LoadTicket`, `Settle`, `Stamp`): delete it and its logic returns duplicated into the queue and History slots, which are its two callers today. That is leverage. **Keep.**
- `Lib.Selected`, `Lib.Standing`, `Lib.DecisionSlot`, `Lib.History`: delete any one and its content returns to `Queue`. Nothing duplicates, so the argument is locality, not leverage. Each is a state machine whose invariant reads in one file (about 150 to 500 lines), and `Session` depends on each without depending on the queue producers. That is enough at this size. **Keep, as locality splits.** They do not earn depth through opacity yet (see residual R2).
- Further splitting of `Queue` (page state versus producers versus text): the deletion test fails. Every part has one caller, and the parts share the page types. **Do not split.**

## 3. Chosen design

### 3.1 Modules and dependency direction

```
Lib.Epoch  Lib.Index  Lib.Db  Lib.Failure  ...      (unchanged; Db -> Index stays the only backwards import, not widened)
    \         |         |
     Lib.Slot                       Stamp, LoadTicket, LoadSlot, Settle, owns
       |
       +-- Lib.Selected             SelectedView + transitions + text
       +-- Lib.Standing             Standing, StandingRead + transitions + loadStanding producer
       +-- Lib.DecisionSlot         DecidableRow, DecisionSlot, RefusalPanel, Draft,
       |                            decidableAs/decidableRow/offered* + transitions + text
       +-- Lib.History              HistoryWant, History page types, producer, text
       +-- Lib.Queue                QueueState, QueueWant, page, paging, producers, decide/decideRefusal sinks, text
                 |
           Lib.Session              Model, Msg, Page, KeyOffers, Effect, DecisionPlan,
                 |                  step (with shownPanel at its one exit), read queries
           Lib.App                  update (interpreter), run : AppSettings -> Effect -> Cmd Msg, callbacks
                 |
     Main  ->  Lib.View             View imports Session (+ slot modules for types/text); never Lib.App
```

Rules, each pinned by a test (section 6):

- `Lib.Db` and `Lib.Index` import none of the new modules.
- `Lib.Session` imports neither `Ipe.Tea.Web.Cmd` nor `Ipe.Task`, and it names no producer task.
- `Lib.View` does not import `Lib.App`.
- The slot modules import `Lib.Slot` and never each other, with one exception: `Lib.DecisionSlot` reads `Lib.Selected` (`decidableSource`) and `Lib.Queue` (the page state), exactly as `Queue`'s internal calls do today.

### 3.2 The completion stamp (one ownership rule)

```elm
-- Lib.Slot
type Stamp key = Stamp Epoch key          -- opaque: no constructor exposed

stamp : Epoch -> key -> Stamp key         -- callers: the five start functions only (scan, section 6)
owns : Epoch -> Stamp key -> Maybe (Stamp key) -> Bool
owns current arrived running =
    case running of
        Just held -> held == arrived && epochOf arrived == current
        Nothing -> False
```

Each slot stores the stamp of the task it runs, and each completion `Msg` carries the stamp its `Effect` carried:

| Slot | Running state | Stamp key | Completion `Msg` |
|---|---|---|---|
| queue | `LoadRunning (Stamp LoadTicket) (Maybe QueueWant)` | `LoadTicket` | `PendingLoaded (Stamp LoadTicket) (Result LoadFailure QueuePage)` |
| History | `LoadRunning (Stamp LoadTicket) (Maybe HistoryWant)` | `LoadTicket` | `HistoryPageLoaded (Stamp LoadTicket) (Result ...)` |
| selected view | `ViewLoading { running : Stamp Uid, wanted, fresh }` | `Uid` | `SelectedViewLoaded (Stamp Uid) (Result ...)` |
| standing | `StandingReading (Stamp StandingKey) (Maybe StandingKey)`, `StandingKey = ( Uid, String )` | uid + body hash | `StandingLoaded (Stamp StandingKey) (Result ...)` |
| decision | `DecisionSaving (Stamp Uid)`, `DecisionRefreshing (Stamp Uid)` | `Uid` | `DecisionSaved (Stamp Uid) (Result SaveFailure ( Attested, Written ))` |

Epoch rules:

- A slot whose running stamp has an epoch other than `settings.epoch` reads as idle. `Slot.running current slot` returns `Nothing`, which replaces `ownedSlot`/`ownedView`/`busyOwnedBy` and the owner checks in `loadArrived`/`viewArrived`/`standingArrived`.
- Every `*Arrived` asks `Slot.owns settings.epoch stamp (running slot)` first, and only that function. When it returns `False`, the step returns the model unchanged and `[]`. That covers a stale ticket, a foreign epoch, a uid or hash mismatch, and a forged or replayed `Msg`.
- The content checks the slots make today stay after the ownership check, inside `owns`'s key equality. Examples: the standing body hash, the view uid. Nothing is dropped.
- The interpreter never mints and never compares. It copies the stamp from the `Effect` into the callback (`queueLoaded stamp`, ...).

The queue and History completions gaining the epoch changes no live behavior: a live completion's stamp epoch is always `settings.epoch`. It removes the second ownership rule.

### 3.3 Effects

```elm
-- Lib.Session
type Effect
    = LoadQueue (Stamp LoadTicket) QueueWant
    | LoadHistory (Stamp LoadTicket) HistoryWant
    | LoadView (Stamp Uid)
    | LoadStanding (Stamp StandingKey)
    | SaveDecision (Stamp Uid) MacKey DecisionPlan LibDb.Decision

type DecisionPlan
    = WriteUnit Index.ShownSource          -- the source the reviewer was shown
    | WriteFile Uid Index.RefusalDigest    -- the digest the reviewer was shown

decisionPlan : Model -> DecidableRow -> Result DecideRefusal DecisionPlan
```

- **One constructor per slot.** Every `Effect` is emitted only by the start function of its slot: the transition idle (or foreign) -> running, or running -> running with a held want at its completion. That function writes the same stamp into the slot. So the stamps in flight are at most the running slots, five, and `SESSION_CMD_CEILING = 64` (`src/runtime/rust/src/web/budget.rs`) is never the limit a reviewer reaches. The relation 5 <= 64 is asserted by a test that reads `budget.rs` (section 6, closes the 8cc gap the `Model` doc comment states only in prose).
- **`decisionPlan` is an exact port of `decisionTask`'s model reads.** Unit offer: listed in `queueList`, then `offeredSource row model.selectedView`, otherwise `DrawnChanged`/`SourceNotShown`/`NotQueued`. File offer: `pageRefusal` digest equal to the drawn digest, otherwise `DrawnChanged`/`FileNotAcknowledgeable`/`FileNotQueued`. It moves to `Session` because it reads `Model`. `run` gets no `Model`, so a decision task can no longer re-read session state at build time.
- **A refused decision emits no `Effect`.** `saveDecision` refuses in today's order: off queue, `ReadOnly`, `decidableAs` `Err`, then `decisionPlan` `Err`. The last step is new: the refusal goes through `decisionRefused` and emits no `SaveDecision`. Today that state builds a task that answers `Task.succeed (Err refusal)` with no write. `decidableAs` `Ok` implies `decisionPlan` `Ok` on every reachable model (pinned, section 6), so the change touches only states no live session reaches (decision D1).
- **The sinks stay the second, independent edge.** `Queue.decide` re-proves the shown source (`Index.reverify`), `Queue.decideRefusal` the digest (`Index.reverifyRefusal`), and `drainThenLoad` the pair (debugger-import spec). The step's refusals are the first edge (class 6, defence in depth).
- **The `MacKey` inside `SaveDecision`.** It was parsed once at startup (`Signing MacKey`), and the step proved `Signing` before emitting. The interpreter therefore never matches `settings.key`, so there is no unreachable `ReadOnly` arm. `MacKey` renders redacted. Tests match `Effect`s by `case`, never by `==` on a value carrying a key.
- **Ordering.** `List Effect` is in emission order. The interpreter maps it through `Cmd.batch`, whose run order is not part of the contract. Tests assert per slot (a multiset per slot), never across slots.

### 3.4 The interpreter (`Lib.App`)

```elm
update : AppSettings -> Msg -> Model -> ( Model, Cmd Msg )
update settings msg model =
    case Session.step settings msg model of
        ( next, effects ) -> ( next, Cmd.batch (List.map (run settings) effects) )

run : AppSettings -> Effect -> Cmd Msg
run settings effect =
    case effect of
        LoadQueue stamp want -> Cmd.perform (ServerLog.logged "queue load failed" (queueTask settings want)) (queueLoaded stamp)
        LoadHistory stamp want -> ...
        LoadView stamp -> ...
        LoadStanding stamp -> ...
        SaveDecision stamp macKey plan decision -> Cmd.perform (ServerLog.logged "decision save failed" (decideTask settings macKey plan decision)) (decisionSaved stamp)
```

- `update`'s annotation stays as `settingsNeverInSessionState` pins it.
- `App` builds no `Model`, so a `{ model |` record update in `App.ipe` is refused by scan. With no `Model` built there, the interpreter has no early return that could bypass `shownPanel`. That normalization is the last expression of `Session.step` (8ei).
- There is one `Cmd.perform` per `Effect` arm, all inside `run`. `Cmd.batch` appears only in `update`.

### 3.5 Slot-modules versus one Session

The slot modules own their state machines, and `Session` composes them. The rejected alternatives:

- **One `Session` module holding every slot.** Roughly 2000 lines, and the locality is lost. The deletion test on `Queue` already shows the four machines are independent.
- **Each slot module emitting its own `Effect`.** That needs one `Effect` type per module, or a shared one in `Lib.Slot`. The first spreads the five-constructor bound across five types, which loses the single place the 5 <= 64 relation reads. The second makes `Lib.Slot` depend on `QueueWant`, `HistoryWant`, `ShownSource` and `Decision`, which inverts the direction.

Chosen shape: each slot start function returns `( slot, Maybe start )`, as `requestLoad`/`loadArrived` already do, and `Session` maps the `start` to its one `Effect` constructor.

### 3.6 View's read interface (question 4)

View uses no transition, so its `Queue.` uses become the same names qualified by their new module. Its `App.` uses (`keyOffers`, `unitPageState`, `decidableRow`, `queueList`, `Model`, `Msg`, `Page`) become `Session.` uses.

A narrower read interface (a per-render read record) would rewrite View's 1505 lines for a property View cannot break anyway: View produces no `Cmd`, and `Model` is not writable from View. Its value is below the 95% bar, so it is not proposed.

The property that matters is 8dx: view and step decide "decidable" by one predicate. It holds by construction: `View` and `Session.step` both call `Session.decidableRow`. Pins: View does not import `Lib.App`, and View names no `Effect` constructor.

## 4. Class-closing property

**Every task the session starts is a value `Session.step` returns. Each value is emitted by exactly the transition that writes its stamp into its slot, so emission happens at most once per stamp. Each completion changes the model if and only if `Slot.owns` holds for its stamp, and `Slot.owns` is the one ownership rule for all five slots.**

What follows from it:

- The single-flight class (8ee) is checked as a property of transitions, not only as syntax.
- The stale or foreign completion class has one decision point instead of two.
- "A refused decision starts nothing" is a value equality (`[]`), not an absence inferred from state.

## 5. Slices (ordered, each behavior-preserving, each green under `ipe test`)

Every slice moves names or adds stamps without changing an assertion's expectation. Moved names keep their spelling, and only the qualifier changes.

**Slice 1: split `Queue` (pure move).**

- New: `src/Lib/Slot.ipe`, `src/Lib/Selected.ipe`, `src/Lib/Standing.ipe`, `src/Lib/DecisionSlot.ipe`, `src/Lib/History.ipe`.
- Edited:
  - `src/Lib/Queue.ipe`, `src/Lib/App.ipe`, `src/Lib/View.ipe`;
  - `src/Main.ipe`, only if `resyncReviewed` moves, and it does not;
  - every test naming a moved item: `tests/QueueTests.ipe`, `tests/SingleFlightTests.ipe`, `tests/TestSupport.ipe`, `tests/ViewRenderTests.ipe`, `tests/ViewTests.ipe`, `tests/DbTests.ipe`, `tests/TypedRowsTests.ipe`, `tests/FailureScanTests.ipe` and `tests/TextSinkScanTests.ipe` (mutation-fixture paths `Lib/Queue.ipe` re-pointed to the file now holding the function), `tests/SettingsTests.ipe` (the `evaded` env-read mutations naming `Lib/Queue.ipe`);
  - `QueueTests.reviewWritesGoThroughWriteTransaction` `others`: add the five modules.
- No behavior change.

**Slice 2: one stamp, one ownership rule.**

- Files: `src/Lib/Slot.ipe` (`Stamp`, `stamp`, `owns`, `running`), `src/Lib/Selected.ipe`, `src/Lib/Standing.ipe`, `src/Lib/DecisionSlot.ipe`, `src/Lib/History.ipe`, `src/Lib/Queue.ipe` (the `LoadRunning` shape), and `src/Lib/App.ipe`:
  - the `Msg` completions carry a `Stamp`;
  - the callbacks take the stamp;
  - the `DecisionSaved Ok` drain is moved behind `owns`.
- Tests: `tests/SingleFlightTests.ipe`, `tests/QueueTests.ipe`, `tests/TestSupport.ipe` (stamps built only through the production start functions, 8cz).
- Persisted `Model` shape changes (decision D2).

**Slice 3: decision plan.**

- `src/Lib/App.ipe`:
  - `decisionPlan` is split out of `decisionTask`;
  - `decisionTask settings macKey model row decision` becomes `decidePlan settings macKey plan decision` after `decisionPlan`;
  - a `decisionPlan` `Err` is refused in `saveDecision` with no `Cmd`.
- Tests:
  - `tests/SingleFlightTests.ipe`: `decisionRefusedBeforeReading` and the reshown checks retarget from `App.decisionTask` to `App.decisionPlan`, with the same models and the same expected refusals. The `Failure.saved` mapping assertions are kept.
  - `tests/ViewTests.ipe`: the `Queue.decide `/`decideOn `/`offeredSource` call-site pins are re-pointed to the new text, with the same counts, the same single calls, and still none in `Main`.

**Slice 4: Session and the two adapters.**

- New: `src/Lib/Session.ipe` (`Model`, `Msg`, `Page`, `KeyOffers`, `Effect`, `DecisionPlan`, `step`, `decisionPlan`, read queries, `initialModel`).
- `src/Lib/App.ipe` becomes `update` + `run` + callbacks + producers glue (`queueTask`, `decidePlan`).
- `src/Lib/View.ipe` and `src/Main.ipe` imports change to `Session`.
- Tests:
  - `tests/TestSupport.ipe`: `record : AppSettings -> List Msg -> Model -> ( Model, List (List Effect) )`.
  - `tests/SingleFlightTests.ipe`:
    - `after` keeps its signature over `Session.step`;
    - every existing assertion is kept, and the effect assertions are added;
    - the new refusal tests 1-9 go here;
    - `everyTaskStartsAtItsSlot` is re-pointed (section 6).
  - `tests/SettingsTests.ipe`:
    - the `Model` declaration moves to `Lib/Session.ipe`, and the mutation follows it;
    - the `update` annotation stays in `Lib/App.ipe`;
    - the `view`, `init` and `subscriptions` annotations still read `Model`;
    - `stateWiring` is unchanged.
  - `tests/FailureScanTests.ipe`: the 8b frontier becomes `[("Lib/Session.ipe","Model"),("Lib/Session.ipe","Msg")]`.
  - `tests/ViewTests.ipe`, `tests/ViewRenderTests.ipe`, `tests/TextSinkScanTests.ipe`: paths and qualifiers re-pointed.
  - `QueueTests` `others`: add `Session`.

**Disjointness.**

- The four slices conflict with each other and must land in order.
- They conflict with KeyMode on `App.ipe`, `View.ipe`, `Keys` use and `SingleFlightTests.ipe`. KeyMode lands first, and slice 1 is cut from the tree it leaves.
- They conflict with any open code-review work on `Queue.ipe`, `View.ipe` or `App.ipe`: the debugger-import drain re-proof on `Queue.drainThenLoad`, highlight, columns and autofocus in `View.ipe`. Land those before slice 1, or after slice 4. Never between two slices, because slice 1 moves the names they edit.
- Nothing here touches `Index.ipe`, `Db.ipe`, the runtime or the compiler.

## 6. Tests

**Survive with their assertions unchanged** (qualifier and path edits only):

- every `QueueTests` slot and page test;
- `ViewRenderTests`, `ViewTests` render checks;
- `DbTests`, `TypedRowsTests`;
- the `SingleFlightTests` single-flight set: `queueLoadsSingleFlight`, `supersededQueueResultDropped`, `refreshingSettlesOnlyAfterWrite`, `drainAbsorbsReload`, `historyLoadsSingleFlight`, `standingSingleFlight`, `foreignLoadSlotIdle`, `ceilingRefusalReleasesSlot`, `decisionsSingleFlight`, `refusalPanelLivesInIdleSlot`, `busyRendered`;
- the drawn-offer and reshown set.

**Retargeted onto a pure function** (same models, same expected values): `decisionRefusedBeforeReading` and the reshown checks, from `App.decisionTask` to `Session.decisionPlan` (slice 3, then slice 4).

**Strengthened onto the recorder** (slice 4): every `SingleFlightTests` test driven by `after` also asserts its effects per step. No existing assertion is removed.

**New refusal tests** (`tests/SingleFlightTests.ipe`, run by `ipe test`):

1. `staleCompletionDropped`. For each of the five completion `Msg`s, a completion is dropped (model unchanged, `[]`) in each of these cases:
   - (a) its stamp carries a foreign epoch, minted by a real start under a second `AppSettings`;
   - (b) its stamp is superseded (an older ticket, or another uid or hash);
   - (c) it arrives while its slot is idle.
   Mutation: replace `owns` with key-only equality, and (a) goes red.
2. `secondRequestHeldNotStarted`. For each slot, a second request while running emits no `Effect` for that slot: the queue/History want is merged and held, a view `wanted` is recorded, a standing want is held, and a decision is refused busy. The held want's completion emits exactly one.
3. `effectOncePerTransition`. A property over the scripted sequences of the existing tests. For every step and every slot, the `Effect`s for that slot number 1 when the slot's running stamp changed to a new one, and 0 otherwise. A slot leaves running only on its owned completion.
4. `refusedDecisionEmitsNoEffect`. Every `saveDecision` refusal emits `[]`: off queue, `ReadOnly`, `decidableAs` `DrawnChanged`, not decidable, `decisionPlan` `Err` (driven by a model built through production transitions where the plan fails), and busy.
5. `decidableImpliesPlan`. Over every fixture model, `decidableAs ... == Ok row` implies `decisionPlan model row` is `Ok` (pins D1's "unreachable" claim).
6. `unownedDecisionSavedDrainsNothing`. `DecisionSaved (Ok pair)` with an unowned stamp emits no `LoadQueue` and leaves `queueLoad` unchanged.
7. `sessionStartsNothing` (scan through `TextSinkScanTests.lex`, 8ck):
   - `Lib/Session.ipe` imports neither `Ipe.Tea.Web.Cmd` nor `Ipe.Task`, under any alias or exposing (8dn);
   - `perform`/`attempt`/`batch` appear only in `App.run`/`App.update`;
   - `App.ipe` holds no `{ model |`;
   - `Lib/View.ipe` imports no `Lib.App` and names no `Effect` constructor.
   This replaces `everyTaskStartsAtItsSlot`'s site list. Every existing refusal fixture of that test is kept and re-pointed: a renamed `Cmd` import, an exposing import, and a perform in `View`.
8. `stampMintedAtStartsOnly` (scan). `Slot.stamp` is referenced only inside the five start functions, which are bound to their modules. The `Stamp` constructor is not exposed. Mutation: a `Slot.stamp` call in `Session.step` goes red.
9. `effectSlotsUnderCeiling`. The `Effect` constructors lexed from `Lib/Session.ipe` are exactly the five slot names, and their count is <= the `SESSION_CMD_CEILING` value read from `src/runtime/rust/src/web/budget.rs` (precedent `IndexTests` budget read). Mutations: a sixth constructor goes red, and a ceiling edited below 5 goes red.

No test is deleted or weakened.

## 7. BUG-CLASSES

- **6** (re-prove at the sink): kept. `decide`/`decideRefusal`/`drainThenLoad` are untouched, and the step refusal is the first, independent edge.
- **8b** (no `Error` in page state): the frontier moves to `Session`'s `Model`/`Msg`; `Effect` is not persisted.
- **8cc** (two ceilings without a tie): closed for 5 <= 64 by test 9.
- **8ck** (scans read through the lexer): tests 7 and 8 use `TextSinkScanTests.lex`.
- **8cz** (state reached through the production constructor): stamps are minted only by real starts, in tests too, via `TestSupport`.
- **8dn** (every spelling): test 7 covers aliased, exposing and qualified imports and both `perform` and `attempt`.
- **8dx** (one predicate for view and update): `Session.decidableRow` is shared by construction.
- **8ec** (decision bound to the drawn offer): unchanged. `Msg` still carries the `DecidableRow` the reviewer was shown, and `decisionPlan` binds the drawn source or digest.
- **8ee** (one task per slot; every start is idle -> running): extended from syntax to the value property in tests 2, 3 and 8.
- **8ei** (normalization bypassed by an early exit): `shownPanel` is the last expression of `Session.step`, and `App` builds no `Model` (test 7).
- **New class, id assigned at landing (next free id):** "a test driver discards the effects a transition emits, so 'started nothing' is proved by a state proxy". Closed by the recorder adapter.

## 8. SCEF risks and per-slice checks for the diff review

- **Decision bound to the shown digest (security/correctness).** Slices 3 and 4.
  - `decisionPlan` must read exactly what `decisionTask` read: `queueList`, `offeredSource row model.selectedView`, `pageRefusal`. The refusal order must stay the same.
  - `WriteUnit` must carry the `ShownSource` from `offeredSource`, never a re-derived one.
  - `WriteFile` must carry the drawn digest only after the equality.
  - The reviewer diffs the old and new arms line by line, and checks that tests 4 and 5 and the retargeted `decisionRefusedBeforeReading` are red under a swapped refusal.
- **Single-flight (correctness/efficiency).** Slices 2 and 4.
  - Every `( slot, Maybe start )` maps to exactly one `Effect`, and no step emits an `Effect` whose stamp is not the slot's new running stamp.
  - Check test 3 under the mutation "emit the start twice".
- **Epoch ownership (security).** Slice 2.
  - `owns` compares the full stamp and the current epoch.
  - No `*Arrived` keeps a second, local owner check that could disagree.
  - `running` returns `Nothing` for a foreign epoch.
  - The `DecisionSaved Ok` drain is behind `owns`.
  - Test 1(a) is driven with a stamp from a real start under another epoch.
- **Persisted shape (soundness).** Slice 2. The runtime's reject-before-deserialize gate (`src/runtime/rust/src/web/additive.rs`) drops a stored session of the old shape into a fresh `init`, never a partial decode. Confirm that no persisted field is reordered without that gate seeing it.
- **Pure-move slices (1).** No arm, guard or text changes, only qualifiers. Reviewer check: a word diff of the moved bodies is empty apart from qualifiers.
- **Every slice:**
  - `ipe test` green (about 514 tests, plus the new ones in slice 4);
  - `ipe fmt` clean on the touched files;
  - the touched-module scans in `TextSinkScanTests`/`FailureScanTests` re-pointed, never narrowed. The fixture count per scan must not drop.

## 9. Better than the proposal (>= 95% confidence, expressible in today's Ipê)

Adopted:

- **Stamp stored in the slot.** The proposal carried the epoch in the `Effect`. Storing the full stamp in the slot also makes "exactly once" a checkable property (test 3) and makes ownership one function (`owns`).
- **`shownPanel` inside `Session.step`,** not in the interpreter, so no adapter can skip it.
- **The decision plan resolved in `step`.** `run` is `Model`-free, and a refused decision is `[]` rather than a task that answers a refusal.

These use only what the base already uses: parametric opaque types (`LoadSlot want`), tuples, `case`, `List`, and structural `==` on stamps. They need no new syntax or capability.

Rejected:

- **Deriving effects from a before/after slot diff.** `LoadRunning` does not hold the running want. Two reads of the same uid would be indistinguishable without a ticket. `DecisionSaving` would have to persist the `ShownSource`, which multiplies session bytes (8cc).
- **A per-render View read record** (section 3.6).
- **One `Session` module for every slot** (section 3.5).

## 10. Residuals

- **R1, runtime LIMIT, recorded in `misc/security-issues/debugger-import-forges-opaque-msgs.md`.** A debugger import can forge any `Msg`, including a stamp equal to a running one, because the runtime has no session generation. `owns` drops every forged stamp that does not match. A matching forged result is caught by the sinks' re-proof (`drainThenLoad`), not by this design.
- **R2.** The slot types keep `(..)` exposure in these slices, because the existing tests read their constructors. Opaque slot types would give the split modules depth, not only locality. That needs the tests rewritten onto queries, which is a separate, test-only change (decision D4).
- **R3.** The recorder proves which `Effect` a transition emits, not that `run` maps it to the right producer. `run`'s arms are pinned by the `ViewTests` call-site counts and by test 7. A swapped producer between two arms of the same result type would need a type difference to be unrepresentable. Today the five producers have five distinct result types, so `Msg` typing already refuses such a swap.

## 11. Open maintainer decisions (default in brackets)

- **D1 [yes].** On states no live session reaches, `decisionPlan` `Err` emits no task, where today it emits a task that answers the refusal; and an unowned `DecisionSaved Ok` no longer drains. Both are pinned by tests 4, 5 and 6.
- **D2 [yes].** The persisted `Model` shape changes (stamps in the slots), so live sessions reset to `init` once on upgrade, and an open refusal draft is lost.
- **D3 [yes].** Module names: `Lib.Slot`, `Lib.Selected`, `Lib.Standing`, `Lib.DecisionSlot`, `Lib.History`, `Lib.Session`.
- **D4 [later, separate change].** Make the slot types opaque (R2).
