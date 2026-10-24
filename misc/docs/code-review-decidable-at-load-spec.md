# code-review: a decision is offered only where it can be recorded

Designed by: security-soundness-guardian
Reviewed by: security-soundness-guardian (re-planned on `origin/main` `a95c1c1af`, after the session-effects refactor #3826 moved the gate)
Finding: PROBE-2026-10-22 D-01 (MEDIUM). Decided: the tool alone refuses such
a unit, with a notice in place of its controls; `ipe-index` and its schema
are not changed.

## Defect (verified on `a95c1c1af`)

A unit whose stored `kind`, `qualified` or `path` is past
`UnitName.nameMaxChars` (2048 code points, `UnitName.ipe:52`), or is not whole
text (cut at a NUL, or not stored as text), is drawn with Approve and Refuse.
A click then reaches `Session.decisionPlan` (`Session.ipe:751`), the save runs
`Index.reverify` (`Index.ipe:2781`), and `Index.attestedWith` (`:2850`)
refuses it as `NamePastCeiling` or `NameUnreadable` after the trip to the
index. The same holds for an unreviewable file whose stored `path` breaks the
ceiling: it is drawn with Acknowledge.

Cause: the one predicate the view draws controls by,
`DecisionSlot.decidableRow` (`DecisionSlot.ipe:71`), reads the log state, the
page's refusal row digest and `Selected.decidableSource` (`Selected.ipe:251`),
never the name. The name is parsed only at decide time, by
`UnitName.unitFromColumns` / `UnitName.fileFromColumn` (`UnitName.ipe:84`,
`:99`). The page read already holds the same `Label.Column` values
(`Index.RowShown`, `Index.ipe:355`; `RawRefusal.path`, `:1292`), windowed at
`Label.windowChars` = 4096 > 2048, so the parse can run at decode time with
the same verdict.

## Class-closing property

Whether a row's name can be recorded is parsed ONCE, at the row's decode
point, into a typed value carried on the row; the draw gate, the click
pre-check and the notice all read that value. No second predicate exists to
drift from it.

1. `Index.Unit` (`Index.ipe:42`) and `Index.RefusalRow` (`:1280`) gain
   `record : Result DecideRefusal RecordedName`. `Index.withRow` (`:2574`) sets
   it from `UnitName.unitFromColumns { kind = shown.kind, qualified =
   shown.qualified, path = shown.path, line = row.lineStart }`;
   `Index.refusalRowOf` (`:1334`) from `UnitName.fileFromColumn raw.path`.
2. The `NameRefusal -> DecideRefusal` mapping inline in `Index.attestedWith`
   is extracted to `Index.nameDecision : Result NameRefusal RecordedName ->
   Result DecideRefusal RecordedName` (exhaustive `case`, no wildcard:
   `PartPastCeiling` to `NamePastCeiling`, the other three to
   `NameUnreadable`), used by `withRow`, `refusalRowOf` and `attestedWith`.
3. `DecisionSlot.decidableRow` offers a `UnitOffer` only when the selected
   unit's `record` is `Ok`, and a `FileOffer` only when the refusal row's
   `record` is `Ok` (and, as now, its digest is present). `decidableAs`
   therefore refuses a click on such a row with no Db call.
4. `DecisionSlot.undecidable` (`:185`) names the row's own `record` refusal
   first: `SaveRefused NamePastCeiling` / `SaveRefused NameUnreadable`,
   ahead of `SourceNotShown` and `NotQueued`'s queue-state causes, so the
   refusal text names the cause the row has (8dv).
5. `View.decisionButtons` (`View.ipe:1115`) and `View.refusalControls`
   (`:302`) draw, where the row's `record` is `Err r`, the text
   `Failure.saveFailureText (Failure.SaveRefused r)` in place of the
   controls. The text comes from the row's value; the controls still come
   only from `offered`, so no branch can draw a control the gate refused.
6. Defence in depth is kept unchanged: `Index.reverify` and
   `Index.reverifyRefusal` re-read and re-parse the name at decide time (a row
   can change between load and click), and migration 0009's `CHECK`s still
   bound the stored review-log parts.

## Files touched

- `tools/code-review/src/Lib/Index.ipe` — `Unit`, `RefusalRow`, `withRow`,
  `refusalRowOf`, `nameDecision` (exposed), `attestedWith`.
- `tools/code-review/src/Lib/DecisionSlot.ipe` — `decidableRow`,
  `undecidable`.
- `tools/code-review/src/Lib/View.ipe` — `decisionButtons`,
  `refusalControls`.
- Tests: `tests/QueueTests.ipe` (`sampleQueuedUnit` near :1046 gains
  `record`), `tests/SingleFlightTests.ipe` and `tests/ViewRenderTests.ipe`
  (`RefusalRow` and `Unit` literals gain `record`), `tests/IndexTests.ipe`
  (decode tests).

Not touched: `Session.ipe`, `App.ipe`, `Queue.ipe`, `Selected.ipe`,
`Failure.ipe`, `UnitName.ipe`, `tools/ipe-index`, any migration.

## Refusal tests

Local proof only: `cd tools/code-review && ipe test` (no CI job runs the
code-review suite). Each goes red with its rule removed; the implementer
records the mutation that turns each red.

- R1 `pastCeilingNameOffersNoDecision` (IndexTests or QueueTests): an index
  row whose `qualified` is `nameMaxChars + 1` characters decodes with
  `record = Err NamePastCeiling`, and `DecisionSlot.decidableRow` returns
  `Nothing` for it with its source shown. Red if the gate skips `record`.
- R2 `atCeilingNameOffersDecision`: the same row at exactly `nameMaxChars`
  decodes `Ok` and is offered (one step inside the limit).
- R3 `unreadableNameOffersNoDecision`: a part cut at a NUL byte decodes
  `Err NameUnreadable`; no offer.
- R4 `clickOnPastCeilingRefusedWithoutDb` (SingleFlightTests): `Session.step`
  on a decide Msg for such a unit, with a drawn offer forged to match,
  returns `SaveRefused NamePastCeiling` and no Effect that reaches the Db
  (pin the effect list empty of save effects).
- R5 `pastCeilingRefusalRowNoAck` (ViewRenderTests): a refusal row whose path
  breaks the ceiling renders no Acknowledge or Refuse control and renders the
  `NamePastCeiling` text.
- R6 `pastCeilingUnitDrawsNotice` (ViewRenderTests): the unit card renders the
  `NamePastCeiling` text and no Approve or Refuse control.
- R7 `nameDecisionTotal`: each `NameRefusal` constructor maps to its
  `DecideRefusal` (pins the extracted mapping against a swapped arm).
- R8 `undecidableNamesNameFirst`: `undecidable` on a past-ceiling queued unit
  whose source is not shown gives `NamePastCeiling`, not `SourceNotShown`.
- R9 (defence in depth kept) `reverifyStillRefusesChangedName`: a row decoded
  decidable, then rewritten past the ceiling in the index before the click,
  is refused by `reverify` at decide time.

## BUG-CLASSES entries

File: `misc/plugins/ipe/skills/lane-brief/BUG-CLASSES.md`.

- 8dv (refusal text asserting a cause only some producers have): touched and
  closed for this producer set: `undecidable` names the row's own refusal
  before the queue-state causes (R8).
- 8dx (an update that acts on a state the view draws by another predicate):
  applied: the gate and the notice read the one `record` field.
- 8cz (a test certifies a state production cannot reach): R1 to R3 build the
  row through `withRow` / `refusalRowOf` from columns, never a hand-set
  `record`.
- New class (the next free id, `8en` if free): "a control drawn by one
  predicate and refused by another". Check: every control whose action the
  server can refuse is drawn from the same typed decidability value the
  action's pre-check reads. e.g. D-01.

## Stop conditions (exit with `LIMIT:`)

- The page read's columns are not the `Label.Column` values `reverify` parses
  (a different window, a cast, another query): stop; the decode-time verdict
  could differ from the decide-time one.
- The change needs `Session.ipe`, `App.ipe`, `Queue.ipe` or `Selected.ipe`:
  stop and re-plan; the gate lives in `DecisionSlot`.
- Any change to `tools/ipe-index` or its schema: out of scope (decided).
- A `RecordedName` would have to be built outside `UnitName`: stop; it is
  opaque by design.

## Sequencing

One of the code-review session files (`View.ipe`, `SingleFlightTests.ipe`):
no other change touching `Session.ipe`, `App.ipe`, `View.ipe`, `Queue.ipe`
or `SingleFlightTests.ipe` runs beside it. Index probe wording of
`code-review-startup-refusal-layout-spec.md` waits for it (`Index.ipe`).
Dropping the unused `DecisionSlot.openPanel` follows it (same file).
