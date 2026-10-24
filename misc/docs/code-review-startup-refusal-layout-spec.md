# code-review: every startup line has one layout, rendered in one place

Designed by: security-soundness-guardian
Base: `origin/main` `a95c1c1af`. Principle: ease of use (diagnostics that name
the problem and the one fix), bounded by security (a foreign value enters the
line only quoted, capped and escaped). No new CLI command or flag, no syntax,
no stdlib surface, no `unsafe`.

## Defect (verified on `a95c1c1af`)

`EnvLookup.startupRefusal` (`tools/code-review/src/Lib/EnvLookup.ipe:80`) is
the one renderer of `VAR: cannot use "<file>": <problem>; fix: <fix>`, and
`Settings`, `ReviewKey` and `Db` build their refusals through it
(`Settings.ipe:233`, `:429`; `ReviewKey.ipe:55`, `:92`; `Db.ipe:665`). Four
producers still lay their text out by hand, so the lead, separator, line
break and fix are each one's choice (BUG-CLASSES 8eb, still open for them):

1. `EnvLookup.requiredVarRefusal` (`EnvLookup.ipe:21`) takes the variable as a
   `String`, prints `code-review: required environment variable KEY is not
   set.\n  <fix>`, and its callers pass free text fixes with their own
   embedded `\n  ` (`Main.ipe:169`, `:170`). Two lines, no `fix:` lead.
2. `Bind.refusalText` (`Bind.ipe:119`) prints `IPE_HTTP_BIND is ...` with its
   remedy after a `; `, and `Main.requireLoopbackBind` (`Main.ipe:150`) adds
   its own `code-review: ` prefix. `IPE_HTTP_BIND` is not a `StartupVar`, so
   no check covers it; the foreign value's cap (`Bind.echoMaxChars`) lives
   in `Bind`, outside the renderer.
3. `ReviewKey.readOnlyNotice` (`ReviewKey.ipe:102`) prints a two-line notice
   with a literal `\n  fix:`.
4. The `code-review: ` prefix is written in three places (`Main.ipe:64` via
   `requiredVarRefusal`, `:91` `printStartupFailure`, `:150`).

The index probes' read failures (`Index.ipe:2248`) are out of scope here (see
Stop conditions).

## Class-closing property

A startup line is one typed value rendered by one function: every refusal is
a `StartupRefusal` (variable, optional file, optional foreign value, problem,
one fix) rendered by `EnvLookup.startupRefusal`, every notice a
`StartupNotice` rendered by `EnvLookup.startupNotice` in the same layout, and
one printer, `Main.printStartupFailure`, adds the `code-review: ` prefix. No
producer writes a separator, a line break, a `fix:` lead or the prefix; a
foreign value reaches the line only through the renderer's cap and quoting.

## Design

- `EnvLookup.StartupVar` gains `HttpBindVar` (`IPE_HTTP_BIND`), named in
  `startupVarName` and listed in `startupVars` (exhaustive `case`).
- `StartupRefusal` gains `given : Maybe String`, the variable's own value when
  the refusal shows it. The renderer shows it after the variable as
  `is "<value>"` with `SafeText.quoted (String.left echoMaxChars value)` and a
  `…` cut mark past the cap. `echoMaxChars` (64) moves from `Bind` to
  `EnvLookup` (SSOT). Every existing producer sets `given = Nothing`.
- `requiredVarRefusal : StartupVar -> Error -> Error` builds a
  `StartupRefusal` with problem `it is not set` or `it could not be read
  from the environment` (decided by `isUnset`, never the failure text) and
  the fix from `requiredFix : StartupVar -> String` (exhaustive). The
  `IPE_INDEX_DB` fix is one line: "set it to the path of the ipe-index
  index.db (absolute, or relative to the working directory); build it first
  from the repo root with `tools/scripts/ipe-index index`".
  `Main.requireEnv` takes a `StartupVar`, and its recovery calls
  `printStartupFailure`.
- `Bind.refusal : BindRefusal -> Error` replaces `refusalText`: `EmptyBind`,
  `NotLoopback raw` (`given = Just raw`) and `UnreadableBind` each a
  `StartupRefusal` on `HttpBindVar`, its problem naming why (not one of the
  accepted loopback spellings; the page is unauthenticated, so it listens on
  loopback only), its one fix the unset / accepted-spellings / SSH tunnel
  remedy. `Main.requireLoopbackBind` uses `printStartupFailure`.
- `EnvLookup.StartupNotice = { var : StartupVar, problem : String, fix :
  String }` and `startupNotice : StartupNotice -> String` render
  `code-review: VAR: <problem>; fix: <fix>` on one line;
  `ReviewKey.readOnlyNotice` is built through it.
- `Main.printStartupFailure` is the only `code-review: ` prefix of a refusal.

## Files touched

- `tools/code-review/src/Lib/EnvLookup.ipe`
- `tools/code-review/src/Lib/Bind.ipe`
- `tools/code-review/src/Lib/ReviewKey.ipe`
- `tools/code-review/src/Lib/Settings.ipe` (`given = Nothing` at the two
  producers)
- `tools/code-review/src/Lib/Db.ipe` (`given = Nothing` at `:665`)
- `tools/code-review/src/Main.ipe`
- `tools/code-review/tests/SettingsTests.ipe`
- `tools/code-review/tests/TextSinkScanTests.ipe` (the layout scan)
- `misc/plugins/ipe/skills/lane-brief/BUG-CLASSES.md` (8eb example)

Not touched: `Index.ipe`, `Session.ipe`, `App.ipe`, `View.ipe`, `Queue.ipe`,
`SingleFlightTests.ipe`, `QueueTests.ipe` (it lists module paths only; no
module is added or removed).

## Refusal tests

Local proof only: `cd tools/code-review && ipe test` (no CI job runs the
code-review suite). Each goes red with its rule removed; the implementer
records the mutation that turns each red.

- S1 `requiredVarRefusalExactLine`: for `IndexDbVar` and `IndexRootVar`, under
  `Error.notFound` and under `Error.permissionDenied`, the printed text is
  pinned exactly (`IPE_INDEX_DB: it is not set; fix: ...`), one line, and never
  holds the failure's own message. Red if the `\n  ` layout returns or the
  kind test reads the text. Replaces `requiredVarRefusalByKind`.
- S2 `bindRefusalExactLines`: `EmptyBind`, `UnreadableBind` and
  `NotLoopback raw` with `raw` holding `"`, `; fix: `, a line break, an ESC
  and 70 characters: each pinned exactly, byte for byte, as the printer
  prints it; the value appears capped at 64 with `…`, quoted and escaped, so
  its `"` cannot close the quotes and its `; fix: ` stays inside them;
  `UnreadableBind` shows no value. The benign refusals (`EmptyBind`,
  `UnreadableBind`, `NotLoopback` of a plain value) also pass
  `oneLineRefusal`; the hostile one cannot, since `oneLineRefusal` refuses
  any `\` and the escapes are the point, so its exact pin is its proof.
  Keeps the needles of `bindRefusalNamesRemedy`.
- S3 `readOnlyNoticeOneLine`: the notice is pinned exactly, one line, one
  `; fix: `.
- S4 `startupRefusalsOneLine` (extended): its rendered list gains every bind
  refusal and both required-var refusals; the `startupVars` count is
  computed from the `case` it must cover (one sample per constructor), not a
  literal 5 or 6 (8cb).
- S5 `startupLayoutHasOneRenderer` (TextSinkScanTests): no source file under
  `tools/code-review/src` except `Lib/EnvLookup.ipe` holds the text `fix: `
  in a string literal, a `\n` or `\r` escape amid other text in a string
  literal (a literal of line breaks alone is a separator), or the literal
  `code-review: ` outside
  `Main.printStartupFailure` and `EnvLookup.startupNotice`. Driven with a
  planted copy to prove it can fail (8cz).

## BUG-CLASSES entries

File: `misc/plugins/ipe/skills/lane-brief/BUG-CLASSES.md`.

- 8eb (a message layout assembled by each producer): closed for every
  startup line but the index probes; the example names
  `requiredVarRefusal`, `Bind.refusal` and `readOnlyNotice`, and S5 is its
  check.
- 8ci (untrusted text flattened at a display sink): applied: the bind value
  enters only through the renderer's quoting (S2).
- 8cb (an expected value taken from a spec claim): applied to the
  `startupVars` count (S4).
- No new class.

## Stop conditions (exit with `LIMIT:`)

- Any change to `Index.ipe` (the probe read failures at `:2248`): stop; it
  waits for `code-review-decidable-at-load-spec.md`, which owns `Index.ipe`,
  and is then planned as its own change.
- A fix text that needs two lines or a second `fix:`: stop; one fix per
  refusal is the rule, so the problem is split instead.
- `printStartupFailure`'s second `renderForeign` pass changes a pinned
  existing line (`startupRefusalQuotesFile`): stop and report; the printer
  stays as is in this change.
- Anything in the runtime's own `IPE_HTTP_BIND` reading: out of scope.
