# The unsafe database surface

`Ipe.Db.Unsafe` is the one home for the database members that bypass a security or
type invariant of the safe default — raw SQL and untyped column reads. Each exists
for a residual case the safe surface cannot express; reaching for one is a
deliberate act with a visible cost.

## When to reach for it

The safe defaults handle almost everything: parameterised `Db.exec` /
`Db.queryDecode` with the `Sql.*` combinators over a validated `SqlFragment`, and
the typed row codec that decodes each column with proof. Reach into
`Ipe.Db.Unsafe` only when the safe surface genuinely cannot express the query —
and know exactly which invariant you are taking ownership of, because the module
hatches two distinct axes:

- **The SQL-injection axis.** `unsafeExecRaw` / `unsafeQuery` issue verbatim,
  caller-authored SQL text; `unsafeFragment` mints a `SqlFragment` from an
  unchecked string, deliberately skipping the `Sql.column` identifier validation.
  No validator makes arbitrary SQL safe — the caller asserts the text is safe. The
  safe default is parameterised binds and the validated `Sql.*` combinators.
- **The type-safety axis.** The `unsafeGet*` family (`unsafeGetString`,
  `unsafeGetInt`, `unsafeGetBool`, `unsafeGetField`) reads a field of a payload
  `Dict String String` (a request or message field map) by string key with no
  decode proof. No SQL is issued, so there is no injection risk on this axis — but
  the caller asserts the field's runtime type matches the read. A database row is
  not a payload map: every raw read returns `Dict String (Maybe String)`, with SQL
  `NULL` as `Nothing`, and `Ipe.Db.Store`'s `readText` / `readInt` / `readFloat` /
  `readBool` parse one cell, a `NULL` or missing column as a typed `Err`. The safe
  default is `Db.queryDecode`'s row codec.

```ipe
import Ipe.Db.Unsafe exposing (unsafeQuery)

-- The query TEXT is caller-authored verbatim; only the binds are parameterised.
-- The caller now owns the injection invariant `Db.queryDecode` would have held.
-- Each row maps a column to its cell text, `Nothing` for SQL `NULL`.
rows : Task Error (List (Dict String (Maybe String)))
rows =
    unsafeQuery conn "SELECT * FROM audit WHERE ts > ?" [ SqlString cutoff ]
```

## The safety boundary

Every member's `unsafe` prefix names the invariant it bypasses at the call site.
Two things keep the cost visible rather than silent:

- **The hatches live in a separate submodule.** They are not on the native
  `Ipe.Db` / `Ipe.Db.Sql` surface, so they cannot be reached by accident — you
  import `Ipe.Db.Unsafe` on purpose.
- **Importing it discloses the `unsafe` capability program-wide.** A dependency's
  raw-SQL or untyped-read sink is visible before the program runs, so an auditor
  can see that some code bypasses the parameterised / typed defaults without
  reading every line.

`unsafeExecRawOn` adds one further guard: it requires a `Connection ReadWrite`, so
a read-only connection cannot reach it — a compile error, not a runtime check.

## The why

Keeping raw SQL and untyped reads off the default surface and behind a disclosed
capability is [security][principles] and [defence in depth][principles] together:
the parameterised, typed default is one boundary, and the fact that bypassing it
is both explicitly named (`unsafe`) and program-visible (the capability) is the
second. The safe surface covers the common case without ever issuing verbatim SQL
or reading a column without proof, so each hatch stays reserved for the residual
it was built for, and every use of one is an auditable decision.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Db.Unsafe` — `unsafeExecRaw`,
  `unsafeQuery`, `unsafeFragment`, the `unsafeGet*` reads, and `unsafeExecRawOn`
  (the read-write-only raw exec). The safe siblings are `ipe doc Ipe.Db` and
  `ipe doc Ipe.Db.Sql` — parameterised exec/query and the validated `Sql.*`
  combinators.
- **Sibling guides:** [Database codecs](db-codec.md) — the typed row seam the
  `unsafeGet*` family bypasses. [The secret-reveal escape hatch](secret-unsafe.md)
  — the other escape hatch, and the same `unsafe`-capability disclosure model.
