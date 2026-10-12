# Store

A `Store a` is one typed database table whose schema, reads, and writes all derive
from a single `Codec a`. The codec is the one source of truth: its shape names the
columns, its encoder writes a row, its decoder reads one back. A `Store` is *deny-by-default*:
`fromCodec` yields a `Draft` with no read or write operation, and only an explicit
classification — `public` (world-open) or `secured` (policy-guarded) — turns it
into something queryable. This guide is about the secured half: attaching a
row-security `Policy` so the database itself never returns, nor writes, a row the
caller is not entitled to.

## The mental model

Four ideas carry the whole security model.

- **Classification is the only door, and it is closed by default.** `fromCodec`
  returns a `Draft a` — schema known, access intent unknown, no operation attached.
  `public` promotes it to a world-open `Store a` (read and written by `all` / `get`
  / `insert` / `upsert` / …); `secured policy` promotes it to a `Secured a` (read and written
  *only* through the authenticated `allAs` / `getAs` / `insertAs` / `updateAs` /
  `deleteAs` operations, each of which takes a `Principal`). A table nobody
  classified has no read or write function that will accept it — an unguarded table
  is not a review you might skip, it is a value that does not exist.
- **The `Principal` is minted only by the auth middleware.** Application code cannot
  fabricate one; it arrives as the second argument of an authenticated route handler
  (`Server.getAuthed` / `postAuthed` / `putAuthed` / `deleteAuthed`), after the
  fail-closed middleware has verified the token. So an unauthenticated request can
  reach none of the `…As` operations — there is no `Principal` to pass them.
- **A `Policy` is per-operation, and every operation it does not open is `never`.**
  `ownerColumn .author` scopes read, get, update, and delete to `author = $subject`,
  forces the owner column to the caller on insert, and never rewrites it on update,
  so a caller can neither read nor write a row it does not own, nor hand one to
  another principal. `readOnly p` opens reads to `p` and leaves every write at
  `never`; a write path is opened deliberately with `alsoInsert` / `alsoUpdate` /
  `alsoDelete`, never by omission. The unspecified operation fails closed because
  its predicate is `never`, which has no representation as an open one.
- **A write keeps only a row its policy admits.** `insertAs` and `updateAs` each
  run as one statement in its own savepoint whose `RETURNING` evaluates the insert
  or update predicate over the row as stored; the savepoint is kept only when that
  check holds. A write the policy refuses returns `0` and writes nothing, so a
  `readOnly` store rejects every `insertAs`, and an update cannot move a row out of
  what the policy lets the caller update.
- **The policy compiles to a bound-param `WHERE`, never interpolation.** The owner
  filter lowers through `Sql.column` (for the validated column) and `Sql.param` (for
  the subject); the caller-side leaves — `role` / `memberOf` / `claimEquals` — read
  the principal's *verified* claims through fail-closed accessors (an absent role,
  group, or claim DENIES) and fold to an always-true or always-false fragment. No
  caller value is ever concatenated into SQL text.

For composing owner, tenant, RBAC, and sharing rules into reusable policy helpers —
the deep predicate algebra (`allOf` / `anyOf` / `notPred` / `existsIn` / `correlate`) —
see the sibling guide [Composing row-security policies](db-store-rls-composition.md).

## A worked example: store-secured-owner

A per-owner secured store, end to end. The example under
[`examples/shapes/script/store-secured-owner`](../../examples/shapes/script/store-secured-owner/src/Main.ipe)
builds a `Note` table from a codec, secures it with an owner policy, and both writes
and reads it as the authenticated caller through `insertAs` and `allAs`.

The row type and codec — the field names become the columns (`author`,
`created_at`, `body`):

```ipe
type alias Note =
    { author : String
    , createdAt : String
    , body : String
    }


noteCodec : Codec Note
noteCodec =
    Codec.auto blankNote
```

The policy: each row is owned by its `.author`, and `.createdAt` is immutable —
fixed at insert, dropped from every update SET so a later write cannot change it:

```ipe
notePolicy : Store.Policy Note
notePolicy =
    Store.ownerColumn .author
        |> Store.andPolicy (Store.immutable .createdAt)
```

`secured` attaches the policy and yields a `Secured Note`, failing closed if the
policy names a column the store does not have:

```ipe
securedNotes : Result Error (Secured Note)
securedNotes =
    case Store.fromCodec "notes" noteCodec of
        Err e ->
            Err e

        Ok store ->
            Store.secured notePolicy (Store.primaryKey .body store)
```

The authenticated write-then-read handler. `insertAs` *forces* the `author` column
to the principal's subject (the record's `author` is ignored), so no caller can
forge authorship; `allAs` then returns only the rows the owner filter admits for
that same caller. The `do` block chains the `Task`s — each `x <- task` line desugars
to `Task.andThen`:

```ipe
handleAddNote : Request -> Auth.Principal -> Task Error Response
handleAddNote _ principal =
    Task.onError (\_ -> Task.succeed (Server.text "none"))
        (case securedNotes of
            Err _ ->
                Task.succeed (Server.text "policy-error")

            Ok secured ->
                do
                    db <- Db.connect ()
                    _ <- Store.insertAs principal db secured newNote
                    notes <- Store.allAs principal db secured
                    Task.succeed
                        (Server.text (String.join "\n" (List.map .body notes)))
        )
```

The handler is reachable only behind an authenticated route, where the middleware
mints the `principal`:

```ipe
main =
    ...
        (Server.listen
            8000
            [ Server.postAuthed "/notes" authCfg handleAddNote
            , Server.getAuthed "/my/notes" authCfg handleMyNotes
            ]
        )
```

Running it (`ipe dev run`) prints its name — the store is assembled and the route wired,
but the never-served `listen` is caught by `Task.onError`, so no live database or
network is needed to prove the model compiles and the security path type-checks:

```
store-secured-owner
```

The load-bearing proof is the SEAL: this program is built and run under `IPE_E2E=1`,
so a language change that broke the secured path — the policy builders, the `…As`
operations, or the principal-threading — would fail CI here.

## The why

A `Draft` with no read or write operation, promoted only through a named
classification, is [make invalid states unrepresentable][principles]: an unguarded
table is not a runtime check you might forget, it is a value the `…As` functions will
not accept. Scoping every unspecified operation to `never`, and reading absent
roles/groups/claims as denials, is [security][principles]'s fail-closed rule — with
no proof the caller is entitled, the reachable outcome is refusal, not access.
Forcing the owner column to the subject on insert, never rewriting it on update,
checking every secured write over the row as stored, and compiling the owner filter to
a bound-param `WHERE`, is [security][principles] again at the SQL boundary: a caller
can neither forge a row it could not read back nor smuggle a value into the query
text. And enforcing the filter *in the emitted SQL* — not merely in a post-fetch
check — is [defence in depth][principles]: the database never hands back an
out-of-policy row for application code to mishandle.

The `Principal` being mintable only by the auth middleware, never by application
code, keeps the trust boundary in one place: the `…As` operations cannot be called
without an authenticated caller, so authentication is a structural precondition of
every secured read and write, not a convention.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Db.Store` — `fromCodec`, `public`,
  `secured`, `explain`, the `Policy` builders (`ownerColumn` / `readOnly` /
  `immutable` / `andPolicy` / `alsoInsert` / `alsoUpdate` / `alsoDelete` / `mask`),
  the predicate leaves (`always` / `never` / `allOf` / `anyOf` / `notPred` /
  `matchWhere` / `role` / `memberOf` / `claimEquals` / `existsIn` / `correlate`), and
  the authenticated operations (`allAs` / `getAs` / `insertAs` / `updateAs` /
  `deleteAs`), each with its signature.
- **Sibling guides:** [Composing row-security policies](db-store-rls-composition.md)
  — the deep predicate algebra for owner / tenant / RBAC / sharing rules as
  composable helpers. [Codec](codec.md) — the single source of truth a store derives
  from. [Database codecs](db-codec.md) — that codec as a raw row and back.
  [Connection descriptors](dsn.md) — the typed `Dsn` that opens the connection.
  [The unsafe database surface](db-unsafe.md) — raw SQL and untyped reads.
- **Concepts:** [The `do` idiom](../idioms/do-notation.md) — the `Task`-chaining
  notation the handler uses. [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — identifier validation as a construction-time parse.
