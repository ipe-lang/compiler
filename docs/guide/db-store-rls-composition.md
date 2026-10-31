# Composing row-level security

`Ipe.Db.Store` ships a small, principled row-security core: opaque `Pred`/`Policy`
values, the boolean builders `allOf` / `anyOf` / `notPred`, the row-side leaf
`matchWhere`, the caller-side leaves `role` / `memberOf` / `claimEquals`, the
correlated-subquery leaf `existsIn` / `correlate`, the owner-scoped `ownerColumn`,
and the composers `andPolicy` / `readOnly` / `alsoInsert` / `alsoUpdate` /
`alsoDelete`. The four row-level-security patterns real applications need — Owner,
RBAC, Tenant, Sharing — are not four more core functions. Each is a thin
composition YOU write over those exports. Breadth grows as your own package code,
never by editing the core.

## The mental model

Three ideas.

- **A policy is data you compose, not a callback you register.** A `Pred` carries
  only concrete data (column names, bound values, nested predicates), never a
  function, so it can be simplified, explained, and its refusals generated. You
  build a pattern by combining leaves with `allOf` / `anyOf` / `andPolicy`, and you
  read back the exact meaning with `Store.explain`.
- **The caller-side leaves gate on WHO is asking, and fail closed.** `role` /
  `memberOf` / `claimEquals` name no row column; they answer against the
  authenticated caller's verified claims. An absent role, an absent group, an
  absent or mismatched claim each contribute the *deny* fragment — so a caller a
  leaf cannot prove satisfies it is turned away, never admitted by omission.
- **Every operation a pattern does not open stays `never`.** `readOnly p` opens
  only reads; insert/update/delete stay at their fail-closed `never` default. A
  write path is opened deliberately (`alsoInsert` …) or by `ownerColumn` (which
  scopes writes to the owner). Deny-by-default holds *through* the composition —
  an unopened write has no open-write representation.

## A worked example: the four patterns

The policy surface is pure — `explain` renders a policy as text and `secured`
classifies a store, neither needing a live database or a `Principal` — so the whole
demonstration runs deterministically. The multi-module package under
[`examples/shapes/script/rls-composition-builders`](https://github.com/ipe-lang/compiler/blob/main/examples/shapes/script/rls-composition-builders/src/Main.ipe)
puts each pattern in its own `Rls.*` sub-module of composition helpers, and its
`Main` exercises all four. The sealed, self-contained twin is
[`tests/golden/db_store_rls_composition_builders_seal`](https://github.com/ipe-lang/compiler/blob/main/tests/golden/db_store_rls_composition_builders_seal/src/Main.ipe).

**Owner** — the simplest pattern: every row is private to the user who created it,
and no one else can see or change it (think a personal notes or drafts table). A row
belongs to the caller when its owner column equals the caller's subject; `ownerColumn`
scopes all four operations to `column = $subject`, forces that column on insert, and
never rewrites it on update, so a caller can never write a row it could not read back
nor hand one to another principal. Compose `immutable` to pin a
column at insert:

```ipe
Store.ownerColumn .author
    |> Store.andPolicy (Store.immutable .createdAt)
```

**RBAC** — *role-based access control*: who may see or change a row is decided by
the **role** the caller was granted (`admin`, `editor`, `viewer`, …), not by who
owns the row. One admin sees every row; a viewer only reads. It is built from the
fail-closed caller leaves, alone or in a disjunction with a row match. "Only an admin
may read"; "the owner-value row OR any admin may read":

```ipe
Store.readOnly (Store.role "admin")

Store.readOnly
    (Store.anyOf
        [ Store.matchWhere (Store.eq .author "root")
        , Store.role "admin"
        ]
    )
```

**Tenant** — in a multi-tenant application one deployment serves many independent
customers (each company or organization is a *tenant*), and every tenant's rows must
be completely invisible to every other tenant — the hard data-isolation boundary a
SaaS depends on. `claimEquals` gates the whole table to one tenant, keyed on the
caller's verified `tenant` claim (fail-closed on an absent or mismatched claim, so a
caller with no tenant sees nothing). For per-row isolation across many tenants,
correlate each row against a caller-scoped memberships store with `existsIn` instead:

```ipe
Store.readOnly (Store.claimEquals "tenant" "acme")
```

**Sharing** — one user explicitly grants another user (or a team) access to a
*specific* record — a shared document, a delegated folder. Access is per-record and
recorded in a separate `shares` table, not global like a role. A row is visible when
that SECURED shares store holds a share row that correlates to it. Because the shares
store is itself secured to the caller, its own read policy composes into the `EXISTS`
subquery — defence in depth: a share the caller cannot read cannot open a row:

```ipe
Store.readOnly
    (Store.existsIn securedShares
        (\share doc -> Store.correlate share.docId doc.id)
    )
```

`Store.explain` renders the sharing policy's read clause as transparent text, so a
reviewer reads the intent beside the generated SQL:

```
exists in shares where shares.doc_id = id and its read policy: (member = caller subject)
```

The example also pins the refusals: every read-only pattern's insert/update/delete
explains as `no row (denied)`, and `secured` over a store whose columns lack a
policy column returns a typed `Err` — deny-by-default proven, not assumed.

## The why

That the core needs no new function for Owner, RBAC, Tenant, or Sharing is
[community-extensibility][principles] made concrete: the language core and standard
library stay deliberately small and principled, and breadth grows as community
packages built on them. Your RLS vocabulary is your own composition helpers over
the audited leaves — you extend the language without waiting on the core, and
without a fork.

The fail-closed caller leaves and the `never`-by-default writes are
[security][principles]'s fail-closed rule carried through composition: absent proof
the caller holds a role or claim, the conservative branch (deny) is the only
reachable one, and a write the pattern never opened has no representation as an open
write. The shares store's own read policy folded into the `existsIn` subquery is
[defence in depth][principles] — the visibility guarantee does not rest on the
correlation alone. And because a `Pred` is data, `explain` can state a policy's full
meaning, so a wrong composition is legible before it ships an insecure idiom.

[principles]: https://github.com/ipe-lang/compiler/blob/main/PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Db.Store` — `always` / `never`, `allOf` /
  `anyOf` / `notPred`, `matchWhere`, `role` / `memberOf` / `claimEquals`,
  `correlate` / `existsIn`, `ownerColumn` / `immutable` / `mask`, `readOnly` /
  `alsoInsert` / `alsoUpdate` / `alsoDelete` / `andPolicy`, `secured`, `explain`,
  and the secured operations `allAs` / `getAs` / `insertAs` / `updateAs` /
  `deleteAs`, each with its signature.
- **Worked example:**
  [`examples/shapes/script/rls-composition-builders`](https://github.com/ipe-lang/compiler/blob/main/examples/shapes/script/rls-composition-builders/src/Main.ipe)
  — the four patterns as `Rls.*` composition helpers.
- **The SEAL:**
  [`tests/golden/db_store_rls_composition_builders_seal`](https://github.com/ipe-lang/compiler/blob/main/tests/golden/db_store_rls_composition_builders_seal/src/Main.ipe)
  — ipe-accepts ⇒ cargo-builds ⇒ runs ⇒ output matches `expected.txt`.
- **Sibling guides:** [Store](db-store.md) — the typed table the policy secures.
  [Codec](codec.md) — the single source of truth a store and its columns derive
  from. [Database codecs](db-codec.md) — a row as raw columns and back.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — the untrusted boundary turned into a typed value once.
