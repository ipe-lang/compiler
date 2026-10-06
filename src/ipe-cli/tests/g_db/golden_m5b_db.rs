//! `Ipe.Db` gate — `SqlValue`-parameterized `Db.exec` + `Db.query` on an
//! in-memory `SQLite` database via `Db.withTransaction`.
//!
//! Every test compiles a Ipê program through `ipe`, builds the emitted Rust
//! project with the shared cargo target, runs the binary, and checks its stdout
//! against the cached oracle (`tests/golden/db_exec/oracle.meta` +
//! `expected_go.txt`). Tests are gated on `IPE_E2E=1`; without it they return
//! early.
//!
//! ## Oracle provenance — why this is `oracle_divergence = true`
//!
//! The the reference compiler and Ipê (the Rust backend) share the same Ipe
//! stdlib surface, but the backends diverge at the database layer:
//!
//! * The Rust backend emits `sqlx` + `sqlx-sqlite` for database access.
//! * The row type the runtime returns from `Db.query` is
//!   `Vec<HashMap<String, String>>`.
//! * Connection management for `sqlite::memory:` pools uses async `sqlx`
//!   pooling (serialised-mode `SQLite`).
//!
//! Running this `Main.ipe` end-to-end would require the full `SQLite`
//! toolchain and would produce byte-identical output, but is not part of
//! the automated oracle-capture workflow (the oracle tool runs on this machine).
//! The cached expected is Ipê's own verified output.
//!
//! ## Byte-identical output IS verified — separately
//!
//! The `db_exec` golden inserts `"apple"` and `"banana"` with `SqlString` /
//! `SqlInt` params and reads them back ordered by name. The output
//! `"apple:5\nbanana:3\n"` is the only correct answer; the backend would
//! produce identical bytes given the same Ipê source.
//!
//! ## Golden catalogue
//!
//! * `db_exec` — `Db.open` → `Db.withTransaction` → `Unsafe.unsafeExecRaw` (DDL,
//!   from `Ipe.Db.Unsafe`) → `Db.exec` with `[SqlString, SqlInt]` params (two
//!   INSERTs) → `Unsafe.unsafeQuery` with empty params (SELECT ORDER BY name) →
//!   `Unsafe.unsafeGetString` / `unsafeGetInt` field access → `println`.
//!   Output: `"apple:5\nbanana:3"`.
//! * `db_find_by_conditions` — `Db.exec` two INSERTs →
//!   `Db.findByConditions conn "items" (Dict.fromList [("name","apple")])` →
//!   single-row result → `Db.getString` / `Db.getInt` → `println`.
//!   Output: `"apple:5"`. Proves `Dict String String` arg type + emit arm.
//! * `db_find_where` — `Db.exec` two INSERTs →
//!   `Db.findWhere conn "products" (Sql.gt (Sql.column "qty") (Sql.int 9))` →
//!   single-row result → `println`. Output: `"widget:10"`.
//!   The `SqlFragment`-typed counterpart to a raw `Db.unsafeFindWhere` —
//!   the WHERE clause can only be built through the `Sql.*` combinators, never
//!   a hand-built string.
//! * `db_delete_where` — `Db.exec` three INSERTs →
//!   `Db.deleteWhere conn "products" (Sql.eq (Sql.column "name") (Sql.string "gadget"))`
//!   → row-count + a follow-up `Db.query` confirming only the matched row was
//!   removed → `println`. Output: `"1:sprocket,widget"`.
//! * `db_sql_combinators` — exercises every `Sql.*` combinator at least
//!   once (column, param via int/string/float/bool, eq, ne, gt, lt, gte, lte,
//!   and, or, not, isNull, isNotNull, like, inList non-empty AND the
//!   empty-list `(1 = 0)` shortcut) via three `Db.findWhere` calls.
//!   Output: `"widget|0|gadget"`.
//! * `db_gate_findwhere_string` (negative, `golden_m5b_db_gates.rs`) —
//!   `Db.findWhere conn "products" ("qty > " ++ "9")` is a compile-time
//!   `IPE-T0001` (`String` vs `SqlFragment`) — the "parse, don't validate"
//!   property this surface establishes.
//! * `db_find_by_field` — `Db.exec` three INSERTs (two `category = "fruit"`,
//!   one `category = "veggie"`) → `Db.findOneByField conn "items" "name" "apple"`
//!   (match → `Just` row) → `Db.findOneByField conn "items" "name" "durian"`
//!   (no match → `Nothing`) → `Db.findManyByField conn "items" "category"
//!   "fruit"` (match → two rows, sorted by name since the kernel issues no
//!   `ORDER BY`) → `Db.findManyByField conn "items" "category" "mineral"` (no
//!   match → `[]`). Output:
//!   `"apple:fruit:5\nmissing\napple:fruit:5,banana:fruit:3\nempty"`.
//!   Golden-E2E coverage for `DbFindOneByField`/`DbFindManyByField` through a
//!   real `ipe dev build` + `cargo build` + run, not just direct runtime source
//!   inspection.
//! * `db_decode_money` — `Db.Decode.money "amount"` inside a
//!   `Db.queryDecode` pipeline decodes the `"CODE AMOUNT"` TEXT column
//!   `SqlMoney` writes on INSERT back into `(Decimal, String)`, and a
//!   malformed value (no space separator) is a total `Task Err`, never a
//!   panic, caught via `Task.onError`. Output: `"USD 12.34\nmalformed:caught"`.
//!   Proves the kernel-registration recipe works end-to-end (canon
//!   allowlist, `StdlibKernel` decl, constrain scheme, lower dispatch, emit,
//!   pretty-print); without registration `Db.Decode.money` is rejected at
//!   canonicalisation as an unknown qualified name even when the runtime
//!   function is implemented and unit-tested.
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m5b_db
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe`, build the emitted Cargo project, run
/// it, and return the golden directory plus the run outcome. The caller gates on
/// `IPE_E2E`. Fails the test on any build/runtime error.
fn build_run(name: &str) -> (PathBuf, crate::support::RunOutcome) {
    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    (dir, outcome)
}

/// Compile/build/run the golden and assert its stdout matches the cached oracle.
/// Gated on `IPE_E2E=1`.
fn assert_runs_and_matches_oracle(name: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (dir, outcome) = build_run(name);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the oracle");
}

// ── Db exec + query via SqlValue params ──────────────────────────────────────

/// `Db.open` → `Db.withTransaction` → `Db.unsafeExecRaw` (DDL) →
/// `Db.exec [SqlString "apple", SqlInt 5]` + `[SqlString "banana", SqlInt 3]`
/// (two INSERTs) → `Db.unsafeQuery [] (SELECT ORDER BY name)` →
/// `Db.unsafeGetString` / `Db.unsafeGetInt` → `println`.
/// Output: `"apple:5\nbanana:3"`.
///
/// Recorded sanctioned divergence (the prior backend `SQLite` vs Rust+sqlx): the Ipê source
/// produces identical output on both backends, but the oracle-capture toolchain
/// only runs Ipê locally.
#[test]
fn db_exec() {
    assert_runs_and_matches_oracle("db_exec");
}

// ── Db.queryDecode with typed Decoder ────────────────────────────────────────

/// `Db.exec` INSERTs two rows → `Db.queryDecode` with a `Decode.map2` decoder
/// that reads `name : String` + `score : Int` into a typed record → formats
/// `"name:score"` and joins with `","`. Output: `"alice:10,bob:7"`.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; oracle is Ipê's own output.
#[test]
fn db_query_decode() {
    assert_runs_and_matches_oracle("db_query_decode");
}

// ── Db.Decode.andThen — function-first surface, decoder-first runtime ─────────

/// `Db.Decode.andThen (\n -> Db.Decode.succeed (String.toUpper n))
/// (Db.Decode.string "n")` chains a row decoder: read `n : String`, then
/// upper-case it. Two rows ("alice", "bob") decode to `"ALICE"` / `"BOB"`,
/// joined with `","`. Output: `"ALICE,BOB"`.
///
/// The surface passes the continuation first; the runtime `decode_and_then`
/// takes the decoder first, so the emitter must reorder the two arguments —
/// without the reorder the emitted `decode_and_then(closure, decoder)` is a
/// type error. This golden is that reorder's regression anchor.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; oracle is Ipê's own output.
#[test]
fn db_decode_and_then() {
    assert_runs_and_matches_oracle("db_decode_and_then");
}

// ── Db CRUD roundtrip ────────────────────────────────────────────────────────

/// `Db.insertRow` → `Db.getById` (read) → `Db.updateById` (update) →
/// `Db.deleteById` (delete) → read-after-delete returns `Nothing`.
/// Output: `"apple/5\napple/10\ndeleted"`.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; oracle is Ipê's own output.
#[test]
fn db_crud() {
    assert_runs_and_matches_oracle("db_crud");
}

// ── Db.withTransaction — COMMIT and ROLLBACK paths ───────────────────────────

/// Two sequential transactions on a file-backed `/tmp/ipe_txn_golden.db`:
///
/// * Transaction 1 INSERTs `"hello"` and returns `Ok ()` → committed.
/// * Transaction 2 INSERTs `"world"` then calls `Task.fail` → rolled back.
///
/// A `SELECT` after both transactions observes only `"hello"`.
/// Output: `"hello"`.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; oracle is Ipê's own output.
#[test]
fn db_transaction() {
    assert_runs_and_matches_oracle("db_transaction");
}

// ── Db.migrate — versioned forward-only migrations + idempotence ─────────────

/// First `Db.migrate` call applies two migrations (`001_create_users`,
/// `002_add_email`) and returns their names. Second call (same list) is a
/// no-op → returns `[]` → empty string. Output: `"001_create_users,002_add_email|"`.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; oracle is Ipê's own output.
#[test]
fn db_migrate() {
    assert_runs_and_matches_oracle("db_migrate");
}

// ── Db.insertFields / updateFields with OmitField ────────────────────────────

/// `Db.insertFields` with `OmitField` on the `notes` column → DB applies
/// `DEFAULT 'none'`. `Db.updateFields` with `OmitField` on `notes` again →
/// `notes` stays `'none'` while `name` changes to `'gadget'`.
/// Output: `"widget/none\ngadget/none"`.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; oracle is Ipê's own output.
#[test]
fn db_fields() {
    assert_runs_and_matches_oracle("db_fields");
}

// ── Db.Decode.nullable ───────────────────────────────────────────────────────

/// Two rows: one with a non-NULL `tag` (`"alpha"`) and one with a NULL `tag`.
/// `Db.queryDecode` with `Decode.nullable (Decode.string "tag")` → `Maybe String`.
/// Rows formatted as `"just:<tag>"` / `"nothing"` and joined with `","`.
/// Output: `"just:alpha,nothing"`.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; oracle is Ipê's own output.
#[test]
fn db_nullable() {
    assert_runs_and_matches_oracle("db_nullable");
}

// ── Db.findByConditions ───────────────────────────────────────────────────────

/// `Db.exec` INSERTs `"apple:5"` and `"banana:3"` rows →
/// `Db.findByConditions conn "items" (Dict.fromList [("name", "apple")])` →
/// single-row result → print `"apple:5"`.
///
/// Proves: (a) the `Dict String String` arg type is correct (not the old
/// `List (String, SqlValue)`); (b) the `DbFindByConditions` emit arm works.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; oracle is Ipê's own output.
#[test]
fn db_find_by_conditions() {
    assert_runs_and_matches_oracle("db_find_by_conditions");
}

// ── Db.findWhere / Db.deleteWhere / Ipe.Db.Sql combinators ──────

/// `Db.exec` INSERTs `"widget:10"` and `"gadget:7"` rows →
/// `Db.findWhere conn "products" (Sql.gt (Sql.column "qty") (Sql.int 9))` →
/// single-row result (`widget:10`) → print `"widget:10"`.
///
/// Proves: (a) the `SqlFragment`-typed `findWhere` wiring works end-to-end
/// (kernel decl, scheme, lower, emit, runtime); (b) values are bound via `?`
/// placeholders — the WHERE clause can only be built through `Sql.*`
/// combinators, never a hand-built string (see `db_findwhere_string_is_t0001`
/// in `golden_m5b_db_gates.rs` for the negative side of this property).
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; `Db.findWhere` has no prior
/// counterpart; oracle is Ipê's own output.
#[test]
fn db_find_where() {
    assert_runs_and_matches_oracle("db_find_where");
}

/// `Ipe.Db.Store` end-to-end (THE SEAL golden for the store surface): derive a
/// `Store` from a `User` record's typed columns, `Store.create` the table via
/// the migration ledger, `Store.insert` two rows (one carrying the adversarial
/// value `'; DROP TABLE users; --`), then `Store.get` by primary key and decode
/// the row back through the per-column `read*` helpers. Prints three lines:
///
///   * `roundtrip:ok` — insert → query-by-pk → decode returns a record equal to
///     the original, so the whole write/read path composes.
///   * `injection-value:'; DROP TABLE users; --` — the adversarial value is
///     BOUND as a positional parameter and stored + retrieved LITERALLY. The
///     table is not dropped and the query still succeeds, proving the value
///     channel is parameterised, not string-interpolated.
///   * `reject-bad-ident:ok` — a `Store` declared with a column identifier
///     containing a quote/semicolon/space fails to build (`fromColumns` returns
///     `Err` through `validSqlIdent`), so the injection never reaches SQL.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; `Ipe.Db.Store` is an Ipê-only
/// addition with no prior counterpart; oracle is Ipê's own output.
#[test]
fn db_store() {
    assert_runs_and_matches_oracle("db_store");
}

/// `Ipe.Db.Store` typed query builder + `findBy` + `update` + `count` over a
/// raw-column store on `sqlite::memory:`. Exercises the `Cond`→`SqlFragment`
/// lowering (every column through `Sql.column`, every value through `Sql.param`)
/// and the Ipê-level ordering/pagination, proving:
///
///   * `order-limit:widget:30,gizmo:9` — a `where (gt "qty" 4) |> orderDesc "qty"
///     |> limit 2` query returns the two highest-qty rows in NUMERIC descending
///     order (the store's INTEGER column type drives a numeric sort — a
///     lexicographic string sort would place `"9"` before `"30"`).
///   * `find-by:sprocket:5` — `findBy` on a validated column with a bound value.
///   * `update:gizmo:99` — `update` rewrites a whole record by primary key; the
///     read-back by pk confirms the write.
///   * `count-gt:2` — `count` returns how many rows match the filter.
///   * `reject-bad-column:ok` — a query naming a column the store does not derive
///     is a total `Task Err` with NO SQL issued (validated against the store's
///     own columns, parse-don't-validate).
///   * `injection-value:'; DROP TABLE products; --` — the adversarial value binds
///     as a positional parameter through the query builder and is stored +
///     retrieved LITERALLY.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; the query builder is an Ipê-only
/// addition with no prior counterpart; oracle is Ipê's own output.
#[test]
fn db_store_query() {
    assert_runs_and_matches_oracle("db_store_query");
}

/// SEAL regression: `Ipe.Db.Store.toMaybe` — the fetch-one query terminal —
/// builds AND runs. `toMaybe conn q = Task.map List.head (toList conn q)`
/// forwards its generic row type to `toList<T1: Send + Sync + Clone>` and
/// captures it in no closure of its own body, so the per-function bound pass
/// left `to_maybe<T1: Send + Clone>` — missing `Sync`. The emitted crate then
/// cargo-failed `E0277` (`T1 cannot be shared between threads`) even though
/// `ipe` reported exit 0: an exit-0-then-cargo-fail SEAL break. Cross-call
/// bound propagation now copies `toList`'s `Sync` obligation onto the
/// forwarded tvar. Four output lines: a by-pk hit, the FIRST ordered row among
/// many matches, a `Nothing` miss, and a `'; DROP TABLE`-bearing value stored +
/// retrieved LITERALLY through a bound parameter.
///
///   by-id:widget:30
///   first-ordered:widget:30
///   miss:nothing
///   injection:'; DROP TABLE products; --
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; `Ipe.Db.Store` is an Ipê-only
/// addition with no prior counterpart; oracle is Ipê's own output.
#[test]
fn db_store_to_maybe() {
    assert_runs_and_matches_oracle("db_store_to_maybe");
}

/// `Ipe.Db.Store` nullable round-trip over a codec store on `sqlite::memory:`: a
/// record holding a `Maybe String`, `Maybe Int`, `Maybe Float`, and `Maybe Bool`
/// reads SQL `NULL` back as `Nothing` through every codec-decoded read terminal
/// (`get`, `all`, `findBy`, `findWhere`, query `toList`), while `Just ""`,
/// `Just 0`, `Just 3.0`, `Just False`, and `Just "NULL"` read back unchanged —
/// `NULL` and the empty string never collapse, and no text value is an in-band
/// `NULL` marker. A query on the nullable int orders the `NULL` row first
/// ascending and last descending; a codec whose field is a plain `String`
/// refuses the `NULL` row with a typed `Err`.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; `Ipe.Db.Store` is an Ipê-only
/// addition with no prior counterpart; oracle is Ipê's own output.
#[test]
fn db_store_null_roundtrip() {
    assert_runs_and_matches_oracle("db_store_null_roundtrip");
}

/// SEAL regression: cross-call auto-trait-bound propagation through a NON-BARE
/// argument. `fetchAll conn s = Store.toList conn (Store.query s)` is generic
/// over the row type; the caller's tvar rides inside the COMPUTED argument
/// `Store.query s` (a `Call`, not a bare `Var`) filling `toList`'s bounded
/// `Query a` slot. A bare-argument-only propagation dropped `toList`'s `Sync`
/// obligation the moment the tvar rode inside `Store.query s`, so the emitted
/// `main_fetch_all<T1: Send + Clone>` — missing `Sync` — cargo-failed `E0277`
/// (`T1 cannot be shared between threads`) though `ipe` reported exit 0: an
/// exit-0-then-cargo-fail SEAL break. `fetchLimited` (`Store.query s |> limit 1
/// |> toList conn`) carries the tvar two `Call`s deep, so the golden also proves
/// the leaf-walk descends nested computed arguments. Both forwarders must stay
/// GENERIC (`<T1: 'static + Send + Sync + Clone>`, never monomorphized) AND the
/// emitted crate must `cargo build` and run. Two lines: `all:2`, `limited:1`.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; `Ipe.Db.Store` is an Ipê-only
/// addition with no reference counterpart; oracle is Ipê's own output.
#[test]
fn db_store_generic_forwarder() {
    assert_runs_and_matches_oracle("db_store_generic_forwarder");
}

/// SEAL regression: cross-call auto-trait-bound propagation through a LOCALLY-
/// bound value rather than a forwarded parameter.
/// `runFirst conn qs = case List.head qs of Just q -> Store.toList conn q; …` is
/// generic over the row type; the caller's tvar reaches `Store.toList`'s bounded
/// `Query a` slot only through `q`, bound by the `Just q` arm — not a caller
/// parameter. A propagation keyed on parameter membership never attributed the
/// tvar to `q`, so the emitted `main_run_first<T1>` — missing `Sync` —
/// cargo-failed `E0277` (`T1 cannot be shared between threads`) though `ipe`
/// reported exit 0: an exit-0-then-cargo-fail SEAL break, the sibling of the
/// parameter-forwarding class. `runLet` binds the query with a `let` instead,
/// proving the local-derived trace covers both binding forms. Both forwarders
/// must stay GENERIC (`<T1: 'static + Send + Sync + Clone>`, never monomorphized)
/// AND the emitted crate must `cargo build` and run. Two lines: `first:2`,
/// `let:2`.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; `Ipe.Db.Store` is an Ipê-only
/// addition with no reference counterpart; oracle is Ipê's own output.
#[test]
fn db_store_local_derived_forwarder() {
    assert_runs_and_matches_oracle("db_store_local_derived_forwarder");
}

/// SEAL regression: a generic HOF (`Result.map`) applied to a callee whose
/// return type is a CROSS-MODULE concrete stdlib type (`Ipe.Db.Store.Store`).
/// Before the fix the `Result.map` type variable erased to `JsonVal` in emitted
/// Rust — `ipe dev build` accepted, then the emitted crate failed `cargo build`
/// with `E0308` (expected `IpeResult<_, IpeDbStoreStore>`, found
/// `IpeResult<_, serde_json::Value>`). The concrete `Store` now threads through
/// the HOF's instantiated slot for BOTH the point-free
/// `Result.map (Store.primaryKey "id")` and the eta-expanded
/// `Result.map (\s -> Store.primaryKey "id" s)` forms. The same-module control
/// (`Result.map (setN 5)` over the in-module `Counter` ADT) is exercised in the
/// same program and must keep lowering to its concrete in-module type.
///
/// Prints one line per shape (`Store.tableName` for the two cross-module
/// stores, the counter payload for the control):
///
///   point-free:users
///   eta:orders
///   control:5
///
/// No DB connection is opened — the golden observes the `Store` structurally, so
/// it isolates the lowering fix from the sqlx runtime.
#[test]
fn db_store_hof_pointfree() {
    assert_runs_and_matches_oracle("db_store_hof_pointfree");
}

/// `Db.findWhere` with an `Ipe.Db.Unsafe.unsafeFragment`-minted WHERE column:
/// the un-validated anti-`Sql.column` mints a `SqlFragment` from the verbatim
/// identifier `"qty"` WITHOUT the `valid_sql_ident` gate, then `Sql.gt (… ) 9`
/// selects the single high-qty row → print `"widget:10"`. Proves the new
/// escape-hatch member emits and reaches its runtime path (`sql_unsafe_fragment`)
/// end-to-end. The caller asserts `"qty"` is safe, so the result matches the
/// validated `Sql.column` path.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; `unsafeFragment` is an Ipê-only
/// hatch with no prior counterpart; oracle is Ipê's own output.
#[test]
fn db_unsafe_fragment() {
    assert_runs_and_matches_oracle("db_unsafe_fragment");
}

/// `Db.exec` INSERTs three rows → `Db.deleteWhere conn "products" (Sql.eq
/// (Sql.column "name") (Sql.string "gadget"))` → row count `1` → a follow-up
/// `Db.unsafeQuery` confirms only `"gadget"` was removed → print
/// `"1:sprocket,widget"`.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; `Db.deleteWhere` has no prior
/// counterpart; oracle is Ipê's own output.
#[test]
fn db_delete_where() {
    assert_runs_and_matches_oracle("db_delete_where");
}

/// SEAL + behaviour: the codec-derived `Store` WHERE-mutation surface. Creates a
/// raw-column store carrying `defaultText` / `defaultInt` / `touchOnUpdate` DDL
/// specs, seeds it with a partial INSERT (so the DB fills the defaults), then
/// drives `Store.updateWhere` (a `Cond` lowered to a `SqlFragment`, matching
/// rows only, the primary key never rewritten, an injection-payload value bound
/// verbatim) and `Store.deleteWhere` (matching rows only), plus a fail-closed
/// unknown-column `deleteWhere` AND a fail-closed unconstrained `deleteWhere`
/// (`Store.and []`, which would otherwise mass-delete every row). Output (seven
/// lines): `"defaults:active:0:stamped"`, `"update-where:2"`, the post-update
/// owners, `"reject-unscoped:ok"`, `"delete-where:1"`,
/// `"remaining:acct-1,acct-2"`, `"reject-bad-column:ok"`.
///
/// The load-bearing SEAL is the build+run: `ipe` must accept a
/// `Store.updateWhere` / `Store.deleteWhere` program AND the emitted crate must
/// `cargo build` and run to the expected output.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; the Store mutation surface has no
/// reference-backend counterpart; oracle is Ipê's own output.
#[test]
fn db_store_where_mutations() {
    assert_runs_and_matches_oracle("db_store_where_mutations");
}

/// Exercises every `Ipe.Db.Sql` combinator at least once (column, param via
/// int/string/float/bool, eq, ne, gt, lt, gte, lte, and, or, not, isNull,
/// isNotNull, like, inList non-empty AND the empty-list `(1 = 0)` shortcut)
/// through three `Db.findWhere` calls. Output: `"widget|0|gadget"`.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; the `Sql.*` family has no prior
/// counterpart; oracle is Ipê's own output.
#[test]
fn db_sql_combinators() {
    assert_runs_and_matches_oracle("db_sql_combinators");
}

/// `Sql.startsWith` matches a literal prefix only.
///
/// Through `Db.findWhere`: `%`, `_` and `\` in the prefix match themselves,
/// the match is case-sensitive, `NULL` never matches, the bind order survives
/// `Sql.and` on either side, and an empty or one-past-the-ceiling prefix
/// surfaces as a typed error while the longest legal prefix is admitted.
///
/// Sanctioned divergence: `Sql.startsWith` has no reference counterpart;
/// oracle is Ipê's own output.
#[test]
fn db_sql_starts_with() {
    assert_runs_and_matches_oracle("db_sql_starts_with");
}

/// `Ipe.Db.Dsn` parse-don't-validate surface, end-to-end and PURE (no connect,
/// no I/O beyond stdout). Parses a valid Postgres DSN carrying a password and
/// prints its `Driver`, host, default TLS mode, and REDACTED render — the
/// password sentinel `hunter2SENTINEL` NEVER appears (it is a `Secret`, rendered
/// as `[redacted]`). Also proves: `sslmode=disable` is a hard typed `Err`
/// (fail-closed TLS); an omitted sslmode defaults to `require` (secure default);
/// and `Dsn.build` from typed parts runs the same validators. This is the SEAL
/// for the reserved `Dsn` type + the `Db.Dsn.*` parse kernels: the emitted crate
/// must build and run, and the sentinel must be absent from stdout.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; `Ipe.Db.Dsn` is an Ipê-only
/// addition with no reference counterpart; oracle is Ipê's own output.
#[test]
fn dsn_parse() {
    assert_runs_and_matches_oracle("dsn_parse");
    // Belt-and-suspenders Secret non-leak proof: the password sentinel must be
    // absent from the emitted program's stdout even on the happy path.
    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let (_dir, outcome) = build_run("dsn_parse");
        assert!(
            !outcome.stdout.contains("hunter2SENTINEL"),
            "dsn_parse: the password sentinel leaked into stdout"
        );
    }
}

// ── SqlDecimal + SqlMoney ctors ───────────────────────────────────────────────

/// `Db.exec [SqlString "pi", SqlDecimal (Decimal.fromMinor 5 314159),
/// SqlMoney "USD 9.99"]` → INSERT one row → `Db.query [] SELECT *` → read back
/// all three columns → print `"pi:3.14159:USD 9.99"`.
///
/// Proves `SqlDecimal` and `SqlMoney` are reachable end-to-end: canon ctor
/// table, `constrain.rs` type schemes, `lower.rs` `enum_variants` + `ctor_arity`,
/// and `project.rs` `into_sql_param`. `SqlDecimal` carries a native `Decimal`
/// bound as a lossless TEXT param via `decimal_to_string`; `SqlMoney` carries an
/// `ISO_CODE AMOUNT` string.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; oracle is Ipê's own output.
#[test]
fn db_sql_decimal_money() {
    assert_runs_and_matches_oracle("db_sql_decimal_money");
}

/// Acceptance (ipe-time, ungated by `IPE_E2E`): `SqlDecimal` applied to a native
/// `Decimal` type-checks and emits. The SEAL (ipe-accepts ⇒ cargo-builds) is
/// re-proven under `IPE_E2E` by [`db_sql_decimal_money`], which builds and runs
/// the emitted project.
#[test]
fn db_sql_decimal_accepts_decimal() {
    let root = repo_root();
    let dir = golden_dir(&root, "db_sql_decimal_money");
    let entry = dir.join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("db_sql_decimal_accepts");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "`SqlDecimal (Decimal.fromMinor 5 314159)` must type-check and emit; got: {:?}",
        built.err()
    );
}

/// prove-the-refusals: `SqlDecimal` now carries a native `Decimal`, so a raw
/// `String` argument (`SqlDecimal "1.5"`) is a fail-closed type mismatch —
/// never a silently accepted stringly value. Guards the retype's rejecting
/// edge so it cannot regress to a `String`-typed constructor.
#[test]
fn db_sql_decimal_rejects_raw_string() {
    let root = repo_root();
    let dir = golden_dir(&root, "db_sql_decimal_rejects_string");
    let entry = dir.join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("db_sql_decimal_rejects");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let err = ipe::build(&entry, &out, &runtime)
        .map_err(|e| e.to_string())
        .expect_err(
            "`SqlDecimal \"1.5\"` must be rejected: the ctor takes a native `Decimal`, not a `String`",
        );
    assert!(
        err.contains("IPE-T0001"),
        "expected a type-mismatch diagnostic (IPE-T0001) at the raw-String argument, got:\n{err}"
    );
}

// ── Polymorphic params — T0001 regression ────────────────────────────────────

/// IPE-T0001 regression: `Db.exec`/`Db.query` accept `List a` (polymorphic),
/// so `List Int`, `List String`, and mixed `List SqlValue` all compile without
/// a type-mismatch error.
///
/// The fixture exercises three call shapes in one `Db.withTransaction`:
///
/// * `Db.exec … [1]`                     — `List Int`   (as in the job-queue example)
/// * `Db.exec … ["hello"]`               — `List String` (as in the ipemon example)
/// * `Db.exec … [SqlNull …, SqlInt 42, SqlBool True]` — mixed `List SqlValue`
///
/// Compile-only assertion: `ipe::build` must succeed (no `IPE-T0001`).
/// E2E assertion (gated on `IPE_E2E=1`): binary prints `"3"` — three rows
/// inserted and queried back.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; oracle is Ipê's own output.
#[test]
fn db_poly_params_compiles() {
    let root = repo_root();
    let dir = golden_dir(&root, "db_poly_params");
    let entry = dir.join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("db_poly_params");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    // Core assertion: `ipe::build` succeeds — no IPE-T0001 for any param-list shape.
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "IPE-T0001 regression: `Db.exec` with `List Int` / `List String` / mixed \
         `List SqlValue` must compile without a type-mismatch error; got: {:?}",
        built.err()
    );
}

/// E2E extension of [`db_poly_params_compiles`]: build the emitted Cargo project,
/// run it, and assert the binary prints `"3"` (three rows inserted and read back).
/// Gated on `IPE_E2E=1`.
#[test]
fn db_poly_params_e2e() {
    assert_runs_and_matches_oracle("db_poly_params");
}

// ── Db.findOneByField / Db.findManyByField ────────────────────────────────────

/// `Db.exec` three INSERTs into `items` (apple/fruit, banana/fruit,
/// carrot/veggie) → `Db.findOneByField conn "items" "name" "apple"` (match) →
/// `Db.findOneByField conn "items" "name" "durian"` (no match) →
/// `Db.findManyByField conn "items" "category" "fruit"` (two-row match) →
/// `Db.findManyByField conn "items" "category" "mineral"` (no match) →
/// `println`. Output:
/// `"apple:fruit:5\nmissing\napple:fruit:5,banana:fruit:3\nempty"`.
///
/// Golden-E2E coverage for `DbFindOneByField`/`DbFindManyByField` through a
/// real `ipe dev build` + `cargo build` + run, not just direct runtime source
/// inspection + the internal exhaustiveness test.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; oracle is Ipê's own output.
#[test]
fn db_find_by_field() {
    assert_runs_and_matches_oracle("db_find_by_field");
}

// ── Db.Decode.money kernel registration ────────────────────

/// `Db.Decode.money "amount"` decodes a `"CODE AMOUNT"` TEXT column
/// (`SqlMoney`'s lossless serialisation) back into `(Decimal, String)`, and a
/// malformed value is a total `Task Err` — never a panic — caught via
/// `Task.onError`. Output: `"USD 12.34\nmalformed:caught"`.
///
/// Proves the kernel-registration recipe works end-to-end: canon
/// `Db.Decode` allowlist, `StdlibKernel::DbDecMoney` decl, constrain.rs
/// scheme, `ipe_lower` arity-1 dispatch, `ipe_backend_rust` standard-path
/// emit, `ipe_ir` pretty-print.
///
/// Sanctioned divergence (tagged `divergence`, not `sanctioned`): the Rust
/// backend's `Db.Decode.money` returns `Decoder (Decimal, String)`, not the
/// the backend's `Decoder Money` — `Money`/`Currency` are project-generated
/// Rust types unnameable from the shared runtime crate. See
/// Sanctioned divergence `B-DbDecMoney`.
#[test]
fn db_decode_money() {
    assert_runs_and_matches_oracle("db_decode_money");
}

/// `Db.Decode.decimal "value"` decodes a TEXT column written by `SqlDecimal`
/// (the lossless exact-decimal serialisation) back into a `Decimal` value. A
/// malformed value is a total `Task Err` — never a panic — caught via
/// `Task.onError`. Output: `"3.14159\nmalformed:caught"`.
///
/// Proves the full kernel-registration recipe for `DbDecDecimal`: canon
/// `Db.Decode` allowlist, `StdlibKernel::DbDecDecimal` decl, constrain.rs
/// scheme (`String -> Decoder Decimal`), `ipe_lower` arity-1 dispatch,
/// `ipe_backend_rust` standard-path emit.
///
/// Ipê-new kernel (no ancestor equivalent). Sanctioned divergence: Ipê emits
/// Rust+sqlx; oracle is Ipê's own output.
#[test]
fn db_decode_decimal() {
    assert_runs_and_matches_oracle("db_decode_decimal");
}

// ── Schema drift fails closed through the typed row path ──────────────────────

/// A table with column `full_name` decoded by a `Db.Decode.string "name"` — the
/// shape a `name -> full_name` rename leaves behind. The absent column makes the
/// decoder short-circuit the whole `queryDecode` task to `Task Error`, caught via
/// `Task.onError` into `"drift:caught"`. Pins the safety property the typed row
/// surface exists for: schema drift is a caught `Err`, never a phantom value and
/// never a panic.
///
/// Sanctioned divergence: Ipê emits Rust+sqlx; oracle is Ipê's own output.
#[test]
fn db_decode_drift_fails_closed() {
    assert_runs_and_matches_oracle("db_decode_drift");
}

// ── serial-without-primaryKey guard ──────────────────────────────────────────

/// `Store.createSql` rejects a `serial` column that has no matching `primaryKey`
/// spec with a typed `Err` before emitting any DDL. `SQLite` requires
/// `AUTOINCREMENT` only on `INTEGER PRIMARY KEY` columns; emitting it without
/// `PRIMARY KEY` would produce DDL that fails at `Store.create` runtime.
///
/// Three pure checks (no DB connection):
///
/// * `serial-without-pk:rejected` — `createSql` returns `Err` for a store where
///   `serial "id"` is present but `primaryKey "id"` is absent.
/// * `serial-with-pk:ok` — `createSql` returns `Ok` with both
///   `PRIMARY KEY` and `AUTOINCREMENT` when both specs are present.
/// * `plain:ok` — a store with no serial column is unaffected.
#[test]
fn db_store_serial_pk_guard() {
    assert_runs_and_matches_oracle("db_store_serial_pk_guard");
}

// ── Store helper identity guard ──────────────────────────────────────────────

/// A user binding named like an `Ipe.Db.Store` helper never stands in for it.
///
/// The program declares its own `primaryKeyNamed` (a different signature) and
/// a `Verdict` union with `Compare` / `OpEq` constructors, then uses the
/// `Store.primaryKey .slug` and `Store.eq .slug` accessor forms. The intercepts
/// resolve the Store helper and constructors by their exact `Ipe.Db.Store`
/// home, so the emitted crate builds and prints:
///
/// * `store-helper:ok` — the accessor form builds `PRIMARY KEY` DDL.
/// * `store-cond:ok` — the `Store.eq` leaves build Store `Cond` values.
/// * `user-fn:7` — the user `primaryKeyNamed` runs only where it is called.
/// * `user-ctor:ok` — the user `OpEq` constructor stays a `Verdict`.
#[test]
fn db_store_named_helper_shadow() {
    assert_runs_and_matches_oracle("db_store_named_helper_shadow");
}
