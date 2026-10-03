//! `Store.insertIfAbsent`: the first write of a key wins.
//!
//! The `db_store_insert_if_absent_guard` golden drives the refusals (a store
//! with no primary key and no `unique` column, a key the database fills) and
//! the accepted shape (a composite key: the first insert of a key affects one
//! row, a second insert of that key affects none and leaves the stored row
//! unchanged, a key differing in one column is inserted) against a live
//! `sqlite::memory:` database, one oracle line each. Passing a `Draft` or a
//! `Secured` store never reaches the runtime: each is an ipe-time `IPE-T0001`,
//! so `insertIfAbsent` can bypass neither deny-by-default nor a row policy.
//!
//! ```text
//! # ipe-time refusals only (fast):
//! cargo test -p ipe --test g_db golden_db_store_insert_if_absent
//! # full (cargo build + run the golden):
//! IPE_E2E=1 cargo test -p ipe --test g_db golden_db_store_insert_if_absent
//! ```

use ipe::CliError;

use crate::support::repo_root;

const GOLDEN: &str = "db_store_insert_if_absent_guard";

/// Build and run the `db_store_insert_if_absent_guard` golden under
/// `IPE_E2E=1`, asserting its stdout matches the oracle.
///
/// Every refusal line is pinned on Store's own message naming
/// `insertIfAbsent`, and the refusal stores are never created, so a refusal
/// that reached SQL surfaces as a missing-table error and the line goes red.
#[test]
fn insert_if_absent_matches_oracle() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let dir = root.join("tests").join("golden").join(GOLDEN);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "build failed for {GOLDEN}: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted(GOLDEN, &out);
    crate::support::assert_go_parity(GOLDEN, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

/// One program whose only variable is the store `save` hands to
/// `Store.insertIfAbsent`: `TARGET` is replaced by `store` (a `Store Doc`),
/// `draft` (a `Draft Doc`) or `secured` (a `Secured Doc`). Each refusal is
/// paired with the `store` control, so a fixture that failed for an unrelated
/// reason cannot pass as a refusal.
const INSERT_IF_ABSENT_TEMPLATE: &str = r#"module Main exposing (main)

import Ipe.Codec as Codec
import Ipe.Db as Db exposing (Db)
import Ipe.Db.Store as Store exposing (Draft, Secured, Store)
import Ipe.Error exposing (Error)
import Ipe.Io as Io
import Ipe.Result as Result exposing (Result(..))
import Ipe.String as String
import Ipe.Task as Task exposing (Task)


type alias Doc =
    { author : String
    , body : String
    }


blankDoc : Doc
blankDoc =
    { author = "", body = "" }


docDraft : Result Error (Draft Doc)
docDraft =
    Result.map (\d -> Store.primaryKey .author d) (Store.fromCodec "docs" (Codec.auto blankDoc))


save : Db -> Draft Doc -> Store Doc -> Secured Doc -> Task Error Int
save conn draft store secured =
    Store.insertIfAbsent conn TARGET { author = "a", body = "b" }


main : Task Error ()
main =
    case docDraft of
        Ok draft ->
            case Store.secured (Store.ownerColumn .author) draft of
                Ok secured ->
                    Task.andThen
                        (\conn ->
                            Task.andThen
                                (\n -> Io.println (String.fromInt n))
                                (save conn draft (Store.public draft) secured)
                        )
                        (Db.open "sqlite" "sqlite::memory:")

                Err _ ->
                    Io.println "secured failed"

        Err _ ->
            Io.println "build failed"
"#;

/// Build the template with `target` in place of `TARGET`, under scratch `name`.
fn build_with_target(name: &str, target: &str) -> Result<(), CliError> {
    let dir = crate::support::scratch_root().join(name);
    let _ = std::fs::remove_dir_all(&dir);
    let src = dir.join("src");
    crate::support::expect_scratch_step(name, std::fs::create_dir_all(&src));
    let entry = src.join("Main.ipe");
    let source = INSERT_IF_ABSENT_TEMPLATE.replace("TARGET", target);
    crate::support::expect_scratch_step(name, std::fs::write(&entry, source));
    let out = crate::support::scratch_root().join(format!("{name}_out"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, &out, &runtime)
}

/// Assert the `store` control builds and `target` is rejected with `IPE-T0001`.
fn assert_target_rejected(name: &str, target: &str, why: &str) {
    let control = build_with_target(&format!("{name}_control"), "store");
    assert!(
        control.is_ok(),
        "{name}: the `Store.insertIfAbsent` control on a `Store` MUST build, so \
         the refusal below is caused by the store kind alone; got: {control:?}"
    );

    let built = build_with_target(name, target);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0001),
        "{why} MUST be rejected with IPE-T0001; got: {built:?}"
    );
}

/// `Store.insertIfAbsent` on an unclassified `Draft` MUST be an ipe-time type
/// mismatch: it cannot write a table nobody classified (deny-by-default).
#[test]
fn insert_if_absent_on_draft_is_rejected() {
    assert_target_rejected(
        "ipec_db_store_insert_if_absent_draft_rejected",
        "draft",
        "`Store.insertIfAbsent` on an unclassified `Draft`",
    );
}

/// `Store.insertIfAbsent` on a `Secured` store MUST be an ipe-time type
/// mismatch: a policy-guarded table is written only through the authenticated
/// `…As` operations, so it cannot bypass its row policy.
#[test]
fn insert_if_absent_on_secured_is_rejected() {
    assert_target_rejected(
        "ipec_db_store_insert_if_absent_secured_rejected",
        "secured",
        "`Store.insertIfAbsent` on a `Secured` store",
    );
}
