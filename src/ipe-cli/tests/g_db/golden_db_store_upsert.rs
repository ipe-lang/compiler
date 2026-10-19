//! `Store.upsert`: a conflict target derived from the store's declared key.
//!
//! The `db_store_upsert` golden drives every runtime refusal (no key, several
//! `unique` columns, an illegal key declaration, an unknown or invalid target
//! column, a DB-filled key, a `NULL` key) and every accepted shape (single,
//! composite, `unique`-column and renamed key) against a live
//! `sqlite::memory:` database, one oracle line each. Passing a `Draft` or a
//! `Secured` store never reaches the runtime: each is an ipe-time `IPE-T0001`,
//! so an upsert can bypass neither deny-by-default nor a row policy.
//!
//! ```text
//! # ipe-time refusals only (fast):
//! cargo test -p ipe --test g_db golden_db_store_upsert
//! # full (cargo build + run the golden):
//! IPE_E2E=1 cargo test -p ipe --test g_db golden_db_store_upsert
//! ```

use ipe::CliError;

use crate::support::repo_root;

const GOLDEN: &str = "db_store_upsert";

/// Build and run the `db_store_upsert` golden under `IPE_E2E=1`, asserting its
/// stdout matches the oracle.
///
/// Every refusal line is pinned on Store's own message, so removing a Store
/// guard surfaces the kernel's refusal or a success instead and the line goes
/// red; the row counts read before and after the refusals prove none of them
/// wrote. Under `IPE_E2E=1` the emitted project is built and run, so `ipe`
/// accepting `Store.upsert` is proven to `cargo build`.
#[test]
fn upsert_matches_oracle() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let dir = root.join("tests").join("golden").join(GOLDEN);
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&dir, &out, &runtime);
    assert!(
        built.is_ok(),
        "build failed for {GOLDEN}: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted(GOLDEN, &out);
    crate::support::assert_go_parity(GOLDEN, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

/// One program whose only variable is the store `save` hands to `Store.upsert`:
/// `TARGET` is replaced by `store` (a `Store Doc`), `draft` (a `Draft Doc`) or
/// `secured` (a `Secured Doc`). Each refusal is paired with the `store` control,
/// so a fixture that failed for an unrelated reason cannot pass as a refusal.
const UPSERT_TEMPLATE: &str = r#"module Main exposing (main)

import Ipe.Codec as Codec
import Ipe.Db as Db exposing (Db)
import Ipe.Db.Location as Location
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
    Store.upsert conn TARGET { author = "a", body = "b" }


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
                        (Db.open Location.memory)

                Err _ ->
                    Io.println "secured failed"

        Err _ ->
            Io.println "build failed"
"#;

/// Build the template with `target` in place of `TARGET`, under scratch `name`.
fn build_with_target(name: &str, target: &str) -> Result<(), CliError> {
    let source = UPSERT_TEMPLATE.replace("TARGET", target);
    #[allow(clippy::expect_used)] // a fixture-setup failure must fail the test loudly
    let fixture = ipe::RootFixture::main(&source).expect("the fixture project resolves");
    let out = crate::support::scratch_root().join(format!("{name}_out"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build_fixture(&fixture, &out, &runtime).map(drop)
}

/// Assert the `store` control builds and `target` is rejected with `IPE-T0001`.
fn assert_target_rejected(name: &str, target: &str, why: &str) {
    let control = build_with_target(&format!("{name}_control"), "store");
    assert!(
        control.is_ok(),
        "{name}: the `Store.upsert` control on a `Store` MUST build, so the \
         refusal below is caused by the store kind alone; got: {control:?}"
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

/// `Store.upsert` on an unclassified `Draft` MUST be an ipe-time type mismatch:
/// an upsert cannot write a table nobody classified (deny-by-default).
#[test]
fn upsert_on_draft_is_rejected() {
    assert_target_rejected(
        "ipec_db_store_upsert_draft_rejected",
        "draft",
        "`Store.upsert` on an unclassified `Draft`",
    );
}

/// `Store.upsert` on a `Secured` store MUST be an ipe-time type mismatch: a
/// policy-guarded table is written only through the authenticated `…As`
/// operations, so an upsert cannot bypass its row policy.
#[test]
fn upsert_on_secured_is_rejected() {
    assert_target_rejected(
        "ipec_db_store_upsert_secured_rejected",
        "secured",
        "`Store.upsert` on a `Secured` store",
    );
}
