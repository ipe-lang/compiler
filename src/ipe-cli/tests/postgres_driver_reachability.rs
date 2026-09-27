//! `package.ipe`'s `build = { database = Postgres }` must actually change
//! what gets emitted rather than being a silent no-op: the driver choice threads
//! through to `ipe_backend_rust::project::emit_program`'s template selection
//! instead of the sqlite `config.rs` template being written unconditionally.
//!
//! No live Postgres needed: this only proves the STRUCTURAL wiring —
//! manifest → `RustBackend::with_db_driver` → `EmitCtx::db_driver` →
//! `emit_program`'s config.rs/Cargo.toml selection — actually threads the
//! driver choice through to the emitted project's files. `crates/ipe/src/project.rs`'s
//! `mod tests` covers the manifest-parsing half in isolation;
//! `crates/ipe_backend_rust/src/project.rs`'s `mod tests` covers the
//! `db_cargo_toml` / template-selection half in isolation. This test proves
//! the two halves are actually wired together end-to-end through
//! `ipe::build_project`.

use std::fs;
use std::path::PathBuf;

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    ipe::resolve_runtime().expect("runtime must resolve for this test")
}

/// Minimal Db-kernel-using Ipê program — enough to set `EmitCtx::uses_db =
/// true` (any `Db.*` call site does), nothing more. Never built/run (no
/// `IPE_E2E` gate here) — this test only inspects the EMITTED files, not
/// runtime behaviour (which needs a live Postgres and is out of scope for the
/// default `cargo test` gate per the Class 7 spec's two-tier test strategy).
const MAIN_IPE: &str = "\
module Main exposing (main)
import Ipe.Db
import Ipe.Db.Unsafe
import Ipe.Task

main =
    Task.andThen
        (\\conn ->
            Unsafe.unsafeExecRaw conn \"CREATE TABLE t (id INTEGER)\"
        )
        (Db.open \"sqlite\" \"sqlite::memory:\")
";

/// Write a minimal project (`package.ipe` + `src/Main.ipe`) under a fresh temp
/// dir, with the given record-field fragment spliced into the `package` record
/// verbatim (empty string → no extra field at all, i.e. the default driver).
#[allow(clippy::expect_used)]
fn write_project(test_name: &str, database_stage: &str) -> PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ipec_pg_reachability_{test_name}"));
    let _ = fs::remove_dir_all(&dir);
    let src = dir.join("src");
    fs::create_dir_all(&src).expect("create src/");
    fs::write(src.join("Main.ipe"), MAIN_IPE).expect("write Main.ipe");
    fs::write(
        dir.join("package.ipe"),
        format!(
            "module Package exposing (package)\n\nimport Ipe.Package exposing (..)\n\n\npackage : Package\npackage =\n    {{ name = \"pgtest\"{database_stage} }}\n"
        ),
    )
    .expect("write package.ipe");
    dir
}

/// `build = { database = Postgres }` in `package.ipe` must cause the
/// emitted `src/ipe_runtime/config.rs` to declare `sqlx::postgres::PgPool` /
/// `PgRow` and `DB_USES_RETURNING_ID: bool = true` — NOT the sqlite template.
#[test]
fn postgres_driver_selects_postgres_config_template() {
    let dir = write_project("postgres_select", ", build = { database = Postgres }");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("pg_reachability_postgres_select");
    let _ = fs::remove_dir_all(&out);

    let built = ipe::build_project(&dir.join("package.ipe"), &out, &runtime());
    assert!(
        built.is_ok(),
        "build_project must succeed for a postgres-driver db-using project: {:?}",
        built.err()
    );

    // Under the default dependency model the DB driver aliases (`PgPool`/`PgRow`
    // vs `SqlitePool`/`SqliteRow`, and the `DB_USES_RETURNING_ID` constant) live
    // inside the runtime crate, selected by the `db-postgres` / `db-sqlite`
    // feature — no `config.rs` is vendored into the user crate. The structural
    // wiring this test guards is therefore the FEATURE the emitted manifest
    // selects: `driver = "postgres"` must put `db-postgres` in the runtime
    // dependency's feature list.
    let cargo_toml =
        fs::read_to_string(out.join("Cargo.toml")).expect("emitted Cargo.toml must exist");
    assert!(
        cargo_toml.contains("package = \"ipe-runtime-rust\""),
        "the emitted manifest must declare the runtime as a path dependency:\n{cargo_toml}"
    );
    assert!(
        cargo_toml.contains("\"db-postgres\""),
        "driver = \"postgres\" must select the runtime `db-postgres` feature (which \
         pulls both the postgres AND sqlite sqlx drivers — the always-emitted \
         telemetry_spill / web::hub / web::store runtime modules hardcode \
         SqlitePool independently of the app's driver choice):\n{cargo_toml}"
    );
    assert!(
        !cargo_toml.contains("\"db-sqlite\""),
        "driver = \"postgres\" must NOT also select db-sqlite (the driver features \
         are mutually exclusive; db-postgres already implies sqlx/sqlite):\n{cargo_toml}"
    );

    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&out);
}

/// `IPE_E2E` tier: the emitted Postgres-driver project must actually
/// `cargo build` (isolated target dir) — proves the seal (ipe exit 0
/// implies cargo build exit 0) for the whole Postgres codegen path, not just
/// the config.rs/Cargo.toml source-text assertions above. This is the check
/// that catches a SEAL violation where an exclusive
/// sqlite-vs-postgres sqlx feature selection compiles fine as SOURCE TEXT
/// but fails `cargo build` because always-emitted runtime modules unrelated
/// to the `[database]` driver hardcode `SqlitePool` — source-text greps
/// alone cannot catch a missing Cargo feature dependency.
#[test]
fn postgres_driver_project_cargo_builds() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let dir = write_project("postgres_cargo_build", ", build = { database = Postgres }");
    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("pg_reachability_postgres_cargo_build");
    let _ = fs::remove_dir_all(&out);

    let built = ipe::build_project(&dir.join("package.ipe"), &out, &runtime());
    assert!(
        built.is_ok(),
        "build_project must succeed for a postgres-driver db-using project: {:?}",
        built.err()
    );

    // Forward the warm shared target (IPE_ORACLE_SHARED_TARGET in CI, else an
    // ambient CARGO_TARGET_DIR a local lane set); fall back to an isolated
    // scratch dir so a bare local run stays hermetic.
    let target = e2e_support::child_shared_target_from_env().map_or_else(
        || {
            std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
                .join("r_class7")
                .join("postgres_driver_cargo_build")
        },
        PathBuf::from,
    );
    #[allow(clippy::expect_used)]
    let check_output = std::process::Command::new("cargo")
        .arg("check")
        .env("CARGO_TARGET_DIR", &target)
        .current_dir(&out)
        .output()
        .expect("cargo must spawn");
    assert!(
        check_output.status.success(),
        "emitted driver=\"postgres\" project must cargo-check clean \
         (no live Postgres connection needed for `cargo check`)\n\
         --- cargo stderr ---\n{}",
        String::from_utf8_lossy(&check_output.stderr),
    );

    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&out);
}

/// Non-regression: a project with NO `[database]` section (or an explicit
/// `driver = "sqlite"`) must still emit the sqlite `config.rs` template —
/// this feature is additive, so every existing sqlite-driver project's
/// emitted output is unaffected.
#[test]
fn no_database_section_still_selects_sqlite_config_template() {
    let dir = write_project("sqlite_default", "");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("pg_reachability_sqlite_default");
    let _ = fs::remove_dir_all(&out);

    let built = ipe::build_project(&dir.join("package.ipe"), &out, &runtime());
    assert!(
        built.is_ok(),
        "build_project must succeed for the default (no [database] section) project: {:?}",
        built.err()
    );

    // Dep-model expression of the default: no vendored config.rs; the sqlite
    // driver is selected via the runtime `db-sqlite` feature.
    let cargo_toml =
        fs::read_to_string(out.join("Cargo.toml")).expect("emitted Cargo.toml must exist");
    assert!(
        cargo_toml.contains("\"db-sqlite\""),
        "no [database] section must default to the runtime `db-sqlite` feature:\n{cargo_toml}"
    );
    assert!(
        !cargo_toml.contains("\"db-postgres\""),
        "the sqlite default must NOT select db-postgres:\n{cargo_toml}"
    );

    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&out);
}
