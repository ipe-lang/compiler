//! The stringly row-read surface is `Ipe.Db.Unsafe.unsafeQuery` /
//! `unsafeGetField` / `unsafeGetString` / `unsafeGetInt` / `unsafeGetBool`, and
//! neither the old unmarked names nor the relocated `Db.unsafe*` off a plain
//! `import Ipe.Db` exist. This pins the schema-drift property that the
//! silently-coercing row readers are only reachable through the lexically-marked
//! `unsafe` names in the disclosed `Ipe.Db.Unsafe` submodule — a caller cannot
//! fall into a `"" `/`0`-on-drift read by using an unmarked default, nor without
//! disclosing the `unsafe` capability. The typed `Db.queryDecode` +
//! `Db.Decode.*` path (which a missing/renamed column fails closed on) is the
//! unmarked row-read default and stays in `Ipe.Db`.
//!
//! The guarantee is checked on BOTH resolution routes:
//!
//! * the surface qualifier (`Unsafe.unsafeGetField` off `import Ipe.Db.Unsafe`,
//!   and — for the relocation — `Db.unsafeGetField` off plain `Ipe.Db` failing),
//!   and
//! * the `Kernel.kernel "Db_unsafeGetField"` string-alias route. Minting a kernel
//!   alias is the exclusive privilege of the driver-vouched standard library /
//!   FFI interface: a `Kernel.kernel "…"` binding in USER source is rejected by the
//!   origin gate (IPE-N0042) before the registry is even consulted. So the
//!   string-alias route cannot smuggle a user program to the marked kernel at
//!   all — the only path to the unsafe row read stays the disclosed
//!   `Ipe.Db.Unsafe` surface. This closes the capability-model bypass whereby a
//!   user `Kernel.kernel` alias reached an unsafe kernel with no `unsafe`
//!   disclosure.

use std::fs;
use std::path::{Path, PathBuf};

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    e2e_support::require_runtime().into_path_buf()
}

#[allow(clippy::expect_used)]
fn write_project(test_name: &str, main_ipe: &str) -> PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ipe_db_row_marker_{test_name}"));
    let _ = fs::remove_dir_all(&dir);
    let src = dir.join("src");
    fs::create_dir_all(&src).expect("create src/");
    fs::write(src.join("Main.ipe"), main_ipe).expect("write Main.ipe");
    fs::write(
        dir.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"dbrowmarker\" }\n",
    )
    .expect("write package.ipe");
    dir
}

fn build(dir: &Path, test_name: &str) -> Result<(), ipe::CliError> {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("db_row_marker_{test_name}"));
    let _ = fs::remove_dir_all(&out);
    ipe::build_project(&dir.join("package.ipe"), &out, &runtime())
}

// ── Direct-qualifier route ────────────────────────────────────────────────────

/// `Ipe.Db.Unsafe.unsafeGetField` is the marked stringly row accessor — it
/// type-checks when imported from its `.Unsafe` submodule (the untyped
/// convenience stays available for genuinely dynamic reads).
#[test]
fn marked_get_field_type_checks() {
    let dir = write_project(
        "marked",
        "\
module Main exposing (main)
import Ipe.Db.Unsafe
import Ipe.Dict as Dict
import Ipe.Io as Io

main =
    let
        row =
            Dict.fromList [ ( \"name\", \"ada\" ) ]
    in
    Io.println (Unsafe.unsafeGetField \"name\" row)
",
    );
    let built = build(&dir, "marked");
    assert!(
        built.is_ok(),
        "Ipe.Db.Unsafe.unsafeGetField must type-check as the marked stringly accessor: {:?}",
        built.err()
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The relocated `unsafeGetField` no longer resolves off a plain `import Ipe.Db`:
/// the untyped row-read surface LEFT `Ipe.Db` for `Ipe.Db.Unsafe`, so reaching
/// it without importing the disclosed `.Unsafe` submodule is a compile error.
#[test]
fn relocated_get_field_off_plain_db_no_longer_compiles() {
    let dir = write_project(
        "relocated_direct",
        "\
module Main exposing (main)
import Ipe.Db
import Ipe.Dict as Dict
import Ipe.Io as Io

main =
    let
        row =
            Dict.fromList [ ( \"name\", \"ada\" ) ]
    in
    Io.println (Db.unsafeGetField \"name\" row)
",
    );
    let built = build(&dir, "relocated_direct");
    assert!(
        built.is_err(),
        "Db.unsafeGetField off a plain `import Ipe.Db` must NOT compile — the \
         untyped row-read surface relocated to the disclosed `Ipe.Db.Unsafe` submodule"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The old unmarked `Db.getField` name is gone: reaching the silently-coercing
/// row read without typing `unsafe` is a compile error, so the drift-prone
/// default is unreachable through the direct qualifier.
#[test]
fn unmarked_get_field_no_longer_compiles() {
    let dir = write_project(
        "unmarked_direct",
        "\
module Main exposing (main)
import Ipe.Db
import Ipe.Dict as Dict
import Ipe.Io as Io

main =
    let
        row =
            Dict.fromList [ ( \"name\", \"ada\" ) ]
    in
    Io.println (Db.getField \"name\" row)
",
    );
    let built = build(&dir, "unmarked_direct");
    assert!(
        built.is_err(),
        "the unmarked Db.getField name must NOT compile — the stringly row read \
         may only be reached through the marked Db.unsafeGetField"
    );
    let _ = fs::remove_dir_all(&dir);
}

// ── Kernel.kernel string-alias route ─────────────────────────────────────────────

/// A USER program cannot mint the marked kernel through a `Kernel.kernel
/// "Db_unsafeGetField"` alias — minting a kernel is reserved to the vouched
/// standard library / FFI interface, so the alias is rejected by the origin gate
/// (IPE-N0042) regardless of whether the named kernel is registered. The unsafe
/// row read is reachable ONLY through the disclosed `Ipe.Db.Unsafe` surface,
/// never a hand-minted alias that would reach it with no `unsafe` disclosure.
#[test]
fn user_kernel_alias_to_marked_kernel_is_rejected() {
    let dir = write_project(
        "marked_alias",
        "\
module Main exposing (main)
import Ipe.Ffi.Kernel as Kernel
import Ipe.Dict as Dict
import Ipe.Io as Io

getField : String -> Dict String String -> String
getField =
    Kernel.kernel \"Db_unsafeGetField\"

main =
    let
        row =
            Dict.fromList [ ( \"name\", \"ada\" ) ]
    in
    Io.println (getField \"name\" row)
",
    );
    let built = build(&dir, "marked_alias");
    let is_user_alias = matches!(
        &built,
        Err(ipe::CliError::Pipeline { diag, .. })
            if matches!(
                &**diag,
                ipe_diagnostics::Diagnostic::Name {
                    msg: ipe_diagnostics::NameError::KernelAliasInUserSource { .. },
                    ..
                }
            )
    );
    assert!(
        is_user_alias,
        "Kernel.kernel \"Db_unsafeGetField\" in user source must be rejected with \
         IPE-N0042 — a user program may not mint a kernel alias: {built:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A user `Kernel.kernel "Db_getField"` alias is likewise rejected by the origin
/// gate. The gate fires on the alias SHAPE in user source, before the registry
/// is consulted, so the rejection is IPE-N0042 (user source may not mint a
/// kernel) rather than IPE-N0028 (unknown kernel) — either way the smuggled row
/// read is unrepresentable.
#[test]
fn user_kernel_alias_to_unmarked_kernel_is_rejected() {
    let dir = write_project(
        "unmarked_alias",
        "\
module Main exposing (main)
import Ipe.Ffi.Kernel as Kernel
import Ipe.Dict as Dict
import Ipe.Io as Io

getField : String -> Dict String String -> String
getField =
    Kernel.kernel \"Db_getField\"

main =
    let
        row =
            Dict.fromList [ ( \"name\", \"ada\" ) ]
    in
    Io.println (getField \"name\" row)
",
    );
    let built = build(&dir, "unmarked_alias");
    let is_user_alias = matches!(
        &built,
        Err(ipe::CliError::Pipeline { diag, .. })
            if matches!(
                &**diag,
                ipe_diagnostics::Diagnostic::Name {
                    msg: ipe_diagnostics::NameError::KernelAliasInUserSource { .. },
                    ..
                }
            )
    );
    assert!(
        is_user_alias,
        "Kernel.kernel \"Db_getField\" in user source must be rejected with IPE-N0042 — \
         a user program may not mint a kernel alias: {built:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}
