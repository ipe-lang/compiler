//! `{{expr}}` interpolation and `Log.*With` attributes admit exactly the closed
//! scalar set `String` / `Int` / `Float` / `Bool` / `Char`.
//!
//! Every other type — a request, a record, a custom type, a `Maybe`, a `List`,
//! a `Secret`, a `Pii` — is refused at `ipe` time with IPE-T0014, never
//! accepted and left to a `cargo` E0277 or a `Debug` rendering that could leak
//! a secret or print a `HashMap` in nondeterministic order. The acceptance case
//! pins the five scalars, and the table test pins the type-side set to the
//! runtime's sealed `IpeInterpolate` impl set.
//!
//! Compile-only: a refused program has nothing to run.

use std::path::PathBuf;

const HEAD: &str = "module Main exposing (main)\n\nimport Ipe.Io as Io\n";

/// Run the `ipe` pipeline (no `cargo`) on `src` written as a fresh `Main.ipe`.
///
/// `Ok(())` on acceptance, or `Err` carrying the pipeline diagnostic's code
/// (`None` for any other failure). The runtime must resolve: a missing runtime
/// fails the test rather than passing it vacuously.
fn build_source(name: &str, src: &str) -> Result<(), Option<ipe_diagnostics::Code>> {
    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let dir = scratch.join(format!("interp_scalars_{name}"));
    let out = scratch.join(format!("interp_scalars_{name}_out"));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&out);
    assert!(
        std::fs::create_dir_all(&dir).is_ok(),
        "{name}: scratch dir must be creatable"
    );
    let entry = dir.join("Main.ipe");
    assert!(
        std::fs::write(&entry, src).is_ok(),
        "{name}: fixture must be writable"
    );
    let runtime = e2e_support::require_runtime().into_path_buf();
    match ipe::build(&entry, &out, &runtime) {
        Ok(()) => Ok(()),
        Err(ipe::CliError::Pipeline { diag, .. }) => Err(Some(diag.code())),
        Err(_) => Err(None),
    }
}

/// Assert `src` is refused as not interpolable (IPE-T0014).
fn assert_refused(name: &str, src: &str) {
    assert_eq!(
        build_source(name, src),
        Err(Some(ipe_diagnostics::IPE_T0014)),
        "{name}: interpolating a non-scalar must be refused with IPE-T0014"
    );
}

#[test]
fn interpolating_a_request_is_refused() {
    let src = format!(
        "{HEAD}import Ipe.Http.Server as Server\n\
         import Ipe.Http.Server exposing (Request, Response)\n\
         import Ipe.Task as Task\n\n\
         handle : Request -> Task Error Response\n\
         handle req =\n    Task.succeed (Server.html \"\"\"<p>{{{{req}}}}</p>\"\"\")\n\n\
         main =\n    Io.println \"x\"\n"
    );
    assert_refused("request", &src);
}

#[test]
fn interpolating_a_record_is_refused() {
    let src = format!(
        "{HEAD}\npoint =\n    {{ x = 1, y = 2 }}\n\n\
         main =\n    Io.println \"\"\"at {{{{point}}}}\"\"\"\n"
    );
    assert_refused("record", &src);
}

#[test]
fn interpolating_a_maybe_int_is_refused() {
    let src = format!(
        "{HEAD}\nm =\n    Just 1\n\n\
         main =\n    Io.println \"\"\"m={{{{m}}}}\"\"\"\n"
    );
    assert_refused("maybe_int", &src);
}

#[test]
fn interpolating_a_list_of_strings_is_refused() {
    let src = format!(
        "{HEAD}\nnames =\n    [ \"a\", \"b\" ]\n\n\
         main =\n    Io.println \"\"\"names={{{{names}}}}\"\"\"\n"
    );
    assert_refused("list_string", &src);
}

#[test]
fn interpolating_a_custom_type_is_refused() {
    let src = format!(
        "{HEAD}\ntype Shape\n    = Circle Int\n    | Empty\n\n\
         shape =\n    Circle 5\n\n\
         main =\n    Io.println \"\"\"shape={{{{shape}}}}\"\"\"\n"
    );
    assert_refused("custom_type", &src);
}

#[test]
fn interpolating_pii_is_refused() {
    let src = format!(
        "{HEAD}import Ipe.Analytics as Analytics\n\n\
         p =\n    Analytics.pii \"alice@example.com\"\n\n\
         main =\n    Io.println \"\"\"p={{{{p}}}}\"\"\"\n"
    );
    assert_refused("pii", &src);
}

#[test]
fn logging_a_record_attribute_is_refused() {
    let src = format!(
        "{HEAD}import Ipe.Log as Log\n\n\
         main : Task Error ()\n\
         main =\n    Log.infoWith \"boot\" [ {{ x = 1 }} ]\n"
    );
    assert_refused("log_record", &src);
}

#[test]
fn logging_a_secret_attribute_is_refused() {
    let src = format!(
        "{HEAD}import Ipe.Log as Log\nimport Ipe.Secret as Secret\n\n\
         main : Task Error ()\n\
         main =\n    Log.infoWith \"boot\" [ Secret.fromString \"sk_live_x\" ]\n"
    );
    assert_refused("log_secret", &src);
}

/// A generic that interpolates its argument passes the obligation to its
/// caller: using it at a record is refused exactly as a direct `{{record}}`.
#[test]
fn interpolating_generic_used_at_a_record_is_refused() {
    let src = format!(
        "{HEAD}\ndescribe : a -> String\ndescribe x =\n    \"\"\"<{{{{x}}}}>\"\"\"\n\n\
         main =\n    Io.println (describe {{ x = 1 }})\n"
    );
    assert_refused("generic_record", &src);
}

#[test]
fn interpolating_unit_is_refused() {
    let src = format!(
        "{HEAD}\nu =\n    ()\n\n\
         main =\n    Io.println \"\"\"u={{{{u}}}}\"\"\"\n"
    );
    assert_refused("unit", &src);
}

#[test]
fn interpolating_a_tuple_is_refused() {
    let src = format!(
        "{HEAD}\npair =\n    ( 1, \"a\" )\n\n\
         main =\n    Io.println \"\"\"pair={{{{pair}}}}\"\"\"\n"
    );
    assert_refused("tuple", &src);
}

#[test]
fn interpolating_a_dict_is_refused() {
    let src = format!(
        "{HEAD}import Ipe.Dict as Dict\n\n\
         d =\n    Dict.singleton \"k\" 1\n\n\
         main =\n    Io.println \"\"\"d={{{{d}}}}\"\"\"\n"
    );
    assert_refused("dict", &src);
}

#[test]
fn interpolating_a_secret_is_refused() {
    let src = format!(
        "{HEAD}import Ipe.Secret as Secret\n\n\
         key =\n    Secret.fromString \"sk_live_x\"\n\n\
         main =\n    Io.println \"\"\"key={{{{key}}}}\"\"\"\n"
    );
    assert_refused("secret", &src);
}

#[test]
fn interpolating_a_function_is_refused() {
    let src = format!(
        "{HEAD}\ninc : Int -> Int\ninc n =\n    n + 1\n\n\
         main =\n    Io.println \"\"\"f={{{{inc}}}}\"\"\"\n"
    );
    assert_refused("function", &src);
}

/// A wildcard-`any` parameter carries the obligation like a named variable:
/// calling the function at a record is refused, never emitted as an
/// `IpeInterpolate`-bounded generic that `cargo` then rejects.
#[test]
fn interpolating_an_any_parameter_used_at_a_record_is_refused() {
    let src = format!(
        "{HEAD}\nrender : any -> String\nrender x =\n    \"\"\"<{{{{x}}}}>\"\"\"\n\n\
         main =\n    Io.println (render {{ x = 1 }})\n"
    );
    assert_refused("any_record", &src);
}

/// An interpolating generic called from another generic leaves the obligation
/// on a variable no concrete type pins: refused (fail-closed), even though the
/// outer caller passes an `Int`.
#[test]
fn interpolation_obligation_escaping_into_an_enclosing_generic_is_refused() {
    let src = format!(
        "{HEAD}\ninner : a -> String\ninner x =\n    \"\"\"<{{{{x}}}}>\"\"\"\n\n\
         outer : b -> String\nouter y =\n    inner y\n\n\
         main =\n    Io.println (outer 1)\n"
    );
    assert_refused("escaping_generic", &src);
}

/// A generic `Log.*With` attribute element carries the obligation to the
/// caller: logging a record through it is refused.
#[test]
fn logging_a_generic_attribute_used_at_a_record_is_refused() {
    let src = format!(
        "{HEAD}import Ipe.Log as Log\n\n\
         logIt : a -> Task Error ()\nlogIt v =\n    Log.infoWith \"boot\" [ v ]\n\n\
         main : Task Error ()\n\
         main =\n    logIt {{ x = 1 }}\n"
    );
    assert_refused("log_generic_record", &src);
}

/// An unannotated binding whose parameter is only pinned by a later use (here
/// to a `List`) is checked against that final type.
#[test]
fn interpolating_a_late_pinned_list_is_refused() {
    let src = format!(
        "{HEAD}\nshow xs =\n    \"\"\"<{{{{xs}}}}>\"\"\"\n\n\
         main =\n    Io.println (show [ 1, 2 ])\n"
    );
    assert_refused("late_list", &src);
}

/// All five scalars interpolate, directly and as `Log.*With` attributes.
#[test]
fn interpolating_each_scalar_is_accepted() {
    let src = format!(
        "{HEAD}import Ipe.Log as Log\nimport Ipe.Task as Task\n\n\
         s =\n    \"text\"\n\nn =\n    1\n\nf =\n    1.5\n\nb =\n    True\n\nc =\n    'x'\n\n\
         main : Task Error ()\n\
         main =\n    Io.println \"\"\"{{{{s}}}} {{{{n}}}} {{{{f}}}} {{{{b}}}} {{{{c}}}}\"\"\"\n\
         \x20       |> Task.andThen (\\_ -> Log.infoWith \"ints\" [ n, 2 ])\n\
         \x20       |> Task.andThen (\\_ -> Log.infoWith \"chars\" [ c ])\n"
    );
    assert_eq!(
        build_source("scalars", &src),
        Ok(()),
        "String, Int, Float, Bool and Char must all interpolate and log"
    );
}

/// The type checker's interpolable set and the runtime's sealed
/// `IpeInterpolate` impl set are the same five types, in the same order.
#[test]
fn interpolable_set_matches_the_runtime_impl_set() {
    assert_eq!(
        ipe_diagnostics::INTERPOLABLE_TYPES,
        ipe_runtime_rust::stringify::INTERPOLABLE_IPE_TYPES
    );
}
