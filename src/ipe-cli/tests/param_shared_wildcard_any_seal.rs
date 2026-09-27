//! A wildcard `any` in PARAMETER position that the body THREADS into an `any`
//! return (`thread : any -> any; thread x = x`) must not emit a generic
//! parameter beside a concrete return. The checker unifies the two independent
//! `any` occurrences through the body, so the parameter's solved type is the
//! single call-site-pinned concrete type; emitting the parameter as a generic
//! `T{n}` while the return is that concrete type makes the body return the
//! generic where the concrete is expected (E0308) — an accept-then-`cargo`-fail
//! (THE SEAL). A wildcard `any` has ONE concrete lowering per position: the
//! threaded parameter concretizes to the same type as the return.
//!
//! The positive cases route through [`support::assert_seal_builds`] so the SEAL
//! claim is backed by an actual `cargo build` under `IPE_E2E=1`.

mod support;

use std::fs;
use std::path::{Path, PathBuf};

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    ipe::resolve_runtime().expect("runtime must resolve for this test")
}

#[allow(clippy::expect_used)]
fn write_entry(test_name: &str, main_ipe: &str) -> PathBuf {
    let dir = crate::support::scratch_root().join(format!("ipe_param_any_seal_{test_name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create source dir");
    let entry = dir.join("Main.ipe");
    fs::write(&entry, main_ipe).expect("write Main.ipe");
    entry
}

#[allow(clippy::expect_used)]
fn emit(entry: &Path, test_name: &str) -> (Result<(), ipe::CliError>, PathBuf) {
    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("param_any_seal_{test_name}"));
    let _ = fs::remove_dir_all(&out);
    // The single-entry path emits a crate named `ipe-app`, the anchor
    // `support::assert_seal_builds` retargets under `IPE_E2E=1`.
    let result = ipe::build(entry, &out, &runtime());
    (result, out)
}

/// The repro: `thread : any -> any` threaded through the body, called at one
/// concrete type. `ipe` accepts it AND the emitted crate builds — the parameter
/// concretizes to the return's type (`fn(x: String) -> String`), never a generic
/// `T{n}` returned where `String` is expected.
#[test]
fn threaded_param_any_concretizes_and_builds() {
    let entry = write_entry(
        "threaded",
        "\
module Main exposing (main)
import Ipe.Io as Io

thread : any -> any
thread x = x

main : Task Error ()
main = Io.println (thread \"hi\")
",
    );
    let (built, out) = emit(&entry, "threaded");
    assert!(
        built.is_ok(),
        "`thread : any -> any; thread x = x` called at a concrete type must be \
         accepted (ipe-accept): {:?}",
        built.err()
    );
    let emitted = support::read_all_emitted_src(&out);
    assert!(
        emitted.contains("fn main_thread(x: String) -> String"),
        "the threaded parameter must concretize to the return type \
         (`fn main_thread(x: String) -> String`), never a generic beside a \
         concrete return:\n{emitted}"
    );
    support::assert_seal_builds("param_any_seal_threaded", &out);
    if let Some(parent) = entry.parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

/// A parameter `any` the body does NOT thread into the `any` return
/// (`constFn x = "hi"`) leaves its region a bare solver var — it stays a generic
/// `T{n}`, which is sound because the parameter never flows into the concrete
/// return. This proves the fix distinguishes threading from non-threading rather
/// than blanket-rejecting or blanket-concretizing every param-any + return-any.
#[test]
fn unthreaded_param_any_stays_generic_and_builds() {
    let entry = write_entry(
        "unthreaded",
        "\
module Main exposing (main)
import Ipe.Io as Io

constFn : any -> any
constFn x = \"hi\"

main : Task Error ()
main = Io.println (constFn \"yo\")
",
    );
    let (built, out) = emit(&entry, "unthreaded");
    assert!(
        built.is_ok(),
        "`constFn : any -> any; constFn x = \"hi\"` must be accepted (the param is \
         not threaded into the return): {:?}",
        built.err()
    );
    let emitted = support::read_all_emitted_src(&out);
    assert!(
        emitted.contains("fn main_const_fn<T1: Clone>(x: T1) -> String"),
        "an unthreaded parameter `any` stays generic (`fn main_const_fn<T1>(x: T1) \
         -> String`):\n{emitted}"
    );
    support::assert_seal_builds("param_any_seal_unthreaded", &out);
    if let Some(parent) = entry.parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

/// A genuine NAMED type variable threaded through the body (`id2 : a -> a`) is
/// rank-1 polymorphism, not a wildcard — it must stay generic (`fn id2<T>(x: T)
/// -> T`), never be concretized by the param-`any` substitution (which keys on
/// the minted `any` symbols, not a named variable).
#[test]
fn named_type_var_stays_generic_and_builds() {
    let entry = write_entry(
        "namedvar",
        "\
module Main exposing (main)
import Ipe.Io as Io

id2 : a -> a
id2 x = x

main : Task Error ()
main = Io.println (id2 \"hey\")
",
    );
    let (built, out) = emit(&entry, "namedvar");
    assert!(
        built.is_ok(),
        "`id2 : a -> a; id2 x = x` is genuine rank-1 polymorphism and must be \
         accepted: {:?}",
        built.err()
    );
    let emitted = support::read_all_emitted_src(&out);
    assert!(
        emitted.contains("fn main_id2<T1: Clone>(x: T1) -> T1"),
        "a named type variable stays generic (`fn main_id2<T1>(x: T1) -> T1`):\n{emitted}"
    );
    support::assert_seal_builds("param_any_seal_namedvar", &out);
    if let Some(parent) = entry.parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

/// Calling a threaded `any -> any` at two DIFFERENT concrete types is a type
/// error at `ipe` time, not an accept-then-`cargo`-fail: the body-threaded
/// unification forces ONE concrete type, so a second differing call site cannot
/// unify. One concrete lowering per wildcard position, exactly as `any` requires.
#[test]
fn threaded_param_any_at_two_types_is_rejected() {
    let entry = write_entry(
        "two_types",
        "\
module Main exposing (main)
import Ipe.Io as Io
import Ipe.String as String

thread : any -> any
thread x = x

main : Task Error ()
main = Io.println (String.concat (thread \"hi\") (thread (String.fromInt 3)))
",
    );
    let (built, _out) = emit(&entry, "two_types");
    assert!(
        built.is_err(),
        "a threaded `any -> any` used at two different concrete types must be an \
         `ipe`-time type error (one concrete lowering), never an accept-then-cargo-fail"
    );
    if let Some(parent) = entry.parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

/// A wildcard-`any` parameter that the body BOTH reads via a `Db.get*` ROW
/// accessor AND returns, with signature `any -> any`. The parameter's correct
/// lowering is the `<R: IpeRow>` bounded generic — it must NOT concretize to the
/// row carrier. The return, threaded from that same parameter, must FOLLOW the
/// parameter's bounded generic, never an independently-concretized carrier
/// (`HashMap<String, String>`) that diverges from it — the E0308 that was an
/// accept-then-`cargo`-fail (THE SEAL).
#[test]
fn row_accessor_param_threaded_to_return_builds() {
    let entry = write_entry(
        "row_thread",
        "\
module Main exposing (main)
import Ipe.Dict as Dict
import Ipe.Db.Unsafe
import Ipe.Io as Io

thread : any -> any
thread payload =
  let
    name = Unsafe.unsafeGetString \"name\" payload
  in
  payload

main : Task Error ()
main =
  let
    p = Dict.fromList [ ( \"name\", \"ada\" ) ]
    r = thread p
  in
  Io.println (Unsafe.unsafeGetString \"name\" r)
",
    );
    let (built, out) = emit(&entry, "row_thread");
    assert!(
        built.is_ok(),
        "a row-accessor param threaded into an `any` return must be accepted \
         (the return follows the param's `<R: IpeRow>` generic): {:?}",
        built.err()
    );
    let emitted = support::read_all_emitted_src(&out);
    assert!(
        emitted.contains("fn main_thread<T1: Clone + ipe_runtime::db::IpeRow>(payload: T1) -> T1"),
        "the return must follow the row-accessor param's bounded generic \
         (`fn main_thread<T1: … + IpeRow>(payload: T1) -> T1`), never the \
         independently-concretized row carrier:\n{emitted}"
    );
    support::assert_seal_builds("param_any_seal_row_thread", &out);
    if let Some(parent) = entry.parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

/// A record threaded through a wildcard-`any` `any -> any` (`useIt p = p`,
/// called on a full record). The parameter's solved region is a STRUCTURAL
/// record — narrowed to only the fields the body reads — which is NOT the same
/// identity as the caller's full nominal record. Concretizing the parameter to
/// that narrowed record makes the caller's full record mismatch (E0308,
/// accept-then-`cargo`-fail). The parameter must stay a generic `T{n}` so it
/// monomorphises to the caller's own record, and the return must follow it.
#[test]
fn record_threaded_through_any_builds() {
    let entry = write_entry(
        "record_thread",
        "\
module Main exposing (main)
import Ipe.Io as Io

type alias Person =
  { name : String
  , age : Int
  }

useIt : any -> any
useIt p = p

main : Task Error ()
main =
  let
    person = { name = \"ada\", age = 3 }
    r = useIt person
  in
  Io.println r.name
",
    );
    let (built, out) = emit(&entry, "record_thread");
    assert!(
        built.is_ok(),
        "a record threaded through `any -> any` must be accepted (the param \
         stays generic, the return follows it): {:?}",
        built.err()
    );
    let emitted = support::read_all_emitted_src(&out);
    assert!(
        emitted.contains("fn main_use_it<T1: Clone>(p: T1) -> T1"),
        "a record threaded through `any -> any` keeps the param generic and the \
         return follows it (`fn main_use_it<T1: Clone>(p: T1) -> T1`), never a \
         narrowed structural record that a full-record caller mismatches:\n{emitted}"
    );
    support::assert_seal_builds("param_any_seal_record_thread", &out);
    if let Some(parent) = entry.parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

/// A record param the body BOTH threads to an `any` return AND directly
/// field-reads cannot stay a bare generic (`p.name` on a bare `T{n}` is
/// `E0609 no field`). It erases to a row generic bounded by one witness trait
/// per read field, so it accepts the caller's own record and the threaded
/// return follows it. It must build.
#[test]
fn record_threaded_and_field_read_builds() {
    let entry = write_entry(
        "record_thread_read",
        "\
module Main exposing (main)
import Ipe.Io as Io

tag : any -> any
tag p =
    let n = p.name in
    p

main : Task Error ()
main =
  let
    u = { name = \"alice\" }
    v = tag u
  in
  Io.println v.name
",
    );
    let (built, out) = emit(&entry, "record_thread_read");
    assert!(
        built.is_ok(),
        "a record param the body threads AND field-reads must be accepted and \
         concretized (a bare generic has no field to read): {:?}",
        built.err()
    );
    support::assert_seal_builds("param_any_seal_record_thread_read", &out);
    if let Some(parent) = entry.parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

/// A wildcard-`any` parameter used ONLY via direct field access, called with a
/// record carrying MORE fields than the body reads. The parameter's solved
/// region narrows to just the read field (`{name}`); concretizing to that
/// narrowed nominal record makes the wider caller record (`{name, age}`)
/// mismatch (E0308, accept-then-`cargo`-fail — THE SEAL). The parameter must
/// erase to a witness-bounded row generic (`<R: IpeHasName<Name = String> +
/// Clone>`) that rustc monomorphises to the caller's own record, so the wider
/// record satisfies the witness and builds.
#[test]
fn field_read_param_accepts_wider_caller_record() {
    let entry = write_entry(
        "field_read_wider",
        "\
module Main exposing (main)
import Ipe.Io as Io

getName : any -> String
getName p =
    p.name

main : Task Error ()
main =
    let
        u = { name = \"ada\", age = 3 }
    in
    Io.println (getName u)
",
    );
    let (built, out) = emit(&entry, "field_read_wider");
    assert!(
        built.is_ok(),
        "a field-read `any` param must accept a caller record wider than the \
         read fields (the param erases to a row generic): {:?}",
        built.err()
    );
    let emitted = support::read_all_emitted_src(&out);
    assert!(
        emitted
            .contains("fn main_get_name<R1: IpeHasName<Name = String> + Clone>(p: R1) -> String"),
        "a field-read `any` param erases to a witness-bounded row generic that \
         monomorphises to the caller's own record, never a narrowed structural \
         record a wider caller mismatches:\n{emitted}"
    );
    support::assert_seal_builds("param_any_seal_field_read_wider", &out);
    if let Some(parent) = entry.parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

/// The same field-read `any` param called with a record carrying EXACTLY the
/// read fields (`{name}`) still builds — the row-generic erasure is a superset
/// of the exact-match case, so no shape is regressed.
#[test]
fn field_read_param_accepts_exact_caller_record() {
    let entry = write_entry(
        "field_read_exact",
        "\
module Main exposing (main)
import Ipe.Io as Io

getName : any -> String
getName p =
    p.name

main : Task Error ()
main =
    let
        u = { name = \"ada\" }
    in
    Io.println (getName u)
",
    );
    let (built, out) = emit(&entry, "field_read_exact");
    assert!(
        built.is_ok(),
        "a field-read `any` param must still accept a caller record of exactly \
         the read fields: {:?}",
        built.err()
    );
    support::assert_seal_builds("param_any_seal_field_read_exact", &out);
    if let Some(parent) = entry.parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

/// A wildcard-`any` parameter RELAYED straight into a callee that reads it as a
/// field (`relay x = getField x`), then `relay` called at a concrete record.
/// `relay`'s own body never field-reads `x`, so `x` stays a bare `T{n}: Clone`
/// generic — but `getField` requires an `IpeHasName` witness bound the bare
/// generic cannot satisfy. Emitting that Rust fails cargo E0277
/// (accept-then-`cargo`-fail — THE SEAL). The relay must be rejected at `ipe`
/// time (IPE-L0131), never emitted. Instantiating `relay` at a concrete type is
/// essential: the unsatisfiable bound only surfaces once rustc monomorphises.
#[test]
fn any_param_relayed_into_row_callee_is_rejected() {
    let entry = write_entry(
        "relay_row_callee",
        "\
module Main exposing (main)
import Ipe.Io as Io

getField : any -> String
getField p =
    p.name

relay : any -> String
relay x =
    getField x

main : Task Error ()
main =
    Io.println (relay { name = \"Ada\" })
",
    );
    let (built, _out) = emit(&entry, "relay_row_callee");
    assert!(
        built.is_err(),
        "an `any` param relayed into a field-reading callee cannot satisfy the \
         callee's row-witness bound and must be rejected at `ipe` time, never \
         emitted as Rust that fails cargo E0277"
    );
    if let Some(parent) = entry.parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

/// A wildcard-`any` parameter passed as a CALL ARGUMENT to a field-reading
/// callee (`firstName p = snd p p` where `snd a b = a.name`), then `firstName`
/// called at a concrete record. `p` stays a bare generic in `firstName` and
/// flows into `snd`'s `IpeHasName`-bounded slot — the emitted Rust fails cargo
/// E0277. Must be rejected at `ipe` time (IPE-L0131). The call site forces
/// monomorphisation, which is where the unsatisfiable bound would otherwise
/// surface.
#[test]
fn any_param_in_call_arg_position_is_rejected_when_called() {
    let entry = write_entry(
        "callarg_row_callee",
        "\
module Main exposing (main)
import Ipe.Io as Io

snd : any -> any -> String
snd a b =
    a.name

firstName : any -> String
firstName p =
    snd p p

main : Task Error ()
main =
    Io.println (firstName { name = \"Ada\" })
",
    );
    let (built, _out) = emit(&entry, "callarg_row_callee");
    assert!(
        built.is_err(),
        "an `any` param in call-arg position of a field-reading callee cannot \
         satisfy the callee's row-witness bound and must be rejected at `ipe` \
         time, never emitted as Rust that fails cargo E0277"
    );
    if let Some(parent) = entry.parent() {
        let _ = fs::remove_dir_all(parent);
    }
}
