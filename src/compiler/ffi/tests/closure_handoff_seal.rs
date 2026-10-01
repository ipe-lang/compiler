//! SEAL fixture for the closure→run HANDOFF.
//!
//! The `closure_adapter_seal` fixture proves the emitted adapter turns an Ipê
//! function value into a boxed Rust closure. The `define_forwarder_seal` fixture
//! proves `define.struct`/`enum` constructors admit as Ipê forwarders. This
//! fixture proves the missing link between them: a `define.closure` adapter now
//! ADMITS as an arity-1 Ipê forwarder `(Model -> Msg -> Model) -> <Handle>`, the
//! program HOLDS the returned closure as the opaque handle nominal, and hands it
//! to a foreign `run`-style entrypoint that DRIVES a real loop.
//!
//! An `iced::Sandbox::run` proper needs a lifetime/generic `Element<'a, Msg>` in
//! its `view` return, which the bare-handle carrier still refuses (proven by
//! `define_opaque_return_seal`'s over-drop). This fixture uses an owned-return
//! `run(model, update)` shape — the SAME handoff mechanism, with an owned
//! `Model`/`Message` surface — to prove the mechanism end-to-end; the
//! Iced-specific parameterised-opaque residual stays refused there.
//!
//! The interface-admission assertions run in the DEFAULT gate; the cargo build+run
//! proof of the assembled module tree is `IPE_E2E`-gated (it shells out to
//! `cargo`), matching the repo's other SEAL fixtures.
#![allow(clippy::expect_used)] // test setup: a failed decode / scratch-dir op IS the failure

use ipe_ffi::bindings::emit_bindings;
use ipe_ffi::interface::crate_interface;
use ipe_ffi::pkginfo::PkgInfo;

/// A one-crate package with the full TEA counter surface: a `Counter` model
/// (`define.struct`), a `Message` sum (`define.enum`), and an `update_fn`
/// (`define.closure`) whose signature is `Fn(Counter, Message) -> Counter` —
/// the shape a driver hands to a `run(model, update)` loop.
fn counter_app_pkg() -> PkgInfo {
    let doc = serde_json::json!({
        "pkg": "demo", "name": "demo", "version": "0.1.0",
        "functions": [
            {
                "name": "counter_new", "effect": "pure", "isStructCtor": true,
                "structName": "Counter",
                "structFields": [{ "name": "value", "type": "i64" }],
                "structDerives": ["Default", "Clone", "Debug"]
            },
            {
                "name": "message_new", "effect": "pure", "isEnumDef": true,
                "enumName": "Message",
                "enumVariants": [
                    { "name": "Increment", "payload": [] },
                    { "name": "SetValue", "payload": ["i64"] }
                ],
                "enumDerives": ["Clone", "Debug"]
            },
            {
                "name": "update_fn", "effect": "pure", "isClosureAdapter": true,
                "closureSig": "Fn(Counter, Message) -> Result<Counter, Error> + Send + Sync + 'static"
            }
        ],
        "errors": []
    })
    .to_string();
    PkgInfo::decode_json(&doc).expect("counter app surface decodes")
}

/// The interface admits the closure adapter as an arity-1 forwarder whose Ipê
/// signature takes the Ipê `update` FUNCTION value (parenthesised) and returns
/// the opaque handle nominal, and registers that handle as a define type.
/// Default gate — no cargo.
#[test]
fn closure_forwarder_and_handle_nominal_are_admitted() {
    let iface = crate_interface(&counter_app_pkg());

    // The synthesized handle nominal registers as a define-defined type, beside
    // the struct/enum nominals.
    assert!(
        iface.define_types.contains("UpdateFnClosure"),
        "handle nominal must register as a define type:\n{:?}",
        iface.define_types
    );

    let uf = iface.bindings.iter().find(|b| b.ref_name == "update_fn");
    assert!(
        uf.is_some(),
        "update_fn forwarder must be admitted:\n{:?}",
        iface.skipped
    );
    let uf = uf.expect("asserted present just above");
    // Arity 1: the single argument is the Ipê function value. The signature
    // PARENTHESISES that function value so it reads as one higher-order argument,
    // never a wrong-arity `Counter -> Message -> Counter -> UpdateFnClosure`.
    assert_eq!(
        (uf.arity, uf.sig.as_str()),
        (1, "(Counter -> Message -> Counter) -> UpdateFnClosure")
    );

    // The module renders the handle nominal + the forwarder body.
    let src = &iface.source;
    assert!(
        src.contains("\ntype UpdateFnClosure = UpdateFnClosure\n"),
        "{src}"
    );
    assert!(
        src.contains("update_fn : (Counter -> Message -> Counter) -> UpdateFnClosure"),
        "{src}"
    );
    assert!(
        src.contains("update_fn arg0 =\n    Ffi.binding \"demo_update_fn\" arg0"),
        "{src}"
    );
}

/// A closure handle nominal that collides with a define-struct nominal is
/// refused fail-closed WHICHEVER surface declares it second — never renamed,
/// never both emitted (two `UpdateFnClosure` definitions in one module would be
/// an `E0428` the app crate cannot compile, an `ipe`-exit-0 ⇒ cargo-fail breach).
/// Default gate — no cargo.
#[test]
fn a_handle_colliding_with_a_struct_nominal_is_refused_either_order() {
    // A `define.struct` literally named `UpdateFnClosure` — the exact nominal the
    // `update_fn` closure adapter synthesises — plus that adapter. In manifest
    // order the struct is declared FIRST, so it claims the nominal and the closure
    // is refused; the reverse order refuses the struct. Either way, exactly one
    // survives and the module never defines the name twice.
    let doc = serde_json::json!({
        "pkg": "demo", "name": "demo", "version": "0.1.0",
        "functions": [
            {
                "name": "make_thing", "effect": "pure", "isStructCtor": true,
                "structName": "UpdateFnClosure",
                "structFields": [{ "name": "value", "type": "i64" }],
                "structDerives": ["Clone"]
            },
            {
                "name": "update_fn", "effect": "pure", "isClosureAdapter": true,
                "closureSig": "Fn(Int) -> Result<Int, Error> + Send + Sync + 'static"
            }
        ],
        "errors": []
    })
    .to_string();
    let pkg = PkgInfo::decode_json(&doc).expect("collision surface decodes");
    let iface = crate_interface(&pkg);

    // The struct is declared first → it claims the nominal; the closure adapter is
    // refused with a collision reason. Exactly one binding names the nominal.
    let closure_admitted = iface.bindings.iter().any(|b| b.ref_name == "update_fn");
    assert!(
        !closure_admitted,
        "the second surface to claim the nominal must be refused:\n{:?}",
        iface.bindings
    );
    assert!(
        iface
            .skipped
            .iter()
            .any(|s| s.ref_name == "update_fn" && s.reason.contains("collides")),
        "the refusal must record a collision reason:\n{:?}",
        iface.skipped
    );
    // The nominal is registered exactly once (by the winning struct, which —
    // all-identity-carrier and referenced by no other define surface —
    // surfaces as a transparent record).
    assert!(
        iface.transparent_types.contains_key("UpdateFnClosure"),
        "{iface:?}"
    );
    assert!(!iface.define_types.contains("UpdateFnClosure"), "{iface:?}");
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, assemble the app-crate module
/// tree the backend emits and RUN a real counter loop DRIVEN by an Ipê `update`
/// closure handed to a foreign `run(model, update)` entrypoint. Without the
/// admission, `Main.ipe` could name the closure but never pass it onward; with
/// it, the handle flows into `run` and the loop drives.
#[test]
fn closure_driven_loop_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let cargo = ipe_env::var("CARGO").expect("cargo sets CARGO for every test it runs");

    let pkg = counter_app_pkg();
    let bindings = emit_bindings(&pkg);
    let slug = "demo";

    // Mirror `ipe_backend_rust::project` + `ipe-cli::assemble_emit`: `src/ffi.rs`
    // wraps the generated bindings in `pub mod <slug> { … } pub use <slug>::*;`.
    // The emitted region carries the `Counter`/`Message` defs, every constructor
    // forwarder, the `UpdateFnClosure` handle alias, AND the `update_fn` adapter.
    let ffi_rs = format!("pub mod {slug} {{\n{bindings}}}\npub use {slug}::*;\n");

    // The `main` is the driver a `Main.ipe` compiles to: it builds the Ipê
    // `update` function value, adapts it through the forwarder to get the opaque
    // `UpdateFnClosure` handle, and hands that handle to a foreign `run(model,
    // messages, update)` loop — the closure-to-run handoff. The loop calls the
    // held closure once per message; the Ipê logic drives every step.
    let main_rs = format!(
        r#"mod ffi;
use crate::ffi::{slug}::{{Counter, Message, UpdateFnClosure}};

// The runtime glue the emitted `Result` adapter arm references via `use crate::*`
// — `str_err` / `IpeError`. The real runtime crate supplies these; the fixture
// stands them in.
#[derive(Debug)]
pub struct IpeError(String);
pub fn str_err<E: From<String>>(s: &str) -> E {{ s.to_string().into() }}
pub fn ipe_error_from_panic<E: From<String>>(c: &str, _p: Box<dyn std::any::Any + Send>) -> E {{ c.to_string().into() }}
pub fn note_foreign_panic(_c: &str, _p: Box<dyn std::any::Any + Send>) -> String {{ String::new() }}
pub fn note_foreign_error<T: std::fmt::Debug>(_e: T) -> String {{ String::new() }}
pub fn ipe_error_from_foreign<T: std::fmt::Debug, E: From<String>>(_e: T) -> E {{ "external operation failed".to_string().into() }}
impl From<String> for IpeError {{ fn from(s: String) -> Self {{ IpeError(s) }} }}

// A foreign `run`-style entrypoint: it OWNS the handoffed closure handle and
// DRIVES a loop with it — the exact shape `iced::Sandbox::run` / a Bevy system
// registrar has, minus the parameterised-opaque `Element` view (owned-return
// stand-in). It never sees the `Box<dyn Fn>` internals; `UpdateFnClosure` is the
// opaque handle the program held.
fn run(initial: Counter, messages: Vec<Message>, update: UpdateFnClosure) -> Counter {{
    let mut model = initial;
    for msg in messages {{
        // The adapted closure folds the panic in-band to `Err`; a driver treats
        // an `Err` step as a no-op (keep the prior model). The happy path here
        // always yields `Ok`.
        model = match update(model.clone(), msg) {{
            Ok(next) => next,
            Err(_) => model,
        }};
    }}
    model
}}

fn main() {{
    // The Ipê `update` function value: on the app side exactly a
    // `Box<dyn Fn(Counter, Message) -> Result<Counter, IpeError> + Send + Sync
    // + 'static>`. It folds a message into the model — real TEA `update` logic.
    let ipe_update: Box<
        dyn Fn(Counter, Message) -> Result<Counter, IpeError> + Send + Sync + 'static,
    > = Box::new(|c, m| {{
        Ok(match m {{
            Message::Increment => crate::ffi::demo_counter_new(c.value + 1),
            Message::SetValue(v) => crate::ffi::demo_counter_new(v),
        }})
    }});

    // Adapt it through the forwarder -> the opaque `UpdateFnClosure` handle.
    let update_handle: UpdateFnClosure = crate::ffi::demo_update_fn(ipe_update);

    // Construct the model + a message stream via the sibling forwarders, then
    // HAND the handle to `run` — the loop drives on the Ipê closure.
    let model0 = crate::ffi::demo_counter_new(0);
    let messages = vec![
        crate::ffi::demo_message_new_increment(()),   // 0 -> 1
        crate::ffi::demo_message_new_increment(()),   // 1 -> 2
        crate::ffi::demo_message_new_set_value(40), // 2 -> 40
        crate::ffi::demo_message_new_increment(()),   // 40 -> 41
    ];
    let final_model = run(model0, messages, update_handle);

    // 0 -> 1 -> 2 -> 40 -> 41 ; print 42.
    println!("{{}}", final_model.value + 1);
}}
"#
    );

    let dir = ipe_test_temp::temp_root().join(format!(
        "ipe_ffi_closure_handoff_seal_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("mkdir");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"closure_handoff_seal\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
         [[bin]]\nname = \"closure_handoff_seal\"\npath = \"src/main.rs\"\n\
         # catch_unwind soundness requires panic=unwind (the emitter's own fence)\n\
         [profile.dev]\npanic = \"unwind\"\n",
    )
    .expect("Cargo.toml");
    std::fs::write(dir.join("src").join("ffi.rs"), ffi_rs).expect("ffi.rs");
    std::fs::write(dir.join("src").join("main.rs"), main_rs).expect("main.rs");

    let out = std::process::Command::new(&cargo)
        .arg("run")
        .arg("--quiet")
        .current_dir(&dir)
        .output()
        .expect("cargo run spawns");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "the assembled closure-handoff module tree must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.trim() == "42",
        "the Ipê `update` closure handed to `run` must drive the loop.\nstdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
