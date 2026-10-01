//! Soundness gate: a function value reaching a CONSTRUCTOR PAYLOAD
//! THROUGH a type variable must NEVER emit cargo-failing Rust silently.
//!
//! The shape — `type Box a = Mk a`, with `Mk (\n -> n + 1)` — instantiates the
//! payload field `a` to `Int -> Int` at the use site. There is no blanket
//! rejection for enum-like heads (`Maybe`/`Result`/user unions): the
//! runtime/derive machinery already tolerates a function payload there — the
//! derive-demotion fixpoint drops `MainBox<T1>`'s `#[derive(Clone, Debug,
//! PartialEq)]` when a field is not derivable, and its hand-written
//! `IpeStringify` impl renders the non-derivable field as `<fn>` instead of
//! calling a derive. So this fixture now takes the BUILD-AND-RUN branch below —
//! `ipe` accepts it, `cargo` builds it, and it runs, printing `2`
//! (`(\n -> n + 1) 1 == 2`).
//!
//! This pins the recurring soundness-floor class (the sibling of the M2C
//! function-in-record gate): the driver must produce EITHER a clean Ipê
//! diagnostic (IPE-L0114, for a shape #90 does NOT cover — a collection-of-
//! functions payload, or a curried `andMap` chain) OR Rust that builds and runs
//! with the semantically-correct output. It must NEVER accept the program and
//! then cargo-fail.
//!
//! Marked `oracle_divergence = true`: there is no external oracle output for
//! this shape, so the golden is Ipê's own emitted-and-run result.

use std::path::{Path, PathBuf};

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("function_payload_gate")
        .join("Main.ipe")
}

#[test]
fn rejects_cleanly_or_builds_and_runs_never_silent_cargo_fail() {
    let root = repo_root();
    let entry = example_entry(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m3a_function_payload_gate_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);

    // The minimal sound outcome: a clean constructor-payload-function
    // diagnostic naming the constructor-payload carrier (IPE-L0114), distinct
    // from the record-field gap (IPE-L0107).
    if let Err(CliError::Pipeline { diag, .. }) = &built {
        assert_eq!(
            diag.code(),
            ipe_diagnostics::IPE_L0114,
            "a function value reaching a constructor payload through a type \
             variable must surface IPE-L0114, got: {diag:?}"
        );
    } else {
        // The only other acceptable outcome is full acceptance — never another
        // driver error, and never a silent accept that later cargo-fails.
        assert!(
            built.is_ok(),
            "must reject cleanly (IPE-L0114) or accept fully — never another error: {:?}",
            built.err()
        );

        // With proper support (an eager `Box<dyn Fn>` coercion), the emitted crate
        // MUST build and run with the semantically-correct output. Gated on IPE_E2E
        // so default runs stay fast.
        if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
            let outcome = crate::support::build_and_run_emitted("function_payload_gate", &out);
            crate::support::assert_go_parity(
                "function_payload_gate",
                &repo_root()
                    .join("tests")
                    .join("golden")
                    .join("function_payload_gate"),
                &outcome.stdout,
            );
            assert_eq!(outcome.exit_code, Some(0), "exit 0");
        }
    }
}
