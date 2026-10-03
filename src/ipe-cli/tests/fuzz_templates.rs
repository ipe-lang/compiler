#![forbid(unsafe_code)]
//! The fuzz templates under `tests/fuzz/` hold against the current compiler.
//!
//! Every well-typed template must type-check at its min, max and seeded fills;
//! every ill-typed template's base must be accepted and its mutant refused with
//! exactly the declared code. Under `IPE_E2E=1` each well-typed template also
//! builds with cargo and runs clean. The refusal tests drive each harness guard
//! with a fixture that clears the guards before it, so no guard can pass
//! vacuously. `tools/scripts/fuzz-well-typed.sh` and `fuzz-ill-typed.sh` run
//! `random_well_typed_run` / `random_ill_typed_run` with a chosen seed and count.

#[path = "fuzz_templates/harness.rs"]
mod harness;

use std::ffi::OsStr;
use std::path::PathBuf;

use harness::{
    FileRole, FillPlan, FuzzIters, HarnessError, ILL_TYPED, KnobError, MAX_ITERS, RunCapture,
    TemplateParseError, WELL_TYPED,
};
use ipe_diagnostics::{IPE_N0001, IPE_N0022, IPE_T0001, IPE_T0012};

/// The runtime tree every in-process build links against.
fn runtime() -> PathBuf {
    e2e_support::require_runtime().into_path_buf()
}

/// Whether the heavy build-and-run checks are on.
fn e2e_on() -> bool {
    e2e_support::e2e_tier() == e2e_support::Tier::E2e
}

/// A well-typed program whose prelude import no longer resolves (`IPE-N0022`).
const ROTTED_WELL_TYPED: &str = r"-- fuzz-slot n1 : Int 0 9
module Main exposing (main)

import Ipe.Log exposing (println)
import Ipe.String as String


main =
    println (String.fromInt @n1@)
";

/// An ill-typed template whose mutant fill is the base fill, so the mutant type-checks.
const MUTANT_EQUALS_BASE: &str = r"-- fuzz-hole arg
--   base: 1
--   mutant: 1
-- fuzz-expect IPE-T0001
module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


main =
    Io.println (String.fromInt @arg@)
";

/// An ill-typed template whose mutant is refused (`IPE-N0001`), but which declares `IPE-T0012`.
const MUTANT_WRONG_REASON: &str = r"-- fuzz-hole addend
--   base: 0
--   mutant: undef_x
-- fuzz-expect IPE-T0012
module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


main =
    Io.println (String.fromInt (1 + @addend@))
";

/// An ill-typed template whose body no longer compiles, so its base is refused.
const ROTTED_BASE: &str = r"-- fuzz-hole addend
--   base: 0
--   mutant: undef_x
-- fuzz-expect IPE-N0001
module Main exposing (main)

import Ipe.Log exposing (println)
import Ipe.String as String


main =
    println (String.fromInt (1 + @addend@))
";

/// A well-typed program that divides by zero at run time.
const DIVIDES_BY_ZERO: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


main =
    Io.println (String.fromInt (42 // 0))
";

/// Parse `main` as a one-file well-typed template.
fn well_typed(main: &str) -> Result<harness::Template, TemplateParseError> {
    harness::parse_well_typed("inline", &[(FileRole::Main, main)])
}

/// Parse `main` as a one-file ill-typed template.
fn ill_typed(main: &str) -> Result<harness::Mutant, TemplateParseError> {
    harness::parse_ill_typed("inline", &[(FileRole::Main, main)])
}

#[test]
fn every_well_typed_template_type_checks_at_min_max_and_seeded_fills() {
    let templates = harness::load_well_typed();
    let templates = templates.expect("templates is Ok");
    assert_eq!(templates.len(), WELL_TYPED.len());
    let runtime = runtime();
    let failures: Vec<String> = templates
        .iter()
        .flat_map(|t| {
            harness::check_plans()
                .into_iter()
                .map(move |plan| (t, plan))
        })
        .filter_map(|(t, plan)| harness::check_well_typed(t, plan, &runtime).err())
        .map(|f| f.to_string())
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn every_ill_typed_base_is_accepted_and_its_mutant_rejected_with_the_declared_code() {
    let mutants = harness::load_ill_typed();
    let mutants = mutants.expect("mutants is Ok");
    assert_eq!(mutants.len(), ILL_TYPED.len());
    let runtime = runtime();
    let failures: Vec<String> = mutants
        .iter()
        .flat_map(|m| {
            harness::check_plans()
                .into_iter()
                .map(move |plan| (m, plan))
        })
        .filter_map(|(m, plan)| harness::check_mutant(m, plan, &runtime).err())
        .map(|f| f.to_string())
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn a_well_typed_template_that_fails_to_type_check_fails_the_harness() {
    let template = well_typed(ROTTED_WELL_TYPED);
    let template = template.expect("template is Ok");
    let checked = harness::check_well_typed(&template, FillPlan::Min, &runtime());
    assert!(
        matches!(
            checked.as_ref().map_err(|f| &f.error),
            Err(HarnessError::TemplateRejected { code: Some(code), .. }) if *code == IPE_N0022
        ),
        "{checked:?}"
    );
}

#[test]
fn an_ill_typed_mutant_that_type_checks_fails_the_harness() {
    let mutant = ill_typed(MUTANT_EQUALS_BASE);
    let mutant = mutant.expect("mutant is Ok");
    let checked = harness::check_mutant(&mutant, FillPlan::Min, &runtime());
    assert!(
        matches!(
            checked.as_ref().map_err(|f| &f.error),
            Err(HarnessError::FalseAcceptance)
        ),
        "{checked:?}"
    );
}

#[test]
fn a_mutant_rejected_for_another_reason_fails_the_harness() {
    let mutant = ill_typed(MUTANT_WRONG_REASON);
    let mutant = mutant.expect("mutant is Ok");
    assert_eq!(mutant.expect(), IPE_T0012);
    let checked = harness::check_mutant(&mutant, FillPlan::Min, &runtime());
    assert!(
        matches!(
            checked.as_ref().map_err(|f| &f.error),
            Err(HarnessError::WrongCode { expected, got: Some(got) })
                if *expected == IPE_T0012 && *got == IPE_N0001
        ),
        "{checked:?}"
    );
}

#[test]
fn a_mutant_whose_base_is_rejected_fails_the_harness() {
    let mutant = ill_typed(ROTTED_BASE);
    let mutant = mutant.expect("mutant is Ok");
    let checked = harness::check_mutant(&mutant, FillPlan::Min, &runtime());
    assert!(
        matches!(
            checked.as_ref().map_err(|f| &f.error),
            Err(HarnessError::BaseRejected { code: Some(code), .. }) if *code == IPE_N0022
        ),
        "{checked:?}"
    );
}

#[test]
fn the_catalogue_matches_the_pinned_template_lists() {
    let root = harness::fuzz_root();
    let well = harness::list_templates(&root.join("well-typed"));
    let ill = harness::list_templates(&root.join("ill-typed"));
    let well = well.expect("well-typed templates list");
    let ill = ill.expect("ill-typed templates list");
    let ill_pinned: Vec<&str> = ILL_TYPED.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        harness::compare_catalogue("well-typed", WELL_TYPED, &well),
        Ok(())
    );
    assert_eq!(
        harness::compare_catalogue("ill-typed", &ill_pinned, &ill),
        Ok(())
    );
    let loaded_well = harness::load_well_typed().map(|t| t.len());
    let loaded_ill = harness::load_ill_typed().map(|m| m.len());
    assert_eq!(loaded_well, Ok(WELL_TYPED.len()));
    assert_eq!(loaded_ill, Ok(ILL_TYPED.len()));
}

#[test]
fn catalogue_drift_is_refused() {
    let found = ["arith".to_owned(), "zzz-unlisted".to_owned()];
    assert_eq!(
        harness::compare_catalogue("well-typed", &["arith", "tuple"], &found),
        Err(HarnessError::CatalogueDrift {
            missing: vec!["tuple".to_owned()],
            extra: vec!["zzz-unlisted".to_owned()],
        })
    );
    assert_eq!(
        harness::compare_catalogue("well-typed", &["arith"], &[]),
        Err(HarnessError::EmptyCatalogue {
            dir: "well-typed".to_owned()
        })
    );
    assert_eq!(
        harness::compare_catalogue("well-typed", &[], &found),
        Err(HarnessError::EmptyCatalogue {
            dir: "well-typed".to_owned()
        })
    );
    let mutant = ill_typed(MUTANT_EQUALS_BASE);
    let mutant = mutant.expect("mutant is Ok");
    assert_eq!(
        harness::check_pinned_expect(&mutant, IPE_N0001),
        Err(HarnessError::ExpectDrift {
            template: "inline".to_owned(),
            declared: IPE_T0001,
            pinned: IPE_N0001,
        })
    );
    assert_eq!(harness::check_pinned_expect(&mutant, IPE_T0001), Ok(()));
}

/// The body every header-refusal fixture shares: it uses `@n1@`.
const BODY: &str = "module Main exposing (main)\n\nmain =\n    @n1@\n";

/// An owned copy of `text`.
fn owned(text: &str) -> String {
    text.to_owned()
}

/// A header plus [`BODY`].
fn with_body(header: &str) -> String {
    format!("{header}{BODY}")
}

#[test]
fn template_header_refusals() {
    let slot = "-- fuzz-slot n1 : Int 0 9\n";
    let expect = "-- fuzz-expect IPE-T0001\n";
    let well = |text: &str| well_typed(text).err();
    let ill = |text: &str| ill_typed(text).err();

    assert_eq!(well(&with_body(slot)), None, "the control fixture parses");
    assert_eq!(
        harness::parse_well_typed("inline", &[(FileRole::Lib, BODY)]).err(),
        Some(TemplateParseError::MissingMain)
    );
    assert_eq!(
        well(&with_body("-- fuzz-slat n1 : Int 0 9\n")),
        Some(TemplateParseError::UnknownDirective {
            line: owned("-- fuzz-slat n1 : Int 0 9")
        })
    );
    assert_eq!(
        well(&format!("{}-- fuzz-slot n2 : Int 0 9\n", with_body(slot))),
        Some(TemplateParseError::DirectiveOutsideHeader {
            line: owned("-- fuzz-slot n2 : Int 0 9")
        })
    );
    assert_eq!(
        harness::parse_well_typed(
            "inline",
            &[
                (FileRole::Main, with_body(slot).as_str()),
                (
                    FileRole::Lib,
                    "-- fuzz-expect IPE-T0001\nmodule Lib exposing (x)\n"
                ),
            ]
        )
        .err(),
        Some(TemplateParseError::DirectiveOutsideHeader {
            line: owned("-- fuzz-expect IPE-T0001")
        })
    );
    for bad in [
        "-- fuzz-slot n1 : Int 0\n",
        "-- fuzz-slot n1 : Int 0 x\n",
        "-- fuzz-slot n1 : Real 0 9\n",
        "-- fuzz-slot N1 : Int 0 9\n",
        "-- fuzz-slot n1 Int 0 9\n",
        "-- fuzz-slot n1 : Int 0 70000\n",
    ] {
        assert_eq!(
            well(&with_body(bad)),
            Some(TemplateParseError::BadDecl {
                line: owned(bad.trim_end())
            }),
            "{bad:?}"
        );
    }
    assert_eq!(
        well(&with_body(&format!("{slot}{slot}"))),
        Some(TemplateParseError::DuplicateName { name: owned("n1") })
    );
    assert_eq!(
        ill(&with_body(&format!(
            "{slot}-- fuzz-hole n1\n--   base: 1\n--   mutant: 2\n{expect}"
        ))),
        Some(TemplateParseError::DuplicateName { name: owned("n1") })
    );
    assert_eq!(
        well(&with_body("-- fuzz-slot n1 : Int 9 0\n")),
        Some(TemplateParseError::InvertedRange { slot: owned("n1") })
    );
    assert_eq!(
        well(&with_body("-- fuzz-slot n1 : IntList 3 1 0 9\n")),
        Some(TemplateParseError::InvertedRange { slot: owned("n1") })
    );
    assert_eq!(
        well(&with_body("-- fuzz-slot n1 : Lower 1 33\n")),
        Some(TemplateParseError::LengthAboveCap { slot: owned("n1") })
    );
    assert_eq!(
        ill(&with_body(&format!(
            "{slot}-- fuzz-hole h\n--   mutant: 2\n{expect}"
        ))),
        Some(TemplateParseError::MissingHoleFill { hole: owned("h") })
    );
    assert_eq!(
        well(&with_body(&format!("{slot}-- fuzz-expect IPE-T9999\n"))),
        Some(TemplateParseError::UnknownCode {
            raw: owned("IPE-T9999")
        })
    );
}

#[test]
fn template_hole_and_token_refusals() {
    let slot = "-- fuzz-slot n1 : Int 0 9\n";
    let hole = "-- fuzz-hole h\n--   base: 1\n--   mutant: 2\n";
    let expect = "-- fuzz-expect IPE-T0001\n";
    let well = |text: &str| well_typed(text).err();
    let ill = |text: &str| ill_typed(text).err();
    let placed = "module Main exposing (main)\n\nmain =\n    @n1@ + @h@\n";
    assert_eq!(
        ill(&format!("{slot}{hole}{placed}")),
        Some(TemplateParseError::MissingExpect)
    );
    assert_eq!(
        ill(&format!("{slot}{hole}{expect}{expect}{placed}")),
        Some(TemplateParseError::DuplicateExpect)
    );
    assert_eq!(
        ill(&format!("{slot}{expect}{BODY}")),
        Some(TemplateParseError::ZeroHoles)
    );
    assert_eq!(
        ill(&format!(
            "{slot}{hole}-- fuzz-hole g\n--   base: 1\n--   mutant: 2\n{expect}{BODY}"
        )),
        Some(TemplateParseError::TwoOrMoreHoles)
    );
    assert_eq!(
        well(&format!("{slot}{hole}{placed}")),
        Some(TemplateParseError::HoleInWellTyped)
    );
    assert_eq!(
        well(&format!("{slot}{expect}{BODY}")),
        Some(TemplateParseError::ExpectInWellTyped)
    );
    assert_eq!(
        well(&format!("{slot}{BODY}@n1")),
        Some(TemplateParseError::MalformedToken { text: owned("n1") })
    );
    assert_eq!(
        well(&format!("{slot}{BODY}@N1@")),
        Some(TemplateParseError::MalformedToken { text: owned("N1@") })
    );
    assert_eq!(
        well(&format!("{slot}{BODY}@n2@")),
        Some(TemplateParseError::UndeclaredToken { name: owned("n2") })
    );
    assert_eq!(
        ill(&format!(
            "{slot}-- fuzz-hole h\n--   base: 1\n--   mutant: @h@\n{expect}{placed}"
        )),
        Some(TemplateParseError::UndeclaredToken { name: owned("h") })
    );
    assert_eq!(
        well(&with_body(&format!("{slot}-- fuzz-slot n2 : Hex4\n"))),
        Some(TemplateParseError::UnusedSlot { name: owned("n2") })
    );
    assert_eq!(
        ill(&format!("{slot}{hole}{expect}{BODY}")),
        Some(TemplateParseError::HoleNotPlacedOnce { count: 0 })
    );
    assert_eq!(
        ill(&format!("{slot}{hole}{expect}{placed}@h@")),
        Some(TemplateParseError::HoleNotPlacedOnce { count: 2 })
    );
}

#[test]
fn a_template_file_that_is_not_main_or_lib_is_refused() {
    let scratch = harness::Scratch::new("unknown-file");
    let scratch = scratch.expect("scratch is Ok");
    let dir = scratch.path().join("stray");
    let written = std::fs::create_dir(&dir)
        .and_then(|()| std::fs::write(dir.join("Main.ipe.tmpl"), BODY))
        .and_then(|()| std::fs::write(dir.join("Extra.ipe.tmpl"), BODY));
    assert!(written.is_ok(), "{written:?}");
    assert_eq!(
        harness::list_templates(scratch.path()),
        Ok(vec!["stray".to_owned()])
    );
    assert_eq!(
        harness::read_template_dir(&dir, "stray").err(),
        Some(HarnessError::Parse {
            template: "stray".to_owned(),
            error: TemplateParseError::UnknownFile {
                name: "Extra.ipe.tmpl".to_owned()
            },
        })
    );
}

#[test]
fn fuzz_iters_refuses_zero_above_cap_and_garbage() {
    let os = OsStr::new;
    assert_eq!(
        harness::parse_iters(None).map(FuzzIters::get),
        Ok(harness::FIXED_SEED_ITERS)
    );
    assert_eq!(
        harness::parse_iters(Some(os("1"))).map(FuzzIters::get),
        Ok(1)
    );
    assert_eq!(
        harness::parse_iters(Some(os(&MAX_ITERS.to_string()))).map(FuzzIters::get),
        Ok(MAX_ITERS)
    );
    assert_eq!(harness::parse_iters(Some(os("0"))), Err(KnobError::Zero));
    let above = MAX_ITERS + 1;
    assert_eq!(
        harness::parse_iters(Some(os(&above.to_string()))),
        Err(KnobError::AboveCap { got: above })
    );
    for garbage in ["", "ten", "-1", "1.5", " 3", "99999999999"] {
        assert_eq!(
            harness::parse_iters(Some(os(garbage))),
            Err(KnobError::NotANumber {
                var: harness::ITERS_VAR,
                raw: garbage.to_owned()
            }),
            "{garbage:?}"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(
            harness::parse_iters(Some(OsStr::from_bytes(b"\xff"))),
            Err(KnobError::NotUnicode {
                var: harness::ITERS_VAR
            })
        );
        assert_eq!(
            harness::parse_seed(Some(OsStr::from_bytes(b"\xff"))),
            Err(KnobError::NotUnicode {
                var: harness::SEED_VAR
            })
        );
    }
    assert_eq!(harness::parse_seed(None), Ok(harness::FIXED_SEED));
    assert_eq!(harness::parse_seed(Some(os("0"))), Ok(0));
    assert_eq!(harness::parse_seed(Some(os("4294967295"))), Ok(u32::MAX));
    assert_eq!(
        harness::parse_seed(Some(os("4294967296"))),
        Err(KnobError::NotANumber {
            var: harness::SEED_VAR,
            raw: "4294967296".to_owned()
        })
    );
}

#[test]
fn the_seeded_pick_is_deterministic_and_refuses_an_empty_catalogue() {
    let mut lcg = harness::Lcg::new(1);
    assert_eq!(lcg.next_value(), 1_103_527_590);
    let items = ["a", "b", "c"];
    assert_eq!(harness::pick(&items, 7), harness::pick(&items, 7));
    assert!(harness::pick(&items, 7).is_some());
    assert_eq!(harness::pick::<&str>(&[], 7), None);
}

#[test]
fn the_classifier_flags_each_fault_and_passes_a_clean_run() {
    let run = |exit: Option<i32>, timed_out: bool, stdout: &str, stderr: &str| RunCapture {
        exit,
        timed_out,
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
    };
    assert_eq!(harness::classify(run(Some(0), false, "ok\n", "")), Ok(()));
    assert!(matches!(
        harness::classify(run(None, true, "", "")),
        Err(HarnessError::RunTimedOut { .. })
    ));
    for stderr in [
        "[error] DivisionByZero (ref 1a2b3c4d): attempt to divide by zero",
        r#"{"level":"error","kind":"IndexOutOfBounds","errId":"x","message":"m"}"#,
        "thread 'main' panicked at src/main.rs:1:1:",
        "note: run with `RUST_BACKTRACE=1` to display a backtrace",
    ] {
        assert!(
            matches!(
                harness::classify(run(Some(0), false, "", stderr)),
                Err(HarnessError::PanicMarker { .. })
            ),
            "{stderr:?}"
        );
    }
    assert!(matches!(
        harness::classify(run(Some(0), false, "[error] Boom (ref x): y", "")),
        Err(HarnessError::PanicMarker { .. })
    ));
    assert_eq!(
        harness::classify(run(Some(0), false, "[error] two words (ref x): y", "")),
        Ok(())
    );
    assert!(matches!(
        harness::classify(run(Some(1), false, "", "")),
        Err(HarnessError::RunFailed { exit: Some(1), .. })
    ));
    assert!(matches!(
        harness::classify(run(None, false, "", "")),
        Err(HarnessError::RunFailed { exit: None, .. })
    ));
}

#[test]
fn random_well_typed_run() {
    let (seed, iters) = harness::knobs_from_env().expect("fuzz knobs parse");
    let templates = harness::load_well_typed();
    let templates = templates.expect("templates is Ok");
    let runtime = runtime();
    let run = e2e_on();
    for i in 0..iters.get() {
        let iter_seed = seed.wrapping_add(i);
        let picked = harness::pick(&templates, iter_seed);
        let (template, plan) = picked.expect("an empty catalogue picks nothing");
        let checked = if run {
            harness::run_well_typed(template, plan, &runtime)
        } else {
            harness::check_well_typed(template, plan, &runtime)
        };
        assert!(
            checked.is_ok(),
            "iteration seed {iter_seed} (rerun with IPE_FUZZ_SEED={iter_seed} IPE_FUZZ_ITERS=1): {}",
            checked.err().map_or_else(String::new, |f| f.to_string())
        );
    }
}

#[test]
fn random_ill_typed_run() {
    let (seed, iters) = harness::knobs_from_env().expect("fuzz knobs parse");
    let mutants = harness::load_ill_typed();
    let mutants = mutants.expect("mutants is Ok");
    let runtime = runtime();
    for i in 0..iters.get() {
        let iter_seed = seed.wrapping_add(i);
        let picked = harness::pick(&mutants, iter_seed);
        let (mutant, plan) = picked.expect("an empty catalogue picks nothing");
        let checked = harness::check_mutant(mutant, plan, &runtime);
        assert!(
            checked.is_ok(),
            "iteration seed {iter_seed} (rerun with IPE_FUZZ_SEED={iter_seed} IPE_FUZZ_ITERS=1): {}",
            checked.err().map_or_else(String::new, |f| f.to_string())
        );
    }
}

#[test]
fn every_well_typed_template_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let templates = harness::load_well_typed();
    let templates = templates.expect("templates is Ok");
    let runtime = runtime();
    let failures: Vec<String> = templates
        .iter()
        .filter_map(|t| harness::run_well_typed(t, FillPlan::Max, &runtime).err())
        .map(|f| f.to_string())
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn the_detector_flags_division_by_zero() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let template = well_typed(DIVIDES_BY_ZERO);
    let template = template.expect("template is Ok");
    let built = harness::accept_well_typed(&template, FillPlan::Min, &runtime());
    let built = built.expect("built is Ok");
    let judged = harness::build_and_run(&built, "fuzz_divides_by_zero");
    assert!(
        matches!(
            judged,
            Err(HarnessError::RunFailed { .. } | HarnessError::PanicMarker { .. })
        ),
        "{judged:?}"
    );
}
