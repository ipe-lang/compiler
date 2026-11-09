//! End-to-end gate: `Time.daysInMonth` refuses a month outside 1 to 12 with a
//! typed runtime error, never a sentinel day count printed as if it were one.
//!
//! The emitted program asks for the days of month 13; it must exit 1 with
//! nothing on stdout. Gated on `IPE_E2E=1`.

use std::path::PathBuf;

use crate::support::repo_root;

fn entry() -> PathBuf {
    repo_root()
        .join("tests")
        .join("golden")
        .join("time_days_in_month_domain")
}

#[test]
fn days_in_month_outside_the_year_is_a_typed_error() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let name = "time_days_in_month_domain";
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    e2e_support::scratch::fresh(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&entry(), &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(1),
        "month 13 must end in the typed InvalidInput error (exit 1), not a day count"
    );
    assert_eq!(
        outcome.stdout, "",
        "no day count is printed once the month is refused"
    );
}
