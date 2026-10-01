//! Accepted: the first-statement tier gate and exits that fail the test.

use e2e_support::{Tier, e2e_tier};

const GOLDEN: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/x"));

#[test]
fn gated_unit() {
    if e2e_tier() == Tier::Unit {
        return;
    }
    assert!(!GOLDEN.is_empty());
}

#[test]
fn gated_result() -> Result<(), String> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    if GOLDEN.is_empty() {
        return Err(String::from("the golden is empty"));
    }
    Ok(())
}

#[test]
fn gated_with_a_message() {
    if e2e_tier() == Tier::Unit {
        eprintln!("unit tier: the end-to-end half runs under the e2e tier");
        return;
    }
    let largest = |xs: &[u8]| {
        if xs.is_empty() {
            return 0;
        }
        xs.iter().copied().max().unwrap_or(0)
    };
    assert_eq!(largest(&[1, 2]), 2);
}
