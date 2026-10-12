// None of the lines below is an abrupt-failure construct; the scanner must
// produce ZERO hits here.
//
// Mentions in comments are not code: panic!() unreachable!() .unwrap() assert_eq!(a,b)
/// Doc comment: prefer `.unwrap()` never; `panic!` is banned. (ignored)
fn n01() { let s = "call .unwrap() then panic!() and assert_eq!(a,b)"; } // in a string
fn n02() { let s = "assert!(false)"; }
fn n03() { let _ = o.unwrap_or(0); }          // total combinator
fn n04() { let _ = o.unwrap_or_else(f); }     // total combinator
fn n05() { let _ = o.unwrap_or_default(); }   // total combinator
fn n06() { let _ = expectation(); }           // identifier contains 'expect'
fn n07() { let _ = panic_hook(); }            // identifier contains 'panic'
fn n08() { reassert(); }                      // identifier contains 'assert'
fn n09() { let _ = arr.get(i); }              // safe access, no panic
fn n10() { let _ = matches!(x, Some(_)); }    // matches! never panics
fn n11() { assert_impl_all!(T: Send); }       // a different macro, compile-time
fn n12() { let r = r#"raw .unwrap() panic!()"#; } // raw string literal
fn n13() { let _ = value.expected; }          // field named 'expected'
fn n14() { let _ = o.unwrap_none(); }         // not in the banned set
fn n18() { let _ = Result::unwrap_or(r, 0); } // UFCS total combinator, no panic
fn n19() { let _ = Vec::unwrap_none(v); }     // UFCS, not in the banned set
fn n20() { let _ = module::process(x); }      // trailing ident not a method

// Sanctioned sites: a real construct carrying the audit marker on its own line,
// or on the line directly above it, is a reviewed ledger exception — no hit.
fn n15() { std::process::exit(1); } // IPE-RUST-AUDIT:ACCEPTED — boundary exit [ledger #X]
// IPE-RUST-AUDIT:ACCEPTED — provably-dead branch [ledger #X]
fn n16() { let _ = o.expect("dead branch"); }
fn n17() {
    // IPE-RUST-AUDIT:ACCEPTED — marker on the line above a multi-line construct
    panic!(
        "sanctioned multi-line"
    );
}

#[cfg(test)]
mod tests {
    // Real constructs here are TEST code and must be ignored by the production scan.
    fn t01() { panic!("in a test — ignored"); }
    fn t02() { let _ = o.unwrap(); }
    fn t03() { assert_eq!(a, b); }
}

// `all(test, …)` gates the item to test-only compilation, so its body is test
// code even when the attribute is not the bare `cfg(test)` form.
#[cfg(all(test, unix))]
mod platform_tests {
    fn u01() { assert_eq!(a, b); }
    fn u02() { panic!("test-only on unix — ignored"); }
}

#[cfg(all(unix, test))]
mod platform_tests_reordered {
    fn r01() { let _ = o.unwrap(); }
}

#[cfg(all(test, feature = "tokio"))]
mod feature_gated_tests {
    // `feature = "tokio"` is a string value; the top-level split still finds the
    // `test` conjunct, so this body is test-only and ignored.
    fn g01() { assert!(ready); }
}
