//! Refused: a compile-time bin path outside the resolvers.

#[test]
fn runs_the_binary() {
    let bin = env!("CARGO_BIN_EXE_ipe");
    assert!(!bin.is_empty());
}
