//! Refused: reading the tier variable directly instead of through `e2e_tier`.

#[test]
fn reads_the_tier_itself() {
    let _tier = ipe_env::var_os("IPE_E2E");
}
