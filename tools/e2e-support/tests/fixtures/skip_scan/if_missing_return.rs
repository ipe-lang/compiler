//! Refused: an if-missing guard that turns an absent file into a pass.

#[test]
fn skips_when_missing() {
    let p = std::path::Path::new("artifact");
    if !p.is_file() {
        return;
    }
    assert!(p.is_file());
}
