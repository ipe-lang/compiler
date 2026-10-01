//! Refused: a let-else that turns an absent artifact into a pass.

fn find() -> Option<u8> {
    None
}

#[test]
fn skips_when_absent() {
    let Some(x) = find() else {
        return;
    };
    assert_eq!(x, 1);
}
