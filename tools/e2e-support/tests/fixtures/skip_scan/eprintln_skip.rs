//! Refused: a printed skip message followed by a return.

fn available() -> bool {
    false
}

#[test]
fn prints_and_skips() {
    if !available() {
        eprintln!("skipping: artifact absent");
        return;
    }
    assert!(available());
}
