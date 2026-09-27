#[test]
fn first() {
    assert_eq!(vec![1u8].first().copied().unwrap(), 1);
}
