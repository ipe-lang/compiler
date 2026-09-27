pub fn first(xs: Vec<u8>) -> u8 {
    xs.first().copied().unwrap()
}
