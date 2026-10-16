// The OS draw inside an opaque macro body.
macro_rules! m {
    () => {
        getrandom::getrandom(&mut b)
    };
}
