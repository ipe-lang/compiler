// A `getrandom` type behind a qualified self.
fn draw() {
    let _ = <getrandom::Error>::UNSUPPORTED;
}
