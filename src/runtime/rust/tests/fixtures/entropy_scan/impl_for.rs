// A trait implemented for `OsRng`, whose `Self` paths name it.
impl Draw for OsRng {
    fn draw(&mut self) {
        Self::try_fill(self);
    }
}
