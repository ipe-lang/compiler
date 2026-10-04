# bitwise-flags

A `Program`-shape tool showing `Ipe.Bitwise`: a permission set packed into the
low bits of one `Int`, combined with OR, tested with AND, and cleared with the
complement. The worked example for the [Bitwise guide](../../../../docs/guide/bitwise.md).

```
ipe dev build package.ipe
cargo run --manifest-path out/rust/Cargo.toml
```
