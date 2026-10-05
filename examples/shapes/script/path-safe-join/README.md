# path-safe-join

A `Program`-shape tool showing `Ipe.Path`: the opaque, traversal-safe `Path`.
`Path.fromString` is the one gate — it rejects a `..` escape or a NUL byte — so a
value of type `Path` is proof it is clean. The worked example for the
[Path guide](../../../../docs/guide/path.md).

```
ipe dev build package.ipe
cargo run --manifest-path out/rust/Cargo.toml
```
