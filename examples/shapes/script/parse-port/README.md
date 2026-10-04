# parse-port

A `Program`-shape tool showing **parse, don't validate**: a `String -> Maybe Port`
boundary parser turns untyped input into a typed `Port` once, so no downstream code
re-checks the range. The worked example for the
[parse-don't-validate idiom](../../../../docs/idioms/parse-dont-validate.md).

```
ipe dev build package.ipe
cargo run --manifest-path out/rust/Cargo.toml
```
