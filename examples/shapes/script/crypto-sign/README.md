# crypto-sign

A `Program`-shape tool showing `Ipe.Crypto`: a `sha256` fingerprint, an
HMAC-SHA-256 signature built with a typed `Key`, and a `constantTimeEqual`
verification. The `Key` type makes passing a message where a key is expected a
compile error. The worked example for the [Cryptography guide](../../../../docs/guide/crypto.md).

```
ipe dev build package.ipe
cargo run --manifest-path out/rust/Cargo.toml
```
