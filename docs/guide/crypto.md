# Cryptography

`Ipe.Crypto` is the cryptographic toolbox: hashes, HMAC, AEAD encryption, RSA
signatures, and secure randomness. Its distinguishing move is a typed `Key`: every
keyed operation requires one, so a plaintext message can never be mistaken for a
key at a call site — a whole class of misuse becomes a compile error rather than a
silent vulnerability.

## The mental model

Three knots.

- **Hashes are pure; keyed operations take a `Key`.** `sha256`, `sha512`, `sha1`,
  and `md5` are pure `String -> String` fingerprints — deterministic, no key.
  Everything keyed — `hmacSha256`, the AEAD encrypt/decrypt pairs — requires a typed
  `Key`, not a bare `String`. You build a `Key` once, at the boundary, with
  `keyFromString` (or a password-derivation function); passing a message where a
  `Key` is expected does not type-check. Key/message role confusion is
  unrepresentable.
- **A MAC is a typed value; verify it in constant time.** `hmacSha256` returns a
  `Mac`, not a `String`. Render it with `macToHex` for storage; to check a stored
  or presented tag, parse it once with `macFromHex` (exactly 64 or 128 hex digits,
  `Nothing` otherwise) and pass the `Mac` to `verifyHmacSha256 key message mac`,
  which recomputes the tag and compares the raw bytes in constant time — never
  `==` on the hex. A normal equality check exits at the first differing byte, and
  that early exit leaks — through timing — how long a prefix matched, which is
  enough to forge a signature one byte at a time.
- **AEAD is nonce-safe by construction; randomness is an effect.** `aesGcmEncrypt`
  and `chacha20Encrypt` generate a fresh random nonce on every call and prepend it
  to the ciphertext, so `decrypt` can recover it — you never manage a nonce, and you
  can never reuse one by mistake. Because they draw fresh entropy, and because
  `randomBytes` / `randomToken` do too, those are `Task Error _`: nondeterministic
  effects, sequenced like any other.

## A worked example: signing and verifying

The example under
[`examples/shapes/script/crypto-sign`](../../examples/shapes/script/crypto-sign/src/Main.ipe)
hashes a string, builds a signing key once, signs a message, and verifies both a
correct and a tampered signature.

The key is built at the boundary — `keyFromString` returns `Maybe Key`, so the
fallible parse happens once and everything downstream holds a real `Key`:

```ipe
signingKey =
    Crypto.keyFromString "s3cret-signing-key"
```

`sign` takes a `Key` (it cannot be called with a bare string), and `verify`
compares in constant time:

```ipe
sign key message =
    Crypto.macToHex (Crypto.hmacSha256 key message)

verify key message presented =
    Crypto.constantTimeEqual (sign key message) presented
```

Running it (`ipe dev run`) prints the hash, the signature, and the two verifications:

```
sha256(hello): 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
signature: 2c69896ccfef8cf87755eab6f2d7525f23a4ea54455d196d952d3c64e6cbbeb9
verify (correct): accepted
verify (tampered): rejected
```

## The why

The typed `Key` is [make invalid states unrepresentable][principles] pointed at a
security boundary: "encrypt this message with that message" is a real,
catastrophic bug in stringly-typed crypto APIs, and here it simply does not
type-check. The key material is opaque and never logged, so it cannot leak through
a stray debug line.

Forcing `constantTimeEqual` for MAC comparison rather than `==` is
[deny-by-default][principles] against a timing side channel: the safe compare is the
one the API hands you, and the leaky one (`==` on the raw bytes) is not even
reachable, because a `Mac` is opaque. Generating the AEAD nonce internally is the
same idea — the single most common way to catastrophically misuse AES-GCM (nonce
reuse) is removed by never letting the caller supply one.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Crypto` — hashes, `hmacSha256` /
  `hmacSha512`, the AEAD pairs (`aesGcmEncrypt` / `aesGcmDecrypt`,
  `chacha20Encrypt` / `chacha20Decrypt`), `keyFromString` / `keyFromBytes`,
  `macToHex` / `macFromHex`, `verifyHmacSha256`, `constantTimeEqual`, and
  `randomBytes` / `randomToken`.
- **Sibling guides:** [Text encodings](encoding.md) — hex and base64 for rendering
  digests and ciphertext. [Bytes](bytes.md) — the raw octet type. [Tasks](task.md)
  — how the randomness effects are sequenced. [Network primitives](net.md) and the
  [HTTP client](http.md) — the boundaries where signed tokens travel.
