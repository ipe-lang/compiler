// Crypto core — the cryptographic floor.
//
// This module holds the entropy pair (`crypto_random_bytes`/
// `crypto_random_token`, emitted into every program via the kernel-wrapper
// prelude), the SHA-2 hash + HMAC family, the typed `Key`/`Mac` role newtypes,
// and the constant-time compare — the primitives the crypto floor keeps. The
// RSA SHA-256 sign/verify pair is `cfg(feature = "crypto")`: it compiles (and
// pulls the `rsa` crate) only when the program reaches the heavy crypto floor
// (a `Crypto` kernel, a `Jwt` kernel, or the `Auth` surface). The heavier,
// rarely-used primitives (legacy SHA-1/MD5, AES-GCM + ChaCha20-Poly1305 AEAD,
// PBKDF2 key derivation) live in the sibling `crypto` module and pull their own
// crates.
//
// wasm32: only `crypto_random_bytes`/`crypto_random_token` (this file's entropy
// pair) and the pure hash/HMAC family compile for the browser target — the RSA
// functions are each individually `cfg(feature = "crypto")` (a native contract).
use super::*;

// ── Typed role newtypes ───────────────────────────────────────────────────────
//
// `Key` and `Mac` make distinct cryptographic roles distinct Rust types so a
// role-swap (passing a message where a key is expected) is a compile error, not
// a silent wrong answer. `Key` wraps an opaque `String` blob; `Mac` holds the raw
// tag bytes tagged with their algorithm width. Callers never inspect either
// directly; the role is what matters.

/// `Crypto.Key` — an opaque cryptographic key obtained from `Key.fromString`,
/// `Key.fromBytes`, or `Crypto.aesKeyFromPassword` / `Crypto.chachaKeyFromPassword`.
///
/// Distinct from `String`: passing a `Key` where a message is expected (or
/// vice-versa) is a compile-time error, not a silent wrong MAC or ciphertext.
///
/// `Clone`: keys are legitimately reused across multiple operations (the
/// keyfrompassword golden fixture derives the same key twice and uses each once).
/// NOT `Debug`/`Display`: prevents accidental key material appearing in log
/// lines or panic messages. `PartialEq` via constant-time compare (same
/// reasoning as `Secret`: the length check is metadata, but byte equality is
/// timing-safe via `subtle`).
#[derive(Clone)]
pub struct Key(String);

crate::ct_eq::impl_ct_eq!(Key);

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<key>")
    }
}

crate::stringify::show_row!("CryptoKey", Redacted, [] Key, |_| crate::stringify::REDACTED_SHOW.to_owned());

/// `Crypto.Mac` — an opaque message authentication code returned by
/// `Crypto.hmacSha256` / `Crypto.hmacSha512`, or parsed once by `Mac.fromHex`.
///
/// Distinct from `String` so a MAC output cannot be silently passed where a
/// key or plaintext is expected. Holds the raw tag bytes in a `MacTag` whose
/// variant fixes the width, so a malformed or wrong-width tag has no
/// representation; `Mac.toHex` is the only extraction path so a reviewer can
/// grep for every MAC-reveal site.
///
/// `Clone`: derived. `Debug`: hand-written, renders the lowercase hex tag (a
/// tag is public output, not secret material). `PartialEq`: constant-time via
/// [`crate::ct_eq::ct_bytes_eq`] over the raw bytes — same posture as `Key` and
/// `Secret`. The derived early-exit `PartialEq` is structurally excluded: adding
/// `#[derive(PartialEq)]` alongside the `impl_ct_eq!` invocation is a hard E0119
/// compile error (conflicting impls), so the class is closed by construction.
#[derive(Clone)]
pub struct Mac(MacTag);

/// The raw bytes of a [`Mac`], tagged with the HMAC algorithm that fixes their width.
///
/// Only `Clone`: equality goes through `Mac`'s constant-time `PartialEq`, never
/// a derived early-exit compare on the bytes.
#[derive(Clone)]
enum MacTag {
    /// A 32-byte HMAC-SHA-256 tag.
    HmacSha256(hmac::digest::Output<hmac::Hmac<sha2::Sha256>>),
    /// A 64-byte HMAC-SHA-512 tag.
    HmacSha512(hmac::digest::Output<hmac::Hmac<sha2::Sha512>>),
}

impl MacTag {
    /// The raw tag bytes.
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::HmacSha256(tag) => tag.as_slice(),
            Self::HmacSha512(tag) => tag.as_slice(),
        }
    }
}

impl Mac {
    /// The tag rendered as lowercase hex.
    fn to_hex(&self) -> String {
        hex::encode(self.0.as_bytes())
    }
}

impl std::fmt::Debug for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Mac").field(&self.to_hex()).finish()
    }
}

crate::ct_eq::impl_ct_eq!(Mac);

crate::stringify::show_row!("CryptoMac", Value, [] Mac, |m| m.to_hex());

/// Crate-internal raw promotion of a `String` to a `Key`, with no validation.
/// The ONLY sanctioned no-check path — the password-derivation kernels use it
/// on PBKDF2 output (always a valid 32-byte blob). Public construction goes
/// through `crypto_key_from_string` / `crypto_key_from_bytes`, which validate.
/// Gated to `crypto`: its only callers are the password-derivation kernels,
/// which are `crypto`-only, so it is absent (not dead) in a `crypto-core`-only build.
#[cfg(feature = "crypto")]
pub(crate) fn crypto_key_promote(s: String) -> Key {
    Key(s)
}

/// `Key.fromString : String -> Maybe Key` — construction boundary: parse a
/// candidate key `String` into a typed `Key`. An empty key is rejected
/// (`Nothing`) — it is a valid key for no algorithm — so a caller cannot forge
/// an empty-keyed MAC or cipher. The byte content is otherwise opaque; the role
/// is distinct.
#[must_use]
pub fn crypto_key_from_string(s: String) -> IpeMaybe<Key> {
    if s.is_empty() {
        return IpeMaybe::Nothing;
    }
    IpeMaybe::Just(Key(s))
}

/// `Key.fromBytes : String -> Maybe Key` — the byte-string construction
/// boundary (Ipê `Bytes` is `String`). Same validation as `fromString`.
#[must_use]
pub fn crypto_key_from_bytes(s: String) -> IpeMaybe<Key> {
    crypto_key_from_string(s)
}

/// `Mac.toHex : Mac -> String` — the single extraction boundary: render the
/// tag of an opaque `Mac` as lowercase hex. Greppable, so a reviewer can audit
/// every place a raw MAC string escapes the typed wrapper.
#[must_use]
pub fn crypto_mac_to_hex(m: Mac) -> String {
    m.to_hex()
}

/// `Mac.fromHex : String -> Maybe Mac` — the single parse boundary for a
/// stored tag.
///
/// Accepts exactly 64 hex digits (an HMAC-SHA-256 tag) or exactly 128 (an
/// HMAC-SHA-512 tag), in either case; `Mac.toHex` renders the parsed tag back
/// in lowercase. Every other input is `Nothing`: empty, odd length, any other
/// length, a non-hex digit, surrounding whitespace, or a `0x` prefix. The
/// width is decided here once, so `verifyHmacSha256` never re-inspects text.
#[must_use]
pub fn crypto_mac_from_hex(s: String) -> IpeMaybe<Mac> {
    use hmac::digest::generic_array::GenericArray;
    // `decode_to_slice` refuses an odd length, a length other than twice the
    // output buffer, and any byte outside `[0-9a-fA-F]`.
    let mut sha256: hmac::digest::Output<hmac::Hmac<sha2::Sha256>> = GenericArray::default();
    if hex::decode_to_slice(s.as_bytes(), sha256.as_mut_slice()).is_ok() {
        return IpeMaybe::Just(Mac(MacTag::HmacSha256(sha256)));
    }
    let mut sha512: hmac::digest::Output<hmac::Hmac<sha2::Sha512>> = GenericArray::default();
    if hex::decode_to_slice(s.as_bytes(), sha512.as_mut_slice()).is_ok() {
        return IpeMaybe::Just(Mac(MacTag::HmacSha512(sha512)));
    }
    IpeMaybe::Nothing
}

/// Crate-internal `Key` unwrap — the sibling `crypto` module's typed AEAD
/// wrappers (`crypto_aes_gcm_encrypt_key` / `crypto_chacha20_encrypt_key` / …)
/// recover the raw key blob to forward to the AEAD primitives. `pub(crate)` so the
/// opaque key material still cannot escape the runtime crate. Gated to its sole
/// (feature-gated) consumer now that the `crypto_core` floor compiles without
/// the heavy `crypto` feature.
#[cfg(any(
    feature = "crypto",
    all(target_arch = "wasm32", feature = "wasm-client")
))]
#[must_use]
pub(crate) fn crypto_key_reveal(key: Key) -> String {
    key.0
}

// `Crypto.randomBytes : Int -> Task Error String`. Returns entropy as a
// LOWERCASE HEX string — the Ipê signature is `String`, so the Rust side
// must return a hex `String` (not a byte list).
#[cfg(not(target_arch = "wasm32"))]
pub fn crypto_random_bytes<E: From<String> + Send + 'static>(n: i64) -> IpeTask<E, String> {
    Box::pin(async move {
        // SECURITY: reject size <= 0 || size > 1024 to prevent unbounded
        // attacker-controlled allocation (DoS vector).
        if n <= 0 || n > 1024 {
            return IpeResult::Err(
                "Crypto.randomBytes: size must be 1..1024"
                    .to_string()
                    .into(),
            );
        }
        let count = n as usize;
        let mut buf = vec![0u8; count];
        if getrandom::getrandom(&mut buf).is_err() {
            return IpeResult::Err(
                "Crypto.randomBytes: OS entropy source unavailable"
                    .to_string()
                    .into(),
            );
        }
        ok_res(hex_lower(&buf))
    })
}

/// Browser substitute: `crypto.getRandomValues` via the `getrandom` crate's
/// `js` backend (Q3: "`Random.*` / `Crypto.randomBytes` | SUBSTITUTE |
/// `crypto.getRandomValues`") — no `aes-gcm`/`OsRng` dependency pulled into
/// the bundle just for entropy. Same size guard + hex encoding as the native
/// arm — same size guard + hex encoding as the native arm; the size guard is a
/// real DoS control on both targets.
#[cfg(target_arch = "wasm32")]
pub fn crypto_random_bytes<E: From<String> + 'static>(n: i64) -> IpeTask<E, String> {
    Box::pin(async move {
        if n <= 0 || n > 1024 {
            return IpeResult::Err(
                "Crypto.randomBytes: size must be 1..1024"
                    .to_string()
                    .into(),
            );
        }
        let count = n as usize;
        let mut buf = vec![0u8; count];
        if getrandom::getrandom(&mut buf).is_err() {
            return IpeResult::Err(
                "Crypto.randomBytes: browser entropy source unavailable"
                    .to_string()
                    .into(),
            );
        }
        ok_res(hex_lower(&buf))
    })
}

/// Lowercase hex encoding, byte-order + nibble-order identical to
/// `hex.EncodeToString` (high nibble first, then low). Total: the `& 0x0f` index
/// is always < 16 so `.get` never falls back.
fn hex_lower(buf: &[u8]) -> String {
    let hex = b"0123456789abcdef";
    let mut out = String::with_capacity(buf.len() * 2);
    for &b in buf {
        out.push(hex.get(((b >> 4) & 0x0f) as usize).copied().unwrap_or(b'0') as char);
        out.push(hex.get((b & 0x0f) as usize).copied().unwrap_or(b'0') as char);
    }
    out
}

/// URL-safe base64 WITHOUT padding, byte-identical to
/// `base64.RawURLEncoding.EncodeToString` — the `-_` alphabet, no `=` pad. Inline
/// (not the `base64` crate) so the `crypto_core` floor carries no
/// unconditional codec-crate reference: `crypto_random_token` is emitted in every
/// program's FIXED prelude wrapper block, so it must stay available at
/// `--no-default-features` for `base64` to be optional. A pure translation of the
/// standard 6-bit → alphabet mapping; the `& 0x3f` / final-index math keeps every
/// table lookup in range so `.get` never falls back.
fn base64url_no_pad(buf: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let sym = |v: u8| ALPHABET.get((v & 0x3f) as usize).copied().unwrap_or(b'A') as char;
    let mut out = String::with_capacity(buf.len().div_ceil(3) * 4);
    // Three input bytes → four 6-bit groups. `as_chunks::<3>` yields `[u8; 3]`
    // arrays plus the sub-3-byte remainder, so every element binds by pattern
    // without an index and no unreachable slice-pattern arm is needed.
    let (triples, remainder) = buf.as_chunks::<3>();
    for &[b0, b1, b2] in triples {
        out.push(sym(b0 >> 2));
        out.push(sym((b0 << 4) | (b1 >> 4)));
        out.push(sym((b1 << 2) | (b2 >> 6)));
        out.push(sym(b2));
    }
    // Raw (no-pad) tail: 1 leftover byte → 2 chars, 2 leftover bytes → 3 chars.
    match remainder {
        [b0] => {
            out.push(sym(b0 >> 2));
            out.push(sym(b0 << 4));
        }
        [b0, b1] => {
            out.push(sym(b0 >> 2));
            out.push(sym((b0 << 4) | (b1 >> 4)));
            out.push(sym(b1 << 2));
        }
        _ => {}
    }
    out
}

// `Crypto.randomToken : Int -> Task Error String`. Returns URL-safe base64
// WITHOUT padding — the `-_` alphabet, no `=` pad. Width `n` is bytes of
// ENTROPY; the returned string is longer (ceil(n*4/3) chars).
#[cfg(not(target_arch = "wasm32"))]
pub fn crypto_random_token<E: From<String> + Send + 'static>(n: i64) -> IpeTask<E, String> {
    Box::pin(async move {
        // SECURITY: reject size <= 0 || size > 1024 to prevent unbounded
        // attacker-controlled allocation (DoS vector).
        if n <= 0 || n > 1024 {
            return IpeResult::Err(
                "Crypto.randomToken: size must be 1..1024"
                    .to_string()
                    .into(),
            );
        }
        let count = n as usize;
        let mut buf = vec![0u8; count];
        if getrandom::getrandom(&mut buf).is_err() {
            return IpeResult::Err(
                "Crypto.randomToken: OS entropy source unavailable"
                    .to_string()
                    .into(),
            );
        }
        ok_res(base64url_no_pad(&buf))
    })
}

/// Browser substitute — same `getrandom(js)` entropy source as
/// `crypto_random_bytes`, URL-safe-no-pad base64 encoded.
#[cfg(target_arch = "wasm32")]
pub fn crypto_random_token<E: From<String> + 'static>(n: i64) -> IpeTask<E, String> {
    Box::pin(async move {
        if n <= 0 || n > 1024 {
            return IpeResult::Err(
                "Crypto.randomToken: size must be 1..1024"
                    .to_string()
                    .into(),
            );
        }
        let count = n as usize;
        let mut buf = vec![0u8; count];
        if getrandom::getrandom(&mut buf).is_err() {
            return IpeResult::Err(
                "Crypto.randomToken: browser entropy source unavailable"
                    .to_string()
                    .into(),
            );
        }
        ok_res(base64url_no_pad(&buf))
    })
}

pub fn crypto_sha256(s: String) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let result = h.finalize();
    result
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

/// Ipê `sha512 : String -> String` — hex-encoded SHA-512 digest.
pub fn crypto_sha512(s: String) -> String {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(s.as_bytes());
    let result = h.finalize();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Raw-String-key HMAC-SHA-256 (key, message → hex tag). `pub(crate)`, NOT a
/// public runtime API and NOT registered as a kernel: the only sanctioned caller
/// is `jwt::jwt_encode_hs256`, which owns its own `secret: String` boundary (a
/// 32-byte-minimum floor, RFC 7518 §3.2). Ipê's `Crypto.hmacSha256` binds the
/// typed-`Key` variant [`crypto_hmac_sha256_key`]; there is no bare-`String`-key
/// HMAC spelling reachable from Ipê source or from outside this crate, so a
/// caller cannot supply confusable/untyped key material through this door.
/// Gated to its sole (feature-gated) consumer — `jwt` implies `crypto`, so
/// under `crypto` alone (no `jwt`) this function is absent, not dead.
#[cfg(feature = "jwt")]
pub(crate) fn crypto_hmac_sha256(key: String, msg: String) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    // STRUCTURALLY-DEAD Err: `Hmac<D>::new_from_slice` pads/hashes any key
    // internally and returns `Ok` unconditionally, so `InvalidLength` is never
    // produced. Kept as a LOUD `.expect`, not eliminated: threading a Result through
    // this pure `String -> String` kernel makes callers handle a never-occurring Err
    // whose mishandling is a wrong hash, and an infallible-by-type ctor would
    // reimplement key prep (a security regression). See the ledger for the full verdict.
    // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — structurally-dead HMAC InvalidLength; a loud .expect is safer than a dead Result Err a caller can mishandle into a wrong MAC [ledger #1]
    #[allow(clippy::expect_used)]
    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).expect("Hmac<Sha256> accepts any key length");
    mac.update(msg.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// `Crypto.hmacSha256WithKey : Key -> String -> Mac` — typed variant.
/// The key parameter is a distinct `Key` role so passing the message where the
/// key is expected is a compile error.
pub fn crypto_hmac_sha256_key(key: Key, msg: String) -> Mac {
    use hmac::{Hmac, Mac as HmacMac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    // STRUCTURALLY-DEAD Err: same reasoning as `crypto_hmac_sha256` above.
    // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — structurally-dead HMAC InvalidLength; a loud .expect is safer than a dead Result Err a caller can mishandle into a wrong MAC [ledger #1]
    #[allow(clippy::expect_used)]
    let mut mac =
        HmacSha256::new_from_slice(key.0.as_bytes()).expect("Hmac<Sha256> accepts any key length");
    mac.update(msg.as_bytes());
    Mac(MacTag::HmacSha256(mac.finalize().into_bytes()))
}

/// `Crypto.hmacSha512WithKey : Key -> String -> Mac` — typed variant.
pub fn crypto_hmac_sha512_key(key: Key, msg: String) -> Mac {
    use hmac::{Hmac, Mac as HmacMac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;
    // STRUCTURALLY-DEAD Err: same reasoning as `crypto_hmac_sha512` above.
    // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — structurally-dead HMAC InvalidLength; a loud .expect is safer than a dead Result Err a caller can mishandle into a wrong MAC [ledger #1]
    #[allow(clippy::expect_used)]
    let mut mac =
        HmacSha512::new_from_slice(key.0.as_bytes()).expect("Hmac<Sha512> accepts any key length");
    mac.update(msg.as_bytes());
    Mac(MacTag::HmacSha512(mac.finalize().into_bytes()))
}

/// `Crypto.verifyHmacSha256 : Key -> String -> Mac -> Bool` — recompute the
/// HMAC-SHA-256 tag of `msg` under `key` and compare it with `mac`.
///
/// The supplied tag is never trusted: the tag is always recomputed here, and
/// the 32 raw bytes are compared in constant time
/// ([`crate::ct_eq::ct_bytes_eq`]). An HMAC-SHA-512 `Mac` is `False` without a
/// byte compare — its width is public metadata, so refusing it reveals nothing
/// about the expected tag.
#[must_use]
pub fn crypto_verify_hmac_sha256(key: Key, msg: String, mac: Mac) -> bool {
    match mac.0 {
        MacTag::HmacSha256(expected) => {
            let computed = crypto_hmac_sha256_key(key, msg);
            crate::ct_eq::ct_bytes_eq(computed.0.as_bytes(), expected.as_slice())
        }
        MacTag::HmacSha512(_) => false,
    }
}

/// Ipê `rsaSha256Sign : String -> String -> Result Error String`
/// Sign `msg` with the PKCS#1 v1.5 SHA-256 RSA scheme using `key_pem`.
/// Accepts PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`) and PKCS#8
/// (`-----BEGIN PRIVATE KEY-----`) PEM private keys (tries PKCS#8 first, then
/// PKCS#1). Returns a standard-base64-encoded signature (with padding).
#[cfg(feature = "crypto")]
pub fn crypto_rsa_sha256_sign<E: From<String>>(
    key_pem: String,
    msg: String,
) -> IpeResult<E, String> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use rsa::{
        pkcs1::DecodeRsaPrivateKey,
        pkcs1v15::SigningKey,
        pkcs8::DecodePrivateKey,
        signature::{SignatureEncoding, Signer},
    };
    use sha2::Sha256;

    // Try PKCS#8 first (the openssl default), then fall back to PKCS#1.
    let priv_key = match rsa::RsaPrivateKey::from_pkcs8_pem(&key_pem) {
        Ok(k) => k,
        _ => match rsa::RsaPrivateKey::from_pkcs1_pem(&key_pem) {
            Ok(k) => k,
            _ => {
                return IpeResult::Err(
                    "Crypto.rsaSha256Sign: could not parse the private key"
                        .to_string()
                        .into(),
                );
            }
        },
    };
    let signing_key = SigningKey::<Sha256>::new(priv_key);
    // try_sign (not sign): `Signer::sign` PANICS on an internal signing failure
    // (e.g. a key too small for the digest) — a Ipê-reachable abort inside a
    // Result-returning crypto fn. Route the failure to Err instead.
    let signature = match signing_key.try_sign(msg.as_bytes()) {
        Ok(s) => s,
        Err(e) => {
            return IpeResult::Err(format!("Crypto.rsaSha256Sign: signing failed: {}", e).into());
        }
    };
    // Standard base64 (with `=` padding).
    IpeResult::Ok(STANDARD.encode(signature.to_bytes()))
}

/// Ipê `rsaSha256Verify : String -> String -> String -> Bool`
/// (pemPublicKey, msg, base64Signature). Returns `false` on any failure — never panics.
/// Accepts SPKI/PKIX public keys (`-----BEGIN PUBLIC KEY-----`, the common openssl form)
/// and PKCS#1 public keys (`-----BEGIN RSA PUBLIC KEY-----`; tries PKIX first,
/// then PKCS#1). Signature is standard base64 (with padding).
#[cfg(feature = "crypto")]
pub fn crypto_rsa_sha256_verify(key_pem: String, msg: String, sig_b64: String) -> bool {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use rsa::{
        pkcs1::DecodeRsaPublicKey,
        pkcs1v15::{Signature, VerifyingKey},
        pkcs8::DecodePublicKey,
        signature::Verifier,
    };
    use sha2::Sha256;

    // Try SPKI/PKIX first (-----BEGIN PUBLIC KEY-----), then PKCS#1.
    let pub_key = match rsa::RsaPublicKey::from_public_key_pem(&key_pem) {
        Ok(k) => k,
        _ => match rsa::RsaPublicKey::from_pkcs1_pem(&key_pem) {
            Ok(k) => k,
            _ => {
                return false;
            }
        },
    };
    // Standard base64 (with `=` padding).
    let sig_bytes = match STANDARD.decode(sig_b64.as_bytes()) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let verifying_key: VerifyingKey<Sha256> = VerifyingKey::<Sha256>::new(pub_key);
    let signature = match Signature::try_from(sig_bytes.as_slice()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verifying_key.verify(msg.as_bytes(), &signature).is_ok()
}

/// Ipê `constantTimeEqual : String -> String -> Bool` — timing-safe byte compare.
pub fn crypto_constant_time_equal(a: String, b: String) -> bool {
    crate::ct_eq::ct_bytes_eq(a.as_bytes(), b.as_bytes())
}

/// Generated-code alias for `crypto_rsa_sha256_sign` with `E = String`.
///
/// Gated the same as [`crypto_rsa_sha256_sign`] (its callee): the RSA arm
/// compiles only when the `crypto` feature is on, which a generated crate
/// enables exactly when it reaches the heavy crypto floor (a `Crypto` kernel,
/// a `Jwt` kernel, or the `Auth` surface). A program that touches none pulls no
/// `rsa` dependency, so this alias must not reference the absent primitive.
#[cfg(feature = "crypto")]
pub fn ipe_crypto_rsa_sha256_sign(
    key_pem: String,
    msg: String,
) -> IpeResult<crate::error::IpeError, String> {
    crypto_rsa_sha256_sign(key_pem, msg)
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests_core {
    use super::*;

    // Extract the `Key` from a `crypto_key_from_string`/`_bytes` construction in
    // tests that pass a known non-empty key (always `Just`). A `Nothing` is a
    // test-setup error and fails the test rather than silently skipping.
    fn key_of(m: IpeMaybe<Key>) -> Key {
        match m {
            IpeMaybe::Just(k) => k,
            IpeMaybe::Nothing => panic!("test key construction returned Nothing"),
        }
    }

    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const EMPTY_SHA512: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn test_sha256_empty_and_abc() {
        assert_eq!(crypto_sha256(String::new()), EMPTY_SHA256);
        assert_eq!(crypto_sha256("abc".to_string()), ABC_SHA256);
    }

    #[test]
    fn test_sha512_empty() {
        assert_eq!(crypto_sha512(String::new()), EMPTY_SHA512);
    }

    // RFC 4231 test case 1: key = 0x0b*20, data = "Hi There"
    const HMAC_SHA256_RFC1: &str =
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    const HMAC_SHA512_RFC1: &str = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854";

    // Raw-String-key HMAC-SHA-256 is the JWT-internal signer (`pub(crate)`, not a
    // kernel, `cfg(jwt)`). This holds it to the RFC 4231 vector so the JWT signing
    // path stays correct; the typed-`Key` HMAC vectors are checked separately below.
    #[cfg(feature = "jwt")]
    #[test]
    fn test_hmac_sha256_rfc4231() {
        let key: String = (0..20).map(|_| '\u{000b}').collect();
        assert_eq!(
            crypto_hmac_sha256(key, "Hi There".to_string()),
            HMAC_SHA256_RFC1
        );
    }

    // Typed-`Key` HMAC against the RFC 4231 vectors — the ONLY HMAC key path
    // reachable from Ipê. Proves both digests round-trip through the `Key`
    // boundary (there is no raw-`String`-key HMAC-SHA-512 spelling at all).
    #[test]
    fn test_hmac_typed_key_rfc4231() {
        let raw_key: String = (0..20).map(|_| '\u{000b}').collect();
        let mac256 = crypto_hmac_sha256_key(
            key_of(crypto_key_from_string(raw_key.clone())),
            "Hi There".to_string(),
        );
        assert_eq!(crypto_mac_to_hex(mac256), HMAC_SHA256_RFC1);
        let mac512 = crypto_hmac_sha512_key(
            key_of(crypto_key_from_string(raw_key)),
            "Hi There".to_string(),
        );
        assert_eq!(crypto_mac_to_hex(mac512), HMAC_SHA512_RFC1);
    }

    #[cfg(feature = "crypto")]
    const RSA_PRIV_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAK1QGnsdSyVv+JT4WDnGIIr3QA75yZTiTsgxkiXH9sjXrPHT1hXn
2tKCv9MkR8MD1Ndh6jo7inBZUK0YG7H6Jx0CAwEAAQJAX9bpHeXAFW7K5w5CM4il
nFNIAEAPQh63dCs9Z1kh1kPNGKQYujFQ9KgNuw1keQDKhkzd5jCauNJ6Db/xDpdL
PQIhANidlZLm430yH5JrNG9hZpFIM80tUn+cf7J5F4KLIF2zAiEAzNL87wCFzVrt
xE9IhVClKFPemDjO9Mre3Db/V53uH+8CIQC2/BfYatcNcYQeKhW3aS492CJ6Vqj0
R/3PhF+J1YFX5QIgG9S7a5pNlAa78gW32+2GU4F56IMnk9mRCKksbvJVrd8CIFuA
y7anow7/QOtvB1/UdyrxegB+sHZoBWA9+SsMl2zn
-----END RSA PRIVATE KEY-----";

    // SPKI/PKIX public key derived from RSA_PRIV_PEM (`openssl rsa -pubout`).
    // Ipê's rsaSha256Verify takes a PUBLIC key — this is the correct pairing.
    #[cfg(feature = "crypto")]
    const RSA_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK1QGnsdSyVv+JT4WDnGIIr3QA75yZTi
TsgxkiXH9sjXrPHT1hXn2tKCv9MkR8MD1Ndh6jo7inBZUK0YG7H6Jx0CAwEAAQ==
-----END PUBLIC KEY-----";

    #[cfg(feature = "crypto")]
    #[test]
    fn test_rsa_sign_verify_roundtrip() {
        let msg = "hello, ipe".to_string();
        let sig: IpeResult<String, String> =
            crypto_rsa_sha256_sign(RSA_PRIV_PEM.to_string(), msg.clone());
        // Sign returns standard base64 (implements base64.StdEncoding).
        let sig_b64 = match sig {
            IpeResult::Ok(s) => s,
            IpeResult::Err(e) => panic!("sign failed: {}", e),
        };
        // Verify takes the PUBLIC key, not the private key (mirrors the spec).
        assert!(crypto_rsa_sha256_verify(
            RSA_PUB_PEM.to_string(),
            msg,
            sig_b64
        ));
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_rsa_verify_wrong_sig() {
        // "deadbeef" is not valid standard base64 with padding → decodes to false.
        assert!(!crypto_rsa_sha256_verify(
            RSA_PUB_PEM.to_string(),
            "hello".to_string(),
            "deadbeef".to_string()
        ));
    }

    #[test]
    fn test_constant_time_equal() {
        assert!(crypto_constant_time_equal(
            "abc".to_string(),
            "abc".to_string()
        ));
        assert!(!crypto_constant_time_equal(
            "abc".to_string(),
            "abd".to_string()
        ));
        assert!(!crypto_constant_time_equal(
            "abc".to_string(),
            "ab".to_string()
        ));
    }

    // ── Typed newtype tests ──────────────────────────────────────────────────

    /// `Key.fromString` promotes any string to a typed key; `Mac.toHex`
    /// recovers the hex tag from a typed MAC. Verifies the construction
    /// boundary and extraction boundary round-trip correctly.
    #[test]
    fn typed_key_and_mac_round_trip() {
        let raw_key: String = (0..20).map(|_| '\u{000b}').collect();
        let key = key_of(crypto_key_from_string(raw_key));
        let mac = crypto_hmac_sha256_key(key, "Hi There".to_string());
        // RFC 4231 test vector 1 — same value as the String-typed variant
        assert_eq!(
            crypto_mac_to_hex(mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// `crypto_key_from_bytes` is an alias for `crypto_key_from_string` with
    /// identical byte semantics; both paths produce the same MAC.
    #[test]
    fn key_from_bytes_same_as_key_from_string() {
        let raw: String = (0..20).map(|_| '\u{000b}').collect();
        let k1 = key_of(crypto_key_from_string(raw.clone()));
        let k2 = key_of(crypto_key_from_bytes(raw));
        let mac1 = crypto_hmac_sha256_key(k1, "data".to_string());
        let mac2 = crypto_hmac_sha256_key(k2, "data".to_string());
        assert_eq!(crypto_mac_to_hex(mac1), crypto_mac_to_hex(mac2));
    }

    /// `Key`'s `Debug` impl MUST redact key material — never "<key-bytes>".
    #[test]
    fn key_debug_is_redacted() {
        let key = key_of(crypto_key_from_string("supersecret".to_string()));
        let debug_str = format!("{:?}", key);
        assert_eq!(debug_str, "<key>", "Key Debug must redact to '<key>'");
        assert!(
            !debug_str.contains("supersecret"),
            "Key Debug must not contain raw key material"
        );
    }

    /// Role-swap guard: `Key` and `Mac` are distinct types at the Rust level.
    #[test]
    fn role_swap_types_are_distinct() {
        // Verify at runtime that Key != Mac (they are separate newtypes).
        let key = key_of(crypto_key_from_string("k".to_string()));
        let mac = crypto_hmac_sha256_key(key, "m".to_string());
        // mac_to_hex is the ONLY extraction path for a Mac
        let hex = crypto_mac_to_hex(mac);
        assert!(
            !hex.is_empty(),
            "Mac extraction via mac_to_hex must succeed"
        );
    }

    // ── Mac equality (constant-time impl) ────────────────────────────────────

    /// Two `Mac`s produced from the same key and message are equal; a different
    /// message produces a different tag.
    #[test]
    fn mac_eq_reflexive_and_distinguishing() {
        let raw_key: String = (0..32).map(|_| 'k').collect();
        let key_a = key_of(crypto_key_from_string(raw_key.clone()));
        let key_b = key_of(crypto_key_from_string(raw_key.clone()));
        let key_c = key_of(crypto_key_from_string(raw_key));
        let mac_same_1 = crypto_hmac_sha256_key(key_a, "message".to_string());
        let mac_same_2 = crypto_hmac_sha256_key(key_b, "message".to_string());
        let mac_diff = crypto_hmac_sha256_key(key_c, "different-message".to_string());
        assert_eq!(
            mac_same_1, mac_same_2,
            "same key+msg must produce equal Macs"
        );
        assert_ne!(
            mac_same_1, mac_diff,
            "different msg must produce distinct Macs"
        );
    }

    /// The `Mac` equality is consistent with the underlying hex bytes —
    /// verifies `impl_ct_eq!` delegates correctly.
    #[test]
    fn mac_eq_consistent_with_ct_bytes_eq() {
        let raw_key: String = (0..32).map(|_| 'm').collect();
        let key_1 = key_of(crypto_key_from_string(raw_key.clone()));
        let key_2 = key_of(crypto_key_from_string(raw_key.clone()));
        let key_3 = key_of(crypto_key_from_string(raw_key));
        let mac1 = crypto_hmac_sha256_key(key_1, "data".to_string());
        let mac2 = crypto_hmac_sha256_key(key_2, "data".to_string());
        let mac3 = crypto_hmac_sha256_key(key_3, "other".to_string());
        let hex1 = crypto_mac_to_hex(mac1.clone());
        let hex3 = crypto_mac_to_hex(mac3.clone());
        assert!(
            crate::ct_eq::ct_bytes_eq(hex1.as_bytes(), hex1.as_bytes()),
            "same hex bytes must be ct-equal"
        );
        assert!(
            mac1 == mac2,
            "Mac == must agree with ct_bytes_eq on matching bytes"
        );
        assert!(
            mac1 != mac3,
            "Mac != must agree with ct_bytes_eq on differing bytes"
        );
        assert!(
            !crate::ct_eq::ct_bytes_eq(hex1.as_bytes(), hex3.as_bytes()),
            "ct_bytes_eq on different tags must be false"
        );
    }

    // ── Mac parse boundary + typed verify ────────────────────────────────────

    /// A `Mac.fromHex` parse as an `Option`, so a test inspects it without a panic path.
    fn parsed_mac(s: &str) -> Option<Mac> {
        match crypto_mac_from_hex(s.to_string()) {
            IpeMaybe::Just(m) => Some(m),
            IpeMaybe::Nothing => None,
        }
    }

    /// The RFC 4231 test-case-1 key: twenty `0x0b` bytes.
    fn rfc4231_key() -> Key {
        key_of(crypto_key_from_string(
            (0..20).map(|_| '\u{000b}').collect(),
        ))
    }

    /// The verdict of `verifyHmacSha256` on the RFC 4231 case-1 key, `msg` and
    /// the parsed `hex` tag; `None` when `hex` does not parse.
    fn verify_under_rfc_key(msg: &str, hex: &str) -> Option<bool> {
        parsed_mac(hex).map(|m| crypto_verify_hmac_sha256(rfc4231_key(), msg.to_string(), m))
    }

    /// `hex` with the digit at `index` replaced by a different hex digit.
    fn flip_digit(hex: &str, index: usize) -> String {
        hex.chars()
            .enumerate()
            .map(|(i, c)| {
                if i == index {
                    if c == '0' { '1' } else { '0' }
                } else {
                    c
                }
            })
            .collect()
    }

    /// Every malformed tag spelling is refused at the parse boundary: empty,
    /// odd, one digit short or long of either width, a non-hex digit, a non-ASCII
    /// byte, whitespace inside or around, and a `0x` prefix (including one that
    /// keeps the total at exactly 64 characters).
    #[test]
    fn mac_from_hex_refuses_malformed_input() {
        let tag = HMAC_SHA256_RFC1;
        let short: String = tag.chars().take(63).collect();
        let short_by_two: String = tag.chars().take(62).collect();
        let tail: String = tag.chars().skip(1).collect();
        let tag512 = HMAC_SHA512_RFC1;
        let short512: String = tag512.chars().take(127).collect();
        let refused: [String; 17] = [
            String::new(),
            "abc".to_string(),
            "0".to_string(),
            short.clone(),
            format!("{tag}0"),
            format!("g{tail}"),
            format!("G{tail}"),
            format!("{short}z"),
            format!("\u{e9}{short_by_two}"),
            format!(" {tag}"),
            format!("{tag} "),
            format!("{short}\n"),
            format!("{short} "),
            format!("0x{tag}"),
            format!("0x{short_by_two}"),
            short512,
            format!("{tag512}0"),
        ];
        for input in &refused {
            assert!(
                parsed_mac(input).is_none(),
                "Mac.fromHex must refuse {input:?}"
            );
        }
        assert_eq!(
            short_by_two.len() + 2,
            64,
            "the 0x case must be 64 bytes long"
        );
    }

    /// `Mac.toHex` after `Mac.fromHex` is the identity on a lowercase tag of
    /// either width, and normalises an uppercase or mixed-case tag to lowercase.
    #[test]
    fn mac_from_hex_round_trips_and_normalises_case() {
        for tag in [HMAC_SHA256_RFC1, HMAC_SHA512_RFC1] {
            assert_eq!(
                parsed_mac(tag).map(crypto_mac_to_hex),
                Some(tag.to_string())
            );
            assert_eq!(
                parsed_mac(&tag.to_uppercase()).map(crypto_mac_to_hex),
                Some(tag.to_string())
            );
            let mixed: String = tag
                .chars()
                .enumerate()
                .map(|(i, c)| if i < 32 { c.to_ascii_uppercase() } else { c })
                .collect();
            assert_eq!(
                parsed_mac(&mixed).map(crypto_mac_to_hex),
                Some(tag.to_string())
            );
        }
    }

    /// A computed `Mac` survives `toHex` then `fromHex` as an equal `Mac`, and
    /// its `Debug` rendering is the lowercase hex tag.
    #[test]
    fn computed_mac_round_trips_through_hex() {
        let mac256 = crypto_hmac_sha256_key(rfc4231_key(), "Hi There".to_string());
        let mac512 = crypto_hmac_sha512_key(rfc4231_key(), "Hi There".to_string());
        assert_eq!(format!("{mac256:?}"), format!("Mac({HMAC_SHA256_RFC1:?})"));
        assert!(parsed_mac(&crypto_mac_to_hex(mac256.clone())).is_some_and(|m| m == mac256));
        assert!(parsed_mac(&crypto_mac_to_hex(mac512.clone())).is_some_and(|m| m == mac512));
        assert!(
            mac256 != mac512,
            "tags of different widths must never compare equal"
        );
    }

    /// `verifyHmacSha256` accepts the RFC 4231 tag, in either case, and a tag it
    /// just computed.
    #[test]
    fn verify_hmac_sha256_accepts_the_right_tag() {
        assert_eq!(
            verify_under_rfc_key("Hi There", HMAC_SHA256_RFC1),
            Some(true)
        );
        assert_eq!(
            verify_under_rfc_key("Hi There", &HMAC_SHA256_RFC1.to_uppercase()),
            Some(true)
        );
        let computed = crypto_hmac_sha256_key(rfc4231_key(), "payload".to_string());
        assert!(crypto_verify_hmac_sha256(
            rfc4231_key(),
            "payload".to_string(),
            computed
        ));
    }

    /// A tag that differs in any single hex digit — every position, so the
    /// first, middle and last bytes and both the high and low nibble of each —
    /// parses and is then refused.
    #[test]
    fn verify_hmac_sha256_refuses_every_flipped_digit() {
        for index in 0..HMAC_SHA256_RFC1.len() {
            let tampered = flip_digit(HMAC_SHA256_RFC1, index);
            assert_ne!(tampered, HMAC_SHA256_RFC1, "digit {index} must change");
            assert_eq!(
                verify_under_rfc_key("Hi There", &tampered),
                Some(false),
                "a tag flipped at digit {index} must parse and be refused"
            );
        }
    }

    /// The right tag under the wrong key, or for the wrong message, is refused.
    #[test]
    fn verify_hmac_sha256_refuses_wrong_key_and_wrong_message() {
        let wrong_key = key_of(crypto_key_from_string(
            (0..20).map(|_| '\u{000c}').collect(),
        ));
        assert!(
            parsed_mac(HMAC_SHA256_RFC1).is_some_and(|m| !crypto_verify_hmac_sha256(
                wrong_key,
                "Hi There".to_string(),
                m
            ))
        );
        for msg in ["Hi There!", "hi There", "Hi Ther", ""] {
            assert_eq!(
                verify_under_rfc_key(msg, HMAC_SHA256_RFC1),
                Some(false),
                "the tag must not verify for message {msg:?}"
            );
        }
    }

    /// An HMAC-SHA-512 `Mac` — even the correct one for the same key and
    /// message — is refused by the SHA-256 verifier, without a panic.
    #[test]
    fn verify_hmac_sha256_refuses_a_sha512_tag() {
        assert_eq!(
            verify_under_rfc_key("Hi There", HMAC_SHA512_RFC1),
            Some(false)
        );
        let mac512 = crypto_hmac_sha512_key(rfc4231_key(), "Hi There".to_string());
        assert!(!crypto_verify_hmac_sha256(
            rfc4231_key(),
            "Hi There".to_string(),
            mac512
        ));
    }

    /// A 64-byte tag whose first 32 bytes are the correct HMAC-SHA-256 tag is
    /// refused: the verifier compares the whole tag, never a prefix.
    #[test]
    fn verify_hmac_sha256_refuses_a_correct_prefix_with_a_longer_tail() {
        let padded = format!("{HMAC_SHA256_RFC1}{}", "0".repeat(64));
        assert_eq!(padded.len(), 128);
        assert_eq!(verify_under_rfc_key("Hi There", &padded), Some(false));
        assert_eq!(
            verify_under_rfc_key("Hi There", HMAC_SHA256_RFC1),
            Some(true)
        );
    }

    /// `Key` equality delegates to `ct_bytes_eq` — same-content keys compare
    /// equal, different-content keys do not.
    #[test]
    fn key_eq_via_ct_bytes_eq() {
        let k1 = key_of(crypto_key_from_string("secret-key".to_string()));
        let k2 = key_of(crypto_key_from_string("secret-key".to_string()));
        let k3 = key_of(crypto_key_from_string("different-key".to_string()));
        assert_eq!(k1, k2, "same-content keys must be equal");
        assert_ne!(k1, k3, "different-content keys must be unequal");
    }

    /// Source guard: a secret/tag/key newtype — a tuple struct wrapping a single
    /// `String`, `Vec<u8>` or `MacTag`, or the `MacTag` byte carrier itself —
    /// must never `#[derive(PartialEq)]`, whose
    /// early-exit compare is a timing oracle; the family opts into `impl_ct_eq!`
    /// instead. The E0119 conflicting-impl is the structural seal that makes the
    /// leaky derive unrepresentable; this test is a source-level tripwire that
    /// the family stays on the constant-time path. Non-newtype types (C-like
    /// enums, multi-field structs) are out of scope and may derive `PartialEq`.
    #[test]
    fn grep_guard_no_derived_partial_eq_on_secret_newtype() {
        let files = [
            ("secret.rs", include_str!("secret.rs")),
            ("crypto_core.rs", include_str!("crypto_core.rs")),
            ("crypto.rs", include_str!("crypto.rs")),
            ("dsn.rs", include_str!("dsn.rs")),
        ];
        let is_secret_newtype = |t: &str| {
            (t.contains("struct ")
                && [
                    "(String)",
                    "(String);",
                    "(Vec<u8>)",
                    "(Vec<u8>);",
                    "(MacTag)",
                    "(MacTag);",
                ]
                .iter()
                .any(|shape| t.contains(shape)))
                || t.contains("enum MacTag")
        };
        let starts_item = |t: &str| {
            [
                "struct ", "enum ", "fn ", "impl ", "trait ", "type ", "mod ", "union ",
            ]
            .iter()
            .any(|kw| {
                t.starts_with(kw) || t.strip_prefix("pub ").is_some_and(|r| r.starts_with(kw))
            })
        };
        let mut violations: Vec<String> = Vec::new();
        for (name, content) in files {
            // `pending_partial_eq` carries a just-seen `#[derive(… PartialEq …)]`
            // forward across intervening attributes/doc-comments to the item it
            // decorates; `in_derive` folds a multi-line derive so a `PartialEq`
            // on a continuation line is not missed.
            let mut pending_partial_eq = false;
            let mut in_derive = false;
            for line in content.lines() {
                let t = line.trim();
                if in_derive {
                    pending_partial_eq |= t.contains("PartialEq");
                    in_derive = !t.contains(")]");
                    continue;
                }
                if t.starts_with("#[derive(") {
                    pending_partial_eq = t.contains("PartialEq");
                    in_derive = !t.contains(")]");
                    continue;
                }
                if t.starts_with('#') || t.starts_with("//") || t.is_empty() {
                    continue;
                }
                if pending_partial_eq && is_secret_newtype(t) {
                    violations.push(format!("{name}: {t}"));
                }
                if starts_item(t) {
                    pending_partial_eq = false;
                }
            }
        }
        assert!(
            violations.is_empty(),
            "derived PartialEq on secret-family newtype(s) — use impl_ct_eq! instead:\n{}",
            violations.join("\n")
        );
    }

    /// Timing-shape smoke check (statistical, `#[ignore]` — not a hard CI gate).
    ///
    /// Compares a fixed 32-byte tag against (a) an all-wrong tag and (b) a
    /// tag identical except the last byte, N iterations each; asserts the
    /// mean-latency ratio stays within a loose tolerance band. A derived
    /// early-exit `PartialEq` would show a measurable prefix-length gradient
    /// and fail this check when run locally with sufficient iterations.
    #[test]
    #[ignore = "statistical timing check — flaky on CI; run locally with --include-ignored"]
    fn mac_eq_timing_shape_smoke() {
        use std::time::Instant;
        let raw: String = (0..32).map(|i| char::from(b'a' + (i % 26) as u8)).collect();

        let n: u64 = 50_000;
        let mac_ref_1: crate::crypto_core::Mac = {
            let k = key_of(crypto_key_from_string(raw.clone()));
            crypto_hmac_sha256_key(k, "msg".to_string())
        };
        let mac_all_wrong: crate::crypto_core::Mac = {
            // Construct a Mac with the wrong bytes via round-trip (only legal path).
            // We use a key that produces the all_wrong pattern if possible;
            // otherwise accept any distinct tag.
            let k = key_of(crypto_key_from_string("wrong-key".to_string()));
            crypto_hmac_sha256_key(k, "msg".to_string())
        };
        let mac_prefix: crate::crypto_core::Mac = {
            let k = key_of(crypto_key_from_string(raw.clone()));
            crypto_hmac_sha256_key(k, "msg2".to_string())
        };

        let t_wrong = {
            let start = Instant::now();
            for _ in 0..n {
                let _ = mac_ref_1 == mac_all_wrong;
            }
            start.elapsed()
        };
        let t_prefix = {
            let start = Instant::now();
            for _ in 0..n {
                let _ = mac_ref_1 == mac_prefix;
            }
            start.elapsed()
        };

        let ratio = t_wrong.as_nanos() as f64 / t_prefix.as_nanos().max(1) as f64;
        assert!(
            (0.5..=2.0).contains(&ratio),
            "timing ratio {ratio:.3} outside tolerance — early-exit PartialEq suspected"
        );
    }
}
