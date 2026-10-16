// Crypto heavy primitives — the gated, rarely-used cryptography.
//
// This module holds the legacy checksum hashes (SHA-1/MD5), the symmetric AEAD
// ciphers (AES-256-GCM + ChaCha20-Poly1305) and the PBKDF2 password-key
// derivation — each pulling a crate used nowhere else (`sha1`, `md-5`,
// `aes-gcm`, `chacha20poly1305`, `pbkdf2`). The crypto floor — the entropy
// pair, the SHA-2 hash/HMAC family, the RSA sign/verify pair, the typed
// `Key`/`Mac` newtypes and the constant-time compare — lives in the sibling
// `crypto_core` module and is re-exported here, so every `crypto::…` path
// (including the ones the kernel-wrapper prelude and generated user code name)
// keeps resolving unchanged.
//
// wasm32: every function in THIS file is individually `cfg(not(target_arch =
// "wasm32"))` (a stated M4 exclusion, same class as the M0 floor's
// crypto-feature exclusion: untested browser entropy support across the whole
// RustCrypto stack, and no browser-bundle reason to pull
// `aes-gcm`/`chacha20poly1305`/`pbkdf2` for symmetric AEAD that isn't in the M4
// scope). `Ipe.Crypto.aesGcmEncrypt`/friends therefore stay UNTAGGED in the
// `WasmClient` kernel registry — the wrapper is compiled out entirely, not
// merely unreachable.
use super::*;

// The cryptographic floor (`crypto_core`) is re-exported through this
// module so every `crypto::…` path — the kernel-wrapper prelude's
// `crypto_random_bytes`/`crypto_random_token`, `jwt`'s
// `crypto_hmac_sha256`/`crypto_rsa_sha256_sign` reaches, and generated user
// code naming `crypto::Key`/`crypto::Mac` — resolves regardless of this split.
pub use crate::crypto_core::*;

/// SECURITY (parity-locked): `sha1` and `md5` below are COLLISION-BROKEN and are
/// exposed ONLY as named checksum/interop hashes, matching the
/// surface. They MUST NOT be used as a security primitive (password hashing,
/// signatures, integrity against an adversary) — those paths use SHA-256/512 +
/// HMAC + bcrypt/PBKDF2 elsewhere in this module. Removing them would break
/// parity; the hardening is this contract note. (Audit finding: low/weak-crypto.)
///
/// Ipê `sha1 : String -> String` — hex-encoded SHA-1 digest.
#[cfg(not(target_arch = "wasm32"))]
pub fn crypto_sha1(s: String) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

/// Ipê `md5 : String -> String` — hex-encoded MD5 digest.
#[cfg(not(target_arch = "wasm32"))]
pub fn crypto_md5(s: String) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

// ═══════════════════════════════════════════════════════════
// Symmetric AEAD — AES-256-GCM + ChaCha20-Poly1305
// ═══════════════════════════════════════════════════════════
//
// Output format // tag[16] ) — a single opaque UTF-8 string. The 32-byte KEY, however, is
// base64-encoded here (raw bytes internally). Keys are opaque and
// never cross the backend boundary, so this backend-local encoding is sound and
// is what lets a PBKDF2-derived key (arbitrary bytes) live in a Rust `String`
// (which must be valid UTF-8). aesKeyFromPassword emits the base64 form; the
// AEAD fns base64-decode it back to 32 raw bytes.

#[cfg(not(target_arch = "wasm32"))]
const AEAD_KEY_BYTES: usize = 32;
// PBKDF2-HMAC-SHA256 work factor. PINNED to the  value: a
// password-derived key/blob produced on one backend must verify/decrypt on the
// other, so this is a cross-backend interop contract, NOT a Rust-local knob.
// It is below current OWASP guidance (≈600k for PBKDF2-SHA256); raising it is a
// COORDINATED cross-backend migration (re-derive + re-encrypt existing data),
// not a unilateral Rust change. (Audit finding: low/weak-crypto — accepted,
// parity/key-compat-locked.)
#[cfg(not(target_arch = "wasm32"))]
const PBKDF2_ITERS: u32 = 100_000;

// Decode a base64 key string to exactly 32 bytes, or an error message.
#[cfg(not(target_arch = "wasm32"))]
fn aead_read_key(name: &str, key: &str) -> Result<Vec<u8>, String> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let k = STANDARD.decode(key.as_bytes()).map_err(|_| {
        format!(
            "{}: key must be a 32-byte key from Crypto.aesKeyFromPassword",
            name
        )
    })?;
    if k.len() != AEAD_KEY_BYTES {
        return Err(format!(
            "{}: key must be {} bytes, got {} (derive via Crypto.aesKeyFromPassword)",
            name,
            AEAD_KEY_BYTES,
            k.len()
        ));
    }
    Ok(k)
}

// Crypto.aesGcmEncrypt : Key -> String -> Result Error String  (typed key)
#[cfg(not(target_arch = "wasm32"))]
pub fn crypto_aes_gcm_encrypt_key<E: From<String> + FromUnavailable>(
    key: Key,
    plaintext: String,
) -> IpeResult<E, String> {
    crypto_aes_gcm_encrypt(crate::crypto_core::crypto_key_reveal(key), plaintext)
}

// Crypto.aesGcmDecrypt : Key -> String -> Result Error String  (typed key)
#[cfg(not(target_arch = "wasm32"))]
pub fn crypto_aes_gcm_decrypt_key<E: From<String>>(
    key: Key,
    encoded: String,
) -> IpeResult<E, String> {
    crypto_aes_gcm_decrypt(crate::crypto_core::crypto_key_reveal(key), encoded)
}

// Internal String-keyed AES-256-GCM core — `pub(crate)`, reached only through the
// typed `crypto_aes_gcm_encrypt_key` wrapper (which unwraps a `Key`). Not a public
// runtime API and not a kernel: the raw-String-key path cannot be reached from Ipê
// source or from outside this crate, so no caller can supply untyped key material.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn crypto_aes_gcm_encrypt<E: From<String> + FromUnavailable>(
    key: String,
    plaintext: String,
) -> IpeResult<E, String> {
    crypto_aes_gcm_encrypt_with(crate::entropy::fill_entropy, key, plaintext)
}

/// [`crypto_aes_gcm_encrypt`] drawing its 12-byte nonce from `fill`.
///
/// A refused draw produces no ciphertext and fails with kind `Unavailable`.
#[cfg(not(target_arch = "wasm32"))]
fn crypto_aes_gcm_encrypt_with<E: From<String> + FromUnavailable>(
    fill: impl FnOnce(&mut [u8]) -> Result<(), crate::entropy::EntropyError>,
    key: String,
    plaintext: String,
) -> IpeResult<E, String> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    use base64::{Engine, engine::general_purpose::STANDARD};
    let k = match aead_read_key("Crypto.aesGcmEncrypt", &key) {
        Ok(k) => k,
        Err(e) => return IpeResult::Err(e.into()),
    };
    // aead_read_key validated len == 32 just above, so the Err is structurally
    // unreachable — but propagate into the existing IpeResult channel rather than panic.
    let cipher = match Aes256Gcm::new_from_slice(&k) {
        Ok(c) => c,
        Err(e) => return IpeResult::Err(format!("Crypto.aesGcmEncrypt: {}", e).into()),
    };
    let mut nonce_bytes = [0u8; 12];
    if fill(&mut nonce_bytes).is_err() {
        return IpeResult::Err(E::from_unavailable(
            "Crypto.aesGcmEncrypt: the OS random source is unavailable".to_owned(),
        ));
    }
    let nonce = Nonce::from_slice(&nonce_bytes);
    match cipher.encrypt(nonce, plaintext.as_bytes()) {
        Ok(ct) => {
            let mut out = nonce_bytes.to_vec();
            out.extend_from_slice(&ct);
            IpeResult::Ok(STANDARD.encode(out))
        }
        Err(e) => IpeResult::Err(format!("Crypto.aesGcmEncrypt: {}", e).into()),
    }
}

// Internal String-keyed AES-256-GCM core — `pub(crate)`, reached only through the
// typed `crypto_aes_gcm_decrypt_key` wrapper. No bare-String-key path escapes the crate.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn crypto_aes_gcm_decrypt<E: From<String>>(
    key: String,
    encoded: String,
) -> IpeResult<E, String> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    use base64::{Engine, engine::general_purpose::STANDARD};
    let k = match aead_read_key("Crypto.aesGcmDecrypt", &key) {
        Ok(k) => k,
        Err(e) => return IpeResult::Err(e.into()),
    };
    let buf = match STANDARD.decode(encoded.as_bytes()) {
        Ok(b) => b,
        Err(e) => {
            return IpeResult::Err(format!("Crypto.aesGcmDecrypt: invalid base64: {}", e).into());
        }
    };
    if buf.len() < 12 {
        return IpeResult::Err(
            "Crypto.aesGcmDecrypt: ciphertext too short"
                .to_string()
                .into(),
        );
    }
    let (nonce_bytes, ct) = buf.split_at(12);
    let cipher = match Aes256Gcm::new_from_slice(&k) {
        Ok(c) => c,
        Err(e) => return IpeResult::Err(format!("Crypto.aesGcmDecrypt: {}", e).into()),
    };
    match cipher.decrypt(Nonce::from_slice(nonce_bytes), ct) {
        // A Ipê String is UTF-8 by construction.  oracle returns string(pt)
        // , but lossy-replacing invalid UTF-8 here
        // would silently corrupt the plaintext. Reject non-UTF-8 plaintext with a
        // structured Err instead — total, and surfaces the mismatch at the boundary.
        Ok(pt) => match String::from_utf8(pt) {
            Ok(s) => IpeResult::Ok(s),
            Err(_) => IpeResult::Err(
                "Crypto.aesGcmDecrypt: decrypted plaintext is not valid UTF-8"
                    .to_string()
                    .into(),
            ),
        },
        Err(e) => IpeResult::Err(format!("Crypto.aesGcmDecrypt: {}", e).into()),
    }
}

// Crypto.chacha20Encrypt : Key -> String -> Result Error String  (typed key)
#[cfg(not(target_arch = "wasm32"))]
pub fn crypto_chacha20_encrypt_key<E: From<String> + FromUnavailable>(
    key: Key,
    plaintext: String,
) -> IpeResult<E, String> {
    crypto_chacha20_encrypt(crate::crypto_core::crypto_key_reveal(key), plaintext)
}

// Crypto.chacha20Decrypt : Key -> String -> Result Error String  (typed key)
#[cfg(not(target_arch = "wasm32"))]
pub fn crypto_chacha20_decrypt_key<E: From<String>>(
    key: Key,
    encoded: String,
) -> IpeResult<E, String> {
    crypto_chacha20_decrypt(crate::crypto_core::crypto_key_reveal(key), encoded)
}

// Internal String-keyed ChaCha20-Poly1305 core — `pub(crate)`, reached only through
// the typed `crypto_chacha20_encrypt_key` wrapper. No bare-String-key path escapes the crate.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn crypto_chacha20_encrypt<E: From<String> + FromUnavailable>(
    key: String,
    plaintext: String,
) -> IpeResult<E, String> {
    crypto_chacha20_encrypt_with(crate::entropy::fill_entropy, key, plaintext)
}

/// [`crypto_chacha20_encrypt`] drawing its 12-byte nonce from `fill`.
///
/// A refused draw produces no ciphertext and fails with kind `Unavailable`.
#[cfg(not(target_arch = "wasm32"))]
fn crypto_chacha20_encrypt_with<E: From<String> + FromUnavailable>(
    fill: impl FnOnce(&mut [u8]) -> Result<(), crate::entropy::EntropyError>,
    key: String,
    plaintext: String,
) -> IpeResult<E, String> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
    let k = match aead_read_key("Crypto.chacha20Encrypt", &key) {
        Ok(k) => k,
        Err(e) => return IpeResult::Err(e.into()),
    };
    let cipher = match ChaCha20Poly1305::new_from_slice(&k) {
        Ok(c) => c,
        Err(e) => return IpeResult::Err(format!("Crypto.chacha20Encrypt: {}", e).into()),
    };
    let mut nonce_bytes = [0u8; 12];
    if fill(&mut nonce_bytes).is_err() {
        return IpeResult::Err(E::from_unavailable(
            "Crypto.chacha20Encrypt: the OS random source is unavailable".to_owned(),
        ));
    }
    let nonce = Nonce::from_slice(&nonce_bytes);
    match cipher.encrypt(nonce, plaintext.as_bytes()) {
        Ok(ct) => {
            let mut out = nonce_bytes.to_vec();
            out.extend_from_slice(&ct);
            IpeResult::Ok(STANDARD.encode(out))
        }
        Err(e) => IpeResult::Err(format!("Crypto.chacha20Encrypt: {}", e).into()),
    }
}

// Internal String-keyed ChaCha20-Poly1305 core — `pub(crate)`, reached only through
// the typed `crypto_chacha20_decrypt_key` wrapper. No bare-String-key path escapes the crate.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn crypto_chacha20_decrypt<E: From<String>>(
    key: String,
    encoded: String,
) -> IpeResult<E, String> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
    let k = match aead_read_key("Crypto.chacha20Decrypt", &key) {
        Ok(k) => k,
        Err(e) => return IpeResult::Err(e.into()),
    };
    let buf = match STANDARD.decode(encoded.as_bytes()) {
        Ok(b) => b,
        Err(e) => {
            return IpeResult::Err(format!("Crypto.chacha20Decrypt: invalid base64: {}", e).into());
        }
    };
    if buf.len() < 12 {
        return IpeResult::Err(
            "Crypto.chacha20Decrypt: ciphertext too short"
                .to_string()
                .into(),
        );
    }
    let (nonce_bytes, ct) = buf.split_at(12);
    let cipher = match ChaCha20Poly1305::new_from_slice(&k) {
        Ok(c) => c,
        Err(e) => return IpeResult::Err(format!("Crypto.chacha20Decrypt: {}", e).into()),
    };
    match cipher.decrypt(Nonce::from_slice(nonce_bytes), ct) {
        // A Ipê String is UTF-8 by construction (see aesGcmDecrypt note). Reject
        // non-UTF-8 plaintext with a structured Err rather than lossy-corrupting it.
        Ok(pt) => match String::from_utf8(pt) {
            Ok(s) => IpeResult::Ok(s),
            Err(_) => IpeResult::Err(
                "Crypto.chacha20Decrypt: decrypted plaintext is not valid UTF-8"
                    .to_string()
                    .into(),
            ),
        },
        Err(e) => IpeResult::Err(format!("Crypto.chacha20Decrypt: {}", e).into()),
    }
}

// PBKDF2-HMAC-SHA256, 100k iters, 32-byte key, returned base64-encoded.
// `pub(crate)`, NOT a public runtime API or kernel: it returns a raw `String`,
// so it is reached only through the typed `_key` variants below, which promote
// the PBKDF2 output into an opaque `Key`. There is no bare-`String`-key
// derivation spelling reachable from Ipê source or from outside this crate.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn crypto_aes_key_from_password(password: String, salt: String) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut key = [0u8; AEAD_KEY_BYTES];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
        password.as_bytes(),
        salt.as_bytes(),
        PBKDF2_ITERS,
        &mut key,
    );
    STANDARD.encode(key)
}

// Crypto.aesKeyFromPassword : String -> String -> Key
//
// Returns a typed `Key` rather than a bare `String` so the derived key can
// only be passed to typed AEAD operations, making a role-swap a compile error.
#[cfg(not(target_arch = "wasm32"))]
pub fn crypto_aes_key_from_password_key(password: String, salt: String) -> Key {
    crypto_key_promote(crypto_aes_key_from_password(password, salt))
}

// Crypto.chachaKeyFromPassword : String -> String -> Key
#[cfg(not(target_arch = "wasm32"))]
pub fn crypto_chacha_key_from_password_key(password: String, salt: String) -> Key {
    crypto_key_promote(crypto_aes_key_from_password(password, salt))
}

// ── Concrete (non-generic) wrappers for generated Ipê code ─────────────
//
// The generic `crypto_aes_gcm_encrypt<E>`, `crypto_aes_gcm_decrypt<E>`,
// `crypto_chacha20_encrypt<E>`, `crypto_chacha20_decrypt<E>` above use a
// flexible `E: From<String>` bound so the error type can be inferred from
// context. Generated Ipê code sets `IpeError = ipe_runtime::error::IpeError`,
// but Rust's type inference cannot pin `E` when the error arm is discarded
// (e.g. `Err _ ->` in a case expression). These concrete aliases pin
// `E = IpeError` up-front, eliminating the ambiguity without changing runtime
// semantics.

/// Generated-code alias for `crypto_aes_gcm_encrypt_key` with `E = IpeError`.
#[cfg(not(target_arch = "wasm32"))]
pub fn ipe_aes_gcm_encrypt_key(
    key: Key,
    plaintext: String,
) -> IpeResult<crate::error::IpeError, String> {
    crypto_aes_gcm_encrypt_key(key, plaintext)
}

/// Generated-code alias for `crypto_aes_gcm_decrypt_key` with `E = IpeError`.
#[cfg(not(target_arch = "wasm32"))]
pub fn ipe_aes_gcm_decrypt_key(
    key: Key,
    encoded: String,
) -> IpeResult<crate::error::IpeError, String> {
    crypto_aes_gcm_decrypt_key(key, encoded)
}

/// Generated-code alias for `crypto_chacha20_encrypt_key` with `E = IpeError`.
#[cfg(not(target_arch = "wasm32"))]
pub fn ipe_chacha20_encrypt_key(
    key: Key,
    plaintext: String,
) -> IpeResult<crate::error::IpeError, String> {
    crypto_chacha20_encrypt_key(key, plaintext)
}

/// Generated-code alias for `crypto_chacha20_decrypt_key` with `E = IpeError`.
#[cfg(not(target_arch = "wasm32"))]
pub fn ipe_chacha20_decrypt_key(
    key: Key,
    encoded: String,
) -> IpeResult<crate::error::IpeError, String> {
    crypto_chacha20_decrypt_key(key, encoded)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests_heavy_hashes {
    use super::*;

    const EMPTY_SHA1: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    const EMPTY_MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";

    #[test]
    fn test_sha1_empty() {
        assert_eq!(crypto_sha1(String::new()), EMPTY_SHA1);
    }

    #[test]
    fn test_md5_empty() {
        assert_eq!(crypto_md5(String::new()), EMPTY_MD5);
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::entropy::EntropyError;
    use crate::{IpeError, IpeErrorKind};

    /// The base64 form of a 32-byte all-zero key, which `aead_read_key` accepts.
    fn key() -> String {
        format!("{}=", "A".repeat(43))
    }

    fn is_unavailable(r: &IpeResult<IpeError, String>) -> bool {
        matches!(
            r,
            IpeResult::Err(IpeError::Error(IpeErrorKind::Unavailable, _))
        )
    }

    /// An AES-GCM encryption without entropy yields no ciphertext and kind
    /// `Unavailable`.
    #[test]
    fn aes_gcm_encrypt_refuses_without_entropy() {
        let refused: IpeResult<IpeError, String> =
            crypto_aes_gcm_encrypt_with(|_| Err(EntropyError), key(), "msg".to_string());
        assert!(is_unavailable(&refused), "{refused:?}");
        let sealed: IpeResult<IpeError, String> =
            crypto_aes_gcm_encrypt_with(|_| Ok(()), key(), "msg".to_string());
        assert!(matches!(sealed, IpeResult::Ok(_)), "{sealed:?}");
    }

    /// A ChaCha20-Poly1305 encryption without entropy yields no ciphertext and
    /// kind `Unavailable`.
    #[test]
    fn chacha20_encrypt_refuses_without_entropy() {
        let refused: IpeResult<IpeError, String> =
            crypto_chacha20_encrypt_with(|_| Err(EntropyError), key(), "msg".to_string());
        assert!(is_unavailable(&refused), "{refused:?}");
        let sealed: IpeResult<IpeError, String> =
            crypto_chacha20_encrypt_with(|_| Ok(()), key(), "msg".to_string());
        assert!(matches!(sealed, IpeResult::Ok(_)), "{sealed:?}");
    }
}
