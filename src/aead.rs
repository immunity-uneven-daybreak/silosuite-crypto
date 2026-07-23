// SPDX-License-Identifier: Apache-2.0
//! XChaCha20-Poly1305 envelope format.
//!
//! Every ciphertext produced by this module is structured as:
//!
//! ```text
//! [ version (2B) | nonce (24B) | ciphertext+tag ]
//! ```
//!
//! - `version` is a 2-byte big-endian algorithm identifier (currently
//!   `0x0001` for XChaCha20-Poly1305).
//! - `nonce` is a fresh 24-byte random value per encryption.
//! - `ciphertext+tag` is the AEAD output: ciphertext concatenated with
//!   the 16-byte Poly1305 tag.
//!
//! XChaCha20-Poly1305 was chosen over AES-GCM because the 24-byte nonce
//! is large enough that random nonce generation is collision-safe by
//! birthday bound (2^96 messages before collision becomes likely vs.
//! 2^48 for AES-GCM's 96-bit nonce).

use alloc::vec::Vec;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce,
};

use crate::envelope_versions::V1_XCHACHA20_POLY1305;
use crate::errors::{CryptoError, CryptoResult};
use crate::lengths::{SYMMETRIC_KEY_LEN, XCHACHA_NONCE_LEN};

const VERSION_LEN: usize = 2;
const HEADER_LEN: usize = VERSION_LEN + XCHACHA_NONCE_LEN;

/// Encrypt `plaintext` under `key`, with optional `aad`, producing a
/// versioned envelope.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidLength`] if `key.len != 32`.
/// Returns [`CryptoError::EncryptionFailed`] if the underlying AEAD fails
/// (extremely rare; only on RNG failure).
pub fn wrap_envelope(plaintext: &[u8], key: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != SYMMETRIC_KEY_LEN {
        return Err(CryptoError::InvalidLength);
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidLength)?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ct = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(&V1_XCHACHA20_POLY1305.to_be_bytes());
    out.extend_from_slice(nonce.as_slice());
    out.extend(ct);
    Ok(out)
}

/// Decrypt a versioned envelope under `key`, with the same `aad` used at
/// encryption time. Returns the plaintext.
///
/// # Errors
///
/// Returns [`CryptoError::CiphertextTooShort`] if the input is shorter than
/// the header.
/// Returns [`CryptoError::UnsupportedVersion`] if the version prefix is
/// unrecognized.
/// Returns [`CryptoError::InvalidLength`] if `key.len != 32`.
/// Returns [`CryptoError::DecryptionFailed`] for any AEAD verification
/// failure (wrong key, tampered ciphertext, mismatched AAD).
pub fn unwrap_envelope(envelope: &[u8], key: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
    if envelope.len() < HEADER_LEN {
        return Err(CryptoError::CiphertextTooShort);
    }
    if key.len() != SYMMETRIC_KEY_LEN {
        return Err(CryptoError::InvalidLength);
    }

    let version = u16::from_be_bytes([envelope[0], envelope[1]]);
    match version {
        V1_XCHACHA20_POLY1305 => unwrap_v1(envelope, key, aad),
        _ => Err(CryptoError::UnsupportedVersion),
    }
}

fn unwrap_v1(envelope: &[u8], key: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
    let nonce = XNonce::from_slice(&envelope[VERSION_LEN..HEADER_LEN]);
    let ct = &envelope[HEADER_LEN..];

    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidLength)?;
    let payload = Payload { msg: ct, aad };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Returns the algorithm version of the supplied envelope.
///
/// # Errors
/// Returns [`CryptoError::CiphertextTooShort`] if the envelope is too short
/// to contain a version prefix.
pub fn envelope_version(envelope: &[u8]) -> CryptoResult<u16> {
    if envelope.len() < VERSION_LEN {
        return Err(CryptoError::CiphertextTooShort);
    }
    Ok(u16::from_be_bytes([envelope[0], envelope[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).unwrap();
        k
    }

    #[test]
    fn round_trip() {
        let k = key();
        let ct = wrap_envelope(b"hello world", &k, b"").unwrap();
        let pt = unwrap_envelope(&ct, &k, b"").unwrap();
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn aad_is_authenticated() {
        let k = key();
        let ct = wrap_envelope(b"x", &k, b"context-A").unwrap();
        assert!(unwrap_envelope(&ct, &k, b"context-B").is_err());
        assert!(unwrap_envelope(&ct, &k, b"").is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = key();
        let k2 = key();
        let ct = wrap_envelope(b"x", &k1, b"").unwrap();
        assert!(unwrap_envelope(&ct, &k2, b"").is_err());
    }

    #[test]
    fn tampering_detected() {
        let k = key();
        let mut ct = wrap_envelope(b"hello", &k, b"").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert!(unwrap_envelope(&ct, &k, b"").is_err());
    }

    #[test]
    fn fresh_nonce_per_encryption() {
        let k = key();
        let a = wrap_envelope(b"same", &k, b"").unwrap();
        let b = wrap_envelope(b"same", &k, b"").unwrap();
        assert_ne!(a, b);
        // Both decrypt to the same plaintext
        assert_eq!(unwrap_envelope(&a, &k, b"").unwrap(), b"same");
        assert_eq!(unwrap_envelope(&b, &k, b"").unwrap(), b"same");
    }

    #[test]
    fn version_prefix_present() {
        let k = key();
        let ct = wrap_envelope(b"x", &k, b"").unwrap();
        let v = envelope_version(&ct).unwrap();
        assert_eq!(v, V1_XCHACHA20_POLY1305);
    }

    #[test]
    fn rejects_short_envelope() {
        let k = key();
        assert!(matches!(
            unwrap_envelope(&[0u8; 10], &k, b""),
            Err(CryptoError::CiphertextTooShort)
        ));
    }

    #[test]
    fn rejects_wrong_key_size() {
        assert!(matches!(
            wrap_envelope(b"x", &[0u8; 16], b""),
            Err(CryptoError::InvalidLength)
        ));
    }
}
