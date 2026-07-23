// SPDX-License-Identifier: Apache-2.0
//! Per-resource Data Encryption Keys (DEKs).
//!
//! Each resource (e.g. a `LinkSilo` page) gets its own
//! 32-byte DEK. The DEK encrypts the resource content; the DEK itself is
//! wrapped under the user's master key.
//!
//! When a page is published, a separate Publish-Public-Key (PPK) is
//! generated. The published payload is encrypted with PPK; PPK is stored
//! alongside the page (server-readable) so the rendering service can decrypt.
//! Unpublishing a page = `NULLing` the stored publish key = crypto-shredding the
//! published copy.

use alloc::vec::Vec;

use crate::aead::{unwrap_envelope, wrap_envelope};
use crate::errors::{CryptoError, CryptoResult};
use crate::lengths::SYMMETRIC_KEY_LEN;

/// Generate a fresh 32-byte DEK.
///
/// Return type is `Zeroizing<[u8; 32]>` so the bytes wipe on drop.
/// Callers can dereference for slice-accepting APIs.
///
/// # Errors
/// Returns [`CryptoError::RngFailure`] on RNG failure.
pub fn generate_dek() -> CryptoResult<zeroize::Zeroizing<[u8; SYMMETRIC_KEY_LEN]>> {
    let mut k = zeroize::Zeroizing::new([0u8; SYMMETRIC_KEY_LEN]);
    getrandom::getrandom(&mut *k)?;
    Ok(k)
}

/// Wrap a DEK under the master key.
///
/// `aad` should bind the wrapped DEK to its resource (e.g., `b"page:" ||
/// page_id`) so that a leaked wrapped DEK can't be substituted for another
/// resource's wrapped DEK.
///
/// # Errors
/// Returns [`CryptoError::EncryptionFailed`] only on RNG failure.
pub fn wrap_dek(
    dek: &[u8; SYMMETRIC_KEY_LEN],
    master_key: &[u8; SYMMETRIC_KEY_LEN],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    wrap_envelope(dek, master_key, aad)
}

/// Unwrap a wrapped DEK.
///
/// Return type is `Zeroizing<[u8; 32]>` so the bytes wipe on drop.
///
/// # Errors
/// Returns [`CryptoError::DecryptionFailed`] on any AEAD failure.
pub fn unwrap_dek(
    wrapped: &[u8],
    master_key: &[u8; SYMMETRIC_KEY_LEN],
    aad: &[u8],
) -> CryptoResult<zeroize::Zeroizing<[u8; SYMMETRIC_KEY_LEN]>> {
    use zeroize::Zeroize;

    let mut bytes = unwrap_envelope(wrapped, master_key, aad)?;
    if bytes.len() != SYMMETRIC_KEY_LEN {
        // Best-effort zeroize on the wrong-length error path too.
        bytes.zeroize();
        return Err(CryptoError::InvalidLength);
    }
    let mut k = zeroize::Zeroizing::new([0u8; SYMMETRIC_KEY_LEN]);
    k.copy_from_slice(&bytes);
    // Zeroize the intermediate Vec before its allocation goes back to
    // the heap pool.
    bytes.zeroize();
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        // Dereference to drop the Zeroizing wrapper for test convenience.
        // Tests don't care about heap residue.
        *generate_dek().unwrap()
    }

    #[test]
    fn dek_wrap_unwrap_roundtrip() {
        let mk = key();
        let dek = key();
        let wrapped = wrap_dek(&dek, &mk, b"page:test").unwrap();
        let unwrapped = unwrap_dek(&wrapped, &mk, b"page:test").unwrap();
        assert_eq!(dek, *unwrapped);
    }

    #[test]
    fn aad_substitution_fails() {
        let mk = key();
        let dek = key();
        let wrapped = wrap_dek(&dek, &mk, b"page:A").unwrap();
        // Attempting to use this wrapped DEK with a different resource's AAD fails.
        assert!(unwrap_dek(&wrapped, &mk, b"page:B").is_err());
    }

    #[test]
    fn wrong_master_key_fails() {
        let mk1 = key();
        let mk2 = key();
        let dek = key();
        let wrapped = wrap_dek(&dek, &mk1, b"page:A").unwrap();
        assert!(unwrap_dek(&wrapped, &mk2, b"page:A").is_err());
    }

    #[test]
    fn deks_are_unique() {
        let a = generate_dek().unwrap();
        let b = generate_dek().unwrap();
        assert_ne!(a, b);
    }
}
