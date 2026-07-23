// SPDX-License-Identifier: Apache-2.0
//! HKDF-SHA256 (RFC 5869).
//!
//! Used wherever a single high-entropy input key needs to derive multiple
//! output keys with domain separation. Specifically:
//!
//! - Deriving subkeys from MK for different purposes (e.g., subkeys for
//!   features that need independent key material).
//! - Deriving rotating salts for privacy-preserving analytics.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::errors::{CryptoError, CryptoResult};

/// HKDF expand: from a pseudo-random key (PRK), derive `out_len` bytes of
/// output keyed material with the given `info` (context).
///
/// Use this for domain-separating derived keys from a master key.
///
/// # Errors
/// Returns [`CryptoError::InvalidLength`] if `out_len > 8160` (RFC 5869 limit).
pub fn hkdf_expand(prk: &[u8], info: &[u8], out_len: usize) -> CryptoResult<alloc::vec::Vec<u8>> {
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| CryptoError::InvalidLength)?;
    let mut out = alloc::vec![0u8; out_len];
    hk.expand(info, &mut out)
        .map_err(|_| CryptoError::InvalidLength)?;
    Ok(out)
}

/// HKDF full extract-and-expand: from input keying material (IKM) of any
/// strength, plus an optional salt, derive `out_len` bytes.
///
/// Use this when the input is not already high-entropy.
///
/// # Errors
/// Returns [`CryptoError::InvalidLength`] if `out_len > 8160`.
pub fn hkdf_extract_expand(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    out_len: usize,
) -> CryptoResult<alloc::vec::Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = alloc::vec![0u8; out_len];
    hk.expand(info, &mut out)
        .map_err(|_| CryptoError::InvalidLength)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 Test Case 1
    #[test]
    fn rfc5869_test_case_1() {
        let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_decode("000102030405060708090a0b0c");
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
        let expected_okm = hex_decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );
        let okm = hkdf_extract_expand(&ikm, Some(&salt), &info, 42).unwrap();
        assert_eq!(okm, expected_okm);
    }

    /// RFC 5869 Test Case 3 (no salt, no info)
    #[test]
    fn rfc5869_test_case_3() {
        let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let expected_okm = hex_decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        );
        let okm = hkdf_extract_expand(&ikm, None, b"", 42).unwrap();
        assert_eq!(okm, expected_okm);
    }

    fn hex_decode(s: &str) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = hex_digit(bytes[i]);
            let lo = hex_digit(bytes[i + 1]);
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn hex_digit(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex"),
        }
    }
}
