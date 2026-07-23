// SPDX-License-Identifier: Apache-2.0
//! Argon2id key derivation.
//!
//! All password-based key derivation in `SiloSuite` uses Argon2id with a
//! minimum-acceptable parameter set:
//!
//! - **memory**: 64 MiB (65536 KiB)
//! - **iterations**: 2
//! - **parallelism**: 1 (browser-compatible)
//!
//! These are the OWASP 2024 floor for Argon2id. Capability detection
//! (`measure_capability`) lets clients tune parameters upward when the
//! device can sustain higher memory cost.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{CryptoError, CryptoResult};
use crate::lengths::ARGON2_SALT_LEN;

/// Argon2id parameter set as stored on the server alongside an account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArgonParams {
    /// Algorithm name; always `"argon2id"` in v1.
    pub algorithm: ArgonAlgorithm,
    /// Memory cost in KiB.
    pub memory_kb: u32,
    /// Iteration count.
    pub iterations: u32,
    /// Parallelism (lanes).
    pub parallelism: u32,
    /// Hex-encoded 16-byte salt.
    pub salt_hex: heapless::String<32>,
}

/// Algorithm identifier for the Argon2 family. Argon2id is the only
/// variant supported in v1; Argon2i and Argon2d are not exposed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ArgonAlgorithm {
    /// Argon2id (the only supported variant currently).
    Argon2id,
}

/// Minimum parameter values per OWASP 2024.
pub const MIN_MEMORY_KB: u32 = 65_536;
/// Minimum iteration count (OWASP 2024 floor for Argon2id).
pub const MIN_ITERATIONS: u32 = 2;
/// Minimum parallelism / lane count. Set to 1 because the WASM
/// build target runs Argon2id single-threaded; raising the floor
/// would break browser-side key derivation.
pub const MIN_PARALLELISM: u32 = 1;

/// Maximum parameter values. The server NEVER runs the user-supplied
/// Argon2id params (it uses its own server-controlled params for
/// verifier hashing) -- these caps exist only to protect the user
/// against accidentally locking themselves out by submitting params
/// their own browser can't satisfy on login. Caps are well above
/// any reasonable hardware in 2026 but well below "your tab will
/// hang for 5 minutes" levels.
pub const MAX_MEMORY_KB: u32 = 1_048_576; // 1 GiB
/// Maximum iteration count accepted at the API boundary.
pub const MAX_ITERATIONS: u32 = 10;
/// Maximum parallelism accepted at the API boundary.
pub const MAX_PARALLELISM: u32 = 16;

impl ArgonParams {
    /// Validate that this parameter set meets the minimum security floor.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidArgonParams`] if any parameter is below
    /// the floor or if the salt length is wrong.
    pub fn validate(&self) -> CryptoResult<()> {
        if self.algorithm != ArgonAlgorithm::Argon2id {
            return Err(CryptoError::InvalidArgonParams);
        }
        if self.memory_kb < MIN_MEMORY_KB || self.memory_kb > MAX_MEMORY_KB {
            return Err(CryptoError::InvalidArgonParams);
        }
        if self.iterations < MIN_ITERATIONS || self.iterations > MAX_ITERATIONS {
            return Err(CryptoError::InvalidArgonParams);
        }
        if self.parallelism < MIN_PARALLELISM || self.parallelism > MAX_PARALLELISM {
            return Err(CryptoError::InvalidArgonParams);
        }
        // Salt is 16 bytes hex-encoded -> 32 chars
        if self.salt_hex.len() != ARGON2_SALT_LEN * 2 {
            return Err(CryptoError::InvalidArgonParams);
        }
        for c in self.salt_hex.chars() {
            if !c.is_ascii_hexdigit() {
                return Err(CryptoError::InvalidArgonParams);
            }
        }
        Ok(())
    }

    /// Return the salt as 16 raw bytes.
    fn salt_bytes(&self) -> CryptoResult<[u8; ARGON2_SALT_LEN]> {
        let mut out = [0u8; ARGON2_SALT_LEN];
        if self.salt_hex.len() != ARGON2_SALT_LEN * 2 {
            return Err(CryptoError::InvalidArgonParams);
        }
        for (i, byte) in out.iter_mut().enumerate() {
            let hi = hex_digit(self.salt_hex.as_bytes()[2 * i])?;
            let lo = hex_digit(self.salt_hex.as_bytes()[2 * i + 1])?;
            *byte = (hi << 4) | lo;
        }
        Ok(out)
    }
}

fn hex_digit(c: u8) -> CryptoResult<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(CryptoError::InvalidArgonParams),
    }
}

/// A KEK (key-encryption-key) derived from a password.
///
/// Wrapped in a struct that zeroizes on drop so the bytes don't sit in
/// memory after we're done with them.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKek(pub [u8; 32]);

impl DerivedKek {
    /// Read the bytes. Caller must avoid copying or persisting.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derive a 32-byte KEK from a password and Argon2id parameters.
///
/// The output is suitable for use as a symmetric key (e.g., to wrap the
/// master key with [`crate::aead::wrap_envelope`]).
///
/// # Errors
///
/// Returns [`CryptoError::InvalidArgonParams`] if `params` is below the
/// minimum security floor.
pub fn derive_kek(password: &[u8], params: &ArgonParams) -> CryptoResult<DerivedKek> {
    params.validate()?;

    let argon_params = Params::new(
        params.memory_kb,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| CryptoError::InvalidArgonParams)?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let salt = params.salt_bytes()?;

    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, &salt, &mut out)
        .map_err(|_| CryptoError::InvalidArgonParams)?;

    Ok(DerivedKek(out))
}

/// Generate a fresh 16-byte salt suitable for a new account.
///
/// # Errors
///
/// Returns [`CryptoError::RngFailure`] if the system RNG fails.
pub fn generate_salt() -> CryptoResult<[u8; ARGON2_SALT_LEN]> {
    let mut salt = [0u8; ARGON2_SALT_LEN];
    getrandom::getrandom(&mut salt)?;
    Ok(salt)
}

/// Encode a 16-byte salt to a 32-character lowercase hex string.
#[must_use]
pub fn salt_to_hex(salt: &[u8; ARGON2_SALT_LEN]) -> heapless::String<32> {
    let mut s: heapless::String<32> = heapless::String::new();
    for byte in salt {
        let hi = (byte >> 4) & 0xF;
        let lo = byte & 0xF;
        s.push(hex_char(hi)).ok();
        s.push(hex_char(lo)).ok();
    }
    s
}

fn hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + nibble - 10) as char,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_params() -> ArgonParams {
        let mut salt_hex: heapless::String<32> = heapless::String::new();
        for _ in 0..32 {
            salt_hex.push('0').unwrap();
        }
        ArgonParams {
            algorithm: ArgonAlgorithm::Argon2id,
            memory_kb: MIN_MEMORY_KB,
            iterations: MIN_ITERATIONS,
            parallelism: MIN_PARALLELISM,
            salt_hex,
        }
    }

    #[test]
    fn validates_floor() {
        good_params().validate().unwrap();
    }

    #[test]
    fn rejects_low_memory() {
        let mut p = good_params();
        p.memory_kb = 1024;
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_low_iterations() {
        let mut p = good_params();
        p.iterations = 1;
        assert!(p.validate().is_err());
    }

    #[test]
    fn derives_deterministically() {
        let p = good_params();
        let k1 = derive_kek(b"hello world", &p).unwrap();
        let k2 = derive_kek(b"hello world", &p).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_passwords_different_keys() {
        let p = good_params();
        let k1 = derive_kek(b"hello", &p).unwrap();
        let k2 = derive_kek(b"world", &p).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn salt_round_trip() {
        let salt = generate_salt().unwrap();
        let hex = salt_to_hex(&salt);
        let mut p = good_params();
        p.salt_hex = hex;
        let bytes = p.salt_bytes().unwrap();
        assert_eq!(bytes, salt);
    }
}
