// SPDX-License-Identifier: Apache-2.0
//! Error types.
//!
//! Errors deliberately carry no secret material and are coarse enough that
//! they don't leak which step failed in ways that would help an attacker.

use thiserror::Error;

/// Result alias for operations in this crate.
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Cryptographic operation error.
///
/// Variants are coarse on purpose; we don't distinguish (e.g.) "wrong key"
/// from "tampered ciphertext" because both are "decryption failed" from a
/// security-relevant standpoint and revealing which would help an attacker.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// AEAD decryption failed (wrong key, tampered ciphertext, or malformed).
    #[error("decryption failed")]
    DecryptionFailed,

    /// AEAD encryption failed.
    #[error("encryption failed")]
    EncryptionFailed,

    /// A key, salt, or other byte slice had the wrong length.
    #[error("invalid length")]
    InvalidLength,

    /// Argon2id parameters out of acceptable range.
    #[error("invalid Argon2 parameters")]
    InvalidArgonParams,

    /// Envelope version is unknown / unsupported.
    #[error("unsupported envelope version")]
    UnsupportedVersion,

    /// Ciphertext is too short to be a valid envelope.
    #[error("ciphertext too short")]
    CiphertextTooShort,

    /// Random number generator failure (extremely rare; e.g., empty entropy).
    #[error("rng failure")]
    RngFailure,

    /// BIP-39 phrase invalid (wrong word, bad checksum).
    #[error("invalid recovery phrase")]
    InvalidRecoveryPhrase,

    /// Internal error -- should never reach the caller.
    #[error("internal: {0}")]
    Internal(&'static str),
}

impl From<chacha20poly1305::Error> for CryptoError {
    fn from(_: chacha20poly1305::Error) -> Self {
        CryptoError::DecryptionFailed
    }
}

impl From<argon2::Error> for CryptoError {
    fn from(e: argon2::Error) -> Self {
        match e {
            argon2::Error::OutputTooShort | argon2::Error::OutputTooLong => {
                CryptoError::InvalidLength
            }
            _ => CryptoError::InvalidArgonParams,
        }
    }
}

impl From<getrandom::Error> for CryptoError {
    fn from(_: getrandom::Error) -> Self {
        CryptoError::RngFailure
    }
}
