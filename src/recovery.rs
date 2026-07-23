// SPDX-License-Identifier: Apache-2.0
//! BIP-39 recovery phrases.
//!
//! On signup the user can opt into a 24-word phrase. From the phrase we
//! derive a separate KEK (RKEK) used to wrap a copy of the master key.
//! Recovery is then "give us your phrase + a new password; we re-derive
//! RKEK, unwrap MK, re-wrap under the new password's KEK."

use alloc::string::{String, ToString};
use bip39::{Language, Mnemonic};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{CryptoError, CryptoResult};
use crate::kdf::{
    derive_kek, ArgonAlgorithm, ArgonParams, MIN_ITERATIONS, MIN_MEMORY_KB, MIN_PARALLELISM,
};

/// A 24-word BIP-39 recovery phrase.
///
/// Zeroizes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryPhrase {
    /// Space-separated mnemonic words.
    phrase: String,
}

impl RecoveryPhrase {
    /// Construct from a known phrase (for recovery flow).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidRecoveryPhrase`] if the phrase fails
    /// BIP-39 checksum or wordlist validation.
    pub fn from_phrase(phrase: &str) -> CryptoResult<Self> {
        let trimmed = phrase.trim();
        Mnemonic::parse_in_normalized(Language::English, trimmed)
            .map_err(|_| CryptoError::InvalidRecoveryPhrase)?;
        Ok(Self {
            phrase: trimmed.to_string(),
        })
    }

    /// Read the phrase string. Caller must avoid logging.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.phrase
    }

    /// Number of words in the phrase.
    #[must_use]
    pub fn word_count(&self) -> usize {
        self.phrase.split_whitespace().count()
    }
}

/// Generate a fresh 24-word BIP-39 phrase.
///
/// # Errors
///
/// Returns [`CryptoError::RngFailure`] on RNG failure.
pub fn generate_recovery_phrase() -> CryptoResult<RecoveryPhrase> {
    // 256 bits -> 24 words
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy)?;

    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|_| CryptoError::Internal("BIP-39 mnemonic generation failed"))?;

    let phrase = RecoveryPhrase {
        phrase: mnemonic.to_string(),
    };

    // Zeroize the entropy buffer in place. The previous version of
    // this code copied `entropy` into a separate `entropy_zero`
    // local and zeroized the copy -- leaving the original 32 bytes
    // of master-key seed material on the stack until the function
    // returned. With the copy fix, the on-stack entropy is wiped
    // before we leave the function.
    //
    // (We can't help that `Mnemonic::from_entropy_in` may keep an
    // internal reference; that's bip39's responsibility. But our
    // local is the one we control.)
    entropy.zeroize();

    Ok(phrase)
}

/// A recovery KEK derived from a BIP-39 phrase.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKek(pub [u8; 32]);

impl RecoveryKek {
    /// View the bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derive the recovery KEK from a BIP-39 phrase + per-user salt.
///
/// Uses Argon2id. The phrase itself provides 256 bits of entropy so
/// brute force is infeasible regardless of salt; the per-user salt
/// prevents cross-account precomputation if an attacker breaches
/// `wrappedMKRecovery` for many accounts at once. (Without a per-user
/// salt, ONE rainbow table works for every breached user.)
///
/// `salt` MUST be 16 random bytes generated at signup time and stored
/// alongside `wrappedMKRecovery` on the server. The salt is NOT secret;
/// it just ensures domain separation between users.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidArgonParams`] only if KDF setup fails.
pub fn derive_recovery_kek(phrase: &RecoveryPhrase, salt: &[u8; 16]) -> CryptoResult<RecoveryKek> {
    let mut salt_hex: heapless::String<32> = heapless::String::new();
    for _ in 0..32 {
        salt_hex.push('0').ok();
    }
    let mut params = ArgonParams {
        algorithm: ArgonAlgorithm::Argon2id,
        memory_kb: MIN_MEMORY_KB,
        iterations: MIN_ITERATIONS,
        parallelism: MIN_PARALLELISM,
        salt_hex,
    };
    params.salt_hex = crate::kdf::salt_to_hex(salt);

    let derived = derive_kek(phrase.as_str().as_bytes(), &params)?;
    Ok(RecoveryKek(*derived.as_bytes()))
}

/// Generate a fresh 16-byte recovery salt. Caller stores this on the
/// server alongside `wrappedMKRecovery`. Not secret.
///
/// # Errors
/// Returns [`CryptoError::RngFailure`] on RNG failure.
pub fn generate_recovery_salt() -> CryptoResult<[u8; 16]> {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt)?;
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_24_words() {
        let p = generate_recovery_phrase().unwrap();
        assert_eq!(p.word_count(), 24);
    }

    #[test]
    fn generated_phrases_are_unique() {
        let p1 = generate_recovery_phrase().unwrap();
        let p2 = generate_recovery_phrase().unwrap();
        assert_ne!(p1.as_str(), p2.as_str());
    }

    #[test]
    fn parses_valid_phrase() {
        let p = generate_recovery_phrase().unwrap();
        let phrase_str = p.as_str().to_string();
        let parsed = RecoveryPhrase::from_phrase(&phrase_str).unwrap();
        assert_eq!(parsed.word_count(), 24);
    }

    #[test]
    fn rejects_invalid_phrase() {
        // Wrong word count
        assert!(RecoveryPhrase::from_phrase("just three words").is_err());
        // Random words that aren't a valid BIP-39 phrase (bad checksum)
        let bad = "apple ".repeat(24);
        assert!(RecoveryPhrase::from_phrase(&bad).is_err());
    }

    #[test]
    fn same_phrase_same_rkek() {
        let p = generate_recovery_phrase().unwrap();
        let salt = generate_recovery_salt().unwrap();
        let k1 = derive_recovery_kek(&p, &salt).unwrap();
        let k2 = derive_recovery_kek(&p, &salt).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_phrases_different_rkek() {
        let p1 = generate_recovery_phrase().unwrap();
        let p2 = generate_recovery_phrase().unwrap();
        let salt = generate_recovery_salt().unwrap();
        let k1 = derive_recovery_kek(&p1, &salt).unwrap();
        let k2 = derive_recovery_kek(&p2, &salt).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn same_phrase_different_salts_different_rkek() {
        // Per-user salt diversifies derived keys even when the phrase
        // hypothetically collides -- e.g., RNG bias bug at signup.
        let p = generate_recovery_phrase().unwrap();
        let salt_a = generate_recovery_salt().unwrap();
        let salt_b = generate_recovery_salt().unwrap();
        let k1 = derive_recovery_kek(&p, &salt_a).unwrap();
        let k2 = derive_recovery_kek(&p, &salt_b).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }
}
