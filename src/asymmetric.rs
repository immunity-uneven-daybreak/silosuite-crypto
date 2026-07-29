// SPDX-License-Identifier: Apache-2.0
//! Asymmetric cryptography.
//!
//! - **X25519** for Diffie-Hellman / sealed boxes (anonymous encryption to
//!   a known recipient public key).
//! - **Ed25519** for signatures.
//!
//! Ed25519 signatures come from ed25519-dalek. X25519 key generation and
//! sealed boxes go through `crypto_box`, a `RustCrypto` crate whose curve
//! arithmetic is dalek-cryptography's curve25519-dalek. Both dalek crates
//! are widely used in security-critical projects, including Signal and
//! Tor.

use alloc::vec::Vec;
// Migrating from XSalsa20-Poly1305 (SalsaBox) to XChaCha20-Poly1305-IETF
// (ChaChaBox) to match the standing primitive declared.
// Both are 256-bit-key authenticated encryption with 192-bit nonces
// from RustCrypto's stack; the change unifies the symmetric and
// asymmetric stream cipher to XChaCha20 and picks up the
// libsodium-compat fix from crypto_box 0.9.0. The wire format is NOT
// interoperable with either NaCl or any prior tagged release of this
// crate that may have used SalsaBox; this is a fresh primitive choice
// with no existing ciphertexts to migrate.
//
// SECURITY: Both XSalsa20-Poly1305 and XChaCha20-Poly1305-IETF are
// 256-bit-key, 192-bit-nonce authenticated encryption with AEAD
// security against IND-CCA2 adversaries. The migration is a primitive
// SUBSTITUTION, not a security upgrade or downgrade -- both options
// provide equivalent guarantees. The reason for the change is
// architectural (single stream cipher across symmetric and asymmetric
// paths) and consistency with the documented spec, not a security
// improvement.
use crypto_box::{
    // AeadCore brings the generate_nonce method into scope.
    aead::{AeadCore, OsRng as BoxOsRng},
    ChaChaBox,
    PublicKey as BoxPub,
    SecretKey as BoxSec,
};
use ed25519_dalek::{
    Signature as EdSignature, Signer as _, SigningKey as EdSigning, Verifier as _,
    VerifyingKey as EdVerifying,
};
use rand_core::OsRng;

use crate::errors::{CryptoError, CryptoResult};
use crate::lengths::{ED25519_KEY_LEN, X25519_KEY_LEN};

// -------------------------------------------------------------------------
// X25519
// -------------------------------------------------------------------------

/// Generate a fresh X25519 keypair.
///
/// Returns `(secret, public)`. The secret is 32 bytes and should be stored
/// encrypted (the master-key flow does this).
///
/// # Errors
/// Returns [`CryptoError::RngFailure`] on RNG failure.
pub fn generate_x25519_keypair() -> CryptoResult<([u8; X25519_KEY_LEN], [u8; X25519_KEY_LEN])> {
    let secret = BoxSec::generate(&mut BoxOsRng);
    let public = secret.public_key();
    let secret_bytes: [u8; 32] = secret.to_bytes();
    let public_bytes: [u8; 32] = public.to_bytes();
    Ok((secret_bytes, public_bytes))
}

/// Anonymously encrypt a message to a recipient's X25519 public key.
///
/// This is libsodium's `crypto_box_seal` construction: the sender generates an
/// ephemeral keypair, performs a key exchange, and discards their secret.
/// Recipient can decrypt; sender identity is unrecoverable.
///
/// Used for: contact form submissions, supporter tip messages.
///
/// # Errors
/// Returns [`CryptoError::EncryptionFailed`] only on RNG failure.
pub fn seal_to_pubkey(
    recipient_pubkey: &[u8; X25519_KEY_LEN],
    plaintext: &[u8],
) -> CryptoResult<Vec<u8>> {
    use crypto_box::aead::Aead;

    let recipient = BoxPub::from(*recipient_pubkey);
    let ephemeral = BoxSec::generate(&mut BoxOsRng);
    let ephemeral_pub: [u8; 32] = ephemeral.public_key().to_bytes();

    // NOTE: this is NOT byte-for-byte NaCl `crypto_box_seal`. NaCl's
    // seal derives the nonce as BLAKE2b(eph_pub || recipient_pub),
    // making the nonce reconstructable on the recipient side from
    // data already in the wire format + their own pubkey. We use a
    // random nonce shipped on the wire instead. The semantics
    // (anonymity, recipient-only decryption) are equivalent; the
    // wire format is NOT interoperable with NaCl tooling. Don't
    // rename to `nacl_seal` or `crypto_box_seal` to avoid confusion.
    let nonce = ChaChaBox::generate_nonce(&mut BoxOsRng);
    let chacha_box = ChaChaBox::new(&recipient, &ephemeral);
    let ct = chacha_box
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    // Format: [ephemeral_pub (32) | nonce (24) | ciphertext]
    let mut out = Vec::with_capacity(32 + 24 + ct.len());
    out.extend_from_slice(&ephemeral_pub);
    out.extend_from_slice(nonce.as_slice());
    out.extend(ct);
    Ok(out)
}

/// Open a sealed box using the recipient's X25519 secret + public keys.
///
/// # Errors
/// Returns [`CryptoError::DecryptionFailed`] on any AEAD failure.
/// Returns [`CryptoError::CiphertextTooShort`] if the input is malformed.
pub fn open_sealed(
    recipient_secret: &[u8; X25519_KEY_LEN],
    sealed: &[u8],
) -> CryptoResult<Vec<u8>> {
    use crypto_box::aead::Aead;
    use crypto_box::Nonce;

    if sealed.len() < 32 + 24 {
        return Err(CryptoError::CiphertextTooShort);
    }
    let mut eph_pub_bytes = [0u8; 32];
    eph_pub_bytes.copy_from_slice(&sealed[..32]);
    let eph_pub = BoxPub::from(eph_pub_bytes);

    let nonce = Nonce::from_slice(&sealed[32..56]);
    let ct = &sealed[56..];

    let secret = BoxSec::from(*recipient_secret);
    let chacha_box = ChaChaBox::new(&eph_pub, &secret);

    chacha_box
        .decrypt(nonce, ct)
        .map_err(|_| CryptoError::DecryptionFailed)
}

// -------------------------------------------------------------------------
// Ed25519
// -------------------------------------------------------------------------

/// Generate a fresh Ed25519 keypair.
///
/// # Errors
/// Returns [`CryptoError::RngFailure`] on RNG failure.
pub fn generate_ed25519_keypair() -> CryptoResult<([u8; ED25519_KEY_LEN], [u8; ED25519_KEY_LEN])> {
    let signing = EdSigning::generate(&mut OsRng);
    let secret_bytes: [u8; 32] = signing.to_bytes();
    let public_bytes: [u8; 32] = signing.verifying_key().to_bytes();
    Ok((secret_bytes, public_bytes))
}

/// Sign `message` with an Ed25519 secret key.
#[must_use]
pub fn sign(secret: &[u8; ED25519_KEY_LEN], message: &[u8]) -> [u8; 64] {
    let signing = EdSigning::from_bytes(secret);
    signing.sign(message).to_bytes()
}

/// Verify an Ed25519 signature.
///
/// # Errors
/// Returns [`CryptoError::DecryptionFailed`] on any verification failure
/// (the variant is reused for "asymmetric verification failed").
pub fn verify(
    public: &[u8; ED25519_KEY_LEN],
    message: &[u8],
    signature: &[u8; 64],
) -> CryptoResult<()> {
    let verifying = EdVerifying::from_bytes(public).map_err(|_| CryptoError::InvalidLength)?;
    let sig = EdSignature::from_bytes(signature);
    verifying
        .verify(message, &sig)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_seal_and_open() {
        let (secret, public) = generate_x25519_keypair().unwrap();
        let ct = seal_to_pubkey(&public, b"contact form message").unwrap();
        let pt = open_sealed(&secret, &ct).unwrap();
        assert_eq!(pt, b"contact form message");
    }

    #[test]
    fn x25519_wrong_secret_fails() {
        let (_, public_a) = generate_x25519_keypair().unwrap();
        let (secret_b, _) = generate_x25519_keypair().unwrap();
        let ct = seal_to_pubkey(&public_a, b"x").unwrap();
        assert!(open_sealed(&secret_b, &ct).is_err());
    }

    #[test]
    fn x25519_fresh_ephemeral_each_call() {
        let (_, public) = generate_x25519_keypair().unwrap();
        let a = seal_to_pubkey(&public, b"same").unwrap();
        let b = seal_to_pubkey(&public, b"same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn ed25519_sign_verify() {
        let (secret, public) = generate_ed25519_keypair().unwrap();
        let sig = sign(&secret, b"hello");
        verify(&public, b"hello", &sig).unwrap();
    }

    #[test]
    fn ed25519_tampered_message_fails() {
        let (secret, public) = generate_ed25519_keypair().unwrap();
        let sig = sign(&secret, b"hello");
        assert!(verify(&public, b"world", &sig).is_err());
    }

    #[test]
    fn ed25519_tampered_signature_fails() {
        let (secret, public) = generate_ed25519_keypair().unwrap();
        let mut sig = sign(&secret, b"hello");
        sig[0] ^= 1;
        assert!(verify(&public, b"hello", &sig).is_err());
    }
}
