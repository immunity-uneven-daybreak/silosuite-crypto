// SPDX-License-Identifier: Apache-2.0
//! The master-key flow.
//!
//! The master key (MK) is a 32-byte symmetric
//! secret that the user owns. All other resource-level keys are derived
//! from or wrapped by MK.
//!
//! ## Bitwarden-style two-secret design
//!
//! The user has ONE password. From it we derive TWO secrets:
//!
//! 1. **`AuthKey`** (32 bytes): proves identity to the server. The server
//!    stores `argon2id(authKey)` as a verifier.
//! 2. **KEK** (32 bytes): wraps the master key locally. Never leaves the
//!    client.
//!
//! Both are derived via Argon2id with separate domain-separation strings,
//! ensuring that revealing `AuthKey` to the server does not reveal KEK.
//!
//! ## Recovery
//!
//! Optionally, the user gets a 24-word BIP-39 phrase. From the phrase we
//! derive a recovery KEK (RKEK) and store a second copy of MK wrapped
//! under RKEK. Recovery proceeds by re-deriving RKEK from the phrase
//! and unwrapping MK locally.
//!
//! ## What's stored where
//!
//! Server-stored, per-account:
//! - `argon2id(authKey, server_argon_params)` -- verifier
//! - `wrappedMK` = AEAD(MK, KEK) -- opaque to server
//! - `wrappedMKRecovery` = AEAD(MK, RKEK) -- opaque to server (optional)
//! - `argonParams` -- the *client-side* Argon2id parameters (salt + tuning)
//! - `pubkey_x25519`, `pubkey_ed25519` -- public asymmetric keys
//! - `wrappedPrivateKeys` = AEAD(privX25519 || privEd25519, MK)
//!
//! The server NEVER sees: password, KEK, RKEK, MK, or private keys.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aead::{unwrap_envelope, wrap_envelope};
use crate::asymmetric::{generate_ed25519_keypair, generate_x25519_keypair};
use crate::errors::{CryptoError, CryptoResult};
use crate::kdf::{
    derive_kek, generate_salt, salt_to_hex, ArgonAlgorithm, ArgonParams, MIN_ITERATIONS,
    MIN_MEMORY_KB, MIN_PARALLELISM,
};
use crate::lengths::MASTER_KEY_LEN;
use crate::recovery::{derive_recovery_kek, generate_recovery_phrase, RecoveryPhrase};

// -------------------------------------------------------------------------
// Domain separation
//
// AuthKey and KEK derivations use distinct prefix bytes to ensure that
// even if the underlying KDF leaks one, the other remains independent.
// -------------------------------------------------------------------------

const DOMAIN_AUTH_KEY: &[u8] = b"silosuite-v1-auth-key";
const DOMAIN_KEK: &[u8] = b"silosuite-v1-kek";

/// Master key -- 32 bytes of symmetric key material.
///
/// Zeroizes on drop. Caller should keep instances short-lived.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub [u8; MASTER_KEY_LEN]);

impl MasterKey {
    /// Generate a fresh master key.
    ///
    /// # Errors
    /// Returns [`CryptoError::RngFailure`] on RNG failure.
    pub fn generate() -> CryptoResult<Self> {
        let mut bytes = [0u8; MASTER_KEY_LEN];
        getrandom::getrandom(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// View the raw bytes. Caller must avoid copying or persisting.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.0
    }
}

// -------------------------------------------------------------------------
// Bundle types
// -------------------------------------------------------------------------

/// The complete bundle a client sends to the server at signup.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignupBundle {
    /// `AuthKey`, base64-encoded (32 bytes).
    pub auth_key: alloc::string::String,
    /// Argon2id parameters used to derive `AuthKey` + KEK.
    pub argon_params: ArgonParams,
    /// Wrapped master key under KEK.
    pub wrapped_mk: alloc::vec::Vec<u8>,
    /// Optional: wrapped master key under recovery KEK.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_mk_recovery: Option<alloc::vec::Vec<u8>>,
    /// Optional: per-user recovery KEK salt (16 bytes). Hex-encoded
    /// to avoid binary-in-JSON issues. Present iff `wrapped_mk_recovery`
    /// is Some. Diversifies recovery KEKs across users so an attacker
    /// who breaches `wrapped_mk_recovery` for many accounts cannot
    /// build one rainbow table that works for all of them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_salt_hex: Option<alloc::string::String>,
    /// X25519 public key.
    pub pubkey_x25519: [u8; 32],
    /// Ed25519 public key.
    pub pubkey_ed25519: [u8; 32],
    /// Concatenated private keys, encrypted under MK.
    pub wrapped_private_keys: alloc::vec::Vec<u8>,
}

/// Result of [`create_master_key_bundle`] -- the bundle to send to the
/// server, plus (optionally) the recovery phrase to display ONCE to the
/// user.
pub struct CreatedBundle {
    /// Send this to the server.
    pub bundle: SignupBundle,
    /// Display this to the user ONCE if they opted into recovery.
    pub recovery_phrase: Option<RecoveryPhrase>,
}

// -------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------

/// Create a fresh master-key bundle for a new account.
///
/// Generates:
/// - Master key
/// - X25519 keypair
/// - Ed25519 keypair
/// - Argon2id salt
/// - `AuthKey` (sent to server)
/// - KEK (kept local; wraps MK)
/// - Optionally: recovery phrase + RKEK (RKEK wraps a second copy of MK)
///
/// # Errors
///
/// Returns [`CryptoError::RngFailure`] on RNG failure (should never happen
/// in normal operation).
pub fn create_master_key_bundle(
    password: &[u8],
    include_recovery_phrase: bool,
) -> CryptoResult<CreatedBundle> {
    // Generate salt + argon params
    let salt = generate_salt()?;
    let salt_hex = salt_to_hex(&salt);
    let argon_params = ArgonParams {
        algorithm: ArgonAlgorithm::Argon2id,
        memory_kb: MIN_MEMORY_KB,
        iterations: MIN_ITERATIONS,
        parallelism: MIN_PARALLELISM,
        salt_hex,
    };

    // Derive AuthKey (server-bound) and KEK (local)
    let auth_key = derive_with_domain(password, &argon_params, DOMAIN_AUTH_KEY)?;
    let kek = derive_with_domain(password, &argon_params, DOMAIN_KEK)?;

    // Generate master key
    let mk = MasterKey::generate()?;

    // Wrap MK under KEK
    // Deref through Zeroizing<[u8;32]> to &[u8;32], which then coerces
    // to &[u8] in slice arguments. The deref produces a borrow, not a
    // move, so the wrapper's Drop still wipes the bytes when `kek` goes
    // out of scope. Equivalent to `kek.as_slice` but matches the
    // `&kek` style used elsewhere in this file.
    let wrapped_mk = wrap_envelope(mk.as_bytes(), &*kek, b"silosuite-v1-mk-kek")?;

    // Generate asymmetric keys.
    //
    // generate_*_keypair returns raw 32-byte arrays. The dalek
    // signing-key types are ZeroizeOnDrop, but the to_bytes
    // accessor produces a fresh unprotected copy. Immediately wrap
    // the privates in Zeroizing so the local stack/heap copies wipe
    // when this function returns.
    let (x25519_priv_bytes, x25519_pub) = generate_x25519_keypair()?;
    let (ed25519_priv_bytes, ed25519_pub) = generate_ed25519_keypair()?;
    let x25519_priv = zeroize::Zeroizing::new(x25519_priv_bytes);
    let ed25519_priv = zeroize::Zeroizing::new(ed25519_priv_bytes);

    // Wrap private keys under MK
    let mut priv_combined = zeroize::Zeroizing::new(Vec::with_capacity(64));
    priv_combined.extend_from_slice(&*x25519_priv);
    priv_combined.extend_from_slice(&*ed25519_priv);
    let wrapped_private_keys =
        wrap_envelope(&priv_combined, mk.as_bytes(), b"silosuite-v1-privkeys")?;
    // priv_combined drops here, auto-zeroizing.

    // Optionally generate recovery
    let (wrapped_mk_recovery, recovery_salt_hex, recovery_phrase) = if include_recovery_phrase {
        let phrase = generate_recovery_phrase()?;
        let r_salt = crate::recovery::generate_recovery_salt()?;
        let rkek = derive_recovery_kek(&phrase, &r_salt)?;
        let wmk_r = wrap_envelope(mk.as_bytes(), rkek.as_bytes(), b"silosuite-v1-mk-rkek")?;
        (
            Some(wmk_r),
            Some(salt_to_hex(&r_salt).as_str().to_string()),
            Some(phrase),
        )
    } else {
        (None, None, None)
    };

    let bundle = SignupBundle {
        auth_key: base64_encode(&*auth_key),
        argon_params,
        wrapped_mk,
        wrapped_mk_recovery,
        recovery_salt_hex,
        pubkey_x25519: x25519_pub,
        pubkey_ed25519: ed25519_pub,
        wrapped_private_keys,
    };

    Ok(CreatedBundle {
        bundle,
        recovery_phrase,
    })
}

/// Derive ONLY the `AuthKey` from password + Argon2id params. Used at
/// login to produce the server-bound proof of identity, without
/// running the second derivation (KEK) yet.
///
/// The login flow is:
/// 1. the login-preparation endpoint returns the account's `argon_params`
/// 2. Browser calls `derive_auth_key(password, argon_params)`
/// 3. Browser POSTs the `AuthKey` to the login endpoint
/// 4. On success, browser calls `unlock_master_key(...)` to derive
///    the KEK and unwrap the master key locally
///
/// # Errors
/// Returns [`CryptoError::InvalidArgonParams`] if `argon_params` is
/// malformed or below the security floor.
///
/// Return type is `Zeroizing<[u8; 32]>` so the `AuthKey` bytes wipe
/// when the wrapper drops. Callers can dereference to `&[u8]` for
/// slice-accepting APIs.
pub fn derive_auth_key(
    password: &[u8],
    argon_params: &ArgonParams,
) -> CryptoResult<zeroize::Zeroizing<[u8; 32]>> {
    derive_with_domain(password, argon_params, DOMAIN_AUTH_KEY)
}

/// Unlock a stored master key using a password.
///
/// Re-derives KEK from the password and unwraps the stored `wrappedMK`.
///
/// # Errors
///
/// Returns [`CryptoError::DecryptionFailed`] if the password is wrong.
pub fn unlock_master_key(
    password: &[u8],
    argon_params: &ArgonParams,
    wrapped_mk: &[u8],
) -> CryptoResult<MasterKey> {
    let kek = derive_with_domain(password, argon_params, DOMAIN_KEK)?;
    let mut mk_bytes = unwrap_envelope(wrapped_mk, &*kek, b"silosuite-v1-mk-kek")?;
    if mk_bytes.len() != MASTER_KEY_LEN {
        mk_bytes.zeroize();
        return Err(CryptoError::InvalidLength);
    }
    let mut mk = [0u8; MASTER_KEY_LEN];
    mk.copy_from_slice(&mk_bytes);
    // Zeroize the intermediate Vec -- the MK is now in the caller's
    // MasterKey struct (which itself zeroizes on drop).
    mk_bytes.zeroize();
    Ok(MasterKey(mk))
}

/// Rewrap an existing master key under a new password.
///
/// Used when the user changes their password. Returns a fresh argon params
/// (with a new salt) and new wrappedMK. The old wrappedMK should be
/// discarded server-side.
///
/// # Errors
///
/// Returns [`CryptoError::EncryptionFailed`] only on RNG failure.
pub fn rewrap_master_key(
    new_password: &[u8],
    mk: &MasterKey,
) -> CryptoResult<(ArgonParams, Vec<u8>)> {
    let salt = generate_salt()?;
    let argon_params = ArgonParams {
        algorithm: ArgonAlgorithm::Argon2id,
        memory_kb: MIN_MEMORY_KB,
        iterations: MIN_ITERATIONS,
        parallelism: MIN_PARALLELISM,
        salt_hex: salt_to_hex(&salt),
    };
    let kek = derive_with_domain(new_password, &argon_params, DOMAIN_KEK)?;
    let wrapped = wrap_envelope(mk.as_bytes(), &*kek, b"silosuite-v1-mk-kek")?;
    Ok((argon_params, wrapped))
}

/// Serialize the recovery-rewrap bundle for the WASM -> TS boundary.
///
/// Keys are `snake_case` to match the TS `RecoverInitiate` / `RewrapResult`
/// contract; byte fields are emitted as JSON number-arrays (the TS layer
/// base64-encodes them via `bytesToBase64`, the same convention
/// `createMasterKeyBundle` uses). `wrapped_mk_recovery` is null: recovery
/// preserves the BIP-39 phrase, so the existing recovery blob still unlocks
/// the (unchanged) MK and the server keeps it when this is null.
///
/// Extracted from the wasm-only binding so the boundary contract is
/// host-testable. The previous inline JSON used camelCase keys and omitted
/// `auth_key` entirely, so the recovery-initiate body deserialized to
/// `{email}` only and the server rejected it.
// Only called from the wasm bindings, which are cfg-gated to wasm32,
// so non-test host builds see no caller. Covered by the contract test
// below.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub(crate) fn rewrap_bundle_json(
    auth_key: &[u8],
    argon_params: &ArgonParams,
    wrapped_mk: &[u8],
) -> alloc::string::String {
    serde_json::json!({
        "auth_key": auth_key,
        "argon_params": argon_params,
        "wrapped_mk": wrapped_mk,
        "wrapped_mk_recovery": serde_json::Value::Null,
    })
    .to_string()
}

/// Recover an account using its BIP-39 phrase + per-user recovery salt.
///
/// The salt is the same one generated at signup and stored alongside
/// `wrapped_mk_recovery`. Server returns it on the recovery-preparation endpoint.
///
/// Returns the unwrapped master key. The caller is responsible for
/// generating a new password and calling [`rewrap_master_key`] to issue
/// fresh `wrappedMK` + `argon_params`.
///
/// # Errors
///
/// Returns [`CryptoError::DecryptionFailed`] if the phrase is wrong.
pub fn recover_master_key(
    phrase: &RecoveryPhrase,
    recovery_salt: &[u8; 16],
    wrapped_mk_recovery: &[u8],
) -> CryptoResult<MasterKey> {
    let rkek = derive_recovery_kek(phrase, recovery_salt)?;
    let mut mk_bytes = unwrap_envelope(
        wrapped_mk_recovery,
        rkek.as_bytes(),
        b"silosuite-v1-mk-rkek",
    )?;
    if mk_bytes.len() != MASTER_KEY_LEN {
        mk_bytes.zeroize();
        return Err(CryptoError::InvalidLength);
    }
    let mut mk = [0u8; MASTER_KEY_LEN];
    mk.copy_from_slice(&mk_bytes);
    mk_bytes.zeroize();
    Ok(MasterKey(mk))
}

// -------------------------------------------------------------------------
// Internals
// -------------------------------------------------------------------------

fn derive_with_domain(
    password: &[u8],
    argon_params: &ArgonParams,
    domain: &[u8],
) -> CryptoResult<zeroize::Zeroizing<[u8; 32]>> {
    // Domain separation: prepend domain to password
    let mut input = zeroize::Zeroizing::new(Vec::with_capacity(domain.len() + 1 + password.len()));
    input.extend_from_slice(domain);
    input.push(0u8);
    input.extend_from_slice(password);

    let kek = derive_kek(&input, argon_params)?;
    let bytes = zeroize::Zeroizing::new(*kek.as_bytes());
    // `kek` (DerivedKek) and `input` zeroize on drop
    Ok(bytes)
}

fn base64_encode(bytes: &[u8]) -> alloc::string::String {
    use alloc::string::String;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[((b0 & 0x03) << 4 | b1 >> 4) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((b1 & 0x0f) << 2 | b2 >> 6) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signup_unlock_roundtrip() {
        let password = b"correct horse battery staple";
        let created = create_master_key_bundle(password, false).unwrap();

        let mk = unlock_master_key(
            password,
            &created.bundle.argon_params,
            &created.bundle.wrapped_mk,
        )
        .unwrap();

        // MK is non-zero
        assert!(mk.as_bytes().iter().any(|&b| b != 0));
    }

    #[test]
    fn unlock_with_wrong_password_fails() {
        let created = create_master_key_bundle(b"right", false).unwrap();
        assert!(unlock_master_key(
            b"wrong",
            &created.bundle.argon_params,
            &created.bundle.wrapped_mk,
        )
        .is_err());
    }

    #[test]
    fn rewrap_with_new_password_works() {
        let created = create_master_key_bundle(b"old-pw", false).unwrap();
        let mk = unlock_master_key(
            b"old-pw",
            &created.bundle.argon_params,
            &created.bundle.wrapped_mk,
        )
        .unwrap();
        let mk_bytes_before = *mk.as_bytes();

        let (new_params, new_wrapped) = rewrap_master_key(b"new-pw", &mk).unwrap();

        let mk2 = unlock_master_key(b"new-pw", &new_params, &new_wrapped).unwrap();
        assert_eq!(&mk_bytes_before, mk2.as_bytes());
    }

    // Regression guard: the recovery-rewrap boundary JSON must use
    // snake_case keys, include auth_key, and emit byte fields as arrays.
    // The original wasm binding emitted camelCase + omitted auth_key, which
    // the server's RecoverInitiate deserializer rejected.
    #[test]
    fn g26_rewrap_bundle_json_contract() {
        // Use a real ArgonParams from the rewrap path (salt_hex is a
        // fixed-capacity string, awkward to hand-construct in a test).
        let created = create_master_key_bundle(b"pw", false).unwrap();
        let mk = unlock_master_key(
            b"pw",
            &created.bundle.argon_params,
            &created.bundle.wrapped_mk,
        )
        .unwrap();
        let (params, wrapped) = rewrap_master_key(b"new-pw", &mk).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&rewrap_bundle_json(&[1, 2, 3, 4], &params, &wrapped)).unwrap();
        // snake_case keys present (the contract the server + page expect)
        assert!(
            v.get("auth_key").is_some(),
            "auth_key must be present in the envelope"
        );
        assert!(v.get("argon_params").is_some());
        assert!(v.get("wrapped_mk").is_some());
        assert!(v.get("wrapped_mk_recovery").is_some());
        // no camelCase siblings (the pre-fix keys)
        assert!(
            v.get("argonParams").is_none(),
            "must not emit camelCase argonParams"
        );
        assert!(
            v.get("wrappedMk").is_none(),
            "must not emit camelCase wrappedMk"
        );
        // byte fields are number-arrays (TS bytesToBase64-converts them)
        assert!(v["auth_key"].is_array() && v["wrapped_mk"].is_array());
        assert!(v["wrapped_mk_recovery"].is_null());
    }

    #[test]
    fn recovery_phrase_recovers_mk() {
        use hex::FromHex;

        let created = create_master_key_bundle(b"forgotten", true).unwrap();
        let phrase = created.recovery_phrase.as_ref().unwrap();
        let wrapped_recovery = created.bundle.wrapped_mk_recovery.as_ref().unwrap();

        // Decode the hex-encoded recovery salt back to raw bytes. In
        // production the server reads the hex form from
        // storage, returns it on the recovery-preparation endpoint, and the browser
        // decodes it before calling recover_master_key. The test
        // mirrors that flow.
        let salt_hex = created.bundle.recovery_salt_hex.as_ref().unwrap();
        let salt: [u8; 16] = <[u8; 16]>::from_hex(salt_hex).unwrap();

        let mk_via_password = unlock_master_key(
            b"forgotten",
            &created.bundle.argon_params,
            &created.bundle.wrapped_mk,
        )
        .unwrap();
        let mk_via_recovery = recover_master_key(phrase, &salt, wrapped_recovery).unwrap();

        assert_eq!(mk_via_password.as_bytes(), mk_via_recovery.as_bytes());
    }

    #[test]
    fn auth_key_and_kek_differ() {
        let password = b"test password";
        let created = create_master_key_bundle(password, false).unwrap();
        let kek = derive_with_domain(password, &created.bundle.argon_params, DOMAIN_KEK).unwrap();
        let auth =
            derive_with_domain(password, &created.bundle.argon_params, DOMAIN_AUTH_KEY).unwrap();
        // Zeroizing doesn't implement PartialEq for the wrapped type;
        // dereference to the inner [u8; 32] for the comparison.
        assert_ne!(*kek, *auth);
    }
}
