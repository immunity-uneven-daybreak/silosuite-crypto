// SPDX-License-Identifier: Apache-2.0
//! WebAssembly bindings.
//!
//! Compiled into a `wasm32-unknown-unknown` artifact and consumed from
//! JavaScript. `wasm-bindgen` generates TypeScript declarations and a JS
//! glue module so callers can invoke these functions naturally.
//!
//! Build: `wasm-pack build --target web`. Output goes to `pkg/`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use wasm_bindgen::prelude::*;

use crate::aead::{unwrap_envelope, wrap_envelope};
use crate::asymmetric::{
    generate_ed25519_keypair, generate_x25519_keypair, open_sealed, seal_to_pubkey,
    sign as ed_sign, verify as ed_verify,
};
use crate::dek::{generate_dek, unwrap_dek, wrap_dek};
use crate::master_key::{
    create_master_key_bundle, derive_auth_key, recover_master_key as recover_mk,
    rewrap_bundle_json, rewrap_master_key, unlock_master_key, MasterKey, SignupBundle,
};
use crate::recovery::{generate_recovery_phrase, RecoveryPhrase};

/// Initialize panic hook for better error reporting in browser console.
#[wasm_bindgen(start)]
pub fn _init() {
    console_error_panic_hook::set_once();
}

// -------------------------------------------------------------------------
// AEAD
// -------------------------------------------------------------------------

/// Encrypt `plaintext` under `key` (32 bytes) with optional `aad`.
///
/// Returns versioned ciphertext envelope.
#[wasm_bindgen(js_name = wrapEnvelope)]
pub fn js_wrap_envelope(
    plaintext: &[u8],
    key: &[u8],
    aad: &[u8],
) -> Result<alloc::boxed::Box<[u8]>, JsValue> {
    wrap_envelope(plaintext, key, aad)
        .map(Vec::into_boxed_slice)
        .map_err(to_js_error)
}

/// Decrypt a versioned ciphertext envelope under `key` and `aad`.
#[wasm_bindgen(js_name = unwrapEnvelope)]
pub fn js_unwrap_envelope(
    envelope: &[u8],
    key: &[u8],
    aad: &[u8],
) -> Result<alloc::boxed::Box<[u8]>, JsValue> {
    unwrap_envelope(envelope, key, aad)
        .map(Vec::into_boxed_slice)
        .map_err(to_js_error)
}

// -------------------------------------------------------------------------
// Master-key bundle
// -------------------------------------------------------------------------

/// Create a fresh master-key bundle for signup.
///
/// Returns a JSON string the caller parses. The JSON contains the
/// `bundle` object (to send to the server) and an optional
/// `recoveryPhrase` (to display to the user once if requested).
#[wasm_bindgen(js_name = createMasterKeyBundle)]
pub fn js_create_master_key_bundle(
    password: &[u8],
    include_recovery: bool,
) -> Result<String, JsValue> {
    let created = create_master_key_bundle(password, include_recovery).map_err(to_js_error)?;

    let bundle_json = serde_json::to_value(&created.bundle)
        .map_err(|e| JsValue::from_str(&format!("serialize bundle: {e}")))?;

    // BOUNDARY NOTE: the recovery phrase is converted to a String for
    // the JSON return value. JS strings are immutable and GC-managed --
    // once they leave the WASM boundary, they cannot be wiped on
    // demand. This is a known limitation of the WASM-as-crypto-core
    // pattern; in practice the recovery phrase is shown to the user
    // for ~30 seconds at signup and then expected to be written down
    // / pasted into a password manager. The DOM nodes that display
    // it would hold the same string regardless. If we ever need to
    // tighten this, the right move is an opaque handle JS retrieves
    // word-by-word with explicit dispose, but that's a significant
    // API change.
    let phrase = created
        .recovery_phrase
        .as_ref()
        .map(|p| p.as_str().to_string());

    let result = serde_json::json!({
        "bundle": bundle_json,
        "recoveryPhrase": phrase,
    });

    Ok(result.to_string())
}

/// Derive ONLY the AuthKey from password + Argon2id params. Used at
/// login: the server sends `argon_params` from the login-preparation endpoint, the
/// browser derives the AuthKey here and POSTs it to the login endpoint.
///
/// Does NOT derive the KEK (that happens at unlock time). This split
/// avoids running the full 64MB Argon2id KDF twice when only the
/// server-bound proof is needed for the round-trip.
#[wasm_bindgen(js_name = deriveAuthKey)]
pub fn js_derive_auth_key(
    password: &[u8],
    argon_params_json: &str,
) -> Result<alloc::boxed::Box<[u8]>, JsValue> {
    let argon_params: crate::kdf::ArgonParams = serde_json::from_str(argon_params_json)
        .map_err(|e| JsValue::from_str(&format!("parse argon params: {e}")))?;

    let auth_key = derive_auth_key(password, &argon_params).map_err(to_js_error)?;
    // The returned Box transfers ownership of the AuthKey bytes to
    // the wasm-bindgen glue, which copies them into a JS Uint8Array.
    // The Rust-side Box drops after that copy, but the WASM
    // allocator does not guarantee zeroization of freed pages.
    //
    // The defense-in-depth contract is JS-side: callers MUST invoke
    // wipeSecret on the returned Uint8Array as soon as the AuthKey
    // has been used (typically: derive, send to the login endpoint, wipe).
    // The calling JS module owns that wipe, as part of its login and
    // unlock flow.
    let bytes: Vec<u8> = auth_key.to_vec();
    Ok(bytes.into_boxed_slice())
}

/// Unlock a stored master-key bundle. Returns 32-byte MK.
///
/// `bundleJson` is the JSON form of the SignupBundle the server stores
/// (or whatever subset is needed: argon_params + wrapped_mk).
///
/// SAME BOUNDARY CONTRACT AS deriveAuthKey: the returned Uint8Array
/// holds the most sensitive secret this library handles. The JS-side
/// caller MUST call wipeSecret on it after the Master Key has been
/// used to derive its child DEKs. The calling JS module owns that wipe
/// as part of its session-management flow.
#[wasm_bindgen(js_name = unlockMasterKey)]
pub fn js_unlock_master_key(
    password: &[u8],
    argon_params_json: &str,
    wrapped_mk: &[u8],
) -> Result<alloc::boxed::Box<[u8]>, JsValue> {
    let argon_params: crate::kdf::ArgonParams = serde_json::from_str(argon_params_json)
        .map_err(|e| JsValue::from_str(&format!("parse argon params: {e}")))?;

    let mk = unlock_master_key(password, &argon_params, wrapped_mk).map_err(to_js_error)?;
    let bytes: Vec<u8> = mk.as_bytes().to_vec();
    Ok(bytes.into_boxed_slice())
}

/// Rewrap an MK under a new password. Returns JSON `{ argonParams, wrappedMk }`.
#[wasm_bindgen(js_name = rewrapMasterKey)]
pub fn js_rewrap_master_key(new_password: &[u8], mk_bytes: &[u8]) -> Result<String, JsValue> {
    if mk_bytes.len() != 32 {
        return Err(JsValue::from_str("MK must be 32 bytes"));
    }
    let mut mk = [0u8; 32];
    mk.copy_from_slice(mk_bytes);
    let mk = MasterKey(mk);

    let (params, wrapped) = rewrap_master_key(new_password, &mk).map_err(to_js_error)?;
    // Also derive the new AuthKey (server verifier) -- the rewrap path
    // previously omitted it AND used camelCase keys, so the recovery-initiate
    // body deserialized to {email} only and the server rejected it. Serialize
    // via the host-tested rewrap_bundle_json (snake_case keys, byte fields as
    // arrays; TS base64-encodes them, same as createMasterKeyBundle).
    let auth_key = derive_auth_key(new_password, &params).map_err(to_js_error)?;
    Ok(rewrap_bundle_json(&auth_key[..], &params, &wrapped))
}

/// Recover MK using a BIP-39 phrase + per-user recovery salt + the
/// stored `wrappedMkRecovery`. Salt is hex-encoded as it came from
/// the server.
#[wasm_bindgen(js_name = recoverMasterKey)]
pub fn js_recover_master_key(
    phrase: &str,
    recovery_salt_hex: &str,
    wrapped_mk_recovery: &[u8],
) -> Result<alloc::boxed::Box<[u8]>, JsValue> {
    let phrase = RecoveryPhrase::from_phrase(phrase).map_err(to_js_error)?;
    if recovery_salt_hex.len() != 32 {
        return Err(JsValue::from_str("recovery_salt_hex must be 32 chars"));
    }
    let mut salt = [0u8; 16];
    for i in 0..16 {
        let hi = decode_hex_nibble(recovery_salt_hex.as_bytes()[2 * i])?;
        let lo = decode_hex_nibble(recovery_salt_hex.as_bytes()[2 * i + 1])?;
        salt[i] = (hi << 4) | lo;
    }
    let mk = recover_mk(&phrase, &salt, wrapped_mk_recovery).map_err(to_js_error)?;
    let bytes: Vec<u8> = mk.as_bytes().to_vec();
    Ok(bytes.into_boxed_slice())
}

fn decode_hex_nibble(c: u8) -> Result<u8, JsValue> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(JsValue::from_str("invalid hex character in recovery salt")),
    }
}

// -------------------------------------------------------------------------
// DEK helpers
// -------------------------------------------------------------------------

/// Generate a fresh 32-byte DEK.
#[wasm_bindgen(js_name = generateDek)]
pub fn js_generate_dek() -> Result<alloc::boxed::Box<[u8]>, JsValue> {
    let dek = generate_dek().map_err(to_js_error)?;
    Ok(dek.to_vec().into_boxed_slice())
}

/// Wrap a DEK under MK with the given AAD.
#[wasm_bindgen(js_name = wrapDek)]
pub fn js_wrap_dek(dek: &[u8], mk: &[u8], aad: &[u8]) -> Result<alloc::boxed::Box<[u8]>, JsValue> {
    if dek.len() != 32 || mk.len() != 32 {
        return Err(JsValue::from_str("DEK and MK must be 32 bytes each"));
    }
    use zeroize::Zeroizing;
    let mut dek_arr = Zeroizing::new([0u8; 32]);
    dek_arr.copy_from_slice(dek);
    let mut mk_arr = Zeroizing::new([0u8; 32]);
    mk_arr.copy_from_slice(mk);
    wrap_dek(&*dek_arr, &*mk_arr, aad)
        .map(Vec::into_boxed_slice)
        .map_err(to_js_error)
}

/// Unwrap a wrapped DEK.
#[wasm_bindgen(js_name = unwrapDek)]
pub fn js_unwrap_dek(
    wrapped: &[u8],
    mk: &[u8],
    aad: &[u8],
) -> Result<alloc::boxed::Box<[u8]>, JsValue> {
    if mk.len() != 32 {
        return Err(JsValue::from_str("MK must be 32 bytes"));
    }
    // Hold the MK copy in a Zeroizing<[u8; 32]> so the stack-allocated
    // bytes are explicitly wiped when this function returns. Stack
    // frames are NOT auto-zeroed on return; the bytes persist in
    // freed-stack memory until overwritten.
    use zeroize::Zeroizing;
    let mut mk_arr = Zeroizing::new([0u8; 32]);
    mk_arr.copy_from_slice(mk);
    let dek = unwrap_dek(wrapped, &*mk_arr, aad).map_err(to_js_error)?;
    Ok(dek.to_vec().into_boxed_slice())
}

// -------------------------------------------------------------------------
// Sealed boxes (X25519)
// -------------------------------------------------------------------------

/// Anonymously encrypt a message to a recipient's X25519 public key.
#[wasm_bindgen(js_name = sealToPubkey)]
pub fn js_seal_to_pubkey(
    recipient_pubkey: &[u8],
    plaintext: &[u8],
) -> Result<alloc::boxed::Box<[u8]>, JsValue> {
    if recipient_pubkey.len() != 32 {
        return Err(JsValue::from_str("X25519 pubkey must be 32 bytes"));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(recipient_pubkey);
    seal_to_pubkey(&pk, plaintext)
        .map(Vec::into_boxed_slice)
        .map_err(to_js_error)
}

/// Open a sealed box.
#[wasm_bindgen(js_name = openSealed)]
pub fn js_open_sealed(
    recipient_secret: &[u8],
    sealed: &[u8],
) -> Result<alloc::boxed::Box<[u8]>, JsValue> {
    if recipient_secret.len() != 32 {
        return Err(JsValue::from_str("X25519 secret must be 32 bytes"));
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(recipient_secret);
    open_sealed(&sk, sealed)
        .map(Vec::into_boxed_slice)
        .map_err(to_js_error)
}

// -------------------------------------------------------------------------
// Recovery phrases (standalone, e.g., for re-displaying or validating)
// -------------------------------------------------------------------------

/// Generate a fresh 24-word BIP-39 recovery phrase.
#[wasm_bindgen(js_name = generateRecoveryPhrase)]
pub fn js_generate_recovery_phrase() -> Result<String, JsValue> {
    let p = generate_recovery_phrase().map_err(to_js_error)?;
    Ok(p.as_str().to_string())
}

/// Validate a recovery phrase (BIP-39 checksum + wordlist).
#[wasm_bindgen(js_name = validateRecoveryPhrase)]
pub fn js_validate_recovery_phrase(phrase: &str) -> bool {
    RecoveryPhrase::from_phrase(phrase).is_ok()
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

fn to_js_error<E: core::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}
