# silosuite-crypto

> Cryptographic primitives for SiloSuite. A single Rust implementation used
> natively on the server and in the browser via WebAssembly.

A small, misuse-resistant end-to-end-encryption API: authenticated encryption
with versioned envelopes, password-based key derivation, key wrapping, sealed
boxes, signatures, and BIP-39 recovery phrases. It composes established
primitives; it implements none of its own.

## Install

Not yet published to crates.io. Add it as a git dependency:

```toml
[dependencies]
silosuite-crypto = { git = "https://github.com/immunity-uneven-daybreak/silosuite-crypto" }
```

## Usage

```rust
use silosuite_crypto::aead::{wrap_envelope, unwrap_envelope};
use silosuite_crypto::CryptoResult;

fn example() -> CryptoResult<()> {
    // A 32-byte key. Derive real keys with the `kdf` or `master_key`
    // modules rather than hard-coding one.
    let key = [0x42u8; 32];

    // `aad` is authenticated but not encrypted. Unwrapping with different
    // aad fails, which binds a ciphertext to the context it was made for.
    let envelope = wrap_envelope(b"hello world", &key, b"note:42")?;
    let plaintext = unwrap_envelope(&envelope, &key, b"note:42")?;

    assert_eq!(plaintext, b"hello world");
    Ok(())
}
```

## Why Rust

This crate is the security-critical core of anything built on it: master
keys, wrapped private keys, AEAD primitives, KDF tuning, recovery phrases,
and asymmetric crypto all pass through it. A bug here compromises every user
of the application above it.

Rust gives us:

- **Memory safety without GC.** No buffer overflows, no use-after-free,
  no double-free.
- **`Zeroize` and `ZeroizeOnDrop` everywhere.** Secret material is wiped
  from memory after use; `subtle::ConstantTimeEq` for all sensitive
  comparisons.
- **Established primitive crates.** Every algorithm comes from RustCrypto
  or dalek-cryptography, with BIP-39 recovery phrases from rust-bitcoin's
  `bip39`. The table below names the exact crate behind each operation.
- **`#![deny(unsafe_code)]`** at the crate root. The only `unsafe` in this
  crate is the WASM zeroizing-allocator wrapper (`zeroizing_alloc.rs`,
  module-scoped `#![allow(unsafe_code)]`); every other module is
  unsafe-free.
- **Single source of truth for browser and server.** The same Rust code,
  built once for native and once for WASM, so there is no second
  implementation to drift out of sync.

## Build

### Native

```bash
cargo build --release
cargo test
```

### WebAssembly

```bash
wasm-pack build --target web --out-dir pkg --release
```

The generated `pkg/` directory is a standard `wasm-pack` package. It can be
consumed by any bundler, or imported directly:

```js
import init, { wrapEnvelope, createMasterKeyBundle } from './pkg/silosuite_crypto.js';
await init(); // initialize the WASM module
```

## Algorithms

| Operation             | Algorithm                          | Crate                     |
| --------------------- | ---------------------------------- | ------------------------- |
| Symmetric AEAD        | XChaCha20-Poly1305 (24-byte nonce) | `chacha20poly1305`        |
| KDF (password)        | Argon2id (m=64MB, t=2, p=1 floor)  | `argon2`                  |
| KDF (subkey deriv.)   | HKDF-SHA256                        | `hkdf` + `sha2`           |
| Asymmetric (DH)       | X25519                             | `x25519-dalek`            |
| Sealed box            | X25519 + XChaCha20-Poly1305 (ChaChaBox) | `crypto_box`         |
| Signatures            | Ed25519                            | `ed25519-dalek`           |
| Recovery phrases      | BIP-39 (24 words / 256-bit ent.)   | `bip39`                   |
| Constant-time compare | —                                  | `subtle`                  |
| Memory zeroization    | —                                  | `zeroize`                 |
| Random source         | OS RNG (browser: WebCrypto)        | `getrandom` w/ `js` feat. |

## Envelope format

All ciphertext blobs use a 2-byte version prefix:

```
[ version (2B BE) | nonce (24B) | ciphertext + tag (16B) ]
```

Currently `0x0001` = XChaCha20-Poly1305. Future versions are added
without breaking old data: the unwrap function dispatches on the version
prefix.

## Master-key flow

See `src/master_key.rs` for the canonical reference. Two-secret design:

- `AuthKey = Argon2id(domain="silosuite-v1-auth-key" || password, salt, params)` — server-bound
- `KEK = Argon2id(domain="silosuite-v1-kek" || password, salt, params)` — client-only
- `MK = random_bytes(32)` — generated once
- `wrappedMK = AEAD(MK, KEK)` — server stores
- `wrappedMKRecovery = AEAD(MK, RKEK)` — optional, for BIP-39 recovery
- `RKEK = Argon2id(phrase, per_user_recovery_salt)` — derived from BIP-39 phrase (16-byte per-user salt)

The server never sees password, KEK, RKEK, MK, or private keys.

## Tests

```bash
cargo test                    # unit tests
cargo test --release          # release-mode tests (catches optimization-sensitive issues)
cargo clippy -- -D warnings   # lint
```

RFC 5869 HKDF test vectors are included in `src/hkdf.rs`.

Consumers are encouraged to run `cargo audit` and `cargo deny` under their
own advisory and licence policy.

## Security boundaries

This crate **does not**:
- Send anything over the network.
- Read or write files.
- Log anything (the application layer logs error CODES, never the keys
  themselves; the error type is deliberately opaque).
- Implement TLS, JWT, or any higher-level protocol.

This crate **does**:
- Generate random keys.
- Encrypt and decrypt blobs.
- Derive subkeys.
- Sign and verify messages.
- Validate parameter floors (Argon2id minimum).

## Reporting a vulnerability

Please report security issues privately through GitHub's private
vulnerability reporting on this repository — the **Security** tab, then
**Report a vulnerability** — rather than opening a public issue.

## Audit trail

This library has not yet been independently audited. If and when an
external audit is completed, its report will be linked here.

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE) or
<http://www.apache.org/licenses/LICENSE-2.0>).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be licensed as above, without any additional terms or
conditions.
