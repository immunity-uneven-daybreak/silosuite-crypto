# Security policy

## Reporting a vulnerability

Report security issues privately through GitHub's private vulnerability
reporting on this repository — the **Security** tab, then **Report a
vulnerability** — as described in the
[README](README.md#reporting-a-vulnerability). Please don't open a public
issue for a suspected vulnerability, and don't look for a security email
address: private reporting on this repository is the only channel.

Reports are read and taken seriously. This is a small project, though —
there is no security team behind it and no guaranteed response time.

## Supported versions

The crate is at version 0.1.0 and not yet published to crates.io. Only
the latest commit on `main` is supported. There are no release branches,
no LTS versions, and no backports: security fixes land on `main` and
nowhere else. If you pin a git revision, picking up a fix means moving
your pin forward. The API is pre-1.0 and may change between those
revisions.

## Audit status

This library has not been independently audited (see the README's
[Audit trail](README.md#audit-trail) section). It composes established
primitives from the RustCrypto and dalek ecosystems, with BIP-39
recovery phrases from rust-bitcoin's `bip39`, rather than implementing
its own — but that is a statement about its dependencies,
not a substitute for an audit of this crate. Evaluate accordingly before
depending on it for anything critical.
