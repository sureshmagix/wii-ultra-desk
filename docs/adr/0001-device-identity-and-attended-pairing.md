# ADR 0001: Device identity, attended pairing, and coordinator authentication

- Status: accepted for Phase 2A implementation
- Date: 2026-10-07

## Context

Device locators, bookmarks, names, coordinator presence, and authorization
grants have different security meanings. Treating any one of them as another
would allow a guessed identifier or a compromised coordination service to grant
access. Phase 2A needs durable device identity and an attended trust bootstrap
before any remote operation is enabled.

The coordinator is deliberately not a trust authority: it can be unavailable or
malicious, can observe metadata and opaque relay traffic, and can attempt key
substitution or replay. It must not be able to make two devices trust different
keys without a human-visible failure.

## Decision

### Key material and durable storage

Each native agent owns two independently generated key pairs:

1. An Ed25519 signing key, used for coordinator challenges, identity-bundle
   signatures, trust-link attestations, and transcript bindings.
2. An X25519 static key used only by the Noise handshake. It is never derived
   from the Ed25519 key and is not reused as a signing key.

The Rust agent uses `ed25519-dalek` for Ed25519 and `snow` for the established
Noise Protocol Framework. Private key bytes are placed only in the OS credential
store through the Rust `keyring` crate: macOS Keychain, Windows Credential
Manager, or the Linux Secret Service. If protected storage is unavailable, the
agent fails closed; it does not fall back to a plaintext file or SQLite.

The agent creates a random 128-bit, base64url device locator. It is a routing
handle, not a secret or credential. The agent writes public identity metadata,
trusted peers, grants, revocations, and migration state into its local SQLite
database through `rusqlite`. Migrations and trust/grant changes execute in one
SQLite transaction. The database contains no private key material.

A device identity bundle contains:

- protocol version;
- locator;
- 32-byte Ed25519 public signing key;
- 32-byte Noise X25519 static public key;
- creation time; and
- Ed25519 signature over a domain-separated, length-delimited binary encoding
  of those preceding fields.

The fingerprint shown to a person is lowercase SHA-256 of the domain-separated
Ed25519 public key. Device display names are entirely local metadata and are
not signed identity claims.

### Attended pairing protocol

Pairing uses `Noise_XX_25519_ChaChaPoly_SHA256`, not a bespoke key exchange.
The coordinator relays only opaque Noise frames and cannot decrypt them.

1. The host owner creates a short-lived, single-use invitation locally. The
   displayed QR/manual payload includes the coordinator URL, host identity
   bundle, and a 256-bit random invitation token. The coordinator retains only
   a SHA-256 token hash, expiry, and host identity; the token is a rendezvous
   capability, not access authorization.
2. A controller submits the invitation token and its self-signed identity bundle.
   The coordinator routes this only to the invitation's host. The host agent
   displays the controller fingerprint and requires a local owner approval
   before relaying Noise frames.
3. The agents complete the Noise XX handshake with the exact three-message
   pattern. In the resulting encrypted transport, they exchange signed identity
   bundles and signatures binding each role, both bundles, and the Noise
   handshake hash. Each rejects a mismatch between the remote Noise static key
   and the remote bundle, an invalid bundle signature, a duplicate/expired
   invitation, or a replayed pairing identifier.
4. Both interfaces show the same short authentication string derived from the
   Noise handshake hash and both verified fingerprints. The host owner must
   compare/confirm it through an independent channel; the controller user also
   confirms. A locator, QR scan, or unverified public key by itself never
   creates trust.
5. Only after both confirmations does each agent atomically persist the peer's
   pinned signing and Noise keys, fingerprint, locator, and a default-empty
   grant set. The coordinator may then receive a signed mutual trust-link
   attestation. No remote operation is opened by pairing.

Pairing invitations expire after ten minutes, are consumed once, have bounded
frame counts/sizes, and are rate-limited. The UI must make cancellation and
expiry explicit. Re-pairing a known locator with a new key is rejected until the
old trust is explicitly revoked locally.

### Authenticated coordination

The Node coordinator stores public device registrations in SQLite. A WebSocket
connection has no authenticated state until it completes this server-issued
challenge:

1. `AUTH_BEGIN` supplies a schema-validated identity bundle.
2. The coordinator validates its self-signature and returns a random,
   connection-bound nonce with a short expiry.
3. `AUTH_PROVE` supplies an Ed25519 signature over a domain-separated encoding
   of the nonce, connection ID, locator, bundle fingerprint, and expiry.
4. The coordinator verifies the signature using the registered public key. A
   locator already registered with a different bundle is rejected rather than
   replaced. Authentication state is server-side only; a client field named
   `authenticated` is ignored and never consulted.

Only authenticated sessions may register presence, create an invitation, submit
pairing frames, submit a signed trust-link attestation, or signal a peer. Normal
signaling requires a current mutually signed trust link and an exact destination
locator/fingerprint match. Pairing frames can target only a live, unexpired host
invitation. The coordinator enforces message/body limits, schemas, nonce and
session expiry, per-IP and per-device token-bucket limits, a global connection
limit, and a per-device connection limit.

The coordinator stores public keys and metadata only. It never receives agent
private keys, unattended grants, plaintext Noise frames, SSH credentials, or
file contents. A coordinator compromise can deny service, reveal metadata, or
relay malformed frames, but cannot silently replace a pinned peer identity:
both agents compare the first-pairing authentication string and later verify
the persisted pinned keys on every session setup.

### Local Electron-to-agent IPC

The Electron renderer never connects to the agent. The Electron main process
uses a versioned local IPC protocol and exposes a narrow, redacted API through
the existing preload bridge. On Unix, the agent socket sits in a directory owned
by the logged-in user (`0700`) and has mode `0600`; the agent also validates the
peer UID (`getpeereid` on macOS or `SO_PEERCRED` on Linux). On Windows, the
agent uses a named pipe protected by an ACL containing only the expected user
SID and the authorized service/broker SID. Cross-user clients are rejected.

Only status, invitation creation/cancellation, pairing approval/rejection,
trust-list, grant-management, and revocation requests are planned IPC methods.
Private keys, pairing secrets, raw Noise frames, and OS credential-store values
are never returned. The service/broker design is specified here but requires
native platform validation before being claimed as operational.

## Threat assumptions and limits

- Operating-system compromise, malware with the user's credential-store access,
  or a user approving the wrong verification string is out of scope for this
  phase; all are documented security boundaries, not accepted silent failures.
- TLS protects transport to the coordinator but is not the peer-identity trust
  mechanism. Pairing remains safe against coordinator key substitution only
  when the humans perform the authentication-string comparison.
- Expiry uses wall time with bounded clock-skew tolerance. Existing pinned keys
  always take precedence over a newly presented key for the same locator.
- Device trust is local and explicit. Bookmarks, display names, online presence,
  and a coordinator registration are never authorization grants.

## Consequences

Phase 2A can establish, preserve, revoke, and expose trust state, but it does
not implement WebRTC transport, desktop capture/input, SSH, files, TURN
credentials, unattended session execution, or installers. Those features must
verify the pinned identity and enforce the native-agent grant on every future
operation.

## References

- [Noise Protocol Framework](https://noiseprotocol.org/noise.html)
- [snow 0.10 Rust implementation](https://docs.rs/snow/0.10.0/snow/)
- [ed25519-dalek](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/)
- [keyring secure-store backends](https://docs.rs/keyring/latest/keyring/v1/)
- [Node.js SQLite API](https://nodejs.org/api/sqlite.html)
