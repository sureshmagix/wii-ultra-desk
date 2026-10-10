# Phase 2A local development harness

This repository contains two different development checks. Neither is a remote
desktop session and neither enables unattended access.

## Native two-agent coordinator harness

```bash
npm run dev:native-two-agent
```

This starts an in-memory loopback coordinator and two separate Rust native-agent
processes with different protected-store identities. Both perform the real
server nonce/Ed25519 proof flow. It deletes only its temporary SQLite state on
exit; the platform credential store may retain development key entries associated
with those temporary paths. It deliberately does **not** pair the agents, add a
trust link, request a TURN credential, create a WebRTC peer connection, or claim
an authenticated remote session.

## Coordinator authentication harness

```bash
npm ci
npm run dev:two-device
```

The harness creates two ephemeral development Ed25519 identities, completes
server-issued coordinator challenges, creates a single-use invitation, delivers
the request only to the intended host, and requires host approval before the
coordinator relays opaque frames. It does **not** run the native agent's Noise
transport, compare a short authentication string, persist a trusted peer, send
a trust attestation, or claim that pairing/authenticated remote access succeeded.

Use `npm test` for the full coordinator authorization test suite. It includes
key substitution, replay, expiry, rate limit, signaling authorization,
revocation, and restart-persistence scenarios.

## Native-agent identity and policy checks

```bash
cargo test --manifest-path agent/Cargo.toml --locked

# Use separate throwaway state directories for two development identities.
cargo run --manifest-path agent/Cargo.toml --locked -- init --state-dir /tmp/wii-agent-host
cargo run --manifest-path agent/Cargo.toml --locked -- init --state-dir /tmp/wii-agent-controller
```

The `init` output contains only the public locator and fingerprint. Its private
Ed25519 and Noise static keys are held by the supported OS credential store;
the agent SQLite database stores public identity metadata, trust/grant state,
and migrations. The Rust tests run the same unattended-policy conformance
vectors as JavaScript and verify trust/grant persistence and revocation across
a SQLite restart.

## Not yet a live two-agent pairing command

The native Noise frame transport, user-facing SAS confirmation, and the
credential-checked Electron-to-agent IPC service are not connected into a live
two-agent command in this phase. Do not use a coordinator trust attestation as
evidence that an unverified or scripted pairing is safe. Follow
[ADR 0001](adr/0001-device-identity-and-attended-pairing.md) when integrating
that transport: local host approval and independent short-authentication-string
comparison are mandatory before persisting trust.
