# Implementation phases and acceptance gates

## Phase 1 — foundation (this package)

Implemented: local Electron bookmark shell; health-only coordinator;
standalone unattended policy; Node tests; Rust status-probe source; architecture
and relay template. No authenticated remote operations exist.

Validation results are recorded separately in VALIDATION.md.

## Phase 2A — device identity and authenticated coordination

Implemented and test-covered in this source package: native-agent Ed25519 and
Noise static identity generation; protected-store source integration; SQLite
trust/grant migrations; Node coordinator Ed25519 challenge authentication;
immutable locator/key registration; single-use invitations; host approval gate;
opaque pairing-frame routing; bilateral signed trust attestations; restricted
presence/signaling; expiry, request-size, rate, and connection limits; shared
JavaScript/Rust unattended-policy vectors; and a redacted Electron status view.

Not complete: a native-agent-to-native-agent Noise transport, human SAS
confirmation UI, agent-to-coordinator client, credential-checked local IPC
server, and a live two-agent pair command. The coordinator trust-attestation
test is a coordinator authorization test, not evidence that Noise pairing has
completed. See ADR 0001.

## Phase 2B — authenticated WebRTC transport boundary

Implemented and actually tested on local Intel macOS: the Rust agent has a
pure-Rust WebRTC data-channel transport, bounded status-only messages and
backpressure, signed short-lived SDP envelopes, replay/substitution/expiry
rejection, host/direct selected-candidate evidence, rustls-backed native
coordinator challenge authentication, and a coordinator TURN REST credential
endpoint guarded by trust and `desktop.view`. The coturn local fixture provides
generated local secrets, quotas, a bounded port range, and private-destination
restrictions; it was not launched here.

Still required before this is a real two-device product connection:

- Wire Noise XX frames and transcript bindings through two native agents; require
  host local approval and independent SAS confirmation before writing trust.
- Implement and validate credential-checked local IPC on macOS, Windows and
  Linux. Electron main must use it; renderers remain unprivileged.
- Connect two live agents through the authenticated coordinator, consume signed
  offers/answers/candidates, request scoped TURN credentials, and enforce a
  fresh local `desktop.view` decision on every new/reconnected session.
- Add the session controller state machine: cancellation, expiry, cleanup,
  bounded retry/backoff, reauthentication after reconnect, ICE restart, and
  desktop diagnostics fed from selected candidate pairs rather than guesses.
- Validate actual same-LAN, server-reflexive, forced-relay, allocation failure,
  credential expiry, CGNAT, blocked UDP, and TURN/TLS cases on target hardware.

See [ADR 0002](adr/0002-native-webrtc-transport-and-turn.md) and
[WEBRTC_TESTING.md](WEBRTC_TESTING.md). The existing direct test is host/direct
loopback evidence only, not a completed native pairing or relay fallback claim.

## Phase 3 — desktop control

- Native capture and input adapters; React session UI; controller/host roles.
- Quality modes, multi-monitor/DPI coordinate mapping, keyboard layouts,
  performance telemetry and input cleanup on disconnect.
- Acceptance on real Windows, Ubuntu X11/Wayland, Intel Mac and Apple Silicon.
- ARM64 boards get separate measured profiles and feature support tables.

## Phase 4 — SSH and file transfer

- Embedded terminal, actual SSH tunnel, pinned host keys and normal SSH auth.
- Authorized two-pane file manager, resume, integrity, quotas, collision handling.
- Test large files, interrupted transfers, traversal/symlink attacks and contention
  with desktop streaming. Do not expose arbitrary proxy destinations.

## Phase 5 — unattended service lifecycle

- Owner opt-in, trusted device management, expiring scoped grants, local disconnect.
- Protected persistence, startup, session helpers, expiry/revocation termination.
- Test reconnect after agent restart, user logout, OS reboot, sleep/wake and
  password/permission changes. Mark unsupported login/preboot cases explicitly.
- Local metadata migration to SQLite; credentials remain in protected stores.

## Phase 6 — packaged pilot and release hardening

- Build signed Windows/macOS packages, Ubuntu and ARM64 packages.
- Installer repair/uninstall; service cleanup; signed updates and rollback protection.
- SBOM and dependency review, vulnerability scanning, fuzzing, independent assessment.
- Defined pilot concurrency/bandwidth goals; load test coordinator and TURN.
- Test clean-machine installs with no developer tools, upgrades and recovery.

## Needed before deployment, not required to review this source

- Git repository destination (suggestion: wii-ultra-desk).
- Utho test host and chosen DNS names / dedicated TURN address strategy.
- Exact Raspberry Pi models, Jetson models and OS/JetPack versions.
- OS versions for both Mac architectures, especially any Ventura-only requirement.
- Code-signing identities and update hosting when reaching packaged pilot.

No cloud resources, DNS records, repositories or services were modified by
preparing this package. The next concrete coding phase is Phase 2.
