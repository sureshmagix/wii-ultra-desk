# Implementation phases and acceptance gates

## Phase 1 — foundation (this package)

Implemented: local Electron bookmark shell; health-only coordinator;
standalone unattended policy; Node tests; Rust status-probe source; architecture
and relay template. No authenticated remote operations exist.

Validation results are recorded separately in VALIDATION.md.

## Phase 2 — authenticated connectivity

- Select and review identity/pairing protocol; generate device keys in protected storage.
- Authenticated registration, presence and signaling with rate limits and revocation.
- WebRTC transport in UI and native agent; do not rely on Electron staying open
  for headless/unattended transport.
- Short-lived TURN credentials, private-peer restrictions, allocation quotas.
- Host authorization enforcement and session binding; port policy tests to Rust.
- Verify two distinct internet connections, same LAN, CGNAT, blocked UDP,
  forced relay and identity spoof/replay rejection. Capture route evidence.

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
