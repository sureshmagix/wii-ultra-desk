# Progress — 10 October 2026

## Release validation — 10 October 2026

The current Phase 5 commit candidate was revalidated without source changes.

| Command | Result |
| --- | --- |
| `npm run build` | Passed: desktop UI build, syntax/repository hygiene for 25 JavaScript files, all 25 Node tests, and locked native-agent build. |
| `npm run test:native-unattended-lifecycle` | Passed on this macOS host: the daemon remained independent of Electron, rejected malformed local IPC, and acknowledged signed remote revocation only after host-side termination state changed. |
| `cargo fmt --manifest-path agent/Cargo.toml -- --check`; `git diff --check` | Passed. |

The platform and two-machine limitations, blockers, and next task remain those
recorded in the Phase 5 handoff below.

## Phase 5 — operational unattended-access lifecycle and background services

Phase 5 now persists and enforces the unattended lifecycle in the native
agent. It is default-off and deliberately local-owner enabled; it does not
turn bookmarks into authority or claim a physical unattended desktop, SSH, or
file session. The only implemented remote lifecycle action is signed controller
revocation with host acknowledgement, not a generic remote command listener.

### Changed

- Added SQLite migration v2 for explicit unattended enablement/scopes/epoch,
  active five-minute service leases, remote-revocation state, and bounded
  security-event history. Identity keys remain in OS credential storage;
  database records contain public identity/lifecycle metadata only.
- Added local owner commands for deliberate enable/disable, status, trusted
  device/grant inspection, event history, local disconnect, grant renewal via
  replacement, local revocation, and remote-revoke requests. Background host
  paths must opt into `--unattended`; they recheck scopes, grants, revocation,
  expiry, clock anomaly, enablement, and lease state while active.
- Added `daemon`, a native service that remains after Electron closes. On Unix
  it exposes only a mode-0600, peer-UID-checked local lifecycle socket. Deep
  state paths use a deterministic owner-only short `/tmp` control directory to
  remain within macOS Unix-socket limits. Windows deliberately has no local
  control transport yet; it does not claim a named-pipe implementation.
- Added signed `control.revocation` / acknowledgement signaling. A controller
  records pending before sending; the host authenticates the exact pinned
  controller, persists the request, revokes its identity, marks active service
  sessions terminated, and only then signs the acknowledgement. Offline or
  unacknowledged requests remain pending rather than reporting a false success.
- Added sender-validated Electron IPC and UI actions for local Disconnect and
  Disable. The renderer cannot provide a command, socket path, executable, or
  confirmation token; Electron stops its owned children then invokes a fixed
  native `local-control` action.
- Added per-user Ubuntu systemd and macOS LaunchAgent templates plus a separate
  unprivileged Ubuntu/Windows headless SSH/files core template. Nothing was
  installed on this development machine. Added platform limitations, exact
  test-machine install/uninstall effects, and a reproducible two-device guide.
- Added a native lifecycle harness that proves default-off daemon behavior,
  malformed local IPC rejection, and signed remote revocation/host
  acknowledgement with paired ephemeral agents through the loopback
  coordinator.

### Commands run and actual results

| Command | Result |
| --- | --- |
| `npm run build` | Passed: desktop UI build, syntax/repository hygiene for 25 JavaScript files, all 25 Node tests, and locked native-agent build. |
| `npm run test:native-unattended-lifecycle` | Passed on this macOS host. It built the locked agent, ran an independent daemon after pairing two ephemeral identities, rejected malformed local IPC, and completed a signed remote-revocation acknowledgement. This is not a live desktop/SSH/file-operation termination or two-machine result. |
| `cargo test --manifest-path agent/Cargo.toml --locked --no-fail-fast` | Passed: all 22 native tests, including the real local WebRTC loopback test, unattended store/lifecycle tests, and a constructed Phase 4 database migration that initializes v2 default-off state. |
| `cargo fmt --manifest-path agent/Cargo.toml -- --check`; `git diff --check` | Passed at the focused validation point. |

### Still unvalidated

- No physical service install/uninstall, window-close observation, agent
  restart, OS reboot, sleep/wake, network-change, login-session, TCC/desktop
  permission, or cross-user local-socket test has run.
- No live unattended desktop, SSH, or file channel was terminated by grant
  expiry, local disconnect/disable, local revocation, remote revocation, or
  offline lease expiry. The source and harness establish lifecycle wiring, not
  those hardware/OS observations.
- No Windows named-pipe/SID ACL or interactive-desktop broker exists; Windows
  remains headless-core template only. Ubuntu systemd/Secret Service and macOS
  LaunchAgent/Keychain signing behavior are untested. No login screen,
  FileVault/preboot, Windows secure desktop, Linux display manager, or Wayland
  portal access is claimed.

### Exact next task

Use two authorized machines to execute every step in
[the unattended acceptance guide](UNATTENDED_ACCEPTANCE.md), recording service
installation effects, enabled scope/grant expiry, exact close timing and audit
events for active desktop/SSH/file channels, offline pending/acknowledged remote
revocation, cross-user local IPC rejection, controller-key replacement,
migration from a preserved Phase 4 database, agent restart/reboot, sleep/wake,
and network change. Implement the missing Windows named-pipe/SID ACL and
interactive-user broker only after this platform-specific evidence is captured;
do not claim login-screen or preboot access.

## Phase 4 — authenticated SSH and root-confined file transfer

Phase 4 now has separate native WebRTC channels for SSH and files, surfaced by
a sandboxed React UI. The available direct file path has real two-native-agent
evidence. It does **not** establish relay support, a two-machine result, or a
working SSH login: the local SSH server was not listening and was not enabled.

### Changed

- Added the maintained pinned `@xterm/xterm` 6.0.0 terminal and fit addon to
  the React renderer. Narrow, sender-validated IPC accepts only bounded terminal
  input/resize and fixed SSH/file session schemas; the renderer remains
  sandboxed, context-isolated, cannot select a process, endpoint, root, or
  credential store, and receives only schema-checked native events.
- Added the native `wii-ssh-v1` channel. A controller launches the system
  OpenSSH client in a PTY to an agent-owned loopback listener; the host checks
  an active `ssh` grant before setup and on each byte direction, then connects
  only to its configured `127.0.0.1:<port>` endpoint. OpenSSH retains normal
  user authentication, first-use host-key prompt and changed-key rejection;
  forwarding is cleared and no custom shell/remote TCP proxy exists.
- Added the native `wii-files-v1` channel and two-pane UI. Host-side
  `files.read` and `files.write` checks are independent and repeated per
  operation/chunk. Roots are configured only in the native store; path walking
  uses capability directories and no-follow opens, rejects traversal, symlink
  escapes, path races and non-portable/malicious names, supports files plus
  bounded (512-entry) directory trees and empty directories.
- File transfers use 32 KiB stop-and-wait chunks, a roughly 2 MiB/s pacing
  ceiling and bounded channel buffers,
  manifest SHA-256, per-chunk fsync, source-size checks, atomic same-directory
  completion, explicit fail/replace collision policy, cancellation, and 24-hour
  partial-file retention. Resume reauthorizes and rejects a mismatched manifest.
- Added `configure-file-roots`, `configure-ssh-endpoint`, scoped SSH/files
  grant commands, focused Rust regressions, an actual direct file harness, and
  [SSH/file procedures and limitations](SSH_FILE_TESTING.md).

### Commands run and actual results

| Command | Result |
| --- | --- |
| `npm run build:desktop-ui`; `npm run lint` | Passed: React/xterm bundle and 24 JavaScript files passed syntax/repository-hygiene checks. |
| `cargo test --manifest-path agent/Cargo.toml --locked` | Passed: all 18 native tests, including real loopback WebRTC status transport, file traversal/symlink/integrity/resume/portable-tree tests, SSH control bounds, and read-without-write authorization. |
| `npm run build` | Passed: JSX/xterm build, 24 JavaScript linted, all 25 Node tests, and locked agent build. |
| `npm run test:native-file-session` | Passed outside the workspace socket sandbox. Two agents completed attended pairing, host-only `files.read`/`files.write` grants, root configuration, real direct WebRTC upload/download of a 4 MiB file, nested tree and empty directory. It intentionally omits an unreachable TURN URL from ICE and is **not** relay evidence. |
| `command -v ssh`; `command -v sshd`; strict loopback port-22 OpenSSH probe | `/usr/bin/ssh` and `/usr/sbin/sshd` are installed on this Mac; strict probe returned `Connection refused`. No service was installed, enabled, configured, or authenticated against. |
| `cargo fmt -- --check`; `git diff --check` | Passed at the focused validation point. |

### Still unvalidated

- No real SSH endpoint/login, normal user authentication, first-use host-key
  approval, changed-key test, PTY resize/cancellation, SSH disconnect/revoke,
  or SSH relay session has run. Port 22 was refused locally.
- No selected relay candidate, coturn allocation, same-LAN/two-machine file
  transfer, disk-full/ACL result, interruption/restart with a persisted partial,
  revocation mid-transfer, malicious Windows reparse point, or active desktop
  contention result has run. The only file evidence is local host/direct.
- A folder queue restarts explicitly after connection loss; individual partial
  files retain their manifest-checked resume state. It must not be described as
  an automatically durable whole-tree resume feature.

### Exact next task

On two permitted machines, manually enable/configure a restricted local SSH
server only if policy allows it, set the agent's approved loopback port, and
test normal OpenSSH host-key/new-key/changed-key/authentication/resize/revoke
flows. Deploy restricted coturn, repeat SSH and file in `relay-only` mode with
allocation and selected-candidate evidence, then exercise filesystem ACL,
disk-full, source-change, resume, revocation, large-file and desktop-contention
procedures in [SSH/file testing](SSH_FILE_TESTING.md). Do not claim those cases
until their measurements are recorded.

## Phase 3 follow-up — host-only authorization and transport validation

The native desktop controller no longer has to grant a host reverse desktop
access merely to verify that host's signed SDP. The host remains the sole
desktop authorization boundary. This correction was validated through the real
loopback native-agent WebRTC path; it is not a claim of relay or desktop runtime
success.

### Changed

- Added a native-store pinned, non-revoked peer lookup for signed-session
  verification. A controller uses it before applying an answer (and repeats it
  after waiting for signaling), while a host must continue to obtain a current
  `desktop.view` grant before setup, before accepting an offer, and before each
  capture. `desktop.control` remains a separate host-side check on every input.
- Applied the same initiator/responder distinction to the status transport so
  its documented one-way host grant is real rather than requiring a reciprocal
  grant.
- Updated the two-native-agent harness to issue only the host's fresh
  `desktop.view` grant. It now proves the corrected permission topology during
  attended pairing, fresh coordinator authentication, signed signaling, and
  direct WebRTC ping/pong.
- Added a native-store regression test proving that a pinned peer can verify
  signed session material without gaining `desktop.view`, and that revocation
  removes the verification path as well.

### Commands run and actual results

| Command | Result |
| --- | --- |
| `npm run build` | Passed outside the workspace sandbox: JSX build, lint, all 25 Node tests, and locked agent build. The sandbox itself blocks loopback TCP with `EPERM`, so its failed in-sandbox attempt was not treated as a code failure. |
| `cargo test --manifest-path agent/Cargo.toml --locked` | All 13 tests covered across the focused in-sandbox run (12 non-UDP tests) and the unrestricted transport run (4 transport tests, including the otherwise blocked UDP test). |
| `npm run test:transport` | Passed outside the sandbox. Two real signed loopback WebRTC peers exchanged a bounded status ping; selected ICE evidence was `local=Host, remote=Host`. |
| `npm run test:native-status-session` | Passed outside the sandbox. Two native agents completed attended pairing, **one host-only fresh view grant**, coordinator signaling, and a real `host/direct` WebRTC ping/pong. The harness uses an unreachable TURN URL, so this is explicitly not relay evidence. |
| `cargo fmt --manifest-path agent/Cargo.toml -- --check` and `git diff --check` | Passed. |
| `docker --version`; `command -v turnserver` | Neither Docker nor coturn is installed on this development Mac, so no local TURN allocation could be run. |

### Still unvalidated

- There is no selected `relay` candidate, coturn allocation, TURN/TLS path, or
  direct desktop session evidence. A TURN credential or configured URL is not
  a relay-success claim.
- This development Mac still has no enumerated capture monitor because Screen
  Recording is not granted. Capture and input probes fail closed with
  `requested_monitor_not_found`; no pixels were captured or input injected.
- Windows, macOS ARM64, Ubuntu X11/Wayland, Raspberry Pi, and Jetson adapters
  remain explicitly unsupported at runtime pending native implementation and
  physical hardware validation.

### Exact next task

On two permitted machines, grant macOS Screen Recording and Accessibility to
the signed agent, then follow [desktop testing](DESKTOP_TESTING.md) to record a
direct desktop session first. Deploy or start a restricted coturn instance and
repeat in `relay-only` mode, retaining coturn allocation plus selected `relay`
candidate evidence from both agents. Then test monitor/DPI changes, view-only
input rejection, revocation/held-input cleanup, reconnect, and each quality
mode before claiming runtime support.

## Phase 3 — native desktop viewing and quality controls

Phase 3 implements the native desktop-session boundary and React UI. It does
**not** turn the existing Phase 2B direct status-ping evidence into successful
desktop or TURN-relay evidence. This development Mac denied Screen Recording,
so the adapter correctly performed no capture or input action.

### Implemented

- Migrated the Electron renderer from static JavaScript to React 19.3.0 JSX,
  bundled locally with pinned esbuild 0.28.2. Bookmarks remain locators only.
  The sandboxed renderer has a narrow context-bridge API and sender-validated
  IPC for fixed-schema desktop start/stop/input/events; it cannot select a
  process path, open a network connection, or access agent credentials.
- Added a fixed-path native-agent launcher controlled only by the main process
  (`WII_AGENT_BINARY` must be an absolute path) and bounded JSON-line plumbing.
  Agent events and JPEG data are schema/size validated before entering the
  renderer. Application shutdown requests native session cleanup.
- Added the headless Rust `desktop-host` and `desktop-controller` runners. They
  reuse fresh coordinator authentication, signed SDP/ICE setup and coordinator-
  supplied short-lived TURN credentials on a separate bounded
  `wii-desktop-v1` data channel. Retries repeat local authorization and
  authentication. No TURN shared secret is ever distributed to a client.
- Added a strict desktop protocol: monitor metadata, capped 80 KiB messages and
  52 KiB JPEGs, typed/validated input, frame statistics, quality requests,
  ordered input sequence numbers, data-channel admission/backpressure, timed
  sessions, cancellation, connection cleanup, and no arbitrary command type.
- Implemented separate host enforcement: `desktop.view` is checked before
  setup and each capture; `desktop.control` is checked before control is
  advertised and on every ordered input. View-only controllers never enable
  UI input. Session termination releases held keys/buttons and stops capture.
- Selected and pinned a macOS-first native Rust adapter: `xcap` 0.9.8 for
  display capture, `enigo` 0.6.1 for native input, and software JPEG through
  `image` 0.25.10. Hardware encoding is intentionally reported as unverified.
  Windows and Linux currently return explicit capability errors, not simulated
  success. The evaluation and build requirements are in
  [ADR 0003](adr/0003-native-desktop-adapter.md).
- Added Auto, Clear text, Smooth motion and Low bandwidth profiles. Auto uses
  bounded encoder/admission feedback; UI diagnostics show state, selected route,
  host indicator, monitor/DPI metadata, dropped/sent frames, encode time and
  hardware-encoder status.
- Added [desktop testing](DESKTOP_TESTING.md) and expanded platform limitations,
  including macOS TCC, FileVault/login, Windows secure desktop, Ubuntu
  X11/Wayland/portal and ARM64 boundaries.

### Commands run and actual results

| Command | Result |
| --- | --- |
| `npm run build:desktop-ui` | Passed: React JSX bundled to the ignored local renderer asset. |
| `npm run lint` | Passed: 23 JavaScript/JSX files and repository-hygiene check. |
| `npm test` | Passed: 25 Node tests. Node emitted its existing SQLite experimental warning. |
| `cargo test --manifest-path agent/Cargo.toml --locked` | Passed: 12 Rust tests, including desktop protocol bounds/unknown-command rejection, automatic quality backpressure behavior, and the independent `desktop.view`/`desktop.control` store checks. |
| `npm run test:transport` | Passed outside the workspace sandbox: genuine two-peer loopback status ping with selected ICE evidence `local=Host, remote=Host`. The sandbox itself denied its UDP bind, so its result was not used. This is still status-only host/direct evidence, not desktop or relay evidence. |
| `cargo fmt --manifest-path agent/Cargo.toml -- --check` | Passed. |
| `npm run test:native-status-session` | Passed the existing real two-native-agent status ping over selected `host/direct` loopback. It intentionally used an unreachable TURN URL; it is not relay evidence or desktop evidence. |
| `cargo run --manifest-path agent/Cargo.toml --locked -- desktop-capabilities` | Ran on macOS 13 Intel: `monitors: []`, `screen_recording_permission_required`, `accessibility_permission_required`, bounded software JPEG, no hardware encoder. |
| `cargo run --manifest-path agent/Cargo.toml --locked -- desktop-capture-probe` and `desktop-input-permission-probe` | Both failed closed with `requested_monitor_not_found`; no Screen Recording permission/monitor was available, so neither capture nor input occurred. |

### Not tested or deliberately not claimed

- No genuine desktop capture, input injection, screen-size/DPI change, visual
  Electron inspection, or macOS Screen Recording/Accessibility approval has
  completed. The host adapter code compiles but is not a runtime-support claim.
- No same-LAN desktop, forced TURN relay desktop, relayed selected candidates,
  coturn allocation/expiry/quota, reconnect after desktop transport failure,
  CGNAT, blocked UDP, or TURN/TLS desktop run has happened. The only real
  candidate evidence remains Phase 2B status `host`/`host` loopback.
- Windows, macOS ARM64, Ubuntu X11/Wayland, Raspberry Pi and Jetson adapters
  are unimplemented/unsupported at runtime and untested. Cross-compilation is
  not evidence.
- There is still no installed background-service manager or credential-checked
  local IPC service. Electron starts only a user-specified fixed binary in this
  developer workflow; production packaging/signing requires review.

### Exact next task

Grant macOS Screen Recording and Accessibility to the built agent, run the
two-device procedure in [DESKTOP_TESTING.md](DESKTOP_TESTING.md), and record
direct then selected-relay evidence before describing relay desktop fallback as
working. Implement and hardware-test each additional platform adapter through
its native permission model; do not expose an unsupported adapter.

## Phase 2C — Utho staging deployment preparation

Prepared a repository-only staging deployment package for the existing
authenticated coordination service and coturn. No VPS, Utho account, DNS,
firewall, certificate authority, Nginx, MQTT, ArchidTech, or other live service
was contacted or changed.

### Implemented

- Added [DEPLOY_UTHO.md](DEPLOY_UTHO.md), separating developer-machine and VPS
  commands in execution order. It derives the actual coordinator surface
  (loopback `127.0.0.1:4310`, `/healthz`, and `/v1/connect`) and documents
  dedicated unprivileged service accounts, Nginx HTTPS/WSS ingress, health and
  WebSocket timeouts, NAT mapping, firewall ports, renewal, journald rotation,
  monitoring, SQLite backup/restore, upgrade, rollback, and a narrow uninstall.
- Added dedicated systemd units for the coordinator and coturn, a scoped Nginx
  server-block template, and install/validate/upgrade/uninstall scripts. They
  create or remove only WII-named paths/units, preserve data and secrets, avoid
  starting/reloading existing services during installation, and refuse
  differing managed files or occupied selected TURN ports.
- Added a strict server-local coturn generator plus a non-secret environment
  example. It rejects missing/placeholder input, weak/default-looking shared
  secrets, invalid DNS/URLs/quotas/port ranges/NAT mappings, unprivileged-port
  exceptions such as 443, missing TLS files, and unsafe listeners. It generates
  TURN REST authentication, TLS/DTLS, quotas, bounded relay ports, and explicit
  private/metadata/loopback/multicast destination denials. The shared secret is
  runtime-only in `/etc/wii-ultra-desk/staging.env`; it is never shipped to an
  agent or source control.
- Added generator acceptance/rejection tests. The release and upgrade copiers
  exclude local `.env`, key/certificate, and SQLite artifacts. The coordinator
  remains loopback-only; public exposure is documented solely through reviewed
  HTTPS/WSS ingress. TURN is explicitly direct L4 and is never placed behind an
  HTTP reverse-proxy location.

### Commands run and actual results

| Command | Result |
| --- | --- |
| `bash -n scripts/utho/{install-staging,validate-staging,upgrade-staging,uninstall-staging}.sh` | Passed. |
| `node --test tests/production-coturn-config.test.mjs` | Passed: 2 tests covering valid generated REST/TLS configuration and rejection of weak secrets, placeholders, malformed URLs, loopback listeners, a private relay without a NAT mapping, and port 443. |
| `npm run lint` | Passed: 21 JavaScript files and repository hygiene checks. |
| `npm test` | Passed: 25 Node tests, including coordinator authorization/short-lived TURN credential tests and the production generator tests. Node reported its existing SQLite experimental warning. |
| `npm run build` | Passed: lint, 25 Node tests, and locked Rust-agent build. |
| `git diff --check` | Passed. |

### Deliberately unvalidated

- No real Ubuntu coturn binary or Nginx/systemd parser is installed on this
  macOS development host, so generated configuration has not been parsed or
  started by those production binaries.
- No Utho networking, DNS, certificate issuance/renewal, firewall/security
  group, NAT, relay allocation, TCP/TLS fallback, quota exhaustion, or
  two-device internet test has run. Configuration is not relay-fallback proof.

### Exact next task

Obtain the seven deployment inputs listed in [DEPLOY_UTHO.md](DEPLOY_UTHO.md),
especially topology/IPs, DNS/TLS ownership, current port/vhost inventory,
firewall approval, backup policy, capacity limits, and any required TURN/TLS
443 architecture. With explicit authorization, perform the documented VPS
inventory and then validate the generated configuration before starting only
the new WII services.

## Phase 2B — authenticated WebRTC status session

Phase 2B now has a headless native-agent, authenticated **status-only** WebRTC
session. It is not remote desktop or unattended access. Electron still has no
local agent IPC and deliberately does not start sessions.

### Implemented

- Added [ADR 0002](adr/0002-native-webrtc-transport-and-turn.md), documenting
  the `webrtc` 0.21.0 pure-Rust selection, target/build implications, signed
  offer/answer binding, ICE modes, TURN REST credentials, limits, and the test
  configuration boundary.
- Added the locked `webrtc` 0.21.0/Tokio/rustls native transport dependencies.
  The agent has a reliable bounded `wii-status-v1` WebRTC data channel, strict
  status-message schema/size checks, a 16 KiB send-buffer cap, close handling,
  and no generic remote-command surface.
- Added a domain-separated signed session envelope. It carries fresh session
  and nonce values, exact source/destination locator and fingerprint pairs,
  expiry, role, and SDP/candidate body. Agents reject substituted pinned keys,
  stale or replayed envelopes, oversized material, and malformed status data
  before a remote SDP is applied.
- Added a native-store `desktop.view` authorization object that can only be
  constructed after exact pinned-peer and current scoped-grant checks; a
  caller-supplied `authorized` flag cannot reach the signed-SDP acceptance API.
- Completed attended native pairing: host-approved coordinator frames carry
  signed public bundles, while agents exchange the same bundles inside Noise
  XX, verify the observed Noise static key, display a transcript-derived SAS,
  and require the local operator to type it before persisting trust or signing
  the trust attestation. Pairing creates no access grant.
- Added headless `pair-host`, `pair-controller`, `grant-desktop-view`,
  `status-listen`, and `status-initiate` commands. Each status attempt does a
  fresh local grant check, a fresh coordinator Ed25519 challenge, new session
  ID/nonces/SDP, fresh TURN credential request, signed-SDP verification, and a
  bounded ping/pong. Transient WebRTC/coordinator timeouts retry at most three
  times with backoff and reauthorization; final diagnostics expose state,
  selected route, session ID, attempt count, and ping outcome without exposing
  SDP, candidate addresses, or credentials.
- Added a rustls-backed native coordinator client. Each connection performs the
  server nonce/Ed25519 proof again; remote plain WebSockets are rejected and no
  existing coordinator session is reused after reconnect.
- Restricted coordinator signals to WebRTC signaling kinds and added authenticated
  short-lived coturn REST credential issuance. Credentials require an active
  trust link and exact destination; host-side `desktop.view` is enforced by the
  native agent before desktop setup and capture. The server-only HMAC shared
  secret is never sent to an agent.
- Added a generated-secret, quota-bounded, private-destination-restricted local
  coturn Docker fixture under `infra/coturn`; it is separate from production
  settings and was not started on this host because neither Docker nor coturn is
  installed.
- Added redacted desktop transport diagnostics. They explicitly show `No session`
  and `Not connected` until local agent IPC exists; no secret, candidate address,
  or credential is exposed.

### Commands run and actual results

| Command | Result |
| --- | --- |
| `cargo test --manifest-path agent/Cargo.toml --locked transport::tests::two_real_local_webrtc_peers_exchange_a_bounded_status_ping -- --nocapture` | Passed: genuine loopback signed-SDP WebRTC ping, malformed/oversize validation, and actual `ErrSendBufferFull` queue-exhaustion behavior. Selected evidence: `local=Host, remote=Host`. |
| `cargo test --manifest-path agent/Cargo.toml --locked` | Passed: 10 Rust tests, including signed bundle/SAS tamper checks. |
| `npm run lint` / `npm test` | Passed: 19 JavaScript files syntax-checked and 23 Node tests, including coordinator-issued TURN REST credentials and unauthorized capability/trust rejection. Node SQLite emitted its existing experimental warning. |
| `npm run test:native-status-session` | Passed: separate native identities completed host-approved Noise/SAS pairing, a host-only view grant, fresh coordinator authentication, signed coordinator offer/answer relay, and a real loopback `host_direct` WebRTC ping/pong. The harness requests a valid scoped TURN credential but deliberately omits an unreachable test TURN URL from local ICE gathering; it is **not** relay evidence. |
| `npm run build`, `cargo fmt --manifest-path agent/Cargo.toml -- --check`, `git diff --check` | Passed: locked Rust build, Node lint/tests, Rust formatting, and whitespace checks. |
| `PORT=4311 ... node services/coordinator/server.mjs` plus `cargo run ... coordinator-status --coordinator ws://127.0.0.1:4311/v1/connect` | Passed against a temporary loopback SQLite coordinator: native agent performed a real Ed25519 coordinator authentication. Temporary process was stopped. |
| `npm run dev:native-two-agent` | Passed: two separate native agent processes with distinct identities independently completed real signed coordinator authentication against an in-memory loopback coordinator; it intentionally made no pairing, trust, TURN, or WebRTC success claim. |
| `npm run desktop` | Started the Electron shell with the redacted transport diagnostics; it was stopped after startup. Visual and platform-permission inspection were not performed. |
| `npm run build`, `cargo fmt --manifest-path agent/Cargo.toml -- --check`, `git diff --check` | Passed: 18 JavaScript files linted, 23 Node tests, locked native-agent build, Rust formatting, and whitespace check. |

### Not tested or not yet safe to expose

- No credential-checked local IPC or Electron-to-agent status client exists.
- Same-LAN two-machine, server-reflexive, coturn allocation, forced relay,
  reconnect/ICE restart, allocation quota failure, credential expiry at coturn,
  CGNAT, blocked UDP, TCP/TLS fallback, Windows, Linux, ARM64, and Apple Silicon
  validation were not run. A configured TURN service does not count as relay
  fallback evidence.
- The local coturn fixture lacks TLS by design. Production TURN certificate,
  Utho networking, secret injection/rotation, firewall controls, and external
  monitoring remain deployment work and were not modified.

Read [WEBRTC_TESTING.md](WEBRTC_TESTING.md) for exact currently runnable
commands and the manual network-validation checklist. Do not call the current
transport a desktop, SSH, file, or unattended-access session.

### Next task

Run the documented same-LAN and coturn relay procedures, record selected pair
evidence, then add credential-checked local IPC for redacted Electron
diagnostics. Remote desktop remains a later phase.

## Phase 2A — device identity and authenticated coordination

Phase 2A is implemented to the tested boundary below. It is **not** a ready
remote-access product and does not claim a completed native-agent pairing.

### Implemented

- Added [ADR 0001](adr/0001-device-identity-and-attended-pairing.md), defining
  separate locators, names, identities, trust, grants, the Noise XX protocol,
  first-pairing SAS verification, coordinator threat model, and local IPC rules.
- Added a Rust native-agent library with Ed25519 signing identity, separate
  Noise X25519 static key, Keychain/Credential Manager/Secret Service integration
  through `keyring`, SQLite migrations, pinned trust, grant persistence,
  revocation, and default-off unattended state. Private keys are not written to
  SQLite or emitted by status.
- Added the Node/SQLite WebSocket coordinator: strict device-bundle validation,
  server nonce challenges, signature proof, immutable locator/key registration,
  invitation expiry/single use, host approval gate, opaque pairing frames,
  bilateral signed trust-link records, restricted presence/signaling, rate and
  connection limits, session/challenge expiry, request limits, and revocation.
- Added shared unattended-policy vectors exercised by Node and Rust; added Rust
  Noise XX and persistent trust/grant/revocation tests.
- Added redacted Electron agent/pairing status presentation. It does not start
  or impersonate the agent and returns no secrets.
- Added a non-secret development coordinator configuration and a two-device
  harness. The harness deliberately stops before Noise/SAS/trust completion.

### Commands run and actual results

| Command | Result |
| --- | --- |
| `cargo generate-lockfile --manifest-path agent/Cargo.toml` | Generated locked Rust dependency graph (125 packages) from exact direct dependency pins |
| `cargo test --manifest-path agent/Cargo.toml --locked` | Passed: 3 tests (Noise XX, shared policy vectors, trust/grant restart and revocation) |
| `cargo run --manifest-path agent/Cargo.toml --locked -- status --state-dir /private/tmp/...` | Passed; generated a public locator/fingerprint with `unattended:false` and `remote_access:false` |
| `npm run lint` | Passed: 15 JavaScript files plus README encoding guard |
| `npm test` | Passed outside sandbox: 21 tests, 0 failures |
| `npm run dev:two-device` | Passed signed coordinator authentication, invitation delivery, and host approval; intentionally no completed pairing claim |
| `npm run build` | Passed: lint, 21 Node tests, and locked Rust build |
| `npm run desktop` | Started the updated Electron shell for the observation window; stopped with SIGINT; visual/permission-flow inspection not performed |

### Blocked, untested, or deliberately deferred

- Native agents do not yet transport Noise frames through the coordinator,
  exchange transcript-bound identity bundles, display/confirm a SAS, or emit a
  trust attestation after that verification. The coordinator can record only
  bilateral agent attestations; it cannot verify a human's comparison itself.
- The documented peer-credential local IPC server is not implemented. Electron
  currently shows redacted unavailable status rather than accessing agent state.
- No agent-to-coordinator client, WebRTC identity binding, TURN credentials,
  screen/control, SSH, file transfer, unattended execution, installer, or
  external deployment has been implemented.
- Keychain behavior was exercised by the local status probe, but access-group,
  code-signing, service, and cross-platform secure-store behavior have not been
  audited or tested on the other target systems.
- CI was updated locally but not dispatched. Node SQLite is experimental in
  Node 22 and emits a warning; replacing it requires a reviewed storage choice.

### Exact local commands

```bash
npm ci
npm run lint
npm test
npm run dev:two-device

cargo test --manifest-path agent/Cargo.toml --locked
cargo run --manifest-path agent/Cargo.toml --locked -- init --state-dir /tmp/wii-agent-host
cargo run --manifest-path agent/Cargo.toml --locked -- init --state-dir /tmp/wii-agent-controller
```

Read [DEVELOPMENT_PAIRING.md](DEVELOPMENT_PAIRING.md) before interpreting the
two-device harness. It is not a substitute for validated native-agent pairing.

### Next task: Phase 2B

Connect two Rust agents to the coordinator over authenticated WebSockets;
relay real Noise XX messages; bind signed identity bundles and the transcript;
require host-local approval and independent SAS confirmation before atomic trust
persistence and signed trust attestations; then add credential-checked local IPC
and a real Electron status client. Only after that should WebRTC setup bind to
pinned identity and host-side grants.

## Foundation readiness

The foundation is ready for the next coding prompt: **authenticated
connectivity**. This does not mean remote access is ready. No device identity,
pairing, signaling, WebRTC session, TURN allocation, screen capture/input,
SSH, file transfer, unattended service, installer, or deployment is
implemented.

### Implemented in this update

- Repaired `README.md` by removing a trailing UTF-16/NUL-encoded duplicate
  fragment while preserving the valid README content. The lint command now
  rejects a future NUL byte in that file.
- Added root `AGENTS.md` with project safety, stack, identity/authorization,
  secrets, dependency, validation, and handoff rules.
- Pinned Electron 44.5.1 exactly in `package.json` and `package-lock.json`, and
  raised the Node.js development floor to 22.12.0 to satisfy Electron's package
  engine requirement. Electron 44 is compatible with macOS 13 Ventura
  (including Intel) and x64 or arm64 runtimes. Its 64-bit-only and
  Unity-desktop exclusions are documented in `PLATFORM_SUPPORT.md`.
- Added `npm run lint`, `npm test`, `npm run build:agent`, `npm run test:agent`,
  `npm run agent:status`, and `npm run build`. The lint command uses Node's
  parser across project JavaScript plus the README encoding guard; it does not
  replace the existing behavioral tests.
- Added the no-dependency Rust `Cargo.lock` and a least-privilege GitHub Actions
  workflow (`contents: read`) for Node checks and native-agent build/test.
- Added the platform matrix and refreshed validation evidence for the actual
  host used here.

### Commands run and actual results

| Command | Result |
| --- | --- |
| `git status --short`, `git branch --show-current`, `git remote -v` | Started from `main` with a pre-existing untracked `package-lock.json`; created and worked on `chore/foundation-readiness`; remote remained unchanged |
| `uname -a`, `sw_vers`, `uname -m`, tool checks | macOS 13.0 Ventura on Intel x86_64; Node 22.22.0/npm 11.8.0; Cargo/rustc/Electron initially absent |
| `npm test` before edits | Passed: 10 tests |
| `npm install` | Installed the exact Electron 44.5.1 package and updated the existing lockfile |
| `npm run lint` | Passed: 10 JavaScript files syntax-checked and README NUL guard passed |
| `npm test` after edits | Passed outside the workspace sandbox: 10 tests, 0 failures |
| `npm run desktop` | Electron shell started on the local Intel Ventura host, stayed active for the observation window, and exited cleanly when stopped |
| `node --test tests/server.test.mjs` inside sandbox | Blocked by `listen EPERM` on an ephemeral `127.0.0.1` port; passed outside the sandbox |

### Blocked or untested

- Rust build, Rust tests, and the status probe were not run because neither
  `cargo` nor `rustc` is installed on this host.
- Electron visual rendering, Screen Recording, Accessibility, multi-monitor,
  and permission-flow checks were not inspected. The shell-process launch was
  verified only.
- CI has been added but cannot be dispatched without pushing a branch or
  otherwise changing external repository state; neither was performed.
- Apple Silicon, Windows, Ubuntu X11/Wayland, Raspberry Pi, Jetson, installer,
  signing/notarization, native-agent integration, and all remote-access
  capabilities remain untested or unimplemented.

### Exact local validation commands

```bash
npm ci
npm run lint
npm test
npm run desktop

# After installing Rust with rustup or your platform package manager:
npm run build:agent
npm run test:agent
npm run agent:status
npm run build
```

If a sandboxed runner rejects loopback socket binding, execute `npm test` in a
normal local terminal; the test intentionally starts a `127.0.0.1` HTTP server.

## Next task: authenticated connectivity

Implement and review device identity storage in protected OS facilities, an
authenticated pairing and signaling protocol, coordinator registration/presence
with rate limits, WebRTC session binding to verified peer identities, short-lived
TURN credentials, direct and forced-relay diagnostics, and host-side
authorization enforcement. Port the unattended policy vectors to the Rust
enforcement boundary before any remote desktop control work. Do not begin the
remote-desktop phase until those acceptance criteria are evidenced.
