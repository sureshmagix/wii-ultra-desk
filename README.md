# WII Ultra Desk — Phase 5 operational unattended-access lifecycle

Agreed direction: Electron desktop app, native Rust agent, direct WebRTC P2P,
TURN relay fallback, and opt-in unattended access. Application and coordination
code are JavaScript/JSX.

This is a development source package, NOT a working remote-access product or
a complete installer. Phase 5 adds a native unattended-access lifecycle:
explicit local enablement, scoped and expiring controller grants, a background
daemon, bounded authorization leases, local Disconnect/Disable, audit history,
and signed remote-revocation acknowledgement. It does **not** yet have a
physical two-device unattended-session, desktop-session, service-install, or
TURN-relay result, and it does not expose a general remote-command listener.

## Included and usable

- React Electron UI: bookmarks, authenticated-session configuration, route/
  state/quality diagnostics, remote-frame display, and host control state.
- Renderer sandbox, context isolation, restricted asset protocol and narrow IPC.
- Loopback-only Node.js coordinator health endpoint.
- Operational native unattended authorization with explicit local enablement,
  scoped/expiring verified-controller grants, renewal, revocation, audit data,
  and default-off persistence. Bookmarks remain locators only.
- Independently runnable native lifecycle daemon with owner-authenticated local
  control on Unix and signed remote-revocation acknowledgement. It has no
  arbitrary remote-command RPC.
- Architecture, unattended lifecycle, platform gates and relay configuration template.
- Durable native-agent Ed25519/Noise identity source backed by protected OS
  credential storage and a SQLite trust/grant database.
- Authenticated local coordinator registration, invitation routing, opaque
  pairing frames, bilateral trust attestations, restricted presence/signaling,
  rate limits, expiry, and SQLite migrations.
- Native WebRTC data-channel source with signed offer/answer validation,
  replay/expiry/key-substitution rejection, automatic and relay-only ICE
  configurations, bounded status messages and send backpressure.
- Native authenticated coordinator client and coordinator-only coturn REST
  credential issuance. The TURN shared secret is not present in Electron,
  native-agent configuration, or source control.
- A native macOS-first screen/input adapter with monitor/DPI metadata, bounded
  software JPEG frames, explicit quality profiles, held-input release, and
  separate host-side `desktop.view`/`desktop.control` enforcement. Unsupported
  targets report capability errors rather than pretending to capture or inject.

## Install, check, and run

Prerequisite for developers: Node.js 22.12.0 or later (required by the pinned
Electron development package). Install the pinned development dependencies and
run the repeatable JavaScript checks:

```bash
cd wii-ultra-desk
npm ci
npm run lint
npm test
```

Run the local development coordinator:

```bash
npm run server
```

Open http://127.0.0.1:4310/healthz to verify the development service. Stop with
Ctrl+C. PORT may be set to another local port. This endpoint reports health,
not authenticated session readiness. No Utho deployment has been performed.

The coordinator uses Node's built-in SQLite API, which remains experimental in
the supported Node 22 line and emits a warning during tests. It binds only to
loopback for development. `services/coordinator/.env.example` documents the
non-secret development configuration; do not place production credentials or
TURN secrets there.

## Run the Electron development shell

On a supported desktop development machine, from the project root after `npm ci`:

```bash
npm run desktop
```

Electron is pinned to 44.5.1 in `package.json` and `package-lock.json`. Electron
44 requires macOS 13 (Ventura) or later, including Intel Macs, so it is compatible
with the desired Intel Ventura target. It has x64 and arm64 artifacts; it does
not support 32-bit Windows or Linux ARMv7, nor the Unity Linux desktop. These
constraints do not conflict with the agreed x64/ARM64 product targets, but Ubuntu
validation must use a supported desktop environment. See
[platform support](docs/PLATFORM_SUPPORT.md).

Electron bundles its runtime for end users. The repository now has repeatable
local packaging commands; the resulting artifacts remain unsigned development
builds, not supported product releases. Do not disable Electron sandboxing to
work around a launch issue.

The shell uses React/JSX bundled locally by esbuild. Set `WII_AGENT_BINARY` to
an operator-configured absolute built-agent path and `WII_AGENT_STATE_DIR` before starting
a desktop session; the renderer cannot choose an executable or read agent
secrets. Bookmarks are stored under Electron's userData directory in
bookmarks.json, not in the source tree. They contain no passwords or trust grants.

## Build desktop packages

Each packaging command builds the React bundle, compiles the matching native
agent in release mode, and places it under the packaged app's `resources/agent`
directory. Artifacts are written to the ignored `release/` directory and
publishing is disabled.

```bash
npm run dist:mac:intel
npm run dist:mac:silicon
WII_ZIG_BINARY=/absolute/path/to/zig npm run dist:ubuntu
WII_WINDOWS_GNU_TOOLCHAIN_BIN=/absolute/path/to/mingw/bin npm run dist:win
```

The Ubuntu cross-build requires Zig `0.17.0`. A Windows package built off
Windows requires a complete `x86_64-w64-mingw32` toolchain, including its
runtime/import libraries; the command deliberately fails without it rather
than emitting an agentless installer. Before distributing any artifact, replace
the Debian maintainer placeholder `maintainers@wii-ultra-desk.invalid`, add a
custom icon, and obtain the applicable Windows/macOS signing and macOS
notarization credentials. Physical clean-machine install and runtime validation
remain mandatory.

## Build the agent probe

Requires an installed Rust toolchain; run from the project root:

```bash
npm run build:agent
npm run test:agent
npm run test:transport
cargo run --manifest-path agent/Cargo.toml --locked -- status --state-dir /tmp/wii-ultra-desk-agent
```

`npm run build` runs the JavaScript checks and tests plus the Rust build. The
transport test is a genuine same-machine test: two Rust peers verify signed
offer/answer SDPs, open a data channel, exchange a bounded ping, and report
selected ICE candidate types. It is host/direct loopback evidence only. The
status test is not a capture or relay test. To inspect the native desktop
adapter and its operating-system permission boundary, follow
[desktop testing](docs/DESKTOP_TESTING.md). The independently runnable daemon
opens only its owner-authenticated local lifecycle socket; it does not execute
remote commands or expose a network management listener. See
[operational unattended access](docs/UNATTENDED_ACCESS.md).

Run the native lifecycle harness (loopback coordinator, two paired ephemeral
agents, malformed local IPC rejection, and signed remote revocation):

```bash
npm run test:native-unattended-lifecycle
```

## Local TURN fixture

The optional coturn fixture is a separate, generated-secret local environment:

```bash
npm run coturn:env
docker compose --env-file infra/coturn/.env -f infra/coturn/docker-compose.local.yml up -d
```

It is not a production configuration and has not been run on this host. See
[WebRTC testing](docs/WEBRTC_TESTING.md) and
[infra/coturn](infra/coturn/README.md) before using it. A configured relay is
not treated as successful fallback until a selected relay candidate and
allocation are actually recorded.

## Pairing development checks

```bash
npm run dev:two-device
```

This local harness uses two ephemeral development identities to verify the
coordinator's signed challenge, invitation routing, and host approval boundary.
It stops before Noise transport/SAS verification and trust attestation, so it
does not claim a successful authenticated pairing or remote session. See
[development pairing](docs/DEVELOPMENT_PAIRING.md) and the protocol
[ADR](docs/adr/0001-device-identity-and-attended-pairing.md).

## Project layout

| Path | Purpose |
| --- | --- |
| apps/desktop | Sandboxed React Electron UI and narrow native-session IPC |
| services/coordinator | Local development HTTP service |
| packages/policy | Reference unattended-access decision logic |
| packages/protocol | Strict device-identity and coordinator message primitives |
| agent | Native identity, WebRTC, capture/input, and desktop-session agent |
| infra | Non-deployable relay configuration template |
| tests | Node built-in test runner suites |
| docs | Architecture, security boundaries and implementation phases |

## Next implementation milestone

Run the documented physical two-device unattended lifecycle tests: deliberate
enablement, grant expiry, local disconnect/disable, controller-key change,
active-operation revocation, offline remote revocation, daemon restart/reboot,
and service install/uninstall. Then validate desktop/SSH/file paths and relay
on supported hardware rather than relying on loopback or cross-compilation.
See [the acceptance guide](docs/UNATTENDED_ACCEPTANCE.md),
[current progress](docs/PROGRESS.md), [platform support](docs/PLATFORM_SUPPORT.md),
and [operational unattended access](docs/UNATTENDED_ACCESS.md).

No source license is assigned by this starter; choose one before redistribution.
