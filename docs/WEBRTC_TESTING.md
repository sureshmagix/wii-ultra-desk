# Phase 2B WebRTC transport testing

## What is currently real

The Rust agent now contains a native `webrtc` 0.21.0 status-session runner. It
creates an ordered/reliable `wii-status-v1` data channel with a 16 KiB send
buffer cap, validates inbound JSON `ping`, `pong`, and `status` messages at 1
KiB, and does not expose an RPC, shell, SSH, file, capture, or input channel.

The offer and answer SDPs are each wrapped in a short-lived, signed session
envelope. The recipient verifies the sender's locally pinned Ed25519 key,
exact source/destination locator and fingerprint, expiry, session shape, and a
one-time nonce cache *before* applying the SDP. The signed SDP contains the
WebRTC DTLS fingerprint, so selected DTLS endpoint and device identity are
bound together. Reusing an envelope, changing a pinned peer, using an expired
envelope, or exceeding the body limit fails before WebRTC receives it.

Run the complete same-machine test:

```bash
npm ci
npm run test:transport
npm run test:native-status-session
```

`test:transport` creates two independent Rust WebRTC peers on loopback, signs
and verifies SDP, opens SCTP, sends a bounded status ping, and proves that the
16 KiB data-channel send bound returns `ErrSendBufferFull` under a burst.
`test:native-status-session` runs separate native processes through attended
Noise XX/SAS pairing, one explicit host-side view grant, fresh coordinator
authentication, real signed signaling, and a ping/pong. It reports selected
evidence such as:

```text
selected ICE route evidence: local=Host, remote=Host
```

That output is evidence only for the same-host **host/direct** path. The native
session harness requests a short-lived credential but intentionally excludes an
unreachable test TURN URL from ICE gathering with
`--local-test-skip-turn-transport`; it is not relay evidence. It is not evidence
of STUN, NAT traversal, a connection between two machines, or a desktop session.

The native coordinator client can also perform a genuine fresh Ed25519
challenge response. For a local-only coordinator:

```bash
PORT=4311 WII_COORDINATOR_DB=/tmp/wii-ultra-desk-coordinator.sqlite npm run server
# In another terminal:
npm run agent:coordinator-status -- --state-dir /tmp/wii-ultra-desk-agent-a --coordinator ws://127.0.0.1:4311/v1/connect
```

Plain `ws://` is rejected except for loopback development; `wss://` uses the
native rustls certificate-verification path. Each reconnect must call this
challenge flow again; old coordinator sessions are not reused.

For manual attended pairing, start two local terminals with `--state-dir`
directories that are private to each agent. The host prints a one-time token;
the controller submits it. Compare the identical SAS on both terminals and type
it independently. Pairing alone creates no grant.

```bash
# host terminal
cargo run --manifest-path agent/Cargo.toml --locked -- pair-host --state-dir /tmp/wii-host --coordinator ws://127.0.0.1:4310/v1/connect

# controller terminal
cargo run --manifest-path agent/Cargo.toml --locked -- pair-controller --state-dir /tmp/wii-controller --coordinator ws://127.0.0.1:4310/v1/connect --token TOKEN_FROM_HOST
```

On the host, grant the requesting controller's exact fingerprint a short,
bounded `desktop.view` grant, then run `status-listen` on the host and
`status-initiate` on the controller with the peer locator/fingerprint shown by
pairing. The controller needs the host's current pinned trust record to verify
signed SDP; it does not need to grant the host reverse access. Normal sessions
request TURN credentials and include them in ICE; add `--stun stun:...` for
configured STUN.
Use `--ice-mode relay-only` only for relay diagnostics. The loopback-only
`--local-test-skip-turn-transport` switch is reserved for the harness and
rejects non-loopback coordinator or bind addresses.

Each status attempt has a 25-second signaling/connection timeout and at most
three bounded retries. A Ctrl+C cancels the local runner and emits a redacted
`cancelled` diagnostic; the dropped native transport closes its socket/driver.
Reconnect attempts repeat local grant verification and coordinator
authentication rather than retaining a prior session.

## Coordinator and TURN checks

```bash
npm test
```

This verifies the coordinator rejects unauthorized signaling and capability
requests, issues only short-lived coturn REST credentials after exact
trust-link authorization, and does not return the TURN shared secret. It does
not contact a TURN allocation server.

Create the optional local coturn fixture:

```bash
npm run coturn:env
docker compose --env-file infra/coturn/.env -f infra/coturn/docker-compose.local.yml up -d
docker compose --env-file infra/coturn/.env -f infra/coturn/docker-compose.local.yml logs -f
```

Read [infra/coturn/README.md](../infra/coturn/README.md) before running it. The
fixture is intentionally separate from production configuration, generates its
secret locally, constrains relay ports and allocations, and allows only the
loopback peer destination needed for a same-host allocation. It has no TLS
certificate and is not a production template.

## Relay boundary

The native runner obtains TURN credentials only after the coordinator confirms
authenticated active trust. It never receives the shared secret. Electron does
not access agent credentials or start sessions; credential-checked local IPC is
the next integration task.

Consequently, the following have **not** been run here: same-LAN two-machine
connection, forced coturn relay, reconnect/ICE restart, allocation exhaustion,
TURN credential expiry at coturn, CGNAT, blocked UDP, and TURN/TLS. A configured
TURN URL or a gathered relay candidate is not recorded as successful fallback.

## Manual network validation procedure

Use this exact checklist rather than changing authentication checks to make a
network test pass:

1. Pair two agents with the attended Noise/SAS flow and inspect both pinned
   fingerprints locally. Give the requesting peer only an explicit current
   `desktop.view` grant; leave unattended access off.
2. Start the coordinator over `wss://` with a runtime-only
   `WII_TURN_SHARED_SECRET` and public `WII_TURN_URLS`. Confirm each agent
   reports a new authenticated coordinator session after reconnect.
3. Start a status session in automatic ICE mode on the same LAN. Save the
   selected candidate-pair type from both agents; it must be `host` to record
   host/direct, or `srflx` to record server-reflexive/direct.
4. Start the same session in relay-only diagnostic mode. Verify both selected
   candidate types are `relay`, coturn reports an allocation, and the agent
   labels the route `Relayed`. Test quota failure by opening more than the
   configured fixture permits and record the failure state.
5. Disable the selected network path, wait for cleanup, then reconnect. Verify
   a new session ID, new nonce, new coordinator challenge, new signed SDP, and
   a fresh local grant check. Replayed SDP or stale TURN credentials must fail.
6. On separate networks, repeat with CGNAT and with UDP blocked. For TCP/TLS,
   deploy coturn with a valid certificate, expose `turns:host:5349?transport=tcp`,
   retain the private-destination firewall restrictions, and verify the selected
   pair rather than accepting configuration as evidence.

Capture only candidate type, route label, timestamps, state transitions, and
error codes in test records. Do not log SDP, TURN usernames/credentials,
identity private keys, or the coturn shared secret.

## Phase 3 desktop sessions

The Rust agent now reuses the same signed SDP, coordinator authentication, ICE
and short-lived TURN-credential path for a separate bounded
`wii-desktop-v1` data channel. This is not a media or command channel: it has
only monitor, JPEG frame, statistics, quality, disconnect, and typed
keyboard/mouse messages. The native host checks `desktop.view` before setup and
before each capture; it checks `desktop.control` at setup and again for every
ordered input. See [desktop testing](DESKTOP_TESTING.md) for the exact setup
and test matrix.

As of 7 October 2026, no desktop session has passed this procedure. The only
genuine selected candidate evidence remains the Phase 2B same-host status-ping
result `local=Host, remote=Host`; it is not proof of direct desktop viewing or
TURN relay fallback.
