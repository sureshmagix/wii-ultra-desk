# ADR 0002: Native WebRTC transport, session binding, and TURN credentials

- Status: accepted for Phase 2B implementation
- Date: 2026-10-07

## Context

Phase 2A deliberately stopped before a native agent could use the coordinator
or create a remote channel. A WebRTC offer alone is not an authenticated peer
identity: a compromised coordinator can substitute an SDP, replay it, or route
it to another authenticated device. The native agent must therefore own the
transport while an Electron window is absent and must bind every offer and
answer to the agent's already pinned device identity.

## Options evaluated

| Option | Strengths | Cost / decision |
| --- | --- | --- |
| `webrtc` 0.21.0 from the maintained `webrtc-rs` project | Pure Rust, async data channels, ICE/STUN/TURN, DTLS/SCTP, candidate statistics, ICE restart, and a bounded data-channel send-buffer API. It therefore fits the existing Rust background agent and has no Electron-window dependency. | **Selected** for a data-channel-only Phase 2B transport. It has not yet been compiled or run on Windows, Linux, or ARM64; each target remains a required validation gate. |
| `shiguredo/webrtc-rs` libwebrtc bindings | Uses Google's native libwebrtc implementation. | Rejected for this phase: prebuilt/bundled libwebrtc and C++/Clang build requirements materially complicate Windows, macOS architectures, Ubuntu, and ARM64 release reproducibility. |
| GStreamer `webrtcbin` | Mature media integrations on Linux. | Rejected: adds platform plugin/runtime dependencies and is poorly aligned with a cross-platform, headless-first harmless data-channel milestone. |

The selected crate's native requirements are a supported Rust toolchain and
network socket access. `webrtc` 0.21.0 uses a Tokio runtime and Rust crypto by
default; no system libwebrtc binary, browser, or Electron process is required.
The application will use the crate only for an ordered, reliable `wii-status-v1`
data channel until the later desktop-media phase.

## Decision

### Session authorization and identity binding

Before creating a `PeerConnection`, an agent must have an active local pinned
trust entry for the exact peer locator, fingerprint, Ed25519 key, and Noise key.
It must have an authorized `desktop.view` session decision for the requested
operation. Phase 2B's status exchange is harmless but uses the same authorization
gate so later capabilities do not inherit an unverified transport.

The coordinator continues to route only between mutually trusted exact
locator/fingerprint pairs. It does not authorize a peer because it supplied a
`kind`, a client-side `authenticated` flag, a bookmark, or an ID.

Every signaling payload is a schema-limited `SessionEnvelope` with:

- a random 128-bit session ID and a distinct 128-bit nonce;
- source and destination locator/fingerprint pairs;
- role (`offer`, `answer`, `cancel`, or `ice-candidate`);
- created and expiry times (60 seconds for offer/answer, 15 minutes maximum
  for a running session);
- the SDP or candidate body; and
- an Ed25519 signature over a domain-separated, length-delimited encoding of
  every preceding field.

The recipient verifies the signature using its **locally pinned** peer signing
key, verifies both identity directions, enforces expiry and a one-time
session/nonce cache, and limits SDP/candidate bytes before passing data to the
WebRTC library. WebRTC in turn verifies the DTLS certificate fingerprint in the
signed SDP. This makes the WebRTC DTLS endpoint, the fresh session ID, and the
long-term pinned identity one binding; coordinator substitution or replay fails
before a data channel is accepted. A reconnect creates a new session ID,
reauthenticates to the coordinator, rechecks local trust and grants, and sends
new signed signaling material.

### ICE and route handling

Normal mode uses host, server-reflexive, and relay candidates from supplied
STUN/TURN servers. Relay-only diagnostic mode uses WebRTC's `Relay` ICE policy,
and is explicitly marked as a diagnostic. Candidate route evidence is computed
only from selected candidates or peer-connection statistics: host/direct,
server-reflexive/direct, relay, or unknown. A gathered relay candidate is not
reported as a successful fallback.

Session state transitions are explicit: `idle`, `authorizing`, `signaling`,
`connecting`, `connected`, `reconnecting`, `failed`, `cancelled`, and `closed`.
Offer/answer wait time is bounded, failed connections are cleaned up, and retry
uses a bounded exponential backoff. Remote execution is not represented in this
protocol.

### TURN credentials and local test configuration

The coordinator receives the coturn shared secret only from its runtime
environment (`WII_TURN_SHARED_SECRET`). It issues a time-limited coturn REST
credential after authenticated exact-peer trust authorization. The client sees
only a username containing its expiry/session context, a HMAC-SHA1 credential,
and configured public TURN URLs; it never receives the shared secret. Credential
issuance is rate-limited and expires with the session invitation.

`infra/coturn` is a local-only test fixture. Its generated `.env` contains a
random secret and is ignored by Git. It sets quotas, a constrained relay-port
range, and private-destination denials. Loopback is an explicit test-only
exception required for a same-machine relay test; it must not appear in a
production configuration. Production TURN URL, TLS certificate, shared secret,
network ACLs, and observability are deployment inputs, not repository defaults.

## Consequences and validation boundary

The first connected channel parses bounded JSON `ping`/`pong`/`status` messages
only. The native runner performs exactly one ping/pong then closes. It applies a
per-message byte limit and a 16 KiB WebRTC send-buffer limit, proven by a real
`ErrSendBufferFull` burst test; a future long-lived consumer must add its own
bounded inbound queue before it is exposed to a peer. It does not accept shell
commands, screen input, files, SSH payloads, or a generic RPC mechanism.

The selected library's own examples demonstrate ICE, TURN relay, data channels,
backpressure, and ICE restart. That is not evidence that WII Ultra Desk has
validated those modes on every target. This implementation must record actual
candidate and route evidence from its own two-peer test; absent coturn/Docker or
a second network, relay, CGNAT, blocked UDP, and TURN/TLS remain manual test
procedures rather than successful claims.

## References

- [webrtc-rs 0.21 crate](https://crates.io/crates/webrtc/0.21.0)
- [webrtc-rs data-channel and ICE examples](https://github.com/webrtc-rs/webrtc/tree/master/examples)
- [coturn manual: peer IP restrictions](https://manpages.debian.org/trixie/coturn/coturn.1.en.html)
- [TURN REST credential mechanism](https://tools.ietf.org/html/draft-uberti-behave-turn-rest)
