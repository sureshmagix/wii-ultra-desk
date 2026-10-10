# Validation — 7 October 2026

Environment for this update: macOS 13.0 Ventura (`22A380`) on Intel `x86_64`;
Node.js v22.22.0/npm 11.8.0; Rust/cargo 1.99.0 installed through rustup.

| Check | Result |
| --- | --- |
| JavaScript lint and README encoding guard | Passed after Phase 2B: 18 JavaScript files syntax-checked; no README NUL byte |
| Node automated tests | Passed outside the workspace sandbox after Phase 2B: 23 passed, 0 failed |
| Coordinator authentication | Tested with real Ed25519 proof-of-possession challenges; spoofed `authenticated` field, invalid credentials, replayed challenge, and locator key substitution are rejected |
| Pairing coordinator boundary | Tested invitation expiry/single consumption, host approval gate, opaque-frame routing, bilateral signed attestation, rate limiting, malformed input, signaling authorization, and trust revocation |
| Coordinator persistence | Tested registered identity survives SQLite restart and a replacement key for its locator is rejected |
| TURN credential boundary | Passed: a mutually trusted authenticated peer receives a short-lived coturn REST HMAC credential for `desktop.view`; no configured secret, wrong capability, and unauthorized destination are rejected |
| Shared unattended policy vectors | Passed in JavaScript (7 vectors) and Rust (same JSON vectors) |
| Native-agent tests | Passed after Phase 2B: 9 tests, including Noise XX, SQLite trust/grant persistence/revocation and scoped session authorization, policy conformance, coordinator URL/retry rejection, signed session envelope rejection, status schema/route bounds, and real loopback WebRTC ping |
| Native WebRTC direct evidence | Passed: two independent local Rust peer connections signed/verified their actual offer/answer SDPs, sent a bounded SCTP status ping, and reported selected candidate types `Host`/`Host` |
| Native coordinator client | Passed against an isolated temporary loopback Node coordinator: OS-backed identity completed the real Ed25519 challenge/proof flow |
| Native agent status probe | Passed using a temporary state directory; public locator/fingerprint only; `unattended:false`, `remote_access:false` |
| Two-device development harness | Passed real signed coordinator auth, invitation delivery, and host approval; intentionally stopped before native Noise/SAS/trust completion |
| Electron shell after Phase 2A UI changes | Started on the local Intel Ventura host and remained active for the observation window; stopped with SIGINT; visual/permission-flow inspection not performed |
| Electron shell after Phase 2B UI changes | Started with redacted connection/route diagnostics and then stopped; visual and permission-flow inspection not performed |
| CI workflow execution | Workflow updated in source but not dispatched |
| Live native-agent pairing, local IPC, coordinator-signaled two-agent WebRTC, coturn allocation/relay | Not implemented or not tested end to end; no successful relay claim is made |
| Desktop capture/input, SSH, files, installers | Not implemented or tested |
| Vulnerability assessment | Not performed; these checks are not a security audit |

Node's SQLite API emits an experimental warning in the supported Node 22 line.
The test coordinator binds an ephemeral `127.0.0.1` port; sandboxed execution
may reject that bind with `EPERM`, while the same suite passes outside it.

Coordinator trust attestations are not proof that a Noise pairing succeeded. The
native agent must complete Noise transcript binding and human SAS verification
before it emits one; that live path remains the next Phase 2B integration task.

Docker/coturn were absent from this host. The checked-in local fixture has not
been started. Same-LAN, server-reflexive, forced relay, TURN/TLS, allocation
failure, credential expiry at coturn, reconnect/ICE restart, CGNAT, and
blocked-UDP results are therefore untested. See `WEBRTC_TESTING.md`.
