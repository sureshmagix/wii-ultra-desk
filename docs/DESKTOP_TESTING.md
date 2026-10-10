# Phase 3 desktop session testing

## Current evidence boundary

The native agent now implements a macOS-first capture/input adapter and the
sandboxed Electron UI can start only a fixed, developer-configured native agent
binary. The only genuine WebRTC evidence currently recorded is the Phase 2B
same-host `host/direct` **status ping**. The local Mac used for this work
returned no monitors because Screen Recording was not granted; both capture and
input probes stopped with `requested_monitor_not_found`. No desktop pixels,
keyboard/mouse action, same-LAN desktop session, or relayed desktop session has
been claimed successful.

Read [WebRTC testing](WEBRTC_TESTING.md) before this guide. In particular, do
not call a configured TURN URL a fallback until coturn records an allocation
and both agents report selected `relay` candidates.

## Build and permission probe (macOS)

On the developer machine, build first:

```bash
npm ci
npm run build:desktop-ui
cargo build --manifest-path agent/Cargo.toml --locked
cargo run --manifest-path agent/Cargo.toml --locked -- desktop-capabilities
cargo run --manifest-path agent/Cargo.toml --locked -- desktop-capture-probe
cargo run --manifest-path agent/Cargo.toml --locked -- desktop-input-permission-probe
```

Grant **Screen Recording** to the terminal or signed agent application in
System Settings → Privacy & Security → Screen Recording. Grant
**Accessibility** separately before testing input. Restart the agent after
changing either setting. The input probe creates the native input adapter but
does not inject an event. If either permission is absent, record its capability
error and stop; never weaken TCC, SIP, or the app sandbox.

For a particular monitor, use the numeric ID emitted by `desktop-capabilities`:

```bash
cargo run --manifest-path agent/Cargo.toml --locked -- desktop-capture-probe --monitor MONITOR_ID
```

The response reports only frame dimensions and JPEG byte count. It does not
write a screenshot to disk.

## Two-device authenticated desktop test

These steps need a coordinator and TURN service that have completed the Phase
2B prerequisites. Values in angle brackets are values produced by pairing or
the staging deployment; do not place them in source control.

1. On each computer, run the attended pairing flow in
   [WebRTC testing](WEBRTC_TESTING.md). Compare and independently confirm the
   SAS. Save each peer's locator and fingerprint from the pairing result.
2. On the host, grant the controller a short-lived view grant. Use the control
   command only for an explicitly approved control test:

   ```bash
   cargo run --manifest-path agent/Cargo.toml --locked -- grant-desktop-view \
     --state-dir <HOST_STATE_DIR> --peer-fingerprint <CONTROLLER_FINGERPRINT> \
     --expires-at <UNIX_MS_WITHIN_24_HOURS>

   # Replaces the view-only grant with both desktop.view and desktop.control.
   cargo run --manifest-path agent/Cargo.toml --locked -- grant-desktop-control \
     --state-dir <HOST_STATE_DIR> --peer-fingerprint <CONTROLLER_FINGERPRINT> \
     --expires-at <UNIX_MS_WITHIN_24_HOURS>
   ```

3. Start the host. It does not capture until the authenticated controller
   opens the data channel:

   ```bash
   cargo run --manifest-path agent/Cargo.toml --locked -- desktop-host \
     --state-dir <HOST_STATE_DIR> --coordinator <WSS_COORDINATOR_URL> \
     --peer-locator <CONTROLLER_LOCATOR> --peer-fingerprint <CONTROLLER_FINGERPRINT> \
     --ice-mode automatic --quality auto --bind 0.0.0.0:0
   ```

4. Start the controller in another terminal. Add `--request-control` only
   after the host has the independent control grant:

   ```bash
   cargo run --manifest-path agent/Cargo.toml --locked -- desktop-controller \
     --state-dir <CONTROLLER_STATE_DIR> --coordinator <WSS_COORDINATOR_URL> \
     --peer-locator <HOST_LOCATOR> --peer-fingerprint <HOST_FINGERPRINT> \
     --ice-mode automatic --quality auto --bind 0.0.0.0:0 --request-control
   ```

   Both runners output redacted JSON events. Preserve `state`, selected
   `route`, frame statistics, and error codes only—never SDP, candidates,
   credentials, or keys.

5. To use the Electron controller UI after the Rust binary is built, set only
   the fixed binary and state directory; the renderer cannot select an
   executable:

   ```bash
   WII_AGENT_BINARY="$PWD/agent/target/debug/wii-ultra-desk-agent" \
   WII_AGENT_STATE_DIR=<CONTROLLER_STATE_DIR> npm run desktop
   ```

   Enter the coordinator, the **verified** paired locator/fingerprint, desired
   ICE mode, and a STUN URL if configured. A saved bookmark is merely a label;
   it cannot supply trust or a grant. The remote viewport enables mouse and
   keyboard events only after the native host sends `control: allowed`.

## Required test matrix and records

| Test | Expected record |
| --- | --- |
| Same machine / separate identities | Fresh coordinator authentication, fresh session ID, selected candidate types, and `host/direct` only if actually selected. |
| Same LAN | A new direct session record; include selected `host` or `srflx` candidates from both peers. |
| Forced relay | Start both desktop sessions with `--ice-mode relay-only`; retain the coturn allocation and selected `relay` evidence from both peers. |
| Disconnect/reconnect | Stop the network/session, reconnect, and verify a new session ID, coordinator authentication, authorization check, and cleanup. |
| View only | Omit `desktop.control`; the controller must keep controls disabled and host must reject any forged input. |
| Revocation | Revoke or expire `desktop.view` during capture; next host frame check must terminate capture. Revoke `desktop.control` during input; the next input must fail and all held inputs must release. |
| Bounds/malformed | Send more than 80 KiB, invalid coordinates, an unknown message type, and queue bursts; each must be rejected/limited without capture or command execution. |
| Quality | Exercise the four modes under competing traffic. Record emitted/drop counts and encode time; this adapter must report software JPEG, not hardware encoding. |
| Monitor/DPI | Use each monitor, change display scale/geometry, reconnect, and verify pointer lands correctly at corners and centre. |

## Other platforms and known limits

- **macOS:** Screen Recording and Accessibility are independent user grants.
  The login window and FileVault pre-boot environment are not capturable or
  controllable; secure UI may be unavailable even after login.
- **Windows:** the current native adapter returns an explicit unsupported
  capability error. It has no tested UAC/secure-desktop or login-screen access.
- **Ubuntu/Linux:** the current adapter returns an explicit unsupported
  capability error. A future X11 adapter must be tested with its input/capture
  permissions; a Wayland adapter must use desktop portals and must not claim
  support from xcap/enigo cross-compilation or experimental upstream features.
- **macOS ARM64 and Linux ARM64:** no runtime result is recorded. Cross-builds
  do not establish capture, input, encoder, or permission support.
- **Internet/CGNAT/blocked UDP/TURN TLS:** follow steps 4–6 of the manual
  network procedure in [WebRTC testing](WEBRTC_TESTING.md). For TURN/TLS use a
  public certificate and `turns:` TCP listener; record selected candidates,
  not configuration alone.
