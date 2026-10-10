# ADR 0003: native desktop capture and input boundary

## Status

Accepted for the first runtime adapter on 7 October 2026. Runtime validation is
limited to the macOS Intel development host described in
[Platform support](../PLATFORM_SUPPORT.md); its current TCC permissions deny
capture and input, so this is an implementation decision, not a platform
support claim.

## Context

Desktop pixels and input must not enter Electron's renderer process. A native
agent must keep working without an open window, enforce separate
`desktop.view`/`desktop.control` grants, and use the existing authenticated
WebRTC transport. The transport has a tested same-host direct status session;
it does **not** yet have successful TURN-relay evidence.

## Options assessed

| Option | Windows / Ubuntu / macOS / Linux ARM64 | Decision |
| --- | --- | --- |
| Pure Rust [`xcap` 0.9.8](https://github.com/nashaofu/xcap) capture + [`enigo` 0.6.1](https://github.com/enigo-rs/enigo) input | `xcap` advertises macOS, Windows, and Linux capture; Enigo uses native macOS/Windows/X11 input. Wayland support is experimental and runtime/package requirements differ by target. Both build in Rust and avoid shipping a C++ capture shim. | Selected for a macOS-first, agent-owned adapter. Current source deliberately compiles the adapter only on macOS; other targets return explicit unavailable-capability errors until hardware-tested adapters exist. |
| GStreamer/pipewire/desktop-portal media graph | Strong Linux/Wayland route, with mature codec choices; entails system libraries, portal/session integration, and target-specific deployment. | Deferred. A future Linux adapter must use the portal/pipewire permissions rather than bypassing them. |
| Platform C/C++ capture and input SDK bindings | Could access DXGI/Windows Graphics Capture, ScreenCaptureKit, or X11/Wayland integrations directly. Each needs reviewed unsafe bindings, signing/permission work, CI toolchains, and physical hardware validation. | Deferred. Cross-compilation alone is not runtime evidence. |

`xcap` and `enigo` are pinned exactly in `agent/Cargo.toml` and recorded in
`agent/Cargo.lock`. The selected Rust toolchain floor is 1.88 because the
bounded JPEG encoder dependency requires it. The macOS adapter uses software
JPEG only; it makes no hardware-encoder claim.

## Decision

The Rust agent owns `wii-desktop-v1`, an ordered/reliable bounded WebRTC data
channel. It sends validated monitor announcements, bounded base64 JPEG frames,
quality/statistics messages, and a small input enum; there is no command,
shell, transfer, or arbitrary-RPC message.

On macOS, `xcap` enumerates and captures the selected display and `enigo` is
constructed lazily only when input is authorized. The adapter maps normalized
controller coordinates to the chosen native monitor rectangle, retains held
keys/buttons, and releases them on every session termination. Capturing stops
as soon as a host-side `desktop.view` recheck fails. Every input rechecks
`desktop.control` at the host. The controller sees an advisory control state,
but never becomes an authorization boundary.

`Auto` quality adapts a bounded software JPEG profile using encoder time and
data-channel admission. `Clear text`, `Smooth motion`, and `Low bandwidth` are
fixed, capped profiles. The first implementation has no media codec, audio,
clipboard, file transfer, or hardware encoder.

## Consequences

- Electron remains sandboxed; it may start a fixed-path native agent process
  and exchange only schema-validated events/input through sender-validated IPC.
- macOS requires Screen Recording for monitor/capture and Accessibility for
  input. The adapter reports capability errors rather than faking success.
- Windows, Ubuntu X11/Wayland, ARM64 Linux, and macOS ARM64 are intentionally
  unsupported at runtime in this phase until actual platform adapters and
  physical validation are added.
- An authenticated WebRTC session is necessary but insufficient for a desktop
  session. A successful TURN allocation and selected relay candidate remain
  required before stating relay desktop fallback works.
