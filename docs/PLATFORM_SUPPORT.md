# Platform support and validation matrix

Status terms: **compatible** means the selected Electron release publishes a
runtime that matches the OS/CPU target; it is not a claim that WII Ultra Desk
has been tested or packaged there. **Planned** means no product support should
be claimed yet.

## Runtime selection

The foundation pins Electron 44.5.1. Electron's release notes state that v44
requires macOS 13 (Ventura) or newer and publishes only 64-bit artifacts. Its
installation documentation lists x64 and arm64 as supported architectures.
Electron's own current support window is its latest three stable major lines,
so this version must be reviewed and deliberately updated before a release.

| Target | Runtime compatibility | Foundation validation | Product/package status | Required next validation |
| --- | --- | --- | --- | --- |
| macOS 13 Ventura, Intel x64 | Compatible with Electron 44 | Host OS detected locally; Electron shell launched and remained running, but no visual or permission-flow inspection | Planned signed/notarized DMG or PKG | Screen recording, Accessibility, multi-monitor/DPI, launch-agent behavior, signing and notarization |
| macOS 13+, Apple Silicon arm64 | Compatible runtime architecture | Not run; no Apple Silicon hardware available | Planned native signed/notarized DMG or PKG | Same as Intel on physical Apple Silicon hardware |
| Windows x64 | Compatible runtime architecture | Not run | Planned signed EXE installer | Input, DPI, multi-monitor, UAC/service boundaries, clean install/upgrade/uninstall |
| Ubuntu x64 (GNOME/KDE; X11 and Wayland) | Compatible runtime architecture | Not run | Planned DEB with bundled runtime | Test X11 and Wayland independently, portals/permissions, clean install/upgrade/uninstall |
| ARM64 Linux / Raspberry Pi | Compatible runtime architecture | Not run; no board/toolchain available | Planned ARM64 DEB plus separately scoped headless agent | Record exact model/OS/graphics session, capture/input permissions, encoder measurements, and installer lifecycle |
| NVIDIA Jetson ARM64 | Compatible runtime architecture subject to distro libraries | Not run; no Jetson/JetPack available | Conditional native package | Record exact module, JetPack, Ubuntu/glibc, graphics stack, encoder path, and installer lifecycle |

## Deliberate exclusions and constraints

- Electron 44 no longer supports macOS 12 or older. Ventura is the minimum
  supported macOS floor for this pin.
- Electron 44 ships only x64 and arm64 builds. Windows x86 and Linux armv7l
  are excluded. This repository targets ARM64 Linux, not 32-bit Raspberry Pi OS.
- Electron 44 no longer supports the Unity desktop environment. Ubuntu testing
  must use a supported desktop environment and include both X11 and Wayland
  where the product claims either.
- No installer, service manager, or production TURN deployment is implemented.
  Phase 4 adds a deliberately restricted native SSH/file implementation but
  never installs or enables an SSH service. Phase 3 adds a deliberately
  narrow macOS-first capture/input adapter; compatible Electron runtimes do
  not establish desktop feature support.

## Phase 2A native-agent validation

The Rust agent now has source integrations for Ed25519 identity, Noise XX static
keys, protected key storage, and SQLite trust/grant migrations. On the local
Intel Ventura development host, the locked agent dependency set compiled, its
Noise/policy/storage tests passed, and `status` initialized a device identity.
That is not a platform certification of Keychain access controls, local IPC, or
background-service behavior.

| Target | Native protected-store plan | Phase 2A result | Remaining validation |
| --- | --- | --- | --- |
| macOS Intel Ventura | Keychain Services through `keyring` | Source compiled; local status probe passed | Inspect Keychain access group/signing behavior, local socket peer credentials, launch agent, SAS UI, and service/user-session boundary |
| macOS Apple Silicon | Keychain Services through `keyring` | Not run | Compile and run the same agent tests plus physical permission and IPC checks |
| Windows x64 | Windows Credential Manager through `keyring` | Not run | Credential-manager scope, named-pipe SID ACL, service/broker split, and UAC behavior |
| Ubuntu x64 / ARM64 Linux | Secret Service through `keyring` | Not run | Secret-service availability in each desktop/headless target, socket UID checks, and packaging dependencies |
| Raspberry Pi / Jetson | Same Linux Secret Service plan, subject to OS image | Not run | Exact OS image, secret-service provider, graphics session, and headless-agent support |

The protocol source requires private-key storage to fail closed if the intended
protected store is unavailable. It does not use an unencrypted SQLite fallback.
See [ADR 0001](adr/0001-device-identity-and-attended-pairing.md).

## Phase 2B native WebRTC transport

Phase 2B selects the pure-Rust `webrtc` 0.21.0 crate with its Tokio runtime and
rustls native-root WebSocket client for a headless data-channel boundary. This
avoids a bundled C++ libwebrtc binary and lets the agent own transport without
Electron, but it is not a portability certification. It requires a supported
Rust toolchain, OS network sockets, and a functional protected store from Phase
2A; coturn/TLS is a separate runtime service. See
[ADR 0002](adr/0002-native-webrtc-transport-and-turn.md).

| Target | Phase 2B compile / WebRTC result | Required next validation |
| --- | --- | --- |
| macOS Intel Ventura | Locked transport built. A real same-process loopback data channel exchanged a bounded ping; selected ICE evidence was `host`/`host`. Native coordinator Ed25519 authentication passed against loopback. | Two physical devices, local IPC, signed-SDP route display, STUN, coturn relay, reconnect, Screen Recording/Accessibility boundaries. |
| macOS Apple Silicon | Not run | Native build/test; Keychain and socket behavior; direct/relay network paths and signed packaging. |
| Windows x64 | Not run | Native build with rustls roots, Credential Manager, networking/firewall, named-pipe ACL, direct/relay/TLS paths. |
| Ubuntu x64 | Not run | Native build plus Secret Service/headless conditions, firewall, X11/Wayland coexistence, direct/relay/TLS paths. |
| Linux ARM64 / Raspberry Pi / Jetson | Not run | Native build on each supported OS image, memory/CPU measurements, UDP/TCP/TLS relay behavior, and background-service lifecycle. |

The host/direct loopback evidence does **not** establish same-LAN, server-
reflexive, relay, CGNAT, blocked-UDP, or TURN/TLS support. The local coturn
fixture is unrun because Docker/coturn was unavailable. See
[WebRTC testing](WEBRTC_TESTING.md) for the exact manual validation sequence.

## Phase 3 desktop adapter

The native desktop boundary is documented in
[ADR 0003](adr/0003-native-desktop-adapter.md). It pins `xcap` 0.9.8 for
capture and `enigo` 0.6.1 for input only under the macOS target. The agent
reports monitor identity/geometry/scale, applies normalized coordinate mapping
in native code, and uses software JPEG; it does not claim hardware encoding.
Every other current target returns a capability error rather than simulated
capture or input.

| Target | Phase 3 actual result | Required work before any support claim |
| --- | --- | --- |
| macOS Ventura Intel x64 | Source and native dependencies compiled; protocol/policy tests passed. `desktop-capabilities` returned no monitors with `screen_recording_permission_required`; capture and input probes failed closed before doing either action. | Grant Screen Recording and Accessibility on physical hardware; test real capture/control, display hot-plug/DPI, revoke/cleanup, direct, relay, and signed/notarized application behavior. |
| macOS Apple Silicon arm64 | Not run. | Compile and run capture/input/permission/quality tests on physical Apple Silicon; validate signing and all direct/relay paths. |
| Windows x64 | Explicit unsupported adapter at runtime; not tested. | Implement and hardware-test a Windows capture/input adapter including DPI, keyboard layouts, UAC/secure desktop, lock/login window, and cleanup. |
| Ubuntu x64 X11 | Explicit unsupported adapter at runtime; not tested. | Implement an X11 adapter and test session permissions, coordinate transforms, keyboard layout, display changes, direct/relay and logout/lock cleanup. |
| Ubuntu x64 Wayland | Explicit unsupported adapter at runtime; not tested. | Use a supported portal/PipeWire design. Do not bypass portal consent or infer support from experimental upstream APIs. Document compositor-specific restrictions. |
| Linux ARM64 / Raspberry Pi / Jetson | Explicit unsupported adapter at runtime; not tested. | Repeat actual capture/input/encoder/network validation on each OS image and graphics stack; cross-compilation is not sufficient. |

Screen sharing cannot reach the macOS login window or FileVault pre-boot UI. No
Windows secure-desktop, Linux login manager, or Wayland support is claimed.
These OS-protected surfaces are not bypassed.

## Phase 4 SSH and files

| Target | Phase 4 actual result | Required work before any support claim |
| --- | --- | --- |
| macOS Ventura Intel x64 | Native SSH/file source and locked dependencies compile. A direct same-host two-native-agent file transfer passed with independent configured roots, scoped host `files.read`/`files.write`, a 4 MiB file, nested tree, empty directory, SHA-256 completion and atomic destination. `/usr/bin/ssh` and `/usr/sbin/sshd` exist, but strict loopback port-22 probe returned `Connection refused`; no SSH login was run. | Manually enable/configure Remote Login only if intended; test first-use/changed host keys, normal authentication, terminal resize/cancellation, file ACL/disk-full/revocation/resume, second machine, desktop contention and selected relay. |
| macOS Apple Silicon arm64 | Not run. | Repeat real SSH/file/direct/relay/permissions tests on physical hardware; validate packaging and Keychain scope. |
| Windows x64 | Not run. | Test actual optional OpenSSH Server configuration, host-key behavior, NTFS ACLs, reparse-point races, filenames, atomic replacement, and relay. |
| Ubuntu x64 X11/Wayland | Not run. | Test administrator-managed OpenSSH service, POSIX ACLs, symlink races, paths, desktop/file contention, and relay separately for X11/Wayland. |
| Linux ARM64 / Raspberry Pi / Jetson | Not run. | Test on each OS image with real filesystem, SSH service, CPU/memory/bandwidth measurements and direct/relay paths. |

The Phase 4 direct file harness deliberately omits its unreachable TURN URL
from ICE gathering. It proves neither relay nor general two-device platform
support. SSH uses the system OpenSSH client with normal host-key verification;
there is no custom agent command shell or unrestricted TCP forwarding. See
[SSH and file testing](SSH_FILE_TESTING.md).

## Phase 5 unattended lifecycle and background service

Phase 5 adds a native SQLite migration for explicit unattended enablement,
scoped grants, bounded service leases, lifecycle/audit metadata, local
Disconnect/Disable, signed remote-revocation acknowledgement, and a
same-user-authenticated Unix control socket. It does not convert compatibility
into platform support or bypass OS-protected logon/pre-boot surfaces.

| Target | Phase 5 source status | What remains before support may be claimed |
| --- | --- | --- |
| macOS Ventura Intel x64 | Per-user LaunchAgent template and native mode-0600/peer-UID local socket compile. The LaunchAgent is intended for the logged-in GUI user; no install, login-screen, FileVault, TCC, service restart, or remote-revocation physical test has run. | Physical LaunchAgent/bootstrap/uninstall, Keychain signing scope, TCC consent persistence, sleep/wake, network transition, remote revocation and two-device active-session termination. |
| macOS Apple Silicon arm64 | Template only; not run. | Same physical lifecycle/Keychain/TCC tests on signed Apple Silicon build. |
| Ubuntu x64 | Per-user systemd and isolated unprivileged headless-core templates are provided, not installed or executed. The headless core uses a separate identity and `PrivateDevices=yes`; it cannot offer desktop capture/input. | Actual Secret Service behavior with user/system state separation, socket peer credentials, systemd restart/reboot, SSH/files, desktop X11/Wayland, remote revoke and package/uninstall tests. |
| Windows x64 | A LocalService headless-core test script is provided but not run. The Rust Unix socket implementation is unavailable on Windows, so no named-pipe service-SID IPC claim is made. | Implement and test named-pipe SID ACL transport, Credential Manager service/user isolation, service install/upgrade/uninstall, interactive desktop broker, UAC/secure desktop restrictions and reboot/revocation tests. |
| Linux ARM64 / Raspberry Pi / Jetson | Templates only; not run. | Repeat user-session/headless service, protected store, reboot, SSH/files, graphics-session and resource tests on every OS image. |

Logged-in desktop sessions remain distinct from headless SSH/files. No source
component reaches macOS FileVault/preboot or login window, Windows secure
desktop/login screen, a Linux display manager, or an unapproved Wayland portal.
See [operational unattended access](UNATTENDED_ACCESS.md) and the
[two-device acceptance guide](UNATTENDED_ACCEPTANCE.md).

## Sources to recheck before every runtime update

- [Electron releases and support policy](https://releases.electronjs.org/)
- [Electron 44 release notes](https://www.electronjs.org/blog/electron-44-0)
- [Electron installation architectures](https://www.electronjs.org/docs/latest/tutorial/installation)
- [Electron breaking changes](https://www.electronjs.org/docs/latest/breaking-changes)

Platform claims remain constrained to this matrix until device-specific
validation has run.
