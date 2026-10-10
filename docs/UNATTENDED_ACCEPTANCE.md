# Two-device unattended-access acceptance guide

Run this only on two machines and accounts you are authorized to administer.
Do not test against a login window, FileVault/pre-boot UI, Windows secure
desktop, or any OS-protected surface.

1. Build the exact locked agent on both devices. Create separate private state
   directories. Start the per-user daemon on the host and confirm
   `local-control --action status` reports `enabled:false`.
2. Complete attended pairing and compare the displayed SAS on both machines.
   Save no authorization in bookmarks. Record host/controller locator and
   fingerprint from native status output.
3. On the host configure only required file roots or the local SSH loopback
   endpoint. Give the controller one short (for example five-minute) scope.
   Enable unattended locally with the exact selected `--allow` scopes. For
   desktop, separately approve the native signed agent in Screen Recording and
   Accessibility, then require the enable preflight to pass.
4. Close Electron on the host. Verify its per-user native service continues.
   Start a host command with `--unattended` and an authenticated controller
   from the second machine. Verify host event history records start/end only,
   never terminal/file/screen/keyboard content.
5. While SSH/file/desktop is active, use Electron **Disconnect unattended**.
   Verify the host process closes promptly, held input is released, transfer
   stops, and the service reports zero active sessions. Repeat using **Disable
   unattended access** and verify a new service-owned host attempt is denied.
6. Renew the grant, reconnect, then wait through expiry during an active
   operation. Verify the affected channel terminates. Reconnect and use
   `revoke-peer`; verify all its current channels end and it no longer appears
   as active in trusted-device management.
7. Disconnect the coordinator/network during an active service session.
   Confirm it cannot exceed its five-minute authorization lease without fresh
   online authentication. Restore network and establish a fresh session; do
   not reuse SDP, TURN credentials, or session IDs.
8. Restart the agent and, where authorized, reboot the host. Confirm stale
   session records are recovered, no channel is treated as live after reboot,
   and the native service starts while Electron remains closed. Validate a
   sleep/wake and network-change recovery likewise.
9. Attempt local control from another OS user. The private socket path/UID
   check must reject it. Attempt to substitute the controller key for its
   locator; pairing/signaling must fail and require re-pairing.
10. Upgrade from a Phase 4 state database. Verify migration v2 preserves
    trusted devices/grants, initializes unattended disabled, and records no
    secret material. Preserve a copy for rollback before any test migration.

Record command versions, OS version/session type, selected ICE route, exact
scope/expiry, timing of each termination, service logs, and expected failure
codes. Current source validation does not substitute for these physical tests.
