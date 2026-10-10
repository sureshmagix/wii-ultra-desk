# Operational unattended access

Unattended access is off after a fresh install and stays off after pairing.
Bookmarks are locators only; they have no role in authorization. The host's
native SQLite store is the only local source of trusted controller identity,
scope, expiry, revocation, background enablement, leases, and audit metadata.

## Enable, grant, renew, revoke

The owner performs every enable operation locally, under the target user's OS
account, after pairing the controller and reviewing the exact scope. The
command refuses an empty scope and checks desktop permissions by opening the
native adapter; SSH/files require no screen/input permission.

```bash
AGENT=/absolute/path/to/wii-ultra-desk-agent
STATE="$HOME/.local/state/wii-ultra-desk"

# Pair first using the attended procedure, then grant one bounded scope.
"$AGENT" grant-ssh --state-dir "$STATE" --peer-fingerprint CONTROLLER_FP --expires-at UNIX_MS

# Deliberate local owner confirmation; this example enables SSH only.
"$AGENT" enable-unattended --state-dir "$STATE" \
  --owner-confirmation ENABLE_UNATTENDED --allow ssh
```

Desktop scopes may be included only after the command's capture/input preflight
succeeds. The preflight does not retain or transmit pixels or keystrokes. On
unsupported adapters it fails; it never treats a UI checkbox as OS consent.

Renewal is the same bounded grant command with a future expiry (maximum 24
hours). It replaces that controller's previous scope set atomically. Do not
issue a renewal through a bookmark. Revoke a trusted identity locally:

```bash
"$AGENT" revoke-peer --state-dir "$STATE" --peer-fingerprint CONTROLLER_FP
"$AGENT" trusted-devices --state-dir "$STATE"
"$AGENT" security-events --state-dir "$STATE" --limit 50
```

`revoke-peer`, expiry, disabling unattended access, and local Disconnect mark
affected live service sessions terminated. Host loops recheck authorization on
each desktop capture/input, SSH byte direction, and file operation; an idle
SSH/file channel also checks its lease once per second. Held desktop input is
released by the desktop session cleanup. A service-issued lease lasts at most
five minutes and fails closed rather than being extended by wall-clock rollback.

Use the Electron **Disconnect unattended** and **Disable unattended access**
buttons only when its per-user service is running. They pass through the
sender-validated Electron IPC and then a mode-0600 native Unix socket whose
peer UID is verified by the agent. They also stop Electron-owned desktop, SSH,
and file children before asking the agent to terminate background channels.

The service socket intentionally exposes no secret export, arbitrary command,
screen, keyboard, or file RPC. It accepts only status, device/event summaries,
Disconnect, and Disable. Event history records lifecycle and authorization
events only; it never records screen contents, file data, terminal content,
keystrokes, passwords, or secrets.

## Background agent and service boundaries

Start the native authorization service independently of Electron:

```bash
"$AGENT" daemon --state-dir "$STATE" --coordinator wss://coord.example/v1/connect
"$AGENT" local-control --state-dir "$STATE" --action status
```

It recovers any stale session records after restart and keeps the local control
socket in the private state directory when its pathname fits Unix limits. For
deep state paths, it uses a deterministic owner-only `0700` directory below
`/tmp`; the socket remains mode `0600` and its peer UID is still checked. It
does not make Electron a privileged broker. A service-owned host command must
opt into the enforced path with
`--unattended`; without that switch, existing Electron flows remain attended.

```bash
"$AGENT" ssh-host --unattended --state-dir "$STATE" ...
"$AGENT" file-host --unattended --state-dir "$STATE" ...
"$AGENT" desktop-host --unattended --state-dir "$STATE" ...
```

The daemon accepts only a signed `control.revocation` lifecycle envelope from
an already trusted controller. It persists the request as `pending`, revokes
the exact pinned controller identity, marks its active channels terminated,
and sends a signed acknowledgement. The controller keeps the request pending
until that acknowledgement verifies against the host's pinned key:

```bash
"$AGENT" remote-revoke-peer --state-dir "$STATE" \
  --coordinator wss://coord.example/v1/connect \
  --peer-locator HOST_LOCATOR --peer-fingerprint HOST_FP
```

If the host is offline, the command leaves a pending record rather than
claiming success. The host's bounded five-minute session leases still fail
closed while online revocation delivery is unavailable. Automatic
coordinator-triggered host-session dispatch is not implemented; the daemon is
an authorization/lifecycle service, not a general remote-command listener.

## Platform/service installation on test machines

These are explicit test-machine actions. They are not run by this repository
and do not install a privileged service on the development machine.

### Ubuntu

For interactive desktop sessions, install only the **per-user** unit. It runs
as the signed-in user, uses that user's protected store, and is the only place
desktop capture/input can be attempted. It writes one unit file below the
user's home directory and starts one user service; it does not create users,
open ports, change SSH, or grant Wayland/X11 permissions.

```bash
mkdir -p ~/.config/systemd/user ~/.config/wii-ultra-desk ~/.local/state/wii-ultra-desk
printf '%s\n' 'WII_COORDINATOR_URL=wss://coord.example/v1/connect' > ~/.config/wii-ultra-desk/agent.env
chmod 600 ~/.config/wii-ultra-desk/agent.env
install -m 0644 infra/agent-services/systemd/wii-ultra-desk-agent.service \
  ~/.config/systemd/user/wii-ultra-desk-agent.service
systemctl --user daemon-reload
systemctl --user enable --now wii-ultra-desk-agent.service
systemctl --user status wii-ultra-desk-agent.service --no-pager
```

Remove it without deleting evidence or identity material:

```bash
systemctl --user disable --now wii-ultra-desk-agent.service
rm ~/.config/systemd/user/wii-ultra-desk-agent.service
systemctl --user daemon-reload
```

`wii-ultra-desk-core.service` is a separate, unprivileged system-account
template for headless SSH/files. It has `PrivateDevices=yes` and cannot do
desktop capture/input. Its state and identity are distinct and must be paired
again; never point it at a user's keyring/state directory. An administrator
must review paths, create `wii-ultra-desk`, install the binary and unit, then
run `systemctl enable --now wii-ultra-desk-core`. No command in this repository
does that automatically.

### macOS

Use the LaunchAgent template in the logged-in GUI session, never a root daemon,
for any desktop scope. Substitute absolute paths in a copy, then bootstrap it:

```bash
STATE="$HOME/Library/Application Support/WII Ultra Desk"
mkdir -p "$STATE" "$HOME/Library/LaunchAgents"
sed -e "s|__AGENT_PATH__|/absolute/path/wii-ultra-desk-agent|g" \
    -e "s|__STATE_DIR__|$STATE|g" \
  infra/agent-services/macos/org.wii-ultra-desk.agent.plist.template \
  > "$HOME/Library/LaunchAgents/org.wii-ultra-desk.agent.plist"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/org.wii-ultra-desk.agent.plist"
```

This creates a per-user plist and starts a user-session process. It does not
grant Screen Recording or Accessibility, does not bypass FileVault/pre-boot,
and cannot show or control the login window. Remove with
`launchctl bootout gui/$(id -u)/org.wii-ultra-desk.agent` and delete only the
plist if preserving audit/state is desired.

### Windows

`install-headless-core.ps1` creates an auto-start LocalService **headless
core** only after an administrator explicitly runs it with absolute binary and
state paths. It creates the service, makes the supplied state directory
accessible only to LocalService and SYSTEM, sets two restart attempts, and
starts it. It does not install drivers, grant UAC/secure-desktop access, open
firewall ports, configure OpenSSH, or share the signed-in user's identity.

```powershell
PowerShell -ExecutionPolicy RemoteSigned -File .\infra\agent-services\windows\install-headless-core.ps1 `
  -AgentPath 'C:\Program Files\WII Ultra Desk\wii-ultra-desk-agent.exe' `
  -StateDirectory 'C:\ProgramData\WII Ultra Desk\core'
```

Uninstall removes only the service registration and preserves its state:

```powershell
PowerShell -ExecutionPolicy RemoteSigned -File .\infra\agent-services\windows\uninstall-headless-core.ps1
```

Windows desktop capture/input and the service-SID/named-pipe transport remain
unsupported pending physical validation. No Windows login or secure desktop
access is claimed.

## Identity, restart, sleep, network and clock handling

Identity keys remain in the OS credential store; SQLite contains public trust
and lifecycle metadata only. If the protected key is absent or does not match
the recorded public material, the agent refuses to start. A reinstall with a
new state/identity or an identity-key change requires attended re-pairing.

Session records are made stale on agent restart. Sleep/wake and network changes
must reconnect with new coordinator authentication, new SDP/ICE material and
new short-lived relay credentials; old channels are not resumed. A backwards
wall-clock movement greater than five minutes is an audited anomaly and blocks
new unattended authorization until local time is corrected. Existing grants
are always bounded by expiry; they do not become perpetual when offline.
