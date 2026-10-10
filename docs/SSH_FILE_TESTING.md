# SSH and file-transfer testing

## Evidence boundary

Phase 4 adds native, authenticated WebRTC channels for SSH and files. The
file harness has completed an attended-pairing, host/direct loopback transfer
in both directions, including a nested tree and an empty directory. Its TURN
URL is intentionally unreachable, so this is not relay evidence.

The development Mac has `/usr/bin/ssh` and `/usr/sbin/sshd`, but a strict,
non-mutating probe found port 22 **connection refused**. No SSH service was
enabled or installed. Consequently there is no genuine SSH login, terminal
authentication, first-use host-key, changed-key, or relay result yet.

## Prepare an SSH host manually

The host agent forwards only to `127.0.0.1:<approved-port>`. It does not expose
a controller-selected host, a LAN TCP proxy, shell command API, agent shell,
or SSH forwarding. An administrator must first decide to run an SSH server and
which local users may log in; the agent never installs, enables, or starts one.

On macOS, turn on **System Settings → General → Sharing → Remote Login** and
restrict access to the intended users. On Ubuntu, an administrator may choose
to install `openssh-server` and enable the `ssh` service after reviewing its
firewall and account policy. On Windows, install the optional **OpenSSH
Server** feature and start/configure its service through the normal Windows
administration tools. These are operating-system changes outside this project.

After an SSH server is already listening locally, configure only its loopback
port and grant the paired controller a short-lived `ssh` capability:

```bash
cargo run --manifest-path agent/Cargo.toml --locked -- configure-ssh-endpoint \
  --state-dir <HOST_STATE_DIR> --port 22

cargo run --manifest-path agent/Cargo.toml --locked -- grant-ssh \
  --state-dir <HOST_STATE_DIR> --peer-fingerprint <CONTROLLER_FINGERPRINT> \
  --expires-at <UNIX_MS_WITHIN_24_HOURS>
```

Start `ssh-host` first and `ssh-controller` second with the paired locator,
fingerprint, coordinator, and bind/ICE options shown in the desktop guide. The
controller additionally requires `--username <OS_USER>`. The React terminal
uses a local PTY running the system `ssh` client, so passwords, private-key
passphrases, MFA prompts, and keys are entered into OpenSSH and are never put
in renderer storage, agent configuration, or diagnostics.

The client uses a host-specific alias and a known-hosts file inside the agent
state directory. At first use, OpenSSH shows its normal fingerprint prompt;
compare it with an out-of-band administrator value before approving. A changed
key is rejected and surfaced as a warning—do not delete or override the known
host entry as a workaround. Resize, disconnect, EOF, host revocation, or a
transport failure closes the PTY, loopback listener, data channel, and approved
endpoint socket.

## Configure approved file roots

File paths are virtual: `0/.` is the first configured root, and `0/docs/a.txt`
is beneath that root. The renderer has no ambient path API. Configure roots
locally on each agent; one installation may act as controller or host.

```bash
cargo run --manifest-path agent/Cargo.toml --locked -- configure-file-roots \
  --state-dir <STATE_DIR> --read-root <ABSOLUTE_READ_ROOT> \
  --write-root <ABSOLUTE_WRITE_ROOT>

# Read listing/download and upload are independently enforced at the host.
cargo run --manifest-path agent/Cargo.toml --locked -- grant-files-read-write \
  --state-dir <HOST_STATE_DIR> --peer-fingerprint <CONTROLLER_FINGERPRINT> \
  --expires-at <UNIX_MS_WITHIN_24_HOURS>
```

Use separate `grant-files-read` or `grant-files-write` commands for a
read-only or write-only test. The host reports both values when the session
opens and rechecks the relevant grant on every request/chunk/directory action.
Revocation, expiry, disconnect, and resume all require a fresh current grant.

Files and bounded folder trees (maximum 512 entries and 8 GiB aggregate) move
one 32 KiB chunk at a time only after a receiver pull/ack, paced at roughly
2 MiB/s payload. This intentionally leaves network/encoder capacity for
desktop and input. SHA-256 manifests,
strict offsets, and final rehashing detect source changes/corruption. New data
lands in a same-directory `.wii-transfer-<id>.part` file and becomes visible
only after an atomic rename. Collision mode is explicit: **Fail safely** or
**Atomically replace**. A reconnect may resume an individual partial file only
when its transfer ID, path, size, and hash still match; a changed manifest is
rejected. An interrupted folder queue is restarted explicitly; already-complete
members then follow its selected collision policy rather than being silently
assumed valid.

Traversal, absolute paths, symlinks/reparse points, non-UTF-8 names, control
characters, Windows-reserved names, and names not portable across the target
filesystems are rejected. Directories are created component-by-component under
the approved write root; neither an existing symlink nor a file can be used as
a directory. Disk-full, permissions, source-change, path-race, integrity,
collision, and connection errors close or reject the affected operation without
claiming success.

Partial files and their manifest metadata are retained for 24 hours to support
resume. They are removed after successful atomic completion; on a later retry
to that destination, stale partial metadata older than 24 hours is removed.
There is deliberately no ambient startup sweep of user directories.

## Run the available direct integration

```bash
npm run test:native-file-session
```

This harness creates temporary roots and agent state, performs attended
pairing, configures roots, grants both file capabilities at the host, and
verifies a 4 MiB file plus nested and empty-directory upload/download. It
cleans temporary data afterward. It does not test relay, disk-full, OS ACL
denial, a real second machine, hostile Windows reparse points, or contention
with active desktop capture; record those manual tests before claiming them.

For relay validation, deploy restricted coturn as documented in
[WebRTC testing](WEBRTC_TESTING.md), run two permitted machines in
`relay-only` mode, and retain coturn allocation plus selected `relayed`
candidate evidence. Do not treat a configured URL or cross-compilation as
runtime support.
