# Unattended access — required behavior

Unattended access is an accepted product requirement. It is not available in
Phase 1. Default OFF; no universal password, hidden access or automatic trust
from saving a device bookmark.

## Setup

1. Host owner enables unattended access locally and approves required OS permissions.
2. Controller and host pair with authenticated device keys. Compare a verification
   code or use an audited authenticated pairing protocol; a short locator ID is
   never the sole secret. Rate-limit all enrollment attempts.
3. Host owner chooses capabilities, validity and trusted controller identity.
4. Agent persists the grant with protected host-owned storage and an audit entry.
5. Subsequent approved sessions can proceed without a person clicking Accept.

Capabilities: desktop.view, desktop.control, ssh, files.read and files.write.
Control does not automatically permit SSH or files. The desktop UI must explain
that useful interactive desktop control normally also needs view permission.
A reconnect reuses identity and grants, not a stored plaintext session password.

## Lifecycle

Disabled -> local opt-in -> authenticated pairing -> active grant -> expiry/revocation.
Expired/revoked grants require deliberate renewal. Reinstallation or key changes
must trigger re-pairing; matching device names must not restore trust.

Agent checks grants before starting sessions and before privileged operations.
For long-lived screen/control/SSH streams, expiry timers and revocation events
terminate affected channels and release resources. Files stop at a safe checkpoint.
UI reports success only after the host acknowledges revocation; remote revocation
cannot be claimed instantaneous while the host is unreachable. Account-managed
grants should use short online authorization leases and fail closed on lease
expiry if revocation status cannot be refreshed. Local host revocation is immediate.
Do not represent Phase 1's standalone policy tests as working session termination.

## Background execution

Install service/launch agent only after host consent. Use platform-appropriate
user-session helpers for capture and a minimally privileged service for startup
and protected operations. Define authenticated, ACL-restricted local IPC. Never
run the Electron renderer as administrator/root to solve input permissions.

Show a session indicator and provide a local Disconnect / Disable access action.
Log controller identity, capability grants, session timing and revocation events;
do not log screen contents, keystrokes, credentials or private file data by default.

## Threat and acceptance tests

| Scenario | Required result |
| --- | --- |
| Guessed device ID | No access or trust |
| Forged authentication field | Rejected before policy evaluation |
| Replayed handshake/token | Rejected by freshness/session binding |
| Compromised coordinator substitutes key | Identity mismatch blocks connection |
| View-only peer sends input/SSH/file command | Denied by host |
| Grant expires during SSH/video | Active affected channels terminate |
| Host disables unattended access | Denies new sessions; closes unattended sessions |
| Host offline during remote revoke | UI reports pending; no false success |
| Symlink or path traversal file request | No escape from approved roots |
| Interrupted upload/reconnect | Resume only with renewed authorization and integrity checks |
| Service restart or clock rollback | Expiry/freshness behavior fails safely |

Production release requires protocol review, tests on real devices and an
independent penetration assessment against a defined scope. Passing tests is
not a guarantee of absence of vulnerabilities.
