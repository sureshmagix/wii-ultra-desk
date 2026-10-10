# Ubuntu Utho staging deployment

This runbook prepares a **new WII Ultra Desk staging footprint only**. It does
not authorize connecting to Utho, editing DNS/firewall rules, installing
packages, or reloading any service. Review the commands with the VPS owner and
run them on a maintenance window. Existing Nginx, MQTT, ArchidTech, and other
services are explicitly out of scope.

The currently implemented product surface is an authenticated, status-only
WebRTC ping/pong. It is not remote desktop, arbitrary command execution, SSH,
file transfer, or unattended access.

## Derived deployment requirements

The Node coordinator binds `127.0.0.1` only and exposes `GET /healthz` plus
WebSocket `/v1/connect`; Nginx terminates HTTPS/WSS on a separate public DNS
name and proxies only those paths. Its SQLite database needs a private,
durable writable directory. The coordinator must receive `WII_TURN_URLS` and
the TURN REST shared secret at runtime; clients receive only short-lived HMAC
credentials.

coturn is a direct UDP/TCP/TLS service, not HTTP. It must bind its own public
listener and relay ports. Do **not** create an Nginx `location` for TURN or put
it behind a normal HTTP reverse proxy.

| Required value | Staging value to obtain; do not invent it |
| --- | --- |
| Coordinator DNS | `coord.<staging-domain>` A record for the VPS ingress IPv4; add AAAA only after a separate IPv6 ingress review |
| TURN DNS | `turn.<staging-domain>` A record for the TURN ingress IPv4; do not publish AAAA for this IPv4-only staging generator |
| Coordinator ingress | TCP 443, Nginx → `127.0.0.1:4310` |
| TURN ingress | UDP/TCP 3478; TLS/DTLS 5349; UDP/TCP relay range 49160–49200 |
| Coordinator storage | `/var/lib/wii-ultra-desk/coordinator.sqlite`, backed up consistently |
| Runtime secret file | `/etc/wii-ultra-desk/staging.env`, root-owned, mode `0640`, group `wii-ultra-secrets` |
| TURN certificate copies | `/etc/wii-ultra-desk/tls/fullchain.pem` and `privkey.pem`, readable by `wii-ultra-secrets` only |

Do not use port 443 for TURN on the same IP as Nginx. If TURN/TLS on 443 is a
real requirement, reserve a dedicated public IP for coturn, or commission a
reviewed L4/SNI design that proves it can distinguish non-HTTP TURN/TLS from
HTTPS without weakening either service. The supplied generator deliberately
rejects privileged listener ports, including 443.

This first staging generator intentionally accepts only IPv4 listener, relay,
and NAT-mapping addresses. It therefore must not be paired with an IPv6 TURN
DNS record or an IPv6 firewall opening. IPv6 deployment needs a separately
reviewed listener, relay mapping, destination-policy, and test plan.

## Developer machine — prepare and validate the artifact

Run these from the checkout. They do not touch a VPS.

```bash
npm ci
npm run lint
npm test
npm run build
bash -n scripts/utho/install-staging.sh
bash -n scripts/utho/validate-staging.sh
bash -n scripts/utho/upgrade-staging.sh
bash -n scripts/utho/uninstall-staging.sh
```

The automated Node tests include production coturn generator acceptance and
rejection cases. The generator is tested with temporary dummy certificate files;
it is not a coturn binary integration test. Build a reviewable release archive
from the exact Git revision only after these pass. Preserve `package-lock.json`
with the source artifact.

## VPS — inventory before any install

The following are read-only checks. Record their output in the change request
so current Nginx, MQTT, ArchidTech, certificates, ports, and firewall rules are
known before any change.

```bash
hostnamectl
node --version
npm --version
turnserver --version
nginx -V
sudo systemctl --type=service --all | grep -Ei 'nginx|mqtt|mosquitto|archid|turn|wii' || true
sudo nginx -T
sudo ss -H -ltnup
sudo ss -H -lnup
sudo ufw status verbose || true
```

Require Node `>=22.12.0`, a current Ubuntu-supported coturn package, Nginx,
`sqlite3`, `curl`, `openssl`, and `rsync` or `tar`. Do not replace the installed
Nginx, MQTT, ArchidTech, or coturn package/configuration merely to satisfy this
runbook. Resolve every existing 3478, 5349, relay-range, coordinator-FQDN, and
443 conflict first.

## VPS — install the isolated staging footprint

After copying the reviewed source archive to the VPS and extracting it outside
the release target, run the safe installer. It creates dedicated system users,
a versioned release directory, protected directories, and WII-specific systemd
units. It does not start, enable, reload, remove, or modify an existing service.

```bash
sudo bash /path/to/checkout/scripts/utho/install-staging.sh \
  --source /path/to/checkout \
  --release GIT_REVISION_OR_RELEASE_ID \
  --confirm-staging
```

The installer refuses an existing release identifier, a non-checkout source,
occupied 3478/5349 ports, and differing WII-managed unit files. Before a
first start, the validator checks the selected listener and every selected
relay port. Neither copier carries `.env`, key/certificate, or SQLite artifacts
from a source checkout into the release. It creates
`/opt/wii-ultra-desk/current` as the only mutable release pointer; data and
secrets are outside it.

## VPS — protected runtime configuration and TLS

The installer creates an empty protected runtime file. Populate it once using
the checked-in example as a reference; do not overwrite a populated file, and
never copy it back to the developer machine or Git. Generate the secret on the
VPS, not in a shell history or terminal log.

```bash
sudo test ! -s /etc/wii-ultra-desk/staging.env
sudo sed -n '1,200p' /opt/wii-ultra-desk/current/infra/utho/staging.env.example
sudoedit /etc/wii-ultra-desk/staging.env
# Generate and paste one value while editing, rather than printing it:
# openssl rand -base64 48 | tr '+/' '-_' | tr -d '='
```

Set real coordinator/TURN DNS names, local relay address, optional public NAT
address, port range, quotas, and the three URLs in `WII_TURN_URLS`. The
coordinator and coturn must use the same secret. The generator rejects
placeholder values, weak/repeated secrets, unquoted shell syntax, invalid URLs,
loopback listeners, privileged ports, missing TLS files, and unsafe relay
ranges.

Obtain certificates using the existing certificate authority and renewal flow.
For coturn, install narrow-permission copies rather than granting its service
account access to the entire Let’s Encrypt directory:

```bash
sudo install -d -o root -g wii-ultra-secrets -m 0750 /etc/wii-ultra-desk/tls
sudo install -o root -g wii-ultra-secrets -m 0640 /path/to/fullchain.pem /etc/wii-ultra-desk/tls/fullchain.pem
sudo install -o root -g wii-ultra-secrets -m 0640 /path/to/privkey.pem /etc/wii-ultra-desk/tls/privkey.pem
sudo node /opt/wii-ultra-desk/current/scripts/utho/generate-coturn-config.mjs \
  --env /etc/wii-ultra-desk/staging.env \
  --out /etc/wii-ultra-desk/turnserver.conf
sudo chown root:wii-ultra-secrets /etc/wii-ultra-desk/turnserver.conf
sudo chmod 0640 /etc/wii-ultra-desk/turnserver.conf
```

Add an audited renewal deploy hook that repeats the two `install` commands,
regenerates the config, validates it, and restarts **only**
`wii-ultra-turn.service` in its approved maintenance window. Existing Nginx
certificate renewal/reload policy remains its owner’s responsibility.

## NAT, firewall, and ingress design

For a directly public VPS, set `WII_TURN_RELAY_IP` to the public interface
address and omit `WII_TURN_PUBLIC_IP`. For one-to-one NAT, set relay IP to the
VPS-private address and public IP to the NAT address. The generator emits
`external-ip=PUBLIC/PRIVATE`; the NAT must preserve every relay port exactly.
Do not use this single-address staging layout for multi-address or asymmetric
NAT without a reviewed mapping design.

Ask the VPS/network owner to add the following ingress rules after checking
existing rules; this runbook does not change a firewall.

| Protocol | Ports | Purpose |
| --- | --- | --- |
| TCP | 443 | HTTPS/WSS coordinator via existing Nginx |
| UDP and TCP | 3478 | TURN/STUN listener |
| UDP and TCP | 5349 | TURN TLS/DTLS listener |
| UDP and TCP | 49160–49200 | coturn allocation relay range |

Maintain normal SSH access according to the provider policy. Do not expose
4310 publicly. The generated coturn policy denies loopback, RFC1918, CGNAT,
link-local (including cloud metadata `169.254.169.254`), multicast, and IPv6
ULA/link-local destinations. It also limits each user to two allocations and
the server to 64; resize only after measured capacity review.

## HTTPS/WSS ingress without disturbing existing Nginx

Copy the Nginx template only after replacing the DNS placeholder, verifying no
existing server block owns that name, and confirming certificate paths. It
proxies `/healthz` and `/v1/connect` only; the latter has WebSocket upgrade
headers, buffering disabled, and a 960-second read timeout to cover the
coordinator’s 15-minute authenticated session limit.

```bash
sudo cp infra/utho/nginx/wii-ultra-desk-coordinator.conf.template /tmp/wii-ultra-desk-coordinator.conf
sudoedit /tmp/wii-ultra-desk-coordinator.conf
sudo install -m 0644 /tmp/wii-ultra-desk-coordinator.conf /etc/nginx/conf.d/wii-ultra-desk-coordinator.conf
sudo nginx -t
# Obtain existing Nginx owner approval before: sudo systemctl reload nginx
```

Never proxy TURN through this file. A `turns:` URL on 443 needs the dedicated
IP/reviewed L4 design described above, not an Nginx HTTP location.

## VPS — validate, start, and smoke test

Validation regenerates a mode-0600 temporary coturn config, verifies unit
syntax, optionally validates Nginx, and queries health only if the coordinator
is already active. It does not start/reload anything.

```bash
sudo bash /opt/wii-ultra-desk/current/scripts/utho/validate-staging.sh
sudo systemctl daemon-reload
sudo systemctl enable --now wii-ultra-desk-coordinator.service wii-ultra-turn.service
sudo systemctl status wii-ultra-desk-coordinator.service wii-ultra-turn.service --no-pager
curl --fail --silent --show-error http://127.0.0.1:4310/healthz
curl --fail --silent --show-error https://COORDINATOR_FQDN/healthz
sudo ss -H -ltnup | grep -E ':(3478|5349)\b'
sudo ss -H -lnup | grep -E ':(3478|5349)\b'
```

Then perform the two-device procedure in [WEBRTC_TESTING.md](WEBRTC_TESTING.md):
pair via `wss://COORDINATOR_FQDN/v1/connect`, grant only current
`desktop.view`, run automatic ICE on two LANs, then relay-only ICE. Record
selected candidate types from both agents, coturn allocation logs, failure
codes, and fresh-session evidence after a disconnect/reconnect. A successful
relay test requires selected `relay` candidates and coturn allocation evidence;
configuration or gathered candidates are not success evidence.

## Operations: logs, monitoring, backup, upgrade, rollback

Both new services log to journald, deliberately avoiding secret-bearing
application log files. Use scoped inspection only:

```bash
sudo journalctl -u wii-ultra-desk-coordinator.service -u wii-ultra-turn.service --since '1 hour ago'
sudo systemctl is-active wii-ultra-desk-coordinator.service wii-ultra-turn.service
curl --fail --silent http://127.0.0.1:4310/healthz
```

Keep existing journal rotation/retention policy unless its owner approves a
change; inspect it with `journalctl --disk-usage` and
`systemd-analyze cat-config systemd/journald.conf`. Monitor systemd restarts,
free disk, file descriptors, relay allocation failures, quota rejections, and
the HTTPS health endpoint. No Prometheus endpoint is configured in this
repository.

Back up SQLite using its backup API while the coordinator is running, retain
encrypted off-VPS copies according to your policy, and restore only during a
maintenance window:

```bash
sudo install -d -m 0700 /var/backups/wii-ultra-desk
sudo -u wii-ultra sqlite3 /var/lib/wii-ultra-desk/coordinator.sqlite \
  ".backup '/var/backups/wii-ultra-desk/coordinator-UTC_TIMESTAMP.sqlite'"
```

For an application upgrade, use the safe script. It creates a new release,
uses SQLite’s `.backup`, changes only `current`, restarts only the coordinator,
checks local health, and restores the previous pointer on failure. It does not
upgrade coturn, Nginx, system packages, or any unrelated service.

```bash
sudo bash /path/to/checkout/scripts/utho/upgrade-staging.sh \
  --source /path/to/new-checkout --release NEW_RELEASE_ID \
  --backup-dir /var/backups/wii-ultra-desk --confirm-staging
```

To remove only WII-owned units and its named Nginx snippet, preserving releases,
SQLite, secrets, certificates, and all unrelated services for recovery:

```bash
sudo bash /opt/wii-ultra-desk/current/scripts/utho/uninstall-staging.sh \
  --confirm-remove-wii-ultra-desk
```

## Unvalidated settings and required deployment inputs

The checked-in generator and Nginx/systemd syntax can be tested locally, but
this repository has not started coturn, parsed the generated file with a real
Ubuntu coturn binary, obtained a certificate, contacted Utho, or tested a real
network relay. The following cases remain mandatory staging validation: NAT
mapping, firewall/security-group behavior, TURN UDP/TCP/TLS allocation,
quota/allocation failure, renewal reload, two-device relay-only success,
CGNAT, blocked UDP, and target-platform client tests.

Before a real staging deployment, provide:

1. Ubuntu release, VPS hostname, direct-public vs NAT topology, public and
   private IPv4 addresses, existing IPv6 inventory (not for this initial
   configuration), and whether a second public IPv4 is available.
2. Coordinator and TURN DNS names, DNS control/propagation process, and TLS
   certificate/renewal owner.
3. Existing Nginx vhost/include layout, active listeners, and confirmation that
   443, 3478, 5349, and 49160–49200 do not conflict with MQTT, ArchidTech, or
   other services.
4. Firewall/security-group owner and approval for the listed TCP/UDP ports.
5. Chosen SQLite backup destination, encryption, retention, restore owner, and
   maintenance window.
6. Staging capacity target: expected concurrent allocations, relay bandwidth,
   CPU/RAM/disk limits, alert destination, and log-retention policy.
7. Whether TURN/TLS on 443 is genuinely required; if so, the dedicated-IP or
   reviewed L4 architecture approval.
