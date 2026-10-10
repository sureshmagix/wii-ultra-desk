# Local coturn relay fixture

This directory is a **local test fixture**, not Utho or production
infrastructure. It uses coturn's immutable `4.18.0-r0` test image tag, a
generated 256-bit REST shared secret, two allocations per user, eight total
allocations, and relay ports `49160-49170` only. Its generated `.env` is ignored
by Git and must never be reused outside the local machine.

```bash
node infra/coturn/generate-local-env.mjs
docker compose --env-file infra/coturn/.env -f infra/coturn/docker-compose.local.yml up -d
docker compose --env-file infra/coturn/.env -f infra/coturn/docker-compose.local.yml logs -f
```

The `allowed-peer-ip=127.0.0.1` exception exists solely to make a same-host
relay allocation possible. It is deliberately accompanied by denials for the
other private, CGNAT, link-local, multicast, and unspecified address ranges.
Docker Desktop's VM network can make that loopback exception unsuitable on
macOS/Windows; run the allocation test on a Linux host-network setup or use two
Linux machines for a real relay test. Do not remove the private-destination
restrictions simply to make a test pass.

To supply the matching secret only to a local coordinator process:

```bash
set -a
source infra/coturn/.env
set +a
WII_TURN_URLS=turn:127.0.0.1:3478?transport=udp npm run server
```

The agent receives only a scoped, expiring username and HMAC credential through
the authenticated coordinator. It never reads `WII_TURN_SHARED_SECRET`.

Stop and remove the local fixture when done:

```bash
docker compose --env-file infra/coturn/.env -f infra/coturn/docker-compose.local.yml down
```

No coturn/Docker binary was present on the Phase 2B development host, so this
fixture has not been started or validated here. Use the manual procedure in
`docs/WEBRTC_TESTING.md` for real relay, TLS, CGNAT, and blocked-UDP checks.
