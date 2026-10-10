# Relay deployment notes

For a generated-secret, intentionally non-production local coturn fixture, see
[`coturn/README.md`](coturn/README.md). It has a bounded relay range and quotas
but must not be mistaken for a validated relay fallback or a production Utho
deployment.

For the repository-only Ubuntu staging configuration, operational sequence, and
explicitly unvalidated production checks, see
[`../docs/DEPLOY_UTHO.md`](../docs/DEPLOY_UTHO.md).

turnserver.conf.template is a planning template, not a validated production
configuration. No coturn service is installed by this package. Validate syntax
and all IPv4/IPv6 destination restrictions against the selected coturn release.
Use egress firewall restrictions as defense in depth, including IPv4-mapped IPv6
and provider-specific metadata/service networks.

Allocate dedicated DNS names and decide public/private IP mapping. Expose only
the selected listeners and relay UDP range through the firewall. 100 configured
allocations is a sample limit, not a guarantee of 100 simultaneous user sessions.
Tune quotas, bandwidth caps, file descriptor limits and range size under load.

The shared TURN credential secret belongs only on the coordinator and coturn
host. Do not put it in Electron, the agent or source control. Issue short-lived
credentials to authenticated authorized sessions; renewal must preserve active
allocation behavior while respecting revoked access.

Use valid TLS certificates, least-privilege file permissions, log retention,
monitoring and rotation. A TURN relay can see connection metadata but must not
have endpoint session keys. No media recording or decrypting gateway is planned.

Nginx HTTP proxy configuration alone is insufficient for TURN. TURN/TLS 443
needs a dedicated address or reviewed L4 arrangement. Existing ArchidTech web
and MQTT services must not be displaced.

Before public exposure, test anonymous allocation rejection, expired credentials,
private-network/metadata destination rejection, quotas, certificate validation,
TCP/TLS fallback and forced-relay sessions on separate networks.
