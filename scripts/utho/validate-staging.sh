#!/usr/bin/env bash
# Read-only except for a short-lived, mode-0600 generated config in /run.
set -euo pipefail

ETC_ROOT=/etc/wii-ultra-desk
APP_ROOT=/opt/wii-ultra-desk
die() { echo "validate-staging: $*" >&2; exit 1; }
require_supported_node() {
  local version major minor patch
  version=$(node -p 'process.versions.node')
  [[ $version =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || die "could not parse Node version: $version"
  major=${BASH_REMATCH[1]}
  minor=${BASH_REMATCH[2]}
  patch=${BASH_REMATCH[3]}
  (( major > 22 || (major == 22 && (minor > 12 || (minor == 12 && patch >= 0))) )) || die "Node $version is unsupported; require >=22.12.0"
}
[[ $EUID -eq 0 ]] || { echo 'validate-staging: must run as root' >&2; exit 1; }
[[ -f $ETC_ROOT/staging.env ]] || { echo "validate-staging: missing $ETC_ROOT/staging.env" >&2; exit 1; }
[[ -x $APP_ROOT/current/scripts/utho/generate-coturn-config.mjs || -f $APP_ROOT/current/scripts/utho/generate-coturn-config.mjs ]] || { echo 'validate-staging: release is not installed' >&2; exit 1; }
for command in node systemd-analyze systemctl curl mktemp awk sort tr; do command -v "$command" >/dev/null || { echo "validate-staging: missing $command" >&2; exit 1; }; done
require_supported_node

temporary=$(mktemp /run/wii-ultra-turn-config.XXXXXX)
trap 'rm -f "$temporary"' EXIT
chmod 0600 "$temporary"
node "$APP_ROOT/current/scripts/utho/generate-coturn-config.mjs" --env "$ETC_ROOT/staging.env" --out "$temporary"
systemd-analyze verify /etc/systemd/system/wii-ultra-desk-coordinator.service /etc/systemd/system/wii-ultra-turn.service

command -v turnserver >/dev/null || die 'coturn turnserver binary is required for staging validation'
if command -v ss >/dev/null && ! systemctl is-active --quiet wii-ultra-turn; then
  mapfile -t turn_ports < <(awk -F= '/^(listening-port|tls-listening-port|min-port|max-port)=/ { print $2 }' "$temporary")
  [[ ${#turn_ports[@]} -eq 4 ]] || { echo 'validate-staging: generated TURN ports could not be read' >&2; exit 1; }
  occupied=$(ss -H -ltnu | awk -v first_listener="${turn_ports[0]}" -v second_listener="${turn_ports[1]}" \
    -v relay_first="${turn_ports[2]}" -v relay_last="${turn_ports[3]}" '
      { endpoint = $5; sub(/^.*:/, "", endpoint) }
      endpoint ~ /^[0-9]+$/ && (endpoint == first_listener || endpoint == second_listener ||
        (endpoint >= relay_first && endpoint <= relay_last)) { print endpoint }' | sort -nu | tr '\n' ' ')
  [[ -z $occupied ]] || { echo "validate-staging: selected TURN ports are already occupied: $occupied" >&2; exit 1; }
fi
if command -v nginx >/dev/null && [[ -f /etc/nginx/conf.d/wii-ultra-desk-coordinator.conf ]]; then nginx -t; fi
if systemctl is-active --quiet wii-ultra-desk-coordinator; then curl --fail --silent --show-error http://127.0.0.1:4310/healthz >/dev/null; fi
echo 'Staging configuration validation completed. No service was started or reloaded.'
