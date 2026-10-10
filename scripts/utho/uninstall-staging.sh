#!/usr/bin/env bash
# Safe uninstall: removes only named unit/snippet files and leaves release
# history, SQLite data, protected secrets, TLS material, Nginx core config and
# every unrelated service untouched for manual review/recovery.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'uninstall-staging: must run as root' >&2; exit 1; }
[[ ${1:-} == --confirm-remove-wii-ultra-desk ]] || { echo 'Usage: sudo uninstall-staging.sh --confirm-remove-wii-ultra-desk' >&2; exit 2; }
systemctl disable --now wii-ultra-desk-coordinator.service wii-ultra-turn.service 2>/dev/null || true
rm -f /etc/systemd/system/wii-ultra-desk-coordinator.service /etc/systemd/system/wii-ultra-turn.service
rm -f /etc/nginx/conf.d/wii-ultra-desk-coordinator.conf
systemctl daemon-reload
echo 'Removed WII Ultra Desk service units and its Nginx snippet only. Preserved /opt/wii-ultra-desk, /var/lib/wii-ultra-desk and /etc/wii-ultra-desk for backup/manual review.'
