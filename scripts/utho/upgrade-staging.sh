#!/usr/bin/env bash
# Creates a new immutable release, snapshots the coordinator DB, then rolls
# current back if the coordinator health check does not recover.
set -euo pipefail

APP_ROOT=/opt/wii-ultra-desk
DATA_ROOT=/var/lib/wii-ultra-desk
SOURCE=
RELEASE=
BACKUP_DIR=
CONFIRM=false
die() { printf '%s\n' "upgrade-staging: $*" >&2; exit 1; }
require_supported_node() {
  local version major minor patch
  version=$(node -p 'process.versions.node')
  [[ $version =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || die "could not parse Node version: $version"
  major=${BASH_REMATCH[1]}
  minor=${BASH_REMATCH[2]}
  patch=${BASH_REMATCH[3]}
  (( major > 22 || (major == 22 && (minor > 12 || (minor == 12 && patch >= 0))) )) || die "Node $version is unsupported; require >=22.12.0"
}
while (($#)); do
  case "$1" in
    --source) SOURCE=${2:-}; shift 2 ;;
    --release) RELEASE=${2:-}; shift 2 ;;
    --backup-dir) BACKUP_DIR=${2:-}; shift 2 ;;
    --confirm-staging) CONFIRM=true; shift ;;
    -h|--help) echo 'Usage: sudo upgrade-staging.sh --source CHECKOUT --release ID --backup-dir ABSOLUTE_DIRECTORY --confirm-staging'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ $EUID -eq 0 && $CONFIRM == true ]] || die 'must run as root with --confirm-staging'
[[ -d $SOURCE && -f $SOURCE/package-lock.json ]] || die 'invalid --source'
[[ $RELEASE =~ ^[A-Za-z0-9._-]{7,80}$ && ! -e $APP_ROOT/releases/$RELEASE ]] || die 'invalid or existing --release'
[[ $BACKUP_DIR =~ ^/[A-Za-z0-9._/-]+$ ]] || die '--backup-dir must be an absolute path containing only letters, digits, dot, slash, underscore, or hyphen'
for command in tar npm sqlite3 systemctl curl; do command -v "$command" >/dev/null || die "missing required command: $command"; done
require_supported_node
previous=$(readlink -f "$APP_ROOT/current")
[[ -d $previous ]] || die 'current release is not a directory'
install -d -m 0700 "$BACKUP_DIR"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
sqlite3 "$DATA_ROOT/coordinator.sqlite" ".backup '$BACKUP_DIR/coordinator-$timestamp.sqlite'"
target="$APP_ROOT/releases/$RELEASE"
install -d -o root -g root -m 0755 "$target"
(cd "$SOURCE" && tar --exclude=.git --exclude=node_modules --exclude=target --exclude=dist \
  --exclude=.env --exclude='.env.*' --exclude='*.pem' --exclude='*.key' \
  --exclude='*.sqlite' --exclude='*.sqlite-shm' --exclude='*.sqlite-wal' -cf - .) | tar -C "$target" -xf -
(cd "$target" && npm ci --omit=dev --ignore-scripts)
ln -s "releases/$RELEASE" "$APP_ROOT/current.new"
mv -T "$APP_ROOT/current.new" "$APP_ROOT/current"
if ! systemctl restart wii-ultra-desk-coordinator.service || ! timeout 15 bash -c 'until curl --fail --silent http://127.0.0.1:4310/healthz >/dev/null; do sleep 1; done'; then
  ln -s "$previous" "$APP_ROOT/current.rollback"
  mv -T "$APP_ROOT/current.rollback" "$APP_ROOT/current"
  systemctl restart wii-ultra-desk-coordinator.service || true
  die "coordinator did not recover; current was restored to $previous"
fi
echo "Upgrade succeeded. Database backup: $BACKUP_DIR/coordinator-$timestamp.sqlite"
