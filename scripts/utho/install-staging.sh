#!/usr/bin/env bash
# Installs only WII Ultra Desk-owned paths. It never enables/restarts Nginx,
# coturn, or the coordinator; review and start them explicitly after validation.
set -euo pipefail

APP_ROOT=/opt/wii-ultra-desk
ETC_ROOT=/etc/wii-ultra-desk
DATA_ROOT=/var/lib/wii-ultra-desk
SOURCE=
RELEASE=
COORDINATOR_FQDN=
INSTALL_NGINX=false
CONFIRM=false

die() { printf '%s\n' "install-staging: $*" >&2; exit 1; }
require_supported_node() {
  local version major minor patch
  version=$(node -p 'process.versions.node')
  [[ $version =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || die "could not parse Node version: $version"
  major=${BASH_REMATCH[1]}
  minor=${BASH_REMATCH[2]}
  patch=${BASH_REMATCH[3]}
  (( major > 22 || (major == 22 && (minor > 12 || (minor == 12 && patch >= 0))) )) || die "Node $version is unsupported; require >=22.12.0"
}
usage() { cat >&2 <<'EOF'
Usage: sudo scripts/utho/install-staging.sh --source /path/to/checkout --release RELEASE_ID --confirm-staging [--install-nginx --coordinator-fqdn name]
Creates WII-owned accounts, release directory, units and protected runtime paths.
It does not install OS packages, edit firewall/DNS, enable/restart services, or overwrite differing managed files.
EOF
}

while (($#)); do
  case "$1" in
    --source) SOURCE=${2:-}; shift 2 ;;
    --release) RELEASE=${2:-}; shift 2 ;;
    --install-nginx) INSTALL_NGINX=true; shift ;;
    --coordinator-fqdn) COORDINATOR_FQDN=${2:-}; shift 2 ;;
    --confirm-staging) CONFIRM=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die 'must run as root'
[[ $CONFIRM == true ]] || die 'refusing without --confirm-staging'
[[ -n $SOURCE && -d $SOURCE && -f $SOURCE/package.json && -f $SOURCE/package-lock.json ]] || die '--source must be a checkout containing package.json and package-lock.json'
[[ $RELEASE =~ ^[A-Za-z0-9._-]{7,80}$ ]] || die '--release must be a safe 7-80 character release identifier'
if [[ $INSTALL_NGINX == true ]]; then
  [[ $COORDINATOR_FQDN =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] || die '--coordinator-fqdn must be a DNS name'
fi
for command in install tar npm node systemctl getent; do command -v "$command" >/dev/null || die "missing required command: $command"; done
require_supported_node
[[ ! -e "$APP_ROOT/releases/$RELEASE" ]] || die "release already exists: $APP_ROOT/releases/$RELEASE"

install_managed() {
  local source=$1 destination=$2 mode=$3
  if [[ -e $destination ]] && ! cmp -s "$source" "$destination"; then
    die "managed file differs and will not be overwritten: $destination"
  fi
  install -D -m "$mode" "$source" "$destination"
}

ensure_system_account() {
  local name=$1 group=$2
  getent group "$group" >/dev/null || groupadd --system "$group"
  getent passwd "$name" >/dev/null || useradd --system --gid "$group" --home-dir /nonexistent --shell /usr/sbin/nologin "$name"
}

# Fail before adding service files if another program already owns the TURN ports.
if command -v ss >/dev/null; then
  for port in 3478 5349; do
    if ss -H -ltnu | awk -v p=":$port" '$5 ~ (p "$") { found=1 } END { exit !found }'; then
      die "a process is already listening on TURN port $port; inspect it before installation"
    fi
  done
fi

ensure_system_account wii-ultra wii-ultra
ensure_system_account wii-ultra-turn wii-ultra-turn
getent group wii-ultra-secrets >/dev/null || groupadd --system wii-ultra-secrets
usermod -a -G wii-ultra-secrets wii-ultra
usermod -a -G wii-ultra-secrets wii-ultra-turn

install -d -o root -g root -m 0755 "$APP_ROOT/releases"
install -d -o wii-ultra -g wii-ultra -m 0750 "$DATA_ROOT"
install -d -o root -g wii-ultra-secrets -m 0750 "$ETC_ROOT"
install -d -o root -g wii-ultra-secrets -m 0750 "$ETC_ROOT/tls"
if [[ ! -e $ETC_ROOT/staging.env ]]; then
  install -m 0640 -o root -g wii-ultra-secrets /dev/null "$ETC_ROOT/staging.env"
fi

target="$APP_ROOT/releases/$RELEASE"
install -d -o root -g root -m 0755 "$target"
(cd "$SOURCE" && tar --exclude=.git --exclude=node_modules --exclude=target --exclude=dist \
  --exclude=.env --exclude='.env.*' --exclude='*.pem' --exclude='*.key' \
  --exclude='*.sqlite' --exclude='*.sqlite-shm' --exclude='*.sqlite-wal' -cf - .) | tar -C "$target" -xf -
(cd "$target" && npm ci --omit=dev --ignore-scripts)

install_managed "$SOURCE/infra/utho/systemd/wii-ultra-desk-coordinator.service" /etc/systemd/system/wii-ultra-desk-coordinator.service 0644
install_managed "$SOURCE/infra/utho/systemd/wii-ultra-turn.service" /etc/systemd/system/wii-ultra-turn.service 0644

if [[ $INSTALL_NGINX == true ]]; then
  command -v nginx >/dev/null || die 'nginx is required for --install-nginx'
  nginx -T 2>/dev/null | grep -Fq "server_name $COORDINATOR_FQDN" && die "Nginx already declares server_name $COORDINATOR_FQDN"
  nginx -T 2>/dev/null | grep -Eq '(:|\.)4310\b' && die 'Nginx configuration already references coordinator port 4310; review manually'
  nginx_target=/etc/nginx/conf.d/wii-ultra-desk-coordinator.conf
  [[ ! -e $nginx_target ]] || die "will not overwrite existing Nginx snippet: $nginx_target"
  sed "s/__COORDINATOR_FQDN__/$COORDINATOR_FQDN/g" "$SOURCE/infra/utho/nginx/wii-ultra-desk-coordinator.conf.template" >"$nginx_target"
  chmod 0644 "$nginx_target"
  nginx -t || { rm -f "$nginx_target"; die 'generated Nginx snippet failed validation and was removed'; }
fi

ln -s "releases/$RELEASE" "$APP_ROOT/current.new"
mv -T "$APP_ROOT/current.new" "$APP_ROOT/current"
systemctl daemon-reload
printf '%s\n' "Installed release $RELEASE without starting services. Fill $ETC_ROOT/staging.env, provision TLS copies, generate coturn config, then run scripts/utho/validate-staging.sh."
