#!/usr/bin/env bash
# WireGuard Dashboard installer — interactive by default, fully scriptable.
# Usage: sudo bash install.sh [--unattended --admin-user admin --admin-pass '...' ...]
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${WGDASH_INSTALL_DIR:-/opt/wireguard-dashboard}"
CONFIG_DIR="${WGDASH_CONFIG_DIR:-/etc/wireguard-dashboard}"
DATA_DIR="${WGDASH_DATA_DIR:-/var/lib/wireguard-dashboard}"
CONFIG="$CONFIG_DIR/config.json"
WG_INTERFACE="${WGDASH_WG_INTERFACE:-wg0}"
WG_CONF="${WGDASH_WG_CONF:-/etc/wireguard/$WG_INTERFACE.conf}"
VENV="$INSTALL_DIR/venv"
WRAPPER=/usr/local/bin/wgdash
SERVICE=/etc/systemd/system/wireguard-dashboard.service

UNATTENDED=0
ADMIN_USER="${WGDASH_ADMIN_USER:-}"
ADMIN_PASS="${WGDASH_ADMIN_PASS:-}"
PORT="${WGDASH_PORT:-}"
BIND="${WGDASH_BIND:-}"
DOMAIN="${WGDASH_DOMAIN:-}"
EMAIL="${WGDASH_EMAIL:-}"
ENDPOINT="${WGDASH_ENDPOINT:-}"
TG_TOKEN="${WGDASH_TELEGRAM_TOKEN:-}"
TG_ADMIN="${WGDASH_TELEGRAM_ADMIN:-}"
NO_CADDY=0
NO_START=0
CREATE_WG=""

usage() {
  cat <<EOF
WireGuard Dashboard installer

  sudo bash install.sh                     # interactive (asks everything)
  sudo bash install.sh --unattended \\
      --admin-user admin --admin-pass 'a-very-long-password' \\
      --domain vpn.example.com --email admin@example.com \\
      --telegram-token '123:ABC' --telegram-admin 12345678

Options:
  --unattended          No prompts (missing values use safe defaults)
  --admin-user NAME     Dashboard admin username
  --admin-pass PASS     Dashboard admin password (>=10 chars)
  --port PORT           Web UI port (default 8080)
  --bind ADDR           127.0.0.1 (behind Caddy) or 0.0.0.0 (direct)
  --domain HOST         Public hostname; Caddy will get a Let's Encrypt cert
  --email EMAIL         Contact address for the TLS certificate
  --endpoint HOST:PORT  WireGuard endpoint used in client configs
  --telegram-token T    Bot token from @BotFather
  --telegram-admin ID   Your Telegram chat ID (repeat flag not needed; comma list)
  --wg-interface IFACE  WireGuard interface (default wg0)
  --no-caddy            Do not configure Caddy even if installed
  --no-start            Install files but do not start the service
  -h, --help            Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --unattended) UNATTENDED=1; shift;;
    --admin-user) ADMIN_USER="$2"; shift 2;;
    --admin-pass) ADMIN_PASS="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    --bind) BIND="$2"; shift 2;;
    --domain) DOMAIN="$2"; shift 2;;
    --email) EMAIL="$2"; shift 2;;
    --endpoint) ENDPOINT="$2"; shift 2;;
    --telegram-token) TG_TOKEN="$2"; shift 2;;
    --telegram-admin) TG_ADMIN="$2"; shift 2;;
    --wg-interface) WG_INTERFACE="$2"; WG_CONF="/etc/wireguard/$WG_INTERFACE.conf"; shift 2;;
    --no-caddy) NO_CADDY=1; shift;;
    --no-start) NO_START=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

log()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }

ask() {
  local var="$1" prompt="$2" default="${3:-}" val=""
  if [[ $UNATTENDED -eq 1 ]]; then
    eval "$var=\"\${$var:-$default}\""; return
  fi
  if [[ -n "$default" ]]; then read -r -p "$prompt [$default]: " val; else read -r -p "$prompt: " val; fi
  eval "$var=\"\${val:-$default}\""
}
ask_secret() {
  local var="$1" prompt="$2" val=""
  if [[ $UNATTENDED -eq 1 ]]; then return; fi
  while true; do
    read -rs -p "$prompt (min 10 chars, input hidden): " val; echo
    if [[ ${#val} -ge 10 ]]; then eval "$var=\"$val\""; break; fi
    warn "Too short, try again."
  done
}
yesno() {
  local prompt="$1" default="${2:-Y}" ans=""
  [[ $UNATTENDED -eq 1 ]] && { [[ "$default" =~ ^[Yy] ]] && return 0 || return 1; }
  read -r -p "$prompt [${default}/n]: " ans
  [[ -z "$ans" ]] && ans="$default"
  [[ "$ans" =~ ^[Yy] ]]
}

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash install.sh"
command -v python3 >/dev/null || die "Python 3 is required"
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
[[ "$PY_MAJOR" -ge 3 && "$PY_MINOR" -ge 9 ]] || die "Python 3.9+ is required (found $(python3 --version))"
command -v systemctl >/dev/null || die "systemd is required"

log "Checking dependencies"
MISSING=()
command -v wg >/dev/null || MISSING+=(wireguard-tools)
command -v curl >/dev/null || MISSING+=(curl)
python3 -c 'import venv' 2>/dev/null || MISSING+=(python3-venv)
if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo "Missing packages: ${MISSING[*]}"
  if command -v apt-get >/dev/null && yesno "Install them with apt-get?" Y; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${MISSING[@]}"
  else
    die "Install ${MISSING[*]} manually, then re-run."
  fi
fi
command -v wg >/dev/null || die "wireguard-tools (wg command) is required"

log "Gathering installation settings"
ask ADMIN_USER "Dashboard admin username" "admin"
while [[ -z "$ADMIN_PASS" || ${#ADMIN_PASS} -lt 10 ]]; do
  ask_secret ADMIN_PASS "Dashboard admin password"
  if [[ -z "$ADMIN_PASS" && $UNATTENDED -eq 1 ]]; then
    ADMIN_PASS="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)"
    echo "Generated admin password: $ADMIN_PASS"
  elif [[ -z "$ADMIN_PASS" ]]; then
    ADMIN_PASS="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)"
    echo "Generated admin password: $ADMIN_PASS"
  fi
done

PUBLIC_IP="$(curl -s --max-time 5 https://api.ipify.org || true)"
WG_PORT="$(awk -F' *= *' '/^ListenPort/{print $2; exit}' "$WG_CONF" 2>/dev/null || echo 51820)"
[[ -n "$WG_PORT" ]] || WG_PORT=51820
DEFAULT_ENDPOINT="${PUBLIC_IP:+${PUBLIC_IP}:${WG_PORT}}"
ask ENDPOINT "Public WireGuard endpoint (host:port)" "$DEFAULT_ENDPOINT"

if command -v caddy >/dev/null && [[ $NO_CADDY -eq 0 ]]; then
  echo "Caddy detected — recommended: HTTPS reverse proxy with automatic certificates."
  ask DOMAIN "Dashboard domain (empty = no Caddy config)" "${DOMAIN:-}"
  if [[ -n "$DOMAIN" ]]; then ask EMAIL "Certificate email" "${EMAIL:-admin@$DOMAIN}"; fi
fi
if [[ -n "$DOMAIN" ]]; then BIND="127.0.0.1"; else ask BIND "Web UI bind address" "${BIND:-0.0.0.0}"; fi
ask PORT "Web UI port" "${PORT:-8080}"
ask TG_TOKEN "Telegram bot token (empty = configure later in the UI)" "${TG_TOKEN:-}"
if [[ -n "$TG_TOKEN" ]]; then ask TG_ADMIN "Your Telegram chat ID (for admin access)" "${TG_ADMIN:-}"; fi

log "Preparing WireGuard configuration"
mkdir -p "$DATA_DIR" "$CONFIG_DIR" /etc/wireguard
if [[ -f "$WG_CONF" ]]; then
  cp -a "$WG_CONF" "$DATA_DIR/original-$(basename "$WG_CONF")-$(date +%Y%m%d-%H%M%S).bak"
  chmod 600 "$DATA_DIR"/original-*.bak 2>/dev/null || true
  echo "Existing $WG_CONF backed up to $DATA_DIR (peers will be imported, not deleted)."
else
  if [[ $UNATTENDED -eq 1 ]]; then CREATE_WG="${WGDASH_CREATE_WG:-Y}"; else
    yesno "No $WG_CONF found. Create a NEW WireGuard server config?" Y && CREATE_WG=Y || CREATE_WG=N
  fi
  if [[ "$CREATE_WG" == "Y" ]]; then
    EXT_IF="$(ip route 2>/dev/null | awk '/default/{print $5; exit}' || echo eth0)"
    [[ -n "$EXT_IF" ]] || EXT_IF=eth0
    WG_PORT_NEW="$WG_PORT"
    [[ "$WG_PORT_NEW" == "51820" ]] && WG_PORT_NEW=$((40000 + RANDOM % 20000))
    umask 077
    wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
    PRIV="$(cat /etc/wireguard/privatekey)"
    cat > "$WG_CONF" <<EOF
[Interface]
PrivateKey = $PRIV
Address = 10.8.0.1/24
ListenPort = $WG_PORT_NEW
SaveConfig = false
PostUp = iptables -A FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -t nat -A POSTROUTING -o $EXT_IF -j MASQUERADE; iptables -A FORWARD -o $WG_INTERFACE -j ACCEPT
PostDown = iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -t nat -D POSTROUTING -o $EXT_IF -j MASQUERADE; iptables -D FORWARD -o $WG_INTERFACE -j ACCEPT
EOF
    chmod 600 "$WG_CONF" /etc/wireguard/privatekey
    unset PRIV
    WG_PORT="$WG_PORT_NEW"
    ENDPOINT="${PUBLIC_IP:+${PUBLIC_IP}:${WG_PORT}}"
    if yesno "Enable IPv4/IPv6 forwarding in /etc/sysctl.d/99-wireguard.conf?" Y; then
      cat > /etc/sysctl.d/99-wireguard.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
      sysctl -p /etc/sysctl.d/99-wireguard.conf >/dev/null || true
    fi
    if yesno "Open UDP $WG_PORT in the firewall (ufw)?" Y && command -v ufw >/dev/null; then
      ufw allow "$WG_PORT"/udp >/dev/null || true
    fi
    if [[ $NO_START -eq 0 ]] && yesno "Start wg-quick@$WG_INTERFACE now?" Y; then
      systemctl enable --now "wg-quick@$WG_INTERFACE" || warn "Could not start WireGuard; check 'systemctl status wg-quick@$WG_INTERFACE'"
    fi
  else
    die "Cannot continue without $WG_CONF. Create your WireGuard server first."
  fi
fi

log "Installing application to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR" "$DATA_DIR/backups"
tar -C "$SRC" --exclude='./venv' --exclude='./demo-data' --exclude='./.git' \
    --exclude='./__pycache__' --exclude='./tests/__pycache__' -cf - . | tar -C "$INSTALL_DIR" -xf -
python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet -r "$INSTALL_DIR/requirements.txt"

log "Writing configuration"
PUBLIC_URL=""
[[ -n "$DOMAIN" ]] && PUBLIC_URL="https://$DOMAIN"
"$VENV/bin/python" - "$CONFIG" <<PY
import json, os, sys, secrets, time
path = sys.argv[1]
cfg = {
  "demo": False,
  "install_dir": "$INSTALL_DIR",
  "config_dir": "$CONFIG_DIR",
  "data_dir": "$DATA_DIR",
  "db_path": "$DATA_DIR/wgdash.db",
  "key_path": "$DATA_DIR/secret.key",
  "backup_dir": "$DATA_DIR/backups",
  "wg_interface": "$WG_INTERFACE",
  "wg_conf": "$WG_CONF",
  "wg_pubkey_file": "/etc/wireguard/publickey",
  "wg_privkey_file": "/etc/wireguard/privatekey",
  "public_endpoint": "$ENDPOINT",
  "listen_host": "$BIND",
  "listen_port": int("$PORT"),
  "public_url": "$PUBLIC_URL",
  "secret_key": secrets.token_urlsafe(48),
  "bootstrap_admin": None,
  "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
}
os.makedirs(os.path.dirname(path), exist_ok=True)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as fh:
    json.dump(cfg, fh, indent=2)
PY
chmod 700 "$CONFIG_DIR" "$DATA_DIR"
chmod 600 "$CONFIG"

PY="$VENV/bin/python"
log "Creating admin account and importing existing peers"
WGDASH() { "$PY" -m wgdash.cli --config "$CONFIG" "$@"; }
WGDASH init-admin --username "$ADMIN_USER" --password "$ADMIN_PASS" >/dev/null
WGDASH detect >/dev/null 2>&1 || true
if [[ -n "$ENDPOINT" ]]; then WGDASH set-setting endpoint "$ENDPOINT" >/dev/null; fi
if [[ -n "$TG_TOKEN" ]]; then
  WGDASH set-setting telegram_token "$TG_TOKEN" >/dev/null \
    || warn "Could not save the Telegram token — set it later in the dashboard."
  if [[ -n "$TG_ADMIN" ]]; then
    ADMINS_JSON="$("$VENV/bin/python" -c 'import json,sys; print(json.dumps([x for x in sys.argv[1].replace(",", " ").split() if x]))' "$TG_ADMIN")"
    WGDASH set-setting telegram_admins "$ADMINS_JSON" >/dev/null && echo "Telegram admins: $TG_ADMIN" \
      || warn "Could not save Telegram admin IDs — set them later in Settings → Telegram."
  fi
fi
# Import any [Peer] blocks already present in wg0.conf (idempotent).
WGDASH sync >/dev/null 2>&1 || true

cat > "$WRAPPER" <<EOF
#!/bin/sh
# WireGuard Dashboard CLI
exec "$VENV/bin/python" -m wgdash.cli --config "$CONFIG" "\$@"
EOF
chmod 755 "$WRAPPER"

sed -e "s|@@INSTALL_DIR@@|$INSTALL_DIR|g" \
    -e "s|@@CONFIG@@|$CONFIG|g" \
    -e "s|@@PYTHON@@|$PY|g" \
    -e "s|wg-quick@%i.service|wg-quick@$WG_INTERFACE.service|g" \
    "$INSTALL_DIR/systemd/wireguard-dashboard.service" > "$SERVICE"
chmod 644 "$SERVICE"

if [[ -n "$DOMAIN" ]] && command -v caddy >/dev/null && [[ $NO_CADDY -eq 0 ]]; then
  log "Configuring Caddy for https://$DOMAIN"
  mkdir -p /etc/caddy/conf.d /var/log/caddy
  sed -e "s|@@DOMAIN@@|$DOMAIN|g" -e "s|@@EMAIL@@|${EMAIL:-}|g" -e "s|@@PORT@@|$PORT|g" \
      "$INSTALL_DIR/caddy/wireguard-dashboard.caddy" > /etc/caddy/conf.d/wireguard-dashboard.caddy
  if [[ -f /etc/caddy/Caddyfile ]] && ! grep -q 'wireguard-dashboard' /etc/caddy/Caddyfile; then
    printf '\n# WireGuard Dashboard\nimport /etc/caddy/conf.d/wireguard-dashboard.caddy\n' >> /etc/caddy/Caddyfile
  elif [[ ! -f /etc/caddy/Caddyfile ]]; then
    printf 'import /etc/caddy/conf.d/*.caddy\n' > /etc/caddy/Caddyfile
  fi
  caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1 || warn "Caddy config validation failed — check /etc/caddy/Caddyfile"
  systemctl reload caddy 2>/dev/null || systemctl restart caddy 2>/dev/null || warn "Could not reload Caddy"
fi

if [[ "$BIND" == "0.0.0.0" ]] && command -v ufw >/dev/null && ufw status 2>/dev/null | grep -qw active; then
  if yesno "Allow TCP $PORT through ufw (dashboard is exposed directly)?" Y; then
    ufw allow "$PORT"/tcp >/dev/null || true
  fi
fi

log "Starting service"
systemctl daemon-reload
systemctl enable wireguard-dashboard.service >/dev/null 2>&1 || true
if [[ $NO_START -eq 0 ]]; then
  systemctl restart wireguard-dashboard.service
  sleep 2
  systemctl is-active --quiet wireguard-dashboard.service || {
    warn "Service failed to start. Recent logs:"; journalctl -u wireguard-dashboard.service -n 30 --no-pager || true;
  }
fi

echo
echo "════════════════════════════════════════════════════════════════"
echo "  WireGuard Dashboard installed"
echo "════════════════════════════════════════════════════════════════"
echo "  URL:        ${PUBLIC_URL:-http://$BIND:$PORT}"
echo "  Username:   $ADMIN_USER"
echo "  Password:   $ADMIN_PASS"
echo "  Config:     $CONFIG  (mode 0600)"
echo "  Database:   $DATA_DIR/wgdash.db"
echo "  CLI:        wgdash status | wgdash add phone | wgdash list"
echo "  Endpoint:   ${ENDPOINT:-auto-detected}"
echo "  Telegram:   ${TG_TOKEN:+configured}${TG_TOKEN:-configure in Settings → Telegram}"
echo "  Logs:       journalctl -u wireguard-dashboard -f"
echo "════════════════════════════════════════════════════════════════"
echo
echo "Next: open the URL, sign in, then open Peers → Add peer."
echo "Security: keep the panel on 127.0.0.1 behind Caddy/HTTPS, or restrict the port"
echo "to your own IP with ufw. Never expose the admin panel without TLS."
echo
