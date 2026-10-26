#!/usr/bin/env bash
# Remove WireGuard Dashboard. Your wg0.conf and client peers are NOT deleted.
set -euo pipefail
CONFIG_DIR="${WGDASH_CONFIG_DIR:-/etc/wireguard-dashboard}"
DATA_DIR="${WGDASH_DATA_DIR:-/var/lib/wireguard-dashboard}"
INSTALL_DIR="${WGDASH_INSTALL_DIR:-/opt/wireguard-dashboard}"
[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
echo "This stops/removes the dashboard service, /usr/local/bin/wgdash, $INSTALL_DIR,"
echo "the Caddy snippet and the systemd unit. WireGuard and wg0.conf are untouched."
read -r -p "Continue? [y/N]: " ans
[[ "$ans" =~ ^[Yy] ]] || { echo "Cancelled"; exit 0; }
systemctl stop wireguard-dashboard.service 2>/dev/null || true
systemctl disable wireguard-dashboard.service 2>/dev/null || true
rm -f /etc/systemd/system/wireguard-dashboard.service /usr/local/bin/wgdash \
      /etc/caddy/conf.d/wireguard-dashboard.caddy
systemctl daemon-reload
if [[ -f /etc/caddy/Caddyfile ]]; then
  sed -i '/wireguard-dashboard/d' /etc/caddy/Caddyfile
  systemctl reload caddy 2>/dev/null || true
fi
rm -rf "$INSTALL_DIR"
read -r -p "Also delete config, database, encryption key and backups ($CONFIG_DIR $DATA_DIR)? [y/N]: " ans2
if [[ "$ans2" =~ ^[Yy] ]]; then rm -rf "$CONFIG_DIR" "$DATA_DIR"; else echo "Kept $CONFIG_DIR and $DATA_DIR"; fi
echo "Done. WireGuard is still running with its current peers."
