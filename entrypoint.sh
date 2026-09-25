#!/bin/sh
set -eu
PORT="${PORT:-8080}"
export DASHBOARD_PORT=8081
export TROJAN_PASSWORD="${TROJAN_PASSWORD:-Ghanizada}"
export WS_PATH="${WS_PATH:-/ws/Ghanizada}"
export VLESS_WS_PATH="${VLESS_WS_PATH:-/ws/VLESS-Ghanizada}"
export VMESS_WS_PATH="${VMESS_WS_PATH:-/ws/VMess-Ghanizada}"
export SNI="${SNI:-firebase-settings.crashlytics.com}"
export OWNER_KEY="${OWNER_KEY:-Ghanizada}"
export USERS_FILE="${USERS_FILE:-/tmp/ghanizada-users.json}"
export XRAY_CONFIG="${XRAY_CONFIG:-/tmp/xray-managed.json}"

mkdir -p /tmp
cp /etc/xray/config.json "$XRAY_CONFIG"

start_xray() {
  /usr/bin/xray run -c "$XRAY_CONFIG" >/tmp/xray.log 2>&1 &
  echo $! >/tmp/xray.pid
}

start_xray
python3 /app/server.py >/tmp/dashboard.log 2>&1 &

# Restart Xray when the dashboard changes its users/configuration.
(
  while true; do
    if [ -f /tmp/xray-reload ]; then
      rm -f /tmp/xray-reload
      if [ -f /tmp/xray.pid ]; then kill "$(cat /tmp/xray.pid)" 2>/dev/null || true; fi
      sleep 0.4
      start_xray
    fi
    sleep 0.5
  done
) &

touch /tmp/caddy-ready
exec /usr/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
