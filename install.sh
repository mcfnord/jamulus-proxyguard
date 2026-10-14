#!/bin/bash
# sudo ./install.sh [--port N ...] [--dry]     install as a systemd service (ports auto-detected from the running server)
# sudo ./install.sh --uninstall
set -euo pipefail
BIN=/usr/local/sbin/jamulus-proxyguard; UNIT=/etc/systemd/system/jamulus-proxyguard.service
PORTS=(); ENFORCE=--enforce
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
while [ $# -gt 0 ]; do case "$1" in
  --port) PORTS+=("$2"); shift 2 ;;
  --dry) ENFORCE=; shift ;;
  --uninstall) systemctl disable --now jamulus-proxyguard 2>/dev/null || true; rm -f "$UNIT" "$BIN"; systemctl daemon-reload
               nft delete table inet jamulus_proxyguard 2>/dev/null || true; echo "removed (config in /etc/jamulus-proxyguard and cache in /var/lib/jamulus-proxyguard kept)"; exit 0 ;;
  *) sed -n '2,3p' "$0"; exit 1 ;;
esac; done
command -v nft >/dev/null || { apt-get install -y nftables 2>/dev/null || dnf install -y nftables || yum install -y nftables; }
command -v python3 >/dev/null || { apt-get install -y python3 2>/dev/null || dnf install -y python3 || yum install -y python3; }
if [ ${#PORTS[@]} = 0 ]; then
  mapfile -t PORTS < <(ss -Hulnp | grep -i jamulus | awk '{print $4}' | sed 's/.*://' | sort -un)
  [ ${#PORTS[@]} -gt 0 ] || { echo "no running Jamulus server found; pass --port <udp port>"; exit 1; }
  echo "detected Jamulus UDP port(s): ${PORTS[*]}"
fi
PORTARGS=; for p in "${PORTS[@]}"; do PORTARGS+=" --port $p"; done
install -m 0755 "$(dirname "$0")/jamulus-proxyguard.py" "$BIN"
install -d -m 0755 /etc/jamulus-proxyguard
[ -f /etc/jamulus-proxyguard/allow.txt ] || echo '# addresses or CIDRs never blocked, one per line' > /etc/jamulus-proxyguard/allow.txt
cat > "$UNIT" <<EOF
[Unit]
Description=jamulus-proxyguard: drop VPN/proxy exits on the Jamulus port(s)
After=network.target

[Service]
ExecStart=/usr/bin/env python3 $BIN run$PORTARGS $ENFORCE
ExecStopPost=-$(command -v nft) delete table inet jamulus_proxyguard
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable --now jamulus-proxyguard >/dev/null 2>&1; systemctl restart jamulus-proxyguard; sleep 2
systemctl is-active --quiet jamulus-proxyguard || { journalctl -u jamulus-proxyguard -n 20 --no-pager; exit 1; }
journalctl -u jamulus-proxyguard -n 3 --no-pager -o cat | grep START
echo "installed. Watch: journalctl -fu jamulus-proxyguard   Allow a player: /etc/jamulus-proxyguard/allow.txt then systemctl restart jamulus-proxyguard"
