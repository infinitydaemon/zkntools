#!/bin/bash

set -e

# Define paths
RULES_SCRIPT="/etc/wireguard/iptables-wg.sh"
SERVICE_FILE="/etc/systemd/system/wg-iptables.service"

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root."
  exit 1
fi

# Create the iptables rule script
cat > "$RULES_SCRIPT" <<EOF
#!/bin/bash
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
EOF

chmod +x "$RULES_SCRIPT"

# Create the systemd service
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=WireGuard iptables rules
After=network.target

[Service]
Type=oneshot
ExecStart=$RULES_SCRIPT
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd, enable and start the service
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable wg-iptables
systemctl start wg-iptables

echo "✅ WireGuard iptables rules have been installed and enabled to run at boot."
