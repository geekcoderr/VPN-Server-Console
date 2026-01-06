#!/bin/bash
# WireGuard Fresh Initialization Script
# Run this when migrating to a new server without the original wg0.conf

set -e

WG_DIR="/etc/wireguard"
WG_CONF="$WG_DIR/wg0.conf"
WG_INTERFACE="wg0"

# Server Network Config
SERVER_IP="10.50.0.1/24"
LISTEN_PORT="51820"

echo "==========================================="
echo "WireGuard Fresh Initialization"
echo "==========================================="

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./init-wireguard.sh)"
    exit 1
fi

# Check if config already exists
if [ -f "$WG_CONF" ]; then
    echo "⚠️  $WG_CONF already exists!"
    read -p "Overwrite? (y/N): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        exit 0
    fi
fi

# Create directory
mkdir -p "$WG_DIR"
chmod 700 "$WG_DIR"

# Generate server keys
echo "[1/4] Generating server keypair..."
SERVER_PRIVATE_KEY=$(wg genkey)
SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)

echo "   Private Key: [HIDDEN]"
echo "   Public Key:  $SERVER_PUBLIC_KEY"

# Detect primary network interface
MAIN_IFACE=$(ip route get 8.8.8.8 | awk -- '{print $5}')
echo "[2/4] Detected network interface: $MAIN_IFACE"

# Create wg0.conf
echo "[3/4] Creating $WG_CONF..."
cat > "$WG_CONF" << EOF
# GeekSTunnel WireGuard Server Configuration
# Generated: $(date)

[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = $SERVER_IP
ListenPort = $LISTEN_PORT
SaveConfig = false

# NAT Masquerade (Replace $MAIN_IFACE if needed)
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $MAIN_IFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $MAIN_IFACE -j MASQUERADE

# Peers will be added dynamically by the dashboard
EOF

chmod 600 "$WG_CONF"

# Enable and start WireGuard
echo "[4/4] Starting WireGuard..."
systemctl enable wg-quick@$WG_INTERFACE
systemctl restart wg-quick@$WG_INTERFACE

echo ""
echo "==========================================="
echo "WireGuard Initialized Successfully!"
echo "==========================================="
echo ""
echo "Server Public Key: $SERVER_PUBLIC_KEY"
echo "Listening Port:    $LISTEN_PORT"
echo "VPN Subnet:        10.50.0.0/24"
echo ""
echo "⚠️  IMPORTANT: All old client configs are now INVALID."
echo "    Delete all users from the database and re-provision them."
echo ""
echo "To delete all users from database, run:"
echo "  docker exec -i vpn-mysql mysql -u vpn_user -pvpn_pass vpn_control -e 'DELETE FROM users;'"
echo ""
