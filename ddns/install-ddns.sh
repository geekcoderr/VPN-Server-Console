#!/bin/bash
# Cloudflare DDNS Installer
# Deploys the DDNS updater script and systemd units.

set -e

DDNS_DIR="/opt/vpn-control/ddns"
ENV_FILE="/etc/cf-ddns.env"

echo "==========================================="
echo "Cloudflare Dynamic DNS - Installer"
echo "==========================================="

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./install-ddns.sh)"
    exit 1
fi

# Install dependencies
echo "[1/5] Installing dependencies..."
apt install -y curl jq

# Create environment file template
echo "[2/5] Creating environment file..."
if [ ! -f "$ENV_FILE" ]; then
    cat > "$ENV_FILE" << 'EOF'
# Cloudflare API Token (DNS Edit + Zone Read permissions)
CF_API_TOKEN=YOUR_CLOUDFLARE_API_TOKEN_HERE

# Your root domain in Cloudflare
ZONE_NAME=nishantmaheshwari.online

# Subdomains to update (space-separated)
RECORDS="wg vpn"
EOF
    chmod 600 "$ENV_FILE"
    echo "   Created: $ENV_FILE"
    echo "   ⚠️  IMPORTANT: Edit this file with your Cloudflare API Token!"
else
    echo "   Environment file already exists."
fi

# Make script executable
echo "[3/5] Setting permissions..."
chmod +x "$DDNS_DIR/cf-ddns.sh"

# Install systemd units
echo "[4/5] Installing systemd units..."
cp "$DDNS_DIR/cf-ddns.service" /etc/systemd/system/
cp "$DDNS_DIR/cf-ddns.timer" /etc/systemd/system/
systemctl daemon-reload

# Enable and start
echo "[5/5] Enabling timer..."
systemctl enable cf-ddns.service
systemctl enable --now cf-ddns.timer

echo ""
echo "==========================================="
echo "Installation Complete!"
echo "==========================================="
echo ""
echo "Next Steps:"
echo "  1. Edit /etc/cf-ddns.env with your Cloudflare API Token"
echo "  2. Test manually: sudo systemctl start cf-ddns.service"
echo "  3. Check logs: cat /var/log/cf-ddns.log"
echo ""
echo "The timer will run every 5 minutes and at boot."
echo ""
