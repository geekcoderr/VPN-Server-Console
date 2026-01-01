#!/bin/bash
# VPN Control Plane - Complete Server Setup Script
# Run as root on your VPN server

set -e

echo "=========================================="
echo "VPN Control Plane - Server Setup"
echo "=========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./setup.sh)"
    exit 1
fi

# Variables
DOMAIN="vpn.nishantmaheshwari.online"
APP_DIR="/opt/vpn-control"
NGINX_CONF="/etc/nginx/sites-available/vpn-control"

echo ""
echo "[1/6] Installing dependencies..."
apt install -y python3 python3-venv python3-pip nginx certbot python3-certbot-nginx

# Enable IP Forwarding permanently
echo "Enabling IPv4 Forwarding..."
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | tee -a /etc/sysctl.conf || true

echo ""
echo "[2/6] Setting up application..."
mkdir -p $APP_DIR
cp -r ./* $APP_DIR/ 2>/dev/null || true
cd $APP_DIR

# Create virtual environment
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

# Set permissions
chown -R root:root $APP_DIR
chmod 600 $APP_DIR/app/config.py

echo ""
echo "[3/6] Installing systemd service..."
cp $APP_DIR/systemd/vpn-control.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable vpn-control

echo ""
echo "[4/6] Configuring Nginx..."
cp $APP_DIR/nginx/vpn-control.conf $NGINX_CONF

# Create symlink to enable site
ln -sf $NGINX_CONF /etc/nginx/sites-enabled/vpn-control

# Remove default site if exists
rm -f /etc/nginx/sites-enabled/default

# Test nginx config (will fail until SSL cert exists)
echo "Note: Nginx config test may fail until SSL certificate is obtained"

echo ""
echo "[5/6] Obtaining SSL certificate..."
# Stop nginx temporarily for standalone cert
systemctl stop nginx || true

# Get certificate
certbot certonly --standalone -d $DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN || {
    echo "Certbot failed. Make sure:"
    echo "  1. DNS is pointing to this server"
    echo "  2. Port 80 is open"
    echo "  3. Run: certbot certonly --standalone -d $DOMAIN"
}

# Test and start nginx
nginx -t && systemctl start nginx

echo ""
echo "[6/6] Starting VPN Control service..."
systemctl start vpn-control
systemctl status vpn-control --no-pager

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Access your dashboard at:"
echo "  https://$DOMAIN"
echo ""
echo "Default credentials:"
echo "  Username: geek"
echo "  Password: ChangeMeNow123!"
echo ""
echo "IMPORTANT: Change the password after first login!"
echo ""
echo "Commands:"
echo "  sudo systemctl status vpn-control  # Check app status"
echo "  sudo systemctl restart vpn-control # Restart app"
echo "  sudo journalctl -u vpn-control -f  # View logs"
echo ""
