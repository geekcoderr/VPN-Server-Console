#!/bin/bash
set -e

echo "🔧 Fixing Network Settings..."

# 1. Enable IP Forwarding
echo "[1/3] Enabling IPv4 Forwarding..."
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard.conf

# 2. Restart CoreDNS (Fixes DNS/Internet)
echo "[2/3] Restarting CoreDNS..."
docker restart vpn-dns || echo "⚠️  CoreDNS container not found (vpn-dns)"

# 3. Flush and Re-init Firewall (Safe)
echo "[3/3] Re-initializing Firewall..."
# We rely on the app to do this on restart, so we will restart the app
systemctl restart vpn-control

echo "✅ Network Fixes Applied. Try connecting now."
