#!/bin/bash
# VPN Speed Optimization Script (BBR + Kernel Tuning)
# Run as root: sudo ./optimize_speed.sh

set -e

echo "🚀 Starting Speed Optimization..."

# 1. Enable TCP BBR Congestion Control
echo "[+] Enabling TCP BBR..."
if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
fi
if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
fi

# 2. Tune Network Buffers (Critical for High-Speed UDP/WireGuard)
echo "[+] Tuning Kernel Network Buffers..."
cat <<EOF > /etc/sysctl.d/99-vpn-speed.conf
# Increase buffer sizes for high-performance UDP/TCP
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_window_scaling = 1
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
EOF

# Apply sysctl changes
sysctl -p /etc/sysctl.conf
sysctl -p /etc/sysctl.d/99-vpn-speed.conf

# 3. Increase Interface Queue Length (Reduce Packet Drops)
echo "[+] Increasing Interface Queue Length (txqueuelen)..."
WG_IFACE="wg0"
MAIN_IFACE=$(ip route get 8.8.8.8 | awk -- '{print $5}')

ip link set dev $WG_IFACE txqueuelen 2000 || true
ip link set dev $MAIN_IFACE txqueuelen 2000 || true

echo "✅ Optimization Complete!"
echo "   - BBR Enabled: $(sysctl net.ipv4.tcp_congestion_control)"
echo "   - Buffers Increased: 16MB"
echo "   - Queue Length: 2000"
echo ""
echo "⚠️  NOTE: Please generate NEW client configs (or update MTU manually to 1420) to fully benefit."
