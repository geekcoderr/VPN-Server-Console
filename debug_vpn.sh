#!/bin/bash
# Deep Debug Script for VPN Connectivity
# Run as root: sudo ./debug_vpn.sh

echo "--- 🔍 VPN NETWORK DIAGNOSTIC ---"

echo "1. IP Forwarding Status:"
cat /proc/sys/net/ipv4/ip_forward

echo -e "\n2. WAN Interface Detection:"
ip route get 8.8.8.8 | grep -oP 'dev \K\S+'

echo -e "\n3. WireGuard Status:"
sudo wg show

echo -e "\n4. IPTables NAT Table (Check for MASQUERADE):"
sudo iptables -t nat -L -n -v | grep -A 5 "POSTROUTING"

echo -e "\n5. IPTables FORWARD Chain (Check for wg0):"
sudo iptables -L FORWARD -n -v | grep -A 10 "Chain FORWARD"

echo -e "\n6. Check for Docker & UFW Conflicts:"
sudo ufw status || echo "UFW not installed"
sudo iptables -L DOCKER-USER -n -v 2>/dev/null || echo "No DOCKER-USER chain"
sudo iptables -L INPUT -n -v | grep 51820 || echo "No explicit 51820 hole in INPUT chain"

echo -e "\n7. Socket Status (Check if listening):"
sudo ss -lu | grep 51820 || echo "Not listening on 51820!"

echo -e "\n8. Route Table:"
ip route show

echo -e "\n--- END OF DIAGNOSTICS ---"
