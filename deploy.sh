#!/bin/bash
# GeekSTunnel - Unified Deployment & Self-Healing Script
# Usage: sudo ./deploy.sh

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}   GeekSTunnel - Unified Deployment v4.0  ${NC}"
echo -e "${GREEN}==========================================${NC}"

# 1. Root Check
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./deploy.sh)${NC}"
    exit 1
fi

APP_DIR="/opt/vpn-control"
DOMAIN="vpn.nishantmaheshwari.online"

echo ""
echo -e "${YELLOW}[1/7] Updating System & Installing Dependencies...${NC}"
apt update -y
apt install -y python3 python3-venv python3-pip nginx certbot python3-certbot-nginx fail2ban wireguard docker.io docker-compose

# 2. Network Hardening (Self-Healing)
echo ""
echo -e "${YELLOW}[2/7] Applying Network Hardening...${NC}"
echo "Enabling IPv4 Forwarding..."
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-geekstunnel.conf

# 3. Application Setup
echo ""
echo -e "${YELLOW}[3/7] Setting up Application Code...${NC}"
mkdir -p $APP_DIR
# Copy files if we are in the source directory
if [ -f "requirements.txt" ]; then
    cp -r ./* $APP_DIR/
fi
cd $APP_DIR

# 4. Python Environment
echo ""
echo -e "${YELLOW}[4/7] Building Python Environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

# 5. Service Architecture (Docker & CoreDNS)
echo ""
echo -e "${YELLOW}[5/7] Launching Service Architecture...${NC}"
# Ensure Docker is running
systemctl start docker
systemctl enable docker

# Start Containers (Redis, MySQL, CoreDNS)
docker-compose up -d

# Wait for CoreDNS to be healthy
echo "Waiting for CoreDNS..."
sleep 5
if docker ps | grep -q "vpn-dns"; then
    echo -e "${GREEN}✅ CoreDNS is running.${NC}"
else
    echo -e "${RED}⚠️  CoreDNS failed to start. Attempting fix...${NC}"
    docker restart vpn-dns
fi

# 6. Systemd Service
echo ""
echo -e "${YELLOW}[6/7] Installing Systemd Service...${NC}"
cp systemd/vpn-control.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable vpn-control
systemctl restart vpn-control

# 7. Nginx & SSL
echo ""
echo -e "${YELLOW}[7/7] Configuring Web Server & SSL...${NC}"
if [ -d "/etc/letsencrypt/live/$DOMAIN" ]; then
    echo -e "${GREEN}✅ SSL Certificates found.${NC}"
else
    echo "Obtaining SSL Certificate..."
    certbot certonly --standalone -d $DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN
fi

# Link Nginx Config
cp nginx/vpn-control.conf /etc/nginx/sites-available/vpn-control
ln -sf /etc/nginx/sites-available/vpn-control /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
systemctl restart nginx

echo ""
echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}   DEPLOYMENT COMPLETE! 🚀                ${NC}"
echo -e "${GREEN}==========================================${NC}"
echo -e "Dashboard: https://$DOMAIN"
echo -e "Admin:     geek / ChangeMeNow123!"
echo ""
