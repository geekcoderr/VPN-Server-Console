# GeekSTunnel: Professional Migration & Persistence Guide (v3.2.1)

This guide ensures a **state-preserved migration** from your old server to a new one, including Dockerized components and reboot persistence.

---

## 1. Preparation (Old Server)
Before shutting down the old server, capture your data:

```bash
# 1. Export Database State
docker exec vpn-mysql mysqldump -u vpn_user -p vpn_control > /tmp/vpn_state.sql

# 2. Backup Certificates (Same Domain)
sudo tar -cvzf certs_backup.tar.gz /etc/letsencrypt/live/vpn.nishantmaheshwari.online /etc/letsencrypt/archive/vpn.nishantmaheshwari.online

# 3. Secure Secrets
# Capture your SESSION_SECRET_KEY from app/config.py or .env
```

## 2. Infrastructure Setup (New Server)
Installs Docker, WireGuard, and persistent IP forwarding.

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git wireguard iptables-persistent docker.io docker-compose

# Enable IP Forwarding (Persistence)
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## 3. Data & SSL Restoration
Restores certificates and prepares Docker volumes.

```bash
# Clone the repository
git clone https://github.com/geekcoderr/VPN-Server-Console.git /opt/vpn-control
cd /opt/vpn-control

# Restore SSL Certificates to EXACT same path
sudo tar -xvzf certs_backup.tar.gz -C /
```

## 4. Docker Deployment (DB & Nginx)
1.  **Database**: Start the DB first and restore data.
    ```bash
    docker-compose -f docker-compose.db.yml up -d
    sleep 10
    docker exec -i vpn-mysql mysql -u vpn_user -p vpn_control < /tmp/vpn_state.sql
    ```
2.  **Nginx**: Start the "Fluid" proxy.
    ```bash
    docker-compose up -d nginx
    ```

## 5. Backend Deployment (Host-Secured)
1.  **Domain & Secrets Sync**: 
    - Ensure `app/config.py` has the SAME `SESSION_SECRET_KEY` and `DOMAIN`.
2.  **Run Setup**:
    ```bash
    sudo ./setup.sh
    ```

## 6. Reboot Persistence Hardening
To ensure everything survives a server crash or reboot:

```bash
# 1. Enable Services
sudo systemctl enable docker vpn-control wg-quick@wg0

# 2. Verify MASQUERADE (NAT) Rules
# Ensure /etc/wireguard/wg0.conf [Interface] has:
# PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
# PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
# (Replace eth0 with your public interface name if different)

# 3. Save IPTables for good measure
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

## 8. Firewall (UFW)
```bash
sudo ufw allow 22,80,443/tcp
sudo ufw allow 51820/udp
sudo ufw enable
```

## 9. Performance Optimization
Apply the kernel speed tweaks:
```bash
sudo ./optimize_speed.sh
```

## 10. Final Verification
- Run `sudo wg show` to confirm the interface is up.
- Run `docker ps` to see Nginx and MySQL healthy.
- Run `journalctl -u vpn-control -f` to watch the backend logs.

---
**Your server is now a mirror image of the original, hardened for reboots!** 🛡️🏁
