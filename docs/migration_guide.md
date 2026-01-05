# GeekSTunnel: Global Migration & Re-deployment Master Guide (v3.2.1)

This guide provides the exact sequence to replicate your **GeekSTunnel** environment on a fresh server from scratch.

---

### Step 1: DNS & Preparation
1.  **Point DNS**: Point your domain (e.g., `wg.yourdomain.com`) to the **New IP** of your fresh server.
2.  **Wait**: Ensure DNS propagation is active (check via `ping wg.yourdomain.com`).

### Step 2: System Pre-requisites
SSH into the fresh server and install the core stack:
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git wireguard curl ufw nginx certbot python3-certbot-nginx
```

### Step 3: Database Engine (MariaDB)
Your application requires a MySQL-compatible database.
```bash
sudo apt install -y mariadb-server
sudo mysql_secure_installation

# Create the Database & User
sudo mysql -e "CREATE DATABASE vpn_control;"
sudo mysql -e "CREATE USER 'vpn_user'@'localhost' IDENTIFIED BY 'vpn_pass';"
sudo mysql -e "GRANT ALL PRIVILEGES ON vpn_control.* TO 'vpn_user'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"
```

### Step 4: Clone & App Setup
```bash
sudo mkdir -p /opt/vpn-control
sudo chown $USER:$USER /opt/vpn-control
git clone https://github.com/geekcoderr/VPN-Server-Console.git /opt/vpn-control
cd /opt/vpn-control

# Update the Domain in setup.sh
# Change line 18: DOMAIN="wg.yourdomain.com"
nano setup.sh

sudo chmod +x setup.sh
sudo ./setup.sh
```

### Step 5: Configuration Sync
**CRITICAL**: You must update the Domain in `app/config.py` so client configs are generated correctly.
```bash
# Change line 24: VPN_SERVER_ENDPOINT = "wg.yourdomain.com:51820"
nano app/config.py
```

### Step 6: Security (Firewall)
Apply the "Fluid Shield" rules:
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 80,443/tcp  # Web Dashboard
sudo ufw allow 51820/udp   # WireGuard Tunnel
sudo ufw enable
```

### Step 7: Speed Tuning (Fluid Engine)
```bash
sudo chmod +x optimize_speed.sh
sudo ./optimize_speed.sh
```

### Step 8: Data Migration (Optional)
If you want to move your **existing users** from the old server:
1.  **Old Server**: `mysqldump -u vpn_user -p vpn_control > dump.sql`
2.  **Transfer**: `scp dump.sql root@NEW_IP:/tmp/`
3.  **New Server**: `mysql -u vpn_user -p vpn_control < /tmp/dump.sql`

### Step 9: Verify Heartbeat
```bash
sudo systemctl restart vpn-control
sudo systemctl status vpn-control
sudo wg show
```

### Step 10: Final Test
Visit your domain in a browser. Log in and create a test node. Verify that you can download the config and connect! 🛡️🏁
