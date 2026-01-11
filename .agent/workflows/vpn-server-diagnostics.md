---
description: Standard VPN server diagnostic commands to provide after any code change
---

# VPN Server Diagnostics Workflow

After pushing ANY code changes related to the VPN Control Plane, I MUST provide the user with these commands to run on their **production server** (accessed via `ssh geeksConsoleVPN`).

## Standard Post-Deployment Commands
// turbo-all
```bash
# 1. Pull latest changes
cd /opt/vpn-control
sudo git pull origin main

# 2. Restart the backend service
sudo systemctl restart vpn-control

# 3. Restart CoreDNS container (if DNS changes were made)
sudo docker compose up -d --force-recreate coredns

# 4. Verify vpn-control service is running
sudo systemctl status vpn-control --no-pager

# 5. Check backend logs for errors
sudo journalctl -u vpn-control -n 50 --no-pager
```

## DNS Blocking Specific Diagnostics
```bash
# Check if blocked.conf is populated
sudo cat /opt/vpn-control/coredns/blocked.conf

# Check CoreDNS logs
sudo docker logs vpn-dns --tail 30

# Check Redis blacklist content
sudo docker exec vpn-redis redis-cli SMEMBERS blacklist

# Check iptables DNS hijacking rules
sudo iptables -t nat -L PREROUTING -n -v | grep 53
```

## Important Rules for Agent
1. **NEVER assume the user can run commands locally** - All diagnostics run on the remote server.
2. **ALWAYS provide commands after pushing changes** - Don't just say "it should work now."
3. **ALWAYS ask for output** - Don't proceed without seeing actual server output.
4. **NEVER make more than 2 iterative fixes** - If something doesn't work after 2 tries, STOP and rescope.
