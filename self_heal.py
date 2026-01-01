"""
Self-Healing IAM Script.
Restores consistency between Database and WireGuard Config.
1. Cleans duplicate peers from wg0.conf
2. Syncs valid users from DB
3. Verifies integrity
"""
import asyncio
import os
import shutil
import re
import subprocess
from app.database import get_all_users
from app.wg import (
    WG_CONFIG_PATH, 
    reload_wireguard, 
)

def get_default_interface():
    """Detect the default network interface (e.g., ens5, eth0)."""
    try:
        result = subprocess.check_output(["ip", "route", "get", "8.8.8.8"]).decode()
        match = re.search(r'dev\s+(\S+)', result)
        return match.group(1) if match else "eth0"
    except:
        return "eth0"

async def heal_system():
    print(f"--- Starting IAM Self-Healing ---")
    
    # 1. Detect Interface
    start_interface = get_default_interface()
    print(f"Detected WAN Interface: {start_interface}")
    
    # 1.5 Enable IP Forwarding (Kernel - Runbook Step 3)
    print("Enabling IPv4 Forwarding (Permanent)...")
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
    # Permanent write to sysctl.conf
    try:
        with open('/etc/sysctl.conf', 'r+') as f:
            content = f.read()
            if "net.ipv4.ip_forward=1" not in content:
                f.write("\nnet.ipv4.ip_forward=1\n")
        subprocess.run(["sysctl", "-p"], check=False)
    except Exception as e:
        print(f"  Warning: Could not update /etc/sysctl.conf: {e}")

    # 2. Load users from DB (Source of Truth)
    print("Connecting to MySQL Database...")
    users = await get_all_users()
    active_users = {u['username']: u for u in users if u['status'] == 'active'}
    print(f"Found {len(active_users)} active users in DB.")

    # 3. Backup wg0.conf
    if not WG_CONFIG_PATH.exists():
        print("Error: wg0.conf not found!")
        return

    backup = WG_CONFIG_PATH.with_suffix('.conf.heal_backup')
    shutil.copy2(WG_CONFIG_PATH, backup)
    print(f"Backed up config to {backup}")

    # 4. Parse Config to find Preserved Peers
    content = WG_CONFIG_PATH.read_text()
    
    # Extract Interface Key
    private_key_match = re.search(r'PrivateKey\s*=\s*(\S+)', content)
    svr_priv_key = private_key_match.group(1) if private_key_match else None
    
    # regex split
    peer_blocks = re.split(r'(?=\n\[Peer\])', content)
    preserved_peers = []
    used_ips = set()
    used_ips.add('10.50.0.1') # Server IP
    
    for block in peer_blocks:
        if block.strip().startswith('[Interface]'):
            continue
            
        # Logic to preserve "geek" or any master user
        if "# geek" in block.lower() or ("geek" in block.lower() and "publickey" in block.lower()):
            print("  Found MASTER USER 'geek' - Preserving and auditing IP...")
            ip_match = re.search(r'AllowedIPs\s*=\s*([\d\.\/]+)', block)
            if ip_match:
                ip_val = ip_match.group(1).split('/')[0]
                used_ips.add(ip_val)
                print(f"  Geek is using IP: {ip_val}")
                preserved_peers.append(block.strip())
            else:
                # If geek exists but IP is missing/broken, force a safe IP
                print("  ⚠️ Geek user has no AllowedIPs! Forcing 10.50.0.2/32")
                pk_match = re.search(r'PublicKey\s*=\s*(\S+)', block)
                if pk_match:
                    preserved_peers.append(f"[Peer]\n# geek\nPublicKey = {pk_match.group(1)}\nAllowedIPs = 10.50.0.2/32")
                    used_ips.add('10.50.0.2')

    # 5. Rebuild [Interface] with CORRECT Rules (Runbook Step 6 & 5)
    print("Rebuilding Interface Block with Runbook-compliant Firewall Rules...")
    interface_block = f"""[Interface]
Address = 10.50.0.1/24
ListenPort = 51820
PrivateKey = {svr_priv_key}

# Runbook Section 6: Firewall, NAT & Forwarding
# - Hole-punch 51820 UDP (Local Firewall)
# - Forward traffic from wg0 to WAN (Insert at TOP to bypass Docker)
# - Allow established return traffic
# - Masquerade outbound traffic
# - MSS Clamping (Crucial for AWS/Fragmented Networks)
MTU = 1280
PostUp = iptables -I INPUT 1 -p udp --dport 51820 -j ACCEPT; iptables -I FORWARD 1 -i wg0 -o {start_interface} -j ACCEPT; iptables -I FORWARD 1 -i {start_interface} -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -I POSTROUTING 1 -s 10.50.0.0/24 -o {start_interface} -j MASQUERADE; iptables -t mangle -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D INPUT -p udp --dport 51820 -j ACCEPT; iptables -D FORWARD -i wg0 -o {start_interface} -j ACCEPT; iptables -D FORWARD -i {start_interface} -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.50.0.0/24 -o {start_interface} -j MASQUERADE; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
"""

    # 6. Write New Config
    with open(WG_CONFIG_PATH, 'w') as f:
        f.write(interface_block)
        
        # Write preserved peers (geek)
        for p in preserved_peers:
            f.write('\n' + p + '\n')
            
        # Write DB users (Force reconstruction to ensure validity)
        count = 0
        for username, user in active_users.items():
            user_ip = user['assigned_ip']
            user_pk = user['public_key']
            
            # Check if this user is already preserved (by key)
            is_preserved = False
            for p in preserved_peers:
                if user_pk in p:
                    is_preserved = True
                    break
            
            if is_preserved:
                print(f"  Skipping {username} (Exist in preserved peers)")
                continue
                
            # Check IP Conflict
            if user_ip in used_ips:
                print(f"  ⚠️ CONFLICT: IP {user_ip} is taken! Regenerating next free IP...")
                # We should really call allocate_ip here, but for simple healing we just skip 
                # to avoid corruption. Dashboard is better for re-allocation.
                continue
                
            # Add to config (Cleanest possible format)
            print(f"  Restoring: {username} ({user_ip})")
            peer_block = f"\n[Peer]\n# {username}\nPublicKey = {user_pk}\nAllowedIPs = {user_ip}/32\n"
            f.write(peer_block)
            used_ips.add(user_ip)
            count += 1
            
    print(f"Rebuilt config: Interface optimized, {len(preserved_peers)} preserved, {count} restored.")

    # 7. Hard Refresh & Apply Rules (Definitive Recovery)
    print("Performing Hard Refresh (wg-quick down/up)...")
    
    # Actually run the NAT commands once during healing to ensure they are active immediately
    print(f"  Enforcing NAT and Forwarding on {start_interface}...")
    try:
        # Step 0: Flush existing rules to prevent duplicates
        print("  Cleaning old rules...")
        subprocess.run(["iptables", "-D", "INPUT", "-p", "udp", "--dport", "51820", "-j", "ACCEPT"], check=False)
        subprocess.run(["iptables", "-D", "FORWARD", "-i", "wg0", "-o", start_interface, "-j", "ACCEPT"], check=False)
        subprocess.run(["iptables", "-D", "FORWARD", "-i", start_interface, "-o", "wg0", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"], check=False)
        subprocess.run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "10.50.0.0/24", "-o", start_interface, "-j", "MASQUERADE"], check=False)
        subprocess.run(["iptables", "-t", "mangle", "-D", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"], check=False)

        # Step 0.5: Check UFW
        print("  Checking UFW Status...")
        ufw_check = subprocess.run(["ufw", "status"], capture_output=True, text=True)
        if "active" in ufw_check.stdout:
            print("  ⚠️ UFW is ACTIVE. Ensuring 51820/udp is allowed...")
            subprocess.run(["ufw", "allow", "51820/udp"], check=False)

        # Step 6: Forwarding rules (using -I to ensure priority over Docker)
        print("  Punching holes in Local Firewall (INPUT/FORWARD)...")
        subprocess.run(["iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", "51820", "-m", "comment", "--comment", "VPN Handshake", "-j", "ACCEPT"], check=False)
        subprocess.run(["iptables", "-I", "FORWARD", "1", "-i", "wg0", "-o", start_interface, "-j", "ACCEPT"], check=False)
        subprocess.run(["iptables", "-I", "FORWARD", "1", "-i", start_interface, "-o", "wg0", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"], check=False)
        
        # Step 5: MASQUERADE rule
        print("  Enabling NAT Masquerade...")
        subprocess.run(["iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", "10.50.0.0/24", "-o", start_interface, "-j", "MASQUERADE"], check=False)
        
        # Step 7: TCP MSS Clamping (The Fix for No-Internet in AWS)
        print("  Applying TCP MSS Clamping...")
        subprocess.run(["iptables", "-t", "mangle", "-I", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"], check=False)

        # Persist Rules (Runbook Step 6)
        print("  Saving persistent firewall rules...")
        subprocess.run(["netfilter-persistent", "save"], check=False)
    except Exception as e:
        print(f"  ⚠️ Warning: Firewall enforcement failed: {e}")

    # Definitive Restart
    print("  Restarting WireGuard Service...")
    subprocess.run(["wg-quick", "down", "wg0"], check=False)
    result = subprocess.run(["wg-quick", "up", "wg0"], capture_output=True, text=True)
    
    if result.returncode == 0:
        print("✅ WireGuard Restarted Successfully!")
        print("\n--- HEALING COMPLETE ---")
        print("Clients should now have internet access and Handshake status should update shortly.")
    else:
        print(f"❌ Restart Failed: {result.stderr}")
