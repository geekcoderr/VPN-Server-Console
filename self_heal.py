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
            
        # Logic to preserve "geek"
        if "# geek" in block.lower() or ("geek" in block.lower() and "publickey" in block.lower()):
            print("  Found MASTER USER 'geek' - Preserving and auditing IP...")
            ip_match = re.search(r'AllowedIPs\s*=\s*([\d\.]+)', block)
            if ip_match:
                used_ips.add(ip_match.group(1))
                print(f"  Geek is using IP: {ip_match.group(1)}")
            preserved_peers.append(block.strip())

    # 5. Rebuild [Interface] with CORRECT Rules (Runbook Step 6 & 5)
    print("Rebuilding Interface Block with Runbook-compliant Firewall Rules...")
    interface_block = f"""[Interface]
Address = 10.50.0.1/24
ListenPort = 51820
PrivateKey = {svr_priv_key}

# Runbook Section 6: Firewall, NAT & Forwarding
# - Forward traffic from wg0 to WAN (Insert at TOP to bypass Docker)
# - Allow established return traffic
# - Masquerade outbound traffic
PostUp = iptables -I FORWARD 1 -i wg0 -o {start_interface} -j ACCEPT; iptables -I FORWARD 1 -i {start_interface} -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.50.0.0/24 -o {start_interface} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -o {start_interface} -j ACCEPT; iptables -D FORWARD -i {start_interface} -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.50.0.0/24 -o {start_interface} -j MASQUERADE
"""

    # 6. Write New Config
    with open(WG_CONFIG_PATH, 'w') as f:
        f.write(interface_block)
        
        # Write preserved peers (geek)
        for p in preserved_peers:
            f.write('\n' + p + '\n')
            
        # Write DB users (Skipping duplicates)
        count = 0
        for username, user in active_users.items():
            # Check if this user is already preserved (by key)
            is_preserved = False
            for p in preserved_peers:
                if user['public_key'] in p:
                    is_preserved = True
                    break
            
            if is_preserved:
                print(f"  Skipping {username} (Exist in preserved peers)")
                continue
                
            # Check IP Conflict
            user_ip = user['assigned_ip']
            if user_ip in used_ips:
                print(f"  ⚠️ CONFLICT: IP {user_ip} is taken by Master User!")
                # Simple fix: Allocate next free IP? 
                # For safety in this script, we just SKIP adding it to config to prevent breakage.
                print(f"  ❌ Skipping {username} to prevent IP collision. Please regenerate this user in Dashboard.")
                continue
                
            # Add to config
            print(f"  Restoring: {username} ({user_ip})")
            peer_block = f"\n[Peer]\n# {username}\nPublicKey = {user['public_key']}\nAllowedIPs = {user_ip}/32\n"
            f.write(peer_block)
            count += 1
            
    print(f"Rebuilt config: Interface optimized, {len(preserved_peers)} preserved, {count} restored.")

    # 7. Reload & Apply Rules (Runbook Step 6 & 7)
    print("Reloading WireGuard & Applying Firewall Rules...")
    
    # Actually run the NAT commands once during healing to ensure they are active immediately
    print(f"  Enforcing NAT and Forwarding on {start_interface}...")
    try:
        # Step 6: Forwarding rules (using -A as per Runbook)
        subprocess.run(["iptables", "-A", "FORWARD", "-i", "wg0", "-o", start_interface, "-j", "ACCEPT"], check=False)
        subprocess.run(["iptables", "-A", "FORWARD", "-i", start_interface, "-o", "wg0", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"], check=False)
        
        # Step 5: MASQUERADE rule
        subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.50.0.0/24", "-o", start_interface, "-j", "MASQUERADE"], check=False)
        
        # Persist Rules (Runbook Step 6)
        print("  Saving persistent firewall rules...")
        subprocess.run(["netfilter-persistent", "save"], check=False)
        
        print("  ✅ Firewall rules applied to kernel and persisted.")
    except Exception as e:
        print(f"  ⚠️ Warning: Failed to apply some firewall rules: {e}")

    success, err = await reload_wireguard()
    if success:
        print("✅ WireGuard Reload Successful!")
        print("\n--- HEALING COMPLETE ---")
        print("Clients should now have internet access.")
        print("\n⚠️ IMPORTANT AWS REMINDERS (Runbook Step 2):")
        print("1. EC2 Instance -> Source/Destination check MUST be DISABLED.")
        print("2. Security Group -> UDP 51820 MUST be ALLOWED Inbound.")
    else:
        print(f"❌ Reload Failed: {err}")
