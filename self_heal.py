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
from app.database import get_all_users, DB_PATH
from app.wg import (
    WG_CONFIG_PATH, 
    reload_wireguard, 
    parse_config, 
    build_config,
    add_peer_to_config
)
from app.audit import log_wg_reload

async def heal_system():
    print(f"--- Starting IAM Self-Healing ---")
    
    # 1. Load users from DB (Source of Truth)
    print(f"Reading Database: {DB_PATH}")
    users = await get_all_users()
    active_users = {u['username']: u for u in users if u['status'] == 'active'}
    print(f"Found {len(active_users)} active users in DB.")

    # 2. Backup wg0.conf
    if not WG_CONFIG_PATH.exists():
        print("Error: wg0.conf not found!")
        return

    backup = WG_CONFIG_PATH.with_suffix('.conf.heal_backup')
    shutil.copy2(WG_CONFIG_PATH, backup)
    print(f"Backed up config to {backup}")

    # 3. Read content
    content = WG_CONFIG_PATH.read_text()
    
    # Extract Interface block
    interface_section = ""
    match = re.search(r'(.*?)(?=\n\[Peer\]|$)', content, re.DOTALL)
    if match:
        interface_section = match.group(0).strip()
    else:
        interface_section = content.strip()

    print("Cleaned Interface config retained.")

    # 4. PRESERVE SPECIAL PEERS (like 'geek')
    # We look for a peer block that has the comment "# geek" or matches known public key if you have it
    preserved_peers = []
    
    # Regex to find all peer blocks
    # Logic: Find [Peer] ... until next [Peer] or EOF
    peer_blocks = re.split(r'(?=\n\[Peer\])', content)
    
    for block in peer_blocks:
        if "# geek" in block.lower():
            print("  Found MASTER USER 'geek' in config - Preserving it!")
            preserved_peers.append(block.strip())
        elif "geek" in block.lower() and "publickey" in block.lower():
             # Fallback if comment is slightly different
             print("  Found likely 'geek' peer - Preserving it!")
             preserved_peers.append(block.strip())

    # 5. Write clean config (Interface + Preserved + DB Users)
    with open(WG_CONFIG_PATH, 'w') as f:
        f.write(interface_section + '\n')
        
        # Write preserved first
        for p in preserved_peers:
            f.write('\n' + p + '\n')
    
    print("Purged duplicates, kept Interface + Master User.")

    # 6. Re-add valid users from DB (Avoid duplicates if DB has 'geek' too)
    print("Restoring valid peers from DB...")
    count = 0
    for username, user in active_users.items():
        # Check if we already preserved this user (by public key comparison to be safe)
        is_preserved = False
        for p in preserved_peers:
            if user['public_key'] in p:
                is_preserved = True
                print(f"  Skipping {username} (Already preserved as master peer)")
                break
        
        if is_preserved:
            continue

        print(f"  Restoring: {username} ({user['assigned_ip']})")
        peer_block = f"\n[Peer]\n# {username}\nPublicKey = {user['public_key']}\nAllowedIPs = {user['assigned_ip']}/32\n"
        
        with open(WG_CONFIG_PATH, 'a') as f:
            f.write(peer_block)
        count += 1


    print(f"Restored {count} peers.")

    # 6. Reload WireGuard
    print("Reloading WireGuard...")
    success, err = await reload_wireguard()
    if success:
        print("✅ WireGuard Reload Successful!")
        print("System is consistent.")
    else:
        print(f"❌ Reload Failed: {err}")
        print("Restoring backup...")
        shutil.copy2(backup, WG_CONFIG_PATH)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: Must run as root")
        exit(1)
    asyncio.run(heal_system())
