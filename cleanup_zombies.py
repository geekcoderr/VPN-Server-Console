
import asyncio
from app.database import get_all_users
from app.wg import run_command, WG_INTERFACE

async def clean_zombies():
    print("🧟 Starting Zombie Peer Cleanup...")
    
    # 1. Get Valid Public Keys from DB
    users = await get_all_users()
    valid_keys = {u.public_key for u in users if u.status == 'active'}
    print(f"✅ Found {len(valid_keys)} valid active users in Database.")
    
    # 2. Get Current Kernel Peers
    # wg show wg0 peers
    code, out, err = await run_command(["wg", "show", WG_INTERFACE, "peers"])
    if code != 0:
        print(f"❌ Failed to list peers: {err}")
        return
        
    current_peers = set(out.strip().splitlines()) if out.strip() else set()
    print(f"🧐 Found {len(current_peers)} peers in Kernel.")
    
    # 3. Identify Zombies
    zombies = current_peers - valid_keys
    
    if not zombies:
        print("✨ System clean! No zombies found.")
        return
        
    print(f"⚠️  Found {len(zombies)} ZOMBIE peers (In Kernel but not DB/Active).")
    
    # 4. Terminate Zombies
    for z_key in zombies:
        print(f"🔫 Removing Zombie: {z_key}...")
        # wg set wg0 peer <KEY> remove
        await run_command(["wg", "set", WG_INTERFACE, "peer", z_key, "remove"])
        
    print("🧹 Cleanup Complete.")

if __name__ == "__main__":
    asyncio.run(clean_zombies())
