"""
Stats persistence module.
Periodically saves WireGuard transfer stats to database for persistence across reboots.
"""
from sqlalchemy import update, func
from .database import AsyncSessionLocal, User
from .wg import get_connected_peers


async def sync_stats_to_db():
    """
    Pull live WireGuard stats and update cumulative total_rx/total_tx in database.
    Also updates last_endpoint and last_login timestamps.
    """
    try:
        peers = await get_connected_peers(use_cache=False)  # Fresh dump
        
        async with AsyncSessionLocal() as db:
            for pub_key, info in peers.items():
                # Only update if there's actual transfer data
                rx = info.get("transfer_rx", 0)
                tx = info.get("transfer_tx", 0)
                
                if rx == 0 and tx == 0:
                    continue
                
                # Build update values
                update_values = {
                    "total_rx": User.total_rx + rx,
                    "total_tx": User.total_tx + tx,
                }
                
                # Update endpoint if available
                if info.get("endpoint"):
                    update_values["last_endpoint"] = info["endpoint"]
                
                # Update last_login if handshake exists
                if info.get("latest_handshake"):
                    update_values["last_login"] = func.from_unixtime(info["latest_handshake"])
                
                await db.execute(
                    update(User)
                    .where(User.public_key == pub_key)
                    .values(**update_values)
                )
            
            await db.commit()
            
    except Exception as e:
        print(f"⚠️  Stats sync error: {e}")
