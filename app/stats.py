"""
Stats persistence module.
Periodically saves WireGuard transfer stats to database for persistence across reboots.
Also tracks logical User Sessions (Connect/Disconnect events).
"""
from sqlalchemy import update, func, select, and_
from .database import AsyncSessionLocal, User, Session
from .wg import get_connected_peers
from datetime import datetime
import time

# Memory-based tracker for deltas
_last_stats = {}

# Session Timeout (3 minutes + buffer)
SESSION_TIMEOUT = 200 

async def sync_stats_to_db():
    """
    Delta-based stats tracking.
    1. Calculate delta since last sync.
    2. Add delta to cumulative total in DB.
    3. Handle WireGuard counter resets (reloads).
    """
    global _last_stats
    try:
        peers = await get_connected_peers(use_cache=False)
        now = datetime.now()
        
        async with AsyncSessionLocal() as db:
            for pub_key, info in peers.items():
                rx = info.get("transfer_rx", 0)
                tx = info.get("transfer_tx", 0)
                
                # Calculate Delta
                last = _last_stats.get(pub_key, {"rx": 0, "tx": 0})
                
                # If current < last, WireGuard reset (reload). Delta is just current.
                delta_rx = rx - last["rx"] if rx >= last["rx"] else rx
                delta_tx = tx - last["tx"] if tx >= last["tx"] else tx
                
                if delta_rx > 0 or delta_tx > 0:
                    await db.execute(
                        update(User)
                        .where(User.public_key == pub_key)
                        .values(
                            total_rx=func.coalesce(User.total_rx, 0) + delta_rx,
                            total_tx=func.coalesce(User.total_tx, 0) + delta_tx,
                            last_login=func.from_unixtime(info["latest_handshake"]) if info.get("latest_handshake") else User.last_login,
                            last_endpoint=info.get("endpoint") or User.last_endpoint
                        )
                    )
                
                # Update memory tracker
                _last_stats[pub_key] = {"rx": rx, "tx": tx}

            await db.commit()
            
    except Exception as e:
        print(f"⚠️  Stats sync error: {e}")
