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

# Session Timeout (3 minutes + buffer)
SESSION_TIMEOUT = 200 

async def sync_stats_to_db():
    """
    1. Pull live WireGuard stats.
    2. Update cumulative total_rx/total_tx in `users` table.
    3. Manage `vpn_sessions` (Start/End logic).
    """
    try:
        peers = await get_connected_peers(use_cache=False)  # Fresh dump
        now = datetime.now()
        timestamp_now = int(time.time())
        
        async with AsyncSessionLocal() as db:
            # 1. Get all active sessions from DB to check for timeouts
            active_sessions_result = await db.execute(
                select(Session).where(Session.is_active == 1)
            )
            active_sessions = {s.public_key: s for s in active_sessions_result.scalars().all()}
            
            for pub_key, info in peers.items():
                # --- A. CUMULATIVE STATS UPDATE ---
                rx = info.get("transfer_rx", 0)
                tx = info.get("transfer_tx", 0)
                
                if rx > 0 or tx > 0:
                    update_values = {
                        "total_rx": User.total_rx + rx,
                        "total_tx": User.total_tx + tx,
                    }
                    if info.get("endpoint"):
                        update_values["last_endpoint"] = info["endpoint"]
                    if info.get("latest_handshake"):
                        update_values["last_login"] = func.from_unixtime(info["latest_handshake"])
                    
                    await db.execute(
                        update(User)
                        .where(User.public_key == pub_key)
                        .values(**update_values)
                    )

                # --- B. SESSION LOGIC ---
                latest_handshake = info.get("latest_handshake", 0)
                is_connected = False
                if latest_handshake > 0:
                    delta = timestamp_now - latest_handshake
                    is_connected = delta < SESSION_TIMEOUT

                # Case 1: User is Connected
                if is_connected:
                    if pub_key not in active_sessions:
                        # START NEW SESSION
                        # First, get user_id
                        user_res = await db.execute(select(User).where(User.public_key == pub_key))
                        user = user_res.scalar_one_or_none()
                        
                        if user:
                            new_session = Session(
                                user_id=user.id,
                                public_key=pub_key,
                                start_time=now,
                                source_ip=info.get("endpoint"),
                                bytes_rx=rx, # Initial snapshot
                                bytes_tx=tx,
                                is_active=1
                            )
                            db.add(new_session)
                            print(f"🟢 Session Started: {user.username}")
                    else:
                        # UPDATE EXISTING SESSION
                        session = active_sessions[pub_key]
                        # Update bytes (cumulative for this session)
                        # Note: WireGuard resets counters on reload, so this is tricky.
                        # For now, we just update the snapshot. 
                        # Ideally, we should track delta, but WG counters are absolute until reset.
                        session.bytes_rx = rx
                        session.bytes_tx = tx
                        session.source_ip = info.get("endpoint")
                        # Remove from active_sessions list so we don't close it later
                        del active_sessions[pub_key]

            # Case 2: Handle Disconnects (Timeouts)
            # Any session still in active_sessions means the user is no longer in the 'connected' list from WG
            for pub_key, session in active_sessions.items():
                session.is_active = 0
                session.end_time = now
                print(f"🔴 Session Ended: {pub_key[:8]}...")
            
            await db.commit()
            
    except Exception as e:
        print(f"⚠️  Stats sync error: {e}")
