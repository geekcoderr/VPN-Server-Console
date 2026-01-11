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

# Track active sessions in memory
_active_sessions = {}  # {public_key: session_id}

# Session Timeout (3 minutes + buffer)
SESSION_TIMEOUT = 200 

async def sync_stats_to_db():
    """
    Delta-based stats tracking.
    1. Calculate delta since last sync.
    2. Add delta to cumulative total in DB.
    3. Handle WireGuard counter resets (reloads).
    4. Create/close session records based on connection state.
    """
    global _last_stats, _active_sessions
    try:
        peers = await get_connected_peers(use_cache=False)
        now = datetime.now()
        current_connected = set()
        
        async with AsyncSessionLocal() as db:
            for pub_key, info in peers.items():
                rx = info.get("transfer_rx", 0)
                tx = info.get("transfer_tx", 0)
                is_connected = info.get("connected", False)
                
                # Get user for this public key
                result = await db.execute(select(User).where(User.public_key == pub_key))
                user = result.scalars().first()
                if not user:
                    continue
                
                # Track connected peers
                if is_connected:
                    current_connected.add(pub_key)
                
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
                
                # Session Management
                if is_connected and pub_key not in _active_sessions:
                    # User just connected - create new session
                    new_session = Session(
                        user_id=user.id,
                        public_key=pub_key,
                        start_time=now,
                        source_ip=info.get("endpoint", "").split(":")[0] if info.get("endpoint") else None,
                        bytes_rx=0,
                        bytes_tx=0,
                        is_active=1
                    )
                    db.add(new_session)
                    await db.flush()  # Get the ID
                    _active_sessions[pub_key] = new_session.id
                    print(f"📡 Session started: {user.username} ({pub_key[:8]}...)")
                
                elif is_connected and pub_key in _active_sessions:
                    # Update active session with transfer data
                    await db.execute(
                        update(Session)
                        .where(Session.id == _active_sessions[pub_key])
                        .values(
                            bytes_rx=Session.bytes_rx + delta_rx,
                            bytes_tx=Session.bytes_tx + delta_tx
                        )
                    )
                
                # Update memory tracker
                _last_stats[pub_key] = {"rx": rx, "tx": tx}
            
            # Check for disconnected users (close their sessions)
            for pub_key, session_id in list(_active_sessions.items()):
                if pub_key not in current_connected:
                    # User disconnected - close session
                    await db.execute(
                        update(Session)
                        .where(Session.id == session_id)
                        .values(
                            end_time=now,
                            is_active=0
                        )
                    )
                    del _active_sessions[pub_key]
                    print(f"🔌 Session ended: session_id={session_id}")

            await db.commit()
            
    except Exception as e:
        print(f"⚠️  Stats sync error: {e}")
