from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager

from .database import init_db
from .auth import router as auth_router, ensure_admin_exists, get_current_admin
from .users import router as users_router
from .websockets import manager
from .wg import get_connected_peers

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    from .database import db_health_check
    if not await db_health_check():
        print("🚨 CRITICAL: Could not establish database connection. Sync aborted.")
    else:
        await init_db()
        await ensure_admin_exists()
        
        # Critical: Enforce Kernel State Sync
        from .wg import sync_wireguard_state
        await sync_wireguard_state()
        
        # Initialize Firewall & ACLs
        from .firewall import init_firewall_chains, apply_acl
        from .database import get_all_users
        
        print("🛡️  Initializing Firewall ACLs...")
        init_firewall_chains()
        
        # Re-apply ACLs for all users
        all_users = await get_all_users()
        for user in all_users:
            if user.assigned_ip and user.acl_profile:
                apply_acl(user.assigned_ip, user.acl_profile)
        print(f"✅ Applied ACLs for {len(all_users)} users.")
    
    # Background task for broadcasting metrics
    app.state.broadcast_task = asyncio.create_task(broadcast_metrics())
    
    # Start Alert Worker
    from .worker import alert_worker
    app.state.alert_worker_task = asyncio.create_task(alert_worker())
    
    yield
    # Shutdown
    app.state.broadcast_task.cancel()
    app.state.alert_worker_task.cancel()

async def persist_to_db(metrics: dict):
    """Auxiliary task to persist metrics to DB without blocking the broadcast loop."""
    from .database import AsyncSessionLocal, User
    from sqlalchemy import update
    try:
        async with AsyncSessionLocal() as db:
            for pubkey, stats in metrics.items():
                # Only update if there's actual data
                rx = stats.get('transfer_rx', 0)
                tx = stats.get('transfer_tx', 0)
                
                if rx == 0 and tx == 0:
                    continue
                
                # INCREMENT cumulative counters (not replace)
                await db.execute(
                    update(User)
                    .where(User.public_key == pubkey)
                    .values(
                        total_rx=User.total_rx + rx,
                        total_tx=User.total_tx + tx,
                        last_login=datetime.fromtimestamp(stats['latest_handshake']) if stats.get('latest_handshake') else None,
                        last_endpoint=stats.get('endpoint')
                    )
                )
            await db.commit()
    except Exception as e:
        print(f"Database Persistence Error: {e}")

async def broadcast_metrics():
    """
    Background task to broadcast WireGuard stats and sync to DB.
    
    STRATEGY: High-Frequency Polling (2s) for UI, Throttled Persistence (20s) for DB.
    This gives "Immediate" feedback to the user without destroying disk I/O.
    """
    import time
    last_db_sync = 0
    DB_SYNC_INTERVAL = 20  # Seconds
    
    while True:
        try:
            # 0. CHECK ACTIVE SESSIONS
            # If no admin is watching, don't waste CPU polling WireGuard
            if len(manager.active_connections) == 0:
                await asyncio.sleep(10)
                continue

            # 1. FAST LOOP (3s): Updates Global Cache & UI
            # Force fresh poll to get latest handshake IMMEDIATELY
            connected = await get_connected_peers(use_cache=False)
            
            # Broadcast to WebSocket (Priority)
            await manager.broadcast({"type": "metrics", "data": connected})
            
            # 2. SLOW LOOP (20s): Persist to Database
            # Only write to disk occasionally to save resources
            now = time.time()
            if now - last_db_sync > DB_SYNC_INTERVAL:
                asyncio.create_task(persist_to_db(connected))
                last_db_sync = now
            
        except Exception as e:
            print(f"Broadcast error: {e}")
        
        # High-Frequency Polling Sleep (3s)
        await asyncio.sleep(3)

app = FastAPI(
    title="VPN Control API",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict this in production to your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(users_router)
from .alerts import router as alerts_router
app.include_router(alerts_router)

@app.websocket("/ws/stats")
async def stats_websocket(websocket: WebSocket):
    """WebSocket for live VPN stats."""
    await manager.connect(websocket)
    try:
        # Send IMMEDIATE initial state to the new client
        initial_data = await get_connected_peers(use_cache=True)
        await websocket.send_json({"type": "metrics", "data": initial_data})
        
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
