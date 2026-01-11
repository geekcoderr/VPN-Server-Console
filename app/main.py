from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, Request
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager

from .database import init_db
from .auth import router as auth_router, ensure_admin_exists, get_current_admin
from .users import router as users_router
from .websockets import manager
from .wg import get_connected_peers

from .limiter import limiter
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from fastapi_csrf_protect import CsrfProtect
from fastapi_csrf_protect.exceptions import CsrfProtectError
from fastapi.responses import JSONResponse
from .config import SESSION_SECRET_KEY

# Rate Limiter
# (Initialized in .limiter)

class CsrfSettings(BaseModel):
    secret_key: str = SESSION_SECRET_KEY
    cookie_samesite: str = "lax"

@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    from .database import db_health_check
    if not await db_health_check():
        print("🚨 CRITICAL: Could not establish database connection. Sync aborted.")
    else:
        await init_db()
        await ensure_admin_exists()
        
        # Sync Blacklist to CoreDNS (v4.0 - file-based)
        from .alerts import _load_blacklist, _sync_to_hosts
        domains = _load_blacklist()
        _sync_to_hosts(domains)
        
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

async def persist_to_db(connected_peers: dict):
    """Consolidated stats persistence."""
    from .stats import sync_stats_to_db
    await sync_stats_to_db()

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
            
            # Enrich with DB totals for cumulative display
            from .database import get_all_users
            all_users = await get_all_users()
            enriched_data = {}
            for user in all_users:
                peer_info = connected.get(user.public_key, {})
                enriched_data[user.public_key] = {
                    **peer_info,
                    "transfer_rx": (user.total_rx or 0) + peer_info.get("transfer_rx", 0),
                    "transfer_tx": (user.total_tx or 0) + peer_info.get("transfer_tx", 0),
                    "connected": peer_info.get("connected", False)
                }

            # Broadcast to WebSocket (Priority)
            await manager.broadcast({"type": "metrics", "data": enriched_data})
            
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
    title="GeekSTunnel Premium Console",
    version="4.0.0",
    lifespan=lifespan
)

# Rate Limit Handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CSRF Error Handler
@app.exception_handler(CsrfProtectError)
def csrf_protect_exception_handler(request: Request, exc: CsrfProtectError):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})

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
from .invites import router as invites_router
app.include_router(invites_router)

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
