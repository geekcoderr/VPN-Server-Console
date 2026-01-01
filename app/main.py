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
    await init_db()
    await ensure_admin_exists()
    
    # Background task for broadcasting metrics
    app.state.broadcast_task = asyncio.create_task(broadcast_metrics())
    
    yield
    # Shutdown
    app.state.broadcast_task.cancel()

async def broadcast_metrics():
    """Background task to broadcast WireGuard stats and sync to DB every 10 seconds."""
    from .database import AsyncSessionLocal, User
    from sqlalchemy import update
    
    while True:
        try:
            connected = await get_connected_peers()
            await manager.broadcast({"type": "metrics", "data": connected})
            
            # Persist to DB
            async with AsyncSessionLocal() as db:
                for pubkey, stats in connected.items():
                    await db.execute(
                        update(User)
                        .where(User.public_key == pubkey)
                        .values(
                            total_rx=stats['transfer_rx'],
                            total_tx=stats['transfer_tx'],
                            last_login=datetime.fromtimestamp(stats['latest_handshake']) if stats['latest_handshake'] else None
                        )
                    )
                await db.commit()
        except Exception as e:
            print(f"Broadcast/Sync error: {e}")
        await asyncio.sleep(10)

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

@app.websocket("/ws/stats")
async def stats_websocket(websocket: WebSocket):
    """WebSocket for live VPN stats."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
