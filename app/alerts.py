from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import redis.asyncio as redis
from .config import REDIS_HOST, REDIS_PORT, REDIS_DB
from .auth import get_current_admin

import os
from .config import PROJECT_ROOT

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

# Path to CoreDNS blocked hosts file
BLOCKED_HOSTS_PATH = PROJECT_ROOT / "coredns" / "blocked.hosts"

class BlacklistRequest(BaseModel):
    domain: str

async def get_redis():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)

async def sync_blacklist_to_hosts():
    """Sync Redis blacklist to CoreDNS hosts file."""
    r = await get_redis()
    domains = await r.smembers("blacklist")
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(BLOCKED_HOSTS_PATH), exist_ok=True)
    
    # Robustness: If BLOCKED_HOSTS_PATH is a directory (Docker issue), remove it
    if os.path.isdir(BLOCKED_HOSTS_PATH):
        import shutil
        shutil.rmtree(BLOCKED_HOSTS_PATH)
    
    with open(BLOCKED_HOSTS_PATH, "w") as f:
        f.write("# CoreDNS Blocked Hosts - AUTO-GENERATED\n")
        for domain in domains:
            if domain.strip():
                f.write(f"0.0.0.0 {domain.strip()}\n")
    
    # Note: CoreDNS with 'hosts' plugin and 'fallthrough' 
    # will reload the file automatically if it changes (depending on config)
    # or we can rely on its internal refresh.

@router.get("/blacklist")
async def get_blacklist(admin: str = Depends(get_current_admin)):
    r = await get_redis()
    # We use a Redis Set for the blacklist
    domains = await r.smembers("blacklist")
    return {"domains": list(domains)}

@router.post("/blacklist")
async def add_to_blacklist(req: BlacklistRequest, admin: str = Depends(get_current_admin)):
    r = await get_redis()
    await r.sadd("blacklist", req.domain)
    await sync_blacklist_to_hosts()
    return {"status": "added", "domain": req.domain}

@router.delete("/blacklist/{domain}")
async def remove_from_blacklist(domain: str, admin: str = Depends(get_current_admin)):
    r = await get_redis()
    await r.srem("blacklist", domain)
    await sync_blacklist_to_hosts()
    return {"status": "removed", "domain": domain}
