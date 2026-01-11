from fastapi import APIRouter, Depends, HTTPException, Form
from pydantic import BaseModel
import redis.asyncio as redis
import os
from .config import REDIS_HOST, REDIS_PORT, REDIS_DB, PROJECT_ROOT
from .auth import get_current_admin

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

# Path to CoreDNS blocked config file
BLOCKED_CONF_PATH = PROJECT_ROOT / "coredns" / "blocked.conf"

class BlacklistRequest(BaseModel):
    domain: str

async def get_redis():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)

async def get_redis_blacklist():
    r = await get_redis()
    return await r.smembers("blacklist")

async def sync_blacklist_to_dns():
    """Sync Redis blacklist to CoreDNS configuration using template plugin."""
    domains = await get_redis_blacklist()
    
    # Ensure the directory exists
    os.makedirs(os.path.dirname(BLOCKED_CONF_PATH), exist_ok=True)
    
    with open(BLOCKED_CONF_PATH, "w") as f:
        f.write("# CoreDNS Blocked Domains - AUTO-GENERATED\n")
        if domains:
            for d in domains:
                clean_d = d.strip()
                if clean_d:
                    # Use template plugin for each domain (A, HTTPS, SVCB)
                    # This avoids long lines and ensures clean NXDOMAIN response
                    f.write(f"template ANY ANY {clean_d} www.{clean_d} {{\n")
                    f.write("    rcode NXDOMAIN\n")
                    f.write("}\n")
    
    print(f"🛡️  DNS Blacklist synced: {len(domains)} domains (NXDOMAIN enforcement)")

@router.get("/blacklist")
async def get_blacklist(admin: str = Depends(get_current_admin)):
    r = await get_redis()
    domains = await r.smembers("blacklist")
    return {"domains": list(domains)}

@router.post("/blacklist")
async def add_to_blacklist(req: BlacklistRequest, admin: str = Depends(get_current_admin)):
    """Add a domain to the blacklist."""
    r = await get_redis()
    await r.sadd("blacklist", req.domain)
    await sync_blacklist_to_dns()
    return {"message": f"Domain {req.domain} restricted"}

@router.delete("/blacklist/{domain}")
async def remove_from_blacklist(domain: str, admin: str = Depends(get_current_admin)):
    """Remove a domain from the blacklist."""
    r = await get_redis()
    await r.srem("blacklist", domain)
    await sync_blacklist_to_dns()
    return {"message": f"Domain {domain} removed from restriction"}
