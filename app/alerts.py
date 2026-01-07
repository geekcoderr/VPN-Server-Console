from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import redis.asyncio as redis
from .config import REDIS_HOST, REDIS_PORT, REDIS_DB
from .auth import get_current_admin

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

class BlacklistRequest(BaseModel):
    domain: str

async def get_redis():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)

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
    return {"status": "added", "domain": req.domain}

@router.delete("/blacklist/{domain}")
async def remove_from_blacklist(domain: str, admin: str = Depends(get_current_admin)):
    r = await get_redis()
    await r.srem("blacklist", domain)
    return {"status": "removed", "domain": domain}
