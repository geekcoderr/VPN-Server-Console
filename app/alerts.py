"""
DNS Blocking Module - Military-Grade v4.0
Simple, robust, file-based approach. No Redis dependency.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import json
import os
from pathlib import Path
from .config import PROJECT_ROOT, DATA_DIR
from .auth import get_current_admin

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

# File paths
BLACKLIST_JSON = DATA_DIR / "blacklist.json"
BLOCKED_HOSTS = PROJECT_ROOT / "coredns" / "blocked.hosts"

class DomainRequest(BaseModel):
    domain: str

def _load_blacklist() -> list:
    """Load blacklist from JSON file."""
    if not BLACKLIST_JSON.exists():
        return []
    try:
        with open(BLACKLIST_JSON, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return []

def _save_blacklist(domains: list):
    """Save blacklist to JSON file."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(BLACKLIST_JSON, "w") as f:
        json.dump(domains, f, indent=2)

def _sync_to_hosts(domains: list):
    """Write domains to CoreDNS hosts file."""
    os.makedirs(os.path.dirname(BLOCKED_HOSTS), exist_ok=True)
    with open(BLOCKED_HOSTS, "w") as f:
        f.write("# CoreDNS Blocked Hosts - AUTO-GENERATED\n")
        f.write("# Do not edit manually. Use the admin dashboard.\n\n")
        for domain in domains:
            d = domain.strip().lower()
            if d:
                # Block the domain and www variant
                f.write(f"0.0.0.0 {d}\n")
                if not d.startswith("www."):
                    f.write(f"0.0.0.0 www.{d}\n")
    print(f"🛡️  DNS Blacklist synced: {len(domains)} domains")

@router.get("/blacklist")
async def get_blacklist(admin: str = Depends(get_current_admin)):
    """Get all blocked domains."""
    domains = _load_blacklist()
    return {"domains": domains}

@router.post("/blacklist")
async def add_to_blacklist(req: DomainRequest, admin: str = Depends(get_current_admin)):
    """Add a domain to the blacklist."""
    domain = req.domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty")
    
    domains = _load_blacklist()
    if domain in domains:
        raise HTTPException(status_code=400, detail="Domain already blocked")
    
    domains.append(domain)
    _save_blacklist(domains)
    _sync_to_hosts(domains)
    
    return {"message": f"Domain {domain} blocked", "total": len(domains)}

@router.delete("/blacklist/{domain}")
async def remove_from_blacklist(domain: str, admin: str = Depends(get_current_admin)):
    """Remove a domain from the blacklist."""
    domain = domain.strip().lower()
    domains = _load_blacklist()
    
    if domain not in domains:
        raise HTTPException(status_code=404, detail="Domain not found in blacklist")
    
    domains.remove(domain)
    _save_blacklist(domains)
    _sync_to_hosts(domains)
    
    return {"message": f"Domain {domain} unblocked", "total": len(domains)}

@router.get("/test-blocking")
async def test_blocking(admin: str = Depends(get_current_admin)):
    """Self-test endpoint to verify entire DNS blocking chain."""
    results = {
        "json_file": {"exists": False, "domains": 0},
        "hosts_file": {"exists": False, "lines": 0},
        "status": "UNKNOWN"
    }
    
    # Check JSON file
    if BLACKLIST_JSON.exists():
        results["json_file"]["exists"] = True
        domains = _load_blacklist()
        results["json_file"]["domains"] = len(domains)
    
    # Check hosts file
    if BLOCKED_HOSTS.exists():
        results["hosts_file"]["exists"] = True
        with open(BLOCKED_HOSTS, "r") as f:
            lines = [l for l in f.readlines() if l.strip() and not l.startswith("#")]
            results["hosts_file"]["lines"] = len(lines)
    
    # Determine status
    if results["json_file"]["exists"] and results["hosts_file"]["exists"]:
        if results["json_file"]["domains"] > 0 and results["hosts_file"]["lines"] > 0:
            results["status"] = "WORKING"
        elif results["json_file"]["domains"] == 0:
            results["status"] = "EMPTY - No domains in blacklist"
        else:
            results["status"] = "SYNC ERROR - Hosts file not updated"
    else:
        results["status"] = "FILES MISSING"
    
    return results
