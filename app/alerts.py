"""
DNS Blocking Module - Network-Level v4.3.0
Simple, robust, file-based approach with instant reload.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import json
import os
import subprocess
from pathlib import Path
from .config import PROJECT_ROOT, DATA_DIR
from .auth import get_current_admin

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

# File paths
BLACKLIST_JSON = DATA_DIR / "blacklist.json"
BLOCKED_HOSTS = PROJECT_ROOT / "coredns" / "blocked.hosts"
WILDCARDS_CONF = PROJECT_ROOT / "coredns" / "wildcards.conf"

class DomainRequest(BaseModel):
    domain: str | None = None
    domains: list[str] | None = None

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

def _sync_to_wildcards(domains: list):
    """Write wildcard rules to CoreDNS wildcards.conf using template plugin."""
    os.makedirs(os.path.dirname(WILDCARDS_CONF), exist_ok=True)
    with open(WILDCARDS_CONF, "w") as f:
        f.write("# CoreDNS Wildcard Rules - AUTO-GENERATED\n\n")
        for domain in domains:
            d = domain.strip().lower()
            if d:
                # Use template plugin to block the domain and all subdomains
                # This matches d and *.d
                f.write(f"template ANY ANY {d} {{\n")
                f.write(f"    answer \"{{{{ .Name }}}} 1 IN A 0.0.0.0\"\n")
                f.write("}\n\n")
    print(f"🌐 Wildcard rules synced: {len(domains)} domains")

def _reload_coredns():
    """Signal CoreDNS to reload configuration for instant blocking."""
    try:
        # Send SIGHUP to CoreDNS container to trigger config reload
        subprocess.run(["docker", "kill", "-s", "HUP", "vpn-dns"], 
                       capture_output=True, timeout=5)
        print("🔄 CoreDNS reloaded for instant blocking")
    except Exception as e:
        print(f"⚠️  CoreDNS reload failed: {e}")

@router.get("/blacklist")
async def get_blacklist(admin: str = Depends(get_current_admin)):
    """Get all blocked domains."""
    domains = _load_blacklist()
    return {"domains": domains}

@router.post("/blacklist")
async def add_to_blacklist(req: DomainRequest, admin: str = Depends(get_current_admin)):
    """Add multiple domains to the blacklist."""
    input_domains = []
    if req.domain: input_domains.append(req.domain)
    if req.domains: input_domains.extend(req.domains)
    
    new_domains = [d.strip().lower() for d in input_domains if d.strip()]
    if not new_domains:
        raise HTTPException(status_code=400, detail="No valid domains provided")
    
    domains = _load_blacklist()
    added_count = 0
    for domain in new_domains:
        if domain not in domains:
            domains.append(domain)
            added_count += 1
    
    if added_count > 0:
        _save_blacklist(domains)
        _sync_to_hosts(domains)
        _sync_to_wildcards(domains)
        _reload_coredns()
    
    return {"message": f"Successfully blocked {added_count} new domains", "total": len(domains)}

@router.post("/blacklist/delete")
async def bulk_remove_from_blacklist(req: DomainRequest, admin: str = Depends(get_current_admin)):
    """Remove multiple domains from the blacklist."""
    input_domains = []
    if req.domain: input_domains.append(req.domain)
    if req.domains: input_domains.extend(req.domains)
    
    to_remove = [d.strip().lower() for d in input_domains if d.strip()]
    domains = _load_blacklist()
    
    initial_count = len(domains)
    domains = [d for d in domains if d not in to_remove]
    removed_count = initial_count - len(domains)
    
    if removed_count > 0:
        _save_blacklist(domains)
        _sync_to_hosts(domains)
        _sync_to_wildcards(domains)
        _reload_coredns()
    
    return {"message": f"Successfully unblocked {removed_count} domains", "total": len(domains)}

@router.delete("/blacklist/{domain}")
async def remove_from_blacklist(domain: str, admin: str = Depends(get_current_admin)):
    """Remove a single domain from the blacklist."""
    domain = domain.strip().lower()
    domains = _load_blacklist()
    
    if domain not in domains:
        raise HTTPException(status_code=404, detail="Domain not found in blacklist")
    
    domains.remove(domain)
    _save_blacklist(domains)
    _sync_to_hosts(domains)
    _sync_to_wildcards(domains)
    _reload_coredns()
    
    return {"message": f"Domain {domain} unblocked", "total": len(domains)}

@router.get("/test-blocking")
async def test_blocking(admin: str = Depends(get_current_admin)):
    """Self-test endpoint to verify entire DNS blocking chain."""
    results = {
        "json_file": {"exists": False, "domains": 0},
        "hosts_file": {"exists": False, "lines": 0},
        "wildcards_file": {"exists": False},
        "coredns": {"running": False},
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
    
    # Check wildcards file
    if WILDCARDS_CONF.exists():
        results["wildcards_file"]["exists"] = True
    
    # Check CoreDNS container
    try:
        result = subprocess.run(["docker", "ps", "--filter", "name=vpn-dns", "--format", "{{.Status}}"],
                                capture_output=True, text=True, timeout=5)
        if "Up" in result.stdout:
            results["coredns"]["running"] = True
    except:
        pass
    
    # Determine status
    if results["json_file"]["exists"] and results["hosts_file"]["exists"] and \
       results["wildcards_file"]["exists"] and results["coredns"]["running"]:
        if results["json_file"]["domains"] > 0 and results["hosts_file"]["lines"] > 0:
            results["status"] = "WORKING"
        elif results["json_file"]["domains"] == 0:
            results["status"] = "EMPTY - No domains in blacklist"
        else:
            results["status"] = "SYNC ERROR - Hosts file not updated"
    elif not results["coredns"]["running"]:
        results["status"] = "COREDNS NOT RUNNING"
    else:
        results["status"] = "FILES MISSING"
    
    return results
