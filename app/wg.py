"""
WireGuard management module.
Handles key generation, config file updates, and WireGuard reload.

CRITICAL RULES:
- Server NEVER acts as a client (no 0.0.0.0/0 on server side)
- All changes use atomic writes with file locking
- Rollback on reload failure
"""
import asyncio
import fcntl
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Tuple, Optional, Dict, List

from .config import (
    WG_CONFIG_PATH,
    WG_INTERFACE,
    VPN_SERVER_IP,
    VPN_IP_START,
    VPN_IP_END,
    VPN_SERVER_ENDPOINT,
    CLIENT_DNS,
    CLIENT_MTU,
    PERSISTENT_KEEPALIVE,
)
from .audit import log_wg_reload


class WireGuardError(Exception):
    """Custom exception for WireGuard operations."""
    pass


async def run_command(cmd: list) -> Tuple[int, str, str]:
    """Run a shell command and return (returncode, stdout, stderr)."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    return proc.returncode, stdout.decode().strip(), stderr.decode().strip()


async def generate_keypair() -> Tuple[str, str]:
    """
    Generate a WireGuard keypair.
    Returns (private_key, public_key).
    Private key is NEVER stored - only returned for immediate use.
    """
    # Generate private key
    code, private_key, err = await run_command(["wg", "genkey"])
    if code != 0:
        raise WireGuardError(f"Failed to generate private key: {err}")
    
    # Derive public key
    proc = await asyncio.create_subprocess_exec(
        "wg", "pubkey",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate(input=private_key.encode())
    if proc.returncode != 0:
        raise WireGuardError(f"Failed to derive public key: {stderr.decode()}")
    
    public_key = stdout.decode().strip()
    return private_key, public_key


async def get_server_public_key() -> str:
    """
    Extract server's public key from wg0.conf.
    """
    if not WG_CONFIG_PATH.exists():
        raise WireGuardError(f"WireGuard config not found: {WG_CONFIG_PATH}")
    
    content = WG_CONFIG_PATH.read_text()
    
    # Find PrivateKey in [Interface] section
    match = re.search(r'PrivateKey\s*=\s*(\S+)', content)
    if not match:
        raise WireGuardError("Could not find server PrivateKey in wg0.conf")
    
    server_private_key = match.group(1)
    
    # Derive public key
    proc = await asyncio.create_subprocess_exec(
        "wg", "pubkey",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate(input=server_private_key.encode())
    if proc.returncode != 0:
        raise WireGuardError(f"Failed to derive server public key: {stderr.decode()}")
    
    return stdout.decode().strip()


def allocate_ip(used_ips: set) -> str:
    """
    Allocate the next available IP from the VPN subnet.
    Range: 10.50.0.2 - 10.50.0.254 (server is 10.50.0.1)
    """
    for i in range(VPN_IP_START, VPN_IP_END + 1):
        candidate = f"10.50.0.{i}"
        if candidate not in used_ips:
            return candidate
    
    raise WireGuardError("No available IP addresses in VPN subnet")


# Global Cache for WireGuard Metrics
_metrics_cache: Dict[str, dict] = {}

async def get_connected_peers(use_cache: bool = True) -> Dict[str, dict]:
    """
    Get currently connected peers from WireGuard runtime or cache.
    Returns dict mapping public_key -> {endpoint, latest_handshake, transfer_rx, transfer_tx}
    Set use_cache=False to force a fresh poll from the system.
    
    CONNECTED LOGIC: A peer is "online" if their last handshake was within 180 seconds (3 mins).
    This accounts for WireGuard's PersistentKeepalive (25s) with buffer for network jitter.
    """
    import time
    global _metrics_cache
    
    HANDSHAKE_TIMEOUT = 300  # Seconds - 5 minutes for max mobile stability
    
    if use_cache and _metrics_cache:
        return _metrics_cache

    code, stdout, stderr = await run_command(["wg", "show", WG_INTERFACE, "dump"])
    if code != 0:
        return _metrics_cache # Return stale cache if command fails
    
    peers = {}
    lines = stdout.strip().split('\n')
    now = int(time.time())
    
    # Skip first line (interface info)
    for line in lines[1:]:
        parts = line.split('\t')
        if len(parts) >= 5:
            public_key = parts[0]
            endpoint = parts[2] if parts[2] != '(none)' else None
            latest_handshake = int(parts[4]) if parts[4] != '0' else None
            transfer_rx = int(parts[5]) if len(parts) > 5 else 0
            transfer_tx = int(parts[6]) if len(parts) > 6 else 0
            
            # FIXED: Check if handshake is RECENT, not just if it exists
            is_connected = False
            if latest_handshake is not None and latest_handshake > 0:
                handshake_age = now - latest_handshake
                is_connected = handshake_age < HANDSHAKE_TIMEOUT
            
            peers[public_key] = {
                'endpoint': endpoint,
                'latest_handshake': latest_handshake,
                'transfer_rx': transfer_rx,
                'transfer_tx': transfer_tx,
                'connected': is_connected
            }
    
    # Update global cache
    _metrics_cache = peers
    return peers


def read_config() -> str:
    """Read wg0.conf content."""
    if not WG_CONFIG_PATH.exists():
        raise WireGuardError(f"Config not found: {WG_CONFIG_PATH}")
    return WG_CONFIG_PATH.read_text()


def parse_config(content: str) -> Tuple[str, List[dict]]:
    """
    Parse wg0.conf into interface section and list of peers.
    Returns (interface_section, [peer_dicts])
    """
    # Split into sections, keeping the delimiters
    sections = re.split(r'(?=\[(?:Interface|Peer)\])', content.strip())
    
    interface = ""
    peers = []
    
    for section in sections:
        section = section.strip()
        if not section:
            continue
            
        if section.startswith('[Interface]'):
            # Capture EVERYTHING hasta the next section
            interface = section
        elif section.startswith('[Peer]'):
            peer = {'raw': section}
            
            # Extract PublicKey for comparison logic
            pk_match = re.search(r'PublicKey\s*=\s*(\S+)', section)
            if pk_match:
                peer['public_key'] = pk_match.group(1)
            
            peers.append(peer)
    
    if not interface:
        print("⚠️ Warning: No [Interface] section found during parse!")
        
    return interface, peers


def build_config(interface: str, peers: List[dict]) -> str:
    """
    Rebuild config from interface string and list of peer dicts.
    Handles both 'raw' blocks and structured dictionary data.
    """
    parts = [interface.strip()]
    for peer in peers:
        if 'raw' in peer:
            parts.append(peer['raw'].strip())
        else:
            # Generate from structured data
            block = f"[Peer]\nPublicKey = {peer['public_key']}\nAllowedIPs = {peer['allowed_ips']}"
            if 'persistent_keepalive' in peer:
                block += f"\nPersistentKeepalive = {peer['persistent_keepalive']}"
            parts.append(block)
    return '\n\n'.join(parts) + '\n'


def peer_exists_in_config(public_key: str) -> bool:
    """Check if a peer exists in wg0.conf."""
    try:
        content = read_config()
        return public_key in content
    except:
        return False


async def add_peer_to_config(public_key: str, allowed_ip: str, comment: str = None) -> None:
    """
    Add a new [Peer] block to wg0.conf.
    Uses file locking and atomic writes.
    """
    peer_block = f"""[Peer]"""
    if comment:
        peer_block += f"""\n# {comment}"""
    peer_block += f"""
PublicKey = {public_key}
AllowedIPs = {allowed_ip}/32"""
    
    # Open with lock
    fd = os.open(str(WG_CONFIG_PATH), os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        
        # Read current content
        with open(WG_CONFIG_PATH, 'r') as f:
            content = f.read()
        
        # Check for duplicate
        if public_key in content:
            raise WireGuardError("Public key already exists in config")
        
        # Create backup
        backup_path = WG_CONFIG_PATH.with_suffix('.conf.bak')
        shutil.copy2(WG_CONFIG_PATH, backup_path)
        
        # Append peer
        new_content = content.rstrip() + '\n\n' + peer_block + '\n'
        
        # Write to temp file
        temp_fd, temp_path = tempfile.mkstemp(
            dir=WG_CONFIG_PATH.parent,
            prefix='.wg0.',
            suffix='.tmp'
        )
        try:
            with os.fdopen(temp_fd, 'w') as tmp:
                tmp.write(new_content)
            os.chmod(temp_path, 0o600)
            os.rename(temp_path, WG_CONFIG_PATH)
        except:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise
        
        # Reload WireGuard
        success, error = await reload_wireguard()
        if not success:
            # Rollback
            shutil.copy2(backup_path, WG_CONFIG_PATH)
            await reload_wireguard()
            raise WireGuardError(f"WireGuard reload failed: {error}")
            
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


async def remove_peer_from_config(public_key: str) -> None:
    """
    Remove a [Peer] block from wg0.conf AND explicitly purge from Kernel.
    This is a double-tap removal to prevent Zombie peers.
    """
    # 1. EXPLICIT KERNEL REMOVAL (Immediate action)
    print(f"🧹 Purging peer {public_key[:8]}... from Kernel")
    await run_command(["wg", "set", WG_INTERFACE, "peer", public_key, "remove"])

    # 2. FILE SYSTEM SYNC
    fd = os.open(str(WG_CONFIG_PATH), os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        
        content = read_config()
        
        # Check if peer exists in file
        if public_key not in content:
            return
        
        # Parse and filter
        interface, peers = parse_config(content)
        peers = [p for p in peers if p.get('public_key') != public_key]
        
        # Rebuild config
        new_content = build_config(interface, peers)
        
        # Write atomically
        temp_fd, temp_path = tempfile.mkstemp(
            dir=WG_CONFIG_PATH.parent,
            prefix='.wg0.',
            suffix='.tmp'
        )
        try:
            with os.fdopen(temp_fd, 'w') as tmp:
                tmp.write(new_content)
            os.chmod(temp_path, 0o600)
            os.rename(temp_path, WG_CONFIG_PATH)
        except:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise
            
        # Optional: Syncconf to be absolutely sure
        await reload_wireguard()
            
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


async def reload_wireguard() -> Tuple[bool, str]:
    """
    Reload WireGuard configuration without bringing the interface down.
    Uses 'wg syncconf' for zero-downtime updates.
    """
    try:
        # 1. Create temporary strip config (removes wg-quick specific directives)
        print(f"🔧 [KERNEL] Stripping config {WG_CONFIG_PATH}...")
        code, stdout, stderr = await run_command(["wg-quick", "strip", str(WG_CONFIG_PATH)])
        if code != 0:
            msg = f"Failed to strip config: {stderr}"
            print(f"❌ [KERNEL] {msg}")
            return False, msg
        
        stripped_config = stdout
        
        # 2. Write to temp file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
            tmp.write(stripped_config)
            tmp_path = tmp.name
            
        try:
            # 3. Sync configuration to running interface
            print(f"🔧 [KERNEL] Executing wg syncconf {WG_INTERFACE}...")
            code, stdout, stderr = await run_command(["wg", "syncconf", WG_INTERFACE, tmp_path])
            
            success = code == 0
            error = stderr if not success else ""
            
            if not success:
                print(f"❌ [KERNEL] syncconf failed: {error}")
            else:
                print(f"✅ [KERNEL] Interface {WG_INTERFACE} state synchronized with disk.")
            
            log_wg_reload(success, error if error else None)
            return success, error
            
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        
    except Exception as e:
        print(f"🔥 [KERNEL] Reload exception: {e}")
        log_wg_reload(False, str(e))
        return False, str(e)


def generate_client_config(
    private_key: str,
    assigned_ip: str,
    server_public_key: str,
    client_os: str = 'android'
) -> str:
    """
    Generate the client configuration file content.
    For Linux: Uses PostUp/PostDown for DNS (avoids resolvconf issues).
    For Android/iOS: Uses standard config.
    """
    # Base configuration
    config = f"""[Interface]
PrivateKey = {private_key}
Address = {assigned_ip}/32
"""
    
    # DNS handling differs by OS
    if client_os == 'linux':
        # Linux: Don't use DNS= (resolvconf is inconsistent across distros)
        # Instead, use PostUp/PostDown to directly set DNS
        config += f"MTU = {CLIENT_MTU}\n"
        config += f"""
# Linux DNS & IPv6 Leak Prevention (Direct method - no resolvconf needed)
PreUp = sysctl -w net.ipv6.conf.all.disable_ipv6=1
PostUp = cp /etc/resolv.conf /etc/resolv.conf.wg-backup && echo "nameserver {CLIENT_DNS}" > /etc/resolv.conf
PostDown = mv /etc/resolv.conf.wg-backup /etc/resolv.conf || true
PostDown = sysctl -w net.ipv6.conf.all.disable_ipv6=0
"""
        allowed_ips = "0.0.0.0/0"
    else:
        # Non-Linux: Use standard DNS directive
        config += f"DNS = {CLIENT_DNS}\n"
        config += f"MTU = {CLIENT_MTU}\n"
        
        if client_os in ('macos', 'ios', 'android', 'windows'):
            allowed_ips = "0.0.0.0/0, ::/0"
        else:
            allowed_ips = "0.0.0.0/0"

    config += f"""
[Peer]
PublicKey = {server_public_key}
Endpoint = {VPN_SERVER_ENDPOINT}
AllowedIPs = {allowed_ips}
PersistentKeepalive = {PERSISTENT_KEEPALIVE}
"""
    return config

async def sync_wireguard_state():
    """
    ULTIMATE HOMEEOSTATIC SYNC:
    1. Removes any peer in Kernel not in DB.
    2. Overwrites wg0.conf to match DB exactly (Immune System).
    3. Updates/Adds all active users from DB.
    """
    from .database import get_all_users
    import tempfile
    import shutil
    
    print("🔄 STARTING COMPREHENSIVE MESH SYNC (v3.0.9)...")
    try:
        # 1. Get Truth from DB
        users = await get_all_users()
        active_users = [u for u in users if u.status == 'active']
        db_keys = {u.public_key for u in active_users}
        db_user_map = {u.public_key: u for u in active_users}

        # 2. Get Current Kernel State
        code, out, err = await run_command(["wg", "show", WG_INTERFACE, "peers"])
        if code != 0:
            print(f"❌ Failed to reach Kernel: {err}")
            return
        kernel_keys = set(out.strip().splitlines()) if out.strip() else set()

        # 3. IDENTIFY ZOMBIES (In Kernel but NOT in DB active list)
        zombies = kernel_keys - db_keys
        if zombies:
            print(f"🧟 Found {len(zombies)} Zombie peers in Kernel. Purging...")
            for z_key in zombies:
                await run_command(["wg", "set", WG_INTERFACE, "peer", z_key, "remove"])

        # 4. HOMEOSTATIC FILE SYNC (Overhaul wg0.conf)
        print("💾 Hardening File System (Immune System Sync)...")
        content = read_config()
        interface_cfg, _ = parse_config(content)
        
        if not interface_cfg:
            print("🚨 CRITICAL: Cannot find [Interface] section in wg0.conf! Aborting file overhaul to prevent corruption.")
        else:
            # Build new peers list for file
            new_file_peers = []
            for u in active_users:
                new_file_peers.append({
                    'public_key': u.public_key,
                    'allowed_ips': f"{u.assigned_ip}/32",
                    'persistent_keepalive': PERSISTENT_KEEPALIVE
                })
                
            new_content = build_config(interface_cfg, new_file_peers)
            
            # Write to wg0.conf atomically
            temp_fd, temp_path = tempfile.mkstemp(dir=WG_CONFIG_PATH.parent, prefix='.wg0.', suffix='.tmp')
            try:
                with os.fdopen(temp_fd, 'w') as tmp:
                    tmp.write(new_content)
                os.chmod(temp_path, 0o600)
                os.rename(temp_path, WG_CONFIG_PATH)
                print("✅ File System overhauled and hardened.")
            except Exception as file_err:
                print(f"❌ File Sync Failed: {file_err}")
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            
        # 5. ENFORCE ACTIVE PEERS in Kernel
        if not db_keys:
            print("✨ All peers purged from DB. Cleaning Kernel...")
            success, err = await reload_wireguard() # Sync kernel to empty (peers-wise) config
            if not success:
                print(f"❌ Failed to purge Kernel: {err}")
            return

        cmd = ["wg", "set", WG_INTERFACE]
        for key in db_keys:
            user = db_user_map[key]
            cmd.extend(["peer", key, "allowed-ips", f"{user.assigned_ip}/32"])
        
        print(f"⚡ Enforcing {len(db_keys)} Active peers in Kernel...")
        code, out, err = await run_command(cmd)
        if code != 0:
            print(f"❌ ENFORCEMENT FAILED: {err}")
        else:
            # Critical: Syncconf to ensure kernel matches the updated file
            success, err = await reload_wireguard()
            if not success:
                print(f"❌ Post-Sync Kernel reload failed: {err}")
            else:
                print("✅ Mesh state synchronized with Kernel and File System.")
            
    except Exception as e:
        print(f"🔥 FATAL SYNC ERROR: {e}")
        import traceback
        traceback.print_exc()
