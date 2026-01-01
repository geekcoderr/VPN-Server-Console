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


async def get_connected_peers() -> Dict[str, dict]:
    """
    Get currently connected peers from WireGuard runtime.
    Returns dict mapping public_key -> {endpoint, latest_handshake, transfer_rx, transfer_tx}
    """
    code, stdout, stderr = await run_command(["wg", "show", WG_INTERFACE, "dump"])
    if code != 0:
        return {}
    
    peers = {}
    lines = stdout.strip().split('\n')
    
    # Skip first line (interface info)
    for line in lines[1:]:
        parts = line.split('\t')
        if len(parts) >= 5:
            public_key = parts[0]
            endpoint = parts[2] if parts[2] != '(none)' else None
            latest_handshake = int(parts[4]) if parts[4] != '0' else None
            transfer_rx = int(parts[5]) if len(parts) > 5 else 0
            transfer_tx = int(parts[6]) if len(parts) > 6 else 0
            
            peers[public_key] = {
                'endpoint': endpoint,
                'latest_handshake': latest_handshake,
                'transfer_rx': transfer_rx,
                'transfer_tx': transfer_tx,
                'connected': latest_handshake is not None and latest_handshake > 0
            }
    
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
    # Split into sections
    sections = re.split(r'(?=\[(?:Interface|Peer)\])', content.strip())
    
    interface = ""
    peers = []
    
    for section in sections:
        section = section.strip()
        if not section:
            continue
            
        if section.startswith('[Interface]'):
            interface = section
        elif section.startswith('[Peer]'):
            peer = {'raw': section}
            
            # Extract PublicKey
            pk_match = re.search(r'PublicKey\s*=\s*(\S+)', section)
            if pk_match:
                peer['public_key'] = pk_match.group(1)
            
            # Extract AllowedIPs
            ip_match = re.search(r'AllowedIPs\s*=\s*(\S+)', section)
            if ip_match:
                peer['allowed_ips'] = ip_match.group(1)
            
            peers.append(peer)
    
    return interface, peers


def build_config(interface: str, peers: List[dict]) -> str:
    """Rebuild config from interface and peers."""
    parts = [interface.strip()]
    for peer in peers:
        parts.append(peer['raw'].strip())
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
    Remove a [Peer] block from wg0.conf by public key.
    """
    fd = os.open(str(WG_CONFIG_PATH), os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        
        content = read_config()
        
        # Check if peer exists
        if public_key not in content:
            # Peer not in config - just return success (idempotent)
            return
        
        # Parse and filter
        interface, peers = parse_config(content)
        original_count = len(peers)
        peers = [p for p in peers if p.get('public_key') != public_key]
        
        if len(peers) == original_count:
            # Peer not found - already removed
            return
        
        # Backup
        backup_path = WG_CONFIG_PATH.with_suffix('.conf.bak')
        shutil.copy2(WG_CONFIG_PATH, backup_path)
        
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
        
        # Reload
        success, error = await reload_wireguard()
        if not success:
            shutil.copy2(backup_path, WG_CONFIG_PATH)
            await reload_wireguard()
            raise WireGuardError(f"WireGuard reload failed: {error}")
            
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
        # wg-quick strip outputs the raw config that `wg` command accepts
        code, stdout, stderr = await run_command(["wg-quick", "strip", str(WG_CONFIG_PATH)])
        if code != 0:
            return False, f"Failed to strip config: {stderr}"
        
        stripped_config = stdout
        
        # 2. Write to temp file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
            tmp.write(stripped_config)
            tmp_path = tmp.name
            
        try:
            # 3. Sync configuration to running interface
            code, stdout, stderr = await run_command(["wg", "syncconf", WG_INTERFACE, tmp_path])
            
            success = code == 0
            error = stderr if not success else ""
            
            log_wg_reload(success, error if error else None)
            return success, error
            
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        
    except Exception as e:
        log_wg_reload(False, str(e))
        return False, str(e)


def generate_client_config(
    private_key: str,
    assigned_ip: str,
    server_public_key: str
) -> str:
    """
    Generate the client configuration file content.
    This is what gets encoded in the QR code.
    """
    return f"""[Interface]
PrivateKey = {private_key}
Address = {assigned_ip}/32,fd42:42:42::{assigned_ip.split('.')[-1]}/128
DNS = {CLIENT_DNS}
MTU = {CLIENT_MTU}

[Peer]
PublicKey = {server_public_key}
Endpoint = {VPN_SERVER_ENDPOINT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = {PERSISTENT_KEEPALIVE}
"""
