"""
User lifecycle management module.
Handles creation, deletion, enable/disable of VPN users.
"""
import re
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, validator

from .auth import get_current_admin
from .database import (
    get_all_users,
    get_user_by_username,
    create_user,
    update_user_status,
    delete_user as db_delete_user,
    get_used_ips,
)
from .wg import (
    generate_keypair,
    get_server_public_key,
    allocate_ip,
    add_peer_to_config,
    remove_peer_from_config,
    generate_client_config,
    get_connected_peers,
    peer_exists_in_config,
    WireGuardError,
)
from .qr import generate_qr_data_uri
from .audit import log_user_created, log_user_deleted, log_user_disabled, log_user_enabled

router = APIRouter(prefix="/api/users", tags=["users"])


class CreateUserRequest(BaseModel):
    username: str
    client_os: str = 'android'
    
    @validator('username')
    def validate_username(cls, v):
        if not v or len(v) < 2:
            raise ValueError("Username must be at least 2 characters")
        if len(v) > 32:
            raise ValueError("Username must be at most 32 characters")
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError("Username can only contain letters, numbers, underscores, and hyphens")
        return v.lower()

    @validator('client_os')
    def validate_client_os(cls, v):
        if v not in ('android', 'linux', 'ios', 'windows', 'macos'):
            raise ValueError("Invalid client OS. Must be: android, linux, ios, windows, macos")
        return v.lower()


class UserResponse(BaseModel):
    id: int
    username: str
    public_key: str
    assigned_ip: str
    client_os: str
    status: str
    created_at: str


class CreateUserResponse(BaseModel):
    user: UserResponse
    client_config: str
    qr_code: str


@router.get("")
async def list_users(admin: str = Depends(get_current_admin)):
    """List all VPN users with connection status."""
    users = await get_all_users()
    
    # Get connected peers from WireGuard
    connected = await get_connected_peers()
    
    # Enrich users with connection info
    for user in users:
        peer_info = connected.get(user['public_key'], {})
        user['connected'] = peer_info.get('connected', False)
        user['endpoint'] = peer_info.get('endpoint')
        user['transfer_rx'] = peer_info.get('transfer_rx', 0)
        user['transfer_tx'] = peer_info.get('transfer_tx', 0)
    
    return {"users": users}


@router.post("")
async def create_vpn_user(
    request: CreateUserRequest,
    admin: str = Depends(get_current_admin)
):
    """
    Create a new VPN user.
    
    Flow:
    1. Generate keypair
    2. Allocate next free IP
    3. Add peer to wg0.conf (atomic) - FIRST
    4. Reload WireGuard
    5. Only then save to database
    6. Generate client config + QR
    """
    username = request.username
    client_os = request.client_os
    
    # Check if user already exists
    existing = await get_user_by_username(username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    try:
        # Generate keypair
        private_key, public_key = await generate_keypair()
        
        # Allocate IP
        used_ips = await get_used_ips()
        assigned_ip = allocate_ip(used_ips)
        
        # Add to WireGuard config FIRST (this is the critical operation)
        # If this fails, nothing is saved to DB
        await add_peer_to_config(public_key, assigned_ip, username)
        
        # Now save to database (WireGuard already has the peer)
        await create_user(username, public_key, assigned_ip, client_os)
        
        # Get server public key for client config
        server_public_key = await get_server_public_key()
        
        # Generate client config
        client_config = generate_client_config(private_key, assigned_ip, server_public_key, client_os)
        
        # Generate QR code
        qr_code = generate_qr_data_uri(client_config)
        
        # Audit log
        log_user_created(username, assigned_ip, admin)
        
        # Fetch created user
        user = await get_user_by_username(username)
        
        return {
            "user": user,
            "client_config": client_config,
            "qr_code": qr_code
        }
        
    except WireGuardError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create user: {str(e)}")


@router.delete("/{username}")
async def delete_vpn_user(
    username: str,
    admin: str = Depends(get_current_admin)
):
    """
    Delete a VPN user.
    Removes from both WireGuard config and database.
    """
    user = await get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    try:
        # Remove from WireGuard config (idempotent - won't fail if not present)
        await remove_peer_from_config(user['public_key'])
        
        # Delete from database
        await db_delete_user(username)
        
        # Audit log
        log_user_deleted(username, admin)
        
        return {"message": f"User {username} deleted successfully"}
        
    except WireGuardError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete user: {str(e)}")


@router.patch("/{username}/toggle")
async def toggle_user_status(
    username: str,
    admin: str = Depends(get_current_admin)
):
    """
    Toggle user status between active and disabled.
    """
    user = await get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    try:
        if user['status'] == 'active':
            # Disable: remove from config
            await remove_peer_from_config(user['public_key'])
            await update_user_status(username, 'disabled')
            log_user_disabled(username, admin)
            return {"message": f"User {username} disabled", "status": "disabled"}
        else:
            # Re-enable: add back to config
            await add_peer_to_config(user['public_key'], user['assigned_ip'], username)
            await update_user_status(username, 'active')
            log_user_enabled(username, admin)
            return {"message": f"User {username} enabled", "status": "active"}
            
    except WireGuardError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to toggle user: {str(e)}")


@router.get("/{username}/config")
async def get_user_config(
    username: str,
    admin: str = Depends(get_current_admin)
):
    """
    Regenerate config for an existing user.
    WARNING: This generates a NEW keypair. The old config will stop working.
    """
    user = await get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user['status'] != 'active':
        raise HTTPException(status_code=400, detail="Cannot regenerate config for disabled user")
    
    try:
        # Generate new keypair
        private_key, public_key = await generate_keypair()
        
        # Remove old peer (idempotent)
        await remove_peer_from_config(user['public_key'])
        
        # Add new peer
        await add_peer_to_config(public_key, user['assigned_ip'])
        
        # Update database with new public key
        from .database import DB_PATH
        import aiosqlite
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE users SET public_key = ? WHERE username = ?",
                (public_key, username)
            )
            await db.commit()
        
        # Get server public key
        server_public_key = await get_server_public_key()
        
        # Generate client config
        client_config = generate_client_config(private_key, user['assigned_ip'], server_public_key)
        
        # Generate QR
        qr_code = generate_qr_data_uri(client_config)
        
        return {
            "client_config": client_config,
            "qr_code": qr_code
        }
        
    except WireGuardError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to regenerate config: {str(e)}")


@router.post("/{username}/sync")
async def sync_user_to_config(
    username: str,
    admin: str = Depends(get_current_admin)
):
    """
    Sync a user from database to WireGuard config.
    Use this to fix users that exist in DB but not in wg0.conf.
    """
    user = await get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user['status'] != 'active':
        raise HTTPException(status_code=400, detail="User is disabled")
    
    try:
        # Check if already in config
        if peer_exists_in_config(user['public_key']):
            return {"message": "User already synced", "status": "ok"}
        
        # Add to config
        await add_peer_to_config(user['public_key'], user['assigned_ip'])
        
        return {"message": f"User {username} synced to WireGuard", "status": "synced"}
        
    except WireGuardError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sync_all")
async def sync_all_users(admin: str = Depends(get_current_admin)):
    """
    Sync ALL active users from DB to WireGuard config.
    Useful if multiple users are missing from wg0.conf.
    """
    users = await get_all_users()
    synced_count = 0
    errors = []
    
    for user in users:
        if user['status'] == 'active':
            try:
                if not peer_exists_in_config(user['public_key']):
                    await add_peer_to_config(user['public_key'], user['assigned_ip'])
                    synced_count += 1
            except Exception as e:
                errors.append(f"{user['username']}: {str(e)}")
    
    return {
        "message": f"Synced {synced_count} users",
        "errors": errors if errors else None
    }
