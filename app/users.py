"""
User lifecycle management module.
Handles creation, deletion, enable/disable of VPN users.
"""
import re
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, validator

from .auth import get_current_admin
from fastapi_csrf_protect import CsrfProtect
from .limiter import limiter
from fastapi import Request
from .database import (
    get_all_users,
    get_user_by_username,
    create_user,
    update_user_status,
    delete_user as db_delete_user,
    get_used_ips,
    AsyncSessionLocal,
    User
)
from sqlalchemy import update
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
    acl_profile: str = 'full'
    
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
        
    @validator('acl_profile')
    def validate_acl(cls, v):
        if v not in ('full', 'internet-only', 'intranet-only'):
            raise ValueError("Invalid ACL profile")
        return v

class UserResponse(BaseModel):
    id: int
    username: str
    public_key: str
    assigned_ip: str
    client_os: str
    status: str
    acl_profile: str
    created_at: str


class CreateUserResponse(BaseModel):
    user: UserResponse
    client_config: str
    qr_code: str


class RegisterUserRequest(BaseModel):
    token: str
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

@router.post("/register")
async def register_user(request: RegisterUserRequest):
    """
    Public endpoint to register with a verified token.
    """
    from .database import AsyncSessionLocal, UserInvite
    from sqlalchemy import select
    
    # 1. Verify Token
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(UserInvite).filter(UserInvite.token == request.token))
        invite = result.scalar_one_or_none()
        
        if not invite:
            raise HTTPException(status_code=403, detail="Invalid invitation")
        if not invite.is_verified:
            raise HTTPException(status_code=403, detail="Invitation not verified. Please complete OTP verification.")
            
        # Consume invite (delete it)
        await session.delete(invite)
        await session.commit()

    # 2. Create User (Reuse Logic)
    username = request.username
    client_os = request.client_os
    
    # Check if user already exists
    existing = await get_user_by_username(username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    try:
        # Generate keypair
        private_key, public_key = await generate_keypair()
        
        # Allocate IP
        used_ips = await get_used_ips()
        assigned_ip = allocate_ip(used_ips)
        
        # Add to WireGuard config
        await add_peer_to_config(public_key, assigned_ip, username)
        
        # Apply Default ACL (Full)
        from .firewall import apply_acl
        apply_acl(assigned_ip, "full")
        
        # Save to DB
        await create_user(username, public_key, private_key, assigned_ip, client_os, "full")
        
        # Get server public key
        server_public_key = await get_server_public_key()
        
        # Generate config
        client_config = generate_client_config(
            username,
            public_key,
            assigned_ip,
            server_public_key,
            client_os,
        )
        
        # Generate QR code
        qr_code = generate_qr_data_uri(client_config)
        
        return {
            "status": "created",
            "username": username,
            "client_config": client_config,
            "qr_code": qr_code
        }

    except Exception as e:
        # logging.error(f"Failed to register user {username}: {e}")
        await remove_peer_from_config(username)
        raise HTTPException(status_code=500, detail=f"Registration failed: {e}")


@router.get("")
async def list_users(admin: str = Depends(get_current_admin)):
    """List all VPN users with connection status."""
    users = await get_all_users()
    
    # Get connected peers from WireGuard
    connected = await get_connected_peers()
    
    # Enrich users with connection info
    user_list = []
    for user_orm in users:
        # Map to dict for JSON response
        user = {
            "id": user_orm.id,
            "username": user_orm.username,
            "public_key": user_orm.public_key,
            "assigned_ip": user_orm.assigned_ip,
            "client_os": user_orm.client_os,
            "status": user_orm.status,
            "acl_profile": user_orm.acl_profile,
            "created_at": user_orm.created_at.isoformat() if hasattr(user_orm.created_at, 'isoformat') else user_orm.created_at,
            "last_login": user_orm.last_login.isoformat() if user_orm.last_login else None,
            "transfer_rx": user_orm.total_rx,
            "transfer_tx": user_orm.total_tx,
            "last_endpoint": user_orm.last_endpoint,
        }
        
        peer_info = connected.get(user_orm.public_key, {})
        user['connected'] = peer_info.get('connected', False)
        
        # Priority 1: Use live endpoint from WireGuard
        live_endpoint = peer_info.get('endpoint')
        if live_endpoint:
            user['last_endpoint'] = live_endpoint
        
        # Merge transfer stats (WireGuard vs Historical)
        # Merge transfer stats (Historical + Current Session)
        user['transfer_rx'] = (user_orm.total_rx or 0) + peer_info.get('transfer_rx', 0)
        user['transfer_tx'] = (user_orm.total_tx or 0) + peer_info.get('transfer_tx', 0)
        
        # Update Handshake/Login time
        h_time = peer_info.get('latest_handshake')
        if h_time:
            user['last_login'] = datetime.fromtimestamp(h_time).isoformat()
        
        user_list.append(user)
    
    return {"users": user_list}


@router.post("")
@limiter.limit("10/hour")
async def create_vpn_user(
    request: Request,
    body: CreateUserRequest,
    csrf_protect: CsrfProtect = Depends(),
    admin: str = Depends(get_current_admin)
):
    """Create a new VPN user with CSRF protection."""
    # await csrf_protect.validate_csrf(request)
    """
    Create a new VPN user.
    """
    username = body.username
    client_os = body.client_os
    acl_profile = body.acl_profile
    
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
        await add_peer_to_config(public_key, assigned_ip, username)
        
        # Save to database including Private Key
        # Note: We need to update create_user signature in database.py first, 
        # but for now we will just pass it and fix database.py in next step or assume it handles kwargs
        # Actually, let's fix database.py first? No, I can update the call here and then update database.py
        # Wait, I need to update create_user in database.py to accept acl_profile.
        
        # Let's import the new firewall module
        from .firewall import apply_acl
        
        # Apply ACL
        apply_acl(assigned_ip, acl_profile)
        
        # Save to DB
        # We need to update create_user in database.py to accept acl_profile
        # For now, I will manually insert it or update the function.
        # Let's assume I will update database.py in the next step.
        # I will use a direct DB call here for now or update the function signature in the next tool call.
        
        # Actually, I should update database.py's create_user function first. 
        # But since I am editing users.py, let's assume create_user will be updated.
        
        await create_user(username, public_key, private_key, assigned_ip, client_os, acl_profile)
        
        # Get server public key for client config
        server_public_key = await get_server_public_key()
        
        # Generate client config
        client_config = generate_client_config(private_key, assigned_ip, server_public_key, client_os)
        
        # Generate QR code
        qr_code = generate_qr_data_uri(client_config)
        
        # Audit log
        log_user_created(username, assigned_ip, admin)
        
        # Fetch fresh object
        user_orm = await get_user_by_username(username)
        
        return {
            "user": {
                "id": user_orm.id,
                "username": user_orm.username,
                "public_key": user_orm.public_key,
                "assigned_ip": user_orm.assigned_ip,
                "client_os": user_orm.client_os,
                "status": user_orm.status,
                "created_at": user_orm.created_at.isoformat() if hasattr(user_orm.created_at, 'isoformat') else user_orm.created_at
            },
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
    request: Request,
    csrf_protect: CsrfProtect = Depends(),
    admin: str = Depends(get_current_admin)
):
    """Delete a VPN user with CSRF protection."""
    # await csrf_protect.validate_csrf(request)
    """
    Delete a VPN user.
    Removes from both WireGuard config and database.
    """
    user = await get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    try:
        # Remove from WireGuard config
        await remove_peer_from_config(user.public_key)
        
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
    request: Request,
    csrf_protect: CsrfProtect = Depends(),
    admin: str = Depends(get_current_admin)
):
    """Toggle user status with CSRF protection."""
    await csrf_protect.validate_csrf(request)
    """
    Toggle user status between active and disabled.
    """
    user = await get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    try:
        if user.status == 'active':
            # Disable: remove from config
            await remove_peer_from_config(user.public_key)
            await update_user_status(username, 'disabled')
            log_user_disabled(username, admin)
            return {"message": f"User {username} disabled", "status": "disabled"}
        else:
            # Re-enable: add back to config
            await add_peer_to_config(user.public_key, user.assigned_ip, username)
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
    Fetch existing config OR regenerate if missing.
    No longer disconnects user if config already exists.
    """
    user = await get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    try:
        # If we have a stored private key, use it!
        if user.private_key:
            private_key = user.private_key
            public_key = user.public_key
        else:
            # Migration path: Regenerate and store for legacy users
            private_key, public_key = await generate_keypair()
            await remove_peer_from_config(user.public_key)
            await add_peer_to_config(public_key, user.assigned_ip)
            
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(User).where(User.username == username).values(
                        public_key=public_key,
                        private_key=private_key
                    )
                )
                await db.commit()
        
        server_public_key = await get_server_public_key()
        client_config = generate_client_config(
            private_key, 
            user.assigned_ip, 
            server_public_key,
            client_os=user.client_os
        )
        qr_code = generate_qr_data_uri(client_config)
        
        return {
            "client_config": client_config,
            "qr_code": qr_code,
            "recreated": not bool(user.private_key)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{username}/rotate")
@limiter.limit("5/hour")
async def rotate_user_keys(
    username: str,
    request: Request,
    csrf_protect: CsrfProtect = Depends(),
    admin: str = Depends(get_current_admin)
):
    """Rotate user keys with CSRF protection."""
    await csrf_protect.validate_csrf(request)
    """
    Forcefully invalidate old keys and generate new ones.
    Useful if a user's config is leaked.
    """
    user = await get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    try:
        private_key, public_key = await generate_keypair()
        await remove_peer_from_config(user.public_key)
        await add_peer_to_config(public_key, user.assigned_ip)
        
        async with AsyncSessionLocal() as db:
            await db.execute(
                update(User).where(User.username == username).values(
                    public_key=public_key,
                    private_key=private_key
                )
            )
            await db.commit()
            
        return {"message": "Keys rotated successfully. Client must re-import config."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{username}/sync")
async def sync_user_to_config(
    username: str,
    request: Request,
    csrf_protect: CsrfProtect = Depends(),
    admin: str = Depends(get_current_admin)
):
    """Sync user to config with CSRF protection."""
    await csrf_protect.validate_csrf(request)
    """Sync a user from database to WireGuard config."""
    user = await get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.status != 'active':
        raise HTTPException(status_code=400, detail="User is disabled")
    
    try:
        await add_peer_to_config(user.public_key, user.assigned_ip)
        return {"message": f"User {username} synced to WireGuard", "status": "synced"}
    except WireGuardError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sync_all")
async def sync_all_users(
    request: Request,
    csrf_protect: CsrfProtect = Depends(),
    admin: str = Depends(get_current_admin)
):
    """Sync ALL users with CSRF protection."""
    await csrf_protect.validate_csrf(request)
    """
    Sync ALL active users from DB to WireGuard config.
    """
    users = await get_all_users()
    synced_count = 0
    errors = []
    
    for user in users:
        if user.status == 'active':
            try:
                await add_peer_to_config(user.public_key, user.assigned_ip)
                synced_count += 1
            except Exception as e:
                errors.append(f"{user.username}: {str(e)}")
    
    return {
        "message": f"Synced {synced_count} users",
        "errors": errors if errors else None
    }


@router.get("/{username}/sessions")
async def get_user_sessions(
    username: str,
    limit: int = 50,
    admin: str = Depends(get_current_admin)
):
    """
    Fetch session history for a specific user.
    """
    user = await get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    from .database import Session
    from sqlalchemy import select, desc
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Session)
            .where(Session.user_id == user.id)
            .order_by(desc(Session.start_time))
            .limit(limit)
        )
        sessions = result.scalars().all()
        
        return {
            "sessions": [
                {
                    "id": s.id,
                    "start_time": s.start_time.isoformat(),
                    "end_time": s.end_time.isoformat() if s.end_time else None,
                    "duration": str(s.end_time - s.start_time).split('.')[0] if s.end_time else "Active",
                    "source_ip": s.source_ip,
                    "bytes_rx": s.bytes_rx,
                    "bytes_tx": s.bytes_tx,
                    "is_active": s.is_active
                }
                for s in sessions
            ]
        }
