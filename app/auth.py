"""
Admin authentication module.
Single admin user with bcrypt password hashing.
Session-based authentication with secure cookies.
"""
import bcrypt
from fastapi import APIRouter, Request, Response, HTTPException, Form, Depends
from fastapi.responses import RedirectResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from .database import get_admin, create_admin
from .config import SESSION_SECRET_KEY, SESSION_MAX_AGE, DEFAULT_ADMIN_USER, DEFAULT_ADMIN_PASS
from .audit import log_admin_login

router = APIRouter()

# Session serializer
serializer = URLSafeTimedSerializer(SESSION_SECRET_KEY)

SESSION_COOKIE_NAME = "vpn_admin_session"


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode(), password_hash.encode())


async def ensure_admin_exists():
    """Create default admin user if none exists."""
    admin = await get_admin()
    if not admin:
        password_hash = hash_password(DEFAULT_ADMIN_PASS)
        await create_admin(DEFAULT_ADMIN_USER, password_hash)


async def get_current_admin(request: Request) -> str:
    """
    Dependency to get current authenticated admin.
    Raises HTTPException if not authenticated.
    """
    session_cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_cookie:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        username = serializer.loads(session_cookie, max_age=SESSION_MAX_AGE)
        return username
    except (BadSignature, SignatureExpired):
        raise HTTPException(status_code=401, detail="Session expired")


def require_auth(request: Request) -> str:
    """
    Synchronous version for template rendering.
    Returns None if not authenticated (for redirect handling).
    """
    session_cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_cookie:
        return None
    
    try:
        username = serializer.loads(session_cookie, max_age=SESSION_MAX_AGE)
        return username
    except (BadSignature, SignatureExpired):
        return None


@router.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    """Process login form."""
    client_ip = request.client.host if request.client else "unknown"
    
    admin = await get_admin()
    if not admin or admin['username'] != username:
        log_admin_login(username, success=False, ip=client_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(password, admin['password_hash']):
        log_admin_login(username, success=False, ip=client_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create session
    session_token = serializer.dumps(username)
    
    log_admin_login(username, success=True, ip=client_ip)
    
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=True  # HTTPS enabled via Nginx
    )
    
    return response


@router.post("/logout")
async def logout():
    """Clear session and redirect to login."""
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


@router.get("/me")
async def get_me(admin: str = Depends(get_current_admin)):
    """Get current admin info."""
    return {"username": admin}


@router.post("/change-password")
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    admin: str = Depends(get_current_admin)
):
    """Change admin password."""
    admin_data = await get_admin()
    
    if not verify_password(current_password, admin_data['password_hash']):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    
    new_hash = hash_password(new_password)
    await create_admin(admin, new_hash)
    
    return {"message": "Password changed successfully"}
