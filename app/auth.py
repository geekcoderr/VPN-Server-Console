"""
Admin authentication module.
Single admin user with bcrypt password hashing.
Session-based authentication with secure cookies.
"""
import bcrypt
from fastapi import APIRouter, Request, Response, HTTPException, Form, Depends
from fastapi.responses import RedirectResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from .database import get_admin, create_admin, AsyncSessionLocal, Admin
from .config import SESSION_SECRET_KEY, SESSION_MAX_AGE, DEFAULT_ADMIN_USER, DEFAULT_ADMIN_PASS
from .audit import log_admin_login
from .totp import random_base32, get_provisioning_uri, verify_totp
from .qr import generate_qr_data_uri
from .limiter import limiter
from sqlalchemy import update

router = APIRouter()

SESSION_COOKIE_NAME = "admin_session"
serializer = URLSafeTimedSerializer(SESSION_SECRET_KEY)

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash."""
    return bcrypt.checkpw(password.encode(), hashed.encode())

async def get_current_admin(request: Request) -> str:
    """Dependency to get current admin from session cookie."""
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        username = serializer.loads(session_token, max_age=SESSION_MAX_AGE)
        return username
    except (BadSignature, SignatureExpired):
        raise HTTPException(status_code=401, detail="Invalid or expired session")

async def ensure_admin_exists():
    """Ensure at least one admin exists in the database."""
    admin = await get_admin()
    if not admin:
        print(f"Creating default admin: {DEFAULT_ADMIN_USER}")
        hashed = hash_password(DEFAULT_ADMIN_PASS)
        await create_admin(DEFAULT_ADMIN_USER, hashed)

@router.post("/login")
@limiter.limit("5/minute")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    totp_code: str = Form(None)
):
    """Process login form."""
    # Get real client IP (handle Nginx proxy)
    client_ip = request.headers.get("X-Forwarded-For")
    if client_ip:
        client_ip = client_ip.split(",")[0].strip()
    else:
        client_ip = request.client.host if request.client else "unknown"
    
    admin = await get_admin()
    if not admin or admin['username'] != username:
        log_admin_login(username, success=False, ip=client_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(password, admin['password_hash']):
        log_admin_login(username, success=False, ip=client_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # 2FA Check
    if admin.get('totp_secret'):
        if not totp_code:
            # Signal frontend to show 2FA input
            raise HTTPException(status_code=403, detail="2FA Required")
        
        if not verify_totp(admin['totp_secret'], totp_code):
            log_admin_login(username, success=False, ip=client_ip)
            raise HTTPException(status_code=401, detail="Invalid 2FA Code")
    
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

@router.get("/csrf")
async def get_csrf_token(csrf_protect: CsrfProtect = Depends()):
    """Provide a CSRF token to the frontend."""
    token = csrf_protect.generate_csrf()
    response = JSONResponse(content={"csrf_token": token})
    csrf_protect.set_csrf_cookie(token, response)
    return response


@router.get("/me")
async def get_me(admin: str = Depends(get_current_admin)):
    """Get current admin info."""
    admin_data = await get_admin()
    return {
        "username": admin,
        "2fa_enabled": bool(admin_data.get('totp_secret'))
    }


from pydantic import BaseModel
from fastapi_csrf_protect import CsrfProtect

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str

@router.put("/password")
@limiter.limit("3/hour")
async def change_password(
    request: PasswordChangeRequest,
    csrf_protect: CsrfProtect = Depends(),
    admin: str = Depends(get_current_admin)
):
    """Change admin password with CSRF protection."""
    await csrf_protect.validate_csrf(request)
    admin_data = await get_admin()
    
    if not verify_password(request.current_password, admin_data['password_hash']):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    if len(request.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    
    new_hash = hash_password(request.new_password)
    await create_admin(admin, new_hash)
    
    return {"message": "Password changed successfully"}

@router.post("/2fa/setup")
@limiter.limit("5/hour")
async def setup_2fa(
    csrf_protect: CsrfProtect = Depends(),
    admin: str = Depends(get_current_admin)
):
    """Setup 2FA with CSRF protection."""
    secret = random_base32()
    uri = get_provisioning_uri(admin, secret)
    qr = generate_qr_data_uri(uri)
    return {"secret": secret, "qr_code": qr}

class TOTPVerifyRequest(BaseModel):
    secret: str
    code: str

@router.post("/2fa/verify")
async def verify_2fa_setup(
    request: TOTPVerifyRequest,
    csrf_protect: CsrfProtect = Depends(),
    admin: str = Depends(get_current_admin)
):
    """Verify 2FA setup with CSRF protection."""
    await csrf_protect.validate_csrf(request)
    if verify_totp(request.secret, request.code):
        # Save to DB
        async with AsyncSessionLocal() as session:
            await session.execute(update(Admin).where(Admin.username == admin).values(totp_secret=request.secret))
            await session.commit()
        return {"status": "enabled"}
    raise HTTPException(status_code=400, detail="Invalid code")

@router.post("/2fa/disable")
async def disable_2fa(
    request: Request,
    password: str = Form(...),
    csrf_protect: CsrfProtect = Depends(),
    admin: str = Depends(get_current_admin)
):
    """Disable 2FA with CSRF protection."""
    await csrf_protect.validate_csrf(request)
    admin_data = await get_admin()
    if not verify_password(password, admin_data['password_hash']):
        raise HTTPException(status_code=400, detail="Invalid password")
        
    async with AsyncSessionLocal() as session:
        await session.execute(update(Admin).where(Admin.username == admin).values(totp_secret=None))
        await session.commit()
    return {"status": "disabled"}
