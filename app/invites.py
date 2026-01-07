from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, update
from datetime import datetime, timedelta
import secrets
import string

from .database import AsyncSessionLocal, UserInvite
from .auth import get_current_admin
from .email import send_email
from .config import VPN_SERVER_ENDPOINT

router = APIRouter(prefix="/api/invites", tags=["invites"])

class InviteRequest(BaseModel):
    email: str

class VerifyOTPRequest(BaseModel):
    otp: str

def generate_token():
    return secrets.token_urlsafe(32)

def generate_otp():
    return ''.join(secrets.choice(string.digits) for _ in range(6))

@router.post("")
async def create_invite(req: InviteRequest, admin: str = Depends(get_current_admin)):
    token = generate_token()
    
    async with AsyncSessionLocal() as session:
        # Check if email already invited
        existing = await session.execute(select(UserInvite).filter(UserInvite.email == req.email))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Email already invited")
            
        invite = UserInvite(email=req.email, token=token)
        session.add(invite)
        await session.commit()
        
    # Send Email
    link = f"https://{VPN_SERVER_ENDPOINT.split(':')[0]}/register?token={token}"
    body = f"You have been invited to join the VPN.\n\nClick here to register: {link}"
    send_email(req.email, "VPN Invitation", body)
    
    return {"status": "invited", "token": token} # Return token for debug/manual sharing

@router.get("/{token}")
async def get_invite(token: str):
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(UserInvite).filter(UserInvite.token == token))
        invite = result.scalar_one_or_none()
        
        if not invite:
            raise HTTPException(status_code=404, detail="Invalid token")
            
        return {"email": invite.email, "is_verified": invite.is_verified}

@router.post("/{token}/otp")
async def request_otp(token: str):
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(UserInvite).filter(UserInvite.token == token))
        invite = result.scalar_one_or_none()
        
        if not invite:
            raise HTTPException(status_code=404, detail="Invalid token")
            
        otp = generate_otp()
        expires = datetime.now() + timedelta(minutes=10)
        
        invite.otp = otp
        invite.otp_expires_at = expires
        await session.commit()
        
        # Send Email
        send_email(invite.email, "VPN Verification Code", f"Your OTP is: {otp}")
        
        return {"status": "sent"}

@router.post("/{token}/verify")
async def verify_otp(token: str, req: VerifyOTPRequest):
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(UserInvite).filter(UserInvite.token == token))
        invite = result.scalar_one_or_none()
        
        if not invite:
            raise HTTPException(status_code=404, detail="Invalid token")
            
        if not invite.otp or invite.otp != req.otp:
            raise HTTPException(status_code=400, detail="Invalid OTP")
            
        if datetime.now() > invite.otp_expires_at:
            raise HTTPException(status_code=400, detail="OTP expired")
            
        invite.is_verified = True
        invite.otp = None # Clear OTP after use
        await session.commit()
        
        return {"status": "verified"}
