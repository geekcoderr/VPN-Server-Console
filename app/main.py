"""
VPN Control Plane - FastAPI Application
Main entrypoint for the admin dashboard.
"""
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import TEMPLATES_DIR, DATA_DIR
from .database import init_db
from .auth import router as auth_router, ensure_admin_exists, require_auth
from .users import router as users_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler - runs on startup/shutdown."""
    # Startup
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    await init_db()
    await ensure_admin_exists()
    yield
    # Shutdown
    pass


app = FastAPI(
    title="VPN Control Plane",
    description="Commercial WireGuard VPN Management System",
    version="1.0.0",
    lifespan=lifespan
)

# Templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Include routers
app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(users_router)


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return {"status": "healthy", "service": "vpn-control"}


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page."""
    # If already authenticated, redirect to dashboard
    if require_auth(request):
        return RedirectResponse(url="/", status_code=303)
    
    return templates.TemplateResponse(
        "login.html",
        {"request": request}
    )


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Admin dashboard - main page."""
    admin = require_auth(request)
    if not admin:
        return RedirectResponse(url="/login", status_code=303)
    
    return templates.TemplateResponse(
        "admin.html",
        {"request": request, "admin": admin}
    )
