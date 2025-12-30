"""
Audit logging module.
All admin actions are logged to a JSON-lines file.
NEVER logs traffic content - metadata only.
"""
import json
from datetime import datetime
from pathlib import Path
from .config import AUDIT_LOG_PATH


def log_action(action: str, username: str, details: dict = None, admin: str = None):
    """
    Log an admin action to the audit log.
    
    Args:
        action: Action type (e.g., 'user_created', 'user_deleted')
        username: The VPN user affected
        details: Additional metadata (never traffic content)
        admin: Admin who performed the action
    """
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "action": action,
        "username": username,
        "admin": admin,
        "details": details or {}
    }
    
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def log_user_created(username: str, assigned_ip: str, admin: str = None):
    """Log user creation."""
    log_action("user_created", username, {"assigned_ip": assigned_ip}, admin)


def log_user_deleted(username: str, admin: str = None):
    """Log user deletion."""
    log_action("user_deleted", username, admin=admin)


def log_user_disabled(username: str, admin: str = None):
    """Log user disabled."""
    log_action("user_disabled", username, admin=admin)


def log_user_enabled(username: str, admin: str = None):
    """Log user enabled."""
    log_action("user_enabled", username, admin=admin)


def log_admin_login(admin: str, success: bool, ip: str = None):
    """Log admin login attempt."""
    log_action(
        "admin_login_success" if success else "admin_login_failed",
        admin,
        {"ip": ip}
    )


def log_wg_reload(success: bool, error: str = None):
    """Log WireGuard reload attempt."""
    log_action(
        "wg_reload",
        "system",
        {"success": success, "error": error}
    )
