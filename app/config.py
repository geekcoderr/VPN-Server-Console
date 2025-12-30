"""
Configuration for VPN Control Plane.
"""
import os
from pathlib import Path

# Paths
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
TEMPLATES_DIR = PROJECT_ROOT / "templates"

# WireGuard configuration
WG_CONFIG_PATH = Path("/etc/wireguard/wg0.conf")
WG_INTERFACE = "wg0"

# VPN Network Configuration
VPN_SUBNET = "10.50.0.0/24"
VPN_SERVER_IP = "10.50.0.1"
VPN_IP_START = 2      # First client IP: 10.50.0.2
VPN_IP_END = 254      # Last client IP: 10.50.0.254

# Server Endpoint
# FORCED to your domain. No environment variable fallback to avoid confusion.
VPN_SERVER_ENDPOINT = "wg.nishantmaheshwari.online:51820"

# Client config defaults
CLIENT_DNS = "1.1.1.1"
CLIENT_MTU = 1280
PERSISTENT_KEEPALIVE = 25

# Admin defaults
DEFAULT_ADMIN_USER = "geek"
DEFAULT_ADMIN_PASS = "ChangeMeNow123!"

# Session
SESSION_SECRET_KEY = os.getenv("SESSION_SECRET", "change-this-in-production-use-openssl-rand-hex-32")
SESSION_MAX_AGE = 86400  # 24 hours

# Audit log
AUDIT_LOG_PATH = DATA_DIR / "audit.log"
