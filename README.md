# VPN Control Plane

Commercial-grade WireGuard VPN management system.

## Quick Start

```bash
# 1. Copy to server
sudo cp -r vpn-control /opt/

# 2. Create virtual environment
cd /opt/vpn-control
sudo python3 -m venv venv
sudo ./venv/bin/pip install -r requirements.txt

# 3. Configure (edit these values)
export VPN_ENDPOINT="your-vpn-server.com:51820"
export SESSION_SECRET=$(openssl rand -hex 32)

# 4. Install systemd service
sudo cp systemd/vpn-control.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-control

# 5. Access dashboard
curl http://127.0.0.1:8000/health
```

## Default Credentials

- **Username:** `geek`
- **Password:** `ChangeMeNow123!`

⚠️ Change these immediately after first login!

## Configuration

Edit `/opt/vpn-control/app/config.py` or set environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `VPN_ENDPOINT` | Server public hostname:port | `vpn.example.com:51820` |
| `SESSION_SECRET` | Session signing key | (auto-generated) |

## Nginx Reverse Proxy (Optional)

```nginx
server {
    listen 443 ssl;
    server_name vpn-admin.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Project Structure

```
/opt/vpn-control/
├── app/
│   ├── main.py      # FastAPI app
│   ├── auth.py      # Admin authentication
│   ├── users.py     # User lifecycle API
│   ├── wg.py        # WireGuard management
│   ├── qr.py        # QR code generation
│   ├── database.py  # SQLite models
│   ├── config.py    # Configuration
│   └── audit.py     # Audit logging
├── templates/
│   ├── login.html   # Login page
│   └── admin.html   # Dashboard
├── data/
│   ├── users.db     # User database
│   └── audit.log    # Audit log
└── systemd/
    └── vpn-control.service
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/` | Admin dashboard |
| GET | `/login` | Login page |
| POST | `/auth/login` | Login |
| POST | `/auth/logout` | Logout |
| GET | `/api/users` | List all users |
| POST | `/api/users` | Create user |
| DELETE | `/api/users/{username}` | Delete user |
| PATCH | `/api/users/{username}/toggle` | Enable/disable user |
| GET | `/api/users/{username}/config` | Regenerate config |

## Safety Features

- ✅ Atomic config updates with file locking
- ✅ Rollback on WireGuard reload failure
- ✅ No duplicate IPs or public keys
- ✅ Client private keys never stored
- ✅ Bcrypt password hashing
- ✅ Audit logging (metadata only)
