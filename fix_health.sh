#!/bin/bash
# VPN Control Plane - Medical Health & Recovery Script (v2.6.2)
# Resolves: MySQL Redo Log Permission Errors (Error 13) & Docker Command Compatibility

echo "🎭 Starting Infinity-Fix Recovery (v2)..."

# 0. Detect Docker Compose Version
COMPOSE_CMD=""
if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
    echo "✅ Detected Plugin: docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
    echo "✅ Detected Binary: docker-compose"
else
    echo "❌ Error: Neither 'docker compose' nor 'docker-compose' found. Please install one."
    exit 1
fi

# 1. STOP Services First (Critical)
echo "🛑 Stopping Mesh Services to safely fix storage..."
$COMPOSE_CMD -f docker-compose.db.yml down
$COMPOSE_CMD -f docker-compose.yml down
sudo systemctl stop vpn-control

# 2. Fix MySQL Permissions (The Error 13 Cure)
echo "🛡️  Restoring Database Volume Integrity..."
if [ -d "data/mysql" ]; then
    sudo chown -R 999:999 data/mysql
    sudo chmod -R 750 data/mysql
    echo "✅ Permissions Reset to UID 999 (MySQL Standard)."
else
    echo "⚠️  data/mysql directory not found. MySQL might be using an internal volume."
fi

# 3. Purge Redo Logs (Now safe because DB is stopped)
echo "🧹 Cleaning Redo Log Artifacts..."
sudo find data/mysql/#innodb_redo -type f -exec rm -f {} \; 2>/dev/null

# 4. Restart the Stack
echo "🔄 Rebooting Mesh Services..."
$COMPOSE_CMD -f docker-compose.db.yml up -d
$COMPOSE_CMD -f docker-compose.yml up -d
sudo systemctl start vpn-control

echo "✨ System Shield Restored. Performance should be nominal."
