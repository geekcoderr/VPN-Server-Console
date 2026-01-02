#!/bin/bash
# VPN Control Plane - Medical Health & Recovery Script
# Resolves: MySQL Redo Log Permission Errors (Error 13) & Application Sluggishness

echo "🎭 Starting Infinity-Fix Recovery..."

# 1. Identify the project root
PROJECT_ROOT=$(pwd)
if [ ! -f "docker-compose.db.yml" ]; then
    echo "❌ Error: Run this from the /opt/vpn-control directory."
    exit 1
fi

# 2. Fix MySQL Permissions (The Error 13 Cure)
echo "🛡️  Restoring Database Volume Integrity..."
if [ -d "data/mysql" ]; then
    sudo chown -R 999:999 data/mysql
    sudo chmod -R 750 data/mysql
    echo "✅ Permissions Reset to UID 999 (MySQL Standard)."
else
    echo "⚠️  data/mysql directory not found. MySQL might be using an internal volume."
fi

# 3. Purge Redo Logs (If corrupted/blocked)
# MySQL 8.0 redo logs are in #innodb_redo. If permission was denied, they might be stale.
echo "🧹 Cleaning Redo Log Artifacts..."
sudo find data/mysql/#innodb_redo -type f -exec rm -f {} \; 2>/dev/null

# 4. Restart the Stack
echo "🔄 Rebooting Mesh Services..."
docker compose -f docker-compose.db.yml down
docker compose -f docker-compose.yml down
docker compose -f docker-compose.db.yml up -d
docker compose -f docker-compose.yml up -d
sudo systemctl restart vpn-control

echo "✨ System Shield Restored. Performance should be nominal."
