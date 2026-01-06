#!/bin/bash
# Cloudflare Dynamic DNS Updater
# Updates A records for specified subdomains when public IP changes.
# Logs to /var/log/cf-ddns.log

set -euo pipefail

LOG_FILE="/var/log/cf-ddns.log"
ENV_FILE="/etc/cf-ddns.env"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Load environment
if [ ! -f "$ENV_FILE" ]; then
    log "ERROR: Environment file not found: $ENV_FILE"
    exit 1
fi
source "$ENV_FILE"

# Validate required variables
: "${CF_API_TOKEN:?CF_API_TOKEN not set in $ENV_FILE}"
: "${ZONE_NAME:?ZONE_NAME not set in $ENV_FILE}"

# Records to update (space-separated subdomains)
RECORDS="${RECORDS:-wg vpn}"

# Detect public IP
PUBLIC_IP=$(curl -s https://api.ipify.org || curl -s https://ifconfig.me)
if [ -z "$PUBLIC_IP" ]; then
    log "ERROR: Could not detect public IP"
    exit 1
fi
log "Detected public IP: $PUBLIC_IP"

# Get Zone ID
ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$ZONE_NAME" \
    -H "Authorization: Bearer $CF_API_TOKEN" \
    -H "Content-Type: application/json" | jq -r '.result[0].id')

if [ -z "$ZONE_ID" ] || [ "$ZONE_ID" == "null" ]; then
    log "ERROR: Could not find Zone ID for $ZONE_NAME"
    exit 1
fi
log "Zone ID: $ZONE_ID"

# Update each record
for SUBDOMAIN in $RECORDS; do
    RECORD_NAME="${SUBDOMAIN}.${ZONE_NAME}"
    
    # Get existing record
    RECORD_DATA=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=A&name=$RECORD_NAME" \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json")
    
    RECORD_ID=$(echo "$RECORD_DATA" | jq -r '.result[0].id')
    CURRENT_IP=$(echo "$RECORD_DATA" | jq -r '.result[0].content')
    
    if [ "$CURRENT_IP" == "$PUBLIC_IP" ]; then
        log "$RECORD_NAME: IP unchanged ($PUBLIC_IP)"
        continue
    fi
    
    if [ -z "$RECORD_ID" ] || [ "$RECORD_ID" == "null" ]; then
        # Create new record (DNS-only, TTL 120)
        log "$RECORD_NAME: Creating new A record..."
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
            -H "Authorization: Bearer $CF_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"A\",\"name\":\"$RECORD_NAME\",\"content\":\"$PUBLIC_IP\",\"ttl\":120,\"proxied\":false}" | jq -r '.success'
        log "$RECORD_NAME: Created → $PUBLIC_IP"
    else
        # Update existing record
        log "$RECORD_NAME: Updating $CURRENT_IP → $PUBLIC_IP"
        curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID" \
            -H "Authorization: Bearer $CF_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"A\",\"name\":\"$RECORD_NAME\",\"content\":\"$PUBLIC_IP\",\"ttl\":120,\"proxied\":false}" | jq -r '.success'
        log "$RECORD_NAME: Updated → $PUBLIC_IP"
    fi
done

log "DDNS update complete."
