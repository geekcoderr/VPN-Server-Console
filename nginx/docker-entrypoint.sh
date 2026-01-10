#!/bin/bash
set -e

# Check if real SSL certs exist (mounted from host)
DOMAIN="vpn.nishantmaheshwari.online"
if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    echo "✅ Using Let's Encypt certificates for $DOMAIN"
    cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem /etc/nginx/certs/fullchain.pem
    cp /etc/letsencrypt/live/$DOMAIN/privkey.pem /etc/nginx/certs/privkey.pem
else
    echo "⚠️  No Let's Encrypt certs found for $DOMAIN, using self-signed"
fi

# ALWAYS use the SSL config (it has IP blocking + security)
echo "📋 Loading nginx-ssl.conf (with IP blocking)"
cp /etc/nginx/nginx-ssl.conf /usr/local/openresty/nginx/conf/nginx.conf

exec "$@"
