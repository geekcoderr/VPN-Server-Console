#!/bin/bash
set -e

# Check if real SSL certs exist (mounted from host)
if [ -f "/etc/nginx/certs-letsencrypt/fullchain.pem" ]; then
    echo "✅ Using Let's Encrypt certificates"
    cp /etc/nginx/certs-letsencrypt/fullchain.pem /etc/nginx/certs/fullchain.pem
    cp /etc/nginx/certs-letsencrypt/privkey.pem /etc/nginx/certs/privkey.pem
else
    echo "⚠️  No Let's Encrypt certs found, using self-signed"
fi

# ALWAYS use the SSL config (it has IP blocking + security)
echo "📋 Loading nginx-ssl.conf (with IP blocking)"
cp /etc/nginx/nginx-ssl.conf /usr/local/openresty/nginx/conf/nginx.conf

exec "$@"
