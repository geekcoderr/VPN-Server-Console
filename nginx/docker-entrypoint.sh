#!/bin/bash
set -e

# Check if real SSL certs exist (mounted from host)
if [ -f "/etc/nginx/certs-letsencrypt/fullchain.pem" ]; then
    echo "Using Let's Encrypt certificates"
    cp /etc/nginx/certs-letsencrypt/fullchain.pem /etc/nginx/certs/fullchain.pem
    cp /etc/nginx/certs-letsencrypt/privkey.pem /etc/nginx/certs/privkey.pem
    # Use SSL config
    cp /etc/nginx/nginx-ssl.conf /usr/local/openresty/nginx/conf/nginx.conf
else
    echo "Using self-signed certificate (replace with Let's Encrypt)"
fi

exec "$@"
