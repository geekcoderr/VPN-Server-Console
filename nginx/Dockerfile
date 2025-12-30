FROM openresty/openresty:alpine

# Install certbot and curl for healthcheck
RUN apk add --no-cache certbot curl bash openssl

# Copy nginx configuration (HTTP only initially)
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

# Copy SSL config template
COPY nginx-ssl.conf /etc/nginx/nginx-ssl.conf

# Create directories
RUN mkdir -p /var/www/html /etc/nginx/certs /var/log/openresty

# Create self-signed cert as placeholder (will be replaced by real cert)
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/certs/privkey.pem \
    -out /etc/nginx/certs/fullchain.pem \
    -subj "/CN=localhost"

# Startup script
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Expose ports
EXPOSE 80 443

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["openresty", "-g", "daemon off;"]
