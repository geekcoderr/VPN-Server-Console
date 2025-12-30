FROM openresty/openresty:alpine

# Install certbot for SSL
RUN apk add --no-cache certbot

# Copy nginx configuration
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

# Create directories
RUN mkdir -p /var/www/html /etc/nginx/certs

# Expose ports
EXPOSE 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost/health || exit 1

CMD ["openresty", "-g", "daemon off;"]
