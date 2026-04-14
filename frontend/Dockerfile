# Build stage
FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci

COPY . .
RUN npm run build

# Production stage
FROM nginx:alpine

# Nyx nginx config
COPY --from=builder /app/dist /usr/share/nginx/html
RUN cat > /etc/nginx/conf.d/default.conf << 'EOF'
server {
    listen 80;
    root /usr/share/nginx/html;
    index index.html;

    # Security headers for all responses (L-2)
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header X-XSS-Protection "0" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    # CSP: allow same-origin scripts/styles; data: URIs for inline SVG/images
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';" always;

    # SPA routing
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Proxy API calls to backend — gzip disabled on API routes (L3 BREACH mitigation)
    location /api/ {
        proxy_pass http://backend:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        gzip off;
    }

    # Proxy auth endpoints — /auth/session, /auth/logout, /auth/whoami live at the root, not under /api/
    location /auth/ {
        proxy_pass http://backend:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        gzip off;
    }

    # Proxy health endpoints — /health and /health/integrations live at the root
    location /health {
        proxy_pass http://backend:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        gzip off;
    }

    # Gzip for static assets only (not JSON API responses)
    gzip on;
    gzip_types text/plain text/css application/javascript text/xml;
    # Explicitly exclude JSON — compressed JSON over HTTPS is vulnerable to BREACH
    gzip_disable "application/json";
}
EOF

# Run as non-root for security hardening
RUN chown -R nginx:nginx /usr/share/nginx/html /var/cache/nginx /var/log/nginx && \
    chmod -R 755 /usr/share/nginx/html && \
    touch /run/nginx.pid && chown nginx:nginx /run/nginx.pid
USER nginx

EXPOSE 80
