FROM python:3.12-slim

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends gcc gosu && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Create data/logs directories and non-root user
RUN mkdir -p /app/data /app/logs && \
    addgroup --system nyx && \
    adduser --system --ingroup nyx nyx

COPY entrypoint.sh /entrypoint.sh
COPY log_config.json /app/log_config.json
RUN chmod +x /entrypoint.sh

EXPOSE 8000

# Entrypoint runs as root briefly to fix volume ownership, then drops to nyx
ENTRYPOINT ["/entrypoint.sh"]
