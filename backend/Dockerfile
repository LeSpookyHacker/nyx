FROM python:3.12-slim

WORKDIR /app

ENV PYTHONPATH=/app

# Install build dependencies (no gosu — container runs as nyx from the start)
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY scripts/ ./scripts/

# Create data/logs directories, create non-root user, set ownership
RUN mkdir -p /app/data /app/logs && \
    addgroup --system nyx && \
    adduser --system --ingroup nyx nyx && \
    chown -R nyx:nyx /app/data /app/logs && \
    chmod 700 /app/data /app/logs

COPY entrypoint.sh /entrypoint.sh
COPY log_config.json /app/log_config.json
RUN chmod +x /entrypoint.sh

EXPOSE 8000

# Run as non-root user — compatible with no-new-privileges:true
USER nyx

ENTRYPOINT ["/entrypoint.sh"]
