# ⚔️ Kaido WAF — Docker Image
FROM python:3.13-slim

LABEL maintainer="Gustavo <gustavo@kaido.team>"
LABEL description="Kaido WAF — Web Application Firewall"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r kaido && useradd -r -g kaido -d /opt/kaido-waf -s /sbin/nologin kaido

WORKDIR /opt/kaido-waf

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create log directory
RUN mkdir -p /var/log/kaido-waf && chown -R kaido:kaido /var/log/kaido-waf

# Switch to non-root user
USER kaido

# Expose ports
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/__health')" || exit 1

# Entry point
ENTRYPOINT ["python3", "-m", "kaido_waf.main"]
CMD []
