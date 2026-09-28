# Dockerfile for NIDS Alert Manager
# ============================================================
# Multi-stage build for minimal production image
# ============================================================

# Build stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi7 \
    libssl3 \
    iptables \
    iproute2 \
    iputils-ping \
    net-tools \
    dnsutils \
    curl \
    jq \
    vim \
    && rm -rf /var/log/apt/* /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Make sure scripts in .local are usable
ENV PATH=/root/.local/bin:$PATH

# Create non-root user
RUN groupadd -r nids && useradd -r -g nids -d /app -s /bin/bash nids

# Create directories
RUN mkdir -p /var/log/suricata /var/log/snort /var/log/nids /app/responders /var/log/nids/blocks

# Set permissions
RUN chown -R nids:nids /app /var/log/suricata /var/log/snort /var/log/nids

# Copy application code
COPY --chown=nids:nids alert_manager.py /app/
COPY --chown=nids:nids responders/ /app/responders/
COPY --chown=nids:nids config.yaml /app/
COPY --chown=nids:nids requirements.txt /app/

# Switch to non-root user
USER nids

# Expose metrics port
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python3 -c "import requests; requests.get('http://localhost:9090/health', timeout=5)" || exit 1

# Default command
CMD ["python3", "alert_manager.py"]