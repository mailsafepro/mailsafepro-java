# Multi-stage Dockerfile for MailSafePro API
# Optimized for production with security and size in mind

# =============================================================================
# Stage 1: Builder - Install dependencies and build
# =============================================================================
FROM python:3.14-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# =============================================================================
# Stage 2: Runtime - Minimal production image
# =============================================================================
FROM python:3.14-slim

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r mailsafepro && \
    useradd -r -g mailsafepro -u 1000 -m -s /bin/bash mailsafepro

# Set working directory
WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy application code
COPY --chown=mailsafepro:mailsafepro . .

# Set environment variables
# NOTE: PORT is NOT set here - Render assigns it dynamically via environment variable
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

# Create necessary directories with correct permissions
RUN mkdir -p /app/logs /app/.cache && \
    chown -R mailsafepro:mailsafepro /app

# Switch to non-root user
USER mailsafepro

# Health check - uses PORT from environment or defaults to 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/healthcheck || exit 1

# Expose default port (Render overrides via PORT env var)
EXPOSE 8000

# Start application with uvicorn - PORT is injected by Render, fallback to 8000 for local dev
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 2"]

