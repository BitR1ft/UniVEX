# ==============================================================================
# UniVex Backend - FastAPI Application
# Purpose: Main API server with WebSocket, SSE, and Docker SDK support
# ==============================================================================

FROM python:3.11-slim-bookworm

LABEL maintainer="BitR1FT"
LABEL description="UniVex - FastAPI Backend"
LABEL version="1.0.0"

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# ==============================================================================
# SYSTEM DEPENDENCIES
# ==============================================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    gcc \
    g++ \
    make \
    # PostgreSQL client
    postgresql-client \
    libpq-dev \
    # Network tools
    curl \
    wget \
    nmap \
    # Node.js and npm (for Wappalyzer)
    nodejs \
    npm \
    # Other utilities
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ==============================================================================
# GO INSTALLATION (for httpx and other tools)
# ==============================================================================
ENV GO_VERSION=1.21.5
RUN wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# ==============================================================================
# SECURITY TOOLS INSTALLATION
# ==============================================================================
# Install httpx (HTTP probing)
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install Wappalyzer CLI (Technology detection)
RUN npm install -g wappalyzer-cli

# Verify installations
RUN httpx -version && nmap --version && npm list -g wappalyzer-cli

# ==============================================================================
# PYTHON ENVIRONMENT
# ==============================================================================
# Upgrade pip
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Set working directory
WORKDIR /app

# Copy requirements first (for Docker layer caching)
COPY requirements.txt requirements-dev.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Docker SDK for Python (for container orchestration)
RUN pip install --no-cache-dir docker

# ==============================================================================
# APPLICATION CODE
# ==============================================================================
# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /var/log/univex /cache

# ==============================================================================
# RUNTIME USER (Security)
# ==============================================================================
# Create non-root user for running the application
RUN useradd -m -u 1000 univex && \
    chown -R univex:univex /app /var/log/univex /cache && \
    chmod +x /app/entrypoint.sh

# ==============================================================================
# EXPOSE PORTS
# ==============================================================================
EXPOSE 8000

# ==============================================================================
# HEALTH CHECK
# ==============================================================================
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# ==============================================================================
# RUNTIME CONFIGURATION
# ==============================================================================
# Switch to non-root user
USER univex

# Run migrations then start the application
CMD ["/app/entrypoint.sh"]
