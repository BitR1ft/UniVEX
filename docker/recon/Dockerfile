# ==============================================================================
# Reconnaissance Container
# Purpose: Dedicated container for reconnaissance tools and scripts
# ==============================================================================

FROM python:3.11-slim-bookworm

LABEL maintainer="BitR1FT"
LABEL description="UniVex - Reconnaissance Container"
LABEL version="1.0.0"

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# ==============================================================================
# SYSTEM DEPENDENCIES
# ==============================================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Essential tools
    ca-certificates \
    curl \
    wget \
    git \
    # Build tools
    build-essential \
    gcc \
    g++ \
    # Network tools
    nmap \
    dnsutils \
    iputils-ping \
    netcat-traditional \
    whois \
    # Node.js for Wappalyzer (Month 5)
    nodejs \
    npm \
    # Other utilities
    jq \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# ==============================================================================
# NODE.JS TOOLS (Month 5)
# ==============================================================================
# Install Wappalyzer for technology detection
RUN npm install -g wappalyzer || true

# ==============================================================================
# PYTHON ENVIRONMENT
# ==============================================================================
# Upgrade pip
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Install Python dependencies for reconnaissance
RUN pip install --no-cache-dir \
    # HTTP libraries
    requests \
    httpx \
    aiohttp \
    # HTML parsing
    beautifulsoup4 \
    lxml \
    # DNS tools
    dnspython \
    # Async libraries
    asyncio \
    aiofiles \
    # Network libraries
    python-nmap \
    python-whois \
    # Data handling
    pydantic \
    # Utilities
    colorama \
    termcolor \
    rich \
    tqdm \
    # Subdomain enumeration libraries
    sublist3r \
    # Month 5: HTTP probing
    mmh3==4.1.0 \
    cryptography==42.0.0

# ==============================================================================
# GO TOOLS INSTALLATION
# ==============================================================================
# Install Go for modern recon tools
RUN wget -q https://go.dev/dl/go1.21.6.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz && \
    rm go1.21.6.linux-amd64.tar.gz

# Set up Go environment
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

# Install modern reconnaissance tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/tomnomnom/httprobe@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    # Month 6: Resource enumeration tools
    go install -v github.com/lc/gau/v2/cmd/gau@latest

# Update nuclei templates
RUN nuclei -update-templates || true

# ==============================================================================
# KITERUNNER INSTALLATION (Month 6)
# ==============================================================================
# Install Kiterunner for API endpoint discovery
RUN KITERUNNER_VERSION="v1.0.2" && \
    wget -q https://github.com/assetnote/kiterunner/releases/download/${KITERUNNER_VERSION}/kiterunner_${KITERUNNER_VERSION:1}_linux_amd64.tar.gz && \
    tar -xzf kiterunner_${KITERUNNER_VERSION:1}_linux_amd64.tar.gz && \
    mv kr /usr/local/bin/kr && \
    chmod +x /usr/local/bin/kr && \
    rm kiterunner_${KITERUNNER_VERSION:1}_linux_amd64.tar.gz

# Download Kiterunner wordlists
RUN mkdir -p /usr/share/kiterunner && \
    # Download routes-large wordlist
    wget -q -O /tmp/routes-large.kite.tar.gz https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz && \
    tar -xzf /tmp/routes-large.kite.tar.gz -C /usr/share/kiterunner/ && \
    rm /tmp/routes-large.kite.tar.gz && \
    # Download routes-small wordlist
    wget -q -O /tmp/routes-small.kite.tar.gz https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz && \
    tar -xzf /tmp/routes-small.kite.tar.gz -C /usr/share/kiterunner/ && \
    rm /tmp/routes-small.kite.tar.gz

# ==============================================================================
# WORKSPACE SETUP
# ==============================================================================
# Create working directories
RUN mkdir -p /app /results/recon /configs

# Set working directory
WORKDIR /app

# ==============================================================================
# ENTRYPOINT SCRIPT
# ==============================================================================
# Create entrypoint script for recon container
RUN echo '#!/bin/bash\n\
set -e\n\
echo "=== UniVex - Reconnaissance Container ==="\n\
echo "Container started at: $(date)"\n\
echo "Tools available:"\n\
echo "  - Subfinder: $(subfinder -version 2>&1 | head -1)"\n\
echo "  - Nuclei: $(nuclei -version 2>&1 | head -1)"\n\
echo "  - Naabu: $(naabu -version 2>&1 | head -1)"\n\
echo "  - Httpx: $(httpx -version 2>&1 | head -1)"\n\
echo "  - Katana: $(katana -version 2>&1 | head -1)"\n\
echo "  - GAU: $(gau --version 2>&1 | head -1)"\n\
echo "  - Kiterunner: $(kr version 2>&1 | head -1)"\n\
echo "  - Nmap: $(nmap --version | head -1)"\n\
echo "  - Python: $(python --version)"\n\
echo "  - Node.js: $(node --version 2>&1)"\n\
echo ""\n\
echo "Ready to receive reconnaissance tasks..."\n\
exec "$@"' > /entrypoint.sh && chmod +x /entrypoint.sh

# ==============================================================================
# HEALTH CHECK
# ==============================================================================
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD subfinder -version || exit 1

# ==============================================================================
# RUNTIME CONFIGURATION
# ==============================================================================
ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/dev/null"]
