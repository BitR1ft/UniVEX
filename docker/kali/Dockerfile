# ==============================================================================
# Kali Linux Security Tools Container
# Purpose: Base container with essential penetration testing tools
# ==============================================================================

FROM kalilinux/kali-rolling:latest

LABEL maintainer="BitR1FT"
LABEL description="UniVex - Kali Linux Tools Container"
LABEL version="1.0.0"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TERM=xterm-256color

# Update and upgrade system
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get dist-upgrade -y

# ==============================================================================
# ESSENTIAL SYSTEM TOOLS
# ==============================================================================
RUN apt-get install -y --no-install-recommends \
    # Core utilities
    ca-certificates \
    curl \
    wget \
    git \
    vim \
    nano \
    tmux \
    screen \
    net-tools \
    iputils-ping \
    dnsutils \
    traceroute \
    netcat-traditional \
    socat \
    telnet \
    ftp \
    # Build tools
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    # Kerberos development headers (required to build krb5/gssapi pip packages)
    libkrb5-dev \
    # Python ecosystem
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    # Other essentials
    jq \
    unzip \
    zip \
    p7zip-full \
    tar \
    gzip

# Create 'python' symlink so scripts using 'python' work alongside python3
RUN ln -sf /usr/bin/python3 /usr/bin/python

# ==============================================================================
# NETWORK RECONNAISSANCE TOOLS
# ==============================================================================
RUN apt-get install -y --no-install-recommends \
    # Port scanning
    nmap \
    masscan \
    # Network discovery
    netdiscover \
    arp-scan \
    # DNS enumeration
    dnsrecon \
    dnsenum \
    fierce \
    # SSL/TLS testing
    sslscan \
    sslyze \
    testssl.sh \
    # Service enumeration
    enum4linux \
    nbtscan \
    onesixtyone \
    snmp \
    # Active Directory attack tools (Day 12-13)
    responder \
    evil-winrm \
    crackmapexec \
    bloodhound \
    neo4j

# ==============================================================================
# WEB APPLICATION TESTING TOOLS
# ==============================================================================
RUN apt-get install -y --no-install-recommends \
    # Web scanners
    nikto \
    dirb \
    dirbuster \
    gobuster \
    wfuzz \
    # Web proxies
    burpsuite \
    zaproxy \
    # Web crawlers
    whatweb \
    wafw00f \
    # Subdomain enumeration
    sublist3r \
    # HTTP clients
    httpie

# ==============================================================================
# EXPLOITATION FRAMEWORKS
# ==============================================================================
RUN apt-get install -y --no-install-recommends \
    # Metasploit Framework
    metasploit-framework \
    # Exploit databases
    exploitdb \
    # Social engineering
    set

# ==============================================================================
# PASSWORD CRACKING & BRUTE FORCING
# ==============================================================================
RUN apt-get install -y --no-install-recommends \
    # Password crackers
    john \
    hashcat \
    hydra \
    medusa \
    # Hash identification
    hashid \
    hash-identifier \
    # Wordlists
    wordlists \
    # Credential tools
    crunch

# ==============================================================================
# WIRELESS SECURITY TOOLS
# ==============================================================================
RUN apt-get install -y --no-install-recommends \
    # Wireless tools
    aircrack-ng \
    reaver \
    pixiewps \
    # Bluetooth tools
    bluez \
    bluez-tools

# ==============================================================================
# FORENSICS & ANALYSIS TOOLS
# ==============================================================================
RUN apt-get install -y --no-install-recommends \
    # Forensics
    autopsy \
    sleuthkit \
    # Binary analysis
    binwalk \
    foremost \
    # Network analysis
    wireshark \
    tshark \
    tcpdump \
    # Steganography
    steghide \
    stegosuite

# ==============================================================================
# POST-EXPLOITATION TOOLS
# ==============================================================================
RUN apt-get install -y --no-install-recommends \
    # Privilege escalation
    unix-privesc-check \
    # Persistence
    weevely \
    # Data exfiltration
    dnschef

# ==============================================================================
# DESERIALIZATION EXPLOITATION TOOLS (Day 10)
# ==============================================================================

# ysoserial — Java deserialization payload generator
# Pre-built JAR downloaded from GitHub releases
RUN mkdir -p /opt/ysoserial && \
    wget -q "https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar" \
        -O /opt/ysoserial/ysoserial.jar || \
    echo "Warning: ysoserial download failed — place ysoserial.jar at /opt/ysoserial/ysoserial.jar manually"

# Wrapper script so 'ysoserial' works as a plain command
RUN printf '#!/bin/sh\nexec java -jar /opt/ysoserial/ysoserial.jar "$@"\n' \
        > /usr/local/bin/ysoserial && \
    chmod +x /usr/local/bin/ysoserial

# phpggc — PHP generic gadget chains generator
RUN git clone --depth 1 https://github.com/ambionics/phpggc.git /opt/phpggc 2>/dev/null || \
    echo "Warning: phpggc clone failed — install manually at /opt/phpggc"

RUN if [ -f /opt/phpggc/phpggc ]; then \
        ln -sf /opt/phpggc/phpggc /usr/local/bin/phpggc && chmod +x /opt/phpggc/phpggc; \
    fi

# Java runtime (required for ysoserial)
RUN apt-get install -y --no-install-recommends default-jre-headless

# Set ysoserial env var for Python tool wrappers
ENV YSOSERIAL_PATH=/usr/local/bin/ysoserial
ENV PHPGGC_PATH=/usr/local/bin/phpggc

# ==============================================================================
# TUNNELING & PIVOTING TOOLS (Day 11)
# ==============================================================================

# proxychains4 — route tools through SOCKS/HTTP proxy chains
RUN apt-get install -y --no-install-recommends proxychains4

# sshuttle — VPN-over-SSH transparent proxy (no root needed on client)
RUN apt-get install -y --no-install-recommends sshuttle

# chisel — HTTP-based TCP tunnelling (Go binary)
# Download pre-compiled binary from GitHub releases
RUN CHISEL_VERSION="1.9.1" && \
    wget -q "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_amd64.gz" \
        -O /tmp/chisel.gz && \
    gunzip /tmp/chisel.gz && \
    mv /tmp/chisel /usr/local/bin/chisel && \
    chmod +x /usr/local/bin/chisel || \
    echo "Warning: chisel download failed — place chisel binary at /usr/local/bin/chisel manually"

# Set chisel env var for Python tool wrappers
ENV CHISEL_PATH=/usr/local/bin/chisel

# ==============================================================================
# PYTHON SECURITY LIBRARIES
# ==============================================================================
RUN pip3 install --no-cache-dir --break-system-packages --ignore-installed \
    # Core libraries
    requests \
    beautifulsoup4 \
    lxml \
    # Network libraries
    scapy \
    impacket \
    bloodhound \
    # AD/Kerberos attack libraries (Day 12-13)
    ldapdomaindump \
    ldap3 \
    pyasn1 \
    pyOpenSSL \
    pycryptodomex \
    gssapi \
    krb5 \
    pywhisker \
    # Web libraries
    selenium \
    mechanize \
    # Exploitation libraries
    pwntools \
    # Cryptography
    pycryptodome \
    # Other utilities
    colorama \
    termcolor \
    python-nmap \
    python-whois \
    # HTTP fingerprinting helpers (Week 4)
    mmh3==4.1.0 \
    # MCP Server dependencies (Month 11)
    fastapi \
    uvicorn[standard] \
    pydantic \
    aiohttp

# ==============================================================================
# AD ATTACK TOOLS — BloodHound Engine (Day 12-13)
# ==============================================================================

# bloodhound-python — remote AD collection over LDAP/Kerberos
RUN pip3 install --no-cache-dir --break-system-packages bloodhound || \
    echo "Warning: bloodhound-python install failed — install manually with pip install bloodhound"

# pywhisker — Shadow Credentials attack tool
RUN pip3 install --no-cache-dir --break-system-packages pywhisker || \
    echo "Warning: pywhisker install failed"

# certipy — Active Directory Certificate Services (ADCS) attacks
RUN pip3 install --no-cache-dir --break-system-packages certipy-ad || \
    echo "Warning: certipy-ad install failed"

# NetExec (CrackMapExec successor) via pip
RUN pip3 install --no-cache-dir --break-system-packages netexec || \
    echo "Warning: netexec install failed — crackmapexec may still be available"

# hashcat is included in Kali; ensure it is present
RUN apt-get install -y --no-install-recommends \
    hashcat \
    john \
    samdump2 \
    mimikatz 2>/dev/null || \
    apt-get install -y --no-install-recommends hashcat john samdump2 || \
    echo "Warning: some hash cracking tools may not be available"

# Ensure impacket suite scripts are in PATH
RUN pip3 install --no-cache-dir --break-system-packages 'impacket>=0.12.0' && \
    ln -sf /usr/local/bin/secretsdump.py /usr/bin/secretsdump.py 2>/dev/null || true && \
    ln -sf /usr/local/bin/ticketer.py    /usr/bin/ticketer.py    2>/dev/null || true && \
    ln -sf /usr/local/bin/ntlmrelayx.py  /usr/bin/ntlmrelayx.py  2>/dev/null || true && \
    echo "Impacket suite ready"
# Create directory for MCP servers
RUN mkdir -p /app/mcp/servers

# Copy MCP server files (will be mounted from backend)
# Note: Files will be mounted at runtime via docker-compose volumes

# Copy startup script
COPY start-mcp-servers.sh /usr/local/bin/start-mcp-servers.sh
RUN chmod +x /usr/local/bin/start-mcp-servers.sh

# ==============================================================================
# GO TOOLCHAIN
# ==============================================================================
RUN apt-get install -y --no-install-recommends golang-go libpcap-dev

# Set up Go environment
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

# ==============================================================================
# MODERN RECON TOOLS – PINNED VERSIONS (Week 4, Day 23)
#
# Versions are pinned to ensure reproducible builds.
# Update the version tags here when you want to upgrade a tool.
# ==============================================================================

# projectdiscovery/naabu – fast port scanner
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.3

# projectdiscovery/nuclei – vulnerability scanner
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.10

# projectdiscovery/httpx – HTTP probing / fingerprinting
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.6.10

# projectdiscovery/katana – next-gen web crawler
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@v1.1.2

# projectdiscovery/subfinder – passive subdomain enumeration
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.7

# lc/gau – get all URLs (Wayback, Common Crawl, OTX, URLScan)
RUN go install -v github.com/lc/gau/v2/cmd/gau@v2.2.4

# assetnote/kiterunner – API endpoint discovery
# The v1.0.2 tag predates the cmd/kr package layout; cmd/kr only exists in HEAD.
# Build from HEAD and make the step best-effort so a transient failure does not
# abort the entire image build.
RUN git clone --depth 1 https://github.com/assetnote/kiterunner.git /tmp/kiterunner \
 && cd /tmp/kiterunner \
 && go build -o "${GOPATH}/bin/kr" ./cmd/kr \
 && rm -rf /tmp/kiterunner \
 || { rm -rf /tmp/kiterunner; echo "[warn] kiterunner build failed - skipping"; }

# tomnomnom utilities
RUN go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/tomnomnom/httprobe@latest

# ffuf – fast web fuzzer
RUN go install -v github.com/ffuf/ffuf/v2@v2.1.0

# Update nuclei templates after binary install
RUN nuclei -update-templates || true

# ==============================================================================
# WAPPALYZER CLI (Node.js based technology detection)
# ==============================================================================
RUN apt-get install -y --no-install-recommends nodejs npm && \
    npm install -g wappalyzer-cli@latest

# ==============================================================================
# WORDLISTS SETUP
# ==============================================================================
# Extract SecLists (common wordlists for security testing)
RUN mkdir -p /usr/share/wordlists && \
    cd /usr/share/wordlists && \
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git

# Uncompress rockyou wordlist if compressed
RUN if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
        gunzip /usr/share/wordlists/rockyou.txt.gz; \
    fi

# ==============================================================================
# CLEANUP
# ==============================================================================
RUN apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# ==============================================================================
# WORKSPACE SETUP
# ==============================================================================
# Create working directories
RUN mkdir -p /results /configs /root/tools

# Set working directory
WORKDIR /root

# ==============================================================================
# HEALTH CHECK
# ==============================================================================
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nmap --version || exit 1

# ==============================================================================
# METADATA – document pinned tool versions
# ==============================================================================
RUN echo "=== Kali Tools Container - Installed Versions ===" > /root/tool-versions.txt && \
    echo "Nmap:      $(nmap --version | head -1)" >> /root/tool-versions.txt && \
    echo "Metasploit: $(msfconsole --version 2>/dev/null || echo 'not available')" >> /root/tool-versions.txt && \
    echo "Nuclei:    $(nuclei --version 2>&1 | head -1)" >> /root/tool-versions.txt && \
    echo "Naabu:     $(naabu --version 2>&1 | head -1)" >> /root/tool-versions.txt && \
    echo "httpx:     $(httpx --version 2>&1 | head -1)" >> /root/tool-versions.txt && \
    echo "Katana:    $(katana --version 2>&1 | head -1)" >> /root/tool-versions.txt && \
    echo "Subfinder: $(subfinder --version 2>&1 | head -1)" >> /root/tool-versions.txt && \
    echo "gau:       $(gau --version 2>&1 | head -1)" >> /root/tool-versions.txt && \
    echo "ffuf:      $(ffuf --version 2>&1 | head -1)" >> /root/tool-versions.txt && \
    echo "Python:    $(python3 --version)" >> /root/tool-versions.txt && \
    echo "Go:        $(go version)" >> /root/tool-versions.txt && \
    echo "Node:      $(node --version)" >> /root/tool-versions.txt

# Default command (keep container running)
CMD ["tail", "-f", "/dev/null"]
