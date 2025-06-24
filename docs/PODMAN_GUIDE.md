# UniVex — Podman Deployment Guide

> Last updated: 2026-03-26 · Author: BitR1FT

---

## Table of Contents

1. [Why Podman?](#1-why-podman)
2. [Requirements](#2-requirements)
3. [Quick Start — Rootless Podman](#3-quick-start--rootless-podman)
4. [Detailed Setup](#4-detailed-setup)
   - 4.1 [Install Podman](#41-install-podman)
   - 4.2 [Configure Rootless Mode](#42-configure-rootless-mode)
   - 4.3 [Install podman-compose](#43-install-podman-compose)
   - 4.4 [Run the TUI Installer](#44-run-the-tui-installer)
5. [SELinux Configuration](#5-selinux-configuration)
6. [Networking in Rootless Podman](#6-networking-in-rootless-podman)
7. [Systemd Integration](#7-systemd-integration)
8. [Podman vs Docker — Differences](#8-podman-vs-docker--differences)
9. [Troubleshooting](#9-troubleshooting)
10. [Enterprise RHEL Deployment](#10-enterprise-rhel-deployment)

---

## 1. Why Podman?

| Feature | Docker (rootful) | Podman (rootless) |
|---------|-----------------|-------------------|
| Daemon required | Yes | No |
| Root privileges | Yes (daemon) | **No** |
| OCI-compliant | Yes | **Yes** |
| SELinux integration | Limited | **Full** |
| Systemd integration | Via shim | **Native** |
| RHEL/Fedora support | Extra steps | **Included** |
| Docker API compatibility | Native | Socket API |

UniVex supports **rootless Podman** as a first-class deployment target.
Rootless containers run entirely within your user namespace — no `sudo`,
no daemon with root privileges, and full SELinux label support.

---

## 2. Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | RHEL 8 / Fedora 36 / Ubuntu 22.04 | RHEL 9 / Fedora 39+ |
| Podman | 4.0 | 5.0+ |
| podman-compose | 1.0 | 1.2+ |
| RAM | 4 GB | 8+ GB |
| Free disk | 20 GB | 50+ GB |
| Python | 3.10 | 3.12 |

---

## 3. Quick Start — Rootless Podman

```bash
# Clone UniVex
git clone https://github.com/BitR1ft/UniVex.git
cd UniVex

# Run the Podman TUI installer
bash scripts/install-podman.sh

# Access the application
open http://localhost:3000/setup
```

> The installer handles socket configuration, .env generation, and service startup.

---

## 4. Detailed Setup

### 4.1 Install Podman

**RHEL 8 / CentOS Stream 8:**
```bash
sudo dnf install -y @container-tools
```

**RHEL 9 / Fedora 36+:**
```bash
sudo dnf install -y podman
```

**Ubuntu 22.04+:**
```bash
sudo apt-get update
sudo apt-get install -y podman
```

**Verify installation:**
```bash
podman version
# Server:    Engine:
# Version:      4.9.4
podman info | grep -E "rootless|cgroup"
```

---

### 4.2 Configure Rootless Mode

Rootless Podman requires user namespace support.

```bash
# Enable lingering (allows user services to run without active login session)
loginctl enable-linger $(whoami)

# Verify user namespace support
cat /proc/sys/kernel/unprivileged_userns_clone   # Should be 1

# If 0, enable it (requires root):
sudo sysctl -w kernel.unprivileged_userns_clone=1
# Make permanent:
echo "kernel.unprivileged_userns_clone=1" | sudo tee /etc/sysctl.d/99-userns.conf

# Verify subuid / subgid mappings are configured
grep $(whoami) /etc/subuid   # e.g.: username:100000:65536
grep $(whoami) /etc/subgid
# If missing:
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $(whoami)
```

**Enable the rootless Podman API socket:**
```bash
systemctl --user enable --now podman.socket

# Verify
systemctl --user status podman.socket
ls -la ${XDG_RUNTIME_DIR}/podman/podman.sock
```

---

### 4.3 Install podman-compose

```bash
pip install --user podman-compose

# Verify
podman-compose version
```

> `podman-compose` implements the Docker Compose v2 spec and is compatible
> with the `docker-compose.yml` files included in UniVex.

---

### 4.4 Run the TUI Installer

```bash
# Interactive installer (recommended)
bash scripts/install-podman.sh

# Non-interactive (CI/CD, uses defaults)
bash scripts/install-podman.sh --non-interactive

# Dry-run: generates .env only, does not start containers
bash scripts/install-podman.sh --dry-run

# Rootful Podman (if rootless is unavailable)
bash scripts/install-podman.sh --rootful
```

The installer will:
1.  Check Podman version, podman-compose, RAM, and disk space
2.  Guide you through LLM provider selection
3.  Collect API keys with masked input
4.  Let you choose optional services (MinIO, Langfuse, etc.)
5.  Generate cryptographically secure secrets
6.  Write a production `.env` file (permissions: 600)
7.  Pull images and start all services
8.  Run a health check and display service URLs

---

## 5. SELinux Configuration

On RHEL/Fedora with SELinux in **Enforcing** mode, container volume mounts
require a security context label to be accessible by container processes.

### Volume Mount Labels

UniVex's `docker-compose.yml` uses Podman-compatible SELinux label annotations:

```yaml
volumes:
  # :z — shared label (multiple containers can access)
  - ./backend/init-scripts:/docker-entrypoint-initdb.d:z,ro

  # :Z — private label (exclusive to one container)
  - postgres-data:/var/lib/postgresql/data:Z
```

### Manual Context Fix

If a container fails to read a bind-mounted directory:

```bash
# Apply shared container label to a host directory
sudo chcon -Rt container_file_t ./data/

# Or relabel the entire project directory (broad — use with caution)
chcon -Rt svirt_sandbox_file_t .

# Verify
ls -Z ./data/
```

### SELinux Booleans

Some optional services require additional SELinux booleans:

```bash
# Allow containers to connect to the network
sudo setsebool -P container_connect_any 1

# Allow containers to use CGROUPS
sudo setsebool -P container_manage_cgroup 1

# Verify
getsebool container_connect_any
```

---

## 6. Networking in Rootless Podman

Rootless Podman uses **slirp4netns** (or Pasta) for network access instead of
kernel-level bridge networking. This has a few implications:

### Port Binding

Rootless containers cannot bind to ports below 1024 without a kernel tunable:

```bash
# Check current minimum unprivileged port (default: 1024)
cat /proc/sys/net/ipv4/ip_unprivileged_port_start

# Lower to 80 to allow binding port 80 without root
echo "net.ipv4.ip_unprivileged_port_start=80" | sudo tee /etc/sysctl.d/99-portstart.conf
sudo sysctl -p /etc/sysctl.d/99-portstart.conf
```

### DNS Resolution

Rootless containers use an internal DNS resolver. No changes are required for
UniVex — all inter-service communication uses Compose service names as hostnames.

### External Connectivity

Container-to-host network access uses the special IP `10.0.2.2` in slirp4netns:

```bash
# Inside a container, reach the host machine
curl http://10.0.2.2:8080/api
```

### Pasta (Podman 5.0+)

Podman 5.0 replaces slirp4netns with **pasta** for better performance:

```bash
# Check which network mode is active
podman info | grep -i netDriver
```

---

## 7. Systemd Integration

Running UniVex as a **user systemd service** ensures it starts on boot without
a login session.

### Generate Systemd Units

```bash
cd /path/to/UniVex

# Start the stack and generate units
podman-compose -f docker-compose.yml up -d

# Generate quadlet unit files for each service
mkdir -p ~/.config/containers/systemd/
podman generate systemd --new --name univex-backend \
  > ~/.config/containers/systemd/univex-backend.service

# Reload and enable
systemctl --user daemon-reload
systemctl --user enable --now univex-backend.service
```

### Auto-Start on Boot

```bash
# Enable lingering to run services without an active login
loginctl enable-linger $(whoami)

# Verify
loginctl show-user $(whoami) | grep Linger
# Linger=yes
```

---

## 8. Podman vs Docker — Differences

When using Podman with UniVex, be aware of these differences:

| Behaviour | Docker | Podman (rootless) |
|-----------|--------|-------------------|
| Default UID inside container | root (0) | mapped host UID |
| Volume ownership | root owns files | host user owns files |
| `userns_mode: keep-id` | no-op / ignored | maps host UID into container |
| Network mode | bridge | slirp4netns / pasta |
| Compose driver | Compose plugin | podman-compose |
| Docker socket | `/var/run/docker.sock` | `$XDG_RUNTIME_DIR/podman/podman.sock` |
| Daemon | Required | **Not required** |

### `userns_mode: keep-id`

UniVex services that write to shared volumes include the Compose annotation:

```yaml
# Example in docker-compose.yml
services:
  backend:
    userns_mode: keep-id   # rootless Podman only — ignored by Docker
    volumes:
      - backend-cache:/app/cache:Z
```

This ensures that files created by the container are owned by your host user,
not by the remapped UID 0 that rootless containers normally produce.

---

## 9. Troubleshooting

### Container exits immediately with exit code 1

```bash
# Check logs
podman-compose logs backend

# Common causes:
# 1. Missing .env — run: bash scripts/install-podman.sh
# 2. Port conflict — check with: ss -tnlp | grep 8000
# 3. SELinux denial — check: sudo ausearch -c 'podman' | grep denied
```

### Permission denied on volume mounts (SELinux)

```bash
# Check AVC denials
sudo ausearch -c 'podman' --raw | audit2allow
# Apply relabel
sudo chcon -Rt container_file_t /path/to/volume
```

### `DOCKER_HOST` not recognized

```bash
# Ensure the Podman socket is running
systemctl --user status podman.socket

# Export the socket path
export DOCKER_HOST="unix://${XDG_RUNTIME_DIR}/podman/podman.sock"
```

### Network connectivity between containers

```bash
# List Podman networks
podman network ls

# Inspect a network
podman network inspect podman

# If services can't reach each other, ensure they share a network:
podman-compose -f docker-compose.yml ps
```

### `newuidmap` / `newgidmap` errors

```bash
# Check if newuidmap is installed and has correct capabilities
ls -la /usr/bin/newuidmap
# Should be owned by root with the setuid bit

# Install if missing (RHEL/Fedora)
sudo dnf install -y shadow-utils
```

---

## 10. Enterprise RHEL Deployment

For air-gapped RHEL/RHCOS environments with a private container registry:

### Mirror Images to Private Registry

```bash
# Pull all UniVex images
podman pull postgres:16-alpine
podman pull redis:7-alpine
# ... (see docker-compose.yml for the full image list)

# Tag and push to private registry
podman tag postgres:16-alpine registry.internal.corp:5000/univex/postgres:16-alpine
podman push registry.internal.corp:5000/univex/postgres:16-alpine
```

### Custom CA for Private Registry

```bash
# Copy your corporate CA to the trusted store
sudo cp /path/to/corp-root-ca.pem /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust

# Configure UniVex to use the same CA for outbound API calls
export EXTERNAL_SSL_CA_PATH=/etc/pki/ca-trust/source/anchors/corp-root-ca.pem
```

### Override Image Names

```bash
# Use a .env override to point to private registry
cat >> .env <<EOF
REGISTRY_PREFIX=registry.internal.corp:5000/univex/
EOF

# Or use an override Compose file
podman-compose -f docker-compose.yml -f docker-compose.registry-override.yml up -d
```

### FIPS Mode

RHEL in FIPS mode requires SHA-256 or stronger for all cryptographic operations.
UniVex is FIPS-compatible — all JWTs use HS256, and the cookie signing module
uses HMAC-SHA256.

```bash
# Verify FIPS mode
fips-mode-setup --check

# UniVex settings for FIPS environments
SSL_MIN_TLS_VERSION=TLSv1_2   # TLSv1.0 and TLSv1.1 are automatically blocked
```

---

*For general Docker deployment, see [docs/INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md).*  
*For custom CA and cookie security configuration, see [docs/SECURITY.md](SECURITY.md).*
