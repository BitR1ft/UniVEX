# UniVex — Complete Setup Guide

> **Universal + Vulnerability Execution** — Professional open-source security platform by BitR1FT.
> This guide walks you through **every step** to get UniVex running from a fresh machine,
> including full error-handling notes for the most common failure modes.

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Install Prerequisites](#2-install-prerequisites)
3. [Clone the Repository](#3-clone-the-repository)
4. [Configure Environment Variables](#4-configure-environment-variables)
5. [Quick Start — Docker Compose (Recommended)](#5-quick-start--docker-compose-recommended)
6. [Database Setup & Migrations](#6-database-setup--migrations)
7. [Seed the Database (Optional)](#7-seed-the-database-optional)
8. [Verify Everything is Healthy](#8-verify-everything-is-healthy)
9. [Manual / Local Development Setup](#9-manual--local-development-setup)
   - [9a. Backend (FastAPI)](#9a-backend-fastapi)
   - [9b. Frontend (Next.js)](#9b-frontend-nextjs)
10. [Running Tests](#10-running-tests)
11. [Useful Day-to-Day Commands](#11-useful-day-to-day-commands)
12. [Error Handling — Common Problems & Fixes](#12-error-handling--common-problems--fixes)
    - [Docker / Container Errors](#docker--container-errors)
    - [Database Errors](#database-errors)
    - [Backend / Python Errors](#backend--python-errors)
    - [Frontend / Node.js Errors](#frontend--nodejs-errors)
    - [AI Agent / LLM Errors](#ai-agent--llm-errors)
    - [Neo4j Errors](#neo4j-errors)
    - [Port Conflicts](#port-conflicts)
13. [Resetting to a Clean State](#13-resetting-to-a-clean-state)
14. [Uninstallation](#14-uninstallation)

---

## 1. System Requirements

### Hardware

| Environment | CPU | RAM | Free Disk |
|-------------|-----|-----|-----------|
| Development | 2 cores | 8 GB | 20 GB |
| Staging | 4 cores | 16 GB | 50 GB |
| Production | 8 cores | 32 GB | 200 GB+ |

> ⚠️ Neo4j alone requires at least 2 GB of RAM; 8 GB total is the realistic minimum.

### Supported Operating Systems

- **Linux** — Ubuntu 22.04 LTS / Debian 12 / Kali 2024.x or later (recommended)
- **macOS** — 13 Ventura or later (Docker Desktop required)
- **Windows** — Windows 11 with WSL2 + Docker Desktop (Linux containers mode)

---

## 2. Install Prerequisites

### Docker Engine + Docker Compose

Docker Compose V2 (the `docker compose` plugin, **not** the legacy `docker-compose` standalone binary) is required.

**Ubuntu / Debian:**
```bash
# Remove old versions if present
sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

# Install Docker Engine
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Allow running docker without sudo
sudo usermod -aG docker $USER
newgrp docker
```

**Verify the installation:**
```bash
docker --version          # Docker version 25.x or later
docker compose version    # Docker Compose version v2.24 or later
```

**macOS (Docker Desktop):**
Download and install from https://docs.docker.com/desktop/mac/install/

**Windows (WSL2):**
1. Install WSL2: `wsl --install` in PowerShell (Admin)
2. Install Docker Desktop from https://docs.docker.com/desktop/windows/install/
3. In Docker Desktop → Settings → Resources → WSL Integration → enable your distro

---

### Git

```bash
# Ubuntu / Debian
sudo apt-get install -y git

# macOS (via Homebrew)
brew install git

# Verify
git --version   # 2.40 or later recommended
```

---

### Python 3.11 (local dev only — not needed for Docker)

```bash
# Ubuntu / Debian
sudo apt-get install -y python3.11 python3.11-venv python3.11-dev

# macOS (via pyenv — recommended)
brew install pyenv
pyenv install 3.11.9
pyenv local 3.11.9

# Verify
python3.11 --version   # Python 3.11.x
```

---

### Node.js 20 LTS (local dev only — not needed for Docker)

```bash
# Ubuntu / Debian — via NodeSource
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# macOS (via nvm — recommended)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
source ~/.nvm/nvm.sh
nvm install 20
nvm use 20

# Verify
node --version   # v20.x
npm --version    # 10.x
```

---

## 3. Clone the Repository

```bash
git clone https://github.com/BitR1ft/UniVex.git univex
cd univex
```

> **Note:** All subsequent commands in this guide assume you are inside the `univex/` directory unless stated otherwise.

---

## 4. Configure Environment Variables

UniVex uses a single `.env` file at the repository root that is read by both Docker Compose and the backend application.

### Step 1 — Copy the example file

```bash
cp .env.example .env
```

### Step 2 — Generate secrets

```bash
# Generate a strong SECRET_KEY (copy the output into .env)
openssl rand -hex 32
```

### Step 3 — Edit `.env`

Open `.env` in your editor and set **at minimum** the following values:

```dotenv
# Security 
SECRET_KEY=<paste the openssl output here>       # REQUIRED — min 32 hex chars

# Database passwords 
POSTGRES_USER=univex
POSTGRES_PASSWORD=<strong-password-here>         # REQUIRED
POSTGRES_DB=univex
DATABASE_URL=postgresql://univex:<POSTGRES_PASSWORD>@postgres:5432/univex

NEO4J_USER=neo4j
NEO4J_PASSWORD=<strong-password-here>            # REQUIRED — min 8 chars

# Observability 
GRAFANA_USER=admin
GRAFANA_PASSWORD=<strong-password-here>          # REQUIRED

# AI Providers (at least ONE required for the AI agent) 
# Free tier options:
# Google Gemini  → https://aistudio.google.com/app/apikey
# Groq           → https://console.groq.com/keys
#
OPENAI_API_KEY=sk-...                            # Optional but recommended
GOOGLE_API_KEY=AIza...                           # Free tier available
GROQ_API_KEY=gsk_...                             # Free tier available
```

> **Security rules:**
> - Never commit `.env` to version control (it is already in `.gitignore`).
> - Use a unique password for every service.
> - Minimum password length: 16 characters in staging/production.

---

## 5. Quick Start — Docker Compose (Recommended)

This single command starts the entire stack (databases, backend, frontend, monitoring):

```bash
docker compose --profile dev up -d --build
```

> The `--build` flag is only needed on the first run or after code changes.
> Subsequent starts: `docker compose --profile dev up -d`

### What starts

| Container | Port(s) | Description |
|-----------|---------|-------------|
| `univex-postgres` | 5432 | PostgreSQL 16 (relational DB) |
| `univex-neo4j` | 7474, 7687 | Neo4j 5.15 (attack graph DB) |
| `univex-backend` | 8000 | FastAPI REST + WebSocket API |
| `univex-frontend` | 3000 | Next.js web application |
| `univex-prometheus` | 9090 | Prometheus metrics scraper |
| `univex-grafana` | 3001 | Grafana dashboards |
| `univex-kali-tools` | 8000–8007 | Kali Linux + MCP tool servers |
| `univex-recon` | — | Dedicated recon tools container |

### Watch startup progress

```bash
# Stream all logs (press Ctrl+C to stop streaming; containers keep running)
docker compose logs -f

# Wait until all services are healthy (~60–90 seconds on first run)
docker compose ps
```

Expected output once healthy:
```
NAME                STATUS        PORTS
univex-backend      healthy       0.0.0.0:8000->8000/tcp
univex-frontend     healthy       0.0.0.0:3000->3000/tcp
univex-postgres     healthy       127.0.0.1:5432->5432/tcp
univex-neo4j        healthy       127.0.0.1:7474->7474/tcp
```

---

## 6. Database Setup & Migrations

> **If you used Docker Compose, migrations run automatically** via `entrypoint.sh` when the backend container starts. You can skip to Step 8 to verify.

If you need to run migrations manually (e.g. after a fresh clone with an existing volume, or for local development):

### Apply migrations (safe — idempotent, no data loss)

```bash
# Via Docker
docker compose exec backend python -m prisma migrate deploy

# Or locally (with DATABASE_URL exported in your shell)
cd backend
python -m prisma migrate deploy
```

### Check migration status

```bash
docker compose exec backend python -m prisma migrate status
```

### What the migration creates

| Table | Purpose |
|-------|---------|
| `users` | Registered user accounts |
| `sessions` | JWT refresh token store |
| `projects` | Penetration testing projects |
| `tasks` | Task records (recon / port scan / http probe) |
| `recon_tasks` | Domain discovery results |
| `port_scan_tasks` | Port scanning results |
| `http_probe_tasks` | HTTP probe results |
| `task_results` | Arbitrary JSON output blobs |
| `task_logs` | Structured execution log entries |
| `task_metrics` | Performance metrics (duration, memory, CPU) |

---

## 7. Seed the Database (Optional)

The seed script creates default demo accounts and sample projects.

```bash
# Via Docker
docker compose exec backend python prisma/seed.py

# Or locally
cd backend
python prisma/seed.py
```

**Default accounts created:**

| Username | Password | Role |
|----------|----------|------|
| `admin` | `Admin@12345` | Administrator |
| `demo` | `Demo@12345` | Regular user |

> ⚠️ **Change these passwords immediately in production.**

---

## 8. Verify Everything is Healthy

### Check the health endpoint

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
```

Expected response:
```json
{
  "status": "healthy",
  "services": {
    "api": "operational",
    "database": "healthy",
    "neo4j": "healthy"
  }
}
```

If `"database": "unavailable"` appears, see [Database Errors](#database-errors) below.

### Check the readiness endpoint

```bash
curl -s http://localhost:8000/readiness | python3 -m json.tool
# Expected HTTP 200 with "status": "ready"
```

### Access the web interfaces

| Service | URL | Credentials |
|---------|-----|-------------|
| **Web App** | http://localhost:3000 | Register or use seed accounts |
| **API Docs (Swagger)** | http://localhost:8000/docs | — |
| **API Docs (ReDoc)** | http://localhost:8000/redoc | — |
| **Neo4j Browser** | http://localhost:7474 | `neo4j` / `$NEO4J_PASSWORD` |
| **Grafana** | http://localhost:3001 | `admin` / `$GRAFANA_PASSWORD` |
| **Prometheus** | http://localhost:9090 | — |

---

## 9. Manual / Local Development Setup

Use this when you want live hot-reload for backend or frontend code without rebuilding Docker images.

Start only the databases via Docker, then run the app services locally:

```bash
docker compose up -d postgres neo4j
```

---

### 9a. Backend (FastAPI)

```bash
cd backend

# Create and activate a virtual environment
python3.11 -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate.bat       # Windows CMD
# .venv\Scripts\Activate.ps1       # Windows PowerShell

# Upgrade pip to latest
pip install --upgrade pip setuptools wheel

# Install runtime + development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Generate the Prisma client (must be done once and after schema changes)
python -m prisma generate

# Export required environment variables
export DATABASE_URL="postgresql://univex:yourpassword@localhost:5432/univex"
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="yourpassword"
export SECRET_KEY="$(openssl rand -hex 32)"
export ENVIRONMENT="development"
# Add any AI provider keys you need:
export OPENAI_API_KEY="sk-..."

# Apply database migrations
python -m prisma migrate deploy

# Start the development server with auto-reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API is now available at **http://localhost:8000**
Interactive docs: **http://localhost:8000/docs**

---

### 9b. Frontend (Next.js)

Open a **new terminal** (keep the backend running):

```bash
cd frontend

# Install Node.js dependencies
npm install

# Create local environment file
cp .env.local.example .env.local 2>/dev/null || true

# If .env.local.example doesn't exist, create .env.local manually:
cat > .env.local <<EOF
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000
EOF

# Start the Next.js dev server with hot-reload
npm run dev
```

The frontend is now available at **http://localhost:3000**

---

## 10. Running Tests

### Backend tests

```bash
# Via Docker (recommended — has all dependencies)
docker compose exec backend python -m pytest tests/ --ignore=tests/test_auth.py -q

# Locally (requires live postgres on localhost:5432 for test_auth)
cd backend
source .venv/bin/activate
python -m pytest tests/ --ignore=tests/test_auth.py -q

# Run with coverage report
python -m pytest tests/ --ignore=tests/test_auth.py --cov=app --cov-report=term-missing -q

# Run only auth tests (requires a live PostgreSQL connection)
python -m pytest tests/test_auth.py -v
```

### Frontend tests

```bash
# Via Docker
docker compose exec frontend npm test -- --watchAll=false

# Locally
cd frontend
npm test -- --watchAll=false

# Type-check only (no test runner needed)
npm run type-check
```

### E2E tests (Playwright)

```bash
# Ensure the full stack is running first
docker compose --profile dev up -d

# Install Playwright browsers (first time only)
npx playwright install --with-deps

# Run all E2E tests
npx playwright test

# Run with UI mode
npx playwright test --ui

# Run a specific spec
npx playwright test e2e/auth.spec.ts
```

---

## 11. Useful Day-to-Day Commands

### Stack management

```bash
# Start the full stack
docker compose --profile dev up -d

# Start only infrastructure (no app containers)
docker compose up -d postgres neo4j

# Stop all containers (keeps volumes / data)
docker compose down

# Stop and remove ALL volumes (wipes all data — use with care)
docker compose down -v

# Restart a single service
docker compose restart backend

# Rebuild and restart one service
docker compose up -d --build backend
```

### Logs

```bash
# All services
docker compose logs -f

# One service only
docker compose logs -f backend
docker compose logs -f frontend
docker compose logs -f postgres
docker compose logs -f neo4j

# Last 100 lines of backend logs
docker compose logs --tail=100 backend
```

### Database

```bash
# Open a PostgreSQL shell
docker exec -it univex-postgres psql -U univex

# Run a quick query
docker exec -it univex-postgres psql -U univex -c "SELECT COUNT(*) FROM users;"

# Apply pending migrations
docker compose exec backend python -m prisma migrate deploy

# Check migration status
docker compose exec backend python -m prisma migrate status

# Regenerate Prisma client (after schema.prisma changes)
docker compose exec backend python -m prisma generate

# Back up the database
docker exec univex-postgres pg_dump -U univex univex > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore a backup
docker exec -i univex-postgres psql -U univex univex < backup_20240101_000000.sql
```

### Neo4j

```bash
# Open the Cypher shell
docker exec -it univex-neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD"

# Run a quick query
docker exec -it univex-neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD" \
  "MATCH (n) RETURN count(n) AS node_count;"
```

### Kali tools container

```bash
# Open a bash shell inside Kali
docker exec -it univex-kali-tools bash

# Run nmap from the Kali container
docker exec univex-kali-tools nmap -sV 10.10.10.3
```

### Container resource usage

```bash
docker stats --no-stream
```

---

## 12. Error Handling — Common Problems & Fixes

---

### Docker / Container Errors

#### `Cannot connect to the Docker daemon`

```
Error response from daemon: dial unix /var/run/docker.sock: connect: permission denied
```

**Fix:**
```bash
sudo usermod -aG docker $USER
newgrp docker
# Or log out and back in
```

---

#### Container exits immediately / `Exited (1)`

```bash
# Check the logs to find the real error
docker compose logs <service-name> --tail=50

# Example
docker compose logs backend --tail=50
```

---

#### `Port already in use`

```
Error response from daemon: Ports are not available: address already in use
```

**Fix — find and stop the conflicting process:**
```bash
# Linux / macOS
sudo lsof -i :<PORT>          # e.g. sudo lsof -i :8000
sudo kill -9 <PID>

# Windows (PowerShell)
netstat -ano | findstr :<PORT>
taskkill /PID <PID> /F
```

Or change the host port in `docker-compose.yml`:
```yaml
ports:
  - "8001:8000"   # Changed host port from 8000 to 8001
```

---

#### Service stuck in `starting` / health check failing

```bash
# Increase start_period in docker-compose.yml if services take longer to boot
# Or wait and re-check
docker compose ps

# Force-recreate a specific container
docker compose up -d --force-recreate backend
```

---

#### `no space left on device`

```bash
# Remove stopped containers, dangling images, unused networks
docker system prune

# Also remove unused volumes (⚠️ deletes data not attached to running containers)
docker system prune --volumes

# Check disk usage by Docker
docker system df
```

---

### Database Errors

#### `"database": "unavailable"` in `/health`

The Prisma migrations have not been applied — no tables exist in the database.

**Fix:**
```bash
docker compose exec backend python -m prisma migrate deploy
```

If the above fails with `relation "_prisma_migrations" already exists`:
```bash
# The migration tracking table exists but has no rows
# Force-resolve by marking the migration as applied
docker exec -it univex-postgres psql -U univex -c \
  "DELETE FROM _prisma_migrations;"

# Then re-deploy
docker compose exec backend python -m prisma migrate deploy
```

---

#### `FATAL: password authentication failed for user "univex"`

The `POSTGRES_PASSWORD` in `.env` doesn't match what was used when the volume was first created.

**Option A — update the password to match the existing volume:**
Find what password was used and set it in `.env`.

**Option B — wipe the volume and start fresh:**
```bash
docker compose down -v
docker compose --profile dev up -d --build
```

---

#### `prisma migrate dev --name init` fails with `relation "_prisma_migrations" already exists`

The migration tracking table already exists from a previous aborted run.

**Fix:**
```bash
# Use 'deploy' instead of 'dev' — it is designed for this case
docker compose exec backend python -m prisma migrate deploy
```

---

#### `FATAL: database "univex" does not exist`

The database was not created on first init (either the volume predates it or init scripts didn't run).

**Fix:**
```bash
docker exec -it univex-postgres psql -U univex -c "CREATE DATABASE univex;"
docker compose exec backend python -m prisma migrate deploy
```

---

#### Prisma client not generated (`ModuleNotFoundError: No module named 'prisma.models'`)

```bash
docker compose exec backend python -m prisma generate
# Or locally:
cd backend && python -m prisma generate
```

---

### Backend / Python Errors

#### `ModuleNotFoundError` when running tests locally

The virtual environment is not activated, or dependencies are missing.

```bash
cd backend
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

---

#### `ResolutionImpossible` / pip dependency conflict

```bash
pip install --upgrade pip
pip install -r requirements.txt --no-cache-dir
```

---

#### `address already in use` on port 8000

```bash
# Find the PID using port 8000
lsof -i :8000
kill -9 <PID>

# Or use a different port
uvicorn app.main:app --reload --port 8001
```

---

#### `SECRET_KEY` error on startup

```
ValueError: SECRET_KEY must be at least 32 characters
```

```bash
# Generate a valid key
openssl rand -hex 32
# Paste the output into .env as SECRET_KEY=<value>
```

---

#### `uvicorn: command not found`

The virtual environment is not activated:

```bash
cd backend
source .venv/bin/activate
which uvicorn   # Should show .venv path
```

---

#### Backend health check reports `"neo4j": "unknown"` or `"degraded"`

Neo4j is still starting up (it takes ~30–60 seconds).

```bash
# Wait and retry
sleep 30
curl -s http://localhost:8000/health | python3 -m json.tool

# Check Neo4j logs
docker compose logs neo4j --tail=30
```

---

### Frontend / Node.js Errors

#### `npm install` fails with `ERESOLVE`

Dependency tree conflicts.

```bash
cd frontend
rm -rf node_modules package-lock.json
npm install --legacy-peer-deps
```

---

#### Frontend build fails (`next build`)

```bash
cd frontend
rm -rf .next node_modules
npm install
npm run build
```

---

#### `TypeError` or `Cannot find module` after pulling new code

Dependencies changed. Re-install:

```bash
cd frontend
npm install
```

---

#### `NEXT_PUBLIC_API_URL` is undefined / frontend can't reach the backend

```bash
# Check the value in .env (or frontend/.env.local for local dev)
grep NEXT_PUBLIC_API_URL .env

# It must be reachable from your browser:
# - Docker: http://localhost:8000
# - Remote server: http://<server-ip>:8000
```

> **Note:** `NEXT_PUBLIC_*` variables are baked in at **build time** by Next.js.
> If you change them, you must rebuild the frontend container:
> ```bash
> docker compose up -d --build frontend
> ```

---

#### Frontend container fails health check

```
univex-frontend   unhealthy
```

```bash
docker compose logs frontend --tail=50

# The health check calls /api/health on port 3000
# If Next.js hasn't fully started, wait 60s and check again
docker compose ps
```

---

### AI Agent / LLM Errors

#### `AuthenticationError: No API key provided`

No LLM provider key is configured in `.env`.

```bash
# Set at least one — free options:
# Google Gemini
GOOGLE_API_KEY=AIza...   # → https://aistudio.google.com/app/apikey
# Groq
GROQ_API_KEY=gsk_...     # → https://console.groq.com/keys
```

After editing `.env`, restart the backend:
```bash
docker compose restart backend
```

---

#### `RateLimitError` from OpenAI / Anthropic

You've exceeded the API rate limit.

**Fix:**
- Wait and retry.
- Switch to a different provider by setting a different `*_API_KEY` in `.env`.
- Use `GROQ_API_KEY` (very generous free tier) as a fallback.

---

#### AI agent returns empty responses or hangs

```bash
# Check the AI configuration in .env
grep -E "OPENAI|ANTHROPIC|GOOGLE|GROQ" .env

# Check backend logs for LLM errors
docker compose logs backend --tail=100 | grep -i "error\|llm\|openai"
```

---

### Neo4j Errors

#### `Neo.ClientError.Security.Unauthorized` — Authentication failed

The `NEO4J_PASSWORD` in `.env` doesn't match what Neo4j has stored.

**Fix A — change the password to match:**
```bash
docker exec -it univex-neo4j cypher-shell -u neo4j -p <current-password> \
  "ALTER CURRENT USER SET PASSWORD FROM '<current>' TO '<new>';"
# Update NEO4J_PASSWORD in .env to match
```

**Fix B — wipe the Neo4j volume:**
```bash
docker compose stop neo4j
docker volume rm univex-neo4j-data
docker compose up -d neo4j
```

---

#### Neo4j browser not loading at `localhost:7474`

```bash
docker compose logs neo4j --tail=50

# Check if the port is bound
docker compose ps neo4j
```

Ensure `NEO4J_HTTP_PORT=7474` is set in `.env` and there is no firewall blocking it.

---

#### `ServiceUnavailable: Failed to establish connection to neo4j:7687`

Neo4j is still booting. It typically takes 30–60 seconds.

```bash
# Watch the logs until "Started" appears
docker compose logs -f neo4j | grep -i "started\|bolt\|http"
```

---

### Port Conflicts

Default ports and how to change them:

| Service | Default Port | `.env` Variable |
|---------|-------------|-----------------|
| Frontend | 3000 | `FRONTEND_PORT` |
| Backend API | 8000 | `API_PORT` |
| PostgreSQL | 5432 | `POSTGRES_PORT` |
| Neo4j HTTP | 7474 | `NEO4J_HTTP_PORT` |
| Neo4j Bolt | 7687 | `NEO4J_BOLT_PORT` |
| Grafana | 3001 | — (hardcoded in compose) |
| Prometheus | 9090 | — (hardcoded in compose) |

**Example — change the frontend port to 4000:**
```dotenv
# .env
FRONTEND_PORT=4000
```

Then restart:
```bash
docker compose --profile dev up -d
```

---

## 13. Resetting to a Clean State

### Soft reset — restart all containers (keeps data)

```bash
docker compose down
docker compose --profile dev up -d --build
```

### Hard reset — wipe all data and start fresh

```bash
# Stop containers and delete all volumes (ALL DATA WILL BE LOST)
docker compose down -v

# Remove built images too (forces a full rebuild)
docker compose down -v --rmi local

# Start fresh
docker compose --profile dev up -d --build
```

### Reset only the database

```bash
# Stop only the backend and database
docker compose stop backend postgres

# Remove the postgres volume
docker volume rm univex-postgres-data

# Restart and re-migrate
docker compose up -d postgres
sleep 10
docker compose up -d backend
docker compose exec backend python -m prisma migrate deploy
```

---

## 14. Uninstallation

### Remove containers and data

```bash
docker compose down -v
```

> ⚠️ `-v` permanently deletes all database volumes. Back up first if needed.

### Remove Docker images

```bash
# Remove only UniVex-built images
docker images | grep univex | awk '{print $3}' | xargs docker rmi -f

# Remove ALL unused images (affects other projects)
docker image prune -a
```

### Remove the repository

```bash
cd ..
rm -rf univex
```

---

## Quick Reference Card

```
# First-time setup
git clone https://github.com/BitR1ft/UniVex.git univex && cd univex
cp .env.example .env && $EDITOR .env
docker compose --profile dev up -d --build

# Check health
curl -s http://localhost:8000/health | python3 -m json.tool

# Seed demo data
docker compose exec backend python prisma/seed.py

# Logs
docker compose logs -f backend

# Apply migrations
docker compose exec backend python -m prisma migrate deploy

# Run backend tests
docker compose exec backend python -m pytest tests/ --ignore=tests/test_auth.py -q

# Stop everything
docker compose down

# Full wipe + restart
docker compose down -v && docker compose --profile dev up -d --build
```

---

> **⚠️ Legal Disclaimer**: UniVex is a professional security research tool. Only use it against systems you own or have explicit written authorisation to test. Unauthorised security testing is illegal and unethical.

---

*Maintained by [BitR1FT](https://github.com/BitR1ft) — UniVex v1.0.0*
