# UniVex — Installation Guide (v1.0.0)

> **v1.0.0** — Comprehensive setup guide for development, staging and production environments.

---

## Table of Contents

0. [Quick Install (one-liner)](#0-quick-install-one-liner)
1. [Prerequisites](#prerequisites)
2. [Quick Start (Docker — recommended)](#quick-start-docker--recommended)
3. [Manual Development Setup](#manual-development-setup)
4. [Production Deployment](#production-deployment)
5. [Post-Installation Verification](#post-installation-verification)
6. [Troubleshooting](#troubleshooting)
7. [Uninstallation](#uninstallation)

---

## 0. Quick Install (one-liner)

The fastest way to install UniVex is using the pre-built installer from the latest
GitHub Release. **Always verify the checksum before executing.**

### Docker-based (recommended)

```bash
curl -LO https://github.com/BitR1ft/UniVex/releases/latest/download/install.sh
curl -LO https://github.com/BitR1ft/UniVex/releases/latest/download/install.sh.sha256
sha256sum -c install.sh.sha256
bash install.sh
```

### Podman / rootless containers

```bash
curl -LO https://github.com/BitR1ft/UniVex/releases/latest/download/install-podman.sh
curl -LO https://github.com/BitR1ft/UniVex/releases/latest/download/install-podman.sh.sha256
sha256sum -c install-podman.sh.sha256
bash install-podman.sh
```

### Verify all release assets at once

```bash
curl -LO https://github.com/BitR1ft/UniVex/releases/latest/download/checksums.txt
sha256sum -c checksums.txt
```

> ⚠️ **Security note:** Never pipe an installer directly to `bash` without checksum
> verification (`curl -sL ... | bash`). The `.sha256` files allow you to verify that
> the downloaded file has not been tampered with before execution.

---

## Prerequisites

### Hardware

| Environment | CPU | RAM | Disk |
|-------------|-----|-----|------|
| Development | 2 cores | 4 GB | 20 GB |
| Staging | 4 cores | 8 GB | 50 GB |
| Production | 8 cores | 16 GB | 200 GB+ |

### Software

| Dependency | Minimum | Recommended | Notes |
|------------|---------|-------------|-------|
| Docker | 24.0 | 25.0+ | Required for containerised setup |
| Docker Compose | 2.20 | 2.24+ | Compose V2 (plugin, not standalone) |
| Python | 3.11 | 3.11.x | For local backend dev only |
| Node.js | 20 LTS | 20.x | For local frontend dev only |
| Git | 2.40 | latest | Any recent version |
| make | 3.81+ | any | Optional but recommended |

### External Services (optional but recommended)

- **OpenAI API key** — GPT-4o for AI agent (set `OPENAI_API_KEY`)
- **Anthropic API key** — Claude fallback (set `ANTHROPIC_API_KEY`)
- **LangSmith key** — observability tracing (set `LANGSMITH_API_KEY`)

### Kali Linux Tooling (for real recon)

The backend can run reconnaissance tools inside a Kali container. Ensure Docker can
pull `kalilinux/kali-rolling` from Docker Hub, or pre-pull it:

```bash
docker pull kalilinux/kali-rolling
```

---

## Quick Start (Docker — recommended)

### 1. Clone the repository

```bash
git clone https://github.com/BitR1ft/UniVex.git univex
cd univex
```

### 2. Create your environment file

```bash
cp .env.example .env
```

Edit `.env` and set **at minimum**:

```dotenv
# Required — change all of these
SECRET_KEY=<run: openssl rand -hex 32>
DATABASE_URL=postgresql://univex:changeme@postgres:5432/univex
NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=changeme
GRAFANA_PASSWORD=changeme

# AI providers (at least one required)
OPENAI_API_KEY=sk-...
```

### 3. Start the stack

```bash
docker compose up -d
```

This starts:

| Service | Port | Description |
|---------|------|-------------|
| `frontend` | 3000 | Next.js web application |
| `backend` | 8000 | FastAPI REST + WebSocket API |
| `postgres` | 5432 | PostgreSQL 16 database |
| `neo4j` | 7474 / 7687 | Neo4j graph database |
| `prometheus` | 9090 | Metrics collection |
| `grafana` | 3001 | Metrics dashboards |

### 4. Run database migrations

```bash
docker compose exec backend python -m prisma migrate deploy
```

### 5. Create the first admin user

```bash
docker compose exec backend python -c "
from app.core.database import get_db
from app.services.auth import create_user
import asyncio

async def main():
    async for db in get_db():
        await create_user(db, username='admin', password='ChangeMe123!', role='admin')
        print('Admin user created')

asyncio.run(main())
"
```

### 6. Open the application

Navigate to **http://localhost:3000** and log in with the credentials you just set.

---

## Manual Development Setup

Use this if you want hot-reload for both the backend and frontend simultaneously.

### Backend (FastAPI)

#### a. Create a Python virtual environment

```bash
cd backend
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate           # Windows
```

#### b. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

#### c. Start infrastructure only (Postgres + Neo4j)

```bash
docker compose up -d postgres neo4j
```

#### d. Set environment variables

```bash
export DATABASE_URL="postgresql://univex:changeme@localhost:5432/univex"
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="changeme"
export SECRET_KEY="$(openssl rand -hex 32)"
export ENVIRONMENT="development"
```

Or copy `.env.example` to `backend/.env` and use `python-dotenv`.

#### e. Apply migrations

```bash
python -m prisma migrate dev --name init
```

#### f. Start the dev server

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API is now available at **http://localhost:8000** with interactive docs at
**http://localhost:8000/docs**.

---

### Frontend (Next.js)

#### a. Install Node dependencies

```bash
cd frontend
npm install
```

#### b. Set environment variables

```bash
cp .env.local.example .env.local
```

Edit `frontend/.env.local`:

```dotenv
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000
```

#### c. Start the dev server

```bash
npm run dev
```

The frontend is now available at **http://localhost:3000**.

---

## Production Deployment

See [OPERATIONS_RUNBOOK.md](./OPERATIONS_RUNBOOK.md) and
[CI_CD_GUIDE.md](./CI_CD_GUIDE.md) for full deployment instructions.

### High-level steps

1. Provision a server meeting the hardware requirements above.
2. Install Docker Engine + Compose V2.
3. Clone the repository.
4. Configure production secrets (never use defaults).
5. Run `docker compose -f docker/production/docker-compose.production.yml up -d`.
6. Configure Nginx reverse proxy with TLS (see `docker/production/`).
7. Set up daily backups (pg_dump sidecar is pre-configured).
8. Register GitHub Environments for deployment approvals.

---

## Post-Installation Verification

Run the built-in health check:

```bash
curl http://localhost:8000/health
# Expected: {"status":"healthy","database":"connected","neo4j":"connected"}
```

Run the backend test suite:

```bash
docker compose exec backend pytest tests/ -q --tb=short
```

Run the frontend type-check:

```bash
docker compose exec frontend npm run type-check
```

Check container resource usage:

```bash
docker stats --no-stream
```

---

## Troubleshooting

### Container fails to start

```bash
docker compose logs <service-name> --tail=50
```

Common causes:

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `port already in use` | Port conflict | Change host port in `docker-compose.yml` |
| `connection refused` to Postgres | DB not ready yet | Wait 30 s; add `depends_on` healthcheck |
| `invalid SECRET_KEY` | Env var not set | Set `SECRET_KEY` to 32+ hex chars |
| Neo4j `Authentication failed` | Wrong credentials | Check `NEO4J_PASSWORD` matches both services |

### Python dependency conflict

If you see `ResolutionImpossible` during `pip install`:

```bash
pip install --upgrade pip
pip install -r requirements.txt --no-cache-dir
```

### Frontend build errors

```bash
cd frontend
rm -rf .next node_modules
npm install
npm run build
```

### Database migration fails

```bash
docker compose exec backend python -m prisma migrate reset --force
docker compose exec backend python -m prisma migrate deploy
```

### Grafana login fails

Default credentials are `admin` / the value of `GRAFANA_PASSWORD` in `.env`.
If you've forgotten it, reset via:

```bash
docker compose exec grafana grafana-cli admin reset-admin-password <new-password>
```

### Neo4j browser not loading

Ensure port 7474 is accessible. If behind a reverse proxy, set:

```
dbms.default_advertised_address=<your-host>
```

in `neo4j.conf`.

---

## Uninstallation

### Remove containers and volumes

```bash
docker compose down -v
```

> ⚠️ **Warning**: `-v` deletes all data volumes including the database. Back up first.

### Remove images

```bash
docker image prune -a --filter "label=com.univex=true"
```

### Remove the repository

```bash
cd ..
rm -rf univex
```

---

*Last updated: March 2026*