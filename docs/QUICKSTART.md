# UniVex — Quick Start Guide

> **v1.0.0** | Get up and running in 5 minutes with Docker

---

## Prerequisites

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Docker Engine | 24.0+ | |
| Docker Compose | v2.20+ | Compose V2 plugin (`docker compose`, not `docker-compose`) |
| OpenAI **or** Anthropic API key | — | Required for AI agent |
| Git | any | |

Hardware: 8 GB RAM, 20 GB free disk space.

---

## 1 — Clone & Configure

```bash
git clone https://github.com/BitR1ft/UniVex.git univex
cd univex
cp .env.example .env
```

Open `.env` and set **at minimum** these values:

```dotenv
# Generate with: openssl rand -hex 32
SECRET_KEY=<your-32-byte-hex-string>

# At least one LLM provider (free options: GOOGLE_API_KEY or GROQ_API_KEY)
OPENAI_API_KEY=sk-...
# ANTHROPIC_API_KEY=sk-ant-...
# GOOGLE_API_KEY=AIza...        ← free tier at aistudio.google.com
# GROQ_API_KEY=gsk_...          ← free tier at console.groq.com
# OPENROUTER_API_KEY=sk-or-v1-... ← openrouter.ai

# Database passwords (change all defaults)
POSTGRES_PASSWORD=changeme
NEO4J_PASSWORD=changeme

# Grafana dashboard password
GRAFANA_PASSWORD=changeme

# Auto-approval level for AutoChain
# none=all need approval | high=auto-approve low/med/high | critical=fully-autonomous
AUTO_APPROVE_RISK_LEVEL=none
```

---

## 2 — Start the Stack

```bash
docker compose up -d
```

This starts all 8 services. First run pulls images (~2-3 GB) — allow 2-3 minutes.

```bash
# Watch startup progress
docker compose logs -f --tail=50

# Check all services are healthy (wait ~60s)
docker compose ps
```

All services should show `healthy` or `running`:

```
NAME                          STATUS        PORTS
univex-backend         healthy       0.0.0.0:8000->8000/tcp
univex-frontend        healthy       0.0.0.0:3000->3000/tcp
univex-postgres        healthy       0.0.0.0:5432->5432/tcp
univex-neo4j           healthy       0.0.0.0:7474->7474/tcp
univex-kali-tools      running       0.0.0.0:8000-8007->8000-8007/tcp
univex-prometheus      running       0.0.0.0:9090->9090/tcp
univex-grafana         running       0.0.0.0:3001->3000/tcp
```

---

## 3 — Verify Health

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
```

Expected:
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

---

## 4 — Access the Services

| Service | URL | Credentials |
|---------|-----|-------------|
| **Web App** | http://localhost:3000 | Register on first visit |
| **API Docs (Swagger)** | http://localhost:8000/docs | — |
| **API Docs (ReDoc)** | http://localhost:8000/redoc | — |
| **Neo4j Browser** | http://localhost:7474 | `neo4j` / `$NEO4J_PASSWORD` |
| **Grafana Dashboards** | http://localhost:3001 | `admin` / `$GRAFANA_PASSWORD` |
| **Prometheus** | http://localhost:9090 | — |

---

## 5 — First Scan (Web UI)

1. Open http://localhost:3000 and **Register** an account
2. Click **New Project**
3. Enter target: `10.10.10.3` (or any authorised host)
4. Click **Create Project**
5. Click **Start Scan** — watch real-time progress in the Scan Progress panel
6. Open the **Attack Graph** tab to see discovered assets in Neo4j
7. Open the **AI Agent** tab and ask: *"What did you find?"*

---

## 6 — First AutoChain Run (API)

```bash
# Save your token
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"YOUR_USER","password":"YOUR_PASS"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Launch automated chain (htb_easy template)
CHAIN=$(curl -s -X POST http://localhost:8000/api/autochain/start/template \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"template_id":"htb_easy","target":"10.10.10.3"}')

echo $CHAIN | python3 -m json.tool

# Extract chain_id and stream progress
CHAIN_ID=$(echo $CHAIN | python3 -c "import sys,json; print(json.load(sys.stdin)['chain_id'])")
curl -N http://localhost:8000/api/autochain/$CHAIN_ID/stream

# View captured flags when done
curl -s http://localhost:8000/api/autochain/$CHAIN_ID/flags | python3 -m json.tool
```

---

## 7 — Local Development Setup

If you want to develop without Docker:

**Databases only via Docker:**
```bash
docker compose up -d postgres neo4j
```

**Backend:**
```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
prisma generate && prisma db push
uvicorn app.main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

**Run tests:**
```bash
# Backend
cd backend && pytest -v

# Frontend
cd frontend && npm test
```

---

## 8 — Useful Commands

```bash
# Stop all services
docker compose down

# Stop and remove all volumes (clean slate)
docker compose down -v

# Tail all logs
docker compose logs -f

# Restart a single service
docker compose restart backend

# View backend logs only
docker compose logs -f backend

# Open a shell in the Kali container
docker exec -it univex-kali-tools bash

# Connect to PostgreSQL
docker exec -it univex-postgres psql -U univex

# Open Neo4j shell
docker exec -it univex-neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD"
```

---

## Troubleshooting

**Port already in use:**
```bash
# Find what's using port 8000
lsof -i :8000       # macOS / Linux
netstat -ano | findstr :8000   # Windows

# Change port in .env and docker-compose.yml if needed
```

**Service not healthy:**
```bash
docker compose logs postgres    # Check DB startup errors
docker compose logs backend     # Check API startup errors
docker compose logs neo4j       # Check graph DB errors
```

**Frontend can't connect to backend:**
```bash
# Ensure NEXT_PUBLIC_API_URL is correct in .env
echo $NEXT_PUBLIC_API_URL     # Should be http://localhost:8000
```

**OpenAI / Anthropic API errors:**
- Verify your API key is set correctly in `.env`
- Ensure you have sufficient credits
- Check model availability in your region

**Neo4j authentication failure:**
- Ensure `NEO4J_PASSWORD` in `.env` matches `NEO4J_AUTH` format in docker-compose.yml
- Default format: `NEO4J_AUTH=neo4j/<password>`

---

## Next Steps

-  **Full usage guide**: [docs/USER_MANUAL.md](USER_MANUAL.md)
-  **API reference**: [docs/API_REFERENCE.md](API_REFERENCE.md)
-  **Architecture**: [docs/ARCHITECTURE.md](ARCHITECTURE.md)
-  **All config options**: [docs/CONFIGURATION_GUIDE.md](CONFIGURATION_GUIDE.md)
-  **Production deployment**: [README.md — Section 5.2](../README.md#52-production-deployment)

---

> **⚠️ Legal**: Only test systems you own or have explicit written permission to test.
