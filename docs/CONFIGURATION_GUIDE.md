# UniVex — Configuration Guide

> Complete reference for every environment variable, configuration file, and
> runtime option in UniVex.

---

## Table of Contents

1. [Environment Variables Reference](#environment-variables-reference)
2. [Configuration Files](#configuration-files)
3. [Feature Flags](#feature-flags)
4. [Rate Limiting Configuration](#rate-limiting-configuration)
5. [AI Agent Configuration](#ai-agent-configuration)
6. [Security Configuration](#security-configuration)
7. [Observability Configuration](#observability-configuration)
8. [Docker Compose Overrides](#docker-compose-overrides)
9. [Environment-Specific Best Practices](#environment-specific-best-practices)

---

## Environment Variables Reference

Copy `.env.example` to `.env` and configure each section below.

### Core Application

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` |  | — | 32-byte hex secret for JWT signing. Generate: `openssl rand -hex 32` |
| `ENVIRONMENT` |  | `production` | One of `development`, `testing`, `staging`, `production` |
| `DEBUG` | — | `false` | Enable debug logging. **Never true in production** |
| `ALLOWED_ORIGINS` | — | `http://localhost:3000` | Comma-separated CORS allowed origins |
| `API_PREFIX` | — | `/api/v1` | URL prefix for all API routes |
| `APP_NAME` | — | `UniVex` | Application name shown in docs |

### Database

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` |  | — | PostgreSQL DSN, e.g. `postgresql+asyncpg://user:pass@host:5432/db` |
| `DB_POOL_SIZE` | — | `20` | SQLAlchemy connection pool size |
| `DB_MAX_OVERFLOW` | — | `10` | Additional connections beyond pool size |
| `DB_POOL_TIMEOUT` | — | `30` | Seconds to wait for a connection from pool |
| `DB_ECHO` | — | `false` | Log all SQL statements (development only) |

### Neo4j Graph Database

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NEO4J_URI` |  | — | Bolt URI, e.g. `bolt://neo4j:7687` |
| `NEO4J_USER` |  | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` |  | — | Neo4j password |
| `NEO4J_DATABASE` | — | `neo4j` | Database name (Enterprise: custom databases) |
| `NEO4J_MAX_CONNECTION_POOL_SIZE` | — | `50` | Max concurrent Neo4j connections |

### Authentication & Security

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `JWT_ALGORITHM` | — | `HS256` | JWT signing algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | — | `30` | Access token TTL |
| `REFRESH_TOKEN_EXPIRE_DAYS` | — | `7` | Refresh token TTL |
| `BCRYPT_ROUNDS` | — | `12` | bcrypt work factor (≥10 in production) |
| `WAF_ENABLED` | — | `true` | Enable WAF middleware (SQL injection / XSS detection) |
| `RATE_LIMIT_ENABLED` | — | `true` | Enable sliding-window rate limiting |

### AI Providers

At least one AI provider must be configured for the agent to function.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_API_KEY` | ⚠️ | — | OpenAI API key (GPT-4o default model) |
| `OPENAI_MODEL` | — | `gpt-4o` | OpenAI model name |
| `ANTHROPIC_API_KEY` | ⚠️ | — | Anthropic API key (Claude fallback) |
| `ANTHROPIC_MODEL` | — | `claude-3-5-sonnet-20241022` | Anthropic model name |
| `GOOGLE_API_KEY` | ⚠️ | — | Google API key (Gemini — free tier available) |
| `GOOGLE_MODEL` | — | `gemini-1.5-flash` | Google Gemini model name |
| `GROQ_API_KEY` | ⚠️ | — | Groq API key (free tier, fast inference) |
| `GROQ_MODEL` | — | `llama-3.3-70b-versatile` | Groq model name |
| `OPENROUTER_API_KEY` | ⚠️ | — | OpenRouter API key (access 100+ models) |
| `OPENROUTER_MODEL` | — | `anthropic/claude-3.5-sonnet` | OpenRouter model name |
| `AI_TEMPERATURE` | — | `0.1` | LLM sampling temperature (0–1) |
| `AI_MAX_TOKENS` | — | `4096` | Max tokens per LLM response |
| `AI_MAX_ITERATIONS` | — | `20` | Max ReAct loop iterations per agent session |
| `AI_TIMEOUT_SECONDS` | — | `300` | Total timeout for one agent task |

### LangSmith (optional)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LANGCHAIN_TRACING_V2` | — | `false` | Enable LangSmith tracing |
| `LANGCHAIN_API_KEY` | — | — | LangSmith API key |
| `LANGCHAIN_PROJECT` | — | `univex` | LangSmith project name |

### Tool Execution

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TOOL_EXECUTION_TIMEOUT` | — | `300` | Seconds before a tool subprocess is killed |
| `TOOL_MAX_CONCURRENT` | — | `3` | Max simultaneous tool processes per user |
| `KALI_IMAGE` | — | `kalilinux/kali-rolling` | Docker image for Kali tool sandbox |
| `TOOL_NETWORK_MODE` | — | `bridge` | Docker network mode for tool containers |
| `TOOL_MEMORY_LIMIT` | — | `512m` | Memory limit for each tool container |
| `TOOL_CPU_QUOTA` | — | `100000` | CPU quota (100000 = 1 core) |

### Frontend (Next.js — prefix `NEXT_PUBLIC_` for client-side)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NEXT_PUBLIC_API_URL` |  | `http://localhost:8000` | Backend API base URL |
| `NEXT_PUBLIC_WS_URL` |  | `ws://localhost:8000` | WebSocket base URL |
| `NEXT_PUBLIC_APP_NAME` | — | `UniVex` | Branding name |
| `NEXT_PUBLIC_ENABLE_REGISTRATION` | — | `true` | Show registration form |
| `NEXT_PUBLIC_MAX_UPLOAD_MB` | — | `10` | Max file upload size shown to users |

### Observability

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OTEL_ENABLED` | — | `false` | Enable OpenTelemetry tracing |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | `http://jaeger:4317` | OTLP gRPC endpoint |
| `OTEL_SERVICE_NAME` | — | `univex-backend` | Service name in traces |
| `PROMETHEUS_ENABLED` | — | `true` | Expose `/metrics` endpoint |
| `GRAFANA_PASSWORD` | — | `admin` | Grafana admin password (change in production!) |

### Email (optional — for alerts)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SMTP_HOST` | — | — | SMTP server hostname |
| `SMTP_PORT` | — | `587` | SMTP port |
| `SMTP_USER` | — | — | SMTP username |
| `SMTP_PASSWORD` | — | — | SMTP password |
| `SMTP_FROM` | — | `noreply@univex.local` | From address for system emails |
| `ALERT_EMAIL_TO` | — | — | Comma-separated alert recipients |

---

## Configuration Files

### `.env` / `.env.example`

Root-level file loaded by Docker Compose. Copy to `.env` and edit before first run.

```bash
cp .env.example .env
$EDITOR .env
```

### `backend/.env` (local dev only)

Optional backend-only overrides when running the API server directly with uvicorn.
Takes precedence over the root `.env` when the backend process loads it via
`python-dotenv`.

### `frontend/.env.local` (local dev only)

Next.js local dev overrides. Values prefixed with `NEXT_PUBLIC_` are exposed to
the browser bundle.

```bash
cp frontend/.env.local.example frontend/.env.local
```

### `docker-compose.yml`

Default stack configuration (development). Do not store secrets directly in this
file — use `.env` interpolation (`${VAR}`).

### `docker/staging/docker-compose.staging.yml`

Extends the base compose file with staging-specific resource limits and reduced
replica counts. Use:

```bash
docker compose -f docker-compose.yml -f docker/staging/docker-compose.staging.yml up -d
```

### `docker/production/docker-compose.production.yml`

Production configuration: 2 backend replicas, Nginx TLS termination, nightly
pg_dump sidecar, strict resource limits. See [OPERATIONS_RUNBOOK.md](./OPERATIONS_RUNBOOK.md).

---

## Feature Flags

Control optional features via environment variables without redeploying code.

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `ENABLE_CHAOS_MODE` | `true`/`false` | `false` | Enable chaos engineering endpoints (dev/staging only) |
| `ENABLE_GRAPH_EXPORT` | `true`/`false` | `true` | Allow graph export (GEXF, JSON) |
| `ENABLE_AUTO_EXPLOIT` | `true`/`false` | `false` | Enable autonomous exploitation (requires human approval) |
| `ENABLE_SUBDOMAIN_BRUTE` | `true`/`false` | `true` | Allow subdomain brute-forcing |
| `ENABLE_SELF_REGISTRATION` | `true`/`false` | `true` | Allow new users to register |
| `ENABLE_MULTI_TENANCY` | `true`/`false` | `false` | Enforce project-level tenant isolation |
| `ENABLE_AUDIT_LOG` | `true`/`false` | `true` | Persist audit events to structured log |
| `ENABLE_RATE_LIMITING` | `true`/`false` | `true` | API rate limiting middleware |

---

## Rate Limiting Configuration

Rate limits are configured in `backend/app/core/rate_limit.py` and can be tuned
via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_USER_RPM` | `60` | General API requests per minute per user |
| `RATE_LIMIT_SCAN_RPH` | `10` | Scan-start requests per hour per user |
| `RATE_LIMIT_LOGIN_ATTEMPTS` | `5` | Login attempts per 15 minutes per IP |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Default sliding-window duration |

To disable rate limiting globally (e.g., during load tests):

```bash
RATE_LIMIT_ENABLED=false
```

---

## AI Agent Configuration

### Model selection

The agent uses a priority-based provider selection:

1. `OPENAI_API_KEY` set → GPT-4o
2. `ANTHROPIC_API_KEY` set → Claude 3.5 Sonnet
3. `GOOGLE_API_KEY` set → Gemini 1.5 Flash
4. `GROQ_API_KEY` set → Llama 3.3 70B
5. `OPENROUTER_API_KEY` set → Claude 3.5 Sonnet (via OpenRouter)
6. None set → agent raises `ConfigurationError` at startup

Override per-request via the API:

```json
POST /api/v1/agent/chat
{
  "message": "...",
  "model_override": "gpt-4o-mini"
}
```

### Safety limits

```dotenv
AI_MAX_ITERATIONS=20           # Hard cap on ReAct loop steps
AI_TIMEOUT_SECONDS=300         # Wall-clock timeout per task
APPROVAL_REQUIRED_RISK=high    # Risk level requiring human approval: low/medium/high/critical
```

### Risk tiers

| Tier | Examples | Behaviour |
|------|----------|-----------|
| `low` | subdomain enum, banner grab | Auto-execute |
| `medium` | full port scan, web crawl | Auto-execute with audit log |
| `high` | vulnerability exploit PoC | Pause, request human approval |
| `critical` | data exfiltration, destruction | Blocked by default |

---

## Security Configuration

### Secrets rotation

Rotate all secrets on this schedule (see [OPERATIONS_RUNBOOK.md](./OPERATIONS_RUNBOOK.md)):

| Secret | Rotation Period |
|--------|----------------|
| `SECRET_KEY` | 90 days |
| Database passwords | 90 days |
| Neo4j password | 90 days |
| API keys (OpenAI, Anthropic) | As needed |
| Grafana password | 90 days |

### TLS (production)

In production, Nginx handles TLS termination. Configure certificates in
`docker/production/nginx/`:

```
docker/production/nginx/
 nginx.conf
 certs/
    fullchain.pem   ← place your cert here
    privkey.pem     ← place your key here
```

### Allowed hosts

```dotenv
ALLOWED_HOSTS=univex.example.com,www.univex.example.com
```

Leave empty to allow all hosts (development only).

---

## Observability Configuration

### Prometheus

Prometheus scrapes `/metrics` every 15 seconds by default.  
To change the interval, edit `docker/monitoring/prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'univex-backend'
    scrape_interval: 30s     # ← change here
```

### Grafana dashboards

Dashboards are auto-provisioned from `docker/monitoring/grafana/provisioning/`.
To add custom dashboards, drop JSON files into
`docker/monitoring/grafana/dashboards/` and restart Grafana.

### OpenTelemetry (optional)

```dotenv
OTEL_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
OTEL_SERVICE_NAME=univex-backend
```

Add Jaeger to your compose file:

```yaml
jaeger:
  image: jaegertracing/all-in-one:1.57
  ports:
    - "16686:16686"
    - "4317:4317"
```

---

## Docker Compose Overrides

Create a `docker-compose.override.yml` (git-ignored) for local tweaks without
modifying the tracked compose file:

```yaml
# docker-compose.override.yml
services:
  backend:
    environment:
      DEBUG: "true"
      DB_ECHO: "true"
    volumes:
      - ./backend:/app   # live code mount for hot-reload
  frontend:
    environment:
      NEXT_PUBLIC_API_URL: "http://localhost:8000"
```

Docker Compose automatically merges `docker-compose.override.yml`.

---

## Environment-Specific Best Practices

### Development

```dotenv
ENVIRONMENT=development
DEBUG=true
DB_ECHO=false        # only enable when debugging SQL
SECRET_KEY=dev-only-secret-not-secure
GRAFANA_PASSWORD=admin
RATE_LIMIT_ENABLED=false   # easier testing
```

### Staging

```dotenv
ENVIRONMENT=staging
DEBUG=false
SECRET_KEY=<32-byte random>
GRAFANA_PASSWORD=<strong password>
RATE_LIMIT_ENABLED=true
OTEL_ENABLED=true
```

### Production

```dotenv
ENVIRONMENT=production
DEBUG=false
SECRET_KEY=<32-byte random, rotated quarterly>
GRAFANA_PASSWORD=<strong password>
RATE_LIMIT_ENABLED=true
WAF_ENABLED=true
OTEL_ENABLED=true
BCRYPT_ROUNDS=14      # higher work factor
```

> ⚠️ **Never** commit `.env` to source control. It is in `.gitignore` by default.

---

## SSL & Custom CA Configuration 

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `EXTERNAL_SSL_CA_PATH` | — | `""` | Path to custom CA cert file or directory. Merged with system trust store. |
| `SSL_VERIFY` | — | `true` | Disable TLS verification (dev only — **never false in production**) |
| `SSL_MIN_TLS_VERSION` | — | `TLSv1_2` | Minimum TLS version for outbound connections (`TLSv1_2` or `TLSv1_3`) |
| `SSL_CLIENT_CERT_PATH` | — | `""` | PEM file path for mTLS client certificate |
| `SSL_CLIENT_KEY_PATH` | — | `""` | PEM private key for mTLS client certificate |
| `SSL_CLIENT_KEY_PASSWORD` | — | `""` | Password for encrypted mTLS private key |

See [docs/SECURITY.md#14-custom-ca-certificates--ssl-configuration](SECURITY.md) for full usage.

---

## Cookie Security Configuration 

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `COOKIE_SIGNING_SALT` |  prod | `""` | HMAC-SHA256 salt for cookie signing. Min 32 chars. |
| `SESSION_COOKIE_SECURE` | — | `true` | Set `Secure` flag (HTTPS only) |
| `SESSION_COOKIE_HTTPONLY` | — | `true` | Set `HttpOnly` flag (no JS access) |
| `SESSION_COOKIE_SAMESITE` | — | `Lax` | CSRF mode: `Strict` / `Lax` / `None` |
| `SESSION_COOKIE_MAX_AGE` | — | `1800` | TTL in seconds (default 30 min) |
| `SESSION_COOKIE_DOMAIN` | — | `""` | Cookie domain scope |
| `SESSION_COOKIE_PATH` | — | `/` | Cookie path scope |

Generate the signing salt:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

See [docs/SECURITY.md#15-cookie-security--signing](SECURITY.md) for full usage.

---

## v1.0.0 — New Environment Variables (Days 1–22)

### AI Agent Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PLANNER_MODEL` | — | `OPENAI_MODEL` | LLM model for PlannerAgent |
| `RECON_MODEL` | — | `OPENAI_MODEL` | LLM model for ReconAgent |
| `EXPLOIT_MODEL` | — | `OPENAI_MODEL` | LLM model for ExploitAgent |
| `WEBAPP_MODEL` | — | `OPENAI_MODEL` | LLM model for WebAgent |
| `REPORT_MODEL` | — | `OPENAI_MODEL` | LLM model for ReportAgent |
| `REFINER_MODEL` | — | `OPENAI_MODEL` | LLM model for RefinerAgent |
| `ENRICHER_MODEL` | — | `OPENAI_MODEL` | LLM model for EnricherAgent |
| `ADVISER_MODEL` | — | `OPENAI_MODEL` | LLM model for AdviserAgent |
| `AGENTS_CONFIG_PATH` | — | `examples/configs/agents/agents.yaml` | Path to `agents.yaml` for per-agent model config |
| `AGENT_MAX_TOKENS` | — | `128000` | Maximum tokens per agent context window |
| `AGENT_SUMMARY_THRESHOLD` | — | `0.75` | Trigger context summarization at this % of max tokens |
| `PROXY_URL` | — | — | SOCKS5/HTTP proxy for all LLM API calls (e.g. `socks5://host:1080`) |
| `MOCK_MODE` | — | `false` | Enable `MockLLMProvider` + `MockToolServer` for offline testing |

### Graphiti Knowledge Graph 

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GRAPHITI_URL` | — | `http://graphiti:8010` | Graphiti REST API URL |
| `GRAPHITI_ENABLED` | — | `true` | Enable knowledge graph integration |

### New LLM Providers 

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DEEPSEEK_API_KEY` | — | — | DeepSeek API key |
| `DEEPSEEK_BASE_URL` | — | `https://api.deepseek.com/v1` | DeepSeek API base URL |
| `QWEN_API_KEY` | — | — | Alibaba Qwen API key |
| `GLM_API_KEY` | — | — | Zhipu GLM API key |
| `KIMI_API_KEY` | — | — | Moonshot AI Kimi API key |
| `VLLM_BASE_URL` | — | `http://vllm:8000/v1` | vLLM cluster base URL |
| `AWS_REGION` | — | `us-east-1` | AWS region for Bedrock |
| `AWS_ACCESS_KEY_ID` | — | — | AWS credentials for Bedrock |
| `AWS_SECRET_ACCESS_KEY` | — | — | AWS credentials for Bedrock |

### Search & OSINT Tools 

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SPLOITUS_BASE_URL` | — | `https://sploitus.com` | Sploitus API base URL |
| `PERPLEXITY_API_KEY` | — | — | Perplexity AI API key (sonar-pro) |
| `TRAVERSAAL_API_KEY` | — | — | Traversaal Ares API key |
| `GOOGLE_CSE_ID` | — | — | Google Custom Search Engine ID |
| `SEARXNG_URL` | — | `http://searxng:8080` | Searxng self-hosted URL |

### Embedding Providers 

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `EMBEDDING_PROVIDER` |  | `openai` | Active embedding provider. Options: `openai`, `ollama`, `mistral`, `jina`, `huggingface`, `google`, `voyage` |
| `EMBEDDING_BATCH_SIZE` | — | `100` | Documents per embedding batch |
| `VECTOR_STORE` | — | `chromadb` | Vector store backend: `chromadb` or `pgvector` |
| `OLLAMA_BASE_URL` | — | `http://ollama:11434` | Ollama local service URL |
| `MISTRAL_API_KEY` | — | — | Mistral AI embedding API key |
| `JINA_API_KEY` | — | — | Jina AI embedding API key |
| `HUGGINGFACE_API_KEY` | — | — | HuggingFace Inference API key |
| `VOYAGE_API_KEY` | — | — | VoyageAI embedding API key |

### Observability Stack (Days 11–14)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LANGFUSE_ENABLED` | — | `false` | Enable Langfuse LLM analytics |
| `LANGFUSE_PUBLIC_KEY` | ⚠️ | — | Required if `LANGFUSE_ENABLED=true` |
| `LANGFUSE_SECRET_KEY` | ⚠️ | — | Required if `LANGFUSE_ENABLED=true` |
| `LANGFUSE_HOST` | — | `http://langfuse:3002` | Langfuse service URL |
| `LOKI_URL` | — | `http://loki:3100` | Loki log aggregation URL |
| `JAEGER_ENDPOINT` | — | `http://jaeger:14268/api/traces` | Jaeger trace ingest endpoint |
| `VICTORIA_METRICS_URL` | — | `http://victoriametrics:8428` | VictoriaMetrics URL |
| `CLICKHOUSE_HOST` | — | `clickhouse` | ClickHouse analytics host |
| `CLICKHOUSE_PORT` | — | `9000` | ClickHouse native protocol port |
| `CLICKHOUSE_DATABASE` | — | `univex` | ClickHouse database name |
| `CLICKHOUSE_USER` | — | `univex` | ClickHouse username |
| `CLICKHOUSE_PASSWORD` | ⚠️ | — | ClickHouse password |
| `MINIO_ENDPOINT` | — | `minio:9000` | MinIO S3-compatible endpoint |
| `MINIO_ACCESS_KEY` | — | `univex` | MinIO access key |
| `MINIO_SECRET_KEY` | ⚠️ | — | MinIO secret key |
| `MINIO_BUCKET` | — | `univex-artifacts` | MinIO artifact bucket |
| `MINIO_SECURE` | — | `false` | Enable HTTPS for MinIO |

### Worker Node 

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WORKER_URL` | — | — | Worker node base URL (e.g. `http://worker:8001`) |
| `WORKER_API_KEY` | ⚠️ | — | Shared API key for worker authentication |
| `WORKER_TIMEOUT_SECONDS` | — | `300` | Max seconds to wait for a worker job |
| `WORKER_MAX_RETRIES` | — | `3` | Circuit-breaker retry limit |

### OOB Attack Support 

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OOB_EXTERNAL_IP` | — | — | Public IP for OOB callback listeners |
| `OOB_HTTP_PORT` | — | `8888` | OOB HTTP listener port |
| `OOB_DNS_PORT` | — | `5353` | OOB DNS listener port |
| `OOB_SMTP_PORT` | — | `2525` | OOB SMTP listener port |

### API Versioning & GraphQL (Days 19–20)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `API_VERSION` | — | `1` | Current canonical API version (sets `/v{n}/` prefix) |
| `GRAPHQL_ENABLED` | — | `true` | Enable `/graphql` endpoint |
| `GRAPHQL_PLAYGROUND` | — | `false` | Enable GraphQL playground (dev only) |

---

*Last updated: v1.0.0 | BitR1FT*
