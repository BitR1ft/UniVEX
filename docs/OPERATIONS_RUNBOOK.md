# UniVex — Operations Runbook

> This runbook covers all operational procedures for UniVex including
> deployment, monitoring, incident response, backup, and disaster recovery.

---

## System Overview

| Component | Technology | Port |
|-----------|-----------|------|
| Backend API | FastAPI + Uvicorn | 8000 |
| Frontend | Next.js | 3000 |
| PostgreSQL | v16 Alpine | 5432 |
| Neo4j | v5.15 Community | 7474 / 7687 |
| Prometheus | v2.51 | 9090 |
| Grafana | v10.4 | 3001 |
| Nginx | v1.25 | 80 / 443 |

---

## Deployment Procedures

### Standard Deployment (Staging)

```bash
# 1. Set the image tag
export IMAGE_TAG=sha-$(git rev-parse --short HEAD)

# 2. Pull latest images
docker compose -f docker/staging/docker-compose.staging.yml pull

# 3. Deploy with zero-downtime rolling update
docker compose -f docker/staging/docker-compose.staging.yml up -d --no-build

# 4. Verify health
curl http://staging.univex.local/health
curl http://staging.univex.local/api/health
```

### Blue/Green Deployment (Production)

```bash
# Step 1: Deploy to inactive slot (does NOT affect live traffic)
gh workflow run blue-green.yml \
  -f action=deploy \
  -f image_tag=v1.2.3 \
  -f environment=production

# Step 2: Verify inactive slot health
curl http://green.univex.example.com/health

# Step 3: Switch traffic (requires approval in GitHub)
gh workflow run blue-green.yml \
  -f action=switch \
  -f environment=production

# Step 4: Monitor for 10 minutes
# Watch Grafana dashboard, Prometheus alerts, error rates

# Step 5: If issues: rollback
gh workflow run blue-green.yml \
  -f action=rollback \
  -f environment=production
```

### Manual Deployment (Emergency)

```bash
# Pull specific image directly on server
ssh deploy@production-server

cd /opt/univex
export IMAGE_TAG=v1.2.2  # Previous stable version
export POSTGRES_PASSWORD=$(cat /run/secrets/postgres_password)
export SECRET_KEY=$(cat /run/secrets/secret_key)
export NEO4J_PASSWORD=$(cat /run/secrets/neo4j_password)

docker compose -f docker/production/docker-compose.production.yml pull
docker compose -f docker/production/docker-compose.production.yml up -d
```

---

## Rollback Procedures

### Immediate Rollback (< 5 minutes)

```bash
# Option 1: GitHub Actions (preferred)
gh workflow run blue-green.yml -f action=rollback -f environment=production

# Option 2: Docker compose on server
ssh deploy@production-server
cd /opt/univex
export IMAGE_TAG=$(cat .previous-image-tag)
docker compose -f docker/production/docker-compose.production.yml up -d --no-build
```

### Database Rollback

```bash
# ⚠️ WARNING: Database rollbacks can cause data loss
# Only perform if the migration is destructive and reversible

# 1. Stop application
docker compose stop backend

# 2. Restore from backup
BACKUP_FILE=/backups/backup-20260307-020000.sql.gz
gunzip -c $BACKUP_FILE | docker compose exec -T postgres psql -U univex univex

# 3. Restart application with previous image
export IMAGE_TAG=v1.2.2
docker compose up -d
```

### Full System Rollback

```bash
# 1. Rollback application images
export IMAGE_TAG=$(cat .previous-image-tag)
docker compose -f docker/production/docker-compose.production.yml up -d

# 2. Verify health
./scripts/health-check.sh production

# 3. If database schema incompatible, run database rollback (above)

# 4. Alert team
echo "Full rollback executed at $(date)" | notify-slack
```

---

## Backup Procedures

### PostgreSQL Backup

```bash
# Manual backup
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
docker compose exec postgres pg_dump \
  -U univex \
  univex \
  | gzip > /backups/manual-backup-$TIMESTAMP.sql.gz

# Verify backup
gunzip -c /backups/manual-backup-$TIMESTAMP.sql.gz | head -20

# List all backups
ls -lh /backups/*.sql.gz | sort -k6 -r
```

### Neo4j Backup

```bash
# Neo4j Community backup (offline)
docker compose stop neo4j

# Copy data directory
docker run --rm \
  -v univex-prod-neo4j-data:/data \
  -v /backups/neo4j:/backup \
  alpine tar czf /backup/neo4j-$(date +%Y%m%d).tar.gz /data

docker compose start neo4j
```

### Backup Verification

```bash
# Test PostgreSQL backup restoration
docker run --rm \
  -e POSTGRES_USER=univex \
  -e POSTGRES_PASSWORD=testpass \
  -e POSTGRES_DB=restore_test \
  postgres:16-alpine \
  &

sleep 10

# Restore to test database
gunzip -c /backups/latest.sql.gz | \
  PGPASSWORD=testpass psql -h localhost -U univex restore_test

echo " Backup verification complete"
```

---

## Health Checks

### Service Health Check Script

```bash
#!/bin/bash
# health-check.sh

ENV=${1:-production}
API_URL="http://localhost:8000"
FRONTEND_URL="http://localhost:3000"

echo "=== UniVex Health Check ==="
echo "Environment: $ENV"
echo "Time: $(date)"
echo ""

# Backend API
STATUS=$(curl -sf $API_URL/health | jq -r '.status' 2>/dev/null || echo "ERROR")
echo "Backend API:  $STATUS"

# Frontend
HTTP_CODE=$(curl -so /dev/null -w "%{http_code}" $FRONTEND_URL 2>/dev/null)
echo "Frontend:     HTTP $HTTP_CODE"

# PostgreSQL
PG_OK=$(docker compose exec -T postgres pg_isready -U univex && echo "OK" || echo "ERROR")
echo "PostgreSQL:   $PG_OK"

# Neo4j
NEO_CODE=$(curl -so /dev/null -w "%{http_code}" http://localhost:7474 2>/dev/null)
echo "Neo4j:        HTTP $NEO_CODE"

# Prometheus
PROM_CODE=$(curl -so /dev/null -w "%{http_code}" http://localhost:9090/-/ready 2>/dev/null)
echo "Prometheus:   HTTP $PROM_CODE"

echo ""
echo "=== Container Status ==="
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
```

---

## Incident Response

### Severity Levels

| Level | Description | Response Time | Example |
|-------|-------------|---------------|---------|
| P1 | Service completely down | < 15 min | All users cannot access |
| P2 | Major feature broken | < 1 hour | Authentication failing |
| P3 | Minor feature broken | < 4 hours | Graph export not working |
| P4 | Performance degradation | < 24 hours | Slow page loads |

### P1 Incident Playbook

```bash
# 1. Immediately notify team via PagerDuty/Slack

# 2. Check service health
./scripts/health-check.sh production

# 3. Check recent deployments
docker inspect univex-prod-backend | grep -A5 "Image"
git log --oneline -5

# 4. Check application logs
docker compose logs backend --tail=200 --since=30m
docker compose logs frontend --tail=100 --since=30m

# 5. Check system resources
docker stats --no-stream
df -h

# 6. If deployment issue: rollback
gh workflow run blue-green.yml -f action=rollback -f environment=production

# 7. If database issue: check connectivity
docker compose exec postgres pg_isready

# 8. Document timeline in incident report
```

### Log Analysis

```bash
# View real-time logs
docker compose logs -f backend

# Search for errors in last hour
docker compose logs backend --since=1h 2>&1 | grep -E "ERROR|CRITICAL|Exception"

# Export logs for analysis
docker compose logs backend --since=2h > /tmp/incident-$(date +%Y%m%d-%H%M).log

# View structured JSON logs
docker compose logs backend --since=30m | jq '.level == "ERROR"' 2>/dev/null
```

---

## Monitoring & Alerting

### Key Metrics to Watch

| Metric | Normal | Warning | Critical |
|--------|--------|---------|----------|
| API error rate | < 0.1% | 1-5% | > 5% |
| API p95 latency | < 200ms | 500ms | > 1s |
| PostgreSQL connections | < 100 | 200-400 | > 450 |
| Memory usage (backend) | < 500MB | 750MB-1GB | > 1.5GB |
| Disk usage | < 70% | 70-85% | > 85% |

### Grafana Dashboards

- **API Metrics**: `http://localhost:3001/d/api-metrics`
- **Tool Execution**: `http://localhost:3001/d/tool-execution`
- **System Resources**: `http://localhost:3001/d/system-resources`

### Prometheus Alerts

Alerts are configured in `docker/monitoring/prometheus-alerts.yml`:

- `HighErrorRate`: > 5% error rate for 5 minutes
- `VeryHighErrorRate`: > 20% error rate for 1 minute
- `HighLatency`: p95 > 2s for 5 minutes
- `NoActiveScans`: No scan activity for 30 minutes (business hours)

---

## Secrets Management

### Rotating Secrets

```bash
# 1. Generate new secret
NEW_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")

# 2. Update in GitHub Secrets (via gh CLI)
echo "$NEW_SECRET" | gh secret set SECRET_KEY

# 3. Update in running environment
# ⚠️ Requires rolling restart of backend
docker compose exec backend env SECRET_KEY=$NEW_SECRET

# 4. Trigger deployment to apply new secret
gh workflow run deploy.yml -f environment=production -f image_tag=latest
```

### Secret Rotation Schedule

| Secret | Rotation Frequency | Last Rotated |
|--------|-------------------|--------------|
| SECRET_KEY | 90 days | 2026-01-01 |
| POSTGRES_PASSWORD | 180 days | 2026-01-01 |
| NEO4J_PASSWORD | 180 days | 2026-01-01 |
| GRAFANA_PASSWORD | 90 days | 2026-01-01 |

---

## Common Operations

### Running Database Migrations

```bash
# Development
cd backend
alembic upgrade head

# Production (via container)
docker compose exec backend alembic upgrade head

# Check migration status
docker compose exec backend alembic current
docker compose exec backend alembic history --verbose
```

### Scaling Services

```bash
# Scale backend to 3 replicas (Docker Swarm)
docker service scale univex_backend=3

# Scale with compose (development/staging)
docker compose up -d --scale backend=2
```

### Clearing Caches

```bash
# Clear Next.js build cache
docker compose exec frontend rm -rf .next/cache

# Restart with fresh cache
docker compose restart frontend

# Clear application cache
docker compose exec backend python -c "from app.core.cache import clear_all; clear_all()"
```

### Viewing Audit Logs

```bash
# View recent audit events
docker compose logs backend | grep '"type":"audit"' | jq '.' | tail -50

# Filter by action
docker compose logs backend | grep '"action":"login_failed"'

# Export audit log
docker compose logs backend --since=24h \
  | grep '"type":"audit"' \
  | jq '.' > /tmp/audit-$(date +%Y%m%d).jsonl
```

---

## Escalation Contacts

| Role | Contact | When to Contact |
|------|---------|-----------------|
| On-call Engineer | PagerDuty schedule | P1/P2 incidents |
| Tech Lead | Slack @tech-lead | Architecture decisions |
| Security Team | security@company.com | Security incidents |
| Database Admin | Slack @dba | Database emergencies |

---


---

## v1.0.0 Security Operations


### Health Checks

```bash
# Run full health check for all services
./scripts/health-check.sh

# JSON output for monitoring integration
./scripts/health-check.sh --json

# Single service check
curl -sf http://localhost:8000/health | jq
```

### Database Backups

```bash
# Manual backup to default directory (/backups)
./scripts/backup-databases.sh

# Custom destination and 14-day retention
./scripts/backup-databases.sh --dest /mnt/nas/backups --retention 14

# Verify backup integrity
gzip -t /backups/univex-backup-*.tar.gz && echo "Backup OK"
```

### Secret Rotation

```bash
# Preview rotation (no changes)
./scripts/rotate-secrets.sh --dry-run --env-file .env.production

# Execute rotation
./scripts/rotate-secrets.sh --env-file .env.production

# Post-rotation: verify all services healthy
./scripts/health-check.sh
```

### 2FA Administration

```bash
# List users with 2FA enabled (direct DB query)
docker compose exec postgres psql -U univex -d univex \
  -c "SELECT email, totp_enabled, created_at FROM users WHERE totp_enabled=true;"

# Disable 2FA for a user (emergency recovery)
curl -X DELETE http://localhost:8000/api/auth/2fa/disable \
  -H "Authorization: Bearer <admin-token>" \
  -d '{"user_id": "<user-id>"}'
```

### Account Lockout Management

```bash
# Check if account is locked (Python console)
docker compose exec backend python3 -c "
from app.core.lockout import account_lockout
locked, retry = account_lockout.is_locked('user@example.com')
print(f'Locked: {locked}, Retry after: {retry:.0f}s')
"

# Unlock account (emergency)
docker compose exec backend python3 -c "
from app.core.lockout import account_lockout
account_lockout.reset('user@example.com')
print('Account unlocked')
"
```

### IP Allow-List Management

```bash
# View current admin IP allowlist
docker compose exec backend python3 -c "
from app.core.ip_allowlist import admin_ip_allowlist
for cidr in admin_ip_allowlist.list_cidrs():
    print(cidr)
"

# Temporarily add IP (runtime only, not persisted)
docker compose exec backend python3 -c "
from app.core.ip_allowlist import admin_ip_allowlist
admin_ip_allowlist.add_cidr('203.0.113.42/32')
print('Added')
"

# For permanent changes: update ADMIN_IP_ALLOWLIST env var and restart
```

### Container Security Scans

```bash
# Manual Trivy scan (requires Trivy installed)
trivy image --severity CRITICAL,HIGH univex-backend:latest

# Scan all images
for img in univex-backend univex-frontend; do
    echo "=== Scanning $img ==="
    trivy image --severity CRITICAL,HIGH ${img}:latest
done
```

### Nginx Operations

```bash
# Reload Nginx config without downtime
docker compose exec nginx nginx -s reload

# Test Nginx config
docker compose exec nginx nginx -t

# View Nginx access logs (JSON format)
docker compose exec nginx tail -f /var/log/nginx/access.log | jq

# View rate limit hits
docker compose exec nginx grep "limiting" /var/log/nginx/error.log | tail -20
```

---

*v1.0.0 additions — Security Hardening & Production Readiness | BitR1FT*
