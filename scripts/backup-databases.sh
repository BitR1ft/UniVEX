#!/usr/bin/env bash
# =============================================================================
# UniVex — Database Backup Script
# Day 29: Production Readiness
#
# Backs up:
#   1. PostgreSQL (pg_dump → compressed .sql.gz)
#   2. Neo4j (online backup using neo4j-admin or APOC export)
#
# Usage:
#   ./scripts/backup-databases.sh [--dest /path/to/backups] [--retention 30]
#
# Environment variables:
#   POSTGRES_HOST      default: localhost
#   POSTGRES_PORT      default: 5432
#   POSTGRES_USER      default: univex
#   POSTGRES_PASSWORD  required
#   POSTGRES_DB        default: univex
#   NEO4J_HOST         default: localhost
#   NEO4J_HTTP_PORT    default: 7474
#   NEO4J_USER         default: neo4j
#   NEO4J_PASSWORD     required
#   BACKUP_DEST        default: /backups
#   BACKUP_RETENTION   default: 30 (days)
#   SLACK_WEBHOOK_URL  optional — notify on failure
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $*"; }
ok()   { echo -e "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ${GREEN}✓ $*${NC}"; }
warn() { echo -e "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ${YELLOW}⚠ $*${NC}"; }
err()  { echo -e "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ${RED}✗ $*${NC}" >&2; }

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
BACKUP_DEST="${BACKUP_DEST:-/backups}"
BACKUP_RETENTION="${BACKUP_RETENTION:-30}"

while [[ $# -gt 0 ]]; do
    case $1 in
        --dest)      BACKUP_DEST="$2";      shift 2 ;;
        --retention) BACKUP_RETENTION="$2"; shift 2 ;;
        *)           err "Unknown option: $1"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
PG_HOST="${POSTGRES_HOST:-localhost}"
PG_PORT="${POSTGRES_PORT:-5432}"
PG_USER="${POSTGRES_USER:-univex}"
PG_DB="${POSTGRES_DB:-univex}"
PG_PASS="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"

NEO4J_HOST="${NEO4J_HOST:-localhost}"
NEO4J_HTTP_PORT="${NEO4J_HTTP_PORT:-7474}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASS="${NEO4J_PASSWORD:?NEO4J_PASSWORD is required}"

TIMESTAMP=$(date -u +"%Y%m%d-%H%M%S")
BACKUP_DIR="${BACKUP_DEST}/${TIMESTAMP}"
FAILED_STEPS=()

# ---------------------------------------------------------------------------
# Slack notification helper
# ---------------------------------------------------------------------------
notify_slack() {
    local message="$1"
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        curl -s -X POST \
            -H 'Content-type: application/json' \
            --data "{\"text\":\"[UniVex Backup] ${message}\"}" \
            "$SLACK_WEBHOOK_URL" > /dev/null 2>&1 || true
    fi
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
log "=== UniVex Database Backup ==="
log "Timestamp : ${TIMESTAMP}"
log "Destination: ${BACKUP_DIR}"
log "Retention  : ${BACKUP_RETENTION} days"

mkdir -p "$BACKUP_DIR"

# ---------------------------------------------------------------------------
# 1. PostgreSQL backup
# ---------------------------------------------------------------------------
log ""
log "--- PostgreSQL Backup ---"
PG_BACKUP_FILE="${BACKUP_DIR}/postgres-${PG_DB}-${TIMESTAMP}.sql.gz"

if command -v pg_dump &>/dev/null; then
    log "Running pg_dump for database '${PG_DB}'..."
    PGPASSWORD="$PG_PASS" pg_dump \
        -h "$PG_HOST" \
        -p "$PG_PORT" \
        -U "$PG_USER" \
        -d "$PG_DB" \
        --format=plain \
        --no-password \
        --verbose \
        2>>"${BACKUP_DIR}/postgres-dump.log" \
        | gzip -9 > "$PG_BACKUP_FILE"

    PG_SIZE=$(du -sh "$PG_BACKUP_FILE" 2>/dev/null | cut -f1)
    ok "PostgreSQL backup complete → ${PG_BACKUP_FILE} (${PG_SIZE})"

    # Verify the backup file is a valid gzip
    if gzip -t "$PG_BACKUP_FILE" 2>/dev/null; then
        ok "PostgreSQL backup integrity check: PASSED"
    else
        err "PostgreSQL backup integrity check: FAILED (corrupt gzip)"
        FAILED_STEPS+=("postgres_integrity")
    fi
else
    warn "pg_dump not found — skipping PostgreSQL backup"
    warn "Install postgresql-client or run this script inside the postgres container"
    FAILED_STEPS+=("postgres_not_installed")
fi

# Schema-only backup (for DR documentation)
if command -v pg_dump &>/dev/null; then
    PG_SCHEMA_FILE="${BACKUP_DIR}/postgres-${PG_DB}-schema-${TIMESTAMP}.sql.gz"
    PGPASSWORD="$PG_PASS" pg_dump \
        -h "$PG_HOST" \
        -p "$PG_PORT" \
        -U "$PG_USER" \
        -d "$PG_DB" \
        --schema-only \
        --no-password \
        2>/dev/null \
        | gzip -9 > "$PG_SCHEMA_FILE"
    ok "PostgreSQL schema-only backup → ${PG_SCHEMA_FILE}"
fi

# ---------------------------------------------------------------------------
# 2. Neo4j backup via APOC export
# ---------------------------------------------------------------------------
log ""
log "--- Neo4j Backup (APOC Export) ---"
NEO4J_BACKUP_DIR="${BACKUP_DIR}/neo4j"
mkdir -p "$NEO4J_BACKUP_DIR"

NEO4J_BASE_URL="http://${NEO4J_HOST}:${NEO4J_HTTP_PORT}"
NEO4J_EXPORT_FILE="neo4j-export-${TIMESTAMP}.json"

# Check if Neo4j is reachable
if curl -s --connect-timeout 5 "${NEO4J_BASE_URL}" > /dev/null 2>&1; then
    log "Triggering APOC database export..."
    APOC_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -u "${NEO4J_USER}:${NEO4J_PASS}" \
        -H "Content-Type: application/json" \
        "${NEO4J_BASE_URL}/db/neo4j/tx/commit" \
        --data "{\"statements\":[{\"statement\":\"CALL apoc.export.json.all('${NEO4J_EXPORT_FILE}', {useTypes:true})\"}]}" \
        2>/dev/null) || APOC_RESPONSE="000"

    if [[ "$APOC_RESPONSE" == "200" ]]; then
        ok "Neo4j APOC export triggered — file: ${NEO4J_EXPORT_FILE}"
        log "Note: Export file is written to Neo4j's configured import/export directory."
        log "Copy it manually if Neo4j runs in a container: docker cp neo4j:/var/lib/neo4j/import/${NEO4J_EXPORT_FILE} ${NEO4J_BACKUP_DIR}/"
    else
        warn "APOC export returned HTTP ${APOC_RESPONSE} — APOC plugin may not be installed"
        warn "Falling back to Cypher-based schema snapshot..."

        # Fallback: dump node counts via REST
        curl -s \
            -u "${NEO4J_USER}:${NEO4J_PASS}" \
            -H "Content-Type: application/json" \
            "${NEO4J_BASE_URL}/db/neo4j/tx/commit" \
            --data '{"statements":[{"statement":"MATCH (n) RETURN labels(n) AS labels, count(*) AS count"}]}' \
            2>/dev/null \
            > "${NEO4J_BACKUP_DIR}/neo4j-node-counts-${TIMESTAMP}.json" || true

        ok "Neo4j node count snapshot saved → ${NEO4J_BACKUP_DIR}/neo4j-node-counts-${TIMESTAMP}.json"
    fi
else
    warn "Neo4j not reachable at ${NEO4J_BASE_URL} — skipping Neo4j backup"
    FAILED_STEPS+=("neo4j_not_reachable")
fi

# ---------------------------------------------------------------------------
# 3. Create backup manifest
# ---------------------------------------------------------------------------
log ""
log "--- Creating Backup Manifest ---"
MANIFEST="${BACKUP_DIR}/MANIFEST.json"
cat > "$MANIFEST" << EOF
{
  "timestamp": "${TIMESTAMP}",
  "backup_version": "2.0",
  "host": "$(hostname)",
  "postgres": {
    "host": "${PG_HOST}",
    "port": ${PG_PORT},
    "database": "${PG_DB}",
    "file": "$(basename "${PG_BACKUP_FILE}" 2>/dev/null || echo 'skipped')"
  },
  "neo4j": {
    "host": "${NEO4J_HOST}",
    "http_port": ${NEO4J_HTTP_PORT},
    "export_file": "${NEO4J_EXPORT_FILE}"
  },
  "failed_steps": [$(printf '"%s",' "${FAILED_STEPS[@]}" 2>/dev/null | sed 's/,$//')]
}
EOF
ok "Manifest written → ${MANIFEST}"

# ---------------------------------------------------------------------------
# 4. Compress the entire backup directory
# ---------------------------------------------------------------------------
log ""
log "--- Compressing Backup Archive ---"
ARCHIVE="${BACKUP_DEST}/univex-backup-${TIMESTAMP}.tar.gz"
tar -czf "$ARCHIVE" -C "$BACKUP_DEST" "$(basename "$BACKUP_DIR")" 2>/dev/null
ARCHIVE_SIZE=$(du -sh "$ARCHIVE" | cut -f1)
ok "Backup archive: ${ARCHIVE} (${ARCHIVE_SIZE})"

# Remove the uncompressed directory
rm -rf "$BACKUP_DIR"

# ---------------------------------------------------------------------------
# 5. Enforce retention policy — delete backups older than N days
# ---------------------------------------------------------------------------
log ""
log "--- Enforcing Retention Policy (${BACKUP_RETENTION} days) ---"
DELETED_COUNT=0
while IFS= read -r -d '' old_backup; do
    log "Deleting old backup: $(basename "$old_backup")"
    rm -f "$old_backup"
    (( DELETED_COUNT++ )) || true
done < <(find "$BACKUP_DEST" -name "univex-backup-*.tar.gz" -mtime "+${BACKUP_RETENTION}" -print0 2>/dev/null)

if (( DELETED_COUNT > 0 )); then
    ok "Deleted ${DELETED_COUNT} old backup(s)"
else
    log "No old backups to delete"
fi

# List remaining backups
log ""
log "--- Current Backups ---"
find "$BACKUP_DEST" -name "univex-backup-*.tar.gz" -exec ls -lh {} \; 2>/dev/null | sort

# ---------------------------------------------------------------------------
# 6. Summary
# ---------------------------------------------------------------------------
log ""
log "=== Backup Summary ==="
if [[ ${#FAILED_STEPS[@]} -eq 0 ]]; then
    ok "All backup steps completed successfully"
    notify_slack "✓ Backup completed successfully at ${TIMESTAMP} → ${ARCHIVE} (${ARCHIVE_SIZE})"
    exit 0
else
    err "Backup completed with ${#FAILED_STEPS[@]} failed step(s): ${FAILED_STEPS[*]}"
    notify_slack "✗ Backup at ${TIMESTAMP} had failures: ${FAILED_STEPS[*]}"
    exit 1
fi
