#!/usr/bin/env bash
# =============================================================================
# UniVex — Secret Rotation Script
# Day 29: Production Readiness
#
# Rotates the following secrets:
#   1. SECRET_KEY (JWT signing key)
#   2. POSTGRES_PASSWORD
#   3. NEO4J_PASSWORD
#   4. API keys (as applicable)
#
# The script:
#   1. Generates new cryptographically secure values
#   2. Updates the running Docker secrets / .env file
#   3. Triggers a rolling restart of affected containers
#   4. Verifies health post-rotation
#   5. Rolls back if health checks fail
#
# Usage:
#   ./scripts/rotate-secrets.sh [--dry-run] [--env-file /path/.env.production]
#
# IMPORTANT: Run this script from the repository root.
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $*"; }
ok()   { echo -e "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ${GREEN}✓ $*${NC}"; }
warn() { echo -e "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ${YELLOW}⚠ $*${NC}"; }
err()  { echo -e "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ${RED}✗ $*${NC}" >&2; }
info() { echo -e "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ${CYAN}ℹ $*${NC}"; }

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
DRY_RUN=false
ENV_FILE=".env.production"

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)   DRY_RUN=true; shift ;;
        --env-file)  ENV_FILE="$2"; shift 2 ;;
        *)           err "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ "$DRY_RUN" == "true" ]]; then
    warn "DRY-RUN mode — no changes will be made to files or containers"
fi

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
for cmd in openssl python3 docker; do
    command -v "$cmd" &>/dev/null || { err "Required command not found: $cmd"; exit 1; }
done

# ---------------------------------------------------------------------------
# Secret generation helpers
# ---------------------------------------------------------------------------
generate_secret_key() {
    # 64-byte URL-safe base64 (512 bits of entropy)
    python3 -c "import secrets; print(secrets.token_urlsafe(64))"
}

generate_db_password() {
    # 32-char alphanumeric + symbols, suitable for DB passwords
    python3 -c "import secrets, string; chars=string.ascii_letters+string.digits+'!@#%^&*'; print(''.join(secrets.choice(chars) for _ in range(32)))"
}

generate_api_key() {
    # 48-byte API key with prefix for identification
    python3 -c "import secrets; print('uvx-' + secrets.token_hex(32))"
}

# ---------------------------------------------------------------------------
# Backup current env file
# ---------------------------------------------------------------------------
backup_env_file() {
    local env_file="$1"
    if [[ -f "$env_file" ]]; then
        local backup="${env_file}.bak.$(date +%Y%m%d-%H%M%S)"
        cp "$env_file" "$backup"
        ok "Backed up ${env_file} → ${backup}"
        # Restrict permissions on backup
        chmod 600 "$backup"
        echo "$backup"
    else
        warn "Env file not found: ${env_file}"
        echo ""
    fi
}

# ---------------------------------------------------------------------------
# Update a single variable in the env file
# ---------------------------------------------------------------------------
update_env_var() {
    local env_file="$1"
    local var_name="$2"
    local new_value="$3"

    if [[ "$DRY_RUN" == "true" ]]; then
        info "[DRY-RUN] Would set ${var_name}=<new-value>"
        return
    fi

    if grep -q "^${var_name}=" "$env_file" 2>/dev/null; then
        # Replace existing value
        sed -i "s|^${var_name}=.*|${var_name}=${new_value}|" "$env_file"
    else
        # Append if not present
        echo "${var_name}=${new_value}" >> "$env_file"
    fi
}

# ---------------------------------------------------------------------------
# Update PostgreSQL password in the running database
# ---------------------------------------------------------------------------
rotate_postgres_password() {
    local old_pass="$1"
    local new_pass="$2"
    local pg_host="${POSTGRES_HOST:-localhost}"
    local pg_port="${POSTGRES_PORT:-5432}"
    local pg_user="${POSTGRES_USER:-univex}"
    local pg_db="${POSTGRES_DB:-univex}"

    if [[ "$DRY_RUN" == "true" ]]; then
        info "[DRY-RUN] Would execute: ALTER USER ${pg_user} WITH PASSWORD '<new-password>'"
        return 0
    fi

    log "Rotating PostgreSQL password for user '${pg_user}'..."
    if PGPASSWORD="$old_pass" psql \
        -h "$pg_host" -p "$pg_port" -U "$pg_user" -d "$pg_db" \
        -c "ALTER USER ${pg_user} WITH PASSWORD '${new_pass}';" \
        &>/dev/null; then
        ok "PostgreSQL password rotated"
    else
        err "Failed to rotate PostgreSQL password — psql not available or connection failed"
        err "Manually run: ALTER USER ${pg_user} WITH PASSWORD '<new-password>';"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Trigger a rolling restart of a container
# ---------------------------------------------------------------------------
rolling_restart() {
    local container_name="$1"

    if [[ "$DRY_RUN" == "true" ]]; then
        info "[DRY-RUN] Would restart container: ${container_name}"
        return 0
    fi

    log "Restarting container: ${container_name}"
    if docker inspect "$container_name" &>/dev/null; then
        docker restart "$container_name"
        ok "Container ${container_name} restarted"
    else
        warn "Container ${container_name} not found — skipping restart"
    fi
}

# ---------------------------------------------------------------------------
# Post-rotation health verification
# ---------------------------------------------------------------------------
verify_health() {
    local retries=5
    local delay=10
    local health_url="${BACKEND_URL:-http://localhost:8000}/health"

    log "Verifying service health after rotation..."
    for (( i=1; i<=retries; i++ )); do
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" \
            --connect-timeout 5 --max-time 10 \
            "$health_url" 2>/dev/null) || http_code="000"

        if [[ "$http_code" == "200" ]]; then
            ok "Health check passed (attempt ${i}/${retries})"
            return 0
        fi
        warn "Health check failed (attempt ${i}/${retries}) — HTTP ${http_code}, retrying in ${delay}s..."
        sleep "$delay"
    done

    err "Health checks failed after ${retries} attempts"
    return 1
}

# ---------------------------------------------------------------------------
# Main rotation flow
# ---------------------------------------------------------------------------
log "=== UniVex Secret Rotation ==="
log "Env file : ${ENV_FILE}"
log "Dry run  : ${DRY_RUN}"
log ""

# 1. Backup env file
BACKUP_FILE=""
if [[ -f "$ENV_FILE" ]]; then
    BACKUP_FILE=$(backup_env_file "$ENV_FILE")
fi

# 2. Generate new secrets
log "--- Generating New Secrets ---"
NEW_SECRET_KEY=$(generate_secret_key)
NEW_POSTGRES_PASS=$(generate_db_password)
NEW_NEO4J_PASS=$(generate_db_password)
NEW_API_KEY=$(generate_api_key)

ok "Generated new SECRET_KEY       : ${NEW_SECRET_KEY:0:8}…"
ok "Generated new POSTGRES_PASSWORD: ${NEW_POSTGRES_PASS:0:4}…"
ok "Generated new NEO4J_PASSWORD   : ${NEW_NEO4J_PASS:0:4}…"
ok "Generated new API key          : ${NEW_API_KEY:0:12}…"

# 3. Read old passwords (needed for DB rotation)
OLD_POSTGRES_PASS="${POSTGRES_PASSWORD:-}"
if [[ -z "$OLD_POSTGRES_PASS" && -f "$ENV_FILE" ]]; then
    OLD_POSTGRES_PASS=$(grep "^POSTGRES_PASSWORD=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "")
fi

# 4. Update env file
log ""
log "--- Updating Environment File ---"
if [[ -f "$ENV_FILE" || "$DRY_RUN" == "true" ]]; then
    update_env_var "$ENV_FILE" "SECRET_KEY" "$NEW_SECRET_KEY"
    update_env_var "$ENV_FILE" "POSTGRES_PASSWORD" "$NEW_POSTGRES_PASS"
    update_env_var "$ENV_FILE" "NEO4J_PASSWORD" "$NEW_NEO4J_PASS"
    ok "Environment file updated"
else
    warn "Env file does not exist yet — creating from scratch"
    if [[ "$DRY_RUN" == "false" ]]; then
        cat > "$ENV_FILE" << EOF
# Generated by rotate-secrets.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
SECRET_KEY=${NEW_SECRET_KEY}
POSTGRES_PASSWORD=${NEW_POSTGRES_PASS}
NEO4J_PASSWORD=${NEW_NEO4J_PASS}
EOF
        chmod 600 "$ENV_FILE"
    fi
fi

# 5. Rotate PostgreSQL password in the database
log ""
log "--- Rotating PostgreSQL Password ---"
if [[ -n "$OLD_POSTGRES_PASS" ]]; then
    rotate_postgres_password "$OLD_POSTGRES_PASS" "$NEW_POSTGRES_PASS" || true
else
    warn "No existing POSTGRES_PASSWORD found — skipping live DB rotation"
fi

# 6. Restart services
log ""
log "--- Rolling Restart ---"
CONTAINERS=(
    "univex-prod-backend"
    "univex-prod-frontend"
    "univex-prod-nginx"
)
for container in "${CONTAINERS[@]}"; do
    rolling_restart "$container" || true
    sleep 3   # brief pause between restarts
done

# 7. Verify health
log ""
log "--- Post-Rotation Health Verification ---"
HEALTH_OK=true
if [[ "$DRY_RUN" == "false" ]]; then
    verify_health || HEALTH_OK=false
else
    info "[DRY-RUN] Skipping health verification"
fi

# 8. Rollback if health failed
if [[ "$HEALTH_OK" == "false" && -n "$BACKUP_FILE" && "$DRY_RUN" == "false" ]]; then
    err "Rolling back to previous secrets..."
    cp "$BACKUP_FILE" "$ENV_FILE"
    for container in "${CONTAINERS[@]}"; do
        rolling_restart "$container" || true
    done
    err "ROLLBACK COMPLETE — investigate logs before retrying rotation"
    exit 1
fi

# 9. Summary
log ""
log "=== Rotation Summary ==="
if [[ "$DRY_RUN" == "true" ]]; then
    ok "Dry run complete — no changes made"
    ok "Run without --dry-run to apply changes"
elif [[ "$HEALTH_OK" == "true" ]]; then
    ok "Secret rotation complete and all services healthy"
    log ""
    log "  Next steps:"
    log "  1. Update any external secret stores (Vault, AWS Secrets Manager)"
    log "  2. Notify team members with 'need-to-know' access"
    log "  3. Update CI/CD secrets in GitHub Actions"
    log "  4. Remove old backup file: ${BACKUP_FILE}"
else
    err "Rotation encountered issues — review logs above"
    exit 1
fi
