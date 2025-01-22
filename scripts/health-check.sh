#!/usr/bin/env bash
# =============================================================================
# UniVex — Comprehensive Health Check Script
# Day 29: Production Readiness
#
# Checks all UniVex services and exits non-zero if any are unhealthy.
# Suitable for use in monitoring, CI/CD gates, and Docker HEALTHCHECK.
#
# Usage:
#   ./scripts/health-check.sh [--json] [--timeout 5]
#
# Options:
#   --json       Output results as JSON (default: human-readable)
#   --timeout N  HTTP request timeout in seconds (default: 5)
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
JSON_OUTPUT=false
TIMEOUT=5
OVERALL_STATUS=0

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case $1 in
        --json)      JSON_OUTPUT=true; shift ;;
        --timeout)   TIMEOUT="$2"; shift 2 ;;
        *)           echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Colour helpers (suppressed in JSON mode)
# ---------------------------------------------------------------------------
if [[ "$JSON_OUTPUT" == "false" ]]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    GREEN='' RED='' YELLOW='' NC=''
fi

# ---------------------------------------------------------------------------
# Service definitions — [name]="url"
# ---------------------------------------------------------------------------
declare -A HTTP_CHECKS=(
    ["backend_api"]="${BACKEND_URL:-http://localhost:8000}/health"
    ["frontend"]="${FRONTEND_URL:-http://localhost:3000}"
    ["prometheus"]="${PROMETHEUS_URL:-http://localhost:9090}/-/healthy"
    ["grafana"]="${GRAFANA_URL:-http://localhost:3001}/api/health"
)

declare -A TCP_CHECKS=(
    ["postgres"]="${POSTGRES_HOST:-localhost}:${POSTGRES_PORT:-5432}"
    ["neo4j_bolt"]="${NEO4J_HOST:-localhost}:7687"
    ["redis"]="${REDIS_HOST:-localhost}:6379"
)

# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------
declare -A RESULTS
declare -A LATENCIES

# ---------------------------------------------------------------------------
# HTTP health check
# ---------------------------------------------------------------------------
check_http() {
    local name="$1"
    local url="$2"
    local start
    start=$(date +%s%3N)

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout "$TIMEOUT" \
        --max-time "$TIMEOUT" \
        "$url" 2>/dev/null) || http_code="000"

    local end
    end=$(date +%s%3N)
    local latency=$(( end - start ))

    LATENCIES["$name"]="${latency}ms"

    if [[ "$http_code" =~ ^(200|204|301|302)$ ]]; then
        RESULTS["$name"]="healthy"
        return 0
    else
        RESULTS["$name"]="unhealthy (HTTP $http_code)"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# TCP connectivity check
# ---------------------------------------------------------------------------
check_tcp() {
    local name="$1"
    local host_port="$2"
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    local start
    start=$(date +%s%3N)

    if timeout "$TIMEOUT" bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null; then
        local end
        end=$(date +%s%3N)
        LATENCIES["$name"]="$(( end - start ))ms"
        RESULTS["$name"]="healthy"
        return 0
    else
        LATENCIES["$name"]="${TIMEOUT}000ms (timeout)"
        RESULTS["$name"]="unhealthy (connection refused or timeout)"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Neo4j HTTP check (additional to bolt)
# ---------------------------------------------------------------------------
check_neo4j_http() {
    local url="${NEO4J_URL:-http://localhost:7474}"
    local start
    start=$(date +%s%3N)
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout "$TIMEOUT" \
        --max-time "$TIMEOUT" \
        "$url" 2>/dev/null) || http_code="000"
    local end
    end=$(date +%s%3N)
    LATENCIES["neo4j_http"]="$(( end - start ))ms"
    if [[ "$http_code" == "200" ]]; then
        RESULTS["neo4j_http"]="healthy"
        return 0
    else
        RESULTS["neo4j_http"]="unhealthy (HTTP $http_code)"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# ChromaDB check
# ---------------------------------------------------------------------------
check_chromadb() {
    local url="${CHROMADB_URL:-http://localhost:8020}/api/v1/heartbeat"
    local start
    start=$(date +%s%3N)
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout "$TIMEOUT" \
        --max-time "$TIMEOUT" \
        "$url" 2>/dev/null) || http_code="000"
    local end
    end=$(date +%s%3N)
    LATENCIES["chromadb"]="$(( end - start ))ms"
    if [[ "$http_code" == "200" ]]; then
        RESULTS["chromadb"]="healthy"
        return 0
    else
        RESULTS["chromadb"]="unhealthy (HTTP $http_code)"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Disk space check — warn if < 10 GB free on /var
# ---------------------------------------------------------------------------
check_disk_space() {
    local path="${1:-/}"
    local available_kb
    available_kb=$(df -Pk "$path" 2>/dev/null | awk 'NR==2 {print $4}')
    local available_gb=$(( available_kb / 1048576 ))
    LATENCIES["disk_space"]="${available_gb}GB free"
    if (( available_gb >= 10 )); then
        RESULTS["disk_space"]="healthy"
        return 0
    elif (( available_gb >= 5 )); then
        RESULTS["disk_space"]="warning (${available_gb}GB free, < 10GB threshold)"
        return 0   # warning but not failure
    else
        RESULTS["disk_space"]="unhealthy (${available_gb}GB free, < 5GB critical)"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Run all checks
# ---------------------------------------------------------------------------
echo ""
if [[ "$JSON_OUTPUT" == "false" ]]; then
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         UniVex — Production Health Check                    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo "  Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo ""
fi

# HTTP service checks
for name in "${!HTTP_CHECKS[@]}"; do
    check_http "$name" "${HTTP_CHECKS[$name]}" || OVERALL_STATUS=1
done

# Neo4j HTTP
check_neo4j_http || OVERALL_STATUS=1

# ChromaDB
check_chromadb || OVERALL_STATUS=1

# TCP connectivity checks
for name in "${!TCP_CHECKS[@]}"; do
    check_tcp "$name" "${TCP_CHECKS[$name]}" || OVERALL_STATUS=1
done

# Disk space
check_disk_space / || OVERALL_STATUS=1

# ---------------------------------------------------------------------------
# Output results
# ---------------------------------------------------------------------------
if [[ "$JSON_OUTPUT" == "true" ]]; then
    echo "{"
    echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
    echo "  \"overall\": \"$([ $OVERALL_STATUS -eq 0 ] && echo healthy || echo unhealthy)\","
    echo "  \"services\": {"
    first=true
    for name in "${!RESULTS[@]}"; do
        [[ "$first" == "true" ]] || echo ","
        printf "    \"%s\": {\"status\": \"%s\", \"latency\": \"%s\"}" \
            "$name" "${RESULTS[$name]}" "${LATENCIES[$name]:-N/A}"
        first=false
    done
    echo ""
    echo "  }"
    echo "}"
else
    # Human-readable table
    printf "  %-25s %-35s %s\n" "SERVICE" "STATUS" "LATENCY"
    printf "  %-25s %-35s %s\n" "-------" "------" "-------"
    for name in "${!RESULTS[@]}"; do
        status="${RESULTS[$name]}"
        latency="${LATENCIES[$name]:-N/A}"
        if [[ "$status" == "healthy" ]]; then
            printf "  ${GREEN}%-25s ✓ %-33s %s${NC}\n" "$name" "$status" "$latency"
        elif [[ "$status" == warning* ]]; then
            printf "  ${YELLOW}%-25s ⚠ %-33s %s${NC}\n" "$name" "$status" "$latency"
        else
            printf "  ${RED}%-25s ✗ %-33s %s${NC}\n" "$name" "$status" "$latency"
        fi
    done
    echo ""
    if [[ $OVERALL_STATUS -eq 0 ]]; then
        echo -e "  ${GREEN}✓ All services healthy${NC}"
    else
        echo -e "  ${RED}✗ One or more services are unhealthy${NC}"
    fi
    echo ""
fi

exit $OVERALL_STATUS
