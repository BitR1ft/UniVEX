#!/usr/bin/env bash
# ==============================================================================
# UniVex Interactive TUI Installer
# Version: 2.1.0  Author: BitR1FT  License: MIT
#
# Interactive shell installer using whiptail (or dialog as fallback).
# Supports Docker & Docker Compose environments.
#
# Usage:
#   bash scripts/install.sh
#   bash scripts/install.sh --non-interactive   # skip prompts, use .env defaults
#   bash scripts/install.sh --dry-run           # generate .env only, no compose up
# ==============================================================================

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Globals
# ─────────────────────────────────────────────────────────────────────────────
UNIVEX_VERSION="2.1.0"
COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

NON_INTERACTIVE=false
DRY_RUN=false
RUNTIME="docker"                     # docker | podman

# Colours
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ─────────────────────────────────────────────────────────────────────────────
# CLI argument parsing
# ─────────────────────────────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --non-interactive) NON_INTERACTIVE=true ;;
    --dry-run)         DRY_RUN=true ;;
    --help|-h)
      echo "Usage: $0 [--non-interactive] [--dry-run]"
      exit 0
      ;;
  esac
done

# ─────────────────────────────────────────────────────────────────────────────
# Utility functions
# ─────────────────────────────────────────────────────────────────────────────
log()  { echo -e "${CYAN}[UniVex]${RESET} $*"; }
ok()   { echo -e "${GREEN}  ✔${RESET} $*"; }
warn() { echo -e "${YELLOW}  ⚠${RESET} $*"; }
err()  { echo -e "${RED}  ✘${RESET} $*" >&2; }
die()  { err "$*"; exit 1; }

hr()   { echo -e "${BLUE}──────────────────────────────────────────${RESET}"; }

# Detect whiptail or dialog
TUI_CMD=""
if command -v whiptail &>/dev/null; then
  TUI_CMD="whiptail"
elif command -v dialog &>/dev/null; then
  TUI_CMD="dialog"
fi

# TUI helpers (fallback to plain prompts when TUI unavailable)
tui_available() { [[ -n "$TUI_CMD" && "$NON_INTERACTIVE" == false ]]; }

tui_msgbox() {
  local title="$1"; local msg="$2"
  if tui_available; then
    $TUI_CMD --title "$title" --msgbox "$msg" 20 70
  else
    echo -e "\n${BOLD}=== ${title} ===${RESET}\n${msg}\n"
  fi
}

tui_yesno() {
  local title="$1"; local msg="$2"
  if tui_available; then
    $TUI_CMD --title "$title" --yesno "$msg" 12 60
    return $?
  fi
  return 0  # default yes in non-interactive
}

tui_inputbox() {
  local title="$1"; local msg="$2"; local default="${3:-}"
  if tui_available; then
    $TUI_CMD --title "$title" --inputbox "$msg" 10 60 "$default" 3>&1 1>&2 2>&3 || echo "$default"
  else
    echo "$default"
  fi
}

tui_passwordbox() {
  local title="$1"; local msg="$2"
  if tui_available; then
    $TUI_CMD --title "$title" --passwordbox "$msg" 10 60 "" 3>&1 1>&2 2>&3 || echo ""
  else
    # In non-interactive, return empty (caller will generate a secret)
    echo ""
  fi
}

tui_menu() {
  # $1=title $2=msg $3=default $4+ = "tag description" pairs
  local title="$1"; local msg="$2"; local default="$3"; shift 3
  if tui_available; then
    local pairs=("$@")
    $TUI_CMD --title "$title" --default-item "$default" \
      --menu "$msg" 20 70 10 "${pairs[@]}" 3>&1 1>&2 2>&3 || echo "$default"
  else
    echo "$default"
  fi
}

tui_checklist() {
  # $1=title $2=msg $3+ = "tag description status" triples
  local title="$1"; local msg="$2"; shift 2
  if tui_available; then
    local items=("$@")
    $TUI_CMD --title "$title" --checklist "$msg" 20 70 10 "${items[@]}" 3>&1 1>&2 2>&3 || echo ""
  else
    # Default: return all items with status "on"
    local result=()
    local i=0
    local args=("$@")
    while (( i < ${#args[@]} )); do
      local tag="${args[$i]}"
      local status="${args[$((i+2))]}"
      [[ "$status" == "on" ]] && result+=("$tag")
      (( i+=3 ))
    done
    printf '%s\n' "${result[@]}"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 0 — Welcome screen
# ─────────────────────────────────────────────────────────────────────────────
show_welcome() {
  hr
  echo -e "${BOLD}${CYAN}"
  cat <<'EOF'
 _   _       _  _     _
| | | |_ __ (_)| |   | | _____ __
| | | | '_ \| || |   | |/ _ \ \/ /
| |_| | | | | || |___| |  __/>  <
 \___/|_| |_|_||_____|_|\___/_/\_\
EOF
  echo -e "${RESET}"
  echo -e "  ${BOLD}AI-Powered Penetration Testing Framework${RESET}"
  echo -e "  Version ${UNIVEX_VERSION}  ·  Author: BitR1FT  ·  MIT License"
  hr
  echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Prerequisite checks
# ─────────────────────────────────────────────────────────────────────────────
check_prerequisites() {
  log "Checking prerequisites …"

  local ERRORS=0

  # Docker / Docker Compose
  if ! command -v docker &>/dev/null; then
    err "Docker not found. Install Docker: https://docs.docker.com/get-docker/"
    (( ERRORS++ )) || true
  else
    ok "Docker: $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 'installed')"
  fi

  if ! docker compose version &>/dev/null 2>&1; then
    err "Docker Compose plugin not found. Upgrade Docker Desktop or install the plugin."
    (( ERRORS++ )) || true
  else
    ok "Docker Compose: $(docker compose version --short 2>/dev/null || echo 'available')"
  fi

  # RAM
  if [[ -f /proc/meminfo ]]; then
    local MEM_KB
    MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    local MEM_GB=$(( MEM_KB / 1024 / 1024 ))
    if (( MEM_GB < 4 )); then
      warn "Only ${MEM_GB} GB RAM found — recommend 4+ GB for full stack"
    else
      ok "RAM: ${MEM_GB} GB"
    fi
  fi

  # Disk
  local FREE_GB
  FREE_GB=$(df -BG . | awk 'NR==2 {gsub("G","",$4); print $4}')
  if (( FREE_GB < 20 )); then
    warn "Only ${FREE_GB} GB free disk space — recommend 20+ GB"
  else
    ok "Free disk: ${FREE_GB} GB"
  fi

  # Port conflict checks for critical ports
  local CRITICAL_PORTS=(8000 3000 5432 7687 6379 8080 8888 8090 8008)
  for port in "${CRITICAL_PORTS[@]}"; do
    if ss -tnlp 2>/dev/null | grep -q ":${port} " || \
       netstat -tnlp 2>/dev/null | grep -q ":${port} "; then
      warn "Port ${port} appears to be in use"
    fi
  done

  if (( ERRORS > 0 )); then
    die "Pre-flight checks failed. Fix the above errors and re-run."
  fi

  ok "All prerequisite checks passed"
  echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — LLM provider selection
# ─────────────────────────────────────────────────────────────────────────────
select_llm_provider() {
  LLM_PROVIDER=$(tui_menu \
    "LLM Provider" \
    "Select your primary AI/LLM provider:" \
    "openai" \
    "openai"     "OpenAI (GPT-4o / GPT-4.1)" \
    "anthropic"  "Anthropic (Claude 3.5 / 3.7)" \
    "google"     "Google Gemini (Gemini 1.5 / 2.0)" \
    "groq"       "Groq (Llama 3.3 Ultra-fast)" \
    "openrouter" "OpenRouter (Multi-model gateway)" \
    "bedrock"    "AWS Bedrock (Enterprise)" \
    "deepseek"   "DeepSeek (Cost-efficient)" \
    "qwen"       "Alibaba Qwen" \
    "glm"        "Zhipu GLM (ChatGLM)" \
    "kimi"       "Moonshot Kimi" \
    "vllm"       "vLLM (Self-hosted / air-gapped)" \
  )
  log "LLM provider: ${LLM_PROVIDER}"
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — API key collection
# ─────────────────────────────────────────────────────────────────────────────
collect_api_keys() {
  case "$LLM_PROVIDER" in
    openai)
      OPENAI_API_KEY=$(tui_passwordbox "OpenAI API Key" "Enter your OpenAI API key:")
      ;;
    anthropic)
      ANTHROPIC_API_KEY=$(tui_passwordbox "Anthropic API Key" "Enter your Anthropic API key:")
      ;;
    google)
      GOOGLE_API_KEY=$(tui_passwordbox "Google API Key" "Enter your Google Gemini API key (https://aistudio.google.com/apikey):")
      ;;
    groq)
      GROQ_API_KEY=$(tui_passwordbox "Groq API Key" "Enter your Groq API key:")
      ;;
    openrouter)
      OPENROUTER_API_KEY=$(tui_passwordbox "OpenRouter API Key" "Enter your OpenRouter API key:")
      ;;
    bedrock)
      AWS_ACCESS_KEY_ID=$(tui_inputbox "AWS Credentials" "AWS Access Key ID:" "")
      AWS_SECRET_ACCESS_KEY=$(tui_passwordbox "AWS Credentials" "AWS Secret Access Key:")
      AWS_DEFAULT_REGION=$(tui_inputbox "AWS Region" "AWS Region:" "us-east-1")
      ;;
    deepseek)
      DEEPSEEK_API_KEY=$(tui_passwordbox "DeepSeek API Key" "Enter your DeepSeek API key:")
      ;;
    qwen)
      QWEN_API_KEY=$(tui_passwordbox "Qwen API Key" "Enter your Qwen API key:")
      ;;
    glm)
      GLM_API_KEY=$(tui_passwordbox "Zhipu GLM API Key" "Enter your Zhipu GLM API key (https://open.bigmodel.cn):")
      ;;
    kimi)
      KIMI_API_KEY=$(tui_passwordbox "Moonshot Kimi API Key" "Enter your Moonshot Kimi API key (https://platform.moonshot.cn):")
      ;;
    vllm)
      VLLM_BASE_URL=$(tui_inputbox "vLLM Base URL" "Enter vLLM server URL:" "http://localhost:8080")
      ;;
  esac
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — Optional feature selection
# ─────────────────────────────────────────────────────────────────────────────
select_features() {
  local raw
  raw=$(tui_checklist \
    "Optional Services" \
    "Select optional services to enable (Space to toggle, Enter to confirm):" \
    "minio"            "MinIO Artifact Storage      (2 GB)" "on"  \
    "langfuse"         "Langfuse LLM Observability  (1 GB)" "on"  \
    "searxng"          "SearXNG Privacy Search      (500 MB)" "off" \
    "clickhouse"       "ClickHouse Analytics        (3 GB)" "off" \
    "victoria_metrics" "VictoriaMetrics Time Series (500 MB)" "on" \
  )
  ENABLED_FEATURES="${raw}"
  log "Enabled features: ${ENABLED_FEATURES:-none}"
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 5 — Generate secure passwords
# ─────────────────────────────────────────────────────────────────────────────
generate_secrets() {
  log "Generating cryptographically secure secrets …"

  if ! command -v python3 &>/dev/null; then
    die "python3 not found — cannot generate secrets. Install Python 3.10+ and retry."
  fi

  SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))" || die "Failed to generate SECRET_KEY")
  POSTGRES_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))" || die "Failed to generate POSTGRES_PASSWORD")
  NEO4J_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))" || die "Failed to generate NEO4J_PASSWORD")
  GRAFANA_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))" || die "Failed to generate GRAFANA_PASSWORD")
  COOKIE_SIGNING_SALT=$(python3 -c "import secrets; print(secrets.token_hex(32))" || die "Failed to generate COOKIE_SIGNING_SALT")
  MINIO_ACCESS_KEY=$(python3 -c "import secrets; print('univex-' + secrets.token_hex(8))" || die "Failed to generate MINIO_ACCESS_KEY")
  MINIO_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))" || die "Failed to generate MINIO_SECRET_KEY")
  ok "Secrets generated"
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 6 — Write .env file
# ─────────────────────────────────────────────────────────────────────────────
write_env_file() {
  log "Writing ${ENV_FILE} …"

  if [[ -f "${ROOT_DIR}/${ENV_FILE}" ]]; then
    local backup="${ROOT_DIR}/${ENV_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    cp "${ROOT_DIR}/${ENV_FILE}" "$backup"
    log "Existing .env backed up to ${backup}"
  fi

  cat > "${ROOT_DIR}/${ENV_FILE}" <<ENV
# UniVex .env — generated by install.sh $(date)
# Review all values before deploying to production.

# ===========================================================================
# Core
# ===========================================================================
ENVIRONMENT=production
SECRET_KEY=${SECRET_KEY:-}
DEBUG=false

# ===========================================================================
# Databases
# ===========================================================================
POSTGRES_USER=univex
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-}
POSTGRES_DB=univex
POSTGRES_HOST=postgres
POSTGRES_PORT=5432

NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=${NEO4J_PASSWORD:-}
NEO4J_DATABASE=neo4j

REDIS_URL=redis://redis:6379/0

# ===========================================================================
# LLM Provider
# ===========================================================================
DEFAULT_LLM_PROVIDER=${LLM_PROVIDER:-openai}
OPENAI_API_KEY=${OPENAI_API_KEY:-}
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
GOOGLE_API_KEY=${GOOGLE_API_KEY:-}
GROQ_API_KEY=${GROQ_API_KEY:-}
OPENROUTER_API_KEY=${OPENROUTER_API_KEY:-}
DEEPSEEK_API_KEY=${DEEPSEEK_API_KEY:-}
QWEN_API_KEY=${QWEN_API_KEY:-}
GLM_API_KEY=${GLM_API_KEY:-}
KIMI_API_KEY=${KIMI_API_KEY:-}
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-}
AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-east-1}
VLLM_BASE_URL=${VLLM_BASE_URL:-}

# ===========================================================================
# Cookie Security
# ===========================================================================
COOKIE_SIGNING_SALT=${COOKIE_SIGNING_SALT:-}
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=Lax

# ===========================================================================
# Observability
# ===========================================================================
GRAFANA_PASSWORD=${GRAFANA_PASSWORD:-}
PROMETHEUS_URL=http://prometheus:9090

# ===========================================================================
# MinIO Artifact Storage
# ===========================================================================
MINIO_ACCESS_KEY=${MINIO_ACCESS_KEY:-}
MINIO_SECRET_KEY=${MINIO_SECRET_KEY:-}
MINIO_REGION=us-east-1
MINIO_PORT=9100
MINIO_CONSOLE_PORT=9101
MINIO_BUCKET_SCREENSHOTS=univex-screenshots

# ===========================================================================
# Optional Features
# ===========================================================================
MINIO_ENABLED=$(echo "${ENABLED_FEATURES}" | grep -q minio && echo true || echo false)
LANGFUSE_ENABLED=$(echo "${ENABLED_FEATURES}" | grep -q langfuse && echo true || echo false)
SEARXNG_ENABLED=$(echo "${ENABLED_FEATURES}" | grep -q searxng && echo true || echo false)
CLICKHOUSE_ENABLED=$(echo "${ENABLED_FEATURES}" | grep -q clickhouse && echo true || echo false)
VICTORIA_METRICS_ENABLED=$(echo "${ENABLED_FEATURES}" | grep -q victoria_metrics && echo true || echo false)
ENV

  chmod 600 "${ROOT_DIR}/${ENV_FILE}"
  ok ".env written (permissions: 600)"
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 7 — Pull images and start services
# ─────────────────────────────────────────────────────────────────────────────
start_services() {
  if [[ "$DRY_RUN" == true ]]; then
    log "Dry-run mode — skipping compose up"
    return 0
  fi

  log "Pulling container images (this may take a few minutes) …"
  cd "${ROOT_DIR}"
  docker compose -f "${COMPOSE_FILE}" pull --quiet

  log "Starting UniVex services …"
  docker compose -f "${COMPOSE_FILE}" up -d --remove-orphans

  ok "Services started"
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 8 — Health check summary
# ─────────────────────────────────────────────────────────────────────────────
health_check_summary() {
  if [[ "$DRY_RUN" == true ]]; then
    return 0
  fi

  log "Waiting for services to become healthy …"
  local MAX_WAIT=120
  local waited=0
  while (( waited < MAX_WAIT )); do
    if curl -sf http://localhost:8000/api/health &>/dev/null; then
      ok "Backend API: healthy"
      break
    fi
    sleep 5
    (( waited+=5 ))
  done
  if (( waited >= MAX_WAIT )); then
    warn "Backend did not become healthy within ${MAX_WAIT}s — check: docker compose logs backend"
  fi

  hr
  echo ""
  echo -e "${BOLD}${GREEN}🚀 UniVex is ready!${RESET}"
  echo ""
  echo -e "  Frontend:     ${CYAN}http://localhost:3000${RESET}"
  echo -e "  Backend API:  ${CYAN}http://localhost:8000/docs${RESET}"
  echo -e "  Grafana:      ${CYAN}http://localhost:3030${RESET}"
  echo ""
  echo -e "  First-user setup: ${YELLOW}http://localhost:3000/setup${RESET}"
  echo ""
  hr
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
main() {
  # Initialise key variables (prevent unbound variable errors)
  LLM_PROVIDER="openai"
  OPENAI_API_KEY=""
  ANTHROPIC_API_KEY=""
  GOOGLE_API_KEY=""
  GROQ_API_KEY=""
  OPENROUTER_API_KEY=""
  DEEPSEEK_API_KEY=""
  QWEN_API_KEY=""
  GLM_API_KEY=""
  KIMI_API_KEY=""
  AWS_ACCESS_KEY_ID=""
  AWS_SECRET_ACCESS_KEY=""
  AWS_DEFAULT_REGION="us-east-1"
  VLLM_BASE_URL=""
  ENABLED_FEATURES=""
  SECRET_KEY=""
  POSTGRES_PASSWORD=""
  NEO4J_PASSWORD=""
  GRAFANA_PASSWORD=""
  COOKIE_SIGNING_SALT=""
  MINIO_ACCESS_KEY=""
  MINIO_SECRET_KEY=""

  show_welcome
  check_prerequisites
  select_llm_provider
  collect_api_keys
  select_features
  generate_secrets
  write_env_file
  start_services
  health_check_summary
}

main "$@"
