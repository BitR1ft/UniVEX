#!/usr/bin/env bash
# ==============================================================================
# UniVex Interactive TUI Installer — Podman Edition
# Version: 2.1.0  Author: BitR1FT  License: MIT
#
# Rootless Podman + podman-compose installer for RHEL/Fedora/CentOS environments.
# Supports SELinux enforcing mode with :z / :Z volume label annotations.
#
# Usage:
#   bash scripts/install-podman.sh
#   bash scripts/install-podman.sh --non-interactive
#   bash scripts/install-podman.sh --dry-run
#   bash scripts/install-podman.sh --rootful    # use rootful Podman (requires sudo)
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
ROOTFUL=false

# Colours
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ─────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --non-interactive) NON_INTERACTIVE=true ;;
    --dry-run)         DRY_RUN=true ;;
    --rootful)         ROOTFUL=true ;;
    --help|-h)
      echo "Usage: $0 [--non-interactive] [--dry-run] [--rootful]"
      exit 0
      ;;
  esac
done

# ─────────────────────────────────────────────────────────────────────────────
# Utility functions
# ─────────────────────────────────────────────────────────────────────────────
log()  { echo -e "${CYAN}[UniVex/Podman]${RESET} $*"; }
ok()   { echo -e "${GREEN}  ✔${RESET} $*"; }
warn() { echo -e "${YELLOW}  ⚠${RESET} $*"; }
err()  { echo -e "${RED}  ✘${RESET} $*" >&2; }
die()  { err "$*"; exit 1; }
hr()   { echo -e "${BLUE}──────────────────────────────────────────${RESET}"; }

TUI_CMD=""
command -v whiptail &>/dev/null && TUI_CMD="whiptail"
[[ -z "$TUI_CMD" ]] && command -v dialog &>/dev/null && TUI_CMD="dialog"

tui_available() { [[ -n "$TUI_CMD" && "$NON_INTERACTIVE" == false ]]; }

tui_msgbox() {
  local title="$1"; local msg="$2"
  tui_available && $TUI_CMD --title "$title" --msgbox "$msg" 20 70 || \
    echo -e "\n${BOLD}=== ${title} ===${RESET}\n${msg}\n"
}

tui_menu() {
  local title="$1"; local msg="$2"; local default="$3"; shift 3
  if tui_available; then
    $TUI_CMD --title "$title" --default-item "$default" \
      --menu "$msg" 20 70 10 "$@" 3>&1 1>&2 2>&3 || echo "$default"
  else
    echo "$default"
  fi
}

tui_passwordbox() {
  local title="$1"; local msg="$2"
  tui_available && $TUI_CMD --title "$title" --passwordbox "$msg" 10 60 "" 3>&1 1>&2 2>&3 || echo ""
}

tui_inputbox() {
  local title="$1"; local msg="$2"; local default="${3:-}"
  tui_available && \
    $TUI_CMD --title "$title" --inputbox "$msg" 10 60 "$default" 3>&1 1>&2 2>&3 || echo "$default"
}

tui_checklist() {
  local title="$1"; local msg="$2"; shift 2
  if tui_available; then
    $TUI_CMD --title "$title" --checklist "$msg" 20 70 10 "$@" 3>&1 1>&2 2>&3 || echo ""
  else
    local result=()
    local i=0
    local args=("$@")
    while (( i < ${#args[@]} )); do
      [[ "${args[$((i+2))]}" == "on" ]] && result+=("${args[$i]}")
      (( i+=3 ))
    done
    printf '%s\n' "${result[@]}"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 0 — Welcome
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
  echo -e "  ${BOLD}UniVex — Podman Installer${RESET} (Rootless / RHEL / Fedora)"
  echo -e "  Version ${UNIVEX_VERSION}  ·  Author: BitR1FT"
  hr
  echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Podman prerequisite checks
# ─────────────────────────────────────────────────────────────────────────────
check_prerequisites() {
  log "Checking Podman prerequisites …"
  local ERRORS=0

  # Podman binary
  if ! command -v podman &>/dev/null; then
    err "Podman not found. Install: sudo dnf install -y podman  (RHEL/Fedora)"
    err "               Or:        sudo apt-get install -y podman  (Ubuntu 22.04+)"
    (( ERRORS++ )) || true
  else
    ok "Podman: $(podman version --format '{{.Version}}' 2>/dev/null || echo 'installed')"
  fi

  # podman-compose
  if ! command -v podman-compose &>/dev/null; then
    err "podman-compose not found. Install: pip install --user podman-compose"
    (( ERRORS++ )) || true
  else
    ok "podman-compose: $(podman-compose version 2>/dev/null | head -1 || echo 'available')"
  fi

  # Rootless user-namespace support
  if [[ "$ROOTFUL" == false ]]; then
    if ! podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null | grep -q true; then
      warn "Rootless Podman may not be fully configured."
      warn "Run: loginctl enable-linger \$(whoami)"
      warn "     sudo sysctl -w kernel.unprivileged_userns_clone=1"
    else
      ok "Rootless Podman: configured"
    fi
  fi

  # SELinux detection
  if command -v getenforce &>/dev/null; then
    local SELINUX_MODE
    SELINUX_MODE=$(getenforce 2>/dev/null || echo "Unknown")
    if [[ "$SELINUX_MODE" == "Enforcing" ]]; then
      warn "SELinux is Enforcing — volume mounts will use :z label"
      warn "If you encounter permission errors, run: setsebool -P container_manage_cgroup 1"
      SELINUX_ENFORCING=true
    else
      ok "SELinux: ${SELINUX_MODE}"
      SELINUX_ENFORCING=false
    fi
  else
    SELINUX_ENFORCING=false
  fi

  # RAM / Disk (same as Docker installer)
  if [[ -f /proc/meminfo ]]; then
    local MEM_GB
    MEM_GB=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)
    (( MEM_GB < 4 )) && warn "Only ${MEM_GB} GB RAM — 4+ GB recommended" || ok "RAM: ${MEM_GB} GB"
  fi

  local FREE_GB
  FREE_GB=$(df -BG . | awk 'NR==2 {gsub("G","",$4); print $4}')
  (( FREE_GB < 20 )) && warn "Only ${FREE_GB} GB free — 20+ GB recommended" || ok "Disk: ${FREE_GB} GB"

  # Port conflict checks for critical ports
  local CRITICAL_PORTS=(8000 3000 5432 7687 6379 8080 8888 8090 8008)
  for port in "${CRITICAL_PORTS[@]}"; do
    if ss -tnlp 2>/dev/null | grep -q ":${port} " || \
       netstat -tnlp 2>/dev/null | grep -q ":${port} "; then
      warn "Port ${port} appears to be in use"
    fi
  done

  (( ERRORS > 0 )) && die "Fix the above errors and re-run."
  ok "Prerequisite checks passed"
  echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 2-4 — LLM provider, API keys, features (identical logic to install.sh)
# ─────────────────────────────────────────────────────────────────────────────
select_llm_provider() {
  LLM_PROVIDER=$(tui_menu \
    "LLM Provider" "Select your primary AI/LLM provider:" "openai" \
    "openai"     "OpenAI (GPT-4o / GPT-4.1)" \
    "anthropic"  "Anthropic (Claude 3.5 / 3.7)" \
    "google"     "Google Gemini (Gemini 1.5 / 2.0)" \
    "groq"       "Groq (Ultra-fast Llama)" \
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

collect_api_keys() {
  case "$LLM_PROVIDER" in
    openai)    OPENAI_API_KEY=$(tui_passwordbox "OpenAI" "OpenAI API key:") ;;
    anthropic) ANTHROPIC_API_KEY=$(tui_passwordbox "Anthropic" "Anthropic API key:") ;;
    google)    GOOGLE_API_KEY=$(tui_passwordbox "Google Gemini" "Google Gemini API key (https://aistudio.google.com/apikey):") ;;
    groq)      GROQ_API_KEY=$(tui_passwordbox "Groq" "Groq API key:") ;;
    openrouter) OPENROUTER_API_KEY=$(tui_passwordbox "OpenRouter" "OpenRouter API key:") ;;
    bedrock)
      AWS_ACCESS_KEY_ID=$(tui_inputbox "AWS" "Access Key ID:" "")
      AWS_SECRET_ACCESS_KEY=$(tui_passwordbox "AWS" "Secret Access Key:")
      AWS_DEFAULT_REGION=$(tui_inputbox "AWS" "Region:" "us-east-1")
      ;;
    deepseek)  DEEPSEEK_API_KEY=$(tui_passwordbox "DeepSeek" "DeepSeek API key:") ;;
    qwen)      QWEN_API_KEY=$(tui_passwordbox "Qwen" "Qwen API key (https://bailian.console.aliyun.com):") ;;
    glm)       GLM_API_KEY=$(tui_passwordbox "Zhipu GLM" "Zhipu GLM API key (https://open.bigmodel.cn):") ;;
    kimi)      KIMI_API_KEY=$(tui_passwordbox "Moonshot Kimi" "Moonshot Kimi API key (https://platform.moonshot.cn):") ;;
    vllm)      VLLM_BASE_URL=$(tui_inputbox "vLLM" "vLLM URL:" "http://localhost:8080") ;;
  esac
}

select_features() {
  ENABLED_FEATURES=$(tui_checklist \
    "Optional Services" "Select optional services to enable:" \
    "minio"            "MinIO Artifact Storage"          "on"  \
    "langfuse"         "Langfuse LLM Observability"      "on"  \
    "searxng"          "SearXNG Privacy Search"          "off" \
    "clickhouse"       "ClickHouse Analytics"            "off" \
    "victoria_metrics" "VictoriaMetrics Time Series"     "on"  \
  )
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 5 — Configure Podman socket for podman-compose
# ─────────────────────────────────────────────────────────────────────────────
configure_podman_socket() {
  log "Configuring Podman socket …"

  local UID_VAL="${UID:-$(id -u)}"
  local XDG_RUNTIME="${XDG_RUNTIME_DIR:-/run/user/${UID_VAL}}"
  local SOCKET_PATH="${XDG_RUNTIME}/podman/podman.sock"

  if [[ "$ROOTFUL" == true ]]; then
    SOCKET_PATH="/run/podman/podman.sock"
    log "Rootful mode — using system socket: ${SOCKET_PATH}"
  else
    # Enable and start the rootless Podman socket
    if command -v systemctl &>/dev/null; then
      systemctl --user enable --now podman.socket 2>/dev/null || \
        warn "Could not enable podman.socket systemd unit — start it manually."
    fi
    log "Rootless socket: ${SOCKET_PATH}"
  fi

  export DOCKER_HOST="unix://${SOCKET_PATH}"
  PODMAN_SOCKET_PATH="${SOCKET_PATH}"

  ok "DOCKER_HOST=${DOCKER_HOST}"
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 6 — Generate secrets
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
# Step 7 — Write .env with Podman-specific overrides
# ─────────────────────────────────────────────────────────────────────────────
write_env_file() {
  log "Writing ${ENV_FILE} …"

  if [[ -f "${ROOT_DIR}/${ENV_FILE}" ]]; then
    local backup="${ROOT_DIR}/${ENV_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    cp "${ROOT_DIR}/${ENV_FILE}" "$backup"
    log "Backed up existing .env to ${backup}"
  fi

  cat > "${ROOT_DIR}/${ENV_FILE}" <<ENV
# UniVex .env — generated by install-podman.sh $(date)
# Podman / rootless deployment — RHEL/Fedora/CentOS

ENVIRONMENT=production
SECRET_KEY=${SECRET_KEY:-}
DEBUG=false

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

COOKIE_SIGNING_SALT=${COOKIE_SIGNING_SALT:-}
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=Lax

GRAFANA_PASSWORD=${GRAFANA_PASSWORD:-}
PROMETHEUS_URL=http://prometheus:9090

MINIO_ACCESS_KEY=${MINIO_ACCESS_KEY:-}
MINIO_SECRET_KEY=${MINIO_SECRET_KEY:-}
MINIO_REGION=us-east-1
MINIO_PORT=9100
MINIO_CONSOLE_PORT=9101
MINIO_BUCKET_SCREENSHOTS=univex-screenshots

MINIO_ENABLED=$(echo "${ENABLED_FEATURES}" | grep -q minio && echo true || echo false)
LANGFUSE_ENABLED=$(echo "${ENABLED_FEATURES}" | grep -q langfuse && echo true || echo false)
SEARXNG_ENABLED=$(echo "${ENABLED_FEATURES}" | grep -q searxng && echo true || echo false)
CLICKHOUSE_ENABLED=$(echo "${ENABLED_FEATURES}" | grep -q clickhouse && echo true || echo false)
VICTORIA_METRICS_ENABLED=$(echo "${ENABLED_FEATURES}" | grep -q victoria_metrics && echo true || echo false)

# Podman-specific — used by podman-compose and the UniVex backend
DOCKER_HOST=unix://${PODMAN_SOCKET_PATH:-/run/user/1000/podman/podman.sock}
COMPOSE_IGNORE_ORPHANS=true
CONTAINER_RUNTIME=podman
ENV

  chmod 600 "${ROOT_DIR}/${ENV_FILE}"
  ok ".env written (permissions: 600)"
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 8 — Launch with podman-compose
# ─────────────────────────────────────────────────────────────────────────────
start_services() {
  if [[ "$DRY_RUN" == true ]]; then
    log "Dry-run — skipping podman-compose up"
    return 0
  fi

  cd "${ROOT_DIR}"
  log "Pulling images via podman-compose …"
  DOCKER_HOST="${DOCKER_HOST}" podman-compose -f "${COMPOSE_FILE}" pull

  log "Starting services …"
  DOCKER_HOST="${DOCKER_HOST}" podman-compose -f "${COMPOSE_FILE}" up -d

  ok "Services started"
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 9 — Health check
# ─────────────────────────────────────────────────────────────────────────────
health_check_summary() {
  [[ "$DRY_RUN" == true ]] && return 0

  log "Waiting for backend API …"
  local waited=0
  while (( waited < 120 )); do
    curl -sf http://localhost:8000/api/health &>/dev/null && break
    sleep 5; (( waited+=5 ))
  done
  (( waited >= 120 )) && warn "Backend health check timed out"

  hr
  echo ""
  echo -e "${BOLD}${GREEN}🚀 UniVex (Podman) is ready!${RESET}"
  echo ""
  echo -e "  Frontend:     ${CYAN}http://localhost:3000${RESET}"
  echo -e "  Backend API:  ${CYAN}http://localhost:8000/docs${RESET}"
  echo ""
  echo -e "  First-user setup: ${YELLOW}http://localhost:3000/setup${RESET}"
  echo ""
  if [[ "${SELINUX_ENFORCING:-false}" == true ]]; then
    echo -e "  ${YELLOW}SELinux note:${RESET} Volume labels (:z) applied automatically."
    echo -e "  If containers fail to read mounts, run:"
    echo -e "    sudo chcon -Rt container_file_t ./data/"
  fi
  hr
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
main() {
  LLM_PROVIDER="openai"
  OPENAI_API_KEY=""; ANTHROPIC_API_KEY=""; GOOGLE_API_KEY=""
  GROQ_API_KEY=""; OPENROUTER_API_KEY=""; DEEPSEEK_API_KEY=""
  QWEN_API_KEY=""; GLM_API_KEY=""; KIMI_API_KEY=""
  AWS_ACCESS_KEY_ID=""; AWS_SECRET_ACCESS_KEY=""; AWS_DEFAULT_REGION="us-east-1"
  VLLM_BASE_URL=""
  ENABLED_FEATURES=""; SELINUX_ENFORCING=false
  SECRET_KEY=""; POSTGRES_PASSWORD=""; NEO4J_PASSWORD=""
  GRAFANA_PASSWORD=""; COOKIE_SIGNING_SALT=""
  MINIO_ACCESS_KEY=""; MINIO_SECRET_KEY=""
  PODMAN_SOCKET_PATH="/run/user/$(id -u)/podman/podman.sock"
  DOCKER_HOST="unix://${PODMAN_SOCKET_PATH}"

  show_welcome
  check_prerequisites
  select_llm_provider
  collect_api_keys
  select_features
  configure_podman_socket
  generate_secrets
  write_env_file
  start_services
  health_check_summary
}

main "$@"
