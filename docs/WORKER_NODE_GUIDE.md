# UniVex Worker Node Guide

**Version:** 2.1.0  
**Author:** BitR1FT  
**Updated:** March 2026

---

## Overview

UniVex supports a **two-node worker architecture** that separates the main orchestration server from a dedicated isolated worker node. This architecture is essential for:

- Running dangerous exploit tools (Metasploit, shellcode, Burp extensions) in a contained environment
- Compliance requirements that prohibit exploit tools on the same host as user data
- Scaling tool execution independently from the API server
- Air-gapped or network-segmented deployments

```

                  MAIN SERVER (Node 1)               
                                                     
        
    FastAPI    Next.js      PostgreSQL +      
    Backend    Frontend     Neo4j + Redis     
        
                                                    
                               
    Agent Orchestrator                             
    (planner/report)                               
                               

          mTLS gRPC / REST  (port 9443)

               WORKER NODE (Node 2)                  
                                                     
     
             UniVex Worker Agent                   
    (recon / exploit / webapp / coder agents)     
      
                                                     
        
    Naabu      Nuclei         Metasploit      
    FFuf       SQLMap         searchsploit    
    WPScan     Hydra          Impacket        
        
                                                     
  [Kali Linux container or dedicated VM]             

```

---

## Prerequisites

### Main Server (Node 1)
- Ubuntu 22.04 LTS or Debian 12 (minimum 4 vCPU, 8 GB RAM)
- Docker Engine 25+ and Docker Compose v2
- Ports: 80, 443, 8000, 3000 (public); 9443 (private, worker-facing)
- UniVex deployed via `docker compose up`

### Worker Node (Node 2)
- Ubuntu 22.04 LTS, Debian 12, **or** Kali Linux 2024+ (minimum 4 vCPU, 8 GB RAM, 80 GB disk)
- Docker Engine 25+
- No public internet exposure required (private link to main server only)
- GPU optional but recommended for local LLM inference (see `VLLM_CLUSTER_GUIDE.md`)

---

## Step 1: Generate mTLS Certificates

All communication between the main server and worker is encrypted with mutual TLS. Run this script on the main server:

```bash
#!/bin/bash
# Run on: Main Server (Node 1)
CERT_DIR=/etc/univex/certs
mkdir -p "$CERT_DIR"

# Certificate Authority
openssl genrsa -out "$CERT_DIR/ca.key" 4096
openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" \
  -sha256 -days 3650 \
  -subj "/CN=UniVex-CA/O=UniVex/C=US" \
  -out "$CERT_DIR/ca.crt"

# Main Server certificate
openssl genrsa -out "$CERT_DIR/server.key" 4096
openssl req -new -key "$CERT_DIR/server.key" \
  -subj "/CN=univex-main/O=UniVex/C=US" \
  -out "$CERT_DIR/server.csr"
openssl x509 -req -in "$CERT_DIR/server.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -days 365 -sha256 -out "$CERT_DIR/server.crt"

# Worker Node certificate
openssl genrsa -out "$CERT_DIR/worker.key" 4096
openssl req -new -key "$CERT_DIR/worker.key" \
  -subj "/CN=univex-worker/O=UniVex/C=US" \
  -out "$CERT_DIR/worker.csr"
openssl x509 -req -in "$CERT_DIR/worker.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -days 365 -sha256 -out "$CERT_DIR/worker.crt"

echo "Certificates generated in $CERT_DIR"
echo "Copy the following files to the worker node:"
echo "  $CERT_DIR/ca.crt"
echo "  $CERT_DIR/worker.crt"
echo "  $CERT_DIR/worker.key"
```

Copy the worker certificates to Node 2:

```bash
# Run on: Main Server — copy certs to worker
scp /etc/univex/certs/ca.crt worker@<WORKER_IP>:/etc/univex/certs/
scp /etc/univex/certs/worker.crt worker@<WORKER_IP>:/etc/univex/certs/
scp /etc/univex/certs/worker.key worker@<WORKER_IP>:/etc/univex/certs/
```

---

## Step 2: Configure the Main Server

Add the following to your `backend/.env` on Node 1:

```env
# Worker Node Configuration
WORKER_MODE=main
WORKER_NODE_URL=https://<WORKER_IP>:9443
WORKER_NODE_CERT=/etc/univex/certs/server.crt
WORKER_NODE_KEY=/etc/univex/certs/server.key
WORKER_NODE_CA=/etc/univex/certs/ca.crt

# Agents that run on the worker node (comma-separated)
REMOTE_AGENTS=recon,exploit,webapp,coder

# Agents that stay on the main server
LOCAL_AGENTS=planner,report,refiner,adviser,reflector,enricher,simple_json,installer
```

Expose port 9443 from the main server's firewall **only to the worker's IP address**:

```bash
# Main Server firewall
ufw allow from <WORKER_IP> to any port 9443 proto tcp
```

---

## Step 3: Deploy the Worker Node

On Node 2, clone the UniVex repository and prepare the worker compose:

```bash
# On: Worker Node (Node 2)
git clone https://github.com/BitR1ft/UniVex.git /opt/univex
cd /opt/univex

# Create worker environment file
cat > backend/.env.worker << 'EOF'
WORKER_MODE=worker
MAIN_SERVER_URL=https://<MAIN_SERVER_IP>:9443
WORKER_CERT=/etc/univex/certs/worker.crt
WORKER_KEY=/etc/univex/certs/worker.key
WORKER_CA=/etc/univex/certs/ca.crt

# Worker registration token (generate with: openssl rand -hex 32)
WORKER_TOKEN=<SECURE_RANDOM_TOKEN>

# Which agents this worker hosts
WORKER_AGENTS=recon,exploit,webapp,coder

# Tool paths (adjust for your OS / tool installation method)
NAABU_PATH=/usr/local/bin/naabu
NUCLEI_PATH=/usr/local/bin/nuclei
FFUF_PATH=/usr/local/bin/ffuf
SQLMAP_PATH=/usr/bin/sqlmap
METASPLOIT_PATH=/usr/bin/msfconsole

# No frontend, no main DB on worker
DATABASE_URL=
NEO4J_URI=
EOF
```

Start the worker using the dedicated compose file:

```bash
cd /opt/univex
docker compose -f docker/worker/docker-compose.worker.yml up -d
```

**`docker/worker/docker-compose.worker.yml`:**

```yaml
version: "3.9"

services:
  univex-worker:
    build:
      context: .
      dockerfile: docker/worker/Dockerfile.worker
    container_name: univex-worker
    restart: unless-stopped
    ports:
      - "9443:9443"
    environment:
      - WORKER_MODE=worker
    env_file:
      - backend/.env.worker
    volumes:
      - /etc/univex/certs:/etc/univex/certs:ro
      - worker-results:/app/results
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW         # for raw socket tools (naabu, nmap)
      - NET_ADMIN       # for VPN tunnel tools

  # Kali security tools (privileged container — network scan only)
  univex-kali:
    image: kalilinux/kali-rolling:latest
    container_name: univex-kali-worker
    restart: unless-stopped
    network_mode: host
    privileged: true
    command: ["sleep", "infinity"]
    volumes:
      - worker-results:/results

volumes:
  worker-results:
```

---

## Step 4: Install Security Tools on the Worker

For Kali Linux worker nodes, tools are pre-installed. For Ubuntu/Debian:

```bash
# Go-based tools
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf/v2@latest

# Python tools
pip install sqlmap

# Metasploit (Ubuntu) — download, verify, then execute
curl -fsSL -o /tmp/msfinstall.erb \
  https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb
# Review the script before proceeding:
# less /tmp/msfinstall.erb
sudo ruby /tmp/msfinstall.erb
rm -f /tmp/msfinstall.erb

# WPScan
gem install wpscan

# Hydra
apt-get install -y hydra

# Update nuclei templates
nuclei -update-templates
```

---

## Step 5: Register the Worker with the Main Server

```bash
# On: Worker Node
curl -k --cert /etc/univex/certs/worker.crt \
        --key /etc/univex/certs/worker.key \
        --cacert /etc/univex/certs/ca.crt \
  -X POST https://<MAIN_SERVER_IP>:9443/worker/register \
  -H "Authorization: Bearer <WORKER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": "worker-01",
    "agents": ["recon", "exploit", "webapp", "coder"],
    "capacity": 4,
    "tools": ["naabu", "nuclei", "ffuf", "sqlmap", "metasploit"]
  }'
```

The main server will respond with a `200 OK` and the assigned task queue topics.

---

## Step 6: Verify the Connection

On the main server, check the worker status:

```bash
# Check worker health from main server
curl -sk --cert /etc/univex/certs/server.crt \
         --key /etc/univex/certs/server.key \
         --cacert /etc/univex/certs/ca.crt \
  https://<WORKER_IP>:9443/worker/health | jq

# Expected response:
# {
# "status": "healthy",
# "node_id": "worker-01",
# "agents": ["recon", "exploit", "webapp", "coder"],
# "active_tasks": 0,
# "uptime_seconds": 1234
# }
```

From the main server's admin panel:

```
Settings → Worker Nodes → worker-01 → Status:  Connected
```

---

## Step 7: Configure Agent Routing

Edit `examples/configs/agents/agents.yaml` on the main server to pin specific agents to the worker:

```yaml
# examples/configs/agents/agents.yaml (main server)
agents:
  recon:
    model: gpt-4o-mini
    provider: openai
    temperature: 0.1
    # Route this agent to the worker node
    worker_node: worker-01

  exploit:
    model: claude-3-5-sonnet-20241022
    provider: anthropic
    temperature: 0.1
    worker_node: worker-01

  planner:
    model: gpt-4o
    provider: openai
    temperature: 0.2
    # No worker_node = runs on main server
```

---

## Security Hardening

### Worker Node Isolation

```bash
# Restrict outbound traffic from worker (allow only to main server and target network)
iptables -A OUTPUT -d <MAIN_SERVER_IP> -j ACCEPT
iptables -A OUTPUT -d <TARGET_NETWORK_CIDR> -j ACCEPT
iptables -A OUTPUT -j DROP

# Ensure worker containers cannot access host metadata endpoints (cloud environments)
iptables -I DOCKER-USER -d 169.254.169.254 -j DROP
```

### Automatic Certificate Rotation

Add a cron job on both nodes to rotate certificates 30 days before expiry:

```bash
# /etc/cron.d/univex-cert-rotation
0 2 1 * * root /opt/univex/scripts/rotate-secrets.sh --certs-only
```

### Worker Audit Logging

The worker logs all tool executions to a tamper-evident audit trail:

```bash
# View worker audit log
docker exec univex-worker tail -f /var/log/univex/audit.jsonl | jq
```

---

## Monitoring the Worker

The worker exposes Prometheus metrics at `https://<WORKER_IP>:9443/metrics` (mTLS required):

| Metric | Description |
|---|---|
| `univex_worker_tasks_total` | Total tasks processed |
| `univex_worker_task_duration_seconds` | Task execution duration histogram |
| `univex_worker_active_tasks` | Currently running tasks |
| `univex_worker_tool_calls_total` | Tool invocations by tool name |
| `univex_worker_errors_total` | Error count by agent + error type |

Add the worker to your Prometheus scrape config:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: univex-worker
    scheme: https
    tls_config:
      cert_file: /etc/univex/certs/server.crt
      key_file: /etc/univex/certs/server.key
      ca_file: /etc/univex/certs/ca.crt
    static_configs:
      - targets: ["<WORKER_IP>:9443"]
        labels:
          node: worker-01
```

---

## Scaling to Multiple Workers

UniVex supports unlimited worker nodes. Each worker registers independently:

```bash
# Register a second worker (GPU-equipped for ML tasks)
curl -k ... https://<MAIN_SERVER_IP>:9443/worker/register \
  -d '{
    "node_id": "worker-02-gpu",
    "agents": ["recon", "exploit"],
    "capacity": 8,
    "tags": ["gpu", "ml-enabled"]
  }'
```

The main server uses **round-robin with capacity weighting** to distribute tasks across registered workers. Workers with higher `capacity` receive proportionally more tasks.

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `Connection refused` on port 9443 | Worker firewall blocking | `ufw allow 9443/tcp` on worker |
| `certificate verify failed` | CA mismatch | Regenerate certs with correct CA |
| `Worker not appearing in admin panel` | Registration token wrong | Check `WORKER_TOKEN` matches on both nodes |
| Agent tasks timing out | Worker overloaded | Reduce `capacity` or add another worker |
| Tools not found | PATH not set in Docker container | Check `Dockerfile.worker` ENV section |

---

## Related Documentation

- [`docs/VLLM_CLUSTER_GUIDE.md`](VLLM_CLUSTER_GUIDE.md) — Add local LLM inference to the worker node
- [`docs/OPERATIONS_RUNBOOK.md`](OPERATIONS_RUNBOOK.md) — Production operations procedures
- [`docs/CLOUD_SECURITY_GUIDE.md`](CLOUD_SECURITY_GUIDE.md) — Cloud deployment security controls
- [`AGENT_BENCHMARK_GUIDE.md`](AGENT_BENCHMARK_GUIDE.md) — Benchmarking agents across nodes

---

## Implementation Reference

### WorkerServer API (REST)

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | None | Health check — returns worker status and registered MCP servers |
| `GET` | `/api/worker/capabilities` | Bearer | List available MCP servers and tools on this worker |
| `POST` | `/api/worker/execute` | Bearer | Execute a tool on the worker node |

**Execute request body:**
```json
{
  "job_id": "uuid-hex-optional",
  "tool_name": "execute_naabu",
  "server_name": "naabu",
  "params": { "target": "10.0.0.1", "ports": "top-1000" },
  "timeout": 120,
  "classification": "remote"
}
```

**Execute response body:**
```json
{
  "job_id": "abc123",
  "tool_name": "execute_naabu",
  "server_name": "naabu",
  "success": true,
  "result": { "ports": [...] },
  "error": null,
  "duration_ms": 4320.5,
  "worker_id": "worker-1"
}
```

### JobDispatcher — Tool Classification

The `JobDispatcher` (`backend/app/worker/job_dispatcher.py`) automatically classifies tool calls:

```python
from app.worker.job_dispatcher import JobDispatcher, JobClassification
from app.agent.state.agent_state import Phase

dispatcher = JobDispatcher()

# Classification
dispatcher.classify("naabu_scan")          # → JobClassification.REMOTE
dispatcher.classify("web_search")          # → JobClassification.LOCAL
dispatcher.classify("unknown_tool", Phase.EXPLOITATION)  # → REMOTE (phase heuristic)

# Dispatch
result = await dispatcher.dispatch(
    tool_name="naabu_scan",
    params={"target": "10.0.0.1"},
    phase=Phase.EXPLOITATION,
)
```

**Default ALWAYS_REMOTE tools** include: `naabu_scan`, `exploit_execute`, `metasploit_execute`, `sqlmap_*`, `brute_force`, `reverse_shell`, `file_operations`, all browser tools, `nuclei_scan`, `ffuf_*`.

**Default ALWAYS_LOCAL tools** include: `echo`, `calculator`, `query_graph`, `web_search`, all OOB tools, all search tools.

### WorkerClient — Circuit Breaker

The `WorkerClient` includes a built-in circuit breaker:

- Opens after **5 consecutive failures**
- Resets after **60 seconds** (half-open: sends one test request)
- Falls back to degraded-mode error dict when circuit is open and `WORKER_FALLBACK=true`

```python
from app.worker.worker_client import WorkerClient

client = WorkerClient(
    base_url="https://worker.internal:9443",
    secret="your-shared-secret",
    timeout=310,
    fallback_to_local=True,
)

# Health check before critical scans
if not await client.health_check():
    logger.warning("Worker unavailable — using degraded mode")

result = await client.execute(
    tool_name="execute_naabu",
    server_name="naabu",
    params={"target": "10.0.0.1", "ports": "top-1000"},
)
```

### OrchestratorAgent Integration

Attach a `JobDispatcher` to the `OrchestratorAgent` for automatic routing:

```python
from app.agent.orchestrator import OrchestratorAgent
from app.worker.job_dispatcher import JobDispatcher
from app.worker.worker_client import WorkerClient

worker_client = WorkerClient(base_url="https://worker:9443", secret="...")
dispatcher = JobDispatcher(worker_client=worker_client)

orchestrator = OrchestratorAgent(registry=registry, llm=llm)
orchestrator.set_job_dispatcher(dispatcher)

# All tool calls are now automatically routed local or remote
result = await orchestrator.dispatch_tool(
    tool_name="naabu_scan",
    params={"target": "10.0.0.1"},
    phase=Phase.EXPLOITATION,
)
```

### mTLS Certificate Setup

For production deployments, generate mTLS certificates:

```bash
# Run once on the main node
bash scripts/gen-worker-certs.sh

# Copy worker cert to worker node
scp certs/worker/worker.crt certs/worker/worker.key worker-host:/etc/univex/certs/

# Set environment on main node
export WORKER_MTLS_CERT_PATH=/etc/univex/certs/worker.crt
export WORKER_MTLS_KEY_PATH=/etc/univex/certs/worker.key
export WORKER_MTLS_CA_PATH=/etc/univex/certs/ca.crt

# Set shared secret as backup (recommended for defence-in-depth)
export WORKER_SHARED_SECRET=$(openssl rand -hex 32)
```

### Worker-Only Compose File

The `docker-compose-worker.yml` starts only the worker-side services:

```bash
# On the worker node
cp .env.example .env.worker
# Edit .env.worker: set WORKER_SHARED_SECRET, MSF_PASSWORD, OOB_EXTERNAL_IP

docker compose -f docker-compose-worker.yml --env-file .env.worker up -d

# Verify worker is reachable from main node
curl -H "Authorization: Bearer $WORKER_SHARED_SECRET" \
     http://<WORKER_IP>:9443/api/worker/capabilities
```

### Firewall Rules (Worker Node)

```bash
# Allow main node to reach WorkerServer
ufw allow from <MAIN_NODE_IP> to any port 9443 proto tcp

# Allow OOB HTTP callbacks from anywhere (needed for blind vuln detection)
ufw allow 8080/tcp comment "OOB HTTP callbacks"
ufw allow 5353/udp comment "OOB DNS callbacks"
ufw allow 2525/tcp comment "OOB SMTP callbacks"

# Block all other inbound by default
ufw default deny incoming
ufw enable
```
