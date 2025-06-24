# UniVex — System Architecture Documentation

> Comprehensive system architecture documentation including component
> interactions, data flow, deployment architecture, and design decisions.

---

## System Overview

UniVex is a **full-stack AI-powered penetration testing assistant**
that automates the reconnaissance and vulnerability assessment phases of
security testing, guided by an LLM-powered AI agent.

### Core Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Frontend** | Next.js 14 + TypeScript | Web UI for users |
| **Backend API** | FastAPI (Python 3.11) | Core API server |
| **AI Agent** | LangChain + GPT-4 | Autonomous assessment |
| **Graph DB** | Neo4j 5.15 | Attack surface graph |
| **Relational DB** | PostgreSQL 16 | User/project data |
| **MCP Servers** | Python + MCP Protocol | Tool execution layer |
| **Observability** | Prometheus + Grafana | Metrics + alerting |
| **Tracing** | OpenTelemetry | Distributed tracing |

---

## High-Level Architecture

```

                              INTERNET                                 

                                  HTTPS/WSS
                         
                             Nginx     
                          (TLS Termination
                          Load Balancer)
                         
                                   
                    
                 Next.js           FastAPI    
                 Frontend          Backend    
                 (Port 3000)       (Port 8000)
                    
                                         
              
                                        
             
       PostgreSQL               Neo4j        
       (Port 5432)            (Port 7687)   
       User/Project           Attack Graph  
             
              
     
                Security Tools Layer             
          
        Naabu    Nuclei    Metasploit     
        MCP      MCP       MCP Server     
        Server   Server    (Port 8003)    
          
     
              
     
                Observability Stack              
             
         Prometheus         Grafana         
         (Port 9090)      (Port 3001)      
            
     
```

---

## Data Flow Diagrams

### Scan Initiation Flow

```
User clicks "Start Scan"
        
        
Frontend validates project state
        
        
POST /api/projects/{id}/start
        
        
Auth middleware validates JWT + RBAC (PROJECT_START permission)
        
        
WAF middleware checks for injection attacks
        
        
Rate limiter checks (10 starts/hour)
        
        
Project service updates status: draft → queued
        
        
Background task launched (Celery/asyncio)
        
         Recon Phase: subfinder, amass, naabu
         Probe Phase: httpx, whatweb
         Vuln Phase: nuclei, nmap scripts
         Graph Phase: ingest all results to Neo4j
        
        
SSE stream pushes progress updates to frontend
        
        
Project status updated: running → completed/failed
```

### AI Agent Chat Flow

```
User message: "What vulnerabilities did you find?"
        
        
POST /api/agent/chat
        
        
AgentSession loaded (or created)
        
        
Context built: project data + scan results + conversation history
        
        
LLM (GPT-4) generates response + optional tool call
        
        [No tool call] Stream text response to user via SSE
        
        [Tool call] Check risk level
                         
                         [LOW/MEDIUM] Execute immediately
                                           Stream result + agent reasoning
                         
                         [HIGH/CRITICAL] Send approval_required event
                                               Wait for user approval/rejection
```

### Graph Data Ingestion Flow

```
Tool completes (e.g., subfinder finds subdomains)
        
        
Raw output parsed to ToolResult
        
        
TaskResult stored in PostgreSQL
        
        
Graph ingestion pipeline triggered
        
        
Neo4j nodes created:
  - Domain node (if not exists)
  - Subdomain nodes
  - HAS_SUBDOMAIN relationships
        
        
Graph updated in real-time
        
        
Frontend graph view reloads on next poll/SSE event
```

---

## Security Architecture

### Defense in Depth

```
Layer 1: Network (Nginx)
  - TLS 1.3 termination
  - DDoS protection
  - IP rate limiting

Layer 2: Application Gateway
  - JWT authentication
  - RBAC authorization
  - WAF (SQL injection, XSS, path traversal)

Layer 3: Business Logic
  - Input validation (Pydantic)
  - Sliding window rate limiting
  - Audit logging

Layer 4: Data
  - Encrypted at rest (PostgreSQL + Neo4j)
  - Row-level security (user_id isolation)
  - Secret management (environment variables)

Layer 5: Operations
  - Secret rotation
  - Dependency scanning (Dependabot)
  - Container scanning (Trivy)
  - SAST (Bandit + CodeQL)
```

---

## Network Segmentation

```

                      Docker Networks                             
                                                                  
    
    prod-db (internal, no external access)                    
    172.20.1.0/24                                             
    postgres  neo4j  backend                         
    
                                                                  
    
    prod-backend                                              
    172.20.2.0/24                                             
    backend  prometheus                                   
    
                                                                  
    
    prod-frontend (internet-accessible)                       
    172.20.3.0/24                                             
    nginx  frontend  backend                         
    
                                                                  
    
    tools-network (isolated, controlled access)               
    172.20.4.0/24                                             
    kali-tools  recon-container  backend             
    

```

---

## Performance Architecture

### Caching Strategy

| Layer | Cache | TTL | What's Cached |
|-------|-------|-----|---------------|
| CDN | Nginx `proxy_cache` | 1 hour | Static assets |
| Application | In-memory dict | 5 min | CVE enrichment data |
| Database | PostgreSQL buffer | Runtime | Hot query results |
| Graph | Neo4j page cache | Runtime | Frequently traversed paths |

### Async Architecture

The backend uses **async Python** throughout:

```python
# FastAPI endpoints are all async
@router.get("/projects")
async def list_projects(db: AsyncPrismaClient):
    return await db.project.find_many()

# Background tasks use asyncio
async def run_recon_phase(project_id: str):
    results = await asyncio.gather(
        run_subfinder(target),
        run_amass(target),
        run_naabu(target),
    )
```

### Database Connection Pooling

- **PostgreSQL**: Connection pool managed by Prisma (default: 10 connections)
- **Neo4j**: Connection pool via official Python driver (default: 5 connections)

---

## Deployment Architecture

### Container Topology (Production)

```
Load Balancer (Nginx)
    
     backend (replica 1, 2 cpus, 2GB)
     backend (replica 2, 2 cpus, 2GB)
    
     frontend (replica 1, 1 cpu, 1GB)
     frontend (replica 2, 1 cpu, 1GB)
    
     postgres (single, 4 cpus, 4GB)
            backup service
    
     neo4j (single, 4 cpus, 6GB)
    
     tools (isolated)
             kali-tools (4 cpus, 4GB)
             recon-container (2 cpus, 2GB)
```

### Blue/Green Deployment

See `.github/workflows/blue-green.yml` and `docs/OPERATIONS_RUNBOOK.md`
for the complete blue/green deployment process.

---

## Technology Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Backend language | Python 3.11 | Security ecosystem, asyncio, team expertise |
| Web framework | FastAPI | Async support, OpenAPI auto-generation, Pydantic |
| Frontend | Next.js 14 | SSR, App Router, TypeScript |
| State management | Zustand + React Query | Lightweight, composable |
| Relational DB | PostgreSQL | JSON support, reliability, community |
| Graph DB | Neo4j | Native graph queries for attack surface |
| AI agent framework | LangChain | Tool calling, memory, streaming |
| MCP Protocol | JSON-RPC 2.0 | Standardized tool interface |
| Observability | Prometheus + Grafana | Industry standard, self-hosted |
| Tracing | OpenTelemetry | Vendor-neutral distributed tracing |

---


---

## v1.0.0 Architecture — Multi-Agent Orchestration


### Multi-Agent System Architecture

```

                    MULTI-AGENT ORCHESTRATION                    
                                                                         
   User Request → Orchestrator Agent                                     
                                                                        
                                    
                                                                      
                       
     Planner       Recon         Exploit                          
     Agent         Agent         Agent                            
    (CoT+DAG)     (passive)    (active testing)                   
                       
                                                                      
                      
     Validator     Reporting Agent                                 
     Agent         (PDF + compliance mapping)                      
                      

```

### Plugin System Architecture 

```

                   Plugin Registry                    
                                                      
        
     Plugin A       Plugin B       Plugin C    
    (custom-       (slack-        (user-       
     payloads)      notifier)      defined)    
        
                                                   
                   
                                                     
                                       
                     Sandbox                        
                     Executor                       
                    (Docker                         
                     container                      
                     isolation)                     
                                      

```

### Cloud Scanning Data Flow (Days 19–21)

```
UniVex Backend
    
     AWS Scanner  boto3 → AWS APIs (read-only)
                                        S3, IAM, EC2, RDS, Lambda
                                        CloudTrail, CloudWatch
    
     Azure Scanner  azure-sdk → Azure APIs (read-only)
                                        Storage, ARM, AD, Key Vault
                                        Security Center
    
     GCP Scanner  google-cloud → GCP APIs (read-only)
                                        Cloud Storage, IAM, Compute
                                        GKE, Cloud SQL
    
     Results → ComplianceMapper
                                         
                                   
                                     Neo4j    
                                     Cloud    
                                     Nodes    
                                   
```

### Report Generation Pipeline 

```
Findings DB (PostgreSQL)
    
    
ReportEngine.gather_data()
    
     ChartGenerator  Matplotlib/Plotly → SVG/PNG charts
    
     Jinja2 Templates → HTML
          executive_template.html
          technical_template.html
          compliance_template.html
    
     PDFGenerator  WeasyPrint → PDF/A
              
               POST /api/reports/{id}/pdf
```

### Campaign Engine Architecture 

```
Campaign (PostgreSQL)
    
     Targets: [url1, url2, ..., urlN]
    
     Executor 
                                            
       Worker-1    Worker-2    Worker-3    Worker-N  (asyncio)
                                            
       Target-1    Target-2    Target-3    Target-N
    
     Progress Tracker  Redis pub/sub → WebSocket → UI
    
     Result Aggregator  Deduplicate → Finding DB
```

---

## v1.0.0 Architecture Additions (Days 1–22)

### Full Service Map (v1.0.0 — 20+ Services)

```

                         UniVex v1.0.0                               

  Layer     Services                                                        

  UI        Next.js 14 (PWA, 3D Graph, Cyberpunk UI, Command Palette)       

  API       FastAPI REST + Strawberry GraphQL (/graphql)                    
            API versioning: /v1/ prefix + X-API-Version header              

  Agents    13 roles via LangGraph StateGraph                               
            planner · recon · exploit · webapp · report · refiner           
            generator · adviser · reflector · enricher · coder              
            installer · simple_json                                         

  Memory    EpisodicMemoryStore → ChromaDB / pgvector                      
            GraphitiClient → Neo4j (Graphiti :8010)                        
            FlowMemoryNamespace (per-campaign isolation)                    
            ContextSummarizer (75% threshold compression)                   

  LLM       ProviderRegistry: OpenAI · Anthropic · Groq · OpenRouter        
            Bedrock · DeepSeek · Qwen · GLM · Kimi · vLLM                   
            Per-agent model config: agents.yaml / env vars                  
            PROXY_URL: SOCKS5/HTTP proxy for all LLM calls                  

  Search    SploitusTool · DuckDuckGoTool · PerplexityTool · SearxngTool   
            TraversaalTool · GoogleCustomSearchTool                         

  Embed     EmbeddingRegistry: OpenAI · Ollama · Mistral · Jina             
            HuggingFace · Google · VoyageAI                                 
            Vector stores: ChromaDB | pgvector (VECTOR_STORE=pgvector)      

  Tools     MCP Servers: Naabu · Nuclei · FFuf · WPScan · SQLMap · Nikto   
            Browser (Playwright + MinIO) · OOBListener (HTTP/DNS/SMTP)     
            AWS/Azure/GCP/K8s · Container/K8s tools                        

  Data      PostgreSQL 16 + pgvector · Neo4j 5 · Redis 7 · ChromaDB        
            ClickHouse (analytics) · MinIO (artifact storage)               

  Observe   Prometheus + Grafana · Langfuse (LLM analytics)                 
            Loki + Promtail (logs) · Jaeger (traces) · VictoriaMetrics      

  Worker    WorkerServer (FastAPI :8001) — remote tool execution            
            WorkerClient (circuit breaker + retry) · JobDispatcher          
            mTLS with custom CA for node-to-node communication              

  Infra     Docker Compose · Podman (rootless) · Nginx (TLS termination)   
            Blue-green deployment · Searxng (self-hosted meta-search)       
            Graphiti (Neo4j knowledge graph service)                        

```

### Two-Node Worker Architecture (v1.0.0)

```
        mTLS        
     Orchestrator Node      ←→     Worker Node           
     (main backend)                              (isolated execution)  
                                                                       
           JobDispatcher       
     OrchestratorAgent→  →   WorkerServer        
           POST /execute     :8001               
                                                  
                               
     WorkerClient     ← ← result ←    Kali Linux Tools    
     (circuit breaker)                        (Nuclei, FFuf,      
                              SQLMap, etc.)      
                    
```

### AI Agent Data Flow (v1.0.0)

```
User Input
    
    
IntentClassifier (SVM + TF-IDF)
    
     web_app_attack  → WebAgent
     cloud_attack    → CloudAgent + AzureTools/GCPTools/K8sTools
     recon          → ReconAgent → EpisodicMemory.query()
                                   → GraphitiClient.search()
     exploit        → ExploitAgent + WorkerClient.dispatch()
     report         → ReportAgent + EnricherAgent
     simple_json    → SimpleJSONAgent
              
              
    ContextSummarizer (auto-compress if >75% context)
              
              
    LLMProvider (ProviderRegistry → per-agent model)
              
              
    AutoCaptureMiddleware → ChromaDB / pgvector
                         → GraphitiClient (Neo4j)
                         → EpisodicMemoryStore
```

---

## HTTP Proxy / Interceptor Architecture

The proxy engine provides a full Burp Suite Community Edition equivalent, built on `mitmproxy` and integrated with the LangGraph agent system.

```
Browser (Chrome/Firefox)
        │  (PAC / manual proxy: 127.0.0.1:8080)
        ▼
  ProxyServer (mitmproxy)
        │  ssl_context.py — dynamic CA + leaf cert per-host
        │  interceptor.py — ScopeFilter, InterceptRule
        ▼
  RequestStore (Redis + in-memory)
        │  HAR / JSON / CSV export
        ├── replay_request()     → RequestReplayTool
        ├── intruder_attack()    → RequestIntruderTool (Sniper/BatteringRam/Pitchfork/ClusterBomb)
        └── compare_requests()  → RequestComparerTool
        │
  WebSocketInterceptor
        │  frame capture, replay, mutation
        ▼
  ProxyMCPServer (:8008)   ←→   Agent (HttpInterceptTool, ScopeManagerTool, TrafficLoggerTool)
        │
  REST API /api/proxy/*    ←→   ProxyDashboard (React)
                                RequestTable / RequestDetail / ReplayPanel / IntruderPanel
```

**Key files:**
| File | Role |
|------|------|
| `backend/app/proxy/ssl_context.py` | Dynamic CA + leaf certificate generation |
| `backend/app/proxy/interceptor.py` | mitmproxy wrapper, scope + intercept rules |
| `backend/app/proxy/request_store.py` | In-memory + Redis storage with TTL and export |
| `backend/app/proxy/websocket_interceptor.py` | WebSocket session management |
| `backend/app/proxy/browser_bridge.py` | Browser PAC / proxy auto-config |
| `backend/app/mcp/servers/proxy_server.py` | MCP proxy server (:8008) |
| `backend/app/agent/tools/proxy_tools.py` | Agent tool wrappers (6 tools) |
| `backend/app/api/proxy.py` | 17 REST endpoints |
| `frontend/components/proxy/` | React dashboard components |

---

## Active Directory / BloodHound Architecture

The AD attack engine integrates SharpHound data with the existing Neo4j graph, adding BloodHound-compatible node types alongside UniVex's native attack surface nodes.

```
Target Domain
      │
      ├── SharpHoundCollect ──────────────────────────────┐
      │   (BloodHoundCollectTool → JSON/ZIP)              │
      │                                                    ▼
      │                                         BloodHoundIngestTool
      │                                                    │
      │                                         Neo4j Graph
      │                                          ├── BHUser nodes
      │                                          ├── BHComputer nodes
      │                                          ├── BHGroup / BHGPO / BHOP
      │                                          ├── BHDomain / BHTrust
      │                                          └── ADMIN_TO / HAS_SESSION / MEMBER_OF / ACL edges
      │                                                    │
      │                                         AttackPathQueryTool
      │                                          28 Cypher queries:
      │                                          ├── Shortest path → Domain Admin
      │                                          ├── DCSync rights holders
      │                                          ├── AdminTo chains
      │                                          └── Kerberoastable DA paths
      │
      ├── CredentialAttackChain
      │   Responder → NTLMRelay → SecretsDump → Mimikatz → DCSync → GoldenTicket
      │
      └── KerberosChain
          Enum → ASREPRoast/Kerberoast → HashCrack → PtH/PtT → DCSync
```

**Key files:**
| File | Role |
|------|------|
| `backend/app/graph/bloodhound_ingest.py` | BloodHound data ingestion into Neo4j |
| `backend/data/bloodhound_queries.json` | 28 curated Cypher attack path queries |
| `backend/app/agent/tools/bloodhound_tools.py` | 5 BloodHound agent tools |
| `backend/app/agent/tools/credential_tools.py` | 7 credential attack tools |
| `backend/app/agent/tools/active_directory_tools.py` | Extended AD tools + HashCrack |

---

## Tunneling & Pivoting Architecture

The pivoting engine enables multi-hop internal network access from the attacker's machine through compromised pivot hosts.

```
Attacker Machine
      │
      ├── SSH Dynamic (-D 1080) ─────────────────► SOCKSProxyTool
      │                                             Proxychains → any tool
      │
      ├── Chisel Server ◄─── Chisel Client ──────► Internal Pivot Host
      │   (HTTP tunnel)         (firewall bypass)   ├── Local subnet reachable
      │                                             └── Additional hops possible
      │
      ├── SSH LocalForward (-L 3389:internal:3389) → PortForwardTool
      │
      ├── SSH RemoteForward (-R 4444:attacker:4444) → callback from DMZ host
      │
      └── SSHTunnelManagerTool
          Multi-hop: attacker → hop1 → hop2 → target
          ProxychainsTool: routes naabu/nuclei/ffuf through pivot chain

NetworkPivotMapTool → Neo4j subgraph
  ├── Pivot nodes (reachable subnets)
  ├── SOCKS tunnels as graph edges
  └── Visualization overlay on Attack Surface Graph
```

**Key files:**
| File | Role |
|------|------|
| `backend/app/agent/tools/pivoting_tools.py` | 6 pivoting agent tools |
| `docs/PIVOTING_GUIDE.md` | Full operational pivoting guide |

---

*v1.0.0 architecture — UniVex | BitR1FT*
