# UniVex — User Manual

> **Version 1.0.0** | Last Updated: March 2026

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Requirements](#2-system-requirements)
3. [Installation](#3-installation)
4. [Configuration](#4-configuration)
5. [Getting Started](#5-getting-started)
6. [Dashboard Overview](#6-dashboard-overview)
7. [Creating a Project](#7-creating-a-project)
8. [Running the AI Agent](#8-running-the-ai-agent)
9. [Reconnaissance Pipeline](#9-reconnaissance-pipeline)
10. [Exploitation Phase](#10-exploitation-phase)
11. [Post-Exploitation](#11-post-exploitation)
12. [Attack Graph Visualization](#12-attack-graph-visualization)
13. [Approval Workflow](#13-approval-workflow)
14. [Agent Controls](#14-agent-controls)
15. [API Reference](#15-api-reference)
16. [Troubleshooting](#16-troubleshooting)
17. [Security & Ethics](#17-security--ethics)
18. [FAQ](#18-faq)
19. [AutoChain — Automated Pentest Pipeline](#19-autochain--automated-pentest-pipeline)
20. [Feature Highlights](#20-feature-highlights)

---

## 1. Introduction

UniVex is an AI-powered penetration testing framework that automates the complete penetration testing lifecycle. The AI agent uses the ReAct (Reasoning + Acting) pattern to autonomously:

- Discover and enumerate targets
- Identify vulnerabilities
- Exploit weaknesses with human approval
- Perform post-exploitation enumeration
- Generate engagement summaries

The tool is designed for **authorized security testing only** and includes safety controls such as approval gates for dangerous operations and scope enforcement.

### Key Concepts

| Term | Description |
|------|-------------|
| **Project** | A penetration testing engagement targeting a specific host or network |
| **Phase** | The current stage of the engagement (Informational → Exploitation → Post-Exploitation → Complete) |
| **Agent** | The AI-powered assistant that executes the testing workflow |
| **Tool** | A security tool (Nmap, Nuclei, Metasploit, etc.) wrapped for agent use |
| **Attack Graph** | A Neo4j graph database that maps the entire attack surface |
| **MCP Server** | Model Context Protocol server that bridges the AI agent and security tools |

---

## 2. System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Linux (Ubuntu 22.04+), macOS 13+, or Windows 11 with WSL2 |
| **CPU** | 4 cores |
| **RAM** | 8 GB |
| **Disk** | 20 GB free space |
| **Docker** | Docker Desktop 4.0+ or Docker Engine 24+ with Docker Compose v2 |
| **Node.js** | 22.0+ (for frontend development) |
| **Python** | 3.11+ (for backend development) |

### Required API Keys

| Service | Purpose | Required? |
|---------|---------|-----------|
| **OpenAI** | GPT-4 for AI agent reasoning | Yes (or Anthropic) |
| **Anthropic** | Claude for AI agent reasoning | Yes (or OpenAI) |
| **Tavily** | Web search for OSINT gathering | Optional |
| **NVD** | National Vulnerability Database enrichment | Optional |

---

## 3. Installation

### Option A: Docker Compose (Recommended)

This is the quickest way to get all services running.

```bash
# 1. Clone the repository
git clone https://github.com/BitR1ft/UniVex.git
cd UniVex

# 2. Copy and configure environment variables
cp .env.example .env
# Edit .env with your API keys and passwords (see Section 4)

# 3. Start all services
docker-compose up -d

# 4. Verify services are running
docker-compose ps
```

After startup, access:
- **Frontend Dashboard**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Neo4j Browser**: http://localhost:7474

### Option B: Development Setup

For active development, run services individually.

#### Backend

```bash
cd backend

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up Prisma ORM
prisma generate

# Start the backend server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

#### Databases

```bash
# Start PostgreSQL and Neo4j via Docker
docker-compose up -d postgres neo4j
```

---

## 4. Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure the following:

#### Essential Settings

```bash
# AI Provider (at least one required)
OPENAI_API_KEY=sk-your-openai-key-here
OPENAI_MODEL=gpt-4-turbo-preview

# Or use Anthropic
ANTHROPIC_API_KEY=sk-ant-your-key-here
ANTHROPIC_MODEL=claude-3-opus-20240229

# Database passwords (change these!)
POSTGRES_PASSWORD=your_secure_password_here
NEO4J_PASSWORD=your_secure_password_here

# JWT Secret (change this!)
SECRET_KEY=your_random_32_char_secret_here
```

#### Optional Settings

```bash
# Web search for OSINT
TAVILY_API_KEY=your_tavily_key_here

# Vulnerability enrichment
NVD_API_KEY=your_nvd_key_here

# LangSmith tracing (for debugging)
LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=your_langsmith_key_here

# Feature flags
FEATURE_AI_AGENT=true
FEATURE_AUTO_EXPLOITATION=false  # Requires explicit enable
```

---

## 5. Getting Started

### Step 1: Register an Account

1. Open http://localhost:3000 in your browser
2. Click **Register** on the login page
3. Enter your username, email, and password
4. Click **Create Account**

### Step 2: Log In

1. Enter your credentials on the login page
2. Click **Sign In**
3. You'll be redirected to the dashboard

### Step 3: Create Your First Project

1. Click **New Project** on the dashboard
2. Fill in the project details:
   - **Name**: A descriptive name (e.g., "HTB Lame Assessment")
   - **Target**: The target IP or hostname (e.g., "10.10.10.3")
   - **Description**: Brief description of the engagement scope
3. Click **Create Project**

### Step 4: Start the AI Agent

1. Open your project from the dashboard
2. Navigate to the **Chat** tab
3. Type your initial instruction, for example:
   ```
   Scan the target 10.10.10.3 and identify all open ports and services
   ```
4. Press Enter and watch the agent work

---

## 6. Dashboard Overview

The dashboard provides a centralized view of all your penetration testing projects.

### Main Sections

| Section | Description |
|---------|-------------|
| **Sidebar** | Navigation between Dashboard, Projects, Chat, and Graph views |
| **Project List** | All active and completed projects with status indicators |
| **Quick Stats** | Summary of findings across all projects |

### Navigation

- **Dashboard** (`/dashboard`): Overview of all projects and recent activity
- **Projects** (`/projects`): Create, view, and manage pentesting engagements
- **Chat** (`/chat`): Interactive AI agent interface
- **Graph** (`/graph`): Attack surface visualization

---

## 7. Creating a Project

### Project Configuration

When creating a project, you can configure:

| Field | Description | Example |
|-------|-------------|---------|
| **Name** | Project identifier | "Corporate Network Pentest" |
| **Target** | IP address, hostname, or CIDR range | "192.168.1.0/24" |
| **Description** | Scope and objectives | "External assessment of web servers" |

### Best Practices

- Use descriptive names that identify the engagement
- Specify the exact target scope to prevent out-of-scope testing
- Document the authorization details in the description

---

## 8. Running the AI Agent

### Chat Interface

The chat interface is your primary way to interact with the AI agent.

#### Giving Instructions

You can give the agent natural language instructions:

```
# Reconnaissance
"Enumerate all subdomains for example.com"
"Scan ports 1-1000 on 10.10.10.3"
"Probe HTTP services and detect technologies"

# Exploitation
"Search for CVEs affecting Apache 2.4.49"
"Try to exploit CVE-2021-41773 on the target"
"Brute force SSH login with common credentials"

# Post-Exploitation
"Enumerate the system and find privilege escalation vectors"
"Look for the user flag"
"Try to escalate to root"
```

#### Understanding Agent Responses

The agent communicates its reasoning process:

- **THOUGHT**: The agent's analysis and decision-making
- **ACTION**: The tool being executed and why
- **OBSERVATION**: Results from tool execution
- **SUMMARY**: Final findings and recommendations

### Agent Phases

The agent operates in four phases:

| Phase | Purpose | Available Tools |
|-------|---------|-----------------|
| **INFORMATIONAL** | Reconnaissance and discovery | Naabu, Curl, Nuclei, Query Graph, Web Search |
| **EXPLOITATION** | Gaining access | Metasploit, Exploit Execute, Brute Force, Session Manager |
| **POST_EXPLOITATION** | Maximizing access | File Operations, System Enumeration, Privilege Escalation |
| **COMPLETE** | Reporting findings | Summary generation |

The agent transitions between phases based on progress. You can also guide phase transitions manually.

---

## 9. Reconnaissance Pipeline

UniVex includes a 5-phase reconnaissance pipeline:

### Phase 1: Domain Discovery
- Subdomain enumeration
- DNS resolution
- Domain relationship mapping

### Phase 2: Port Scanning
- **Naabu**: Fast port scanning
- Service detection and version identification
- CDN detection
- Results stored in Neo4j graph

### Phase 3: HTTP Probing
- HTTP/HTTPS service probing
- Technology detection (Wappalyzer-style fingerprinting)
- TLS certificate inspection
- Security headers analysis

### Phase 4: Resource Enumeration
- **Katana**: Web crawler for endpoint discovery
- **GAU**: Historical URLs from web archives
- **Kiterunner**: API route brute-forcing

### Phase 5: Vulnerability Scanning
- **Nuclei**: Template-based vulnerability scanning
- CVE enrichment with CVSS scores
- MITRE ATT&CK technique mapping
- Findings stored as graph nodes

---

## 10. Exploitation Phase

### Attack Path Router

The agent uses an intelligent attack path router that:
1. **Classifies** your intent into one of 10 attack categories
2. **Scores confidence** and suggests alternatives if classification is uncertain
3. **Generates** a step-by-step attack plan
4. **Requests approval** for dangerous operations

### Attack Categories

| Category | Risk Level | Requires Approval |
|----------|-----------|-------------------|
| CVE Exploitation | Critical |  Yes |
| Brute Force | High |  Yes |
| Web App Attack | High | No |
| Privilege Escalation | Critical |  Yes |
| Lateral Movement | Critical |  Yes |
| Password Spray | Medium | No |
| Social Engineering | Medium | No |
| Network Pivot | High | No |
| File Exfiltration | High | No |
| Persistence | Critical | No |

### Available Exploitation Tools

| Tool | Description |
|------|-------------|
| **ExploitExecuteTool** | Execute CVE exploits via Metasploit |
| **BruteForceTool** | Multi-service brute force (SSH, FTP, SMB, HTTP, etc.) |
| **MetasploitTool** | Search and configure Metasploit modules |
| **SessionManagerTool** | Manage Meterpreter and shell sessions |

---

## 11. Post-Exploitation

Once initial access is gained, the agent can:

### System Enumeration
- Operating system and kernel version
- User accounts and groups
- Network configuration and connections
- Running processes and services
- Installed software

### File Operations
- Download files from the target
- Upload tools to the target
- List directory contents
- Search for flags and sensitive files

### Privilege Escalation
- Automated `getsystem` attempts
- Suggest escalation exploits based on system enumeration
- Execute escalation modules
- Verify elevated privileges

### Credential Harvesting
- Extract discovered credentials
- Store credentials in the Neo4j graph
- Use credentials for lateral movement

---

## 12. Attack Graph Visualization

The attack graph provides a visual representation of the entire attack surface.

### Graph Node Types

The graph includes 17+ node types:
- **Domain**, **Subdomain**: DNS structure
- **IP**, **Port**, **Service**: Network topology
- **Technology**: Detected software and versions
- **Endpoint**, **Parameter**: Web application structure
- **Vulnerability**, **CVE**: Security findings
- **Session**, **Credential**: Access gained
- **MITRE Technique**: ATT&CK mapping

### Using the Graph Viewer

1. Navigate to the **Graph** tab in your project
2. The graph loads automatically with all discovered data
3. Use the controls to:
   - **Zoom**: Scroll wheel or pinch
   - **Pan**: Click and drag on empty space
   - **Inspect Node**: Click a node to see details in the Node Inspector panel
   - **Filter**: Use the Filter Panel to show/hide node types
   - **Export**: Export graph data for reporting

### Graph Filters

Filter the graph by:
- Node type (Domain, IP, Port, Vulnerability, etc.)
- Severity level (Critical, High, Medium, Low)
- Phase (Reconnaissance, Exploitation, Post-Exploitation)

---

## 13. Approval Workflow

For dangerous operations, the agent requests human approval before proceeding.

### How It Works

1. The agent identifies an action that requires approval (e.g., CVE exploitation)
2. An **Approval Modal** appears in the chat interface
3. The modal shows:
   - **Action**: What the agent wants to do
   - **Risk Level**: Critical, High, Medium, or Low
   - **Target**: The system being affected
   - **Justification**: Why the agent recommends this action
4. You can **Approve** or **Reject** the action
5. If approved, the agent proceeds; if rejected, it stops or finds alternatives

### Approval Categories

| Category | Examples |
|----------|---------|
| **Exploitation** | Running CVE exploits, deploying payloads |
| **Credential Attacks** | Brute force, password spraying |
| **Privilege Escalation** | Kernel exploits, SUID abuse |
| **Lateral Movement** | Moving to other hosts via compromised credentials |

---

## 14. Agent Controls

### Real-Time Controls

| Control | Endpoint | Description |
|---------|----------|-------------|
| **Stop** | `POST /agent/stop` | Halt agent execution immediately |
| **Resume** | `POST /agent/resume` | Resume a stopped agent |
| **Guide** | `POST /agent/guide` | Send real-time guidance to redirect the agent |
| **Approve** | `POST /agent/approve` | Approve or reject a pending action |

### Sending Guidance

You can redirect the agent mid-execution:

```
"Focus on the web application on port 8080 instead"
"Skip brute force and try the CVE-2021-41773 exploit"
"Enumerate SUID binaries for privilege escalation"
```

The agent incorporates your guidance into its next reasoning step.

---

## 15. API Reference

### Authentication

```bash
# Register
POST /auth/register
{
  "username": "analyst",
  "email": "analyst@example.com",
  "password": "secure_password"
}

# Login
POST /auth/login
{
  "username": "analyst",
  "password": "secure_password"
}
# Returns: { "access_token": "jwt_token", "token_type": "bearer" }
```

### Projects

```bash
# Create project
POST /api/projects
{
  "name": "Target Assessment",
  "target": "10.10.10.3",
  "description": "Authorized pentest"
}

# List projects
GET /api/projects

# Get project details
GET /api/projects/{id}
```

### Agent

```bash
# Chat with agent
POST /api/agent/chat
{
  "message": "Scan the target for open ports",
  "project_id": "project_uuid",
  "thread_id": "thread_uuid"
}

# Stop agent
POST /api/agent/stop

# Resume agent
POST /api/agent/resume

# Send guidance
POST /api/agent/guide
{
  "message": "Focus on web vulnerabilities"
}

# Approve/reject action
POST /api/agent/approve
{
  "approved": true
}
```

### Reconnaissance

```bash
# Trigger port scan
POST /api/recon/port-scan
{
  "target": "10.10.10.3",
  "ports": "1-1000"
}

# Trigger HTTP probe
POST /api/recon/http-probe
{
  "targets": ["http://10.10.10.3"]
}
```

### Graph

```bash
# Query attack graph
GET /api/graph/nodes?type=Vulnerability&project_id=xxx

# Get graph statistics
GET /api/graph/stats?project_id=xxx
```

For the full interactive API documentation, visit http://localhost:8000/docs when the backend is running.

---

## 16. Troubleshooting

### Common Issues

#### Docker Services Won't Start

```bash
# Check Docker is running
docker info

# View container logs
docker-compose logs backend
docker-compose logs frontend

# Restart services
docker-compose down && docker-compose up -d
```

#### Database Connection Errors

```bash
# Verify PostgreSQL is running
docker-compose ps postgres

# Check Neo4j
docker-compose ps neo4j

# Test database connectivity
docker-compose exec postgres pg_isready
```

#### AI Agent Not Responding

1. Verify your API key is set in `.env`:
   ```bash
   grep OPENAI_API_KEY .env
   ```
2. Check backend logs for errors:
   ```bash
   docker-compose logs backend | tail -50
   ```
3. Ensure the agent feature flag is enabled:
   ```bash
   grep FEATURE_AI_AGENT .env  # Should be true
   ```

#### Frontend Build Errors

```bash
cd frontend
npm install  # Reinstall dependencies
npm run build  # Check for build errors
npm run type-check  # Check TypeScript errors
```

#### Port Conflicts

If ports 3000, 8000, 7474, or 7687 are already in use:

```bash
# Find what's using a port
lsof -i :3000

# Change ports in docker-compose.yml or .env
```

### Getting Help

- Check the [API Documentation](http://localhost:8000/docs) for endpoint details
- Review the [Architecture Guide](ARCHITECTURE.md) for system design
- Open an issue on [GitHub](https://github.com/BitR1ft/UniVex/issues)

---

## 17. Security & Ethics

### Authorized Use Only

> **⚠️ WARNING**: This framework is designed exclusively for **authorized penetration testing**. Unauthorized use against systems you do not own or have explicit written permission to test is **illegal and unethical**.

### Safety Controls

UniVex includes multiple safety mechanisms:

| Control | Description |
|---------|-------------|
| **Approval Gates** | Dangerous operations require explicit human approval |
| **Phase Gating** | Exploitation tools are only available after reconnaissance |
| **Scope Enforcement** | Agent is restricted to configured target scope |
| **Audit Logging** | All actions are logged for review and compliance |
| **Stop Controls** | Agent can be halted immediately at any time |
| **Live Guidance** | Redirect agent behavior in real-time |

### Best Practices

1. **Always** obtain written authorization before testing
2. **Define scope** clearly in the project configuration
3. **Review** approval requests carefully before approving
4. **Monitor** agent activity via the chat interface
5. **Document** findings and remediation for the target organization
6. **Clean up** any artifacts left on target systems after testing

### Responsible Disclosure

If you discover vulnerabilities during authorized testing:
1. Document findings with evidence
2. Report to the system owner through agreed-upon channels
3. Provide remediation guidance
4. Allow reasonable time for fixes before any public disclosure
5. Follow your organization's disclosure policy

---

## 18. FAQ

**Q: Which LLM provider should I use?**
A: Both OpenAI (GPT-4) and Anthropic (Claude) are supported. GPT-4 Turbo is recommended for the best balance of capability and speed.

**Q: Can I test multiple targets simultaneously?**
A: v1.0 supports one target per project. Multi-target campaigns are planned for Year 2.

**Q: Does the agent need internet access?**
A: The AI agent needs internet access for LLM API calls and optional web search (Tavily). Security tools can run in isolated networks.

**Q: How do I add custom tools?**
A: Create a new tool class extending `BaseTool` in `backend/app/agent/tools/`, implement the `execute()` method, and register it in the `ToolRegistry`. See existing tools for examples.

**Q: What happens if the agent gets stuck?**
A: Use the **Stop** control to halt the agent, then use **Guide** to redirect it, or **Resume** with new instructions.

**Q: Is my data stored securely?**
A: Project data is stored in PostgreSQL (encrypted at rest with database-level encryption) and Neo4j. API keys are stored in environment variables, never in code. All API endpoints use JWT authentication.

**Q: Can I export the attack graph?**
A: Yes, use the **Graph Export** feature in the dashboard to export graph data in JSON format for reporting.

**Q: How accurate is the intent classification?**
A: v1.0 uses keyword-based classification with confidence scoring. The system reports its confidence level and suggests alternatives when uncertain. ML-based classification is planned for Year 2.

---

---

## 19. AutoChain — Automated Pentest Pipeline

**AutoChain** is a deterministic, non-LLM automated pipeline that runs the full
pentest kill chain using direct MCP tool calls. Unlike the free-form AI agent, it
follows a fixed phase sequence defined by a JSON template, making it faster and
more predictable.

### Starting a Chain via the API

```bash
# Start a custom chain
curl -s -X POST http://localhost:8000/api/autochain/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "10.10.10.3",
    "auto_approve_risk_level": "high",
    "project_id": "optional-uuid"
  }' | python3 -m json.tool

# Start from an HTB template
curl -s -X POST http://localhost:8000/api/autochain/start/template \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"template_id": "htb_easy", "target": "10.10.10.3"}' \
  | python3 -m json.tool

# Stream real-time progress
curl -N http://localhost:8000/api/autochain/$CHAIN_ID/stream

# Check status
curl -s http://localhost:8000/api/autochain/$CHAIN_ID | python3 -m json.tool

# Retrieve captured flags (MD5-verified)
curl -s http://localhost:8000/api/autochain/$CHAIN_ID/flags | python3 -m json.tool
```

### HTB Templates

Two templates are shipped:

**`htb_easy`** — For HackTheBox Easy machines:
1. Naabu port scan (top 1000)
2. ffuf directory/file brute-force
3. Nuclei CVE/web vulnerability scan
4. Metasploit auto-exploitation (retry × 3)
5. Session upgrade → Meterpreter / TTY stabilise
6. System enumeration (sysinfo, whoami, ifconfig)
7. Flag capture (`/root/root.txt`, `~/user.txt`) + MD5 verification

**`htb_medium`** — Adds: LDAP enumeration, SQLMap injection testing, CMS
detection, lateral movement scanning, vhost fuzzing, and extended priv-esc.

### Auto-Approval Levels

| Level | Behaviour |
|-------|-----------|
| `none` | All high/critical operations require manual approval (safest) |
| `low` | Auto-approve only low-risk operations |
| `medium` | Auto-approve low + medium risk |
| `high` | Auto-approve low/medium/high — critical still needs approval |
| `critical` | Fully autonomous — only use in isolated lab environments |

Set `AUTO_APPROVE_RISK_LEVEL` in `.env` or pass `auto_approve_risk_level` in the
API request body to override per-run.

---

## 20. Feature Highlights

### Real-Time Scan Progress

The project detail page now shows a live **Scan Progress Panel** when a scan is
running or queued:

- Phase indicator (Recon → Exploitation → Post-Exploitation)
- Current tool name and progress bar
- Live log lines streamed via SSE
- Status dot (green = running, amber = queued, red = error)

### 3D Attack Graph

The **Graph Explorer** page offers a 2D/3D toggle:

- **2D mode**: Force-directed graph with node click/hover interactions
- **3D mode**: Perspective canvas graph using a Fibonacci sphere layout; drag to
  rotate, click to inspect

Switch between modes using the toggle in the top-right of the Graph Explorer page.

### Graph Export

Export the attack graph in two formats:

| Format | Button | Use Case |
|--------|--------|---------|
| **JSON** | `Export JSON` | Machine-readable, API integrations |
| **GEXF 1.2** | `Export GEXF` | Gephi / network analysis tools |

A "Copy Link" button copies a direct share URL to clipboard with toast feedback.

### Toast Notifications

The UI now shows non-blocking toast notifications for:

- Scan start / complete / error events
- Export success / failure
- Session expiry warnings

Toasts auto-dismiss after 4 seconds and are screen-reader accessible.

### Responsive Filter Bar

On mobile devices, the project filter bar collapses into a toggleable panel to
reduce visual clutter. Tap the **Filters** button to expand.

### Performance & Observability

- Prometheus metrics endpoint (`/metrics`) for Grafana dashboards
- Grafana pre-provisioned at **http://localhost:3001** (admin / your GRAFANA_PASSWORD)
- Structured JSON audit log for compliance reporting

---

## 20. Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `N` | New project (from projects list) |
| `Ctrl+K` / `⌘K` | Quick search |
| `/` | Focus filter input |
| `Esc` | Close modal / panel |
| `G` then `P` | Go to Projects |
| `G` then `G` | Go to Graph Explorer |
| `G` then `C` | Go to Agent Chat |

---

*UniVex v1.0.0 — User Manual*
*Last updated: March 2026*
*© 2026 BitR1FT. All rights reserved.*

---

## 21. v1.0.0 New Features Guide


### Two-Factor Authentication (2FA)

1. Navigate to **Settings → Security → Two-Factor Authentication**
2. Click **Enable 2FA**
3. Scan the QR code with Google Authenticator, Authy, or 1Password
4. Enter the 6-digit code to confirm enrollment
5. **Save your backup codes** — you'll need these if you lose your device

On login, you'll be prompted for your TOTP code after entering your password.

### Compliance Scanning

1. Open a project and click **Compliance** in the sidebar
2. Select frameworks to assess: OWASP Top 10, PCI-DSS, NIST 800-53, CIS Controls
3. Click **Run Assessment** — UniVex maps existing findings to each framework
4. View the **Compliance Scorecard** with pass/fail per control
5. Download a **Compliance PDF Report** from the Reports page

### Campaign Management

1. Navigate to **Campaigns → New Campaign**
2. Step 1: Add targets (URLs, domains, IPs)
3. Step 2: Select tools (web scan, API scan, cloud scan)
4. Step 3: Set schedule (one-time or recurring)
5. Click **Launch** — campaign runs in parallel across all targets
6. Monitor progress in real-time on the campaign dashboard

### Findings Triage

1. Navigate to **Findings** to see all findings across projects
2. Filter by severity (Critical/High/Medium/Low/Info), status, project
3. Click a finding to open the detail view:
   - Set **Status**: Open → In Review → Resolved / Won't Fix
   - Assign to a team member
   - Mark as **False Positive**
   - Attach evidence or notes
4. Click **Create Ticket** to create a Jira/ServiceNow ticket automatically

### Cloud Security Scans

1. Navigate to **Settings → Integrations → Cloud Providers**
2. Configure AWS (IAM user keys), Azure (service principal), or GCP (service account JSON)
3. In the agent chat, type: `Scan my AWS environment for security issues`
4. Review cloud findings in the **Findings** page with provider/region filters
5. Generate a **Cloud Security Report** from the Reports page

### Plugin Marketplace

1. Navigate to **Settings → Plugins**
2. Browse available plugins
3. Click **Install** on any plugin
4. Configure plugin settings in the plugin detail view
5. Enable/disable plugins without uninstalling

### Command Palette (Ctrl+K)

Press `Ctrl+K` (or `⌘K` on Mac) to open the command palette:
- Navigate to any page instantly
- Start a new scan by typing the target
- Search findings by title or CVE
- Run compliance assessment

---

*UniVex v1.0.0 — User Manual*  
*Last updated: March 2026*  
*© 2026 BitR1FT. All rights reserved.*
