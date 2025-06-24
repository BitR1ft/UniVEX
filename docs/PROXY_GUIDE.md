# UniVex — HTTP Proxy / Interceptor Guide

> **v3.0.0 NEW** — Complete HTTP/HTTPS intercepting proxy, equivalent to Burp Suite Community Edition.

---

## Overview

UniVex v3.0 ships with a full HTTP/HTTPS intercepting proxy built on [mitmproxy](https://mitmproxy.org/). The proxy engine allows you to:

- Capture and inspect all HTTP/HTTPS traffic between your browser and target applications
- Replay and modify captured requests
- Run automated attacks with the Intruder tool (4 attack modes)
- Intercept and replay WebSocket frames
- Export captured traffic as HAR, JSON, or CSV
- Configure scope rules to focus on relevant traffic
- Automatically configure Chrome, Firefox, or system proxy settings

The proxy integrates directly with the AI agent — you can ask the agent to "analyze the captured traffic" or "fuzz the login endpoint" and it will use the proxy tools automatically.

---

## Architecture

```
Browser (Chrome/Firefox)
        │ HTTP/HTTPS traffic
        ▼
┌──────────────────────────────┐
│  Proxy Engine (mitmproxy)    │  port 8080 (configurable)
│  ├── SSL Context             │  dynamic CA + leaf cert generation
│  ├── ScopeFilter             │  include/exclude patterns
│  ├── InterceptRules          │  match/modify/drop rules
│  └── WebSocket Interceptor   │  WS frame capture + replay
└──────────────────────────────┘
        │
        ▼
┌──────────────────────────────┐
│  Request Store               │  in-memory + Redis backing
│  ├── Full request/response   │
│  ├── TTL management          │
│  └── HAR/JSON/CSV export     │
└──────────────────────────────┘
        │
        ▼
┌──────────────────────────────┐
│  Proxy MCP Server (:8008)    │  JSON-RPC 2.0 API
│  13 tools                    │
└──────────────────────────────┘
        │
        ▼
┌──────────────────────────────┐
│  Agent Tools                 │
│  HttpInterceptTool           │
│  RequestReplayTool           │
│  RequestIntruderTool         │
│  RequestComparerTool         │
│  TrafficLoggerTool           │
│  ScopeManagerTool            │
└──────────────────────────────┘
        │
        ▼
┌──────────────────────────────┐
│  Frontend Proxy Dashboard    │
│  /proxy page                 │
│  RequestTable                │
│  RequestDetail               │
│  ReplayPanel                 │
│  IntruderPanel               │
└──────────────────────────────┘
```

---

## Setup

### 1. Configure Environment

```bash
# In your .env file:
PROXY_PORT=8080            # Port the proxy listens on
PROXY_SSL_VERIFY=false     # Set to false to intercept HTTPS
PROXY_UPSTREAM=            # Leave empty for direct connections
PROXY_MCP_PORT=8008        # Proxy MCP server port
PROXY_MCP_API_KEY=         # Optional API key for MCP server
```

### 2. Install the CA Certificate

The proxy uses a dynamically generated CA certificate to decrypt HTTPS traffic. You need to install this certificate in your browser or OS trust store **once**.

#### Via the Web UI

1. Go to **http://localhost:3000/proxy**
2. Click **"Download CA Certificate"**
3. Follow the browser-specific installation instructions shown

#### Via API

```bash
# Download the CA certificate
curl -o univex-ca.pem http://localhost:8000/api/proxy/ca-cert

# Install in system trust store (Ubuntu/Debian)
sudo cp univex-ca.pem /usr/local/share/ca-certificates/univex-ca.crt
sudo update-ca-certificates

# Install in system trust store (macOS)
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain univex-ca.pem
```

#### Chrome

```bash
# Open: chrome://settings/certificates → Authorities → Import
# Select the downloaded univex-ca.pem
# Check "Trust this certificate for identifying websites"
```

#### Firefox

```bash
# Open: about:preferences#privacy → View Certificates → Authorities → Import
# Select univex-ca.pem
# Check "Trust this CA to identify websites"
```

### 3. Configure Your Browser

#### Automatic Configuration (PAC File)

The easiest method — the PAC file auto-configures the proxy for all HTTP/HTTPS traffic:

```bash
# Set your browser to use this PAC file URL:
http://localhost:8000/api/proxy.pac
```

#### Manual Configuration

Set your browser's HTTP proxy to: `localhost:8080`

The proxy handles HTTPS via CONNECT tunneling — configure the same host/port for HTTPS proxy.

#### Auto-Configure Script

```bash
# Download browser configuration
curl -o browser-config.json http://localhost:8000/api/proxy/browser-config

# Apply to Chrome (macOS)
open -a "Google Chrome" --args --proxy-server="http://localhost:8080"

# Apply via system proxy (Linux)
export http_proxy=http://localhost:8080
export https_proxy=http://localhost:8080
```

---

## Starting and Stopping the Proxy

### Via Web UI

1. Navigate to **http://localhost:3000/proxy**
2. Click the **"Start Proxy"** button
3. Configure port and options in the dialog
4. The status indicator turns green when the proxy is running

### Via API

```bash
# Start the proxy
curl -X POST http://localhost:8000/api/proxy/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "port": 8080,
    "ssl_verify": false,
    "scope_include": [".*\\.example\\.com"],
    "scope_exclude": [".*\\.google\\.com"]
  }'

# Check status
curl http://localhost:8000/api/proxy/status \
  -H "Authorization: Bearer $TOKEN"

# Stop the proxy
curl -X POST http://localhost:8000/api/proxy/stop \
  -H "Authorization: Bearer $TOKEN"
```

### Via AI Agent

```
User: Start the proxy and intercept traffic to example.com

Agent: Starting proxy on port 8080 with scope set to example.com...
       [HttpInterceptTool]: Proxy started. Captured 0 requests.
       Your browser proxy is now configured. Browse to example.com to begin capturing.
```

---

## Capturing Requests

Once the proxy is running and your browser is configured, all HTTP/HTTPS traffic flowing through it is automatically captured.

### Viewing Captured Requests

**Web UI:**
- Go to `/proxy` — the **Request Table** shows all captured requests in real time
- Click any row to open the full **Request Detail** view
- Filter by method, URL, status code, or content type using the filter bar
- Search across all captured request/response content

**API:**
```bash
# List all requests (paginated)
curl "http://localhost:8000/api/proxy/requests?page=1&page_size=50" \
  -H "Authorization: Bearer $TOKEN"

# Filter by URL pattern
curl "http://localhost:8000/api/proxy/requests?url_filter=login" \
  -H "Authorization: Bearer $TOKEN"

# Get full detail for a specific request
curl "http://localhost:8000/api/proxy/requests/req_abc123" \
  -H "Authorization: Bearer $TOKEN"
```

### Scope Management

Configure which hosts are in scope to filter out noise:

```bash
# Set scope (in-scope patterns override out-of-scope)
curl -X POST http://localhost:8000/api/proxy/scope \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "include": [".*\\.example\\.com", "api\\.example\\.com"],
    "exclude": [".*\\.google\\.com", ".*\\.jquery\\.com"]
  }'
```

---

## Replaying Requests

The Replay Engine lets you modify and resend any captured request.

### Via Web UI

1. Click a request in the Request Table
2. Click **"Send to Repeater"** (or use the replay icon)
3. The **Replay Panel** opens with the full request — method, URL, headers, and body
4. Modify any part of the request
5. Click **"Send"** to resend
6. Compare the original and replayed responses side by side

### Via API

```bash
# Replay a captured request with modifications
curl -X POST "http://localhost:8000/api/proxy/replay/req_abc123" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "modifications": {
      "headers": {
        "Cookie": "session=MODIFIED_SESSION_ID"
      },
      "body": "{\"username\": \"admin\", \"password\": \"admin123\"}"
    }
  }'
```

### Via AI Agent

```
User: Replay the POST /api/login request but change the password to "admin123"

Agent: [RequestReplayTool]: Replaying req_abc123 with modified body...
       Response: 200 OK — {"token": "eyJ..."} 
       Authentication succeeded with password "admin123".
```

---

## Intruder — Automated Attack Modes

The Intruder tool automates repetitive testing against a target endpoint. Four attack modes are supported:

### Sniper
Tests one position at a time with one payload list. Each payload replaces a single marked position while the others remain static.

```
Position 1: §username§  → [admin, root, test, user]
Position 2: §password§  → (static: password123)

Requests:
  username=admin&password=password123
  username=root&password=password123
  ...
```

### Battering Ram
Uses the same payload in all positions simultaneously.

```
Positions: §username§ / §password§  → [admin, root]

Requests:
  username=admin&password=admin
  username=root&password=root
```

### Pitchfork
Iterates multiple payload lists in parallel (same index from each list).

```
List 1 (username): [admin, root]
List 2 (password): [admin123, toor]

Requests:
  username=admin&password=admin123
  username=root&password=toor
```

### Cluster Bomb
Tests every combination of all payload lists (Cartesian product).

```
List 1 (username): [admin, root]
List 2 (password): [admin123, toor]

Requests:
  username=admin&password=admin123
  username=admin&password=toor
  username=root&password=admin123
  username=root&password=toor
```

### Running the Intruder

**Via Web UI:**
1. Right-click a request → **"Send to Intruder"**
2. Mark payload positions with `§ §` brackets
3. Load payload lists (file, wordlist, or inline)
4. Select attack mode
5. Click **"Start Attack"**

**Via API:**
```bash
curl -X POST "http://localhost:8000/api/proxy/requests/req_abc123/intruder" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "sniper",
    "positions": [{"start": 45, "end": 55, "name": "username"}],
    "payloads": [["admin", "root", "administrator", "test"]]
  }'
```

**Via AI Agent:**
```
User: Run a credential stuffing attack against POST /api/auth/login using the rockyou wordlist

Agent: [RequestIntruderTool]: Configuring Cluster Bomb attack...
       Positions: username (§admin§), password (§password§)
       Payloads: username_list.txt (1,000 entries), password_list.txt (500 entries)
       Total requests: 500,000 — this will take ~8 minutes at 1,000 req/min.
       
       Proceed? [Y/n]
```

---

## WebSocket Interception

The proxy also captures WebSocket traffic.

### Viewing WebSocket Sessions

```bash
# List active WebSocket sessions
curl "http://localhost:8000/api/proxy/websocket-sessions" \
  -H "Authorization: Bearer $TOKEN"

# List captured frames
curl "http://localhost:8000/api/proxy/websocket-frames?session_id=ws_xyz" \
  -H "Authorization: Bearer $TOKEN"
```

### Replaying WebSocket Frames

```bash
# Replay a captured frame with modifications
curl -X POST "http://localhost:8000/api/proxy/websocket-frames/frame_001/replay" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": "{\"type\": \"message\", \"content\": \"INJECTED PAYLOAD\"}"
  }'
```

---

## Exporting Traffic

```bash
# Export as HAR (HTTP Archive)
curl "http://localhost:8000/api/proxy/requests/export?format=har" \
  -H "Authorization: Bearer $TOKEN" \
  -o captured-traffic.har

# Export as JSON
curl "http://localhost:8000/api/proxy/requests/export?format=json" \
  -H "Authorization: Bearer $TOKEN" \
  -o captured-traffic.json

# Export as CSV (summary)
curl "http://localhost:8000/api/proxy/requests/export?format=csv" \
  -H "Authorization: Bearer $TOKEN" \
  -o captured-traffic.csv
```

---

## Highlight Rules

Color-code requests matching specific patterns:

```bash
# Add a highlight rule
curl -X POST http://localhost:8000/api/proxy/highlight-rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "pattern": "password|passwd|pwd|secret",
    "colour": "red",
    "label": "Credential Parameters"
  }'
```

---

## Integration with AI Agent

All proxy capabilities are available via the AI chat interface:

```
# Common agent prompts:
"Start intercepting traffic to app.example.com"
"Show me all POST requests captured in the last 10 minutes"
"Replay the /api/login request with admin credentials"
"Fuzz the 'id' parameter in the last captured GET request"
"Export all captured traffic as HAR"
"Set proxy scope to include only *.example.com"
"Analyze the captured WebSocket messages for authentication tokens"
```

---

## Troubleshooting

### Browser shows SSL error after enabling proxy

The CA certificate is not installed. Download and install it:
```bash
curl -o univex-ca.pem http://localhost:8000/api/proxy/ca-cert
# Then install per-browser instructions above
```

### Proxy captures HTTP but not HTTPS

Ensure `PROXY_SSL_VERIFY=false` is set in your `.env` and the CA certificate is trusted in your browser.

### Requests not appearing in the table

Check the scope configuration — requests outside the scope patterns are silently dropped. Try setting a permissive scope:
```bash
curl -X POST http://localhost:8000/api/proxy/scope \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"include": [".*"], "exclude": []}'
```

### High memory usage from large traffic captures

Clear the capture history and reduce `PROXY_REQUEST_TTL`:
```bash
curl -X DELETE http://localhost:8000/api/proxy/requests \
  -H "Authorization: Bearer $TOKEN"
```

---

## See Also

- [API Reference](API_REFERENCE.md) — Full proxy endpoint documentation
- [Architecture](ARCHITECTURE.md) — Proxy engine design
- [AD Attack Guide](AD_ATTACK_GUIDE.md) — Using the proxy for AD web attacks
