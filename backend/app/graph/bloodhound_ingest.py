"""
BloodHound AD Graph Ingestion Engine

Parses SharpHound JSON collection output and ingests it into UniVex's Neo4j
instance as AD-specific node types.  Supports:

  • Users, Groups, Computers, OUs, GPOs, Domains, Trusts
  • 15+ relationship types (MemberOf, HasSession, AdminTo, CanRDP,
    CanPSRemote, GenericAll, WriteDACL, DCSync, ForceChangePassword,
    GenericWrite, WriteOwner, AllExtendedRights, Owns, AddKeyCredentialLink,
    AllowedToAct, TrustedBy, GpLink)

Usage:
    ingest = BloodHoundIngest(neo4j_client)
    stats = await ingest.ingest_zip("/tmp/sharphound_2024.zip")
    stats = await ingest.ingest_directory("/tmp/sharphound_json/")
    stats = await ingest.ingest_file("/tmp/users.json")
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SharpHound JSON file type → handler mapping
# ---------------------------------------------------------------------------

_FILE_TYPE_MAP: Dict[str, str] = {
    "users": "users",
    "groups": "groups",
    "computers": "computers",
    "ous": "ous",
    "gpos": "gpos",
    "domains": "domains",
    "containers": "containers",
}


# ---------------------------------------------------------------------------
# Ingestion Statistics
# ---------------------------------------------------------------------------


@dataclass
class IngestStats:
    """Running counters for a BloodHound ingestion run."""

    nodes_created: int = 0
    nodes_merged: int = 0
    relationships_created: int = 0
    errors: List[str] = field(default_factory=list)
    files_processed: List[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"Ingestion complete: {self.nodes_created} nodes created, "
            f"{self.nodes_merged} merged, "
            f"{self.relationships_created} relationships, "
            f"{len(self.errors)} errors, "
            f"{len(self.files_processed)} files processed."
        )


# ---------------------------------------------------------------------------
# Main ingest class
# ---------------------------------------------------------------------------


class BloodHoundIngest:
    """
    Parse SharpHound JSON output and write AD objects into Neo4j as typed
    nodes and relationships.  All write operations are wrapped in try/except
    so a single bad record never aborts the whole ingestion.
    """

    # AD node label constants
    LABEL_USER = "ADUser"
    LABEL_GROUP = "ADGroup"
    LABEL_COMPUTER = "ADComputer"
    LABEL_OU = "ADOU"
    LABEL_GPO = "ADGPO"
    LABEL_DOMAIN = "ADDomain"
    LABEL_TRUST = "ADTrust"

    def __init__(self, neo4j_client: Any) -> None:
        """
        Args:
            neo4j_client: UniVex Neo4jClient instance (or any object exposing
                          run_query(cypher, params) → list[dict]).
        """
        self.client = neo4j_client

    # ------------------------------------------------------------------
    # Public entry-points
    # ------------------------------------------------------------------

    async def ingest_zip(self, zip_path: str) -> IngestStats:
        """Extract a SharpHound ZIP and ingest every JSON file inside it."""
        stats = IngestStats()
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(tmpdir)
            stats = await self.ingest_directory(tmpdir)
        return stats

    async def ingest_directory(self, directory: str) -> IngestStats:
        """Ingest all SharpHound JSON files found in *directory*."""
        stats = IngestStats()
        for fname in sorted(os.listdir(directory)):
            if not fname.lower().endswith(".json"):
                continue
            path = os.path.join(directory, fname)
            file_stats = await self.ingest_file(path)
            stats.nodes_created += file_stats.nodes_created
            stats.nodes_merged += file_stats.nodes_merged
            stats.relationships_created += file_stats.relationships_created
            stats.errors.extend(file_stats.errors)
            stats.files_processed.extend(file_stats.files_processed)
        return stats

    async def ingest_file(self, json_path: str) -> IngestStats:
        """Ingest a single SharpHound JSON file."""
        stats = IngestStats(files_processed=[os.path.basename(json_path)])
        try:
            with open(json_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            stats.errors.append(f"Cannot read {json_path}: {exc}")
            return stats

        meta = data.get("meta", {})
        file_type = meta.get("type", "").lower()

        # Detect type from filename if not in meta
        if not file_type:
            basename = os.path.basename(json_path).lower()
            for key in _FILE_TYPE_MAP:
                if key in basename:
                    file_type = key
                    break

        handler_map = {
            "users": self._ingest_users,
            "groups": self._ingest_groups,
            "computers": self._ingest_computers,
            "ous": self._ingest_ous,
            "gpos": self._ingest_gpos,
            "domains": self._ingest_domains,
            "containers": self._ingest_containers,
        }

        handler = handler_map.get(file_type)
        if handler is None:
            stats.errors.append(
                f"Unknown file type '{file_type}' in {json_path} — skipped."
            )
            return stats

        data_list = data.get("data", [])
        logger.info(
            "Ingesting %d %s records from %s", len(data_list), file_type, json_path
        )
        await handler(data_list, stats)
        return stats

    # ------------------------------------------------------------------
    # Per-type handlers
    # ------------------------------------------------------------------

    async def _ingest_users(self, records: List[Dict], stats: IngestStats) -> None:
        for rec in records:
            try:
                props = self._extract_user_props(rec)
                await self._merge_node(self.LABEL_USER, "objectid", props, stats)
                await self._create_member_of(rec, stats)
                await self._create_acls(rec, self.LABEL_USER, stats)
                await self._create_sessions(rec, stats)
            except Exception as exc:
                stats.errors.append(f"User ingest error: {exc}")

    async def _ingest_groups(self, records: List[Dict], stats: IngestStats) -> None:
        for rec in records:
            try:
                props = self._extract_group_props(rec)
                await self._merge_node(self.LABEL_GROUP, "objectid", props, stats)
                await self._create_member_of(rec, stats)
                await self._create_acls(rec, self.LABEL_GROUP, stats)
            except Exception as exc:
                stats.errors.append(f"Group ingest error: {exc}")

    async def _ingest_computers(self, records: List[Dict], stats: IngestStats) -> None:
        for rec in records:
            try:
                props = self._extract_computer_props(rec)
                await self._merge_node(self.LABEL_COMPUTER, "objectid", props, stats)
                await self._create_acls(rec, self.LABEL_COMPUTER, stats)
                await self._create_local_admins(rec, stats)
                await self._create_remote_desktop(rec, stats)
                await self._create_ps_remote(rec, stats)
                await self._create_sessions_on_computer(rec, stats)
            except Exception as exc:
                stats.errors.append(f"Computer ingest error: {exc}")

    async def _ingest_ous(self, records: List[Dict], stats: IngestStats) -> None:
        for rec in records:
            try:
                props = self._extract_ou_props(rec)
                await self._merge_node(self.LABEL_OU, "objectid", props, stats)
                await self._create_gp_links(rec, stats)
                await self._create_acls(rec, self.LABEL_OU, stats)
            except Exception as exc:
                stats.errors.append(f"OU ingest error: {exc}")

    async def _ingest_gpos(self, records: List[Dict], stats: IngestStats) -> None:
        for rec in records:
            try:
                props = self._extract_gpo_props(rec)
                await self._merge_node(self.LABEL_GPO, "objectid", props, stats)
                await self._create_acls(rec, self.LABEL_GPO, stats)
            except Exception as exc:
                stats.errors.append(f"GPO ingest error: {exc}")

    async def _ingest_domains(self, records: List[Dict], stats: IngestStats) -> None:
        for rec in records:
            try:
                props = self._extract_domain_props(rec)
                await self._merge_node(self.LABEL_DOMAIN, "objectid", props, stats)
                await self._create_trusts(rec, stats)
                await self._create_acls(rec, self.LABEL_DOMAIN, stats)
            except Exception as exc:
                stats.errors.append(f"Domain ingest error: {exc}")

    async def _ingest_containers(
        self, records: List[Dict], stats: IngestStats
    ) -> None:
        for rec in records:
            try:
                props = {
                    "objectid": rec.get("ObjectIdentifier", ""),
                    "name": rec.get("Properties", {}).get("name", ""),
                    "distinguishedname": rec.get("Properties", {}).get(
                        "distinguishedname", ""
                    ),
                }
                await self._merge_node("ADContainer", "objectid", props, stats)
            except Exception as exc:
                stats.errors.append(f"Container ingest error: {exc}")

    # ------------------------------------------------------------------
    # Property extractors
    # ------------------------------------------------------------------

    def _extract_user_props(self, rec: Dict) -> Dict[str, Any]:
        p = rec.get("Properties", {})
        return {
            "objectid": rec.get("ObjectIdentifier", ""),
            "name": p.get("name", ""),
            "displayname": p.get("displayname", ""),
            "samaccountname": p.get("samaccountname", ""),
            "distinguishedname": p.get("distinguishedname", ""),
            "description": p.get("description", ""),
            "enabled": p.get("enabled", True),
            "lastlogon": p.get("lastlogon", -1),
            "lastlogontimestamp": p.get("lastlogontimestamp", -1),
            "pwdlastset": p.get("pwdlastset", -1),
            "dontreqpreauth": p.get("dontreqpreauth", False),
            "hasspn": p.get("hasspn", False),
            "serviceprincipalnames": p.get("serviceprincipalnames", []),
            "admincount": p.get("admincount", False),
            "owned": rec.get("IsACLProtected", False),
            "highvalue": p.get("highvalue", False),
            "pwdneverexpires": p.get("pwdneverexpires", False),
            "sensitive": p.get("sensitive", False),
            "domain": p.get("domain", ""),
            "objecttype": "User",
        }

    def _extract_group_props(self, rec: Dict) -> Dict[str, Any]:
        p = rec.get("Properties", {})
        return {
            "objectid": rec.get("ObjectIdentifier", ""),
            "name": p.get("name", ""),
            "samaccountname": p.get("samaccountname", ""),
            "distinguishedname": p.get("distinguishedname", ""),
            "description": p.get("description", ""),
            "admincount": p.get("admincount", False),
            "highvalue": p.get("highvalue", False),
            "domain": p.get("domain", ""),
            "objecttype": "Group",
        }

    def _extract_computer_props(self, rec: Dict) -> Dict[str, Any]:
        p = rec.get("Properties", {})
        return {
            "objectid": rec.get("ObjectIdentifier", ""),
            "name": p.get("name", ""),
            "samaccountname": p.get("samaccountname", ""),
            "distinguishedname": p.get("distinguishedname", ""),
            "description": p.get("description", ""),
            "operatingsystem": p.get("operatingsystem", ""),
            "enabled": p.get("enabled", True),
            "unconstraineddelegation": p.get("unconstraineddelegation", False),
            "constraineddelegation": p.get("constraineddelegation", False),
            "allowedtodelegate": p.get("allowedtodelegate", []),
            "haslaps": p.get("haslaps", False),
            "lastlogontimestamp": p.get("lastlogontimestamp", -1),
            "pwdlastset": p.get("pwdlastset", -1),
            "highvalue": p.get("highvalue", False),
            "owned": rec.get("IsACLProtected", False),
            "domain": p.get("domain", ""),
            "objecttype": "Computer",
        }

    def _extract_ou_props(self, rec: Dict) -> Dict[str, Any]:
        p = rec.get("Properties", {})
        return {
            "objectid": rec.get("ObjectIdentifier", ""),
            "name": p.get("name", ""),
            "distinguishedname": p.get("distinguishedname", ""),
            "description": p.get("description", ""),
            "blocksinheritance": p.get("blocksinheritance", False),
            "domain": p.get("domain", ""),
            "objecttype": "OU",
        }

    def _extract_gpo_props(self, rec: Dict) -> Dict[str, Any]:
        p = rec.get("Properties", {})
        return {
            "objectid": rec.get("ObjectIdentifier", ""),
            "name": p.get("name", ""),
            "distinguishedname": p.get("distinguishedname", ""),
            "description": p.get("description", ""),
            "gpcpath": p.get("gpcpath", ""),
            "domain": p.get("domain", ""),
            "objecttype": "GPO",
        }

    def _extract_domain_props(self, rec: Dict) -> Dict[str, Any]:
        p = rec.get("Properties", {})
        return {
            "objectid": rec.get("ObjectIdentifier", ""),
            "name": p.get("name", ""),
            "distinguishedname": p.get("distinguishedname", ""),
            "description": p.get("description", ""),
            "functionallevel": p.get("functionallevel", ""),
            "domain": p.get("domain", p.get("name", "")),
            "highvalue": True,
            "objecttype": "Domain",
        }

    # ------------------------------------------------------------------
    # Relationship creators
    # ------------------------------------------------------------------

    async def _create_member_of(self, rec: Dict, stats: IngestStats) -> None:
        members = rec.get("Members", [])
        target_id = rec.get("ObjectIdentifier", "")
        for member in members:
            member_id = member.get("ObjectIdentifier", "")
            member_type = member.get("ObjectType", "Base")
            if not member_id or not target_id:
                continue
            await self._merge_rel_by_id(
                member_id, member_type, "MemberOf", target_id, "Group", {}, stats
            )

        # Also handle Memberships on user records
        for entry in rec.get("PrimaryGroupSid", []):
            await self._merge_rel_by_id(
                rec.get("ObjectIdentifier", ""),
                "User",
                "MemberOf",
                entry,
                "Group",
                {"primary": True},
                stats,
            )

    async def _create_acls(
        self, rec: Dict, src_label: str, stats: IngestStats
    ) -> None:
        src_id = rec.get("ObjectIdentifier", "")
        for ace in rec.get("Aces", []):
            principal_id = ace.get("PrincipalSID", "")
            principal_type = ace.get("PrincipalType", "Base")
            right_name = ace.get("RightName", "")
            if not principal_id or not right_name:
                continue
            props = {
                "isinherited": ace.get("IsInherited", False),
                "inheritedfromproperty": ace.get("InheritedFromProperty", ""),
            }
            await self._merge_rel_by_id(
                principal_id,
                principal_type,
                right_name,
                src_id,
                src_label,
                props,
                stats,
            )

    async def _create_sessions(self, rec: Dict, stats: IngestStats) -> None:
        user_id = rec.get("ObjectIdentifier", "")
        for sess in rec.get("Sessions", {}).get("Results", []):
            computer_id = sess.get("ComputerSID", "")
            if not computer_id:
                continue
            await self._merge_rel_by_id(
                user_id, "User", "HasSession", computer_id, "Computer", {}, stats
            )

    async def _create_sessions_on_computer(
        self, rec: Dict, stats: IngestStats
    ) -> None:
        computer_id = rec.get("ObjectIdentifier", "")
        for sess in rec.get("Sessions", {}).get("Results", []):
            user_id = sess.get("UserSID", "")
            if not user_id:
                continue
            await self._merge_rel_by_id(
                user_id, "User", "HasSession", computer_id, "Computer", {}, stats
            )

    async def _create_local_admins(self, rec: Dict, stats: IngestStats) -> None:
        computer_id = rec.get("ObjectIdentifier", "")
        for entry in rec.get("LocalAdmins", {}).get("Results", []):
            admin_id = entry.get("ObjectIdentifier", "")
            admin_type = entry.get("ObjectType", "Base")
            if not admin_id:
                continue
            await self._merge_rel_by_id(
                admin_id, admin_type, "AdminTo", computer_id, "Computer", {}, stats
            )

    async def _create_remote_desktop(self, rec: Dict, stats: IngestStats) -> None:
        computer_id = rec.get("ObjectIdentifier", "")
        for entry in rec.get("RemoteDesktopUsers", {}).get("Results", []):
            principal_id = entry.get("ObjectIdentifier", "")
            principal_type = entry.get("ObjectType", "Base")
            if not principal_id:
                continue
            await self._merge_rel_by_id(
                principal_id,
                principal_type,
                "CanRDP",
                computer_id,
                "Computer",
                {},
                stats,
            )

    async def _create_ps_remote(self, rec: Dict, stats: IngestStats) -> None:
        computer_id = rec.get("ObjectIdentifier", "")
        for entry in rec.get("PSRemoteUsers", {}).get("Results", []):
            principal_id = entry.get("ObjectIdentifier", "")
            principal_type = entry.get("ObjectType", "Base")
            if not principal_id:
                continue
            await self._merge_rel_by_id(
                principal_id,
                principal_type,
                "CanPSRemote",
                computer_id,
                "Computer",
                {},
                stats,
            )

    async def _create_gp_links(self, rec: Dict, stats: IngestStats) -> None:
        ou_id = rec.get("ObjectIdentifier", "")
        for gpl in rec.get("GPOChanges", {}).get("LocalAdmins", []):
            gpo_id = gpl.get("GPOID", "")
            if not gpo_id:
                continue
            await self._merge_rel_by_id(
                gpo_id, "GPO", "GpLink", ou_id, "OU", {}, stats
            )
        for link in rec.get("Links", []):
            gpo_id = link.get("GUID", "")
            if not gpo_id:
                continue
            await self._merge_rel_by_id(
                gpo_id,
                "GPO",
                "GpLink",
                ou_id,
                "OU",
                {"enforced": link.get("IsEnforced", False)},
                stats,
            )

    async def _create_trusts(self, rec: Dict, stats: IngestStats) -> None:
        domain_id = rec.get("ObjectIdentifier", "")
        for trust in rec.get("Trusts", []):
            target_domain = trust.get("TargetDomainName", "")
            if not target_domain:
                continue
            props = {
                "trusttype": trust.get("TrustType", ""),
                "transitive": trust.get("IsTransitive", False),
                "direction": trust.get("TrustDirection", 0),
                "sidfiltering": trust.get("SidFilteringEnabled", False),
                "targetdomainsid": trust.get("TargetDomainSid", ""),
            }
            # Trust nodes
            target_props = {
                "objectid": trust.get("TargetDomainSid", target_domain),
                "name": target_domain.upper(),
                "domain": target_domain,
                "objecttype": "Domain",
                "highvalue": True,
            }
            await self._merge_node(self.LABEL_DOMAIN, "objectid", target_props, stats)
            await self._merge_rel_by_id(
                domain_id,
                "Domain",
                "HasTrust",
                trust.get("TargetDomainSid", target_domain),
                "Domain",
                props,
                stats,
            )

    # ------------------------------------------------------------------
    # Neo4j helpers
    # ------------------------------------------------------------------

    async def _merge_node(
        self,
        label: str,
        key_prop: str,
        props: Dict[str, Any],
        stats: IngestStats,
    ) -> None:
        """MERGE a node by *key_prop* and SET all other properties."""
        key_val = props.get(key_prop, "")
        if not key_val:
            return
        set_clause = ", ".join(
            f"n.{k} = ${k}" for k in props if k != key_prop
        )
        cypher = (
            f"MERGE (n:{label} {{{key_prop}: ${key_prop}}}) "
            + (f"SET {set_clause} " if set_clause else "")
            + "RETURN n"
        )
        try:
            result = self.client.run_query(cypher, props)
            if result:
                stats.nodes_merged += 1
            else:
                stats.nodes_created += 1
        except Exception as exc:
            stats.errors.append(f"MERGE node {label}/{key_val}: {exc}")

    async def _merge_rel_by_id(
        self,
        src_id: str,
        src_hint: str,
        rel_type: str,
        dst_id: str,
        dst_hint: str,
        props: Dict[str, Any],
        stats: IngestStats,
    ) -> None:
        """
        MERGE a relationship between two nodes identified by objectid.
        src_hint / dst_hint are label suggestions; we use Base as catch-all.
        """
        if not src_id or not dst_id:
            return
        set_parts = " ".join(f"r.{k} = ${k}" for k in props)
        set_clause = f"SET {set_parts}" if set_parts else ""
        cypher = (
            "MATCH (a {objectid: $src_id}), (b {objectid: $dst_id}) "
            f"MERGE (a)-[r:{rel_type}]->(b) "
            f"{set_clause} RETURN r"
        )
        params = {"src_id": src_id, "dst_id": dst_id, **props}
        try:
            self.client.run_query(cypher, params)
            stats.relationships_created += 1
        except Exception as exc:
            stats.errors.append(
                f"MERGE rel {rel_type} {src_id}→{dst_id}: {exc}"
            )


# ---------------------------------------------------------------------------
# Schema helper — create AD-specific constraints / indexes
# ---------------------------------------------------------------------------

AD_CONSTRAINTS: List[Tuple[str, str]] = [
    ("ADUser", "objectid"),
    ("ADGroup", "objectid"),
    ("ADComputer", "objectid"),
    ("ADOU", "objectid"),
    ("ADGPO", "objectid"),
    ("ADDomain", "objectid"),
    ("ADTrust", "objectid"),
]

AD_INDEXES: List[Tuple[str, str]] = [
    ("ADUser", "name"),
    ("ADUser", "samaccountname"),
    ("ADGroup", "name"),
    ("ADComputer", "name"),
    ("ADDomain", "name"),
]


async def create_ad_schema(neo4j_client: Any) -> None:
    """Create Neo4j uniqueness constraints and indexes for AD node types."""
    for label, prop in AD_CONSTRAINTS:
        cypher = (
            f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{label}) "
            f"REQUIRE n.{prop} IS UNIQUE"
        )
        try:
            neo4j_client.run_query(cypher, {})
            logger.debug("Constraint created: %s.%s", label, prop)
        except Exception as exc:
            logger.warning("Could not create constraint %s.%s: %s", label, prop, exc)

    for label, prop in AD_INDEXES:
        cypher = (
            f"CREATE INDEX IF NOT EXISTS FOR (n:{label}) ON (n.{prop})"
        )
        try:
            neo4j_client.run_query(cypher, {})
            logger.debug("Index created: %s.%s", label, prop)
        except Exception as exc:
            logger.warning("Could not create index %s.%s: %s", label, prop, exc)
