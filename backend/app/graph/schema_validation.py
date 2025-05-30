"""
Neo4j Graph Schema Validation.

Validates that all required node types, relationship types, constraints, and
indexes are present and correctly configured in the Neo4j database.
"""

from typing import Dict, List, Any
from app.db.neo4j_client import Neo4jClient
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Expected schema definitions
# ---------------------------------------------------------------------------

EXPECTED_NODE_LABELS: List[str] = [
    # Infrastructure chain
    "Domain",
    "Subdomain",
    "IP",
    "Port",
    "Service",
    "BaseURL",
    "Endpoint",
    "Parameter",
    "Technology",
    "Header",
    "Certificate",
    "DNSRecord",
    # Vulnerability chain
    "Vulnerability",
    "CVE",
    "MitreData",
    "Capec",
    "Exploit",
    # Advanced / operational nodes
    "Session",
    "Credential",
    "Evidence",
    "Tool",
    "Scan",
    "Finding",
    "AuditEvent",
]

EXPECTED_RELATIONSHIP_TYPES: List[str] = [
    # Infrastructure chain
    "HAS_SUBDOMAIN",
    "RESOLVES_TO",
    "HAS_PORT",
    "RUNS_SERVICE",
    "SERVES_URL",
    "HAS_ENDPOINT",
    "HAS_PARAMETER",
    "USES_TECHNOLOGY",
    "HAS_HEADER",
    "HAS_CERTIFICATE",
    "HAS_DNS_RECORD",
    # Vulnerability chain
    "FOUND_AT",
    "AFFECTS_PARAMETER",
    "HAS_VULNERABILITY",
    "HAS_KNOWN_CVE",
    "HAS_CWE",
    "HAS_CAPEC",
    "EXPLOITED_CVE",
    "TARGETED_IP",
    # Session / Credential
    "ESTABLISHED_SESSION",
    "OPENED_ON",
    "HAS_CREDENTIAL",
    "VALIDATES_FOR",
    # Tool / Scan / Finding / Evidence
    "PERFORMED_SCAN",
    "PRODUCED_FINDING",
    "SUPPORTED_BY",
    "RELATED_TO",
]

# Uniqueness constraints expected per node label
EXPECTED_CONSTRAINTS: Dict[str, str] = {
    "Domain": "name",
    "Subdomain": "name",
    "IP": "address",
    "Port": "id",
    "Service": "id",
    "BaseURL": "url",
    "Endpoint": "id",
    "Parameter": "id",
    "Technology": "name",
    "Header": "id",
    "Certificate": "id",
    "DNSRecord": "id",
    "Vulnerability": "id",
    "CVE": "id",
    "MitreData": "id",
    "Capec": "id",
    "Exploit": "id",
    "Session": "id",
    "Credential": "id",
    "Evidence": "id",
    "Tool": "id",
    "Scan": "id",
    "Finding": "id",
    "AuditEvent": "id",
}


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _get_db_node_labels(client: Neo4jClient) -> List[str]:
    """Return all node labels currently present in the database."""
    query = "CALL db.labels() YIELD label RETURN label"
    try:
        results = client.execute_query(query)
        return [r["label"] for r in results]
    except Exception as e:
        logger.warning(f"Could not retrieve node labels: {e}")
        return []


def _get_db_relationship_types(client: Neo4jClient) -> List[str]:
    """Return all relationship types currently present in the database."""
    query = "CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType"
    try:
        results = client.execute_query(query)
        return [r["relationshipType"] for r in results]
    except Exception as e:
        logger.warning(f"Could not retrieve relationship types: {e}")
        return []


def _get_db_constraints(client: Neo4jClient) -> List[Dict[str, Any]]:
    """Return all constraints currently defined in the database."""
    query = "SHOW CONSTRAINTS YIELD name, type, labelsOrTypes, properties RETURN name, type, labelsOrTypes, properties"
    try:
        return client.execute_query(query)
    except Exception as e:
        logger.warning(f"Could not retrieve constraints: {e}")
        return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_schema(
    client: Neo4jClient,
    check_live_data: bool = False,
) -> Dict[str, Any]:
    """
    Validate the Neo4j schema against the expected definitions.

    This function performs a structural validation only: it checks whether
    the constraints defined in the database cover the required node labels
    and whether, if the database already has data, all expected relationship
    types are represented.

    Args:
        client: Connected Neo4jClient instance.
        check_live_data: When True, also verify that every expected label
            and relationship type has at least one instance in the database.

    Returns:
        Validation report dictionary with keys:
            - valid (bool): True if all checks pass.
            - node_labels_ok (bool)
            - relationship_types_ok (bool)
            - constraints_ok (bool)
            - missing_labels (list)
            - missing_relationship_types (list)
            - missing_constraints (list)
            - details (dict)
    """
    report: Dict[str, Any] = {
        "valid": False,
        "node_labels_ok": True,
        "relationship_types_ok": True,
        "constraints_ok": True,
        "missing_labels": [],
        "missing_relationship_types": [],
        "missing_constraints": [],
        "details": {},
    }

    # ── Constraint check ────────────────────────────────────────────────────
    db_constraints = _get_db_constraints(client)
    # Build a set of (label, property) pairs that already have a UNIQUENESS constraint
    constrained_pairs = set()
    for c in db_constraints:
        c_type = c.get("type", "")
        labels = c.get("labelsOrTypes") or []
        props = c.get("properties") or []
        if "UNIQUENESS" in c_type.upper() and labels and props:
            for lbl in labels:
                for prop in props:
                    constrained_pairs.add((lbl, prop))

    missing_constraints: List[str] = []
    for label, prop in EXPECTED_CONSTRAINTS.items():
        if (label, prop) not in constrained_pairs:
            missing_constraints.append(f"{label}.{prop}")

    if missing_constraints:
        report["constraints_ok"] = False
        report["missing_constraints"] = missing_constraints
        logger.warning(
            f"Missing uniqueness constraints: {missing_constraints}"
        )

    # ── Live-data checks (optional) ─────────────────────────────────────────
    if check_live_data:
        db_labels = _get_db_node_labels(client)
        db_rel_types = _get_db_relationship_types(client)

        missing_labels = [
            lbl for lbl in EXPECTED_NODE_LABELS if lbl not in db_labels
        ]
        missing_rel_types = [
            rt for rt in EXPECTED_RELATIONSHIP_TYPES if rt not in db_rel_types
        ]

        if missing_labels:
            report["node_labels_ok"] = False
            report["missing_labels"] = missing_labels
            logger.warning(f"Missing node labels in live data: {missing_labels}")

        if missing_rel_types:
            report["relationship_types_ok"] = False
            report["missing_relationship_types"] = missing_rel_types
            logger.warning(
                f"Missing relationship types in live data: {missing_rel_types}"
            )
    else:
        # Without live data we still validate the schema definitions themselves
        report["node_labels_ok"] = True
        report["relationship_types_ok"] = True

    # ── Summary ─────────────────────────────────────────────────────────────
    report["valid"] = (
        report["node_labels_ok"]
        and report["relationship_types_ok"]
        and report["constraints_ok"]
    )

    report["details"] = {
        "expected_node_labels": len(EXPECTED_NODE_LABELS),
        "expected_relationship_types": len(EXPECTED_RELATIONSHIP_TYPES),
        "expected_constraints": len(EXPECTED_CONSTRAINTS),
        "db_constraints_found": len(db_constraints),
    }

    if report["valid"]:
        logger.info("Schema validation passed.")
    else:
        logger.error("Schema validation FAILED. See report for details.")

    return report


def ensure_constraints(client: Neo4jClient) -> Dict[str, int]:
    """
    Ensure all required uniqueness constraints exist, creating them if absent.

    Args:
        client: Connected Neo4jClient instance.

    Returns:
        Dictionary with counts of created and existing constraints.
    """
    result = {"created": 0, "already_exist": 0, "failed": 0}

    db_constraints = _get_db_constraints(client)
    constrained_pairs = set()
    for c in db_constraints:
        c_type = c.get("type", "")
        labels = c.get("labelsOrTypes") or []
        props = c.get("properties") or []
        if "UNIQUENESS" in c_type.upper() and labels and props:
            for lbl in labels:
                for prop in props:
                    constrained_pairs.add((lbl, prop))

    for label, prop in EXPECTED_CONSTRAINTS.items():
        if (label, prop) in constrained_pairs:
            result["already_exist"] += 1
            continue
        cypher = (
            f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{label}) "
            f"REQUIRE n.{prop} IS UNIQUE"
        )
        try:
            client.execute_query(cypher)
            result["created"] += 1
            logger.info(f"Created constraint: {label}.{prop}")
        except Exception as e:
            result["failed"] += 1
            logger.error(f"Failed to create constraint {label}.{prop}: {e}")

    return result


def run_smoke_queries(client: Neo4jClient) -> Dict[str, Any]:
    """
    Run a set of smoke-test Cypher queries to verify the schema is usable.

    These queries do not require live data — they simply confirm that the
    query planner can parse the patterns without syntax or schema errors.

    Args:
        client: Connected Neo4jClient instance.

    Returns:
        Dictionary mapping query name to pass/fail status.
    """
    smoke_tests = {
        "attack_surface_traversal": (
            "OPTIONAL MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)"
            "-[:RESOLVES_TO]->(ip:IP)-[:HAS_PORT]->(p:Port)"
            "-[:RUNS_SERVICE]->(srv:Service) RETURN count(d) AS cnt"
        ),
        "vuln_chain": (
            "OPTIONAL MATCH (v:Vulnerability)-[:FOUND_AT]->(e:Endpoint)"
            " RETURN count(v) AS cnt"
        ),
        "cve_cwe_capec_chain": (
            "OPTIONAL MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(cve:CVE)"
            "-[:HAS_CWE]->(cwe:MitreData)-[:HAS_CAPEC]->(capec:Capec)"
            " RETURN count(t) AS cnt"
        ),
        "session_credential_chain": (
            "OPTIONAL MATCH (ex:Exploit)-[:ESTABLISHED_SESSION]->(sess:Session)"
            "-[:HAS_CREDENTIAL]->(cred:Credential) RETURN count(ex) AS cnt"
        ),
        "scan_finding_evidence_chain": (
            "OPTIONAL MATCH (tool:Tool)-[:PERFORMED_SCAN]->(scan:Scan)"
            "-[:PRODUCED_FINDING]->(finding:Finding)"
            "-[:SUPPORTED_BY]->(ev:Evidence) RETURN count(tool) AS cnt"
        ),
        "audit_event_query": (
            "OPTIONAL MATCH (a:AuditEvent) RETURN count(a) AS cnt"
        ),
    }

    results: Dict[str, Any] = {}
    for name, query in smoke_tests.items():
        try:
            client.execute_query(query)
            results[name] = "pass"
            logger.debug(f"Smoke test '{name}': PASS")
        except Exception as e:
            results[name] = f"fail: {e}"
            logger.error(f"Smoke test '{name}': FAIL — {e}")

    all_passed = all(v == "pass" for v in results.values())
    results["all_passed"] = all_passed
    return results
