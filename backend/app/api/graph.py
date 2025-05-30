"""
Graph API endpoints for Neo4j attack surface graph.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, Optional
from app.db.neo4j_client import get_neo4j_client, Neo4jClient
from app.graph.ingestion import (
    ingest_domain_discovery,
    ingest_port_scan,
    ingest_http_probe,
    ingest_resource_enumeration,
    ingest_vulnerability_scan,
    ingest_mitre_data
)
from pydantic import BaseModel
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/graph", tags=["graph"])


class GraphIngestRequest(BaseModel):
    """Request model for graph data ingestion."""
    phase: str  # domain_discovery, port_scan, http_probe, resource_enum, vuln_scan, mitre
    data: Dict[str, Any]
    user_id: Optional[str] = None
    project_id: Optional[str] = None


class GraphQueryRequest(BaseModel):
    """Request model for graph queries."""
    query: str
    parameters: Optional[Dict[str, Any]] = None


@router.post("/ingest")
async def ingest_data(
    request: GraphIngestRequest,
    client: Neo4jClient = Depends(get_neo4j_client)
) -> Dict[str, Any]:
    """
    Ingest data into the Neo4j graph database.
    
    Args:
        request: Ingestion request with phase, data, and tenant info
        client: Neo4j client instance
        
    Returns:
        Ingestion statistics
    """
    try:
        # Route to appropriate ingestion function
        if request.phase == "domain_discovery":
            stats = ingest_domain_discovery(
                client, request.data, request.user_id, request.project_id
            )
        elif request.phase == "port_scan":
            stats = ingest_port_scan(
                client, request.data, request.user_id, request.project_id
            )
        elif request.phase == "http_probe":
            stats = ingest_http_probe(
                client, request.data, request.user_id, request.project_id
            )
        elif request.phase == "resource_enum":
            stats = ingest_resource_enumeration(
                client, request.data, request.user_id, request.project_id
            )
        elif request.phase == "vuln_scan":
            stats = ingest_vulnerability_scan(
                client, request.data, request.user_id, request.project_id
            )
        elif request.phase == "mitre":
            stats = ingest_mitre_data(
                client, request.data, request.user_id, request.project_id
            )
        else:
            raise HTTPException(status_code=400, detail=f"Unknown phase: {request.phase}")
        
        return {
            "success": True,
            "phase": request.phase,
            "stats": stats
        }
        
    except Exception as e:
        logger.error(f"Error ingesting data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/query")
async def execute_query(
    request: GraphQueryRequest,
    client: Neo4jClient = Depends(get_neo4j_client)
) -> Dict[str, Any]:
    """
    Execute a Cypher query on the graph database.
    
    Args:
        request: Query request with Cypher query and parameters
        client: Neo4j client instance
        
    Returns:
        Query results
    """
    try:
        results = client.execute_query(request.query, request.parameters)
        
        return {
            "success": True,
            "count": len(results),
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Error executing query: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack-surface/{project_id}")
async def get_attack_surface(
    project_id: str,
    client: Neo4jClient = Depends(get_neo4j_client)
) -> Dict[str, Any]:
    """
    Get the complete attack surface for a project.
    
    Args:
        project_id: Project identifier
        client: Neo4j client instance
        
    Returns:
        Attack surface graph data
    """
    try:
        data = client.get_attack_surface(project_id)
        
        return {
            "success": True,
            "project_id": project_id,
            "data": data
        }
        
    except Exception as e:
        logger.error(f"Error getting attack surface: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vulnerabilities/{project_id}")
async def get_vulnerabilities(
    project_id: str,
    severity: Optional[str] = None,
    client: Neo4jClient = Depends(get_neo4j_client)
) -> Dict[str, Any]:
    """
    Get vulnerabilities for a project.
    
    Args:
        project_id: Project identifier
        severity: Optional severity filter (info, low, medium, high, critical)
        client: Neo4j client instance
        
    Returns:
        List of vulnerabilities
    """
    try:
        query = """
        MATCH (v:Vulnerability {project_id: $project_id})
        """
        
        parameters = {"project_id": project_id}
        
        if severity:
            query += " WHERE v.severity = $severity"
            parameters["severity"] = severity
        
        query += """
        OPTIONAL MATCH (v)-[:FOUND_AT]->(e:Endpoint)
        OPTIONAL MATCH (v)-[:AFFECTS_PARAMETER]->(p:Parameter)
        RETURN v, e, collect(p) as parameters
        ORDER BY v.severity DESC, v.discovered_at DESC
        """
        
        results = client.execute_query(query, parameters)
        
        return {
            "success": True,
            "project_id": project_id,
            "severity": severity,
            "count": len(results),
            "vulnerabilities": results
        }
        
    except Exception as e:
        logger.error(f"Error getting vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/technologies/{project_id}")
async def get_technologies(
    project_id: str,
    with_cves: bool = False,
    client: Neo4jClient = Depends(get_neo4j_client)
) -> Dict[str, Any]:
    """
    Get technologies detected for a project.
    
    Args:
        project_id: Project identifier
        with_cves: Whether to include CVE information
        client: Neo4j client instance
        
    Returns:
        List of technologies
    """
    try:
        if with_cves:
            query = """
            MATCH (t:Technology {project_id: $project_id})
            OPTIONAL MATCH (t)-[:HAS_KNOWN_CVE]->(cve:CVE)
            RETURN t, collect(cve) as cves
            ORDER BY t.name
            """
        else:
            query = """
            MATCH (t:Technology {project_id: $project_id})
            RETURN t
            ORDER BY t.name
            """
        
        results = client.execute_query(query, {"project_id": project_id})
        
        return {
            "success": True,
            "project_id": project_id,
            "count": len(results),
            "technologies": results
        }
        
    except Exception as e:
        logger.error(f"Error getting technologies: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/project/{project_id}")
async def clear_project_data(
    project_id: str,
    client: Neo4jClient = Depends(get_neo4j_client)
) -> Dict[str, Any]:
    """
    Clear all graph data for a project.
    
    Args:
        project_id: Project identifier
        client: Neo4j client instance
        
    Returns:
        Number of nodes deleted
    """
    try:
        deleted_count = client.clear_project_data(project_id)
        
        return {
            "success": True,
            "project_id": project_id,
            "deleted_count": deleted_count
        }
        
    except Exception as e:
        logger.error(f"Error clearing project data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check(
    client: Neo4jClient = Depends(get_neo4j_client)
) -> Dict[str, Any]:
    """
    Check Neo4j database health.
    
    Returns:
        Health status information
    """
    try:
        health = client.health_check()
        return health
        
    except Exception as e:
        logger.error(f"Error checking health: {e}")
        return {
            "status": "error",
            "healthy": False,
            "error": str(e)
        }


@router.get("/stats/{project_id}")
async def get_stats(
    project_id: str,
    client: Neo4jClient = Depends(get_neo4j_client)
) -> Dict[str, Any]:
    """
    Get statistics for a project's graph data.
    
    Args:
        project_id: Project identifier
        client: Neo4j client instance
        
    Returns:
        Graph statistics
    """
    try:
        query = """
        MATCH (n {project_id: $project_id})
        WITH labels(n) as node_labels
        UNWIND node_labels as label
        RETURN label, count(*) as count
        ORDER BY count DESC
        """
        
        results = client.execute_query(query, {"project_id": project_id})
        
        # Convert to dictionary
        stats = {result['label']: result['count'] for result in results}
        
        return {
            "success": True,
            "project_id": project_id,
            "node_counts": stats,
            "total_nodes": sum(stats.values())
        }
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats/{project_id}/relationships")
async def get_relationship_stats(
    project_id: str,
    client: Neo4jClient = Depends(get_neo4j_client),
) -> Dict[str, Any]:
    """
    Get relationship-level statistics for a project.

    Returns per-type relationship counts and the total across all types.
    """
    try:
        data = client.get_relationship_stats(project_id)
        return {"success": True, "project_id": project_id, **data}
    except Exception as e:
        logger.error(f"Error getting relationship stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats/{project_id}/health")
async def get_graph_health_metrics(
    project_id: str,
    client: Neo4jClient = Depends(get_neo4j_client),
) -> Dict[str, Any]:
    """
    Compute and return health metrics for the project graph.

    Metrics include node/relationship counts, isolated nodes,
    orphaned vulnerabilities/IPs, and schema coverage fraction.
    """
    try:
        metrics = client.get_graph_health_metrics(project_id)
        return {"success": True, **metrics}
    except Exception as e:
        logger.error(f"Error getting health metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack-surface/{project_id}/services")
async def get_exposed_services(
    project_id: str,
    user_id: Optional[str] = None,
    client: Neo4jClient = Depends(get_neo4j_client),
) -> Dict[str, Any]:
    """
    List all publicly exposed services with IP, port, and service details.
    """
    try:
        from app.graph.graph_queries import AttackSurfaceQueries
        qs = AttackSurfaceQueries(client)
        services = qs.get_exposed_services(project_id, user_id=user_id)
        return {
            "success": True,
            "project_id": project_id,
            "count": len(services),
            "services": services,
        }
    except Exception as e:
        logger.error(f"Error getting exposed services: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack-surface/{project_id}/overview")
async def get_attack_surface_overview(
    project_id: str,
    user_id: Optional[str] = None,
    client: Neo4jClient = Depends(get_neo4j_client),
) -> Dict[str, Any]:
    """
    Return an aggregate overview of the project's attack surface
    (domain, subdomain, IP, port, service, endpoint counts).
    """
    try:
        from app.graph.graph_queries import AttackSurfaceQueries
        qs = AttackSurfaceQueries(client)
        overview = qs.get_attack_surface_overview(project_id, user_id=user_id)
        return {"success": True, "project_id": project_id, "overview": overview}
    except Exception as e:
        logger.error(f"Error getting overview: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vulnerabilities/{project_id}/exploitable")
async def get_exploitable_vulnerabilities(
    project_id: str,
    user_id: Optional[str] = None,
    min_cvss: float = 7.0,
    client: Neo4jClient = Depends(get_neo4j_client),
) -> Dict[str, Any]:
    """
    Return vulnerabilities with associated CVEs above the CVSS threshold,
    ordered by exploitability (CVSS score, exploit count).
    """
    try:
        from app.graph.graph_queries import VulnerabilityQueries
        qs = VulnerabilityQueries(client)
        vulns = qs.get_exploitable_vulnerabilities(
            project_id, user_id=user_id, min_cvss=min_cvss
        )
        return {
            "success": True,
            "project_id": project_id,
            "min_cvss": min_cvss,
            "count": len(vulns),
            "vulnerabilities": vulns,
        }
    except Exception as e:
        logger.error(f"Error getting exploitable vulns: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vulnerabilities/{project_id}/cve-chain/{cve_id}")
async def get_cve_chain(
    project_id: str,
    cve_id: str,
    user_id: Optional[str] = None,
    client: Neo4jClient = Depends(get_neo4j_client),
) -> Dict[str, Any]:
    """
    Return the full CVE → CWE → CAPEC knowledge chain for a specific CVE.
    """
    try:
        from app.graph.graph_queries import VulnerabilityQueries
        qs = VulnerabilityQueries(client)
        chain = qs.get_cve_chain(project_id, cve_id, user_id=user_id)
        return {
            "success": True,
            "project_id": project_id,
            "cve_id": cve_id,
            "chain": chain,
        }
    except Exception as e:
        logger.error(f"Error getting CVE chain: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/paths/{project_id}/attack")
async def get_attack_paths(
    project_id: str,
    user_id: Optional[str] = None,
    max_depth: int = 5,
    client: Neo4jClient = Depends(get_neo4j_client),
) -> Dict[str, Any]:
    """
    Discover all attack paths from exposed IPs to vulnerable endpoints.
    """
    try:
        from app.graph.graph_queries import PathFindingQueries
        qs = PathFindingQueries(client)
        paths = qs.discover_attack_paths(
            project_id, user_id=user_id, max_depth=max_depth
        )
        return {
            "success": True,
            "project_id": project_id,
            "count": len(paths),
            "paths": paths,
        }
    except Exception as e:
        logger.error(f"Error getting attack paths: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/paths/{project_id}/critical")
async def get_critical_paths(
    project_id: str,
    user_id: Optional[str] = None,
    client: Neo4jClient = Depends(get_neo4j_client),
) -> Dict[str, Any]:
    """
    Identify the highest-risk attack paths (critical/high severity + CVSS + exploits).
    """
    try:
        from app.graph.graph_queries import PathFindingQueries
        qs = PathFindingQueries(client)
        paths = qs.identify_critical_paths(project_id, user_id=user_id)
        return {
            "success": True,
            "project_id": project_id,
            "count": len(paths),
            "paths": paths,
        }
    except Exception as e:
        logger.error(f"Error getting critical paths: {e}")
        raise HTTPException(status_code=500, detail=str(e))
