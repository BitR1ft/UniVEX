"""
Neo4j Database Client
Manages connections and operations for the attack surface graph database
"""
from typing import Dict, List, Optional, Any
from neo4j import GraphDatabase, Driver
from neo4j.exceptions import ServiceUnavailable, AuthError
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)


class Neo4jClient:
    """Neo4j database client for attack graph operations"""
    
    def __init__(self):
        self.driver: Optional[Driver] = None
        self.uri = settings.NEO4J_URI
        self.user = settings.NEO4J_USER
        self.password = settings.NEO4J_PASSWORD
        self.database = getattr(settings, 'NEO4J_DATABASE', 'neo4j')
    
    def connect(self) -> None:
        """Establish connection to Neo4j database"""
        try:
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
                max_connection_lifetime=3600,
                max_connection_pool_size=50,
                connection_acquisition_timeout=120,
            )
            # Verify connectivity
            self.driver.verify_connectivity()
            logger.info(f"Connected to Neo4j at {self.uri}")
            
            # Initialize constraints and indexes
            self._initialize_schema()
            
        except (ServiceUnavailable, AuthError) as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            raise
    
    def close(self) -> None:
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")
    
    def _initialize_schema(self) -> None:
        """Initialize database constraints and indexes for all 17 node types"""
        with self.driver.session(database=self.database) as session:
            # Create constraints for unique node properties (all 17 node types)
            constraints = [
                # Infrastructure nodes
                "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.name IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (ip:IP) REQUIRE ip.address IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Port) REQUIRE p.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (srv:Service) REQUIRE srv.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (u:BaseURL) REQUIRE u.url IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (prm:Parameter) REQUIRE prm.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Technology) REQUIRE t.name IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (h:Header) REQUIRE h.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (cert:Certificate) REQUIRE cert.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (dns:DNSRecord) REQUIRE dns.id IS UNIQUE",
                # Vulnerability and exploit nodes
                "CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (cve:CVE) REQUIRE cve.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (cwe:MitreData) REQUIRE cwe.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (cap:Capec) REQUIRE cap.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (exp:Exploit) REQUIRE exp.id IS UNIQUE",
                # Advanced / operational nodes
                "CREATE CONSTRAINT IF NOT EXISTS FOR (sess:Session) REQUIRE sess.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (cred:Credential) REQUIRE cred.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (ev:Evidence) REQUIRE ev.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (tool:Tool) REQUIRE tool.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (scan:Scan) REQUIRE scan.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (ae:AuditEvent) REQUIRE ae.id IS UNIQUE",
            ]
            
            for constraint in constraints:
                try:
                    session.run(constraint)
                    logger.debug(f"Created constraint: {constraint}")
                except Exception as e:
                    logger.warning(f"Constraint creation failed (may already exist): {e}")
            
            # Create indexes for performance on commonly queried fields
            indexes = [
                # Time-based indexes
                "CREATE INDEX IF NOT EXISTS FOR (d:Domain) ON (d.discovered_at)",
                "CREATE INDEX IF NOT EXISTS FOR (s:Subdomain) ON (s.discovered_at)",
                "CREATE INDEX IF NOT EXISTS FOR (ip:IP) ON (d:discovered_at)",
                "CREATE INDEX IF NOT EXISTS FOR (v:Vulnerability) ON (v.discovered_at)",
                # Severity indexes
                "CREATE INDEX IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)",
                "CREATE INDEX IF NOT EXISTS FOR (cve:CVE) ON (cve.severity)",
                # State indexes
                "CREATE INDEX IF NOT EXISTS FOR (p:Port) ON (p.state)",
                "CREATE INDEX IF NOT EXISTS FOR (u:BaseURL) ON (u.status_code)",
                # Multi-tenancy indexes
                "CREATE INDEX IF NOT EXISTS FOR (n:Domain) ON (n.project_id)",
                "CREATE INDEX IF NOT EXISTS FOR (n:Domain) ON (n.user_id)",
                "CREATE INDEX IF NOT EXISTS FOR (n:Subdomain) ON (n.project_id)",
                "CREATE INDEX IF NOT EXISTS FOR (n:Vulnerability) ON (n.project_id)",
            ]
            
            for index in indexes:
                try:
                    session.run(index)
                    logger.debug(f"Created index: {index}")
                except Exception as e:
                    logger.warning(f"Index creation failed (may already exist): {e}")
    
    def execute_query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict]:
        """
        Execute a Cypher query and return results
        
        Args:
            query: Cypher query string
            parameters: Query parameters
            
        Returns:
            List of result records as dictionaries
        """
        if not self.driver:
            raise RuntimeError("Neo4j driver not initialized. Call connect() first.")
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query, parameters or {})
            return [dict(record) for record in result]
    
    def create_node(
        self, 
        label: str, 
        properties: Dict[str, Any], 
        merge: bool = True
    ) -> Dict:
        """
        Create or merge a node in the graph
        
        Args:
            label: Node label (e.g., 'Domain', 'IP', 'Vulnerability')
            properties: Node properties
            merge: If True, use MERGE instead of CREATE (prevents duplicates)
            
        Returns:
            Created/merged node properties
        """
        operation = "MERGE" if merge else "CREATE"
        
        # Build property string
        prop_strings = [f"{k}: ${k}" for k in properties.keys()]
        prop_str = "{" + ", ".join(prop_strings) + "}"
        
        query = f"""
        {operation} (n:{label} {prop_str})
        RETURN n
        """
        
        result = self.execute_query(query, properties)
        return result[0]['n'] if result else {}
    
    def create_relationship(
        self,
        from_label: str,
        from_property: str,
        from_value: Any,
        to_label: str,
        to_property: str,
        to_value: Any,
        rel_type: str,
        rel_properties: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Create a relationship between two nodes
        
        Args:
            from_label: Source node label
            from_property: Source node property to match
            from_value: Source node property value
            to_label: Target node label
            to_property: Target node property to match
            to_value: Target node property value
            rel_type: Relationship type
            rel_properties: Optional relationship properties
            
        Returns:
            True if relationship created successfully
        """
        rel_props = ""
        params = {
            'from_value': from_value,
            'to_value': to_value
        }
        
        if rel_properties:
            prop_strings = [f"{k}: ${k}" for k in rel_properties.keys()]
            rel_props = "{" + ", ".join(prop_strings) + "}"
            params.update(rel_properties)
        
        query = f"""
        MATCH (from:{from_label} {{{from_property}: $from_value}})
        MATCH (to:{to_label} {{{to_property}: $to_value}})
        MERGE (from)-[r:{rel_type} {rel_props}]->(to)
        RETURN r
        """
        
        result = self.execute_query(query, params)
        return len(result) > 0
    
    def find_nodes(
        self, 
        label: str, 
        properties: Optional[Dict[str, Any]] = None,
        limit: int = 100
    ) -> List[Dict]:
        """
        Find nodes by label and properties
        
        Args:
            label: Node label
            properties: Optional properties to match
            limit: Maximum number of results
            
        Returns:
            List of matching nodes
        """
        where_clause = ""
        params = {}
        
        if properties:
            conditions = [f"n.{k} = ${k}" for k in properties.keys()]
            where_clause = "WHERE " + " AND ".join(conditions)
            params = properties
        
        query = f"""
        MATCH (n:{label})
        {where_clause}
        RETURN n
        LIMIT {limit}
        """
        
        result = self.execute_query(query, params)
        return [record['n'] for record in result]
    
    def get_attack_surface(self, project_id: str) -> Dict[str, Any]:
        """
        Get the complete attack surface for a project
        
        Args:
            project_id: Project identifier
            
        Returns:
            Attack surface graph data
        """
        query = """
        MATCH (d:Domain {project_id: $project_id})
        OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IP)
        OPTIONAL MATCH (ip)-[:HAS_PORT]->(port:Port)
        OPTIONAL MATCH (port)-[:RUNS_SERVICE]->(service:Service)
        OPTIONAL MATCH (service)-[:HAS_VULNERABILITY]->(vuln:Vulnerability)
        RETURN d, collect(DISTINCT ip) as ips, 
               collect(DISTINCT port) as ports,
               collect(DISTINCT service) as services,
               collect(DISTINCT vuln) as vulnerabilities
        """
        
        result = self.execute_query(query, {'project_id': project_id})
        return result[0] if result else {}
    
    def clear_project_data(self, project_id: str) -> int:
        """
        Clear all data for a specific project
        
        Args:
            project_id: Project identifier
            
        Returns:
            Number of nodes deleted
        """
        query = """
        MATCH (n {project_id: $project_id})
        DETACH DELETE n
        RETURN count(n) as deleted_count
        """
        
        result = self.execute_query(query, {'project_id': project_id})
        return result[0]['deleted_count'] if result else 0

    def get_relationship_stats(self, project_id: str) -> Dict[str, Any]:
        """
        Get relationship statistics for a project.

        Args:
            project_id: Project identifier

        Returns:
            Dict with relationship type counts and total
        """
        query = """
        MATCH (a {project_id: $project_id})-[r]->(b)
        WHERE b.project_id = $project_id OR b.project_id IS NULL
        RETURN type(r) AS relationship_type, count(r) AS count
        ORDER BY count DESC
        """
        try:
            result = self.execute_query(query, {'project_id': project_id})
            rel_counts = {r['relationship_type']: r['count'] for r in result}
            return {
                'relationship_counts': rel_counts,
                'total_relationships': sum(rel_counts.values()),
            }
        except Exception as e:
            logger.error(f"Failed to get relationship stats: {e}")
            return {'relationship_counts': {}, 'total_relationships': 0}

    def get_graph_health_metrics(self, project_id: str) -> Dict[str, Any]:
        """
        Compute graph health metrics for a project.

        Metrics:
          - node_count: total nodes
          - relationship_count: total relationships
          - isolated_nodes: nodes with no relationships
          - orphaned_vulnerabilities: vulnerabilities not linked to any endpoint
          - orphaned_ips: IPs with no ports
          - schema_coverage: fraction of expected labels present

        Args:
            project_id: Project identifier

        Returns:
            Health metrics dictionary
        """
        metrics: Dict[str, Any] = {'project_id': project_id}

        # Total nodes
        try:
            res = self.execute_query(
                "MATCH (n {project_id: $project_id}) RETURN count(n) AS cnt",
                {'project_id': project_id},
            )
            metrics['node_count'] = res[0]['cnt'] if res else 0
        except Exception:
            metrics['node_count'] = 0

        # Total relationships (where at least source node belongs to project)
        try:
            res = self.execute_query(
                "MATCH (a {project_id: $project_id})-[r]->() RETURN count(r) AS cnt",
                {'project_id': project_id},
            )
            metrics['relationship_count'] = res[0]['cnt'] if res else 0
        except Exception:
            metrics['relationship_count'] = 0

        # Isolated nodes (nodes with degree = 0)
        try:
            res = self.execute_query(
                """
                MATCH (n {project_id: $project_id})
                WHERE NOT (n)--()
                RETURN count(n) AS cnt
                """,
                {'project_id': project_id},
            )
            metrics['isolated_nodes'] = res[0]['cnt'] if res else 0
        except Exception:
            metrics['isolated_nodes'] = 0

        # Orphaned vulnerabilities (no FOUND_AT or HAS_VULNERABILITY edges)
        try:
            res = self.execute_query(
                """
                MATCH (v:Vulnerability {project_id: $project_id})
                WHERE NOT (v)-[:FOUND_AT]->()
                  AND NOT ()-[:HAS_VULNERABILITY]->(v)
                RETURN count(v) AS cnt
                """,
                {'project_id': project_id},
            )
            metrics['orphaned_vulnerabilities'] = res[0]['cnt'] if res else 0
        except Exception:
            metrics['orphaned_vulnerabilities'] = 0

        # Orphaned IPs (no HAS_PORT edges)
        try:
            res = self.execute_query(
                """
                MATCH (ip:IP {project_id: $project_id})
                WHERE NOT (ip)-[:HAS_PORT]->()
                RETURN count(ip) AS cnt
                """,
                {'project_id': project_id},
            )
            metrics['orphaned_ips'] = res[0]['cnt'] if res else 0
        except Exception:
            metrics['orphaned_ips'] = 0

        # Schema coverage: number of distinct node labels vs expected 24
        try:
            res = self.execute_query(
                """
                MATCH (n {project_id: $project_id})
                WITH labels(n) AS lbls
                UNWIND lbls AS lbl
                RETURN count(DISTINCT lbl) AS cnt
                """,
                {'project_id': project_id},
            )
            observed = res[0]['cnt'] if res else 0
            metrics['schema_coverage'] = round(observed / 24, 3)
        except Exception:
            metrics['schema_coverage'] = 0.0

        return metrics
    
    def health_check(self) -> Dict[str, Any]:
        """
        Check Neo4j database health
        
        Returns:
            Health status information
        """
        try:
            if not self.driver:
                return {'status': 'disconnected', 'healthy': False}
            
            # Try a simple query
            with self.driver.session(database=self.database) as session:
                result = session.run("RETURN 1 as test")
                record = result.single()
                
                if record and record['test'] == 1:
                    # Get database stats
                    stats_query = """
                    MATCH (n)
                    RETURN count(n) as node_count
                    """
                    stats = session.run(stats_query).single()
                    
                    return {
                        'status': 'healthy',
                        'healthy': True,
                        'node_count': stats['node_count'],
                        'database': self.database
                    }
                else:
                    return {'status': 'unhealthy', 'healthy': False}
                    
        except Exception as e:
            logger.error(f"Neo4j health check failed: {e}")
            return {
                'status': 'error',
                'healthy': False,
                'error': str(e)
            }


# Global Neo4j client instance
neo4j_client = Neo4jClient()


def get_neo4j_client() -> Neo4jClient:
    """Dependency injection for Neo4j client"""
    return neo4j_client
