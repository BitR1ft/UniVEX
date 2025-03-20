"""
MITRE Mapper Module

Maps CVEs to CWE (Common Weakness Enumeration) and CAPEC (Common Attack Pattern
Enumeration and Classification) using the MITRE database.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from .schemas import CWEInfo, CAPECInfo, MITREData, MITREConfig

logger = logging.getLogger(__name__)


class MITREMapper:
    """
    MITRE ATT&CK framework mapper.
    
    Provides:
    - CVE to CWE mapping
    - CWE to CAPEC mapping
    - CWE hierarchy extraction
    - CAPEC attack pattern details
    - Database auto-updates
    """
    
    # API endpoints for MITRE data
    CWE_API = "https://cwe.mitre.org/data/definitions/{cwe_id}.html"
    CAPEC_API = "https://capec.mitre.org/data/definitions/{capec_id}.html"
    
    def __init__(self, config: MITREConfig):
        """
        Initialize MITRE mapper.
        
        Args:
            config: MITRE mapping configuration
        """
        self.config = config
        self.db_path = Path(config.db_path) if config.db_path else Path.home() / ".univex" / "mitre_db"
        self.db_path.mkdir(parents=True, exist_ok=True)
        
        # In-memory databases
        self.cve_to_cwe: Dict[str, List[str]] = {}
        self.cwe_to_capec: Dict[str, List[str]] = {}
        self.cwe_data: Dict[str, Dict] = {}
        self.capec_data: Dict[str, Dict] = {}
        
        # Load databases
        self._load_databases()
        
        if config.auto_update_db:
            self._update_databases()
    
    def _load_databases(self) -> None:
        """Load MITRE databases from local files."""
        try:
            # Load CVE to CWE mappings
            cve_cwe_file = self.db_path / "cve_to_cwe.json"
            if cve_cwe_file.exists():
                with open(cve_cwe_file, 'r') as f:
                    self.cve_to_cwe = json.load(f)
                logger.info(f"Loaded {len(self.cve_to_cwe)} CVE to CWE mappings")
            
            # Load CWE to CAPEC mappings
            cwe_capec_file = self.db_path / "cwe_to_capec.json"
            if cwe_capec_file.exists():
                with open(cwe_capec_file, 'r') as f:
                    self.cwe_to_capec = json.load(f)
                logger.info(f"Loaded {len(self.cwe_to_capec)} CWE to CAPEC mappings")
            
            # Load CWE details
            cwe_data_file = self.db_path / "cwe_data.json"
            if cwe_data_file.exists():
                with open(cwe_data_file, 'r') as f:
                    self.cwe_data = json.load(f)
                logger.info(f"Loaded {len(self.cwe_data)} CWE definitions")
            
            # Load CAPEC details
            capec_data_file = self.db_path / "capec_data.json"
            if capec_data_file.exists():
                with open(capec_data_file, 'r') as f:
                    self.capec_data = json.load(f)
                logger.info(f"Loaded {len(self.capec_data)} CAPEC definitions")
                
        except Exception as e:
            logger.warning(f"Failed to load MITRE databases: {e}")
    
    def _update_databases(self) -> None:
        """
        Update MITRE databases from online sources.
        
        Note: In a production system, this would download and parse official
        MITRE XML/JSON feeds. For this implementation, we'll use a simplified
        approach with common mappings.
        """
        logger.info("Updating MITRE databases...")
        
        try:
            # Initialize with common CVE to CWE mappings
            # In production, this would be downloaded from NVD API or MITRE
            self._initialize_common_mappings()
            
            # Save to disk
            self._save_databases()
            
            logger.info("MITRE databases updated successfully")
            
        except Exception as e:
            logger.error(f"Failed to update MITRE databases: {e}")
    
    def _initialize_common_mappings(self) -> None:
        """
        Initialize common CWE and CAPEC mappings.
        This is a simplified version - production would use official MITRE data.
        """
        # Common CWE data
        self.cwe_data = {
            "CWE-79": {
                "name": "Cross-site Scripting (XSS)",
                "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
                "parent": "CWE-74",
                "abstraction": "Base"
            },
            "CWE-89": {
                "name": "SQL Injection",
                "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.",
                "parent": "CWE-943",
                "abstraction": "Base"
            },
            "CWE-78": {
                "name": "OS Command Injection",
                "description": "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.",
                "parent": "CWE-74",
                "abstraction": "Base"
            },
            "CWE-22": {
                "name": "Path Traversal",
                "description": "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname.",
                "parent": "CWE-706",
                "abstraction": "Base"
            },
            "CWE-94": {
                "name": "Code Injection",
                "description": "The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.",
                "parent": "CWE-913",
                "abstraction": "Base"
            },
            "CWE-918": {
                "name": "Server-Side Request Forgery (SSRF)",
                "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
                "parent": "CWE-441",
                "abstraction": "Base"
            },
            "CWE-611": {
                "name": "XML External Entity (XXE)",
                "description": "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control, causing the product to embed incorrect documents into its output.",
                "parent": "CWE-827",
                "abstraction": "Variant"
            },
            "CWE-287": {
                "name": "Improper Authentication",
                "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
                "parent": "CWE-284",
                "abstraction": "Class"
            },
            "CWE-200": {
                "name": "Information Exposure",
                "description": "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
                "parent": "CWE-668",
                "abstraction": "Class"
            },
            "CWE-16": {
                "name": "Configuration",
                "description": "Weaknesses in this category are typically introduced during the configuration of the software.",
                "parent": "CWE-710",
                "abstraction": "Class"
            }
        }
        
        # CWE to CAPEC mappings
        self.cwe_to_capec = {
            "CWE-79": ["CAPEC-18", "CAPEC-86", "CAPEC-209"],
            "CWE-89": ["CAPEC-66", "CAPEC-7", "CAPEC-108"],
            "CWE-78": ["CAPEC-88", "CAPEC-9"],
            "CWE-22": ["CAPEC-126", "CAPEC-64"],
            "CWE-94": ["CAPEC-242", "CAPEC-35"],
            "CWE-918": ["CAPEC-664"],
            "CWE-611": ["CAPEC-221"],
            "CWE-287": ["CAPEC-114", "CAPEC-115"],
            "CWE-200": ["CAPEC-116", "CAPEC-169"],
            "CWE-16": ["CAPEC-1", "CAPEC-203"]
        }
        
        # CAPEC data
        self.capec_data = {
            "CAPEC-18": {
                "name": "XSS Targeting Non-Script Elements",
                "description": "An adversary uses XSS to render exploit code in the target's browser",
                "likelihood": "High",
                "severity": "High",
                "prerequisites": ["Target application does not sanitize user input"],
                "execution_flow": "1. Survey application\n2. Identify injection point\n3. Craft malicious payload\n4. Execute attack",
                "mitigations": ["Input validation", "Output encoding", "CSP headers"],
                "examples": ["Reflected XSS", "Stored XSS"],
                "references": ["https://capec.mitre.org/data/definitions/18.html"]
            },
            "CAPEC-66": {
                "name": "SQL Injection",
                "description": "An adversary uses SQL injection to manipulate database queries",
                "likelihood": "High",
                "severity": "Very High",
                "prerequisites": ["Application uses SQL database", "User input not sanitized"],
                "execution_flow": "1. Identify SQL injection point\n2. Fingerprint database\n3. Extract data",
                "mitigations": ["Parameterized queries", "Input validation", "Least privilege"],
                "examples": ["UNION-based SQLi", "Blind SQLi"],
                "references": ["https://capec.mitre.org/data/definitions/66.html"]
            },
            "CAPEC-88": {
                "name": "OS Command Injection",
                "description": "An adversary injects OS commands through vulnerable application input",
                "likelihood": "Medium",
                "severity": "Very High",
                "prerequisites": ["Application executes OS commands", "Insufficient input validation"],
                "execution_flow": "1. Identify command execution\n2. Inject command separators\n3. Execute arbitrary commands",
                "mitigations": ["Avoid OS commands", "Input validation", "Sandboxing"],
                "examples": ["Shell command injection", "Path manipulation"],
                "references": ["https://capec.mitre.org/data/definitions/88.html"]
            },
            "CAPEC-126": {
                "name": "Path Traversal",
                "description": "An adversary uses path traversal to access files outside intended directory",
                "likelihood": "High",
                "severity": "High",
                "prerequisites": ["Application accesses files based on user input"],
                "execution_flow": "1. Identify file access functionality\n2. Inject ../ sequences\n3. Access restricted files",
                "mitigations": ["Path canonicalization", "Whitelist validation", "Chroot jail"],
                "examples": ["../../../etc/passwd", "Directory traversal"],
                "references": ["https://capec.mitre.org/data/definitions/126.html"]
            },
            "CAPEC-664": {
                "name": "Server Side Request Forgery",
                "description": "An adversary exploits SSRF to make requests from server context",
                "likelihood": "Medium",
                "severity": "High",
                "prerequisites": ["Application makes requests based on user input"],
                "execution_flow": "1. Identify URL parameter\n2. Craft internal URL\n3. Access internal resources",
                "mitigations": ["URL validation", "Whitelist", "Network segmentation"],
                "examples": ["Internal port scan", "Cloud metadata access"],
                "references": ["https://capec.mitre.org/data/definitions/664.html"]
            }
        }
    
    def _save_databases(self) -> None:
        """Save MITRE databases to local files."""
        try:
            # Save CVE to CWE
            with open(self.db_path / "cve_to_cwe.json", 'w') as f:
                json.dump(self.cve_to_cwe, f, indent=2)
            
            # Save CWE to CAPEC
            with open(self.db_path / "cwe_to_capec.json", 'w') as f:
                json.dump(self.cwe_to_capec, f, indent=2)
            
            # Save CWE data
            with open(self.db_path / "cwe_data.json", 'w') as f:
                json.dump(self.cwe_data, f, indent=2)
            
            # Save CAPEC data
            with open(self.db_path / "capec_data.json", 'w') as f:
                json.dump(self.capec_data, f, indent=2)
            
            logger.debug("MITRE databases saved to disk")
            
        except Exception as e:
            logger.error(f"Failed to save MITRE databases: {e}")
    
    def map_cve_to_mitre(self, cve_id: str, cwe_ids: Optional[List[str]] = None) -> Optional[MITREData]:
        """
        Map a CVE to MITRE CWE and CAPEC.
        
        Args:
            cve_id: CVE identifier
            cwe_ids: Optional list of CWE IDs. If a single string is passed, it will be converted to a list.
            
        Returns:
            MITRE data with CWE and CAPEC information
        """
        if not self.config.enabled:
            return None
        
        # Normalize cwe_ids to list
        if cwe_ids is None:
            cwe_ids = self.cve_to_cwe.get(cve_id, [])
        elif isinstance(cwe_ids, str):
            cwe_ids = [cwe_ids]
        
        if not cwe_ids:
            logger.debug(f"No CWE mapping found for {cve_id}")
            return None
        
        # Use first CWE (primary weakness)
        cwe_id = cwe_ids[0] if isinstance(cwe_ids, list) else cwe_ids
        
        # Get CWE information
        cwe_info = self._get_cwe_info(cwe_id)
        
        # Get CAPEC patterns
        capec_list = []
        if self.config.cwe_to_capec:
            capec_ids = self.cwe_to_capec.get(cwe_id, [])
            for capec_id in capec_ids:
                capec_info = self._get_capec_info(capec_id)
                if capec_info:
                    capec_list.append(capec_info)
        
        if not cwe_info and not capec_list:
            return None
        
        return MITREData(cwe=cwe_info, capec=capec_list)
    
    def _get_cwe_info(self, cwe_id: str) -> Optional[CWEInfo]:
        """
        Get CWE information.
        
        Args:
            cwe_id: CWE identifier (e.g., CWE-79)
            
        Returns:
            CWE information or None
        """
        # Normalize CWE ID
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        
        data = self.cwe_data.get(cwe_id)
        if not data:
            logger.debug(f"No data found for {cwe_id}")
            return None
        
        return CWEInfo(
            cwe_id=cwe_id,
            cwe_name=data.get("name", ""),
            description=data.get("description"),
            parent_cwe=data.get("parent"),
            abstraction_level=data.get("abstraction")
        )
    
    def _get_capec_info(self, capec_id: str) -> Optional[CAPECInfo]:
        """
        Get CAPEC information.
        
        Args:
            capec_id: CAPEC identifier (e.g., CAPEC-18)
            
        Returns:
            CAPEC information or None
        """
        # Normalize CAPEC ID
        if not capec_id.startswith("CAPEC-"):
            capec_id = f"CAPEC-{capec_id}"
        
        data = self.capec_data.get(capec_id)
        if not data:
            logger.debug(f"No data found for {capec_id}")
            return None
        
        return CAPECInfo(
            capec_id=capec_id,
            capec_name=data.get("name", ""),
            description=data.get("description"),
            likelihood=data.get("likelihood"),
            severity=data.get("severity"),
            prerequisites=data.get("prerequisites", []),
            execution_flow=data.get("execution_flow"),
            mitigations=data.get("mitigations", []),
            examples=data.get("examples", []),
            references=data.get("references", [])
        )
    
    def get_cwe_by_category(self, category: str) -> List[str]:
        """
        Get CWE IDs by vulnerability category.
        
        Args:
            category: Vulnerability category (xss, sqli, etc.)
            
        Returns:
            List of relevant CWE IDs
        """
        category_map = {
            "xss": ["CWE-79"],
            "sqli": ["CWE-89"],
            "sql": ["CWE-89"],
            "rce": ["CWE-78", "CWE-94"],
            "lfi": ["CWE-22"],
            "rfi": ["CWE-98"],
            "ssrf": ["CWE-918"],
            "xxe": ["CWE-611"],
            "ssti": ["CWE-94"],
            "auth_bypass": ["CWE-287"],
            "idor": ["CWE-639"],
            "misconfig": ["CWE-16"],
            "exposure": ["CWE-200"]
        }
        
        return category_map.get(category.lower(), [])
