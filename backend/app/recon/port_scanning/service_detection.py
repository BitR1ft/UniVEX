"""
Service Detection Module

Provides service identification using:
1. Nmap service detection
2. IANA service name mapping
3. Version extraction from banners
"""
import asyncio
import logging
import xml.etree.ElementTree as ET
import shutil
from typing import List, Optional, Dict

from .schemas import ServiceInfo, PortInfo

logger = logging.getLogger(__name__)


class ServiceDetector:
    """
    Service detection using Nmap and IANA registry
    """
    
    def __init__(self):
        """Initialize service detector"""
        self.iana_services = self._load_iana_services()
        self.nmap_available = self._check_nmap_installed()
    
    def _check_nmap_installed(self) -> bool:
        """Check if Nmap is installed"""
        return shutil.which("nmap") is not None
    
    def _load_iana_services(self) -> Dict[int, str]:
        """
        Load IANA service name mappings
        
        Common port-to-service mappings based on IANA registry
        """
        # Common service mappings (subset of IANA registry)
        services = {
            20: "ftp-data",
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "microsoft-ds",
            465: "smtps",
            587: "submission",
            993: "imaps",
            995: "pop3s",
            1433: "ms-sql-s",
            1521: "oracle",
            3306: "mysql",
            3389: "ms-wbt-server",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            8080: "http-proxy",
            8443: "https-alt",
            27017: "mongodb",
            # Add more as needed
        }
        return services
    
    def get_service_name(self, port: int) -> Optional[str]:
        """
        Get service name from IANA registry
        
        Args:
            port: Port number
            
        Returns:
            Service name if known, None otherwise
        """
        return self.iana_services.get(port)
    
    async def detect_services_nmap(
        self,
        target: str,
        ports: List[int],
        timeout: int = 30
    ) -> List[ServiceInfo]:
        """
        Detect services using Nmap
        
        Args:
            target: IP address or hostname
            ports: List of ports to scan
            timeout: Scan timeout in seconds
            
        Returns:
            List of ServiceInfo objects
        """
        if not self.nmap_available:
            logger.warning("Nmap is not installed. Using IANA mapping only.")
            return [
                ServiceInfo(
                    port=port,
                    service_name=self.get_service_name(port)
                )
                for port in ports
            ]
        
        if not ports:
            return []
        
        try:
            # Build Nmap command
            port_list = ",".join(map(str, ports))
            cmd = [
                "nmap",
                "-sV",  # Service version detection
                "-p", port_list,
                "--version-intensity", "5",
                "-oX", "-",  # XML output to stdout
                "--host-timeout", f"{timeout}s",
                target
            ]
            
            logger.info(f"Running Nmap service detection on {target}")
            
            # Run Nmap
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Nmap scan failed: {stderr.decode()}")
                return self._fallback_to_iana(ports)
            
            # Parse XML output
            services = self._parse_nmap_xml(stdout.decode())
            
            # Fill in missing services with IANA mapping
            detected_ports = {s.port for s in services}
            for port in ports:
                if port not in detected_ports:
                    service_name = self.get_service_name(port)
                    if service_name:
                        services.append(
                            ServiceInfo(
                                port=port,
                                service_name=service_name
                            )
                        )
            
            return services
            
        except Exception as e:
            logger.error(f"Error in Nmap service detection: {str(e)}")
            return self._fallback_to_iana(ports)
    
    def _parse_nmap_xml(self, xml_output: str) -> List[ServiceInfo]:
        """
        Parse Nmap XML output
        
        Args:
            xml_output: XML string from Nmap
            
        Returns:
            List of ServiceInfo objects
        """
        services = []
        
        try:
            root = ET.fromstring(xml_output)
            
            # Find all port elements
            for port_elem in root.findall(".//port"):
                port_id = int(port_elem.get("portid"))
                protocol = port_elem.get("protocol", "tcp")
                
                # Get state
                state_elem = port_elem.find("state")
                state = state_elem.get("state") if state_elem is not None else "unknown"
                
                if state != "open":
                    continue
                
                # Get service info
                service_elem = port_elem.find("service")
                if service_elem is not None:
                    service_info = ServiceInfo(
                        port=port_id,
                        protocol=protocol,
                        service_name=service_elem.get("name"),
                        product=service_elem.get("product"),
                        version=service_elem.get("version"),
                        cpe=service_elem.get("cpe"),
                        confidence=int(service_elem.get("conf", 0))
                    )
                    services.append(service_info)
                else:
                    # No service detected, use IANA
                    service_name = self.get_service_name(port_id)
                    services.append(
                        ServiceInfo(
                            port=port_id,
                            protocol=protocol,
                            service_name=service_name
                        )
                    )
            
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {str(e)}")
        except Exception as e:
            logger.error(f"Error parsing Nmap output: {str(e)}")
        
        return services
    
    def _fallback_to_iana(self, ports: List[int]) -> List[ServiceInfo]:
        """
        Fallback to IANA service mapping
        
        Args:
            ports: List of ports
            
        Returns:
            List of ServiceInfo with IANA names
        """
        return [
            ServiceInfo(
                port=port,
                service_name=self.get_service_name(port)
            )
            for port in ports
        ]
    
    async def enrich_ports_with_services(
        self,
        target: str,
        ports: List[PortInfo]
    ) -> List[PortInfo]:
        """
        Enrich port information with service detection
        
        Args:
            target: IP address or hostname
            ports: List of PortInfo objects
            
        Returns:
            Enriched list of PortInfo with service information
        """
        if not ports:
            return ports
        
        # Extract port numbers
        port_numbers = [p.port for p in ports]
        
        # Detect services
        services = await self.detect_services_nmap(target, port_numbers)
        
        # Create service lookup
        service_lookup = {s.port: s for s in services}
        
        # Enrich ports
        for port_info in ports:
            if port_info.port in service_lookup:
                port_info.service = service_lookup[port_info.port]
        
        return ports
