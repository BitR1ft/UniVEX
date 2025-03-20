"""
Technology Detector Module - Month 5

Detects web technologies using httpx built-in detection.
Merges results from multiple sources for comprehensive technology fingerprinting.
"""

import re
from typing import List, Dict, Optional
import logging

from .schemas import TechnologyInfo

logger = logging.getLogger(__name__)


class TechDetector:
    """
    Technology detection using httpx's built-in tech-detect feature.
    
    Detects:
    - Web frameworks (React, Vue, Angular, Django, etc.)
    - CMS platforms (WordPress, Drupal, Joomla, etc.)
    - Web servers (Apache, Nginx, IIS, etc.)
    - JavaScript libraries
    - Analytics tools
    - CDN services
    """
    
    def __init__(self):
        """Initialize technology detector"""
        self.confidence_threshold = 50  # Minimum confidence to include
    
    async def detect_from_httpx(
        self,
        url: str,
        httpx_output: Dict
    ) -> List[TechnologyInfo]:
        """
        Extract technology detections from httpx output.
        
        Args:
            url: Target URL
            httpx_output: Parsed httpx JSON output
            
        Returns:
            List of detected technologies
        """
        technologies = []
        
        try:
            # Extract tech-detect results from httpx
            tech_data = httpx_output.get('technologies', [])
            
            for tech in tech_data:
                if isinstance(tech, str):
                    # Simple string format
                    tech_info = TechnologyInfo(
                        name=tech,
                        category="Unknown",
                        confidence=80,
                        source="httpx"
                    )
                elif isinstance(tech, dict):
                    # Dictionary format with more details
                    tech_info = TechnologyInfo(
                        name=tech.get('name', 'Unknown'),
                        version=tech.get('version'),
                        category=tech.get('category', 'Unknown'),
                        confidence=tech.get('confidence', 80),
                        source="httpx",
                        website=tech.get('website')
                    )
                else:
                    continue
                
                technologies.append(tech_info)
            
            # Also detect from headers
            headers_tech = self._detect_from_headers(httpx_output.get('header', {}))
            technologies.extend(headers_tech)
            
            # Detect from server header
            server_tech = self._detect_from_server(httpx_output.get('webserver'))
            if server_tech:
                technologies.append(server_tech)
            
            return self._deduplicate_technologies(technologies)
            
        except Exception as e:
            logger.error(f"Technology detection failed for {url}: {e}")
            return []
    
    def _detect_from_headers(self, headers: Dict[str, str]) -> List[TechnologyInfo]:
        """Detect technologies from HTTP headers"""
        technologies = []
        
        # X-Powered-By header
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            tech = self._parse_powered_by(powered_by)
            if tech:
                technologies.append(tech)
        
        # X-Generator header
        generator = headers.get('X-Generator', '')
        if generator:
            technologies.append(TechnologyInfo(
                name=generator,
                category="CMS",
                confidence=90,
                source="httpx"
            ))
        
        # X-AspNet-Version
        aspnet = headers.get('X-AspNet-Version', '')
        if aspnet:
            technologies.append(TechnologyInfo(
                name="ASP.NET",
                version=aspnet,
                category="Web Framework",
                confidence=100,
                source="httpx"
            ))
        
        # X-Drupal-Cache
        if 'X-Drupal-Cache' in headers or 'X-Drupal-Dynamic-Cache' in headers:
            technologies.append(TechnologyInfo(
                name="Drupal",
                category="CMS",
                confidence=100,
                source="httpx"
            ))
        
        # Via header (proxies/CDN)
        via = headers.get('Via', '')
        if via:
            # Parse via header for CDN/proxy info
            if 'cloudflare' in via.lower():
                technologies.append(TechnologyInfo(
                    name="Cloudflare",
                    category="CDN",
                    confidence=100,
                    source="httpx"
                ))
        
        return technologies
    
    def _parse_powered_by(self, powered_by: str) -> Optional[TechnologyInfo]:
        """Parse X-Powered-By header"""
        # Common formats:
        # "PHP/7.4.3"
        # "ASP.NET"
        # "Express"
        
        # Try to extract name and version
        match = re.match(r'^([A-Za-z.-]+)(?:/([0-9.]+))?', powered_by)
        if match:
            name = match.group(1)
            version = match.group(2)
            
            # Determine category
            category = "Unknown"
            if name.upper() == "PHP":
                category = "Programming Language"
            elif "ASP" in name.upper():
                category = "Web Framework"
            elif name.lower() in ['express', 'koa', 'fastify']:
                category = "Web Framework"
            
            return TechnologyInfo(
                name=name,
                version=version,
                category=category,
                confidence=95,
                source="httpx"
            )
        
        return None
    
    def _detect_from_server(self, server: Optional[str]) -> Optional[TechnologyInfo]:
        """Detect web server from Server header"""
        if not server:
            return None
        
        # Parse server string (e.g., "nginx/1.18.0", "Apache/2.4.41 (Ubuntu)")
        match = re.match(r'^([A-Za-z-]+)(?:/([0-9.]+))?', server)
        if match:
            name = match.group(1)
            version = match.group(2)
            
            return TechnologyInfo(
                name=name,
                version=version,
                category="Web Server",
                confidence=100,
                source="httpx"
            )
        
        return None
    
    def _deduplicate_technologies(self, technologies: List[TechnologyInfo]) -> List[TechnologyInfo]:
        """
        Remove duplicate technologies, keeping the one with highest confidence.
        
        Args:
            technologies: List of detected technologies
            
        Returns:
            Deduplicated list
        """
        # Group by name
        tech_map = {}
        
        for tech in technologies:
            key = tech.name.lower()
            
            if key not in tech_map:
                tech_map[key] = tech
            else:
                # Keep the one with higher confidence
                if tech.confidence > tech_map[key].confidence:
                    tech_map[key] = tech
                # If same confidence but one has version, prefer that
                elif tech.confidence == tech_map[key].confidence and tech.version and not tech_map[key].version:
                    tech_map[key] = tech
        
        return list(tech_map.values())
    
    def merge_technologies(
        self,
        httpx_techs: List[TechnologyInfo],
        wappalyzer_techs: List[TechnologyInfo]
    ) -> List[TechnologyInfo]:
        """
        Merge technologies from httpx and Wappalyzer.
        
        Args:
            httpx_techs: Technologies from httpx
            wappalyzer_techs: Technologies from Wappalyzer
            
        Returns:
            Merged and deduplicated list
        """
        all_techs = httpx_techs + wappalyzer_techs
        return self._deduplicate_technologies(all_techs)
