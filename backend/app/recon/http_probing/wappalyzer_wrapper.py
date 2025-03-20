"""
Wappalyzer Wrapper Module - Month 5

Integrates Wappalyzer for comprehensive web technology detection.
Wappalyzer has 6,000+ technology fingerprints.
"""

import asyncio
import subprocess
import json
import tempfile
import os
from typing import List, Optional
import logging
import httpx

from .schemas import TechnologyInfo

logger = logging.getLogger(__name__)


class WappalyzerWrapper:
    """
    Wrapper for Wappalyzer CLI tool.
    
    Wappalyzer detects:
    - CMS (WordPress, Drupal, Joomla, etc.)
    - Frameworks (React, Vue, Angular, Django, Laravel, etc.)
    - JavaScript libraries (jQuery, Lodash, etc.)
    - Analytics (Google Analytics, Mixpanel, etc.)
    - Advertising networks
    - Payment processors
    - Tag managers
    - And 6,000+ more technologies
    """
    
    def __init__(self, timeout: int = 30):
        """
        Initialize Wappalyzer wrapper.
        
        Args:
            timeout: Request timeout for fetching HTML
        """
        self.timeout = timeout
        self.wappalyzer_available = self._check_wappalyzer()
    
    def _check_wappalyzer(self) -> bool:
        """Check if Wappalyzer is installed"""
        try:
            result = subprocess.run(
                ["wappalyzer", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.warning("Wappalyzer not found. Install with: npm install -g wappalyzer")
            return False
    
    async def detect(self, url: str) -> List[TechnologyInfo]:
        """
        Detect technologies using Wappalyzer.
        
        Args:
            url: Target URL to analyze
            
        Returns:
            List of detected technologies
        """
        if not self.wappalyzer_available:
            logger.debug("Wappalyzer not available, skipping")
            return []
        
        try:
            # Fetch HTML content
            html_content = await self._fetch_html(url)
            if not html_content:
                return []
            
            # Run Wappalyzer analysis
            result = await self._run_wappalyzer(url, html_content)
            
            if result:
                return self._parse_wappalyzer_output(result)
            
            return []
            
        except Exception as e:
            logger.error(f"Wappalyzer detection failed for {url}: {e}")
            return []
    
    async def _fetch_html(self, url: str) -> Optional[str]:
        """Fetch HTML content from URL"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(url)
                response.raise_for_status()
                return response.text
        except Exception as e:
            logger.error(f"Failed to fetch HTML from {url}: {e}")
            return None
    
    async def _run_wappalyzer(self, url: str, html_content: str) -> Optional[str]:
        """
        Run Wappalyzer CLI on HTML content.
        
        Args:
            url: Target URL
            html_content: HTML content to analyze
            
        Returns:
            Wappalyzer JSON output
        """
        try:
            # Create temporary file with HTML content
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
                f.write(html_content)
                temp_file = f.name
            
            try:
                # Run wappalyzer command
                cmd = [
                    "wappalyzer",
                    url,
                    "--pretty",
                ]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout
                )
                
                if process.returncode != 0:
                    logger.error(f"Wappalyzer error: {stderr.decode()}")
                    return None
                
                return stdout.decode()
                
            finally:
                # Clean up temp file
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
                    
        except asyncio.TimeoutError:
            logger.error(f"Wappalyzer timeout for {url}")
            return None
        except Exception as e:
            logger.error(f"Wappalyzer execution error: {e}")
            return None
    
    def _parse_wappalyzer_output(self, output: str) -> List[TechnologyInfo]:
        """
        Parse Wappalyzer JSON output.
        
        Args:
            output: Wappalyzer JSON output
            
        Returns:
            List of TechnologyInfo objects
        """
        technologies = []
        
        try:
            data = json.loads(output)
            
            # Wappalyzer output format:
            # {
            #   "urls": {
            #     "https://example.com": {
            #       "technologies": [
            #         {
            #           "name": "WordPress",
            #           "version": "5.8",
            #           "categories": [{"id": 1, "name": "CMS"}],
            #           "confidence": 100,
            #           "icon": "WordPress.svg",
            #           "website": "https://wordpress.org"
            #         }
            #       ]
            #     }
            #   }
            # }
            
            for url_data in data.get('urls', {}).values():
                for tech in url_data.get('technologies', []):
                    # Extract category names
                    categories = [cat.get('name', 'Unknown') for cat in tech.get('categories', [])]
                    category = categories[0] if categories else "Unknown"
                    
                    tech_info = TechnologyInfo(
                        name=tech.get('name', 'Unknown'),
                        version=tech.get('version'),
                        category=category,
                        confidence=tech.get('confidence', 100),
                        source="wappalyzer",
                        website=tech.get('website'),
                        icon=tech.get('icon'),
                        cpe=tech.get('cpe')
                    )
                    
                    technologies.append(tech_info)
            
            return technologies
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Wappalyzer JSON: {e}")
            return []
        except Exception as e:
            logger.error(f"Error parsing Wappalyzer output: {e}")
            return []
    
    async def update_database(self) -> bool:
        """
        Update Wappalyzer fingerprint database.
        
        Returns:
            True if update successful
        """
        try:
            logger.info("Updating Wappalyzer database...")
            
            # Wappalyzer auto-updates via npm, but we can force reinstall
            process = await asyncio.create_subprocess_shell(
                "npm update -g wappalyzer",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=120  # 2 minutes for npm update
            )
            
            if process.returncode == 0:
                logger.info("Wappalyzer database updated successfully")
                return True
            else:
                logger.error(f"Wappalyzer update failed: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to update Wappalyzer: {e}")
            return False
