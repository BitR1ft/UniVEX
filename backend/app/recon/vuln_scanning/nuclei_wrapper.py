"""
Nuclei Wrapper

Python wrapper for Nuclei vulnerability scanner with template management,
DAST fuzzing, and Interactsh integration.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
"""

import json
import subprocess
import logging
import tempfile
import os
from typing import List
from datetime import datetime

from .schemas import (
    VulnerabilityInfo,
    VulnSeverity,
    VulnCategory,
    NucleiConfig,
)

logger = logging.getLogger(__name__)


class NucleiWrapper:
    """
    Wrapper for Nuclei vulnerability scanner.
    
    Nuclei is a fast tool for configurable targeted scanning based on templates.
    This wrapper provides:
    - Template management and auto-updates
    - Severity and tag filtering
    - DAST mode with fuzzing
    - Interactsh integration for blind vulnerabilities
    - JSON output parsing
    """
    
    def __init__(self, config: NucleiConfig):
        """
        Initialize Nuclei wrapper.
        
        Args:
            config: Nuclei configuration
        """
        self.config = config
        self.temp_files = []  # Track temp files for cleanup
        self._verify_installation()
        
        if config.auto_update_templates:
            self._update_templates()
    
    def _verify_installation(self) -> None:
        """Verify Nuclei is installed and accessible."""
        try:
            result = subprocess.run(
                ["nuclei", "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                raise RuntimeError(f"Nuclei not working properly: {result.stderr}")
            logger.info(f"Nuclei version: {result.stdout.strip()}")
        except FileNotFoundError:
            raise RuntimeError(
                "Nuclei not found. Please install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Nuclei version check timed out")
    
    def _update_templates(self) -> None:
        """Update Nuclei templates to latest version."""
        logger.info("Updating Nuclei templates...")
        try:
            result = subprocess.run(
                ["nuclei", "-update-templates"],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes for template download
            )
            if result.returncode == 0:
                logger.info("Nuclei templates updated successfully")
            else:
                logger.warning(f"Template update failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.warning("Template update timed out")
        except Exception as e:
            logger.warning(f"Template update error: {e}")
    
    def _build_command(self, targets: List[str]) -> List[str]:
        """
        Build Nuclei command with all configured options.
        
        Args:
            targets: List of target URLs/domains
            
        Returns:
            Command as list of arguments
        """
        cmd = ["nuclei"]
        
        # Targets
        if len(targets) == 1:
            cmd.extend(["-u", targets[0]])
        else:
            # Create temporary file with targets
            targets_file = tempfile.NamedTemporaryFile(
                mode='w',
                delete=False,
                suffix='.txt'
            )
            targets_file.write('\n'.join(targets))
            targets_file.close()
            self.temp_files.append(targets_file.name)  # Track for cleanup
            cmd.extend(["-l", targets_file.name])
        
        # Templates
        if self.config.templates_path:
            cmd.extend(["-t", self.config.templates_path])
        elif self.config.template_folders:
            for folder in self.config.template_folders:
                cmd.extend(["-t", folder])
        
        # Severity filtering
        if self.config.severity_filter:
            severities = [s.value for s in self.config.severity_filter]
            cmd.extend(["-s", ",".join(severities)])
        
        # Tag filtering
        if self.config.include_tags:
            cmd.extend(["-tags", ",".join(self.config.include_tags)])
        if self.config.exclude_tags:
            cmd.extend(["-exclude-tags", ",".join(self.config.exclude_tags)])
        
        # DAST mode
        if self.config.dast_enabled:
            cmd.append("-dast")
            # Add fuzzing payloads if configured
            if self.config.fuzz_payloads:
                # Nuclei can accept custom payloads via template variables
                # This would require custom template generation
                logger.info("Custom DAST payloads configured")
        
        # Interactsh
        if self.config.interactsh_enabled:
            cmd.append("-interactsh")
            if self.config.interactsh_server:
                cmd.extend(["-interactsh-url", self.config.interactsh_server])
        
        # Performance settings
        cmd.extend(["-rate-limit", str(self.config.rate_limit)])
        cmd.extend(["-bulk-size", str(self.config.bulk_size)])
        cmd.extend(["-c", str(self.config.concurrency)])
        cmd.extend(["-timeout", str(self.config.timeout)])
        cmd.extend(["-retries", str(self.config.retries)])
        
        # Advanced options
        if self.config.headless_mode:
            cmd.append("-headless")
        
        if not self.config.follow_redirects:
            cmd.append("-no-follow-redirects")
        
        if self.config.custom_headers:
            for key, value in self.config.custom_headers.items():
                cmd.extend(["-H", f"{key}: {value}"])
        
        if self.config.proxy:
            cmd.extend(["-proxy", self.config.proxy])
        
        # Output format
        cmd.extend(["-json", "-silent"])
        
        # Include matched strings and curl commands
        cmd.append("-include-rr")  # Include request/response
        
        return cmd
    
    def _parse_nuclei_output(self, output: str) -> List[VulnerabilityInfo]:
        """
        Parse Nuclei JSON output into VulnerabilityInfo objects.
        
        Args:
            output: Nuclei JSON output (one JSON per line)
            
        Returns:
            List of VulnerabilityInfo objects
        """
        vulnerabilities = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                # Extract severity
                severity_map = {
                    "critical": VulnSeverity.CRITICAL,
                    "high": VulnSeverity.HIGH,
                    "medium": VulnSeverity.MEDIUM,
                    "low": VulnSeverity.LOW,
                    "info": VulnSeverity.INFO,
                }
                severity = severity_map.get(
                    data.get("info", {}).get("severity", "info").lower(),
                    VulnSeverity.INFO
                )
                
                # Extract category from tags
                category = self._infer_category(data.get("info", {}).get("tags", []))
                
                # Build vulnerability info
                vuln = VulnerabilityInfo(
                    id=f"nuclei-{data.get('template-id', 'unknown')}",
                    title=data.get("info", {}).get("name", "Unknown Vulnerability"),
                    description=data.get("info", {}).get("description", "No description available"),
                    severity=severity,
                    category=category,
                    source="nuclei",
                    template_id=data.get("template-id"),
                    matched_at=data.get("matched-at") or data.get("host"),
                    http_method=data.get("type", "").upper() if data.get("type") else None,
                    matched_string=data.get("matched-at"),
                    curl_command=data.get("curl-command"),
                    tags=data.get("info", {}).get("tags", []),
                    references=data.get("info", {}).get("reference", []),
                    remediation=data.get("info", {}).get("remediation"),
                    discovered_at=datetime.utcnow(),
                )
                
                # Extract request/response if available
                if "request" in data:
                    vuln.request = data["request"]
                if "response" in data:
                    vuln.response = data["response"][:500]  # Truncate large responses
                
                vulnerabilities.append(vuln)
                
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse Nuclei JSON: {e}")
            except Exception as e:
                logger.error(f"Error processing Nuclei result: {e}")
        
        return vulnerabilities
    
    def _infer_category(self, tags: List[str]) -> VulnCategory:
        """
        Infer vulnerability category from Nuclei tags.
        
        Args:
            tags: List of template tags
            
        Returns:
            Inferred category
        """
        tags_lower = [tag.lower() for tag in tags]
        
        # Map tags to categories
        category_map = {
            "cve": VulnCategory.CVE,
            "xss": VulnCategory.XSS,
            "sqli": VulnCategory.SQLI,
            "sql": VulnCategory.SQLI,
            "rce": VulnCategory.RCE,
            "lfi": VulnCategory.LFI,
            "rfi": VulnCategory.RFI,
            "ssrf": VulnCategory.SSRF,
            "ssti": VulnCategory.SSTI,
            "xxe": VulnCategory.XXE,
            "idor": VulnCategory.IDOR,
            "misconfig": VulnCategory.MISCONFIG,
            "config": VulnCategory.MISCONFIG,
            "exposure": VulnCategory.EXPOSURE,
            "disclosure": VulnCategory.EXPOSURE,
        }
        
        for tag in tags_lower:
            if tag in category_map:
                return category_map[tag]
        
        return VulnCategory.UNKNOWN
    
    def scan(self, targets: List[str]) -> List[VulnerabilityInfo]:
        """
        Run Nuclei scan on targets.
        
        Args:
            targets: List of target URLs or domains
            
        Returns:
            List of discovered vulnerabilities
            
        Raises:
            RuntimeError: If scan fails
        """
        logger.info(f"Starting Nuclei scan on {len(targets)} targets...")
        logger.info(f"Severity filter: {[s.value for s in self.config.severity_filter]}")
        
        cmd = self._build_command(targets)
        logger.debug(f"Nuclei command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout * len(targets) + 60  # Extra buffer
            )
            
            # Nuclei returns exit code 1 if vulnerabilities found (not an error)
            if result.returncode not in [0, 1]:
                logger.error(f"Nuclei scan failed: {result.stderr}")
                raise RuntimeError(f"Nuclei scan failed: {result.stderr}")
            
            # Parse output
            vulnerabilities = self._parse_nuclei_output(result.stdout)
            
            logger.info(f"Nuclei scan completed: {len(vulnerabilities)} vulnerabilities found")
            
            return vulnerabilities
            
        except subprocess.TimeoutExpired:
            error_msg = f"Nuclei scan timed out after {self.config.timeout * len(targets)} seconds"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        except Exception as e:
            logger.error(f"Nuclei scan error: {e}")
            raise
        finally:
            # Clean up all temporary files
            for temp_file in self.temp_files:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            self.temp_files.clear()
    
    def get_templates_count(self) -> int:
        """
        Get count of available Nuclei templates.
        
        Returns:
            Number of templates
        """
        try:
            result = subprocess.run(
                ["nuclei", "-tl"],
                capture_output=True,
                text=True,
                timeout=10
            )
            # Count lines in output
            return len([ln for ln in result.stdout.split('\n') if ln.strip()])
        except Exception as e:
            logger.warning(f"Failed to count templates: {e}")
            return 0
