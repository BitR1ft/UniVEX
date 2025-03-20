"""
Kiterunner Wrapper

Python wrapper for Kiterunner API endpoint discovery through brute-forcing.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
"""

import subprocess
import json
import logging
from typing import List, Optional
from urllib.parse import urlparse

from .schemas import EndpointInfo, ParameterInfo, EndpointCategory, ParameterType

logger = logging.getLogger(__name__)


class KiterunnerWrapper:
    """
    Wrapper for Kiterunner API endpoint discovery tool.
    
    Kiterunner performs context-based API endpoint brute-forcing.
    """
    
    def __init__(
        self,
        wordlist: str = "routes-large",
        threads: int = 10,
        rate_limit: int = 100,
        timeout: int = 300
    ):
        """
        Initialize Kiterunner wrapper.
        
        Args:
            wordlist: Wordlist to use (routes-large, routes-small, or custom path)
            threads: Number of threads
            rate_limit: Requests per second
            timeout: Timeout in seconds
        """
        self.wordlist = wordlist
        self.threads = min(threads, 50)  # Cap at 50 threads
        self.rate_limit = rate_limit
        self.timeout = timeout
        
        # Verify Kiterunner is installed
        self._verify_installation()
    
    def _verify_installation(self) -> None:
        """Verify that Kiterunner is installed and accessible."""
        try:
            result = subprocess.run(
                ["kr", "version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"Kiterunner version: {result.stdout.strip()}")
            else:
                logger.warning("Kiterunner not found or not working properly")
        except FileNotFoundError:
            logger.error("Kiterunner (kr) is not installed or not in PATH")
        except Exception as e:
            logger.error(f"Error verifying Kiterunner installation: {e}")
    
    def scan(self, targets: List[str]) -> List[EndpointInfo]:
        """
        Scan targets for API endpoints using Kiterunner.
        
        Args:
            targets: List of base URLs to scan
            
        Returns:
            List of discovered endpoints
        """
        logger.info(f"Starting Kiterunner scan of {len(targets)} target(s)")
        
        all_endpoints = []
        
        for target in targets[:10]:  # Limit to 10 targets
            target_endpoints = self._scan_target(target)
            all_endpoints.extend(target_endpoints)
        
        logger.info(f"Kiterunner discovered {len(all_endpoints)} endpoints")
        return all_endpoints
    
    def _scan_target(self, target: str) -> List[EndpointInfo]:
        """
        Scan a single target.
        
        Args:
            target: Base URL to scan
            
        Returns:
            List of discovered endpoints
        """
        # Build Kiterunner command
        cmd = self._build_command(target)
        
        try:
            # Execute Kiterunner
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # Kiterunner may return non-zero even on success, check output
            if result.stdout:
                # Parse output
                endpoints = self._parse_output(result.stdout)
                logger.debug(f"Kiterunner found {len(endpoints)} endpoints for {target}")
                return endpoints
            else:
                logger.debug(f"Kiterunner found no endpoints for {target}")
                return []
            
        except subprocess.TimeoutExpired:
            logger.error(f"Kiterunner timeout for {target} after {self.timeout}s")
            return []
        except Exception as e:
            logger.error(f"Kiterunner execution error for {target}: {e}")
            return []
    
    def _build_command(self, target: str) -> List[str]:
        """
        Build Kiterunner command.
        
        Args:
            target: Target URL
            
        Returns:
            Command as list of arguments
        """
        cmd = [
            "kr",
            "brute",
            target,
        ]
        
        # Add wordlist
        if self.wordlist == "routes-large":
            cmd.extend(["-w", "/usr/share/kiterunner/routes-large.kite"])
        elif self.wordlist == "routes-small":
            cmd.extend(["-w", "/usr/share/kiterunner/routes-small.kite"])
        else:
            # Custom wordlist path
            cmd.extend(["-w", self.wordlist])
        
        # Add configuration
        cmd.extend([
            "-x", str(self.threads),  # Threads
            "-j", "100",  # Delay between requests (ms)
            "--fail-status-codes", "404,400,401,403,429,500,502,503",  # Filter noise
            "-o", "json",  # JSON output
        ])
        
        logger.debug(f"Kiterunner command: {' '.join(cmd)}")
        return cmd
    
    def _parse_output(self, output: str) -> List[EndpointInfo]:
        """
        Parse Kiterunner output.
        
        Args:
            output: Raw Kiterunner output
            
        Returns:
            List of parsed endpoints
        """
        endpoints = []
        seen_urls = set()
        
        for line in output.strip().split('\n'):
            if not line or line.startswith('#'):
                continue
            
            try:
                # Try to parse as JSON
                data = json.loads(line)
                
                method = data.get('method', 'GET').upper()
                path = data.get('path', '/')
                url = data.get('url') or f"{data.get('host', '')}{path}"
                
                if not url or url in seen_urls:
                    continue
                
                seen_urls.add(url)
                
                # Extract status code and content length
                status_code = data.get('status-code') or data.get('status')
                content_length = data.get('content-length') or data.get('length')
                
                # Parse parameters from path
                parameters = self._extract_path_parameters(path)
                
                # Create endpoint info
                endpoint = EndpointInfo(
                    url=url,
                    path=path,
                    method=method,
                    parameters=parameters,
                    source="kiterunner",
                    status_code=status_code,
                    content_length=content_length,
                    is_live=True if status_code and status_code < 500 else None,
                    category=EndpointCategory.API  # Kiterunner finds APIs
                )
                
                endpoints.append(endpoint)
                
            except json.JSONDecodeError:
                # Try parsing as text output format
                # Format: GET    404 [    1234] http://example.com/api/v1/users
                endpoint = self._parse_text_line(line)
                if endpoint and endpoint.url not in seen_urls:
                    seen_urls.add(endpoint.url)
                    endpoints.append(endpoint)
            except Exception as e:
                logger.debug(f"Error parsing line: {e}")
                continue
        
        return endpoints
    
    def _parse_text_line(self, line: str) -> Optional[EndpointInfo]:
        """
        Parse Kiterunner text output line.
        
        Args:
            line: Output line
            
        Returns:
            Parsed endpoint or None
        """
        try:
            parts = line.split()
            if len(parts) < 3:
                return None
            
            method = parts[0].upper()
            status_code = None
            content_length = None
            url = None
            
            # Try to extract status code
            for i, part in enumerate(parts[1:], 1):
                if part.isdigit() and 100 <= int(part) < 600:
                    status_code = int(part)
                elif part.startswith('http'):
                    url = part
                    break
                elif '[' in part and ']' in part:
                    # Content length in brackets
                    try:
                        content_length = int(part.strip('[]').strip())
                    except ValueError:
                        pass
            
            if not url:
                return None
            
            # Extract path
            path = self._extract_path(url)
            
            return EndpointInfo(
                url=url,
                path=path,
                method=method,
                source="kiterunner",
                status_code=status_code,
                content_length=content_length,
                is_live=True if status_code and status_code < 500 else None,
                category=EndpointCategory.API
            )
            
        except Exception as e:
            logger.debug(f"Error parsing text line: {e}")
            return None
    
    def _extract_path(self, url: str) -> str:
        """Extract path from URL."""
        try:
            parsed = urlparse(url)
            path = parsed.path
            if parsed.query:
                path += f"?{parsed.query}"
            return path or "/"
        except Exception:
            return "/"
    
    def _extract_path_parameters(self, path: str) -> List[ParameterInfo]:
        """
        Extract path parameters (e.g., /api/users/{id}).
        
        Args:
            path: URL path
            
        Returns:
            List of parameters
        """
        parameters = []
        
        # Look for path parameters in {brackets} or :colon format
        import re
        
        # Match {id}, {user_id}, etc.
        bracket_params = re.findall(r'\{([^}]+)\}', path)
        for param_name in bracket_params:
            param = ParameterInfo(
                name=param_name,
                type=self._infer_param_type(param_name),
                location="path"
            )
            parameters.append(param)
        
        # Match :id, :user_id, etc.
        colon_params = re.findall(r':([a-zA-Z_][a-zA-Z0-9_]*)', path)
        for param_name in colon_params:
            if param_name not in bracket_params:  # Avoid duplicates
                param = ParameterInfo(
                    name=param_name,
                    type=self._infer_param_type(param_name),
                    location="path"
                )
                parameters.append(param)
        
        return parameters
    
    def _infer_param_type(self, param_name: str) -> ParameterType:
        """
        Infer parameter type from name.
        
        Args:
            param_name: Parameter name
            
        Returns:
            Inferred parameter type
        """
        name_lower = param_name.lower()
        
        if 'id' in name_lower or name_lower.endswith('_id'):
            return ParameterType.ID
        elif 'email' in name_lower:
            return ParameterType.EMAIL
        elif 'search' in name_lower or 'query' in name_lower or 'q' == name_lower:
            return ParameterType.SEARCH
        elif any(x in name_lower for x in ['pass', 'pwd', 'token', 'key', 'secret']):
            return ParameterType.AUTH
        elif 'file' in name_lower or 'upload' in name_lower or 'download' in name_lower:
            return ParameterType.FILE
        elif 'url' in name_lower or 'link' in name_lower:
            return ParameterType.URL
        elif any(x in name_lower for x in ['count', 'page', 'limit', 'offset', 'size']):
            return ParameterType.INTEGER
        
        return ParameterType.STRING
