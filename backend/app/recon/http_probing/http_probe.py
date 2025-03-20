"""
HTTP Probe Module - Month 5

Core HTTP probing functionality using httpx tool.
Handles HTTP/HTTPS requests, metadata extraction, and response analysis.
"""

import asyncio
import json
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
import logging

from .schemas import (
    BaseURLInfo,
    ContentInfo,
    RedirectChain,
    SecurityHeaders
)

logger = logging.getLogger(__name__)


class HttpProbe:
    """
    HTTP probing using httpx tool.
    
    Extracts comprehensive HTTP/HTTPS response metadata including:
    - Status codes and response times
    - Response headers
    - Content metadata (title, length, type)
    - Redirect chains
    - Security headers
    """
    
    def __init__(
        self,
        timeout: int = 10,
        follow_redirects: bool = True,
        max_redirects: int = 10,
        threads: int = 50
    ):
        """
        Initialize HTTP probe.
        
        Args:
            timeout: Request timeout in seconds
            follow_redirects: Whether to follow HTTP redirects
            max_redirects: Maximum redirect depth
            threads: Number of concurrent threads
        """
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.threads = threads
        
    async def probe_url(self, url: str) -> Optional[BaseURLInfo]:
        """
        Probe a single URL with httpx.
        
        Args:
            url: Target URL to probe
            
        Returns:
            BaseURLInfo object with probe results or None on failure
        """
        try:
            # Build httpx command
            cmd = self._build_httpx_command(url)
            
            # Execute httpx
            result = await self._execute_httpx(cmd)
            
            if result:
                return self._parse_httpx_output(result, url)
            return None
            
        except Exception as e:
            logger.error(f"Error probing {url}: {e}")
            return BaseURLInfo(
                url=url,
                scheme=urlparse(url).scheme or "http",
                host=urlparse(url).hostname or url,
                port=urlparse(url).port or 80,
                success=False,
                error=str(e)
            )
    
    async def probe_urls(self, urls: List[str]) -> List[BaseURLInfo]:
        """
        Probe multiple URLs concurrently.
        
        Args:
            urls: List of target URLs
            
        Returns:
            List of BaseURLInfo results
        """
        # Use httpx's built-in parallelism by passing all URLs at once
        try:
            cmd = self._build_httpx_command_bulk(urls)
            results = await self._execute_httpx(cmd)
            
            if results:
                return self._parse_httpx_bulk_output(results, urls)
            return []
            
        except Exception as e:
            logger.error(f"Error probing URLs: {e}")
            return []
    
    def _build_httpx_command(self, url: str) -> List[str]:
        """Build httpx command for single URL"""
        cmd = [
            "httpx",
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-content-length",
            "-content-type",
            "-response-time",
            "-server",
            "-method",
            "-location",
            f"-timeout {self.timeout}",
            f"-threads {self.threads}",
        ]
        
        if self.follow_redirects:
            cmd.extend(["-follow-redirects", f"-max-redirects {self.max_redirects}"])
        
        # Add headers extraction
        cmd.extend(["-include-response-header", "-include-response"])
        
        cmd.append(url)
        
        return cmd
    
    def _build_httpx_command_bulk(self, urls: List[str]) -> List[str]:
        """Build httpx command for multiple URLs"""
        cmd = [
            "httpx",
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-content-length",
            "-content-type",
            "-response-time",
            "-server",
            "-method",
            "-location",
            "-follow-redirects",
            "-max-redirects", str(self.max_redirects),
            "-timeout", str(self.timeout),
            "-threads", str(self.threads),
            "-no-color",
        ]
        
        # Create temporary input file with URLs
        input_data = "\n".join(urls)
        
        return cmd, input_data
    
    async def _execute_httpx(self, cmd) -> Optional[str]:
        """Execute httpx command and return output"""
        try:
            if isinstance(cmd, tuple):
                # Bulk mode with stdin
                cmd_list, input_data = cmd
                process = await asyncio.create_subprocess_exec(
                    *cmd_list,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate(input=input_data.encode())
            else:
                # Single URL mode
                process = await asyncio.create_subprocess_shell(
                    " ".join(cmd),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"httpx error: {stderr.decode()}")
                return None
            
            return stdout.decode()
            
        except Exception as e:
            logger.error(f"Failed to execute httpx: {e}")
            return None
    
    def _parse_httpx_output(self, output: str, url: str) -> Optional[BaseURLInfo]:
        """Parse httpx JSON output for single URL"""
        try:
            data = json.loads(output)
            return self._convert_httpx_to_baseurl(data, url)
        except json.JSONDecodeError:
            logger.error(f"Failed to parse httpx JSON for {url}")
            return None
    
    def _parse_httpx_bulk_output(self, output: str, urls: List[str]) -> List[BaseURLInfo]:
        """Parse httpx JSON output for multiple URLs"""
        results = []
        
        for line in output.strip().split('\n'):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                result = self._convert_httpx_to_baseurl(data)
                if result:
                    results.append(result)
            except json.JSONDecodeError:
                continue
        
        return results
    
    def _convert_httpx_to_baseurl(self, data: Dict[str, Any], original_url: str = None) -> Optional[BaseURLInfo]:
        """Convert httpx JSON output to BaseURLInfo model"""
        try:
            url = data.get('url', original_url)
            parsed = urlparse(url)
            
            # Extract content information
            content = ContentInfo(
                content_type=data.get('content_type'),
                content_length=data.get('content_length'),
                title=data.get('title'),
                word_count=data.get('words'),
                line_count=data.get('lines')
            )
            
            # Parse security headers
            security_headers = self._parse_security_headers(data.get('header', {}))
            
            # Build BaseURLInfo
            result = BaseURLInfo(
                url=url,
                final_url=data.get('final_url', url),
                scheme=data.get('scheme', parsed.scheme or 'http'),
                host=data.get('host', parsed.hostname or ''),
                port=data.get('port', parsed.port or (443 if parsed.scheme == 'https' else 80)),
                ip=data.get('host'),  # httpx returns resolved IP
                status_code=data.get('status_code'),
                status_text=data.get('status_code', ''),
                headers=data.get('header', {}),
                response_time_ms=data.get('time') if data.get('time') else None,
                content=content,
                security_headers=security_headers,
                server_header=data.get('webserver'),
                powered_by=data.get('header', {}).get('X-Powered-By'),
                technologies=[],  # Will be populated by tech detector
                success=True
            )
            
            # Handle redirects
            if data.get('chain'):
                result.redirects = self._parse_redirect_chain(data['chain'])
                result.redirect_count = len(result.redirects)
            
            return result
            
        except Exception as e:
            logger.error(f"Error converting httpx data: {e}")
            return None
    
    def _parse_security_headers(self, headers: Dict[str, str]) -> SecurityHeaders:
        """Parse security headers from response headers"""
        security_headers = SecurityHeaders(
            strict_transport_security=headers.get('Strict-Transport-Security'),
            content_security_policy=headers.get('Content-Security-Policy'),
            x_frame_options=headers.get('X-Frame-Options'),
            x_content_type_options=headers.get('X-Content-Type-Options'),
            x_xss_protection=headers.get('X-XSS-Protection'),
            referrer_policy=headers.get('Referrer-Policy'),
            permissions_policy=headers.get('Permissions-Policy'),
        )
        
        # Calculate security score and missing headers
        expected_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Referrer-Policy'
        ]
        
        present = sum(1 for h in expected_headers if headers.get(h))
        security_headers.security_score = int((present / len(expected_headers)) * 100)
        security_headers.missing_headers = [h for h in expected_headers if not headers.get(h)]
        
        return security_headers
    
    def _parse_redirect_chain(self, chain_data: List[Dict]) -> List[RedirectChain]:
        """Parse redirect chain from httpx output"""
        redirects = []
        
        for item in chain_data:
            redirect = RedirectChain(
                url=item.get('url', ''),
                status_code=item.get('status_code', 0),
                location=item.get('location')
            )
            redirects.append(redirect)
        
        return redirects
