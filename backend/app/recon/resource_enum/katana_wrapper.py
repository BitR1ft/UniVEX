"""
Katana Wrapper

Python wrapper for Katana web crawler for JavaScript-capable endpoint discovery.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
"""

import subprocess
import json
import logging
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs

from .schemas import EndpointInfo, ParameterInfo, FormInfo, EndpointCategory, ParameterType

logger = logging.getLogger(__name__)


class KatanaWrapper:
    """
    Wrapper for Katana web crawler.
    
    Katana is a next-generation crawling and spidering framework with JavaScript parsing.
    """
    
    def __init__(
        self,
        crawl_depth: int = 3,
        max_urls: int = 500,
        js_crawling: bool = True,
        extract_forms: bool = True,
        timeout: int = 300
    ):
        """
        Initialize Katana wrapper.
        
        Args:
            crawl_depth: Maximum crawl depth (1-5)
            max_urls: Maximum number of URLs to crawl
            js_crawling: Enable JavaScript rendering
            extract_forms: Extract HTML forms
            timeout: Timeout in seconds
        """
        self.crawl_depth = crawl_depth
        self.max_urls = max_urls
        self.js_crawling = js_crawling
        self.extract_forms = extract_forms
        self.timeout = timeout
        
        # Verify Katana is installed
        self._verify_installation()
    
    def _verify_installation(self) -> None:
        """Verify that Katana is installed and accessible."""
        try:
            result = subprocess.run(
                ["katana", "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"Katana version: {result.stdout.strip()}")
            else:
                logger.warning("Katana not found or not working properly")
        except FileNotFoundError:
            logger.error("Katana is not installed or not in PATH")
        except Exception as e:
            logger.error(f"Error verifying Katana installation: {e}")
    
    def crawl(self, targets: List[str]) -> List[EndpointInfo]:
        """
        Crawl targets with Katana.
        
        Args:
            targets: List of target URLs to crawl
            
        Returns:
            List of discovered endpoints
        """
        logger.info(f"Starting Katana crawl of {len(targets)} target(s)")
        
        # Build Katana command
        cmd = self._build_command(targets)
        
        try:
            # Execute Katana
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Katana failed: {result.stderr}")
                return []
            
            # Parse output
            endpoints = self._parse_output(result.stdout)
            
            logger.info(f"Katana discovered {len(endpoints)} endpoints")
            return endpoints
            
        except subprocess.TimeoutExpired:
            logger.error(f"Katana timeout after {self.timeout}s")
            return []
        except Exception as e:
            logger.error(f"Katana execution error: {e}")
            return []
    
    def _build_command(self, targets: List[str]) -> List[str]:
        """
        Build Katana command.
        
        Args:
            targets: List of targets to crawl
            
        Returns:
            Command as list of arguments
        """
        cmd = [
            "katana",
            "-d", str(self.crawl_depth),
            "-jc",  # JSON output
            "-kf", "all",  # Known files mode
            "-aff",  # Automatic form fill
        ]
        
        # Add JavaScript crawling
        if self.js_crawling:
            cmd.extend(["-headless", "-jsl"])  # Headless browser + JS link extraction
        
        # Add form extraction
        if self.extract_forms:
            cmd.append("-ef")  # Extract forms
        
        # Rate limiting and parallelism
        cmd.extend([
            "-c", "10",  # Concurrency
            "-p", "5",   # Parallelism
            "-rl", "100" # Rate limit
        ])
        
        # Output configuration
        cmd.extend([
            "-fs", "rdn",  # Field separator
            "-silent"      # Silent mode (only output)
        ])
        
        # Add targets
        for target in targets[:10]:  # Limit to first 10 targets
            cmd.extend(["-u", target])
        
        logger.debug(f"Katana command: {' '.join(cmd)}")
        return cmd
    
    def _parse_output(self, output: str) -> List[EndpointInfo]:
        """
        Parse Katana JSON output.
        
        Args:
            output: Raw Katana output
            
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
                
                url = data.get('url') or data.get('request', {}).get('endpoint')
                if not url or url in seen_urls:
                    continue
                
                seen_urls.add(url)
                
                # Extract parameters from URL
                parameters = self._extract_parameters(url)
                
                # Extract forms if present
                forms = []
                if self.extract_forms and 'form' in data:
                    forms = self._extract_forms(data['form'])
                
                # Determine method
                method = data.get('method', 'GET').upper()
                
                # Create endpoint info
                endpoint = EndpointInfo(
                    url=url,
                    path=self._extract_path(url),
                    method=method,
                    parameters=parameters,
                    forms=forms,
                    source="katana",
                    category=EndpointCategory.UNKNOWN  # Will be classified later
                )
                
                endpoints.append(endpoint)
                
                if len(endpoints) >= self.max_urls:
                    break
                    
            except json.JSONDecodeError:
                # Try parsing as plain URL output
                url = line.strip()
                if url and url not in seen_urls and url.startswith('http'):
                    seen_urls.add(url)
                    
                    endpoint = EndpointInfo(
                        url=url,
                        path=self._extract_path(url),
                        method="GET",
                        parameters=self._extract_parameters(url),
                        source="katana",
                        category=EndpointCategory.UNKNOWN
                    )
                    endpoints.append(endpoint)
                    
                    if len(endpoints) >= self.max_urls:
                        break
            except Exception as e:
                logger.debug(f"Error parsing line: {e}")
                continue
        
        return endpoints
    
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
    
    def _extract_parameters(self, url: str) -> List[ParameterInfo]:
        """
        Extract query parameters from URL.
        
        Args:
            url: URL to parse
            
        Returns:
            List of parameters
        """
        parameters = []
        
        try:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                for name, values in params.items():
                    value = values[0] if values else None
                    
                    param = ParameterInfo(
                        name=name,
                        type=ParameterType.UNKNOWN,  # Will be inferred later
                        location="query",
                        value=value
                    )
                    parameters.append(param)
        except Exception as e:
            logger.debug(f"Error extracting parameters: {e}")
        
        return parameters
    
    def _extract_forms(self, form_data: Any) -> List[FormInfo]:
        """
        Extract form information.
        
        Args:
            form_data: Form data from Katana output
            
        Returns:
            List of forms
        """
        forms = []
        
        try:
            if isinstance(form_data, list):
                for form in form_data:
                    forms.append(self._parse_form(form))
            elif isinstance(form_data, dict):
                forms.append(self._parse_form(form_data))
        except Exception as e:
            logger.debug(f"Error extracting forms: {e}")
        
        return forms
    
    def _parse_form(self, form: Dict[str, Any]) -> FormInfo:
        """Parse a single form."""
        inputs = []
        
        # Extract inputs
        if 'inputs' in form and isinstance(form['inputs'], list):
            for input_field in form['inputs']:
                if isinstance(input_field, dict):
                    param = ParameterInfo(
                        name=input_field.get('name', 'unknown'),
                        type=self._infer_input_type(input_field),
                        location="body",
                        value=input_field.get('value'),
                        required=input_field.get('required', False)
                    )
                    inputs.append(param)
        
        return FormInfo(
            action=form.get('action', ''),
            method=form.get('method', 'GET').upper(),
            inputs=inputs
        )
    
    def _infer_input_type(self, input_field: Dict[str, Any]) -> ParameterType:
        """Infer parameter type from HTML input field."""
        input_type = input_field.get('type', '').lower()
        name = input_field.get('name', '').lower()
        
        # Type based on HTML input type
        if input_type == 'email':
            return ParameterType.EMAIL
        elif input_type == 'file':
            return ParameterType.FILE
        elif input_type in ['number', 'range']:
            return ParameterType.INTEGER
        elif input_type in ['checkbox', 'radio']:
            return ParameterType.BOOLEAN
        elif input_type == 'url':
            return ParameterType.URL
        
        # Type based on name
        if 'email' in name:
            return ParameterType.EMAIL
        elif 'id' in name or name.endswith('_id'):
            return ParameterType.ID
        elif 'search' in name or 'query' in name or 'q' == name:
            return ParameterType.SEARCH
        elif any(x in name for x in ['pass', 'pwd', 'token', 'key', 'secret']):
            return ParameterType.AUTH
        elif 'file' in name or 'upload' in name:
            return ParameterType.FILE
        
        return ParameterType.STRING
