"""
Resource Enumeration Orchestrator

Coordinates Katana, GAU, and Kiterunner for comprehensive endpoint discovery.
Handles parallel execution, URL merging, deduplication, and classification.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
"""

import logging
import asyncio
import time
import re
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from .schemas import (
    ResourceEnumRequest,
    ResourceEnumResult,
    ResourceEnumStats,
    EndpointInfo,
    ParameterInfo,
    EndpointCategory,
    ParameterType,
    EnumMode
)
from .katana_wrapper import KatanaWrapper
from .gau_wrapper import GAUWrapper
from .kiterunner_wrapper import KiterunnerWrapper

logger = logging.getLogger(__name__)


class ResourceOrchestrator:
    """
    Orchestrates resource enumeration using multiple tools.
    
    Features:
    - Parallel execution of Katana, GAU, and Kiterunner
    - URL merging and deduplication
    - Endpoint classification (auth, API, admin, etc.)
    - Parameter type inference
    - Comprehensive statistics
    """
    
    def __init__(self, request: ResourceEnumRequest):
        """
        Initialize orchestrator.
        
        Args:
            request: Resource enumeration request configuration
        """
        self.request = request
        self.errors: List[str] = []
    
    async def run(self) -> ResourceEnumResult:
        """
        Execute resource enumeration.
        
        Returns:
            Complete enumeration result
        """
        logger.info("Starting resource enumeration")
        start_time = time.time()
        
        # Determine which tools to run
        tools_to_run = self._determine_tools()
        
        # Execute tools
        if self.request.parallel_execution and len(tools_to_run) > 1:
            endpoints = await self._run_parallel(tools_to_run)
        else:
            endpoints = await self._run_sequential(tools_to_run)
        
        # Merge and deduplicate
        merged_endpoints = self._merge_endpoints(endpoints)
        
        # Classify endpoints
        if self.request.classify_endpoints:
            merged_endpoints = self._classify_endpoints(merged_endpoints)
        
        # Infer parameter types
        if self.request.infer_param_types:
            merged_endpoints = self._infer_parameter_types(merged_endpoints)
        
        # Calculate statistics
        stats = self._calculate_stats(merged_endpoints, time.time() - start_time)
        
        return ResourceEnumResult(
            request=self.request,
            endpoints=merged_endpoints,
            stats=stats,
            errors=self.errors,
            success=len(merged_endpoints) > 0
        )
    
    def _determine_tools(self) -> List[str]:
        """Determine which tools to run based on mode and settings."""
        tools = []
        
        if self.request.mode == EnumMode.BASIC:
            if self.request.katana_enabled:
                tools.append("katana")
        elif self.request.mode == EnumMode.PASSIVE:
            if self.request.gau_enabled:
                tools.append("gau")
        elif self.request.mode == EnumMode.ACTIVE:
            if self.request.katana_enabled:
                tools.append("katana")
            if self.request.kiterunner_enabled:
                tools.append("kiterunner")
        else:  # FULL mode
            if self.request.katana_enabled:
                tools.append("katana")
            if self.request.gau_enabled:
                tools.append("gau")
            if self.request.kiterunner_enabled:
                tools.append("kiterunner")
        
        logger.info(f"Running tools: {', '.join(tools)}")
        return tools
    
    async def _run_parallel(self, tools: List[str]) -> Dict[str, List[EndpointInfo]]:
        """
        Run tools in parallel using ThreadPoolExecutor.
        
        Args:
            tools: List of tool names to run
            
        Returns:
            Dictionary of tool name to endpoints
        """
        logger.info("Running tools in parallel")
        
        results = {}
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            
            for tool in tools:
                if tool == "katana":
                    future = executor.submit(self._run_katana)
                    futures[future] = "katana"
                elif tool == "gau":
                    future = executor.submit(self._run_gau_sync)
                    futures[future] = "gau"
                elif tool == "kiterunner":
                    future = executor.submit(self._run_kiterunner)
                    futures[future] = "kiterunner"
            
            for future in as_completed(futures):
                tool_name = futures[future]
                try:
                    endpoints = future.result()
                    results[tool_name] = endpoints
                    logger.info(f"{tool_name} completed: {len(endpoints)} endpoints")
                except Exception as e:
                    logger.error(f"Error running {tool_name}: {e}")
                    self.errors.append(f"{tool_name}: {str(e)}")
                    results[tool_name] = []
        
        return results
    
    async def _run_sequential(self, tools: List[str]) -> Dict[str, List[EndpointInfo]]:
        """
        Run tools sequentially.
        
        Args:
            tools: List of tool names to run
            
        Returns:
            Dictionary of tool name to endpoints
        """
        logger.info("Running tools sequentially")
        
        results = {}
        
        for tool in tools:
            try:
                if tool == "katana":
                    results["katana"] = self._run_katana()
                elif tool == "gau":
                    results["gau"] = await self._run_gau()
                elif tool == "kiterunner":
                    results["kiterunner"] = self._run_kiterunner()
                
                logger.info(f"{tool} completed: {len(results.get(tool, []))} endpoints")
            except Exception as e:
                logger.error(f"Error running {tool}: {e}")
                self.errors.append(f"{tool}: {str(e)}")
                results[tool] = []
        
        return results
    
    def _run_katana(self) -> List[EndpointInfo]:
        """Run Katana wrapper."""
        try:
            katana = KatanaWrapper(
                crawl_depth=self.request.crawl_depth,
                max_urls=self.request.max_katana_urls,
                js_crawling=self.request.js_crawling,
                extract_forms=self.request.extract_forms,
                timeout=self.request.timeout
            )
            return katana.crawl(self.request.targets)
        except Exception as e:
            logger.error(f"Katana error: {e}")
            self.errors.append(f"Katana: {str(e)}")
            return []
    
    async def _run_gau(self) -> List[EndpointInfo]:
        """Run GAU wrapper (async)."""
        try:
            gau = GAUWrapper(
                providers=self.request.gau_providers,
                max_urls=self.request.max_gau_urls,
                verify_urls=self.request.verify_urls,
                timeout=self.request.timeout
            )
            # Extract domains from targets
            domains = self._extract_domains(self.request.targets)
            return await gau.fetch_urls(domains)
        except Exception as e:
            logger.error(f"GAU error: {e}")
            self.errors.append(f"GAU: {str(e)}")
            return []
    
    def _run_gau_sync(self) -> List[EndpointInfo]:
        """Run GAU wrapper (sync wrapper for ThreadPoolExecutor)."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self._run_gau())
        finally:
            loop.close()
    
    def _run_kiterunner(self) -> List[EndpointInfo]:
        """Run Kiterunner wrapper."""
        try:
            kiterunner = KiterunnerWrapper(
                wordlist=self.request.wordlist,
                threads=self.request.kite_threads,
                rate_limit=self.request.kite_rate_limit,
                timeout=self.request.timeout
            )
            return kiterunner.scan(self.request.targets)
        except Exception as e:
            logger.error(f"Kiterunner error: {e}")
            self.errors.append(f"Kiterunner: {str(e)}")
            return []
    
    def _extract_domains(self, targets: List[str]) -> List[str]:
        """Extract domain names from URLs."""
        domains = set()
        
        for target in targets:
            try:
                parsed = urlparse(target)
                domain = parsed.netloc or target
                # Remove port if present
                domain = domain.split(':')[0]
                domains.add(domain)
            except Exception:
                # Assume it's already a domain
                domains.add(target.split(':')[0])
        
        return list(domains)
    
    def _merge_endpoints(self, results: Dict[str, List[EndpointInfo]]) -> List[EndpointInfo]:
        """
        Merge and deduplicate endpoints from multiple sources.
        
        Args:
            results: Dictionary of tool name to endpoints
            
        Returns:
            Merged list of unique endpoints
        """
        logger.info("Merging and deduplicating endpoints")
        
        # Track unique URLs
        seen_urls: Set[str] = set()
        merged: List[EndpointInfo] = []
        
        # Process endpoints from each tool
        for tool_name, endpoints in results.items():
            for endpoint in endpoints:
                # Normalize URL for comparison
                normalized_url = self._normalize_url(endpoint.url)
                
                if normalized_url not in seen_urls:
                    seen_urls.add(normalized_url)
                    merged.append(endpoint)
                else:
                    # URL already exists, merge additional information
                    self._merge_endpoint_info(merged, endpoint)
        
        logger.info(f"Merged to {len(merged)} unique endpoints")
        return merged
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for comparison (lowercase, remove trailing slash, etc.)."""
        try:
            parsed = urlparse(url.lower())
            path = parsed.path.rstrip('/')
            if parsed.query:
                path += f"?{parsed.query}"
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        except Exception:
            return url.lower()
    
    def _merge_endpoint_info(self, merged: List[EndpointInfo], new_endpoint: EndpointInfo) -> None:
        """Merge additional info from duplicate endpoint."""
        normalized_url = self._normalize_url(new_endpoint.url)
        
        for existing in merged:
            if self._normalize_url(existing.url) == normalized_url:
                # Merge parameters
                existing_param_names = {p.name for p in existing.parameters}
                for param in new_endpoint.parameters:
                    if param.name not in existing_param_names:
                        existing.parameters.append(param)
                
                # Merge forms
                existing.forms.extend(new_endpoint.forms)
                
                # Update method if new one is more specific
                if new_endpoint.method != "GET" and existing.method == "GET":
                    existing.method = new_endpoint.method
                
                # Update status code if available
                if new_endpoint.status_code and not existing.status_code:
                    existing.status_code = new_endpoint.status_code
                
                break
    
    def _classify_endpoints(self, endpoints: List[EndpointInfo]) -> List[EndpointInfo]:
        """
        Classify endpoints by category.
        
        Args:
            endpoints: List of endpoints
            
        Returns:
            Endpoints with updated categories
        """
        logger.info("Classifying endpoints")
        
        for endpoint in endpoints:
            endpoint.category = self._determine_category(endpoint)
        
        return endpoints
    
    def _determine_category(self, endpoint: EndpointInfo) -> EndpointCategory:
        """Determine endpoint category based on URL patterns."""
        path_lower = endpoint.path.lower()
        endpoint.url.lower()
        
        # Authentication endpoints
        auth_patterns = ['/login', '/signin', '/auth', '/oauth', '/sso', '/logout', '/register', '/signup']
        if any(pattern in path_lower for pattern in auth_patterns):
            return EndpointCategory.AUTH
        
        # API endpoints
        api_patterns = ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql', '/json']
        if any(pattern in path_lower for pattern in api_patterns):
            return EndpointCategory.API
        
        # Admin endpoints
        admin_patterns = ['/admin', '/dashboard', '/console', '/management', '/wp-admin', '/phpmyadmin']
        if any(pattern in path_lower for pattern in admin_patterns):
            return EndpointCategory.ADMIN
        
        # File access endpoints
        file_patterns = ['/upload', '/download', '/file', '/attachment', '/media', '/assets']
        if any(pattern in path_lower for pattern in file_patterns):
            return EndpointCategory.FILE_ACCESS
        
        # Sensitive endpoints
        sensitive_patterns = ['/config', '/backup', '/.env', '/.git', '/secret', '/private', '/internal']
        if any(pattern in path_lower for pattern in sensitive_patterns):
            return EndpointCategory.SENSITIVE
        
        # Static resources
        static_extensions = ['.js', '.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', '.ttf']
        if any(path_lower.endswith(ext) for ext in static_extensions):
            return EndpointCategory.STATIC
        
        # Dynamic content (has parameters)
        if endpoint.parameters or '?' in endpoint.path:
            return EndpointCategory.DYNAMIC
        
        return EndpointCategory.UNKNOWN
    
    def _infer_parameter_types(self, endpoints: List[EndpointInfo]) -> List[EndpointInfo]:
        """
        Infer parameter types for all endpoints.
        
        Args:
            endpoints: List of endpoints
            
        Returns:
            Endpoints with inferred parameter types
        """
        logger.info("Inferring parameter types")
        
        for endpoint in endpoints:
            for param in endpoint.parameters:
                if param.type == ParameterType.UNKNOWN:
                    param.type = self._infer_type(param)
        
        return endpoints
    
    def _infer_type(self, param: ParameterInfo) -> ParameterType:
        """Infer parameter type from name and value."""
        name_lower = param.name.lower()
        
        # Check by name
        if 'email' in name_lower or 'mail' in name_lower:
            return ParameterType.EMAIL
        elif 'id' in name_lower or name_lower.endswith('_id'):
            return ParameterType.ID
        elif 'search' in name_lower or 'query' in name_lower or 'q' == name_lower:
            return ParameterType.SEARCH
        elif any(x in name_lower for x in ['pass', 'pwd', 'password', 'token', 'key', 'secret', 'api_key']):
            return ParameterType.AUTH
        elif 'file' in name_lower or 'upload' in name_lower or 'attachment' in name_lower:
            return ParameterType.FILE
        elif 'url' in name_lower or 'link' in name_lower or 'href' in name_lower:
            return ParameterType.URL
        elif any(x in name_lower for x in ['bool', 'is_', 'has_', 'enabled', 'disabled']):
            return ParameterType.BOOLEAN
        
        # Check by value if available
        if param.value:
            value = param.value
            
            # Email pattern
            if re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', value):
                return ParameterType.EMAIL
            
            # URL pattern
            if value.startswith(('http://', 'https://', 'ftp://')):
                return ParameterType.URL
            
            # Integer
            if value.isdigit():
                return ParameterType.INTEGER
            
            # Boolean
            if value.lower() in ['true', 'false', '1', '0', 'yes', 'no']:
                return ParameterType.BOOLEAN
        
        return ParameterType.STRING
    
    def _calculate_stats(self, endpoints: List[EndpointInfo], execution_time: float) -> ResourceEnumStats:
        """Calculate comprehensive statistics."""
        stats = ResourceEnumStats()
        
        stats.total_endpoints = len(endpoints)
        stats.execution_time = round(execution_time, 2)
        
        # Count by source
        for endpoint in endpoints:
            if endpoint.source == "katana":
                stats.katana_endpoints += 1
            elif endpoint.source == "gau":
                stats.gau_endpoints += 1
            elif endpoint.source == "kiterunner":
                stats.kiterunner_endpoints += 1
            
            # Count live endpoints
            if endpoint.is_live:
                stats.live_endpoints += 1
            
            # Count parameters
            stats.total_parameters += len(endpoint.parameters)
            
            # Count forms
            stats.total_forms += len(endpoint.forms)
            
            # Count by category
            category = endpoint.category.value
            stats.categories[category] = stats.categories.get(category, 0) + 1
            
            # Count by method
            method = endpoint.method
            stats.methods[method] = stats.methods.get(method, 0) + 1
        
        return stats
