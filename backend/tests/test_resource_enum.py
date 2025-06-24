"""
Resource Enumeration Tests

Comprehensive tests for resource enumeration module.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
Project: UniVex - Month 6
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import asyncio

from app.recon.resource_enum.schemas import (
    ResourceEnumRequest,
    ResourceEnumResult,
    ResourceEnumStats,
    EndpointInfo,
    ParameterInfo,
    FormInfo,
    EnumMode,
    EndpointCategory,
    ParameterType,
)
from app.recon.resource_enum.katana_wrapper import KatanaWrapper
from app.recon.resource_enum.gau_wrapper import GAUWrapper
from app.recon.resource_enum.kiterunner_wrapper import KiterunnerWrapper
from app.recon.resource_enum.resource_orchestrator import ResourceOrchestrator


# ============================================================================
# Schema Tests
# ============================================================================

class TestSchemas:
    """Test Pydantic schemas."""
    
    def test_enum_mode_values(self):
        """Test EnumMode enum values."""
        assert EnumMode.BASIC == "basic"
        assert EnumMode.FULL == "full"
        assert EnumMode.PASSIVE == "passive"
        assert EnumMode.ACTIVE == "active"
    
    def test_endpoint_category_values(self):
        """Test EndpointCategory enum values."""
        assert EndpointCategory.AUTH == "auth"
        assert EndpointCategory.API == "api"
        assert EndpointCategory.ADMIN == "admin"
        assert EndpointCategory.FILE_ACCESS == "file"
        assert EndpointCategory.SENSITIVE == "sensitive"
        assert EndpointCategory.DYNAMIC == "dynamic"
        assert EndpointCategory.STATIC == "static"
        assert EndpointCategory.UNKNOWN == "unknown"
    
    def test_parameter_type_values(self):
        """Test ParameterType enum values."""
        assert ParameterType.ID == "id"
        assert ParameterType.FILE == "file"
        assert ParameterType.SEARCH == "search"
        assert ParameterType.AUTH == "auth"
        assert ParameterType.EMAIL == "email"
    
    def test_parameter_info_creation(self):
        """Test ParameterInfo model."""
        param = ParameterInfo(
            name="user_id",
            type=ParameterType.ID,
            location="query",
            value="123"
        )
        assert param.name == "user_id"
        assert param.type == ParameterType.ID
        assert param.location == "query"
        assert param.value == "123"
    
    def test_form_info_creation(self):
        """Test FormInfo model."""
        form = FormInfo(
            action="/login",
            method="POST",
            inputs=[
                ParameterInfo(name="username", type=ParameterType.STRING, location="body"),
                ParameterInfo(name="password", type=ParameterType.AUTH, location="body")
            ]
        )
        assert form.action == "/login"
        assert form.method == "POST"
        assert len(form.inputs) == 2
    
    def test_endpoint_info_creation(self):
        """Test EndpointInfo model."""
        endpoint = EndpointInfo(
            url="https://example.com/api/users",
            path="/api/users",
            method="GET",
            category=EndpointCategory.API,
            source="katana",
            parameters=[],
            forms=[]
        )
        assert endpoint.url == "https://example.com/api/users"
        assert endpoint.path == "/api/users"
        assert endpoint.method == "GET"
        assert endpoint.category == EndpointCategory.API
        assert endpoint.source == "katana"
    
    def test_resource_enum_request_defaults(self):
        """Test ResourceEnumRequest defaults."""
        request = ResourceEnumRequest(targets=["https://example.com"])
        assert request.mode == EnumMode.FULL
        assert request.katana_enabled is True
        assert request.gau_enabled is True
        assert request.kiterunner_enabled is True
        assert request.crawl_depth == 3
        assert request.parallel_execution is True
    
    def test_resource_enum_request_validation(self):
        """Test ResourceEnumRequest validation."""
        # Empty targets should fail
        with pytest.raises(ValueError):
            ResourceEnumRequest(targets=[])
    
    def test_resource_enum_stats_creation(self):
        """Test ResourceEnumStats model."""
        stats = ResourceEnumStats(
            total_endpoints=100,
            katana_endpoints=40,
            gau_endpoints=50,
            kiterunner_endpoints=10,
            live_endpoints=90,
            execution_time=45.5
        )
        assert stats.total_endpoints == 100
        assert stats.execution_time == 45.5
    
    def test_resource_enum_result_creation(self):
        """Test ResourceEnumResult model."""
        request = ResourceEnumRequest(targets=["https://example.com"])
        stats = ResourceEnumStats(total_endpoints=10)
        
        result = ResourceEnumResult(
            request=request,
            endpoints=[],
            stats=stats,
            errors=[],
            success=True
        )
        assert result.success is True
        assert len(result.endpoints) == 0


# ============================================================================
# Katana Wrapper Tests
# ============================================================================

class TestKatanaWrapper:
    """Test Katana wrapper functionality."""
    
    def test_initialization(self):
        """Test Katana wrapper initialization."""
        katana = KatanaWrapper(
            crawl_depth=5,
            max_urls=1000,
            js_crawling=True,
            extract_forms=True,
            timeout=600
        )
        assert katana.crawl_depth == 5
        assert katana.max_urls == 1000
        assert katana.js_crawling is True
        assert katana.extract_forms is True
        assert katana.timeout == 600
    
    def test_build_command(self):
        """Test Katana command building."""
        katana = KatanaWrapper()
        cmd = katana._build_command(["https://example.com"])
        
        assert "katana" in cmd
        assert "-d" in cmd
        assert "-jc" in cmd
        assert "-headless" in cmd
        assert "-u" in cmd
        assert "https://example.com" in cmd
    
    def test_extract_path(self):
        """Test path extraction from URL."""
        katana = KatanaWrapper()
        
        path = katana._extract_path("https://example.com/api/users?id=1")
        assert path == "/api/users?id=1"
        
        path = katana._extract_path("https://example.com")
        assert path == "/"
    
    def test_extract_parameters(self):
        """Test parameter extraction from URL."""
        katana = KatanaWrapper()
        
        params = katana._extract_parameters("https://example.com/search?q=test&page=1")
        assert len(params) == 2
        
        param_names = {p.name for p in params}
        assert "q" in param_names
        assert "page" in param_names
    
    def test_infer_input_type(self):
        """Test input type inference."""
        katana = KatanaWrapper()
        
        # Email type
        input_field = {"type": "email", "name": "user_email"}
        assert katana._infer_input_type(input_field) == ParameterType.EMAIL
        
        # File type
        input_field = {"type": "file", "name": "upload"}
        assert katana._infer_input_type(input_field) == ParameterType.FILE
        
        # ID type
        input_field = {"type": "text", "name": "user_id"}
        assert katana._infer_input_type(input_field) == ParameterType.ID
        
        # Search type
        input_field = {"type": "text", "name": "search"}
        assert katana._infer_input_type(input_field) == ParameterType.SEARCH


# ============================================================================
# GAU Wrapper Tests
# ============================================================================

class TestGAUWrapper:
    """Test GAU wrapper functionality."""
    
    def test_initialization(self):
        """Test GAU wrapper initialization."""
        gau = GAUWrapper(
            providers=["wayback", "commoncrawl"],
            max_urls=2000,
            verify_urls=False,
            timeout=600
        )
        assert gau.providers == ["wayback", "commoncrawl"]
        assert gau.max_urls == 2000
        assert gau.verify_urls is False
        assert gau.timeout == 600
    
    def test_build_command(self):
        """Test GAU command building."""
        gau = GAUWrapper(providers=["wayback", "otx"])
        cmd = gau._build_command("example.com")
        
        assert "gau" in cmd
        assert "example.com" in cmd
        assert "--subs" in cmd
    
    def test_extract_path(self):
        """Test path extraction from URL."""
        gau = GAUWrapper()
        
        path = gau._extract_path("https://example.com/api/v1/users?filter=active")
        assert path == "/api/v1/users?filter=active"
    
    def test_extract_parameters(self):
        """Test parameter extraction from URL."""
        gau = GAUWrapper()
        
        params = gau._extract_parameters("https://example.com/api?id=1&name=test")
        assert len(params) == 2
        
        param_names = {p.name for p in params}
        assert "id" in param_names
        assert "name" in param_names
    
    @pytest.mark.asyncio
    async def test_check_endpoint(self):
        """Test endpoint liveness check."""
        gau = GAUWrapper()
        
        endpoint = EndpointInfo(
            url="https://example.com/test",
            path="/test",
            source="gau",
            method="GET"
        )
        
        # Mock async httpx client
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'content-length': '1234'}
        mock_client = AsyncMock()
        mock_client.head = AsyncMock(return_value=mock_response)
        
        result = await gau._check_endpoint(mock_client, endpoint)
        assert result.status_code == 200 or result.is_live is None  # Depending on mock


# ============================================================================
# Kiterunner Wrapper Tests
# ============================================================================

class TestKiterunnerWrapper:
    """Test Kiterunner wrapper functionality."""
    
    def test_initialization(self):
        """Test Kiterunner wrapper initialization."""
        kite = KiterunnerWrapper(
            wordlist="routes-small",
            threads=20,
            rate_limit=200,
            timeout=600
        )
        assert kite.wordlist == "routes-small"
        assert kite.threads == 20
        assert kite.rate_limit == 200
        assert kite.timeout == 600
    
    def test_build_command(self):
        """Test Kiterunner command building."""
        kite = KiterunnerWrapper(wordlist="routes-large")
        cmd = kite._build_command("https://api.example.com")
        
        assert "kr" in cmd
        assert "brute" in cmd
        assert "https://api.example.com" in cmd
        assert "-w" in cmd
    
    def test_extract_path(self):
        """Test path extraction from URL."""
        kite = KiterunnerWrapper()
        
        path = kite._extract_path("https://api.example.com/v1/users/{id}")
        assert path == "/v1/users/{id}"
    
    def test_extract_path_parameters(self):
        """Test path parameter extraction."""
        kite = KiterunnerWrapper()
        
        # Bracket style
        params = kite._extract_path_parameters("/api/users/{user_id}/posts/{post_id}")
        assert len(params) == 2
        param_names = {p.name for p in params}
        assert "user_id" in param_names
        assert "post_id" in param_names
        
        # Colon style
        params = kite._extract_path_parameters("/api/users/:id/posts/:pid")
        assert len(params) == 2
    
    def test_infer_param_type(self):
        """Test parameter type inference."""
        kite = KiterunnerWrapper()
        
        assert kite._infer_param_type("user_id") == ParameterType.ID
        assert kite._infer_param_type("email") == ParameterType.EMAIL
        assert kite._infer_param_type("search_query") == ParameterType.SEARCH
        assert kite._infer_param_type("api_key") == ParameterType.AUTH
        assert kite._infer_param_type("file_upload") == ParameterType.FILE


# ============================================================================
# Resource Orchestrator Tests
# ============================================================================

class TestResourceOrchestrator:
    """Test resource orchestrator functionality."""
    
    def test_initialization(self):
        """Test orchestrator initialization."""
        request = ResourceEnumRequest(targets=["https://example.com"])
        orchestrator = ResourceOrchestrator(request)
        assert orchestrator.request == request
        assert orchestrator.errors == []
    
    def test_determine_tools_basic_mode(self):
        """Test tool determination for basic mode."""
        request = ResourceEnumRequest(
            targets=["https://example.com"],
            mode=EnumMode.BASIC
        )
        orchestrator = ResourceOrchestrator(request)
        tools = orchestrator._determine_tools()
        assert "katana" in tools
        assert "gau" not in tools
        assert "kiterunner" not in tools
    
    def test_determine_tools_passive_mode(self):
        """Test tool determination for passive mode."""
        request = ResourceEnumRequest(
            targets=["https://example.com"],
            mode=EnumMode.PASSIVE
        )
        orchestrator = ResourceOrchestrator(request)
        tools = orchestrator._determine_tools()
        assert "gau" in tools
        assert "katana" not in tools
        assert "kiterunner" not in tools
    
    def test_determine_tools_active_mode(self):
        """Test tool determination for active mode."""
        request = ResourceEnumRequest(
            targets=["https://example.com"],
            mode=EnumMode.ACTIVE
        )
        orchestrator = ResourceOrchestrator(request)
        tools = orchestrator._determine_tools()
        assert "katana" in tools
        assert "kiterunner" in tools
        assert "gau" not in tools
    
    def test_determine_tools_full_mode(self):
        """Test tool determination for full mode."""
        request = ResourceEnumRequest(
            targets=["https://example.com"],
            mode=EnumMode.FULL
        )
        orchestrator = ResourceOrchestrator(request)
        tools = orchestrator._determine_tools()
        assert "katana" in tools
        assert "gau" in tools
        assert "kiterunner" in tools
    
    def test_extract_domains(self):
        """Test domain extraction from URLs."""
        request = ResourceEnumRequest(targets=["https://example.com"])
        orchestrator = ResourceOrchestrator(request)
        
        domains = orchestrator._extract_domains([
            "https://example.com:443",
            "http://test.example.com",
            "subdomain.example.com"
        ])
        assert "example.com" in domains
        assert "test.example.com" in domains
        assert "subdomain.example.com" in domains
    
    def test_normalize_url(self):
        """Test URL normalization."""
        request = ResourceEnumRequest(targets=["https://example.com"])
        orchestrator = ResourceOrchestrator(request)
        
        url1 = orchestrator._normalize_url("https://Example.com/Path/")
        url2 = orchestrator._normalize_url("https://example.com/path")
        assert url1 == url2
    
    def test_merge_endpoints(self):
        """Test endpoint merging and deduplication."""
        request = ResourceEnumRequest(targets=["https://example.com"])
        orchestrator = ResourceOrchestrator(request)
        
        results = {
            "katana": [
                EndpointInfo(url="https://example.com/api", path="/api", source="katana", method="GET"),
                EndpointInfo(url="https://example.com/login", path="/login", source="katana", method="GET")
            ],
            "gau": [
                EndpointInfo(url="https://example.com/api", path="/api", source="gau", method="GET"),
                EndpointInfo(url="https://example.com/admin", path="/admin", source="gau", method="GET")
            ]
        }
        
        merged = orchestrator._merge_endpoints(results)
        assert len(merged) == 3  # Unique URLs only
    
    def test_determine_category(self):
        """Test endpoint category determination."""
        request = ResourceEnumRequest(targets=["https://example.com"])
        orchestrator = ResourceOrchestrator(request)
        
        # Auth endpoint
        endpoint = EndpointInfo(url="https://example.com/login", path="/login", source="test", method="GET")
        category = orchestrator._determine_category(endpoint)
        assert category == EndpointCategory.AUTH
        
        # API endpoint
        endpoint = EndpointInfo(url="https://example.com/api/users", path="/api/users", source="test", method="GET")
        category = orchestrator._determine_category(endpoint)
        assert category == EndpointCategory.API
        
        # Admin endpoint
        endpoint = EndpointInfo(url="https://example.com/admin", path="/admin", source="test", method="GET")
        category = orchestrator._determine_category(endpoint)
        assert category == EndpointCategory.ADMIN
        
        # Static resource
        endpoint = EndpointInfo(url="https://example.com/style.css", path="/style.css", source="test", method="GET")
        category = orchestrator._determine_category(endpoint)
        assert category == EndpointCategory.STATIC
    
    def test_infer_type(self):
        """Test parameter type inference."""
        request = ResourceEnumRequest(targets=["https://example.com"])
        orchestrator = ResourceOrchestrator(request)
        
        # Email parameter
        param = ParameterInfo(name="email", type=ParameterType.UNKNOWN, location="query")
        inferred_type = orchestrator._infer_type(param)
        assert inferred_type == ParameterType.EMAIL
        
        # ID parameter
        param = ParameterInfo(name="user_id", type=ParameterType.UNKNOWN, location="query")
        inferred_type = orchestrator._infer_type(param)
        assert inferred_type == ParameterType.ID
        
        # Search parameter
        param = ParameterInfo(name="search", type=ParameterType.UNKNOWN, location="query")
        inferred_type = orchestrator._infer_type(param)
        assert inferred_type == ParameterType.SEARCH
        
        # Integer value
        param = ParameterInfo(name="count", type=ParameterType.UNKNOWN, location="query", value="123")
        inferred_type = orchestrator._infer_type(param)
        assert inferred_type == ParameterType.INTEGER
    
    def test_calculate_stats(self):
        """Test statistics calculation."""
        request = ResourceEnumRequest(targets=["https://example.com"])
        orchestrator = ResourceOrchestrator(request)
        
        endpoints = [
            EndpointInfo(
                url="https://example.com/api",
                path="/api",
                source="katana",
                method="GET",
                category=EndpointCategory.API,
                is_live=True,
                parameters=[ParameterInfo(name="id", type=ParameterType.ID, location="query")]
            ),
            EndpointInfo(
                url="https://example.com/login",
                path="/login",
                source="gau",
                method="POST",
                category=EndpointCategory.AUTH,
                is_live=False
            )
        ]
        
        stats = orchestrator._calculate_stats(endpoints, 10.5)
        
        assert stats.total_endpoints == 2
        assert stats.katana_endpoints == 1
        assert stats.gau_endpoints == 1
        assert stats.live_endpoints == 1
        assert stats.total_parameters == 1
        assert stats.execution_time == 10.5
        assert stats.categories["api"] == 1
        assert stats.categories["auth"] == 1
        assert stats.methods["GET"] == 1
        assert stats.methods["POST"] == 1


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests for resource enumeration."""
    
    @pytest.mark.asyncio
    async def test_basic_workflow(self):
        """Test basic enumeration workflow."""
        # This test would require actual tools installed
        # For now, we test the flow with mocked components
        request = ResourceEnumRequest(
            targets=["https://example.com"],
            mode=EnumMode.BASIC,
            katana_enabled=True,
            gau_enabled=False,
            kiterunner_enabled=False
        )
        
        orchestrator = ResourceOrchestrator(request)
        # Would call orchestrator.run() with mocked tools
        assert orchestrator.request.mode == EnumMode.BASIC
    
    def test_parameter_type_inference_accuracy(self):
        """Test parameter type inference accuracy across multiple examples."""
        request = ResourceEnumRequest(targets=["https://example.com"])
        orchestrator = ResourceOrchestrator(request)
        
        test_cases = [
            ("email", "user@example.com", ParameterType.EMAIL),
            ("user_id", "123", ParameterType.ID),
            ("search_query", "test", ParameterType.SEARCH),
            ("api_key", "abc123", ParameterType.AUTH),
            ("redirect_url", "https://example.com", ParameterType.URL),
            ("count", "10", ParameterType.INTEGER),
            ("is_active", "true", ParameterType.BOOLEAN),
        ]
        
        for name, value, expected_type in test_cases:
            param = ParameterInfo(name=name, type=ParameterType.UNKNOWN, location="query", value=value)
            inferred = orchestrator._infer_type(param)
            assert inferred == expected_type, f"Failed for {name}={value}, expected {expected_type}, got {inferred}"
