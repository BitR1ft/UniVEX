"""
Resource Enumeration Schemas

Pydantic models for resource enumeration requests, responses, and data structures.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
"""

from enum import Enum
from typing import List, Optional, Dict
from pydantic import BaseModel, Field, field_validator


class EnumMode(str, Enum):
    """Resource enumeration modes."""
    BASIC = "basic"  # Katana only
    FULL = "full"    # Katana + GAU + Kiterunner
    PASSIVE = "passive"  # GAU only (historical data)
    ACTIVE = "active"    # Katana + Kiterunner (active crawling/bruteforce)


class EndpointCategory(str, Enum):
    """Endpoint classification categories."""
    AUTH = "auth"              # Authentication endpoints
    API = "api"                # API endpoints
    ADMIN = "admin"            # Admin/management endpoints
    FILE_ACCESS = "file"       # File upload/download endpoints
    SENSITIVE = "sensitive"    # Potentially sensitive endpoints
    DYNAMIC = "dynamic"        # Dynamic content endpoints
    STATIC = "static"          # Static resource endpoints
    UNKNOWN = "unknown"        # Unclassified endpoints


class ParameterType(str, Enum):
    """Parameter type classifications."""
    ID = "id"                  # Identifier parameters
    FILE = "file"              # File parameters
    SEARCH = "search"          # Search parameters
    AUTH = "auth"              # Authentication parameters
    EMAIL = "email"            # Email parameters
    URL = "url"                # URL parameters
    INTEGER = "integer"        # Integer parameters
    STRING = "string"          # String parameters
    BOOLEAN = "boolean"        # Boolean parameters
    UNKNOWN = "unknown"        # Unknown type


class ParameterInfo(BaseModel):
    """Information about an endpoint parameter."""
    name: str = Field(..., description="Parameter name")
    type: ParameterType = Field(default=ParameterType.UNKNOWN, description="Inferred parameter type")
    location: str = Field(..., description="Parameter location (query, body, path)")
    value: Optional[str] = Field(None, description="Example value if found")
    required: Optional[bool] = Field(None, description="Whether parameter is required")


class FormInfo(BaseModel):
    """Information about HTML forms."""
    action: str = Field(..., description="Form action URL")
    method: str = Field(..., description="Form HTTP method")
    inputs: List[ParameterInfo] = Field(default_factory=list, description="Form input fields")


class EndpointInfo(BaseModel):
    """Information about a discovered endpoint."""
    url: str = Field(..., description="Full endpoint URL")
    path: str = Field(..., description="URL path")
    method: str = Field(default="GET", description="HTTP method")
    category: EndpointCategory = Field(default=EndpointCategory.UNKNOWN, description="Endpoint category")
    parameters: List[ParameterInfo] = Field(default_factory=list, description="Query/body parameters")
    forms: List[FormInfo] = Field(default_factory=list, description="HTML forms if found")
    source: str = Field(..., description="Discovery source (katana, gau, kiterunner)")
    status_code: Optional[int] = Field(None, description="HTTP status code if verified")
    content_length: Optional[int] = Field(None, description="Response content length")
    is_live: Optional[bool] = Field(None, description="Whether endpoint is currently accessible")


class ResourceEnumRequest(BaseModel):
    """Resource enumeration request configuration."""
    targets: List[str] = Field(..., description="List of target domains or base URLs")
    mode: EnumMode = Field(default=EnumMode.FULL, description="Enumeration mode")
    
    # Katana settings
    katana_enabled: bool = Field(default=True, description="Enable Katana crawling")
    crawl_depth: int = Field(default=3, ge=1, le=5, description="Maximum crawl depth")
    max_katana_urls: int = Field(default=500, ge=1, le=10000, description="Maximum URLs to crawl")
    js_crawling: bool = Field(default=True, description="Enable JavaScript rendering")
    extract_forms: bool = Field(default=True, description="Extract HTML forms")
    
    # GAU settings
    gau_enabled: bool = Field(default=True, description="Enable GAU")
    gau_providers: List[str] = Field(
        default=["wayback", "commoncrawl", "otx", "urlscan"],
        description="GAU providers to use"
    )
    max_gau_urls: int = Field(default=1000, ge=1, le=50000, description="Maximum historical URLs")
    verify_urls: bool = Field(default=True, description="Verify URL liveness")
    
    # Kiterunner settings
    kiterunner_enabled: bool = Field(default=True, description="Enable Kiterunner")
    wordlist: str = Field(default="routes-large", description="Wordlist to use")
    kite_threads: int = Field(default=10, ge=1, le=50, description="Number of threads")
    kite_rate_limit: int = Field(default=100, ge=1, le=1000, description="Requests per second")
    
    # General settings
    timeout: int = Field(default=300, ge=10, le=3600, description="Overall timeout in seconds")
    parallel_execution: bool = Field(default=True, description="Run tools in parallel")
    classify_endpoints: bool = Field(default=True, description="Classify endpoints by category")
    infer_param_types: bool = Field(default=True, description="Infer parameter types")

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v: List[str]) -> List[str]:
        """Validate that targets list is not empty."""
        if not v:
            raise ValueError("Targets list cannot be empty")
        return v


class ResourceEnumStats(BaseModel):
    """Statistics from resource enumeration."""
    total_endpoints: int = Field(default=0, description="Total unique endpoints discovered")
    katana_endpoints: int = Field(default=0, description="Endpoints from Katana")
    gau_endpoints: int = Field(default=0, description="Endpoints from GAU")
    kiterunner_endpoints: int = Field(default=0, description="Endpoints from Kiterunner")
    live_endpoints: int = Field(default=0, description="Verified live endpoints")
    total_parameters: int = Field(default=0, description="Total parameters discovered")
    total_forms: int = Field(default=0, description="Total forms discovered")
    categories: Dict[str, int] = Field(default_factory=dict, description="Endpoints by category")
    methods: Dict[str, int] = Field(default_factory=dict, description="Endpoints by HTTP method")
    execution_time: float = Field(default=0.0, description="Total execution time in seconds")


class ResourceEnumResult(BaseModel):
    """Complete resource enumeration result."""
    request: ResourceEnumRequest = Field(..., description="Original request configuration")
    endpoints: List[EndpointInfo] = Field(default_factory=list, description="Discovered endpoints")
    stats: ResourceEnumStats = Field(..., description="Enumeration statistics")
    errors: List[str] = Field(default_factory=list, description="Errors encountered during enumeration")
    success: bool = Field(default=True, description="Overall success status")
