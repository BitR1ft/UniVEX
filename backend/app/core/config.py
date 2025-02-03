"""
Application Configuration
"""
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import validator


class Settings(BaseSettings):
    """Application settings"""
    
    # Project Information
    PROJECT_NAME: str = "UniVex"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "AI-Powered Penetration Testing Framework"
    ENVIRONMENT: str = "development"
    
    # API Configuration
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_V1_PREFIX: str = "/api"

    # -------------------------------------------------------------------------
    # API Versioning
    # -------------------------------------------------------------------------
    # Current canonical API version — used in X-API-Version response headers
    # and in the versioned route prefix /v{API_VERSION}/.
    # Bump to "2" when /v2/ routes are introduced.
    API_VERSION: str = "1"
    # Whether to expose the legacy /api/* routes alongside /v1/api/* routes.
    # Set to False after a planned deprecation period to force clients to
    # migrate to versioned endpoints.
    API_LEGACY_ROUTES_ENABLED: bool = True
    
    # Security
    # SECRET_KEY has NO default — it MUST be set via environment variable.
    # Generate a safe value with: python -c "import secrets; print(secrets.token_hex(32))"
    # The application will refuse to start if this is unset or too short.
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
    ]
    
    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v):
        if isinstance(v, str):
            return [i.strip() for i in v.split(",")]
        return v
    
    # Database - PostgreSQL
    POSTGRES_USER: str = "univex"
    POSTGRES_PASSWORD: str = "univex_dev_password"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "univex"
    
    @property
    def DATABASE_URL(self) -> str:
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
    
    # Database - Neo4j
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "univex_dev_password"
    NEO4J_DATABASE: str = "neo4j"
    
    # AI Configuration — Global defaults
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o"
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-3-5-sonnet-20241022"
    GOOGLE_API_KEY: str = ""
    GOOGLE_MODEL: str = "gemini-1.5-flash"
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_MODEL: str = "anthropic/claude-3.5-sonnet"

    # -------------------------------------------------------------------------
    # Per-Agent Model Configuration
    # -------------------------------------------------------------------------
    # Each agent role supports an independent model, provider, temperature, and
    # max_tokens setting.  Environment variables take highest priority; fall
    # through to agents.yaml and then the built-in defaults below.
    #
    # Naming convention: {AGENT_ROLE_UPPER}_{SETTING}
    #   e.g.  PLANNER_MODEL, RECON_TEMPERATURE, EXPLOIT_MAX_TOKENS
    # -------------------------------------------------------------------------

    # Planner Agent
    PLANNER_MODEL: str = "gpt-4o"
    PLANNER_TEMPERATURE: float = 0.2
    PLANNER_MAX_TOKENS: int = 4096
    PLANNER_PROVIDER: str = "openai"

    # Recon Agent
    RECON_MODEL: str = "gpt-4o-mini"
    RECON_TEMPERATURE: float = 0.1
    RECON_MAX_TOKENS: int = 4096
    RECON_PROVIDER: str = "openai"

    # Exploit Agent
    EXPLOIT_MODEL: str = "claude-3-5-sonnet-20241022"
    EXPLOIT_TEMPERATURE: float = 0.1
    EXPLOIT_MAX_TOKENS: int = 4096
    EXPLOIT_PROVIDER: str = "anthropic"

    # WebApp Agent
    WEBAPP_MODEL: str = "gpt-4o"
    WEBAPP_TEMPERATURE: float = 0.1
    WEBAPP_MAX_TOKENS: int = 4096
    WEBAPP_PROVIDER: str = "openai"

    # Report Agent
    REPORT_MODEL: str = "gpt-4o-mini"
    REPORT_TEMPERATURE: float = 0.3
    REPORT_MAX_TOKENS: int = 8192
    REPORT_PROVIDER: str = "openai"

    # Global agent settings
    AGENT_MAX_TOKENS: int = 4096
    AGENT_SUMMARY_THRESHOLD: float = 0.75  # Trigger context summarisation at 75%

    # Path to per-agent YAML config (overrides env var per-agent settings)
    AGENTS_CONFIG_PATH: str = ""

    # -------------------------------------------------------------------------
    # Proxy Configuration
    # -------------------------------------------------------------------------
    # Route all LLM provider API calls through a SOCKS5 or HTTP proxy.
    # Examples:
    #   PROXY_URL=socks5://user:pass@proxy.internal:1080
    #   PROXY_URL=http://proxy.internal:8080
    PROXY_URL: Optional[str] = None

    # -------------------------------------------------------------------------
    # Knowledge Graph — Graphiti
    # -------------------------------------------------------------------------
    GRAPHITI_URL: str = "http://graphiti:8010"
    GRAPHITI_API_KEY: Optional[str] = None
    GRAPHITI_ENABLED: bool = True

    # -------------------------------------------------------------------------
    # Episodic Memory
    # -------------------------------------------------------------------------
    # Maximum memory entries stored per pentest flow before eviction
    MEMORY_MAX_ENTRIES_PER_FLOW: int = 10_000
    # Auto-capture agent outputs to memory (can disable for debugging)
    AUTO_CAPTURE_MEMORY: bool = True
    
    # AutoChain — automated pentest pipeline
    # Maximum risk level auto-approved without human confirmation.
    # Values: none | low | medium | high | critical
    # Use 'critical' for HTB lab mode (approves all exploits automatically).
    # Use 'high' to auto-approve up to high-risk actions only.
    AUTO_APPROVE_RISK_LEVEL: str = "none"

    # Redis
    REDIS_URL: str = "redis://localhost:6379"

    # MCP server URLs (overridable for testing / custom deployments)
    NAABU_MCP_URL: str = "http://kali-tools:8000"
    NUCLEI_MCP_URL: str = "http://kali-tools:8002"
    MSF_MCP_URL: str = "http://kali-tools:8003"

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    LOG_CORRELATION_ID_HEADER: str = "X-Request-ID"

    # -------------------------------------------------------------------------
    # Langfuse LLM Observability
    # -------------------------------------------------------------------------
    # Self-hosted: set LANGFUSE_HOST to your Langfuse server URL.
    # Cloud:       leave LANGFUSE_HOST at the default (https://cloud.langfuse.com).
    LANGFUSE_PUBLIC_KEY: str = ""
    LANGFUSE_SECRET_KEY: str = ""
    LANGFUSE_HOST: str = "https://cloud.langfuse.com"
    LANGFUSE_ENABLED: bool = True
    LANGFUSE_DEBUG: bool = False
    # Batch flush settings — tune for throughput vs. latency
    LANGFUSE_FLUSH_AT: int = 15
    LANGFUSE_FLUSH_INTERVAL: float = 0.5
    LANGFUSE_THREADS: int = 1
    # Sample fraction — 0.0 captures nothing, 1.0 captures everything
    LANGFUSE_SAMPLE_RATE: float = 1.0

    # -------------------------------------------------------------------------
    # Loki Log Aggregation
    # -------------------------------------------------------------------------
    LOKI_URL: str = "http://loki:3100"
    LOKI_ENABLED: bool = False   # Enabled automatically when LOKI_URL is reachable
    LOKI_BATCH_SIZE: int = 100
    LOKI_FLUSH_INTERVAL: float = 2.0
    LOKI_TIMEOUT: int = 5

    # -------------------------------------------------------------------------
    # Jaeger Distributed Tracing
    # -------------------------------------------------------------------------
    # When set, the OTEL exporter sends spans to this Jaeger/OTLP endpoint.
    JAEGER_ENABLED: bool = False
    JAEGER_OTLP_ENDPOINT: str = "http://jaeger:4317"   # gRPC OTLP endpoint
    JAEGER_AGENT_HOST: str = "jaeger"
    JAEGER_AGENT_PORT: int = 6831

    # -------------------------------------------------------------------------
    # Custom CA Certificates & SSL
    # -------------------------------------------------------------------------
    # Path to a PEM file or directory containing custom CA certificates.
    # Certificates are merged with the system default trust store so that
    # standard public CAs remain trusted alongside your private PKI.
    # Critical for enterprise environments with internal PKI.
    #   Example: EXTERNAL_SSL_CA_PATH=/etc/ssl/custom-ca/corp-root-ca.pem
    EXTERNAL_SSL_CA_PATH: Optional[str] = None

    # Set to "false" to skip TLS certificate verification.
    # DEVELOPMENT ONLY — never disable in production.
    SSL_VERIFY: bool = True

    # Minimum TLS version to accept for outbound connections.
    # Accepted values: "TLSv1_2" (default) | "TLSv1_3"
    SSL_MIN_TLS_VERSION: str = "TLSv1_2"

    # Client certificate (mTLS) for enterprise SSO or mutual authentication.
    SSL_CLIENT_CERT_PATH: Optional[str] = None
    SSL_CLIENT_KEY_PATH: Optional[str] = None
    SSL_CLIENT_KEY_PASSWORD: Optional[str] = None

    # -------------------------------------------------------------------------
    # Cookie Security
    # -------------------------------------------------------------------------
    # HMAC-SHA256 salt for signing session cookies.
    # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
    # Must be at least 32 characters in production.
    COOKIE_SIGNING_SALT: str = ""

    # Session cookie flags — align with your deployment TLS setup.
    SESSION_COOKIE_SECURE: bool = True      # Set False only behind HTTP load balancers
    SESSION_COOKIE_HTTPONLY: bool = True    # Never expose to JavaScript
    SESSION_COOKIE_SAMESITE: str = "Lax"   # "Strict" | "Lax" | "None"
    SESSION_COOKIE_DOMAIN: Optional[str] = None
    SESSION_COOKIE_PATH: str = "/"
    SESSION_COOKIE_MAX_AGE: int = 1800     # 30 minutes

    class Config:
        env_file = ".env"
        case_sensitive = True


# Create settings instance
settings = Settings()
