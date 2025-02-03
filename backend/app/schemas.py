"""
Pydantic schemas for API request/response validation
"""
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List
from datetime import datetime
from enum import Enum


# ============================================================================
# User Schemas
# ============================================================================

class UserRole(str, Enum):
    """User role enumeration"""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class UserCreate(BaseModel):
    """Schema for user registration"""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)
    full_name: Optional[str] = Field(None, max_length=100)
    role: UserRole = UserRole.ANALYST

    @validator('username')
    def username_alphanumeric(cls, v):
        assert v.replace('_', '').replace('-', '').isalnum(), 'Username must be alphanumeric'
        return v


class UserLogin(BaseModel):
    """Schema for user login"""
    username: str
    password: str


class UserResponse(BaseModel):
    """Schema for user response"""
    id: str
    email: str
    username: str
    full_name: Optional[str]
    is_active: bool
    created_at: datetime
    role: UserRole = UserRole.ANALYST

    class Config:
        from_attributes = True


class Token(BaseModel):
    """Schema for authentication token"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    """Schema for token payload"""
    sub: str  # user_id
    exp: datetime
    iat: datetime
    type: Optional[str] = "access"


# ============================================================================
# Project Schemas
# ============================================================================

class ProjectStatus(str, Enum):
    """Project status enumeration"""
    DRAFT = "draft"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class ProjectCreate(BaseModel):
    """Schema for project creation"""
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    target: str = Field(..., min_length=1, max_length=500)
    project_type: str = Field(default="full_assessment")
    
    # Reconnaissance settings
    enable_subdomain_enum: bool = True
    enable_port_scan: bool = True
    enable_web_crawl: bool = True
    enable_tech_detection: bool = True
    
    # Scanning settings
    enable_vuln_scan: bool = True
    enable_nuclei: bool = True
    
    # Exploitation settings (disabled by default for safety)
    enable_auto_exploit: bool = False
    
    @validator('target')
    def validate_target(cls, v):
        """Validate target format"""
        # Basic validation - will enhance later
        if not v.strip():
            raise ValueError('Target cannot be empty')
        return v.strip()


class ProjectUpdate(BaseModel):
    """Schema for project update"""
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    status: Optional[ProjectStatus] = None


class ProjectResponse(BaseModel):
    """Schema for project response"""
    id: str
    name: str
    description: Optional[str]
    target: str
    project_type: str
    status: str
    created_at: datetime
    updated_at: datetime
    user_id: str
    
    # Settings
    enable_subdomain_enum: bool
    enable_port_scan: bool
    enable_web_crawl: bool
    enable_tech_detection: bool
    enable_vuln_scan: bool
    enable_nuclei: bool
    enable_auto_exploit: bool
    
    class Config:
        from_attributes = True


class ProjectListResponse(BaseModel):
    """Schema for project list response"""
    projects: List[ProjectResponse]
    total: int
    page: int
    page_size: int


# ============================================================================
# Common Schemas
# ============================================================================

class Message(BaseModel):
    """Generic message response"""
    message: str


class ErrorResponse(BaseModel):
    """Error response schema"""
    detail: str
    error_code: Optional[str] = None
