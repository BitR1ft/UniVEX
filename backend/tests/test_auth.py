"""
Tests for authentication endpoints
"""
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.mark.asyncio
async def test_register_user():
    """Test user registration"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/auth/register",
            json={
                "email": "test@example.com",
                "username": "testuser",
                "password": "testpass123",
                "full_name": "Test User"
            }
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "test@example.com"
        assert data["username"] == "testuser"
        assert "id" in data


@pytest.mark.asyncio
async def test_register_duplicate_username():
    """Test registration with duplicate username"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # First registration
        await client.post(
            "/api/auth/register",
            json={
                "email": "user1@example.com",
                "username": "duplicate",
                "password": "password123"
            }
        )
        
        # Second registration with same username
        response = await client.post(
            "/api/auth/register",
            json={
                "email": "user2@example.com",
                "username": "duplicate",
                "password": "password123"
            }
        )
        
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"]


@pytest.mark.asyncio
async def test_login():
    """Test user login"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Register user first
        await client.post(
            "/api/auth/register",
            json={
                "email": "login@example.com",
                "username": "loginuser",
                "password": "loginpass123"
            }
        )
        
        # Login
        response = await client.post(
            "/api/auth/login",
            json={
                "username": "loginuser",
                "password": "loginpass123"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password():
    """Test login with wrong password"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Register user
        await client.post(
            "/api/auth/register",
            json={
                "email": "user@example.com",
                "username": "testuser2",
                "password": "correctpassword"
            }
        )
        
        # Login with wrong password
        response = await client.post(
            "/api/auth/login",
            json={
                "username": "testuser2",
                "password": "wrongpassword"
            }
        )
        
        assert response.status_code == 401
