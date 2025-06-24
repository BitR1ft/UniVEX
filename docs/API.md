# UniVex - API Documentation

## Base URL
```
Development: http://localhost:8000
Production: [To be configured]
```

## Authentication

All protected endpoints require a JWT token in the Authorization header:
```
Authorization: Bearer <access_token>
```

### Endpoints

---

## Authentication Endpoints

### Register User
**POST** `/api/auth/register`

Register a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "username": "username",
  "password": "password123",
  "full_name": "John Doe" // Optional
}
```

**Response:** `201 Created`
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "username": "username",
  "full_name": "John Doe",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00Z"
}
```

**Errors:**
- `400 Bad Request`: Username or email already exists
- `422 Unprocessable Entity`: Invalid input data

---

### Login
**POST** `/api/auth/login`

Authenticate and receive access tokens.

**Request Body:**
```json
{
  "username": "username",
  "password": "password123"
}
```

**Response:** `200 OK`
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer"
}
```

**Errors:**
- `401 Unauthorized`: Invalid credentials
- `403 Forbidden`: User account is inactive

---

### Get Current User
**GET** `/api/auth/me`

Get information about the currently authenticated user.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "username": "username",
  "full_name": "John Doe",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00Z"
}
```

**Errors:**
- `401 Unauthorized`: Invalid or expired token
- `404 Not Found`: User not found

---

### Refresh Token
**POST** `/api/auth/refresh`

Refresh an expired access token using a refresh token.

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Response:** `200 OK`
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer"
}
```

**Errors:**
- `401 Unauthorized`: Invalid or expired refresh token

---

## Project Endpoints

### Create Project
**POST** `/api/projects`

Create a new penetration testing project.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "name": "My Project",
  "description": "Project description",
  "target": "example.com",
  "project_type": "full_assessment",
  "enable_subdomain_enum": true,
  "enable_port_scan": true,
  "enable_web_crawl": true,
  "enable_tech_detection": true,
  "enable_vuln_scan": true,
  "enable_nuclei": true,
  "enable_auto_exploit": false
}
```

**Response:** `201 Created`
```json
{
  "id": "uuid",
  "name": "My Project",
  "description": "Project description",
  "target": "example.com",
  "project_type": "full_assessment",
  "status": "draft",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z",
  "user_id": "uuid",
  "enable_subdomain_enum": true,
  "enable_port_scan": true,
  "enable_web_crawl": true,
  "enable_tech_detection": true,
  "enable_vuln_scan": true,
  "enable_nuclei": true,
  "enable_auto_exploit": false
}
```

**Errors:**
- `401 Unauthorized`: Not authenticated
- `422 Unprocessable Entity`: Invalid input data

---

### List Projects
**GET** `/api/projects`

Get a list of all projects for the current user.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Query Parameters:**
- `page` (int, default: 1): Page number
- `page_size` (int, default: 20, max: 100): Results per page
- `status` (string, optional): Filter by status (draft, queued, running, paused, completed, failed)

**Response:** `200 OK`
```json
{
  "projects": [
    {
      "id": "uuid",
      "name": "My Project",
      "target": "example.com",
      "status": "draft",
      "created_at": "2024-01-01T00:00:00Z",
      ...
    }
  ],
  "total": 10,
  "page": 1,
  "page_size": 20
}
```

**Errors:**
- `401 Unauthorized`: Not authenticated

---

### Get Project
**GET** `/api/projects/{project_id}`

Get details of a specific project.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "name": "My Project",
  "description": "Project description",
  "target": "example.com",
  "status": "draft",
  ...
}
```

**Errors:**
- `401 Unauthorized`: Not authenticated
- `403 Forbidden`: Not authorized to access this project
- `404 Not Found`: Project not found

---

### Update Project
**PATCH** `/api/projects/{project_id}`

Update project details.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "name": "Updated Name",
  "description": "Updated description",
  "status": "queued"
}
```

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "name": "Updated Name",
  "description": "Updated description",
  "status": "queued",
  ...
}
```

**Errors:**
- `401 Unauthorized`: Not authenticated
- `403 Forbidden`: Not authorized to modify this project
- `404 Not Found`: Project not found

---

### Delete Project
**DELETE** `/api/projects/{project_id}`

Delete a project.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "message": "Project deleted successfully"
}
```

**Errors:**
- `401 Unauthorized`: Not authenticated
- `403 Forbidden`: Not authorized to delete this project
- `404 Not Found`: Project not found

---

## Health Check Endpoints

### Root
**GET** `/`

Basic API health check.

**Response:** `200 OK`
```json
{
  "message": "UniVex API",
  "status": "operational",
  "version": "0.1.0",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

---

### Health
**GET** `/health`

Detailed health check including service status.

**Response:** `200 OK`
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00Z",
  "version": "0.1.0",
  "services": {
    "api": "operational",
    "database": "not_configured",
    "neo4j": "not_configured"
  }
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "detail": "Error message",
  "error_code": "ERROR_CODE" // Optional
}
```

### Common HTTP Status Codes
- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Authentication required or failed
- `403 Forbidden`: Authenticated but not authorized
- `404 Not Found`: Resource not found
- `422 Unprocessable Entity`: Validation error
- `500 Internal Server Error`: Server error

---

## Interactive Documentation

When the backend is running, you can access interactive API documentation:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
