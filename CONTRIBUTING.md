# Contributing to UniVex

Thank you for your interest in contributing to UniVex. This document covers everything you need to get started: development setup, coding standards, testing, and the pull request process.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Project Structure](#project-structure)
5. [Coding Standards](#coding-standards)
6. [Testing](#testing)
7. [Pull Request Process](#pull-request-process)
8. [Commit Messages](#commit-messages)
9. [Reporting Bugs and Requesting Features](#reporting-bugs-and-requesting-features)

---

## Code of Conduct

UniVex is a penetration testing platform intended exclusively for authorized security research. All contributors are expected to:

- Only test against systems they own or have explicit written permission to test
- Never use UniVex or its contributions for unauthorized or malicious purposes
- Respect privacy and data protection laws
- Report security vulnerabilities responsibly (see [.github/SECURITY.md](.github/SECURITY.md))

---

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/UniVex.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes and write tests
5. Submit a pull request

---

## Development Setup

### Prerequisites

- Python 3.11+
- Node.js 20+
- Docker 24+ and Docker Compose V2
- Git

### Backend (FastAPI + Python)

```bash
cd backend
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Frontend (Next.js + TypeScript)

```bash
cd frontend
npm install
npm run dev
```

### Full stack via Docker

```bash
cp .env.example .env              # edit with your API keys
docker compose up -d
```

### Running databases only (for local development)

```bash
docker compose up -d postgres neo4j redis
```

---

## Project Structure

```
UniVex/
├── backend/                  # FastAPI backend
│   ├── app/
│   │   ├── agent/            # AI agent, tools, memory, mock
│   │   ├── analytics/        # ClickHouse analytics
│   │   ├── api/              # REST API routes
│   │   ├── campaigns/        # Campaign engine
│   │   ├── compliance/       # Compliance engine
│   │   ├── core/             # Config, auth, security
│   │   ├── embeddings/       # Embedding providers
│   │   ├── graph/            # Neo4j / BloodHound ingestion
│   │   ├── graphql/          # Strawberry GraphQL API
│   │   ├── installer/        # TUI installer
│   │   ├── llm/              # LLM providers and registry
│   │   ├── mcp/              # MCP tool servers
│   │   ├── models/           # Prisma ORM models
│   │   ├── plugins/          # Plugin system
│   │   ├── proxy/            # HTTP proxy engine
│   │   ├── reports/          # PDF/HTML report generation
│   │   ├── schemas/          # Pydantic schemas
│   │   ├── services/         # Business logic
│   │   ├── storage/          # MinIO artifact storage
│   │   ├── worker/           # Distributed worker client/server
│   │   └── oob/              # Out-of-band listener
│   ├── tests/                # pytest tests (4,300+)
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   └── Dockerfile
├── frontend/                 # Next.js frontend
│   ├── app/                  # App router pages
│   ├── components/           # React components
│   ├── hooks/                # Custom React hooks
│   ├── lib/                  # Utilities
│   └── package.json
├── docs/                     # Extended documentation
├── scripts/                  # Installer and helper scripts
├── docker/                   # Dockerfiles for services
├── docker-compose.yml
└── README.md
```

---

## Coding Standards

### Python (Backend)

- Follow **PEP 8** — enforced with `black` (line length 88) and `flake8`
- Use **type hints** on all function signatures
- Use **async/await** for all I/O operations
- Write **docstrings** for all public functions and classes
- Run `mypy` for type checking before submitting

```python
async def create_project(
    project_data: ProjectCreate,
    user_id: str,
) -> Project:
    """
    Create a new penetration testing project.

    Args:
        project_data: Validated project creation payload.
        user_id: ID of the authenticated user.

    Returns:
        The newly created Project instance.

    Raises:
        ValueError: If project_data is invalid.
    """
    ...
```

### TypeScript (Frontend)

- Follow the **Airbnb TypeScript Style Guide**
- Use **strict TypeScript** configuration (`"strict": true`)
- Prefer **Server Components** by default; use Client Components only when necessary
- Write JSDoc comments for non-obvious logic

### General

- DRY (Don't Repeat Yourself) — extract reusable logic
- Meaningful, descriptive names for variables, functions, and classes
- Always handle errors gracefully; never swallow exceptions silently
- Never hardcode secrets — load all credentials from environment variables

---

## Testing

### Backend

Tests run with **pytest**. Run with `PYTHONPATH=backend`:

```bash
# Run all tests
cd backend && PYTHONPATH=backend pytest

# Run a specific test file
PYTHONPATH=backend pytest tests/agent/test_proxy_tools.py

# Verbose output
PYTHONPATH=backend pytest -v

# Coverage report
PYTHONPATH=backend pytest --cov=app
```

Requirements:
- Minimum **80% code coverage** for new modules
- All API endpoints must have tests covering success and failure cases
- Use `asyncio.run()` in async tests — never `asyncio.get_event_loop().run_until_complete()` (fails on Python 3.12+)
- Use fixtures for shared setup

### Frontend

```bash
cd frontend
npm test                    # Run all Jest tests
npm test -- --coverage      # Coverage report
```

### Adding New Agent Tools

When adding a new agent tool:
1. Extend the appropriate base class in `backend/app/agent/tools/`
2. Register the tool in the relevant MCP server under `backend/app/mcp/servers/`
3. Add at least 5 unit tests in `backend/tests/agent/`
4. Document the tool's required environment variables or external dependencies

### Plugin Development

See [docs/PLUGIN_GUIDE.md](docs/PLUGIN_GUIDE.md) for the full plugin development guide.

```python
# backend/app/plugins/my_plugin.py
from app.plugins.base import BasePlugin, PluginResult

class MyPlugin(BasePlugin):
    name = "my-plugin"
    version = "1.0.0"
    description = "My custom UniVex plugin"

    async def execute(self, context: dict) -> PluginResult:
        return PluginResult(success=True, data={"result": "..."})
```

---

## Pull Request Process

1. **Write tests** for all new functionality
2. **Run linters** and fix all reported issues:
   ```bash
   # Backend
   cd backend
   black app/
   flake8 app/
   mypy app/

   # Frontend
   cd frontend
   npm run lint
   npm run type-check
   ```
3. **Ensure all tests pass** locally before opening the PR
4. **Update documentation** if you changed any public API or behavior
5. **Update CHANGELOG.md** with a summary of your change
6. **Reference the relevant issue** in the PR description
7. **Request a review** from a maintainer

PRs without tests, failing CI, or missing documentation will not be merged.

---

## Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <short summary>

<optional body>

<optional footer>
```

**Types:**
- `feat` — new feature
- `fix` — bug fix
- `docs` — documentation only
- `style` — formatting, no logic change
- `refactor` — code restructuring without behavior change
- `test` — adding or updating tests
- `chore` — maintenance, dependency updates

**Examples:**
```
feat(proxy): add WebSocket frame replay support

Implements replay of captured WebSocket frames via the proxy API.
Frames are stored in request_store with the parent request ID.

Closes #234
```

```
fix(auth): resolve token refresh race condition

Concurrent refresh calls now use a lock to prevent duplicate token
issuance. Adds integration test covering the concurrent case.

Fixes #301
```

---

## Reporting Bugs and Requesting Features

### Bug Reports

Open a GitHub Issue and include:
- Clear description of the bug
- Step-by-step reproduction instructions
- Expected vs. actual behavior
- Environment: OS, Docker version, Python/Node version
- Relevant logs or error output

### Feature Requests

Open a GitHub Issue and describe:
- The use case and why the feature is needed
- Your proposed solution or API design
- Security implications, if any

### Security Vulnerabilities

Do **not** open a public issue for security vulnerabilities. Use GitHub's [private security advisory](https://github.com/BitR1ft/UniVex/security/advisories/new). See [.github/SECURITY.md](.github/SECURITY.md) for the full disclosure policy.

---

Thank you for contributing to UniVex.
