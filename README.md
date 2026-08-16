# UniVex

UniVex is an autonomous penetration testing platform that combines AI-driven orchestration with security tooling to help authorized teams run structured offensive security workflows.

> ⚠️ **Authorized use only.** Use UniVex only on systems you own or are explicitly permitted to test.


## Overview

UniVex provides:

- A web interface for managing projects and scan workflows
- A FastAPI backend for orchestration, APIs, and integrations
- Containerized security tooling for recon and validation tasks
- Graph-backed attack/path visualization support

The platform is designed for controlled environments where repeatability, visibility, and authorization are mandatory.

## Key Features

- **AI-assisted orchestration** for pentest workflow automation
- **Project-based targeting** to scope assessments clearly
- **Containerized tool execution** for operational isolation
- **Multi-service architecture** (frontend, backend, databases, tooling)
- **Extensible backend modules** for recon and vulnerability workflows

## Tech Stack

- **Frontend:** Next.js / TypeScript
- **Backend:** Python, FastAPI
- **Datastores:** PostgreSQL, Neo4j
- **Containers:** Docker, Docker Compose
- **Testing:** Pytest, Jest, Playwright

## Repository Structure

```text
UniVex/
├── backend/        # FastAPI services, orchestration, recon modules
├── frontend/       # Next.js application
├── docs/           # Project documentation
├── docker/         # Dockerfiles and container assets
├── e2e/            # End-to-end tests
├── performance/    # Performance/load testing assets
├── scripts/        # Utility and automation scripts
└── docker-compose.yml
```

## Prerequisites

Before running UniVex, ensure you have:

- **Docker Engine** (with Compose plugin)
- **Node.js 20+** (for frontend development)
- **Python 3.11+** (for backend development)

## Quick Start

From the repository root:

```bash
cp .env.example .env
docker compose up --build
```

Then open:

- Frontend: `http://localhost:3000`
- Backend API docs: `http://localhost:8000/docs`

## Local Development

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

## Environment Configuration

1. Copy `.env.example` to `.env`
2. Configure required values (database credentials, auth secrets, provider keys)
3. Never commit real secrets

If you run production-like deployments, use dedicated environment files and secret management.

## Testing

### Backend tests

```bash
cd backend
pytest
```

### Frontend tests

```bash
cd frontend
npm test
```

### End-to-end tests

```bash
npx playwright test
```

## Documentation

See the `/docs` directory for detailed guides and references, including architecture, API usage, and security-related documentation.

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch
3. Add or update tests when applicable
4. Open a pull request

For contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

If you discover a security issue, report it responsibly through GitHub Security Advisories rather than public issues.

## License

This project is licensed under the Apache License. See [LICENSE](LICENSE).
