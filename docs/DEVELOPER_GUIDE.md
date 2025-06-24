# UniVex — Developer Guide

> Everything you need to contribute to UniVex: environment setup, code
> standards, testing practices, and the pull-request workflow.

---

## Table of Contents

1. [Development Environment Setup](#development-environment-setup)
2. [Project Structure](#project-structure)
3. [Code Standards](#code-standards)
4. [Testing Practices](#testing-practices)
5. [API Development](#api-development)
6. [Frontend Development](#frontend-development)
7. [Git Workflow](#git-workflow)
8. [Pull Request Guidelines](#pull-request-guidelines)
9. [Release Process](#release-process)
10. [Debugging Tips](#debugging-tips)

---

## Development Environment Setup

### 1. Fork and clone

```bash
git clone https://github.com/<your-fork>/UniVex.git univex
cd univex
git remote add upstream https://github.com/BitR1ft/UniVex.git
```

### 2. Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt
```

Required tools (installed automatically via `requirements-dev.txt`):

| Tool | Purpose |
|------|---------|
| `pytest` | Test runner |
| `pytest-asyncio` | Async test support |
| `pytest-cov` | Coverage measurement |
| `httpx` | Test HTTP client |
| `ruff` | Linter + formatter |
| `mypy` | Static type checker |
| `bandit` | Security linter |

### 3. Frontend

```bash
cd frontend
npm install
```

### 4. Infrastructure (Postgres + Neo4j)

```bash
docker compose up -d postgres neo4j
```

### 5. Pre-commit hooks (recommended)

```bash
pip install pre-commit
pre-commit install
```

The `.pre-commit-config.yaml` runs ruff, mypy, and ESLint before every commit.

---

## Project Structure

```
univex/
 backend/
    app/
       api/          # FastAPI routers (v1 endpoints)
       core/         # Cross-cutting concerns
          auth.py
          audit.py
          database.py
          logging.py
          metrics.py
          rate_limit.py
          rbac.py
          secrets.py
          tracing.py
          waf.py
       models/       # Pydantic request/response schemas
       services/     # Business logic layer
       agents/       # LangGraph AI agent
       mcp/          # MCP tool server implementations
       main.py       # FastAPI app factory
    prisma/
       schema.prisma # Database schema
       migrations/   # Applied migration SQL files
       seed.py       # Database seeder
    tests/            # pytest test suite
    requirements.txt
    requirements-dev.txt
 frontend/
    app/              # Next.js App Router pages
    components/       # React components
       ui/           # shadcn/ui primitives
       forms/        # Form components
       layout/       # Layout components
       graph/        # Graph visualisation
       chat/         # Agent chat components
    hooks/            # Custom React hooks
    lib/              # Utility libraries
       api.ts        # API client (axios)
       sse.ts        # SSE client utility
       websocket.ts  # WebSocket client utility
       utils.ts      # cn() and helpers
       validations.ts# Zod schemas
    store/            # Zustand state stores
    __tests__/        # Jest unit tests
    e2e/              # Playwright E2E tests (root /e2e/)
 .github/
    workflows/        # CI/CD pipeline definitions
 docker/
    staging/
    production/
 docs/                 # All documentation
 performance/          # k6 load tests
 e2e/                  # Playwright specs
 docker-compose.yml
```

---

## Code Standards

### Python (backend)

| Standard | Tool | Config |
|----------|------|--------|
| Formatting | `ruff format` | `pyproject.toml` |
| Linting | `ruff check` | `pyproject.toml` |
| Type checking | `mypy` | `mypy.ini` |
| Security linting | `bandit -r app/` | CI check |
| Docstrings | Google style | — |

**Run all backend checks:**

```bash
cd backend
ruff check app/ --fix
ruff format app/
mypy app/ --ignore-missing-imports
bandit -r app/ -ll
```

#### Key conventions

- All API endpoints are **async** (`async def`).
- Use `Annotated` + `Depends` for dependency injection.
- Return Pydantic response models — never expose internal ORM models directly.
- Use `logger.info(...)` with structured key-value pairs (not f-strings in log calls).
- Every new module gets a corresponding test file.

### TypeScript / React (frontend)

| Standard | Tool | Config |
|----------|------|--------|
| Formatting | Prettier (via ESLint) | `.eslintrc.json` |
| Linting | ESLint + `@typescript-eslint` | `.eslintrc.json` |
| Type checking | `tsc --noEmit` | `tsconfig.json` |
| Import order | `eslint-plugin-import` | `.eslintrc.json` |

**Run all frontend checks:**

```bash
cd frontend
npm run lint
npm run type-check
```

#### Key conventions

- All components are **functional** with explicit TypeScript props interfaces.
- State is managed via Zustand stores or React Query — avoid prop drilling.
- Server components (`'use server'`) for data-fetching; client components
  (`'use client'`) for interactivity.
- Custom hooks live in `frontend/hooks/` and must have corresponding tests.
- Use `cn()` from `lib/utils.ts` for conditional class names.

---

## Testing Practices

### Backend

```bash
cd backend
pytest tests/ -v --cov=app --cov-report=term-missing
```

Minimum coverage thresholds:

| Layer | Target |
|-------|--------|
| `app/core/` | 90% |
| `app/services/` | 80% |
| `app/api/` | 75% |
| Overall | 70% |

#### Test file naming

| Test type | Convention | Example |
|-----------|-----------|---------|
| Unit | `test_<module>.py` | `test_rate_limit.py` |
| Integration | `test_<week>_integration.py` | `test_week26_integration.py` |
| Chaos | `test_chaos.py` | — |

#### Async tests

Use `@pytest.mark.asyncio` and the shared `async_client` fixture:

```python
@pytest.mark.asyncio
async def test_create_project(async_client: AsyncClient):
    response = await async_client.post("/api/v1/projects", json={...})
    assert response.status_code == 201
```

### Frontend

```bash
cd frontend
npm test               # Jest (watch mode)
npm run test:coverage  # Jest with coverage
```

#### Jest conventions

- Mock external modules at the top of the test file.
- Use `@testing-library/react` for component tests.
- Use `vi.fn()` / `jest.fn()` for callbacks; assert `.toHaveBeenCalledWith()`.
- Every hook should have a test in `__tests__/hooks/`.

#### E2E (Playwright)

```bash
npx playwright test              # run all specs
npx playwright test e2e/auth.spec.ts  # single spec
npx playwright show-report       # open HTML report
```

---

## API Development

### Adding a new endpoint

1. Create route file: `backend/app/api/v1/<resource>.py`
2. Define Pydantic request/response models in `backend/app/models/<resource>.py`
3. Add business logic to `backend/app/services/<resource>.py`
4. Register router in `backend/app/main.py`:
   ```python
   from app.api.v1 import my_resource
   app.include_router(my_resource.router, prefix="/api/v1")
   ```
5. Write tests in `backend/tests/test_<resource>.py`
6. Update `docs/API_REFERENCE.md`

### Endpoint template

```python
from fastapi import APIRouter, Depends, HTTPException, status
from app.core.rbac import require_permission, Permission
from app.models.my_resource import MyResourceCreate, MyResourceResponse

router = APIRouter(prefix="/my-resources", tags=["My Resources"])

@router.post("/", response_model=MyResourceResponse, status_code=status.HTTP_201_CREATED)
async def create_my_resource(
    payload: MyResourceCreate,
    _: None = Depends(require_permission(Permission.WRITE_PROJECTS)),
):
    # implementation
    ...
```

---

## Frontend Development

### Adding a new page

1. Create `frontend/app/(dashboard)/<route>/page.tsx`
2. If data-fetching is needed, use React Query via `hooks/use<Resource>.ts`
3. Add to `frontend/components/layout/Sidebar.tsx` navigation
4. Write tests in `frontend/__tests__/`

### Component template

```tsx
'use client';

import { FC } from 'react';
import { cn } from '@/lib/utils';

interface MyComponentProps {
  title: string;
  className?: string;
}

export const MyComponent: FC<MyComponentProps> = ({ title, className }) => {
  return (
    <div className={cn('rounded-lg p-4', className)}>
      <h2 className="text-lg font-semibold">{title}</h2>
    </div>
  );
};
```

### Adding a custom hook

```typescript
// frontend/hooks/useMyHook.ts
'use client';

import { useQuery } from '@tanstack/react-query';
import { apiClient } from '@/lib/api';

export function useMyHook(id: string) {
  return useQuery({
    queryKey: ['myResource', id],
    queryFn: () => apiClient.get(`/my-resources/${id}`).then(r => r.data),
    enabled: Boolean(id),
  });
}
```

---

## Git Workflow

We follow **GitHub Flow** (single trunk, short-lived feature branches):

```
main 
         ↑                  ↑
  feature/my-feature    fix/bug-description
```

### Branch naming

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feature/<slug>` | `feature/graph-3d-export` |
| Bug fix | `fix/<slug>` | `fix/sse-reconnect-loop` |
| Chore | `chore/<slug>` | `chore/update-dependencies` |
| Docs | `docs/<slug>` | `docs/api-reference` |

### Commit message format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `chore`, `test`, `refactor`, `perf`, `ci`

Examples:

```
feat(agent): add risk-tier approval workflow
fix(auth): prevent token refresh loop on 401
docs(api): document pagination contract
test(chaos): add neo4j unavailability scenario
```

---

## Pull Request Guidelines

### Before opening a PR

- [ ] All tests pass locally (`pytest` + `npm test`)
- [ ] `tsc --noEmit` exits 0
- [ ] `ruff check app/` and `ruff format --check app/` clean
- [ ] No new security issues (`bandit -r app/ -ll`)
- [ ] Documentation updated if behaviour changed
- [ ] `RELEASE_NOTES.md` updated if user-facing change

### PR description template

When opening a PR, use this template (also at `.github/PULL_REQUEST_TEMPLATE.md`):

```markdown
## Summary
Brief description of what and why.

## Changes
- Added X
- Changed Y
- Fixed Z

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual test steps: ...

## Checklist
- [ ] Tests pass
- [ ] Type check passes
- [ ] Lint clean
- [ ] Docs updated
- [ ] Breaking changes documented
```

### Review process

- Minimum 1 approving review required.
- CI must be green (all checks pass).
- No unresolved review comments.
- Squash merge to keep history clean.

---

## Release Process

Releases are automated via `.github/workflows/release.yml`. To trigger:

```bash
gh workflow run release.yml \
  -f bump_type=minor \
  -f dry_run=false
```

The workflow:
1. Bumps version in `package.json` / `pyproject.toml`
2. Generates changelog from `git log`
3. Creates a git tag `vX.Y.Z`
4. Builds and pushes multi-arch Docker images
5. Creates a GitHub Release with changelog

See [CI_CD_GUIDE.md](./CI_CD_GUIDE.md) for full release documentation.

---

## Debugging Tips

### Backend — attach debugger (VS Code)

Add to `.vscode/launch.json`:

```json
{
  "type": "python",
  "request": "attach",
  "name": "Attach to FastAPI",
  "connect": { "host": "localhost", "port": 5678 }
}
```

Start uvicorn with debugpy:

```bash
python -m debugpy --listen 5678 --wait-for-client \
  -m uvicorn app.main:app --reload
```

### Backend — inspect SQL queries

```bash
DB_ECHO=true uvicorn app.main:app --reload
```

### Frontend — Next.js debug mode

```bash
NODE_OPTIONS='--inspect' npm run dev
```

Then open `chrome://inspect` and attach to the Node process.

### Docker — live log tail

```bash
docker compose logs -f backend frontend
```

### Neo4j — query browser

Open **http://localhost:7474** and connect with your Neo4j credentials.

### Postgres — psql shell

```bash
docker compose exec postgres psql -U univex univex
```

---

*Last updated: March 2026*