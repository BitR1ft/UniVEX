# UniVex — Testing Guide

> This document describes the complete testing strategy for UniVex,
> covering unit tests, integration tests, contract tests, E2E tests,
> performance tests, and chaos tests.

---

## Coverage Targets

| Layer              | Tool          | Target | Current |
|--------------------|---------------|--------|---------|
| Backend (Python)   | pytest + coverage.py | ≥ 80% |  |
| Frontend (TS/React)| Jest + Testing Library | ≥ 70% |  |
| E2E                | Playwright    | Key flows covered |  |
| Performance        | k6            | Baselines documented |  |
| Chaos              | pytest + mocks | Failure scenarios |  |

---

## Test File Structure

```
backend/tests/
 conftest.py                    # Shared fixtures & mocks
 test_auth.py                   # Auth unit tests
 test_repositories.py           # Repository layer tests
 test_services.py               # Service layer tests
 test_week3_api.py  # API endpoint tests
 test_week4_framework.py  # Recon framework tests
 test_week5_port_scanning.py  # Port scanning tests
 test_week6_vuln_scanning.py  # Vuln scanning tests
 test_week7_url_discovery.py  # URL discovery tests
 test_week8_tech_detection.py  # Tech detection tests
 test_week9_cve_enrichment.py  # CVE enrichment tests
 test_week10_cwe_capec.py  # CWE/CAPEC tests
 test_week25_security.py  # Security hardening tests
 test_week26_integration.py  # Integration tests
 test_week26_contracts.py  # Contract tests
 test_chaos.py  # Chaos tests

frontend/__tests__/
 auth/
    auth.test.tsx              # LoginForm tests
 components/
    chat/
    forms/
    graph/
       AttackGraph3D.test.tsx
       GraphExport.test.tsx
       GraphFilterPanel.test.tsx
       NodeInspector.test.tsx
    layout/
    projects/
       ProjectCard.test.tsx
       ProjectWizard.test.tsx
    ui/
        Toast.test.tsx
        button.test.tsx
        card.test.tsx
        input.test.tsx
 hooks/
    useFormAutosave.test.ts
    useGraph.test.ts
    useMediaQuery.test.ts
    useProjects.test.ts  #     useSSE.test.ts
    useWebSocket.test.ts  #  lib/
     utils.test.ts  #  validations.test.ts
e2e/
 auth.spec.ts  # Auth E2E
 projects.spec.ts  # Projects E2E
 recon.spec.ts  # Recon E2E
 graph.spec.ts  # Graph E2E

performance/
 k6-api.js  # k6 load tests
 BASELINES.md                   # Performance baselines
```

---

## Backend Testing

### Running Tests

```bash
# Navigate to backend directory
cd backend

# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html --cov-report=term-missing

# Run specific test file
pytest tests/test_week26_integration.py -v

# Run a single test
pytest tests/test_week25_security.py::test_admin_has_all_permissions -v

# Run chaos tests
pytest tests/test_chaos.py -v

# Run with verbose output and stop on first failure
pytest -x -v
```

### Test Categories

| Category | Files | Description |
|----------|-------|-------------|
| Unit | `test_*_security.py`, `test_repositories.py` | Isolated component tests with mocks |
| Integration | `test_week26_integration.py` | Multi-component tests with mocked DB |
| Contract | `test_week26_contracts.py` | API contract validation |
| Chaos | `test_chaos.py` | Failure simulation & degradation tests |

### Key Fixtures (`conftest.py`)

- `async_client` — Async HTTPX client connected to FastAPI app
- `auth_headers` — JWT token headers for authenticated requests
- `mock_project_service` — Pre-configured project service mock
- `mock_auth_service` — Pre-configured auth service mock

### Writing New Backend Tests

```python
import pytest
from unittest.mock import AsyncMock, MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app

@pytest.mark.asyncio
async def test_my_endpoint():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/my-endpoint")
        assert response.status_code == 200
```

---

## Frontend Testing

### Running Tests

```bash
# Navigate to frontend directory
cd frontend

# Run all Jest tests
npm test

# Run with coverage
npm run test:coverage

# Run in watch mode during development
npm test -- --watch

# Run specific test file
npm test -- __tests__/hooks/useSSE.test.ts

# Run with verbose output
npm test -- --verbose
```

### Testing Tools

| Tool | Purpose |
|------|---------|
| **Jest** | Test runner & assertion library |
| **@testing-library/react** | React component testing |
| **@testing-library/user-event** | Simulating user interactions |
| **@testing-library/jest-dom** | Custom DOM matchers |
| **ts-jest** | TypeScript transformation |

### Component Testing Pattern

```tsx
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { MyComponent } from '@/components/MyComponent';

describe('MyComponent', () => {
  it('renders the component', () => {
    render(<MyComponent title="Test" />);
    expect(screen.getByText('Test')).toBeInTheDocument();
  });

  it('handles user interaction', async () => {
    const onSubmit = jest.fn();
    render(<MyComponent onSubmit={onSubmit} />);
    fireEvent.click(screen.getByRole('button', { name: /submit/i }));
    expect(onSubmit).toHaveBeenCalled();
  });
});
```

### Hook Testing Pattern

```typescript
import { renderHook, act } from '@testing-library/react';
import { useMyHook } from '@/hooks/useMyHook';

describe('useMyHook', () => {
  it('initializes with default state', () => {
    const { result } = renderHook(() => useMyHook());
    expect(result.current.value).toBe(null);
  });

  it('updates state on action', () => {
    const { result } = renderHook(() => useMyHook());
    act(() => { result.current.doSomething(); });
    expect(result.current.value).not.toBeNull();
  });
});
```

---

## E2E Testing (Playwright)

### Prerequisites

```bash
# Install Playwright
npm install -D @playwright/test

# Install browsers
npx playwright install chromium

# Start the full stack
docker-compose --profile dev up -d
```

### Running E2E Tests

```bash
# Run all E2E tests
npx playwright test

# Run specific spec
npx playwright test e2e/auth.spec.ts

# Run in headed mode (see browser)
npx playwright test --headed

# Debug mode (pauses at each step)
npx playwright test --debug

# Generate HTML report
npx playwright test --reporter=html
npx playwright show-report
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PLAYWRIGHT_BASE_URL` | `http://localhost:3000` | Frontend URL |
| `E2E_API_URL` | `http://localhost:8000/api` | Backend API URL |
| `E2E_TEST_USER` | `admin` | Test user username |
| `E2E_TEST_PASS` | `Admin1Password!` | Test user password |

### Writing E2E Tests

```typescript
import { test, expect } from '@playwright/test';

test('my feature works end-to-end', async ({ page }) => {
  await page.goto('http://localhost:3000/my-feature');
  await expect(page.getByRole('heading', { name: /my feature/i })).toBeVisible();
  await page.getByLabel(/input/i).fill('test value');
  await page.getByRole('button', { name: /submit/i }).click();
  await expect(page.getByText(/success/i)).toBeVisible({ timeout: 10000 });
});
```

---

## Performance Testing (k6)

### Prerequisites

```bash
# Install k6 (macOS)
brew install k6

# Install k6 (Linux)
sudo snap install k6

# Install k6 (Docker)
docker pull grafana/k6
```

### Running Performance Tests

```bash
# Basic run
k6 run performance/k6-api.js

# With custom target
k6 run -e BASE_URL=http://localhost:8000 performance/k6-api.js

# Higher concurrency stress test
k6 run --vus 50 --duration 30s performance/k6-api.js

# Export results to JSON
k6 run --out json=performance/results-$(date +%Y%m%d).json performance/k6-api.js
```

### Interpreting Results

-  **Pass**: p95 < 500ms, error rate < 1%
- ⚠️ **Warning**: p95 500-1000ms, error rate 1-5%
-  **Fail**: p95 > 1000ms, error rate > 5%

Update `performance/BASELINES.md` after each test run.

---

## Chaos Testing

### Running Chaos Tests

```bash
cd backend
pytest tests/test_chaos.py -v
```

### Chaos Test Scenarios Covered

1. **Database Unavailability** — PostgreSQL connection refused
2. **Neo4j Unavailability** — Graph DB timeout/refusal
3. **Tool Failures** — nmap/nuclei/httpx process errors
4. **Input Validation** — Malformed XML, null bytes, very long strings
5. **Cascading Failures** — Partial failures not propagating
6. **Security** — Secrets not leaking in error messages
7. **Rate Limiter** — Clock skew and exhaustion handling
8. **RBAC** — Unknown roles handled gracefully

---

## Test Execution Checklist

Before merging any PR:

- [ ] `cd backend && pytest` — All backend tests pass
- [ ] `cd backend && pytest --cov=app --cov-report=term` — Coverage ≥ 80%
- [ ] `cd frontend && npm test` — All Jest tests pass
- [ ] `cd frontend && npm run test:coverage` — Coverage ≥ 70%
- [ ] `cd backend && pytest tests/test_chaos.py` — Chaos tests pass
- [ ] E2E tests pass against staging environment (CI gate)
- [ ] Performance baselines not regressed (k6 weekly run)

---

## Troubleshooting

### Backend Tests Fail with Import Errors

```bash
cd backend
pip install -r requirements-dev.txt
export PYTHONPATH=.
pytest
```

### Frontend Tests Fail with Module Resolution

```bash
cd frontend
npm install
npm test
```

### E2E Tests Cannot Connect

1. Ensure full stack is running: `docker-compose --profile dev up -d`
2. Check environment variables
3. Verify `PLAYWRIGHT_BASE_URL` is accessible

### k6 Not Found

```bash
# Alternative: run via Docker
docker run --rm -i grafana/k6 run - < performance/k6-api.js
```

---

