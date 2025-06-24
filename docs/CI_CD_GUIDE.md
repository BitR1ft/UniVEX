# UniVex — CI/CD Guide


> **Complete guide to the Continuous Integration and Continuous Deployment
> pipeline for UniVex.**

---

## Pipeline Overview

```
Pull Request / Push
        
        

                    CI Pipeline (ci.yml)              
                                                      
        
   backend-lint         frontend-lint             
        
                                                   
        
   backend-tests        frontend-tests            
        
                                                   
    
           integration-tests (main/develop)        
    

        
         (on push to main)

              Docker Build (docker-build.yml)         
  Build backend + frontend → GHCR                    
  Generate SBOM, scan with Trivy                     

        
        

              Deploy (deploy.yml)                     
  Staging → smoke tests → Production (with approval) 

        
         (on tags v*.*.*)

              Release (release.yml)                   
  Tag → Multi-arch build → GitHub Release → Deploy   

```

---

## Workflow Files

| File | Trigger | Purpose |
|------|---------|---------|
| `.github/workflows/ci.yml` | Push/PR | Backend + Frontend tests |
| `.github/workflows/security.yml` | Push/Schedule | Vulnerability scanning |
| `.github/workflows/docker-build.yml` | Push/Tags | Build & push Docker images |
| `.github/workflows/deploy.yml` | Push/Release | Deploy to staging/production |
| `.github/workflows/release.yml` | Manual | Create versioned release |
| `.github/workflows/blue-green.yml` | Manual | Blue/green deploy & rollback |

---

## Required GitHub Secrets

Configure these in **Settings → Secrets and variables → Actions**:

### Required Secrets

| Secret | Description | Example |
|--------|-------------|---------|
| `SECRET_KEY` | JWT signing secret (40+ chars) | `openssl rand -base64 50` |
| `POSTGRES_PASSWORD` | Production PostgreSQL password | Strong random password |
| `NEO4J_PASSWORD` | Production Neo4j password | Strong random password |
| `GRAFANA_PASSWORD` | Grafana admin password | Strong random password |

### Optional Secrets (for full CI/CD)

| Secret | Description |
|--------|-------------|
| `STAGING_SSH_KEY` | SSH private key for staging server |
| `STAGING_HOST` | Staging server hostname/IP |
| `PRODUCTION_SSH_KEY` | SSH private key for production server |
| `PRODUCTION_HOST` | Production server hostname/IP |
| `SLACK_WEBHOOK_URL` | Slack webhook for notifications |
| `CODECOV_TOKEN` | Codecov.io upload token |

### Required Variables (Repository Variables)

| Variable | Description |
|----------|-------------|
| `STAGING_URL` | Staging environment URL |
| `PRODUCTION_URL` | Production environment URL |
| `STAGING_ACTIVE_SLOT` | Current active blue/green slot (`blue` or `green`) |

---

## CI Jobs Explained

### 1. `backend-lint` — Python Code Quality

Runs on every push and pull request.

- **Ruff**: Fast Python linter checking style, imports, and common errors
- **Mypy**: Static type checking

```bash
# Run locally
cd backend
pip install ruff mypy
ruff check app/
mypy app/ --ignore-missing-imports
```

### 2. `backend-tests` — Unit & Integration Tests

Runs after lint passes. Requires PostgreSQL service.

```bash
# Run locally
cd backend
pytest --cov=app --cov-report=term-missing --cov-fail-under=70
```

**Coverage requirement**: ≥ 70% (target: 80%)

### 3. `backend-chaos` — Chaos Engineering Tests

Runs on push to main or PRs with `chaos-tests` label.

```bash
# Run locally
cd backend
pytest tests/test_chaos.py -v
```

### 4. `frontend-lint` — TypeScript Code Quality

- **ESLint**: TypeScript/React linting
- **TypeScript**: Type checking (`tsc --noEmit`)

```bash
# Run locally
cd frontend
npm run lint
npm run type-check
```

### 5. `frontend-tests` — Jest Unit Tests

Runs after lint passes.

```bash
# Run locally
cd frontend
npm run test:coverage
```

**Coverage requirement**: ≥ 70%

### 6. `integration-tests` — Full Stack Integration

Runs on push to `main`/`develop` only (not on PRs).

Requires: PostgreSQL + Neo4j services.

---

## Docker Build Pipeline

### Build Strategy

1. **Multi-stage builds**: Separate build and runtime stages for minimal images
2. **Layer caching**: GitHub Actions cache for faster subsequent builds
3. **SBOM generation**: Software Bill of Materials for supply chain security
4. **Trivy scanning**: Container vulnerability scanning
5. **Multi-arch**: amd64 + arm64 for release tags

### Image Tags

| Event | Tag Format | Example |
|-------|-----------|---------|
| Push to branch | `branch-name` | `main` |
| Pull Request | `pr-123` | `pr-42` |
| Push to main | `latest` + `sha-abc1234` | `sha-a1b2c3d` |
| Release tag | `1.2.3` + `latest` | `v1.2.3` |

### Viewing Images

```bash
# List available images
docker pull ghcr.io/bitr1ft/univex-backend --list-digests

# Pull specific version
docker pull ghcr.io/bitr1ft/univex-backend:v1.2.3
```

---

## Deployment Workflow

### Staging Deployment

Automatically triggered on push to `main` branch.

1. Calculate image tag from commit SHA
2. Pull new images
3. Deploy to staging (rolling update)
4. Run smoke tests
5. Notify team

### Production Deployment

Triggered by:
- Publishing a GitHub Release
- Manual `workflow_dispatch` with `environment=production`

**Requires**: GitHub Environment protection rule (manual approval).

### Release Process

```bash
# 1. Run release workflow (dry run first)
gh workflow run release.yml \
  -f version_bump=minor \
  -f dry_run=true

# 2. Review output, then create real release
gh workflow run release.yml \
  -f version_bump=minor \
  -f dry_run=false

# 3. Monitor deployment
gh run list --workflow=deploy.yml
```

---

## Security Scanning

### Automatic Scans

| Tool | What it checks | Schedule |
|------|----------------|----------|
| pip-audit | Python dependency CVEs | Every push |
| npm audit | Node.js dependency CVEs | Every push |
| Bandit | Python SAST | Every push |
| CodeQL | Multi-language SAST | Every push + weekly |
| Gitleaks | Hardcoded secrets | Every push |
| Trivy | Container vulnerabilities | Docker builds |

### Reviewing Security Results

1. Go to **Security** tab in GitHub repository
2. Click **Code scanning alerts**
3. Review and dismiss false positives with justification

---

## Troubleshooting

### CI Job Fails: "Module not found"

```bash
# Check requirements.txt is up to date
cd backend
pip freeze > requirements.txt
git diff requirements.txt
```

### CI Job Fails: "Test coverage below threshold"

```bash
# Find untested code
cd backend
pytest --cov=app --cov-report=html
open htmlcov/index.html
```

### Docker Build Fails: "Out of disk space"

```bash
# Clean GitHub Actions cache (in repository Settings → Actions → Caches)
# Or prune locally
docker system prune --all --volumes
```

### Deployment Times Out

```bash
# Check service health manually
ssh deploy@staging-server
docker compose logs backend --tail=50
curl http://localhost:8000/health
```

---

## Development Workflow

### Recommended Git Flow

```
feature/my-feature → develop → main → v1.2.3
                               
          CI runs       CI+CD     Release
          lint+test     staging
               production
```

### Branch Protection Rules (Recommended)

Configure for `main` and `develop`:
-  Require pull request before merging
-  Require status checks: `backend-tests`, `frontend-tests`
-  Require branches to be up to date
-  Require signed commits (optional)
-  Include administrators

### Local Pre-commit Check

```bash
#!/bin/bash
# Save as .git/hooks/pre-commit and chmod +x

echo "Running pre-commit checks..."

# Backend
cd backend
ruff check app/ || { echo "Ruff failed"; exit 1; }
pytest tests/ -x -q || { echo "Backend tests failed"; exit 1; }
cd ..

# Frontend
cd frontend
npm run lint -- --quiet || { echo "ESLint failed"; exit 1; }
npm test -- --passWithNoTests --ci || { echo "Frontend tests failed"; exit 1; }
cd ..

echo " All pre-commit checks passed"
```

---

