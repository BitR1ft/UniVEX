/**
 * Day 178: Performance Baseline Documentation
 *
 * Recorded baselines from initial performance testing.
 * Update these values after each performance test run.
 *
 * Run: k6 run performance/k6-api.js
 */

# UniVex — Performance Baselines

## Test Environment

| Parameter        | Value                  |
|------------------|------------------------|
| Date             | 2026-03-07             |
| k6 Version       | 0.49+                  |
| Backend          | FastAPI + Uvicorn      |
| Database         | PostgreSQL 16          |
| Graph DB         | Neo4j 5.15             |
| CPU              | 4 cores                |
| RAM              | 8 GB                   |
| VUs Peak         | 20                     |
| Test Duration    | 5 minutes              |

---

## Baseline Thresholds

| Endpoint              | p50 (ms) | p95 (ms) | p99 (ms) | Error Rate |
|-----------------------|----------|----------|----------|------------|
| `GET /health`         | < 10     | < 50     | < 200    | < 0.1%     |
| `POST /api/auth/login`| < 100    | < 500    | < 1000   | < 1%       |
| `GET /api/projects`   | < 100    | < 400    | < 800    | < 1%       |
| `POST /api/projects`  | < 200    | < 800    | < 1500   | < 1%       |
| `GET /api/graph/{id}` | < 300    | < 1000   | < 2000   | < 2%       |
| `GET /metrics`        | < 50     | < 200    | < 500    | < 0.1%     |

---

## Concurrent User Targets

| Scenario         | Target VUs | Duration   | Acceptable p95 |
|------------------|------------|------------|----------------|
| Normal load      | 10         | Sustained  | < 500 ms       |
| Peak load        | 20         | 1 min      | < 1000 ms      |
| Stress test      | 50         | 30 sec     | < 2000 ms      |

---

## How to Run

```bash
# Basic run
k6 run performance/k6-api.js

# With custom environment
k6 run \
  -e BASE_URL=http://localhost:8000 \
  -e USERNAME=admin \
  -e PASSWORD=Admin1Password! \
  performance/k6-api.js

# With HTML report
k6 run --out json=performance/results.json performance/k6-api.js
k6 run --out influxdb=http://localhost:8086/k6 performance/k6-api.js
```

---

## Interpreting Results

- **http_req_duration**: Total time for the complete HTTP request
- **http_req_failed**: Rate of failed requests (non-2xx or network errors)
- **api_success_rate**: Custom metric tracking successful API responses
- **auth_latency_ms**: Authentication endpoint specific latency trend
- **project_list_latency_ms**: Project listing endpoint latency

---

## Recorded Results (Initial Baseline — Week 27)

> Update this table after each test run.

| Date       | VUs | p95 (ms) | Error Rate | Notes             |
|------------|-----|----------|------------|-------------------|
| 2026-03-07 | 10  | < 500    | < 1%       | Initial baseline  |
