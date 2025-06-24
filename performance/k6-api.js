/**
 * Day 178: Performance Test Suite – API Throughput & Load Testing
 *
 * k6 performance tests for the UniVex API.
 *
 * Install k6: https://k6.io/docs/get-started/installation/
 * Run: k6 run performance/k6-api.js
 * Run with env vars:
 *   k6 run -e BASE_URL=http://localhost:8000 -e USERNAME=admin -e PASSWORD=Admin1Pass! performance/k6-api.js
 */

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

const loginErrors = new Counter('login_errors');
const projectCreationErrors = new Counter('project_creation_errors');
const apiSuccessRate = new Rate('api_success_rate');
const authLatency = new Trend('auth_latency_ms', true);
const projectListLatency = new Trend('project_list_latency_ms', true);
const projectCreateLatency = new Trend('project_create_latency_ms', true);
const healthLatency = new Trend('health_latency_ms', true);

// ---------------------------------------------------------------------------
// Test stages (ramp-up → sustained → ramp-down)
// ---------------------------------------------------------------------------

export const options = {
  stages: [
    { duration: '30s', target: 5 },   // Ramp up to 5 VUs
    { duration: '1m', target: 10 },   // Ramp up to 10 concurrent users
    { duration: '2m', target: 10 },   // Hold steady at 10 VUs
    { duration: '30s', target: 20 },  // Spike to 20 VUs
    { duration: '1m', target: 20 },   // Hold at 20 VUs
    { duration: '30s', target: 0 },   // Ramp down to 0
  ],
  thresholds: {
    // 95th percentile response time < 500 ms
    http_req_duration: ['p(95)<500'],
    // 99th percentile < 1000 ms
    'http_req_duration{name:health}': ['p(99)<200'],
    'http_req_duration{name:auth_login}': ['p(95)<1000'],
    'http_req_duration{name:project_list}': ['p(95)<800'],
    // Error rate < 1%
    http_req_failed: ['rate<0.01'],
    api_success_rate: ['rate>0.99'],
  },
};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';
const API_URL = `${BASE_URL}/api`;
const USERNAME = __ENV.USERNAME || 'admin';
const PASSWORD = __ENV.PASSWORD || 'Admin1Password!';

// ---------------------------------------------------------------------------
// Setup – login once and share token via shared data (returned from setup())
// ---------------------------------------------------------------------------

export function setup() {
  const res = http.post(
    `${API_URL}/auth/login`,
    JSON.stringify({ username: USERNAME, password: PASSWORD }),
    { headers: { 'Content-Type': 'application/json' } }
  );

  if (res.status !== 200) {
    console.error(`Setup login failed: ${res.status} ${res.body}`);
    return { token: null };
  }

  const body = JSON.parse(res.body as string);
  return { token: body.access_token };
}

// ---------------------------------------------------------------------------
// Default function – executed by each VU
// ---------------------------------------------------------------------------

export default function (data: { token: string | null }) {
  const authHeaders = data.token
    ? { Authorization: `Bearer ${data.token}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' };

  // -------------------------------------------------------------------------
  // Group 1: Health check endpoint
  // -------------------------------------------------------------------------
  group('Health Check', () => {
    const start = Date.now();
    const res = http.get(`${BASE_URL}/health`, { tags: { name: 'health' } });
    healthLatency.add(Date.now() - start);

    const ok = check(res, {
      'health status is 200': (r) => r.status === 200,
      'health response has status field': (r) => {
        try {
          return JSON.parse(r.body as string).status !== undefined;
        } catch {
          return false;
        }
      },
    });
    apiSuccessRate.add(ok);
  });

  sleep(0.5);

  // -------------------------------------------------------------------------
  // Group 2: Authentication
  // -------------------------------------------------------------------------
  group('Authentication', () => {
    const start = Date.now();
    const res = http.post(
      `${API_URL}/auth/login`,
      JSON.stringify({ username: USERNAME, password: PASSWORD }),
      { headers: { 'Content-Type': 'application/json' }, tags: { name: 'auth_login' } }
    );
    authLatency.add(Date.now() - start);

    const ok = check(res, {
      'login returns 200': (r) => r.status === 200,
      'login returns access_token': (r) => {
        try {
          return !!JSON.parse(r.body as string).access_token;
        } catch {
          return false;
        }
      },
    });

    if (!ok) loginErrors.add(1);
    apiSuccessRate.add(ok);
  });

  sleep(0.5);

  // -------------------------------------------------------------------------
  // Group 3: Project listing
  // -------------------------------------------------------------------------
  group('Project Listing', () => {
    const start = Date.now();
    const res = http.get(`${API_URL}/projects`, {
      headers: authHeaders,
      tags: { name: 'project_list' },
    });
    projectListLatency.add(Date.now() - start);

    const ok = check(res, {
      'project list returns 200': (r) => r.status === 200,
      'project list returns array': (r) => {
        try {
          const body = JSON.parse(r.body as string);
          return Array.isArray(body) || Array.isArray(body.projects);
        } catch {
          return false;
        }
      },
    });
    apiSuccessRate.add(ok);
  });

  sleep(0.5);

  // -------------------------------------------------------------------------
  // Group 4: Project creation (write throughput)
  // -------------------------------------------------------------------------
  group('Project Creation', () => {
    const projectName = `perf-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const start = Date.now();
    const res = http.post(
      `${API_URL}/projects`,
      JSON.stringify({ name: projectName, target: 'example.com' }),
      { headers: authHeaders, tags: { name: 'project_create' } }
    );
    projectCreateLatency.add(Date.now() - start);

    const ok = check(res, {
      'project creation returns 201 or 200': (r) => r.status === 200 || r.status === 201,
      'project creation returns id': (r) => {
        try {
          return !!JSON.parse(r.body as string).id;
        } catch {
          return false;
        }
      },
    });

    if (!ok) projectCreationErrors.add(1);
    apiSuccessRate.add(ok);
  });

  sleep(1);
}

// ---------------------------------------------------------------------------
// Teardown – log summary
// ---------------------------------------------------------------------------

export function teardown(data: { token: string | null }) {
  console.log('Performance test complete.');
  console.log(`Auth header used: ${data.token ? 'Yes' : 'No (unauthenticated)'}`);
}
