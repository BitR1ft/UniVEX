/** Day 28: Concurrent Scan Load Test — 10 simultaneous scans */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

const scanCreationErrors    = new Counter('scan_creation_errors');
const scanCompletionRate    = new Rate('scan_completion_rate');
const scanDuration          = new Trend('scan_duration', true);
const reportGenerationLatency = new Trend('report_generation_latency', true);

// ---------------------------------------------------------------------------
// Stages: ramp to 10 VUs → hold → ramp down
// ---------------------------------------------------------------------------

export const options = {
  stages: [
    { duration: '30s', target: 10 },  // Ramp up to 10 concurrent VUs
    { duration: '5m',  target: 10 },  // Hold 10 VUs for 5 minutes
    { duration: '30s', target: 0  },  // Ramp down
  ],
  thresholds: {
    // At least 80% of scans must complete successfully.
    scan_completion_rate: ['rate>0.80'],
    // p95 scan wall-clock duration < 120 s; p99 < 180 s.
    scan_duration: ['p(95)<120000', 'p(99)<180000'],
  },
};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';
const API_URL  = `${BASE_URL}/api`;
const USERNAME = __ENV.USERNAME || 'admin';
const PASSWORD = __ENV.PASSWORD || 'Admin1Password!';

// Maximum number of poll iterations before giving up on a scan.
const MAX_POLL_ITERATIONS = 12; // 12 × 5 s = 60 s

// ---------------------------------------------------------------------------
// Default function – executed by each VU
// ---------------------------------------------------------------------------

export default function () {
  // Step 1: Authenticate to obtain a JWT.
  const loginRes = http.post(
    `${API_URL}/auth/login`,
    JSON.stringify({ username: USERNAME, password: PASSWORD }),
    { headers: { 'Content-Type': 'application/json' } }
  );

  const loginOk = check(loginRes, {
    'auth: status 200': (r) => r.status === 200,
    'auth: has access_token': (r) => {
      try { return !!JSON.parse(r.body).access_token; } catch { return false; }
    },
  });

  if (!loginOk) {
    scanCreationErrors.add(1);
    scanCompletionRate.add(false);
    return;
  }

  const token = JSON.parse(loginRes.body).access_token;
  const authHeaders = {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  };

  // Step 2: Create a new project.
  const projectName = `scan-perf-${__VU}-${Date.now()}`;
  const projectRes = http.post(
    `${API_URL}/projects`,
    JSON.stringify({ name: projectName, target: 'example.com' }),
    { headers: authHeaders }
  );

  const projectOk = check(projectRes, {
    'project: created (200/201)': (r) => r.status === 200 || r.status === 201,
    'project: has id': (r) => {
      try { return !!JSON.parse(r.body).id; } catch { return false; }
    },
  });

  if (!projectOk) {
    scanCreationErrors.add(1);
    scanCompletionRate.add(false);
    return;
  }

  const projectId = JSON.parse(projectRes.body).id;

  // Step 3: Launch a scan / AutoChain run.
  const scanStartTime = Date.now();

  // Try the AutoChain endpoint first; fall back to the project-scoped scan endpoint.
  let scanId = null;
  const autoChainRes = http.post(
    `${API_URL}/autochain/run`,
    JSON.stringify({ project_id: projectId, target: 'example.com', mode: 'full' }),
    { headers: authHeaders }
  );

  if (autoChainRes.status === 200 || autoChainRes.status === 201 || autoChainRes.status === 202) {
    try { scanId = JSON.parse(autoChainRes.body).id || JSON.parse(autoChainRes.body).run_id; } catch {}
  } else {
    // Fallback: project-scoped scan endpoint.
    const scanRes = http.post(
      `${API_URL}/projects/${projectId}/scan`,
      JSON.stringify({ target: 'example.com', scan_type: 'full' }),
      { headers: authHeaders }
    );
    check(scanRes, { 'scan: launched (200-202)': (r) => r.status >= 200 && r.status < 203 });
    try { scanId = JSON.parse(scanRes.body).id || JSON.parse(scanRes.body).scan_id; } catch {}
  }

  if (!scanId) {
    scanCreationErrors.add(1);
    scanCompletionRate.add(false);
    return;
  }

  // Step 4: Poll scan status every 5 s for up to 60 s.
  let scanComplete = false;
  let scanStatus = 'pending';

  for (let i = 0; i < MAX_POLL_ITERATIONS; i++) {
    sleep(5);

    const statusRes = http.get(
      `${API_URL}/autochain/run/${scanId}`,
      { headers: authHeaders }
    );

    if (statusRes.status === 200) {
      try {
        const body = JSON.parse(statusRes.body);
        scanStatus = body.status || body.state || 'unknown';
        if (['completed', 'done', 'finished', 'success'].includes(scanStatus.toLowerCase())) {
          scanComplete = true;
          break;
        }
        if (['failed', 'error', 'cancelled'].includes(scanStatus.toLowerCase())) {
          break;
        }
      } catch {}
    }
  }

  const elapsed = Date.now() - scanStartTime;
  scanDuration.add(elapsed);
  scanCompletionRate.add(scanComplete);

  if (!scanComplete) {
    return;
  }

  // Step 5: Retrieve results.
  const resultsRes = http.get(
    `${API_URL}/autochain/run/${scanId}/results`,
    { headers: authHeaders }
  );
  check(resultsRes, {
    'results: status 200': (r) => r.status === 200,
  });

  // Step 6: Generate a report.
  const reportStart = Date.now();
  const reportRes = http.post(
    `${API_URL}/reports`,
    JSON.stringify({ project_id: projectId, scan_id: scanId, format: 'pdf' }),
    { headers: authHeaders }
  );
  reportGenerationLatency.add(Date.now() - reportStart);

  check(reportRes, {
    'report: created (200/201/202)': (r) => r.status >= 200 && r.status < 203,
  });
}
