/** Day 28: WebSocket Load Test — 50 concurrent agent sessions */

import http from 'k6/http';
import ws from 'k6/ws';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

const wsConnectionErrors = new Counter('ws_connection_errors');
const wsMessageLatency = new Trend('ws_message_latency', true);
const wsMessagesReceived = new Counter('ws_messages_received');
const wsSuccessRate = new Rate('ws_success_rate');

// ---------------------------------------------------------------------------
// Stages: ramp up → hold small → ramp to peak → hold peak → ramp down
// ---------------------------------------------------------------------------

export const options = {
  stages: [
    { duration: '30s', target: 10 },   // Phase 1: Ramp from 0 → 10 VUs
    { duration: '1m',  target: 10 },   // Phase 2: Hold 10 VUs for 1 minute
    { duration: '30s', target: 50 },   // Phase 3: Ramp from 10 → 50 VUs (peak load)
    { duration: '2m',  target: 50 },   // Phase 4: Hold 50 VUs for 2 minutes (sustained peak)
    { duration: '30s', target: 0  },   // Phase 5: Ramp down to 0
  ],
  thresholds: {
    // At least 95% of WebSocket connections must succeed (i.e. error rate < 5%)
    ws_success_rate: ['rate>0.95'],
    // 95th-percentile message round-trip latency must be under 2 seconds
    ws_message_latency: ['p(95)<2000'],
  },
};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';
const WS_URL   = __ENV.WS_URL   || 'ws://localhost:8000';
const USERNAME = __ENV.USERNAME || 'admin';
const PASSWORD = __ENV.PASSWORD || 'Admin1Password!';

// ---------------------------------------------------------------------------
// Default function – executed by each VU
// ---------------------------------------------------------------------------

export default function () {
  // Step 1: Authenticate via HTTP to obtain a JWT access token.
  const loginRes = http.post(
    `${BASE_URL}/api/auth/login`,
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
    wsConnectionErrors.add(1);
    wsSuccessRate.add(false);
    return;
  }

  const token = JSON.parse(loginRes.body).access_token;
  // Use a unique session ID per VU iteration to avoid collisions.
  const sessionId = `session-${__VU}-${Date.now()}`;
  const wsEndpoint = `${WS_URL}/ws/agent/${sessionId}`;

  // Step 2: Open a WebSocket connection, passing the JWT in the Authorization header.
  const res = ws.connect(
    wsEndpoint,
    { headers: { Authorization: `Bearer ${token}` } },
    function (socket) {
      let messagesReceived = 0;
      let pingStartTime = 0;
      let taskStartTime = 0;
      let pongReceived = false;
      let taskResponseReceived = false;

      // Handle every incoming message from the server.
      socket.on('message', (data) => {
        messagesReceived++;
        wsMessagesReceived.add(1);

        let parsed;
        try { parsed = JSON.parse(data); } catch { parsed = { type: data }; }

        // Step 3b: Record latency for the pong response.
        if ((parsed.type === 'pong' || data === 'pong') && !pongReceived) {
          wsMessageLatency.add(Date.now() - pingStartTime);
          pongReceived = true;
        }

        // Step 4b: Record latency for the first task-related response.
        if (taskStartTime && !taskResponseReceived) {
          wsMessageLatency.add(Date.now() - taskStartTime);
          taskResponseReceived = true;
        }
      });

      socket.on('error', (e) => {
        wsConnectionErrors.add(1);
        console.error(`WS error on VU ${__VU}: ${e.error()}`);
      });

      socket.on('close', () => {
        // Connection closed — evaluate whether this VU session succeeded.
        wsSuccessRate.add(pongReceived);
      });

      // Step 3: Send a "ping" message and wait up to 5s for the "pong".
      pingStartTime = Date.now();
      socket.send(JSON.stringify({ type: 'ping' }));
      sleep(5);

      // Step 4: Send a pentest task and wait up to 10s for any response.
      taskStartTime = Date.now();
      socket.send(JSON.stringify({
        type: 'task',
        payload: {
          task_type: 'pentest',
          target: 'example.com',
          options: { depth: 1, timeout: 30 },
        },
      }));
      sleep(10);

      // Step 5: Stay connected for a further 30s, counting any additional messages.
      sleep(15);

      // Step 6: Cleanly close the connection.
      socket.close();
    }
  );

  check(res, {
    'ws: connection established': (r) => r && r.status === 101,
  });
}
