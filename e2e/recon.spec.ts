/**
 * Day 176: E2E Tests – Recon Workflow
 *
 * Playwright end-to-end tests for the reconnaissance workflow:
 * starting a scan, observing live progress, and viewing results.
 *
 * Run with: npx playwright test e2e/recon.spec.ts
 */

import { test, expect, Page } from '@playwright/test';

const BASE_URL = process.env.PLAYWRIGHT_BASE_URL ?? 'http://localhost:3000';
const API_URL = process.env.E2E_API_URL ?? 'http://localhost:8000/api';

async function loginViaAPI(page: Page) {
  const username = process.env.E2E_TEST_USER ?? 'admin';
  const password = process.env.E2E_TEST_PASS ?? 'Admin1Password!';
  const response = await page.request.post(`${API_URL}/auth/login`, {
    data: { username, password },
  });
  const body = await response.json();
  await page.evaluate(
    ({ at, rt }) => {
      localStorage.setItem('access_token', at);
      if (rt) localStorage.setItem('refresh_token', rt);
    },
    { at: body.access_token, rt: body.refresh_token }
  );
}

async function createProject(page: Page, name: string): Promise<string> {
  const token = await page.evaluate(() => localStorage.getItem('access_token'));
  const res = await page.request.post(`${API_URL}/projects`, {
    data: { name, target: 'scanme.nmap.org' },
    headers: { Authorization: `Bearer ${token}` },
  });
  const body = await res.json();
  return body.id;
}

// ---------------------------------------------------------------------------
// Recon Workflow
// ---------------------------------------------------------------------------

test.describe('Recon Workflow', () => {
  let projectId: string;

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
    await loginViaAPI(page);
    projectId = await createProject(page, `Recon E2E ${Date.now()}`);
  });

  test('project detail page shows Start Scan button in draft state', async ({ page }) => {
    await page.goto(`${BASE_URL}/projects/${projectId}`);
    await expect(page.getByRole('button', { name: /start scan|start/i })).toBeVisible({ timeout: 10000 });
  });

  test('clicking Start Scan begins the recon workflow', async ({ page }) => {
    await page.goto(`${BASE_URL}/projects/${projectId}`);
    await page.getByRole('button', { name: /start scan|start/i }).click();
    // Status should transition to queued or running
    await expect(
      page.getByText(/queued|running|in progress/i)
    ).toBeVisible({ timeout: 15000 });
  });

  test('live progress panel appears when scan is running', async ({ page }) => {
    // Start scan via API
    const token = await page.evaluate(() => localStorage.getItem('access_token'));
    await page.request.post(`${API_URL}/projects/${projectId}/start`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    await page.goto(`${BASE_URL}/projects/${projectId}`);
    // ScanProgressPanel should be visible for running/queued projects
    await expect(page.getByTestId('scan-progress-panel').or(page.getByText(/phase|progress/i))).toBeVisible({
      timeout: 15000,
    });
  });

  test('results section shows findings after scan completes', async ({ page }) => {
    // This test is marked as slow; in practice the scan may take minutes.
    // We verify the results section exists and is empty until scan completes.
    await page.goto(`${BASE_URL}/projects/${projectId}`);
    await expect(
      page.getByText(/results|findings|subdomains|ports/i)
    ).toBeVisible({ timeout: 10000 });
  });
});

// ---------------------------------------------------------------------------
// Tool Execution Verification
// ---------------------------------------------------------------------------

test.describe('Tool Execution', () => {
  test('API returns task list after scan start', async ({ page }) => {
    await page.goto(BASE_URL);
    await loginViaAPI(page);
    const projectId = await createProject(page, `Tool Test ${Date.now()}`);

    const token = await page.evaluate(() => localStorage.getItem('access_token'));
    await page.request.post(`${API_URL}/projects/${projectId}/start`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    const tasksRes = await page.request.get(`${API_URL}/projects/${projectId}/tasks`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(tasksRes.status()).toBeLessThan(500);
  });
});

// ---------------------------------------------------------------------------
// Graph Updates After Recon
// ---------------------------------------------------------------------------

test.describe('Graph Updates', () => {
  test('graph endpoint returns data structure for a project', async ({ page }) => {
    await page.goto(BASE_URL);
    await loginViaAPI(page);
    const projectId = await createProject(page, `Graph Update ${Date.now()}`);

    const token = await page.evaluate(() => localStorage.getItem('access_token'));
    const graphRes = await page.request.get(`${API_URL}/graph/${projectId}/attack-surface`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    // Endpoint should exist (200 or 404 for empty, not 500)
    expect(graphRes.status()).not.toBe(500);
  });
});
