/**
 * Day 175: E2E Tests – Projects
 *
 * Playwright end-to-end tests for the project management flows:
 * creation, listing, editing, deletion, and status lifecycle.
 *
 * Run with: npx playwright test e2e/projects.spec.ts
 */

import { test, expect, Page } from '@playwright/test';

const BASE_URL = process.env.PLAYWRIGHT_BASE_URL ?? 'http://localhost:3000';

// ---------------------------------------------------------------------------
// Auth helper – fast login via API so every test starts authenticated
// ---------------------------------------------------------------------------

async function loginViaAPI(page: Page) {
  const apiUrl = process.env.E2E_API_URL ?? 'http://localhost:8000/api';
  const username = process.env.E2E_TEST_USER ?? 'admin';
  const password = process.env.E2E_TEST_PASS ?? 'Admin1Password!';

  const response = await page.request.post(`${apiUrl}/auth/login`, {
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

// ---------------------------------------------------------------------------
// Project Listing
// ---------------------------------------------------------------------------

test.describe('Project Listing', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
    await loginViaAPI(page);
    await page.goto(`${BASE_URL}/projects`);
  });

  test('displays project list page', async ({ page }) => {
    await expect(page.getByRole('heading', { name: /projects/i })).toBeVisible({ timeout: 10000 });
  });

  test('shows search input', async ({ page }) => {
    await expect(page.getByPlaceholder(/search/i)).toBeVisible({ timeout: 10000 });
  });

  test('shows status filter', async ({ page }) => {
    await expect(page.getByRole('combobox').or(page.getByLabel(/status/i))).toBeVisible({ timeout: 10000 });
  });

  test('search filters project list', async ({ page }) => {
    const search = page.getByPlaceholder(/search/i);
    await search.fill('nonexistent-project-xyz');
    await expect(page.getByText(/no projects found|empty/i)).toBeVisible({ timeout: 5000 });
  });
});

// ---------------------------------------------------------------------------
// Project Creation
// ---------------------------------------------------------------------------

test.describe('Project Creation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
    await loginViaAPI(page);
    await page.goto(`${BASE_URL}/projects/new`);
  });

  test('renders multi-step creation wizard', async ({ page }) => {
    await expect(page.getByText(/basic info|step 1/i)).toBeVisible({ timeout: 10000 });
  });

  test('shows validation error for empty project name', async ({ page }) => {
    const nextBtn = page.getByRole('button', { name: /next|continue/i });
    await nextBtn.click();
    await expect(page.getByText(/must be at least 3 characters|name is required/i)).toBeVisible();
  });

  test('advances to next step with valid basic info', async ({ page }) => {
    await page.getByLabel(/project name/i).fill('E2E Test Project');
    await page.getByLabel(/target/i).fill('example.com');
    await page.getByRole('button', { name: /next|continue/i }).click();
    // Step 2 heading should be visible
    await expect(page.getByText(/target config|step 2/i)).toBeVisible({ timeout: 5000 });
  });

  test('creates project and redirects to detail page', async ({ page }) => {
    const projectName = `E2E Project ${Date.now()}`;
    // Step 1 – Basic Info
    await page.getByLabel(/project name/i).fill(projectName);
    await page.getByLabel(/target/i).fill('scanme.nmap.org');
    await page.getByRole('button', { name: /next/i }).click();
    // Step 2 – Target Config
    await page.getByRole('button', { name: /next/i }).click();
    // Step 3 – Tool Selection
    await page.getByRole('button', { name: /next/i }).click();
    // Step 4 – Review & Create
    await page.getByRole('button', { name: /create|submit/i }).click();
    await expect(page).toHaveURL(/\/projects\/[^/]+/, { timeout: 15000 });
  });
});

// ---------------------------------------------------------------------------
// Project Editing
// ---------------------------------------------------------------------------

test.describe('Project Editing', () => {
  let projectId: string;

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
    await loginViaAPI(page);

    // Create project via API
    const apiUrl = process.env.E2E_API_URL ?? 'http://localhost:8000/api';
    const token = await page.evaluate(() => localStorage.getItem('access_token'));
    const res = await page.request.post(`${apiUrl}/projects`, {
      data: { name: `Edit Test ${Date.now()}`, target: 'example.com' },
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = await res.json();
    projectId = body.id;
  });

  test('navigates to edit page', async ({ page }) => {
    await page.goto(`${BASE_URL}/projects/${projectId}/edit`);
    await expect(page.getByLabel(/project name/i)).toBeVisible({ timeout: 10000 });
  });

  test('saves updated project name', async ({ page }) => {
    await page.goto(`${BASE_URL}/projects/${projectId}/edit`);
    await page.getByLabel(/project name/i).clear();
    await page.getByLabel(/project name/i).fill('Updated Project Name');
    await page.getByRole('button', { name: /save|update/i }).click();
    await expect(page.getByText(/updated project name/i)).toBeVisible({ timeout: 10000 });
  });
});

// ---------------------------------------------------------------------------
// Project Deletion
// ---------------------------------------------------------------------------

test.describe('Project Deletion', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
    await loginViaAPI(page);
  });

  test('deletes a project and removes it from the list', async ({ page }) => {
    // Create project via API
    const apiUrl = process.env.E2E_API_URL ?? 'http://localhost:8000/api';
    const token = await page.evaluate(() => localStorage.getItem('access_token'));
    const uniqueName = `Delete Test ${Date.now()}`;
    const res = await page.request.post(`${apiUrl}/projects`, {
      data: { name: uniqueName, target: 'example.com' },
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = await res.json();

    await page.goto(`${BASE_URL}/projects/${body.id}`);
    await page.getByRole('button', { name: /delete/i }).click();
    // Confirmation dialog
    await page.getByRole('button', { name: /confirm|yes/i }).click();
    await expect(page).toHaveURL(/\/projects$/, { timeout: 10000 });
    await expect(page.getByText(uniqueName)).not.toBeVisible({ timeout: 5000 });
  });
});
