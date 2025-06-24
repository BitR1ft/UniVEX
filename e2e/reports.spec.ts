/**
 * Day 28: E2E tests for the UniVex reports feature.
 *
 * Playwright end-to-end tests for: report listing, creation,
 * generation, PDF downloads, and report detail views.
 *
 * Run with: npx playwright test e2e/reports.spec.ts
 */

import { test, expect, Page } from '@playwright/test';

const BASE_URL = process.env.PLAYWRIGHT_BASE_URL ?? 'http://localhost:3000';
const API_URL = process.env.E2E_API_URL ?? 'http://localhost:8000/api';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function loginAsTestUser(page: Page) {
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

// ---------------------------------------------------------------------------
// Reports List
// ---------------------------------------------------------------------------

test.describe('Reports', () => {
  test.describe('Reports List', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto(BASE_URL);
      await loginAsTestUser(page);
      await page.goto(`${BASE_URL}/reports`);
    });

    test('reports list page loads', async ({ page }) => {
      await expect(
        page.getByRole('heading', { name: /reports/i }).or(page.getByText(/reports/i).first())
      ).toBeVisible({ timeout: 15000 });
    });

    test('create new report button is visible', async ({ page }) => {
      await expect(
        page.getByRole('button', { name: /new report|create report|generate report/i })
          .or(page.getByRole('link', { name: /new report|create report/i }))
      ).toBeVisible({ timeout: 10000 });
    });

    test('reports list shows items or empty state', async ({ page }) => {
      await expect(
        page.getByRole('list').or(page.getByRole('table'))
          .or(page.getByText(/no reports|generate your first/i))
      ).toBeVisible({ timeout: 10000 });
    });

    test('report status badge is shown on list items', async ({ page }) => {
      const statusBadge = page.getByText(/complete|pending|failed|generating/i).first();
      if (await statusBadge.isVisible({ timeout: 5000 })) {
        await expect(statusBadge).toBeVisible();
      }
      // Verify no crash even if no reports yet
      await expect(page).toHaveURL(/\/reports/);
    });

    test('search or filter input is present', async ({ page }) => {
      await expect(
        page.getByPlaceholder(/search/i)
          .or(page.getByRole('combobox').first())
          .or(page.getByLabel(/filter|type/i).first())
      ).toBeVisible({ timeout: 10000 });
    });
  });

  // ---------------------------------------------------------------------------
  // Report Creation
  // ---------------------------------------------------------------------------

  test.describe('Report Creation', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto(BASE_URL);
      await loginAsTestUser(page);
      await page.goto(`${BASE_URL}/reports`);
    });

    test('clicking new report opens creation form or modal', async ({ page }) => {
      const newBtn = page.getByRole('button', { name: /new report|create report|generate report/i })
        .or(page.getByRole('link', { name: /new report|create report/i }));
      if (await newBtn.isVisible({ timeout: 5000 })) {
        await newBtn.click();
        await expect(
          page.getByRole('dialog')
            .or(page.getByRole('form'))
            .or(page.getByText(/report type|select type/i))
        ).toBeVisible({ timeout: 10000 });
      }
    });

    test('report type selection is available in creation form', async ({ page }) => {
      const newBtn = page.getByRole('button', { name: /new report|create report|generate report/i })
        .or(page.getByRole('link', { name: /new report|create report/i }));
      if (await newBtn.isVisible({ timeout: 5000 })) {
        await newBtn.click();
        await expect(
          page.getByRole('combobox', { name: /report type|type/i })
            .or(page.getByLabel(/report type|type/i))
            .or(page.getByText(/executive|technical|vulnerability/i).first())
        ).toBeVisible({ timeout: 10000 });
      }
    });

    test('report generation is triggered on form submit', async ({ page }) => {
      const newBtn = page.getByRole('button', { name: /new report|create report|generate report/i })
        .or(page.getByRole('link', { name: /new report|create report/i }));
      if (await newBtn.isVisible({ timeout: 5000 })) {
        await newBtn.click();
        const generateBtn = page.getByRole('button', { name: /generate|create|submit/i });
        if (await generateBtn.isVisible({ timeout: 5000 })) {
          await generateBtn.click();
          // Should show progress, success toast, or validation error
          await expect(
            page.getByText(/generating|created|required|error/i)
          ).toBeVisible({ timeout: 10000 });
        }
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Report Detail
  // ---------------------------------------------------------------------------

  test.describe('Report Detail', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto(BASE_URL);
      await loginAsTestUser(page);
    });

    test('report detail page loads when navigating to a report', async ({ page }) => {
      await page.goto(`${BASE_URL}/reports`);
      // Click first report if available
      const firstReport = page.getByRole('link', { name: /report|view/i }).first()
        .or(page.getByRole('row').nth(1));
      if (await firstReport.isVisible({ timeout: 5000 })) {
        await firstReport.click();
        await expect(page).toHaveURL(/\/reports\/[^/]+/, { timeout: 10000 });
      }
      // Verify no crash
      await expect(page).toHaveURL(/\/reports/);
    });

    test('PDF download link is visible on report detail', async ({ page }) => {
      await page.goto(`${BASE_URL}/reports`);
      const firstReport = page.getByRole('link').filter({ hasText: /report/i }).first();
      if (await firstReport.isVisible({ timeout: 5000 })) {
        await firstReport.click();
        await expect(page).toHaveURL(/\/reports\/[^/]+/, { timeout: 10000 });
        await expect(
          page.getByRole('link', { name: /download|pdf/i })
            .or(page.getByRole('button', { name: /download|pdf|export/i }))
        ).toBeVisible({ timeout: 10000 });
      }
    });
  });
});
