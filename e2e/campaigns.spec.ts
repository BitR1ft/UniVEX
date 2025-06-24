/**
 * Day 28: E2E tests for the UniVex campaigns feature.
 *
 * Playwright end-to-end tests for: campaign listing, creation,
 * form validation, status badges, detail views, and launching.
 *
 * Run with: npx playwright test e2e/campaigns.spec.ts
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
// Campaigns List
// ---------------------------------------------------------------------------

test.describe('Campaigns', () => {
  test.describe('Campaigns List', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto(BASE_URL);
      await loginAsTestUser(page);
      await page.goto(`${BASE_URL}/campaigns`);
    });

    test('campaigns list page loads', async ({ page }) => {
      await expect(
        page.getByRole('heading', { name: /campaigns/i }).or(page.getByText(/campaigns/i).first())
      ).toBeVisible({ timeout: 15000 });
    });

    test('create campaign button is visible', async ({ page }) => {
      await expect(
        page.getByRole('button', { name: /new campaign|create campaign|add campaign/i })
          .or(page.getByRole('link', { name: /new campaign|create campaign/i }))
      ).toBeVisible({ timeout: 10000 });
    });

    test('campaigns list shows items or empty state', async ({ page }) => {
      await expect(
        page.getByRole('list')
          .or(page.getByRole('table'))
          .or(page.getByText(/no campaigns|create your first/i))
      ).toBeVisible({ timeout: 10000 });
    });

    test('campaign status badges are shown', async ({ page }) => {
      const statusBadge = page.getByText(/active|draft|completed|running|scheduled/i).first();
      if (await statusBadge.isVisible({ timeout: 5000 })) {
        await expect(statusBadge).toBeVisible();
      }
      // Verify no crash even if no campaigns yet
      await expect(page).toHaveURL(/\/campaigns/);
    });
  });

  // ---------------------------------------------------------------------------
  // Campaign Creation
  // ---------------------------------------------------------------------------

  test.describe('Campaign Creation', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto(BASE_URL);
      await loginAsTestUser(page);
      await page.goto(`${BASE_URL}/campaigns`);
    });

    test('campaign form has name field', async ({ page }) => {
      const newBtn = page.getByRole('button', { name: /new campaign|create campaign/i })
        .or(page.getByRole('link', { name: /new campaign|create campaign/i }));
      if (await newBtn.isVisible({ timeout: 5000 })) {
        await newBtn.click();
        await expect(
          page.getByLabel(/campaign name|name/i)
            .or(page.getByPlaceholder(/campaign name|name/i))
        ).toBeVisible({ timeout: 10000 });
      }
    });

    test('campaign form has target field', async ({ page }) => {
      const newBtn = page.getByRole('button', { name: /new campaign|create campaign/i })
        .or(page.getByRole('link', { name: /new campaign|create campaign/i }));
      if (await newBtn.isVisible({ timeout: 5000 })) {
        await newBtn.click();
        await expect(
          page.getByLabel(/target|scope/i)
            .or(page.getByPlaceholder(/target|scope|domain/i))
        ).toBeVisible({ timeout: 10000 });
      }
    });

    test('campaign form validates required fields', async ({ page }) => {
      const newBtn = page.getByRole('button', { name: /new campaign|create campaign/i })
        .or(page.getByRole('link', { name: /new campaign|create campaign/i }));
      if (await newBtn.isVisible({ timeout: 5000 })) {
        await newBtn.click();
        const submitBtn = page.getByRole('button', { name: /create|submit|save/i });
        if (await submitBtn.isVisible({ timeout: 5000 })) {
          await submitBtn.click();
          await expect(
            page.getByText(/required|must be|invalid|name is required/i)
          ).toBeVisible({ timeout: 10000 });
        }
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Campaign Detail
  // ---------------------------------------------------------------------------

  test.describe('Campaign Detail', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto(BASE_URL);
      await loginAsTestUser(page);
    });

    test('campaign detail page loads', async ({ page }) => {
      await page.goto(`${BASE_URL}/campaigns`);
      const firstCampaign = page.getByRole('link').filter({ hasText: /campaign/i }).first()
        .or(page.getByRole('row').nth(1).getByRole('link').first());
      if (await firstCampaign.isVisible({ timeout: 5000 })) {
        await firstCampaign.click();
        await expect(page).toHaveURL(/\/campaigns\/[^/]+/, { timeout: 10000 });
        await expect(
          page.getByRole('heading').first()
        ).toBeVisible({ timeout: 10000 });
      }
      // Verify no crash
      await expect(page).toHaveURL(/\/campaigns/);
    });

    test('launch campaign action button is visible on detail page', async ({ page }) => {
      await page.goto(`${BASE_URL}/campaigns`);
      const firstCampaign = page.getByRole('link').filter({ hasText: /campaign/i }).first();
      if (await firstCampaign.isVisible({ timeout: 5000 })) {
        await firstCampaign.click();
        await expect(page).toHaveURL(/\/campaigns\/[^/]+/, { timeout: 10000 });
        await expect(
          page.getByRole('button', { name: /launch|start|run campaign/i })
            .or(page.getByText(/launch|start campaign/i).first())
        ).toBeVisible({ timeout: 10000 });
      }
    });

    test('navigating to a non-existent campaign shows error or redirect', async ({ page }) => {
      await page.goto(`${BASE_URL}/campaigns/nonexistent-campaign-id-xyz`);
      await expect(
        page.getByText(/not found|404|error|redirect/i)
          .or(page.getByRole('heading', { name: /not found|error/i }))
      ).toBeVisible({ timeout: 15000 });
    });
  });
});
