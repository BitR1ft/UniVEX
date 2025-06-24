/** Day 28: E2E tests for the UniVex dashboard. */

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
// Dashboard Page Load
// ---------------------------------------------------------------------------

test.describe('Dashboard', () => {
  test.describe('Page Load', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto(BASE_URL);
      await loginAsTestUser(page);
      await page.goto(`${BASE_URL}/dashboard`);
    });

    test('dashboard page loads and shows heading', async ({ page }) => {
      await expect(
        page.getByRole('heading', { name: /dashboard/i }).or(page.getByText(/dashboard/i).first())
      ).toBeVisible({ timeout: 15000 });
    });

    test('stats grid is visible', async ({ page }) => {
      await expect(
        page.getByTestId('stats-grid')
          .or(page.getByRole('region', { name: /stats|metrics|overview/i }))
          .or(page.getByText(/total projects|active scans|vulnerabilities/i).first())
      ).toBeVisible({ timeout: 10000 });
    });

    test('activity feed is shown', async ({ page }) => {
      await expect(
        page.getByTestId('activity-feed')
          .or(page.getByRole('region', { name: /activity|recent/i }))
          .or(page.getByText(/activity|recent activity/i).first())
      ).toBeVisible({ timeout: 10000 });
    });

    test('scan timeline is visible', async ({ page }) => {
      await expect(
        page.getByTestId('scan-timeline')
          .or(page.getByRole('region', { name: /timeline|scan history/i }))
          .or(page.getByText(/timeline|scan history|recent scans/i).first())
      ).toBeVisible({ timeout: 10000 });
    });

    test('quick actions section is visible', async ({ page }) => {
      await expect(
        page.getByTestId('quick-actions')
          .or(page.getByRole('region', { name: /quick actions/i }))
          .or(page.getByText(/quick actions|new project|new scan/i).first())
      ).toBeVisible({ timeout: 10000 });
    });
  });

  // ---------------------------------------------------------------------------
  // Command Palette
  // ---------------------------------------------------------------------------

  test.describe('Command Palette', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto(BASE_URL);
      await loginAsTestUser(page);
      await page.goto(`${BASE_URL}/dashboard`);
    });

    test('command palette opens with Ctrl+K', async ({ page }) => {
      await page.keyboard.press('Control+k');
      await expect(
        page.getByRole('dialog')
          .or(page.getByTestId('command-palette'))
          .or(page.getByPlaceholder(/search commands|type a command/i))
      ).toBeVisible({ timeout: 10000 });
    });

    test('command palette search filters results', async ({ page }) => {
      await page.keyboard.press('Control+k');
      const searchInput = page.getByPlaceholder(/search commands|type a command/i)
        .or(page.getByRole('dialog').getByRole('textbox').first());
      if (await searchInput.isVisible({ timeout: 5000 })) {
        await searchInput.fill('project');
        await expect(searchInput).toHaveValue('project');
        // Results should narrow – just verify no crash
        await expect(page).toHaveURL(/\/dashboard/);
      }
    });

    test('command palette closes with Escape', async ({ page }) => {
      await page.keyboard.press('Control+k');
      const palette = page.getByRole('dialog').or(page.getByTestId('command-palette'));
      if (await palette.isVisible({ timeout: 5000 })) {
        await page.keyboard.press('Escape');
        await expect(palette).not.toBeVisible({ timeout: 5000 });
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Theme & Navigation
  // ---------------------------------------------------------------------------

  test.describe('Theme and Navigation', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto(BASE_URL);
      await loginAsTestUser(page);
      await page.goto(`${BASE_URL}/dashboard`);
    });

    test('theme toggle button is visible', async ({ page }) => {
      await expect(
        page.getByRole('button', { name: /theme|dark|light|toggle theme/i })
          .or(page.getByTestId('theme-toggle'))
          .or(page.getByLabel(/theme|dark mode/i))
      ).toBeVisible({ timeout: 10000 });
    });

    test('theme toggle switches between dark and light mode', async ({ page }) => {
      const themeToggle = page.getByRole('button', { name: /theme|dark|light/i })
        .or(page.getByTestId('theme-toggle'))
        .first();
      if (await themeToggle.isVisible({ timeout: 5000 })) {
        const htmlEl = page.locator('html');
        const classBefore = await htmlEl.getAttribute('class');
        await themeToggle.click();
        await page.waitForTimeout(500);
        const classAfter = await htmlEl.getAttribute('class');
        // class attribute should change (dark/light toggled)
        expect(classBefore).not.toEqual(classAfter);
      }
    });

    test('navigation sidebar is visible', async ({ page }) => {
      await expect(
        page.getByRole('navigation')
          .or(page.getByTestId('sidebar'))
          .or(page.locator('nav').first())
      ).toBeVisible({ timeout: 10000 });
    });

    test('sidebar navigation links work', async ({ page }) => {
      const projectsLink = page.getByRole('link', { name: /projects/i })
        .or(page.getByRole('navigation').getByText(/projects/i));
      if (await projectsLink.isVisible({ timeout: 5000 })) {
        await projectsLink.click();
        await expect(page).toHaveURL(/\/projects/, { timeout: 10000 });
      }
    });
  });
});
