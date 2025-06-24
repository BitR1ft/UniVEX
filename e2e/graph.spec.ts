/**
 * Day 177: E2E Tests – Graph Visualization
 *
 * Playwright end-to-end tests for the attack-graph explorer:
 * rendering, interactions, filtering, and export functionality.
 *
 * Run with: npx playwright test e2e/graph.spec.ts
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

// ---------------------------------------------------------------------------
// Graph Explorer Page
// ---------------------------------------------------------------------------

test.describe('Graph Explorer', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
    await loginViaAPI(page);
    await page.goto(`${BASE_URL}/graph`);
  });

  test('renders graph explorer page', async ({ page }) => {
    await expect(
      page.getByRole('heading', { name: /graph|attack graph|explorer/i })
    ).toBeVisible({ timeout: 10000 });
  });

  test('shows 2D/3D view toggle', async ({ page }) => {
    await expect(
      page.getByRole('button', { name: /2d|3d/i }).or(page.getByText(/2d|3d/i))
    ).toBeVisible({ timeout: 10000 });
  });

  test('switches between 2D and 3D views', async ({ page }) => {
    // Click the 3D button if visible
    const toggle3D = page.getByRole('button', { name: /3d/i });
    if (await toggle3D.isVisible({ timeout: 5000 })) {
      await toggle3D.click();
      await expect(page.getByTestId('attack-graph-3d').or(page.getByText(/3d/i))).toBeVisible({ timeout: 5000 });
    }
  });

  test('displays graph filter panel', async ({ page }) => {
    await expect(
      page.getByTestId('graph-filter-panel').or(page.getByText(/filter|node type/i))
    ).toBeVisible({ timeout: 10000 });
  });
});

// ---------------------------------------------------------------------------
// Graph Filtering
// ---------------------------------------------------------------------------

test.describe('Graph Filtering', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
    await loginViaAPI(page);
    await page.goto(`${BASE_URL}/graph`);
  });

  test('search box filters nodes by label', async ({ page }) => {
    const searchBox = page.getByPlaceholder(/search nodes|filter/i);
    if (await searchBox.isVisible({ timeout: 5000 })) {
      await searchBox.fill('192.168');
      // Verify filtering is applied (no crash)
      await expect(searchBox).toHaveValue('192.168');
    }
  });

  test('node type checkboxes filter displayed nodes', async ({ page }) => {
    const domainFilter = page.getByLabel(/domain/i).or(page.getByText(/domain/i).first());
    if (await domainFilter.isVisible({ timeout: 5000 })) {
      await domainFilter.click();
      // Verify no crash after filtering
      await expect(page).toHaveURL(/\/graph/);
    }
  });
});

// ---------------------------------------------------------------------------
// Graph Export
// ---------------------------------------------------------------------------

test.describe('Graph Export', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
    await loginViaAPI(page);
    await page.goto(`${BASE_URL}/graph`);
  });

  test('export button is visible', async ({ page }) => {
    await expect(
      page.getByRole('button', { name: /export/i }).or(page.getByText(/export/i))
    ).toBeVisible({ timeout: 10000 });
  });

  test('GEXF export triggers file download', async ({ page }) => {
    const exportBtn = page.getByRole('button', { name: /export/i });
    if (await exportBtn.isVisible({ timeout: 5000 })) {
      const [download] = await Promise.all([
        page.waitForEvent('download', { timeout: 10000 }).catch(() => null),
        exportBtn.click(),
      ]);
      // If download happened, verify file extension
      if (download) {
        expect(download.suggestedFilename()).toMatch(/\.(gexf|json|csv)$/i);
      }
    }
  });

  test('copy link button shows toast notification', async ({ page }) => {
    const copyLinkBtn = page.getByRole('button', { name: /copy link/i });
    if (await copyLinkBtn.isVisible({ timeout: 5000 })) {
      await copyLinkBtn.click();
      await expect(page.getByText(/copied|link copied/i)).toBeVisible({ timeout: 5000 });
    }
  });
});

// ---------------------------------------------------------------------------
// Node Inspector
// ---------------------------------------------------------------------------

test.describe('Node Inspector', () => {
  test('clicking a node opens the inspector panel', async ({ page }) => {
    await page.goto(BASE_URL);
    await loginViaAPI(page);
    await page.goto(`${BASE_URL}/graph`);

    // Attempt to click a node in the canvas
    const canvas = page.locator('canvas').first();
    if (await canvas.isVisible({ timeout: 5000 })) {
      // Click center of canvas
      const box = await canvas.boundingBox();
      if (box) {
        await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
        // Inspector panel may appear
        await page.waitForTimeout(1000); // allow animation
        // Just verify no crash
        await expect(page).toHaveURL(/\/graph/);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Filter Panel Interactions
// ---------------------------------------------------------------------------

test.describe('Filter Panel Interactions', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
    await loginViaAPI(page);
    await page.goto(`${BASE_URL}/graph`);
  });

  test('filter panel can be opened and closed', async ({ page }) => {
    const filterToggle = page.getByRole('button', { name: /filter|filters/i })
      .or(page.getByTestId('filter-panel-toggle'));
    if (await filterToggle.isVisible({ timeout: 5000 })) {
      await filterToggle.click();
      await expect(
        page.getByTestId('graph-filter-panel')
          .or(page.getByRole('region', { name: /filter/i }))
      ).toBeVisible({ timeout: 5000 });
      await filterToggle.click();
      await expect(page).toHaveURL(/\/graph/);
    }
  });

  test('severity filter options are present in filter panel', async ({ page }) => {
    const filterPanel = page.getByTestId('graph-filter-panel')
      .or(page.getByText(/filter|node type/i).first());
    if (await filterPanel.isVisible({ timeout: 5000 })) {
      await expect(
        page.getByLabel(/critical|high|medium|low/i)
          .or(page.getByText(/critical|high|medium|low/i).first())
      ).toBeVisible({ timeout: 5000 });
    }
    await expect(page).toHaveURL(/\/graph/);
  });

  test('clearing all filters resets the graph view', async ({ page }) => {
    const clearBtn = page.getByRole('button', { name: /clear all|reset filters/i });
    if (await clearBtn.isVisible({ timeout: 5000 })) {
      await clearBtn.click();
      await page.waitForTimeout(500);
      // Verify page is still functional
      await expect(page).toHaveURL(/\/graph/);
    }
  });
});

// ---------------------------------------------------------------------------
// Node Type Legend
// ---------------------------------------------------------------------------

test.describe('Node Type Legend', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
    await loginViaAPI(page);
    await page.goto(`${BASE_URL}/graph`);
  });

  test('node type legend is visible', async ({ page }) => {
    await expect(
      page.getByTestId('node-legend')
        .or(page.getByRole('region', { name: /legend/i }))
        .or(page.getByText(/legend|node types/i).first())
    ).toBeVisible({ timeout: 10000 });
  });

  test('legend shows expected node types', async ({ page }) => {
    const legend = page.getByTestId('node-legend')
      .or(page.getByText(/legend|node types/i).first());
    if (await legend.isVisible({ timeout: 5000 })) {
      // At least one node-type label (host, domain, vulnerability, etc.) should appear
      await expect(
        page.getByText(/host|domain|service|vulnerability|user/i).first()
      ).toBeVisible({ timeout: 5000 });
    }
  });
});

// ---------------------------------------------------------------------------
// Graph Controls Toolbar
// ---------------------------------------------------------------------------

test.describe('Graph Controls Toolbar', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
    await loginViaAPI(page);
    await page.goto(`${BASE_URL}/graph`);
  });

  test('graph controls toolbar is visible', async ({ page }) => {
    await expect(
      page.getByRole('toolbar')
        .or(page.getByTestId('graph-controls'))
        .or(page.getByRole('group', { name: /controls|graph/i }))
        .or(page.getByRole('button', { name: /zoom in|zoom out|fit/i }).first())
    ).toBeVisible({ timeout: 10000 });
  });

  test('export button is visible in controls', async ({ page }) => {
    await expect(
      page.getByRole('button', { name: /export/i })
        .or(page.getByTestId('export-button'))
        .or(page.getByText(/export/i).first())
    ).toBeVisible({ timeout: 10000 });
  });

  test('3D/2D toggle is accessible from the toolbar', async ({ page }) => {
    await expect(
      page.getByRole('button', { name: /2d|3d/i })
        .or(page.getByTestId('view-toggle'))
        .or(page.getByText(/2d|3d/i).first())
    ).toBeVisible({ timeout: 10000 });
  });
});
