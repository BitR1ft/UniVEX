/**
 * Day 174: E2E Tests – Authentication
 *
 * Playwright end-to-end tests for the authentication flows.
 * These specs exercise: login, registration, session expiry, and
 * route protection using the running Next.js + FastAPI stack.
 *
 * Run with: npx playwright test e2e/auth.spec.ts
 */

import { test, expect } from '@playwright/test';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BASE_URL = process.env.PLAYWRIGHT_BASE_URL ?? 'http://localhost:3000';

async function clearStorage(page: any) {
  await page.evaluate(() => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
  });
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

test.describe('Login', () => {
  test.beforeEach(async ({ page }) => {
    await clearStorage(page);
    await page.goto(`${BASE_URL}/login`);
  });

  test('renders login form with username and password fields', async ({ page }) => {
    await expect(page.getByLabel(/username/i)).toBeVisible();
    await expect(page.getByLabel(/password/i)).toBeVisible();
    await expect(page.getByRole('button', { name: /login|sign in/i })).toBeVisible();
  });

  test('shows validation error for empty submission', async ({ page }) => {
    await page.getByRole('button', { name: /login|sign in/i }).click();
    await expect(page.getByText(/must be at least 3 characters/i)).toBeVisible();
  });

  test('shows error for invalid credentials', async ({ page }) => {
    await page.getByLabel(/username/i).fill('wronguser');
    await page.getByLabel(/password/i).fill('WrongPass1!');
    await page.getByRole('button', { name: /login|sign in/i }).click();
    await expect(page.getByText(/invalid credentials|unauthorized/i)).toBeVisible({ timeout: 10000 });
  });

  test('redirects to dashboard on successful login', async ({ page }) => {
    await page.getByLabel(/username/i).fill(process.env.E2E_TEST_USER ?? 'admin');
    await page.getByLabel(/password/i).fill(process.env.E2E_TEST_PASS ?? 'Admin1Password!');
    await page.getByRole('button', { name: /login|sign in/i }).click();
    await expect(page).toHaveURL(/\/dashboard|\/projects/, { timeout: 15000 });
  });

  test('stores access token in localStorage after login', async ({ page }) => {
    await page.getByLabel(/username/i).fill(process.env.E2E_TEST_USER ?? 'admin');
    await page.getByLabel(/password/i).fill(process.env.E2E_TEST_PASS ?? 'Admin1Password!');
    await page.getByRole('button', { name: /login|sign in/i }).click();
    await page.waitForURL(/\/dashboard|\/projects/, { timeout: 15000 });
    const token = await page.evaluate(() => localStorage.getItem('access_token'));
    expect(token).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

test.describe('Registration', () => {
  test.beforeEach(async ({ page }) => {
    await clearStorage(page);
    await page.goto(`${BASE_URL}/register`);
  });

  test('renders registration form', async ({ page }) => {
    await expect(page.getByLabel(/username/i)).toBeVisible();
    await expect(page.getByLabel(/email/i)).toBeVisible();
    await expect(page.getByLabel(/^password$/i)).toBeVisible();
    await expect(page.getByLabel(/confirm password/i)).toBeVisible();
  });

  test('shows password strength meter', async ({ page }) => {
    await page.getByLabel(/^password$/i).fill('weak');
    await expect(page.getByTestId('password-strength')).toBeVisible();
  });

  test('shows error for mismatched passwords', async ({ page }) => {
    await page.getByLabel(/username/i).fill('newuser01');
    await page.getByLabel(/email/i).fill('newuser@example.com');
    await page.getByLabel(/^password$/i).fill('Secure1Pass!');
    await page.getByLabel(/confirm password/i).fill('DifferentPass1!');
    await page.getByRole('button', { name: /register|sign up/i }).click();
    await expect(page.getByText(/passwords don't match/i)).toBeVisible();
  });

  test('navigates to login after successful registration', async ({ page }) => {
    const uniqueUser = `e2euser${Date.now()}`;
    await page.getByLabel(/username/i).fill(uniqueUser);
    await page.getByLabel(/email/i).fill(`${uniqueUser}@example.com`);
    await page.getByLabel(/^password$/i).fill('Secure1Pass!');
    await page.getByLabel(/confirm password/i).fill('Secure1Pass!');
    await page.getByRole('button', { name: /register|sign up/i }).click();
    await expect(page).toHaveURL(/\/login|\/dashboard/, { timeout: 15000 });
  });
});

// ---------------------------------------------------------------------------
// Session Expiry
// ---------------------------------------------------------------------------

test.describe('Session Expiry', () => {
  test('redirects to login when access token is missing', async ({ page }) => {
    await clearStorage(page);
    await page.goto(`${BASE_URL}/projects`);
    await expect(page).toHaveURL(/\/login/, { timeout: 10000 });
  });

  test('redirects to login when access token is invalid', async ({ page }) => {
    await page.evaluate(() => localStorage.setItem('access_token', 'invalid.jwt.token'));
    await page.goto(`${BASE_URL}/projects`);
    await expect(page).toHaveURL(/\/login/, { timeout: 10000 });
  });
});
