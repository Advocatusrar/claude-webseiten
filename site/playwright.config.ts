// Browser tests (tests/e2e). By default they run against "astro preview" of the
// built site in dist/. With E2E_BASE_URL they test a running server instead,
// e.g. the Docker image in CI: E2E_BASE_URL=http://127.0.0.1:8080 npx playwright test
// PW_CHROMIUM_PATH points to a locally installed Chromium if Playwright's own is missing.
import { defineConfig, devices } from '@playwright/test';

const extern = process.env.E2E_BASE_URL;
const PORT = 4329;
const executablePath = process.env.PW_CHROMIUM_PATH || undefined;

export default defineConfig({
  testDir: 'tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: extern ?? `http://127.0.0.1:${PORT}`,
    trace: 'retain-on-failure',
    launchOptions: { executablePath },
  },
  projects: [
    {
      name: 'mobil-hell',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 360, height: 800 },
        colorScheme: 'light',
        launchOptions: { executablePath },
      },
    },
    {
      name: 'desktop-dunkel',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1280, height: 900 },
        colorScheme: 'dark',
        launchOptions: { executablePath },
      },
    },
  ],
  webServer: extern
    ? undefined
    : {
        command: `npx astro preview --host 127.0.0.1 --port ${PORT} --ignore-lock`,
        url: `http://127.0.0.1:${PORT}`,
        reuseExistingServer: !process.env.CI,
      },
});
