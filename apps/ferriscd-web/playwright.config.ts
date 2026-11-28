import { defineConfig, devices } from "@playwright/test";

// Use the host Chrome locally; CI installs the bundled Chromium instead.
const channel = process.env.PW_CHANNEL ?? (process.env.CI ? undefined : "chrome");
const browserChannel = channel ? { channel } : {};

export default defineConfig({
  testDir: "./e2e",
  timeout: 45_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: "http://127.0.0.1:5173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
    reducedMotion: "reduce",
  },
  projects: [
    {
      name: "desktop-dark",
      use: {
        ...devices["Desktop Chrome"],
        ...browserChannel,
        viewport: { width: 1440, height: 1000 },
        colorScheme: "dark",
      },
    },
    {
      name: "desktop-light",
      use: {
        ...devices["Desktop Chrome"],
        ...browserChannel,
        viewport: { width: 1440, height: 1000 },
        colorScheme: "light",
      },
    },
    {
      name: "mobile",
      use: {
        ...devices["Desktop Chrome"],
        ...browserChannel,
        viewport: { width: 390, height: 844 },
        isMobile: true,
        hasTouch: true,
        colorScheme: "dark",
      },
    },
  ],
  webServer: {
    command: "npm run dev -- --host 127.0.0.1",
    url: "http://127.0.0.1:5173",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
