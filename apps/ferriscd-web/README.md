# FerrisCD web UI

React + Vite front end for the FerrisCD control plane.

## Commands

```sh
npm ci
npm run dev            # Vite on :5173, proxies /api to 127.0.0.1:8080
npm run typecheck
npm test -- --run      # Vitest + Testing Library (jsdom)
npm run build
```

## Browser tests (Playwright)

The end-to-end suite is hermetic: every `/api/v1/**` call is answered from the
frozen capture in `e2e/fixtures/api.json`, so no FerrisCD server, Kubernetes
cluster or seed data is required.

```sh
npx playwright install chromium   # first run only
npm run test:e2e                  # smoke + accessibility + visual snapshots
npm run test:e2e:ci               # smoke/a11y/responsive only (used by CI)
```

Locally the config uses the installed Google Chrome (`PW_CHANNEL=chrome` by
default); CI installs and uses the bundled Chromium. Visual baselines are
platform-suffixed (`*-darwin.png`), and the CI job intentionally runs only the
non-snapshot smoke suite so a Linux runner does not compare against macOS
pixels. Update baselines with `npm run test:e2e:update`.
