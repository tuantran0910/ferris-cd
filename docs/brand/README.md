# FerrisCD brand assets

Two source-of-truth SVGs. Both self-adjust between light and dark colour schemes
via an internal `prefers-color-scheme` rule (`#DC4A2B` light, `#FF7657` dark).

| File | Size | Use |
|---|---|---|
| [`ferriscd-mark.svg`](ferriscd-mark.svg) | 64×64 | App favicon, header/login mark, Kubernetes/container icons, avatars. Orange only — safe on light **and** dark backgrounds. |
| [`ferriscd-logo.svg`](ferriscd-logo.svg) | 240×64 | README/docs headers, GitHub social preview, slides. Includes the wordmark; needs a light or dark background that matches the media query. |
| `ferriscd-mark.png` | 512×512 | Raster fallback (GitHub repo avatar upload, Helm chart icon). Transparent background. |
| `ferriscd-social.png` | 1280×640 | GitHub "Social preview" image (Settings → General → Social preview). |

## Where they are used

- **Application:** `apps/ferriscd-web/public/ferriscd-mark.svg` is the favicon and the
  brand mark in the header and on the sign-in card. The wordmark stays HTML text so it
  inherits the app's dark theme (an `<img>` would follow the OS theme, not the app).
- **Repository:** the root `README.md` embeds `docs/brand/ferriscd-logo.svg`; set the
  GitHub organization/repository avatar and social preview from the PNGs above.
- **Packaging:** container images and the Helm chart can reference the mark as their icon.

## Rules

- Never recolour the mark, add outlines, or place it on a low-contrast orange/red field.
- Keep clear space of at least half the mark's width on every side.
- Use the mark alone below 96px; use the lockup (mark + wordmark) at or above that size.
- Do not stretch: the mark is square, the lockup is 15:4.
