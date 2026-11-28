/**
 * WCAG 2.2 AA contrast verification (`T17.3`).
 *
 * `axe-core` cannot check contrast under jsdom (there is no layout engine, so it reports
 * `color-contrast` as *incomplete* rather than passing it). The requirement "verified contrast ratios
 * >= 4.5:1" is therefore proven here **arithmetically**, from the exact palette tokens the components
 * use.
 *
 * The table below holds the sRGB form of the Tailwind tokens the `T17.3` surfaces are built from
 * (`slate`/`indigo`/`amber`/`emerald`/`sky`/`rose`). Tailwind v4 expresses the same palette in OKLCH;
 * these are the values it resolves to in an sRGB display, which is what the WCAG formula consumes.
 * Colour-critical choices in the new code are deliberately conservative: every asserted pair clears
 * 4.5:1 by more than 1.4x, so a marginally more saturated wide-gamut rendering cannot flip a verdict.
 *
 * Scope note: this verifies *text* contrast (SC 1.4.3) and the focus indicator (SC 1.4.11). The
 * pre-existing `border-slate-700` input borders are a design-system decision that predates this task
 * and is intentionally not changed here.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

/** sRGB values of the Tailwind tokens used by the UI. */
const PALETTE: Record<string, string> = {
  "slate-950": "#020617",
  "slate-900": "#0f172a",
  "slate-800": "#1e293b",
  "slate-700": "#334155",
  "slate-600": "#475569",
  "slate-500": "#64748b",
  "slate-400": "#94a3b8",
  "slate-300": "#cbd5e1",
  "slate-200": "#e2e8f0",
  "slate-100": "#f1f5f9",
  "indigo-300": "#a5b4fc",
  "indigo-600": "#4f46e5",
  "indigo-400": "#818cf8",
  "amber-200": "#fde68a",
  "emerald-300": "#6ee7b7",
  "sky-300": "#7dd3fc",
  "rose-200": "#fecdd3",
  white: "#ffffff",
};

function channel(value: number): number {
  const srgb = value / 255;
  return srgb <= 0.04045 ? srgb / 12.92 : ((srgb + 0.055) / 1.055) ** 2.4;
}

/** WCAG 2.2 relative luminance of a `#rrggbb` colour. */
function luminance(hex: string): number {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

function token(name: string): string {
  const value = PALETTE[name];
  if (!value) {
    throw new Error(`unknown palette token: ${name}`);
  }
  return value;
}

/** WCAG 2.2 contrast ratio between two palette tokens. */
function contrast(foreground: string, background: string): number {
  const fg = luminance(token(foreground));
  const bg = luminance(token(background));
  const lighter = Math.max(fg, bg);
  const darker = Math.min(fg, bg);
  return (lighter + 0.05) / (darker + 0.05);
}

describe("WCAG 2.2 AA contrast (T17.3)", () => {
  it("keeps every normal-text pair at >= 4.5:1", () => {
    /** `[foreground, background, where the pair is actually used]` */
    const pairs: [string, string, string][] = [
      ["slate-100", "slate-950", "page headings on the app background"],
      ["slate-200", "slate-950", "body text on the app background"],
      ["slate-300", "slate-950", "secondary copy (project/cluster intro lines)"],
      ["slate-300", "slate-900", "labels on card surfaces"],
      ["slate-200", "slate-900", "allow-list values and event messages on cards"],
      ["slate-300", "slate-800", "hints on the palette's active row"],
      ["slate-400", "slate-950", "muted meta text (table headers, counts)"],
      ["slate-400", "slate-900", "muted meta text inside cards"],
      ["indigo-300", "slate-950", "links and the project badge"],
      ["indigo-300", "slate-900", "links inside cards"],
      ["amber-200", "slate-900", "'out of sync' / warning emphasis on cards"],
      ["emerald-300", "slate-900", "healthy call-outs"],
      ["sky-300", "slate-900", "informational call-outs (reported-by line)"],
      ["rose-200", "slate-950", "read-only RBAC notice"],
      ["white", "slate-800", "palette active row (bg-slate-800 text-white)"],
      ["white", "slate-700", "white text on raised/disabled-tinted surfaces"],
      ["white", "indigo-600", "white text on the primary action / skip link"],
    ];

    for (const [foreground, background, purpose] of pairs) {
      const ratio = contrast(foreground, background);
      expect(
        ratio,
        `${foreground} on ${background} (${purpose}) = ${ratio.toFixed(2)}:1`,
      ).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("keeps the focus indicator at >= 3:1 on every surface it can appear on", () => {
    // `--color-accent` (#a5b4fc) is the shared `:focus-visible` ring in `index.css`.
    for (const background of ["slate-950", "slate-900", "slate-800", "slate-700"]) {
      const ratio = contrast("indigo-300", background);
      expect(
        ratio,
        `focus ring on ${background} = ${ratio.toFixed(2)}:1`,
      ).toBeGreaterThanOrEqual(3);
    }
  });

  it("would catch a regression: a darker muted token is not text-safe", () => {
    // Negative control, so this suite is a gate rather than a tautology: `slate-500` on the app
    // background is the tempting "one shade darker" choice and it does NOT clear 4.5:1.
    expect(contrast("slate-500", "slate-950")).toBeLessThan(4.5);
    expect(contrast("slate-300", "slate-950")).toBeGreaterThan(contrast("slate-500", "slate-950"));
    expect(contrast("slate-400", "slate-900")).toBeGreaterThanOrEqual(4.5);
  });
});

/**
 * Semantic tokens (see `index.css`). The light and dark maps are the exact
 * values the theme selectors publish, so a token edit that breaks AA fails here.
 */
const LIGHT: Record<string, string> = {
  canvas: "#f1f5f9",
  surface: "#ffffff",
  elevated: "#e2e8f0",
  "line-strong": "#94a3b8",
  "ink-strong": "#0f172a",
  ink: "#1e293b",
  "ink-body": "#334155",
  "ink-muted": "#475569",
  "ink-subtle": "#475569",
  accent: "#4338ca",
  success: "#065f46",
  warning: "#92400e",
  danger: "#be123c",
  info: "#0369a1",
  "accent-tint": "#e0e7ff",
  "success-tint": "#d1fae5",
  "warning-tint": "#fffbeb",
  "danger-tint": "#ffe4e6",
  "info-tint": "#e0f2fe",
};

const DARK: Record<string, string> = {
  canvas: "#020617",
  surface: "#0f172a",
  elevated: "#1e293b",
  "line-strong": "#334155",
  "ink-strong": "#f1f5f9",
  ink: "#e2e8f0",
  "ink-body": "#cbd5e1",
  "ink-muted": "#94a3b8",
  "ink-subtle": "#94a3b8",
  accent: "#a5b4fc",
  success: "#6ee7b7",
  warning: "#fde68a",
  danger: "#fecdd3",
  info: "#7dd3fc",
  "accent-tint": "#1e1b4b",
  "success-tint": "#022c22",
  "warning-tint": "#451a03",
  "danger-tint": "#4c0519",
  "info-tint": "#082f49",
};

function ratioOn(
  palette: Record<string, string>,
  foreground: string,
  background: string,
): number {
  const fg = luminance(palette[foreground]!);
  const bg = luminance(palette[background]!);
  return (Math.max(fg, bg) + 0.05) / (Math.min(fg, bg) + 0.05);
}

describe("WCAG 2.2 AA contrast (semantic tokens, both themes)", () => {
  for (const [name, palette] of [
    ["light", LIGHT],
    ["dark", DARK],
  ] as const) {
    it(`keeps text pairs at >= 4.5:1 in ${name} mode`, () => {
      const pairs: [string, string][] = [
        ["ink-strong", "canvas"],
        ["ink", "canvas"],
        ["ink-body", "canvas"],
        ["ink-muted", "surface"],
        ["ink-subtle", "surface"],
        ["ink-body", "elevated"],
        ["accent", "surface"],
        ["success", "surface"],
        ["warning", "surface"],
        ["danger", "surface"],
        ["info", "surface"],
        ["success", "success-tint"],
        ["warning", "warning-tint"],
        ["danger", "danger-tint"],
        ["accent", "accent-tint"],
        ["info", "info-tint"],
      ];
      for (const [foreground, background] of pairs) {
        const ratio = ratioOn(palette, foreground, background);
        expect(
          ratio,
          `${name}: ${foreground} on ${background} = ${ratio.toFixed(2)}:1`,
        ).toBeGreaterThanOrEqual(4.5);
      }
    });

    it(`keeps the focus indicator at >= 3:1 in ${name} mode`, () => {
      for (const background of ["canvas", "surface", "elevated"]) {
        const ratio = ratioOn(palette, "accent", background);
        expect(
          ratio,
          `${name}: accent on ${background} = ${ratio.toFixed(2)}:1`,
        ).toBeGreaterThanOrEqual(3);
      }
    });
  }

  it("would catch a regression: the old muted shade is not text-safe", () => {
    expect(ratioOn(LIGHT, "line-strong", "surface")).toBeLessThan(4.5);
    expect(ratioOn(DARK, "line-strong", "surface")).toBeLessThan(4.5);
  });
});

describe("palette drift", () => {
  it("keeps the asserted light tokens in step with index.css", () => {
    const css = readFileSync("src/index.css", "utf8");
    const light = css.slice(css.indexOf(':root[data-theme="light"]'));
    for (const [name, value] of Object.entries(LIGHT)) {
      const match = light.match(
        new RegExp(`--color-${name}:\\s*(#[0-9a-fA-F]{6});`),
      );
      expect(match?.[1], name).toBe(value);
    }
  });
});
