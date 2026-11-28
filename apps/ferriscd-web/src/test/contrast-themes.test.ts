/**
 * Theme-aware contrast checks for composited colours.
 *
 * `contrast.test.ts` covers opaque dark-theme token pairs. The UI also renders
 * `text-*` on `/15` tinted backgrounds and uses dedicated kind/control tokens,
 * so those need the alpha-over-background composite to be measured too.
 */
import { describe, expect, it } from "vitest";

interface Rgb {
  r: number;
  g: number;
  b: number;
}

function rgb(hex: string): Rgb {
  return {
    r: parseInt(hex.slice(1, 3), 16),
    g: parseInt(hex.slice(3, 5), 16),
    b: parseInt(hex.slice(5, 7), 16),
  };
}

/** `foreground` painted at `alpha` over an opaque `background`. */
function over(foreground: string, alpha: number, background: string): string {
  const fg = rgb(foreground);
  const bg = rgb(background);
  const mix = (a: number, b: number) => Math.round(a * alpha + b * (1 - alpha));
  return (
    "#" +
    [mix(fg.r, bg.r), mix(fg.g, bg.g), mix(fg.b, bg.b)]
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("")
  );
}

function channel(value: number): number {
  const srgb = value / 255;
  return srgb <= 0.04045 ? srgb / 12.92 : ((srgb + 0.055) / 1.055) ** 2.4;
}

function luminance(hex: string): number {
  const { r, g, b } = rgb(hex);
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

function ratio(a: string, b: string): number {
  const la = luminance(a);
  const lb = luminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

const LIGHT = {
  canvas: "#f1f5f9",
  surface: "#ffffff",
  inkStrong: "#0f172a",
  inkBody: "#334155",
  inkMuted: "#475569",
  hint: "#52627a",
  control: "#64748b",
  success: "#065f46",
  warning: "#92400e",
  danger: "#be123c",
  info: "#0369a1",
  accent: "#4338ca",
  kindNamespace: "#6d28d9",
  kindWorkload: "#a21caf",
  kindJob: "#9a3412",
  amber500: "#f59e0b",
  emerald500: "#10b981",
  rose500: "#f43f5e",
  sky500: "#0ea5e9",
  violet500: "#8b5cf6",
  fuchsia500: "#d946ef",
  orange500: "#f97316",
};

const DARK = {
  canvas: "#020617",
  surface: "#0f172a",
  inkStrong: "#f1f5f9",
  inkBody: "#cbd5e1",
  inkMuted: "#94a3b8",
  hint: "#94a3b8",
  control: "#64748b",
  success: "#6ee7b7",
  warning: "#fde68a",
  danger: "#fecdd3",
  info: "#7dd3fc",
  accent: "#a5b4fc",
  kindNamespace: "#c4b5fd",
  kindWorkload: "#f0abfc",
  kindJob: "#fdba74",
  amber500: "#f59e0b",
  emerald500: "#10b981",
  rose500: "#f43f5e",
  sky500: "#0ea5e9",
  violet500: "#8b5cf6",
  fuchsia500: "#d946ef",
  orange500: "#f97316",
};

describe.each([
  ["light", LIGHT],
  ["dark", DARK],
] as const)("%s theme composited contrast", (_name, t) => {
  const tinted = (color: string) => over(color, 0.15, t.surface);

  it("keeps semantic text on tinted surfaces at >= 4.5:1", () => {
    const pairs: [string, string, string][] = [
      [t.success, tinted(t.emerald500), "success tint"],
      [t.warning, tinted(t.amber500), "warning badge"],
      [t.danger, tinted(t.rose500), "danger tint"],
      [t.info, tinted(t.sky500), "info tint"],
      [t.accent, tinted(t.violet500), "accent tint"],
      [t.kindNamespace, tinted(t.violet500), "namespace badge"],
      [t.kindWorkload, tinted(t.fuchsia500), "workload badge"],
      [t.kindJob, tinted(t.orange500), "job badge"],
    ];
    for (const [foreground, background, where] of pairs) {
      expect(ratio(foreground, background), where).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("keeps secondary text and hints at >= 4.5:1", () => {
    expect(ratio(t.inkMuted, t.canvas)).toBeGreaterThanOrEqual(4.5);
    expect(ratio(t.inkMuted, t.surface)).toBeGreaterThanOrEqual(4.5);
    expect(ratio(t.hint, t.canvas)).toBeGreaterThanOrEqual(4.5);
    expect(ratio(t.inkBody, t.canvas)).toBeGreaterThanOrEqual(4.5);
    expect(ratio(t.inkStrong, t.canvas)).toBeGreaterThanOrEqual(4.5);
  });

  it("keeps control and graph boundaries at >= 3:1", () => {
    expect(ratio(t.control, t.surface)).toBeGreaterThanOrEqual(3);
    expect(ratio(t.control, t.canvas)).toBeGreaterThanOrEqual(3);
    // Graph nodes use ink-subtle (mapped to inkMuted here) and edges the same.
    expect(ratio(t.inkMuted, t.surface)).toBeGreaterThanOrEqual(3);
    expect(ratio(t.inkMuted, t.canvas)).toBeGreaterThanOrEqual(3);
  });
});
