/**
 * Secret redaction detection and value formatting helpers for DiffViewer (`T16.4`).
 *
 * `ferriscd-engine` redacts Secret `.data` / `.stringData` values before they
 * ever leave the server using the marker `***REDACTED(sha256:<8-hex>)***`.
 */

const REDACTED_EXACT_RE = /^\*\*\*REDACTED\([^)]*\)\*\*\*$/;
const REDACTED_TEST_RE = /\*\*\*REDACTED\([^)]*\)\*\*\*/;
const REDACTED_MATCH_ALL_RE = /\*\*\*REDACTED\([^)]*\)\*\*\*/g;

export function isRedactedToken(value: unknown): value is string {
  return typeof value === "string" && REDACTED_EXACT_RE.test(value);
}

export function containsRedactedMarker(value: unknown): boolean {
  if (typeof value === "string") {
    return REDACTED_TEST_RE.test(value);
  }
  if (Array.isArray(value)) {
    return value.some((item) => containsRedactedMarker(item));
  }
  if (value !== null && typeof value === "object") {
    return Object.values(value as Record<string, unknown>).some((v) =>
      containsRedactedMarker(v),
    );
  }
  return false;
}

export function extractRedactedMarkers(value: unknown): string[] {
  const markers: string[] = [];
  const visit = (v: unknown) => {
    if (typeof v === "string") {
      const matches = v.match(REDACTED_MATCH_ALL_RE);
      if (matches) {
        markers.push(...matches);
      }
    } else if (Array.isArray(v)) {
      v.forEach(visit);
    } else if (v !== null && typeof v === "object") {
      Object.values(v as Record<string, unknown>).forEach(visit);
    }
  };
  visit(value);
  return Array.from(new Set(markers));
}

export function formatDiffValue(value: unknown): string {
  if (value === undefined || value === null) {
    return "null";
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

export function isSecretResourceKey(key: string): boolean {
  const parts = key.split("/");
  return parts.length >= 2 && parts[1] === "Secret";
}
