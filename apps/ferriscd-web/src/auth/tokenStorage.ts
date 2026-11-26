/**
 * Bearer token storage for FerrisCD Web UI.
 *
 * Security invariant (Trap Guard T16.1):
 * - Tokens are stored ONLY in process memory and `window.sessionStorage`.
 * - Tokens are NEVER written to `localStorage` or serialized into URL query/hash parameters.
 * - URL query/hash parameters are never trusted as a token source.
 */

const SESSION_TOKEN_KEY = "ferriscd.auth.token";
const SESSION_BASE_URL_KEY = "ferriscd.api.baseUrl";

let inMemoryToken: string | null = null;
let inMemoryBaseUrl: string | null = null;

function getSessionStorage(): Storage | null {
  try {
    if (typeof window !== "undefined" && window.sessionStorage) {
      return window.sessionStorage;
    }
  } catch {
    // sessionStorage can throw in restricted browser contexts; fall back to memory only.
  }
  return null;
}

/**
 * Normalizes the API base URL (empty string means same-origin / Vite proxy).
 * Never preserves query params or fragments so secrets cannot leak via URLs.
 */
export function normalizeBaseUrl(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) {
    return "";
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "";
    }
    return `${parsed.origin}${parsed.pathname}`.replace(/\/+$/, "");
  } catch {
    // Allow relative path prefixes such as "/ferriscd"
    const withoutQueryOrHash = trimmed.split(/[?#]/, 1)[0] ?? "";
    return withoutQueryOrHash.replace(/\/+$/, "");
  }
}

export function getStoredToken(): string | null {
  if (inMemoryToken !== null) {
    return inMemoryToken;
  }
  const storage = getSessionStorage();
  const stored = storage?.getItem(SESSION_TOKEN_KEY) ?? null;
  if (stored && stored.trim().length > 0) {
    inMemoryToken = stored;
    return stored;
  }
  return null;
}

export function setStoredToken(token: string): void {
  const trimmed = token.trim();
  if (!trimmed) {
    clearStoredToken();
    return;
  }
  inMemoryToken = trimmed;
  const storage = getSessionStorage();
  try {
    storage?.setItem(SESSION_TOKEN_KEY, trimmed);
  } catch {
    // In-memory token remains active even if sessionStorage quota is exceeded.
  }
}

export function clearStoredToken(): void {
  inMemoryToken = null;
  const storage = getSessionStorage();
  try {
    storage?.removeItem(SESSION_TOKEN_KEY);
  } catch {
    // Ignore storage cleanup errors.
  }
}

export function getStoredBaseUrl(): string {
  if (inMemoryBaseUrl !== null) {
    return inMemoryBaseUrl;
  }
  const storage = getSessionStorage();
  const stored = storage?.getItem(SESSION_BASE_URL_KEY);
  if (stored !== null && stored !== undefined) {
    inMemoryBaseUrl = normalizeBaseUrl(stored);
    return inMemoryBaseUrl;
  }
  const envDefault =
    typeof import.meta !== "undefined" &&
    typeof import.meta.env?.VITE_API_BASE_URL === "string"
      ? normalizeBaseUrl(import.meta.env.VITE_API_BASE_URL)
      : "";
  inMemoryBaseUrl = envDefault;
  return envDefault;
}

export function setStoredBaseUrl(baseUrl: string): void {
  const normalized = normalizeBaseUrl(baseUrl);
  inMemoryBaseUrl = normalized;
  const storage = getSessionStorage();
  try {
    if (normalized) {
      storage?.setItem(SESSION_BASE_URL_KEY, normalized);
    } else {
      storage?.removeItem(SESSION_BASE_URL_KEY);
    }
  } catch {
    // Ignore storage errors.
  }
}

/**
 * Test helper to reset in-memory cache cleanly between test cases.
 */
export function resetTokenMemoryCache(): void {
  inMemoryToken = null;
  inMemoryBaseUrl = null;
}
