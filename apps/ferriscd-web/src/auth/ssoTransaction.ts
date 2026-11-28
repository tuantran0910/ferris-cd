/**
 * The one thing the SPA may persist during an SSO sign-in: the PKCE **transaction** (`T19.2`).
 *
 * A sign-in is a full-page round trip to the IdP, so the `state` and the verifier have to survive a
 * navigation — `sessionStorage` is the only storage that does, and it is cleared with the tab. What is
 * stored is *not* a credential: the verifier is worthless without the authorization code, and the code
 * is delivered to this page only after the IdP authenticated the operator.
 *
 * The invariant the tests assert is the important half: no **token** is ever written here (or to
 * `localStorage`), which is why the type below has no field for one.
 */

import { SSO_CALLBACK_PATH, type PkceTransaction } from "./pkce";

const TRANSACTION_KEY = "ferriscd.auth.pkce";

/**
 * How long a started sign-in stays completable: **10 minutes**.
 *
 * The IdP's own authorization request usually expires sooner (Okta/Auth0/Dex default to 5–10
 * minutes), and the server-side (BFF) flow caps its equivalent at `MAX_TRANSACTION_TTL` (15 minutes)
 * with a 5-minute default — this is the SPA's own ceiling, and it is deliberately shorter than the BFF
 * maximum so a stale transaction is reported as expired rather than replayed.
 */
export const TRANSACTION_TTL_MS = 10 * 60 * 1000;

/** What a returning callback needs to finish the exchange. */
export interface StoredTransaction extends PkceTransaction {
  /** The exact redirect URI sent to the IdP (it must be replayed verbatim at the token endpoint). */
  redirectUri: string;
  /** The discovery endpoints, so the callback does not have to fetch them again. */
  authorizationEndpoint: string;
  tokenEndpoint: string;
  /**
   * The same-origin path the operator was on when the sign-in started (`/projects?sync=…`).
   *
   * Restored after the exchange: the IdP redirects to the fixed {@link SSO_CALLBACK_PATH}, so without
   * this the operator would land on the dashboard instead of the page they were looking at.
   */
  returnTo: string;
  /** When the sign-in started (TTL anchor). */
  createdAt: number;
}

/**
 * Whether `value` is a same-origin path this app may navigate to.
 *
 * A path, not a URL: `//evil.example` is protocol-relative and `\` is treated as `/` by several
 * browsers, so both are refused along with anything absolute or containing a control character. The
 * value is re-validated on **read**, because `sessionStorage` is writable by any script in the origin
 * (and by the operator).
 */
export function isSafeReturnPath(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.startsWith("/") &&
    !value.startsWith("//") &&
    !value.includes("\\") &&
    // eslint-disable-next-line no-control-regex
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function getSessionStorage(): Storage | null {
  try {
    if (typeof window !== "undefined" && window.sessionStorage) {
      return window.sessionStorage;
    }
  } catch {
    // A restricted context (third-party storage blocked) has no sessionStorage.
  }
  return null;
}

/** The message a browser that blocks `sessionStorage` deserves, instead of a silently dead sign-in. */
const STORAGE_UNAVAILABLE =
  "This browser blocks sessionStorage, so the single sign-on round trip cannot complete.";

/**
 * Saves the transaction (replacing any earlier one: two tabs cannot interleave states).
 *
 * Throws **before** the browser leaves for the IdP when `sessionStorage` is unavailable: the callback
 * could never find the verifier, so starting the round trip would only produce a confusing failure
 * after the operator has already authenticated.
 */
export function saveTransaction(transaction: StoredTransaction): void {
  const storage = getSessionStorage();
  if (!storage) {
    throw new Error(STORAGE_UNAVAILABLE);
  }
  try {
    storage.setItem(TRANSACTION_KEY, JSON.stringify(transaction));
  } catch {
    // Quota exceeded, or the context became restricted between the two calls.
    throw new Error(STORAGE_UNAVAILABLE);
  }
}

/**
 * Reads **and removes** the stored transaction.
 *
 * One-shot: a replayed callback finds nothing, and an expired transaction is reported as such instead
 * of being silently retried.
 */
export function takeTransaction(now: number = Date.now()): StoredTransaction | null {
  const storage = getSessionStorage();
  if (!storage) {
    return null;
  }
  let raw: string | null = null;
  try {
    raw = storage.getItem(TRANSACTION_KEY);
    storage.removeItem(TRANSACTION_KEY);
  } catch {
    return null;
  }
  if (!raw) {
    return null;
  }
  let parsed: Partial<StoredTransaction>;
  try {
    parsed = JSON.parse(raw) as Partial<StoredTransaction>;
  } catch {
    return null;
  }
  if (
    typeof parsed.state !== "string" ||
    typeof parsed.verifier !== "string" ||
    typeof parsed.challenge !== "string" ||
    typeof parsed.nonce !== "string" ||
    typeof parsed.redirectUri !== "string" ||
    typeof parsed.authorizationEndpoint !== "string" ||
    typeof parsed.tokenEndpoint !== "string" ||
    typeof parsed.createdAt !== "number"
  ) {
    return null;
  }
  if (now - parsed.createdAt > TRANSACTION_TTL_MS) {
    return null;
  }
  // A tampered/absent `returnTo` is not an error: falling back to the dashboard is the safe answer,
  // and nothing else in the transaction is affected.
  if (!isSafeReturnPath(parsed.returnTo) || parsed.returnTo === SSO_CALLBACK_PATH) {
    parsed.returnTo = "/";
  }
  return parsed as StoredTransaction;
}

/** Drops any stored transaction (an aborted or failed sign-in). */
export function clearTransaction(): void {
  try {
    getSessionStorage()?.removeItem(TRANSACTION_KEY);
  } catch {
    // Nothing to clean up.
  }
}

/** Test helper: whether a transaction is currently stored (no token is ever stored). */
export function hasStoredTransaction(): boolean {
  try {
    // `?? null` matters: without it a *blocked* `sessionStorage` answers `undefined !== null` and
    // reports a transaction that cannot exist.
    return (getSessionStorage()?.getItem(TRANSACTION_KEY) ?? null) !== null;
  } catch {
    return false;
  }
}
