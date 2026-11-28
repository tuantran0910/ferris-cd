import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SSO_CALLBACK_PATH } from "../auth/pkce";
import {
  clearTransaction,
  hasStoredTransaction,
  isSafeReturnPath,
  saveTransaction,
  takeTransaction,
  type StoredTransaction,
} from "../auth/ssoTransaction";

const TRANSACTION_KEY = "ferriscd.auth.pkce";

function transaction(overrides: Partial<StoredTransaction> = {}): StoredTransaction {
  return {
    verifier: "a-verifier-with-at-least-32-characters-of-entropy",
    challenge: "a-challenge",
    state: "the-state",
    nonce: "the-nonce",
    redirectUri: `${window.location.origin}${SSO_CALLBACK_PATH}`,
    authorizationEndpoint: "https://idp.example.com/oauth2/authorize",
    tokenEndpoint: "https://idp.example.com/token",
    returnTo: "/projects",
    createdAt: Date.now(),
    ...overrides,
  };
}

describe("the persisted SSO transaction (T19.2)", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("stores the sign-in material and no credential", () => {
    saveTransaction(transaction());
    expect(hasStoredTransaction()).toBe(true);
    const raw = window.sessionStorage.getItem(TRANSACTION_KEY) ?? "";
    // The verifier is a code-exchange credential, not an access token: nothing in the transaction can
    // be replayed as a bearer credential, and `localStorage` is never touched.
    expect(raw).toContain("the-state");
    expect(raw).not.toContain("access_token");
    expect(window.localStorage.length).toBe(0);

    const restored = takeTransaction();
    expect(restored?.returnTo).toBe("/projects");
    // One-shot: a replayed callback finds nothing.
    expect(takeTransaction()).toBeNull();
    expect(hasStoredTransaction()).toBe(false);
  });

  /**
   * **`T19.2` finding `H2` trap guard:** `sessionStorage` is writable by any script in the origin, so
   * the return path is re-validated on *read*: a tampered value can only ever fall back to the
   * dashboard, never navigate off-origin.
   */
  it("refuses an off-origin return path and falls back to the dashboard", () => {
    for (const hostile of [
      "//evil.example/steal",
      "https://evil.example/steal",
      "/\\evil.example",
      "/projects\u0000",
      "",
    ]) {
      expect(isSafeReturnPath(hostile)).toBe(false);
      window.sessionStorage.clear();
      saveTransaction(transaction());
      const raw = JSON.parse(window.sessionStorage.getItem(TRANSACTION_KEY) ?? "{}") as Record<
        string,
        unknown
      >;
      window.sessionStorage.setItem(
        TRANSACTION_KEY,
        JSON.stringify({ ...raw, returnTo: hostile }),
      );
      expect(takeTransaction()?.returnTo, JSON.stringify(hostile)).toBe("/");
    }
    // A missing `returnTo` is equally harmless.
    window.sessionStorage.setItem(
      TRANSACTION_KEY,
      JSON.stringify({ ...transaction(), returnTo: undefined }),
    );
    expect(takeTransaction()?.returnTo).toBe("/");
    expect(isSafeReturnPath("/projects?sync=OutOfSync")).toBe(true);
  });

  it("refuses to start a sign-in when sessionStorage is blocked", () => {
    // The callback could never find the verifier, so the flow must fail *before* the browser leaves —
    // not after the operator has authenticated against the IdP.
    vi.spyOn(window, "sessionStorage", "get").mockImplementation(() => {
      throw new Error("storage disabled by the browser");
    });
    expect(() => saveTransaction(transaction())).toThrow(/blocks sessionStorage/i);
    // Reading and clearing stay harmless.
    expect(takeTransaction()).toBeNull();
    expect(hasStoredTransaction()).toBe(false);
    expect(() => clearTransaction()).not.toThrow();
  });

  it("reports an expired transaction as absent instead of retrying it", () => {
    saveTransaction(transaction({ createdAt: Date.now() - 11 * 60 * 1000 }));
    expect(takeTransaction()).toBeNull();
    expect(hasStoredTransaction()).toBe(false);
  });
});
