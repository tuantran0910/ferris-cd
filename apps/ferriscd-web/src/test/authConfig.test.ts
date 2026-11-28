import { describe, expect, it } from "vitest";
import type { AuthConfigView } from "../api/types";
import {
  FALLBACK_AUTH_CONFIG,
  hidesTokenFormBehindDisclosure,
  normalizeAuthMode,
  supportsSso,
  supportsTokenLogin,
  usesBffSession,
} from "../auth/authConfig";

function config(overrides: Partial<AuthConfigView>): AuthConfigView {
  return { authMode: "token-review", scopes: [], bffEnabled: false, ...overrides };
}

const oidc = config({
  authMode: "oidc",
  issuer: "https://idp.example.com",
  clientId: "ferriscd-web",
  scopes: ["openid"],
});

describe("auth config interpretation (T19.2)", () => {
  it("falls back to token sign-in when discovery failed", () => {
    expect(normalizeAuthMode(FALLBACK_AUTH_CONFIG.authMode)).toBe("token-review");
    expect(supportsSso(FALLBACK_AUTH_CONFIG)).toBe(false);
    expect(supportsTokenLogin(FALLBACK_AUTH_CONFIG)).toBe(true);
    expect(usesBffSession(FALLBACK_AUTH_CONFIG)).toBe(false);
  });

  it("maps every documented mode and treats anything else as unknown", () => {
    for (const mode of [
      "token-review",
      "oidc",
      "token-review-or-oidc",
      "pass-through",
      "deny-all",
    ] as const) {
      expect(normalizeAuthMode(mode)).toBe(mode);
    }
    expect(normalizeAuthMode("something-new")).toBe("unknown");
    expect(normalizeAuthMode(undefined)).toBe("unknown");
  });

  it("offers SSO only when the server publishes an issuer", () => {
    expect(supportsSso(oidc)).toBe(true);
    expect(supportsSso(config({ authMode: "oidc" }))).toBe(false);
    expect(supportsSso(config({ authMode: "token-review-or-oidc", issuer: "https://idp" }))).toBe(
      true,
    );
    expect(supportsSso(config({ authMode: "token-review", issuer: "https://idp" }))).toBe(false);
  });

  it("keeps the token form available exactly in the two token modes", () => {
    expect(supportsTokenLogin(config({ authMode: "token-review" }))).toBe(true);
    expect(supportsTokenLogin(config({ authMode: "pass-through" }))).toBe(true);
    expect(supportsTokenLogin(config({ authMode: "token-review-or-oidc" }))).toBe(true);
    expect(supportsTokenLogin(oidc)).toBe(false);
    expect(supportsTokenLogin(config({ authMode: "deny-all" }))).toBe(false);
  });

  it("only claims the BFF cookie mode when the server enables it", () => {
    expect(usesBffSession(oidc)).toBe(false);
    expect(usesBffSession({ ...oidc, bffEnabled: true })).toBe(true);
    // A `true` flag without OIDC cannot be a BFF session: there is nobody to authenticate against.
    expect(usesBffSession(config({ authMode: "token-review", bffEnabled: true }))).toBe(false);
  });

  it("hides the token form behind a disclosure only in the mixed mode", () => {
    expect(hidesTokenFormBehindDisclosure(oidc)).toBe(false);
    expect(hidesTokenFormBehindDisclosure(config({ authMode: "token-review" }))).toBe(false);
    expect(hidesTokenFormBehindDisclosure(config({ authMode: "token-review-or-oidc" }))).toBe(true);
  });
});
