/**
 * What `GET /api/v1/auth/config` means for the sign-in screen (`T19.2`).
 *
 * The endpoint is public (`T19.1`): it is how a caller learns which sign-in method this server wants
 * *before* it has a credential. These helpers keep the "which button do I render" decision in one
 * pure place instead of scattering string comparisons through the UI.
 */

import type { AuthConfigView } from "../api/types";

/** The sign-in methods this UI understands. */
export type AuthMode =
  | "token-review"
  | "oidc"
  | "token-review-or-oidc"
  | "pass-through"
  | "deny-all"
  | "unknown";

/**
 * What the UI assumes when the discovery call fails (an older server, an offline dev proxy).
 *
 * Token sign-in: it is the pre-existing behaviour, and it is the mode that does not need any extra
 * network round trip or IdP configuration. A failed discovery must never silently enable SSO.
 */
export const FALLBACK_AUTH_CONFIG: AuthConfigView = {
  authMode: "token-review",
  scopes: [],
  bffEnabled: false,
};

/** Maps the server's `authMode` string onto a known mode. */
export function normalizeAuthMode(value: string | undefined | null): AuthMode {
  switch (value) {
    case "token-review":
    case "oidc":
    case "token-review-or-oidc":
    case "pass-through":
    case "deny-all":
      return value;
    default:
      return "unknown";
  }
}

/** Whether the server can complete an SSO sign-in (both OIDC modes publish issuer + client id). */
export function supportsSso(config: AuthConfigView): boolean {
  const mode = normalizeAuthMode(config.authMode);
  const enabled = mode === "oidc" || mode === "token-review-or-oidc";
  return enabled && typeof config.issuer === "string" && config.issuer.length > 0;
}

/** Whether the server still accepts a pasted Kubernetes `ServiceAccount` bearer token. */
export function supportsTokenLogin(config: AuthConfigView): boolean {
  const mode = normalizeAuthMode(config.authMode);
  return mode === "token-review" || mode === "token-review-or-oidc";
}

/** Whether the server-side (BFF cookie) sign-in flow is available. */
export function usesBffSession(config: AuthConfigView): boolean {
  return config.bffEnabled === true && supportsSso(config);
}

/**
 * Whether the token form should be tucked behind a disclosure.
 *
 * Only in `token-review-or-oidc`, where SSO is the promoted path and the token is the fallback: in
 * `token-review` the form *is* the sign-in method, so hiding it would be a regression.
 */
export function hidesTokenFormBehindDisclosure(config: AuthConfigView): boolean {
  return normalizeAuthMode(config.authMode) === "token-review-or-oidc";
}
