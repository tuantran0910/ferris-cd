/**
 * PKCE (`S256`) and OIDC Authorization Code helpers for the FerrisCD Web UI (`T19.2`).
 *
 * The rules this module encodes, once, so no component can get them wrong:
 *
 * - **Only `S256`.** `code_challenge_method` is a constant; there is no `plain` code path.
 * - **CSPRNG only.** The verifier, `state` and `nonce` are 32 bytes from `crypto.getRandomValues`
 *   (256 bits), base64url-encoded without padding.
 * - **No secrets in a URL.** The authorization URL carries `state`, `nonce` and the S256 challenge —
 *   all of them public by design. An access token never appears in a query string or fragment, and
 *   {@link parseCallbackParams} ignores anything but `code`/`state`/`error`.
 * - **No token in a thrown error.** A failed exchange reports the status, never the body: an IdP
 *   error document can echo the code or the verifier.
 */

/** The one PKCE method this client implements (RFC 7636 §4.2). */
export const PKCE_METHOD = "S256";

/** Bytes behind the verifier/state/nonce: 32 bytes = 256 bits of entropy. */
export const RANDOM_BYTE_LENGTH = 32;

/** The `crypto` surface this module needs (injectable so tests are not tied to jsdom). */
interface CryptoLike {
  getRandomValues<T extends Uint8Array>(array: T): T;
  subtle: { digest(algorithm: "SHA-256", data: Uint8Array): Promise<ArrayBuffer> };
}

function getCrypto(): CryptoLike {
  const candidate = (globalThis as unknown as { crypto?: CryptoLike }).crypto;
  if (!candidate || typeof candidate.getRandomValues !== "function") {
    throw new Error("This browser has no Web Crypto API, so a secure SSO sign-in is not possible.");
  }
  return candidate;
}

/**
 * Encodes bytes as unpadded base64url (RFC 4648 §5).
 *
 * `btoa` is deliberate rather than a hand-rolled loop: it is present in every browser jsdom models,
 * and the alphabet translation is the only difference from base64.
 */
export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decodes unpadded base64url (used by the JWT expiry reader). */
export function base64UrlDecode(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded =
    normalized.length % 4 === 0 ? normalized : normalized + "=".repeat(4 - (normalized.length % 4));
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

/** 32 CSPRNG bytes as an unpadded base64url string (43 characters). */
export function randomUrlSafeToken(byteLength: number = RANDOM_BYTE_LENGTH): string {
  if (!Number.isInteger(byteLength) || byteLength < RANDOM_BYTE_LENGTH) {
    throw new Error("PKCE material must be at least 256 bits of CSPRNG output.");
  }
  const bytes = new Uint8Array(byteLength);
  getCrypto().getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/** A fresh `code_verifier` (32 bytes, the RFC 7636 minimum is 32 characters of entropy). */
export function createCodeVerifier(): string {
  return randomUrlSafeToken();
}

/** `BASE64URL(SHA256(ASCII(verifier)))` — the RFC 7636 `S256` challenge. */
export async function s256Challenge(verifier: string): Promise<string> {
  if (!verifier) {
    throw new Error("A PKCE verifier is required to compute its S256 challenge.");
  }
  const digest = await getCrypto().subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

/** One in-flight sign-in: what the callback has to match and what the exchange needs. */
export interface PkceTransaction {
  verifier: string;
  challenge: string;
  state: string;
  nonce: string;
}

/** Creates a complete transaction (verifier + challenge + `state` + `nonce`). */
export async function createPkceTransaction(): Promise<PkceTransaction> {
  const verifier = createCodeVerifier();
  return {
    verifier,
    challenge: await s256Challenge(verifier),
    state: randomUrlSafeToken(),
    nonce: randomUrlSafeToken(),
  };
}

/** The discovery facts the SPA needs from the IdP. */
export interface OidcEndpoints {
  authorizationEndpoint: string;
  tokenEndpoint: string;
}

/**
 * Fetches `<issuer>/.well-known/openid-configuration` and returns the two endpoints.
 *
 * The document's own `issuer` must equal the configured one (OpenID Connect Discovery 1.0 §4.3):
 * without that check, a hostile discovery document could point the browser's `code` at another IdP.
 */
export async function fetchOidcEndpoints(
  issuer: string,
  fetchImpl: typeof fetch = fetch,
): Promise<OidcEndpoints> {
  const url = `${issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`;
  const response = await fetchImpl(url, {
    headers: { Accept: "application/json" },
    credentials: "omit",
  });
  if (!response.ok) {
    throw new Error(
      `The identity provider's discovery document is unavailable (HTTP ${response.status}).`,
    );
  }
  const document = (await response.json()) as {
    issuer?: unknown;
    authorization_endpoint?: unknown;
    token_endpoint?: unknown;
  };
  if (
    typeof document.issuer !== "string" ||
    document.issuer.replace(/\/+$/, "") !== issuer.replace(/\/+$/, "")
  ) {
    throw new Error("The identity provider's discovery document names a different issuer.");
  }
  const authorizationEndpoint = absoluteEndpoint(document.authorization_endpoint);
  const tokenEndpoint = absoluteEndpoint(document.token_endpoint);
  return { authorizationEndpoint, tokenEndpoint };
}

function absoluteEndpoint(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("The identity provider's discovery document is missing an endpoint.");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("The identity provider's discovery document carries a relative endpoint.");
  }
  const loopback =
    parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost" || parsed.hostname === "[::1]";
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
    throw new Error("The identity provider's endpoints must be https URLs.");
  }
  return value;
}

/** Everything the authorization request needs. */
export interface AuthorizeUrlParams {
  authorizationEndpoint: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
  transaction: Pick<PkceTransaction, "state" | "nonce" | "challenge">;
}

/**
 * Builds the authorization URL.
 *
 * `redirect_uri` is the caller's {@link currentRedirectUri} — this page's **origin** plus the fixed
 * {@link SSO_CALLBACK_PATH}, never `pathname` — so the code always comes back to the one URI the
 * deployment registered and the URL never carries a query or a fragment.
 */
export function buildAuthorizeUrl(params: AuthorizeUrlParams): string {
  const url = new URL(params.authorizationEndpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", params.clientId);
  url.searchParams.set("redirect_uri", params.redirectUri);
  url.searchParams.set("scope", params.scopes.join(" "));
  url.searchParams.set("state", params.transaction.state);
  url.searchParams.set("nonce", params.transaction.nonce);
  url.searchParams.set("code_challenge", params.transaction.challenge);
  url.searchParams.set("code_challenge_method", PKCE_METHOD);
  return url.toString();
}

/** What a callback URL carries. Anything else (including a `token`) is ignored. */
export interface CallbackParams {
  code: string | null;
  state: string | null;
  error: string | null;
}

/** Parses a callback query string, ignoring every parameter but these three. */
export function parseCallbackParams(search: string): CallbackParams {
  const params = new URLSearchParams(search.startsWith("?") ? search.slice(1) : search);
  const read = (name: string): string | null => {
    const value = params.get(name);
    return value && value.trim().length > 0 ? value.trim() : null;
  };
  return { code: read("code"), state: read("state"), error: read("error") };
}

/** A token set plus the absolute expiry the UI schedules its re-auth banner from. */
export interface OidcTokens {
  accessToken: string;
  /** Epoch milliseconds, or `null` when neither `expires_in` nor a JWT `exp` was available. */
  expiresAt: number | null;
}

/** The exchange request. */
export interface ExchangeRequest {
  tokenEndpoint: string;
  clientId: string;
  code: string;
  verifier: string;
  redirectUri: string;
  fetchImpl?: typeof fetch;
  /** Injectable clock (tests assert expiry without waiting). */
  now?: () => number;
}

/**
 * Exchanges an authorization code for an access token (public client: no secret).
 *
 * The request body is `application/x-www-form-urlencoded` and carries the verifier, which is what
 * binds this exchange to the challenge the IdP saw. The response body is never quoted in an error.
 */
export async function exchangeAuthorizationCode(request: ExchangeRequest): Promise<OidcTokens> {
  const fetchImpl = request.fetchImpl ?? fetch;
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: request.code,
    code_verifier: request.verifier,
    redirect_uri: request.redirectUri,
    client_id: request.clientId,
  });
  const response = await fetchImpl(request.tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: body.toString(),
    credentials: "omit",
  });
  if (!response.ok) {
    throw new Error(
      `The identity provider refused the authorization code exchange (HTTP ${response.status}).`,
    );
  }
  const document = (await response.json()) as { access_token?: unknown; expires_in?: unknown };
  const accessToken = typeof document.access_token === "string" ? document.access_token.trim() : "";
  if (!accessToken) {
    throw new Error("The identity provider returned no access token.");
  }
  const now = (request.now ?? Date.now)();
  const expiresIn =
    typeof document.expires_in === "number" && Number.isFinite(document.expires_in)
      ? document.expires_in
      : null;
  const fromJwt = decodeJwtExpiry(accessToken);
  const expiresAt = expiresIn !== null ? now + expiresIn * 1000 : fromJwt;
  return { accessToken, expiresAt };
}

/**
 * Reads the `exp` claim of a JWT without verifying it.
 *
 * Deliberately unverified: this value only decides *when to show a re-authenticate prompt*, and the
 * server verifies the signature/claims on every request anyway. Treating it as an authorization
 * decision would be the bug.
 */
export function decodeJwtExpiry(token: string): number | null {
  const segments = token.split(".");
  const payloadSegment = segments[1];
  if (segments.length !== 3 || payloadSegment === undefined) {
    return null;
  }
  try {
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadSegment))) as {
      exp?: unknown;
    };
    return typeof payload.exp === "number" && Number.isFinite(payload.exp)
      ? payload.exp * 1000
      : null;
  } catch {
    return null;
  }
}

/**
 * The **one** path the IdP redirects back to (`T19.2`, finding `H2`).
 *
 * An OAuth client registers *exact* redirect URIs, so the URI this SPA sends must not depend on the
 * route the operator happens to be on: `origin + pathname` would make every deep link
 * (`/projects`, `/applications/payments/api`, …) a different, unregistered URI that the IdP refuses —
 * and the "fix" an operator would reach for is a wildcard redirect URI, which is precisely the open
 * redirect the allowlist exists to prevent. This path is constant, so a deployment registers exactly
 * one URI: `https://<host>/auth/callback`.
 *
 * The route the operator actually wanted is not lost: it travels in the single-use PKCE transaction
 * (`ssoTransaction.ts`) and is restored after the exchange.
 */
export const SSO_CALLBACK_PATH = "/auth/callback";

/**
 * The redirect URI for this deployment: origin + the fixed {@link SSO_CALLBACK_PATH}.
 *
 * Only `origin` is read, deliberately: a query string or fragment in the address bar (a stale
 * `?code=…`, a deep-link filter) must never become part of the registered URI.
 */
export function currentRedirectUri(location: Pick<Location, "origin">): string {
  return `${location.origin}${SSO_CALLBACK_PATH}`;
}

/**
 * The same-origin path the operator was on, restored after the exchange.
 *
 * `pathname + search` only — never the origin, never the fragment — so the stored value cannot become
 * a navigation to another site even if `sessionStorage` were tampered with (the reader validates it
 * again: see `isSafeReturnPath` in `ssoTransaction.ts`).
 */
export function currentReturnPath(
  location: Pick<Location, "pathname" | "search">,
): string {
  return `${location.pathname}${location.search}`;
}
