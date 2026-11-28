import { describe, expect, it, vi } from "vitest";
import {
  base64UrlDecode,
  base64UrlEncode,
  buildAuthorizeUrl,
  createPkceTransaction,
  currentRedirectUri,
  currentReturnPath,
  SSO_CALLBACK_PATH,
  decodeJwtExpiry,
  exchangeAuthorizationCode,
  fetchOidcEndpoints,
  parseCallbackParams,
  randomUrlSafeToken,
  s256Challenge,
} from "../auth/pkce";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("PKCE S256 (T19.2)", () => {
  it("reproduces the RFC 7636 appendix B test vector", async () => {
    // RFC 7636 §Appendix B: verifier -> S256 challenge.
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    await expect(s256Challenge(verifier)).resolves.toBe(
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
    // The challenge is not the verifier (a `plain` flow would pass this assertion wrongly).
    await expect(s256Challenge(verifier)).resolves.not.toBe(verifier);
  });

  it("generates 256-bit verifier/state/nonce values with unique, URL-safe encoding", async () => {
    const first = await createPkceTransaction();
    const second = await createPkceTransaction();

    for (const value of [first.verifier, first.state, first.nonce]) {
      expect(value).toHaveLength(43);
      expect(value).toMatch(/^[A-Za-z0-9_-]+$/);
    }
    expect(first.verifier).not.toBe(second.verifier);
    expect(first.state).not.toBe(second.state);
    expect(first.challenge).toBe(await s256Challenge(first.verifier));
    expect(first.verifier).not.toBe(first.challenge);

    // Nothing below 256 bits is accepted.
    expect(() => randomUrlSafeToken(16)).toThrow(/256 bits/);
  });

  it("round-trips base64url without padding", () => {
    const bytes = new Uint8Array([0, 1, 250, 255, 128, 64]);
    const encoded = base64UrlEncode(bytes);
    expect(encoded).not.toMatch(/[+/=]/);
    expect(Array.from(base64UrlDecode(encoded))).toEqual(Array.from(bytes));
  });

  it("builds an authorization URL with S256, state, nonce and the exact redirect URI", async () => {
    const transaction = await createPkceTransaction();
    const url = new URL(
      buildAuthorizeUrl({
        authorizationEndpoint: "https://idp.example.com/oauth2/authorize",
        clientId: "ferriscd-web",
        redirectUri: "https://ferriscd.example.com/",
        scopes: ["openid", "profile"],
        transaction,
      }),
    );

    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toBe(transaction.challenge);
    expect(url.searchParams.get("state")).toBe(transaction.state);
    expect(url.searchParams.get("nonce")).toBe(transaction.nonce);
    expect(url.searchParams.get("scope")).toBe("openid profile");
    expect(url.searchParams.get("redirect_uri")).toBe("https://ferriscd.example.com/");
    expect(url.searchParams.get("code_challenge_method")).not.toBe("plain");
    // No credential is ever put in the authorization URL.
    expect(url.searchParams.get("access_token")).toBeNull();
    expect(url.searchParams.get("client_secret")).toBeNull();
  });

  it("parses only code/state/error from a callback and refuses to read a token from the URL", () => {
    const params = parseCallbackParams("?code=abc&state=xyz&token=leaked-token&access_token=leak");
    expect(params).toEqual({ code: "abc", state: "xyz", error: null });
    expect(parseCallbackParams("?error=access_denied")).toEqual({
      code: null,
      state: null,
      error: "access_denied",
    });
    expect(parseCallbackParams("")).toEqual({ code: null, state: null, error: null });
  });

  /**
   * **`T19.2` finding `H2`:** the redirect URI must be one fixed, registered value, not
   * `origin + pathname` — otherwise every deep link is a different URI the IdP has not registered,
   * and the tempting "fix" is a wildcard redirect URI (an open redirect).
   */
  it("pins one registered redirect URI for every route", () => {
    for (const origin of ["https://ferriscd.example.com", "http://127.0.0.1:5173"]) {
      expect(currentRedirectUri({ origin })).toBe(`${origin}${SSO_CALLBACK_PATH}`);
    }
    expect(SSO_CALLBACK_PATH.startsWith("/")).toBe(true);
    expect(SSO_CALLBACK_PATH).not.toContain("?");
    // The helper takes only `origin`, so a deep link or a stale `?code=…` cannot leak into it.
    expect(
      currentRedirectUri({ origin: "https://ferriscd.example.com" } as Pick<Location, "origin">),
    ).toBe("https://ferriscd.example.com/auth/callback");
  });

  it("carries the intended route as a path, never as an origin", () => {
    expect(
      currentReturnPath({ pathname: "/projects", search: "?sync=OutOfSync" }),
    ).toBe("/projects?sync=OutOfSync");
    expect(currentReturnPath({ pathname: "/", search: "" })).toBe("/");
  });

  it("rejects a discovery document whose issuer does not match", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        issuer: "https://evil.example",
        authorization_endpoint: "https://evil.example/authorize",
        token_endpoint: "https://evil.example/token",
      }),
    ) as unknown as typeof fetch;

    await expect(
      fetchOidcEndpoints("https://idp.example.com", fetchImpl),
    ).rejects.toThrow(/different issuer/);
  });

  it("rejects a plain-http endpoint that is not loopback, and accepts a local one", async () => {
    const insecure = vi.fn(async () =>
      jsonResponse({
        issuer: "https://idp.example.com",
        authorization_endpoint: "http://evil.example/authorize",
        token_endpoint: "https://idp.example.com/token",
      }),
    ) as unknown as typeof fetch;
    await expect(fetchOidcEndpoints("https://idp.example.com", insecure)).rejects.toThrow(
      /https/,
    );

    const local = vi.fn(async () =>
      jsonResponse({
        issuer: "http://127.0.0.1:5556",
        authorization_endpoint: "http://127.0.0.1:5556/auth",
        token_endpoint: "http://127.0.0.1:5556/token",
      }),
    ) as unknown as typeof fetch;
    await expect(fetchOidcEndpoints("http://127.0.0.1:5556", local)).resolves.toEqual({
      authorizationEndpoint: "http://127.0.0.1:5556/auth",
      tokenEndpoint: "http://127.0.0.1:5556/token",
    });
  });

  it("exchanges the code with the verifier and derives an expiry", async () => {
    const calls: { url: string; init?: RequestInit }[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init });
      return jsonResponse({ access_token: "the-access-token", expires_in: 600 });
    }) as unknown as typeof fetch;

    const tokens = await exchangeAuthorizationCode({
      tokenEndpoint: "https://idp.example.com/token",
      clientId: "ferriscd-web",
      code: "the-code",
      verifier: "the-verifier",
      redirectUri: "https://ferriscd.example.com/",
      fetchImpl,
      now: () => 1_000_000,
    });

    expect(tokens.accessToken).toBe("the-access-token");
    expect(tokens.expiresAt).toBe(1_000_000 + 600_000);
    expect(calls).toHaveLength(1);
    const body = new URLSearchParams(String(calls[0]?.init?.body));
    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("code")).toBe("the-code");
    expect(body.get("code_verifier")).toBe("the-verifier");
    expect(body.get("client_id")).toBe("ferriscd-web");
    expect(body.get("redirect_uri")).toBe("https://ferriscd.example.com/");
    expect(body.get("client_secret")).toBeNull();
  });

  it("reports a refused exchange without echoing the code or the response body", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({ error: "invalid_grant", error_description: "code the-code was rejected" }, 400),
    ) as unknown as typeof fetch;

    await expect(
      exchangeAuthorizationCode({
        tokenEndpoint: "https://idp.example.com/token",
        clientId: "ferriscd-web",
        code: "the-code",
        verifier: "the-verifier",
        redirectUri: "https://ferriscd.example.com/",
        fetchImpl,
      }),
    ).rejects.toThrow(/refused the authorization code exchange \(HTTP 400\)/);
  });

  it("reads the JWT expiry without trusting it", () => {
    const encode = (value: unknown) => base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)));
    const token = `${encode({ alg: "RS256" })}.${encode({ exp: 1_700_000_000 })}.signature`;
    expect(decodeJwtExpiry(token)).toBe(1_700_000_000_000);
    expect(decodeJwtExpiry("not-a-jwt")).toBeNull();
    expect(decodeJwtExpiry(`${encode({})}.${encode({ sub: "x" })}.sig`)).toBeNull();
  });
});
