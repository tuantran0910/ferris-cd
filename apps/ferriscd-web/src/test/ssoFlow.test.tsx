import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthConfigView } from "../api/types";
import { App } from "../app/App";
import { redirectTo } from "../auth/navigate";
import { SSO_CALLBACK_PATH, s256Challenge } from "../auth/pkce";
import { hasStoredTransaction, saveTransaction, takeTransaction } from "../auth/ssoTransaction";
import { resetTokenMemoryCache, setStoredBaseUrl } from "../auth/tokenStorage";
import { createMockApiClient } from "./fixtures";

vi.mock("../auth/navigate", () => ({ redirectTo: vi.fn() }));

const redirectMock = vi.mocked(redirectTo);

const SSO_TOKEN = "sso-access-token-very-secret";

const oidcConfig: AuthConfigView = {
  authMode: "oidc",
  issuer: "https://idp.example.com",
  clientId: "ferriscd-web",
  scopes: ["openid", "profile", "email"],
  bffEnabled: false,
};

const mixedConfig: AuthConfigView = {
  ...oidcConfig,
  authMode: "token-review-or-oidc",
};

const tokenReviewConfig: AuthConfigView = {
  authMode: "token-review",
  scopes: [],
  bffEnabled: false,
};

function clientWith(config: AuthConfigView) {
  return createMockApiClient({ getAuthConfig: async () => config });
}

/** A `fetch` stub that answers the discovery and token endpoints. */
function idpFetch(options: {
  token?: unknown;
  tokenStatus?: number;
  discovery?: unknown;
}) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    if (url.endsWith("/.well-known/openid-configuration")) {
      return new Response(
        JSON.stringify(
          options.discovery ?? {
            issuer: "https://idp.example.com",
            authorization_endpoint: "https://idp.example.com/oauth2/authorize",
            token_endpoint: "https://idp.example.com/token",
          },
        ),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }
    return new Response(
      JSON.stringify(
        options.token ?? { access_token: SSO_TOKEN, token_type: "Bearer", expires_in: 3600 },
      ),
      {
        status: options.tokenStatus ?? 200,
        headers: { "Content-Type": "application/json" },
      },
    );
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

/** Seeds the exact transaction the flow would have stored before the IdP redirect. */
async function seedTransaction(state: string, returnTo = "/"): Promise<string> {
  const verifier = "a-verifier-with-at-least-32-characters-of-entropy";
  const transaction = {
    verifier,
    challenge: await s256Challenge(verifier),
    state,
    nonce: "the-nonce-value",
    // `H2`: one fixed redirect URI for every route.
    redirectUri: `${window.location.origin}${SSO_CALLBACK_PATH}`,
    authorizationEndpoint: "https://idp.example.com/oauth2/authorize",
    tokenEndpoint: "https://idp.example.com/token",
    returnTo,
    createdAt: Date.now(),
  };
  saveTransaction(transaction);
  return verifier;
}

/** The callback URL the IdP delivers: the one registered path, always. */
function callbackUrl(state: string, code = "the-code"): string {
  return `${SSO_CALLBACK_PATH}?code=${code}&state=${state}`;
}

describe("Web UI SSO / PKCE flow (T19.2)", () => {
  beforeEach(() => {
    resetTokenMemoryCache();
    window.sessionStorage.clear();
    window.localStorage.clear();
    window.history.replaceState({}, "", "/");
    redirectMock.mockClear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders the token sign-in screen when the server advertises token-review", async () => {
    render(<App clientOverride={clientWith(tokenReviewConfig)} />);

    expect(await screen.findByLabelText(/Kubernetes Bearer Token/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Sign in with SSO/i })).not.toBeInTheDocument();
    // No SSO transaction is created for a token-mode server.
    expect(hasStoredTransaction()).toBe(false);
  });

  it("starts an S256 PKCE sign-in for an oidc server and stores no token", async () => {
    const user = userEvent.setup();
    const { fetchImpl } = idpFetch({});
    render(<App clientOverride={clientWith(oidcConfig)} fetchImpl={fetchImpl} />);

    const ssoButton = await screen.findByRole("button", { name: /Sign in with SSO/i });
    // An `oidc`-only server has no token form to fall back to.
    expect(screen.queryByLabelText(/Kubernetes Bearer Token/i)).not.toBeInTheDocument();

    await user.click(ssoButton);

    await waitFor(() => expect(redirectMock).toHaveBeenCalledTimes(1));
    const authorize = new URL(redirectMock.mock.calls[0]?.[0] ?? "");
    expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorize.searchParams.get("state")).toHaveLength(43);
    expect(authorize.searchParams.get("nonce")).toHaveLength(43);
    // `H2`: the redirect URI is the one fixed, registered path — never `origin + pathname`, which
    // would make every deep link a different (unregistered) URI.
    expect(authorize.searchParams.get("redirect_uri")).toBe(
      `${window.location.origin}${SSO_CALLBACK_PATH}`,
    );
    expect(authorize.searchParams.get("client_id")).toBe("ferriscd-web");
    expect(authorize.searchParams.get("scope")).toBe("openid profile email");
    expect(authorize.searchParams.get("access_token")).toBeNull();

    // The verifier is never in the URL; it is in the (single-use) transaction.
    const transaction = takeTransaction();
    expect(transaction).not.toBeNull();
    expect(authorize.searchParams.get("code_challenge")).toBe(await s256Challenge(transaction!.verifier));
    expect(transaction?.state).toBe(authorize.searchParams.get("state"));

    // No token was minted (or stored) by starting the flow.
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.getItem("ferriscd.auth.token")).toBeNull();
    expect(JSON.stringify(window.sessionStorage)).not.toContain(SSO_TOKEN);
  });

  it("offers SSO plus a collapsed ServiceAccount fallback in token-review-or-oidc", async () => {
    const user = userEvent.setup();
    render(<App clientOverride={clientWith(mixedConfig)} />);

    expect(await screen.findByRole("button", { name: /Sign in with SSO/i })).toBeInTheDocument();
    // The token form starts collapsed: SSO is the promoted path.
    expect(screen.queryByLabelText(/Kubernetes Bearer Token/i)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Use a ServiceAccount token instead/i }));
    expect(await screen.findByLabelText(/Kubernetes Bearer Token/i)).toBeInTheDocument();
  });

  it("completes the callback: token in memory only, code stripped from the URL", async () => {
    const verifier = await seedTransaction("issued-state");
    window.history.replaceState({}, "", callbackUrl("issued-state"));
    const { fetchImpl, calls } = idpFetch({});

    render(
      <App clientOverride={clientWith(oidcConfig)} fetchImpl={fetchImpl} />,
    );

    // Authenticated: the dashboard renders.
    expect(await screen.findByText("payments-api")).toBeInTheDocument();

    // The exchange carried the stored verifier (the binding to the challenge the IdP saw).
    const tokenCall = calls.find((call) => call.url.endsWith("/token"));
    expect(tokenCall).toBeDefined();
    const body = new URLSearchParams(String(tokenCall?.init?.body));
    expect(body.get("code")).toBe("the-code");
    expect(body.get("code_verifier")).toBe(verifier);
    expect(body.get("client_secret")).toBeNull();

    // Trap guard: the token never touches localStorage/sessionStorage, and never the URL.
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.getItem("ferriscd.auth.token")).toBeNull();
    const stored = Object.keys(window.sessionStorage).map((key) =>
      window.sessionStorage.getItem(key),
    );
    expect(stored.join("|")).not.toContain(SSO_TOKEN);
    expect(window.location.search).toBe("");
    expect(window.location.href).not.toContain("the-code");
    expect(window.location.href).not.toContain(SSO_TOKEN);
    // The single-use transaction is gone.
    expect(hasStoredTransaction()).toBe(false);
  });

  it("aborts on a state mismatch without ever exchanging the code", async () => {
    await seedTransaction("the-issued-state");
    window.history.replaceState({}, "", callbackUrl("forged-state", "attacker-code"));
    const { fetchImpl, calls } = idpFetch({});

    render(<App clientOverride={clientWith(oidcConfig)} fetchImpl={fetchImpl} />);

    expect(
      await screen.findByText(/did not match this browser's request/i),
    ).toBeInTheDocument();
    // No exchange happened, the code is never echoed, and nothing is stored.
    expect(calls.some((call) => call.url.endsWith("/token"))).toBe(false);
    expect(screen.queryByText("payments-api")).not.toBeInTheDocument();
    expect(screen.queryByText(/attacker-code/)).not.toBeInTheDocument();
    expect(window.location.search).toBe("");
    expect(hasStoredTransaction()).toBe(false);
  });

  it("expires the session, asks to re-authenticate, and keeps the current route", async () => {
    await seedTransaction("expiring-state", "/projects");
    window.history.replaceState({}, "", callbackUrl("expiring-state"));
    const { fetchImpl } = idpFetch({
      token: { access_token: SSO_TOKEN, token_type: "Bearer", expires_in: 60 },
    });

    vi.useFakeTimers({ shouldAdvanceTime: true });
    render(<App clientOverride={clientWith(oidcConfig)} fetchImpl={fetchImpl} />);

    // Authenticated on the projects route.
    expect(await screen.findByRole("heading", { name: /projects/i })).toBeInTheDocument();
    expect(window.location.pathname).toBe("/projects");

    // A minute later the token is gone and the sign-in screen returns *in place*.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(61_000);
    });

    expect(await screen.findByText(/Your SSO session expired/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Sign in with SSO/i })).toBeInTheDocument();
    expect(window.location.pathname).toBe("/projects");
    expect(window.location.search).toBe("");
    // The expired token was dropped from memory, not persisted anywhere.
    expect(JSON.stringify(window.sessionStorage)).not.toContain(SSO_TOKEN);
    expect(window.localStorage.length).toBe(0);
  });

  it("warns before expiry and offers a one-click re-authenticate that keeps the route", async () => {
    await seedTransaction("warning-state", "/projects");
    window.history.replaceState({}, "", callbackUrl("warning-state"));
    const { fetchImpl } = idpFetch({
      token: { access_token: SSO_TOKEN, token_type: "Bearer", expires_in: 120 },
    });

    vi.useFakeTimers({ shouldAdvanceTime: true });
    render(<App clientOverride={clientWith(oidcConfig)} fetchImpl={fetchImpl} />);

    expect(await screen.findByRole("heading", { name: /projects/i })).toBeInTheDocument();
    expect(screen.queryByText(/less than a minute/i)).not.toBeInTheDocument();

    // 60 s before expiry the banner appears while the session is still usable.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(61_000);
    });
    const banner = await screen.findByText(/less than a minute/i);
    expect(banner.closest("[role='status']")).not.toBeNull();
    expect(window.location.pathname).toBe("/projects");

    // One click restarts the PKCE flow instead of dumping the operator on a bare login screen.
    await act(async () => {
      screen.getByRole("button", { name: /Re-authenticate/i }).click();
      await vi.advanceTimersByTimeAsync(0);
    });
    await waitFor(() =>
      expect(redirectMock.mock.calls.map((call) => call[0]).join(" ")).toContain(
        "code_challenge_method=S256",
      ),
    );
  });

  it("sends the browser to the server's BFF login route when cookie mode is enabled", async () => {
    const user = userEvent.setup();
    // A cookie-mode deployment with no cookie yet: the app assumes a session (`C1`), the first API
    // call is a `401`, and the sign-in screen comes back — the documented expiry path.
    setStoredBaseUrl(window.location.origin);
    const { fetchImpl } = bffFetch(
      () =>
        new Response(
          JSON.stringify({ error: { code: "Unauthorized", message: "sign in again" } }),
          { status: 401, headers: { "Content-Type": "application/json" } },
        ),
    );
    render(<App fetchImpl={fetchImpl} />);

    await user.click(await screen.findByRole("button", { name: /Sign in with SSO/i }));

    await waitFor(() => expect(redirectMock).toHaveBeenCalledTimes(1));
    // Resolved against the page origin so the navigation is always an absolute URL.
    expect(redirectMock.mock.calls[0]?.[0]).toBe(
      new URL("/api/v1/auth/login", window.location.origin).toString(),
    );
    // The SPA never starts its own PKCE flow in cookie mode (the server owns the verifier).
    expect(hasStoredTransaction()).toBe(false);
  });

  it("restores the page the operator started from after the fixed callback path", async () => {
    // `H2`: the IdP can only redirect to the ONE registered URI, so the intended route has to travel
    // in the single-use transaction and be restored once the exchange completes.
    await seedTransaction("returning-state", "/projects?sync=OutOfSync");
    window.history.replaceState({}, "", callbackUrl("returning-state"));
    const { fetchImpl } = idpFetch({});

    render(<App clientOverride={clientWith(oidcConfig)} fetchImpl={fetchImpl} />);

    expect(await screen.findByRole("heading", { name: /projects/i })).toBeInTheDocument();
    expect(window.location.pathname).toBe("/projects");
    expect(window.location.search).toBe("?sync=OutOfSync");
    // The callback path itself is gone from the address bar, and the transaction is consumed.
    expect(window.location.pathname).not.toBe(SSO_CALLBACK_PATH);
    expect(hasStoredTransaction()).toBe(false);
  });

  // -------------------------------------------------------------------------
  // The optional server-side (BFF) cookie mode — finding `C1`
  // -------------------------------------------------------------------------

  /** The discovery document of a BFF-enabled server, plus `fetch` responses for the dashboard. */
  function bffFetch(applications: () => Response) {
    // The API client (`openapi-fetch`) calls `fetch(request)`, not `fetch(url, init)`: the URL and the
    // headers both live on the `Request`.
    const calls: { url: string; request?: Request }[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      calls.push({ url, request: input instanceof Request ? input : undefined });
      if (url.endsWith("/api/v1/auth/config")) {
        return new Response(JSON.stringify({ ...mixedConfig, bffEnabled: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (url.endsWith("/api/v1/auth/logout")) {
        return new Response(null, { status: 204 });
      }
      if (url.includes("/api/v1/applications")) {
        return applications();
      }
      return new Response(null, { status: 404 });
    }) as unknown as typeof fetch;
    return { fetchImpl, calls };
  }

  /**
   * **`T19.2` finding `C1`:** with `--oidc-bff-enabled` the browser holds *no* token — the credential
   * is an `HttpOnly` cookie set by `/api/v1/auth/callback`. Counting only an in-memory token left the
   * SPA on the sign-in screen forever after a successful sign-in.
   */
  it("renders the dashboard for a BFF cookie session that holds no in-memory token", async () => {
    // Same-origin is the only sane base URL for a cookie session; jsdom's `Request` cannot express a
    // relative URL, so the test seeds the absolute form of the same thing.
    setStoredBaseUrl(window.location.origin);
    const { fetchImpl, calls } = bffFetch(
      () =>
        new Response(JSON.stringify({ items: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );

    render(<App fetchImpl={fetchImpl} />);

    // The authenticated tree, with nothing in memory to authenticate with.
    expect(
      await screen.findByText(/No Applications visible to your identity/i),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText(/Kubernetes Bearer Token/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Kubernetes-Native GitOps Control Plane/i)).not.toBeInTheDocument();

    // The cookie travels with the request because it is the browser's; the SPA adds no bearer token.
    const list = calls.find((call) => call.url.endsWith("/api/v1/applications"));
    expect(list).toBeDefined();
    expect(list?.request?.headers.get("authorization")).toBeNull();
    // And nothing was persisted on the way.
    expect(window.localStorage.length).toBe(0);
  });

  /** The other half of `C1`: expiry is still detected, by the existing `401 → logout` path. */
  it("returns to the sign-in screen when the BFF session is rejected with 401", async () => {
    setStoredBaseUrl(window.location.origin);
    const { fetchImpl, calls } = bffFetch(
      () =>
        new Response(
          JSON.stringify({
            error: { code: "Unauthorized", message: "your session expired or is not usable; sign in again" },
          }),
          { status: 401, headers: { "Content-Type": "application/json" } },
        ),
    );

    render(<App fetchImpl={fetchImpl} />);

    // Back on the sign-in screen, told why, with the SSO button available again.
    expect(
      await screen.findByText(/Your session was rejected/i),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Sign in with SSO/i })).toBeInTheDocument();
    // The dead session was also cleared server-side (the cookie is `HttpOnly`: only the server can).
    await waitFor(() =>
      expect(calls.some((call) => call.url.endsWith("/api/v1/auth/logout"))).toBe(true),
    );
  });

  it("shows a generic error and never echoes the code when the exchange is refused", async () => {
    await seedTransaction("refused-state");
    window.history.replaceState({}, "", callbackUrl("refused-state", "secret-code"));
    const { fetchImpl } = idpFetch({
      tokenStatus: 400,
      token: { error: "invalid_grant", error_description: "code secret-code is invalid" },
    });

    render(<App clientOverride={clientWith(oidcConfig)} fetchImpl={fetchImpl} />);

    expect(
      await screen.findByText(/refused the authorization code exchange \(HTTP 400\)/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/secret-code/)).not.toBeInTheDocument();
    expect(screen.queryByText("payments-api")).not.toBeInTheDocument();
    expect(window.location.search).toBe("");
  });
});
