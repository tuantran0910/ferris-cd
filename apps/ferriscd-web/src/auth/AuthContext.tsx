import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { AuthConfigView } from "../api/types";
import { createFerrisApiClient, type FerrisApiClient } from "../api/client";
import {
  FALLBACK_AUTH_CONFIG,
  hidesTokenFormBehindDisclosure,
  normalizeAuthMode,
  supportsSso,
  supportsTokenLogin,
  usesBffSession,
  type AuthMode,
} from "./authConfig";
import { redirectTo } from "./navigate";
import {
  buildAuthorizeUrl,
  createPkceTransaction,
  currentRedirectUri,
  currentReturnPath,
  exchangeAuthorizationCode,
  fetchOidcEndpoints,
  parseCallbackParams,
} from "./pkce";
import {
  clearStoredToken,
  getStoredBaseUrl,
  getStoredToken,
  normalizeBaseUrl,
  setStoredBaseUrl,
  setStoredToken,
} from "./tokenStorage";
import { clearTransaction, saveTransaction, takeTransaction } from "./ssoTransaction";

/** How long before expiry the UI starts asking the operator to re-authenticate. */
export const SESSION_EXPIRY_WARNING_MS = 60_000;

/** Where an SSO session is in its lifecycle. */
export type SessionStatus = "none" | "active" | "expiring" | "expired";

/** An SSO session, held **only** in this component's memory. */
export interface SsoSession {
  accessToken: string;
  /** Epoch milliseconds, or `null` when the IdP disclosed no lifetime. */
  expiresAt: number | null;
}

export interface AuthContextValue {
  token: string | null;
  baseUrl: string;
  isAuthenticated: boolean;
  authNotice: string | null;
  apiClient: FerrisApiClient;
  authMode: AuthMode;
  authConfig: AuthConfigView;
  /** The server offers OIDC sign-in. */
  ssoAvailable: boolean;
  /** The server still accepts a Kubernetes `ServiceAccount` token. */
  tokenLoginAvailable: boolean;
  /** The token form belongs behind a disclosure because SSO is the promoted path. */
  tokenFormCollapsed: boolean;
  /** The optional server-side (BFF cookie) flow is enabled. */
  bffEnabled: boolean;
  sessionStatus: SessionStatus;
  sessionExpiresAt: number | null;
  /**
   * The same-origin path to restore after a completed SSO sign-in (`/projects?sync=…`).
   *
   * The IdP always redirects to the one registered callback path, so the router uses this to put the
   * operator back where they started. `null` until a sign-in completes in this page life.
   */
  postLoginPath: string | null;
  ssoBusy: boolean;
  ssoError: string | null;
  beginSsoLogin: (returnTo?: string) => Promise<void>;
  completeSsoLogin: () => Promise<boolean>;
  login: (token: string, baseUrl?: string) => void;
  logout: (notice?: string) => Promise<void>;
  clearNotice: () => void;
  dismissSsoError: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/** Whether two discovery documents say the same thing (so a repeat fetch is a no-op). */
function sameAuthConfig(a: AuthConfigView, b: AuthConfigView): boolean {
  return (
    a.authMode === b.authMode &&
    a.issuer === b.issuer &&
    a.clientId === b.clientId &&
    a.bffEnabled === b.bffEnabled &&
    (a.scopes ?? []).join(" ") === (b.scopes ?? []).join(" ")
  );
}

export interface AuthProviderProps {
  children: ReactNode;
  clientOverride?: FerrisApiClient;
  /** Injectable clock (tests schedule expiry without waiting). */
  now?: () => number;
  /** Injectable `fetch` for the IdP discovery/token calls (tests never touch the network). */
  fetchImpl?: typeof fetch;
}

export function AuthProvider({
  children,
  clientOverride,
  now = Date.now,
  fetchImpl,
}: AuthProviderProps) {
  const queryClient = useQueryClient();
  const [token, setToken] = useState<string | null>(() => getStoredToken());
  const [baseUrl, setBaseUrl] = useState<string>(() => getStoredBaseUrl());
  const [authNotice, setAuthNotice] = useState<string | null>(null);
  const [authConfig, setAuthConfig] = useState<AuthConfigView>(FALLBACK_AUTH_CONFIG);
  // `T19.2`: the SSO access token lives here and nowhere else — no `localStorage`, no
  // `sessionStorage`, no URL. A hard refresh therefore signs the operator out, which is the
  // documented trade-off of the in-memory mode (the BFF mode exists for deployments that need more).
  const [ssoSession, setSsoSession] = useState<SsoSession | null>(null);
  const [ssoBusy, setSsoBusy] = useState(false);
  const [ssoError, setSsoError] = useState<string | null>(null);
  // `T19.2` (finding `C1`): with the optional server-side (BFF) flow enabled the browser holds no
  // token at all — the credential lives in an `HttpOnly` cookie this JavaScript cannot read. So a
  // BFF-enabled server is an authenticated *state* until something says otherwise; the something is
  // the existing `401 → logout` path, which sets `bffSignedOut` so the sign-in screen comes back
  // instead of the app re-rendering a dashboard it cannot load.
  const [bffSignedOut, setBffSignedOut] = useState(false);
  const [postLoginPath, setPostLoginPath] = useState<string | null>(null);
  const ssoSessionRef = useRef<SsoSession | null>(null);
  ssoSessionRef.current = ssoSession;

  const ssoCrossedRef = useRef(false);
  // The client is memoized *after* `logout` (which it depends on), so `logout` reaches it through a
  // ref instead of a circular hook dependency.
  const apiClientRef = useRef<FerrisApiClient | null>(null);

  const clearSsoSession = useCallback(() => {
    ssoSessionRef.current = null;
    setSsoSession(null);
  }, []);

  const logout = useCallback(
    async (notice?: string) => {
      clearSsoSession();
      clearStoredToken();
      clearTransaction();
      setToken(null);
      // A rejected or ended BFF session: stop treating the cookie as a credential, so the sign-in
      // screen appears instead of a dashboard whose every request would be a `401`.
      setBffSignedOut(true);
      setAuthNotice(notice ?? null);
      queryClient.clear();
      // The BFF cookie is not ours to delete from JavaScript (`HttpOnly`): ask the server to expire
      // it. Best effort — logging out must work even when the API is unreachable, and a server
      // without the BFF flow answers 404 (swallowed by the client).
      const client = clientOverride ?? apiClientRef.current;
      if (client?.logoutSession) {
        try {
          await client.logoutSession();
        } catch {
          // Ignored deliberately: the local session is already gone.
        }
      }
    },
    [clearSsoSession, clientOverride, queryClient],
  );

  // Boot: what sign-in methods does this server offer? `FALLBACK_AUTH_CONFIG` (token) is used when
  // the call fails, so an older server or an offline proxy never enables a flow it cannot complete.
  useEffect(() => {
    let cancelled = false;
    const client =
      clientOverride ??
      createFerrisApiClient({
        baseUrl,
        getToken: () => ssoSessionRef.current?.accessToken ?? getStoredToken(),
        fetchImpl,
      });
    if (!client.getAuthConfig) {
      return () => {
        cancelled = true;
      };
    }
    client
      .getAuthConfig()
      .then((config) => {
        if (!cancelled) {
          // Bail out when nothing changed so a mount cannot schedule a pointless re-render.
          setAuthConfig((previous) => (sameAuthConfig(previous, config) ? previous : config));
        }
      })
      .catch(() => {
        if (!cancelled) {
          setAuthConfig((previous) =>
            sameAuthConfig(previous, FALLBACK_AUTH_CONFIG) ? previous : FALLBACK_AUTH_CONFIG,
          );
        }
      });
    return () => {
      cancelled = true;
    };
    // Deliberately runs once per mount/mode change: the discovery document is static for a server.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clientOverride, baseUrl]);

  const login = useCallback(
    (newToken: string, nextBaseUrl?: string) => {
      const cleanedToken = newToken.trim();
      if (!cleanedToken) {
        return;
      }
      clearSsoSession();
      setStoredToken(cleanedToken);
      setToken(cleanedToken);
      if (nextBaseUrl !== undefined) {
        const normalized = normalizeBaseUrl(nextBaseUrl);
        setStoredBaseUrl(normalized);
        setBaseUrl(normalized);
      }
      setAuthNotice(null);
      queryClient.clear();
    },
    [clearSsoSession, queryClient],
  );

  const beginSsoLogin = useCallback(async (returnTo?: string) => {
    setSsoError(null);
    setSsoBusy(true);
    try {
      if (usesBffSession(authConfig)) {
        // Server-side flow: the server owns the cookie and the PKCE verifier, the SPA only navigates.
        // Its own post-login landing path is configured on the server
        // (`--oidc-bff-post-login-path`), so there is no route to carry across.
        const loginPath = `${baseUrl}/api/v1/auth/login`;
        const target = new URL(loginPath, window.location.origin).toString();
        // Cleared before navigating: a redirect that the browser ignores (a blocked popup-style
        // assign, an already-unloaded page) must not leave the button spinning forever.
        setSsoBusy(false);
        redirectTo(target);
        return;
      }
      if (!authConfig.issuer || !authConfig.clientId) {
        throw new Error("This server does not advertise the OIDC client id.");
      }
      const endpoints = await fetchOidcEndpoints(authConfig.issuer, fetchImpl);
      const transaction = await createPkceTransaction();
      // `H2`: one registered redirect URI for every route, and the intended route travels in the
      // transaction instead.
      const redirectUri = currentRedirectUri(window.location);
      saveTransaction({
        ...transaction,
        redirectUri,
        authorizationEndpoint: endpoints.authorizationEndpoint,
        tokenEndpoint: endpoints.tokenEndpoint,
        returnTo: returnTo ?? currentReturnPath(window.location),
        createdAt: now(),
      });
      redirectTo(
        buildAuthorizeUrl({
          authorizationEndpoint: endpoints.authorizationEndpoint,
          clientId: authConfig.clientId,
          redirectUri,
          scopes: authConfig.scopes ?? [],
          transaction,
        }),
      );
    } catch (error) {
      clearTransaction();
      setSsoBusy(false);
      setSsoError(
        error instanceof Error && error.message
          ? error.message
          : "Single sign-on could not be started. Please try again.",
      );
    }
  }, [authConfig, baseUrl, fetchImpl, now]);

  const completeSsoLogin = useCallback(async (): Promise<boolean> => {
    const params = parseCallbackParams(window.location.search);
    if (!params.code && !params.error) {
      return false;
    }
    // The code must not survive in the address bar, whether or not the exchange succeeds.
    const clean = () => {
      window.history.replaceState({}, "", window.location.pathname);
    };
    if (params.error) {
      clearTransaction();
      clean();
      setSsoError("The identity provider refused the sign-in. Please try again.");
      return false;
    }
    setSsoBusy(true);
    try {
      const transaction = takeTransaction(now());
      if (!transaction) {
        throw new Error("The sign-in took too long or was started in another tab. Please retry.");
      }
      if (!params.state || params.state !== transaction.state) {
        // Strict state validation: a mismatch is an abort, not a warning, and the code is discarded
        // without ever reaching the token endpoint.
        throw new Error("The sign-in response did not match this browser's request. Please retry.");
      }
      if (!params.code) {
        throw new Error("The sign-in response carried no authorization code.");
      }
      const tokens = await exchangeAuthorizationCode({
        tokenEndpoint: transaction.tokenEndpoint,
        clientId: authConfig.clientId ?? "",
        code: params.code,
        verifier: transaction.verifier,
        redirectUri: transaction.redirectUri,
        fetchImpl,
        now,
      });
      ssoSessionRef.current = {
        accessToken: tokens.accessToken,
        expiresAt: tokens.expiresAt,
      };
      setSsoSession(ssoSessionRef.current);
      // The operator answered the IdP at the fixed callback path; the router puts them back on the
      // page they started from (`H2`).
      setPostLoginPath(transaction.returnTo);
      setBffSignedOut(false);
      setAuthNotice(null);
      setSsoError(null);
      queryClient.clear();
      return true;
    } catch (error) {
      setSsoError(
        error instanceof Error && error.message
          ? error.message
          : "Single sign-on failed. Please try again.",
      );
      return false;
    } finally {
      setSsoBusy(false);
      clean();
    }
  }, [authConfig.clientId, fetchImpl, now, queryClient]);

  // Complete a callback exactly once, after the configuration (which names the client id) is known.
  useEffect(() => {
    // Wait for the discovery document: the exchange needs the client id it carries.
    if (ssoCrossedRef.current || !supportsSso(authConfig)) {
      return;
    }
    if (!parseCallbackParams(window.location.search).code) {
      return;
    }
    ssoCrossedRef.current = true;
    void completeSsoLogin();
  }, [authConfig, completeSsoLogin]);

  // Expiry: at `expiresAt - WARNING` the banner appears, at `expiresAt` the session is dropped and the
  // sign-in screen returns *in place* — the router keeps its current route, so re-authenticating lands
  // the operator back where they were.
  useEffect(() => {
    if (!ssoSession?.expiresAt) {
      return;
    }
    const nowMs = now();
    const untilExpiry = ssoSession.expiresAt - nowMs;
    if (untilExpiry <= 0) {
      clearSsoSession();
      setAuthNotice("Your SSO session expired. Sign in again to continue where you left off.");
      return;
    }
    const expiryTimer = window.setTimeout(() => {
      clearSsoSession();
      setAuthNotice("Your SSO session expired. Sign in again to continue where you left off.");
    }, untilExpiry);
    const warningTimer =
      untilExpiry > SESSION_EXPIRY_WARNING_MS
        ? window.setTimeout(() => {
            setAuthNotice(
              "Your SSO session expires in less than a minute. Re-authenticate to avoid losing your place.",
            );
          }, untilExpiry - SESSION_EXPIRY_WARNING_MS)
        : undefined;
    return () => {
      window.clearTimeout(expiryTimer);
      if (warningTimer !== undefined) {
        window.clearTimeout(warningTimer);
      }
    };
  }, [clearSsoSession, now, ssoSession]);

  // Computed on every render rather than memoized: the *clock* is the input that changes, and a memo
  // keyed on the session object alone would keep answering "active" after the warning fired.
  const sessionStatus: SessionStatus = (() => {
    if (!ssoSession) {
      return "none";
    }
    if (!ssoSession.expiresAt) {
      return "active";
    }
    const remaining = ssoSession.expiresAt - now();
    if (remaining <= 0) {
      return "expired";
    }
    return remaining <= SESSION_EXPIRY_WARNING_MS ? "expiring" : "active";
  })();

  const clearNotice = useCallback(() => {
    setAuthNotice(null);
  }, []);

  const dismissSsoError = useCallback(() => {
    setSsoError(null);
  }, []);

  const apiClient = useMemo(() => {
    if (clientOverride) {
      return clientOverride;
    }
    return createFerrisApiClient({
      baseUrl,
      getToken: () => ssoSessionRef.current?.accessToken ?? getStoredToken(),
      onUnauthorized: () => {
        void logout("Your session was rejected (401 Unauthorized). Please sign in again.");
      },
      fetchImpl,
    });
  }, [baseUrl, clientOverride, fetchImpl, logout]);
  apiClientRef.current = apiClient;

  const effectiveToken = ssoSession?.accessToken ?? token;
  // `C1`: in the optional server-side (BFF) mode there *is* no token in memory — the session is an
  // `HttpOnly` cookie the browser sends on its own. Treating "no token" as "signed out" therefore left
  // the SPA on the sign-in screen forever after `/api/v1/auth/callback` had already set the cookies.
  // A BFF-enabled deployment is authenticated until a `401` says otherwise (`logout` → `bffSignedOut`).
  const bffEnabled = usesBffSession(authConfig);
  const bffSession = bffEnabled && !bffSignedOut;
  const isAuthenticated =
    (effectiveToken !== null && effectiveToken.length > 0) || bffSession;

  const value = useMemo<AuthContextValue>(
    () => ({
      token: effectiveToken,
      baseUrl,
      isAuthenticated,
      authNotice,
      apiClient,
      authMode: normalizeAuthMode(authConfig.authMode),
      authConfig,
      ssoAvailable: supportsSso(authConfig),
      tokenLoginAvailable: supportsTokenLogin(authConfig),
      tokenFormCollapsed: hidesTokenFormBehindDisclosure(authConfig),
      bffEnabled,
      sessionStatus,
      sessionExpiresAt: ssoSession?.expiresAt ?? null,
      postLoginPath,
      ssoBusy,
      ssoError,
      beginSsoLogin,
      completeSsoLogin,
      login,
      logout,
      clearNotice,
      dismissSsoError,
    }),
    [
      effectiveToken,
      baseUrl,
      authNotice,
      apiClient,
      authConfig,
      bffEnabled,
      isAuthenticated,
      postLoginPath,
      sessionStatus,
      ssoSession?.expiresAt,
      ssoBusy,
      ssoError,
      beginSsoLogin,
      completeSsoLogin,
      login,
      logout,
      clearNotice,
      dismissSsoError,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}
