import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { useQueryClient } from "@tanstack/react-query";
import { createFerrisApiClient, type FerrisApiClient } from "../api/client";
import {
  clearStoredToken,
  getStoredBaseUrl,
  getStoredToken,
  normalizeBaseUrl,
  setStoredBaseUrl,
  setStoredToken,
} from "./tokenStorage";

export interface AuthContextValue {
  token: string | null;
  baseUrl: string;
  isAuthenticated: boolean;
  authNotice: string | null;
  apiClient: FerrisApiClient;
  login: (token: string, baseUrl?: string) => void;
  logout: (notice?: string) => void;
  clearNotice: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export interface AuthProviderProps {
  children: ReactNode;
  clientOverride?: FerrisApiClient;
}

export function AuthProvider({ children, clientOverride }: AuthProviderProps) {
  const queryClient = useQueryClient();
  const [token, setToken] = useState<string | null>(() => getStoredToken());
  const [baseUrl, setBaseUrl] = useState<string>(() => getStoredBaseUrl());
  const [authNotice, setAuthNotice] = useState<string | null>(null);

  const login = useCallback(
    (newToken: string, nextBaseUrl?: string) => {
      const cleanedToken = newToken.trim();
      if (!cleanedToken) {
        return;
      }
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
    [queryClient],
  );

  const logout = useCallback(
    (notice?: string) => {
      clearStoredToken();
      setToken(null);
      setAuthNotice(notice ?? null);
      queryClient.clear();
    },
    [queryClient],
  );

  const clearNotice = useCallback(() => {
    setAuthNotice(null);
  }, []);

  const apiClient = useMemo(() => {
    if (clientOverride) {
      return clientOverride;
    }
    return createFerrisApiClient({
      baseUrl,
      getToken: () => getStoredToken(),
      onUnauthorized: () => {
        logout("Your session token was rejected (401 Unauthorized). Please sign in again.");
      },
    });
  }, [baseUrl, clientOverride, logout]);

  const value = useMemo<AuthContextValue>(
    () => ({
      token,
      baseUrl,
      isAuthenticated: token !== null && token.length > 0,
      authNotice,
      apiClient,
      login,
      logout,
      clearNotice,
    }),
    [token, baseUrl, authNotice, apiClient, login, logout, clearNotice],
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
