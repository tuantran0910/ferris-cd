import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import type { FerrisApiClient } from "../api/client";
import { AuthProvider, useAuth } from "../auth/AuthContext";
import { SSO_CALLBACK_PATH } from "../auth/pkce";
import { ApplicationDetailPage } from "../features/applications/ApplicationDetailPage";
import { ApplicationsPage } from "../features/applications/ApplicationsPage";
import { ClustersPage } from "../features/clusters/ClustersPage";
import { FleetOverviewPage } from "../features/overview/FleetOverviewPage";
import { ProjectsPage } from "../features/projects/ProjectsPage";
import { ApiErrorBoundary } from "../ui/ApiErrorBoundary";
import { Layout } from "./Layout";
import { LoginScreen } from "./LoginScreen";

function AuthenticatedRoutes() {
  const { isAuthenticated, logout, postLoginPath } = useAuth();

  if (!isAuthenticated) {
    // The sign-in screen gets the same error boundary as the authenticated
    // tree: a render crash there would otherwise leave a blank page with no
    // way back.
    return (
      <ApiErrorBoundary>
        <LoginScreen />
      </ApiErrorBoundary>
    );
  }

  return (
    <ApiErrorBoundary onLogout={() => logout()}>
      <Routes>
        {/* `T19.2` (finding `H2`): the IdP's registered redirect URI is the fixed
            `/auth/callback`, so the exchange completes *here* and the operator is then sent back to
            the page they started from (carried through the single-use PKCE transaction). The path
            must be served by the static host exactly like any other deep link. */}
        <Route
          path={SSO_CALLBACK_PATH}
          element={<Navigate to={postLoginPath ?? "/"} replace />}
        />
        <Route element={<Layout />}>
          <Route path="/" element={<ApplicationsPage />} />
          <Route path="/overview" element={<FleetOverviewPage />} />
          <Route path="/projects" element={<ProjectsPage />} />
          <Route path="/clusters" element={<ClustersPage />} />
          <Route
            path="/applications/:namespace/:name"
            element={<ApplicationDetailPage />}
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </ApiErrorBoundary>
  );
}

export interface AppProps {
  clientOverride?: FerrisApiClient;
  /** Injectable clock/fetch for the SSO flow (tests schedule expiry without waiting). */
  now?: () => number;
  fetchImpl?: typeof fetch;
}

export function App({ clientOverride, now, fetchImpl }: AppProps) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            refetchOnWindowFocus: false,
          },
        },
      }),
  );

  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider clientOverride={clientOverride} now={now} fetchImpl={fetchImpl}>
        <BrowserRouter>
          <AuthenticatedRoutes />
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
