import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import type { FerrisApiClient } from "../api/client";
import { AuthProvider, useAuth } from "../auth/AuthContext";
import { ApplicationDetailPage } from "../features/applications/ApplicationDetailPage";
import { ApplicationsPage } from "../features/applications/ApplicationsPage";
import { ClustersPage } from "../features/clusters/ClustersPage";
import { ProjectsPage } from "../features/projects/ProjectsPage";
import { ApiErrorBoundary } from "../ui/ApiErrorBoundary";
import { Layout } from "./Layout";
import { LoginScreen } from "./LoginScreen";

function AuthenticatedRoutes() {
  const { isAuthenticated, logout } = useAuth();

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
        <Route element={<Layout />}>
          <Route path="/" element={<ApplicationsPage />} />
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
}

export function App({ clientOverride }: AppProps) {
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
      <AuthProvider clientOverride={clientOverride}>
        <BrowserRouter>
          <AuthenticatedRoutes />
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
