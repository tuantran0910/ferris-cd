import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import type { FerrisApiClient } from "./api/client";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import { ApiErrorBoundary } from "./components/ApiErrorBoundary";
import { Layout } from "./components/Layout";
import { LoginScreen } from "./components/LoginScreen";
import { ApplicationDetailPage } from "./pages/ApplicationDetailPage";
import { ApplicationsPage } from "./pages/ApplicationsPage";

function AuthenticatedRoutes() {
  const { isAuthenticated, logout } = useAuth();

  if (!isAuthenticated) {
    return <LoginScreen />;
  }

  return (
    <ApiErrorBoundary onLogout={() => logout()}>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<ApplicationsPage />} />
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
