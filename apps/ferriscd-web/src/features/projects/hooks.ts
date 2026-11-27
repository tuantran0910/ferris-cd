import { useQuery } from "@tanstack/react-query";
import { useAuth } from "../../auth/AuthContext";
import {
  PLATFORM_POLL_INTERVAL_MS,
  queryKeys,
} from "../applications/hooks";

/**
 * Data hooks for the `AppProject` catalogue (`GET /api/v1/projects`, `T17.3`).
 *
 * The catalogue is slow-moving, so it polls once a minute instead of every ten seconds, and
 * `enabled` lets a surface that only needs it while open (the command palette) avoid the request
 * entirely. The query key is shared with the palette so both views read one cache entry.
 */
export function useProjects(enabled = true) {
  const { apiClient } = useAuth();
  return useQuery({
    queryKey: queryKeys.projects(),
    queryFn: () => apiClient.listProjects(),
    enabled,
    refetchInterval: PLATFORM_POLL_INTERVAL_MS,
  });
}
