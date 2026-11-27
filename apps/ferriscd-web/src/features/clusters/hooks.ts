import { useQuery } from "@tanstack/react-query";
import { useAuth } from "../../auth/AuthContext";
import {
  PLATFORM_POLL_INTERVAL_MS,
  queryKeys,
} from "../applications/hooks";

/**
 * Data hook for the project-scoped cluster registry (`GET /api/v1/clusters`, `T13.1`/`T17.1`).
 *
 * The server already answers only the clusters the caller's visible `AppProject`s allow, so this
 * hook must never re-filter by cluster name: the response *is* the authorization boundary.
 */
export function useClusters(enabled = true) {
  const { apiClient } = useAuth();
  return useQuery({
    queryKey: queryKeys.clusters(),
    queryFn: () => apiClient.listClusters(),
    enabled,
    refetchInterval: PLATFORM_POLL_INTERVAL_MS,
  });
}
