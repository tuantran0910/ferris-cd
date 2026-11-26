import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiClientError } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";

/**
 * Query keys + data hooks for the applications feature.
 *
 * Every `queryKey` the app uses is declared here so a cache entry can never be
 * written with one spelling and invalidated with another. The string shapes are
 * the ones the pages used before (`["applications"]`,
 * `["application", ns, name]`, ...) — they are part of the runtime contract of
 * polling/invalidation, so they must not change.
 */
export const queryKeys = {
  applications: () => ["applications"] as const,
  application: (namespace: string, name: string) =>
    ["application", namespace, name] as const,
  resources: (namespace: string, name: string) =>
    ["application-resources", namespace, name] as const,
  diff: (namespace: string, name: string) =>
    ["application-diff", namespace, name] as const,
};

export const APPLICATIONS_POLL_INTERVAL_MS = 10_000;
export const DETAIL_POLL_INTERVAL_MS = 10_000;

/**
 * Poll every 10s, except once the server has definitively answered "you may not
 * see this" (403) or "this does not exist" (404): retrying those forever just
 * burns cluster reads and log volume.
 */
export function pollUnlessTerminalError(query: {
  state: { error: unknown };
}): number | false {
  const err = query.state.error;
  if (err instanceof ApiClientError && (err.isForbidden || err.isNotFound)) {
    return false;
  }
  return DETAIL_POLL_INTERVAL_MS;
}

export function useApplications() {
  const { apiClient } = useAuth();
  return useQuery({
    queryKey: queryKeys.applications(),
    queryFn: () => apiClient.listApplications(),
    refetchInterval: APPLICATIONS_POLL_INTERVAL_MS,
  });
}

export function useApplicationDetail(namespace: string, name: string) {
  const { apiClient } = useAuth();
  return useQuery({
    queryKey: queryKeys.application(namespace, name),
    queryFn: () => apiClient.getApplication(namespace, name),
    enabled: Boolean(namespace && name),
    refetchInterval: pollUnlessTerminalError,
  });
}

export function useResources(
  namespace: string,
  name: string,
  enabled = true,
) {
  const { apiClient } = useAuth();
  return useQuery({
    queryKey: queryKeys.resources(namespace, name),
    queryFn: () => apiClient.getResources(namespace, name),
    enabled: Boolean(namespace && name && enabled),
    refetchInterval: pollUnlessTerminalError,
  });
}

export function useDiff(namespace: string, name: string, enabled = true) {
  const { apiClient } = useAuth();
  return useQuery({
    queryKey: queryKeys.diff(namespace, name),
    queryFn: () => apiClient.getDiff(namespace, name),
    enabled: Boolean(namespace && name && enabled),
  });
}

/**
 * Refetch everything a sync/rollback can change, in the order the operator
 * reads it: the detail header first, then its resources and diff, then the list
 * the operator came from.
 */
export function useInvalidateAfterOperation(
  namespace: string,
  name: string,
): () => void {
  const queryClient = useQueryClient();
  return () => {
    void queryClient.invalidateQueries({
      queryKey: queryKeys.application(namespace, name),
    });
    void queryClient.invalidateQueries({
      queryKey: queryKeys.resources(namespace, name),
    });
    void queryClient.invalidateQueries({
      queryKey: queryKeys.diff(namespace, name),
    });
    void queryClient.invalidateQueries({ queryKey: queryKeys.applications() });
  };
}
