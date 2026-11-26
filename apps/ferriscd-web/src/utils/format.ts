/**
 * Presentation helpers for values the API returns verbatim.
 *
 * Two rules:
 * - A commit/timestamp is rendered *short* but its full value stays available
 *   in a `title` attribute, so a 40-char SHA or an RFC 3339 timestamp never
 *   forces a card or table cell to overflow.
 * - Nothing here invents data: an unparseable timestamp is shown as returned.
 */

const EM_DASH = "\u2014";

/** Truncates a revision/commit hash for display, keeping the full value for `title`. */
export function shortRevision(
  revision: string | null | undefined,
  length = 8,
): string {
  if (!revision) {
    return EM_DASH;
  }
  const trimmed = revision.trim();
  if (!trimmed) {
    return EM_DASH;
  }
  return trimmed.length > length
    ? `${trimmed.slice(0, length)}\u2026`
    : trimmed;
}

/**
 * Formats an RFC 3339 timestamp as `YYYY-MM-DD HH:mm:ss UTC`.
 *
 * UTC (not the browser locale) keeps the value identical for every operator
 * looking at the same reconcile, and makes it deterministic in tests.
 */
export function formatTimestamp(value: string | null | undefined): string {
  if (!value) {
    return EM_DASH;
  }
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    return value;
  }
  const iso = new Date(parsed).toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 19)} UTC`;
}

/**
 * Returns a browser-openable URL for a repository, or `null` when the source is
 * not an HTTP(S) clone URL (SSH / scp-style / local paths have no web page).
 *
 * The `.git` suffix is dropped because hosting UIs do not use it, and any
 * embedded credentials are refused so a token can never be leaked into a link.
 */
export function repoWebUrl(repoURL: string | null | undefined): string | null {
  if (!repoURL) {
    return null;
  }
  const trimmed = repoURL.trim();
  if (!/^https?:\/\//i.test(trimmed)) {
    return null;
  }
  try {
    const url = new URL(trimmed);
    if (url.username || url.password) {
      return null;
    }
    const path = url.pathname.replace(/\/+$/, "").replace(/\.git$/i, "");
    return `${url.origin}${path}`;
  } catch {
    return null;
  }
}

/**
 * Returns a web URL for a commit when the repository is HTTP(S) and the
 * revision looks like a SHA, or `null` otherwise.
 *
 * GitLab serves commits under `/-/commit/<sha>`; every other host (GitHub,
 * Gitea, Forgejo, Bitbucket Server, ...) uses `/commit/<sha>`.
 */
export function commitWebUrl(
  repoURL: string | null | undefined,
  revision: string | null | undefined,
): string | null {
  const base = repoWebUrl(repoURL);
  const sha = revision?.trim();
  if (!base || !sha || !/^[0-9a-f]{7,40}$/i.test(sha)) {
    return null;
  }
  const host = new URL(base).hostname.toLowerCase();
  const segment = host === "gitlab.com" || host.startsWith("gitlab.")
    ? "/-/commit/"
    : "/commit/";
  return `${base}${segment}${sha}`;
}
