/**
 * Browser navigation, in one function so it can be replaced in tests.
 *
 * jsdom implements no navigation: calling `window.location.assign` there logs "Not implemented" and
 * changes nothing, so a component test could not tell an SSO redirect from a no-op. Kept separate
 * (rather than inlined in `AuthContext`) so the test can mock *only* the redirect and still exercise
 * the real PKCE code.
 */

/** Sends the browser to `url` after refusing anything that is not an absolute http(s) URL. */
export function redirectTo(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("Refusing to navigate to a URL that is not absolute.");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("Refusing to navigate to a non-http(s) URL.");
  }
  window.location.assign(parsed.toString());
}
