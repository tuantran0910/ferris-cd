import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../App";
import {
  clearStoredToken,
  getStoredToken,
  normalizeBaseUrl,
  resetTokenMemoryCache,
  setStoredToken,
} from "../auth/tokenStorage";
import { ApiErrorBoundary } from "../components/ApiErrorBoundary";
import { createMockApiClient } from "./fixtures";

describe("Token storage & auth security (Trap Guard T16.1)", () => {
  beforeEach(() => {
    resetTokenMemoryCache();
    window.sessionStorage.clear();
    window.localStorage.clear();
    window.history.replaceState({}, "", "/");
  });

  it("stores bearer token ONLY in memory and sessionStorage — NEVER localStorage or URL params", () => {
    const secretToken = "k8s-sa-token-super-secret-value";
    setStoredToken(secretToken);

    expect(getStoredToken()).toBe(secretToken);
    expect(window.sessionStorage.getItem("ferriscd.auth.token")).toBe(
      secretToken,
    );
    expect(window.localStorage.length).toBe(0);
    expect(window.location.search).not.toContain(secretToken);
    expect(window.location.hash).not.toContain(secretToken);

    clearStoredToken();
    expect(getStoredToken()).toBeNull();
    expect(window.sessionStorage.getItem("ferriscd.auth.token")).toBeNull();
  });

  it("never reads or trusts bearer tokens passed via URL query parameters", () => {
    window.history.replaceState({}, "", "/?token=leaked-url-token#token=hash");
    resetTokenMemoryCache();

    expect(getStoredToken()).toBeNull();
  });

  it("strips query params and fragments when normalizing API base URL and rejects non-HTTP schemes", () => {
    expect(
      normalizeBaseUrl("https://ferriscd.internal:8443/api/?token=secret#frag"),
    ).toBe("https://ferriscd.internal:8443/api");
    expect(normalizeBaseUrl("http://localhost:8080/")).toBe(
      "http://localhost:8080",
    );
    expect(normalizeBaseUrl("/ferriscd/")).toBe("/ferriscd");
    expect(normalizeBaseUrl("javascript:alert(1)")).toBe("");
    expect(normalizeBaseUrl("data:text/html,<script>alert(1)</script>")).toBe(
      "",
    );
    expect(normalizeBaseUrl("ftp://files.example.com")).toBe("");
  });

  it("completes token login and logout flows via LoginScreen without writing to localStorage", async () => {
    const user = userEvent.setup();
    const mockClient = createMockApiClient();

    render(<App clientOverride={mockClient} />);

    const tokenField = screen.getByLabelText(/Kubernetes Bearer Token/i);
    await user.type(tokenField, "valid-session-token-123");
    await user.click(screen.getByRole("button", { name: /Sign In/i }));

    expect(await screen.findByText("payments-api")).toBeInTheDocument();
    expect(window.sessionStorage.getItem("ferriscd.auth.token")).toBe(
      "valid-session-token-123",
    );
    expect(window.localStorage.length).toBe(0);
    expect(window.location.href).not.toContain("valid-session-token-123");

    await user.click(screen.getByRole("button", { name: /Sign Out/i }));
    expect(
      screen.getByLabelText(/Kubernetes Bearer Token/i),
    ).toBeInTheDocument();
    expect(window.sessionStorage.getItem("ferriscd.auth.token")).toBeNull();
  });

  it("renders ApiErrorBoundary fallback on unexpected render crashes and allows sign out", async () => {
    const user = userEvent.setup();
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const onLogout = vi.fn();

    function Boom(): never {
      throw new Error("Simulated rendering crash");
    }

    render(
      <ApiErrorBoundary onLogout={onLogout}>
        <Boom />
      </ApiErrorBoundary>,
    );

    expect(screen.getByRole("alert")).toHaveTextContent(
      "Simulated rendering crash",
    );
    await user.click(screen.getByRole("button", { name: /Sign Out/i }));
    expect(onLogout).toHaveBeenCalledTimes(1);
    spy.mockRestore();
  });
});
