import { describe, expect, it, vi } from "vitest";
import { ApiClientError, createFerrisApiClient } from "../api/client";

describe("FerrisApiClient OpenAPI contract (T16.1)", () => {
  it("attaches Authorization Bearer header (never URL query param) and parses 200 responses", async () => {
    const fetchSpy = vi.fn(async (input: RequestInfo | URL) => {
      const req = input as Request;
      expect(req.url).toBe("https://ferriscd.test/api/v1/applications");
      expect(req.url).not.toContain("my-secret-token");
      expect(req.headers.get("Authorization")).toBe("Bearer my-secret-token");
      return new Response(JSON.stringify({ items: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });

    const client = createFerrisApiClient({
      baseUrl: "https://ferriscd.test",
      getToken: () => "my-secret-token",
      fetchImpl: fetchSpy as unknown as typeof fetch,
    });

    const result = await client.listApplications();
    expect(result.items).toEqual([]);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("invokes onUnauthorized on 401 and throws typed ApiClientError on 403", async () => {
    const onUnauthorized = vi.fn();
    let callCount = 0;
    const fetchSpy = vi.fn(async () => {
      callCount += 1;
      if (callCount === 1) {
        return new Response(
          JSON.stringify({
            error: { code: "Unauthorized", message: "invalid token" },
          }),
          { status: 401, headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response(
        JSON.stringify({
          error: { code: "Forbidden", message: "project sync denied" },
        }),
        { status: 403, headers: { "Content-Type": "application/json" } },
      );
    });

    const client = createFerrisApiClient({
      baseUrl: "https://ferriscd.test",
      getToken: () => "token",
      onUnauthorized,
      fetchImpl: fetchSpy as unknown as typeof fetch,
    });

    await expect(client.listApplications()).rejects.toMatchObject({
      status: 401,
      code: "Unauthorized",
      isUnauthorized: true,
    });
    expect(onUnauthorized).toHaveBeenCalledTimes(1);

    try {
      await client.syncApplication("ferriscd-system", "payments-api", {});
      expect.unreachable("expected 403 error");
    } catch (err) {
      expect(err).toBeInstanceOf(ApiClientError);
      const apiErr = err as ApiClientError;
      expect(apiErr.isForbidden).toBe(true);
      expect(apiErr.message).toBe("project sync denied");
    }
  });
});
