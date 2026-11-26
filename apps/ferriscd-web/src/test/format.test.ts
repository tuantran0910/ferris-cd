import { describe, expect, it } from "vitest";
import {
  commitWebUrl,
  formatTimestamp,
  repoWebUrl,
  shortRevision,
} from "../utils/format";

describe("format helpers", () => {
  it("shortens revisions and keeps short ones intact", () => {
    expect(shortRevision("a1b2c3d4e5f60000111122223333444455556666")).toBe(
      "a1b2c3d4…",
    );
    expect(shortRevision("a1b2c3d4e5f6000011112222", 12)).toBe("a1b2c3d4e5f6…");
    expect(shortRevision("deadbeef")).toBe("deadbeef");
    expect(shortRevision("  main  ")).toBe("main");
    expect(shortRevision(null)).toBe("\u2014");
    expect(shortRevision("")).toBe("\u2014");
  });

  it("renders RFC 3339 timestamps in a stable UTC form and never hides bad input", () => {
    expect(formatTimestamp("2026-11-25T18:00:00Z")).toBe(
      "2026-11-25 18:00:00 UTC",
    );
    expect(formatTimestamp("2026-11-25T18:00:00+02:00")).toBe(
      "2026-11-25 16:00:00 UTC",
    );
    expect(formatTimestamp(null)).toBe("\u2014");
    expect(formatTimestamp(undefined)).toBe("\u2014");
    expect(formatTimestamp("not-a-timestamp")).toBe("not-a-timestamp");
  });

  it("links only HTTP(S) repositories and strips the .git suffix", () => {
    expect(repoWebUrl("https://github.com/acme/apps.git")).toBe(
      "https://github.com/acme/apps",
    );
    expect(repoWebUrl("https://github.com/acme/apps/")).toBe(
      "https://github.com/acme/apps",
    );
    expect(repoWebUrl("git@github.com:acme/apps.git")).toBeNull();
    expect(repoWebUrl("ssh://git@github.com/acme/apps.git")).toBeNull();
    expect(repoWebUrl("/local/repo")).toBeNull();
    expect(repoWebUrl("https://user:token@github.com/acme/apps.git")).toBeNull();
    expect(repoWebUrl(null)).toBeNull();
  });

  it("derives commit URLs per host and refuses non-SHA revisions", () => {
    const sha = "a1b2c3d4e5f60000111122223333444455556666";
    expect(commitWebUrl("https://github.com/acme/apps.git", sha)).toBe(
      `https://github.com/acme/apps/commit/${sha}`,
    );
    expect(commitWebUrl("https://gitlab.com/acme/apps", sha)).toBe(
      `https://gitlab.com/acme/apps/-/commit/${sha}`,
    );
    expect(commitWebUrl("https://github.com/acme/apps", "main")).toBeNull();
    expect(commitWebUrl("git@github.com:acme/apps.git", sha)).toBeNull();
    expect(commitWebUrl("https://github.com/acme/apps", null)).toBeNull();
  });
});
