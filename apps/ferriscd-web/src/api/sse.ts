/**
 * Server-Sent Events client for the RBAC-filtered application snapshot feed (`T17.3`).
 *
 * `EventSource` cannot attach an `Authorization` header, and a bearer token must never be placed in
 * a URL (access logs, proxies, `Referer`). This client therefore uses `fetch()` with a streaming
 * body and parses the SSE frames itself.
 */

import { ApiClientError } from "./client";
import type { ApplicationListView } from "./types";

export interface SseMessage {
  event: string;
  data: string;
}

/**
 * Incremental SSE frame parser. Chunks may split anywhere (including between `\r` and `\n`), so the
 * caller feeds decoded text and receives complete messages only.
 */
export class SseParser {
  private buffer = "";
  private event = "";
  private data: string[] = [];

  push(chunk: string): SseMessage[] {
    this.buffer += chunk;
    const messages: SseMessage[] = [];
    let newline = this.buffer.indexOf("\n");
    while (newline >= 0) {
      let line = this.buffer.slice(0, newline);
      this.buffer = this.buffer.slice(newline + 1);
      if (line.endsWith("\r")) {
        line = line.slice(0, -1);
      }
      if (line === "") {
        this.flush(messages);
      } else if (!line.startsWith(":")) {
        this.parseLine(line);
      }
      newline = this.buffer.indexOf("\n");
    }
    return messages;
  }

  private parseLine(line: string): void {
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) {
      value = value.slice(1);
    }
    if (field === "event") {
      this.event = value;
    } else if (field === "data") {
      this.data.push(value);
    }
  }

  private flush(messages: SseMessage[]): void {
    if (this.data.length === 0 && this.event === "") {
      return;
    }
    messages.push({ event: this.event || "message", data: this.data.join("\n") });
    this.event = "";
    this.data = [];
  }
}

export interface ApplicationStreamOptions {
  baseUrl: string;
  token: string;
  signal: AbortSignal;
  onSnapshot: (snapshot: ApplicationListView) => void;
  fetchImpl?: typeof fetch;
}

/** Builds the stream URL without ever putting credentials in it. */
export function applicationStreamUrl(baseUrl: string): string {
  return `${baseUrl.replace(/\/+$/, "")}/api/v1/applications/stream`;
}

/**
 * Opens one SSE connection and resolves when the server ends it.
 *
 * Rejects on a non-2xx response, a transport failure, or a terminal `error` frame so the caller can
 * apply its reconnect policy. Aborting `signal` rejects with the abort error (callers ignore it).
 */
export async function openApplicationStream(
  options: ApplicationStreamOptions,
): Promise<void> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const response = await fetchImpl(applicationStreamUrl(options.baseUrl), {
    headers: {
      Accept: "text/event-stream",
      Authorization: `Bearer ${options.token}`,
    },
    cache: "no-store",
    signal: options.signal,
  });

  if (!response.ok) {
    throw new ApiClientError(
      response.status,
      response.status === 401 ? "Unauthorized" : `HTTP_${response.status}`,
      response.status === 401
        ? "Authentication required. Please sign in again."
        : `The live update stream failed with HTTP ${response.status}.`,
    );
  }
  if (!response.body) {
    throw new ApiClientError(0, "StreamingUnsupported", "This browser cannot read the live update stream.");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const parser = new SseParser();

  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) {
        return;
      }
      const text = decoder.decode(value, { stream: true });
      for (const message of parser.push(text)) {
        if (message.event === "applications") {
          options.onSnapshot(JSON.parse(message.data) as ApplicationListView);
        } else if (message.event === "error") {
          const body = JSON.parse(message.data) as {
            error?: { code?: string; message?: string };
          };
          throw new ApiClientError(
            0,
            body.error?.code ?? "StreamError",
            body.error?.message ?? "The live update stream reported an error.",
          );
        }
      }
    }
  } finally {
    reader.cancel().catch(() => undefined);
  }
}
