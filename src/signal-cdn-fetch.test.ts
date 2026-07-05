import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  agentOptions: [] as unknown[],
  globalFetch: vi.fn(),
  undiciFetch: vi.fn(),
}));

vi.mock("undici", () => {
  function MockAgent(this: unknown, options: unknown): void {
    mocks.agentOptions.push(options);
  }
  return {
    Agent: MockAgent,
    fetch: mocks.undiciFetch,
  };
});

import {
  getSignalMessengerRootCaPem,
  isSignalCdnRequest,
  signalAttachmentFetch,
} from "./signal-cdn-fetch.js";

describe("signalAttachmentFetch", () => {
  beforeEach(() => {
    mocks.agentOptions.length = 0;
    mocks.globalFetch.mockReset();
    mocks.undiciFetch.mockReset();
    vi.stubGlobal("fetch", mocks.globalFetch);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("uses the Signal Messenger root CA for Signal CDN requests", async () => {
    mocks.undiciFetch.mockResolvedValueOnce(new Response(null, { status: 401 }));

    const response = await signalAttachmentFetch("https://cdn3.signal.org/upload/attachments", {
      method: "POST",
    });

    expect(response.status).toBe(401);
    expect(mocks.globalFetch).not.toHaveBeenCalled();
    expect(mocks.undiciFetch).toHaveBeenCalledWith(
      "https://cdn3.signal.org/upload/attachments",
      expect.objectContaining({
        method: "POST",
        dispatcher: expect.any(Object),
      }),
    );
    expect(mocks.agentOptions).toEqual([
      {
        allowH2: false,
        connect: {
          ca: getSignalMessengerRootCaPem(),
          rejectUnauthorized: true,
        },
      },
    ]);
  });

  it("leaves non-Signal CDN requests on the normal fetch path", async () => {
    mocks.globalFetch.mockResolvedValueOnce(new Response("ok"));

    await signalAttachmentFetch("https://example.com/file", { method: "GET" });

    expect(mocks.globalFetch).toHaveBeenCalledOnce();
    expect(mocks.undiciFetch).not.toHaveBeenCalled();
  });
});

describe("isSignalCdnRequest", () => {
  it("matches only HTTPS Signal CDN hosts", () => {
    expect(isSignalCdnRequest("https://cdn.signal.org/attachments/key")).toBe(true);
    expect(isSignalCdnRequest("https://cdn2.signal.org/attachments/key")).toBe(true);
    expect(isSignalCdnRequest("https://cdn3.signal.org/upload/attachments")).toBe(true);
    expect(isSignalCdnRequest("http://cdn3.signal.org/upload/attachments")).toBe(false);
    expect(isSignalCdnRequest("https://cdn3.signal.org.example/upload/attachments")).toBe(false);
  });
});
