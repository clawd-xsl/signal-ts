import { describe, expect, it } from "vitest";
import { fetchTurnServers } from "./relays.js";

function jsonResponse(status: number, payload: unknown) {
  return {
    status,
    message: "",
    headers: [] as [string, string][],
    body: new TextEncoder().encode(JSON.stringify(payload)),
  };
}

const relay = {
  username: "user",
  password: "pass",
  hostname: "turn.example.net",
  urls: ["turn:turn.example.net:80?transport=udp"],
  urlsWithIps: ["turn:198.51.100.7:80?transport=udp"],
};

describe("fetchTurnServers", () => {
  it("splits each relay into an IP-URL server with hostname and a plain-URL server without", async () => {
    // RingRTC rejects an ice server whose hostname is set but whose urls are
    // not raw IPs; the split mirrors Signal-Desktop's iceServerConfigToList.
    const servers = await fetchTurnServers({
      fetch: async () => jsonResponse(200, { relays: [relay] }),
    });
    expect(servers).toEqual([
      {
        urls: relay.urlsWithIps,
        username: "user",
        password: "pass",
        hostname: "turn.example.net",
      },
      { urls: relay.urls, username: "user", password: "pass" },
    ]);
  });

  it("omits empty url groups instead of emitting empty servers", async () => {
    const servers = await fetchTurnServers({
      fetch: async () =>
        jsonResponse(200, { relays: [{ username: "user", password: "pass", urls: relay.urls }] }),
    });
    expect(servers).toEqual([{ urls: relay.urls, username: "user", password: "pass" }]);
  });

  it("throws on non-2xx responses and on responses without usable servers", async () => {
    await expect(fetchTurnServers({ fetch: async () => jsonResponse(404, {}) })).rejects.toThrow(
      "HTTP 404",
    );
    await expect(
      fetchTurnServers({ fetch: async () => jsonResponse(200, { relays: [] }) }),
    ).rejects.toThrow("no usable ICE servers");
  });
});
