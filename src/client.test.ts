import { Aci } from "@signalapp/libsignal-client";
import type { SingleOutboundUnsealedMessage } from "@signalapp/libsignal-client/dist/net/chat/SingleOutboundMessage.js";
import { describe, expect, it, vi } from "vitest";
import { SignalTsClient, type SignalChatConnection } from "./client.js";

describe("SignalTsClient", () => {
  it("connects through the injected connection factory and sends encrypted payloads", async () => {
    const sendMessage = vi.fn(async () => {});
    const sendSyncMessage = vi.fn(async () => {});
    const disconnect = vi.fn(async () => {});
    const connection: SignalChatConnection = {
      sendMessage,
      sendSyncMessage,
      disconnect,
      connectionInfo: () => ({ localPort: 1, ipVersion: "IPv4", toString: () => "fake" }),
    };
    const client = new SignalTsClient({
      account: {
        auth: { username: "user.1", password: "pass" },
        device: {
          aci: "11111111-1111-4111-8111-111111111111",
          deviceId: 1,
          registrationId: 42,
        },
      },
      connectionFactory: async () => connection,
    });

    await client.connect();
    await client.sendEncryptedMessage({
      destination: Aci.fromUuid("22222222-2222-4222-8222-222222222222"),
      timestamp: 123,
      contents: [] as readonly SingleOutboundUnsealedMessage[],
    });
    await client.disconnect();

    expect(sendMessage).toHaveBeenCalledWith(
      {
        destination: Aci.fromUuid("22222222-2222-4222-8222-222222222222"),
        timestamp: 123,
        contents: [],
        onlineOnly: false,
        urgent: true,
      },
      undefined,
    );
    expect(disconnect).toHaveBeenCalledTimes(1);
  });

  it("sends encrypted sync payloads through the authenticated connection", async () => {
    const sendMessage = vi.fn(async () => {});
    const sendSyncMessage = vi.fn(async () => {});
    const connection: SignalChatConnection = {
      sendMessage,
      sendSyncMessage,
      disconnect: vi.fn(async () => {}),
      connectionInfo: () => ({ localPort: 1, ipVersion: "IPv4", toString: () => "fake" }),
    };
    const client = new SignalTsClient({
      account: {
        auth: { username: "user.1", password: "pass" },
        device: {
          aci: "11111111-1111-4111-8111-111111111111",
          deviceId: 1,
          registrationId: 42,
        },
      },
      connectionFactory: async () => connection,
    });

    await client.connect();
    await client.sendSyncMessage({
      timestamp: 456,
      contents: [] as readonly SingleOutboundUnsealedMessage[],
      urgent: false,
    });

    expect(sendSyncMessage).toHaveBeenCalledWith(
      {
        timestamp: 456,
        contents: [],
        urgent: false,
      },
      undefined,
    );
  });

  it("preserves the authenticated connection context while uploading attachments", async () => {
    const uploadFetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") {
        return new Response(null, {
          status: 200,
          headers: { location: "https://upload.example/session" },
        });
      }
      return new Response(null, { status: 200 });
    });
    let observedThis: unknown;
    const connection = {
      marker: "bound-connection",
      sendMessage: vi.fn(async () => {}),
      disconnect: vi.fn(async () => {}),
      connectionInfo: () => ({ localPort: 1, ipVersion: "IPv4" as const, toString: () => "fake" }),
      async getUploadForm(_request, _options) {
        observedThis = this;
        return {
          cdn: 2,
          key: "cdn-key",
          headers: new Map<string, string>(),
          signedUploadUrl: new URL("https://upload.example/start"),
        };
      },
    } satisfies SignalChatConnection & { marker: string };
    const client = new SignalTsClient({
      account: {
        auth: { username: "user.1", password: "pass" },
        device: {
          aci: "11111111-1111-4111-8111-111111111111",
          deviceId: 1,
          registrationId: 42,
        },
      },
      connectionFactory: async () => connection,
    });

    await client.connect();
    await client.uploadAttachment({
      attachment: { data: new Uint8Array([1, 2, 3]), contentType: "image/png" },
      fetch: uploadFetch,
    });

    expect(observedThis).toBe(connection);
  });
});
