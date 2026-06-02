import { Aci } from "@signalapp/libsignal-client";
import type { SingleOutboundUnsealedMessage } from "@signalapp/libsignal-client/dist/net/chat/SingleOutboundMessage.js";
import { describe, expect, it, vi } from "vitest";
import { SignalTsClient, type SignalChatConnection } from "./client.js";

describe("SignalTsClient", () => {
  it("connects through the injected connection factory and sends encrypted payloads", async () => {
    const sendMessage = vi.fn(async () => {});
    const disconnect = vi.fn(async () => {});
    const connection: SignalChatConnection = {
      sendMessage,
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
});
