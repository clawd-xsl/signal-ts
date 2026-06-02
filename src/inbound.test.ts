import { describe, expect, it } from "vitest";
import { bytesToBase64, utf8Bytes } from "./bytes.js";
import {
  normalizeSignalContent,
  signalGroupIdFromMasterKey,
  type SignalIncomingDataMessage,
  type SignalIncomingReactionMessage,
} from "./inbound.js";
import { SignalEnvelopeType } from "./messages.js";

const envelope = {
  type: SignalEnvelopeType.PreKeyMessage,
  sourceServiceId: "11111111-1111-4111-8111-111111111111",
  sourceDeviceId: 2,
  clientTimestamp: 1_766_000_000_001,
  serverTimestamp: 1_766_000_000_002,
};

describe("Signal inbound normalization", () => {
  it("normalizes data messages with attachments, body ranges, and group metadata", () => {
    const masterKey = deterministicBytes(32, 1);
    const groupId = signalGroupIdFromMasterKey(masterKey);
    const messages = normalizeSignalContent({
      envelope,
      content: {
        dataMessage: {
          body: "hello @bot",
          timestamp: 1_766_000_000_003,
          attachments: [{ cdnKey: "cdn-key", cdnNumber: 2, contentType: "image/png" }],
          bodyRanges: [{ start: 6, length: 4, mentionAci: "bot-aci" }],
          groupV2: { masterKey, revision: 9 },
        },
      },
    });

    expect(messages).toHaveLength(1);
    const data = messages[0] as SignalIncomingDataMessage;
    expect(data).toMatchObject({
      kind: "data",
      sender: {
        serviceId: "11111111-1111-4111-8111-111111111111",
        deviceId: 2,
      },
      timestamp: 1_766_000_000_003,
      serverTimestamp: 1_766_000_000_002,
      body: "hello @bot",
      attachments: [{ cdnKey: "cdn-key", cdnNumber: 2, contentType: "image/png" }],
      bodyRanges: [{ start: 6, length: 4, mentionAci: "bot-aci" }],
      group: { id: groupId, revision: 9 },
    });
  });

  it("normalizes reactions as first-class events", () => {
    const messages = normalizeSignalContent({
      envelope,
      content: {
        dataMessage: {
          reaction: {
            emoji: "ok",
            targetAuthorAci: "22222222-2222-4222-8222-222222222222",
            targetSentTimestamp: 123,
          },
        },
      },
    });

    expect(messages).toHaveLength(1);
    const reaction = messages[0] as SignalIncomingReactionMessage;
    expect(reaction.kind).toBe("reaction");
    expect(reaction.reaction).toEqual({
      emoji: "ok",
      targetAuthorAci: "22222222-2222-4222-8222-222222222222",
      targetSentTimestamp: 123,
    });
  });

  it("normalizes receipt and typing messages from the same content payload", () => {
    const groupId = utf8Bytes("group");
    const messages = normalizeSignalContent({
      envelope,
      content: {
        receiptMessage: { type: "read", timestamps: [1, 2] },
        typingMessage: { action: "started", timestamp: 3, groupId },
      },
    });

    expect(messages).toEqual([
      expect.objectContaining({
        kind: "receipt",
        receipt: { type: "read", timestamps: [1, 2] },
      }),
      expect.objectContaining({
        kind: "typing",
        typing: { action: "started", timestamp: 3, groupId },
        group: { id: bytesToBase64(groupId) },
      }),
    ]);
  });

  it("returns an unknown event for content without a supported high-level event", () => {
    expect(
      normalizeSignalContent({
        envelope: {},
        content: { nullMessage: { padding: utf8Bytes("pad") } },
      }),
    ).toEqual([
      expect.objectContaining({
        kind: "unknown",
        sender: {},
      }),
    ]);
  });
});

function deterministicBytes(length: number, seed: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    bytes[index] = (seed + index) % 256;
  }
  return bytes as Uint8Array<ArrayBuffer>;
}
