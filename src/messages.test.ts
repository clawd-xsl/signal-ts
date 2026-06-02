import { describe, expect, it } from "vitest";
import { bytesToBase64 } from "./bytes.js";
import {
  decodeSignalContent,
  decodeSignalEnvelope,
  decodeSignalDeviceName,
  decodeSignalProvisionEnvelope,
  decodeSignalProvisionMessage,
  encodeSignalEnvelope,
  encodeSignalContent,
  encodeSignalDeviceName,
  encodeSignalProvisionEnvelope,
  encodeSignalProvisionMessage,
  createReceiptSignalContent,
  createTypingSignalContent,
  SignalEnvelopeType,
} from "./messages.js";

describe("Signal protobuf messages", () => {
  it("roundtrips a text DataMessage inside Content", () => {
    const encoded = encodeSignalContent({
      dataMessage: {
        body: "hello from signal-ts",
        timestamp: 1_766_000_000_001,
      },
    });

    expect(decodeSignalContent(encoded)).toEqual({
      dataMessage: {
        body: "hello from signal-ts",
        timestamp: 1_766_000_000_001,
      },
    });
  });

  it("roundtrips receipt and typing content through the official schema", () => {
    expect(
      decodeSignalContent(
        encodeSignalContent(createReceiptSignalContent({ type: "read", timestamps: [123, 456] })),
      ),
    ).toEqual({
      receiptMessage: { type: "read", timestamps: [123, 456] },
    });
    expect(
      decodeSignalContent(
        encodeSignalContent(
          createTypingSignalContent({
            action: "started",
            timestamp: 789,
            groupId: Uint8Array.from([1, 2, 3]),
          }),
        ),
      ),
    ).toEqual({
      typingMessage: {
        action: "started",
        timestamp: 789,
        groupId: Uint8Array.from([1, 2, 3]),
      },
    });
  });

  it("decodes the live envelope fields needed for unsealed messages", () => {
    const envelope = encodeSignalEnvelope({
      type: SignalEnvelopeType.PreKeyMessage,
      sourceServiceId: "11111111-1111-4111-8111-111111111111",
      sourceDeviceId: 2,
      clientTimestamp: 1_766_000_000_002,
      content: Uint8Array.from([0x33, 0x01, 0x02]),
      destinationServiceId: "22222222-2222-4222-8222-222222222222",
      urgent: true,
    });

    expect(decodeSignalEnvelope(envelope)).toMatchObject({
      type: SignalEnvelopeType.PreKeyMessage,
      sourceServiceId: "11111111-1111-4111-8111-111111111111",
      sourceDeviceId: 2,
      destinationServiceId: "22222222-2222-4222-8222-222222222222",
      clientTimestamp: 1_766_000_000_002,
      urgent: true,
    });
    expect(bytesToBase64(decodeSignalEnvelope(envelope).content ?? new Uint8Array())).toBe("MwEC");
  });

  it("roundtrips provisioning and device-name protobufs", () => {
    const provisionMessage = encodeSignalProvisionMessage({
      aciIdentityKeyPrivate: Uint8Array.from([1, 2, 3]),
      pniIdentityKeyPrivate: Uint8Array.from([4, 5, 6]),
      aciBinary: Uint8Array.from(Array.from({ length: 16 }, (_, index) => index)),
      pniBinary: Uint8Array.from(Array.from({ length: 16 }, (_, index) => index + 16)),
      number: "+15555550123",
      provisioningCode: "abc",
      readReceipts: true,
      profileKey: Uint8Array.from([7, 8]),
    });
    const envelope = encodeSignalProvisionEnvelope({
      publicKey: Uint8Array.from([9, 10]),
      body: provisionMessage,
    });

    expect(decodeSignalProvisionEnvelope(envelope)).toEqual({
      publicKey: Uint8Array.from([9, 10]),
      body: provisionMessage,
    });
    expect(decodeSignalProvisionMessage(provisionMessage)).toMatchObject({
      number: "+15555550123",
      provisioningCode: "abc",
      readReceipts: true,
      profileKey: Uint8Array.from([7, 8]),
    });
    expect(
      decodeSignalDeviceName(
        encodeSignalDeviceName({
          ephemeralPublic: Uint8Array.from([1]),
          syntheticIv: Uint8Array.from([2]),
          ciphertext: Uint8Array.from([3]),
        }),
      ),
    ).toEqual({
      ephemeralPublic: Uint8Array.from([1]),
      syntheticIv: Uint8Array.from([2]),
      ciphertext: Uint8Array.from([3]),
    });
  });
});
