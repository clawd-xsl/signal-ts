import {
  Aci,
  CiphertextMessageType,
  IdentityKeyPair,
  KEMKeyPair,
  KyberPreKeyRecord,
  PlaintextContent,
  PreKeyBundle,
  PreKeyRecord,
  PrivateKey,
  ProtocolAddress,
  SenderCertificate,
  SenderKeyDistributionMessage,
  SignedPreKeyRecord,
  ServerCertificate,
  processSenderKeyDistributionMessage,
  sealedSenderDecryptToUsmc,
} from "@signalapp/libsignal-client";
import type { SendMessageRequest } from "@signalapp/libsignal-client/dist/net/chat/AuthMessagesService.js";
import { describe, expect, it, vi } from "vitest";
import type { SignalAccountState } from "../account.js";
import { copyBytes } from "../bytes.js";
import {
  SignalTsClient,
  type SignalChatConnection,
  type SignalSealedSenderConnection,
} from "../client.js";
import {
  decryptIncomingEnvelope,
  extractSignalDecryptionErrorMessageFromContent,
} from "../crypto.js";
import { InMemorySignalRepository } from "../memory-store.js";
import { encodeSignalEnvelope, SignalEnvelopeType } from "../messages.js";
import { createLibsignalStores, type LibsignalStores } from "../store.js";

describe("in-process message e2e", () => {
  it("encrypts native content messages through the client and decrypts received envelopes", async () => {
    const sender = await createGeneratedAccount({
      aci: "11111111-1111-4111-8111-111111111111",
      deviceId: 2,
      registrationId: 101,
    });
    const receiver = await createGeneratedAccount({
      aci: "22222222-2222-4222-8222-222222222222",
      deviceId: 2,
      registrationId: 202,
    });
    const sent: SendMessageRequest[] = [];
    const connection: SignalChatConnection = {
      sendMessage: async (request) => {
        sent.push(request);
      },
      disconnect: vi.fn(async () => {}),
      connectionInfo: () => ({ localPort: 1, ipVersion: "IPv4", toString: () => "fake" }),
    };
    const client = new SignalTsClient({
      account: sender.account,
      connectionFactory: async () => connection,
    });
    const timestamp = 1_766_000_000_003;
    const reactionTimestamp = timestamp + 1;
    const receiptTimestamp = timestamp + 2;
    const typingTimestamp = timestamp + 3;
    const body = "hello from native signal-ts";
    const attachmentKey = deterministicBytes(64, 30);
    const attachmentDigest = deterministicBytes(32, 40);
    const attachment = {
      cdnKey: "cdn-key",
      cdnNumber: 2,
      key: attachmentKey,
      digest: attachmentDigest,
      size: 10,
      contentType: "image/png",
      fileName: "image.png",
    };
    const quote = {
      id: 1_766_000_000_000,
      authorAci: receiver.account.device.aci,
      text: "quoted text",
    };
    const bodyRanges = [{ start: 0, length: 5, style: 1 }];

    await client.connect();
    await client.sendMessage({
      destination: receiver.account.device.aci,
      body,
      attachments: [attachment],
      quote,
      bodyRanges,
      stores: sender.stores,
      preKeyBundles: [receiver.preKeyBundle],
      timestamp,
    });
    await client.sendReactionMessage({
      destination: receiver.account.device.aci,
      reaction: {
        emoji: "+1",
        targetAuthorAci: receiver.account.device.aci,
        targetSentTimestamp: 1_766_000_000_000,
      },
      stores: sender.stores,
      preKeyBundles: [receiver.preKeyBundle],
      timestamp: reactionTimestamp,
    });
    await client.sendReceiptMessage({
      destination: receiver.account.device.aci,
      receipt: { type: "read", timestamps: [timestamp] },
      stores: sender.stores,
      preKeyBundles: [receiver.preKeyBundle],
      timestamp: receiptTimestamp,
    });
    await client.sendTypingMessage({
      destination: receiver.account.device.aci,
      typing: { action: "started", timestamp: typingTimestamp },
      stores: sender.stores,
      preKeyBundles: [receiver.preKeyBundle],
      timestamp: typingTimestamp,
    });

    expect(sent).toHaveLength(4);
    const request = requireSentRequest(sent, 0);
    expect(request?.timestamp).toBe(timestamp);
    expect(request?.contents).toHaveLength(1);
    const deviceMessage = request.contents[0];
    expect(deviceMessage?.deviceId).toBe(receiver.account.device.deviceId);
    expect(deviceMessage?.registrationId).toBe(receiver.account.device.registrationId);
    if (!deviceMessage) {
      throw new Error("missing outbound device message");
    }

    const decrypted = await decryptIncomingEnvelope({
      envelope: encodeReceivedEnvelope({
        sender,
        receiver,
        timestamp,
        ciphertextType: deviceMessage.contents.type(),
        ciphertext: deviceMessage.contents.serialize(),
      }),
      localAddress: receiver.localAddress,
      stores: receiver.stores,
    });

    expect(decrypted.envelope.sourceServiceId).toBe(sender.account.device.aci);
    expect(decrypted.content.dataMessage).toEqual({
      body,
      timestamp,
      attachments: [attachment],
      quote,
      bodyRanges,
    });
    expect(
      (await decryptSentRequest({ request: requireSentRequest(sent, 1), sender, receiver })).content
        .dataMessage,
    ).toEqual({
      timestamp: reactionTimestamp,
      reaction: {
        emoji: "+1",
        targetAuthorAci: receiver.account.device.aci,
        targetSentTimestamp: 1_766_000_000_000,
      },
    });
    expect(
      (await decryptSentRequest({ request: requireSentRequest(sent, 2), sender, receiver })).content
        .receiptMessage,
    ).toEqual({
      type: "read",
      timestamps: [timestamp],
    });
    expect(
      (await decryptSentRequest({ request: requireSentRequest(sent, 3), sender, receiver })).content
        .typingMessage,
    ).toEqual({
      action: "started",
      timestamp: typingTimestamp,
    });
    await client.sendRetryReceiptMessage({
      destination: receiver.account.device.aci,
      retry: {
        recipientServiceId: receiver.account.device.aci,
        senderDeviceId: receiver.account.device.deviceId,
        timestamp,
        ciphertextType: deviceMessage.contents.type(),
        originalContent: deviceMessage.contents.serialize(),
      },
      stores: sender.stores,
      timestamp: timestamp + 4,
    });
    expect(sent).toHaveLength(5);
    const retryDeviceMessage = requireSentRequest(sent, 4).contents[0];
    if (!retryDeviceMessage) {
      throw new Error("missing retry receipt device message");
    }
    expect(retryDeviceMessage.contents.type()).toBe(CiphertextMessageType.Plaintext);
    expect(
      extractSignalDecryptionErrorMessageFromContent(
        PlaintextContent.deserialize(retryDeviceMessage.contents.serialize()).body(),
      ),
    ).toMatchObject({
      timestamp,
      deviceId: receiver.account.device.deviceId,
    });
  });

  it("distributes sender keys and decrypts native group messages", async () => {
    const sender = await createGeneratedAccount({
      aci: "11111111-1111-4111-8111-111111111111",
      deviceId: 2,
      registrationId: 101,
    });
    const receiver = await createGeneratedAccount({
      aci: "22222222-2222-4222-8222-222222222222",
      deviceId: 2,
      registrationId: 202,
    });
    const sent: SendMessageRequest[] = [];
    const connection: SignalChatConnection = {
      sendMessage: async (request) => {
        sent.push(request);
      },
      disconnect: vi.fn(async () => {}),
      connectionInfo: () => ({ localPort: 1, ipVersion: "IPv4", toString: () => "fake" }),
    };
    const client = new SignalTsClient({
      account: sender.account,
      connectionFactory: async () => connection,
    });
    const timestamp = 1_766_000_001_000;
    const groupMasterKey = deterministicBytes(32, 80);
    const distributionId = "33333333-3333-4333-8333-333333333333";

    await client.connect();
    await client.sendGroupMessage({
      members: [receiver.account.device.aci],
      group: {
        masterKey: groupMasterKey,
        revision: 7,
        distributionId,
      },
      body: "hello group",
      stores: sender.stores,
      memberPreKeyBundles: new Map([
        [receiver.serviceId.getServiceIdString(), [receiver.preKeyBundle]],
      ]),
      timestamp,
    });
    await client.sendGroupReactionMessage({
      members: [receiver.account.device.aci],
      group: {
        masterKey: groupMasterKey,
        revision: 7,
        distributionId,
      },
      reaction: {
        emoji: "+1",
        targetAuthorAci: receiver.account.device.aci,
        targetSentTimestamp: timestamp,
      },
      stores: sender.stores,
      memberPreKeyBundles: new Map([
        [receiver.serviceId.getServiceIdString(), [receiver.preKeyBundle]],
      ]),
      timestamp: timestamp + 1,
    });

    expect(sent).toHaveLength(4);
    const distribution = await decryptSentRequest({
      request: requireSentRequest(sent, 0),
      sender,
      receiver,
    });
    const distributionBytes = distribution.content.senderKeyDistributionMessage;
    if (!distributionBytes) {
      throw new Error("missing sender key distribution message");
    }
    await processSenderKeyDistributionMessage(
      sender.localAddress,
      SenderKeyDistributionMessage.deserialize(distributionBytes),
      receiver.stores.senderKeyStore,
    );

    const groupDeviceMessage = requireSentRequest(sent, 1).contents[0];
    if (!groupDeviceMessage) {
      throw new Error("missing group device message");
    }
    const inboundGroup = await decryptIncomingEnvelope({
      envelope: {
        type: SignalEnvelopeType.SenderKey,
        sourceServiceId: sender.account.device.aci,
        sourceDeviceId: sender.account.device.deviceId,
        content: groupDeviceMessage.contents.serialize(),
      },
      localAddress: receiver.localAddress,
      stores: receiver.stores,
    });
    expect(inboundGroup.content.dataMessage).toEqual({
      body: "hello group",
      timestamp,
      groupV2: {
        masterKey: groupMasterKey,
        revision: 7,
      },
    });
    const reactionDistribution = await decryptSentRequest({
      request: requireSentRequest(sent, 2),
      sender,
      receiver,
    });
    const reactionDistributionBytes = reactionDistribution.content.senderKeyDistributionMessage;
    if (!reactionDistributionBytes) {
      throw new Error("missing reaction sender key distribution message");
    }
    await processSenderKeyDistributionMessage(
      sender.localAddress,
      SenderKeyDistributionMessage.deserialize(reactionDistributionBytes),
      receiver.stores.senderKeyStore,
    );
    const groupReactionDeviceMessage = requireSentRequest(sent, 3).contents[0];
    if (!groupReactionDeviceMessage) {
      throw new Error("missing group reaction device message");
    }
    const inboundGroupReaction = await decryptIncomingEnvelope({
      envelope: {
        type: SignalEnvelopeType.SenderKey,
        sourceServiceId: sender.account.device.aci,
        sourceDeviceId: sender.account.device.deviceId,
        content: groupReactionDeviceMessage.contents.serialize(),
      },
      localAddress: receiver.localAddress,
      stores: receiver.stores,
    });
    expect(inboundGroupReaction.content.dataMessage).toEqual({
      timestamp: timestamp + 1,
      reaction: {
        emoji: "+1",
        targetAuthorAci: receiver.account.device.aci,
        targetSentTimestamp: timestamp,
      },
      groupV2: {
        masterKey: groupMasterKey,
        revision: 7,
      },
    });
  });

  it("decrypts sealed sender direct messages through the native sealed sender path", async () => {
    const sender = await createGeneratedAccount({
      aci: "11111111-1111-4111-8111-111111111111",
      deviceId: 2,
      registrationId: 101,
    });
    const receiver = await createGeneratedAccount({
      aci: "22222222-2222-4222-8222-222222222222",
      deviceId: 2,
      registrationId: 202,
    });
    const { certificate, trustRoot } = await createSenderCertificate(sender);
    const sealedSent: Parameters<SignalSealedSenderConnection["sendMessage"]>[0][] = [];
    const sealedConnection: SignalSealedSenderConnection = {
      sendMessage: async (request) => {
        sealedSent.push(request);
      },
      disconnect: vi.fn(async () => {}),
      connectionInfo: () => ({ localPort: 1, ipVersion: "IPv4", toString: () => "fake" }),
    };
    const client = new SignalTsClient({
      account: sender.account,
      sealedSenderConnectionFactory: async () => sealedConnection,
    });
    const timestamp = 1_766_000_002_000;
    const body = "sealed hello";

    await client.sendSealedContentMessage({
      destination: receiver.account.device.aci,
      content: { dataMessage: { body, timestamp } },
      senderCertificate: certificate,
      stores: sender.stores,
      preKeyBundles: [receiver.preKeyBundle],
      timestamp,
    });
    const request = sealedSent[0];
    const deviceMessage = request?.contents[0];
    if (!deviceMessage) {
      throw new Error("missing sealed outbound device message");
    }
    const inboundEnvelope = encodeSignalEnvelope({
      type: SignalEnvelopeType.UnidentifiedSender,
      clientTimestamp: timestamp,
      content: copyBytes(deviceMessage.contents),
      destinationServiceId: receiver.account.device.aci,
      urgent: true,
    });
    const decrypted = await decryptIncomingEnvelope({
      envelope: inboundEnvelope,
      localAddress: receiver.localAddress,
      sealedSender: {
        trustRoot,
        localAci: receiver.account.device.aci,
        localDeviceId: receiver.account.device.deviceId,
      },
      stores: receiver.stores,
    });

    expect(decrypted.envelope.sourceServiceId).toBe(sender.account.device.aci);
    expect(decrypted.sealedSender).toMatchObject({
      senderUuid: sender.account.device.aci,
      senderAci: sender.account.device.aci,
      senderE164: null,
      deviceId: sender.account.device.deviceId,
    });
    expect(decrypted.content.dataMessage).toEqual({ body, timestamp });

    await expect(
      decryptIncomingEnvelope({
        envelope: inboundEnvelope,
        localAddress: receiver.localAddress,
        sealedSender: {
          trustRoot,
          localAci: receiver.account.device.aci,
          localDeviceId: receiver.account.device.deviceId,
        },
        stores: receiver.stores,
      }),
    ).rejects.toMatchObject({
      name: "SignalTsDecryptionError",
      retryReceipt: { timestamp },
    });

    const receiverSent: SendMessageRequest[] = [];
    const receiverConnection: SignalChatConnection = {
      sendMessage: async (request) => {
        receiverSent.push(request);
      },
      disconnect: vi.fn(async () => {}),
      connectionInfo: () => ({ localPort: 2, ipVersion: "IPv4", toString: () => "fake" }),
    };
    const receiverClient = new SignalTsClient({
      account: receiver.account,
      connectionFactory: async () => receiverConnection,
    });
    const responseTimestamp = timestamp + 1;
    await receiverClient.connect();
    await receiverClient.sendMessage({
      destination: sender.account.device.aci,
      body: "receiver response",
      stores: receiver.stores,
      preKeyBundles: [sender.preKeyBundle],
      timestamp: responseTimestamp,
    });
    await decryptSentRequest({
      request: requireSentRequest(receiverSent, 0),
      sender: receiver,
      receiver: sender,
    });

    const secondTimestamp = timestamp + 2;
    const secondBody = "sealed followup";
    await client.sendSealedContentMessage({
      destination: receiver.account.device.aci,
      content: { dataMessage: { body: secondBody, timestamp: secondTimestamp } },
      senderCertificate: certificate,
      stores: sender.stores,
      preKeyBundles: [receiver.preKeyBundle],
      timestamp: secondTimestamp,
    });

    const secondDeviceMessage = sealedSent[1]?.contents[0];
    if (!secondDeviceMessage) {
      throw new Error("missing sealed followup outbound device message");
    }
    expect(
      (
        await sealedSenderDecryptToUsmc(secondDeviceMessage.contents, receiver.stores.identityStore)
      ).msgType(),
    ).toBe(CiphertextMessageType.Whisper);
    const secondDecrypted = await decryptIncomingEnvelope({
      envelope: encodeSignalEnvelope({
        type: SignalEnvelopeType.UnidentifiedSender,
        clientTimestamp: secondTimestamp,
        content: copyBytes(secondDeviceMessage.contents),
        destinationServiceId: receiver.account.device.aci,
        urgent: true,
      }),
      localAddress: receiver.localAddress,
      sealedSender: {
        trustRoot,
        localAci: receiver.account.device.aci,
        localDeviceId: receiver.account.device.deviceId + 1,
      },
      stores: receiver.stores,
    });
    expect(secondDecrypted.content.dataMessage).toEqual({
      body: secondBody,
      timestamp: secondTimestamp,
    });
  });
});

type GeneratedAccount = {
  account: SignalAccountState;
  repository: InMemorySignalRepository;
  stores: LibsignalStores;
  localAddress: ProtocolAddress;
  serviceId: ReturnType<typeof Aci.fromUuid>;
  preKeyBundle: PreKeyBundle;
};

async function createGeneratedAccount({
  aci,
  deviceId,
  registrationId,
}: {
  aci: string;
  deviceId: number;
  registrationId: number;
}): Promise<GeneratedAccount> {
  const identityKey = PrivateKey.generate();
  const repository = new InMemorySignalRepository({ identityKey, registrationId });
  const preKeyId = 1;
  const preKey = PrivateKey.generate();
  const signedPreKeyId = 1;
  const signedPreKey = PrivateKey.generate();
  const signedPreKeySignature = identityKey.sign(signedPreKey.getPublicKey().serialize());
  const kyberPreKeyId = 1;
  const kyberKeyPair = KEMKeyPair.generate();
  const kyberPreKeySignature = identityKey.sign(kyberKeyPair.getPublicKey().serialize());
  await repository.savePreKey(preKeyId, PreKeyRecord.new(preKeyId, preKey.getPublicKey(), preKey));
  await repository.saveSignedPreKey(
    signedPreKeyId,
    SignedPreKeyRecord.new(
      signedPreKeyId,
      Date.now(),
      signedPreKey.getPublicKey(),
      signedPreKey,
      signedPreKeySignature,
    ),
  );
  await repository.saveKyberPreKey(
    kyberPreKeyId,
    KyberPreKeyRecord.new(kyberPreKeyId, Date.now(), kyberKeyPair, kyberPreKeySignature),
  );
  const account: SignalAccountState = {
    auth: { username: `${aci}.${deviceId}`, password: "unused" },
    device: { aci, deviceId, registrationId },
  };
  return {
    account,
    repository,
    stores: createLibsignalStores(repository),
    localAddress: ProtocolAddress.new(Aci.fromUuid(aci), deviceId),
    serviceId: Aci.fromUuid(aci),
    preKeyBundle: PreKeyBundle.new(
      registrationId,
      deviceId,
      preKeyId,
      preKey.getPublicKey(),
      signedPreKeyId,
      signedPreKey.getPublicKey(),
      signedPreKeySignature,
      identityKey.getPublicKey(),
      kyberPreKeyId,
      kyberKeyPair.getPublicKey(),
      kyberPreKeySignature,
    ),
  };
}

async function createSenderCertificate(
  account: GeneratedAccount,
): Promise<{ certificate: SenderCertificate; trustRoot: ReturnType<PrivateKey["getPublicKey"]> }> {
  const trustRoot = IdentityKeyPair.generate();
  const serverKey = IdentityKeyPair.generate();
  const serverCertificate = ServerCertificate.new(1, serverKey.publicKey, trustRoot.privateKey);
  const senderIdentity = await account.repository.getLocalIdentityKey();
  return {
    certificate: SenderCertificate.new(
      account.account.device.aci,
      null,
      account.account.device.deviceId,
      senderIdentity.getPublicKey(),
      Date.now() + 7 * 24 * 60 * 60 * 1000,
      serverCertificate,
      serverKey.privateKey,
    ),
    trustRoot: trustRoot.publicKey,
  };
}

function encodeReceivedEnvelope({
  sender,
  receiver,
  timestamp,
  ciphertextType,
  ciphertext,
}: {
  sender: GeneratedAccount;
  receiver: GeneratedAccount;
  timestamp: number;
  ciphertextType: number;
  ciphertext: Uint8Array;
}) {
  return encodeSignalEnvelope({
    type: envelopeTypeForCiphertext(ciphertextType),
    clientTimestamp: timestamp,
    sourceDeviceId: sender.account.device.deviceId,
    content: copyBytes(ciphertext),
    sourceServiceId: sender.account.device.aci,
    destinationServiceId: receiver.account.device.aci,
    urgent: true,
  });
}

function requireSentRequest(sent: SendMessageRequest[], index: number): SendMessageRequest {
  const request = sent[index];
  if (!request) {
    throw new Error(`missing outbound request ${index}`);
  }
  return request;
}

async function decryptSentRequest({
  request,
  sender,
  receiver,
}: {
  request: SendMessageRequest;
  sender: GeneratedAccount;
  receiver: GeneratedAccount;
}) {
  const deviceMessage = request.contents[0];
  if (!deviceMessage) {
    throw new Error("missing outbound device message");
  }
  return await decryptIncomingEnvelope({
    envelope: encodeReceivedEnvelope({
      sender,
      receiver,
      timestamp: request.timestamp,
      ciphertextType: deviceMessage.contents.type(),
      ciphertext: deviceMessage.contents.serialize(),
    }),
    localAddress: receiver.localAddress,
    stores: receiver.stores,
  });
}

function envelopeTypeForCiphertext(type: number): SignalEnvelopeType {
  if (type === CiphertextMessageType.PreKey) {
    return SignalEnvelopeType.PreKeyMessage;
  }
  if (type === CiphertextMessageType.Whisper) {
    return SignalEnvelopeType.DoubleRatchet;
  }
  throw new Error(`Unsupported test ciphertext type: ${type}`);
}

function deterministicBytes(length: number, seed: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    bytes[index] = (seed + index) % 256;
  }
  return bytes as Uint8Array<ArrayBuffer>;
}
