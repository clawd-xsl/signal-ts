import {
  Aci,
  ErrorCode,
  KEMKeyPair,
  KyberPreKeyRecord,
  MismatchedDevicesEntry,
  PreKeyBundle,
  PreKeyRecord,
  PrivateKey,
  ProtocolAddress,
  SignedPreKeyRecord,
  type SessionRecord,
} from "@signalapp/libsignal-client";
import type { SingleOutboundUnsealedMessage } from "@signalapp/libsignal-client/dist/net/chat/SingleOutboundMessage.js";
import { describe, expect, it, vi } from "vitest";
import type { SignalAccountState } from "./account.js";
import {
  SignalTsClient,
  type SendContentMessageParams,
  type UploadAttachmentParams,
  type SignalChatConnection,
} from "./client.js";
import { encryptPayloadForDevice } from "./crypto.js";
import { InMemorySignalRepository } from "./memory-store.js";
import type { SignalAttachmentPointer, SignalContent } from "./messages.js";
import { createLibsignalStores, type LibsignalStores } from "./store.js";

const UTF8_DECODER = new TextDecoder();
const LONG_TEXT_CONTENT_TYPE = "text/x-signal-plain";

function createTestClient(): SignalTsClient {
  return new SignalTsClient({
    account: {
      auth: { username: "user.1", password: "pass" },
      device: {
        aci: "11111111-1111-4111-8111-111111111111",
        deviceId: 1,
        registrationId: 42,
      },
    },
    connectionFactory: async () => {
      throw new Error("test connection factory should not be called");
    },
  });
}

function createContentParams(traceId: string, timestamp: number): SendContentMessageParams {
  return {
    traceId,
    destination: Aci.fromUuid("22222222-2222-4222-8222-222222222222"),
    timestamp,
    content: { nullMessage: { padding: new Uint8Array() } },
    stores: {} as SendContentMessageParams["stores"],
  };
}

function createFakePreKeyBundle(deviceId: number, registrationId: number): PreKeyBundle {
  return {
    deviceId: () => deviceId,
    registrationId: () => registrationId,
  } as unknown as PreKeyBundle;
}

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
  await repository.savePreKey(
    preKeyId,
    PreKeyRecord.new(preKeyId, preKey.getPublicKey(), preKey),
  );
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

function createAttachmentPointer(overrides: Partial<SignalAttachmentPointer> = {}) {
  return {
    cdnKey: "cdn-key",
    cdnNumber: 2,
    contentType: "image/png",
    key: new Uint8Array(64),
    digest: new Uint8Array(32),
    size: 3,
    ...overrides,
  } satisfies SignalAttachmentPointer;
}

describe("SignalTsClient", () => {
  it("serializes content sends that mutate Signal session state", async () => {
    const client = createTestClient();
    const events: string[] = [];
    let resolveFirstStarted!: () => void;
    let releaseFirst!: () => void;
    const firstStarted = new Promise<void>((resolve) => {
      resolveFirstStarted = resolve;
    });
    const firstCanFinish = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const sendContentMessageUnlocked = vi.fn(
      async (params: SendContentMessageParams): Promise<{ timestamp: number }> => {
        events.push(`${params.traceId}:start`);
        if (params.traceId === "first") {
          resolveFirstStarted();
          await firstCanFinish;
        }
        events.push(`${params.traceId}:end`);
        return { timestamp: params.timestamp ?? 0 };
      },
    );
    (
      client as unknown as {
        sendContentMessageUnlocked: typeof sendContentMessageUnlocked;
      }
    ).sendContentMessageUnlocked = sendContentMessageUnlocked;

    const first = client.sendContentMessage(createContentParams("first", 1));
    await firstStarted;
    const second = client.sendContentMessage(createContentParams("second", 2));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(events).toEqual(["first:start"]);

    releaseFirst();
    await expect(Promise.all([first, second])).resolves.toEqual([
      { timestamp: 1 },
      { timestamp: 2 },
    ]);
    expect(events).toEqual(["first:start", "first:end", "second:start", "second:end"]);
  });

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

  it("refreshes every direct session when the mismatch entry has no device details", async () => {
    const destination = Aci.fromUuid("22222222-2222-4222-8222-222222222222");
    const mismatch = Object.assign(new Error("Mismatched devices for recipient"), {
      code: ErrorCode.MismatchedDevices,
      entries: [new MismatchedDevicesEntry({ account: destination })],
    });
    const sendMessage = vi.fn(async (_request: Parameters<SignalChatConnection["sendMessage"]>[0]) => {
      if (sendMessage.mock.calls.length === 1) {
        throw mismatch;
      }
    });
    const connection: SignalChatConnection = {
      sendMessage,
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
    const initialBundle = createFakePreKeyBundle(1, 287);
    const currentBundles = [initialBundle, createFakePreKeyBundle(2, 288)];
    const fetchPreKeyBundles = vi.fn(async () => currentBundles);
    type BuildContentsParams = {
      preKeyBundles: PreKeyBundle[];
      refreshDeviceIds?: ReadonlySet<number>;
    };
    const buildDirectContentMessageContents = vi.fn(
      async ({ preKeyBundles }: BuildContentsParams): Promise<SingleOutboundUnsealedMessage[]> =>
        preKeyBundles.map((bundle) => ({
          deviceId: bundle.deviceId(),
          registrationId: bundle.registrationId(),
          contents: {} as SingleOutboundUnsealedMessage["contents"],
        })),
    );
    const clientInternals = client as unknown as {
      fetchPreKeyBundles: typeof fetchPreKeyBundles;
      buildDirectContentMessageContents: typeof buildDirectContentMessageContents;
    };
    clientInternals.fetchPreKeyBundles = fetchPreKeyBundles;
    clientInternals.buildDirectContentMessageContents = buildDirectContentMessageContents;

    await client.connect();
    await client.sendContentMessage({
      traceId: "content-empty-mismatch",
      destination,
      timestamp: 123,
      content: { nullMessage: { padding: new Uint8Array() } },
      stores: {} as SendContentMessageParams["stores"],
      preKeyBundles: [initialBundle],
    });

    expect(sendMessage).toHaveBeenCalledTimes(2);
    expect(fetchPreKeyBundles).toHaveBeenCalledTimes(1);
    expect(sendMessage.mock.calls[1]?.[0].contents.map((content) => content.deviceId)).toEqual([
      1,
      2,
    ]);
    const retryBuild = buildDirectContentMessageContents.mock.calls[1]?.[0];
    expect([...(retryBuild?.refreshDeviceIds ?? [])]).toEqual([1, 2]);
  });

  it("repairs mismatched devices and retries retry receipts", async () => {
    const destination = Aci.fromUuid("22222222-2222-4222-8222-222222222222");
    const sender = await createGeneratedAccount({
      aci: "11111111-1111-4111-8111-111111111111",
      deviceId: 1,
      registrationId: 42,
    });
    const receiver = await createGeneratedAccount({
      aci: destination.getServiceIdString(),
      deviceId: 1,
      registrationId: 287,
    });
    const deviceMessage = await encryptPayloadForDevice({
      localAddress: sender.localAddress,
      device: {
        serviceId: receiver.serviceId,
        deviceId: receiver.account.device.deviceId,
        registrationId: receiver.account.device.registrationId,
        preKeyBundle: receiver.preKeyBundle,
      },
      payload: new Uint8Array([1, 2, 3]),
      stores: sender.stores,
    });
    const mismatch = Object.assign(new Error("Mismatched devices for recipient"), {
      code: ErrorCode.MismatchedDevices,
      entries: [
        new MismatchedDevicesEntry({
          account: destination,
          missingDevices: [2],
          extraDevices: [4],
          staleDevices: [1],
        }),
      ],
    });
    const sendMessage = vi.fn(async (_request: Parameters<SignalChatConnection["sendMessage"]>[0]) => {
      if (sendMessage.mock.calls.length === 1) {
        throw mismatch;
      }
    });
    const connection: SignalChatConnection = {
      sendMessage,
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
    const currentBundles = [createFakePreKeyBundle(1, 287), createFakePreKeyBundle(2, 288)];
    const fetchPreKeyBundles = vi.fn(async () => currentBundles);
    (
      client as unknown as {
        fetchPreKeyBundles: typeof fetchPreKeyBundles;
      }
    ).fetchPreKeyBundles = fetchPreKeyBundles;
    const removeSession = vi.fn(async (_address: ProtocolAddress) => {});
    const sessionStore = {
      getSession: vi.fn(async (address: ProtocolAddress) => {
        if (address.deviceId() !== 1) {
          return null;
        }
        return { remoteRegistrationId: () => 287 } as unknown as SessionRecord;
      }),
      saveSession: vi.fn(async () => {}),
      getExistingSessions: vi.fn(async () => []),
      removeSession,
    };

    await client.connect();
    await client.sendRetryReceiptMessage({
      traceId: "retry-mismatch",
      destination,
      timestamp: 123,
      retry: {
        recipientServiceId: destination.getServiceIdString(),
        senderDeviceId: 1,
        timestamp: 99,
        ciphertextType: deviceMessage.contents.type(),
        originalContent: deviceMessage.contents.serialize(),
      },
      stores: {
        sessionStore: sessionStore as Parameters<SignalTsClient["sendRetryReceiptMessage"]>[0]["stores"]["sessionStore"],
        identityStore: {} as Parameters<SignalTsClient["sendRetryReceiptMessage"]>[0]["stores"]["identityStore"],
      },
      preKeyBundles: [createFakePreKeyBundle(1, 287)],
    });

    expect(sendMessage).toHaveBeenCalledTimes(2);
    expect(fetchPreKeyBundles).toHaveBeenCalledTimes(1);
    expect(sendMessage.mock.calls[0]?.[0].contents.map((content) => content.deviceId)).toEqual([1]);
    expect(sendMessage.mock.calls[1]?.[0].contents.map((content) => content.deviceId)).toEqual([
      1,
      2,
    ]);
    expect(removeSession.mock.calls.map(([address]) => address.deviceId())).toEqual([1, 4]);
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

  it("sends oversized direct text as a Signal long-text attachment", async () => {
    const client = createTestClient();
    const body = `${"a".repeat(1999)}é-tail`;
    const existingAttachment = createAttachmentPointer({ cdnKey: "image-cdn-key" });
    let sentContent: SignalContent | undefined;
    const uploadAttachment = vi.fn(async (params: UploadAttachmentParams) => {
      expect(params.attachment.contentType).toBe(LONG_TEXT_CONTENT_TYPE);
      expect(params.attachment.uploadTimestamp).toBe(123);
      expect(UTF8_DECODER.decode(params.attachment.data)).toBe(body);
      return {
        encrypted: new Uint8Array(),
        pointer: createAttachmentPointer({
          cdnKey: "long-text-cdn-key",
          contentType: LONG_TEXT_CONTENT_TYPE,
          size: params.attachment.data.byteLength,
        }),
        plaintextHash: "hash",
      };
    });
    const sendContentMessage = vi.fn(async (params: SendContentMessageParams) => {
      sentContent = params.content;
      return { timestamp: params.timestamp ?? 0 };
    });
    Object.assign(client, { uploadAttachment, sendContentMessage });

    await client.sendMessage({
      traceId: "long-direct",
      destination: Aci.fromUuid("22222222-2222-4222-8222-222222222222"),
      body,
      attachments: [existingAttachment],
      timestamp: 123,
      stores: {} as SendContentMessageParams["stores"],
    });

    expect(uploadAttachment).toHaveBeenCalledTimes(1);
    expect(sendContentMessage).toHaveBeenCalledTimes(1);
    expect(sentContent?.dataMessage?.body).toBe("a".repeat(1999));
    expect(sentContent?.dataMessage?.attachments).toEqual([
      expect.objectContaining({
        cdnKey: "long-text-cdn-key",
        contentType: LONG_TEXT_CONTENT_TYPE,
      }),
      existingAttachment,
    ]);
  });

  it("sends oversized group text as a Signal long-text attachment", async () => {
    const client = createTestClient();
    const body = "测".repeat(700);
    let sentContent: SignalContent | undefined;
    const uploadAttachment = vi.fn(async (params: UploadAttachmentParams) => ({
      encrypted: new Uint8Array(),
      pointer: createAttachmentPointer({
        cdnKey: "group-long-text-cdn-key",
        contentType: LONG_TEXT_CONTENT_TYPE,
        size: params.attachment.data.byteLength,
      }),
      plaintextHash: "hash",
    }));
    const sendGroupContentMessage = vi.fn(async (params: { content: SignalContent }) => {
      sentContent = params.content;
      return { timestamp: 456, recipients: 1 };
    });
    Object.assign(client, { uploadAttachment, sendGroupContentMessage });

    await client.sendGroupMessage({
      traceId: "long-group",
      members: [],
      group: {
        masterKey: new Uint8Array(32),
        revision: 7,
        distributionId: "33333333-3333-4333-8333-333333333333",
      },
      body,
      timestamp: 456,
      stores: {} as Parameters<SignalTsClient["sendGroupMessage"]>[0]["stores"],
    });

    expect(uploadAttachment).toHaveBeenCalledTimes(1);
    expect(uploadAttachment.mock.calls[0]?.[0].attachment.contentType).toBe(
      LONG_TEXT_CONTENT_TYPE,
    );
    expect(sentContent?.dataMessage?.body).toBe("测".repeat(666));
    expect(sentContent?.dataMessage?.attachments?.[0]).toEqual(
      expect.objectContaining({
        cdnKey: "group-long-text-cdn-key",
        contentType: LONG_TEXT_CONTENT_TYPE,
      }),
    );
    expect(sentContent?.dataMessage?.groupV2).toEqual({
      masterKey: new Uint8Array(32),
      revision: 7,
    });
  });
});
