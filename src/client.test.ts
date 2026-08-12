import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
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
  type SignalConnectionFactory,
} from "./client.js";
import { encryptPayloadForDevice } from "./crypto.js";
import {
  SqliteSignalIncomingEnvelopeStore,
} from "./incoming-envelope-store.js";
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
  it("persists and server-acks inbound envelopes before exposing them to consumers", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "signal-ts-client-incoming-"));
    const store = new SqliteSignalIncomingEnvelopeStore(path.join(directory, "incoming.sqlite"));
    let listener: Parameters<SignalConnectionFactory>[0]["listener"] | undefined;
    const connection: SignalChatConnection = {
      sendMessage: vi.fn(async () => undefined),
      disconnect: vi.fn(async () => undefined),
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
      incomingEnvelopeStore: store,
      connectionFactory: async (params) => {
        listener = params.listener;
        return connection;
      },
    });
    const envelope = new Uint8Array([9, 8, 7]);
    const serverAck = vi.fn(() => {
      expect(existsSync(path.join(directory, "incoming.sqlite"))).toBe(true);
    });
    const received: Array<{ ack: () => Promise<void> }> = [];
    client.on("incoming", (incoming) => received.push(incoming));

    try {
      await client.connect();
      listener?.onIncomingMessage(envelope, 200, { send: serverAck } as never);
      listener?.onQueueEmpty();
      await client.startIncomingDelivery();
      await vi.waitFor(() => expect(received).toHaveLength(1));

      expect(serverAck).toHaveBeenCalledOnce();
      await client.disconnect();
      await client.connect();
      listener?.onQueueEmpty();
      await client.startIncomingDelivery();
      await vi.waitFor(() => expect(received).toHaveLength(2));

      const complete = vi.spyOn(store, "complete").mockRejectedValueOnce(new Error("disk busy"));
      await expect(received[1]!.ack()).rejects.toThrow("disk busy");
      await vi.waitFor(() => expect(received).toHaveLength(3));
      await received[2]!.ack();
      expect(complete).toHaveBeenCalledTimes(2);
      expect(await store.listPending(16)).toEqual([]);

      listener?.onIncomingMessage(envelope, 200, { send: serverAck } as never);
      await vi.waitFor(() => expect(serverAck).toHaveBeenCalledTimes(2));
      expect(received).toHaveLength(3);
    } finally {
      await client.disconnect();
      store.close();
      await rm(directory, { recursive: true });
    }
  });

  it("replays an unfinished delivery after interruption and ignores the old listener", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "signal-ts-client-reconnect-"));
    const store = new SqliteSignalIncomingEnvelopeStore(path.join(directory, "incoming.sqlite"));
    const listeners: Array<Parameters<SignalConnectionFactory>[0]["listener"]> = [];
    const disconnects: Array<ReturnType<typeof vi.fn>> = [];
    const client = new SignalTsClient({
      account: {
        auth: { username: "user.1", password: "pass" },
        device: {
          aci: "11111111-1111-4111-8111-111111111111",
          deviceId: 1,
          registrationId: 42,
        },
      },
      incomingEnvelopeStore: store,
      connectionFactory: async ({ listener }) => {
        listeners.push(listener);
        const disconnect = vi.fn(async () => undefined);
        disconnects.push(disconnect);
        return {
          sendMessage: vi.fn(async () => undefined),
          disconnect,
          connectionInfo: () => ({ localPort: 1, ipVersion: "IPv4", toString: () => "fake" }),
        };
      },
    });
    const received: Array<{ ack: () => Promise<void> }> = [];
    client.on("incoming", (incoming) => received.push(incoming));
    const envelope = new Uint8Array([6, 5, 4]);

    try {
      await client.connect();
      listeners[0]!.onIncomingMessage(envelope, 100, { send: vi.fn() } as never);
      listeners[0]!.onQueueEmpty();
      await client.startIncomingDelivery();
      await vi.waitFor(() => expect(received).toHaveLength(1));

      listeners[0]!.onConnectionInterrupted(new Error("socket lost") as never);
      await client.disconnect();
      await client.connect();

      const staleAck = vi.fn();
      listeners[0]!.onQueueEmpty();
      listeners[0]!.onIncomingMessage(new Uint8Array([1]), 200, { send: staleAck } as never);
      await client.startIncomingDelivery();
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(received).toHaveLength(1);
      expect(staleAck).not.toHaveBeenCalled();

      listeners[1]!.onQueueEmpty();
      await vi.waitFor(() => expect(received).toHaveLength(2));
      const complete = vi.spyOn(store, "complete").mockRejectedValueOnce(new Error("disk busy"));
      await expect(received[0]!.ack()).rejects.toThrow("disk busy");
      listeners[1]!.onQueueEmpty();
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(received).toHaveLength(2);
      await received[1]!.ack();
      expect(complete).toHaveBeenCalledTimes(2);
      expect(disconnects[0]).toHaveBeenCalledOnce();
    } finally {
      await client.disconnect();
      store.close();
      await rm(directory, { recursive: true });
    }
  });

  it("retries a transient durable-inbox drain failure", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "signal-ts-client-retry-"));
    const store = new SqliteSignalIncomingEnvelopeStore(path.join(directory, "incoming.sqlite"));
    await store.accept({ envelope: new Uint8Array([3, 2, 1]), serverDeliveredTimestamp: 100 });
    const listPending = vi.spyOn(store, "listPending");
    listPending.mockRejectedValueOnce(new Error("disk busy"));
    let listener: Parameters<SignalConnectionFactory>[0]["listener"] | undefined;
    const client = new SignalTsClient({
      account: {
        auth: { username: "user.1", password: "pass" },
        device: {
          aci: "11111111-1111-4111-8111-111111111111",
          deviceId: 1,
          registrationId: 42,
        },
      },
      incomingEnvelopeStore: store,
      connectionFactory: async (params) => {
        listener = params.listener;
        return {
          sendMessage: vi.fn(async () => undefined),
          disconnect: vi.fn(async () => undefined),
          connectionInfo: () => ({ localPort: 1, ipVersion: "IPv4", toString: () => "fake" }),
        };
      },
    });
    const received: Array<{ ack: () => Promise<void> }> = [];
    client.on("incoming", (incoming) => received.push(incoming));

    try {
      await client.connect();
      await client.startIncomingDelivery();
      listener!.onQueueEmpty();
      await vi.waitFor(() => expect(listPending).toHaveBeenCalled());
      await vi.waitFor(() => expect(received).toHaveLength(1), { timeout: 2_000 });
      expect(listPending).toHaveBeenCalledTimes(2);
      await received[0]!.ack();
    } finally {
      await client.disconnect();
      store.close();
      await rm(directory, { recursive: true });
    }
  });

  it("forces server redelivery when initial envelope persistence fails", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "signal-ts-client-accept-fail-"));
    const store = new SqliteSignalIncomingEnvelopeStore(path.join(directory, "incoming.sqlite"));
    const accept = vi.spyOn(store, "accept").mockRejectedValueOnce(new Error("disk unavailable"));
    let listener: Parameters<SignalConnectionFactory>[0]["listener"] | undefined;
    const disconnect = vi.fn(async () => undefined);
    const client = new SignalTsClient({
      account: {
        auth: { username: "user.1", password: "pass" },
        device: {
          aci: "11111111-1111-4111-8111-111111111111",
          deviceId: 1,
          registrationId: 42,
        },
      },
      incomingEnvelopeStore: store,
      connectionFactory: async (params) => {
        listener = params.listener;
        return {
          sendMessage: vi.fn(async () => undefined),
          disconnect,
          connectionInfo: () => ({ localPort: 1, ipVersion: "IPv4", toString: () => "fake" }),
        };
      },
    });
    const onDisconnected = vi.fn();
    client.on("disconnected", onDisconnected);
    const serverAck = vi.fn();

    try {
      await client.connect();
      listener!.onIncomingMessage(new Uint8Array([4]), 100, { send: serverAck } as never);
      listener!.onIncomingMessage(new Uint8Array([5]), 101, { send: serverAck } as never);
      await vi.waitFor(() => expect(onDisconnected).toHaveBeenCalledOnce(), { timeout: 5_000 });
      expect(accept).toHaveBeenCalledOnce();
      expect(serverAck).not.toHaveBeenCalled();
      expect(disconnect).toHaveBeenCalledOnce();
    } finally {
      await client.disconnect();
      store.close();
      await rm(directory, { recursive: true });
    }
  });

  it("forces server redelivery when the server ACK handle fails", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "signal-ts-client-ack-fail-"));
    const store = new SqliteSignalIncomingEnvelopeStore(path.join(directory, "incoming.sqlite"));
    let listener: Parameters<SignalConnectionFactory>[0]["listener"] | undefined;
    const disconnect = vi.fn(async () => undefined);
    const client = new SignalTsClient({
      account: {
        auth: { username: "user.1", password: "pass" },
        device: {
          aci: "11111111-1111-4111-8111-111111111111",
          deviceId: 1,
          registrationId: 42,
        },
      },
      incomingEnvelopeStore: store,
      connectionFactory: async (params) => {
        listener = params.listener;
        return {
          sendMessage: vi.fn(async () => undefined),
          disconnect,
          connectionInfo: () => ({ localPort: 1, ipVersion: "IPv4", toString: () => "fake" }),
        };
      },
    });
    const received: Array<{ ack: () => Promise<void> }> = [];
    const onDisconnected = vi.fn();
    client.on("incoming", (incoming) => received.push(incoming));
    client.on("disconnected", onDisconnected);

    try {
      await client.connect();
      listener!.onIncomingMessage(new Uint8Array([8]), 100, {
        send: () => {
          throw new Error("ACK socket closed");
        },
      } as never);
      listener!.onQueueEmpty();
      await vi.waitFor(() => expect(onDisconnected).toHaveBeenCalledOnce(), { timeout: 5_000 });
      expect(received).toEqual([]);
      expect(disconnect).toHaveBeenCalledOnce();
      await expect(store.listPending(16)).resolves.toHaveLength(1);
    } finally {
      await client.disconnect();
      store.close();
      await rm(directory, { recursive: true });
    }
  });

  it(
    "bounds durable-inbox delivery concurrency and refills on completion",
    async () => {
      const directory = await mkdtemp(path.join(os.tmpdir(), "signal-ts-client-bounded-"));
      const store = new SqliteSignalIncomingEnvelopeStore(
        path.join(directory, "incoming.sqlite"),
      );
      for (let value = 1; value <= 17; value += 1) {
        await store.accept({ envelope: new Uint8Array([value]), serverDeliveredTimestamp: value });
      }
      let listener: Parameters<SignalConnectionFactory>[0]["listener"] | undefined;
      const client = new SignalTsClient({
        account: {
          auth: { username: "user.1", password: "pass" },
          device: {
            aci: "11111111-1111-4111-8111-111111111111",
            deviceId: 1,
            registrationId: 42,
          },
        },
        incomingEnvelopeStore: store,
        connectionFactory: async (params) => {
          listener = params.listener;
          return {
            sendMessage: vi.fn(async () => undefined),
            disconnect: vi.fn(async () => undefined),
            connectionInfo: () => ({ localPort: 1, ipVersion: "IPv4", toString: () => "fake" }),
          };
        },
      });
      const received: Array<{ ack: () => Promise<void> }> = [];
      client.on("incoming", (incoming) => received.push(incoming));

      try {
        await client.connect();
        listener!.onQueueEmpty();
        await client.startIncomingDelivery();
        await vi.waitFor(() => expect(received).toHaveLength(16));
        await new Promise((resolve) => setTimeout(resolve, 50));
        expect(received).toHaveLength(16);

        await received[0]!.ack();
        await vi.waitFor(() => expect(received).toHaveLength(17));
      } finally {
        await client.disconnect();
        store.close();
        await rm(directory, { recursive: true });
      }
    },
    20_000,
  );

  it("recovers inbound decryption failures in signal-cli order", async () => {
    const client = createTestClient();
    const order: string[] = [];
    const archiveSessionsForPeer = vi.fn(async () => {
      order.push("archive");
    });
    const sendContentMessage = vi.fn(async () => {
      order.push("null-message");
      return { timestamp: 1 };
    });
    const sendRetryReceiptMessage = vi.fn(async () => {
      order.push("retry-receipt");
      return { timestamp: 2 };
    });
    Object.assign(client, {
      archiveSessionsForPeer,
      sendContentMessage,
      sendRetryReceiptMessage,
    });
    const preKeyAuth = { accessKey: new Uint8Array([1]) } as never;
    const stores = {} as Parameters<
      SignalTsClient["recoverIncomingDecryptionFailure"]
    >[0]["stores"];
    const retry = {
      recipientServiceId: "22222222-2222-4222-8222-222222222222",
      senderDeviceId: 2,
      timestamp: 99,
      ciphertextType: 2,
      originalContent: new Uint8Array([3]),
    };

    await client.recoverIncomingDecryptionFailure({ retry, stores, preKeyAuth });

    expect(order).toEqual(["archive", "null-message", "retry-receipt"]);
    expect(archiveSessionsForPeer).toHaveBeenCalledWith(
      expect.objectContaining({ serviceId: retry.recipientServiceId, stores }),
    );
    expect(sendContentMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        destination: retry.recipientServiceId,
        content: { nullMessage: { padding: expect.any(Uint8Array) } },
        preKeyAuth,
      }),
    );
    expect(sendRetryReceiptMessage).toHaveBeenCalledWith(
      expect.objectContaining({ destination: retry.recipientServiceId, retry, preKeyAuth }),
    );
  });

  it("archives every established device session during inbound recovery", async () => {
    const client = createTestClient();
    const destination = "22222222-2222-4222-8222-222222222222";
    const sessions = new Map(
      [1, 4].map((deviceId) => [
        deviceId,
        {
          archiveCurrentState: vi.fn(),
        },
      ]),
    );
    const saveSession = vi.fn(async (_address: ProtocolAddress, _session: unknown) => undefined);
    const sessionStore = {
      listDeviceIds: vi.fn(async () => [1, 4]),
      getSession: vi.fn(async (address: ProtocolAddress) => sessions.get(address.deviceId())),
      saveSession,
    } as unknown as Parameters<
      SignalTsClient["archiveSessionsForPeer"]
    >[0]["stores"]["sessionStore"];

    await client.archiveSessionsForPeer({
      serviceId: destination,
      stores: { sessionStore },
    });

    expect(sessions.get(1)?.archiveCurrentState).toHaveBeenCalledOnce();
    expect(sessions.get(4)?.archiveCurrentState).toHaveBeenCalledOnce();
    expect(saveSession.mock.calls.map(([address]) => address.deviceId())).toEqual([1, 4]);
  });

  it("does not archive sessions when recovery is canceled before the state lock", async () => {
    const client = createTestClient();
    const abortController = new AbortController();
    abortController.abort();
    const listDeviceIds = vi.fn(async () => [1]);
    const sessionStore = {
      listDeviceIds,
      getSession: vi.fn(async () => null),
      saveSession: vi.fn(async () => undefined),
    } as unknown as Parameters<
      SignalTsClient["archiveSessionsForPeer"]
    >[0]["stores"]["sessionStore"];

    await expect(
      client.archiveSessionsForPeer({
        serviceId: "22222222-2222-4222-8222-222222222222",
        stores: { sessionStore },
        abortSignal: abortController.signal,
      }),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(listDeviceIds).not.toHaveBeenCalled();
  });

  it("rejects recovery when the session store cannot enumerate peer devices", async () => {
    const client = createTestClient();
    const sessionStore = {
      getSession: vi.fn(async () => null),
      saveSession: vi.fn(async () => undefined),
    } as unknown as Parameters<
      SignalTsClient["archiveSessionsForPeer"]
    >[0]["stores"]["sessionStore"];

    await expect(
      client.archiveSessionsForPeer({
        serviceId: "22222222-2222-4222-8222-222222222222",
        stores: { sessionStore },
      }),
    ).rejects.toThrow("requires a session store with device enumeration");
  });

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
    const fetchPreKeyBundles = vi.fn(async () => [createFakePreKeyBundle(1, 42)]);
    const sendContentMessageLocked = vi.fn(
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
    const clientInternals = client as unknown as {
      fetchPreKeyBundles: typeof fetchPreKeyBundles;
      sendContentMessageLocked: typeof sendContentMessageLocked;
    };
    clientInternals.fetchPreKeyBundles = fetchPreKeyBundles;
    clientInternals.sendContentMessageLocked = sendContentMessageLocked;

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

  it("fetches prekeys outside the state lock so a stalled fetch cannot starve it", async () => {
    const client = createTestClient();
    let releaseFetch!: () => void;
    const fetchGate = new Promise<PreKeyBundle[]>((resolve) => {
      releaseFetch = () => resolve([createFakePreKeyBundle(1, 42)]);
    });
    const fetchPreKeyBundles = vi.fn(async () => await fetchGate);
    const sendContentMessageLocked = vi.fn(
      async (params: SendContentMessageParams): Promise<{ timestamp: number }> => ({
        timestamp: params.timestamp ?? 0,
      }),
    );
    const clientInternals = client as unknown as {
      fetchPreKeyBundles: typeof fetchPreKeyBundles;
      sendContentMessageLocked: typeof sendContentMessageLocked;
    };
    clientInternals.fetchPreKeyBundles = fetchPreKeyBundles;
    clientInternals.sendContentMessageLocked = sendContentMessageLocked;

    // Cold send: its prekey fetch stalls, but it stalls before taking the lock.
    const stalled = client.sendContentMessage(createContentParams("stalled-cold", 1));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(fetchPreKeyBundles).toHaveBeenCalledTimes(1);
    expect(sendContentMessageLocked).not.toHaveBeenCalled();

    // A warm send acquires the lock and completes while the fetch hangs.
    const warmParams = {
      ...createContentParams("warm", 2),
      stores: {
        sessionStore: { listDeviceIds: async () => [1] },
      } as unknown as SendContentMessageParams["stores"],
    };
    await expect(client.sendContentMessage(warmParams)).resolves.toEqual({ timestamp: 2 });

    releaseFetch();
    await expect(stalled).resolves.toEqual({ timestamp: 1 });
  });

  it("skips the prekey fetch when sessions already exist for the destination", async () => {
    const client = createTestClient();
    const fetchPreKeyBundles = vi.fn(async () => [createFakePreKeyBundle(1, 42)]);
    const sendContentMessageLocked = vi.fn(
      async (
        params: SendContentMessageParams & { preKeyBundles?: unknown },
      ): Promise<{ timestamp: number }> => ({ timestamp: params.timestamp ?? 0 }),
    );
    const clientInternals = client as unknown as {
      fetchPreKeyBundles: typeof fetchPreKeyBundles;
      sendContentMessageLocked: typeof sendContentMessageLocked;
    };
    clientInternals.fetchPreKeyBundles = fetchPreKeyBundles;
    clientInternals.sendContentMessageLocked = sendContentMessageLocked;

    const warmParams = {
      ...createContentParams("warm-skip", 7),
      stores: {
        sessionStore: { listDeviceIds: async () => [1, 2] },
      } as unknown as SendContentMessageParams["stores"],
    };
    await expect(client.sendContentMessage(warmParams)).resolves.toEqual({ timestamp: 7 });

    expect(fetchPreKeyBundles).not.toHaveBeenCalled();
    expect(sendContentMessageLocked.mock.calls[0]?.[0]?.preKeyBundles).toBeUndefined();
  });

  it("drops queued sends whose abort deadline passed while waiting for the lock", async () => {
    const client = createTestClient();
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const fetchPreKeyBundles = vi.fn(async () => [createFakePreKeyBundle(1, 42)]);
    const sendContentMessageLocked = vi.fn(
      async (params: SendContentMessageParams): Promise<{ timestamp: number }> => {
        if (params.traceId === "holder") {
          await firstGate;
        }
        return { timestamp: params.timestamp ?? 0 };
      },
    );
    const clientInternals = client as unknown as {
      fetchPreKeyBundles: typeof fetchPreKeyBundles;
      sendContentMessageLocked: typeof sendContentMessageLocked;
    };
    clientInternals.fetchPreKeyBundles = fetchPreKeyBundles;
    clientInternals.sendContentMessageLocked = sendContentMessageLocked;

    const holder = client.sendContentMessage(createContentParams("holder", 1));
    await new Promise((resolve) => setTimeout(resolve, 0));

    const abort = new AbortController();
    const queued = client.sendContentMessage({
      ...createContentParams("expired", 2),
      abortSignal: abort.signal,
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    abort.abort();

    releaseFirst();
    await expect(holder).resolves.toEqual({ timestamp: 1 });
    await expect(queued).rejects.toMatchObject({ name: "AbortError" });
    expect(sendContentMessageLocked).toHaveBeenCalledTimes(1);
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
    const sendMessage = vi.fn(
      async (_request: Parameters<SignalChatConnection["sendMessage"]>[0]) => {
        if (sendMessage.mock.calls.length === 1) {
          throw mismatch;
        }
      },
    );
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
      1, 2,
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
    const sendMessage = vi.fn(
      async (_request: Parameters<SignalChatConnection["sendMessage"]>[0]) => {
        if (sendMessage.mock.calls.length === 1) {
          throw mismatch;
        }
      },
    );
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
        sessionStore: sessionStore as Parameters<
          SignalTsClient["sendRetryReceiptMessage"]
        >[0]["stores"]["sessionStore"],
        identityStore: {} as Parameters<
          SignalTsClient["sendRetryReceiptMessage"]
        >[0]["stores"]["identityStore"],
      },
      preKeyBundles: [createFakePreKeyBundle(1, 287)],
    });

    expect(sendMessage).toHaveBeenCalledTimes(2);
    expect(fetchPreKeyBundles).toHaveBeenCalledTimes(1);
    expect(sendMessage.mock.calls[0]?.[0].contents.map((content) => content.deviceId)).toEqual([1]);
    expect(sendMessage.mock.calls[1]?.[0].contents.map((content) => content.deviceId)).toEqual([
      1, 2,
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

  it("fetches group member prekeys only for members without sessions", async () => {
    const client = createTestClient();
    const warm = "22222222-2222-4222-8222-222222222222";
    const cold = "33333333-3333-4333-8333-333333333333";
    const fetchPreKeyBundlesForGroupMember = vi.fn(
      async (_params: { destination: { getServiceIdString(): string } }) => [
        createFakePreKeyBundle(1, 42),
      ],
    );
    const sendGroupContentMessageLocked = vi.fn(
      async (params: {
        timestamp: number;
        recipients: unknown[];
        memberBundles: Map<string, unknown>;
      }) => ({ timestamp: params.timestamp, recipients: params.recipients.length }),
    );
    const clientInternals = client as unknown as {
      fetchPreKeyBundlesForGroupMember: typeof fetchPreKeyBundlesForGroupMember;
      sendGroupContentMessageLocked: typeof sendGroupContentMessageLocked;
    };
    clientInternals.fetchPreKeyBundlesForGroupMember = fetchPreKeyBundlesForGroupMember;
    clientInternals.sendGroupContentMessageLocked = sendGroupContentMessageLocked;

    await client.sendGroupMessage({
      traceId: "group-warm-cold",
      members: [Aci.fromUuid(warm), Aci.fromUuid(cold)],
      group: {
        masterKey: new Uint8Array(32),
        revision: 7,
        distributionId: "33333333-3333-4333-8333-333333333333",
      },
      body: "hello",
      timestamp: 456,
      stores: {
        sessionStore: {
          listDeviceIds: async (serviceId: string) => (serviceId === warm ? [1, 2] : []),
        },
      } as unknown as Parameters<SignalTsClient["sendGroupMessage"]>[0]["stores"],
    });

    expect(fetchPreKeyBundlesForGroupMember).toHaveBeenCalledTimes(1);
    expect(
      fetchPreKeyBundlesForGroupMember.mock.calls[0]?.[0].destination.getServiceIdString(),
    ).toBe(cold);
    const lockedParams = sendGroupContentMessageLocked.mock.calls[0]?.[0];
    expect(lockedParams?.memberBundles.has(cold)).toBe(true);
    expect(lockedParams?.memberBundles.has(warm)).toBe(false);
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
    expect(uploadAttachment.mock.calls[0]?.[0].attachment.contentType).toBe(LONG_TEXT_CONTENT_TYPE);
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

  describe("app-level keepalive", () => {
    const account = {
      auth: { username: "user.1", password: "pass" },
      device: {
        aci: "11111111-1111-4111-8111-111111111111",
        deviceId: 1,
        registrationId: 42,
      },
    } as const;

    it("marks transport activity on a successful keepalive", async () => {
      vi.useFakeTimers();
      try {
        const fetch = vi.fn(async () => ({
          status: 200,
          message: "",
          headers: [],
          body: undefined,
        }));
        const connection: SignalChatConnection = {
          sendMessage: vi.fn(async () => {}),
          sendSyncMessage: vi.fn(async () => {}),
          disconnect: vi.fn(async () => {}),
          connectionInfo: () => ({ localPort: 1, ipVersion: "IPv4", toString: () => "fake" }),
          fetch,
        };
        const client = new SignalTsClient({
          account,
          connectionFactory: async () => connection,
          keepaliveIntervalMs: 1_000,
          keepaliveTimeoutMs: 500,
        });
        await client.connect();
        const before = client.getLastTransportActivityAt();
        await vi.advanceTimersByTimeAsync(1_000);
        expect(fetch).toHaveBeenCalledWith(
          expect.objectContaining({ verb: "GET", path: "/v1/keepalive" }),
        );
        expect(client.getLastTransportActivityAt()).toBeGreaterThanOrEqual(before ?? 0);
        await client.disconnect();
      } finally {
        vi.useRealTimers();
      }
    });

    it("emits disconnected and tears down the socket when keepalive fails", async () => {
      vi.useFakeTimers();
      try {
        const disconnect = vi.fn(async () => {});
        const connection: SignalChatConnection = {
          sendMessage: vi.fn(async () => {}),
          sendSyncMessage: vi.fn(async () => {}),
          disconnect,
          connectionInfo: () => ({ localPort: 1, ipVersion: "IPv4", toString: () => "fake" }),
          fetch: vi.fn(async () => ({ status: 500, message: "", headers: [], body: undefined })),
        };
        const client = new SignalTsClient({
          account,
          connectionFactory: async () => connection,
          keepaliveIntervalMs: 1_000,
          keepaliveTimeoutMs: 500,
        });
        const onDisconnected = vi.fn();
        client.on("disconnected", onDisconnected);
        await client.connect();
        await vi.advanceTimersByTimeAsync(1_000);
        expect(onDisconnected).toHaveBeenCalledTimes(1);
        expect(disconnect).toHaveBeenCalledTimes(1);
      } finally {
        vi.useRealTimers();
      }
    });
  });
});
