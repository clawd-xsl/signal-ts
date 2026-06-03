import {
  Aci,
  Net,
  ProtocolAddress,
  SenderCertificate,
  SenderKeyDistributionMessage,
  type PreKeyBundle,
  type ServiceId,
  groupEncrypt,
  processPreKeyBundle,
  sealedSenderEncryptMessage,
} from "@signalapp/libsignal-client";
import "@signalapp/libsignal-client/dist/net/chat/AuthMessagesService.js";
import "@signalapp/libsignal-client/dist/net/chat/UnauthMessagesService.js";
import type {
  SendMessageRequest,
  SendSyncMessageRequest,
} from "@signalapp/libsignal-client/dist/net/chat/AuthMessagesService.js";
import type {
  SendSealedMessageRequest,
} from "@signalapp/libsignal-client/dist/net/chat/UnauthMessagesService.js";
import type { SignalAccountState, SignalEnvironment } from "./account.js";
import { resolveLibsignalEnvironment } from "./account.js";
import {
  uploadSignalAttachment,
  type AttachmentUploadConnection,
  type EncryptedSignalAttachment,
  type SignalAttachmentInput,
} from "./attachments.js";
import {
  createSignalDecryptionErrorPlaintextContent,
  encryptPayloadForDevice,
  padSignalMessageBody,
  type SignalRetryReceiptRequest,
} from "./crypto.js";
import { SignalEventHub } from "./events.js";
import type { SignalEventHandler, SignalEventName } from "./events.js";
import { SignalTsStateError } from "./errors.js";
import {
  createReactionSignalContent,
  createReceiptSignalContent,
  createStickerSignalContent,
  createTextSignalContent,
  createTypingSignalContent,
  encodeSignalContent,
  type SignalAttachmentPointer,
  type SignalBodyRange,
  type SignalContent,
  type SignalGroupContextV2,
  type SignalQuote,
  type SignalReaction,
  type SignalReceiptMessage,
  type SignalSticker,
  type SignalTypingMessage,
} from "./messages.js";
import { fetchRecipientPreKeys, type FetchPreKeysParams, type PreKeyAuth } from "./prekeys.js";
import type { LibsignalStores } from "./store.js";
import {
  resolveSignalRecipientTarget,
  type SignalRecipientTarget,
  type SignalTargetResolver,
} from "./targets.js";

export type SignalLogger = {
  debug?: (message: string) => void;
  info?: (message: string) => void;
  warn?: (message: string) => void;
  error?: (message: string, error?: unknown) => void;
};

export type SignalChatConnection = Pick<
  Net.AuthenticatedChatConnection,
  "disconnect" | "connectionInfo"
> & {
  getUploadForm?: AttachmentUploadConnection["getUploadForm"];
  sendMessage: (
    request: SendMessageRequest,
    options?: Net.RequestOptions,
  ) => Promise<void>;
  sendSyncMessage?: (
    request: SendSyncMessageRequest,
    options?: Net.RequestOptions,
  ) => Promise<void>;
};

export type SignalSealedSenderConnection = Pick<
  Net.UnauthenticatedChatConnection,
  "disconnect" | "connectionInfo"
> & {
  sendMessage: (
    request: SendSealedMessageRequest,
    options?: Net.RequestOptions,
  ) => Promise<void>;
};

export type SignalConnectionFactory = (params: {
  net: Net.Net;
  account: SignalAccountState;
  listener: Net.ChatServiceListener;
  abortSignal?: AbortSignal;
}) => Promise<SignalChatConnection>;

export type SignalSealedSenderConnectionFactory = (params: {
  net: Net.Net;
  abortSignal?: AbortSignal;
}) => Promise<SignalSealedSenderConnection>;

export type SignalTsClientOptions = {
  account: SignalAccountState;
  environment?: SignalEnvironment;
  userAgent?: string;
  receiveStories?: boolean;
  logger?: SignalLogger;
  connectionFactory?: SignalConnectionFactory;
  sealedSenderConnectionFactory?: SignalSealedSenderConnectionFactory;
  targetResolver?: SignalTargetResolver;
};

export type SendEncryptedMessageParams = {
  destination: ServiceId | string;
  timestamp?: number;
  contents: SendMessageRequest["contents"];
  onlineOnly?: boolean;
  urgent?: boolean;
  abortSignal?: AbortSignal;
};

export type SendTextMessageParams = {
  destination: SignalRecipientTarget;
  body: string;
} & SendContentMessageBaseParams;

export type SendMessageParams = {
  destination: SignalRecipientTarget;
  body?: string;
  attachments?: SignalAttachmentPointer[];
  quote?: SignalQuote;
  bodyRanges?: SignalBodyRange[];
  groupV2?: SignalGroupContextV2;
} & SendContentMessageBaseParams;

export type SendContentMessageBaseParams = {
  stores: Pick<LibsignalStores, "identityStore" | "sessionStore">;
  preKeyBundles?: PreKeyBundle[];
  preKeyAuth?: PreKeyAuth;
  timestamp?: number;
  onlineOnly?: boolean;
  urgent?: boolean;
  abortSignal?: AbortSignal;
};

export type SendStickerMessageParams = {
  destination: SignalRecipientTarget;
  sticker: SignalSticker;
} & SendContentMessageBaseParams;

export type SendContentMessageParams = {
  destination: SignalRecipientTarget;
  content: SignalContent;
} & SendContentMessageBaseParams;

export type SendRetryReceiptMessageParams = {
  destination: SignalRecipientTarget;
  retry: SignalRetryReceiptRequest;
} & Omit<SendContentMessageBaseParams, "preKeyBundles" | "preKeyAuth">;

export type SendSealedContentMessageParams = {
  destination: SignalRecipientTarget;
  content: SignalContent;
  senderCertificate: SenderCertificate;
  auth?: SealedSenderAuth;
} & SendContentMessageBaseParams;

export type SealedSenderAuth =
  | { kind: "unrestricted" }
  | { kind: "access-key"; accessKey: Uint8Array<ArrayBuffer> }
  | { kind: "story" };

export type SendSyncMessageParams = {
  timestamp?: number;
  contents: SendSyncMessageRequest["contents"];
  urgent?: boolean;
  abortSignal?: AbortSignal;
};

export type SendSyncContentMessageParams = {
  content: SignalContent;
  stores: Pick<LibsignalStores, "identityStore" | "sessionStore">;
  preKeyBundles: PreKeyBundle[];
  timestamp?: number;
  urgent?: boolean;
  abortSignal?: AbortSignal;
};

export type SendReactionMessageParams = {
  destination: SignalRecipientTarget;
  reaction: SignalReaction;
} & SendContentMessageBaseParams;

export type SendReceiptMessageParams = {
  destination: SignalRecipientTarget;
  receipt: SignalReceiptMessage;
} & SendContentMessageBaseParams;

export type SendTypingMessageParams = {
  destination: SignalRecipientTarget;
  typing: SignalTypingMessage;
} & SendContentMessageBaseParams;

export type SignalGroupMessageTarget = {
  members: SignalRecipientTarget[];
  group: {
    masterKey: Uint8Array<ArrayBuffer>;
    revision?: number;
    distributionId: string;
  };
};

export type SendGroupMessageParams = SignalGroupMessageTarget & {
  body?: string;
  attachments?: SignalAttachmentPointer[];
  quote?: SignalQuote;
  bodyRanges?: SignalBodyRange[];
  stores: Pick<LibsignalStores, "identityStore" | "sessionStore" | "senderKeyStore">;
  memberPreKeyBundles?: ReadonlyMap<string, PreKeyBundle[]>;
  preKeyAuth?: PreKeyAuth;
  timestamp?: number;
  onlineOnly?: boolean;
  urgent?: boolean;
  abortSignal?: AbortSignal;
};

export type SendGroupStickerMessageParams = SignalGroupMessageTarget & {
  sticker: SignalSticker;
  stores: Pick<LibsignalStores, "identityStore" | "sessionStore" | "senderKeyStore">;
  memberPreKeyBundles?: ReadonlyMap<string, PreKeyBundle[]>;
  preKeyAuth?: PreKeyAuth;
  timestamp?: number;
  onlineOnly?: boolean;
  urgent?: boolean;
  abortSignal?: AbortSignal;
};

export type SendGroupReactionMessageParams = SignalGroupMessageTarget & {
  reaction: SignalReaction;
  stores: Pick<LibsignalStores, "identityStore" | "sessionStore" | "senderKeyStore">;
  memberPreKeyBundles?: ReadonlyMap<string, PreKeyBundle[]>;
  preKeyAuth?: PreKeyAuth;
  timestamp?: number;
  onlineOnly?: boolean;
  urgent?: boolean;
  abortSignal?: AbortSignal;
};

type SendGroupContentMessageParams = SignalGroupMessageTarget & {
  content: SignalContent;
  stores: Pick<LibsignalStores, "identityStore" | "sessionStore" | "senderKeyStore">;
  memberPreKeyBundles?: ReadonlyMap<string, PreKeyBundle[]>;
  preKeyAuth?: PreKeyAuth;
  timestamp?: number;
  onlineOnly?: boolean;
  urgent?: boolean;
  abortSignal?: AbortSignal;
};

export type UploadAttachmentParams = {
  attachment: SignalAttachmentInput;
  fetch?: typeof globalThis.fetch;
  abortSignal?: AbortSignal;
};

const DEFAULT_USER_AGENT = "OpenClaw signal-ts/0.0.0";

export class SignalTsClient {
  private readonly events = new SignalEventHub();
  private readonly logger: SignalLogger | undefined;
  private readonly connectionFactory: SignalConnectionFactory | undefined;
  private readonly sealedSenderConnectionFactory: SignalSealedSenderConnectionFactory | undefined;
  private net: Net.Net | undefined;
  private connection: SignalChatConnection | undefined;

  constructor(private readonly options: SignalTsClientOptions) {
    this.logger = options.logger;
    this.connectionFactory = options.connectionFactory;
    this.sealedSenderConnectionFactory = options.sealedSenderConnectionFactory;
  }

  on<K extends SignalEventName>(event: K, handler: SignalEventHandler<K>): () => void {
    return this.events.on(event, handler);
  }

  async connect(abortSignal?: AbortSignal): Promise<void> {
    if (this.connection) {
      return;
    }
    const net =
      this.net ??
      new Net.Net({
        env: resolveLibsignalEnvironment(this.options.environment ?? "production"),
        userAgent: this.options.userAgent ?? DEFAULT_USER_AGENT,
      });
    this.net = net;
    const listener = this.createListener();
    this.connection = await (this.connectionFactory ?? defaultConnectionFactory)({
      net,
      account: this.options.account,
      listener,
      ...(abortSignal ? { abortSignal } : {}),
    });
    this.logger?.info?.(`connected to Signal chat (${this.connection.connectionInfo().toString()})`);
  }

  async disconnect(): Promise<void> {
    const connection = this.connection;
    this.connection = undefined;
    if (connection) {
      await connection.disconnect();
    }
  }

  async sendEncryptedMessage(params: SendEncryptedMessageParams): Promise<{ timestamp: number }> {
    const connection = this.connection;
    if (!connection) {
      throw new SignalTsStateError("SignalTsClient is not connected");
    }
    const timestamp = params.timestamp ?? Date.now();
    await connection.sendMessage(
      {
        destination: resolveDestination(params.destination),
        timestamp,
        contents: params.contents,
        onlineOnly: params.onlineOnly ?? false,
        urgent: params.urgent ?? true,
      },
      params.abortSignal ? { abortSignal: params.abortSignal } : undefined,
    );
    return { timestamp };
  }

  async sendTextMessage(params: SendTextMessageParams): Promise<{ timestamp: number }> {
    return await this.sendMessage(params);
  }

  async sendMessage(params: SendMessageParams): Promise<{ timestamp: number }> {
    if (!params.body && (!params.attachments || params.attachments.length === 0)) {
      throw new SignalTsStateError("Signal message requires body or attachments");
    }
    const timestamp = params.timestamp ?? Date.now();
    const contentParams: Parameters<typeof createTextSignalContent>[0] = {
      body: params.body ?? "",
      timestamp,
    };
    if (params.attachments !== undefined) {
      contentParams.attachments = params.attachments;
    }
    if (params.quote !== undefined) {
      contentParams.quote = params.quote;
    }
    if (params.bodyRanges !== undefined) {
      contentParams.bodyRanges = params.bodyRanges;
    }
    if (params.groupV2 !== undefined) {
      contentParams.groupV2 = params.groupV2;
    }
    return await this.sendContentMessage({
      ...params,
      timestamp,
      content: createTextSignalContent(contentParams),
    });
  }

  async sendReactionMessage(params: SendReactionMessageParams): Promise<{ timestamp: number }> {
    const timestamp = params.timestamp ?? Date.now();
    return await this.sendContentMessage({
      ...params,
      timestamp,
      content: createReactionSignalContent(params.reaction, { timestamp }),
    });
  }

  async sendReceiptMessage(params: SendReceiptMessageParams): Promise<{ timestamp: number }> {
    return await this.sendContentMessage({
      ...params,
      content: createReceiptSignalContent(params.receipt),
    });
  }

  async sendTypingMessage(params: SendTypingMessageParams): Promise<{ timestamp: number }> {
    const typing: SignalTypingMessage = {
      timestamp: params.typing.timestamp ?? Date.now(),
    };
    if (params.typing.action !== undefined) {
      typing.action = params.typing.action;
    }
    if (params.typing.groupId !== undefined) {
      typing.groupId = params.typing.groupId;
    }
    return await this.sendContentMessage({
      ...params,
      content: createTypingSignalContent(typing),
    });
  }

  async sendStickerMessage(params: SendStickerMessageParams): Promise<{ timestamp: number }> {
    const timestamp = params.timestamp ?? Date.now();
    return await this.sendContentMessage({
      ...params,
      timestamp,
      content: createStickerSignalContent({
        sticker: params.sticker,
        timestamp,
      }),
    });
  }

  async sendContentMessage(params: SendContentMessageParams): Promise<{ timestamp: number }> {
    const timestamp = params.timestamp ?? Date.now();
    const destination = await this.resolveRecipient(params.destination, params.abortSignal);
    const fetchParams: FetchPreKeysParams = { target: destination };
    if (params.preKeyAuth !== undefined) {
      fetchParams.auth = params.preKeyAuth;
    }
    if (params.abortSignal !== undefined) {
      fetchParams.abortSignal = params.abortSignal;
    }
    if (this.options.userAgent !== undefined) {
      fetchParams.userAgent = this.options.userAgent;
    }
    const preKeyBundles =
      params.preKeyBundles ??
      (await fetchRecipientPreKeys(fetchParams)).preKeyBundles;
    if (preKeyBundles.length === 0) {
      throw new SignalTsStateError("Signal recipient has no available prekey bundles");
    }
    const localAddress = ProtocolAddress.new(
      Aci.fromUuid(this.options.account.device.aci),
      this.options.account.device.deviceId,
    );
    const payload = encodeSignalContent(params.content);
    const contents = await Promise.all(
      preKeyBundles.map(async (bundle) => {
        const remoteAddress = ProtocolAddress.new(destination, bundle.deviceId());
        const existingSession = await params.stores.sessionStore.getSession(remoteAddress);
        const device = {
          serviceId: destination,
          deviceId: bundle.deviceId(),
          registrationId: bundle.registrationId(),
        };
        if (!existingSession) {
          Object.assign(device, { preKeyBundle: bundle });
        }
        return await encryptPayloadForDevice({
          localAddress,
          device,
          payload,
          stores: params.stores,
        });
      }),
    );
    const sendParams: SendEncryptedMessageParams = {
      destination,
      timestamp,
      contents,
    };
    if (params.onlineOnly !== undefined) {
      sendParams.onlineOnly = params.onlineOnly;
    }
    if (params.urgent !== undefined) {
      sendParams.urgent = params.urgent;
    }
    if (params.abortSignal !== undefined) {
      sendParams.abortSignal = params.abortSignal;
    }
    return await this.sendEncryptedMessage(sendParams);
  }

  async sendRetryReceiptMessage(
    params: SendRetryReceiptMessageParams,
  ): Promise<{ timestamp: number }> {
    const timestamp = params.timestamp ?? Date.now();
    const destination = await this.resolveRecipient(params.destination, params.abortSignal);
    const remoteAddress = ProtocolAddress.new(destination, params.retry.senderDeviceId);
    const session = await params.stores.sessionStore.getSession(remoteAddress);
    if (!session) {
      throw new SignalTsStateError(
        `Signal session is missing for retry receipt recipient ${destination.getServiceIdString()}.${params.retry.senderDeviceId}`,
      );
    }
    return await this.sendEncryptedMessage({
      destination,
      timestamp,
      contents: [
        {
          deviceId: params.retry.senderDeviceId,
          registrationId: session.remoteRegistrationId(),
          contents: createSignalDecryptionErrorPlaintextContent(params.retry).asCiphertextMessage(),
        },
      ],
      ...(params.onlineOnly !== undefined ? { onlineOnly: params.onlineOnly } : {}),
      ...(params.urgent !== undefined ? { urgent: params.urgent } : {}),
      ...(params.abortSignal ? { abortSignal: params.abortSignal } : {}),
    });
  }

  async sendSealedContentMessage(
    params: SendSealedContentMessageParams,
  ): Promise<{ timestamp: number }> {
    const timestamp = params.timestamp ?? Date.now();
    const destination = await this.resolveRecipient(params.destination, params.abortSignal);
    const fetchParams: FetchPreKeysParams = { target: destination };
    if (params.preKeyAuth !== undefined) {
      fetchParams.auth = params.preKeyAuth;
    }
    if (params.abortSignal !== undefined) {
      fetchParams.abortSignal = params.abortSignal;
    }
    if (this.options.userAgent !== undefined) {
      fetchParams.userAgent = this.options.userAgent;
    }
    const preKeyBundles =
      params.preKeyBundles ??
      (await fetchRecipientPreKeys(fetchParams)).preKeyBundles;
    if (preKeyBundles.length === 0) {
      throw new SignalTsStateError("Signal recipient has no available prekey bundles");
    }
    const localAddress = this.localAddress();
    const payload = encodeSignalContent(params.content);
    const contents = await Promise.all(
      preKeyBundles.map(async (bundle) => {
        const remoteAddress = ProtocolAddress.new(destination, bundle.deviceId());
        const existingSession = await params.stores.sessionStore.getSession(remoteAddress);
        if (!existingSession) {
          await processPreKeyBundle(
            bundle,
            remoteAddress,
            localAddress,
            params.stores.sessionStore,
            params.stores.identityStore,
          );
        }
        return {
          deviceId: bundle.deviceId(),
          registrationId: bundle.registrationId(),
          contents: await sealedSenderEncryptMessage(
            padSignalMessageBody(payload),
            remoteAddress,
            params.senderCertificate,
            params.stores.sessionStore,
            params.stores.identityStore,
          ),
        };
      }),
    );
    const connection = await this.createSealedSenderConnection(params.abortSignal);
    try {
      await connection.sendMessage(
        {
          destination,
          timestamp,
          contents,
          auth: resolveSealedSenderAuth(params.auth),
          onlineOnly: params.onlineOnly ?? false,
          urgent: params.urgent ?? true,
        },
        params.abortSignal ? { abortSignal: params.abortSignal } : undefined,
      );
    } finally {
      await connection.disconnect();
    }
    return { timestamp };
  }

  async sendSyncMessage(params: SendSyncMessageParams): Promise<{ timestamp: number }> {
    const connection = this.connection;
    if (!connection) {
      throw new SignalTsStateError("SignalTsClient is not connected");
    }
    if (!connection.sendSyncMessage) {
      throw new SignalTsStateError("Signal chat connection does not support sync messages");
    }
    const timestamp = params.timestamp ?? Date.now();
    await connection.sendSyncMessage(
      {
        timestamp,
        contents: params.contents,
        urgent: params.urgent ?? true,
      },
      params.abortSignal ? { abortSignal: params.abortSignal } : undefined,
    );
    return { timestamp };
  }

  async sendSyncContentMessage(
    params: SendSyncContentMessageParams,
  ): Promise<{ timestamp: number }> {
    if (params.preKeyBundles.length === 0) {
      throw new SignalTsStateError("Signal sync message requires linked-device prekey bundles");
    }
    const timestamp = params.timestamp ?? Date.now();
    const localAddress = this.localAddress();
    const destination = Aci.fromUuid(this.options.account.device.aci);
    const payload = encodeSignalContent(params.content);
    const contents = await Promise.all(
      params.preKeyBundles.map(async (bundle) => {
        const remoteAddress = ProtocolAddress.new(destination, bundle.deviceId());
        const existingSession = await params.stores.sessionStore.getSession(remoteAddress);
        const device = {
          serviceId: destination,
          deviceId: bundle.deviceId(),
          registrationId: bundle.registrationId(),
        };
        if (!existingSession) {
          Object.assign(device, { preKeyBundle: bundle });
        }
        return await encryptPayloadForDevice({
          localAddress,
          device,
          payload,
          stores: params.stores,
        });
      }),
    );
    return await this.sendSyncMessage({
      timestamp,
      contents,
      ...(params.urgent !== undefined ? { urgent: params.urgent } : {}),
      ...(params.abortSignal ? { abortSignal: params.abortSignal } : {}),
    });
  }

  async sendGroupMessage(params: SendGroupMessageParams): Promise<{
    timestamp: number;
    recipients: number;
  }> {
    if (!params.body && (!params.attachments || params.attachments.length === 0)) {
      throw new SignalTsStateError("Signal group message requires body or attachments");
    }
    const timestamp = params.timestamp ?? Date.now();
    const contentParams: Parameters<typeof createTextSignalContent>[0] = {
      body: params.body ?? "",
      timestamp,
      groupV2: {
        masterKey: params.group.masterKey,
        ...(params.group.revision !== undefined ? { revision: params.group.revision } : {}),
      },
    };
    if (params.attachments !== undefined) {
      contentParams.attachments = params.attachments;
    }
    if (params.quote !== undefined) {
      contentParams.quote = params.quote;
    }
    if (params.bodyRanges !== undefined) {
      contentParams.bodyRanges = params.bodyRanges;
    }
    return await this.sendGroupContentMessage({
      ...params,
      timestamp,
      content: createTextSignalContent(contentParams),
    });
  }

  async sendGroupStickerMessage(params: SendGroupStickerMessageParams): Promise<{
    timestamp: number;
    recipients: number;
  }> {
    const timestamp = params.timestamp ?? Date.now();
    return await this.sendGroupContentMessage({
      ...params,
      timestamp,
      content: createStickerSignalContent({
        sticker: params.sticker,
        timestamp,
        groupV2: {
          masterKey: params.group.masterKey,
          ...(params.group.revision !== undefined ? { revision: params.group.revision } : {}),
        },
      }),
    });
  }

  async sendGroupReactionMessage(params: SendGroupReactionMessageParams): Promise<{
    timestamp: number;
    recipients: number;
  }> {
    const timestamp = params.timestamp ?? Date.now();
    return await this.sendGroupContentMessage({
      ...params,
      timestamp,
      content: createReactionSignalContent(params.reaction, {
        timestamp,
        groupV2: {
          masterKey: params.group.masterKey,
          ...(params.group.revision !== undefined ? { revision: params.group.revision } : {}),
        },
      }),
    });
  }

  private async sendGroupContentMessage(params: SendGroupContentMessageParams): Promise<{
    timestamp: number;
    recipients: number;
  }> {
    const timestamp = params.timestamp ?? Date.now();
    const localAddress = ProtocolAddress.new(
      Aci.fromUuid(this.options.account.device.aci),
      this.options.account.device.deviceId,
    );
    const recipients = await this.resolveGroupRecipients(params.members, params.abortSignal);
    if (recipients.length === 0) {
      throw new SignalTsStateError("Signal group message has no remote recipients");
    }
    const senderKeyDistribution = await SenderKeyDistributionMessage.create(
      localAddress,
      params.group.distributionId,
      params.stores.senderKeyStore,
    );
    const memberBundles = await Promise.all(
      recipients.map(async (destination) => {
        const bundles =
          params.memberPreKeyBundles?.get(destination.getServiceIdString()) ??
          (await this.fetchPreKeyBundlesForGroupMember({
            destination,
            preKeyAuth: params.preKeyAuth,
            abortSignal: params.abortSignal,
          }));
        await this.sendContentMessage({
          destination,
          content: { senderKeyDistributionMessage: senderKeyDistribution.serialize() },
          stores: params.stores,
          preKeyBundles: bundles,
          timestamp,
          ...(params.onlineOnly !== undefined ? { onlineOnly: params.onlineOnly } : {}),
          ...(params.urgent !== undefined ? { urgent: params.urgent } : {}),
          ...(params.abortSignal ? { abortSignal: params.abortSignal } : {}),
        });
        return { destination, bundles };
      }),
    );
    const groupCiphertext = await groupEncrypt(
      localAddress,
      params.group.distributionId,
      params.stores.senderKeyStore,
      padSignalMessageBody(encodeSignalContent(params.content)),
    );
    await Promise.all(
      memberBundles.map(async ({ destination, bundles }) => {
        await this.sendEncryptedMessage({
          destination,
          timestamp,
          contents: bundles.map((bundle) => ({
            deviceId: bundle.deviceId(),
            registrationId: bundle.registrationId(),
            contents: groupCiphertext,
          })),
          ...(params.onlineOnly !== undefined ? { onlineOnly: params.onlineOnly } : {}),
          ...(params.urgent !== undefined ? { urgent: params.urgent } : {}),
          ...(params.abortSignal ? { abortSignal: params.abortSignal } : {}),
        });
      }),
    );
    return { timestamp, recipients: recipients.length };
  }

  async uploadAttachment(params: UploadAttachmentParams): Promise<EncryptedSignalAttachment> {
    const connection = this.connection;
    if (!connection) {
      throw new SignalTsStateError("SignalTsClient is not connected");
    }
    if (!connection.getUploadForm) {
      throw new SignalTsStateError("Signal chat connection does not support attachment uploads");
    }
    const getUploadForm: AttachmentUploadConnection["getUploadForm"] = (request, options) =>
      connection.getUploadForm!.call(connection, request, options);
    return await uploadSignalAttachment({
      connection: { getUploadForm },
      attachment: params.attachment,
      ...(params.fetch ? { fetch: params.fetch } : {}),
      ...(params.abortSignal ? { abortSignal: params.abortSignal } : {}),
    });
  }

  private async resolveRecipient(
    target: SignalRecipientTarget,
    abortSignal: AbortSignal | undefined,
  ): Promise<ServiceId> {
    const params: Parameters<typeof resolveSignalRecipientTarget>[0] = {
      target,
      account: this.options.account,
    };
    if (this.net) {
      params.net = this.net;
    }
    if (this.options.targetResolver) {
      params.resolver = this.options.targetResolver;
    }
    if (abortSignal) {
      params.abortSignal = abortSignal;
    }
    return await resolveSignalRecipientTarget(params);
  }

  private async resolveGroupRecipients(
    members: SignalRecipientTarget[],
    abortSignal: AbortSignal | undefined,
  ): Promise<ServiceId[]> {
    const localAci = Aci.fromUuid(this.options.account.device.aci).getServiceIdString();
    const recipients = new Map<string, ServiceId>();
    for (const member of members) {
      const serviceId = await this.resolveRecipient(member, abortSignal);
      const key = serviceId.getServiceIdString();
      if (key !== localAci) {
        recipients.set(key, serviceId);
      }
    }
    return [...recipients.values()];
  }

  private async fetchPreKeyBundles({
    destination,
    preKeyAuth,
    abortSignal,
  }: {
    destination: ServiceId;
    preKeyAuth?: PreKeyAuth;
    abortSignal?: AbortSignal;
  }): Promise<PreKeyBundle[]> {
    const fetchParams: FetchPreKeysParams = { target: destination };
    if (preKeyAuth !== undefined) {
      fetchParams.auth = preKeyAuth;
    }
    if (abortSignal !== undefined) {
      fetchParams.abortSignal = abortSignal;
    }
    if (this.options.userAgent !== undefined) {
      fetchParams.userAgent = this.options.userAgent;
    }
    return (await fetchRecipientPreKeys(fetchParams)).preKeyBundles;
  }

  private async fetchPreKeyBundlesForGroupMember({
    destination,
    preKeyAuth,
    abortSignal,
  }: {
    destination: ServiceId;
    preKeyAuth: PreKeyAuth | undefined;
    abortSignal: AbortSignal | undefined;
  }): Promise<PreKeyBundle[]> {
    const bundleParams: Parameters<typeof this.fetchPreKeyBundles>[0] = { destination };
    if (preKeyAuth !== undefined) {
      bundleParams.preKeyAuth = preKeyAuth;
    }
    if (abortSignal !== undefined) {
      bundleParams.abortSignal = abortSignal;
    }
    return await this.fetchPreKeyBundles(bundleParams);
  }

  private localAddress(): ProtocolAddress {
    return ProtocolAddress.new(
      Aci.fromUuid(this.options.account.device.aci),
      this.options.account.device.deviceId,
    );
  }

  private async createSealedSenderConnection(
    abortSignal: AbortSignal | undefined,
  ): Promise<SignalSealedSenderConnection> {
    const net =
      this.net ??
      new Net.Net({
        env: resolveLibsignalEnvironment(this.options.environment ?? "production"),
        userAgent: this.options.userAgent ?? DEFAULT_USER_AGENT,
      });
    this.net = net;
    return await (this.sealedSenderConnectionFactory ?? defaultSealedSenderConnectionFactory)({
      net,
      ...(abortSignal ? { abortSignal } : {}),
    });
  }

  private createListener(): Net.ChatServiceListener {
    return {
      onConnectionInterrupted: (cause) => {
        this.logger?.warn?.(`Signal chat connection interrupted: ${cause?.message ?? "unknown"}`);
        this.events.emit("disconnected", cause);
      },
      onIncomingMessage: (envelope, timestamp, ack) => {
        this.events.emit("incoming", {
          envelope,
          timestamp,
          ack: () => ack.send(200),
        });
      },
      onQueueEmpty: () => {
        this.events.emit("queueEmpty", undefined);
      },
      onReceivedAlerts: (alerts) => {
        if (alerts.length > 0) {
          this.logger?.warn?.(`Signal chat alerts: ${alerts.join(", ")}`);
        }
      },
    };
  }
}

async function defaultConnectionFactory({
  net,
  account,
  listener,
  abortSignal,
}: {
  net: Net.Net;
  account: SignalAccountState;
  listener: Net.ChatServiceListener;
  abortSignal?: AbortSignal;
}): Promise<SignalChatConnection> {
  return await net.connectAuthenticatedChat(
    account.auth.username,
    account.auth.password,
    account.receiveStories ?? false,
    listener,
    abortSignal ? { abortSignal } : undefined,
  ) as unknown as SignalChatConnection;
}

async function defaultSealedSenderConnectionFactory({
  net,
  abortSignal,
}: {
  net: Net.Net;
  abortSignal?: AbortSignal;
}): Promise<SignalSealedSenderConnection> {
  return await net.connectUnauthenticatedChat(
    { onConnectionInterrupted: () => {} },
    abortSignal ? { abortSignal } : undefined,
  ) as unknown as SignalSealedSenderConnection;
}

function resolveDestination(destination: ServiceId | string): ServiceId {
  if (typeof destination !== "string") {
    return destination;
  }
  return Aci.fromUuid(destination);
}

function resolveSealedSenderAuth(auth: SealedSenderAuth | undefined): SendSealedMessageRequest["auth"] {
  if (!auth || auth.kind === "unrestricted") {
    return "unrestricted";
  }
  if (auth.kind === "story") {
    return "story";
  }
  return { accessKey: auth.accessKey };
}
