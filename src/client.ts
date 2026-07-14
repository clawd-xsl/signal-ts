import {
  Aci,
  ErrorCode,
  Net,
  ProtocolAddress,
  SenderCertificate,
  SenderKeyDistributionMessage,
  type MismatchedDevicesEntry,
  type MismatchedDevicesError,
  type PreKeyBundle,
  ServiceId,
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
  type FetchLike,
  type SignalAttachmentInput,
} from "./attachments.js";
import { bytesToHex, utf8Bytes } from "./bytes.js";
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
  decodeSignalEnvelope,
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
import { signalAttachmentFetch } from "./signal-cdn-fetch.js";
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
  traceId?: string;
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
  traceId?: string;
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
} & Omit<SendContentMessageBaseParams, "preKeyBundles" | "preKeyAuth"> & {
  preKeyBundles?: PreKeyBundle[];
  preKeyAuth?: PreKeyAuth;
};

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
  traceId?: string;
  timestamp?: number;
  contents: SendSyncMessageRequest["contents"];
  urgent?: boolean;
  abortSignal?: AbortSignal;
};

export type SendSyncContentMessageParams = {
  traceId?: string;
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
  traceId?: string;
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
  traceId?: string;
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
  traceId?: string;
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
  traceId?: string;
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
  traceId?: string;
  attachment: SignalAttachmentInput;
  fetch?: FetchLike;
  abortSignal?: AbortSignal;
};

const DEFAULT_USER_AGENT = "OpenClaw signal-ts/0.0.0";
const SIGNAL_LONG_TEXT_CONTENT_TYPE = "text/x-signal-plain";
const SIGNAL_MESSAGE_BODY_MAX_BYTES = 2000;

let signalTraceSequence = 0;

function createSignalTraceId(prefix: string): string {
  signalTraceSequence = (signalTraceSequence + 1) % Number.MAX_SAFE_INTEGER;
  return `${prefix}-${Date.now().toString(36)}-${signalTraceSequence.toString(36)}`;
}

function describeSignalError(err: unknown): string {
  if (err instanceof Error) {
    const cause =
      "cause" in err && err.cause !== undefined
        ? `; cause=${describeSignalError(err.cause)}`
        : "";
    return `${err.name}: ${err.message}${cause}`;
  }
  if (typeof err === "string") {
    return err;
  }
  if (err === undefined) {
    return "undefined";
  }
  if (err === null) {
    return "null";
  }
  if (typeof err === "number" || typeof err === "boolean" || typeof err === "bigint") {
    return err.toString();
  }
  if (typeof err === "symbol") {
    return err.description ? `Symbol(${err.description})` : "Symbol()";
  }
  try {
    return JSON.stringify(err) ?? Object.prototype.toString.call(err);
  } catch {
    return Object.prototype.toString.call(err);
  }
}

function describeServiceId(serviceId: ServiceId | string): string {
  return typeof serviceId === "string" ? serviceId : serviceId.getServiceIdString();
}

function describeRecipientTarget(target: SignalRecipientTarget): string {
  if (target instanceof ServiceId) {
    return `aci:${target.getServiceIdString()}`;
  }
  if (typeof target === "string") {
    return target.trim();
  }
  if (target.kind === "aci") {
    return `aci:${describeServiceId(target.aci)}`;
  }
  if (target.kind === "e164") {
    return `e164:${target.e164}`;
  }
  return `username:${target.username}`;
}

function describeSignalContent(content: SignalContent): string {
  const parts: string[] = [];
  if (content.dataMessage) {
    const message = content.dataMessage;
    parts.push(
      [
        "data",
        describeMessageBody(message.body),
        `attachments=${message.attachments?.length ?? 0}`,
        `bodyRanges=${message.bodyRanges?.length ?? 0}`,
        `quote=${message.quote ? "yes" : "no"}`,
        `sticker=${message.sticker ? "yes" : "no"}`,
        `reaction=${message.reaction ? "yes" : "no"}`,
        `groupV2=${message.groupV2 ? "yes" : "no"}`,
      ].join(":"),
    );
  }
  if (content.receiptMessage) {
    parts.push(
      `receipt:type=${content.receiptMessage.type ?? "unknown"} timestamps=${content.receiptMessage.timestamps?.length ?? 0}`,
    );
  }
  if (content.typingMessage) {
    parts.push(
      `typing:action=${content.typingMessage.action ?? "unknown"} timestamp=${content.typingMessage.timestamp ?? "none"} group=${content.typingMessage.groupId ? "yes" : "no"}`,
    );
  }
  if (content.senderKeyDistributionMessage) {
    parts.push(`sender-key-distribution:bytes=${content.senderKeyDistributionMessage.byteLength}`);
  }
  if (content.decryptionErrorMessage) {
    parts.push(`decryption-error:bytes=${content.decryptionErrorMessage.byteLength}`);
  }
  if (content.syncMessage) {
    parts.push("sync");
  }
  if (content.editMessage) {
    parts.push(
      `edit:target=${content.editMessage.targetSentTimestamp ?? "none"} hasData=${content.editMessage.dataMessage ? "yes" : "no"}`,
    );
  }
  if (content.callMessage) {
    parts.push("call");
  }
  if (content.nullMessage) {
    parts.push(`null:padding=${content.nullMessage.padding?.byteLength ?? 0}`);
  }
  if (content.storyMessage) {
    parts.push("story");
  }
  if (content.pniSignatureMessage) {
    parts.push("pni-signature");
  }
  return parts.length > 0 ? parts.join("+") : "empty";
}

function describeMessageBody(body: string | undefined): string {
  if (body === undefined) {
    return "body=missing";
  }
  return `bodyChars=${body.length} body=${JSON.stringify(body)}`;
}

function describeOutboundDevices(
  contents: ReadonlyArray<Readonly<{ deviceId: number; registrationId: number }>>,
): string {
  if (contents.length === 0) {
    return "none";
  }
  return contents.map((content) => `${content.deviceId}/${content.registrationId}`).join(",");
}

function describePreKeyBundleDevices(preKeyBundles: ReadonlyArray<PreKeyBundle>): string {
  if (preKeyBundles.length === 0) {
    return "none";
  }
  return preKeyBundles
    .map((bundle) => `${bundle.deviceId()}/${bundle.registrationId()}`)
    .join(",");
}

type MismatchedDeviceListName = "missingDevices" | "extraDevices" | "staleDevices";

type DeviceMismatchRepair = {
  refreshDeviceIds: Set<number>;
  refreshAllDevices: boolean;
};

type SessionStoreWithRemoval = Pick<LibsignalStores["sessionStore"], "getSession" | "saveSession"> & {
  removeSession?: (address: ProtocolAddress) => Promise<void>;
};

function isMismatchedDevicesError(err: unknown): err is MismatchedDevicesError {
  if (typeof err !== "object" || err === null) {
    return false;
  }
  const candidate = err as Partial<MismatchedDevicesError>;
  return candidate.code === ErrorCode.MismatchedDevices && Array.isArray(candidate.entries);
}

function filterMismatchedEntries(
  entries: ReadonlyArray<MismatchedDevicesEntry>,
  destination: ServiceId,
): MismatchedDevicesEntry[] {
  const destinationKey = describeServiceId(destination).toLowerCase();
  return entries.filter((entry) => describeServiceId(entry.account).toLowerCase() === destinationKey);
}

function collectMismatchedDeviceIds(
  entries: ReadonlyArray<MismatchedDevicesEntry>,
  name: MismatchedDeviceListName,
): Set<number> {
  const deviceIds = new Set<number>();
  for (const entry of entries) {
    for (const deviceId of entry[name]) {
      deviceIds.add(deviceId);
    }
  }
  return deviceIds;
}

function sortedDeviceIds(deviceIds: ReadonlySet<number>): number[] {
  return [...deviceIds].sort((left, right) => left - right);
}

function describeDeviceIds(deviceIds: ReadonlySet<number>): string {
  return deviceIds.size === 0 ? "none" : sortedDeviceIds(deviceIds).join(",");
}

function describeAttachmentInput(attachment: SignalAttachmentInput): string {
  return [
    `bytes=${attachment.data.byteLength}`,
    `contentType=${attachment.contentType ?? "none"}`,
    `fileName=${attachment.fileName ? "yes" : "no"}`,
    attachment.caption ? `caption=${describeMessageBody(attachment.caption)}` : "caption=no",
    `incrementalCandidate=${attachment.contentType === "video/mp4" ? "yes" : "no"}`,
  ].join(" ");
}

function encodeUtf8(text: string): ReturnType<typeof utf8Bytes> {
  return utf8Bytes(text);
}

function splitUtf8TextAtByteLimit(text: string, limit: number): {
  prefix: string;
  prefixBytes: number;
} {
  let byteLength = 0;
  let endIndex = 0;
  for (const segment of text) {
    const segmentBytes = encodeUtf8(segment).byteLength;
    if (byteLength + segmentBytes > limit) {
      break;
    }
    byteLength += segmentBytes;
    endIndex += segment.length;
  }
  return {
    prefix: text.slice(0, endIndex),
    prefixBytes: byteLength,
  };
}

function describeIncomingEnvelope(envelope: Uint8Array, serverDeliveredTimestamp: number): string {
  const parts = [
    `len=${envelope.byteLength}`,
    `serverDelivered=${serverDeliveredTimestamp}`,
    `prefix=${bytesToHex(envelope.subarray(0, Math.min(16, envelope.byteLength)))}`,
  ];
  try {
    const decoded = decodeSignalEnvelope(envelope);
    parts.push(
      [
        "decoded=yes",
        `type=${decoded.type ?? "unknown"}`,
        `source=${decoded.sourceServiceId ?? "none"}`,
        `sourceDevice=${decoded.sourceDeviceId ?? "none"}`,
        `destination=${decoded.destinationServiceId ?? "none"}`,
        `clientTs=${decoded.clientTimestamp ?? "none"}`,
        `serverTs=${decoded.serverTimestamp ?? "none"}`,
        `contentBytes=${decoded.content?.byteLength ?? 0}`,
        `urgent=${decoded.urgent ?? "unknown"}`,
        `serverGuid=${decoded.serverGuid ?? "none"}`,
      ].join(" "),
    );
  } catch (err) {
    parts.push(`decoded=no decodeError=${describeSignalError(err)}`);
  }
  return parts.join(" ");
}

export class SignalTsClient {
  private readonly events = new SignalEventHub();
  private readonly logger: SignalLogger | undefined;
  private readonly connectionFactory: SignalConnectionFactory | undefined;
  private readonly sealedSenderConnectionFactory: SignalSealedSenderConnectionFactory | undefined;
  private signalStateMutationQueue: Promise<void> = Promise.resolve();
  private net: Net.Net | undefined;
  private connection: SignalChatConnection | undefined;

  constructor(private readonly options: SignalTsClientOptions) {
    this.logger = options.logger;
    this.connectionFactory = options.connectionFactory;
    this.sealedSenderConnectionFactory = options.sealedSenderConnectionFactory;
  }

  private logDebug(message: string): void {
    if (this.logger?.debug) {
      this.logger.debug(message);
      return;
    }
    this.logger?.info?.(message);
  }

  private logInfo(message: string): void {
    this.logger?.info?.(message);
  }

  private logWarn(message: string): void {
    this.logger?.warn?.(message);
  }

  private logError(message: string, err?: unknown): void {
    if (this.logger?.error) {
      this.logger.error(message, err);
      return;
    }
    this.logger?.warn?.(err === undefined ? message : `${message}: ${describeSignalError(err)}`);
  }

  private async runSerializedSignalStateMutation<T>(
    traceId: string,
    operation: string,
    run: () => Promise<T>,
  ): Promise<T> {
    const previous = this.signalStateMutationQueue;
    let release!: () => void;
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.signalStateMutationQueue = previous.then(() => current, () => current);
    const waitStartedAt = Date.now();
    await previous.catch(() => undefined);
    const waitMs = Date.now() - waitStartedAt;
    if (waitMs > 0) {
      this.logDebug(`${traceId} ${operation} state-lock acquired waitMs=${waitMs}`);
    }
    try {
      return await run();
    } finally {
      release();
    }
  }

  private async repairMismatchedDevices({
    err,
    traceId,
    operation,
    destination,
    stores,
  }: {
    err: MismatchedDevicesError;
    traceId: string;
    operation: string;
    destination: ServiceId;
    stores: Pick<LibsignalStores, "sessionStore">;
  }): Promise<DeviceMismatchRepair | null> {
    const entries = filterMismatchedEntries(err.entries, destination);
    if (entries.length === 0) {
      return null;
    }

    const missingDeviceIds = collectMismatchedDeviceIds(entries, "missingDevices");
    const extraDeviceIds = collectMismatchedDeviceIds(entries, "extraDevices");
    const staleDeviceIds = collectMismatchedDeviceIds(entries, "staleDevices");
    const refreshAllDevices = entries.some(
      (entry) =>
        entry.missingDevices.length === 0 &&
        entry.extraDevices.length === 0 &&
        entry.staleDevices.length === 0,
    );
    this.logWarn(
      [
        `${traceId} ${operation} device-mismatch`,
        `destination=${describeServiceId(destination)}`,
        `missing=${describeDeviceIds(missingDeviceIds)}`,
        `extra=${describeDeviceIds(extraDeviceIds)}`,
        `stale=${describeDeviceIds(staleDeviceIds)}`,
      ].join(" "),
    );

    const devicesToDrop = new Set([...extraDeviceIds, ...staleDeviceIds]);
    for (const deviceId of sortedDeviceIds(devicesToDrop)) {
      await this.removeRecipientSessionDevice({
        traceId,
        operation,
        destination,
        deviceId,
        sessionStore: stores.sessionStore,
      });
    }

    return {
      refreshDeviceIds: new Set([...missingDeviceIds, ...staleDeviceIds]),
      refreshAllDevices,
    };
  }

  private async removeRecipientSessionDevice({
    traceId,
    operation,
    destination,
    deviceId,
    sessionStore,
  }: {
    traceId: string;
    operation: string;
    destination: ServiceId;
    deviceId: number;
    sessionStore: LibsignalStores["sessionStore"];
  }): Promise<void> {
    const address = ProtocolAddress.new(destination, deviceId);
    const removableSessionStore = sessionStore as SessionStoreWithRemoval;
    if (removableSessionStore.removeSession) {
      await removableSessionStore.removeSession(address);
      this.logDebug(
        `${traceId} ${operation} session removed destination=${describeServiceId(destination)} device=${deviceId}`,
      );
      return;
    }

    const session = await removableSessionStore.getSession(address);
    if (!session) {
      this.logDebug(
        `${traceId} ${operation} session remove skipped destination=${describeServiceId(destination)} device=${deviceId} existingSession=no`,
      );
      return;
    }
    session.archiveCurrentState();
    await removableSessionStore.saveSession(address, session);
    this.logDebug(
      `${traceId} ${operation} session archived destination=${describeServiceId(destination)} device=${deviceId}`,
    );
  }

  private async buildDirectContentMessageContents({
    traceId,
    operation,
    destination,
    payload,
    stores,
    preKeyBundles,
    refreshDeviceIds,
  }: {
    traceId: string;
    operation: string;
    destination: ServiceId;
    payload: Uint8Array<ArrayBuffer>;
    stores: Pick<LibsignalStores, "identityStore" | "sessionStore">;
    preKeyBundles: PreKeyBundle[];
    refreshDeviceIds?: ReadonlySet<number>;
  }): Promise<Array<SendMessageRequest["contents"][number]>> {
    const localAddress = this.localAddress();
    const contents: Array<SendMessageRequest["contents"][number]> = [];
    for (const bundle of preKeyBundles) {
      const deviceId = bundle.deviceId();
      const remoteAddress = ProtocolAddress.new(destination, deviceId);
      const refreshSession = refreshDeviceIds?.has(deviceId) ?? false;
      const existingSession = refreshSession
        ? null
        : await stores.sessionStore.getSession(remoteAddress);
      this.logDebug(
        `${traceId} ${operation} encrypt device=${deviceId} registration=${bundle.registrationId()} existingSession=${existingSession ? "yes" : "no"} refreshSession=${refreshSession ? "yes" : "no"}`,
      );
      const device = {
        serviceId: destination,
        deviceId,
        registrationId: bundle.registrationId(),
      };
      if (!existingSession || refreshSession) {
        Object.assign(device, { preKeyBundle: bundle });
      }
      const encrypted = await encryptPayloadForDevice({
        localAddress,
        device,
        payload,
        stores,
      });
      this.logDebug(
        `${traceId} ${operation} encrypted device=${encrypted.deviceId} registration=${encrypted.registrationId} ciphertextType=${encrypted.contents.type()}`,
      );
      contents.push(encrypted);
    }
    return contents;
  }

  private async buildRetryReceiptContentsForDevice({
    traceId,
    destination,
    retry,
    stores,
    preKeyBundles,
    preKeyAuth,
    abortSignal,
  }: {
    traceId: string;
    destination: ServiceId;
    retry: SignalRetryReceiptRequest;
    stores: Pick<LibsignalStores, "sessionStore">;
    preKeyBundles?: PreKeyBundle[];
    preKeyAuth?: PreKeyAuth;
    abortSignal?: AbortSignal;
  }): Promise<Array<SendMessageRequest["contents"][number]>> {
    const remoteAddress = ProtocolAddress.new(destination, retry.senderDeviceId);
    const session = await stores.sessionStore.getSession(remoteAddress);
    if (session) {
      this.logDebug(
        `${traceId} retry-receipt session destination=${describeServiceId(destination)} senderDevice=${retry.senderDeviceId} registration=${session.remoteRegistrationId()} source=session`,
      );
      return [
        {
          deviceId: retry.senderDeviceId,
          registrationId: session.remoteRegistrationId(),
          contents: createSignalDecryptionErrorPlaintextContent(retry).asCiphertextMessage(),
        },
      ];
    }

    const providedBundle = preKeyBundles?.find((bundle) => bundle.deviceId() === retry.senderDeviceId);
    const fetchedBundle = providedBundle ??
      (await this.fetchPreKeyBundles({
        destination,
        ...(preKeyAuth !== undefined ? { preKeyAuth } : {}),
        ...(abortSignal !== undefined ? { abortSignal } : {}),
        device: { deviceId: retry.senderDeviceId },
      })).find((bundle) => bundle.deviceId() === retry.senderDeviceId);
    if (!fetchedBundle) {
      throw new SignalTsStateError(
        `Signal session is missing for retry receipt recipient ${destination.getServiceIdString()}.${retry.senderDeviceId}`,
      );
    }
    this.logDebug(
      `${traceId} retry-receipt session destination=${describeServiceId(destination)} senderDevice=${retry.senderDeviceId} registration=${fetchedBundle.registrationId()} source=prekey`,
    );
    return [
      {
        deviceId: retry.senderDeviceId,
        registrationId: fetchedBundle.registrationId(),
        contents: createSignalDecryptionErrorPlaintextContent(retry).asCiphertextMessage(),
      },
    ];
  }

  private buildRetryReceiptContentsFromPreKeyBundles({
    retry,
    preKeyBundles,
  }: {
    retry: SignalRetryReceiptRequest;
    preKeyBundles: PreKeyBundle[];
  }): Array<SendMessageRequest["contents"][number]> {
    return preKeyBundles.map((bundle) => ({
      deviceId: bundle.deviceId(),
      registrationId: bundle.registrationId(),
      contents: createSignalDecryptionErrorPlaintextContent(retry).asCiphertextMessage(),
    }));
  }

  on<K extends SignalEventName>(event: K, handler: SignalEventHandler<K>): () => void {
    return this.events.on(event, handler);
  }

  async connect(abortSignal?: AbortSignal): Promise<void> {
    if (this.connection) {
      this.logDebug(
        `connect skipped existing account=${this.options.account.device.aci}.${this.options.account.device.deviceId}`,
      );
      return;
    }
    this.logDebug(
      [
        "connect start",
        `account=${this.options.account.device.aci}.${this.options.account.device.deviceId}`,
        `environment=${this.options.environment ?? "production"}`,
        `receiveStories=${this.options.account.receiveStories ?? this.options.receiveStories ?? false}`,
      ].join(" "),
    );
    const net =
      this.net ??
      new Net.Net({
        env: resolveLibsignalEnvironment(this.options.environment ?? "production"),
        userAgent: this.options.userAgent ?? DEFAULT_USER_AGENT,
      });
    this.net = net;
    const listener = this.createListener();
    try {
      this.connection = await (this.connectionFactory ?? defaultConnectionFactory)({
        net,
        account: this.options.account,
        listener,
        ...(abortSignal ? { abortSignal } : {}),
      });
      this.logInfo(`connected to Signal chat (${this.connection.connectionInfo().toString()})`);
    } catch (err) {
      this.logError("connect failed", err);
      throw err;
    }
  }

  async disconnect(): Promise<void> {
    const connection = this.connection;
    this.connection = undefined;
    if (connection) {
      this.logDebug(`disconnect start (${connection.connectionInfo().toString()})`);
      try {
        await connection.disconnect();
        this.logDebug("disconnect done");
      } catch (err) {
        this.logError("disconnect failed", err);
        throw err;
      }
    }
  }

  async sendEncryptedMessage(params: SendEncryptedMessageParams): Promise<{ timestamp: number }> {
    const traceId = params.traceId ?? createSignalTraceId("encrypted");
    const connection = this.connection;
    if (!connection) {
      this.logWarn(`${traceId} encrypted-send failed: client not connected`);
      throw new SignalTsStateError("SignalTsClient is not connected");
    }
    const timestamp = params.timestamp ?? Date.now();
    const request: SendMessageRequest = {
      destination: resolveDestination(params.destination),
      timestamp,
      contents: params.contents,
      onlineOnly: params.onlineOnly ?? false,
      urgent: params.urgent ?? true,
    };
    this.logDebug(
      [
        `${traceId} encrypted-send start`,
        `destination=${describeServiceId(request.destination)}`,
        `timestamp=${timestamp}`,
        `devices=${describeOutboundDevices(request.contents)}`,
        `onlineOnly=${request.onlineOnly}`,
        `urgent=${request.urgent}`,
      ].join(" "),
    );
    try {
      await connection.sendMessage(
        request,
        params.abortSignal ? { abortSignal: params.abortSignal } : undefined,
      );
      this.logInfo(
        `${traceId} encrypted-send done destination=${describeServiceId(request.destination)} timestamp=${timestamp} devices=${describeOutboundDevices(request.contents)}`,
      );
    } catch (err) {
      this.logError(
        `${traceId} encrypted-send failed destination=${describeServiceId(request.destination)} timestamp=${timestamp} devices=${describeOutboundDevices(request.contents)}`,
        err,
      );
      throw err;
    }
    return { timestamp };
  }

  async sendTextMessage(params: SendTextMessageParams): Promise<{ timestamp: number }> {
    return await this.sendMessage(params);
  }

  private async createTextContent(params: {
    body: string;
    timestamp: number;
    traceId: string;
    attachments?: SignalAttachmentPointer[];
    quote?: SignalQuote;
    bodyRanges?: SignalBodyRange[];
    groupV2?: SignalGroupContextV2;
    abortSignal?: AbortSignal;
  }): Promise<SignalContent> {
    let body = params.body;
    const attachments = params.attachments ? [...params.attachments] : [];
    const bodyBytes = encodeUtf8(body);
    if (bodyBytes.byteLength > SIGNAL_MESSAGE_BODY_MAX_BYTES) {
      const trimmed = splitUtf8TextAtByteLimit(body, SIGNAL_MESSAGE_BODY_MAX_BYTES);
      this.logDebug(
        `${params.traceId} long-text upload start bodyBytes=${bodyBytes.byteLength} prefixBytes=${trimmed.prefixBytes} existingAttachments=${attachments.length}`,
      );
      const uploaded = await this.uploadAttachment({
        traceId: `${params.traceId}:long-text`,
        attachment: {
          data: bodyBytes,
          contentType: SIGNAL_LONG_TEXT_CONTENT_TYPE,
          uploadTimestamp: params.timestamp,
        },
        ...(params.abortSignal ? { abortSignal: params.abortSignal } : {}),
      });
      attachments.unshift(uploaded.pointer);
      body = trimmed.prefix;
      this.logDebug(
        `${params.traceId} long-text upload done bodyBytes=${bodyBytes.byteLength} prefixChars=${body.length} attachments=${attachments.length}`,
      );
    }

    const contentParams: Parameters<typeof createTextSignalContent>[0] = {
      body,
      timestamp: params.timestamp,
    };
    if (attachments.length > 0) {
      contentParams.attachments = attachments;
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
    return createTextSignalContent(contentParams);
  }

  async sendMessage(params: SendMessageParams): Promise<{ timestamp: number }> {
    const traceId = params.traceId ?? createSignalTraceId("message");
    if (!params.body && (!params.attachments || params.attachments.length === 0)) {
      this.logWarn(`${traceId} message-send rejected: missing body and attachments`);
      throw new SignalTsStateError("Signal message requires body or attachments");
    }
    const timestamp = params.timestamp ?? Date.now();
    const content = await this.createTextContent({
      body: params.body ?? "",
      timestamp,
      traceId,
      ...(params.attachments !== undefined ? { attachments: params.attachments } : {}),
      ...(params.quote !== undefined ? { quote: params.quote } : {}),
      ...(params.bodyRanges !== undefined ? { bodyRanges: params.bodyRanges } : {}),
      ...(params.groupV2 !== undefined ? { groupV2: params.groupV2 } : {}),
      ...(params.abortSignal ? { abortSignal: params.abortSignal } : {}),
    });
    return await this.sendContentMessage({
      ...params,
      traceId,
      timestamp,
      content,
    });
  }

  async sendReactionMessage(params: SendReactionMessageParams): Promise<{ timestamp: number }> {
    const traceId = params.traceId ?? createSignalTraceId("reaction");
    const timestamp = params.timestamp ?? Date.now();
    return await this.sendContentMessage({
      ...params,
      traceId,
      timestamp,
      content: createReactionSignalContent(params.reaction, { timestamp }),
    });
  }

  async sendReceiptMessage(params: SendReceiptMessageParams): Promise<{ timestamp: number }> {
    const traceId = params.traceId ?? createSignalTraceId("receipt");
    return await this.sendContentMessage({
      ...params,
      traceId,
      content: createReceiptSignalContent(params.receipt),
    });
  }

  async sendTypingMessage(params: SendTypingMessageParams): Promise<{ timestamp: number }> {
    const traceId = params.traceId ?? createSignalTraceId("typing");
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
      traceId,
      content: createTypingSignalContent(typing),
    });
  }

  async sendStickerMessage(params: SendStickerMessageParams): Promise<{ timestamp: number }> {
    const traceId = params.traceId ?? createSignalTraceId("sticker");
    const timestamp = params.timestamp ?? Date.now();
    return await this.sendContentMessage({
      ...params,
      traceId,
      timestamp,
      content: createStickerSignalContent({
        sticker: params.sticker,
        timestamp,
      }),
    });
  }

  async sendContentMessage(params: SendContentMessageParams): Promise<{ timestamp: number }> {
    const traceId = params.traceId ?? createSignalTraceId("content");
    return await this.runSerializedSignalStateMutation(traceId, "content-send", async () =>
      await this.sendContentMessageUnlocked({ ...params, traceId }),
    );
  }

  private async sendContentMessageUnlocked(
    params: SendContentMessageParams,
  ): Promise<{ timestamp: number }> {
    const traceId = params.traceId ?? createSignalTraceId("content");
    const timestamp = params.timestamp ?? Date.now();
    this.logDebug(
      [
        `${traceId} content-send start`,
        `target=${describeRecipientTarget(params.destination)}`,
        `timestamp=${timestamp}`,
        `content=${describeSignalContent(params.content)}`,
      ].join(" "),
    );
    try {
      const destination = await this.resolveRecipient(
        params.destination,
        params.abortSignal,
        traceId,
      );
      this.logDebug(
        `${traceId} content-send resolved target=${describeRecipientTarget(params.destination)} destination=${describeServiceId(destination)}`,
      );
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
      this.logDebug(
        `${traceId} content-send prekeys start destination=${describeServiceId(destination)} source=${params.preKeyBundles ? "provided" : "fetch"} auth=${params.preKeyAuth ? "yes" : "no"}`,
      );
      const preKeyBundles =
        params.preKeyBundles ??
        (await fetchRecipientPreKeys(fetchParams)).preKeyBundles;
      this.logDebug(
        `${traceId} content-send prekeys done destination=${describeServiceId(destination)} count=${preKeyBundles.length} devices=${describePreKeyBundleDevices(preKeyBundles)}`,
      );
      if (preKeyBundles.length === 0) {
        throw new SignalTsStateError("Signal recipient has no available prekey bundles");
      }
      const payload = encodeSignalContent(params.content);
      this.logDebug(`${traceId} content-send payload encoded bytes=${payload.byteLength}`);
      let contents = await this.buildDirectContentMessageContents({
        traceId,
        operation: "content-send",
        destination,
        payload,
        stores: params.stores,
        preKeyBundles,
      });
      const sendParams: SendEncryptedMessageParams = {
        traceId,
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
      let result: { timestamp: number };
      try {
        result = await this.sendEncryptedMessage(sendParams);
      } catch (err) {
        if (!isMismatchedDevicesError(err)) {
          throw err;
        }
        const repair = await this.repairMismatchedDevices({
          err,
          traceId,
          operation: "content-send",
          destination,
          stores: params.stores,
        });
        if (!repair) {
          throw err;
        }
        const retryPreKeyBundles = await this.fetchPreKeyBundles({
          destination,
          ...(params.preKeyAuth !== undefined ? { preKeyAuth: params.preKeyAuth } : {}),
          ...(params.abortSignal !== undefined ? { abortSignal: params.abortSignal } : {}),
        });
        this.logDebug(
          `${traceId} content-send device-retry prekeys done destination=${describeServiceId(destination)} count=${retryPreKeyBundles.length} devices=${describePreKeyBundleDevices(retryPreKeyBundles)}`,
        );
        const refreshDeviceIds = repair.refreshAllDevices
          ? new Set(retryPreKeyBundles.map((bundle) => bundle.deviceId()))
          : repair.refreshDeviceIds;
        contents = await this.buildDirectContentMessageContents({
          traceId,
          operation: "content-send:device-retry",
          destination,
          payload,
          stores: params.stores,
          preKeyBundles: retryPreKeyBundles,
          refreshDeviceIds,
        });
        result = await this.sendEncryptedMessage({
          ...sendParams,
          traceId: `${traceId}:device-retry`,
          contents,
        });
      }
      this.logInfo(
        `${traceId} content-send done destination=${describeServiceId(destination)} timestamp=${result.timestamp} devices=${describeOutboundDevices(contents)}`,
      );
      return result;
    } catch (err) {
      this.logError(
        `${traceId} content-send failed target=${describeRecipientTarget(params.destination)} timestamp=${timestamp} content=${describeSignalContent(params.content)}`,
        err,
      );
      throw err;
    }
  }

  async sendRetryReceiptMessage(
    params: SendRetryReceiptMessageParams,
  ): Promise<{ timestamp: number }> {
    const traceId = params.traceId ?? createSignalTraceId("retry-receipt");
    return await this.runSerializedSignalStateMutation(traceId, "retry-receipt", async () => {
    const timestamp = params.timestamp ?? Date.now();
    this.logDebug(
      [
        `${traceId} retry-receipt start`,
        `target=${describeRecipientTarget(params.destination)}`,
        `timestamp=${timestamp}`,
        `failedTimestamp=${params.retry.timestamp}`,
        `senderDevice=${params.retry.senderDeviceId}`,
      ].join(" "),
    );
    try {
      const destination = await this.resolveRecipient(
        params.destination,
        params.abortSignal,
        traceId,
      );
      let contents = await this.buildRetryReceiptContentsForDevice({
        traceId,
        destination,
        retry: params.retry,
        stores: params.stores,
        ...(params.preKeyBundles !== undefined ? { preKeyBundles: params.preKeyBundles } : {}),
        ...(params.preKeyAuth !== undefined ? { preKeyAuth: params.preKeyAuth } : {}),
        ...(params.abortSignal !== undefined ? { abortSignal: params.abortSignal } : {}),
      });
      const sendParams: SendEncryptedMessageParams = {
        traceId,
        destination,
        timestamp,
        contents,
        ...(params.onlineOnly !== undefined ? { onlineOnly: params.onlineOnly } : {}),
        ...(params.urgent !== undefined ? { urgent: params.urgent } : {}),
        ...(params.abortSignal ? { abortSignal: params.abortSignal } : {}),
      };
      let result: { timestamp: number };
      try {
        result = await this.sendEncryptedMessage(sendParams);
      } catch (err) {
        if (!isMismatchedDevicesError(err)) {
          throw err;
        }
        const repair = await this.repairMismatchedDevices({
          err,
          traceId,
          operation: "retry-receipt",
          destination,
          stores: params.stores,
        });
        if (!repair) {
          throw err;
        }
        const retryPreKeyBundles = await this.fetchPreKeyBundles({
          destination,
          ...(params.preKeyAuth !== undefined ? { preKeyAuth: params.preKeyAuth } : {}),
          ...(params.abortSignal !== undefined ? { abortSignal: params.abortSignal } : {}),
        });
        this.logDebug(
          `${traceId} retry-receipt device-retry prekeys done destination=${describeServiceId(destination)} count=${retryPreKeyBundles.length} devices=${describePreKeyBundleDevices(retryPreKeyBundles)}`,
        );
        contents = this.buildRetryReceiptContentsFromPreKeyBundles({
          retry: params.retry,
          preKeyBundles: retryPreKeyBundles,
        });
        result = await this.sendEncryptedMessage({
          ...sendParams,
          traceId: `${traceId}:device-retry`,
          contents,
        });
      }
      this.logInfo(
        `${traceId} retry-receipt done destination=${describeServiceId(destination)} timestamp=${result.timestamp} failedTimestamp=${params.retry.timestamp}`,
      );
      return result;
    } catch (err) {
      this.logError(
        `${traceId} retry-receipt failed target=${describeRecipientTarget(params.destination)} failedTimestamp=${params.retry.timestamp} senderDevice=${params.retry.senderDeviceId}`,
        err,
      );
      throw err;
    }
    });
  }

  async sendSealedContentMessage(
    params: SendSealedContentMessageParams,
  ): Promise<{ timestamp: number }> {
    const traceId = params.traceId ?? createSignalTraceId("sealed");
    return await this.runSerializedSignalStateMutation(traceId, "sealed-send", async () => {
    const timestamp = params.timestamp ?? Date.now();
    this.logDebug(
      [
        `${traceId} sealed-send start`,
        `target=${describeRecipientTarget(params.destination)}`,
        `timestamp=${timestamp}`,
        `auth=${params.auth?.kind ?? "unrestricted"}`,
        `content=${describeSignalContent(params.content)}`,
      ].join(" "),
    );
    try {
      const destination = await this.resolveRecipient(
        params.destination,
        params.abortSignal,
        traceId,
      );
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
      this.logDebug(
        `${traceId} sealed-send prekeys start destination=${describeServiceId(destination)} source=${params.preKeyBundles ? "provided" : "fetch"} auth=${params.preKeyAuth ? "yes" : "no"}`,
      );
      const preKeyBundles =
        params.preKeyBundles ??
        (await fetchRecipientPreKeys(fetchParams)).preKeyBundles;
      this.logDebug(
        `${traceId} sealed-send prekeys done destination=${describeServiceId(destination)} count=${preKeyBundles.length} devices=${describePreKeyBundleDevices(preKeyBundles)}`,
      );
      if (preKeyBundles.length === 0) {
        throw new SignalTsStateError("Signal recipient has no available prekey bundles");
      }
      const localAddress = this.localAddress();
      const payload = encodeSignalContent(params.content);
      const contents: Array<SendSealedMessageRequest["contents"][number]> = [];
      for (const bundle of preKeyBundles) {
        const remoteAddress = ProtocolAddress.new(destination, bundle.deviceId());
        const existingSession = await params.stores.sessionStore.getSession(remoteAddress);
        this.logDebug(
          `${traceId} sealed-send encrypt device=${bundle.deviceId()} registration=${bundle.registrationId()} existingSession=${existingSession ? "yes" : "no"}`,
        );
        if (!existingSession) {
          await processPreKeyBundle(
            bundle,
            remoteAddress,
            localAddress,
            params.stores.sessionStore,
            params.stores.identityStore,
          );
          this.logDebug(
            `${traceId} sealed-send processed prekey bundle device=${bundle.deviceId()} registration=${bundle.registrationId()}`,
          );
        }
        const encrypted = await sealedSenderEncryptMessage(
          padSignalMessageBody(payload),
          remoteAddress,
          params.senderCertificate,
          params.stores.sessionStore,
          params.stores.identityStore,
        );
        this.logDebug(
          `${traceId} sealed-send encrypted device=${bundle.deviceId()} registration=${bundle.registrationId()} bytes=${encrypted.byteLength}`,
        );
        contents.push({
          deviceId: bundle.deviceId(),
          registrationId: bundle.registrationId(),
          contents: encrypted,
        });
      }
      this.logDebug(
        `${traceId} sealed-send connection start destination=${describeServiceId(destination)}`,
      );
      const connection = await this.createSealedSenderConnection(params.abortSignal);
      try {
        const request: SendSealedMessageRequest = {
          destination,
          timestamp,
          contents,
          auth: resolveSealedSenderAuth(params.auth),
          onlineOnly: params.onlineOnly ?? false,
          urgent: params.urgent ?? true,
        };
        this.logDebug(
          `${traceId} sealed-send chat request destination=${describeServiceId(destination)} timestamp=${timestamp} devices=${describeOutboundDevices(contents)} auth=${params.auth?.kind ?? "unrestricted"} onlineOnly=${request.onlineOnly} urgent=${request.urgent}`,
        );
        await connection.sendMessage(
          request,
          params.abortSignal ? { abortSignal: params.abortSignal } : undefined,
        );
        this.logInfo(
          `${traceId} sealed-send done destination=${describeServiceId(destination)} timestamp=${timestamp} devices=${describeOutboundDevices(contents)}`,
        );
      } finally {
        await connection.disconnect();
        this.logDebug(`${traceId} sealed-send connection closed`);
      }
      return { timestamp };
    } catch (err) {
      this.logError(
        `${traceId} sealed-send failed target=${describeRecipientTarget(params.destination)} timestamp=${timestamp} content=${describeSignalContent(params.content)}`,
        err,
      );
      throw err;
    }
    });
  }

  async sendSyncMessage(params: SendSyncMessageParams): Promise<{ timestamp: number }> {
    const traceId = params.traceId ?? createSignalTraceId("sync");
    const connection = this.connection;
    if (!connection) {
      this.logWarn(`${traceId} sync-send failed: client not connected`);
      throw new SignalTsStateError("SignalTsClient is not connected");
    }
    if (!connection.sendSyncMessage) {
      this.logWarn(`${traceId} sync-send failed: connection missing sendSyncMessage`);
      throw new SignalTsStateError("Signal chat connection does not support sync messages");
    }
    const timestamp = params.timestamp ?? Date.now();
    const request: SendSyncMessageRequest = {
      timestamp,
      contents: params.contents,
      urgent: params.urgent ?? true,
    };
    this.logDebug(
      `${traceId} sync-send start timestamp=${timestamp} devices=${describeOutboundDevices(request.contents)} urgent=${request.urgent}`,
    );
    try {
      await connection.sendSyncMessage(
        request,
        params.abortSignal ? { abortSignal: params.abortSignal } : undefined,
      );
      this.logInfo(
        `${traceId} sync-send done timestamp=${timestamp} devices=${describeOutboundDevices(request.contents)}`,
      );
    } catch (err) {
      this.logError(
        `${traceId} sync-send failed timestamp=${timestamp} devices=${describeOutboundDevices(request.contents)}`,
        err,
      );
      throw err;
    }
    return { timestamp };
  }

  async sendSyncContentMessage(
    params: SendSyncContentMessageParams,
  ): Promise<{ timestamp: number }> {
    const traceId = params.traceId ?? createSignalTraceId("sync-content");
    return await this.runSerializedSignalStateMutation(traceId, "sync-content", async () => {
    if (params.preKeyBundles.length === 0) {
      this.logWarn(`${traceId} sync-content rejected: no linked-device prekey bundles`);
      throw new SignalTsStateError("Signal sync message requires linked-device prekey bundles");
    }
    const timestamp = params.timestamp ?? Date.now();
    this.logDebug(
      `${traceId} sync-content start timestamp=${timestamp} content=${describeSignalContent(params.content)} prekeys=${describePreKeyBundleDevices(params.preKeyBundles)}`,
    );
    try {
      const localAddress = this.localAddress();
      const destination = Aci.fromUuid(this.options.account.device.aci);
      const payload = encodeSignalContent(params.content);
      this.logDebug(`${traceId} sync-content payload encoded bytes=${payload.byteLength}`);
      const contents: Array<SendSyncMessageRequest["contents"][number]> = [];
      for (const bundle of params.preKeyBundles) {
        const remoteAddress = ProtocolAddress.new(destination, bundle.deviceId());
        const existingSession = await params.stores.sessionStore.getSession(remoteAddress);
        this.logDebug(
          `${traceId} sync-content encrypt device=${bundle.deviceId()} registration=${bundle.registrationId()} existingSession=${existingSession ? "yes" : "no"}`,
        );
        const device = {
          serviceId: destination,
          deviceId: bundle.deviceId(),
          registrationId: bundle.registrationId(),
        };
        if (!existingSession) {
          Object.assign(device, { preKeyBundle: bundle });
        }
        const encrypted = await encryptPayloadForDevice({
          localAddress,
          device,
          payload,
          stores: params.stores,
        });
        this.logDebug(
          `${traceId} sync-content encrypted device=${encrypted.deviceId} registration=${encrypted.registrationId} ciphertextType=${encrypted.contents.type()}`,
        );
        contents.push(encrypted);
      }
      const result = await this.sendSyncMessage({
        traceId,
        timestamp,
        contents,
        ...(params.urgent !== undefined ? { urgent: params.urgent } : {}),
        ...(params.abortSignal ? { abortSignal: params.abortSignal } : {}),
      });
      this.logInfo(
        `${traceId} sync-content done timestamp=${result.timestamp} devices=${describeOutboundDevices(contents)}`,
      );
      return result;
    } catch (err) {
      this.logError(
        `${traceId} sync-content failed timestamp=${timestamp} content=${describeSignalContent(params.content)}`,
        err,
      );
      throw err;
    }
    });
  }

  async sendGroupMessage(params: SendGroupMessageParams): Promise<{
    timestamp: number;
    recipients: number;
  }> {
    const traceId = params.traceId ?? createSignalTraceId("group-message");
    if (!params.body && (!params.attachments || params.attachments.length === 0)) {
      this.logWarn(`${traceId} group-message rejected: missing body and attachments`);
      throw new SignalTsStateError("Signal group message requires body or attachments");
    }
    const timestamp = params.timestamp ?? Date.now();
    const content = await this.createTextContent({
      body: params.body ?? "",
      timestamp,
      traceId,
      groupV2: {
        masterKey: params.group.masterKey,
        ...(params.group.revision !== undefined ? { revision: params.group.revision } : {}),
      },
      ...(params.attachments !== undefined ? { attachments: params.attachments } : {}),
      ...(params.quote !== undefined ? { quote: params.quote } : {}),
      ...(params.bodyRanges !== undefined ? { bodyRanges: params.bodyRanges } : {}),
      ...(params.abortSignal ? { abortSignal: params.abortSignal } : {}),
    });
    return await this.sendGroupContentMessage({
      ...params,
      traceId,
      timestamp,
      content,
    });
  }

  async sendGroupStickerMessage(params: SendGroupStickerMessageParams): Promise<{
    timestamp: number;
    recipients: number;
  }> {
    const traceId = params.traceId ?? createSignalTraceId("group-sticker");
    const timestamp = params.timestamp ?? Date.now();
    return await this.sendGroupContentMessage({
      ...params,
      traceId,
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
    const traceId = params.traceId ?? createSignalTraceId("group-reaction");
    const timestamp = params.timestamp ?? Date.now();
    return await this.sendGroupContentMessage({
      ...params,
      traceId,
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
    const traceId = params.traceId ?? createSignalTraceId("group-content");
    return await this.runSerializedSignalStateMutation(traceId, "group-content", async () =>
      await this.sendGroupContentMessageUnlocked({ ...params, traceId }),
    );
  }

  private async sendGroupContentMessageUnlocked(params: SendGroupContentMessageParams): Promise<{
    timestamp: number;
    recipients: number;
  }> {
    const traceId = params.traceId ?? createSignalTraceId("group-content");
    const timestamp = params.timestamp ?? Date.now();
    this.logDebug(
      [
        `${traceId} group-content start`,
        `timestamp=${timestamp}`,
        `members=${params.members.length}`,
        `distributionId=${params.group.distributionId}`,
        `revision=${params.group.revision ?? "none"}`,
        `content=${describeSignalContent(params.content)}`,
      ].join(" "),
    );
    try {
      const localAddress = ProtocolAddress.new(
        Aci.fromUuid(this.options.account.device.aci),
        this.options.account.device.deviceId,
      );
      const recipients = await this.resolveGroupRecipients(
        params.members,
        params.abortSignal,
        traceId,
      );
      this.logDebug(
        `${traceId} group-content recipients resolved count=${recipients.length} recipients=${recipients.map((recipient) => describeServiceId(recipient)).join(",") || "none"}`,
      );
      if (recipients.length === 0) {
        throw new SignalTsStateError("Signal group message has no remote recipients");
      }
      const senderKeyDistribution = await SenderKeyDistributionMessage.create(
        localAddress,
        params.group.distributionId,
        params.stores.senderKeyStore,
      );
      const senderKeyDistributionBytes = senderKeyDistribution.serialize();
      this.logDebug(
        `${traceId} group-content sender-key-distribution created bytes=${senderKeyDistributionBytes.byteLength}`,
      );
      const memberBundles: Array<{ destination: ServiceId; bundles: PreKeyBundle[] }> = [];
      for (const destination of recipients) {
        const providedBundles = params.memberPreKeyBundles?.get(destination.getServiceIdString());
        this.logDebug(
          `${traceId} group-content member prekeys start destination=${describeServiceId(destination)} source=${providedBundles ? "provided" : "fetch"} auth=${params.preKeyAuth ? "yes" : "no"}`,
        );
        const bundles =
          providedBundles ??
          (await this.fetchPreKeyBundlesForGroupMember({
            destination,
            preKeyAuth: params.preKeyAuth,
            abortSignal: params.abortSignal,
          }));
        this.logDebug(
          `${traceId} group-content member prekeys done destination=${describeServiceId(destination)} count=${bundles.length} devices=${describePreKeyBundleDevices(bundles)}`,
        );
        await this.sendContentMessageUnlocked({
          traceId: `${traceId}:sender-key:${describeServiceId(destination)}`,
          destination,
          content: { senderKeyDistributionMessage: senderKeyDistributionBytes },
          stores: params.stores,
          preKeyBundles: bundles,
          timestamp,
          ...(params.onlineOnly !== undefined ? { onlineOnly: params.onlineOnly } : {}),
          ...(params.urgent !== undefined ? { urgent: params.urgent } : {}),
          ...(params.abortSignal ? { abortSignal: params.abortSignal } : {}),
        });
        memberBundles.push({ destination, bundles });
      }
      const groupPayload = encodeSignalContent(params.content);
      this.logDebug(`${traceId} group-content payload encoded bytes=${groupPayload.byteLength}`);
      const groupCiphertext = await groupEncrypt(
        localAddress,
        params.group.distributionId,
        params.stores.senderKeyStore,
        padSignalMessageBody(groupPayload),
      );
      this.logDebug(
        `${traceId} group-content encrypted bytes=${groupCiphertext.serialize().byteLength}`,
      );
      await Promise.all(
        memberBundles.map(async ({ destination, bundles }) => {
          const contents = bundles.map((bundle) => ({
            deviceId: bundle.deviceId(),
            registrationId: bundle.registrationId(),
            contents: groupCiphertext,
          }));
          this.logDebug(
            `${traceId} group-content fanout start destination=${describeServiceId(destination)} devices=${describeOutboundDevices(contents)}`,
          );
          await this.sendEncryptedMessage({
            traceId: `${traceId}:group-fanout:${describeServiceId(destination)}`,
            destination,
            timestamp,
            contents,
            ...(params.onlineOnly !== undefined ? { onlineOnly: params.onlineOnly } : {}),
            ...(params.urgent !== undefined ? { urgent: params.urgent } : {}),
            ...(params.abortSignal ? { abortSignal: params.abortSignal } : {}),
          });
          this.logDebug(
            `${traceId} group-content fanout done destination=${describeServiceId(destination)} devices=${describeOutboundDevices(contents)}`,
          );
        }),
      );
      this.logInfo(
        `${traceId} group-content done timestamp=${timestamp} recipients=${recipients.length}`,
      );
      return { timestamp, recipients: recipients.length };
    } catch (err) {
      this.logError(
        `${traceId} group-content failed timestamp=${timestamp} members=${params.members.length} content=${describeSignalContent(params.content)}`,
        err,
      );
      throw err;
    }
  }

  async uploadAttachment(params: UploadAttachmentParams): Promise<EncryptedSignalAttachment> {
    const traceId = params.traceId ?? createSignalTraceId("attachment");
    const connection = this.connection;
    if (!connection) {
      this.logWarn(`${traceId} attachment-upload failed: client not connected`);
      throw new SignalTsStateError("SignalTsClient is not connected");
    }
    if (!connection.getUploadForm) {
      this.logWarn(`${traceId} attachment-upload failed: connection missing getUploadForm`);
      throw new SignalTsStateError("Signal chat connection does not support attachment uploads");
    }
    this.logDebug(`${traceId} attachment-upload start ${describeAttachmentInput(params.attachment)}`);
    const getUploadForm: AttachmentUploadConnection["getUploadForm"] = async (request, options) => {
      this.logDebug(`${traceId} attachment-upload form start uploadSize=${request.uploadSize}`);
      try {
        const form = await connection.getUploadForm!.call(connection, request, options);
        this.logDebug(
          `${traceId} attachment-upload form done cdn=${form.cdn} key=${form.key} signedUrl=${form.signedUploadUrl.toString()}`,
        );
        return form;
      } catch (err) {
        this.logError(`${traceId} attachment-upload form failed uploadSize=${request.uploadSize}`, err);
        throw err;
      }
    };
    const fetchImpl = params.fetch ?? signalAttachmentFetch;
    const loggingFetch: FetchLike = async (input, init) => {
      const url = input instanceof URL ? input.toString() : input;
      this.logDebug(
        `${traceId} attachment-upload fetch start method=${init?.method ?? "GET"} url=${url}`,
      );
      try {
        const response = await fetchImpl(input, init);
        this.logDebug(
          `${traceId} attachment-upload fetch done method=${init?.method ?? "GET"} url=${url} status=${response.status}`,
        );
        return response;
      } catch (err) {
        this.logError(
          `${traceId} attachment-upload fetch failed method=${init?.method ?? "GET"} url=${url}`,
          err,
        );
        throw err;
      }
    };
    try {
      const result = await uploadSignalAttachment({
        connection: { getUploadForm },
        attachment: params.attachment,
        fetch: loggingFetch,
        ...(params.abortSignal ? { abortSignal: params.abortSignal } : {}),
      });
      this.logInfo(
        `${traceId} attachment-upload done encryptedBytes=${result.encrypted.byteLength} plaintextSha256=${result.plaintextHash} cdnNumber=${result.pointer.cdnNumber ?? "none"} cdnKey=${result.pointer.cdnKey ?? "none"} contentType=${result.pointer.contentType ?? "none"} size=${result.pointer.size ?? "none"}`,
      );
      return result;
    } catch (err) {
      this.logError(`${traceId} attachment-upload failed ${describeAttachmentInput(params.attachment)}`, err);
      throw err;
    }
  }

  private async resolveRecipient(
    target: SignalRecipientTarget,
    abortSignal: AbortSignal | undefined,
    traceId?: string,
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
    this.logDebug(
      `${traceId ?? "resolve"} recipient-resolve start target=${describeRecipientTarget(target)}`,
    );
    try {
      const serviceId = await resolveSignalRecipientTarget(params);
      this.logDebug(
        `${traceId ?? "resolve"} recipient-resolve done target=${describeRecipientTarget(target)} destination=${describeServiceId(serviceId)} net=${this.net ? "yes" : "no"} customResolver=${this.options.targetResolver ? "yes" : "no"}`,
      );
      return serviceId;
    } catch (err) {
      this.logError(
        `${traceId ?? "resolve"} recipient-resolve failed target=${describeRecipientTarget(target)} net=${this.net ? "yes" : "no"} customResolver=${this.options.targetResolver ? "yes" : "no"}`,
        err,
      );
      throw err;
    }
  }

  private async resolveGroupRecipients(
    members: SignalRecipientTarget[],
    abortSignal: AbortSignal | undefined,
    traceId?: string,
  ): Promise<ServiceId[]> {
    const localAci = Aci.fromUuid(this.options.account.device.aci).getServiceIdString();
    const recipients = new Map<string, ServiceId>();
    for (const member of members) {
      const serviceId = await this.resolveRecipient(member, abortSignal, traceId);
      const key = serviceId.getServiceIdString();
      if (key !== localAci) {
        recipients.set(key, serviceId);
      } else {
        this.logDebug(`${traceId ?? "group"} group-recipient skipped local member=${key}`);
      }
    }
    return [...recipients.values()];
  }

  private async fetchPreKeyBundles({
    destination,
    preKeyAuth,
    abortSignal,
    device,
  }: {
    destination: ServiceId;
    preKeyAuth?: PreKeyAuth;
    abortSignal?: AbortSignal;
    device?: FetchPreKeysParams["device"];
  }): Promise<PreKeyBundle[]> {
    const fetchParams: FetchPreKeysParams = { target: destination };
    if (device !== undefined) {
      fetchParams.device = device;
    }
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
        this.logWarn(
          `Signal chat connection interrupted: ${cause ? describeSignalError(cause) : "null"}`,
        );
        this.events.emit("disconnected", cause);
      },
      onIncomingMessage: (envelope, timestamp, ack) => {
        const traceId = createSignalTraceId("incoming");
        this.logInfo(`${traceId} incoming envelope ${describeIncomingEnvelope(envelope, timestamp)}`);
        this.events.emit("incoming", {
          envelope,
          timestamp,
          ack: () => {
            this.logDebug(`${traceId} incoming ack start status=200`);
            try {
              ack.send(200);
              this.logDebug(`${traceId} incoming ack done status=200`);
            } catch (err) {
              this.logError(`${traceId} incoming ack failed status=200`, err);
              throw err;
            }
          },
        });
      },
      onQueueEmpty: () => {
        this.logDebug("incoming queue empty");
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
