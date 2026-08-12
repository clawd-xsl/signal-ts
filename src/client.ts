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
import type { SendSealedMessageRequest } from "@signalapp/libsignal-client/dist/net/chat/UnauthMessagesService.js";
import type { SignalAccountState, SignalEnvironment } from "./account.js";
import { resolveLibsignalEnvironment } from "./account.js";
import {
  uploadSignalAttachment,
  type AttachmentUploadConnection,
  type EncryptedSignalAttachment,
  type FetchLike,
  type SignalAttachmentInput,
} from "./attachments.js";
import { bytesToHex, utf8Bytes, type Bytes } from "./bytes.js";
import {
  createSignalDecryptionErrorPlaintextContent,
  decryptIncomingEnvelope,
  encryptPayloadForDevice,
  padSignalMessageBody,
  type DecryptedIncomingMessage,
  type DecryptIncomingEnvelopeParams,
  type SignalRetryReceiptRequest,
} from "./crypto.js";
import { SignalTsStateError } from "./errors.js";
import { SignalEventHub } from "./events.js";
import type { SignalEventHandler, SignalEventName } from "./events.js";
import type {
  SignalIncomingEnvelopeAcceptResult,
  SignalIncomingEnvelopeRecord,
  SignalIncomingEnvelopeStore,
} from "./incoming-envelope-store.js";
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
  // Authenticated REST over the live connection. Optional so lightweight test
  // doubles need not implement it; the real libsignal connection always has it.
  fetch?: Net.AuthenticatedChatConnection["fetch"];
  getUploadForm?: AttachmentUploadConnection["getUploadForm"];
  sendMessage: (request: SendMessageRequest, options?: Net.RequestOptions) => Promise<void>;
  sendSyncMessage?: (
    request: SendSyncMessageRequest,
    options?: Net.RequestOptions,
  ) => Promise<void>;
};

export type SignalSealedSenderConnection = Pick<
  Net.UnauthenticatedChatConnection,
  "disconnect" | "connectionInfo"
> & {
  sendMessage: (request: SendSealedMessageRequest, options?: Net.RequestOptions) => Promise<void>;
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
  /** App-level keepalive interval; 0 disables. Default 30s (Signal-Desktop parity). */
  keepaliveIntervalMs?: number;
  /** Per-keepalive timeout before the delivery socket is treated as dead. Default 20s. */
  keepaliveTimeoutMs?: number;
  /** Durable encrypted-envelope inbox used to persist before server acknowledgement. */
  incomingEnvelopeStore?: SignalIncomingEnvelopeStore;
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

export type RecoverIncomingDecryptionFailureParams = {
  retry: SignalRetryReceiptRequest;
  stores: Pick<LibsignalStores, "identityStore" | "sessionStore">;
  preKeyAuth?: PreKeyAuth;
  abortSignal?: AbortSignal;
  traceId?: string;
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
// App-level keepalive. libsignal's own WebSocket ping/pong keeps the socket
// alive at the transport layer, but the server can silently stop delivering
// over an otherwise-ESTABLISHED socket; only an application-level round trip
// (Signal-Desktop/signal-cli GET /v1/keepalive) detects that. On failure the
// delivery socket is dead and we force a reconnect.
const DEFAULT_KEEPALIVE_INTERVAL_MS = 30_000;
const DEFAULT_KEEPALIVE_TIMEOUT_MS = 20_000;
const INITIAL_INCOMING_DRAIN_RETRY_MS = 250;
const MAX_INCOMING_DRAIN_RETRY_MS = 30_000;
const MAX_ACTIVE_INCOMING_DELIVERIES = 16;
const INCOMING_TOMBSTONE_PRUNE_INTERVAL_MS = 24 * 60 * 60 * 1000;
const INCOMING_TOMBSTONE_RETENTION_MS = 7 * INCOMING_TOMBSTONE_PRUNE_INTERVAL_MS;
const KEEPALIVE_PATH = "/v1/keepalive";
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
      "cause" in err && err.cause !== undefined ? `; cause=${describeSignalError(err.cause)}` : "";
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
  return preKeyBundles.map((bundle) => `${bundle.deviceId()}/${bundle.registrationId()}`).join(",");
}

type MismatchedDeviceListName = "missingDevices" | "extraDevices" | "staleDevices";

type DeviceMismatchRepair = {
  refreshDeviceIds: Set<number>;
  refreshAllDevices: boolean;
};

type SessionStoreWithRemoval = Pick<
  LibsignalStores["sessionStore"],
  "getSession" | "saveSession"
> & {
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
  return entries.filter(
    (entry) => describeServiceId(entry.account).toLowerCase() === destinationKey,
  );
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

function splitUtf8TextAtByteLimit(
  text: string,
  limit: number,
): {
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
  private incomingAdmissionQueue: Promise<void> = Promise.resolve();
  private incomingDrainQueue: Promise<void> = Promise.resolve();
  private readonly incomingTasks = new Set<Promise<void>>();
  private readonly activeIncomingEnvelopeClaims = new Map<string, symbol>();
  private serverQueueEmpty = false;
  private incomingDeliveryStarted = false;
  private nextIncomingTombstonePruneAt = 0;
  private acceptingIncoming = false;
  private connectionGeneration = 0;
  private incomingDrainRetryAttempt = 0;
  private incomingDrainRetryTimer: ReturnType<typeof setTimeout> | undefined;
  private readonly connectionCloseTasks = new Set<Promise<void>>();
  private net: Net.Net | undefined;
  private connection: SignalChatConnection | undefined;
  private keepaliveTimer: ReturnType<typeof setInterval> | undefined;
  private keepaliveInFlightGeneration: number | undefined;
  // Last time the server proved this connection alive (a delivered envelope or
  // a successful keepalive). Consumed by the host for stale-socket health.
  private lastTransportActivityAt: number | undefined;

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
    abortSignal: AbortSignal | undefined,
    run: () => Promise<T>,
  ): Promise<T> {
    const previous = this.signalStateMutationQueue;
    let release!: () => void;
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.signalStateMutationQueue = previous.then(
      () => current,
      () => current,
    );
    const waitStartedAt = Date.now();
    await previous.catch(() => undefined);
    const waitMs = Date.now() - waitStartedAt;
    if (waitMs > 0) {
      this.logDebug(`${traceId} ${operation} state-lock acquired waitMs=${waitMs}`);
    }
    try {
      // A queued operation can outlive its caller's deadline while a stalled
      // predecessor holds the lock; running it anyway spends lock time on a
      // result nobody consumes and delays every operation behind it.
      abortSignal?.throwIfAborted();
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

    const providedBundle = preKeyBundles?.find(
      (bundle) => bundle.deviceId() === retry.senderDeviceId,
    );
    const fetchedBundle =
      providedBundle ??
      (
        await this.fetchPreKeyBundles({
          destination,
          ...(preKeyAuth !== undefined ? { preKeyAuth } : {}),
          ...(abortSignal !== undefined ? { abortSignal } : {}),
          device: { deviceId: retry.senderDeviceId },
        })
      ).find((bundle) => bundle.deviceId() === retry.senderDeviceId);
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
    while (this.connectionCloseTasks.size > 0) {
      await Promise.allSettled([...this.connectionCloseTasks]);
    }
    const generation = ++this.connectionGeneration;
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
    this.serverQueueEmpty = false;
    this.incomingDeliveryStarted = false;
    this.acceptingIncoming = true;
    const listener = this.createListener(generation);
    try {
      const connection = await (this.connectionFactory ?? defaultConnectionFactory)({
        net,
        account: this.options.account,
        listener,
        ...(abortSignal ? { abortSignal } : {}),
      });
      if (generation !== this.connectionGeneration) {
        await connection.disconnect().catch(() => undefined);
        throw new SignalTsStateError("Signal chat connection was interrupted while connecting");
      }
      this.connection = connection;
      this.logInfo(`connected to Signal chat (${connection.connectionInfo().toString()})`);
      this.lastTransportActivityAt = Date.now();
      this.startKeepalive(generation);
      this.events.emit("connected", undefined);
    } catch (err) {
      this.invalidateConnectionGeneration(generation);
      this.logError("connect failed", err);
      throw err;
    }
  }

  /** Last time the server proved this connection alive (delivery or keepalive). */
  getLastTransportActivityAt(): number | undefined {
    return this.lastTransportActivityAt;
  }

  /** Starts replay/live delivery after the consumer has made its outbound path ready. */
  async startIncomingDelivery(): Promise<void> {
    const generation = this.connectionGeneration;
    this.incomingDeliveryStarted = true;
    if (this.serverQueueEmpty && this.options.incomingEnvelopeStore) {
      try {
        await this.drainIncomingEnvelopeStore(generation);
      } catch (err) {
        this.scheduleIncomingDrainRetry(generation);
        throw err;
      }
    }
  }

  private startKeepalive(generation: number): void {
    this.stopKeepalive();
    const intervalMs = this.options.keepaliveIntervalMs ?? DEFAULT_KEEPALIVE_INTERVAL_MS;
    if (intervalMs <= 0) {
      return;
    }
    this.keepaliveTimer = setInterval(() => {
      void this.runKeepaliveTick(generation);
    }, intervalMs);
    // Node timers keep the event loop alive; this one should not on its own.
    this.keepaliveTimer.unref?.();
  }

  private stopKeepalive(): void {
    if (this.keepaliveTimer) {
      clearInterval(this.keepaliveTimer);
      this.keepaliveTimer = undefined;
    }
    this.keepaliveInFlightGeneration = undefined;
  }

  private async runKeepaliveTick(generation: number): Promise<void> {
    if (
      generation !== this.connectionGeneration ||
      this.keepaliveInFlightGeneration !== undefined
    ) {
      return;
    }
    const connection = this.connection;
    if (!connection?.fetch) {
      return;
    }
    this.keepaliveInFlightGeneration = generation;
    const timeoutMs = this.options.keepaliveTimeoutMs ?? DEFAULT_KEEPALIVE_TIMEOUT_MS;
    const traceId = createSignalTraceId("keepalive");
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const response = await Promise.race([
        connection.fetch({
          verb: "GET",
          path: KEEPALIVE_PATH,
          headers: [],
          timeoutMillis: timeoutMs,
        }),
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(
            () => reject(new SignalTsStateError(`keepalive timed out after ${timeoutMs}ms`)),
            timeoutMs,
          );
        }),
      ]);
      if (response.status < 200 || response.status >= 300) {
        throw new SignalTsStateError(`keepalive returned HTTP ${response.status}`);
      }
      this.lastTransportActivityAt = Date.now();
      this.logDebug(`${traceId} keepalive ok status=${response.status}`);
    } catch (err) {
      // The delivery socket is dead even if TCP is still ESTABLISHED. Tear it
      // down and surface a disconnect so the monitor reconnects.
      this.logWarn(`${traceId} keepalive failed; forcing reconnect: ${describeSignalError(err)}`);
      this.handleDeadConnection(
        err instanceof Error ? err : new Error(String(err)),
        generation,
      );
    } finally {
      if (timer) {
        clearTimeout(timer);
      }
      if (this.keepaliveInFlightGeneration === generation) {
        this.keepaliveInFlightGeneration = undefined;
      }
    }
  }

  private handleDeadConnection(cause: Error, generation: number): void {
    if (!this.invalidateConnectionGeneration(generation)) {
      return;
    }
    const connection = this.connection;
    this.connection = undefined;
    if (connection) {
      this.trackConnectionClose(connection.disconnect().catch(() => undefined));
    }
    this.events.emit("disconnected", cause);
  }

  async disconnect(): Promise<void> {
    this.invalidateConnectionGeneration(this.connectionGeneration);
    const connection = this.connection;
    this.connection = undefined;
    let disconnectError: unknown;
    if (connection) {
      this.logDebug(`disconnect start (${connection.connectionInfo().toString()})`);
      try {
        await connection.disconnect();
        this.logDebug("disconnect done");
      } catch (err) {
        this.logError("disconnect failed", err);
        disconnectError = err;
      }
    }
    while (this.incomingTasks.size > 0) {
      await Promise.allSettled([...this.incomingTasks]);
    }
    while (this.connectionCloseTasks.size > 0) {
      await Promise.allSettled([...this.connectionCloseTasks]);
    }
    if (disconnectError !== undefined) {
      throw disconnectError;
    }
  }

  /**
   * Issue an authenticated REST request over the EXISTING chat connection. Signal
   * permits only one authenticated socket per device, so callers (e.g. calling
   * TURN fetch) must reuse this rather than opening a second connection — a
   * second authenticated connect triggers a server-side ConnectedElsewhere that
   * disconnects the monitor.
   */
  async fetchAuthenticated(
    ...args: Parameters<NonNullable<SignalChatConnection["fetch"]>>
  ): ReturnType<NonNullable<SignalChatConnection["fetch"]>> {
    const connection = this.connection;
    if (!connection?.fetch) {
      throw new SignalTsStateError("SignalTsClient is not connected");
    }
    return await connection.fetch(...args);
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
      // Recipient resolution and prekey fetches are pure network reads and run
      // OUTSIDE the session-state lock: a stalled unauthenticated prekey
      // connection here used to hold the ratchet lock for tens of seconds,
      // starving inbound decrypts and expiring queued sends (one typing
      // indicator could cost the actual reply).
      const destination = await this.resolveRecipient(
        params.destination,
        params.abortSignal,
        traceId,
      );
      this.logDebug(
        `${traceId} content-send resolved target=${describeRecipientTarget(params.destination)} destination=${describeServiceId(destination)}`,
      );
      let preKeyBundles = params.preKeyBundles;
      if (!preKeyBundles) {
        const warmDeviceIds = await this.listSessionDeviceIds(
          destination,
          params.stores.sessionStore,
        );
        if (warmDeviceIds.length > 0) {
          this.logDebug(
            `${traceId} content-send warm destination=${describeServiceId(destination)} devices=${warmDeviceIds.join(",")}`,
          );
        } else {
          this.logDebug(
            `${traceId} content-send prekeys start destination=${describeServiceId(destination)} source=fetch auth=${params.preKeyAuth ? "yes" : "no"}`,
          );
          preKeyBundles = await this.fetchPreKeyBundles({
            destination,
            ...(params.preKeyAuth !== undefined ? { preKeyAuth: params.preKeyAuth } : {}),
            ...(params.abortSignal !== undefined ? { abortSignal: params.abortSignal } : {}),
          });
          this.logDebug(
            `${traceId} content-send prekeys done destination=${describeServiceId(destination)} count=${preKeyBundles.length} devices=${describePreKeyBundleDevices(preKeyBundles)}`,
          );
          if (preKeyBundles.length === 0) {
            throw new SignalTsStateError("Signal recipient has no available prekey bundles");
          }
        }
      }
      return await this.runSerializedSignalStateMutation(
        traceId,
        "content-send",
        params.abortSignal,
        async () =>
          await this.sendContentMessageLocked({
            ...params,
            traceId,
            timestamp,
            destination,
            ...(preKeyBundles !== undefined ? { preKeyBundles } : {}),
          }),
      );
    } catch (err) {
      this.logError(
        `${traceId} content-send failed target=${describeRecipientTarget(params.destination)} timestamp=${timestamp} content=${describeSignalContent(params.content)}`,
        err,
      );
      throw err;
    }
  }

  /** Device ids with an established session, readable without the state lock. */
  private async listSessionDeviceIds(
    destination: ServiceId,
    sessionStore: SendContentMessageParams["stores"]["sessionStore"],
  ): Promise<number[]> {
    const store = sessionStore as
      | { listDeviceIds?: (serviceId: string) => Promise<number[]> }
      | undefined;
    if (!store || typeof store.listDeviceIds !== "function") {
      // Custom stores without enumeration keep the bundle-driven path.
      return [];
    }
    const serviceId = ProtocolAddress.new(destination, 1).name();
    const deviceIds = await store.listDeviceIds(serviceId);
    if (typeof sessionStore.getSession !== "function") {
      return deviceIds;
    }
    const usableDeviceIds: number[] = [];
    for (const deviceId of deviceIds) {
      const session = await sessionStore.getSession(ProtocolAddress.new(destination, deviceId));
      const hasCurrentState = (
        session as { hasCurrentState?: (requirePqRatio: number, now?: Date) => boolean } | null
      )?.hasCurrentState;
      // libsignal-client 0.96.4 requires the PQ ratio first; zero asks only
      // whether an active sender chain exists, excluding archived sessions.
      if (session && (!hasCurrentState || hasCurrentState.call(session, 0))) {
        usableDeviceIds.push(deviceId);
      }
    }
    return usableDeviceIds;
  }

  /**
   * Decrypts one inbound envelope under the same session-state lock as outbound
   * encryption. libsignal sessions are not safe for concurrent mutation, so
   * running decryption off this lock races the outbound ratchet (e.g. a typing
   * send) and corrupts the session, after which the peer can no longer decrypt
   * our messages. Callers MUST use this instead of the standalone
   * decryptIncomingEnvelope for any session that also sends.
   */
  async decryptIncoming(
    params: DecryptIncomingEnvelopeParams & { traceId?: string },
  ): Promise<DecryptedIncomingMessage> {
    const traceId = params.traceId ?? createSignalTraceId("incoming-decrypt");
    return await this.runSerializedSignalStateMutation(
      traceId,
      "incoming-decrypt",
      undefined,
      async () => decryptIncomingEnvelope(params),
    );
  }

  /**
   * Archives our session with one peer device so the next outbound message
   * re-establishes a fresh session via a prekey handshake. Called when the peer
   * reports it could not decrypt one of our messages (a DecryptionErrorMessage /
   * retry request): the ratchet has diverged, and only a new session recovers
   * it — otherwise the peer keeps showing "message couldn't be delivered".
   */
  async archiveSessionForPeer(params: {
    serviceId: string;
    deviceId: number;
    stores: Pick<LibsignalStores, "sessionStore">;
    traceId?: string;
  }): Promise<void> {
    const traceId = params.traceId ?? createSignalTraceId("session-archive");
    await this.runSerializedSignalStateMutation(traceId, "session-archive", undefined, async () =>
      this.removeRecipientSessionDevice({
        traceId,
        operation: "session-archive",
        destination: Aci.fromUuid(params.serviceId),
        deviceId: params.deviceId,
        sessionStore: params.stores.sessionStore,
      }),
    );
  }

  /** Archives every device session for a sender, matching signal-cli session renewal. */
  async archiveSessionsForPeer(params: {
    serviceId: string;
    stores: Pick<LibsignalStores, "sessionStore">;
    traceId?: string;
    abortSignal?: AbortSignal;
  }): Promise<void> {
    const traceId = params.traceId ?? createSignalTraceId("sessions-archive");
    await this.runSerializedSignalStateMutation(
      traceId,
      "sessions-archive",
      params.abortSignal,
      async () => {
        const destination = Aci.fromUuid(params.serviceId);
        const store = params.stores.sessionStore as typeof params.stores.sessionStore & {
          listDeviceIds?: (serviceId: string) => Promise<number[]>;
        };
        if (!store.listDeviceIds) {
          throw new SignalTsStateError(
            "Signal session recovery requires a session store with device enumeration",
          );
        }
        const deviceIds = await store.listDeviceIds(ProtocolAddress.new(destination, 1).name());
        for (const deviceId of deviceIds) {
          const address = ProtocolAddress.new(destination, deviceId);
          const session = await store.getSession(address);
          if (!session) {
            continue;
          }
          session.archiveCurrentState();
          await store.saveSession(address, session);
          this.logDebug(
            `${traceId} sessions-archive archived destination=${describeServiceId(destination)} device=${deviceId}`,
          );
        }
      },
    );
  }

  /**
   * Restores a failed inbound session exactly like signal-cli: archive all
   * sender sessions, establish fresh sessions with a null message, then ask
   * the sender to resend the original ciphertext.
   */
  async recoverIncomingDecryptionFailure(
    params: RecoverIncomingDecryptionFailureParams,
  ): Promise<void> {
    const traceId = params.traceId ?? createSignalTraceId("incoming-recovery");
    const destination = params.retry.recipientServiceId;
    await this.archiveSessionsForPeer({
      serviceId: destination,
      stores: params.stores,
      traceId: `${traceId}:archive`,
      ...(params.abortSignal === undefined ? {} : { abortSignal: params.abortSignal }),
    });
    // Once current sessions are archived, finish the repair even if the caller
    // cancels. Stopping between archive and the null message strands the peer.
    await this.sendContentMessage({
      destination,
      content: { nullMessage: { padding: new Uint8Array() } },
      stores: params.stores,
      ...(params.preKeyAuth === undefined ? {} : { preKeyAuth: params.preKeyAuth }),
      traceId: `${traceId}:null-message`,
    });
    await this.sendRetryReceiptMessage({
      destination,
      retry: params.retry,
      stores: params.stores,
      ...(params.preKeyAuth === undefined ? {} : { preKeyAuth: params.preKeyAuth }),
      traceId: `${traceId}:retry-receipt`,
    });
  }

  private async sendContentMessageLocked(
    params: Omit<SendContentMessageParams, "destination"> & {
      traceId: string;
      timestamp: number;
      destination: ServiceId;
    },
  ): Promise<{ timestamp: number }> {
    const { traceId, timestamp, destination } = params;
    const payload = encodeSignalContent(params.content);
    this.logDebug(`${traceId} content-send payload encoded bytes=${payload.byteLength}`);
    let contents =
      params.preKeyBundles !== undefined
        ? await this.buildDirectContentMessageContents({
            traceId,
            operation: "content-send",
            destination,
            payload,
            stores: params.stores,
            preKeyBundles: params.preKeyBundles,
          })
        : await this.buildWarmContentMessageContents({
            traceId,
            operation: "content-send",
            destination,
            payload,
            stores: params.stores,
          });
    if (contents === null) {
      // The warm sessions seen by the unlocked peek were archived before we
      // acquired the lock. Rare enough that this in-lock fetch is acceptable;
      // correctness beats latency on this path.
      const preKeyBundles = await this.fetchPreKeyBundles({
        destination,
        ...(params.preKeyAuth !== undefined ? { preKeyAuth: params.preKeyAuth } : {}),
        ...(params.abortSignal !== undefined ? { abortSignal: params.abortSignal } : {}),
      });
      this.logDebug(
        `${traceId} content-send warm-fallback prekeys done destination=${describeServiceId(destination)} count=${preKeyBundles.length} devices=${describePreKeyBundleDevices(preKeyBundles)}`,
      );
      if (preKeyBundles.length === 0) {
        throw new SignalTsStateError("Signal recipient has no available prekey bundles");
      }
      contents = await this.buildDirectContentMessageContents({
        traceId,
        operation: "content-send",
        destination,
        payload,
        stores: params.stores,
        preKeyBundles,
      });
    }
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
  }

  /**
   * Encrypts to every device we already hold a session for, skipping the
   * per-send prekey fetch entirely. A stale device set is corrected by the
   * server's mismatched-devices response on send — the same repair contract
   * the bundle-driven path relies on. Returns null when no session survives,
   * so the caller falls back to prekey bundles.
   */
  private async buildWarmContentMessageContents({
    traceId,
    operation,
    destination,
    payload,
    stores,
  }: {
    traceId: string;
    operation: string;
    destination: ServiceId;
    payload: Uint8Array<ArrayBuffer>;
    stores: Pick<LibsignalStores, "identityStore" | "sessionStore">;
  }): Promise<Array<SendMessageRequest["contents"][number]> | null> {
    const deviceIds = await this.listSessionDeviceIds(destination, stores.sessionStore);
    if (deviceIds.length === 0) {
      return null;
    }
    const localAddress = this.localAddress();
    const contents: Array<SendMessageRequest["contents"][number]> = [];
    for (const deviceId of deviceIds) {
      const remoteAddress = ProtocolAddress.new(destination, deviceId);
      const session = await stores.sessionStore.getSession(remoteAddress);
      if (!session) {
        continue;
      }
      this.logDebug(
        `${traceId} ${operation} encrypt device=${deviceId} registration=${session.remoteRegistrationId()} source=session`,
      );
      const encrypted = await encryptPayloadForDevice({
        localAddress,
        device: {
          serviceId: destination,
          deviceId,
          registrationId: session.remoteRegistrationId(),
        },
        payload,
        stores,
      });
      contents.push(encrypted);
    }
    return contents.length > 0 ? contents : null;
  }

  async sendRetryReceiptMessage(
    params: SendRetryReceiptMessageParams,
  ): Promise<{ timestamp: number }> {
    const traceId = params.traceId ?? createSignalTraceId("retry-receipt");
    return await this.runSerializedSignalStateMutation(
      traceId,
      "retry-receipt",
      params.abortSignal,
      async () => {
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
      },
    );
  }

  async sendSealedContentMessage(
    params: SendSealedContentMessageParams,
  ): Promise<{ timestamp: number }> {
    const traceId = params.traceId ?? createSignalTraceId("sealed");
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
      // Resolution, prekey fetches, and the sealed-sender connection are pure
      // network work and stay OUTSIDE the session-state lock; only bundle
      // processing and ratchet encryption below mutate session state.
      const destination = await this.resolveRecipient(
        params.destination,
        params.abortSignal,
        traceId,
      );
      this.logDebug(
        `${traceId} sealed-send prekeys start destination=${describeServiceId(destination)} source=${params.preKeyBundles ? "provided" : "fetch"} auth=${params.preKeyAuth ? "yes" : "no"}`,
      );
      const preKeyBundles =
        params.preKeyBundles ??
        (await this.fetchPreKeyBundles({
          destination,
          ...(params.preKeyAuth !== undefined ? { preKeyAuth: params.preKeyAuth } : {}),
          ...(params.abortSignal !== undefined ? { abortSignal: params.abortSignal } : {}),
        }));
      this.logDebug(
        `${traceId} sealed-send prekeys done destination=${describeServiceId(destination)} count=${preKeyBundles.length} devices=${describePreKeyBundleDevices(preKeyBundles)}`,
      );
      if (preKeyBundles.length === 0) {
        throw new SignalTsStateError("Signal recipient has no available prekey bundles");
      }
      // Bundle processing and sealed-sender encryption mutate session state,
      // so only this block holds the lock; the connection and send below are
      // pure network work.
      const contents = await this.runSerializedSignalStateMutation(
        traceId,
        "sealed-send",
        params.abortSignal,
        async () => {
          const localAddress = this.localAddress();
          const payload = encodeSignalContent(params.content);
          const encryptedContents: Array<SendSealedMessageRequest["contents"][number]> = [];
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
            encryptedContents.push({
              deviceId: bundle.deviceId(),
              registrationId: bundle.registrationId(),
              contents: encrypted,
            });
          }
          return encryptedContents;
        },
      );

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
    return await this.runSerializedSignalStateMutation(
      traceId,
      "sync-content",
      params.abortSignal,
      async () => {
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
      },
    );
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
      // Same contract as sendContentMessage: recipient resolution and member
      // prekey fetches are pure network reads and run OUTSIDE the state lock.
      // Members we already hold sessions for skip the fetch entirely; their
      // devices are enumerated from the session store inside the lock.
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
      const memberBundles = new Map<string, PreKeyBundle[]>();
      for (const destination of recipients) {
        const memberKey = destination.getServiceIdString();
        const providedBundles = params.memberPreKeyBundles?.get(memberKey);
        if (providedBundles) {
          memberBundles.set(memberKey, providedBundles);
          continue;
        }
        const warmDeviceIds = await this.listSessionDeviceIds(
          destination,
          params.stores.sessionStore,
        );
        if (warmDeviceIds.length > 0) {
          this.logDebug(
            `${traceId} group-content member warm destination=${describeServiceId(destination)} devices=${warmDeviceIds.join(",")}`,
          );
          continue;
        }
        this.logDebug(
          `${traceId} group-content member prekeys start destination=${describeServiceId(destination)} source=fetch auth=${params.preKeyAuth ? "yes" : "no"}`,
        );
        const bundles = await this.fetchPreKeyBundlesForGroupMember({
          destination,
          preKeyAuth: params.preKeyAuth,
          abortSignal: params.abortSignal,
        });
        this.logDebug(
          `${traceId} group-content member prekeys done destination=${describeServiceId(destination)} count=${bundles.length} devices=${describePreKeyBundleDevices(bundles)}`,
        );
        memberBundles.set(memberKey, bundles);
      }
      return await this.runSerializedSignalStateMutation(
        traceId,
        "group-content",
        params.abortSignal,
        async () =>
          await this.sendGroupContentMessageLocked({
            ...params,
            traceId,
            timestamp,
            recipients,
            memberBundles,
          }),
      );
    } catch (err) {
      this.logError(
        `${traceId} group-content failed timestamp=${timestamp} members=${params.members.length} content=${describeSignalContent(params.content)}`,
        err,
      );
      throw err;
    }
  }

  private async sendGroupContentMessageLocked(
    params: SendGroupContentMessageParams & {
      traceId: string;
      timestamp: number;
      recipients: ServiceId[];
      memberBundles: ReadonlyMap<string, PreKeyBundle[]>;
    },
  ): Promise<{
    timestamp: number;
    recipients: number;
  }> {
    const { traceId, timestamp, recipients, memberBundles } = params;
    const localAddress = ProtocolAddress.new(
      Aci.fromUuid(this.options.account.device.aci),
      this.options.account.device.deviceId,
    );
    const senderKeyDistribution = await SenderKeyDistributionMessage.create(
      localAddress,
      params.group.distributionId,
      params.stores.senderKeyStore,
    );
    const senderKeyDistributionBytes = senderKeyDistribution.serialize();
    this.logDebug(
      `${traceId} group-content sender-key-distribution created bytes=${senderKeyDistributionBytes.byteLength}`,
    );
    for (const destination of recipients) {
      const bundles = memberBundles.get(destination.getServiceIdString());
      // Warm members (no fetched bundles) take the session-driven path; if
      // their sessions were archived since the unlocked peek, the locked
      // send falls back to an in-lock bundle fetch and re-establishes them.
      await this.sendContentMessageLocked({
        traceId: `${traceId}:sender-key:${describeServiceId(destination)}`,
        destination,
        content: { senderKeyDistributionMessage: senderKeyDistributionBytes },
        stores: params.stores,
        ...(bundles !== undefined ? { preKeyBundles: bundles } : {}),
        timestamp,
        ...(params.preKeyAuth !== undefined ? { preKeyAuth: params.preKeyAuth } : {}),
        ...(params.onlineOnly !== undefined ? { onlineOnly: params.onlineOnly } : {}),
        ...(params.urgent !== undefined ? { urgent: params.urgent } : {}),
        ...(params.abortSignal ? { abortSignal: params.abortSignal } : {}),
      });
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
      recipients.map(async (destination) => {
        const devices = await this.resolveGroupFanoutDevices({
          destination,
          bundles: memberBundles.get(destination.getServiceIdString()),
          sessionStore: params.stores.sessionStore,
        });
        const contents = devices.map((device) => ({
          deviceId: device.deviceId,
          registrationId: device.registrationId,
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
  }

  /**
   * Devices for one group fanout target: fetched bundles for cold members,
   * the session store for warm ones. Runs inside the state lock, after the
   * sender-key distribution send has (re-)established any missing sessions.
   */
  private async resolveGroupFanoutDevices({
    destination,
    bundles,
    sessionStore,
  }: {
    destination: ServiceId;
    bundles: PreKeyBundle[] | undefined;
    sessionStore: LibsignalStores["sessionStore"];
  }): Promise<Array<{ deviceId: number; registrationId: number }>> {
    if (bundles !== undefined) {
      return bundles.map((bundle) => ({
        deviceId: bundle.deviceId(),
        registrationId: bundle.registrationId(),
      }));
    }
    const devices: Array<{ deviceId: number; registrationId: number }> = [];
    for (const deviceId of await this.listSessionDeviceIds(destination, sessionStore)) {
      const session = await sessionStore.getSession(ProtocolAddress.new(destination, deviceId));
      if (session) {
        devices.push({ deviceId, registrationId: session.remoteRegistrationId() });
      }
    }
    return devices;
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
    this.logDebug(
      `${traceId} attachment-upload start ${describeAttachmentInput(params.attachment)}`,
    );
    const getUploadForm: AttachmentUploadConnection["getUploadForm"] = async (request, options) => {
      this.logDebug(`${traceId} attachment-upload form start uploadSize=${request.uploadSize}`);
      try {
        const form = await connection.getUploadForm!.call(connection, request, options);
        this.logDebug(
          `${traceId} attachment-upload form done cdn=${form.cdn} key=${form.key} signedUrl=${form.signedUploadUrl.toString()}`,
        );
        return form;
      } catch (err) {
        this.logError(
          `${traceId} attachment-upload form failed uploadSize=${request.uploadSize}`,
          err,
        );
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
      this.logError(
        `${traceId} attachment-upload failed ${describeAttachmentInput(params.attachment)}`,
        err,
      );
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

  private createListener(generation: number): Net.ChatServiceListener {
    return {
      onConnectionInterrupted: (cause) => {
        if (generation !== this.connectionGeneration) {
          return;
        }
        this.logWarn(
          `Signal chat connection interrupted: ${cause ? describeSignalError(cause) : "null"}`,
        );
        this.handleDeadConnection(
          cause ?? new Error("Signal chat connection interrupted"),
          generation,
        );
      },
      onIncomingMessage: (envelope, timestamp, ack) => {
        const traceId = createSignalTraceId("incoming");
        if (generation !== this.connectionGeneration || !this.acceptingIncoming) {
          // Do not ACK a callback racing shutdown. Signal retains it for the
          // next authenticated connection, where it can be persisted first.
          this.logWarn(`${traceId} incoming skipped while delivery is stopping`);
          return;
        }
        // A delivered envelope proves the socket is live.
        this.lastTransportActivityAt = Date.now();
        this.logInfo(
          `${traceId} incoming envelope ${describeIncomingEnvelope(envelope, timestamp)}`,
        );
        if (!this.options.incomingEnvelopeStore) {
          this.events.emit("incoming", {
            envelope,
            timestamp,
            ack: async () => {
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
          return;
        }
        this.trackIncomingTask(
          this.admitIncomingEnvelope({
            envelope,
            timestamp,
            generation,
            sendServerAck: () => ack.send(200),
          }),
        );
      },
      onQueueEmpty: () => {
        if (generation !== this.connectionGeneration) {
          return;
        }
        this.logDebug("incoming queue empty");
        this.serverQueueEmpty = true;
        if (this.options.incomingEnvelopeStore && this.incomingDeliveryStarted) {
          this.requestIncomingDrain(generation);
        }
        this.events.emit("queueEmpty", undefined);
      },
      onReceivedAlerts: (alerts) => {
        if (generation !== this.connectionGeneration) {
          return;
        }
        if (alerts.length > 0) {
          this.logger?.warn?.(`Signal chat alerts: ${alerts.join(", ")}`);
        }
      },
    };
  }

  private trackIncomingTask(task: Promise<void>): void {
    const tracked = task
      .catch((err) => {
        this.logError("incoming durable-envelope task failed", err);
      })
      .finally(() => this.incomingTasks.delete(tracked));
    this.incomingTasks.add(tracked);
  }

  private async admitIncomingEnvelope(params: {
    envelope: Bytes;
    timestamp: number;
    generation: number;
    sendServerAck: () => void;
  }): Promise<void> {
    const run = this.incomingAdmissionQueue.then(async () => {
      if (params.generation !== this.connectionGeneration || !this.acceptingIncoming) {
        return;
      }
      await this.acceptIncomingEnvelope(params);
    });
    this.incomingAdmissionQueue = run.catch(() => undefined);
    await run;
  }

  private async acceptIncomingEnvelope(params: {
    envelope: Bytes;
    timestamp: number;
    generation: number;
    sendServerAck: () => void;
  }): Promise<void> {
    const store = this.options.incomingEnvelopeStore;
    if (!store) {
      return;
    }
    let accepted: SignalIncomingEnvelopeAcceptResult;
    try {
      accepted = await store.accept({
        envelope: params.envelope,
        serverDeliveredTimestamp: params.timestamp,
      });
    } catch (err) {
      // We cannot ACK bytes that are not durable. Closing the socket makes the
      // Signal server retain and redeliver the envelope on the next connection.
      this.handleDeadConnection(
        err instanceof Error ? err : new SignalTsStateError(String(err)),
        params.generation,
      );
      throw err;
    }
    this.logDebug(
      `incoming cached id=${accepted.record.id} duplicate=${accepted.duplicate ? "yes" : "no"}`,
    );
    if (params.generation !== this.connectionGeneration || !this.acceptingIncoming) {
      return;
    }
    try {
      params.sendServerAck();
      this.logDebug(`incoming server ack done id=${accepted.record.id} status=200`);
    } catch (err) {
      this.logError(`incoming server ack failed id=${accepted.record.id} status=200`, err);
      this.handleDeadConnection(
        err instanceof Error ? err : new SignalTsStateError(String(err)),
        params.generation,
      );
      return;
    }
    if (
      accepted.record.completedAt !== undefined ||
      !this.serverQueueEmpty ||
      !this.incomingDeliveryStarted
    ) {
      return;
    }
    try {
      await this.drainIncomingEnvelopeStore(params.generation);
    } catch (err) {
      this.scheduleIncomingDrainRetry(params.generation);
      throw err;
    }
  }

  private async drainIncomingEnvelopeStore(generation: number): Promise<void> {
    const store = this.options.incomingEnvelopeStore;
    if (!store || !this.isIncomingDeliveryActive(generation)) {
      return;
    }
    const run = this.incomingDrainQueue.then(async () => {
      if (!this.isIncomingDeliveryActive(generation)) {
        return;
      }
      const now = Date.now();
      if (now >= this.nextIncomingTombstonePruneAt) {
        await store.pruneCompleted(now - INCOMING_TOMBSTONE_RETENTION_MS);
        if (!this.isIncomingDeliveryActive(generation)) {
          return;
        }
        this.nextIncomingTombstonePruneAt = now + INCOMING_TOMBSTONE_PRUNE_INTERVAL_MS;
      }
      if (this.activeIncomingEnvelopeClaims.size >= MAX_ACTIVE_INCOMING_DELIVERIES) {
        this.clearIncomingDrainRetry();
        return;
      }
      for (const record of await store.listPending(MAX_ACTIVE_INCOMING_DELIVERIES)) {
        if (!this.isIncomingDeliveryActive(generation)) {
          return;
        }
        this.emitDurableIncomingEnvelope(record, generation);
        if (this.activeIncomingEnvelopeClaims.size >= MAX_ACTIVE_INCOMING_DELIVERIES) {
          break;
        }
      }
      if (this.isIncomingDeliveryActive(generation)) {
        this.clearIncomingDrainRetry();
      }
    });
    this.incomingDrainQueue = run.catch(() => undefined);
    await run;
  }

  private emitDurableIncomingEnvelope(
    record: SignalIncomingEnvelopeRecord,
    generation: number,
  ): void {
    if (
      !this.isIncomingDeliveryActive(generation) ||
      this.activeIncomingEnvelopeClaims.has(record.id)
    ) {
      return;
    }
    const claim = Symbol(record.id);
    this.activeIncomingEnvelopeClaims.set(record.id, claim);
    let completion: Promise<void> | undefined;
    try {
      this.events.emit("incoming", {
        envelope: record.envelope,
        timestamp: record.serverDeliveredTimestamp,
        ack: () => {
          completion ??= this.options
            .incomingEnvelopeStore!.complete(record.id)
            .then(() => {
              this.logDebug(`incoming consumer complete id=${record.id}`);
              if (this.activeIncomingEnvelopeClaims.get(record.id) === claim) {
                this.activeIncomingEnvelopeClaims.delete(record.id);
                this.requestIncomingDrain(generation);
              }
            })
            .catch((err) => {
              completion = undefined;
              if (this.activeIncomingEnvelopeClaims.get(record.id) === claim) {
                this.activeIncomingEnvelopeClaims.delete(record.id);
                this.scheduleIncomingDrainRetry(generation);
              }
              throw err;
            });
          return completion;
        },
      });
    } catch (err) {
      if (this.activeIncomingEnvelopeClaims.get(record.id) === claim) {
        this.activeIncomingEnvelopeClaims.delete(record.id);
      }
      throw err;
    }
  }

  private isIncomingDeliveryActive(generation: number): boolean {
    return (
      generation === this.connectionGeneration &&
      this.acceptingIncoming &&
      this.serverQueueEmpty &&
      this.incomingDeliveryStarted
    );
  }

  private requestIncomingDrain(generation: number): void {
    this.trackIncomingTask(
      this.drainIncomingEnvelopeStore(generation).catch((err) => {
        this.scheduleIncomingDrainRetry(generation);
        throw err;
      }),
    );
  }

  private scheduleIncomingDrainRetry(generation: number): void {
    if (!this.isIncomingDeliveryActive(generation) || this.incomingDrainRetryTimer) {
      return;
    }
    const delay = Math.min(
      MAX_INCOMING_DRAIN_RETRY_MS,
      INITIAL_INCOMING_DRAIN_RETRY_MS * 2 ** this.incomingDrainRetryAttempt,
    );
    this.incomingDrainRetryAttempt += 1;
    this.incomingDrainRetryTimer = setTimeout(() => {
      this.incomingDrainRetryTimer = undefined;
      this.requestIncomingDrain(generation);
    }, delay);
    this.incomingDrainRetryTimer.unref?.();
    this.logWarn(`incoming durable-envelope drain retry scheduled in ${delay}ms`);
  }

  private clearIncomingDrainRetry(): void {
    if (this.incomingDrainRetryTimer) {
      clearTimeout(this.incomingDrainRetryTimer);
      this.incomingDrainRetryTimer = undefined;
    }
    this.incomingDrainRetryAttempt = 0;
  }

  private invalidateConnectionGeneration(generation: number): boolean {
    if (generation !== this.connectionGeneration) {
      return false;
    }
    this.connectionGeneration += 1;
    this.stopKeepalive();
    this.acceptingIncoming = false;
    this.serverQueueEmpty = false;
    this.incomingDeliveryStarted = false;
    this.clearIncomingDrainRetry();
    this.activeIncomingEnvelopeClaims.clear();
    return true;
  }

  private trackConnectionClose(task: Promise<void>): void {
    const tracked = task.finally(() => this.connectionCloseTasks.delete(tracked));
    this.connectionCloseTasks.add(tracked);
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
  return (await net.connectAuthenticatedChat(
    account.auth.username,
    account.auth.password,
    account.receiveStories ?? false,
    listener,
    abortSignal ? { abortSignal } : undefined,
  )) as unknown as SignalChatConnection;
}

async function defaultSealedSenderConnectionFactory({
  net,
  abortSignal,
}: {
  net: Net.Net;
  abortSignal?: AbortSignal;
}): Promise<SignalSealedSenderConnection> {
  return (await net.connectUnauthenticatedChat(
    { onConnectionInterrupted: () => {} },
    abortSignal ? { abortSignal } : undefined,
  )) as unknown as SignalSealedSenderConnection;
}

function resolveDestination(destination: ServiceId | string): ServiceId {
  if (typeof destination !== "string") {
    return destination;
  }
  return Aci.fromUuid(destination);
}

function resolveSealedSenderAuth(
  auth: SealedSenderAuth | undefined,
): SendSealedMessageRequest["auth"] {
  if (!auth || auth.kind === "unrestricted") {
    return "unrestricted";
  }
  if (auth.kind === "story") {
    return "story";
  }
  return { accessKey: auth.accessKey };
}
