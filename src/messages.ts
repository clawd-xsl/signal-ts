import { fileURLToPath } from "node:url";
import protobuf from "protobufjs";
import { copyBytes, type Bytes } from "./bytes.js";
import { SignalTsStateError } from "./errors.js";

export const enum SignalEnvelopeType {
  Unknown = 0,
  DoubleRatchet = 1,
  PreKeyMessage = 3,
  ServerDeliveryReceipt = 5,
  UnidentifiedSender = 6,
  SenderKey = 7,
  PlaintextContent = 8,
}

export type SignalEnvelope = {
  type?: SignalEnvelopeType;
  sourceServiceId?: string;
  sourceDeviceId?: number;
  destinationServiceId?: string;
  clientTimestamp?: number;
  content?: Bytes;
  serverGuid?: string;
  serverTimestamp?: number;
  urgent?: boolean;
  sourceServiceIdBinary?: Bytes;
  destinationServiceIdBinary?: Bytes;
};

export type SignalAttachmentPointer = {
  cdnId?: number;
  cdnKey?: string;
  clientUuid?: Bytes;
  contentType?: string;
  key?: Bytes;
  size?: number;
  thumbnail?: Bytes;
  digest?: Bytes;
  incrementalMac?: Bytes;
  chunkSize?: number;
  fileName?: string;
  flags?: number;
  width?: number;
  height?: number;
  caption?: string;
  blurHash?: string;
  uploadTimestamp?: number;
  cdnNumber?: number;
};

export type SignalBodyRange = {
  start?: number;
  length?: number;
  mentionAci?: string;
  mentionAciBinary?: Bytes;
  style?: number;
};

export type SignalQuote = {
  id?: number;
  authorAci?: string;
  text?: string;
  attachments?: Array<Record<string, unknown>>;
  bodyRanges?: SignalBodyRange[];
  type?: number;
  authorAciBinary?: Bytes;
};

export type SignalReaction = {
  emoji?: string;
  remove?: boolean;
  targetAuthorAci?: string;
  targetAuthorAciBinary?: Bytes;
  targetSentTimestamp?: number;
};

export type SignalGroupContextV2 = {
  masterKey?: Bytes;
  revision?: number;
  groupChange?: Bytes;
};

export type SignalSticker = {
  packId?: Bytes;
  packKey?: Bytes;
  stickerId?: number;
  data?: SignalAttachmentPointer;
  emoji?: string;
};

export type SignalDataMessage = {
  body?: string;
  attachments?: SignalAttachmentPointer[];
  groupV2?: SignalGroupContextV2;
  flags?: number;
  expireTimer?: number;
  expireTimerVersion?: number;
  profileKey?: Bytes;
  timestamp?: number;
  quote?: SignalQuote;
  sticker?: SignalSticker;
  requiredProtocolVersion?: number;
  isViewOnce?: boolean;
  reaction?: SignalReaction;
  delete?: { targetSentTimestamp?: number };
  bodyRanges?: SignalBodyRange[];
  storyContext?: Record<string, unknown>;
  edit?: Record<string, unknown>;
};

export type SignalReceiptType = "delivery" | "read" | "viewed";

export type SignalReceiptMessage = {
  type?: SignalReceiptType;
  timestamps?: number[];
};

export type SignalTypingAction = "started" | "stopped";

export type SignalTypingMessage = {
  timestamp?: number;
  action?: SignalTypingAction;
  groupId?: Bytes;
};

export type SignalContent = {
  dataMessage?: SignalDataMessage;
  syncMessage?: Record<string, unknown>;
  callMessage?: Record<string, unknown>;
  nullMessage?: { padding?: Bytes };
  receiptMessage?: SignalReceiptMessage;
  typingMessage?: SignalTypingMessage;
  senderKeyDistributionMessage?: Bytes;
  decryptionErrorMessage?: Bytes;
  storyMessage?: Record<string, unknown>;
  editMessage?: {
    targetSentTimestamp?: number;
    dataMessage?: SignalDataMessage;
  };
  pniSignatureMessage?: Record<string, unknown>;
};

export type SignalProvisionEnvelope = {
  publicKey?: Bytes;
  body?: Bytes;
};

export type SignalProvisionMessage = {
  aciIdentityKeyPublic?: Bytes;
  aciIdentityKeyPrivate?: Bytes;
  pniIdentityKeyPublic?: Bytes;
  pniIdentityKeyPrivate?: Bytes;
  aci?: string;
  pni?: string;
  number?: string;
  provisioningCode?: string;
  userAgent?: string;
  profileKey?: Bytes;
  readReceipts?: boolean;
  provisioningVersion?: number;
  masterKey?: Bytes;
  ephemeralBackupKey?: Bytes;
  accountEntropyPool?: string;
  mediaRootBackupKey?: Bytes;
  aciBinary?: Bytes;
  pniBinary?: Bytes;
};

export type SignalDeviceName = {
  ephemeralPublic?: Bytes;
  syntheticIv?: Bytes;
  ciphertext?: Bytes;
};

const signalProtoRoot = protobuf.loadSync(
  fileURLToPath(new URL("../protos/SignalService.proto", import.meta.url)),
);
const deviceMessagesProtoRoot = protobuf.loadSync(
  fileURLToPath(new URL("../protos/DeviceMessages.proto", import.meta.url)),
);
const deviceNameProtoRoot = protobuf.loadSync(
  fileURLToPath(new URL("../protos/DeviceName.proto", import.meta.url)),
);
const envelopeType = signalProtoRoot.lookupType("signalservice.Envelope");
const contentType = signalProtoRoot.lookupType("signalservice.Content");
const dataMessageType = signalProtoRoot.lookupType("signalservice.DataMessage");
const provisionEnvelopeType = deviceMessagesProtoRoot.lookupType("signalservice.ProvisionEnvelope");
const provisionMessageType = deviceMessagesProtoRoot.lookupType("signalservice.ProvisionMessage");
const deviceNameType = deviceNameProtoRoot.lookupType("signalservice.DeviceName");

export function encodeSignalEnvelope(envelope: SignalEnvelope): Bytes {
  return encodeProto(envelopeType, envelopeToProto(envelope));
}

export function decodeSignalEnvelope(bytes: Uint8Array): SignalEnvelope {
  return normalizeEnvelope(decodeProto(envelopeType, bytes));
}

export function encodeSignalContent(content: SignalContent): Bytes {
  return encodeProto(contentType, contentToProto(content));
}

export function decodeSignalContent(bytes: Uint8Array): SignalContent {
  return normalizeContent(decodeProto(contentType, bytes));
}

export function encodeSignalDataMessage(message: SignalDataMessage): Bytes {
  return encodeProto(dataMessageType, dataMessageToProto(message));
}

export function decodeSignalDataMessage(bytes: Uint8Array): SignalDataMessage {
  return normalizeDataMessage(decodeProto(dataMessageType, bytes));
}

export function encodeSignalProvisionEnvelope(envelope: SignalProvisionEnvelope): Bytes {
  return encodeProto(provisionEnvelopeType, cleanOptionalMessage(envelope));
}

export function decodeSignalProvisionEnvelope(bytes: Uint8Array): SignalProvisionEnvelope {
  return normalizeProvisionEnvelope(decodeProto(provisionEnvelopeType, bytes));
}

export function encodeSignalProvisionMessage(message: SignalProvisionMessage): Bytes {
  return encodeProto(provisionMessageType, cleanOptionalMessage(message));
}

export function decodeSignalProvisionMessage(bytes: Uint8Array): SignalProvisionMessage {
  return normalizeProvisionMessage(decodeProto(provisionMessageType, bytes));
}

export function encodeSignalDeviceName(deviceName: SignalDeviceName): Bytes {
  return encodeProto(deviceNameType, cleanOptionalMessage(deviceName));
}

export function decodeSignalDeviceName(bytes: Uint8Array): SignalDeviceName {
  return normalizeDeviceName(decodeProto(deviceNameType, bytes));
}

export function createTextSignalContent(params: {
  body: string;
  timestamp?: number;
  attachments?: SignalAttachmentPointer[];
  quote?: SignalQuote;
  bodyRanges?: SignalBodyRange[];
  groupV2?: SignalGroupContextV2;
}): SignalContent {
  const dataMessage: SignalDataMessage = { body: params.body };
  assignIfDefined(dataMessage, "timestamp", params.timestamp);
  assignIfNonEmptyArray(dataMessage, "attachments", params.attachments);
  assignIfDefined(dataMessage, "quote", params.quote);
  assignIfNonEmptyArray(dataMessage, "bodyRanges", params.bodyRanges);
  assignIfDefined(dataMessage, "groupV2", params.groupV2);
  return { dataMessage };
}

export function createStickerSignalContent(params: {
  sticker: SignalSticker;
  timestamp?: number;
  groupV2?: SignalGroupContextV2;
}): SignalContent {
  const dataMessage: SignalDataMessage = { sticker: params.sticker };
  assignIfDefined(dataMessage, "timestamp", params.timestamp);
  assignIfDefined(dataMessage, "groupV2", params.groupV2);
  return { dataMessage };
}

export function createReactionSignalContent(
  reaction: SignalReaction,
  params: {
    timestamp?: number;
    groupV2?: SignalGroupContextV2;
  } = {},
): SignalContent {
  const dataMessage: SignalDataMessage = { reaction };
  assignIfDefined(dataMessage, "timestamp", params.timestamp);
  assignIfDefined(dataMessage, "groupV2", params.groupV2);
  return { dataMessage };
}

export function createReceiptSignalContent(receipt: SignalReceiptMessage): SignalContent {
  return { receiptMessage: receipt };
}

export function createTypingSignalContent(typing: SignalTypingMessage): SignalContent {
  return { typingMessage: typing };
}

export function requireEnvelopeSource(envelope: SignalEnvelope): {
  serviceId: string;
  deviceId: number;
} {
  const serviceId =
    envelope.sourceServiceId ??
    (envelope.sourceServiceIdBinary ? serviceIdBinaryToUuid(envelope.sourceServiceIdBinary) : null);
  if (!serviceId) {
    throw new SignalTsStateError("Signal envelope is missing sourceServiceId");
  }
  if (envelope.sourceDeviceId === undefined) {
    throw new SignalTsStateError("Signal envelope is missing sourceDeviceId");
  }
  return {
    serviceId,
    deviceId: envelope.sourceDeviceId,
  };
}

function encodeProto(type: protobuf.Type, value: Record<string, unknown>): Bytes {
  const error = type.verify(value);
  if (error) {
    throw new SignalTsStateError(`Invalid ${type.fullName} payload: ${error}`);
  }
  return copyBytes(type.encode(type.create(value)).finish());
}

function decodeProto(type: protobuf.Type, bytes: Uint8Array): Record<string, unknown> {
  return cleanProtoValue(
    type.toObject(type.decode(bytes), {
      bytes: Uint8Array,
      defaults: false,
      enums: Number,
      longs: Number,
      objects: false,
      oneofs: false,
    }),
  ) as Record<string, unknown>;
}

function envelopeToProto(envelope: SignalEnvelope): Record<string, unknown> {
  const proto: Record<string, unknown> = {};
  assignIfDefined(proto, "type", envelope.type);
  assignIfDefined(proto, "sourceServiceId", envelope.sourceServiceId);
  assignIfDefined(proto, "sourceDeviceId", envelope.sourceDeviceId);
  assignIfDefined(proto, "destinationServiceId", envelope.destinationServiceId);
  assignIfDefined(proto, "clientTimestamp", envelope.clientTimestamp);
  assignIfDefined(proto, "content", envelope.content);
  assignIfDefined(proto, "serverGuid", envelope.serverGuid);
  assignIfDefined(proto, "serverTimestamp", envelope.serverTimestamp);
  assignIfDefined(proto, "urgent", envelope.urgent);
  assignIfDefined(proto, "sourceServiceIdBinary", envelope.sourceServiceIdBinary);
  assignIfDefined(proto, "destinationServiceIdBinary", envelope.destinationServiceIdBinary);
  return proto;
}

function contentToProto(content: SignalContent): Record<string, unknown> {
  const proto: Record<string, unknown> = {};
  assignIfDefined(
    proto,
    "dataMessage",
    content.dataMessage ? dataMessageToProto(content.dataMessage) : undefined,
  );
  assignIfDefined(proto, "syncMessage", content.syncMessage);
  assignIfDefined(proto, "callMessage", content.callMessage);
  assignIfDefined(proto, "nullMessage", content.nullMessage);
  assignIfDefined(
    proto,
    "receiptMessage",
    content.receiptMessage ? receiptMessageToProto(content.receiptMessage) : undefined,
  );
  assignIfDefined(
    proto,
    "typingMessage",
    content.typingMessage ? typingMessageToProto(content.typingMessage) : undefined,
  );
  assignIfDefined(proto, "senderKeyDistributionMessage", content.senderKeyDistributionMessage);
  assignIfDefined(proto, "decryptionErrorMessage", content.decryptionErrorMessage);
  assignIfDefined(proto, "storyMessage", content.storyMessage);
  assignIfDefined(
    proto,
    "editMessage",
    content.editMessage
      ? {
          ...content.editMessage,
          dataMessage: content.editMessage.dataMessage
            ? dataMessageToProto(content.editMessage.dataMessage)
            : undefined,
        }
      : undefined,
  );
  assignIfDefined(proto, "pniSignatureMessage", content.pniSignatureMessage);
  return proto;
}

function dataMessageToProto(message: SignalDataMessage): Record<string, unknown> {
  const proto: Record<string, unknown> = {};
  assignIfDefined(proto, "body", message.body);
  assignIfNonEmptyArray(proto, "attachments", message.attachments?.map(cleanProtoValue));
  assignIfDefined(proto, "groupV2", message.groupV2);
  assignIfDefined(proto, "flags", message.flags);
  assignIfDefined(proto, "expireTimer", message.expireTimer);
  assignIfDefined(proto, "expireTimerVersion", message.expireTimerVersion);
  assignIfDefined(proto, "profileKey", message.profileKey);
  assignIfDefined(proto, "timestamp", message.timestamp);
  assignIfDefined(proto, "quote", cleanProtoValue(message.quote));
  assignIfDefined(proto, "sticker", cleanProtoValue(message.sticker));
  assignIfDefined(proto, "requiredProtocolVersion", message.requiredProtocolVersion);
  assignIfDefined(proto, "isViewOnce", message.isViewOnce);
  assignIfDefined(proto, "reaction", cleanProtoValue(message.reaction));
  assignIfDefined(proto, "delete", cleanProtoValue(message.delete));
  assignIfNonEmptyArray(proto, "bodyRanges", message.bodyRanges?.map(cleanProtoValue));
  assignIfDefined(proto, "storyContext", cleanProtoValue(message.storyContext));
  return proto;
}

function receiptMessageToProto(receipt: SignalReceiptMessage): Record<string, unknown> {
  const proto: Record<string, unknown> = {};
  assignIfDefined(proto, "type", receipt.type ? receiptTypeToProto(receipt.type) : undefined);
  assignIfNonEmptyArray(proto, "timestamp", receipt.timestamps);
  return proto;
}

function typingMessageToProto(typing: SignalTypingMessage): Record<string, unknown> {
  const proto: Record<string, unknown> = {};
  assignIfDefined(proto, "timestamp", typing.timestamp);
  assignIfDefined(proto, "action", typing.action ? typingActionToProto(typing.action) : undefined);
  assignIfDefined(proto, "groupId", typing.groupId);
  return proto;
}

function normalizeEnvelope(raw: Record<string, unknown>): SignalEnvelope {
  const envelope: SignalEnvelope = {};
  assignIfDefined(envelope, "type", optionalNumber(raw["type"]) as SignalEnvelopeType | undefined);
  assignIfDefined(envelope, "sourceServiceId", optionalString(raw["sourceServiceId"]));
  assignIfDefined(envelope, "sourceDeviceId", optionalNumber(raw["sourceDeviceId"]));
  assignIfDefined(envelope, "destinationServiceId", optionalString(raw["destinationServiceId"]));
  assignIfDefined(envelope, "clientTimestamp", optionalNumber(raw["clientTimestamp"]));
  assignIfDefined(envelope, "content", optionalBytes(raw["content"]));
  assignIfDefined(envelope, "serverGuid", optionalString(raw["serverGuid"]));
  assignIfDefined(envelope, "serverTimestamp", optionalNumber(raw["serverTimestamp"]));
  assignIfDefined(envelope, "urgent", optionalBoolean(raw["urgent"]));
  assignIfDefined(envelope, "sourceServiceIdBinary", optionalBytes(raw["sourceServiceIdBinary"]));
  assignIfDefined(
    envelope,
    "destinationServiceIdBinary",
    optionalBytes(raw["destinationServiceIdBinary"]),
  );
  return envelope;
}

function normalizeContent(raw: Record<string, unknown>): SignalContent {
  const content: SignalContent = {};
  const dataMessage = optionalRecord(raw["dataMessage"]);
  if (dataMessage) {
    content.dataMessage = normalizeDataMessage(dataMessage);
  }
  assignIfDefined(content, "syncMessage", optionalRecord(raw["syncMessage"]));
  assignIfDefined(content, "callMessage", optionalRecord(raw["callMessage"]));
  assignIfDefined(content, "nullMessage", optionalRecord(raw["nullMessage"]));
  const receiptMessage = optionalRecord(raw["receiptMessage"]);
  if (receiptMessage) {
    content.receiptMessage = normalizeReceiptMessage(receiptMessage);
  }
  const typingMessage = optionalRecord(raw["typingMessage"]);
  if (typingMessage) {
    content.typingMessage = normalizeTypingMessage(typingMessage);
  }
  assignIfDefined(content, "senderKeyDistributionMessage", optionalBytes(raw["senderKeyDistributionMessage"]));
  assignIfDefined(content, "decryptionErrorMessage", optionalBytes(raw["decryptionErrorMessage"]));
  assignIfDefined(content, "storyMessage", optionalRecord(raw["storyMessage"]));
  const editMessage = optionalRecord(raw["editMessage"]);
  if (editMessage) {
    const edit: NonNullable<SignalContent["editMessage"]> = {};
    assignIfDefined(edit, "targetSentTimestamp", optionalNumber(editMessage["targetSentTimestamp"]));
    const editDataMessage = optionalRecord(editMessage["dataMessage"]);
    if (editDataMessage) {
      edit.dataMessage = normalizeDataMessage(editDataMessage);
    }
    content.editMessage = edit;
  }
  assignIfDefined(content, "pniSignatureMessage", optionalRecord(raw["pniSignatureMessage"]));
  return content;
}

function normalizeDataMessage(raw: Record<string, unknown>): SignalDataMessage {
  const message: SignalDataMessage = {};
  assignIfDefined(message, "body", optionalString(raw["body"]));
  assignIfNonEmptyArray(message, "attachments", optionalArray(raw["attachments"]) as SignalAttachmentPointer[] | undefined);
  assignIfDefined(message, "groupV2", optionalRecord(raw["groupV2"]) as SignalGroupContextV2 | undefined);
  assignIfDefined(message, "flags", optionalNumber(raw["flags"]));
  assignIfDefined(message, "expireTimer", optionalNumber(raw["expireTimer"]));
  assignIfDefined(message, "expireTimerVersion", optionalNumber(raw["expireTimerVersion"]));
  assignIfDefined(message, "profileKey", optionalBytes(raw["profileKey"]));
  assignIfDefined(message, "timestamp", optionalNumber(raw["timestamp"]));
  assignIfDefined(message, "quote", optionalRecord(raw["quote"]) as SignalQuote | undefined);
  assignIfDefined(message, "sticker", optionalRecord(raw["sticker"]) as SignalSticker | undefined);
  assignIfDefined(message, "requiredProtocolVersion", optionalNumber(raw["requiredProtocolVersion"]));
  assignIfDefined(message, "isViewOnce", optionalBoolean(raw["isViewOnce"]));
  assignIfDefined(message, "reaction", optionalRecord(raw["reaction"]) as SignalReaction | undefined);
  assignIfDefined(message, "delete", optionalRecord(raw["delete"]) as { targetSentTimestamp?: number } | undefined);
  assignIfNonEmptyArray(message, "bodyRanges", optionalArray(raw["bodyRanges"]) as SignalBodyRange[] | undefined);
  assignIfDefined(message, "storyContext", optionalRecord(raw["storyContext"]));
  return message;
}

function normalizeReceiptMessage(raw: Record<string, unknown>): SignalReceiptMessage {
  const receipt: SignalReceiptMessage = {};
  assignIfDefined(receipt, "type", optionalReceiptType(raw["type"]));
  assignIfNonEmptyArray(receipt, "timestamps", optionalArray(raw["timestamp"]) as number[] | undefined);
  return receipt;
}

function normalizeTypingMessage(raw: Record<string, unknown>): SignalTypingMessage {
  const typing: SignalTypingMessage = {};
  assignIfDefined(typing, "timestamp", optionalNumber(raw["timestamp"]));
  assignIfDefined(typing, "action", optionalTypingAction(raw["action"]));
  assignIfDefined(typing, "groupId", optionalBytes(raw["groupId"]));
  return typing;
}

function normalizeProvisionEnvelope(raw: Record<string, unknown>): SignalProvisionEnvelope {
  const envelope: SignalProvisionEnvelope = {};
  assignIfDefined(envelope, "publicKey", optionalBytes(raw["publicKey"]));
  assignIfDefined(envelope, "body", optionalBytes(raw["body"]));
  return envelope;
}

function normalizeProvisionMessage(raw: Record<string, unknown>): SignalProvisionMessage {
  const message: SignalProvisionMessage = {};
  assignIfDefined(message, "aciIdentityKeyPublic", optionalBytes(raw["aciIdentityKeyPublic"]));
  assignIfDefined(message, "aciIdentityKeyPrivate", optionalBytes(raw["aciIdentityKeyPrivate"]));
  assignIfDefined(message, "pniIdentityKeyPublic", optionalBytes(raw["pniIdentityKeyPublic"]));
  assignIfDefined(message, "pniIdentityKeyPrivate", optionalBytes(raw["pniIdentityKeyPrivate"]));
  assignIfDefined(message, "aci", optionalString(raw["aci"]));
  assignIfDefined(message, "pni", optionalString(raw["pni"]));
  assignIfDefined(message, "number", optionalString(raw["number"]));
  assignIfDefined(message, "provisioningCode", optionalString(raw["provisioningCode"]));
  assignIfDefined(message, "userAgent", optionalString(raw["userAgent"]));
  assignIfDefined(message, "profileKey", optionalBytes(raw["profileKey"]));
  assignIfDefined(message, "readReceipts", optionalBoolean(raw["readReceipts"]));
  assignIfDefined(message, "provisioningVersion", optionalNumber(raw["provisioningVersion"]));
  assignIfDefined(message, "masterKey", optionalBytes(raw["masterKey"]));
  assignIfDefined(message, "ephemeralBackupKey", optionalBytes(raw["ephemeralBackupKey"]));
  assignIfDefined(message, "accountEntropyPool", optionalString(raw["accountEntropyPool"]));
  assignIfDefined(message, "mediaRootBackupKey", optionalBytes(raw["mediaRootBackupKey"]));
  assignIfDefined(message, "aciBinary", optionalBytes(raw["aciBinary"]));
  assignIfDefined(message, "pniBinary", optionalBytes(raw["pniBinary"]));
  return message;
}

function normalizeDeviceName(raw: Record<string, unknown>): SignalDeviceName {
  const deviceName: SignalDeviceName = {};
  assignIfDefined(deviceName, "ephemeralPublic", optionalBytes(raw["ephemeralPublic"]));
  assignIfDefined(deviceName, "syntheticIv", optionalBytes(raw["syntheticIv"]));
  assignIfDefined(deviceName, "ciphertext", optionalBytes(raw["ciphertext"]));
  return deviceName;
}

function cleanProtoValue(value: unknown): unknown {
  if (value instanceof Uint8Array) {
    return copyBytes(value);
  }
  if (Array.isArray(value)) {
    const cleaned = value.map(cleanProtoValue).filter((entry) => entry !== undefined);
    return cleaned.length > 0 ? cleaned : undefined;
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value)) {
      const cleaned = cleanProtoValue(nested);
      if (cleaned !== undefined) {
        out[key] = cleaned;
      }
    }
    return Object.keys(out).length > 0 ? out : undefined;
  }
  return value;
}

function cleanOptionalMessage(value: object): Record<string, unknown> {
  return (cleanProtoValue(value) as Record<string, unknown> | undefined) ?? {};
}

function optionalRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value) || value instanceof Uint8Array) {
    return undefined;
  }
  return value as Record<string, unknown>;
}

function optionalArray(value: unknown): unknown[] | undefined {
  return Array.isArray(value) && value.length > 0 ? value : undefined;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function optionalNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function optionalBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function optionalBytes(value: unknown): Bytes | undefined {
  return value instanceof Uint8Array ? copyBytes(value) : undefined;
}

function optionalReceiptType(value: unknown): SignalReceiptType | undefined {
  const numeric = optionalNumber(value);
  if (numeric === 0) {
    return "delivery";
  }
  if (numeric === 1) {
    return "read";
  }
  if (numeric === 2) {
    return "viewed";
  }
  return undefined;
}

function optionalTypingAction(value: unknown): SignalTypingAction | undefined {
  const numeric = optionalNumber(value);
  if (numeric === 0) {
    return "started";
  }
  if (numeric === 1) {
    return "stopped";
  }
  return undefined;
}

function receiptTypeToProto(type: SignalReceiptType): number {
  if (type === "read") {
    return 1;
  }
  if (type === "viewed") {
    return 2;
  }
  return 0;
}

function typingActionToProto(action: SignalTypingAction): number {
  return action === "stopped" ? 1 : 0;
}

function assignIfDefined<T extends object, K extends keyof T>(
  target: T,
  key: K,
  value: T[K] | undefined,
): void {
  if (value !== undefined) {
    target[key] = value;
  }
}

function assignIfNonEmptyArray<T extends object, K extends keyof T>(
  target: T,
  key: K,
  value: T[K] | undefined,
): void {
  if (Array.isArray(value) && value.length > 0) {
    target[key] = value;
  }
}

export function serviceIdBinaryToUuid(value: Bytes): string | null {
  const uuidBytes = value.byteLength === 16 ? value : value.byteLength === 17 ? value.slice(1) : null;
  if (!uuidBytes) {
    return null;
  }
  const hex = [...uuidBytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
