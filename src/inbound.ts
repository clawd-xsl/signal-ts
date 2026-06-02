import { GroupMasterKey, GroupSecretParams } from "@signalapp/libsignal-client/dist/zkgroup/index.js";
import { bytesToBase64, copyBytes, type Bytes } from "./bytes.js";
import type { DecryptedIncomingMessage } from "./crypto.js";
import {
  requireEnvelopeSource,
  type SignalContent,
  type SignalDataMessage,
  type SignalEnvelope,
  type SignalGroupContextV2,
  type SignalReaction,
  type SignalReceiptMessage,
  type SignalTypingMessage,
} from "./messages.js";

export type SignalIncomingSender = {
  serviceId?: string;
  deviceId?: number;
};

export type SignalIncomingGroup = {
  id?: string;
  masterKey?: Bytes;
  revision?: number;
  groupChange?: Bytes;
};

export type SignalIncomingBase = {
  envelope: SignalEnvelope;
  sender: SignalIncomingSender;
  timestamp?: number;
  serverTimestamp?: number;
};

export type SignalIncomingDataMessage = SignalIncomingBase & {
  kind: "data";
  message: SignalDataMessage;
  body?: string;
  attachments: NonNullable<SignalDataMessage["attachments"]>;
  bodyRanges: NonNullable<SignalDataMessage["bodyRanges"]>;
  group?: SignalIncomingGroup;
};

export type SignalIncomingReactionMessage = SignalIncomingBase & {
  kind: "reaction";
  reaction: SignalReaction;
  group?: SignalIncomingGroup;
};

export type SignalIncomingEditMessage = SignalIncomingBase & {
  kind: "edit";
  targetSentTimestamp?: number;
  message?: SignalDataMessage;
  group?: SignalIncomingGroup;
};

export type SignalIncomingReceiptMessage = SignalIncomingBase & {
  kind: "receipt";
  receipt: SignalReceiptMessage;
};

export type SignalIncomingTypingMessage = SignalIncomingBase & {
  kind: "typing";
  typing: SignalTypingMessage;
  group?: SignalIncomingGroup;
};

export type SignalIncomingSyncMessage = SignalIncomingBase & {
  kind: "sync";
  syncMessage: Record<string, unknown>;
};

export type SignalIncomingUnknownMessage = SignalIncomingBase & {
  kind: "unknown";
  content: SignalContent;
};

export type SignalIncomingMessage =
  | SignalIncomingDataMessage
  | SignalIncomingReactionMessage
  | SignalIncomingEditMessage
  | SignalIncomingReceiptMessage
  | SignalIncomingTypingMessage
  | SignalIncomingSyncMessage
  | SignalIncomingUnknownMessage;

export function normalizeDecryptedIncomingMessage(
  message: DecryptedIncomingMessage,
): SignalIncomingMessage[] {
  return normalizeSignalContent({
    envelope: message.envelope,
    content: message.content,
  });
}

export function normalizeSignalContent({
  envelope,
  content,
  receivedAt,
}: {
  envelope: SignalEnvelope;
  content: SignalContent;
  receivedAt?: number;
}): SignalIncomingMessage[] {
  const baseParams: Parameters<typeof buildIncomingBase>[0] = { envelope };
  if (receivedAt !== undefined) {
    baseParams.receivedAt = receivedAt;
  }
  const base = buildIncomingBase(baseParams);
  const messages: SignalIncomingMessage[] = [];

  if (content.dataMessage) {
    messages.push(normalizeDataMessage(base, content.dataMessage));
  }
  if (content.editMessage) {
    const edit: SignalIncomingEditMessage = {
      ...base,
      kind: "edit",
    };
    if (content.editMessage.targetSentTimestamp !== undefined) {
      edit.targetSentTimestamp = content.editMessage.targetSentTimestamp;
    }
    if (content.editMessage.dataMessage !== undefined) {
      edit.message = content.editMessage.dataMessage;
      const group = normalizeGroup(content.editMessage.dataMessage.groupV2);
      if (group) {
        edit.group = group;
      }
    }
    messages.push(edit);
  }
  if (content.receiptMessage) {
    messages.push({
      ...base,
      kind: "receipt",
      receipt: content.receiptMessage,
    });
  }
  if (content.typingMessage) {
    const typing: SignalIncomingTypingMessage = {
      ...base,
      kind: "typing",
      typing: content.typingMessage,
    };
    if (content.typingMessage.groupId) {
      typing.group = { id: bytesToBase64(content.typingMessage.groupId) };
    }
    messages.push(typing);
  }
  if (content.syncMessage) {
    messages.push({
      ...base,
      kind: "sync",
      syncMessage: content.syncMessage,
    });
  }
  if (messages.length === 0) {
    messages.push({
      ...base,
      kind: "unknown",
      content,
    });
  }
  return messages;
}

export function signalGroupIdFromMasterKey(masterKey: Bytes): string | undefined {
  try {
    const groupMasterKey = new GroupMasterKey(masterKey);
    return GroupSecretParams.deriveFromMasterKey(groupMasterKey)
      .getPublicParams()
      .getGroupIdentifier()
      .toString();
  } catch {
    return undefined;
  }
}

function normalizeDataMessage(
  base: SignalIncomingBase,
  message: SignalDataMessage,
): SignalIncomingDataMessage | SignalIncomingReactionMessage {
  const group = normalizeGroup(message.groupV2);
  if (message.reaction) {
    const reaction: SignalIncomingReactionMessage = {
      ...base,
      kind: "reaction",
      reaction: message.reaction,
    };
    if (group) {
      reaction.group = group;
    }
    return reaction;
  }

  const data: SignalIncomingDataMessage = {
    ...base,
    kind: "data",
    message,
    attachments: message.attachments ?? [],
    bodyRanges: message.bodyRanges ?? [],
  };
  if (message.body !== undefined) {
    data.body = message.body;
  }
  if (message.timestamp !== undefined) {
    data.timestamp = message.timestamp;
  }
  if (group) {
    data.group = group;
  }
  return data;
}

function buildIncomingBase({
  envelope,
  receivedAt,
}: {
  envelope: SignalEnvelope;
  receivedAt?: number;
}): SignalIncomingBase {
  const sender = resolveIncomingSender(envelope);
  const base: SignalIncomingBase = {
    envelope,
    sender,
  };
  const timestamp = envelope.clientTimestamp ?? receivedAt;
  if (timestamp !== undefined) {
    base.timestamp = timestamp;
  }
  if (envelope.serverTimestamp !== undefined) {
    base.serverTimestamp = envelope.serverTimestamp;
  }
  return base;
}

function resolveIncomingSender(envelope: SignalEnvelope): SignalIncomingSender {
  try {
    return requireEnvelopeSource(envelope);
  } catch {
    return {};
  }
}

function normalizeGroup(group: SignalGroupContextV2 | undefined): SignalIncomingGroup | undefined {
  if (!group) {
    return undefined;
  }
  const normalized: SignalIncomingGroup = {};
  if (group.masterKey) {
    normalized.masterKey = copyBytes(group.masterKey);
    const id = signalGroupIdFromMasterKey(group.masterKey);
    if (id) {
      normalized.id = id;
    }
  }
  if (group.revision !== undefined) {
    normalized.revision = group.revision;
  }
  if (group.groupChange) {
    normalized.groupChange = copyBytes(group.groupChange);
  }
  return normalized;
}
