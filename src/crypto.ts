import {
  Aci,
  CiphertextMessageType,
  CiphertextMessage,
  DecryptionErrorMessage,
  PlaintextContent,
  PreKeySignalMessage,
  ProtocolAddress,
  PublicKey,
  SignalMessage,
  type PreKeyBundle,
  type ServiceId,
  groupDecrypt,
  processPreKeyBundle,
  sealedSenderDecryptMessage,
  sealedSenderDecryptToUsmc,
  signalDecrypt,
  signalDecryptPreKey,
  signalEncrypt,
} from "@signalapp/libsignal-client";
import { copyBytes, type Bytes } from "./bytes.js";
import type { LibsignalStores } from "./store.js";
import {
  decodeSignalContent,
  decodeSignalEnvelope,
  requireEnvelopeSource,
  SignalEnvelopeType,
  type SignalContent,
  type SignalEnvelope,
} from "./messages.js";
import { SignalTsUnsupportedError } from "./errors.js";
import { getSignalUnidentifiedSenderTrustRoots } from "./trust-roots.js";

export type SignalRecipientDevice = {
  serviceId: ServiceId;
  deviceId: number;
  registrationId: number;
  preKeyBundle?: PreKeyBundle;
};

export type EncryptForDeviceParams = {
  localAddress: ProtocolAddress;
  device: SignalRecipientDevice;
  payload: Bytes;
  stores: Pick<LibsignalStores, "identityStore" | "sessionStore">;
  now?: Date;
};

export type EncryptedDeviceMessage = {
  deviceId: number;
  registrationId: number;
  contents: CiphertextMessage;
};

export type DecryptIncomingEnvelopeParams = {
  envelope: SignalEnvelope | Bytes;
  localAddress: ProtocolAddress;
  sealedSender?: SealedSenderDecryptOptions;
  stores: Pick<
    LibsignalStores,
    | "identityStore"
    | "sessionStore"
    | "preKeyStore"
    | "signedPreKeyStore"
    | "kyberPreKeyStore"
  > & Partial<Pick<LibsignalStores, "senderKeyStore">>;
};

export type SealedSenderDecryptOptions = {
  trustRoot?: PublicKey;
  trustRoots?: PublicKey[];
  localE164?: string | null;
  localAci: string;
  localDeviceId: number;
};

export type DecryptedIncomingMessage = {
  envelope: SignalEnvelope;
  plaintext: Bytes;
  content: SignalContent;
  sealedSender?: {
    senderAci?: string;
    senderUuid: string;
    senderE164: string | null;
    deviceId: number;
  };
};

export type SignalRetryReceiptRequest = {
  recipientServiceId: string;
  senderDeviceId: number;
  timestamp: number;
  ciphertextType: number;
  originalContent: Bytes;
  groupId?: Bytes;
};

export class SignalTsDecryptionError extends Error {
  readonly retryReceipt: SignalRetryReceiptRequest | undefined;

  constructor(message: string, options: { cause: unknown; retryReceipt?: SignalRetryReceiptRequest }) {
    super(message, { cause: options.cause });
    this.name = "SignalTsDecryptionError";
    this.retryReceipt = options.retryReceipt;
  }
}

export async function encryptPayloadForDevice({
  localAddress,
  device,
  payload,
  stores,
  now,
}: EncryptForDeviceParams): Promise<EncryptedDeviceMessage> {
  const remoteAddress = ProtocolAddress.new(device.serviceId, device.deviceId);
  if (device.preKeyBundle) {
    await processPreKeyBundle(
      device.preKeyBundle,
      remoteAddress,
      localAddress,
      stores.sessionStore,
      stores.identityStore,
      now,
    );
  }
  const contents = await signalEncrypt(
    padSignalMessageBody(payload),
    remoteAddress,
    localAddress,
    stores.sessionStore,
    stores.identityStore,
    now,
  );
  return {
    deviceId: device.deviceId,
    registrationId: device.registrationId,
    contents,
  };
}

export async function decryptIncomingEnvelope({
  envelope: rawEnvelope,
  localAddress,
  sealedSender,
  stores,
}: DecryptIncomingEnvelopeParams): Promise<DecryptedIncomingMessage> {
  const envelope = rawEnvelope instanceof Uint8Array
    ? decodeSignalEnvelope(rawEnvelope)
    : rawEnvelope;
  const encryptedContent = envelope.content;
  if (!encryptedContent) {
    throw new SignalTsUnsupportedError("Signal envelope does not contain encrypted content");
  }
  if (envelope.type === SignalEnvelopeType.UnidentifiedSender) {
    return await decryptSealedSenderEnvelope({
      envelope,
      encryptedContent,
      localAddress,
      sealedSender,
      stores,
    });
  }
  const source = requireEnvelopeSource(envelope);
  const remoteAddress = ProtocolAddress.new(Aci.fromUuid(source.serviceId), source.deviceId);
  let plaintext: Bytes;
  try {
    plaintext = await decryptEnvelopeContent({
      type: envelope.type,
      encryptedContent,
      remoteAddress,
      localAddress,
      stores,
    });
  } catch (err) {
    throw createSignalTsDecryptionError({
      err,
      envelope,
      originalContent: encryptedContent,
      ciphertextType: envelopeTypeToCiphertextMessageType(envelope.type),
      recipientServiceId: source.serviceId,
      senderDeviceId: source.deviceId,
    });
  }
  return buildDecryptedIncomingMessage({ envelope, plaintext });
}

async function decryptSealedSenderEnvelope({
  envelope,
  encryptedContent,
  localAddress,
  sealedSender,
  stores,
}: {
  envelope: SignalEnvelope;
  encryptedContent: Bytes;
  localAddress: ProtocolAddress;
  sealedSender: SealedSenderDecryptOptions | undefined;
  stores: DecryptIncomingEnvelopeParams["stores"];
}): Promise<DecryptedIncomingMessage> {
  const serverTimestamp = envelope.serverTimestamp ?? envelope.clientTimestamp ?? Date.now();
  const trustRoots = sealedSender?.trustRoots ??
    (sealedSender?.trustRoot ? [sealedSender.trustRoot] : getSignalUnidentifiedSenderTrustRoots());

  const direct = await tryDecryptSealedSenderDeviceContent({
    encryptedContent,
    envelope,
    trustRoots,
    localAddress,
    sealedSender,
    stores,
  });
  const decrypted = direct ?? await decryptSealedSenderSenderKeyEnvelope({
    encryptedContent,
    localAddress,
    serverTimestamp,
    trustRoots,
    stores,
  });

  const unsealedEnvelope: SignalEnvelope = {
    ...envelope,
    type: decrypted.envelopeType,
    sourceServiceId: decrypted.senderUuid,
    sourceDeviceId: decrypted.senderDeviceId,
  };
  if (decrypted.content !== undefined) {
    unsealedEnvelope.content = decrypted.content;
  } else {
    delete unsealedEnvelope.content;
  }
  return {
    envelope: unsealedEnvelope,
    plaintext: decrypted.plaintext,
    content: decodeDecryptedSignalContent(decrypted.plaintext),
    sealedSender: {
      ...(decrypted.senderAci ? { senderAci: decrypted.senderAci } : {}),
      senderUuid: decrypted.senderUuid,
      senderE164: decrypted.senderE164,
      deviceId: decrypted.senderDeviceId,
    },
  };
}

async function decryptSealedSenderSenderKeyEnvelope({
  encryptedContent,
  localAddress,
  serverTimestamp,
  trustRoots,
  stores,
}: {
  encryptedContent: Bytes;
  localAddress: ProtocolAddress;
  serverTimestamp: number;
  trustRoots: PublicKey[];
  stores: DecryptIncomingEnvelopeParams["stores"];
}): Promise<DecryptedSealedSenderContent> {
  const messageContent = await sealedSenderDecryptToUsmc(encryptedContent, stores.identityStore);
  const certificate = messageContent.senderCertificate();
  const trustRoot = trustRoots.find((root) => certificate.validateWithTrustRoots([root], serverTimestamp));
  if (!trustRoot) {
    throw new SignalTsUnsupportedError("Sealed sender certificate validation failed");
  }

  const senderAci = certificate.senderAci()?.getServiceIdString();
  const senderUuid = certificate.senderUuid();
  const senderDeviceId = certificate.senderDeviceId();
  if (senderAci === localAddress.name() && senderDeviceId === localAddress.deviceId()) {
    throw new SignalTsUnsupportedError("Received sealed sender message sent by this device");
  }

  const contentType = messageContent.msgType();
  if (contentType !== CiphertextMessageType.SenderKey) {
    if (contentType === CiphertextMessageType.Plaintext) {
      return decryptSealedSenderPlaintextContent({
        messageContent,
        senderUuid,
        senderDeviceId,
      });
    }
    if (contentType === CiphertextMessageType.Whisper || contentType === CiphertextMessageType.PreKey) {
      return await decryptSealedSenderSessionContent({
        messageContent,
        senderUuid,
        senderDeviceId,
        localAddress,
        stores,
      });
    }
    throw new SignalTsUnsupportedError(`Unsupported sealed sender content type: ${contentType}`);
  }
  return await decryptSealedSenderSenderKeyContent({
    messageContent,
    senderUuid,
    senderDeviceId,
    localAddress,
    stores,
  });
}

async function tryDecryptSealedSenderDeviceContent({
  encryptedContent,
  envelope,
  trustRoots,
  localAddress,
  sealedSender,
  stores,
}: {
  encryptedContent: Bytes;
  envelope: SignalEnvelope;
  trustRoots: PublicKey[];
  localAddress: ProtocolAddress;
  sealedSender: SealedSenderDecryptOptions | undefined;
  stores: DecryptIncomingEnvelopeParams["stores"];
}): Promise<DecryptedSealedSenderContent | null> {
  for (const trustRoot of trustRoots) {
    try {
      return await decryptSealedSenderDeviceContent({
        encryptedContent,
        envelope,
        trustRoot,
        localAddress,
        sealedSender,
        stores,
      });
    } catch {
      continue;
    }
  }
  return null;
}

type DecryptedSealedSenderContent = {
  content: Bytes | undefined;
  envelopeType: SignalEnvelopeType;
  plaintext: Bytes;
  senderAci?: string;
  senderUuid: string;
  senderE164: string | null;
  senderDeviceId: number;
};

async function decryptSealedSenderDeviceContent({
  encryptedContent,
  envelope,
  trustRoot,
  localAddress,
  sealedSender,
  stores,
}: {
  encryptedContent: Bytes;
  envelope: SignalEnvelope;
  trustRoot: PublicKey;
  localAddress: ProtocolAddress;
  sealedSender: SealedSenderDecryptOptions | undefined;
  stores: DecryptIncomingEnvelopeParams["stores"];
}): Promise<{
  content: undefined;
  envelopeType: SignalEnvelopeType.PlaintextContent;
  plaintext: Bytes;
  senderAci?: string;
  senderUuid: string;
  senderE164: string | null;
  senderDeviceId: number;
}> {
  const result = await sealedSenderDecryptMessage(
    encryptedContent,
    trustRoot,
    envelope.serverTimestamp ?? envelope.clientTimestamp ?? Date.now(),
    sealedSender?.localE164 ?? null,
    sealedSender?.localAci ?? localAddress.name(),
    sealedSender?.localDeviceId ?? localAddress.deviceId(),
    stores.sessionStore,
    stores.identityStore,
    stores.preKeyStore,
    stores.signedPreKeyStore,
    stores.kyberPreKeyStore,
  );
  const senderAci = result.senderAci()?.getServiceIdString();
  return {
    content: undefined,
    envelopeType: SignalEnvelopeType.PlaintextContent,
    plaintext: stripSignalMessagePadding(result.message()),
    ...(senderAci ? { senderAci } : {}),
    senderUuid: result.senderUuid(),
    senderE164: result.senderE164(),
    senderDeviceId: result.deviceId(),
  };
}

async function decryptSealedSenderSessionContent({
  messageContent,
  senderUuid,
  senderDeviceId,
  localAddress,
  stores,
}: {
  messageContent: Awaited<ReturnType<typeof sealedSenderDecryptToUsmc>>;
  senderUuid: string;
  senderDeviceId: number;
  localAddress: ProtocolAddress;
  stores: DecryptIncomingEnvelopeParams["stores"];
}): Promise<{
  content: Bytes;
  envelopeType: SignalEnvelopeType.PreKeyMessage | SignalEnvelopeType.DoubleRatchet;
  plaintext: Bytes;
  senderAci?: string;
  senderUuid: string;
  senderE164: string | null;
  senderDeviceId: number;
}> {
  const certificate = messageContent.senderCertificate();
  const senderAci = certificate.senderAci()?.getServiceIdString();
  const innerContent = copyBytes(messageContent.contents());
  const contentType = messageContent.msgType();
  const remoteAddress = ProtocolAddress.new(Aci.fromUuid(senderUuid), senderDeviceId);
  try {
    if (contentType === CiphertextMessageType.PreKey) {
      return {
        content: innerContent,
        envelopeType: SignalEnvelopeType.PreKeyMessage,
        plaintext: stripSignalMessagePadding(await signalDecryptPreKey(
          PreKeySignalMessage.deserialize(innerContent),
          remoteAddress,
          localAddress,
          stores.sessionStore,
          stores.identityStore,
          stores.preKeyStore,
          stores.signedPreKeyStore,
          stores.kyberPreKeyStore,
        )),
        ...(senderAci ? { senderAci } : {}),
        senderUuid,
        senderE164: certificate.senderE164(),
        senderDeviceId,
      };
    }
    return {
      content: innerContent,
      envelopeType: SignalEnvelopeType.DoubleRatchet,
      plaintext: stripSignalMessagePadding(await signalDecrypt(
        SignalMessage.deserialize(innerContent),
        remoteAddress,
        localAddress,
        stores.sessionStore,
        stores.identityStore,
      )),
      ...(senderAci ? { senderAci } : {}),
      senderUuid,
      senderE164: certificate.senderE164(),
      senderDeviceId,
    };
  } catch (err) {
    const groupId = messageContent.groupId();
    throw createSignalTsDecryptionError({
      err,
      originalContent: innerContent,
      ciphertextType: contentType,
      recipientServiceId: senderUuid,
      senderDeviceId,
      ...(groupId ? { groupId } : {}),
    });
  }
}

async function decryptSealedSenderSenderKeyContent({
  messageContent,
  senderUuid,
  senderDeviceId,
  localAddress,
  stores,
}: {
  messageContent: Awaited<ReturnType<typeof sealedSenderDecryptToUsmc>>;
  senderUuid: string;
  senderDeviceId: number;
  localAddress: ProtocolAddress;
  stores: DecryptIncomingEnvelopeParams["stores"];
}): Promise<{
  content: Bytes;
  envelopeType: SignalEnvelopeType.SenderKey;
  plaintext: Bytes;
  senderAci?: string;
  senderUuid: string;
  senderE164: string | null;
  senderDeviceId: number;
}> {
  if (!stores.senderKeyStore) {
    throw new SignalTsUnsupportedError("Sealed sender sender-key content requires senderKeyStore");
  }
  const senderAci = messageContent.senderCertificate().senderAci()?.getServiceIdString();
  const innerContent = copyBytes(messageContent.contents());
  const remoteAddress = ProtocolAddress.new(Aci.fromUuid(senderUuid), senderDeviceId);
  return {
    content: innerContent,
    envelopeType: SignalEnvelopeType.SenderKey,
    plaintext: stripSignalMessagePadding(
      await groupDecrypt(remoteAddress, stores.senderKeyStore, innerContent),
    ),
    ...(senderAci ? { senderAci } : {}),
    senderUuid,
    senderE164: messageContent.senderCertificate().senderE164(),
    senderDeviceId,
  };
}

function decryptSealedSenderPlaintextContent({
  messageContent,
  senderUuid,
  senderDeviceId,
}: {
  messageContent: Awaited<ReturnType<typeof sealedSenderDecryptToUsmc>>;
  senderUuid: string;
  senderDeviceId: number;
}): DecryptedSealedSenderContent {
  const senderAci = messageContent.senderCertificate().senderAci()?.getServiceIdString();
  return {
    content: undefined,
    envelopeType: SignalEnvelopeType.PlaintextContent,
    plaintext: stripSignalMessagePadding(
      PlaintextContent.deserialize(messageContent.contents()).body(),
    ),
    ...(senderAci ? { senderAci } : {}),
    senderUuid,
    senderE164: messageContent.senderCertificate().senderE164(),
    senderDeviceId,
  };
}

async function decryptEnvelopeContent({
  type,
  encryptedContent,
  remoteAddress,
  localAddress,
  stores,
}: {
  type: SignalEnvelopeType | undefined;
  encryptedContent: Bytes;
  remoteAddress: ProtocolAddress;
  localAddress: ProtocolAddress;
  stores: DecryptIncomingEnvelopeParams["stores"];
}): Promise<Bytes> {
  if (type === SignalEnvelopeType.PreKeyMessage) {
    return stripSignalMessagePadding(await signalDecryptPreKey(
      PreKeySignalMessage.deserialize(encryptedContent),
      remoteAddress,
      localAddress,
      stores.sessionStore,
      stores.identityStore,
      stores.preKeyStore,
      stores.signedPreKeyStore,
      stores.kyberPreKeyStore,
    ));
  }
  if (type === SignalEnvelopeType.DoubleRatchet) {
    return stripSignalMessagePadding(await signalDecrypt(
      SignalMessage.deserialize(encryptedContent),
      remoteAddress,
      localAddress,
      stores.sessionStore,
      stores.identityStore,
    ));
  }
  if (type === SignalEnvelopeType.SenderKey) {
    if (!stores.senderKeyStore) {
      throw new SignalTsUnsupportedError("Sender-key envelope requires senderKeyStore");
    }
    return stripSignalMessagePadding(
      await groupDecrypt(remoteAddress, stores.senderKeyStore, encryptedContent),
    );
  }
  if (type === SignalEnvelopeType.PlaintextContent) {
    return stripSignalMessagePadding(PlaintextContent.deserialize(encryptedContent).body());
  }
  throw new SignalTsUnsupportedError(`Unsupported Signal envelope type: ${type ?? "missing"}`);
}

export function createSignalDecryptionErrorPlaintextContent(
  retry: SignalRetryReceiptRequest,
): PlaintextContent {
  return PlaintextContent.from(
    DecryptionErrorMessage.forOriginal(
      retry.originalContent,
      retry.ciphertextType as CiphertextMessageType,
      retry.timestamp,
      retry.senderDeviceId,
    ),
  );
}

export function decodeSignalDecryptionErrorMessage(bytes: Bytes): {
  timestamp: number;
  deviceId: number;
  ratchetKey?: PublicKey;
} {
  return normalizeSignalDecryptionErrorMessage(DecryptionErrorMessage.deserialize(bytes));
}

export function extractSignalDecryptionErrorMessageFromContent(bytes: Bytes): {
  timestamp: number;
  deviceId: number;
  ratchetKey?: PublicKey;
} {
  return normalizeSignalDecryptionErrorMessage(
    DecryptionErrorMessage.extractFromSerializedBody(bytes),
  );
}

function normalizeSignalDecryptionErrorMessage(message: DecryptionErrorMessage): {
  timestamp: number;
  deviceId: number;
  ratchetKey?: PublicKey;
} {
  const ratchetKey = message.ratchetKey();
  return {
    timestamp: message.timestamp(),
    deviceId: message.deviceId(),
    ...(ratchetKey ? { ratchetKey } : {}),
  };
}

export function padSignalMessageBody(messageBody: Bytes): Bytes {
  const paddedLength = getPaddedSignalMessageLength(messageBody.byteLength + 1) - 1;
  const padded = new Uint8Array(paddedLength);
  padded.set(messageBody);
  padded[messageBody.byteLength] = 0x80;
  return padded;
}

export function stripSignalMessagePadding(messageWithPadding: Bytes): Bytes {
  for (let index = messageWithPadding.byteLength - 1; index >= 0; index -= 1) {
    const byte = messageWithPadding[index]!;
    if (byte === 0x80) {
      return copyBytes(messageWithPadding.subarray(0, index));
    }
    if (byte !== 0x00) {
      return copyBytes(messageWithPadding);
    }
  }
  return new Uint8Array();
}

function getPaddedSignalMessageLength(messageLength: number): number {
  const blockSize = 80;
  const messageLengthWithTerminator = messageLength + 1;
  return Math.ceil(messageLengthWithTerminator / blockSize) * blockSize;
}

function buildDecryptedIncomingMessage({
  envelope,
  plaintext,
}: {
  envelope: SignalEnvelope;
  plaintext: Bytes;
}): DecryptedIncomingMessage {
  return {
    envelope,
    plaintext,
    content: decodeDecryptedSignalContent(plaintext),
  };
}

function decodeDecryptedSignalContent(plaintext: Bytes): SignalContent {
  try {
    return decodeSignalContent(plaintext);
  } catch (err) {
    throw new Error(
      `Failed to decode decrypted Signal Content (plaintextLen=${plaintext.byteLength}): ${String(err)}`,
    );
  }
}

function createSignalTsDecryptionError({
  err,
  envelope,
  originalContent,
  ciphertextType,
  recipientServiceId,
  senderDeviceId,
  groupId,
}: {
  err: unknown;
  envelope?: SignalEnvelope;
  originalContent: Bytes;
  ciphertextType: number;
  recipientServiceId: string;
  senderDeviceId: number;
  groupId?: Bytes;
}): SignalTsDecryptionError {
  const timestamp = envelope?.clientTimestamp ?? envelope?.serverTimestamp ?? Date.now();
  const retryReceipt: SignalRetryReceiptRequest = {
    recipientServiceId,
    senderDeviceId,
    timestamp,
    ciphertextType,
    originalContent: copyBytes(originalContent),
  };
  if (groupId !== undefined) {
    retryReceipt.groupId = copyBytes(groupId);
  }
  const message = err instanceof Error ? err.message : String(err);
  return new SignalTsDecryptionError(`Failed to decrypt Signal message: ${message}`, {
    cause: err,
    retryReceipt,
  });
}

function envelopeTypeToCiphertextMessageType(type: SignalEnvelopeType | undefined): number {
  if (type === SignalEnvelopeType.PreKeyMessage) {
    return CiphertextMessageType.PreKey;
  }
  if (type === SignalEnvelopeType.SenderKey || type === SignalEnvelopeType.UnidentifiedSender) {
    return CiphertextMessageType.SenderKey;
  }
  if (type === SignalEnvelopeType.PlaintextContent) {
    return CiphertextMessageType.Plaintext;
  }
  return CiphertextMessageType.Whisper;
}
