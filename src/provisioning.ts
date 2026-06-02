import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import {
  Aci,
  IdentityKeyPair,
  Net,
  Pni,
  PrivateKey,
  PublicKey,
  hkdf,
} from "@signalapp/libsignal-client";
import type { ProvisioningConnection } from "@signalapp/libsignal-client/dist/net/Chat.js";
import { copyBytes, utf8Bytes, bytesToBase64, type Bytes } from "./bytes.js";
import { SignalTsStateError } from "./errors.js";
import {
  decodeSignalDeviceName,
  decodeSignalProvisionEnvelope,
  decodeSignalProvisionMessage,
  encodeSignalDeviceName,
  serviceIdBinaryToUuid,
  type SignalProvisionEnvelope,
} from "./messages.js";
import { resolveLibsignalEnvironment, type SignalEnvironment } from "./account.js";

export type SignalProvisionDecryptResult = {
  aciIdentityKeyPair: IdentityKeyPair;
  pniIdentityKeyPair?: IdentityKeyPair;
  number?: string;
  aci: string;
  pni: string;
  provisioningCode?: string;
  userAgent?: string;
  readReceipts: boolean;
  profileKey?: Bytes;
  masterKey?: Bytes;
  accountEntropyPool?: string;
  ephemeralBackupKey?: Bytes;
  mediaRootBackupKey?: Bytes;
};

export type StartSignalDeviceLinkSessionParams = {
  environment?: SignalEnvironment;
  userAgent?: string;
  capabilities?: string[];
  timeoutMs?: number;
  abortSignal?: AbortSignal;
  net?: Net.Net;
};

export type SignalDeviceLinkSession = {
  url: string;
  publicKey: PublicKey;
  waitForProvisioning: () => Promise<SignalProvisionDecryptResult>;
  disconnect: () => Promise<void>;
};

const DEFAULT_USER_AGENT = "OpenClaw signal-ts/0.0.0";
const DEFAULT_LINK_TIMEOUT_MS = 30_000;
const PROVISIONING_INFO = utf8Bytes("TextSecure Provisioning Message");
const ZERO_SALT = new Uint8Array(32) as Bytes;
const VERSION_BYTE = 1;
const IV_LENGTH = 16;
const MAC_LENGTH = 32;
const MAX_DEVICE_NAME_LENGTH = 50;

export class SignalProvisioningCipher {
  private keyPair: IdentityKeyPair | undefined;

  constructor(keyPair?: IdentityKeyPair) {
    this.keyPair = keyPair;
  }

  getPublicKey(): PublicKey {
    this.keyPair ??= IdentityKeyPair.generate();
    return this.keyPair.publicKey;
  }

  decrypt(envelope: SignalProvisionEnvelope | Bytes): SignalProvisionDecryptResult {
    const decoded = envelope instanceof Uint8Array
      ? decodeSignalProvisionEnvelope(envelope)
      : envelope;
    const publicKey = decoded.publicKey;
    const body = decoded.body;
    if (!publicKey) {
      throw new SignalTsStateError("Provision envelope is missing publicKey");
    }
    if (!body) {
      throw new SignalTsStateError("Provision envelope is missing body");
    }
    if ((body[0] ?? 0) !== VERSION_BYTE) {
      throw new SignalTsStateError("Provision envelope has unsupported version");
    }
    if (body.byteLength <= 1 + IV_LENGTH + MAC_LENGTH) {
      throw new SignalTsStateError("Provision envelope body is too short");
    }
    if (!this.keyPair) {
      throw new SignalTsStateError("Provisioning cipher has no key pair");
    }

    const keys = deriveSecrets(
      this.keyPair.privateKey.agree(PublicKey.deserialize(publicKey)),
      ZERO_SALT,
      PROVISIONING_INFO,
    );
    const iv = body.slice(1, 1 + IV_LENGTH);
    const ivAndCiphertext = body.slice(0, body.byteLength - MAC_LENGTH);
    const ciphertext = body.slice(1 + IV_LENGTH, body.byteLength - MAC_LENGTH);
    const mac = body.slice(body.byteLength - MAC_LENGTH);
    verifyHmacSha256(ivAndCiphertext, keys[1], mac, MAC_LENGTH);
    const plaintext = decryptAes256CbcPkcsPadding(keys[0], ciphertext, iv);
    const message = decodeSignalProvisionMessage(plaintext);
    const aciIdentityKeyPrivate = message.aciIdentityKeyPrivate;
    if (!aciIdentityKeyPrivate) {
      throw new SignalTsStateError("Provision message is missing aciIdentityKeyPrivate");
    }

    const aciIdentityKeyPair = createIdentityKeyPair(aciIdentityKeyPrivate);
    const pniIdentityKeyPair = message.pniIdentityKeyPrivate
      ? createIdentityKeyPair(message.pniIdentityKeyPrivate)
      : undefined;
    const aci = normalizeProvisionedAci(message.aciBinary, message.aci);
    const pni = normalizeProvisionedPni(message.pniBinary, message.pni);
    const result: SignalProvisionDecryptResult = {
      aciIdentityKeyPair,
      ...(pniIdentityKeyPair ? { pniIdentityKeyPair } : {}),
      aci,
      pni,
      readReceipts: message.readReceipts ?? false,
    };
    assignIfDefined(result, "number", message.number);
    assignIfDefined(result, "provisioningCode", message.provisioningCode);
    assignIfDefined(result, "userAgent", message.userAgent);
    assignIfDefined(result, "profileKey", message.profileKey);
    assignIfDefined(result, "masterKey", message.masterKey);
    assignIfDefined(result, "accountEntropyPool", message.accountEntropyPool);
    assignIfDefined(result, "ephemeralBackupKey", message.ephemeralBackupKey);
    assignIfDefined(result, "mediaRootBackupKey", message.mediaRootBackupKey);
    return result;
  }
}

export async function startSignalDeviceLinkSession({
  environment = "production",
  userAgent = DEFAULT_USER_AGENT,
  capabilities = ["backup5"],
  timeoutMs = DEFAULT_LINK_TIMEOUT_MS,
  abortSignal,
  net,
}: StartSignalDeviceLinkSessionParams = {}): Promise<SignalDeviceLinkSession> {
  const cipher = new SignalProvisioningCipher();
  const connectionNet = net ?? new Net.Net({
    env: resolveLibsignalEnvironment(environment),
    userAgent,
  });
  const abortController = new AbortController();
  const onAbort = () => abortController.abort();
  abortSignal?.addEventListener("abort", onAbort, { once: true });
  const timer = setTimeout(() => abortController.abort(), timeoutMs);
  const address = deferred<string>();
  const provisioning = deferred<SignalProvisionDecryptResult>();
  let connection: ProvisioningConnection | undefined;

  try {
    connection = await connectionNet.connectProvisioning(
      {
        onReceivedAddress: (receivedAddress, ack) => {
          address.resolve(receivedAddress);
          ack.send(200);
        },
        onReceivedEnvelope: (body, ack) => {
          try {
            provisioning.resolve(cipher.decrypt(body));
            ack.send(200);
          } catch (error) {
            provisioning.reject(error);
            ack.send(500);
          }
        },
        onConnectionInterrupted: (cause) => {
          const error = cause ?? new SignalTsStateError("Signal provisioning connection closed");
          address.reject(error);
          provisioning.reject(error);
        },
      },
      { abortSignal: abortController.signal },
    );
    const provisioningAddress = await address.promise;
    clearTimeout(timer);
    abortSignal?.removeEventListener("abort", onAbort);
    const publicKey = cipher.getPublicKey();
    return {
      url: buildLinkDeviceUrl({
        address: provisioningAddress,
        publicKey,
        capabilities,
      }),
      publicKey,
      waitForProvisioning: () => provisioning.promise,
      disconnect: async () => {
        await connection?.disconnect();
      },
    };
  } catch (error) {
    clearTimeout(timer);
    abortSignal?.removeEventListener("abort", onAbort);
    await connection?.disconnect().catch(() => {});
    throw error;
  }
}

export function buildLinkDeviceUrl({
  address,
  publicKey,
  capabilities = [],
}: {
  address: string;
  publicKey: PublicKey;
  capabilities?: string[];
}): string {
  const params = new URLSearchParams({
    uuid: address,
    pub_key: bytesToBase64(publicKey.serialize()),
    capabilities: capabilities.join(","),
  });
  return `sgnl://linkdevice?${params.toString()}`;
}

export function encryptSignalDeviceName(name: string, identityPublicKey: PublicKey): string | undefined {
  const normalized = normalizeDeviceName(name);
  if (!normalized) {
    return undefined;
  }
  const plaintext = utf8Bytes(normalized.slice(0, MAX_DEVICE_NAME_LENGTH));
  const ephemeralPrivateKey = PrivateKey.generate();
  const masterSecret = ephemeralPrivateKey.agree(identityPublicKey);
  const key1 = hmacSha256(masterSecret, utf8Bytes("auth"));
  const syntheticIv = hmacSha256(key1, plaintext).slice(0, IV_LENGTH);
  const key2 = hmacSha256(masterSecret, utf8Bytes("cipher"));
  const cipherKey = hmacSha256(key2, syntheticIv);
  const ciphertext = encryptAes256Ctr(cipherKey, plaintext, new Uint8Array(IV_LENGTH));
  return bytesToBase64(
    encodeSignalDeviceName({
      ephemeralPublic: ephemeralPrivateKey.getPublicKey().serialize(),
      syntheticIv,
      ciphertext,
    }),
  );
}

export function decryptSignalDeviceName(
  encryptedBase64: string,
  identityPrivateKey: PrivateKey,
): string {
  const deviceName = decodeSignalDeviceName(Buffer.from(encryptedBase64, "base64"));
  if (!deviceName.ephemeralPublic || !deviceName.syntheticIv || !deviceName.ciphertext) {
    throw new SignalTsStateError("Encrypted device name is missing required fields");
  }
  const masterSecret = identityPrivateKey.agree(PublicKey.deserialize(deviceName.ephemeralPublic));
  const key2 = hmacSha256(masterSecret, utf8Bytes("cipher"));
  const cipherKey = hmacSha256(key2, deviceName.syntheticIv);
  const plaintext = decryptAes256Ctr(cipherKey, deviceName.ciphertext, new Uint8Array(IV_LENGTH));
  const key1 = hmacSha256(masterSecret, utf8Bytes("auth"));
  const expectedIv = hmacSha256(key1, plaintext).slice(0, IV_LENGTH);
  if (!timingSafeEqual(Buffer.from(expectedIv), Buffer.from(deviceName.syntheticIv))) {
    throw new SignalTsStateError("Encrypted device name synthetic IV mismatch");
  }
  return new TextDecoder().decode(plaintext);
}

export function createIdentityKeyPair(privateKeyBytes: Bytes): IdentityKeyPair {
  const copy = copyBytes(privateKeyBytes);
  clampPrivateKey(copy);
  const privateKey = PrivateKey.deserialize(copy);
  return new IdentityKeyPair(privateKey.getPublicKey(), privateKey);
}

export function deriveSecrets(
  input: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer>,
  info: Uint8Array<ArrayBuffer>,
): [Bytes, Bytes, Bytes] {
  const output = hkdf(3 * 32, input, info, salt);
  return [
    copyBytes(output.slice(0, 32)),
    copyBytes(output.slice(32, 64)),
    copyBytes(output.slice(64, 96)),
  ];
}

export function hmacSha256(key: Uint8Array, plaintext: Uint8Array): Bytes {
  return copyBytes(createHmac("sha256", key).update(plaintext).digest());
}

function verifyHmacSha256(
  plaintext: Uint8Array,
  key: Uint8Array,
  theirMac: Uint8Array,
  length: number,
): void {
  const ourMac = hmacSha256(key, plaintext);
  if (theirMac.byteLength !== length || ourMac.byteLength < length) {
    throw new SignalTsStateError("Provision envelope MAC length is invalid");
  }
  if (!timingSafeEqual(Buffer.from(ourMac.slice(0, length)), Buffer.from(theirMac))) {
    throw new SignalTsStateError("Provision envelope MAC mismatch");
  }
}

function decryptAes256CbcPkcsPadding(
  key: Uint8Array,
  ciphertext: Uint8Array,
  iv: Uint8Array,
): Bytes {
  const decipher = createDecipheriv("aes-256-cbc", key, iv);
  return copyBytes(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
}

function encryptAes256Ctr(key: Uint8Array, plaintext: Uint8Array, counter: Uint8Array): Bytes {
  const cipher = createCipheriv("aes-256-ctr", key, counter);
  return copyBytes(Buffer.concat([cipher.update(plaintext), cipher.final()]));
}

function decryptAes256Ctr(key: Uint8Array, ciphertext: Uint8Array, counter: Uint8Array): Bytes {
  const decipher = createDecipheriv("aes-256-ctr", key, counter);
  return copyBytes(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
}

function normalizeProvisionedAci(aciBinary: Bytes | undefined, aci: string | undefined): string {
  if (aciBinary) {
    return Aci.fromUuidBytes(aciBinary).getServiceIdString();
  }
  if (aci) {
    return Aci.fromUuid(aci).getServiceIdString();
  }
  throw new SignalTsStateError("Provision message is missing ACI");
}

function normalizeProvisionedPni(pniBinary: Bytes | undefined, pni: string | undefined): string {
  if (pniBinary) {
    return Pni.fromUuidBytes(pniBinary).getServiceIdString();
  }
  if (pni) {
    const normalizedPni = pni.startsWith("PNI:") ? pni : `PNI:${pni}`;
    return Pni.parseFromServiceIdString(normalizedPni).getServiceIdString();
  }
  const pniUuid = pniBinary ? serviceIdBinaryToUuid(pniBinary) : null;
  if (pniUuid) {
    return Pni.fromUuid(pniUuid).getServiceIdString();
  }
  throw new SignalTsStateError("Provision message is missing PNI");
}

function normalizeDeviceName(name: string): string {
  return name.trim().replaceAll("\0", "");
}

function clampPrivateKey(privateKey: Uint8Array): void {
  privateKey[0] = (privateKey[0] ?? 0) & 248;
  privateKey[31] = ((privateKey[31] ?? 0) & 127) | 64;
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (error: unknown) => void;
} {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
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
