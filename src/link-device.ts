import { randomBytes } from "node:crypto";
import {
  IdentityKeyPair,
  KEMKeyPair,
  KyberPreKeyRecord,
  Net,
  PrivateKey,
  SignedPreKeyRecord,
  type KEMPublicKey,
  type PublicKey,
} from "@signalapp/libsignal-client";
import type { ChatRequest, RequestOptions } from "@signalapp/libsignal-client/dist/net/Chat.js";
import type { ChatResponse } from "@signalapp/libsignal-client/dist/Native.js";
import { bytesToBase64, copyBytes, type Bytes } from "./bytes.js";
import { SignalTsStateError } from "./errors.js";
import type { FileSignalAccountState, FileSignalRepository } from "./file-store.js";
import { encryptSignalDeviceName, type SignalProvisionDecryptResult } from "./provisioning.js";
import { resolveLibsignalEnvironment, type SignalAccountState, type SignalEnvironment } from "./account.js";

export type LinkSignalDeviceParams = {
  provisioning: SignalProvisionDecryptResult;
  deviceName: string;
  environment?: SignalEnvironment;
  userAgent?: string;
  repository?: FileSignalRepository;
  password?: string;
  registrationId?: number;
  pniRegistrationId?: number;
  keyIdSeed?: number;
  connectionFactory?: SignalLinkDeviceConnectionFactory;
  abortSignal?: AbortSignal;
};

export type SignalLinkedDeviceAccount = {
  account: SignalAccountState;
  accountState: FileSignalAccountState;
  repositorySnapshot?: ReturnType<FileSignalRepository["repositorySnapshot"]>;
  pni: string;
  password: string;
  registrationId: number;
  pniRegistrationId: number;
  deviceId: number;
};

export type SignalLinkDeviceConnection = {
  fetch: (request: ChatRequest, options?: RequestOptions) => Promise<ChatResponse>;
  disconnect: () => Promise<void>;
};

export type SignalLinkDeviceConnectionFactory = (params: {
  net: Net.Net;
  abortSignal?: AbortSignal;
}) => Promise<SignalLinkDeviceConnection>;

type UploadSignedPreKey = {
  keyId: number;
  publicKey: PublicKey;
  signature: Bytes;
};

type UploadKyberPreKey = {
  keyId: number;
  publicKey: KEMPublicKey;
  signature: Bytes;
};

type GeneratedSignedPreKey = UploadSignedPreKey & {
  record: SignedPreKeyRecord;
};

type GeneratedKyberPreKey = UploadKyberPreKey & {
  record: KyberPreKeyRecord;
};

const DEFAULT_USER_AGENT = "OpenClaw signal-ts/0.0.0";
const LINK_DEVICE_PATH = "/v1/devices/link";

export async function linkSignalDevice({
  provisioning,
  deviceName,
  environment = "production",
  userAgent = DEFAULT_USER_AGENT,
  repository,
  password = generatePassword(),
  registrationId = generateRegistrationId(),
  pniRegistrationId = generateRegistrationId(),
  keyIdSeed = generateKeyId(),
  connectionFactory = defaultLinkDeviceConnectionFactory,
  abortSignal,
}: LinkSignalDeviceParams): Promise<SignalLinkedDeviceAccount> {
  if (!provisioning.number) {
    throw new SignalTsStateError("Provisioning data is missing phone number");
  }
  if (!provisioning.provisioningCode) {
    throw new SignalTsStateError("Provisioning data is missing provisioningCode");
  }
  if (!provisioning.pniIdentityKeyPair) {
    throw new SignalTsStateError("Provisioning data is missing PNI identity key pair");
  }
  if (!provisioning.profileKey) {
    throw new SignalTsStateError("Provisioning data is missing profileKey");
  }
  if (!provisioning.masterKey && !provisioning.accountEntropyPool) {
    throw new SignalTsStateError("Provisioning data is missing masterKey/accountEntropyPool");
  }

  const aciSignedPreKey = generateSignedPreKey(provisioning.aciIdentityKeyPair, keyIdSeed);
  const pniSignedPreKey = generateSignedPreKey(provisioning.pniIdentityKeyPair, keyIdSeed + 1);
  const aciPqLastResortPreKey = generateKyberPreKey(provisioning.aciIdentityKeyPair, keyIdSeed + 2);
  const pniPqLastResortPreKey = generateKyberPreKey(provisioning.pniIdentityKeyPair, keyIdSeed + 3);
  const encryptedDeviceName = encryptSignalDeviceName(
    deviceName,
    provisioning.aciIdentityKeyPair.publicKey,
  );

  const connectionNet = new Net.Net({
    env: resolveLibsignalEnvironment(environment),
    userAgent,
  });
  const connection = await connectionFactory({
    net: connectionNet,
    ...(abortSignal ? { abortSignal } : {}),
  });
  try {
    const response = await connection.fetch(
      {
        verb: "PUT",
        path: LINK_DEVICE_PATH,
        headers: [
          ["Authorization", basicAuth(provisioning.number, password)],
          ["Content-Type", "application/json; charset=utf-8"],
          ["Accept", "application/json"],
          ["X-Signal-Agent", "OWD"],
        ],
        body: copyBytes(Buffer.from(JSON.stringify({
          verificationCode: provisioning.provisioningCode,
          accountAttributes: {
            fetchesMessages: true,
            name: encryptedDeviceName,
            registrationId,
            pniRegistrationId,
            capabilities: {
              attachmentBackfill: true,
              spqr: true,
            },
          },
          aciSignedPreKey: serializeSignedPreKey(aciSignedPreKey),
          pniSignedPreKey: serializeSignedPreKey(pniSignedPreKey),
          aciPqLastResortPreKey: serializeSignedPreKey(aciPqLastResortPreKey),
          pniPqLastResortPreKey: serializeSignedPreKey(pniPqLastResortPreKey),
        }))),
        timeoutMillis: 30_000,
      },
      abortSignal ? { abortSignal } : undefined,
    );
    const result = parseLinkDeviceResponse(response);
    const pni = normalizePniFromResponse(result.pni);
    if (result.uuid !== provisioning.aci) {
      throw new SignalTsStateError("Linked device response ACI does not match provisioning data");
    }
    if (pni !== provisioning.pni) {
      throw new SignalTsStateError("Linked device response PNI does not match provisioning data");
    }
    const account: SignalAccountState = {
      auth: {
        username: `${result.uuid}.${result.deviceId}`,
        password,
      },
      device: {
        aci: result.uuid,
        e164: provisioning.number,
        deviceId: result.deviceId,
        registrationId,
      },
    };
    const accountState = buildAccountState({
      account,
      provisioning,
      pni,
      deviceName,
      userAgent,
    });
    if (repository) {
      await repository.setLocalIdentityKey(provisioning.aciIdentityKeyPair.privateKey, registrationId);
      await repository.saveSignedPreKey(aciSignedPreKey.keyId, aciSignedPreKey.record);
      await repository.saveKyberPreKey(aciPqLastResortPreKey.keyId, aciPqLastResortPreKey.record);
      await repository.setAccount(accountState);
    }
    return {
      account,
      accountState,
      ...(repository ? { repositorySnapshot: repository.repositorySnapshot() } : {}),
      pni,
      password,
      registrationId,
      pniRegistrationId,
      deviceId: result.deviceId,
    };
  } finally {
    await connection.disconnect();
  }
}

export function generateRegistrationId(): number {
  return 1 + Math.floor(Math.random() * 16_383);
}

export function generatePassword(): string {
  const base64 = bytesToBase64(randomBytes(16));
  return base64.slice(0, -2);
}

export function generateKeyId(): number {
  return randomBytes(4).readUInt32LE(0) & 0x00ff_ffff;
}

export function generateSignedPreKey(
  identityKeyPair: IdentityKeyPair,
  keyId: number,
): GeneratedSignedPreKey {
  const privateKey = PrivateKey.generate();
  const publicKey = privateKey.getPublicKey();
  const signature = copyBytes(identityKeyPair.privateKey.sign(publicKey.serialize()));
  return {
    keyId,
    publicKey,
    signature,
    record: SignedPreKeyRecord.new(keyId, Date.now(), publicKey, privateKey, signature),
  };
}

export function generateKyberPreKey(
  identityKeyPair: IdentityKeyPair,
  keyId: number,
): GeneratedKyberPreKey {
  const keyPair = KEMKeyPair.generate();
  const publicKey = keyPair.getPublicKey();
  const signature = copyBytes(identityKeyPair.privateKey.sign(publicKey.serialize()));
  return {
    keyId,
    publicKey,
    signature,
    record: KyberPreKeyRecord.new(keyId, Date.now(), keyPair, signature),
  };
}

async function defaultLinkDeviceConnectionFactory({
  net,
  abortSignal,
}: {
  net: Net.Net;
  abortSignal?: AbortSignal;
}): Promise<SignalLinkDeviceConnection> {
  return await net.connectUnauthenticatedChat(
    { onConnectionInterrupted: () => {} },
    abortSignal ? { abortSignal } : undefined,
  );
}

function buildAccountState({
  account,
  provisioning,
  pni,
  deviceName,
  userAgent,
}: {
  account: SignalAccountState;
  provisioning: SignalProvisionDecryptResult;
  pni: string;
  deviceName: string;
  userAgent: string;
}): FileSignalAccountState {
  const state: FileSignalAccountState = {
    account,
    pni,
    pniIdentityKeyPrivate: bytesToBase64(provisioning.pniIdentityKeyPair?.privateKey.serialize() ?? new Uint8Array()),
    profileKey: bytesToBase64(provisioning.profileKey ?? new Uint8Array()),
    readReceipts: provisioning.readReceipts,
    deviceName,
    userAgent,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  assignIfDefined(state, "masterKey", provisioning.masterKey ? bytesToBase64(provisioning.masterKey) : undefined);
  assignIfDefined(state, "accountEntropyPool", provisioning.accountEntropyPool);
  assignIfDefined(
    state,
    "mediaRootBackupKey",
    provisioning.mediaRootBackupKey ? bytesToBase64(provisioning.mediaRootBackupKey) : undefined,
  );
  return state;
}

function parseLinkDeviceResponse(response: ChatResponse): {
  uuid: string;
  pni: string;
  deviceId: number;
} {
  if (response.status < 200 || response.status >= 300) {
    throw new SignalTsStateError(`Link device failed: HTTP ${response.status}`);
  }
  if (!response.body) {
    throw new SignalTsStateError("Link device response is missing body");
  }
  const parsed = JSON.parse(new TextDecoder().decode(response.body)) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new SignalTsStateError("Link device response must be an object");
  }
  const record = parsed as Record<string, unknown>;
  return {
    uuid: requireString(record["uuid"], "uuid"),
    pni: requireString(record["pni"], "pni"),
    deviceId: requirePositiveInteger(record["deviceId"], "deviceId"),
  };
}

function serializeSignedPreKey(preKey: UploadSignedPreKey | UploadKyberPreKey): {
  keyId: number;
  publicKey: string;
  signature: string;
} {
  return {
    keyId: preKey.keyId,
    publicKey: bytesToBase64(preKey.publicKey.serialize()),
    signature: bytesToBase64(preKey.signature),
  };
}

function basicAuth(username: string, password: string): string {
  return `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`;
}

function normalizePniFromResponse(pni: string): string {
  return pni.startsWith("PNI:") ? pni : `PNI:${pni}`;
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new SignalTsStateError(`Link device response ${field} must be a non-empty string`);
  }
  return value.trim();
}

function requirePositiveInteger(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
    throw new SignalTsStateError(`Link device response ${field} must be a positive integer`);
  }
  return value;
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
