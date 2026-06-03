import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  IdentityChange,
  KyberPreKeyRecord,
  PreKeyRecord,
  PrivateKey,
  PublicKey,
  SenderKeyRecord,
  SessionRecord,
  SignedPreKeyRecord,
  type Uuid,
} from "@signalapp/libsignal-client";
import type { SignalAccountState } from "./account.js";
import { base64ToBytes, bytesToBase64, equalBytes } from "./bytes.js";
import { SignalTsStateError } from "./errors.js";
import {
  senderKeyKey,
  type SerializedSignalRepository,
  type SignalRepository,
} from "./store.js";

export type FileSignalGroupState = {
  id: string;
  masterKey: string;
  distributionId: string;
  revision?: number;
  title?: string;
  members?: string[];
  updatedAt?: number;
};

export type FileSignalAccountState = {
  account: SignalAccountState;
  pni?: string;
  pniIdentityKeyPrivate?: string;
  profileKey?: string;
  masterKey?: string;
  accountEntropyPool?: string;
  mediaRootBackupKey?: string;
  readReceipts?: boolean;
  deviceName?: string;
  userAgent?: string;
  senderCertificates?: {
    withE164?: FileSignalSenderCertificateState;
    withoutE164?: FileSignalSenderCertificateState;
  };
  createdAt?: number;
  updatedAt?: number;
};

export type FileSignalSenderCertificateState = {
  serialized: string;
  expires: number;
};

export type FileSignalRecipientState = {
  aci: string;
  e164?: string | null;
  profileKey?: string;
  accessKey?: string;
  profileUnidentifiedAccessMode?: string;
  name?: string;
  updatedAt?: number;
};

export type FileSignalStickerState = {
  id: number;
  fileName: string;
  emoji?: string;
  contentType?: string;
  size?: number;
};

export type FileSignalStickerPackState = {
  id: string;
  key: string;
  installed?: boolean;
  title?: string;
  author?: string;
  stickers: Record<string, FileSignalStickerState>;
  updatedAt?: number;
};

export type FileSignalStoreData = {
  version: 1;
  repository: SerializedSignalRepository;
  account?: FileSignalAccountState;
  groups: Record<string, FileSignalGroupState>;
  recipients: Record<string, FileSignalRecipientState>;
  stickerPacks: Record<string, FileSignalStickerPackState>;
  usedKyberPreKeys: string[];
};

export type FileSignalRepositoryOptions = {
  initialRepository?: SerializedSignalRepository;
  account?: FileSignalAccountState;
};

export class FileSignalRepository implements SignalRepository {
  private identityKey: PrivateKey;
  private registrationId: number;
  private readonly identities = new Map<string, PublicKey>();
  private readonly sessions = new Map<string, SessionRecord>();
  private readonly preKeys = new Map<number, PreKeyRecord>();
  private readonly signedPreKeys = new Map<number, SignedPreKeyRecord>();
  private readonly kyberPreKeys = new Map<number, KyberPreKeyRecord>();
  private readonly senderKeys = new Map<string, SenderKeyRecord>();
  private readonly groups = new Map<string, FileSignalGroupState>();
  private readonly recipients = new Map<string, FileSignalRecipientState>();
  private readonly stickerPacks = new Map<string, FileSignalStickerPackState>();
  private readonly usedKyberPreKeys = new Set<string>();
  private account: FileSignalAccountState | undefined;
  private pendingPersist: Promise<void> = Promise.resolve();

  private constructor(
    private readonly filePath: string,
    data: FileSignalStoreData,
  ) {
    this.identityKey = PrivateKey.deserialize(base64ToBytes(data.repository.identityKeyPrivate));
    this.registrationId = data.repository.registrationId;
    hydrateMap(data.repository.identities, this.identities, PublicKey.deserialize);
    hydrateMap(data.repository.sessions, this.sessions, SessionRecord.deserialize);
    hydrateNumericMap(data.repository.preKeys, this.preKeys, PreKeyRecord.deserialize);
    hydrateNumericMap(data.repository.signedPreKeys, this.signedPreKeys, SignedPreKeyRecord.deserialize);
    hydrateNumericMap(data.repository.kyberPreKeys, this.kyberPreKeys, KyberPreKeyRecord.deserialize);
    hydrateMap(data.repository.senderKeys, this.senderKeys, SenderKeyRecord.deserialize);
    for (const [id, group] of Object.entries(data.groups)) {
      this.groups.set(id, group);
    }
    for (const [aci, recipient] of Object.entries(data.recipients)) {
      this.recipients.set(aci.toLowerCase(), { ...recipient, aci: recipient.aci.toLowerCase() });
    }
    for (const [id, pack] of Object.entries(data.stickerPacks)) {
      const normalized = normalizeStickerPackId(pack.id || id);
      this.stickerPacks.set(normalized, { ...pack, id: normalized });
    }
    for (const used of data.usedKyberPreKeys) {
      this.usedKyberPreKeys.add(used);
    }
    this.account = data.account;
  }

  static async open(
    filePath: string,
    options: FileSignalRepositoryOptions = {},
  ): Promise<FileSignalRepository> {
    const data = await readStoreFile(filePath, options);
    const repository = new FileSignalRepository(filePath, data);
    if (options.initialRepository || options.account) {
      await repository.persist();
    }
    return repository;
  }

  async getLocalIdentityKey(): Promise<PrivateKey> {
    return this.identityKey;
  }

  async setLocalIdentityKey(identityKey: PrivateKey, registrationId: number): Promise<void> {
    this.identityKey = identityKey;
    this.registrationId = registrationId;
    await this.persist();
  }

  async getLocalRegistrationId(): Promise<number> {
    return this.registrationId;
  }

  async getIdentity(address: string): Promise<PublicKey | null> {
    return this.identities.get(address) ?? null;
  }

  async saveIdentity(address: string, key: PublicKey): Promise<IdentityChange> {
    const existing = this.identities.get(address);
    this.identities.set(address, key);
    await this.persist();
    if (!existing || equalBytes(existing.serialize(), key.serialize())) {
      return IdentityChange.NewOrUnchanged;
    }
    return IdentityChange.ReplacedExisting;
  }

  async getSession(address: string): Promise<SessionRecord | null> {
    return this.sessions.get(address) ?? null;
  }

  async saveSession(address: string, record: SessionRecord): Promise<void> {
    this.sessions.set(address, record);
    await this.persist();
  }

  async getPreKey(id: number): Promise<PreKeyRecord | null> {
    return this.preKeys.get(id) ?? null;
  }

  async savePreKey(id: number, record: PreKeyRecord): Promise<void> {
    this.preKeys.set(id, record);
    await this.persist();
  }

  async removePreKey(id: number): Promise<void> {
    this.preKeys.delete(id);
    await this.persist();
  }

  async getSignedPreKey(id: number): Promise<SignedPreKeyRecord | null> {
    return this.signedPreKeys.get(id) ?? null;
  }

  async saveSignedPreKey(id: number, record: SignedPreKeyRecord): Promise<void> {
    this.signedPreKeys.set(id, record);
    await this.persist();
  }

  async getKyberPreKey(id: number): Promise<KyberPreKeyRecord | null> {
    return this.kyberPreKeys.get(id) ?? null;
  }

  async saveKyberPreKey(id: number, record: KyberPreKeyRecord): Promise<void> {
    this.kyberPreKeys.set(id, record);
    await this.persist();
  }

  async markKyberPreKeyUsed(
    id: number,
    signedPreKeyId: number,
    baseKey: PublicKey,
  ): Promise<void> {
    this.usedKyberPreKeys.add(`${id}:${signedPreKeyId}:${bytesToBase64(baseKey.serialize())}`);
    await this.persist();
  }

  async getSenderKey(sender: string, distributionId: Uuid): Promise<SenderKeyRecord | null> {
    return this.senderKeys.get(senderKeyKey(sender, distributionId)) ?? null;
  }

  async saveSenderKey(
    sender: string,
    distributionId: Uuid,
    record: SenderKeyRecord,
  ): Promise<void> {
    this.senderKeys.set(senderKeyKey(sender, distributionId), record);
    await this.persist();
  }

  async getAccount(): Promise<FileSignalAccountState | undefined> {
    return this.account;
  }

  async setAccount(account: FileSignalAccountState): Promise<void> {
    this.account = { ...account, updatedAt: Date.now() };
    await this.persist();
  }

  async getGroup(id: string): Promise<FileSignalGroupState | undefined> {
    return this.groups.get(id);
  }

  async setGroup(group: FileSignalGroupState): Promise<void> {
    this.groups.set(group.id, { ...group, updatedAt: Date.now() });
    await this.persist();
  }

  async deleteGroup(id: string): Promise<void> {
    this.groups.delete(id);
    await this.persist();
  }

  async getRecipientByAci(aci: string): Promise<FileSignalRecipientState | undefined> {
    return this.recipients.get(aci.toLowerCase());
  }

  async getRecipientByE164(e164: string): Promise<FileSignalRecipientState | undefined> {
    return [...this.recipients.values()].find((recipient) => recipient.e164 === e164);
  }

  async setRecipient(recipient: FileSignalRecipientState): Promise<void> {
    this.recipients.set(recipient.aci.toLowerCase(), {
      ...recipient,
      aci: recipient.aci.toLowerCase(),
      updatedAt: Date.now(),
    });
    await this.persist();
  }

  async getStickerPack(id: string): Promise<FileSignalStickerPackState | undefined> {
    return this.stickerPacks.get(normalizeStickerPackId(id));
  }

  async setStickerPack(pack: FileSignalStickerPackState): Promise<void> {
    const id = normalizeStickerPackId(pack.id);
    this.stickerPacks.set(id, {
      ...pack,
      id,
      updatedAt: Date.now(),
    });
    await this.persist();
  }

  stickerStorePath(): string {
    return `${this.filePath}.stickers`;
  }

  getStickerFilePath(packId: string, fileName: string): string {
    return join(this.stickerStorePath(), normalizeStickerPackId(packId), normalizeStickerFileName(fileName));
  }

  snapshot(): FileSignalStoreData {
    const account = this.account;
    return {
      version: 1,
      repository: this.repositorySnapshot(),
      ...(account ? { account } : {}),
      groups: Object.fromEntries([...this.groups].sort(([a], [b]) => a.localeCompare(b))),
      recipients: Object.fromEntries(
        [...this.recipients].sort(([a], [b]) => a.localeCompare(b)),
      ),
      stickerPacks: Object.fromEntries(
        [...this.stickerPacks].sort(([a], [b]) => a.localeCompare(b)),
      ),
      usedKyberPreKeys: [...this.usedKyberPreKeys].sort(),
    };
  }

  repositorySnapshot(): SerializedSignalRepository {
    return {
      identityKeyPrivate: bytesToBase64(this.identityKey.serialize()),
      registrationId: this.registrationId,
      identities: serializeMap(this.identities, (record) => record.serialize()),
      sessions: serializeMap(this.sessions, (record) => record.serialize()),
      preKeys: serializeNumericMap(this.preKeys, (record) => record.serialize()),
      signedPreKeys: serializeNumericMap(this.signedPreKeys, (record) => record.serialize()),
      kyberPreKeys: serializeNumericMap(this.kyberPreKeys, (record) => record.serialize()),
      senderKeys: serializeMap(this.senderKeys, (record) => record.serialize()),
    };
  }

  private async persist(): Promise<void> {
    const next = this.pendingPersist.then(async () => {
      await mkdir(dirname(this.filePath), { recursive: true });
      const temporaryPath = `${this.filePath}.${process.pid}.tmp`;
      await writeFile(temporaryPath, `${JSON.stringify(this.snapshot(), null, 2)}\n`, {
        mode: 0o600,
      });
      await rename(temporaryPath, this.filePath);
    });
    this.pendingPersist = next.catch(() => {});
    await next;
  }
}

async function readStoreFile(
  filePath: string,
  options: FileSignalRepositoryOptions,
): Promise<FileSignalStoreData> {
  try {
    return parseStoreFile(await readFile(filePath, "utf-8"));
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return createInitialStoreData(options);
    }
    throw error;
  }
}

function createInitialStoreData(options: FileSignalRepositoryOptions): FileSignalStoreData {
  const repository = options.initialRepository ?? {
    identityKeyPrivate: bytesToBase64(PrivateKey.generate().serialize()),
    registrationId: 1 + Math.floor(Math.random() * 16_000),
    identities: {},
    sessions: {},
    preKeys: {},
    signedPreKeys: {},
    kyberPreKeys: {},
    senderKeys: {},
  };
  return {
    version: 1,
    repository,
    ...(options.account ? { account: options.account } : {}),
    groups: {},
    recipients: {},
    stickerPacks: {},
    usedKyberPreKeys: [],
  };
}

function parseStoreFile(raw: string): FileSignalStoreData {
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new SignalTsStateError("Signal state file must contain an object");
  }
  const data = parsed as Partial<FileSignalStoreData>;
  if (data.version !== 1) {
    throw new SignalTsStateError("Unsupported Signal state file version");
  }
  if (!data.repository || !data.groups || !data.usedKyberPreKeys) {
    throw new SignalTsStateError("Signal state file is missing required fields");
  }
  return {
    version: 1,
    repository: data.repository,
    ...(data.account ? { account: data.account } : {}),
    groups: data.groups,
    recipients: data.recipients ?? {},
    stickerPacks: data.stickerPacks ?? {},
    usedKyberPreKeys: data.usedKyberPreKeys,
  };
}

function normalizeStickerPackId(id: string): string {
  const normalized = id.trim().toLowerCase();
  if (!/^(?:[0-9a-f]{2})+$/.test(normalized)) {
    throw new SignalTsStateError("Signal sticker pack id must be even-length hex");
  }
  return normalized;
}

function normalizeStickerFileName(fileName: string): string {
  const normalized = fileName.trim();
  if (
    !normalized ||
    normalized === "." ||
    normalized === ".." ||
    normalized.includes("/") ||
    normalized.includes("\\")
  ) {
    throw new SignalTsStateError("Signal sticker file name must be a relative file name");
  }
  return normalized;
}

function serializeMap<T>(
  map: ReadonlyMap<string, T>,
  serialize: (record: T) => Uint8Array,
): Record<string, string> {
  return Object.fromEntries(
    [...map]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => [key, bytesToBase64(serialize(value))]),
  );
}

function serializeNumericMap<T>(
  map: ReadonlyMap<number, T>,
  serialize: (record: T) => Uint8Array,
): Record<string, string> {
  return Object.fromEntries(
    [...map]
      .sort(([a], [b]) => a - b)
      .map(([key, value]) => [String(key), bytesToBase64(serialize(value))]),
  );
}

function hydrateMap<T>(
  records: Record<string, string>,
  target: Map<string, T>,
  deserialize: (bytes: Uint8Array<ArrayBuffer>) => T,
): void {
  for (const [key, value] of Object.entries(records)) {
    target.set(key, deserialize(base64ToBytes(value)));
  }
}

function hydrateNumericMap<T>(
  records: Record<string, string>,
  target: Map<number, T>,
  deserialize: (bytes: Uint8Array<ArrayBuffer>) => T,
): void {
  for (const [key, value] of Object.entries(records)) {
    const numericKey = Number(key);
    if (Number.isInteger(numericKey)) {
      target.set(numericKey, deserialize(base64ToBytes(value)));
    }
  }
}
