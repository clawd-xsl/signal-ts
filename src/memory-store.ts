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
import { base64ToBytes, bytesToBase64, equalBytes } from "./bytes.js";
import {
  senderKeyKey,
  type SerializedSignalRepository,
  type SignalRepository,
} from "./store.js";

export type InMemorySignalRepositoryOptions = {
  identityKey?: PrivateKey;
  registrationId?: number;
};

export class InMemorySignalRepository implements SignalRepository {
  private readonly identityKey: PrivateKey;
  private readonly registrationId: number;
  private readonly identities = new Map<string, PublicKey>();
  private readonly sessions = new Map<string, SessionRecord>();
  private readonly preKeys = new Map<number, PreKeyRecord>();
  private readonly signedPreKeys = new Map<number, SignedPreKeyRecord>();
  private readonly kyberPreKeys = new Map<number, KyberPreKeyRecord>();
  private readonly senderKeys = new Map<string, SenderKeyRecord>();
  readonly usedKyberPreKeys = new Set<string>();

  constructor(options: InMemorySignalRepositoryOptions = {}) {
    this.identityKey = options.identityKey ?? PrivateKey.generate();
    this.registrationId = options.registrationId ?? 1 + Math.floor(Math.random() * 16_000);
  }

  async getLocalIdentityKey(): Promise<PrivateKey> {
    return this.identityKey;
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
  }

  async removeSession(address: string): Promise<void> {
    this.sessions.delete(address);
  }

  async getPreKey(id: number): Promise<PreKeyRecord | null> {
    return this.preKeys.get(id) ?? null;
  }

  async savePreKey(id: number, record: PreKeyRecord): Promise<void> {
    this.preKeys.set(id, record);
  }

  async removePreKey(id: number): Promise<void> {
    this.preKeys.delete(id);
  }

  async getSignedPreKey(id: number): Promise<SignedPreKeyRecord | null> {
    return this.signedPreKeys.get(id) ?? null;
  }

  async saveSignedPreKey(id: number, record: SignedPreKeyRecord): Promise<void> {
    this.signedPreKeys.set(id, record);
  }

  async getKyberPreKey(id: number): Promise<KyberPreKeyRecord | null> {
    return this.kyberPreKeys.get(id) ?? null;
  }

  async saveKyberPreKey(id: number, record: KyberPreKeyRecord): Promise<void> {
    this.kyberPreKeys.set(id, record);
  }

  async markKyberPreKeyUsed(
    id: number,
    signedPreKeyId: number,
    baseKey: PublicKey,
  ): Promise<void> {
    this.usedKyberPreKeys.add(`${id}:${signedPreKeyId}:${bytesToBase64(baseKey.serialize())}`);
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
  }

  snapshot(): SerializedSignalRepository {
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

  static fromSnapshot(snapshot: SerializedSignalRepository): InMemorySignalRepository {
    const repository = new InMemorySignalRepository({
      identityKey: PrivateKey.deserialize(base64ToBytes(snapshot.identityKeyPrivate)),
      registrationId: snapshot.registrationId,
    });
    hydrateMap(snapshot.identities, repository.identities, PublicKey.deserialize);
    hydrateMap(snapshot.sessions, repository.sessions, SessionRecord.deserialize);
    hydrateNumericMap(snapshot.preKeys, repository.preKeys, PreKeyRecord.deserialize);
    hydrateNumericMap(snapshot.signedPreKeys, repository.signedPreKeys, SignedPreKeyRecord.deserialize);
    hydrateNumericMap(snapshot.kyberPreKeys, repository.kyberPreKeys, KyberPreKeyRecord.deserialize);
    hydrateMap(snapshot.senderKeys, repository.senderKeys, SenderKeyRecord.deserialize);
    return repository;
  }
}

function serializeMap<T>(
  map: ReadonlyMap<string, T>,
  serialize: (record: T) => Uint8Array,
): Record<string, string> {
  return Object.fromEntries([...map].map(([key, value]) => [key, bytesToBase64(serialize(value))]));
}

function serializeNumericMap<T>(
  map: ReadonlyMap<number, T>,
  serialize: (record: T) => Uint8Array,
): Record<string, string> {
  return Object.fromEntries(
    [...map].map(([key, value]) => [String(key), bytesToBase64(serialize(value))]),
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
