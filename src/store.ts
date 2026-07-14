import {
  Direction,
  IdentityChange,
  IdentityKeyPair,
  IdentityKeyStore,
  KyberPreKeyRecord,
  KyberPreKeyStore,
  PreKeyRecord,
  PreKeyStore,
  PrivateKey,
  ProtocolAddress,
  PublicKey,
  SenderKeyRecord,
  SenderKeyStore,
  SessionRecord,
  SessionStore,
  SignedPreKeyRecord,
  SignedPreKeyStore,
  type Uuid,
} from "@signalapp/libsignal-client";
import { equalBytes, type Bytes } from "./bytes.js";
import { SignalTsStateError } from "./errors.js";

export type SerializedSignalRepository = {
  identityKeyPrivate: string;
  registrationId: number;
  identities: Record<string, string>;
  sessions: Record<string, string>;
  preKeys: Record<string, string>;
  signedPreKeys: Record<string, string>;
  kyberPreKeys: Record<string, string>;
  senderKeys: Record<string, string>;
};

export interface SignalRepository {
  getLocalIdentityKey(): Promise<PrivateKey>;
  getLocalRegistrationId(): Promise<number>;

  getIdentity(address: string): Promise<PublicKey | null>;
  saveIdentity(address: string, key: PublicKey): Promise<IdentityChange>;

  getSession(address: string): Promise<SessionRecord | null>;
  saveSession(address: string, record: SessionRecord): Promise<void>;
  removeSession(address: string): Promise<void>;

  getPreKey(id: number): Promise<PreKeyRecord | null>;
  savePreKey(id: number, record: PreKeyRecord): Promise<void>;
  removePreKey(id: number): Promise<void>;

  getSignedPreKey(id: number): Promise<SignedPreKeyRecord | null>;
  saveSignedPreKey(id: number, record: SignedPreKeyRecord): Promise<void>;

  getKyberPreKey(id: number): Promise<KyberPreKeyRecord | null>;
  saveKyberPreKey(id: number, record: KyberPreKeyRecord): Promise<void>;
  markKyberPreKeyUsed(id: number, signedPreKeyId: number, baseKey: PublicKey): Promise<void>;

  getSenderKey(sender: string, distributionId: Uuid): Promise<SenderKeyRecord | null>;
  saveSenderKey(sender: string, distributionId: Uuid, record: SenderKeyRecord): Promise<void>;
}

export function protocolAddressKey(address: ProtocolAddress): string {
  return `${address.name()}.${address.deviceId()}`;
}

export function senderKeyKey(sender: string, distributionId: Uuid): string {
  return `${sender}:${distributionId}`;
}

function missingRecord(kind: string, id: string | number): never {
  throw new SignalTsStateError(`Missing Signal ${kind}: ${id}`);
}

export class RepositorySessionStore extends SessionStore {
  constructor(private readonly repository: SignalRepository) {
    super();
  }

  async saveSession(name: ProtocolAddress, record: SessionRecord): Promise<void> {
    await this.repository.saveSession(protocolAddressKey(name), record);
  }

  async getSession(name: ProtocolAddress): Promise<SessionRecord | null> {
    return await this.repository.getSession(protocolAddressKey(name));
  }

  async removeSession(name: ProtocolAddress): Promise<void> {
    await this.repository.removeSession(protocolAddressKey(name));
  }

  async getExistingSessions(addresses: ProtocolAddress[]): Promise<SessionRecord[]> {
    const sessions: SessionRecord[] = [];
    for (const address of addresses) {
      const session = await this.getSession(address);
      if (session) {
        sessions.push(session);
      }
    }
    return sessions;
  }
}

export class RepositoryIdentityKeyStore extends IdentityKeyStore {
  constructor(private readonly repository: SignalRepository) {
    super();
  }

  async getIdentityKey(): Promise<PrivateKey> {
    return await this.repository.getLocalIdentityKey();
  }

  override async getIdentityKeyPair(): Promise<IdentityKeyPair> {
    const privateKey = await this.repository.getLocalIdentityKey();
    return new IdentityKeyPair(privateKey.getPublicKey(), privateKey);
  }

  async getLocalRegistrationId(): Promise<number> {
    return await this.repository.getLocalRegistrationId();
  }

  async saveIdentity(name: ProtocolAddress, key: PublicKey): Promise<IdentityChange> {
    return await this.repository.saveIdentity(protocolAddressKey(name), key);
  }

  async isTrustedIdentity(
    name: ProtocolAddress,
    key: PublicKey,
    _direction: Direction,
  ): Promise<boolean> {
    const existing = await this.repository.getIdentity(protocolAddressKey(name));
    return existing === null || equalBytes(existing.serialize(), key.serialize());
  }

  async getIdentity(name: ProtocolAddress): Promise<PublicKey | null> {
    return await this.repository.getIdentity(protocolAddressKey(name));
  }
}

export class RepositoryPreKeyStore extends PreKeyStore {
  constructor(private readonly repository: SignalRepository) {
    super();
  }

  async savePreKey(id: number, record: PreKeyRecord): Promise<void> {
    await this.repository.savePreKey(id, record);
  }

  async getPreKey(id: number): Promise<PreKeyRecord> {
    return (await this.repository.getPreKey(id)) ?? missingRecord("prekey", id);
  }

  async removePreKey(id: number): Promise<void> {
    await this.repository.removePreKey(id);
  }
}

export class RepositorySignedPreKeyStore extends SignedPreKeyStore {
  constructor(private readonly repository: SignalRepository) {
    super();
  }

  async saveSignedPreKey(id: number, record: SignedPreKeyRecord): Promise<void> {
    await this.repository.saveSignedPreKey(id, record);
  }

  async getSignedPreKey(id: number): Promise<SignedPreKeyRecord> {
    return (await this.repository.getSignedPreKey(id)) ?? missingRecord("signed prekey", id);
  }
}

export class RepositoryKyberPreKeyStore extends KyberPreKeyStore {
  constructor(private readonly repository: SignalRepository) {
    super();
  }

  async saveKyberPreKey(id: number, record: KyberPreKeyRecord): Promise<void> {
    await this.repository.saveKyberPreKey(id, record);
  }

  async getKyberPreKey(id: number): Promise<KyberPreKeyRecord> {
    return (await this.repository.getKyberPreKey(id)) ?? missingRecord("Kyber prekey", id);
  }

  async markKyberPreKeyUsed(
    id: number,
    signedPreKeyId: number,
    baseKey: PublicKey,
  ): Promise<void> {
    await this.repository.markKyberPreKeyUsed(id, signedPreKeyId, baseKey);
  }
}

export class RepositorySenderKeyStore extends SenderKeyStore {
  constructor(private readonly repository: SignalRepository) {
    super();
  }

  async saveSenderKey(
    sender: ProtocolAddress,
    distributionId: Uuid,
    record: SenderKeyRecord,
  ): Promise<void> {
    await this.repository.saveSenderKey(protocolAddressKey(sender), distributionId, record);
  }

  async getSenderKey(
    sender: ProtocolAddress,
    distributionId: Uuid,
  ): Promise<SenderKeyRecord | null> {
    return await this.repository.getSenderKey(protocolAddressKey(sender), distributionId);
  }
}

export type LibsignalStores = {
  sessionStore: SessionStore;
  identityStore: IdentityKeyStore;
  preKeyStore: PreKeyStore;
  signedPreKeyStore: SignedPreKeyStore;
  kyberPreKeyStore: KyberPreKeyStore;
  senderKeyStore: SenderKeyStore;
};

export function createLibsignalStores(repository: SignalRepository): LibsignalStores {
  return {
    sessionStore: new RepositorySessionStore(repository),
    identityStore: new RepositoryIdentityKeyStore(repository),
    preKeyStore: new RepositoryPreKeyStore(repository),
    signedPreKeyStore: new RepositorySignedPreKeyStore(repository),
    kyberPreKeyStore: new RepositoryKyberPreKeyStore(repository),
    senderKeyStore: new RepositorySenderKeyStore(repository),
  };
}

export type SerializedRecordClass<T> = {
  deserialize(buffer: Bytes): T;
};
