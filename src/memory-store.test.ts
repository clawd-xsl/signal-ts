import { Direction, PrivateKey, ProtocolAddress } from "@signalapp/libsignal-client";
import { describe, expect, it } from "vitest";
import { InMemorySignalRepository } from "./memory-store.js";
import { RepositoryIdentityKeyStore } from "./store.js";

describe("InMemorySignalRepository", () => {
  it("persists local identity state across snapshots", async () => {
    const identityKey = PrivateKey.generate();
    const repository = new InMemorySignalRepository({ identityKey, registrationId: 42 });

    const restored = InMemorySignalRepository.fromSnapshot(repository.snapshot());

    expect((await restored.getLocalIdentityKey()).serialize()).toEqual(identityKey.serialize());
    expect(await restored.getLocalRegistrationId()).toBe(42);
  });

  it("trusts first-use identity and flags replacement", async () => {
    const repository = new InMemorySignalRepository({ registrationId: 42 });
    const store = new RepositoryIdentityKeyStore(repository);
    const address = ProtocolAddress.new("11111111-1111-4111-8111-111111111111", 1);
    const first = PrivateKey.generate().getPublicKey();
    const second = PrivateKey.generate().getPublicKey();

    expect(await store.isTrustedIdentity(address, first, Direction.Sending)).toBe(true);
    await store.saveIdentity(address, first);
    expect(await store.isTrustedIdentity(address, first, Direction.Sending)).toBe(true);
    expect(await store.isTrustedIdentity(address, second, Direction.Sending)).toBe(false);
  });
});
