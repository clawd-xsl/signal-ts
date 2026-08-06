import { Direction, PrivateKey, ProtocolAddress, SessionRecord } from "@signalapp/libsignal-client";
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

  it("lists session device ids per service id", async () => {
    const repository = new InMemorySignalRepository({ registrationId: 42 });
    const record = {} as SessionRecord;
    const serviceId = "11111111-1111-4111-8111-111111111111";
    await repository.saveSession(`${serviceId}.2`, record);
    await repository.saveSession(`${serviceId}.1`, record);
    await repository.saveSession("22222222-2222-4222-8222-222222222222.1", record);

    expect(await repository.listSessionDeviceIds(serviceId)).toEqual([1, 2]);
    await repository.removeSession(`${serviceId}.1`);
    expect(await repository.listSessionDeviceIds(serviceId)).toEqual([2]);
    expect(await repository.listSessionDeviceIds("33333333-3333-4333-8333-333333333333")).toEqual(
      [],
    );
  });
});
