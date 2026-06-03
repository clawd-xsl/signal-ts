import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PrivateKey } from "@signalapp/libsignal-client";
import { describe, expect, it } from "vitest";
import { FileSignalRepository } from "./file-store.js";

describe("FileSignalRepository", () => {
  it("persists repository, account, and group state across opens", async () => {
    const dir = await mkdtemp(join(tmpdir(), "signal-ts-"));
    const filePath = join(dir, "state.json");
    const identityKey = PrivateKey.generate();
    const remoteKey = PrivateKey.generate().getPublicKey();
    const repository = await FileSignalRepository.open(filePath, {
      initialRepository: {
        identityKeyPrivate: Buffer.from(identityKey.serialize()).toString("base64"),
        registrationId: 42,
        identities: {},
        sessions: {},
        preKeys: {},
        signedPreKeys: {},
        kyberPreKeys: {},
        senderKeys: {},
      },
    });

    await repository.saveIdentity("22222222-2222-4222-8222-222222222222.1", remoteKey);
    await repository.setAccount({
      account: {
        auth: { username: "11111111-1111-4111-8111-111111111111.2", password: "secret" },
        device: {
          aci: "11111111-1111-4111-8111-111111111111",
          e164: "+15555550123",
          deviceId: 2,
          registrationId: 42,
        },
      },
      pni: "PNI:33333333-3333-4333-8333-333333333333",
    });
    await repository.setGroup({
      id: "group-id",
      masterKey: "master",
      distributionId: "44444444-4444-4444-8444-444444444444",
      members: ["11111111-1111-4111-8111-111111111111"],
    });
    await repository.setStickerPack({
      id: "aabb",
      key: "pack-key",
      installed: true,
      title: "stickers",
      stickers: {
        "5": {
          id: 5,
          fileName: "5",
          contentType: "image/webp",
          size: 42,
        },
      },
    });

    const restored = await FileSignalRepository.open(filePath);

    expect((await restored.getLocalIdentityKey()).serialize()).toEqual(identityKey.serialize());
    expect(await restored.getLocalRegistrationId()).toBe(42);
    expect((await restored.getIdentity("22222222-2222-4222-8222-222222222222.1"))?.serialize()).toEqual(
      remoteKey.serialize(),
    );
    expect((await restored.getAccount())?.account.auth.username).toBe(
      "11111111-1111-4111-8111-111111111111.2",
    );
    expect((await restored.getGroup("group-id"))?.masterKey).toBe("master");
    expect((await restored.getStickerPack("AABB"))?.stickers["5"]).toMatchObject({
      id: 5,
      fileName: "5",
      contentType: "image/webp",
      size: 42,
    });
    expect(restored.getStickerFilePath("aabb", "5")).toBe(join(filePath + ".stickers", "aabb", "5"));
    expect(JSON.parse(await readFile(filePath, "utf-8"))).toMatchObject({ version: 1 });
  });
});
