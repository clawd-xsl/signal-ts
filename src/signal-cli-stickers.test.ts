import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import { bytesToBase64 } from "./bytes.js";
import { FileSignalRepository } from "./file-store.js";
import { importSignalCliStickerStore } from "./signal-cli-stickers.js";

describe("signal-cli sticker migration", () => {
  it("imports installed sticker packs from the signal-cli db and sticker directory", async () => {
    const dir = await mkdtemp(join(tmpdir(), "signal-ts-stickers-"));
    const accountDbPath = join(dir, "account.db");
    const stickersDir = join(dir, "stickers");
    const packId = "aabbccdd";
    const packKey = Uint8Array.from([1, 2, 3, 4]);
    const database = new DatabaseSync(accountDbPath);
    database.exec("create table sticker (pack_id blob unique, pack_key blob, installed integer)");
    database.prepare("insert into sticker (pack_id, pack_key, installed) values (?, ?, ?)").run(
      Buffer.from(packId, "hex"),
      Buffer.from(packKey),
      1,
    );
    database.close();

    const sourcePackDir = join(stickersDir, packId);
    await mkdir(sourcePackDir, { recursive: true });
    await writeFile(
      join(sourcePackDir, "manifest.json"),
      JSON.stringify({
        title: "test pack",
        author: "tester",
        stickers: [{ id: 5, file: "5", emoji: "x", contentType: "image/webp" }],
      }),
    );
    await writeFile(join(sourcePackDir, "5"), Uint8Array.from([9, 8, 7]));

    const repository = await FileSignalRepository.open(join(dir, "state.json"));
    const result = await importSignalCliStickerStore({
      repository,
      accountDbPath,
      stickersDir,
    });

    expect(result).toEqual({ packs: 1, stickers: 1 });
    expect(await repository.getStickerPack(packId)).toEqual(
      expect.objectContaining({
        id: packId,
        key: bytesToBase64(packKey),
        installed: true,
        title: "test pack",
        author: "tester",
        stickers: {
          "5": {
            id: 5,
            fileName: "5",
            emoji: "x",
            contentType: "image/webp",
            size: 3,
          },
        },
      }),
    );
    await expect(readFile(repository.getStickerFilePath(packId, "5"))).resolves.toEqual(
      Buffer.from([9, 8, 7]),
    );
  });
});
