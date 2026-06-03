import { copyFile, mkdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { bytesToBase64, copyBytes, type Bytes } from "./bytes.js";
import type {
  FileSignalRepository,
  FileSignalStickerPackState,
  FileSignalStickerState,
} from "./file-store.js";
import { SignalTsStateError } from "./errors.js";

export type ImportSignalCliStickerStoreParams = {
  repository: FileSignalRepository;
  accountDbPath: string;
  stickersDir: string;
  installedOnly?: boolean;
};

export type ImportSignalCliStickerStoreResult = {
  packs: number;
  stickers: number;
};

type SignalCliStickerRow = {
  packIdHex: unknown;
  packKey: unknown;
  installed: unknown;
};

type NormalizedManifestSticker = {
  id: number;
  fileName: string;
  emoji?: string;
  contentType?: string;
};

export async function importSignalCliStickerStore({
  repository,
  accountDbPath,
  stickersDir,
  installedOnly = true,
}: ImportSignalCliStickerStoreParams): Promise<ImportSignalCliStickerStoreResult> {
  const database = new DatabaseSync(accountDbPath, { readOnly: true });
  try {
    const rows = database.prepare(
      installedOnly
        ? "select lower(hex(pack_id)) as packIdHex, pack_key as packKey, installed from sticker where installed != 0 order by packIdHex"
        : "select lower(hex(pack_id)) as packIdHex, pack_key as packKey, installed from sticker order by packIdHex",
    ).all() as SignalCliStickerRow[];
    let packCount = 0;
    let stickerCount = 0;
    for (const row of rows) {
      const packId = normalizePackId(row.packIdHex);
      const packKey = readSqliteBlob(row.packKey, `sticker pack ${packId} key`);
      const imported = await importSignalCliStickerPack({
        repository,
        stickersDir,
        packId,
        packKey,
        installed: normalizeInstalled(row.installed),
      });
      packCount += 1;
      stickerCount += imported.stickers;
    }
    return { packs: packCount, stickers: stickerCount };
  } finally {
    database.close();
  }
}

async function importSignalCliStickerPack({
  repository,
  stickersDir,
  packId,
  packKey,
  installed,
}: {
  repository: FileSignalRepository;
  stickersDir: string;
  packId: string;
  packKey: Bytes;
  installed: boolean;
}): Promise<{ stickers: number }> {
  const sourceDir = join(stickersDir, packId);
  const manifest = await readSignalCliManifest(join(sourceDir, "manifest.json"));
  const destinationDir = join(repository.stickerStorePath(), packId);
  await mkdir(destinationDir, { recursive: true });

  const stickers: Record<string, FileSignalStickerState> = {};
  for (const manifestSticker of manifest.stickers) {
    const sourceFileName = normalizeStickerFileName(manifestSticker.fileName);
    const sourcePath = join(sourceDir, sourceFileName);
    const stickerStat = await stat(sourcePath);
    await copyFile(sourcePath, repository.getStickerFilePath(packId, sourceFileName));
    const sticker: FileSignalStickerState = {
      id: manifestSticker.id,
      fileName: sourceFileName,
      size: stickerStat.size,
    };
    if (manifestSticker.emoji !== undefined) {
      sticker.emoji = manifestSticker.emoji;
    }
    if (manifestSticker.contentType !== undefined) {
      sticker.contentType = manifestSticker.contentType;
    }
    stickers[String(sticker.id)] = sticker;
  }

  const pack: FileSignalStickerPackState = {
    id: packId,
    key: bytesToBase64(packKey),
    installed,
    stickers,
  };
  if (manifest.title !== undefined) {
    pack.title = manifest.title;
  }
  if (manifest.author !== undefined) {
    pack.author = manifest.author;
  }
  await repository.setStickerPack(pack);
  return { stickers: Object.keys(stickers).length };
}

async function readSignalCliManifest(path: string): Promise<{
  title?: string;
  author?: string;
  stickers: NormalizedManifestSticker[];
}> {
  const raw = JSON.parse(await readFile(path, "utf-8")) as unknown;
  const manifest = asRecord(raw, "Signal sticker manifest");
  const rawStickers = manifest["stickers"];
  if (!Array.isArray(rawStickers)) {
    throw new SignalTsStateError("Signal sticker manifest is missing stickers");
  }
  const title = optionalString(manifest["title"]);
  const author = optionalString(manifest["author"]);
  return {
    ...(title !== undefined ? { title } : {}),
    ...(author !== undefined ? { author } : {}),
    stickers: rawStickers.map((entry, index) => normalizeManifestSticker(entry, index)),
  };
}

function normalizeManifestSticker(value: unknown, index: number): NormalizedManifestSticker {
  const sticker = asRecord(value, `Signal sticker manifest entry ${index}`);
  const id = normalizeStickerId(sticker["id"], index);
  const fileName = optionalString(sticker["file"]) ?? String(id);
  const emoji = optionalString(sticker["emoji"]);
  const contentType = optionalString(sticker["contentType"]);
  return {
    id,
    fileName,
    ...(emoji !== undefined ? { emoji } : {}),
    ...(contentType !== undefined ? { contentType } : {}),
  };
}

function normalizeStickerId(value: unknown, fallback: number): number {
  const numeric = typeof value === "number" ? value : fallback;
  if (!Number.isInteger(numeric) || numeric < 0) {
    throw new SignalTsStateError("Signal sticker id must be a non-negative integer");
  }
  return numeric;
}

function normalizePackId(value: unknown): string {
  if (typeof value !== "string") {
    throw new SignalTsStateError("Signal sticker pack id must be hex");
  }
  const normalized = value.trim().toLowerCase();
  if (!/^(?:[0-9a-f]{2})+$/.test(normalized)) {
    throw new SignalTsStateError("Signal sticker pack id must be even-length hex");
  }
  return normalized;
}

function normalizeStickerFileName(value: string): string {
  const normalized = value.trim();
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

function readSqliteBlob(value: unknown, label: string): Bytes {
  if (value instanceof Uint8Array) {
    return copyBytes(value);
  }
  if (value instanceof ArrayBuffer) {
    return copyBytes(new Uint8Array(value));
  }
  throw new SignalTsStateError(`Signal ${label} must be a sqlite blob`);
}

function normalizeInstalled(value: unknown): boolean {
  return typeof value === "number" ? value !== 0 : Boolean(value);
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new SignalTsStateError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}
