import { createHash } from "node:crypto";
import { chmod, mkdir, open } from "node:fs/promises";
import { dirname } from "node:path";
import { DatabaseSync, type SQLOutputValue } from "node:sqlite";
import { copyBytes, type Bytes } from "./bytes.js";
import { SignalTsStateError } from "./errors.js";
import { decodeSignalEnvelope } from "./messages.js";

export type SignalIncomingEnvelopeRecord = {
  id: string;
  envelope: Bytes;
  serverDeliveredTimestamp: number;
  receivedAt: number;
  sequence: number;
  completedAt?: number;
};

export type SignalIncomingEnvelopeAcceptResult = {
  duplicate: boolean;
  record: SignalIncomingEnvelopeRecord;
};

export interface SignalIncomingEnvelopeStore {
  accept(params: {
    envelope: Bytes;
    serverDeliveredTimestamp: number;
    receivedAt?: number;
  }): Promise<SignalIncomingEnvelopeAcceptResult>;
  complete(id: string, completedAt?: number): Promise<void>;
  listPending(limit: number): Promise<SignalIncomingEnvelopeRecord[]>;
  pruneCompleted(olderThan: number): Promise<number>;
}

type IncomingEnvelopeRow = Record<string, SQLOutputValue> & {
  id: string;
  envelope: Uint8Array;
  server_delivered_timestamp: number;
  received_at: number;
  sequence: number;
  completed_at: number | null;
};

export function createSignalIncomingEnvelopeId(envelope: Bytes): string {
  const hash = createHash("sha256");
  try {
    const decoded = decodeSignalEnvelope(envelope);
    hash.update("signal-envelope-v1");
    updateHashField(hash, "type", decoded.type?.toString());
    updateHashField(hash, "sourceServiceId", decoded.sourceServiceId);
    updateHashField(hash, "sourceDeviceId", decoded.sourceDeviceId?.toString());
    updateHashField(hash, "destinationServiceId", decoded.destinationServiceId);
    updateHashField(hash, "clientTimestamp", decoded.clientTimestamp?.toString());
    updateHashField(hash, "sourceServiceIdBinary", decoded.sourceServiceIdBinary);
    updateHashField(hash, "destinationServiceIdBinary", decoded.destinationServiceIdBinary);
    updateHashField(hash, "content", decoded.content);
  } catch {
    // Malformed envelopes still need a stable cache key so the consumer can
    // complete them without allowing repeated server delivery.
    hash.update("signal-envelope-raw-v1");
    updateHashField(hash, "envelope", envelope);
  }
  return hash.digest("hex");
}

function updateHashField(
  hash: ReturnType<typeof createHash>,
  name: string,
  value: string | Bytes | undefined,
): void {
  const bytes =
    value === undefined ? undefined : typeof value === "string" ? Buffer.from(value) : value;
  hash.update(`${name}:${bytes?.byteLength ?? -1}:`);
  if (bytes) {
    hash.update(bytes);
  }
  hash.update(";");
}

/** SQLite inbox matching signal-cli's persist-before-ACK contract. */
export class SqliteSignalIncomingEnvelopeStore implements SignalIncomingEnvelopeStore {
  private pendingMutation: Promise<void> = Promise.resolve();
  private database: DatabaseSync | undefined;
  private databaseReady: Promise<DatabaseSync> | undefined;

  constructor(private readonly databasePath: string) {}

  async accept(params: {
    envelope: Bytes;
    serverDeliveredTimestamp: number;
    receivedAt?: number;
  }): Promise<SignalIncomingEnvelopeAcceptResult> {
    return await this.runSerialized(async () => {
      const database = await this.getDatabase();
      const id = createSignalIncomingEnvelopeId(params.envelope);
      const existing = this.readRecord(database, id);
      if (existing) {
        return { duplicate: true, record: existing };
      }
      database
        .prepare(
          `INSERT INTO incoming_envelopes
             (id, envelope, server_delivered_timestamp, received_at)
           VALUES (?, ?, ?, ?)`,
        )
        .run(
          id,
          Buffer.from(params.envelope),
          params.serverDeliveredTimestamp,
          params.receivedAt ?? Date.now(),
        );
      const record = this.readRecord(database, id);
      if (!record) {
        throw new SignalTsStateError(`Signal incoming envelope insert disappeared: ${id}`);
      }
      return { duplicate: false, record };
    });
  }

  async complete(id: string, completedAt = Date.now()): Promise<void> {
    await this.runSerialized(async () => {
      const database = await this.getDatabase();
      const result = database
        .prepare(
          `UPDATE incoming_envelopes
             SET completed_at = COALESCE(completed_at, ?)
           WHERE id = ?`,
        )
        .run(completedAt, id);
      if (Number(result.changes) === 0 && !this.readRecord(database, id)) {
        throw new SignalTsStateError(`Signal incoming envelope is missing: ${id}`);
      }
    });
  }

  async listPending(limit: number): Promise<SignalIncomingEnvelopeRecord[]> {
    if (!Number.isSafeInteger(limit) || limit <= 0) {
      throw new SignalTsStateError(`Invalid Signal incoming envelope page limit: ${limit}`);
    }
    return await this.runSerialized(async () => {
      const database = await this.getDatabase();
      const rows = database
        .prepare(
          `SELECT id, envelope, server_delivered_timestamp, received_at, sequence, completed_at
             FROM incoming_envelopes
            WHERE completed_at IS NULL
            ORDER BY sequence
            LIMIT ?`,
        )
        .all(limit);
      return rows.map((row) => parseRow(row as IncomingEnvelopeRow));
    });
  }

  async pruneCompleted(olderThan: number): Promise<number> {
    return await this.runSerialized(async () => {
      const database = await this.getDatabase();
      const result = database
        .prepare("DELETE FROM incoming_envelopes WHERE completed_at < ?")
        .run(olderThan);
      return Number(result.changes);
    });
  }

  close(): void {
    if (this.database?.isOpen) {
      this.database.close();
    }
    this.database = undefined;
    this.databaseReady = undefined;
  }

  private readRecord(database: DatabaseSync, id: string): SignalIncomingEnvelopeRecord | undefined {
    const row = database
      .prepare(
        `SELECT id, envelope, server_delivered_timestamp, received_at, sequence, completed_at
           FROM incoming_envelopes
          WHERE id = ?`,
      )
      .get(id);
    return row ? parseRow(row as IncomingEnvelopeRow) : undefined;
  }

  private async getDatabase(): Promise<DatabaseSync> {
    this.databaseReady ??= this.openDatabase().catch((err) => {
      this.databaseReady = undefined;
      throw err;
    });
    return await this.databaseReady;
  }

  private async openDatabase(): Promise<DatabaseSync> {
    const parent = dirname(this.databasePath);
    await ensureDurableDirectory(parent);
    await chmod(parent, 0o700);
    const databaseFile = await open(this.databasePath, "a", 0o600);
    await databaseFile.close();
    await chmod(this.databasePath, 0o600);
    const database = new DatabaseSync(this.databasePath);
    try {
      database.exec(`
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = FULL;
        CREATE TABLE IF NOT EXISTS incoming_envelopes (
          sequence INTEGER PRIMARY KEY AUTOINCREMENT,
          id TEXT NOT NULL UNIQUE,
          envelope BLOB NOT NULL,
          server_delivered_timestamp INTEGER NOT NULL,
          received_at INTEGER NOT NULL,
          completed_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS incoming_envelopes_pending_sequence
          ON incoming_envelopes(completed_at, sequence);
      `);
      await syncDirectory(parent);
      this.database = database;
      return database;
    } catch (err) {
      database.close();
      throw err;
    }
  }

  private async runSerialized<T>(run: () => Promise<T>): Promise<T> {
    const previous = this.pendingMutation;
    let release!: () => void;
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.pendingMutation = previous.then(
      () => current,
      () => current,
    );
    await previous.catch(() => undefined);
    try {
      return await run();
    } finally {
      release();
    }
  }
}

function parseRow(row: IncomingEnvelopeRow): SignalIncomingEnvelopeRecord {
  if (
    typeof row.id !== "string" ||
    !(row.envelope instanceof Uint8Array) ||
    !isTimestamp(row.server_delivered_timestamp) ||
    !isTimestamp(row.received_at) ||
    !isSequence(row.sequence) ||
    (row.completed_at !== null && !isTimestamp(row.completed_at))
  ) {
    throw new SignalTsStateError("Invalid Signal incoming envelope database row");
  }
  const envelope = copyBytes(row.envelope);
  if (createSignalIncomingEnvelopeId(envelope) !== row.id) {
    throw new SignalTsStateError(`Signal incoming envelope hash mismatch: ${row.id}`);
  }
  return {
    id: row.id,
    envelope,
    serverDeliveredTimestamp: row.server_delivered_timestamp,
    receivedAt: row.received_at,
    sequence: row.sequence,
    ...(row.completed_at === null ? {} : { completedAt: row.completed_at }),
  };
}

function isTimestamp(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isSequence(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isNodeErrorCode(err: unknown, code: string): boolean {
  return Boolean(err && typeof err === "object" && "code" in err && err.code === code);
}

async function syncDirectory(path: string): Promise<void> {
  if (process.platform === "win32") {
    // Windows does not expose directory handles that Node can fsync. SQLite's
    // FULL sync remains active; directory-entry sync is a POSIX-only hardening.
    return;
  }
  const directory = await open(path, "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

async function ensureDurableDirectory(path: string): Promise<void> {
  const parent = dirname(path);
  if (parent === path) {
    return;
  }
  await ensureDurableDirectory(parent);
  try {
    await mkdir(path, { mode: 0o700 });
  } catch (err) {
    if (!isNodeErrorCode(err, "EEXIST")) {
      throw err;
    }
  }
  await syncDirectory(parent);
}
