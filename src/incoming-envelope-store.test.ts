import { mkdtemp, rm, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  SqliteSignalIncomingEnvelopeStore,
  createSignalIncomingEnvelopeId,
} from "./incoming-envelope-store.js";
import { encodeSignalEnvelope, SignalEnvelopeType } from "./messages.js";

describe("SqliteSignalIncomingEnvelopeStore", () => {
  const tempDirs: string[] = [];
  const stores: SqliteSignalIncomingEnvelopeStore[] = [];

  afterEach(async () => {
    for (const store of stores.splice(0)) {
      store.close();
    }
    await Promise.all(tempDirs.splice(0).map((directory) => rm(directory, { recursive: true })));
  });

  async function createStore(): Promise<SqliteSignalIncomingEnvelopeStore> {
    const directory = await mkdtemp(path.join(os.tmpdir(), "signal-ts-incoming-"));
    tempDirs.push(directory);
    const store = new SqliteSignalIncomingEnvelopeStore(path.join(directory, "incoming.sqlite"));
    stores.push(store);
    return store;
  }

  it("creates a missing multi-level inbox path", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "signal-ts-incoming-parent-"));
    tempDirs.push(root);
    const store = new SqliteSignalIncomingEnvelopeStore(
      path.join(root, "one", "two", "inbox.sqlite"),
    );
    stores.push(store);

    await store.accept({ envelope: new Uint8Array([9]), serverDeliveredTimestamp: 10 });

    await expect(store.listPending(10)).resolves.toHaveLength(1);
    if (process.platform !== "win32") {
      expect((await stat(path.join(root, "one", "two"))).mode & 0o777).toBe(0o700);
      expect((await stat(path.join(root, "one", "two", "inbox.sqlite"))).mode & 0o777).toBe(0o600);
    }
  });

  it("persists encrypted envelopes and returns the original record for duplicates", async () => {
    const store = await createStore();
    const envelope = new Uint8Array([1, 2, 3, 4]);

    const accepted = await store.accept({
      envelope,
      serverDeliveredTimestamp: 200,
      receivedAt: 100,
    });
    const duplicate = await store.accept({
      envelope,
      serverDeliveredTimestamp: 400,
      receivedAt: 300,
    });

    expect(accepted).toMatchObject({
      duplicate: false,
      record: {
        id: createSignalIncomingEnvelopeId(envelope),
        serverDeliveredTimestamp: 200,
        receivedAt: 100,
        sequence: 1,
      },
    });
    expect(duplicate).toMatchObject({
      duplicate: true,
      record: {
        serverDeliveredTimestamp: 200,
        receivedAt: 100,
      },
    });
    expect([...duplicate.record.envelope]).toEqual([...envelope]);
  });

  it("preserves acceptance order when receipt timestamps are equal", async () => {
    const store = await createStore();
    const firstEnvelope = new Uint8Array([5]);
    const secondEnvelope = new Uint8Array([7]);
    expect(
      createSignalIncomingEnvelopeId(firstEnvelope).localeCompare(
        createSignalIncomingEnvelopeId(secondEnvelope),
      ),
    ).toBeGreaterThan(0);

    await store.accept({ envelope: firstEnvelope, serverDeliveredTimestamp: 20, receivedAt: 10 });
    await store.accept({ envelope: secondEnvelope, serverDeliveredTimestamp: 30, receivedAt: 10 });

    expect((await store.listPending(10)).map((record) => [...record.envelope])).toEqual([[5], [7]]);
    expect((await store.listPending(1)).map((record) => [...record.envelope])).toEqual([[5]]);
  });

  it("deduplicates server redelivery when only server metadata changes", async () => {
    const content = new Uint8Array([4, 3, 2, 1]);
    const firstEnvelope = encodeSignalEnvelope({
      type: SignalEnvelopeType.UnidentifiedSender,
      destinationServiceId: "22222222-2222-4222-8222-222222222222",
      clientTimestamp: 100,
      serverTimestamp: 200,
      content,
      urgent: true,
    });
    const redeliveredEnvelope = encodeSignalEnvelope({
      type: SignalEnvelopeType.UnidentifiedSender,
      destinationServiceId: "22222222-2222-4222-8222-222222222222",
      clientTimestamp: 100,
      serverTimestamp: 300,
      content,
      urgent: true,
    });

    expect(createSignalIncomingEnvelopeId(redeliveredEnvelope)).toBe(
      createSignalIncomingEnvelopeId(firstEnvelope),
    );

    const store = await createStore();
    const first = await store.accept({
      envelope: firstEnvelope,
      serverDeliveredTimestamp: 250,
    });
    const redelivered = await store.accept({
      envelope: redeliveredEnvelope,
      serverDeliveredTimestamp: 350,
    });

    expect(first.duplicate).toBe(false);
    expect(redelivered.duplicate).toBe(true);
    expect(redelivered.record.serverDeliveredTimestamp).toBe(250);
  });

  it("keeps incomplete envelopes replayable and prunes completed tombstones", async () => {
    const store = await createStore();
    const first = await store.accept({
      envelope: new Uint8Array([1]),
      serverDeliveredTimestamp: 20,
      receivedAt: 10,
    });
    await store.accept({
      envelope: new Uint8Array([2]),
      serverDeliveredTimestamp: 40,
      receivedAt: 30,
    });

    await store.complete(first.record.id, 60);

    expect((await store.listPending(10)).map((record) => [...record.envelope])).toEqual([[2]]);
    await expect(store.pruneCompleted(61)).resolves.toBe(1);
    await expect(store.pruneCompleted(61)).resolves.toBe(0);
  });
});
