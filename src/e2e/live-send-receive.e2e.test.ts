import { randomUUID } from "node:crypto";
import { Aci, ProtocolAddress } from "@signalapp/libsignal-client";
import { describe, expect, it } from "vitest";
import { SignalTsClient } from "../client.js";
import { decryptIncomingEnvelope } from "../crypto.js";
import { preKeyAuthFromBase64 } from "../prekeys.js";
import { createLibsignalStores, type LibsignalStores } from "../store.js";
import {
  liveE2eEnabled,
  loadLiveE2eConfig,
  loadLiveRepository,
  type LiveE2eAccount,
} from "./live-env.js";

const suite = liveE2eEnabled() ? describe : describe.skip;

suite("live e2e send/receive", () => {
  it("sends and receives a DM text payload through native signal-ts", async () => {
    const config = loadLiveE2eConfig();
    const senderRepository = await loadLiveRepository(config.accounts.sender, "accounts.sender");
    const receiverRepository = await loadLiveRepository(
      config.accounts.receiver,
      "accounts.receiver",
    );
    const senderStores = createLibsignalStores(senderRepository);
    const receiverStores = createLibsignalStores(receiverRepository);
    const sender = new SignalTsClient({
      account: config.accounts.sender.account,
      environment: config.environment,
      logger: liveLogger(),
    });
    const receiver = new SignalTsClient({
      account: config.accounts.receiver.account,
      environment: config.environment,
      logger: liveLogger(),
    });
    const body = `signal-ts e2e ${randomUUID()}`;
    const receiverAddress = localAddress(config.accounts.receiver);
    let armed = false;
    const received = waitForTextBody({
      client: receiver,
      expectedBody: body,
      localAddress: receiverAddress,
      stores: receiverStores,
      timeoutMs: config.timeoutMs,
      shouldRecordErrors: () => armed,
    });

    try {
      await receiver.connect(AbortSignal.timeout(config.timeoutMs));
      await waitForQueueEmpty(receiver, config.timeoutMs);
      await sender.connect(AbortSignal.timeout(config.timeoutMs));
      armed = true;
      await sender.sendTextMessage({
        destination: config.accounts.receiver.account.device.aci,
        body,
        stores: senderStores,
        preKeyAuth: preKeyAuthFromBase64(config.accounts.receiver.accessKeyBase64),
        abortSignal: AbortSignal.timeout(config.timeoutMs),
      });
      await received;
    } finally {
      await Promise.all([sender.disconnect(), receiver.disconnect()]);
    }
    expect(true).toBe(true);
  });
});

function localAddress(account: LiveE2eAccount): ProtocolAddress {
  return ProtocolAddress.new(
    Aci.fromUuid(account.account.device.aci),
    account.account.device.deviceId,
  );
}

function waitForQueueEmpty(client: SignalTsClient, timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      dispose();
      reject(new Error("Timed out waiting for Signal queue empty"));
    }, timeoutMs);
    const dispose = client.on("queueEmpty", () => {
      clearTimeout(timer);
      dispose();
      resolve();
    });
  });
}

function waitForTextBody({
  client,
  expectedBody,
  localAddress,
  stores,
  timeoutMs,
  shouldRecordErrors,
}: {
  client: SignalTsClient;
  expectedBody: string;
  localAddress: ProtocolAddress;
  stores: Pick<
    LibsignalStores,
    | "identityStore"
    | "sessionStore"
    | "preKeyStore"
    | "signedPreKeyStore"
    | "kyberPreKeyStore"
  >;
  timeoutMs: number;
  shouldRecordErrors: () => boolean;
}): Promise<void> {
  return new Promise((resolve, reject) => {
    let lastError: unknown;
    const timer = setTimeout(() => {
      dispose();
      const suffix = lastError instanceof Error ? ` Last decrypt error: ${lastError.message}` : "";
      reject(new Error(`Timed out waiting for Signal text body.${suffix}`));
    }, timeoutMs);
    const dispose = client.on("incoming", (incoming) => {
      void (async () => {
        try {
          const decrypted = await decryptIncomingEnvelope({
            envelope: incoming.envelope,
            localAddress,
            stores,
          });
          if (decrypted.content.dataMessage?.body === expectedBody) {
            clearTimeout(timer);
            dispose();
            incoming.ack();
            resolve();
            return;
          }
        } catch (error) {
          if (shouldRecordErrors()) {
            lastError = error;
          }
        }
        incoming.ack();
      })();
    });
  });
}

function liveLogger() {
  return {
    info: (message: string) => console.info(`[signal-ts:e2e] ${message}`),
    warn: (message: string) => console.warn(`[signal-ts:e2e] ${message}`),
  };
}
