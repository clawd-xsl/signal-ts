import { describe, expect, it } from "vitest";
import { type SignalEnvironment } from "../account.js";
import { bytesToBase64 } from "../bytes.js";
import { FileSignalRepository } from "../file-store.js";
import { linkSignalDevice } from "../link-device.js";
import { startSignalDeviceLinkSession, type SignalProvisionDecryptResult } from "../provisioning.js";
import type { SerializedSignalRepository } from "../store.js";
import { liveE2eEnabled } from "./live-env.js";

const suite = liveE2eEnabled() && process.env["SIGNAL_TS_E2E_LINK_DEVICE"] === "1"
  ? describe
  : describe.skip;

suite("live e2e link device", () => {
  it("links a fresh device through QR provisioning and writes durable state", async () => {
    const environment = parseEnvironment(process.env["SIGNAL_TS_E2E_LINK_ENVIRONMENT"]);
    const outputFile = requireString(
      process.env["SIGNAL_TS_E2E_LINK_OUTPUT_FILE"],
      "SIGNAL_TS_E2E_LINK_OUTPUT_FILE",
    );
    const deviceName = process.env["SIGNAL_TS_E2E_LINK_DEVICE_NAME"]?.trim()
      || "OpenClaw signal-ts e2e";
    const timeoutMs = parseTimeout(process.env["SIGNAL_TS_E2E_LINK_TIMEOUT_MS"]);
    const abortSignal = AbortSignal.timeout(timeoutMs);
    const session = await startSignalDeviceLinkSession({
      environment,
      timeoutMs,
      abortSignal,
    });

    console.info(`[signal-ts:e2e] scan link URL: ${session.url}`);
    try {
      const provisioning = await session.waitForProvisioning();
      const repository = await FileSignalRepository.open(outputFile, {
        initialRepository: initialRepositoryFromProvisioning(provisioning),
      });
      const linked = await linkSignalDevice({
        provisioning,
        deviceName,
        environment,
        repository,
        abortSignal,
      });

      expect(linked.account.auth.username).not.toHaveLength(0);
      expect((await repository.getAccount())?.account.auth.username).toBe(
        linked.account.auth.username,
      );
      console.info(`[signal-ts:e2e] wrote linked device state: ${outputFile}`);
    } finally {
      await session.disconnect();
    }
  });
});

function initialRepositoryFromProvisioning(
  provisioning: SignalProvisionDecryptResult,
): SerializedSignalRepository {
  return {
    identityKeyPrivate: bytesToBase64(provisioning.aciIdentityKeyPair.privateKey.serialize()),
    registrationId: 1,
    identities: {},
    sessions: {},
    preKeys: {},
    signedPreKeys: {},
    kyberPreKeys: {},
    senderKeys: {},
  };
}

function parseEnvironment(value: string | undefined): SignalEnvironment {
  if (value === undefined || value === "" || value === "production") {
    return "production";
  }
  if (value === "staging") {
    return "staging";
  }
  throw new Error("SIGNAL_TS_E2E_LINK_ENVIRONMENT must be production or staging");
}

function parseTimeout(value: string | undefined): number {
  if (value === undefined || value === "") {
    return 300_000;
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1_000) {
    throw new Error("SIGNAL_TS_E2E_LINK_TIMEOUT_MS must be an integer >= 1000");
  }
  return parsed;
}

function requireString(value: string | undefined, name: string): string {
  if (!value?.trim()) {
    throw new Error(`${name} must be set`);
  }
  return value.trim();
}
