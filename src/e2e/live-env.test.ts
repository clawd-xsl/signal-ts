import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PrivateKey } from "@signalapp/libsignal-client";
import { describe, expect, it } from "vitest";
import type { SignalAccountState } from "../account.js";
import { bytesToBase64 } from "../bytes.js";
import { FileSignalRepository } from "../file-store.js";
import type { SerializedSignalRepository } from "../store.js";
import { loadLiveE2eConfig, loadLiveRepository, redactedLiveConfig } from "./live-env.js";

describe("live e2e environment", () => {
  it("loads account state and repository data from file-backed state fixtures", async () => {
    const dir = await mkdtemp(join(tmpdir(), "signal-ts-live-env-"));
    const senderState = await writeState(dir, "sender-state.json", {
      auth: { username: "11111111-1111-4111-8111-111111111111.2", password: "sender-password" },
      device: {
        aci: "11111111-1111-4111-8111-111111111111",
        e164: "+15555550123",
        deviceId: 2,
        registrationId: 12345,
      },
      receiveStories: false,
    });
    await writeState(dir, "receiver-state.json", {
      auth: { username: "22222222-2222-4222-8222-222222222222.2", password: "receiver-password" },
      device: {
        aci: "22222222-2222-4222-8222-222222222222",
        e164: "+15555550124",
        deviceId: 2,
        registrationId: 23456,
      },
    });
    const accountFile = join(dir, "accounts.json");
    await writeFile(
      accountFile,
      JSON.stringify({
        environment: "production",
        accounts: {
          sender: { stateFile: "sender-state.json", accessKeyBase64: null },
          receiver: { stateFile: "receiver-state.json", accessKeyBase64: null },
        },
      }),
    );

    const previous = snapshotSignalTsEnv();
    try {
      process.env["SIGNAL_TS_E2E"] = "1";
      process.env["SIGNAL_TS_E2E_ACCOUNT_FILE"] = accountFile;
      delete process.env["SIGNAL_TS_E2E_ACCOUNT_JSON"];
      delete process.env["SIGNAL_TS_E2E_TIMEOUT_MS"];

      const config = loadLiveE2eConfig();
      expect(config.accounts.sender.account.auth.username).toBe(
        "11111111-1111-4111-8111-111111111111.2",
      );
      expect(config.accounts.sender.stateFile).toBe(senderState);
      expect(redactedLiveConfig(config).accounts).toMatchObject({
        sender: { stateFile: "<state-file>" },
      });

      const repository = await loadLiveRepository(config.accounts.sender, "accounts.sender");
      expect(await repository.getLocalRegistrationId()).toBe(12345);
    } finally {
      restoreSignalTsEnv(previous);
    }
  });
});

async function writeState(
  dir: string,
  fileName: string,
  account: SignalAccountState,
): Promise<string> {
  const filePath = join(dir, fileName);
  await FileSignalRepository.open(filePath, {
    initialRepository: emptyRepository(account.device.registrationId),
    account: { account },
  });
  return filePath;
}

function emptyRepository(registrationId: number): SerializedSignalRepository {
  return {
    identityKeyPrivate: bytesToBase64(PrivateKey.generate().serialize()),
    registrationId,
    identities: {},
    sessions: {},
    preKeys: {},
    signedPreKeys: {},
    kyberPreKeys: {},
    senderKeys: {},
  };
}

function snapshotSignalTsEnv(): Record<string, string | undefined> {
  return {
    SIGNAL_TS_E2E: process.env["SIGNAL_TS_E2E"],
    SIGNAL_TS_E2E_ACCOUNT_FILE: process.env["SIGNAL_TS_E2E_ACCOUNT_FILE"],
    SIGNAL_TS_E2E_ACCOUNT_JSON: process.env["SIGNAL_TS_E2E_ACCOUNT_JSON"],
    SIGNAL_TS_E2E_TIMEOUT_MS: process.env["SIGNAL_TS_E2E_TIMEOUT_MS"],
  };
}

function restoreSignalTsEnv(values: Record<string, string | undefined>): void {
  for (const [key, value] of Object.entries(values)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
}
