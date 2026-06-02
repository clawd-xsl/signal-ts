import { describe, expect, it } from "vitest";
import { SignalTsClient } from "../client.js";
import { liveE2eEnabled, loadLiveE2eConfig } from "./live-env.js";

const suite = liveE2eEnabled() ? describe : describe.skip;

suite("live e2e connect", () => {
  it("opens and closes authenticated Signal chat connections", async () => {
    const config = loadLiveE2eConfig();
    const clients = [
      new SignalTsClient({
        account: config.accounts.sender.account,
        environment: config.environment,
        logger: liveLogger(),
      }),
      new SignalTsClient({
        account: config.accounts.receiver.account,
        environment: config.environment,
        logger: liveLogger(),
      }),
    ];
    try {
      await Promise.all(clients.map((client) => client.connect(AbortSignal.timeout(config.timeoutMs))));
    } finally {
      await Promise.all(clients.map((client) => client.disconnect()));
    }
    expect(true).toBe(true);
  });
});

function liveLogger() {
  return {
    info: (message: string) => console.info(`[signal-ts:e2e] ${message}`),
    warn: (message: string) => console.warn(`[signal-ts:e2e] ${message}`),
  };
}
