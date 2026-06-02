import { describe, expect, it } from "vitest";
import { liveE2eEnabled, loadLiveE2eConfig, redactedLiveConfig } from "./live-env.js";

const suite = liveE2eEnabled() ? describe : describe.skip;

suite("live e2e credentials", () => {
  it("loads and validates the account fixture", () => {
    const config = loadLiveE2eConfig();
    expect(config.accounts.sender.account.auth.username).not.toHaveLength(0);
    expect(config.accounts.sender.account.auth.password).not.toHaveLength(0);
    expect(config.accounts.sender.account.device.deviceId).toBeGreaterThan(0);
    expect(config.accounts.receiver.account.auth.username).not.toHaveLength(0);
    expect(config.accounts.receiver.account.auth.password).not.toHaveLength(0);
    expect(config.accounts.receiver.account.device.deviceId).toBeGreaterThan(0);
    expect(redactedLiveConfig(config)).toMatchObject({
      environment: expect.any(String),
      accounts: expect.any(Object),
      timeoutMs: expect.any(Number),
    });
  });
});
