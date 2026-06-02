import { describe, expect, it } from "vitest";
import { fetchRecipientPreKeys, preKeyAuthFromBase64 } from "../prekeys.js";
import { liveE2eEnabled, loadLiveE2eConfig } from "./live-env.js";

const suite = liveE2eEnabled() ? describe : describe.skip;

suite("live e2e prekeys", () => {
  it("fetches recipient prekeys for the receiver account", async () => {
    const config = loadLiveE2eConfig();
    const result = await fetchRecipientPreKeys({
      target: config.accounts.receiver.account.device.aci,
      auth: preKeyAuthFromBase64(config.accounts.receiver.accessKeyBase64),
      abortSignal: AbortSignal.timeout(config.timeoutMs),
    });
    expect(result.preKeyBundles.length).toBeGreaterThan(0);
    expect(result.identityKey.serialize().byteLength).toBeGreaterThan(0);
  });
});
