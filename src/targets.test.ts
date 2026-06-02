import { Aci } from "@signalapp/libsignal-client";
import { describe, expect, it } from "vitest";
import { parseSignalRecipientTarget, resolveSignalRecipientTarget } from "./targets.js";

const aci = "11111111-1111-4111-8111-111111111111";

describe("Signal recipient targets", () => {
  it("parses explicit and bare ACI targets", () => {
    expect(parseSignalRecipientTarget(aci)).toEqual({ kind: "aci", aci });
    expect(parseSignalRecipientTarget(`signal:uuid:${aci}`)).toEqual({ kind: "aci", aci });
    expect(parseSignalRecipientTarget(`aci:${aci}`)).toEqual({ kind: "aci", aci });
  });

  it("parses phone numbers and username targets", () => {
    expect(parseSignalRecipientTarget("+15551234567")).toEqual({
      kind: "e164",
      e164: "+15551234567",
    });
    expect(parseSignalRecipientTarget("username:alice.42")).toEqual({
      kind: "username",
      username: "alice.42",
    });
    expect(parseSignalRecipientTarget("u:alice.42")).toEqual({
      kind: "username",
      username: "alice.42",
    });
    expect(parseSignalRecipientTarget("alice.42")).toEqual({
      kind: "username",
      username: "alice.42",
    });
  });

  it("resolves targets through injected lookup functions", async () => {
    const expected = Aci.fromUuid(aci);
    await expect(
      resolveSignalRecipientTarget({
        target: { kind: "e164", e164: "+15551234567" },
        resolver: { lookupE164: async () => expected },
      }),
    ).resolves.toBe(expected);
    await expect(
      resolveSignalRecipientTarget({
        target: { kind: "username", username: "alice.42" },
        resolver: { lookupUsername: async () => expected },
      }),
    ).resolves.toBe(expected);
  });

  it("rejects unresolved phone and username targets", async () => {
    await expect(
      resolveSignalRecipientTarget({
        target: { kind: "e164", e164: "+15551234567" },
        resolver: { lookupE164: async () => null },
      }),
    ).rejects.toThrow("Signal phone number not found");
    await expect(
      resolveSignalRecipientTarget({
        target: { kind: "username", username: "missing.99" },
        resolver: { lookupUsername: async () => null },
      }),
    ).rejects.toThrow("Signal username not found");
  });
});
