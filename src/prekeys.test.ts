import { PrivateKey } from "@signalapp/libsignal-client";
import { describe, expect, it } from "vitest";
import { preKeyAuthFromBase64 } from "./prekeys.js";

describe("preKeyAuthFromBase64", () => {
  it("defaults to unrestricted auth", () => {
    expect(preKeyAuthFromBase64()).toEqual({ kind: "unrestricted" });
  });

  it("decodes access-key auth", () => {
    const accessKey = PrivateKey.generate().serialize().slice(0, 16);
    expect(preKeyAuthFromBase64(Buffer.from(accessKey).toString("base64"))).toEqual({
      kind: "access-key",
      accessKey,
    });
  });
});
