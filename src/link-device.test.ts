import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Aci, IdentityKeyPair, Pni } from "@signalapp/libsignal-client";
import type { ChatRequest } from "@signalapp/libsignal-client/dist/net/Chat.js";
import { describe, expect, it, vi } from "vitest";
import { copyBytes, type Bytes } from "./bytes.js";
import { FileSignalRepository } from "./file-store.js";
import { linkSignalDevice, type SignalLinkDeviceConnection } from "./link-device.js";
import type { SignalProvisionDecryptResult } from "./provisioning.js";

describe("linkSignalDevice", () => {
  it("sends the link-device request and persists linked account state", async () => {
    const aci = Aci.fromUuid("11111111-1111-4111-8111-111111111111");
    const pni = Pni.fromUuid("22222222-2222-4222-8222-222222222222");
    const provisioning: SignalProvisionDecryptResult = {
      aciIdentityKeyPair: IdentityKeyPair.generate(),
      pniIdentityKeyPair: IdentityKeyPair.generate(),
      number: "+15555550123",
      aci: aci.getServiceIdString(),
      pni: pni.getServiceIdString(),
      provisioningCode: "code",
      readReceipts: true,
      profileKey: bytes(32, 1),
      masterKey: bytes(32, 2),
    };
    const requests: ChatRequest[] = [];
    const connection: SignalLinkDeviceConnection = {
      fetch: vi.fn(async (request: ChatRequest) => {
        requests.push(request);
        return {
          status: 200,
          message: "OK",
          headers: [["Content-Type", "application/json"] as [string, string]],
          body: copyBytes(Buffer.from(JSON.stringify({
            uuid: aci.getServiceIdString(),
            pni: pni.getRawUuid(),
            deviceId: 2,
          }))),
        };
      }),
      disconnect: vi.fn(async () => {}),
    };
    const dir = await mkdtemp(join(tmpdir(), "signal-ts-link-"));
    const repository = await FileSignalRepository.open(join(dir, "state.json"));

    const result = await linkSignalDevice({
      provisioning,
      deviceName: "OpenClaw",
      repository,
      password: "fixed-password",
      registrationId: 123,
      pniRegistrationId: 456,
      keyIdSeed: 10,
      connectionFactory: async () => connection,
    });

    expect(result.account).toMatchObject({
      auth: {
        username: "11111111-1111-4111-8111-111111111111.2",
        password: "fixed-password",
      },
      device: {
        aci: "11111111-1111-4111-8111-111111111111",
        e164: "+15555550123",
        deviceId: 2,
        registrationId: 123,
      },
    });
    expect(requests).toHaveLength(1);
    const request = requests[0] ?? failRequest();
    expect(request.verb).toBe("PUT");
    expect(request.path).toBe("/v1/devices/link");
    expect(Object.fromEntries(request.headers).Authorization).toBe(
      `Basic ${Buffer.from("+15555550123:fixed-password").toString("base64")}`,
    );
    const body = JSON.parse(new TextDecoder().decode(request.body ?? new Uint8Array())) as Record<string, unknown>;
    expect(body).toMatchObject({
      verificationCode: "code",
      accountAttributes: {
        fetchesMessages: true,
        registrationId: 123,
        pniRegistrationId: 456,
      },
    });
    expect(body["aciSignedPreKey"]).toMatchObject({ keyId: 10 });
    expect(body["pniSignedPreKey"]).toMatchObject({ keyId: 11 });
    expect(await repository.getSignedPreKey(10)).toBeTruthy();
    expect(await repository.getKyberPreKey(12)).toBeTruthy();
    expect((await repository.getAccount())?.account.auth.username).toBe(
      "11111111-1111-4111-8111-111111111111.2",
    );
  });
});

function bytes(length: number, start: number): Bytes {
  return Uint8Array.from(Array.from({ length }, (_, index) => index + start)) as Bytes;
}

function failRequest(): never {
  throw new Error("missing request");
}
