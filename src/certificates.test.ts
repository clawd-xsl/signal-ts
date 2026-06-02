import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IdentityKeyPair, SenderCertificate, ServerCertificate } from "@signalapp/libsignal-client";
import type { ChatRequest } from "@signalapp/libsignal-client/dist/net/Chat.js";
import { describe, expect, it, vi } from "vitest";
import { copyBytes } from "./bytes.js";
import { fetchSenderCertificate, type SenderCertificateConnection } from "./certificates.js";
import { FileSignalRepository } from "./file-store.js";

describe("fetchSenderCertificate", () => {
  it("fetches, validates, and persists sender certificates", async () => {
    const certificate = createSenderCertificate();
    const dir = await mkdtemp(join(tmpdir(), "signal-ts-cert-"));
    const repository = await FileSignalRepository.open(join(dir, "state.json"));
    await repository.setAccount({
      account: {
        auth: { username: "11111111-1111-4111-8111-111111111111.2", password: "secret" },
        device: {
          aci: "11111111-1111-4111-8111-111111111111",
          e164: "+15555550123",
          deviceId: 2,
          registrationId: 42,
        },
      },
    });
    const requests: ChatRequest[] = [];
    const connection: SenderCertificateConnection = {
      fetch: vi.fn(async (request: ChatRequest) => {
        requests.push(request);
        return {
          status: 200,
          message: "OK",
          headers: [["Content-Type", "application/json"] as [string, string]],
          body: copyBytes(Buffer.from(JSON.stringify({
            certificate: Buffer.from(certificate.serialize()).toString("base64"),
          }))),
        };
      }),
      disconnect: vi.fn(async () => {}),
    };

    const fetched = await fetchSenderCertificate({
      account: (await repository.getAccount())?.account ?? failAccount(),
      mode: "without-e164",
      repository,
      connectionFactory: async () => connection,
    });
    const cached = await fetchSenderCertificate({
      account: (await repository.getAccount())?.account ?? failAccount(),
      mode: "without-e164",
      repository,
      connectionFactory: async () => failConnection(),
    });

    expect(fetched.serialize()).toEqual(certificate.serialize());
    expect(cached.serialize()).toEqual(certificate.serialize());
    expect(requests).toHaveLength(1);
    expect(requests[0]?.path).toBe("/v1/certificate/delivery?includeE164=false");
    expect((await repository.getAccount())?.senderCertificates?.withoutE164?.expires).toBe(
      certificate.expiration(),
    );
  });
});

function createSenderCertificate(): SenderCertificate {
  const trustRoot = IdentityKeyPair.generate();
  const serverKey = IdentityKeyPair.generate();
  const senderKey = IdentityKeyPair.generate();
  const serverCertificate = ServerCertificate.new(1, serverKey.publicKey, trustRoot.privateKey);
  return SenderCertificate.new(
    "11111111-1111-4111-8111-111111111111",
    null,
    2,
    senderKey.publicKey,
    Date.now() + 7 * 24 * 60 * 60 * 1000,
    serverCertificate,
    serverKey.privateKey,
  );
}

function failAccount(): never {
  throw new Error("missing account");
}

function failConnection(): never {
  throw new Error("certificate cache was not used");
}
