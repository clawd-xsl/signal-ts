import { createCipheriv } from "node:crypto";
import { Aci, IdentityKeyPair, Pni, PrivateKey } from "@signalapp/libsignal-client";
import { describe, expect, it } from "vitest";
import { copyBytes, utf8Bytes } from "./bytes.js";
import { encodeSignalProvisionEnvelope, encodeSignalProvisionMessage } from "./messages.js";
import {
  SignalProvisioningCipher,
  decryptSignalDeviceName,
  deriveSecrets,
  encryptSignalDeviceName,
  hmacSha256,
} from "./provisioning.js";

describe("Signal provisioning", () => {
  it("encrypts and decrypts device names", () => {
    const identity = IdentityKeyPair.generate();
    const encrypted = encryptSignalDeviceName(" OpenClaw\0 Link ", identity.publicKey);

    expect(encrypted).toBeTruthy();
    expect(decryptSignalDeviceName(encrypted ?? "", identity.privateKey)).toBe("OpenClaw Link");
  });

  it("decrypts a provisioning envelope using the Signal Desktop format", () => {
    const cipher = new SignalProvisioningCipher();
    const aciIdentity = IdentityKeyPair.generate();
    const pniIdentity = IdentityKeyPair.generate();
    const aci = Aci.fromUuid("11111111-1111-4111-8111-111111111111");
    const pni = Pni.fromUuid("22222222-2222-4222-8222-222222222222");
    const profileKey = Uint8Array.from(Array.from({ length: 32 }, (_, index) => index));
    const masterKey = Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 32));
    const plaintext = encodeSignalProvisionMessage({
      aciIdentityKeyPrivate: aciIdentity.privateKey.serialize(),
      pniIdentityKeyPrivate: pniIdentity.privateKey.serialize(),
      aciBinary: aci.getRawUuidBytes(),
      pniBinary: pni.getRawUuidBytes(),
      number: "+15555550123",
      provisioningCode: "provision-me",
      userAgent: "Signal-Desktop",
      readReceipts: true,
      profileKey,
      masterKey,
    });
    const envelope = encryptProvisioningMessage(cipher.getPublicKey(), plaintext);

    const result = cipher.decrypt(envelope);

    expect(result.number).toBe("+15555550123");
    expect(result.provisioningCode).toBe("provision-me");
    expect(result.aci).toBe(aci.getServiceIdString());
    expect(result.pni).toBe(pni.getServiceIdString());
    expect(result.profileKey).toEqual(profileKey);
    expect(result.masterKey).toEqual(masterKey);
    expect(result.aciIdentityKeyPair.privateKey.serialize()).toEqual(aciIdentity.privateKey.serialize());
    expect(result.pniIdentityKeyPair?.privateKey.serialize()).toEqual(
      pniIdentity.privateKey.serialize(),
    );
  });
});

function encryptProvisioningMessage(
  theirPublicKey: ReturnType<PrivateKey["getPublicKey"]>,
  plaintext: Uint8Array<ArrayBuffer>,
): Uint8Array<ArrayBuffer> {
  const masterEphemeral = PrivateKey.generate();
  const keys = deriveSecrets(
    masterEphemeral.agree(theirPublicKey),
    new Uint8Array(32),
    utf8Bytes("TextSecure Provisioning Message"),
  );
  const iv = Uint8Array.from(Array.from({ length: 16 }, (_, index) => index + 1));
  const cipher = createCipheriv("aes-256-cbc", keys[0], iv);
  const ciphertext = copyBytes(Buffer.concat([cipher.update(plaintext), cipher.final()]));
  const ivAndCiphertext = concatBytes([Uint8Array.from([1]), iv, ciphertext]);
  const mac = hmacSha256(keys[1], ivAndCiphertext);
  return encodeSignalProvisionEnvelope({
    publicKey: masterEphemeral.getPublicKey().serialize(),
    body: concatBytes([ivAndCiphertext, mac]),
  });
}

function concatBytes(chunks: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out as Uint8Array<ArrayBuffer>;
}
