import { describe, expect, it, vi } from "vitest";
import { utf8Bytes } from "./bytes.js";
import {
  decryptSignalAttachment,
  downloadSignalAttachment,
  encryptSignalAttachment,
  type FetchLike,
  resolveAttachmentDownloadUrl,
  uploadSignalAttachment,
} from "./attachments.js";

describe("Signal attachments", () => {
  it("encrypts, decrypts, and preserves attachment metadata", async () => {
    const keys = deterministicBytes(64, 1);
    const iv = deterministicBytes(16, 2);
    const data = utf8Bytes("hello attachment");

    const encrypted = await encryptSignalAttachment(
      {
        data,
        contentType: "text/plain",
        fileName: "hello.txt",
        caption: "caption",
      },
      { keys, iv },
    );

    expect(encrypted.pointer).toMatchObject({
      contentType: "text/plain",
      fileName: "hello.txt",
      caption: "caption",
      size: data.byteLength,
    });
    expect(encrypted.pointer.key).toEqual(keys);
    expect(encrypted.pointer.digest).toHaveLength(32);
    expect(encrypted.encrypted.byteLength).toBeGreaterThan(data.byteLength);
    expect(decryptSignalAttachment(encrypted.pointer, encrypted.encrypted)).toEqual(data);
  });

  it("rejects tampered ciphertext and digest", async () => {
    const encrypted = await encryptSignalAttachment(
      { data: utf8Bytes("secret") },
      { keys: deterministicBytes(64, 3), iv: deterministicBytes(16, 4) },
    );
    const tampered = encrypted.encrypted.slice();
    tampered[tampered.byteLength - 1] = (tampered[tampered.byteLength - 1] ?? 0) ^ 0xff;

    expect(() => decryptSignalAttachment(encrypted.pointer, tampered)).toThrow(
      "Signal attachment digest mismatch",
    );
    expect(() =>
      decryptSignalAttachment(
        {
          ...encrypted.pointer,
          digest: deterministicBytes(32, 9),
        },
        encrypted.encrypted,
      )
    ).toThrow("Signal attachment digest mismatch");
  });

  it("adds incremental MAC metadata for mp4 attachments", async () => {
    const encrypted = await encryptSignalAttachment(
      {
        data: deterministicBytes(4096, 5),
        contentType: "video/mp4",
      },
      { keys: deterministicBytes(64, 6), iv: deterministicBytes(16, 7) },
    );

    expect(encrypted.pointer.incrementalMac?.byteLength).toBeGreaterThan(0);
    expect(encrypted.pointer.chunkSize).toBeGreaterThan(0);
  });

  it("uploads encrypted attachments through Signal's resumable form flow", async () => {
    const fetch = vi.fn(async (_input: string | URL, init?: RequestInit): Promise<Response> => {
      if (init?.method === "POST") {
        return new Response(null, {
          status: 200,
          headers: { location: "https://upload.example/session" },
        });
      }
      return new Response(null, { status: 200 });
    });
    const connection = {
      getUploadForm: vi.fn(async () => ({
        cdn: 2,
        key: "cdn-key",
        headers: new Map([["x-signal", "header"]]),
        signedUploadUrl: new URL("https://upload.example/start"),
      })),
    };

    const result = await uploadSignalAttachment({
      connection,
      attachment: { data: utf8Bytes("upload me"), contentType: "text/plain" },
      fetch: fetch as FetchLike,
      encryption: { keys: deterministicBytes(64, 8), iv: deterministicBytes(16, 9) },
    });

    expect(connection.getUploadForm).toHaveBeenCalledWith(
      { uploadSize: BigInt(result.encrypted.byteLength) },
      undefined,
    );
    expect(fetch).toHaveBeenNthCalledWith(
      1,
      new URL("https://upload.example/start"),
      expect.objectContaining({
        method: "POST",
        headers: { "x-signal": "header" },
      }),
    );
    expect(fetch).toHaveBeenNthCalledWith(
      2,
      "https://upload.example/session",
      expect.objectContaining({
        method: "PUT",
        headers: { "Content-Range": `bytes 0-*/${result.encrypted.byteLength}` },
        body: result.encrypted,
      }),
    );
    expect(result.pointer.cdnKey).toBe("cdn-key");
    expect(result.pointer.cdnNumber).toBe(2);
  });

  it("downloads and decrypts attachments from the configured CDN", async () => {
    const encrypted = await encryptSignalAttachment(
      { data: utf8Bytes("download me") },
      { keys: deterministicBytes(64, 10), iv: deterministicBytes(16, 11) },
    );
    const pointer = {
      ...encrypted.pointer,
      cdnKey: "abc/def",
      cdnNumber: 3,
    };
    const fetch = vi.fn(async (): Promise<Response> => new Response(encrypted.encrypted));

    await expect(
      downloadSignalAttachment({
        pointer,
        fetch: fetch as FetchLike,
        cdnUrls: { 0: "https://cdn0.example", 3: "https://cdn3.example/base" },
      }),
    ).resolves.toEqual(utf8Bytes("download me"));
    expect(fetch).toHaveBeenCalledWith(
      new URL("https://cdn3.example/base/attachments/abc/def"),
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("resolves Signal CDN URLs without allowing origin escapes", () => {
    expect(
      resolveAttachmentDownloadUrl(
        { cdnKey: "attachment-key", cdnNumber: 99 },
        { 0: "https://cdn0.example" },
      ).toString(),
    ).toBe("https://cdn0.example/attachments/attachment-key");
  });
});

function deterministicBytes(length: number, seed: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    bytes[index] = (seed + index) % 256;
  }
  return bytes as Uint8Array<ArrayBuffer>;
}
