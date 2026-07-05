import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { Readable, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { RequestOptions, UploadForm } from "@signalapp/libsignal-client/dist/net/Chat.js";
import {
  DigestingPassThrough,
  chunkSizeInBytes,
  inferChunkSize,
} from "@signalapp/libsignal-client/dist/incremental_mac.js";
import { copyBytes, type Bytes } from "./bytes.js";
import { SignalTsStateError } from "./errors.js";
import type { SignalAttachmentPointer } from "./messages.js";
import { signalAttachmentFetch, type SignalFetch } from "./signal-cdn-fetch.js";

const ATTACHMENT_KEY_LENGTH = 64;
const AES_KEY_LENGTH = 32;
const IV_LENGTH = 16;
const MAC_LENGTH = 32;
const DEFAULT_CDN_URLS: Readonly<Record<number, string>> = {
  0: "https://cdn.signal.org",
  2: "https://cdn2.signal.org",
  3: "https://cdn3.signal.org",
};

export type SignalAttachmentInput = {
  data: Bytes;
  contentType?: string;
  fileName?: string;
  flags?: number;
  width?: number;
  height?: number;
  caption?: string;
  blurHash?: string;
  clientUuid?: Bytes;
  uploadTimestamp?: number;
};

export type EncryptSignalAttachmentOptions = {
  keys?: Bytes;
  iv?: Bytes;
  pad?: boolean;
  incrementalMac?: boolean;
};

export type EncryptedSignalAttachment = {
  encrypted: Bytes;
  pointer: SignalAttachmentPointer;
  plaintextHash: string;
  chunkSize?: number;
  incrementalMac?: Bytes;
};

export type AttachmentUploadConnection = {
  getUploadForm: (
    request: { uploadSize: bigint },
    options?: RequestOptions,
  ) => Promise<UploadForm>;
};

export type FetchLike = SignalFetch;

export type UploadSignalAttachmentParams = {
  connection: AttachmentUploadConnection;
  attachment: SignalAttachmentInput;
  fetch?: FetchLike;
  abortSignal?: AbortSignal;
  encryption?: EncryptSignalAttachmentOptions;
};

export type DownloadSignalAttachmentParams = {
  pointer: SignalAttachmentPointer;
  fetch?: FetchLike;
  cdnUrls?: Readonly<Record<number, string>>;
  abortSignal?: AbortSignal;
};

export async function encryptSignalAttachment(
  attachment: SignalAttachmentInput,
  options: EncryptSignalAttachmentOptions = {},
): Promise<EncryptedSignalAttachment> {
  const keys = options.keys ?? randomAttachmentKeys();
  assertLength(keys, ATTACHMENT_KEY_LENGTH, "attachment keys");
  const iv = options.iv ?? copyBytes(randomBytes(IV_LENGTH));
  assertLength(iv, IV_LENGTH, "attachment iv");

  const plaintext = options.pad === false
    ? copyBytes(attachment.data)
    : padAttachmentPlaintext(attachment.data);
  const aesKey = keys.slice(0, AES_KEY_LENGTH);
  const macKey = keys.slice(AES_KEY_LENGTH, ATTACHMENT_KEY_LENGTH);
  const ciphertext = encryptAesCbc(aesKey, iv, plaintext);
  const ivAndCiphertext = concatBytes([iv, ciphertext]);
  const mac = hmacSha256(macKey, ivAndCiphertext);
  const encrypted = concatBytes([ivAndCiphertext, mac]);
  const digest = sha256(encrypted);
  const plaintextHash = bytesToHex(sha256(attachment.data));
  const pointer = buildAttachmentPointer({
    attachment,
    keys,
    digest,
  });

  if (options.incrementalMac === true || shouldUseIncrementalMac(attachment.contentType)) {
    const chunkSizeChoice = inferChunkSize(encrypted.byteLength);
    const incrementalMac = await calculateIncrementalMac(macKey, encrypted, chunkSizeChoice);
    const chunkSize = chunkSizeInBytes(chunkSizeChoice);
    pointer.incrementalMac = incrementalMac;
    pointer.chunkSize = chunkSize;
    return { encrypted, pointer, plaintextHash, incrementalMac, chunkSize };
  }

  return { encrypted, pointer, plaintextHash };
}

export function decryptSignalAttachment(pointer: SignalAttachmentPointer, encrypted: Bytes): Bytes {
  const keys = pointer.key;
  if (!keys) {
    throw new SignalTsStateError("Signal attachment pointer is missing key");
  }
  assertLength(keys, ATTACHMENT_KEY_LENGTH, "attachment keys");
  if (encrypted.byteLength < IV_LENGTH + MAC_LENGTH) {
    throw new SignalTsStateError("Signal attachment ciphertext is too short");
  }
  if (pointer.digest) {
    assertEqualBytes(sha256(encrypted), pointer.digest, "Signal attachment digest mismatch");
  }

  const aesKey = keys.slice(0, AES_KEY_LENGTH);
  const macKey = keys.slice(AES_KEY_LENGTH, ATTACHMENT_KEY_LENGTH);
  const iv = encrypted.slice(0, IV_LENGTH);
  const ciphertext = encrypted.slice(IV_LENGTH, encrypted.byteLength - MAC_LENGTH);
  const mac = encrypted.slice(encrypted.byteLength - MAC_LENGTH);
  const ivAndCiphertext = encrypted.slice(0, encrypted.byteLength - MAC_LENGTH);
  assertEqualBytes(hmacSha256(macKey, ivAndCiphertext), mac, "Signal attachment MAC mismatch");

  const padded = decryptAesCbc(aesKey, iv, ciphertext);
  return pointer.size === undefined ? padded : copyBytes(padded.slice(0, pointer.size));
}

export async function uploadSignalAttachment({
  connection,
  attachment,
  fetch: fetchImpl = signalAttachmentFetch,
  abortSignal,
  encryption,
}: UploadSignalAttachmentParams): Promise<EncryptedSignalAttachment> {
  const encrypted = await encryptSignalAttachment(attachment, encryption);
  const uploadForm = await connection.getUploadForm(
    { uploadSize: BigInt(encrypted.encrypted.byteLength) },
    abortSignal ? { abortSignal } : undefined,
  );
  const uploadParams: Parameters<typeof uploadEncryptedAttachment>[0] = {
    uploadForm,
    encrypted: encrypted.encrypted,
    fetch: fetchImpl,
  };
  if (abortSignal) {
    uploadParams.abortSignal = abortSignal;
  }
  await uploadEncryptedAttachment(uploadParams);
  encrypted.pointer.cdnKey = uploadForm.key;
  encrypted.pointer.cdnNumber = uploadForm.cdn;
  encrypted.pointer.uploadTimestamp = attachment.uploadTimestamp ?? Date.now();
  return encrypted;
}

export async function downloadSignalAttachment({
  pointer,
  fetch: fetchImpl = signalAttachmentFetch,
  cdnUrls = DEFAULT_CDN_URLS,
  abortSignal,
}: DownloadSignalAttachmentParams): Promise<Bytes> {
  if (!pointer.cdnKey) {
    throw new SignalTsStateError("Signal attachment pointer is missing cdnKey");
  }
  const url = resolveAttachmentDownloadUrl(pointer, cdnUrls);
  const init: RequestInit = {
    method: "GET",
    redirect: "error",
  };
  if (abortSignal) {
    init.signal = abortSignal;
  }
  const response = await fetchImpl(url, init);
  if (!response.ok) {
    throw new SignalTsStateError(`Signal attachment download failed: HTTP ${response.status}`);
  }
  return decryptSignalAttachment(pointer, copyBytes(new Uint8Array(await response.arrayBuffer())));
}

export function resolveAttachmentDownloadUrl(
  pointer: Pick<SignalAttachmentPointer, "cdnKey" | "cdnNumber">,
  cdnUrls: Readonly<Record<number, string>> = DEFAULT_CDN_URLS,
): URL {
  if (!pointer.cdnKey) {
    throw new SignalTsStateError("Signal attachment pointer is missing cdnKey");
  }
  const cdnNumber = pointer.cdnNumber ?? 0;
  const base = cdnUrls[cdnNumber] ?? cdnUrls[0];
  if (!base) {
    throw new SignalTsStateError(`No Signal CDN URL configured for cdn ${cdnNumber}`);
  }
  const url = new URL(base);
  const origin = url.origin;
  url.pathname = joinUrlPath(url.pathname, "attachments", pointer.cdnKey);
  url.search = "";
  if (url.origin !== origin) {
    throw new SignalTsStateError("Signal attachment CDN URL escaped configured origin");
  }
  return url;
}

export function shouldUseIncrementalMac(contentType: string | undefined): boolean {
  return contentType === "video/mp4";
}

async function uploadEncryptedAttachment({
  uploadForm,
  encrypted,
  fetch: fetchImpl,
  abortSignal,
}: {
  uploadForm: UploadForm;
  encrypted: Bytes;
  fetch: FetchLike;
  abortSignal?: AbortSignal;
}): Promise<void> {
  if (uploadForm.cdn === 3) {
    const uploadParams: Parameters<typeof uploadEncryptedAttachmentToCdn3>[0] = {
      uploadForm,
      encrypted,
      fetch: fetchImpl,
    };
    if (abortSignal) {
      uploadParams.abortSignal = abortSignal;
    }
    await uploadEncryptedAttachmentToCdn3(uploadParams);
    return;
  }
  if (uploadForm.cdn !== 2) {
    throw new SignalTsStateError(`Unsupported Signal attachment CDN: ${uploadForm.cdn}`);
  }
  const postInit: RequestInit = {
    method: "POST",
    headers: {
      ...uploadHeaders(uploadForm.headers, { omitHost: true }),
      "Content-Length": "0",
      "Content-Type": "application/octet-stream",
    },
    body: new Uint8Array(0),
    redirect: "error",
  };
  if (abortSignal) {
    postInit.signal = abortSignal;
  }
  const initResponse = await fetchImpl(uploadForm.signedUploadUrl, postInit);
  if (!initResponse.ok) {
    throw new SignalTsStateError(`Signal attachment upload init failed: HTTP ${initResponse.status}`);
  }
  const uploadLocation = initResponse.headers.get("location");
  if (!uploadLocation) {
    throw new SignalTsStateError("Signal attachment upload init response is missing Location");
  }
  const putInit: RequestInit = {
    method: "PUT",
    headers: {
      "Content-Range": `bytes 0-${encrypted.byteLength - 1}/${encrypted.byteLength}`,
      "Content-Type": "application/octet-stream",
    },
    body: encrypted,
    redirect: "error",
  };
  if (abortSignal) {
    putInit.signal = abortSignal;
  }
  const putResponse = await fetchImpl(uploadLocation, putInit);
  if (!putResponse.ok) {
    throw new SignalTsStateError(`Signal attachment upload failed: HTTP ${putResponse.status}`);
  }
}

async function uploadEncryptedAttachmentToCdn3({
  uploadForm,
  encrypted,
  fetch: fetchImpl,
  abortSignal,
}: {
  uploadForm: UploadForm;
  encrypted: Bytes;
  fetch: FetchLike;
  abortSignal?: AbortSignal;
}): Promise<void> {
  const init: RequestInit = {
    method: "POST",
    headers: {
      ...uploadHeaders(uploadForm.headers, { omitHost: true }),
      "Content-Type": "application/offset+octet-stream",
      "Tus-Resumable": "1.0.0",
      "Upload-Length": String(encrypted.byteLength),
    },
    body: encrypted,
    redirect: "error",
  };
  if (abortSignal) {
    init.signal = abortSignal;
  }
  const response = await fetchImpl(uploadForm.signedUploadUrl, init);
  if (!response.ok) {
    throw new SignalTsStateError(`Signal attachment upload failed: HTTP ${response.status}`);
  }
}

function buildAttachmentPointer({
  attachment,
  keys,
  digest,
}: {
  attachment: SignalAttachmentInput;
  keys: Bytes;
  digest: Bytes;
}): SignalAttachmentPointer {
  const pointer: SignalAttachmentPointer = {
    key: keys,
    digest,
    size: attachment.data.byteLength,
  };
  assignIfDefined(pointer, "contentType", attachment.contentType);
  assignIfDefined(pointer, "fileName", attachment.fileName);
  assignIfDefined(pointer, "flags", attachment.flags);
  assignIfDefined(pointer, "width", attachment.width);
  assignIfDefined(pointer, "height", attachment.height);
  assignIfDefined(pointer, "caption", attachment.caption);
  assignIfDefined(pointer, "blurHash", attachment.blurHash);
  assignIfDefined(pointer, "clientUuid", attachment.clientUuid);
  assignIfDefined(pointer, "uploadTimestamp", attachment.uploadTimestamp);
  return pointer;
}

function randomAttachmentKeys(): Bytes {
  return copyBytes(randomBytes(ATTACHMENT_KEY_LENGTH));
}

function encryptAesCbc(key: Bytes, iv: Bytes, plaintext: Bytes): Bytes {
  const cipher = createCipheriv("aes-256-cbc", key, iv);
  return concatBytes([cipher.update(plaintext), cipher.final()]);
}

function decryptAesCbc(key: Bytes, iv: Bytes, ciphertext: Bytes): Bytes {
  const decipher = createDecipheriv("aes-256-cbc", key, iv);
  return concatBytes([decipher.update(ciphertext), decipher.final()]);
}

function sha256(bytes: Bytes): Bytes {
  return copyBytes(createHash("sha256").update(bytes).digest());
}

function hmacSha256(key: Bytes, bytes: Bytes): Bytes {
  return copyBytes(createHmac("sha256", key).update(bytes).digest());
}

async function calculateIncrementalMac(
  key: Bytes,
  bytes: Bytes,
  sizeChoice: ReturnType<typeof inferChunkSize>,
): Promise<Bytes> {
  const digester = new DigestingPassThrough(key, sizeChoice);
  await pipeline(Readable.from([Buffer.from(bytes)]), digester, new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  }));
  return copyBytes(digester.getFinalDigest());
}

function padAttachmentPlaintext(plaintext: Bytes): Bytes {
  const paddedSize = logPadSize(plaintext.byteLength);
  if (paddedSize <= plaintext.byteLength) {
    return copyBytes(plaintext);
  }
  const out = new Uint8Array(paddedSize);
  out.set(plaintext);
  return copyBytes(out);
}

function logPadSize(size: number): number {
  return Math.max(541, Math.floor(1.05 ** Math.ceil(Math.log(size) / Math.log(1.05))));
}

function concatBytes(chunks: readonly Uint8Array[]): Bytes {
  const size = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return copyBytes(out);
}

function assertLength(bytes: Uint8Array, expected: number, label: string): void {
  if (bytes.byteLength !== expected) {
    throw new SignalTsStateError(`Invalid ${label} length: ${bytes.byteLength}`);
  }
}

function assertEqualBytes(actual: Bytes, expected: Bytes, message: string): void {
  if (actual.byteLength !== expected.byteLength || !timingSafeEqual(actual, expected)) {
    throw new SignalTsStateError(message);
  }
}

function bytesToHex(bytes: Bytes): string {
  return Buffer.from(bytes).toString("hex");
}

function uploadHeaders(
  headers: Map<string, string>,
  options: { omitHost?: boolean } = {},
): Record<string, string> {
  const entries = [...headers.entries()].filter(
    ([key]) => !(options.omitHost === true && key.toLowerCase() === "host"),
  );
  return Object.fromEntries(entries);
}

function joinUrlPath(...parts: string[]): string {
  return `/${parts.map((part) => part.replace(/^\/+|\/+$/g, "")).filter(Boolean).join("/")}`;
}

function assignIfDefined<T extends object, K extends keyof T>(
  target: T,
  key: K,
  value: T[K] | undefined,
): void {
  if (value !== undefined) {
    target[key] = value;
  }
}
