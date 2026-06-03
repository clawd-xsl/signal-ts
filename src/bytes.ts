export type Bytes = Uint8Array<ArrayBuffer>;

export function copyBytes(bytes: Uint8Array): Bytes {
  const out = new Uint8Array(bytes.byteLength);
  out.set(bytes);
  return out as Bytes;
}

export function utf8Bytes(text: string): Bytes {
  return copyBytes(new TextEncoder().encode(text));
}

export function base64ToBytes(value: string): Bytes {
  return copyBytes(Buffer.from(value, "base64"));
}

export function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export function hexToBytes(value: string): Bytes {
  const normalized = value.trim();
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(normalized)) {
    throw new Error("Hex string must contain an even number of hexadecimal characters");
  }
  return copyBytes(Buffer.from(normalized, "hex"));
}

export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.byteLength; i += 1) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}
