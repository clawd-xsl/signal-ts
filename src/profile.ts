import ProfileKey from "@signalapp/libsignal-client/dist/zkgroup/profiles/ProfileKey.js";
import { base64ToBytes, bytesToBase64, type Bytes } from "./bytes.js";

export function deriveAccessKeyFromProfileKey(profileKey: Bytes): Uint8Array<ArrayBuffer> {
  return new ProfileKey(profileKey).deriveAccessKey();
}

export function deriveAccessKeyBase64FromProfileKeyBase64(profileKeyBase64: string): string {
  return bytesToBase64(deriveAccessKeyFromProfileKey(base64ToBytes(profileKeyBase64)));
}
