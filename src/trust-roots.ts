import { PublicKey } from "@signalapp/libsignal-client";
import type { SignalEnvironment } from "./account.js";
import { base64ToBytes } from "./bytes.js";

const PRODUCTION_UNIDENTIFIED_SENDER_TRUST_ROOTS = [
  "BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF",
  "BUkY0I+9+oPgDCn4+Ac6Iu813yvqkDr/ga8DzLxFxuk6",
] as const;

const STAGING_UNIDENTIFIED_SENDER_TRUST_ROOTS = [
  "BbqY1DzohE4NUZoVF+L18oUPrK3kILllLEJh2UnPSsEx",
  "BYhU6tPjqP46KGZEzRs1OL4U39V5dlPJ/X09ha4rErkm",
] as const;

export function getSignalUnidentifiedSenderTrustRoots(
  environment: SignalEnvironment = "production",
): PublicKey[] {
  const roots = environment === "staging"
    ? STAGING_UNIDENTIFIED_SENDER_TRUST_ROOTS
    : PRODUCTION_UNIDENTIFIED_SENDER_TRUST_ROOTS;
  return roots.map((root) => PublicKey.deserialize(base64ToBytes(root)));
}
