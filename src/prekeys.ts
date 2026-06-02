import { Aci, Net, type PreKeyBundle, type PublicKey, type ServiceId } from "@signalapp/libsignal-client";
import "@signalapp/libsignal-client/dist/net/chat/UnauthKeysService.js";
import type { UnauthKeysService } from "@signalapp/libsignal-client/dist/net/chat/UnauthKeysService.js";
import { base64ToBytes, type Bytes } from "./bytes.js";

export type PreKeyAuth =
  | { kind: "unrestricted" }
  | { kind: "access-key"; accessKey: Bytes };

export type FetchPreKeysParams = {
  target: ServiceId | string;
  device?: "all" | { deviceId: number };
  auth?: PreKeyAuth;
  userAgent?: string;
  abortSignal?: AbortSignal;
};

export type RecipientPreKeys = {
  identityKey: PublicKey;
  preKeyBundles: PreKeyBundle[];
};

type UnauthenticatedKeyConnection = Pick<Net.UnauthenticatedChatConnection, "disconnect"> &
  UnauthKeysService;

const DEFAULT_USER_AGENT = "OpenClaw signal-ts/0.0.0";

export async function fetchRecipientPreKeys(
  params: FetchPreKeysParams,
): Promise<RecipientPreKeys> {
  const net = new Net.Net({
    env: Net.Environment.Production,
    userAgent: params.userAgent ?? DEFAULT_USER_AGENT,
  });
  const connection = (await net.connectUnauthenticatedChat(
    {
      onConnectionInterrupted: () => {},
    },
    params.abortSignal ? { abortSignal: params.abortSignal } : undefined,
  )) as unknown as UnauthenticatedKeyConnection;

  try {
    return await connection.getPreKeys(
      {
        target: resolveTarget(params.target),
        device: params.device ?? "all",
        auth: resolvePreKeyAuth(params.auth),
      },
      params.abortSignal ? { abortSignal: params.abortSignal } : undefined,
    );
  } finally {
    await connection.disconnect();
  }
}

export function preKeyAuthFromBase64(accessKeyBase64?: string | null): PreKeyAuth {
  if (accessKeyBase64?.trim()) {
    return { kind: "access-key", accessKey: base64ToBytes(accessKeyBase64.trim()) };
  }
  return { kind: "unrestricted" };
}

function resolveTarget(target: ServiceId | string): ServiceId {
  if (typeof target !== "string") {
    return target;
  }
  return Aci.fromUuid(target);
}

function resolvePreKeyAuth(auth: PreKeyAuth | undefined) {
  if (!auth || auth.kind === "unrestricted") {
    return "unrestricted" as const;
  }
  return { accessKey: auth.accessKey };
}
