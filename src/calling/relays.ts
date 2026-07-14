// TURN relay fetch for calling. Reuses the authenticated-chat `.fetch` pattern
// from certificates.ts (Net.Net + connectAuthenticatedChat) to GET the Signal
// service calling-relays endpoint and map the ICE server groups it returns.
import { Net } from "@signalapp/libsignal-client";
import type { ChatRequest, RequestOptions } from "@signalapp/libsignal-client/dist/net/Chat.js";
import type { ChatResponse } from "@signalapp/libsignal-client/dist/Native.js";
import type { SignalAccountState, SignalEnvironment } from "../account.js";
import { resolveLibsignalEnvironment } from "../account.js";
import { SignalTsStateError } from "../errors.js";
import type { TurnServer } from "./types.js";

export type TurnRelaysConnection = {
  fetch: (request: ChatRequest, options?: RequestOptions) => Promise<ChatResponse>;
  disconnect: () => Promise<void>;
};

export type TurnRelaysConnectionFactory = (params: {
  net: Net.Net;
  account: SignalAccountState;
  abortSignal?: AbortSignal;
}) => Promise<TurnRelaysConnection>;

export type FetchTurnServersParams = {
  account: SignalAccountState;
  environment?: SignalEnvironment; // default "production"
  userAgent?: string;
  connectionFactory?: TurnRelaysConnectionFactory; // default mirrors certificates.ts factory
  abortSignal?: AbortSignal;
};

const DEFAULT_USER_AGENT = "OpenClaw signal-ts/0.0.0";
// Authenticated calling-relays endpoint. Response carries the short-lived ICE
// server groups (STUN/TURN creds) RingRTC needs to negotiate the peer connection.
const CALLING_RELAYS_PATH = "/v1/calling/relays";

/**
 * GET /v1/calling/relays. Parses `{ relays: [{ username, password, urls, urlsWithIps?, hostname? }] }`
 * (and tolerates a legacy flat single-relay object) into TurnServer[]. Throws
 * SignalTsStateError on non-2xx, missing/malformed body, or an empty server set.
 * Result is short-lived; the caller (manager) fetches once per call and does not cache.
 */
export async function fetchTurnServers({
  account,
  environment = "production",
  userAgent = DEFAULT_USER_AGENT,
  connectionFactory = defaultTurnRelaysConnectionFactory,
  abortSignal,
}: FetchTurnServersParams): Promise<TurnServer[]> {
  const net = new Net.Net({
    env: resolveLibsignalEnvironment(environment),
    userAgent,
  });
  const connection = await connectionFactory({
    net,
    account,
    ...(abortSignal ? { abortSignal } : {}),
  });
  try {
    const response = await connection.fetch(
      {
        verb: "GET",
        path: CALLING_RELAYS_PATH,
        headers: [["Accept", "application/json"]],
        timeoutMillis: 30_000,
      },
      abortSignal ? { abortSignal } : undefined,
    );
    return parseTurnRelaysResponse(response);
  } finally {
    await connection.disconnect();
  }
}

async function defaultTurnRelaysConnectionFactory({
  net,
  account,
  abortSignal,
}: {
  net: Net.Net;
  account: SignalAccountState;
  abortSignal?: AbortSignal;
}): Promise<TurnRelaysConnection> {
  return await net.connectAuthenticatedChat(
    account.auth.username,
    account.auth.password,
    account.receiveStories ?? false,
    {
      onConnectionInterrupted: () => {},
      onIncomingMessage: (_envelope, _timestamp, ack) => ack.send(200),
      onQueueEmpty: () => {},
    },
    abortSignal ? { abortSignal } : undefined,
  );
}

function parseTurnRelaysResponse(response: ChatResponse): TurnServer[] {
  if (response.status < 200 || response.status >= 300) {
    throw new SignalTsStateError(`Calling relays request failed: HTTP ${response.status}`);
  }
  if (!response.body) {
    throw new SignalTsStateError("Calling relays response is missing body");
  }
  const parsed = JSON.parse(new TextDecoder().decode(response.body)) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new SignalTsStateError("Calling relays response must be an object");
  }
  const servers = extractRelayEntries(parsed as Record<string, unknown>)
    .map(toTurnServer)
    .filter((server): server is TurnServer => server !== undefined);
  if (servers.length === 0) {
    throw new SignalTsStateError("Calling relays response contained no usable ICE servers");
  }
  return servers;
}

function extractRelayEntries(record: Record<string, unknown>): Record<string, unknown>[] {
  const relays = record["relays"];
  if (Array.isArray(relays)) {
    return relays.filter(isRelayEntry);
  }
  // Legacy flat shape: the response object is itself a single ICE server group.
  if (Array.isArray(record["urls"]) || Array.isArray(record["urlsWithIps"])) {
    return [record];
  }
  return [];
}

function isRelayEntry(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function toTurnServer(entry: Record<string, unknown>): TurnServer | undefined {
  // Merge plain hostnames and pre-resolved IP URLs into one list; RingRTC's
  // iceServer accepts a flat url array and `hideIp` gates relay-only behavior.
  const urls = [...readStringArray(entry["urls"]), ...readStringArray(entry["urlsWithIps"])];
  if (urls.length === 0) {
    return undefined;
  }
  const username = readOptionalString(entry["username"]);
  const password = readOptionalString(entry["password"]);
  const hostname = readOptionalString(entry["hostname"]);
  return {
    urls,
    ...(username !== undefined ? { username } : {}),
    ...(password !== undefined ? { password } : {}),
    ...(hostname !== undefined ? { hostname } : {}),
  };
}

function readStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

function readOptionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}
