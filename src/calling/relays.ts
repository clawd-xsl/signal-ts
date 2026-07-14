// TURN relay fetch for calling. Runs GET /v2/calling/relays over the caller's
// EXISTING authenticated chat connection (the monitor's live client). Signal
// permits only one authenticated socket per device, so opening a second
// connection here would trigger a server-side ConnectedElsewhere that
// disconnects the monitor mid-call — the fetch MUST be injected, not self-opened.
import type { ChatRequest, RequestOptions } from "@signalapp/libsignal-client/dist/net/Chat.js";
import type { ChatResponse } from "@signalapp/libsignal-client/dist/Native.js";
import { SignalTsStateError } from "../errors.js";
import type { TurnServer } from "./types.js";

/** Authenticated REST over the existing chat connection (SignalTsClient.fetchAuthenticated). */
export type SignalAuthenticatedFetch = (
  request: ChatRequest,
  options?: RequestOptions,
) => Promise<ChatResponse>;

export type FetchTurnServersParams = {
  fetch: SignalAuthenticatedFetch;
  abortSignal?: AbortSignal;
};

// Authenticated calling-relays endpoint. Response carries the short-lived ICE
// server groups (STUN/TURN creds) RingRTC needs to negotiate the peer connection.
// v2 is the current endpoint (Android/Desktop/iOS); v1 returns HTTP 404.
const CALLING_RELAYS_PATH = "/v2/calling/relays";

/**
 * GET /v2/calling/relays. Parses `{ relays: [{ username, password, urls, urlsWithIps?, hostname? }] }`
 * (and tolerates a legacy flat single-relay object) into TurnServer[], splitting each
 * relay into an IP-URL server and a hostname-URL server per the RingRTC contract. Throws
 * SignalTsStateError on non-2xx, missing/malformed body, or an empty server set.
 * Result is short-lived; the caller (manager) fetches once per call and does not cache.
 */
export async function fetchTurnServers({
  fetch,
  abortSignal,
}: FetchTurnServersParams): Promise<TurnServer[]> {
  const response = await fetch(
    {
      verb: "GET",
      path: CALLING_RELAYS_PATH,
      headers: [["Accept", "application/json"]],
      timeoutMillis: 30_000,
    },
    abortSignal ? { abortSignal } : undefined,
  );
  return parseTurnRelaysResponse(response);
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
  const servers = extractRelayEntries(parsed as Record<string, unknown>).flatMap(toTurnServers);
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

function toTurnServers(entry: Record<string, unknown>): TurnServer[] {
  // RingRTC allows `hostname` only when the urls are raw IPs (it rejects the
  // ice server otherwise and PeerConnection creation fails). Mirror
  // Signal-Desktop: split each relay into an IP-URL server carrying hostname
  // and a plain hostname-URL server without it, IP group first to avoid DNS.
  const username = readOptionalString(entry["username"]);
  const password = readOptionalString(entry["password"]);
  const hostname = readOptionalString(entry["hostname"]);
  const credentials = {
    ...(username !== undefined ? { username } : {}),
    ...(password !== undefined ? { password } : {}),
  };
  const servers: TurnServer[] = [];
  const urlsWithIps = readStringArray(entry["urlsWithIps"]);
  if (urlsWithIps.length > 0) {
    servers.push({
      urls: urlsWithIps,
      ...credentials,
      ...(hostname !== undefined ? { hostname } : {}),
    });
  }
  const urls = readStringArray(entry["urls"]);
  if (urls.length > 0) {
    servers.push({ urls, ...credentials });
  }
  return servers;
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
