import { Aci, Net, ServiceId } from "@signalapp/libsignal-client";
import type { RequestOptions } from "@signalapp/libsignal-client/dist/net/Chat.js";
import type { UnauthUsernamesService } from "@signalapp/libsignal-client/dist/net/chat/UnauthUsernamesService.js";
import "@signalapp/libsignal-client/dist/net/chat/UnauthUsernamesService.js";
import { hash as hashUsername } from "@signalapp/libsignal-client/dist/usernames.js";
import type { SignalAccountState } from "./account.js";
import { SignalTsStateError } from "./errors.js";

export type SignalRecipientTarget =
  | ServiceId
  | string
  | { kind: "aci"; aci: string | ServiceId }
  | { kind: "e164"; e164: string }
  | { kind: "username"; username: string };

export type SignalTargetResolver = {
  lookupUsername?: (username: string, options?: RequestOptions) => Promise<ServiceId | null>;
  lookupE164?: (e164: string, options?: RequestOptions) => Promise<ServiceId | null>;
};

export type ResolveSignalRecipientTargetParams = {
  target: SignalRecipientTarget;
  net?: Net.Net;
  account?: SignalAccountState;
  resolver?: SignalTargetResolver;
  abortSignal?: AbortSignal;
};

type ParsedTarget =
  | { kind: "aci"; aci: string | ServiceId }
  | { kind: "e164"; e164: string }
  | { kind: "username"; username: string };

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const E164_RE = /^\+[1-9]\d{6,14}$/;

export async function resolveSignalRecipientTarget({
  target,
  net,
  account,
  resolver,
  abortSignal,
}: ResolveSignalRecipientTargetParams): Promise<ServiceId> {
  const parsed = parseSignalRecipientTarget(target);
  if (parsed.kind === "aci") {
    return normalizeAci(parsed.aci);
  }
  if (parsed.kind === "username") {
    const serviceId = resolver?.lookupUsername
      ? await resolver.lookupUsername(parsed.username, requestOptions(abortSignal))
      : await lookupUsernameWithNet(
          lookupUsernameParams({ username: parsed.username, net, abortSignal }),
        );
    if (!serviceId) {
      throw new SignalTsStateError(`Signal username not found: ${parsed.username}`);
    }
    return serviceId;
  }
  const serviceId = resolver?.lookupE164
    ? await resolver.lookupE164(parsed.e164, requestOptions(abortSignal))
    : await lookupE164WithNet(lookupE164Params({ e164: parsed.e164, net, account, abortSignal }));
  if (!serviceId) {
    throw new SignalTsStateError(`Signal phone number not found: ${parsed.e164}`);
  }
  return serviceId;
}

export function parseSignalRecipientTarget(target: SignalRecipientTarget): ParsedTarget {
  if (target instanceof ServiceId) {
    return { kind: "aci", aci: target };
  }
  if (typeof target !== "string") {
    return target;
  }
  let value = target.trim();
  if (!value) {
    throw new SignalTsStateError("Signal recipient is required");
  }
  if (/^signal:/i.test(value)) {
    value = value.slice("signal:".length).trim();
  }
  const lower = value.toLowerCase();
  if (lower.startsWith("uuid:")) {
    return { kind: "aci", aci: value.slice("uuid:".length).trim() };
  }
  if (lower.startsWith("aci:")) {
    return { kind: "aci", aci: value.slice("aci:".length).trim() };
  }
  if (lower.startsWith("username:")) {
    return { kind: "username", username: requireNonEmpty(value.slice("username:".length)) };
  }
  if (lower.startsWith("u:")) {
    return { kind: "username", username: requireNonEmpty(value.slice("u:".length)) };
  }
  if (E164_RE.test(value)) {
    return { kind: "e164", e164: value };
  }
  if (UUID_RE.test(value)) {
    return { kind: "aci", aci: value };
  }
  return { kind: "username", username: value };
}

async function lookupUsernameWithNet({
  username,
  net,
  abortSignal,
}: {
  username: string;
  net?: Net.Net;
  abortSignal?: AbortSignal;
}): Promise<ServiceId | null> {
  if (!net) {
    throw new SignalTsStateError("Signal username lookup requires a Net instance");
  }
  const chat = await net.connectUnauthenticatedChat(
    { onConnectionInterrupted: () => {} },
    requestOptions(abortSignal),
  );
  try {
    const usernameChat = chat as typeof chat & UnauthUsernamesService;
    return await usernameChat.lookUpUsernameHash(
      { hash: hashUsername(username) },
      requestOptions(abortSignal),
    );
  } finally {
    await chat.disconnect();
  }
}

async function lookupE164WithNet({
  e164,
  net,
  account,
  abortSignal,
}: {
  e164: string;
  net?: Net.Net;
  account?: SignalAccountState;
  abortSignal?: AbortSignal;
}): Promise<ServiceId | null> {
  if (!net || !account) {
    throw new SignalTsStateError("Signal phone number lookup requires Net and account auth");
  }
  const response = await net.cdsiLookup(account.auth, {
    e164s: [e164],
    acisAndAccessKeys: [],
    ...(abortSignal ? { abortSignal } : {}),
  });
  const aci = response.entries.get(e164)?.aci;
  return aci ? Aci.fromUuid(aci) : null;
}

function normalizeAci(aci: string | ServiceId): ServiceId {
  if (aci instanceof ServiceId) {
    return aci;
  }
  const value = aci.trim();
  if (!UUID_RE.test(value)) {
    throw new SignalTsStateError(`Invalid Signal ACI UUID: ${aci}`);
  }
  return Aci.fromUuid(value);
}

function requireNonEmpty(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new SignalTsStateError("Signal recipient is required");
  }
  return trimmed;
}

function requestOptions(abortSignal: AbortSignal | undefined): RequestOptions | undefined {
  return abortSignal ? { abortSignal } : undefined;
}

function lookupUsernameParams(params: {
  username: string;
  net: Net.Net | undefined;
  abortSignal: AbortSignal | undefined;
}): {
  username: string;
  net?: Net.Net;
  abortSignal?: AbortSignal;
} {
  const out: { username: string; net?: Net.Net; abortSignal?: AbortSignal } = {
    username: params.username,
  };
  if (params.net) {
    out.net = params.net;
  }
  if (params.abortSignal) {
    out.abortSignal = params.abortSignal;
  }
  return out;
}

function lookupE164Params(params: {
  e164: string;
  net: Net.Net | undefined;
  account: SignalAccountState | undefined;
  abortSignal: AbortSignal | undefined;
}): {
  e164: string;
  net?: Net.Net;
  account?: SignalAccountState;
  abortSignal?: AbortSignal;
} {
  const out: {
    e164: string;
    net?: Net.Net;
    account?: SignalAccountState;
    abortSignal?: AbortSignal;
  } = {
    e164: params.e164,
  };
  if (params.net) {
    out.net = params.net;
  }
  if (params.account) {
    out.account = params.account;
  }
  if (params.abortSignal) {
    out.abortSignal = params.abortSignal;
  }
  return out;
}
