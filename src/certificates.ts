import { Net, SenderCertificate } from "@signalapp/libsignal-client";
import type { ChatRequest, RequestOptions } from "@signalapp/libsignal-client/dist/net/Chat.js";
import type { ChatResponse } from "@signalapp/libsignal-client/dist/Native.js";
import type { SignalAccountState, SignalEnvironment } from "./account.js";
import { resolveLibsignalEnvironment } from "./account.js";
import { base64ToBytes, bytesToBase64 } from "./bytes.js";
import { SignalTsStateError } from "./errors.js";
import type { FileSignalRepository, FileSignalSenderCertificateState } from "./file-store.js";

export type SenderCertificateMode = "with-e164" | "without-e164";

export type FetchSenderCertificateParams = {
  account: SignalAccountState;
  mode?: SenderCertificateMode;
  environment?: SignalEnvironment;
  userAgent?: string;
  repository?: FileSignalRepository;
  connectionFactory?: SenderCertificateConnectionFactory;
  abortSignal?: AbortSignal;
};

export type SenderCertificateConnection = {
  fetch: (request: ChatRequest, options?: RequestOptions) => Promise<ChatResponse>;
  disconnect: () => Promise<void>;
};

export type SenderCertificateConnectionFactory = (params: {
  net: Net.Net;
  account: SignalAccountState;
  abortSignal?: AbortSignal;
}) => Promise<SenderCertificateConnection>;

const DEFAULT_USER_AGENT = "OpenClaw signal-ts/0.0.0";
const CERTIFICATE_EXPIRATION_BUFFER_MS = 60 * 60 * 1000;

export class SignalSenderCertificateService {
  private readonly inFlight = new Map<string, Promise<SenderCertificate>>();

  async get(params: FetchSenderCertificateParams): Promise<SenderCertificate> {
    const key = `${params.account.auth.username}:${params.mode ?? "with-e164"}`;
    const existing = this.inFlight.get(key);
    if (existing) {
      return await existing;
    }
    const promise = fetchSenderCertificate(params);
    this.inFlight.set(key, promise);
    try {
      return await promise;
    } finally {
      this.inFlight.delete(key);
    }
  }
}

export async function fetchSenderCertificate({
  account,
  mode = "with-e164",
  environment = "production",
  userAgent = DEFAULT_USER_AGENT,
  repository,
  connectionFactory = defaultSenderCertificateConnectionFactory,
  abortSignal,
}: FetchSenderCertificateParams): Promise<SenderCertificate> {
  const cached = await readCachedCertificate(repository, mode);
  if (cached) {
    return cached;
  }
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
        path: mode === "without-e164"
          ? "/v1/certificate/delivery?includeE164=false"
          : "/v1/certificate/delivery",
        headers: [["Accept", "application/json"]],
        timeoutMillis: 30_000,
      },
      abortSignal ? { abortSignal } : undefined,
    );
    const certificate = parseCertificateResponse(response);
    await writeCachedCertificate(repository, mode, certificate);
    return certificate;
  } finally {
    await connection.disconnect();
  }
}

async function defaultSenderCertificateConnectionFactory({
  net,
  account,
  abortSignal,
}: {
  net: Net.Net;
  account: SignalAccountState;
  abortSignal?: AbortSignal;
}): Promise<SenderCertificateConnection> {
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

async function readCachedCertificate(
  repository: FileSignalRepository | undefined,
  mode: SenderCertificateMode,
): Promise<SenderCertificate | undefined> {
  const account = await repository?.getAccount();
  const cached = mode === "with-e164"
    ? account?.senderCertificates?.withE164
    : account?.senderCertificates?.withoutE164;
  if (!cached || !isCertificateFresh(cached.expires)) {
    return undefined;
  }
  return SenderCertificate.deserialize(base64ToBytes(cached.serialized));
}

async function writeCachedCertificate(
  repository: FileSignalRepository | undefined,
  mode: SenderCertificateMode,
  certificate: SenderCertificate,
): Promise<void> {
  const account = await repository?.getAccount();
  if (!repository || !account) {
    return;
  }
  const cacheEntry: FileSignalSenderCertificateState = {
    serialized: bytesToBase64(certificate.serialize()),
    expires: certificate.expiration(),
  };
  await repository.setAccount({
    ...account,
    senderCertificates: {
      ...account.senderCertificates,
      ...(mode === "with-e164" ? { withE164: cacheEntry } : { withoutE164: cacheEntry }),
    },
  });
}

function parseCertificateResponse(response: ChatResponse): SenderCertificate {
  if (response.status < 200 || response.status >= 300) {
    throw new SignalTsStateError(`Sender certificate request failed: HTTP ${response.status}`);
  }
  if (!response.body) {
    throw new SignalTsStateError("Sender certificate response is missing body");
  }
  const parsed = JSON.parse(new TextDecoder().decode(response.body)) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new SignalTsStateError("Sender certificate response must be an object");
  }
  const certificate = (parsed as Record<string, unknown>)["certificate"];
  if (typeof certificate !== "string" || !certificate.trim()) {
    throw new SignalTsStateError("Sender certificate response is missing certificate");
  }
  const decoded = SenderCertificate.deserialize(base64ToBytes(certificate));
  if (!isCertificateFresh(decoded.expiration())) {
    throw new SignalTsStateError("Sender certificate is expired or too close to expiry");
  }
  return decoded;
}

function isCertificateFresh(expires: number): boolean {
  return expires - CERTIFICATE_EXPIRATION_BUFFER_MS > Date.now();
}
