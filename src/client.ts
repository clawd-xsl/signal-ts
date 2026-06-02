import { Aci, Net, type ServiceId } from "@signalapp/libsignal-client";
import "@signalapp/libsignal-client/dist/net/chat/AuthMessagesService.js";
import type { SendMessageRequest } from "@signalapp/libsignal-client/dist/net/chat/AuthMessagesService.js";
import type { SignalAccountState, SignalEnvironment } from "./account.js";
import { resolveLibsignalEnvironment } from "./account.js";
import { SignalEventHub } from "./events.js";
import type { SignalEventHandler, SignalEventName } from "./events.js";
import { SignalTsStateError, SignalTsUnsupportedError } from "./errors.js";

export type SignalLogger = {
  debug?: (message: string) => void;
  info?: (message: string) => void;
  warn?: (message: string) => void;
  error?: (message: string, error?: unknown) => void;
};

export type SignalChatConnection = Pick<
  Net.AuthenticatedChatConnection,
  "disconnect" | "connectionInfo"
> & {
  sendMessage: (
    request: SendMessageRequest,
    options?: Net.RequestOptions,
  ) => Promise<void>;
};

export type SignalConnectionFactory = (params: {
  net: Net.Net;
  account: SignalAccountState;
  listener: Net.ChatServiceListener;
  abortSignal?: AbortSignal;
}) => Promise<SignalChatConnection>;

export type SignalTsClientOptions = {
  account: SignalAccountState;
  environment?: SignalEnvironment;
  userAgent?: string;
  receiveStories?: boolean;
  logger?: SignalLogger;
  connectionFactory?: SignalConnectionFactory;
};

export type SendEncryptedMessageParams = {
  destination: ServiceId | string;
  timestamp?: number;
  contents: SendMessageRequest["contents"];
  onlineOnly?: boolean;
  urgent?: boolean;
  abortSignal?: AbortSignal;
};

const DEFAULT_USER_AGENT = "OpenClaw signal-ts/0.0.0";

export class SignalTsClient {
  private readonly events = new SignalEventHub();
  private readonly logger: SignalLogger | undefined;
  private readonly connectionFactory: SignalConnectionFactory | undefined;
  private net: Net.Net | undefined;
  private connection: SignalChatConnection | undefined;

  constructor(private readonly options: SignalTsClientOptions) {
    this.logger = options.logger;
    this.connectionFactory = options.connectionFactory;
  }

  on<K extends SignalEventName>(event: K, handler: SignalEventHandler<K>): () => void {
    return this.events.on(event, handler);
  }

  async connect(abortSignal?: AbortSignal): Promise<void> {
    if (this.connection) {
      return;
    }
    const net =
      this.net ??
      new Net.Net({
        env: resolveLibsignalEnvironment(this.options.environment ?? "production"),
        userAgent: this.options.userAgent ?? DEFAULT_USER_AGENT,
      });
    this.net = net;
    const listener = this.createListener();
    this.connection = await (this.connectionFactory ?? defaultConnectionFactory)({
      net,
      account: this.options.account,
      listener,
      ...(abortSignal ? { abortSignal } : {}),
    });
    this.logger?.info?.(`connected to Signal chat (${this.connection.connectionInfo().toString()})`);
  }

  async disconnect(): Promise<void> {
    const connection = this.connection;
    this.connection = undefined;
    if (connection) {
      await connection.disconnect();
    }
  }

  async sendEncryptedMessage(params: SendEncryptedMessageParams): Promise<{ timestamp: number }> {
    const connection = this.connection;
    if (!connection) {
      throw new SignalTsStateError("SignalTsClient is not connected");
    }
    const timestamp = params.timestamp ?? Date.now();
    await connection.sendMessage(
      {
        destination: resolveDestination(params.destination),
        timestamp,
        contents: params.contents,
        onlineOnly: params.onlineOnly ?? false,
        urgent: params.urgent ?? true,
      },
      params.abortSignal ? { abortSignal: params.abortSignal } : undefined,
    );
    return { timestamp };
  }

  async sendText(): Promise<never> {
    throw new SignalTsUnsupportedError(
      "Plaintext Signal Content protobuf encoding is not implemented yet; use sendEncryptedMessage with encrypted device payloads.",
    );
  }

  private createListener(): Net.ChatServiceListener {
    return {
      onConnectionInterrupted: (cause) => {
        this.logger?.warn?.(`Signal chat connection interrupted: ${cause?.message ?? "unknown"}`);
        this.events.emit("disconnected", cause);
      },
      onIncomingMessage: (envelope, timestamp, ack) => {
        this.events.emit("incoming", {
          envelope,
          timestamp,
          ack: () => ack.send(200),
        });
      },
      onQueueEmpty: () => {
        this.events.emit("queueEmpty", undefined);
      },
      onReceivedAlerts: (alerts) => {
        if (alerts.length > 0) {
          this.logger?.warn?.(`Signal chat alerts: ${alerts.join(", ")}`);
        }
      },
    };
  }
}

async function defaultConnectionFactory({
  net,
  account,
  listener,
  abortSignal,
}: {
  net: Net.Net;
  account: SignalAccountState;
  listener: Net.ChatServiceListener;
  abortSignal?: AbortSignal;
}): Promise<SignalChatConnection> {
  return await net.connectAuthenticatedChat(
    account.auth.username,
    account.auth.password,
    account.receiveStories ?? false,
    listener,
    abortSignal ? { abortSignal } : undefined,
  ) as unknown as SignalChatConnection;
}

function resolveDestination(destination: ServiceId | string): ServiceId {
  if (typeof destination !== "string") {
    return destination;
  }
  return Aci.fromUuid(destination);
}
