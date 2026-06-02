import type { Bytes } from "./bytes.js";

export type SignalIncomingEnvelope = {
  envelope: Bytes;
  timestamp: number;
  ack: () => void;
};

export type SignalClientEventMap = {
  incoming: SignalIncomingEnvelope;
  queueEmpty: void;
  disconnected: Error | null;
};

export type SignalEventName = keyof SignalClientEventMap;

export type SignalEventHandler<K extends SignalEventName> = (event: SignalClientEventMap[K]) => void;

export class SignalEventHub {
  private readonly listeners = new Map<SignalEventName, Set<(event: unknown) => void>>();

  on<K extends SignalEventName>(event: K, handler: SignalEventHandler<K>): () => void {
    const handlers = this.listeners.get(event) ?? new Set<(value: unknown) => void>();
    handlers.add(handler as (value: unknown) => void);
    this.listeners.set(event, handlers);
    return () => {
      handlers.delete(handler as (value: unknown) => void);
      if (handlers.size === 0) {
        this.listeners.delete(event);
      }
    };
  }

  emit<K extends SignalEventName>(event: K, payload: SignalClientEventMap[K]): void {
    for (const handler of this.listeners.get(event) ?? []) {
      handler(payload);
    }
  }
}
