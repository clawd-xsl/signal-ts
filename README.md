# signal-ts

OpenClaw-focused TypeScript Signal client SDK built on `@signalapp/libsignal-client`.

This is not a CLI replacement surface. The goal is to provide a small SDK that OpenClaw can embed directly instead of supervising `signal-cli` over HTTP JSON-RPC.

## Initial Scope

- Single linked-device account injected by config/state.
- Authenticated chat connection through libsignal `Net`.
- Incoming envelope events for OpenClaw channel handling.
- Direct encrypted-message send primitive.
- libsignal store adapters for sessions, identity keys, prekeys, signed prekeys, Kyber prekeys, and sender keys.

Out of scope for the first pass:

- phone-number registration
- multiple accounts
- group send
- attachment upload/download
- full Signal `Content` protobuf authoring
- QR provisioning UX

## Package

```ts
import { SignalTsClient, InMemorySignalRepository } from "@openclaw/signal-ts";
```

The package is AGPL-3.0-only because `@signalapp/libsignal-client` is AGPL-3.0-only.

## Development

```bash
pnpm install
pnpm check
```
