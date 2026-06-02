# signal-ts

OpenClaw-focused TypeScript Signal client SDK built on `@signalapp/libsignal-client`.

This is not a `signal-cli` JSON-RPC clone. The goal is a native SDK that OpenClaw can embed directly instead of supervising a Java process.

## Scope

- Single linked-device account loaded from durable state or created through QR provisioning/linking.
- Authenticated chat connection through libsignal `Net`.
- Signal `Envelope`/`Content`/`DataMessage`, provisioning, and device-name protobuf encoding from the official schema.
- Direct DM sends for text, attachments, quotes, body ranges, reactions, read/viewed receipts, and typing.
- Attachment encryption/decryption, CDN upload/download, digest checks, and incremental MAC metadata for MP4 attachments.
- Recipient resolution for ACI UUIDs, E.164 phone numbers via CDSI, and usernames via unauthenticated username lookup.
- Sender-key group message primitives when the caller supplies group state, member targets, and a distribution id.
- Incoming content normalization into typed SDK events (`data`, `reaction`, `receipt`, `typing`, `edit`, `sync`, `unknown`).
- libsignal store adapters for sessions, identity keys, prekeys, signed prekeys, Kyber prekeys, and sender keys.
- File-backed state store for local account material, libsignal protocol records, group state, and cached sender certificates.
- QR provisioning primitives plus linked-device completion through `v1/devices/link`.
- Sender certificate fetch/cache, sealed-sender send, sealed-sender decrypt, and low-level sync message sends.

Still to validate live end-to-end:

- live group send validation against the Signal service
- live QR provisioning/linking against a fresh account
- multi-account runtime management

## Package

```ts
import {
  FileSignalRepository,
  SignalTsClient,
  createLibsignalStores,
  startSignalDeviceLinkSession,
  linkSignalDevice,
} from "@openclaw/signal-ts";
```

The package is AGPL-3.0-only because `@signalapp/libsignal-client` is AGPL-3.0-only.

## Development

```bash
pnpm install
pnpm check
```

## Live E2E

Live tests are intentionally opt-in and require local credentials. Put account fixture metadata in an untracked JSON file and point `SIGNAL_TS_E2E_ACCOUNT_FILE` at it:

```bash
SIGNAL_TS_E2E_ACCOUNT_FILE=/secure/path/signal-ts-account.json pnpm test:e2e
```

The preferred fixture form uses `stateFile` entries that point at `FileSignalRepository` JSON state produced by `linkSignalDevice`; relative state paths resolve from the account fixture file. Inline repository snapshots are still supported for isolated test fixtures. The required shape is documented in `.env.example`.

`pnpm test:e2e:dry` verifies that live tests stay opt-in. `pnpm test:e2e` requires two live linked-device account fixtures and runs credential validation, authenticated connect, prekey lookup, and encrypted DM roundtrips.

To create a fresh linked-device state file through QR provisioning, run the link flow separately and scan the printed `sgnl://linkdevice` URL from a Signal primary device:

```bash
SIGNAL_TS_E2E=1 \
SIGNAL_TS_E2E_LINK_DEVICE=1 \
SIGNAL_TS_E2E_LINK_OUTPUT_FILE=/secure/path/new-linked-device-state.json \
pnpm test:e2e -- src/e2e/live-link-device.e2e.test.ts
```
