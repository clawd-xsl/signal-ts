# Roadmap

## Phase 1: SDK Spine

- Define OpenClaw-facing account, connection, event, and send types.
- Implement libsignal store adapters.
- Wrap authenticated chat connect/send/disconnect.
- Keep text/content protobuf construction explicit and unfinished.

## Phase 2: DM Text MVP

- Decode existing linked-device state into `SignalAccountState`.
- Fetch recipient device/prekey bundles.
- Encode basic text `Content` protobuf.
- Encrypt per device and send via authenticated chat.
- Decode incoming envelope enough for OpenClaw direct-message text.

## Phase 3: Runtime Hardening

- Persistent SQLite-backed store.
- Retry and mismatched-device recovery.
- Delivery receipts and typing.
- Backpressure and reconnect policy.
- OpenClaw channel integration behind a feature flag.

## Phase 4: Broader Signal Surface

- Attachments.
- Groups v2 read path.
- Reactions.
- Read receipts.
- Provisioning helper.
