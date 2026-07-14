// Shared calling domain types for the signal-ts Calling module.
//
// The wire type (SignalCallMessage) lives beside the proto encode/decode in
// ../messages.ts; it is re-exported here so calling consumers have one import.
import type { Readable, Writable } from "node:stream";
import type { SignalCallAudioDeviceNames } from "./audio.js";

export type { SignalCallMessage } from "../messages.js";

export type CallId = bigint;
export type CallDirection = "incoming" | "outgoing";

/** Normalized lifecycle FSM (superset of RingRTC CallState + our pre/post states). */
export type CallState = "idle" | "ringing" | "connecting" | "connected" | "ended";

export type CallEndReason =
  | "local-hangup"
  | "remote-hangup"
  | "declined"
  | "busy"
  | "glare"
  | "timeout"
  | "connection-failure"
  | "signaling-failure"
  | "unsupported"
  | "internal-failure";

export type SignalCallPeer = { aci: string; deviceId: number };

/** 48 kHz / signed-16 LE / stereo PCM duplex bound to the Pulse virtual devices. */
export interface AudioBridge {
  readonly format: { readonly sampleRateHz: 48000; readonly channels: 2; readonly encoding: "s16le" };
  readonly mic: Writable; // write PCM the bot should speak (-> INPUT_SINK -> remote hears it)
  readonly ear: Readable; // PCM captured from remote peer (OUTPUT_SINK.monitor)
  close(): Promise<void>;
}

export type SignalCallEvent =
  | { type: "incoming"; callId: CallId; peer: SignalCallPeer; isVideoCall: boolean }
  | { type: "outgoing"; callId: CallId; peer: SignalCallPeer }
  | { type: "state"; callId: CallId; direction: CallDirection; peer: SignalCallPeer; state: CallState }
  | { type: "connected"; callId: CallId; peer: SignalCallPeer; audio: AudioBridge }
  | { type: "ended"; callId: CallId; peer: SignalCallPeer; reason: CallEndReason }
  | { type: "busy"; peer: SignalCallPeer } // inbound offer rejected: already in a call
  | { type: "error"; callId?: CallId; error: Error };

export type TurnServer = { urls: string[]; username?: string; password?: string; hostname?: string };

export type SignalCallManagerConfig = {
  localDeviceId: number;
  selfAci: string;
  fieldTrials?: Record<string, string>; // usually {}
  outgoingRingTimeoutMs?: number; // default 60_000
  maxCallDurationMs?: number; // hard cap; default undefined (no cap)
  hideIp?: boolean; // default false; true => TURN-relay only
  dataMode?: "low" | "normal"; // default "normal"
  audioDeviceNames?: SignalCallAudioDeviceNames; // default derived per call (see audio.ts)
  pulse?: { pactlPath?: string; pacatPath?: string };
};
