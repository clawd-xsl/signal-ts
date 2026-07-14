// Minimal typed view of @signalapp/ringrtc consumed by the calling module.
//
// The native package is an optionalDependency loaded via a non-literal dynamic
// import() (see manager.ts). tsc must never resolve "@signalapp/ringrtc" so the
// build is identical whether or not the prebuild is installed; that is why the
// runtime is described here instead of importing the package's own types. Do NOT
// add `declare module "@signalapp/ringrtc"` — the package ships its own .d.ts
// when installed and the two declarations would merge/conflict.
import type { Bytes } from "../bytes.js";

export type RingRtcUserId = string; // remote ACI uuid string
export type RingRtcDeviceId = number;
export type RingRtcCallId = bigint;

// String union mirrors RingRTC's CallState string enum values verbatim.
export type RingRtcCallState = "idle" | "ringing" | "connected" | "connecting" | "ended";

export const enum RingRtcOfferType {
  AudioCall = 0,
  VideoCall = 1,
}
export const enum RingRtcHangupType {
  Normal = 0,
  Accepted = 1,
  Declined = 2,
  Busy = 3,
  NeedPermission = 4,
}
export const enum RingRtcCallMessageUrgency {
  Droppable = 0,
  HandleImmediately = 1,
}
export const enum RingRtcDataMode {
  Low = 0,
  Normal = 1,
}

export interface RingRtcOfferMessage {
  callId: RingRtcCallId;
  type: RingRtcOfferType;
  opaque: Bytes;
}
export interface RingRtcAnswerMessage {
  callId: RingRtcCallId;
  opaque: Bytes;
}
export interface RingRtcIceCandidateMessage {
  callId: RingRtcCallId;
  opaque: Bytes;
}
export interface RingRtcBusyMessage {
  callId: RingRtcCallId;
}
export interface RingRtcHangupMessage {
  callId: RingRtcCallId;
  type: RingRtcHangupType;
  deviceId: RingRtcDeviceId;
}
export interface RingRtcOpaqueMessage {
  data?: Bytes;
}

export interface RingRtcCallingMessage {
  offer?: RingRtcOfferMessage;
  answer?: RingRtcAnswerMessage;
  // RingRTC field is "iceCandidates"; Signal wire field is "iceUpdate".
  iceCandidates?: RingRtcIceCandidateMessage[];
  busy?: RingRtcBusyMessage;
  hangup?: RingRtcHangupMessage;
  opaque?: RingRtcOpaqueMessage;
  destinationDeviceId?: RingRtcDeviceId;
}

export interface RingRtcAudioDevice {
  name: string;
  index: number;
  uniqueId: string;
  i18nKey?: string;
}
export interface RingRtcIceServer {
  username?: string;
  password?: string;
  hostname?: string;
  urls: string[];
}
export interface RingRtcCallSettings {
  iceServers: RingRtcIceServer[];
  hideIp: boolean;
  dataMode: RingRtcDataMode;
  audioLevelsIntervalMillis?: number;
  // DRED packet-loss audio redundancy duration; RingRTC defaults it to 0 (off).
  dredDuration?: number;
}

export interface RingRtcCall {
  readonly callId: RingRtcCallId;
  readonly remoteUserId: RingRtcUserId;
  readonly isIncoming: boolean;
  readonly isVideoCall: boolean;
  readonly state: RingRtcCallState;
  endedReason?: number; // RingRTC CallEndReason numeric
  handleStateChanged?: () => void;
  handleRemoteAudioEnabled?: () => void;
  accept(): void;
  decline(): void;
  ignore(): void;
  hangup(): void;
  setOutgoingAudioMuted(muted: boolean): void;
}

export interface RingRtcConfig {
  field_trials?: Record<string, string> | undefined;
}

export interface RingRtcHandleCallingMessageOptions {
  remoteUserId: RingRtcUserId;
  remoteUuid?: Bytes; // only consulted for the opaque path
  remoteDeviceId: RingRtcDeviceId;
  localDeviceId: RingRtcDeviceId;
  ageSec: number;
  receivedAtCounter: number;
  receivedAtDate: number;
  senderIdentityKey: Bytes; // REQUIRED for offer/answer injection
  receiverIdentityKey: Bytes; // REQUIRED for offer/answer injection
}

export interface RingRtcService {
  handleOutgoingSignaling:
    | ((remoteUserId: RingRtcUserId, message: RingRtcCallingMessage) => Promise<boolean>)
    | null;
  handleIncomingCall: ((call: RingRtcCall) => Promise<boolean>) | null; // return true to ring, false to ignore
  handleStartCall: ((call: RingRtcCall) => Promise<boolean>) | null; // fired for in/out; drive proceed() from here or after
  handleLogMessage:
    | ((level: number, fileName: string, line: number, message: string) => void)
    | null;

  setConfig(config: RingRtcConfig): void;
  setSelfUuid(uuid: Bytes): void; // 16-byte ACI
  setVoiceProcessingEnabled(enabled: boolean): void; // MUST be false (virtual devices, no acoustic loop)

  startOutgoingCall(
    remoteUserId: RingRtcUserId,
    isVideoCall: boolean,
    localDeviceId: RingRtcDeviceId,
  ): RingRtcCall;
  proceed(callId: RingRtcCallId, settings: RingRtcCallSettings): void;
  accept(callId: RingRtcCallId): void;
  decline(callId: RingRtcCallId): void;
  ignore(callId: RingRtcCallId): void;
  hangup(callId: RingRtcCallId): void;

  handleCallingMessage(
    message: RingRtcCallingMessage,
    options: RingRtcHandleCallingMessageOptions,
  ): void;

  get call(): RingRtcCall | null;
  getCall(callId: RingRtcCallId): RingRtcCall | null;

  getAudioInputs(): RingRtcAudioDevice[];
  setAudioInput(index: number): void;
  getAudioOutputs(): RingRtcAudioDevice[];
  setAudioOutput(index: number): void;
}

/** Shape of the lazily imported @signalapp/ringrtc module (only what we build/inject). */
export interface RingRtcModuleExports {
  RingRTC: RingRtcService;
  CallingMessage: new () => RingRtcCallingMessage;
  OfferMessage: new (callId: RingRtcCallId, type: RingRtcOfferType, opaque: Bytes) => RingRtcOfferMessage;
  AnswerMessage: new (callId: RingRtcCallId, opaque: Bytes) => RingRtcAnswerMessage;
  IceCandidateMessage: new (callId: RingRtcCallId, opaque: Bytes) => RingRtcIceCandidateMessage;
  BusyMessage: new (callId: RingRtcCallId) => RingRtcBusyMessage;
  HangupMessage: new (
    callId: RingRtcCallId,
    type: RingRtcHangupType,
    deviceId: RingRtcDeviceId,
  ) => RingRtcHangupMessage;
}
