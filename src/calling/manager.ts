// SignalCallManager owns the RingRTC <-> Signal signaling <-> Pulse audio wiring
// for a single concurrent 1:1 audio call. RingRTC is the only place the optional
// native @signalapp/ringrtc package is referenced, and only through a non-literal
// dynamic import() cast to our own RingRtcModuleExports interface (ringrtc-types.ts)
// so tsc never resolves the specifier and the build is identical whether or not the
// optionalDependency is installed.
import { Aci, ProtocolAddress, type PreKeyBundle } from "@signalapp/libsignal-client";
import type { SignalAccountState } from "../account.js";
import type { Bytes } from "../bytes.js";
import type { SignalLogger, SignalTsClient } from "../client.js";
import { SignalTsCallingUnavailableError, SignalTsStateError } from "../errors.js";
import { createCallSignalContent } from "../messages.js";
import type { SignalCallMessage, SignalContent } from "../messages.js";
import { fetchRecipientPreKeys, type PreKeyAuth } from "../prekeys.js";
import type { LibsignalStores } from "../store.js";
import {
  defaultSignalCallAudioDeviceNames,
  openSignalCallAudioBridge,
  setupSignalCallAudioDevices,
  teardownSignalCallAudioDevices,
} from "./audio.js";
import type { SignalCallAudioDeviceNames, SignalCallAudioDevices } from "./audio.js";
import { fetchTurnServers } from "./relays.js";
import { RingRtcDataMode, RingRtcHangupType, RingRtcOfferType } from "./ringrtc-types.js";
import type {
  RingRtcCall,
  RingRtcCallSettings,
  RingRtcCallingMessage,
  RingRtcHandleCallingMessageOptions,
  RingRtcIceServer,
  RingRtcModuleExports,
  RingRtcService,
} from "./ringrtc-types.js";
import type {
  AudioBridge,
  CallDirection,
  CallEndReason,
  CallId,
  CallState,
  SignalCallEvent,
  SignalCallManagerConfig,
  SignalCallPeer,
  TurnServer,
} from "./types.js";

// Single-slot module cache for the lazily imported native package. The non-literal
// specifier keeps tsc from resolving "@signalapp/ringrtc"; the cast routes it through
// our typed interface. Missing package => friendly SignalTsCallingUnavailableError so
// text features stay unaffected when the optionalDependency is absent.
let ringRtcPromise: Promise<RingRtcModuleExports> | undefined;
async function loadRingRtcModule(): Promise<RingRtcModuleExports> {
  ringRtcPromise ??= (async () => {
    try {
      const specifier = "@signalapp/ringrtc";
      return (await import(specifier)) as unknown as RingRtcModuleExports;
    } catch (err) {
      ringRtcPromise = undefined;
      throw new SignalTsCallingUnavailableError(
        "Signal voice calling requires the optional @signalapp/ringrtc package to be installed.",
        { cause: err },
      );
    }
  })();
  return await ringRtcPromise;
}

// RingRTC arms its own 60s terminal timer for both directions (CallEndReason
// Timeout), so values above 60s here never fire; only shorter values matter.
const DEFAULT_OUTGOING_RING_TIMEOUT_MS = 60_000;
// RingRTC serializes 1:1 signaling: the next message dispatches only after the
// handleOutgoingSignaling promise settles, so one hung send wedges the whole
// offer/ICE flow. Desktop bounds every send the same way (OUTGOING_SIGNALING_WAIT).
const OUTGOING_SIGNALING_WAIT_MS = 15_000;
// close(): bounded wait for RingRTC's worker to hand over + send the final
// hangup before the signaling hook is released.
const CLOSE_HANGUP_DRAIN_MS = 2_000;
// RingRTC honors AcceptCall only in ConnectedBeforeAccepted (public state
// "ringing"); accept() waits for that transition. ICE normally connects within
// seconds and a call that never connects ends through its own failure path, so
// this cap only guards against a wedged native state machine.
const ACCEPT_RINGING_WAIT_MS = 30_000;
// RingRTC's getAudioInputs/Outputs return a cached device list refreshed
// asynchronously (cubeb device-changed callback) after pactl creates the virtual
// modules, so the freshly loaded sink/source may not be visible immediately.
const AUDIO_DEVICE_WAIT_MS = 3_000;
const AUDIO_DEVICE_POLL_MS = 50;
// RingRTC CallLogLevel values (Service.d.ts): 1=Error 2=Warn 3=Info 4=Debug 5=Trace.
const RINGRTC_LOG_ERROR = 1;
const RINGRTC_LOG_WARN = 2;
const RINGRTC_LOG_INFO = 3;
// Placeholder identity key for non-offer/answer inbound messages, which RingRTC does
// not consult (only offer/answer derive frame crypto from the identity keys).
const EMPTY_IDENTITY_KEY = new Uint8Array(0) as Bytes;

/** Sends one encrypted CallMessage to every device of recipientAci (destinationDeviceId routes it). */
export type SignalCallSendDeps = {
  sendCallMessage(params: {
    recipientAci: string;
    content: SignalContent;
    urgent: boolean;
  }): Promise<void>;
};

/** Serialized identity public keys required by RingRTC.handleCallingMessage for offer/answer. */
export type SignalCallIdentityResolver = {
  localIdentityKey(): Promise<Bytes>;
  remoteIdentityKey(aci: string, deviceId: number): Promise<Bytes | null>;
};

export type SignalCallManagerDeps = {
  config: SignalCallManagerConfig;
  send: SignalCallSendDeps;
  identity: SignalCallIdentityResolver;
  fetchTurnServers: () => Promise<TurnServer[]>;
  logger?: SignalLogger;
};

// Single-call runtime slot. RingRTC's audio device module is process-global, so exactly
// one of these exists at a time; a second inbound offer is rejected (Busy) by RingRTC and
// a second outbound call is refused by isBusy().
type ActiveCall = {
  callId: CallId;
  readonly direction: CallDirection;
  peer: SignalCallPeer;
  readonly ringRtcCall: RingRtcCall;
  readonly isVideoCall: boolean;
  // Latest normalized state; used to dedupe "state" events and gate connect/end handling.
  lastState: CallState;
  // Guards single media bring-up (turn + pulse devices + proceed) per call.
  mediaStarted: boolean;
  // Guards single terminal emit + teardown; set the moment the call is finalized.
  ended: boolean;
  audio?: AudioBridge;
  audioDevices?: SignalCallAudioDevices;
  // Explicit `| undefined` so timers can be cleared back to undefined under
  // exactOptionalPropertyTypes without delete.
  ringTimer?: ReturnType<typeof setTimeout> | undefined;
  maxDurationTimer?: ReturnType<typeof setTimeout> | undefined;
};

export class SignalCallManager {
  private module: RingRtcModuleExports | undefined;
  private readyPromise: Promise<void> | undefined;
  private active: ActiveCall | undefined;
  // Inbound offer carries the sender's exact device id; stash it so onIncomingCall (which
  // only sees call.remoteUserId) can surface the full peer. Single-slot: single call.
  private pendingIncomingPeer: { callId: CallId; peer: SignalCallPeer } | undefined;
  // Latest media teardown so close() can await device release before nulling RingRTC hooks.
  private pendingTeardown: Promise<void> | undefined;
  // True from requesting a hangup/decline until the resulting Hangup message has
  // been handed to handleOutgoingSignaling and sent (or failed). RingRTC hands it
  // over asynchronously, so close() must drain this before releasing the hook or
  // the remote keeps ringing until RingRTC's 60s timeout.
  private pendingHangupSignal = false;
  private readonly listeners = new Set<(event: SignalCallEvent) => void>();

  constructor(private readonly deps: SignalCallManagerDeps) {}

  /** Subscribe to call lifecycle events. Returns an unsubscribe fn (SignalEventHub style). */
  on(listener: (event: SignalCallEvent) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  get activeCallId(): CallId | null {
    return this.active ? this.active.callId : null;
  }

  isBusy(): boolean {
    return Boolean(this.active && !this.active.ended);
  }

  /** Loads + configures RingRTC and installs signaling/lifecycle hooks. Idempotent. */
  async ensureReady(): Promise<void> {
    this.readyPromise ??= this.configureRingRtc();
    await this.readyPromise;
  }

  private async configureRingRtc(): Promise<void> {
    try {
      const mod = await loadRingRtcModule();
      const rtc = mod.RingRTC;
      rtc.setConfig({ field_trials: this.deps.config.fieldTrials ?? {} });
      rtc.setSelfUuid(aciToBytes(this.deps.config.selfAci));
      // Virtual Pulse devices carry clean synth audio with no acoustic loop; AEC/NS/AGC
      // would only mangle it, so voice processing stays off.
      rtc.setVoiceProcessingEnabled(false);
      rtc.handleLogMessage = (level, fileName, line, message) => {
        this.forwardRingRtcLog(level, fileName, line, message);
      };
      // The single outbound signaling hook: RingRTC funnels every onSend{Offer,Answer,
      // IceCandidates,Hangup,Busy} through handleOutgoingSignaling (Service.js sendSignaling).
      rtc.handleOutgoingSignaling = (remoteUserId, message) =>
        this.onOutgoingSignaling(remoteUserId, message);
      rtc.handleIncomingCall = (call) => this.onIncomingCall(call);
      rtc.handleStartCall = (call) => this.onStartCall(call);
      this.module = mod;
    } catch (err) {
      // Reset so a later ensureReady() can retry once the package is installed.
      this.readyPromise = undefined;
      throw err;
    }
  }

  private requireModule(): RingRtcModuleExports {
    if (!this.module) {
      throw new SignalTsCallingUnavailableError(
        "Signal voice calling is not ready; call ensureReady() before using the call manager.",
      );
    }
    return this.module;
  }

  async handleIncomingCallMessage(params: {
    call: SignalCallMessage;
    sender: SignalCallPeer;
    ageSec: number;
    receivedAtCounter: number;
    receivedAtDate: number;
  }): Promise<void> {
    try {
      await this.ensureReady();
      const mod = this.requireModule();
      const { call, sender } = params;
      const receiverIdentityKey = await this.deps.identity.localIdentityKey();
      const senderIdentityKey = await this.deps.identity.remoteIdentityKey(
        sender.aci,
        sender.deviceId,
      );
      // Offer/answer injection is meaningless without the peer identity key; RingRTC would
      // drop the message internally, so fail loudly instead of silently ringing/timing out.
      const identityGatedCallId = call.offer?.callId ?? call.answer?.callId;
      if ((call.offer || call.answer) && !senderIdentityKey) {
        this.emitError(
          identityGatedCallId,
          new SignalTsStateError(
            `no stored identity key for incoming call ${call.offer ? "offer" : "answer"} from ${sender.aci}.${sender.deviceId}`,
          ),
        );
        return;
      }
      if (call.offer) {
        // RingRTC drops offers addressed to another device (destinationDeviceId
        // mismatch, Service.ts guard); don't stash a peer for a call that will
        // never surface through onIncomingCall.
        const targetedHere =
          call.destinationDeviceId === undefined ||
          call.destinationDeviceId === this.deps.config.localDeviceId;
        if (targetedHere) {
          this.pendingIncomingPeer = { callId: call.offer.callId, peer: sender };
        }
      }
      const callingMessage = signalToRingRtcCallingMessage(mod, call);
      const options: RingRtcHandleCallingMessageOptions = {
        remoteUserId: sender.aci,
        remoteUuid: aciToBytes(sender.aci),
        remoteDeviceId: sender.deviceId,
        localDeviceId: this.deps.config.localDeviceId,
        ageSec: params.ageSec,
        receivedAtCounter: params.receivedAtCounter,
        receivedAtDate: params.receivedAtDate,
        senderIdentityKey: senderIdentityKey ?? EMPTY_IDENTITY_KEY,
        receiverIdentityKey,
      };
      mod.RingRTC.handleCallingMessage(callingMessage, options);
    } catch (err) {
      this.emitError(params.call.offer?.callId, toError(err));
    }
  }

  async accept(callId: CallId): Promise<void> {
    await this.ensureReady();
    const active = this.active;
    if (!active || active.callId !== callId || active.ended) {
      this.deps.logger?.warn?.(`signal-call accept: no active call matching ${callId}`);
      return;
    }
    await this.waitUntilAcceptable(active);
    // Media bring-up already ran in handleStartCall; accept just tells RingRTC to answer.
    this.requireModule().RingRTC.accept(callId);
  }

  // RingRTC accepts locally only in state "ringing" (ConnectedBeforeAccepted:
  // ICE connected, not yet accepted). Accepting earlier is NOT an error on the
  // native side — it logs "Unexpected event AcceptCall", drops the request, and
  // the call wedges in connecting until a timeout. Wait for the ringing
  // transition; fail if the call ends first so callers see a real error.
  private async waitUntilAcceptable(active: ActiveCall): Promise<void> {
    if (active.lastState === "ringing" || active.lastState === "connected") {
      return;
    }
    if (active.ended || active.lastState === "ended") {
      throw new SignalTsStateError("Signal call ended before it could be accepted");
    }
    await new Promise<void>((resolve, reject) => {
      let off = (): void => {};
      let timer: ReturnType<typeof setTimeout> | undefined;
      const settle = (fn: () => void): void => {
        off();
        if (timer !== undefined) {
          clearTimeout(timer);
        }
        fn();
      };
      const endedError = (): Error =>
        new SignalTsStateError("Signal call ended before it could be accepted");
      off = this.on((event) => {
        if (event.type === "state" && event.callId === active.callId) {
          if (event.state === "ringing" || event.state === "connected") {
            settle(resolve);
          } else if (event.state === "ended") {
            settle(() => reject(endedError()));
          }
        } else if (event.type === "ended" && event.callId === active.callId) {
          settle(() => reject(endedError()));
        } else if (
          event.type === "error" &&
          (event.callId === undefined || event.callId === active.callId)
        ) {
          settle(() => reject(event.error));
        }
      });
      timer = setTimeout(() => {
        settle(() =>
          reject(
            new SignalTsStateError(
              `Signal call never became acceptable (no ICE connection within ${ACCEPT_RINGING_WAIT_MS}ms)`,
            ),
          ),
        );
      }, ACCEPT_RINGING_WAIT_MS);
    });
  }

  async decline(callId: CallId): Promise<void> {
    await this.ensureReady();
    const active = this.active;
    if (!active || active.callId !== callId || active.ended) {
      this.deps.logger?.warn?.(`signal-call decline: no active call matching ${callId}`);
      return;
    }
    this.pendingHangupSignal = true;
    this.safeRingRtcCall((rtc) => rtc.decline(callId));
    this.finalizeCall(active, "declined");
  }

  /** Hang up the given call, or the current active call when omitted. */
  async hangup(callId?: CallId): Promise<void> {
    const active = this.active;
    if (!active || active.ended) {
      return;
    }
    if (callId !== undefined && active.callId !== callId) {
      return;
    }
    this.endCall(active, "local-hangup", true);
  }

  async startOutgoingCall(params: { recipientAci: string }): Promise<{ callId: CallId }> {
    await this.ensureReady();
    if (this.isBusy()) {
      throw new SignalTsStateError("cannot start an outgoing call: a call is already active");
    }
    const rtc = this.requireModule().RingRTC;
    const call = rtc.startOutgoingCall(params.recipientAci, false, this.deps.config.localDeviceId);
    // Outgoing peer device is unknown until the remote answers; aci is what callers need.
    const peer: SignalCallPeer = { aci: params.recipientAci, deviceId: 0 };
    const active = this.setActiveCall(call, "outgoing", peer);
    // handleStartCall (fired async by RingRTC once the call is registered) drives proceed.
    this.armRingTimeout(active);
    this.emit({ type: "outgoing", callId: call.callId, peer });
    return { callId: call.callId };
  }

  /** Hang up + tear down audio + release RingRTC hooks. */
  async close(): Promise<void> {
    const active = this.active;
    if (active && !active.ended) {
      this.endCall(active, "local-hangup", true);
    }
    // RingRTC hands the final Hangup to handleOutgoingSignaling asynchronously
    // (worker + deferred dispatch). Nulling the hook first hits RingRTC's
    // null-hook branch (signalingMessageSendFailed) and the remote rings on.
    await this.drainPendingHangupSignal();
    if (this.pendingTeardown) {
      await this.pendingTeardown;
    }
    if (this.module) {
      const rtc = this.module.RingRTC;
      rtc.handleOutgoingSignaling = null;
      rtc.handleIncomingCall = null;
      rtc.handleStartCall = null;
      rtc.handleLogMessage = null;
    }
    this.listeners.clear();
    this.readyPromise = undefined;
    this.module = undefined;
  }

  private async drainPendingHangupSignal(): Promise<void> {
    const deadline = Date.now() + CLOSE_HANGUP_DRAIN_MS;
    while (this.pendingHangupSignal && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }

  // --- RingRTC callbacks -----------------------------------------------------

  private async onOutgoingSignaling(
    remoteUserId: string,
    message: RingRtcCallingMessage,
  ): Promise<boolean> {
    // RingRTC auto-sends Busy when an offer arrives while we are already in a call; surface
    // it so the plugin can log/notify the rejected caller.
    if (message.busy) {
      this.emit({
        type: "busy",
        peer: { aci: remoteUserId, deviceId: message.destinationDeviceId ?? 0 },
      });
    }
    try {
      const signalCall = ringRtcCallingMessageToSignal(message);
      const content = createCallSignalContent(signalCall);
      // Only the offer is urgent: it must wake sleeping recipient devices.
      // Desktop: "We want 1:1 call initiate messages to wake up recipient
      // devices, but not others" — answer/ice/hangup/busy ride normal priority.
      const urgent = Boolean(message.offer);
      // Bound the send (Desktop's OUTGOING_SIGNALING_WAIT): RingRTC dispatches
      // the next signaling message only after this promise settles, so a hung
      // send would wedge the offer/ICE flow; false fails the call cleanly.
      const sendPromise = this.deps.send.sendCallMessage({
        recipientAci: remoteUserId,
        content,
        urgent,
      });
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const outcome = await Promise.race([
          sendPromise.then(() => "sent" as const),
          new Promise<"timeout">((resolve) => {
            timer = setTimeout(() => resolve("timeout"), OUTGOING_SIGNALING_WAIT_MS);
          }),
        ]);
        if (outcome === "timeout") {
          // The late settlement must not surface as an unhandled rejection.
          sendPromise.catch(() => {});
          throw new SignalTsStateError(
            `signal-call signaling send timed out after ${OUTGOING_SIGNALING_WAIT_MS}ms`,
          );
        }
      } finally {
        if (timer !== undefined) {
          clearTimeout(timer);
        }
      }
      if (message.hangup) {
        this.pendingHangupSignal = false;
      }
      return true;
    } catch (err) {
      if (message.hangup) {
        this.pendingHangupSignal = false;
      }
      // Returning false makes RingRTC call signalingMessageSendFailed and tear the call down.
      this.emitError(this.active?.callId, toError(err));
      return false;
    }
  }

  private async onIncomingCall(call: RingRtcCall): Promise<boolean> {
    // RingRTC rejects a second offer before reaching here, but guard the single slot anyway.
    if (this.active && !this.active.ended) {
      return false;
    }
    const peer = this.resolveIncomingPeer(call);
    const active = this.setActiveCall(call, "incoming", peer);
    this.emit({
      type: "incoming",
      callId: active.callId,
      peer,
      isVideoCall: call.isVideoCall,
    });
    return true;
  }

  private async onStartCall(call: RingRtcCall): Promise<boolean> {
    const active = this.active;
    if (!active || active.ringRtcCall !== call) {
      return false;
    }
    // Reconcile the finalized callId (RingRTC assigns it before handleStartCall fires).
    active.callId = call.callId;
    try {
      // Canonical RingRTC usage (src/node/test/CallingClass.ts:99-105): proceed for BOTH
      // directions is driven from handleStartCall, after turn + audio device bring-up.
      await this.beginCallMedia(active);
      return true;
    } catch (err) {
      // Media bring-up (TURN fetch, audio devices, proceed) is where a call
      // silently dies; log the raw cause so it is not lost behind the event.
      this.deps.logger?.error?.("signal-call media bring-up failed", toError(err));
      this.emitError(active.callId, toError(err));
      this.finalizeCall(active, "internal-failure");
      return false;
    }
  }

  private onCallStateChanged(call: RingRtcCall): void {
    const active = this.active;
    if (!active || active.ringRtcCall !== call) {
      return;
    }
    // RingRtcCallState and CallState share the exact same string members (Service.d.ts
    // CallState enum values), so the normalized state is a direct passthrough.
    const state: CallState = call.state;
    if (state !== active.lastState) {
      active.lastState = state;
      this.emit({
        type: "state",
        callId: active.callId,
        direction: active.direction,
        peer: active.peer,
        state,
      });
    }
    if (state === "connected") {
      this.handleConnected(active);
    } else if (state === "ended") {
      this.finalizeCall(active, mapCallEndReason(call.endedReason));
    }
  }

  // --- media + lifecycle -----------------------------------------------------

  private setActiveCall(
    call: RingRtcCall,
    direction: CallDirection,
    peer: SignalCallPeer,
  ): ActiveCall {
    const active: ActiveCall = {
      callId: call.callId,
      direction,
      peer,
      ringRtcCall: call,
      isVideoCall: call.isVideoCall,
      lastState: call.state,
      mediaStarted: false,
      ended: false,
    };
    this.active = active;
    // Bind the lifecycle callback once; every state transition routes through here.
    call.handleStateChanged = () => this.onCallStateChanged(call);
    return active;
  }

  private resolveIncomingPeer(call: RingRtcCall): SignalCallPeer {
    const pending = this.pendingIncomingPeer;
    this.pendingIncomingPeer = undefined;
    if (pending && pending.callId === call.callId) {
      return pending.peer;
    }
    // Device id is unknown without the stashed offer; aci still identifies the caller.
    return { aci: call.remoteUserId, deviceId: 0 };
  }

  private async beginCallMedia(active: ActiveCall): Promise<void> {
    if (active.mediaStarted || active.ended) {
      return;
    }
    active.mediaStarted = true;
    const rtc = this.requireModule().RingRTC;
    const turnServers = await this.deps.fetchTurnServers();
    // The call may have been declined/hung up while the (network) turn fetch was in flight.
    if (active.ended) {
      return;
    }
    const names = this.deviceNamesFor(active.callId);
    const devices = await setupSignalCallAudioDevices(names, this.pactlOptions());
    if (active.ended) {
      await teardownSignalCallAudioDevices(devices, this.pactlOptions());
      return;
    }
    active.audioDevices = devices;
    try {
      await this.pointRingRtcAtDevices(rtc, names);
    } catch (err) {
      // Selecting the wrong (default) device would ship a connected-but-silent
      // call, so a failed selection is terminal, not a warning.
      this.emitError(active.callId, toError(err));
      this.endCall(active, "internal-failure", true);
      return;
    }
    if (active.ended) {
      return;
    }
    const settings: RingRtcCallSettings = {
      iceServers: turnServers.map(turnToIceServer),
      hideIp: this.deps.config.hideIp ?? false,
      dataMode: this.deps.config.dataMode === "low" ? RingRtcDataMode.Low : RingRtcDataMode.Normal,
    };
    rtc.proceed(active.callId, settings);
  }

  private async pointRingRtcAtDevices(
    rtc: RingRtcService,
    names: SignalCallAudioDeviceNames,
  ): Promise<void> {
    // The virtual devices publish device.description == our names (audio.ts), which is what
    // cubeb surfaces as AudioDevice.name. Poll the cached device list until both appear,
    // then select by matching index; give up (hard fail) rather than send audio nowhere.
    const deadline = Date.now() + AUDIO_DEVICE_WAIT_MS;
    for (;;) {
      const input = rtc.getAudioInputs().find((device) => device.name === names.inputSource);
      const output = rtc.getAudioOutputs().find((device) => device.name === names.outputSink);
      if (input && output) {
        rtc.setAudioInput(input.index);
        rtc.setAudioOutput(output.index);
        return;
      }
      if (Date.now() >= deadline) {
        throw new SignalTsStateError(
          `RingRTC did not surface the virtual audio devices within ${AUDIO_DEVICE_WAIT_MS}ms ` +
            `(input=${input ? "ok" : "missing"} output=${output ? "ok" : "missing"})`,
        );
      }
      await new Promise((resolve) => setTimeout(resolve, AUDIO_DEVICE_POLL_MS));
    }
  }

  private handleConnected(active: ActiveCall): void {
    this.clearRingTimer(active);
    // "connected" can re-fire after a reconnect; open the pacat bridge only once.
    if (active.audio || active.ended) {
      return;
    }
    const names = active.audioDevices?.names ?? this.deviceNamesFor(active.callId);
    try {
      active.audio = openSignalCallAudioBridge(names, this.pacatOptions());
    } catch (err) {
      this.emitError(active.callId, toError(err));
      this.endCall(active, "internal-failure", true);
      return;
    }
    // RingRTC disables the outgoing audio track on the Accepted transition
    // (Call._outgoingAudioEnabled defaults false), so the PCM we feed the virtual
    // mic is captured but never sent until we explicitly un-mute. Without this the
    // peer hears silence on every call.
    active.ringRtcCall.setOutgoingAudioMuted(false);
    this.emit({
      type: "connected",
      callId: active.callId,
      peer: active.peer,
      audio: active.audio,
    });
    this.armMaxDurationTimer(active);
  }

  // Terminal path for locally initiated ends (hangup/timeout/max-duration): optionally tell
  // RingRTC to hang up, then finalize. Remote-initiated ends arrive via onCallStateChanged.
  private endCall(active: ActiveCall, reason: CallEndReason, sendHangup: boolean): void {
    if (active.ended) {
      return;
    }
    if (sendHangup) {
      this.pendingHangupSignal = true;
      this.safeRingRtcCall((rtc) => rtc.hangup(active.callId));
    }
    this.finalizeCall(active, reason);
  }

  private finalizeCall(active: ActiveCall, reason: CallEndReason): void {
    if (active.ended) {
      return;
    }
    active.ended = true;
    this.clearTimers(active);
    if (this.active === active) {
      this.active = undefined;
    }
    this.emit({ type: "ended", callId: active.callId, peer: active.peer, reason });
    this.pendingTeardown = this.teardownMedia(active);
    void this.pendingTeardown.catch((err) => {
      this.deps.logger?.error?.("signal-call media teardown failed", err);
    });
  }

  private async teardownMedia(active: ActiveCall): Promise<void> {
    if (active.audio) {
      try {
        await active.audio.close();
      } catch (err) {
        this.deps.logger?.warn?.(`signal-call audio bridge close failed: ${describeError(err)}`);
      }
    }
    if (active.audioDevices) {
      await teardownSignalCallAudioDevices(active.audioDevices, this.pactlOptions());
    }
  }

  // --- timers ----------------------------------------------------------------

  private armRingTimeout(active: ActiveCall): void {
    const ms = this.deps.config.outgoingRingTimeoutMs ?? DEFAULT_OUTGOING_RING_TIMEOUT_MS;
    active.ringTimer = setTimeout(() => {
      if (this.active === active && !active.ended && active.lastState !== "connected") {
        this.deps.logger?.info?.(`signal-call: outgoing ring timeout after ${ms}ms; hanging up`);
        this.endCall(active, "timeout", true);
      }
    }, ms);
    active.ringTimer.unref();
  }

  private armMaxDurationTimer(active: ActiveCall): void {
    const ms = this.deps.config.maxCallDurationMs;
    if (ms === undefined) {
      return;
    }
    active.maxDurationTimer = setTimeout(() => {
      if (this.active === active && !active.ended) {
        this.deps.logger?.info?.(`signal-call: max duration ${ms}ms reached; hanging up`);
        this.endCall(active, "local-hangup", true);
      }
    }, ms);
    active.maxDurationTimer.unref();
  }

  private clearRingTimer(active: ActiveCall): void {
    if (active.ringTimer) {
      clearTimeout(active.ringTimer);
      active.ringTimer = undefined;
    }
  }

  private clearTimers(active: ActiveCall): void {
    this.clearRingTimer(active);
    if (active.maxDurationTimer) {
      clearTimeout(active.maxDurationTimer);
      active.maxDurationTimer = undefined;
    }
  }

  // --- helpers ---------------------------------------------------------------

  private deviceNamesFor(callId: CallId): SignalCallAudioDeviceNames {
    return this.deps.config.audioDeviceNames ?? defaultSignalCallAudioDeviceNames(callId);
  }

  private pactlOptions(): { pactlPath?: string } | undefined {
    const pactlPath = this.deps.config.pulse?.pactlPath;
    return pactlPath !== undefined ? { pactlPath } : undefined;
  }

  private pacatOptions(): { pacatPath?: string } | undefined {
    const pacatPath = this.deps.config.pulse?.pacatPath;
    return pacatPath !== undefined ? { pacatPath } : undefined;
  }

  private safeRingRtcCall(action: (rtc: RingRtcService) => void): void {
    if (!this.module) {
      return;
    }
    try {
      action(this.module.RingRTC);
    } catch (err) {
      this.deps.logger?.warn?.(`signal-call RingRTC action failed: ${describeError(err)}`);
    }
  }

  private forwardRingRtcLog(level: number, fileName: string, line: number, message: string): void {
    const text = `ringrtc ${fileName}:${line} ${message}`;
    if (level <= RINGRTC_LOG_ERROR) {
      this.deps.logger?.error?.(text);
    } else if (level === RINGRTC_LOG_WARN) {
      this.deps.logger?.warn?.(text);
    } else if (level === RINGRTC_LOG_INFO) {
      this.deps.logger?.info?.(text);
    } else {
      this.deps.logger?.debug?.(text);
    }
  }

  private emitError(callId: CallId | undefined, error: Error): void {
    this.emit({ type: "error", ...(callId !== undefined ? { callId } : {}), error });
  }

  private emit(event: SignalCallEvent): void {
    for (const listener of [...this.listeners]) {
      try {
        listener(event);
      } catch (err) {
        this.deps.logger?.error?.("signal-call event listener threw", err);
      }
    }
  }
}

/** Convenience factory the plugin uses: wires send/identity/turn from client + stores + account. */
export function createSignalCallManager(params: {
  client: SignalTsClient;
  account: SignalAccountState;
  stores: Pick<LibsignalStores, "identityStore" | "sessionStore">;
  // Per-recipient prekey auth (access key) for call signaling sends, same as
  // the host resolves for normal messages; without it the prekey fetch before
  // the first signaling send is rejected (RequestUnauthorized).
  resolvePreKeyAuth?: (recipientAci: string) => Promise<PreKeyAuth | undefined>;
  config?: Partial<
    Pick<
      SignalCallManagerConfig,
      "hideIp" | "dataMode" | "outgoingRingTimeoutMs" | "maxCallDurationMs" | "fieldTrials" | "pulse"
    >
  >;
  logger?: SignalLogger;
}): SignalCallManager {
  const { client, account, stores } = params;
  const config: SignalCallManagerConfig = {
    localDeviceId: account.device.deviceId,
    selfAci: account.device.aci,
    ...(params.config ?? {}),
  };
  // Single-slot prekey-bundle cache: RingRTC serializes signaling, and without
  // this every offer/ICE/hangup pays a fresh unauthenticated connect + /v2/keys
  // fetch (seconds of setup latency) and drains the peer's one-time prekeys.
  // Cached bundles are inert once sessions exist (only deviceId/registrationId
  // are read), and a device change self-heals: the 409 mismatch repair inside
  // sendContentMessage refetches fresh bundles.
  let cachedPreKeys: { recipientAci: string; bundles: PreKeyBundle[] } | undefined;
  const send: SignalCallSendDeps = {
    sendCallMessage: async ({ recipientAci, content, urgent }) => {
      // Reuses the full content-send path (per-device fan-out + mismatch repair, urgent flag).
      const preKeyAuth = await params.resolvePreKeyAuth?.(recipientAci);
      if (cachedPreKeys?.recipientAci !== recipientAci) {
        const fetched = await fetchRecipientPreKeys({
          target: recipientAci,
          ...(preKeyAuth !== undefined ? { auth: preKeyAuth } : {}),
        });
        cachedPreKeys = { recipientAci, bundles: fetched.preKeyBundles };
      }
      await client.sendContentMessage({
        destination: recipientAci,
        content,
        stores,
        urgent,
        preKeyBundles: cachedPreKeys.bundles,
        ...(preKeyAuth !== undefined ? { preKeyAuth } : {}),
      });
    },
  };
  const identity: SignalCallIdentityResolver = {
    localIdentityKey: async () => {
      const key = await stores.identityStore.getIdentityKey();
      return toRingRtcIdentityKey(key.getPublicKey().serialize());
    },
    remoteIdentityKey: async (aci, deviceId) => {
      const address = ProtocolAddress.new(Aci.fromUuid(aci), deviceId);
      const key = await stores.identityStore.getIdentity(address);
      return key ? toRingRtcIdentityKey(key.serialize()) : null;
    },
  };
  return new SignalCallManager({
    config,
    send,
    identity,
    // Reuse the monitor's single authenticated connection for the TURN fetch; a
    // second authenticated connect would ConnectedElsewhere the monitor mid-call.
    fetchTurnServers: () =>
      fetchTurnServers({ fetch: (request, options) => client.fetchAuthenticated(request, options) }),
    ...(params.logger !== undefined ? { logger: params.logger } : {}),
  });
}

// --- pure conversions --------------------------------------------------------

function aciToBytes(aci: string): Bytes {
  return Aci.fromUuid(aci).getRawUuidBytes();
}

// libsignal serializes public keys with a leading DJB type byte (0x05, 33 bytes
// total); RingRTC derives the call's frame crypto from the raw 32-byte
// Curve25519 key, so a prefixed key breaks SRTP/SRTCP ("Failed to unprotect").
// Signal-Desktop strips the header the same way (calling.preload.ts
// "Ignore the type header"). Pass already-raw keys through untouched.
const DJB_KEY_TYPE = 0x05;
function toRingRtcIdentityKey(serialized: Uint8Array): Bytes {
  if (serialized.length === 33 && serialized[0] === DJB_KEY_TYPE) {
    return serialized.subarray(1) as Bytes;
  }
  return serialized as Bytes;
}

function turnToIceServer(turn: TurnServer): RingRtcIceServer {
  return {
    urls: turn.urls,
    ...(turn.username !== undefined ? { username: turn.username } : {}),
    ...(turn.password !== undefined ? { password: turn.password } : {}),
    ...(turn.hostname !== undefined ? { hostname: turn.hostname } : {}),
  };
}

// Outbound: RingRTC CallingMessage -> Signal wire CallMessage (iceCandidates -> iceUpdate,
// numeric offer/hangup enums -> string unions). Opaque is group-call only and skipped for 1:1.
function ringRtcCallingMessageToSignal(message: RingRtcCallingMessage): SignalCallMessage {
  const signal: SignalCallMessage = {};
  if (message.offer) {
    signal.offer = {
      callId: message.offer.callId,
      type: message.offer.type === RingRtcOfferType.VideoCall ? "video" : "audio",
      opaque: message.offer.opaque,
    };
  }
  if (message.answer) {
    signal.answer = { callId: message.answer.callId, opaque: message.answer.opaque };
  }
  if (message.iceCandidates && message.iceCandidates.length > 0) {
    signal.iceUpdate = message.iceCandidates.map((candidate) => ({
      callId: candidate.callId,
      opaque: candidate.opaque,
    }));
  }
  if (message.busy) {
    signal.busy = { callId: message.busy.callId };
  }
  if (message.hangup) {
    signal.hangup = {
      callId: message.hangup.callId,
      type: ringRtcHangupTypeToUnion(message.hangup.type),
      deviceId: message.hangup.deviceId,
    };
  }
  if (message.opaque?.data) {
    signal.opaque = { data: message.opaque.data, urgency: "handle-immediately" };
  }
  if (message.destinationDeviceId !== undefined) {
    signal.destinationDeviceId = message.destinationDeviceId;
  }
  return signal;
}

// Inbound: decoded Signal wire CallMessage -> RingRTC CallingMessage built via the module
// constructors so RingRTC.handleCallingMessage sees native instances.
// Inbound `opaque` CallMessages (group-call rings, call links) are intentionally
// NOT mapped: this module is 1:1-audio-only and installs no group handlers, so
// forwarding them would only hit RingRTC's unset-handler warnings.
function signalToRingRtcCallingMessage(
  mod: RingRtcModuleExports,
  call: SignalCallMessage,
): RingRtcCallingMessage {
  const message = new mod.CallingMessage();
  if (call.offer) {
    message.offer = new mod.OfferMessage(
      call.offer.callId,
      call.offer.type === "video" ? RingRtcOfferType.VideoCall : RingRtcOfferType.AudioCall,
      call.offer.opaque,
    );
  }
  if (call.answer) {
    message.answer = new mod.AnswerMessage(call.answer.callId, call.answer.opaque);
  }
  if (call.iceUpdate && call.iceUpdate.length > 0) {
    message.iceCandidates = call.iceUpdate.map(
      (candidate) => new mod.IceCandidateMessage(candidate.callId, candidate.opaque),
    );
  }
  if (call.busy) {
    message.busy = new mod.BusyMessage(call.busy.callId);
  }
  if (call.hangup) {
    message.hangup = new mod.HangupMessage(
      call.hangup.callId,
      unionHangupTypeToRingRtc(call.hangup.type),
      call.hangup.deviceId,
    );
  }
  if (call.destinationDeviceId !== undefined) {
    message.destinationDeviceId = call.destinationDeviceId;
  }
  return message;
}

function ringRtcHangupTypeToUnion(
  type: RingRtcHangupType,
): NonNullable<SignalCallMessage["hangup"]>["type"] {
  switch (type) {
    case RingRtcHangupType.Accepted:
      return "accepted";
    case RingRtcHangupType.Declined:
      return "declined";
    case RingRtcHangupType.Busy:
      return "busy";
    case RingRtcHangupType.NeedPermission:
      return "need-permission";
    case RingRtcHangupType.Normal:
      return "normal";
    default:
      return "normal";
  }
}

function unionHangupTypeToRingRtc(
  type: NonNullable<SignalCallMessage["hangup"]>["type"],
): RingRtcHangupType {
  switch (type) {
    case "accepted":
      return RingRtcHangupType.Accepted;
    case "declined":
      return RingRtcHangupType.Declined;
    case "busy":
      return RingRtcHangupType.Busy;
    case "need-permission":
      return RingRtcHangupType.NeedPermission;
    case "normal":
      return RingRtcHangupType.Normal;
  }
}

// Numeric RingRTC CallEndReason (Service.d.ts CallEndReason) -> normalized CallEndReason.
function mapCallEndReason(code: number | undefined): CallEndReason {
  switch (code) {
    case 0: // LocalHangup
    case 13: // AppDroppedCall
    case 14: // DeviceExplicitlyDisconnected
      return "local-hangup";
    case 1: // RemoteHangup
    case 3: // RemoteHangupAccepted (elsewhere)
      return "remote-hangup";
    case 2: // RemoteHangupNeedPermission: callee's message-request gate blocked
      // the call (they lack our profile key). Distinct so hosts can react
      // (send profile key / surface the real failure) instead of seeing an
      // ordinary hangup.
      return "need-permission";
    case 4: // RemoteHangupDeclined
      return "declined";
    case 5: // RemoteHangupBusy
    case 6: // RemoteBusy
      return "busy";
    case 7: // RemoteGlare
    case 8: // RemoteReCall
      return "glare";
    case 9: // Timeout
      return "timeout";
    case 11: // SignalingFailure
      return "signaling-failure";
    case 12: // ConnectionFailure
    case 15: // ServerExplicitlyDisconnected
      return "connection-failure";
    default: // InternalFailure (10) + group/link-only failure modes
      return "internal-failure";
  }
}

function toError(err: unknown): Error {
  return err instanceof Error ? err : new Error(describeError(err));
}

function describeError(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
