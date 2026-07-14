// Headless PulseAudio virtual-device manager for calling media.
//
// RingRTC has no raw-PCM frame API; audio only crosses the OS audio layer (cubeb).
// We therefore mirror Signal's own bin/virtual_audio.sh:setup_linux() and stand up a
// null-sink/remap-source/null-sink triple (all s16 / 48000 / stereo) via `pactl`, then
// bridge the bot's mic/ear over `pacat`:
//
//   bot mic  : write PCM -> pacat --playback -> INPUT_SINK -> INPUT_SINK.monitor
//              -> remap INPUT_SOURCE (what RingRTC captures) -> remote peer
//   bot ear  : remote peer -> RingRTC playback -> OUTPUT_SINK
//              -> pacat --record OUTPUT_SINK.monitor -> read PCM
//
// The manager points RingRTC's setAudioInput/setAudioOutput at INPUT_SOURCE / OUTPUT_SINK
// by matching these device names, so name stability here is a hard contract.
//
// Requires a running PulseAudio (or pipewire-pulse) plus the `pactl`/`pacat` CLIs on the
// host; when absent, setup rejects (pactl spawn error) before a bridge is ever opened.
import { spawn, type ChildProcess } from "node:child_process";
import { SignalTsStateError } from "../errors.js";
import type { AudioBridge, CallId } from "./types.js";

export type SignalCallAudioDeviceNames = {
  inputSink: string;
  inputSource: string;
  outputSink: string;
};

export type SignalCallAudioDevices = {
  names: SignalCallAudioDeviceNames;
  // Loaded PulseAudio module ids, already ordered for safe front-to-back unload
  // (dependents before masters: output sink, then remap source, then input sink).
  moduleIds: number[];
};

// s16le / 48 kHz / stereo everywhere: matches RingRTC's cubeb device expectation and
// bin/virtual_audio.sh. `pactl` spells the format `s16`; `pacat` spells it `s16le`.
const SAMPLE_RATE_HZ = 48000;
const CHANNELS = 2;
const PACTL_SAMPLE_FORMAT = "s16";
const PACAT_SAMPLE_FORMAT = "s16le";

// Fixed AudioBridge format; literal-typed via `as const` to satisfy the AudioBridge contract.
const AUDIO_BRIDGE_FORMAT = {
  sampleRateHz: 48000,
  channels: 2,
  encoding: "s16le",
} as const;

/** Deterministic, collision-free names, e.g. `openclaw_signal_call_<pid>_<callId>_{isink,isrc,osink}`. */
export function defaultSignalCallAudioDeviceNames(callId: CallId): SignalCallAudioDeviceNames {
  // PulseAudio device names should stay to a plain identifier charset; pid + callId
  // makes them unique across concurrent processes and successive calls.
  const prefix = `openclaw_signal_call_${process.pid}_${callId.toString()}`;
  return {
    inputSink: `${prefix}_isink`,
    inputSource: `${prefix}_isrc`,
    outputSink: `${prefix}_osink`,
  };
}

/**
 * Loads, in order:
 *   module-null-sink    sink_name=INPUT_SINK    format=s16 rate=48000 channels=2
 *   module-remap-source source_name=INPUT_SOURCE master=INPUT_SINK.monitor format=s16 rate=48000 channels=2
 *   module-null-sink    sink_name=OUTPUT_SINK   format=s16 rate=48000 channels=2
 * Returns the loaded module ids ordered for teardown (unload front-to-back). On any
 * partial failure it rolls back already-loaded modules so no virtual device leaks.
 */
export async function setupSignalCallAudioDevices(
  names: SignalCallAudioDeviceNames,
  options?: { pactlPath?: string },
): Promise<SignalCallAudioDevices> {
  const pactl = options?.pactlPath ?? "pactl";
  // unshift => moduleIds stays in unload order (dependents first); the remap source
  // reads INPUT_SINK.monitor, so it must be unloaded before its master sink.
  const moduleIds: number[] = [];
  try {
    const inputSinkId = await loadModule(pactl, [
      "load-module",
      "module-null-sink",
      `sink_name=${names.inputSink}`,
      `sink_properties=device.description=${names.inputSink}`,
      `format=${PACTL_SAMPLE_FORMAT}`,
      `rate=${SAMPLE_RATE_HZ}`,
      `channels=${CHANNELS}`,
    ]);
    moduleIds.unshift(inputSinkId);

    const inputSourceId = await loadModule(pactl, [
      "load-module",
      "module-remap-source",
      `source_name=${names.inputSource}`,
      `source_properties=device.description=${names.inputSource}`,
      `master=${names.inputSink}.monitor`,
      "master_channel_map=front-left,front-right",
      "channel_map=front-left,front-right",
      `format=${PACTL_SAMPLE_FORMAT}`,
      `rate=${SAMPLE_RATE_HZ}`,
      `channels=${CHANNELS}`,
      "remix=false",
    ]);
    moduleIds.unshift(inputSourceId);

    const outputSinkId = await loadModule(pactl, [
      "load-module",
      "module-null-sink",
      `sink_name=${names.outputSink}`,
      `sink_properties=device.description=${names.outputSink}`,
      `format=${PACTL_SAMPLE_FORMAT}`,
      `rate=${SAMPLE_RATE_HZ}`,
      `channels=${CHANNELS}`,
    ]);
    moduleIds.unshift(outputSinkId);

    return { names, moduleIds };
  } catch (err) {
    // Best-effort rollback so a half-built device set never lingers in PulseAudio.
    await teardownSignalCallAudioDevices({ names, moduleIds }, options);
    throw err;
  }
}

/** Unloads each moduleId via `pactl unload-module`; tolerant of already-gone modules. */
export async function teardownSignalCallAudioDevices(
  devices: SignalCallAudioDevices,
  options?: { pactlPath?: string },
): Promise<void> {
  const pactl = options?.pactlPath ?? "pactl";
  for (const moduleId of devices.moduleIds) {
    try {
      await runCommand(pactl, ["unload-module", String(moduleId)]);
    } catch {
      // A module may already be gone (PulseAudio auto-unloads dependents), or PulseAudio
      // may be unreachable during cleanup. Teardown must always complete either way.
    }
  }
}

/**
 * Opens the duplex bridge over the (already set-up) devices:
 *   mic: pacat --playback --device=<inputSink>          --format=s16le --rate=48000 --channels=2 (stdin = mic)
 *   ear: pacat --record   --device=<outputSink>.monitor --format=s16le --rate=48000 --channels=2 (stdout = ear)
 * close() kills both processes and awaits exit. AudioBridge.format is fixed {48000,2,"s16le"}.
 */
export function openSignalCallAudioBridge(
  names: SignalCallAudioDeviceNames,
  options?: { pacatPath?: string },
): AudioBridge {
  const pacat = options?.pacatPath ?? "pacat";

  // Bot mic: raw PCM written to stdin is played into inputSink; its monitor feeds the
  // remap source RingRTC captures from, so the remote peer hears it.
  const playback = spawn(pacat, [
    "--playback",
    "--raw",
    `--device=${names.inputSink}`,
    `--format=${PACAT_SAMPLE_FORMAT}`,
    `--rate=${SAMPLE_RATE_HZ}`,
    `--channels=${CHANNELS}`,
  ], { stdio: ["pipe", "ignore", "pipe"] });

  // Bot ear: raw PCM RingRTC played into outputSink is recorded off its monitor to stdout.
  const record = spawn(pacat, [
    "--record",
    "--raw",
    `--device=${names.outputSink}.monitor`,
    `--format=${PACAT_SAMPLE_FORMAT}`,
    `--rate=${SAMPLE_RATE_HZ}`,
    `--channels=${CHANNELS}`,
  ], { stdio: ["ignore", "pipe", "pipe"] });

  const mic = playback.stdin;
  const ear = record.stdout;
  if (!mic || !ear) {
    playback.kill("SIGKILL");
    record.kill("SIGKILL");
    throw new SignalTsStateError("failed to open pacat stdio pipes for the call audio bridge");
  }

  // Keep spawn/pipe failures (e.g. pacat missing, EPIPE when a child dies mid-write) from
  // surfacing as unhandled 'error' events that would crash the host process. There is no
  // error channel on AudioBridge; a failed child manifests as silence and is torn down by
  // the manager. setup already proved PulseAudio + `pactl` exist before we reach here.
  const swallow = () => {};
  playback.on("error", swallow);
  record.on("error", swallow);
  mic.on("error", swallow);
  ear.on("error", swallow);

  let closePromise: Promise<void> | undefined;
  const close = (): Promise<void> => {
    closePromise ??= (async () => {
      mic.destroy();
      playback.kill("SIGKILL");
      record.kill("SIGKILL");
      await Promise.all([whenChildClosed(playback), whenChildClosed(record)]);
    })();
    return closePromise;
  };

  return { format: AUDIO_BRIDGE_FORMAT, mic, ear, close };
}

/** Loads one PulseAudio module and returns the numeric module id `pactl` prints to stdout. */
async function loadModule(pactl: string, args: string[]): Promise<number> {
  const { stdout } = await runCommand(pactl, args);
  const moduleId = Number.parseInt(stdout.trim(), 10);
  if (!Number.isInteger(moduleId)) {
    const moduleName = args[1] ?? "module";
    throw new SignalTsStateError(
      `pactl load-module ${moduleName} did not return a module id (got ${JSON.stringify(stdout.trim())})`,
    );
  }
  return moduleId;
}

/** Spawns a command, collecting stdout/stderr; resolves on exit 0, rejects otherwise. */
async function runCommand(
  command: string,
  args: string[],
): Promise<{ stdout: string; stderr: string }> {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let settled = false;
    child.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.once("error", (err) => {
      if (settled) return;
      settled = true;
      reject(describeSpawnError(command, err));
    });
    child.once("close", (code) => {
      if (settled) return;
      settled = true;
      if (code === 0) {
        resolve({ stdout, stderr });
        return;
      }
      const detail = stderr.trim();
      reject(
        new SignalTsStateError(
          `${command} ${args.join(" ")} exited with code ${code ?? "null"}${detail ? `: ${detail}` : ""}`,
        ),
      );
    });
  });
}

/** Resolves once a child has fully exited; resolves immediately if it already has. */
function whenChildClosed(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve();
  }
  return new Promise<void>((resolve) => {
    child.once("close", () => resolve());
    child.once("error", () => resolve());
  });
}

function describeSpawnError(command: string, err: unknown): SignalTsStateError {
  const detail = err instanceof Error ? err.message : String(err);
  return new SignalTsStateError(
    `failed to run "${command}" (is PulseAudio installed with its CLI tools?): ${detail}`,
  );
}
