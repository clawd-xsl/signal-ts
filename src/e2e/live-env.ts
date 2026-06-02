import fs from "node:fs";
import path from "node:path";
import type { SignalAccountState, SignalEnvironment } from "../account.js";
import { SignalTsStateError } from "../errors.js";
import { FileSignalRepository } from "../file-store.js";
import { InMemorySignalRepository } from "../memory-store.js";
import type { SerializedSignalRepository, SignalRepository } from "../store.js";

export type LiveE2eAccount = {
  account: SignalAccountState;
  accessKeyBase64?: string | null;
  repository?: SerializedSignalRepository;
  stateFile?: string;
};

export type LiveE2eConfig = {
  environment: SignalEnvironment;
  accounts: {
    sender: LiveE2eAccount;
    receiver: LiveE2eAccount;
  };
  timeoutMs: number;
};

export function liveE2eEnabled(): boolean {
  return process.env["SIGNAL_TS_E2E"] === "1";
}

export function loadLiveE2eConfig(): LiveE2eConfig {
  if (!liveE2eEnabled()) {
    throw new SignalTsStateError("Set SIGNAL_TS_E2E=1 to run live Signal e2e tests");
  }
  const source = readAccountJson();
  const parsed = parseJsonObject(source.raw);
  const accounts = requireObject(parsed["accounts"], "accounts");
  return {
    environment: parseEnvironment(parsed["environment"]),
    accounts: {
      sender: parseLiveAccount(accounts["sender"], "accounts.sender", source.baseDir),
      receiver: parseLiveAccount(accounts["receiver"], "accounts.receiver", source.baseDir),
    },
    timeoutMs: parseTimeout(),
  };
}

export function redactedLiveConfig(config: LiveE2eConfig): Record<string, unknown> {
  return {
    environment: config.environment,
    accounts: {
      sender: redactedLiveAccount(config.accounts.sender),
      receiver: redactedLiveAccount(config.accounts.receiver),
    },
    timeoutMs: config.timeoutMs,
  };
}

export async function loadLiveRepository(
  account: LiveE2eAccount,
  path: string,
): Promise<SignalRepository> {
  if (account.stateFile) {
    return await FileSignalRepository.open(account.stateFile);
  }
  if (account.repository) {
    return InMemorySignalRepository.fromSnapshot(account.repository);
  }
  throw new SignalTsStateError(`${path}.stateFile or ${path}.repository is required`);
}

function readAccountJson(): { raw: string; baseDir?: string } {
  const inline = process.env["SIGNAL_TS_E2E_ACCOUNT_JSON"];
  if (inline?.trim()) {
    return { raw: inline };
  }
  const file = process.env["SIGNAL_TS_E2E_ACCOUNT_FILE"];
  if (!file?.trim()) {
    throw new SignalTsStateError(
      "Set SIGNAL_TS_E2E_ACCOUNT_FILE or SIGNAL_TS_E2E_ACCOUNT_JSON for live Signal e2e tests",
    );
  }
  const resolved = path.resolve(file);
  return { raw: fs.readFileSync(resolved, "utf-8"), baseDir: path.dirname(resolved) };
}

function parseJsonObject(raw: string): Record<string, unknown> {
  const parsed = JSON.parse(raw) as unknown;
  return requireObject(parsed, "root");
}

function parseLiveAccount(
  value: unknown,
  path: string,
  baseDir: string | undefined,
): LiveE2eAccount {
  const rawAccount = requireObject(value, path);
  const stateFile = optionalPath(rawAccount["stateFile"], `${path}.stateFile`, baseDir);
  const hasInlineAccount = rawAccount["auth"] !== undefined || rawAccount["device"] !== undefined;
  const account = hasInlineAccount
    ? parseSignalAccountState(rawAccount, path)
    : stateFile
      ? readSignalAccountFromStateFile(stateFile, path)
      : missingAccount(path);
  const parsed: LiveE2eAccount = {
    account,
    accessKeyBase64: optionalString(rawAccount["accessKeyBase64"], `${path}.accessKeyBase64`),
  };
  if (stateFile) {
    parsed.stateFile = stateFile;
  }
  const repository = optionalObject(rawAccount["repository"], `${path}.repository`);
  if (repository) {
    if (stateFile) {
      throw new SignalTsStateError(`${path} must not provide both stateFile and repository`);
    }
    parsed.repository = parseRepositorySnapshot(repository, `${path}.repository`);
  }
  return parsed;
}

function redactedLiveAccount(account: LiveE2eAccount): Record<string, unknown> {
  return {
    auth: {
      username: redactMiddle(account.account.auth.username),
      password: "<redacted>",
    },
    device: {
      aci: redactMiddle(account.account.device.aci),
      e164: account.account.device.e164 ? redactMiddle(account.account.device.e164) : null,
      deviceId: account.account.device.deviceId,
      registrationId: account.account.device.registrationId,
    },
    accessKeyBase64: account.accessKeyBase64 ? "<redacted>" : null,
    stateFile: account.stateFile ? "<state-file>" : null,
    repository: account.repository
      ? {
          identityKeyPrivate: "<redacted>",
          registrationId: account.repository.registrationId,
          identities: Object.keys(account.repository.identities).length,
          sessions: Object.keys(account.repository.sessions).length,
          preKeys: Object.keys(account.repository.preKeys).length,
          signedPreKeys: Object.keys(account.repository.signedPreKeys).length,
          kyberPreKeys: Object.keys(account.repository.kyberPreKeys).length,
          senderKeys: Object.keys(account.repository.senderKeys).length,
        }
      : null,
  };
}

function parseSignalAccountState(value: Record<string, unknown>, path: string): SignalAccountState {
  const auth = requireObject(value["auth"], `${path}.auth`);
  const device = requireObject(value["device"], `${path}.device`);
  const account: SignalAccountState = {
    auth: {
      username: requireString(auth["username"], `${path}.auth.username`),
      password: requireString(auth["password"], `${path}.auth.password`),
    },
    device: {
      aci: requireUuid(device["aci"], `${path}.device.aci`),
      e164: optionalString(device["e164"], `${path}.device.e164`),
      deviceId: requirePositiveInteger(device["deviceId"], `${path}.device.deviceId`),
      registrationId: requirePositiveInteger(
        device["registrationId"],
        `${path}.device.registrationId`,
      ),
    },
  };
  const receiveStories = optionalBoolean(value["receiveStories"], `${path}.receiveStories`);
  if (receiveStories !== undefined) {
    account.receiveStories = receiveStories;
  }
  return account;
}

function readSignalAccountFromStateFile(filePath: string, path: string): SignalAccountState {
  const raw = parseJsonObject(fs.readFileSync(filePath, "utf-8"));
  if (raw["version"] !== 1) {
    throw new SignalTsStateError(`${path}.stateFile must contain a version 1 signal-ts state file`);
  }
  const accountState = requireObject(raw["account"], `${path}.stateFile.account`);
  return parseSignalAccountState(
    requireObject(accountState["account"], `${path}.stateFile.account.account`),
    `${path}.stateFile.account.account`,
  );
}

function missingAccount(path: string): never {
  throw new SignalTsStateError(`${path} must provide auth/device or stateFile`);
}

function parseRepositorySnapshot(
  value: Record<string, unknown>,
  path: string,
): SerializedSignalRepository {
  return {
    identityKeyPrivate: requireString(value["identityKeyPrivate"], `${path}.identityKeyPrivate`),
    registrationId: requirePositiveInteger(value["registrationId"], `${path}.registrationId`),
    identities: requireStringRecord(value["identities"], `${path}.identities`),
    sessions: requireStringRecord(value["sessions"], `${path}.sessions`),
    preKeys: requireStringRecord(value["preKeys"], `${path}.preKeys`),
    signedPreKeys: requireStringRecord(value["signedPreKeys"], `${path}.signedPreKeys`),
    kyberPreKeys: requireStringRecord(value["kyberPreKeys"], `${path}.kyberPreKeys`),
    senderKeys: requireStringRecord(value["senderKeys"], `${path}.senderKeys`),
  };
}

function requireStringRecord(value: unknown, path: string): Record<string, string> {
  const record = requireObject(value, path);
  const out: Record<string, string> = {};
  for (const [key, rawValue] of Object.entries(record)) {
    out[key] = requireString(rawValue, `${path}.${key}`);
  }
  return out;
}

function requireObject(value: unknown, path: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new SignalTsStateError(`${path} must be an object`);
  }
  return value as Record<string, unknown>;
}

function optionalObject(value: unknown, path: string): Record<string, unknown> | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  return requireObject(value, path);
}

function requireString(value: unknown, path: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new SignalTsStateError(`${path} must be a non-empty string`);
  }
  return value.trim();
}

function optionalPath(
  value: unknown,
  errorPath: string,
  baseDir: string | undefined,
): string | undefined {
  const raw = optionalString(value, errorPath);
  if (!raw) {
    return undefined;
  }
  return path.isAbsolute(raw) ? raw : path.resolve(baseDir ?? process.cwd(), raw);
}

function optionalString(value: unknown, path: string): string | null {
  if (value === undefined || value === null || value === "") {
    return null;
  }
  if (typeof value !== "string") {
    throw new SignalTsStateError(`${path} must be a string when provided`);
  }
  return value.trim();
}

function optionalBoolean(value: unknown, path: string): boolean | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== "boolean") {
    throw new SignalTsStateError(`${path} must be a boolean when provided`);
  }
  return value;
}

function requirePositiveInteger(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
    throw new SignalTsStateError(`${path} must be a positive integer`);
  }
  return value;
}

function requireUuid(value: unknown, path: string): string {
  const text = requireString(value, path);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(text)) {
    throw new SignalTsStateError(`${path} must be a UUID`);
  }
  return text.toLowerCase();
}

function parseEnvironment(value: unknown): SignalEnvironment {
  if (value === undefined || value === null || value === "production") {
    return "production";
  }
  if (value === "staging") {
    return "staging";
  }
  throw new SignalTsStateError("environment must be production or staging");
}

function parseTimeout(): number {
  const raw = process.env["SIGNAL_TS_E2E_TIMEOUT_MS"];
  if (!raw) {
    return 120_000;
  }
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1_000) {
    throw new SignalTsStateError("SIGNAL_TS_E2E_TIMEOUT_MS must be an integer >= 1000");
  }
  return parsed;
}

function redactMiddle(value: string): string {
  if (value.length <= 8) {
    return "<redacted>";
  }
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}
