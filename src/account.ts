import type { Net } from "@signalapp/libsignal-client";

export type SignalEnvironment = "production" | "staging";

export type SignalServiceAuth = {
  username: string;
  password: string;
};

export type SignalLocalDevice = {
  aci: string;
  e164?: string | null;
  deviceId: number;
  registrationId: number;
};

export type SignalAccountState = {
  auth: SignalServiceAuth;
  device: SignalLocalDevice;
  receiveStories?: boolean;
};

export function resolveLibsignalEnvironment(environment: SignalEnvironment): Net.Environment {
  return environment === "staging" ? 0 : 1;
}
