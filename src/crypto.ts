import {
  CiphertextMessage,
  ProtocolAddress,
  type PreKeyBundle,
  type ServiceId,
  processPreKeyBundle,
  signalEncrypt,
} from "@signalapp/libsignal-client";
import type { Bytes } from "./bytes.js";
import type { LibsignalStores } from "./store.js";

export type SignalRecipientDevice = {
  serviceId: ServiceId;
  deviceId: number;
  registrationId: number;
  preKeyBundle?: PreKeyBundle;
};

export type EncryptForDeviceParams = {
  localAddress: ProtocolAddress;
  device: SignalRecipientDevice;
  payload: Bytes;
  stores: Pick<LibsignalStores, "identityStore" | "sessionStore">;
  now?: Date;
};

export type EncryptedDeviceMessage = {
  deviceId: number;
  registrationId: number;
  contents: CiphertextMessage;
};

export async function encryptPayloadForDevice({
  localAddress,
  device,
  payload,
  stores,
  now,
}: EncryptForDeviceParams): Promise<EncryptedDeviceMessage> {
  const remoteAddress = ProtocolAddress.new(device.serviceId, device.deviceId);
  if (device.preKeyBundle) {
    await processPreKeyBundle(
      device.preKeyBundle,
      remoteAddress,
      localAddress,
      stores.sessionStore,
      stores.identityStore,
      now,
    );
  }
  const contents = await signalEncrypt(
    payload,
    remoteAddress,
    localAddress,
    stores.sessionStore,
    stores.identityStore,
    now,
  );
  return {
    deviceId: device.deviceId,
    registrationId: device.registrationId,
    contents,
  };
}
