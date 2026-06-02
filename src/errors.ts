export class SignalTsError extends Error {
  constructor(
    message: string,
    readonly code: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "SignalTsError";
  }
}

export class SignalTsUnsupportedError extends SignalTsError {
  constructor(message: string) {
    super(message, "unsupported");
    this.name = "SignalTsUnsupportedError";
  }
}

export class SignalTsStateError extends SignalTsError {
  constructor(message: string) {
    super(message, "state");
    this.name = "SignalTsStateError";
  }
}
