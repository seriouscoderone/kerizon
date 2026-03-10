/** KeyStore is not open when operation attempted. */
export class KeyStoreClosedError extends Error {
  constructor(message = "KeyStore is not open") {
    super(message);
    this.name = "KeyStoreClosedError";
  }
}

/** AEID seed missing or does not match stored AEID. */
export class AuthenticationError extends Error {
  constructor(message = "Authentication failed") {
    super(message);
    this.name = "AuthenticationError";
  }
}

/** AEID is set but no decrypter available; unauthorized decryption. */
export class DecryptionError extends AuthenticationError {
  constructor(message = "Decryption failed") {
    super(message);
    this.name = "DecryptionError";
  }
}

/** Private key not found in KeyStore for given public key. */
export class KeyNotFoundError extends Error {
  constructor(message = "Private key not found") {
    super(message);
    this.name = "KeyNotFoundError";
  }
}

/** Rotation attempted on identifier with empty next key set. */
export class NonTransferableError extends Error {
  constructor(message = "Identifier is non-transferable (no next keys)") {
    super(message);
    this.name = "NonTransferableError";
  }
}

/** Signing threshold not met or index validation failed. */
export class ThresholdError extends Error {
  constructor(message = "Threshold error") {
    super(message);
    this.name = "ThresholdError";
  }
}

/** Invalid key derivation parameters. */
export class DerivationError extends Error {
  constructor(message = "Key derivation error") {
    super(message);
    this.name = "DerivationError";
  }
}

/** Prefix already exists in KeyStore during inception. */
export class DuplicatePrefixError extends Error {
  constructor(message = "Prefix already exists") {
    super(message);
    this.name = "DuplicatePrefixError";
  }
}

/** Prefix not found in KeyStore for rotation/sign/query. */
export class PrefixNotFoundError extends Error {
  constructor(message = "Prefix not found") {
    super(message);
    this.name = "PrefixNotFoundError";
  }
}

/** Named identifier not found in IdentifierRegistry. */
export class IdentifierNotFoundError extends Error {
  constructor(message = "Identifier not found") {
    super(message);
    this.name = "IdentifierNotFoundError";
  }
}
