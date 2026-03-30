/** Security tier for key storage. */
export type SecurityTier = 'low' | 'med' | 'high';

/** Keeper manages private keys at the edge. Keys never leave the device. */
export interface Keeper {
  readonly tier: SecurityTier;
  readonly prefix: string; // controller AID

  /** Sign data with the current signing keys. */
  sign(data: Uint8Array): Promise<Uint8Array[]>;

  /** Rotate to next pre-committed keys. */
  rotate(): Promise<void>;

  /** Derive a key from the salt at a given path. */
  deriveKey(path: string): Promise<Uint8Array>;
}

/** SignifyClient — thin wallet that delegates to a cloud agent. */
export interface SignifyClient {
  /** Connect to a cloud agent service. */
  connect(agentUrl: string, passcode: string): Promise<void>;

  /** Create a new managed identifier via the cloud agent. */
  createIdentifier(
    alias: string,
    opts?: { witnesses?: string[]; toad?: number },
  ): Promise<{ prefix: string }>;

  /** Rotate keys — signs locally, submits to cloud agent. */
  rotateKeys(alias: string): Promise<void>;

  /** Issue a credential via the cloud agent. */
  issueCredential(
    alias: string,
    registryName: string,
    schema: string,
    data: Record<string, unknown>,
  ): Promise<string>;

  /** Get key state from cloud agent. */
  getKeyState(alias: string): Promise<Record<string, unknown>>;
}
