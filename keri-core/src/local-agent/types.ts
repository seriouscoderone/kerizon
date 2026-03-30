/** The local agent API — fat wallet operations. */
export interface LocalAgentPort {
  // Identity
  createIdentifier(config: {
    alias: string;
    transferable?: boolean;
    signingKeyCount?: number;
    nextKeyCount?: number;
  }): Promise<{ prefix: string }>;
  rotateKeys(alias: string): Promise<{ sn: number }>;
  createInteraction(
    alias: string,
    data?: Record<string, unknown>[],
  ): Promise<{ sn: number }>;
  getKeyState(alias: string): Promise<{
    prefix: string;
    sn: number;
    keys: string[];
    transferable: boolean;
  }>;

  // KEL
  exportKel(alias: string): Promise<Uint8Array>;
  importKel(cesr: Uint8Array): Promise<void>;

  // Signing
  sign(alias: string, data: string): Promise<string[]>;
  verify(
    prefix: string,
    data: string,
    signatures: string[],
  ): Promise<boolean>;

  // Credentials
  createRegistry(alias: string, name: string): Promise<string>;
  issueCredential(
    alias: string,
    registryName: string,
    schema: string,
    data: Record<string, unknown>,
  ): Promise<string>;
  listCredentials(
    alias: string,
  ): Promise<Array<{ said: string; state: string }>>;
}
