/**
 * Signify client resource classes — client-side API for managing KERI resources
 * through a cloud agent. Each resource class handles one category of operations.
 */

export interface IdentifierResource {
  list(): Promise<Array<{ alias: string; prefix: string }>>;
  get(alias: string): Promise<{ prefix: string; sn: number; keys: string[] }>;
  create(
    alias: string,
    opts?: { witnesses?: string[]; toad?: number },
  ): Promise<{ prefix: string }>;
  rotate(alias: string): Promise<{ sn: number }>;
  interact(
    alias: string,
    data?: Record<string, unknown>[],
  ): Promise<{ sn: number }>;
}

export interface CredentialResource {
  list(
    filter?: { schema?: string; issuer?: string },
  ): Promise<Array<{ said: string; schema: string; status: string }>>;
  get(said: string): Promise<Record<string, unknown>>;
  issue(
    alias: string,
    registryName: string,
    schema: string,
    data: Record<string, unknown>,
  ): Promise<{ said: string }>;
  revoke(alias: string, said: string): Promise<void>;
}

export interface RegistryResource {
  list(): Promise<Array<{ name: string; regid: string }>>;
  create(alias: string, name: string): Promise<{ regid: string }>;
}

export interface ExchangeResource {
  send(
    alias: string,
    route: string,
    recipient: string,
    payload: Record<string, unknown>,
  ): Promise<{ said: string }>;
  list(
    filter?: { route?: string },
  ): Promise<Array<{ said: string; route: string; datetime: string }>>;
}

export interface OobiResource {
  resolve(url: string): Promise<{ aid: string; endpoints: string[] }>;
  generate(alias: string, role: string): Promise<string[]>;
}

/** Bundle of all Signify client resources. */
export interface SignifyResources {
  identifiers: IdentifierResource;
  credentials: CredentialResource;
  registries: RegistryResource;
  exchanges: ExchangeResource;
  oobis: OobiResource;
}
