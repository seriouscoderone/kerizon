/**
 * PersistencePort — the unified async persistence abstraction for the
 * kerizon monorepo.
 *
 * Every store adapter (in-memory, NeDB, DynamoDB, etc.) implements this
 * single interface. Domain code depends only on this port, never on a
 * concrete store.
 */

// ── Serialized key-state shape ───────────────────────────────────

export interface SerializedKeyState {
  prefix: string;
  sn: number;
  currentKeys: string[];
  signingThreshold: string;
  nextDigests: string[];
  nextThreshold: string;
  witnesses: string[];
  witnessThreshold: number;
  configTraits: string[];
  transferable: boolean;
  lastEstSn: number;
  lastEstSaid: string;
  delegator?: string;
}

// ── Core persistence port ────────────────────────────────────────

/** Async persistence port — the external://persistence abstraction. */
export interface PersistencePort {
  // ── KEL Events ──
  putEvent(prefix: string, sn: number, said: string, raw: string, sigs: string[]): Promise<void>;
  getEvents(prefix: string): Promise<Array<{ sn: number; said: string; raw: string; sigs: string[] }>>;
  getEvent(prefix: string, sn: number): Promise<{ said: string; raw: string; sigs: string[] } | null>;

  // ── Key State ──
  putKeyState(prefix: string, state: SerializedKeyState): Promise<void>;
  getKeyState(prefix: string): Promise<SerializedKeyState | null>;

  // ── Aliases ──
  putAlias(alias: string, prefix: string): Promise<void>;
  getPrefix(alias: string): Promise<string | null>;
  listAliases(): Promise<Array<{ alias: string; prefix: string }>>;

  // ── Signing Keys (private material) ──
  putSigners(prefix: string, data: { alias: string; currentQb64s: string[]; nextQb64s: string[] }): Promise<void>;
  getSigners(prefix: string): Promise<{ alias: string; currentQb64s: string[]; nextQb64s: string[] } | null>;

  // ── Receipts ──
  putReceipt(eventSaid: string, receipt: { signerAid: string; signature: string }): Promise<void>;
  getReceipts(eventSaid: string): Promise<Array<{ signerAid: string; signature: string }>>;

  // ── Registries ──
  putRegistry(name: string, data: { said: string; name: string; lastSaid: string; lastSn: number }): Promise<void>;
  getRegistry(name: string): Promise<{ said: string; name: string; lastSaid: string; lastSn: number } | null>;
  listRegistries(): Promise<Array<{ said: string; name: string }>>;

  // ── Credentials ──
  putCredential(said: string, data: { said: string; registrySaid: string; state: string; raw: string }): Promise<void>;
  getCredential(said: string): Promise<{ said: string; registrySaid: string; state: string; raw: string } | null>;
  listCredentials(): Promise<Array<{ said: string; state: string }>>;

  // ── Endpoints (OOBI URL mappings) ──
  putEndpoint(aid: string, url: string): Promise<void>;
  getEndpoint(aid: string): Promise<string | null>;

  // ── Witness Identity (for witness nodes) ──
  putWitnessIdentity(signerQb64: string, prefix: string): Promise<void>;
  getWitnessIdentity(): Promise<{ signerQb64: string; prefix: string } | null>;

  // ── Lifecycle ──
  close(): Promise<void>;
}
