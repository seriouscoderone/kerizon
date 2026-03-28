/**
 * CLI Adapter interface -- THE core abstraction of the conformance harness.
 *
 * Every KERI implementation provides one adapter that translates these
 * abstract operations to its CLI commands. The harness tests protocol
 * invariants by calling only these methods.
 */

// ─── Result types ──────────────────────────────────────────────

export interface CliResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly durationMs: number;
}

export interface KeyState {
  readonly prefix: string;
  readonly sn: number;
  readonly currentKeys: string[];
  readonly currentThreshold: string | string[][];
  readonly nextKeyDigests: string[];
  readonly nextThreshold: string | string[][];
  readonly backers: string[];
  readonly backerThreshold: number;
  readonly lastEventDigest: string;
  readonly delegator?: string;
  readonly configTraits: string[];
  readonly transferable: boolean;
}

export interface KelEvent {
  readonly version: string;
  readonly type: EventType;
  readonly said: string;
  readonly prefix: string;
  readonly sn: number;
  readonly priorDigest?: string;
  readonly raw: string;
  readonly cesr: Uint8Array;
}

export type EventType = 'icp' | 'rot' | 'ixn' | 'dip' | 'drt';

// ─── Config types ──────────────────────────────────────────────

export interface InceptConfig {
  readonly alias: string;
  readonly transferable?: boolean;
  readonly signingKeyCount?: number;
  readonly nextKeyCount?: number;
  readonly signingThreshold?: string;
  readonly nextThreshold?: string;
  readonly witnesses?: string[];
  readonly witnessThreshold?: number;
  readonly delegator?: string;
  readonly establishmentOnly?: boolean;
  readonly doNotDelegate?: boolean;
  readonly data?: Record<string, unknown>[];
  readonly receiptEndpoint?: boolean;
}

export interface RotateConfig {
  readonly alias: string;
  readonly nextKeyCount?: number;
  readonly signingThreshold?: string;
  readonly nextThreshold?: string;
  readonly witnessesToAdd?: string[];
  readonly witnessesToRemove?: string[];
  readonly witnessThreshold?: number;
  readonly data?: Record<string, unknown>[];
  readonly receiptEndpoint?: boolean;
}

export interface InteractConfig {
  readonly alias: string;
  readonly data?: Record<string, unknown>[];
  readonly receiptEndpoint?: boolean;
}

// ─── Witness handle ────────────────────────────────────────────

export interface WitnessHandle {
  stop(): Promise<void>;
  readonly oobiUrls: string[];
}

// ─── The adapter interface ─────────────────────────────────────

export interface CliAdapter {
  /** Human-readable name, e.g. "keripy-kli" */
  readonly name: string;
  /** Semantic version of the implementation */
  readonly version: string;

  // ── Lifecycle ──

  init(opts: {
    name: string;
    salt?: string;
    passcode?: string;
    nopasscode?: boolean;
    tempDir?: string;
  }): Promise<CliResult>;

  destroy(opts: { name: string }): Promise<CliResult>;

  // ── Identifier operations ──

  incept(config: InceptConfig): Promise<CliResult & { prefix?: string }>;
  rotate(config: RotateConfig): Promise<CliResult>;
  interact(config: InteractConfig): Promise<CliResult>;
  status(alias: string): Promise<CliResult & { keyState?: KeyState }>;

  // ── KEL operations ──

  exportKel(alias: string): Promise<CliResult & { cesr?: Uint8Array }>;
  importKel(cesrBytes: Uint8Array): Promise<CliResult>;
  exportEvents(alias: string): Promise<CliResult & { events?: KelEvent[] }>;

  // ── Signing ──

  sign(alias: string, text: string): Promise<CliResult & { signatures?: string[] }>;
  verify(
    prefix: string,
    text: string,
    signatures: string[],
  ): Promise<CliResult & { valid?: boolean }>;

  // ── OOBI ──

  oobiGenerate(alias: string, role: string): Promise<CliResult & { oobis?: string[] }>;
  oobiResolve(oobi: string, alias?: string): Promise<CliResult>;

  // ── Witnesses ──

  witnessDemo(): Promise<WitnessHandle>;
}
