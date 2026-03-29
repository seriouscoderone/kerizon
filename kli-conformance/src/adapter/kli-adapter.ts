/**
 * keripy kli reference adapter.
 *
 * Translates CliAdapter methods to kli commands using exact flags
 * extracted from /Users/seriouscoderone/code/keripy/src/keri/cli/commands/.
 *
 * Key kli conventions:
 *   - All commands take --name/-n (keystore name), --base/-b, --passcode/-p
 *   - Config files are JSON passed via --file/-f
 *   - Data anchors support @filename via --data/-d
 *   - Output patterns: "Prefix  <pre>", "New Sequence No.  <sn>", etc.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import type {
  CliAdapter,
  CliResult,
  KeyState,
  KelEvent,
  InceptConfig,
  RotateConfig,
  InteractConfig,
  WitnessHandle,
} from './types.js';
import { execCli, execCliBinary } from '../harness/cli-executor.js';
import { createTempEnv, type TempEnv } from '../harness/temp-env.js';
import {
  parsePrefix,
  parseNewSeqNo,
  parsePublicKeys,
  parseSignatures,
  parseVerifyResult,
  parseOobiUrls,
  parseKeyState,
  parseVerboseEvents,
  parseIdentifierList,
  parseEventOutput,
} from '../harness/result-parser.js';

/**
 * Well-known demo witness AIDs (from keripy 1.3.4 witness/demo.py).
 * AIDs verified via: `kli witness demo && kli status --name <name> --alias <name>`
 */
export const DEMO_WITNESSES = {
  wan: { aid: 'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha', http: 5642, tcp: 5632 },
  wil: { aid: 'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM', http: 5643, tcp: 5633 },
  wes: { aid: 'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX', http: 5644, tcp: 5634 },
  wit: { aid: 'BM35JN8XeJSEfpxopjn5jr7tAHCE5749f0OobhMLCorE', http: 5645, tcp: 5635 },
  wub: { aid: 'BIj15u5V11bkbtAxMA7gcNJZcax-7TgaBMLsQnMHpYHP', http: 5646, tcp: 5636 },
  wyz: { aid: 'BF2rZTW79z4IXocYRQnjjsOuvFUQv-ptCf8Yltd7PfsM', http: 5647, tcp: 5637 },
} as const;

export interface KliAdapterOptions {
  /** Path to the kli executable (default: "kli") */
  kliPath?: string;
  /** Keystore name used for all commands. Use unique names for test isolation. */
  keystoreName: string;
  /**
   * Passcode for encrypted keystore.
   * If omitted, use nopasscode=true on init.
   */
  passcode?: string;
  /** Command timeout in ms (default: 30_000) */
  timeout?: number;
}

export class KliAdapter implements CliAdapter {
  readonly name = 'keripy-kli';
  readonly version = '1.x';

  private readonly kli: string;
  private readonly keystoreName: string;
  private readonly passcode?: string;
  private readonly timeout: number;
  private tempEnv?: TempEnv;

  constructor(opts: KliAdapterOptions) {
    this.kli = opts.kliPath ?? 'kli';
    this.keystoreName = opts.keystoreName;
    this.passcode = opts.passcode;
    this.timeout = opts.timeout ?? 30_000;
  }

  /**
   * Common keystore args prepended to every command.
   * Note: kli stores keystores under ~/.keri/ with relative paths only.
   * We use unique keystore names for test isolation instead of --base.
   */
  private keystoreArgs(): string[] {
    const args = ['--name', this.keystoreName];
    if (this.passcode) args.push('--passcode', this.passcode);
    return args;
  }

  private run(subcommand: string[], extraArgs: string[] = []): Promise<CliResult> {
    return execCli(this.kli, [...subcommand, ...this.keystoreArgs(), ...extraArgs], {
      timeout: this.timeout,
    });
  }

  private runBinary(subcommand: string[], extraArgs: string[] = []) {
    return execCliBinary(this.kli, [...subcommand, ...this.keystoreArgs(), ...extraArgs], {
      timeout: this.timeout,
    });
  }

  private async ensureTempEnv(): Promise<TempEnv> {
    if (!this.tempEnv) {
      this.tempEnv = await createTempEnv('kli-adapter-');
    }
    return this.tempEnv;
  }

  // ── Lifecycle ──

  async init(opts: {
    name: string;
    salt?: string;
    passcode?: string;
    nopasscode?: boolean;
    temp?: boolean;
    tempDir?: string;
  }): Promise<CliResult> {
    const args = ['init', '--name', opts.name];
    if (opts.passcode) args.push('--passcode', opts.passcode);
    if (opts.nopasscode) args.push('--nopasscode');
    if (opts.salt) args.push('--salt', opts.salt);
    if (opts.temp) args.push('--temp');

    return execCli(this.kli, args, { timeout: this.timeout });
  }

  async destroy(_opts: { name: string }): Promise<CliResult> {
    // kli doesn't have a destroy command; we clean up temp dirs instead
    if (this.tempEnv) {
      await this.tempEnv.cleanup();
      this.tempEnv = undefined;
    }
    return { exitCode: 0, stdout: '', stderr: '', durationMs: 0 };
  }

  // ── Identifier operations ──

  async incept(config: InceptConfig): Promise<CliResult & { prefix?: string }> {
    const tempEnv = await this.ensureTempEnv();

    // Build config file (kli incept prefers --file for complex configs)
    const fileConfig: Record<string, unknown> = {
      transferable: config.transferable ?? true,
      wits: config.witnesses ?? [],
      toad: config.witnessThreshold ?? 0,
      icount: config.signingKeyCount ?? 1,
      ncount: config.nextKeyCount ?? 1,
      isith: config.signingThreshold ?? '1',
      nsith: config.nextThreshold ?? '1',
    };
    if (config.establishmentOnly) fileConfig['estOnly'] = true;
    if (config.doNotDelegate) fileConfig['DnD'] = true;
    if (config.delegator) fileConfig['delpre'] = config.delegator;
    if (config.data) fileConfig['data'] = config.data;

    const configPath = await tempEnv.writeConfig(`incept-${config.alias}.json`, fileConfig);

    const args = ['--alias', config.alias, '--file', configPath];
    if (config.receiptEndpoint) args.push('--receipt-endpoint');

    const result = await this.run(['incept'], args);
    const prefix = parsePrefix(result.stdout);

    return { ...result, prefix };
  }

  async rotate(config: RotateConfig): Promise<CliResult> {
    const args = ['--alias', config.alias];

    if (config.signingThreshold) args.push('--isith', config.signingThreshold);
    if (config.nextThreshold) args.push('--nsith', config.nextThreshold);
    if (config.nextKeyCount != null) args.push('--next-count', String(config.nextKeyCount));
    if (config.witnessThreshold != null) args.push('--toad', String(config.witnessThreshold));

    if (config.witnessesToRemove) {
      for (const w of config.witnessesToRemove) {
        args.push('--witness-cut', w);
      }
    }
    if (config.witnessesToAdd) {
      for (const w of config.witnessesToAdd) {
        args.push('--witness-add', w);
      }
    }

    if (config.data) {
      const tempEnv = await this.ensureTempEnv();
      const dataPath = await tempEnv.writeConfig(`rotate-data-${config.alias}.json`, { data: config.data });
      args.push('--data', `@${dataPath}`);
    }

    if (config.receiptEndpoint) args.push('--receipt-endpoint');

    return this.run(['rotate'], args);
  }

  async interact(config: InteractConfig): Promise<CliResult> {
    const args = ['--alias', config.alias];

    if (config.data) {
      const tempEnv = await this.ensureTempEnv();
      const dataPath = await tempEnv.writeFile(
        `interact-data-${config.alias}.json`,
        JSON.stringify(config.data),
      );
      args.push('--data', `@${dataPath}`);
    }

    if (config.receiptEndpoint) args.push('--receipt-endpoint');

    return this.run(['interact'], args);
  }

  async status(alias: string): Promise<CliResult & { keyState?: KeyState }> {
    const result = await this.run(['status'], ['--alias', alias, '--verbose']);
    const keyState = parseKeyState(result.stdout);
    return { ...result, keyState };
  }

  // ── KEL operations ──

  async exportKel(alias: string): Promise<CliResult & { cesr?: Uint8Array }> {
    const result = await this.runBinary(['export'], ['--alias', alias]);
    const cesr = result.exitCode === 0 ? new Uint8Array(result.stdoutBuffer) : undefined;
    return { ...result, cesr };
  }

  async importKel(cesrBytes: Uint8Array): Promise<CliResult> {
    const tempEnv = await this.ensureTempEnv();
    const cesrPath = await tempEnv.writeBinary('import.cesr', cesrBytes);
    return this.run(['import'], ['--file', cesrPath]);
  }

  async exportEvents(alias: string): Promise<CliResult & { events?: KelEvent[] }> {
    // Use status --verbose to get JSON events
    const result = await this.run(['status'], ['--alias', alias, '--verbose']);
    if (result.exitCode !== 0) return { ...result, events: undefined };

    const rawEvents = parseVerboseEvents(result.stdout);
    const events: KelEvent[] = rawEvents.map(raw => ({
      version: raw['v'] as string ?? '',
      type: raw['t'] as KelEvent['type'] ?? 'icp',
      said: raw['d'] as string ?? '',
      prefix: raw['i'] as string ?? '',
      sn: typeof raw['s'] === 'string' ? parseInt(raw['s'], 16) : (raw['s'] as number ?? 0),
      priorDigest: raw['p'] as string | undefined,
      raw: JSON.stringify(raw),
      cesr: new Uint8Array(),
    }));

    return { ...result, events };
  }

  // ── Signing ──

  async sign(alias: string, text: string): Promise<CliResult & { signatures?: string[] }> {
    const result = await this.run(['sign'], ['--alias', alias, '--text', text]);
    const signatures = result.exitCode === 0 ? parseSignatures(result.stdout) : undefined;
    return { ...result, signatures };
  }

  async verify(
    prefix: string,
    text: string,
    signatures: string[],
  ): Promise<CliResult & { valid?: boolean }> {
    const args = ['--prefix', prefix, '--text', text];
    for (const sig of signatures) {
      args.push('--signature', sig);
    }

    const result = await this.run(['verify'], args);
    const valid = parseVerifyResult(result.stdout, result.exitCode);
    return { ...result, valid };
  }

  // ── OOBI ──

  async oobiGenerate(alias: string, role: string): Promise<CliResult & { oobis?: string[] }> {
    const result = await this.run(['oobi', 'generate'], ['--alias', alias, '--role', role]);
    const oobis = result.exitCode === 0 ? parseOobiUrls(result.stdout) : undefined;
    return { ...result, oobis };
  }

  async oobiResolve(oobi: string, alias?: string): Promise<CliResult> {
    const args = ['--oobi', oobi];
    if (alias) args.push('--oobi-alias', alias);
    return this.run(['oobi', 'resolve'], args);
  }

  // ── Event inspection ──

  async event(alias: string, flags: {
    said?: boolean; sn?: boolean; raw?: boolean; json?: boolean; seal?: boolean;
  }): Promise<CliResult & {
    said?: string; sn?: number; raw?: string;
    json?: Record<string, unknown>;
    seal?: { i: string; s: string; d: string };
  }> {
    const args = ['--alias', alias];
    if (flags.said) args.push('--said');
    if (flags.sn) args.push('--sn');
    if (flags.raw) args.push('--raw');
    if (flags.json) args.push('--json');
    if (flags.seal) args.push('--seal');

    const result = await this.run(['event'], args);
    const parsed = parseEventOutput(result.stdout, flags);
    return { ...result, ...parsed };
  }

  async list(): Promise<CliResult & { identifiers?: Array<{ name: string; prefix: string }> }> {
    const result = await this.run(['list'], []);
    const identifiers = result.exitCode === 0 ? parseIdentifierList(result.stdout) : undefined;
    return { ...result, identifiers };
  }

  // ── Credential lifecycle ──

  async vcRegistryIncept(alias: string, registryName: string): Promise<CliResult> {
    return this.run(['vc', 'registry', 'incept'], ['--alias', alias, '--registry-name', registryName]);
  }

  async vcCreate(opts: {
    alias: string; registryName: string; schema: string;
    data: Record<string, unknown>; recipient?: string;
  }): Promise<CliResult & { said?: string }> {
    const tempEnv = await this.ensureTempEnv();
    const dataPath = await tempEnv.writeFile('vc-data.json', JSON.stringify(opts.data));
    const args = [
      '--alias', opts.alias,
      '--registry-name', opts.registryName,
      '--schema', opts.schema,
      '--data', `@${dataPath}`,
    ];
    if (opts.recipient) args.push('--recipient', opts.recipient);
    const result = await this.run(['vc', 'create'], args);
    // kli vc create outputs the credential SAID
    const saidMatch = result.stdout.match(/([A-Za-z0-9_-]{44})/);
    return { ...result, said: saidMatch?.[1] };
  }

  async vcList(alias: string): Promise<CliResult> {
    return this.run(['vc', 'list'], ['--alias', alias]);
  }

  async vcRevoke(alias: string, said: string): Promise<CliResult> {
    return this.run(['vc', 'revoke'], ['--alias', alias, '--said', said]);
  }

  // ── Challenge-response ──

  async challengeGenerate(strength?: number): Promise<CliResult & { words?: string[] }> {
    const args: string[] = [];
    if (strength) args.push('--strength', String(strength));
    args.push('--out', 'json');
    const result = await execCli(this.kli, ['challenge', 'generate', ...args], { timeout: this.timeout });
    let words: string[] | undefined;
    if (result.exitCode === 0) {
      try { words = JSON.parse(result.stdout.trim()); } catch { /* ignore */ }
    }
    return { ...result, words };
  }

  async challengeRespond(opts: {
    alias: string; recipient: string; words: string;
  }): Promise<CliResult> {
    return this.run(['challenge', 'respond'], [
      '--alias', opts.alias,
      '--recipient', opts.recipient,
      '--words', opts.words,
    ]);
  }

  async challengeVerify(opts: {
    alias: string; signer: string; words: string;
  }): Promise<CliResult & { verified?: boolean }> {
    const result = await this.run(['challenge', 'verify'], [
      '--signer', opts.signer,
      '--words', opts.words,
    ]);
    return { ...result, verified: result.exitCode === 0 && /successfully responded/.test(result.stdout) };
  }

  // ── Delegation ──

  async delegateConfirm(alias: string, opts?: {
    auto?: boolean; interact?: boolean;
  }): Promise<CliResult> {
    const args = ['--alias', alias];
    if (opts?.auto) args.push('--auto');
    if (opts?.interact) args.push('--interact');
    return this.run(['delegate', 'confirm'], args);
  }

  // ── Escrow ──

  async escrowList(): Promise<CliResult> {
    return this.run(['escrow', 'list'], []);
  }

  // ── Witnesses ──

  async witnessDemo(): Promise<WitnessHandle> {
    return new Promise((resolve, reject) => {
      const proc = spawn(this.kli, ['witness', 'demo'], {
        stdio: ['pipe', 'pipe', 'pipe'],
        detached: false,
      });

      let started = false;

      // Give witnesses time to start up
      const timer = setTimeout(() => {
        if (!started) {
          started = true;
          resolve({
            async stop() {
              proc.kill('SIGTERM');
              await new Promise<void>(r => {
                proc.on('close', () => r());
                setTimeout(() => {
                  if (!proc.killed) proc.kill('SIGKILL');
                  r();
                }, 3000);
              });
            },
            oobiUrls: Object.values(DEMO_WITNESSES).map(
              w => `http://127.0.0.1:${w.http}/oobi/${w.aid}/controller`,
            ),
          });
        }
      }, 3000);

      proc.on('error', (err) => {
        clearTimeout(timer);
        if (!started) reject(err);
      });

      proc.on('close', (code) => {
        clearTimeout(timer);
        if (!started) {
          reject(new Error(`kli witness demo exited with code ${code} before starting`));
        }
      });
    });
  }
}

/**
 * Check if kli is available on this system.
 * Returns the version string or null if not found.
 */
export async function detectKli(kliPath: string = 'kli'): Promise<string | null> {
  try {
    const result = await execCli(kliPath, ['version'], { timeout: 5000 });
    if (result.exitCode === 0) return result.stdout.trim();
    return null;
  } catch {
    return null;
  }
}
